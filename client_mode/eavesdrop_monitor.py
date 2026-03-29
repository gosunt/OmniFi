"""
OmniFi — Eavesdropping & MITM Monitor
========================================
Passively detects signs that someone is intercepting your traffic:

  1. ARP cache poisoning (gateway MAC changed → classic MITM)
  2. Duplicate IP with different MACs in the same ARP exchange
  3. Gratuitous ARP flood (attacker is continuously poisoning)
  4. Cleartext HTTP credential keywords on the wire (Scapy sniffer)
  5. SSL stripping hint — HTTP redirect to HTTP (no HTTPS upgrade)
  6. Unexpected default-gateway change (route table watch)

All detections emit an alert via ALERTS bridge and also return structured
EavesdropEvent objects so the UI can display a live event feed.

Requires:  root / Administrator  +  Scapy  (for packet-level checks).
Runs as a background QThread worker; poll  get_events()  from the UI.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

log = logging.getLogger("OmniFi.EavesdropMonitor")

_SCAPY_OK = False
try:
    from scapy.all import (ARP, IP, TCP, sniff, get_if_hwaddr,   # noqa
                           conf as _scapy_conf)
    _SCAPY_OK = True
except Exception:
    pass


# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class EavesdropEvent:
    ts: float = field(default_factory=time.time)
    category: str = ""          # arp_poison / garp_flood / cleartext / ssl_strip / gw_change
    severity: str = "high"
    message: str = ""
    detail: str = ""
    attacker_mac: str = ""
    attacker_ip: str = ""

    def summary(self) -> str:
        return f"[Eavesdrop/{self.category}] {self.message}"


# ─────────────────────────────────────────────────────────────────────────────
class EavesdropMonitor:
    """
    Start with  start()  — spawns background daemon threads.
    Stop  with  stop().
    Poll results via  get_events(clear=True).
    """

    POLL_INTERVAL   = 10   # seconds between gateway-route checks
    SNIFF_TIMEOUT   = 8    # seconds per Scapy sniff burst
    GARP_THRESHOLD  = 5    # gratuitous ARPs/second → flood alert
    CLEARTEXT_PORTS = {80, 8080, 8000, 21, 23, 110, 143}

    _CRED_PATTERNS = [
        re.compile(rb"(?i)(password|passwd|pass|pwd|secret)\s*=\s*[^\s&]{3,}"),
        re.compile(rb"(?i)(user|username|login|email)\s*=\s*[^\s&]{3,}"),
        re.compile(rb"(?i)Authorization:\s*Basic\s+\S+"),
    ]
    _HTTP_REDIRECT = re.compile(rb"(?i)Location:\s*http://")

    def __init__(self,
                 interface: str = "",
                 on_event: Optional[Callable[[EavesdropEvent], None]] = None,
                 verbose: bool = True):
        self._iface = interface
        self._on_event = on_event
        self._verbose = verbose
        self._stop_flag = threading.Event()
        self._lock = threading.Lock()
        self._events: List[EavesdropEvent] = []

        # ARP state
        self._arp_table: Dict[str, str] = {}   # ip → mac
        self._garp_counts: Dict[str, List[float]] = {}  # mac → [timestamps]

        # Gateway tracking
        self._known_gateway_ip: str = ""
        self._known_gateway_mac: str = ""

        self._threads: List[threading.Thread] = []

    # ── Public ───────────────────────────────────────────────────────────────
    def start(self):
        self._stop_flag.clear()
        # Seed gateway info
        self._known_gateway_ip  = self._get_gateway_ip()
        self._known_gateway_mac = self._resolve_mac(self._known_gateway_ip)

        t1 = threading.Thread(target=self._arp_loop,      daemon=True)
        t2 = threading.Thread(target=self._route_watcher, daemon=True)
        if _SCAPY_OK:
            t3 = threading.Thread(target=self._pkt_sniffer, daemon=True)
            self._threads = [t1, t2, t3]
            t3.start()
        else:
            self._threads = [t1, t2]
        t1.start(); t2.start()
        self._print("Eavesdrop monitor started.")

    def stop(self):
        self._stop_flag.set()
        self._print("Eavesdrop monitor stopped.")

    def get_events(self, clear: bool = False) -> List[EavesdropEvent]:
        with self._lock:
            ev = list(self._events)
            if clear:
                self._events.clear()
        return ev

    # ── ARP loop (OS arp table polling) ──────────────────────────────────────
    def _arp_loop(self):
        while not self._stop_flag.is_set():
            table = self._read_arp_table()
            for ip, mac in table.items():
                prev = self._arp_table.get(ip)
                if prev and prev != mac:
                    # IP now has a different MAC
                    is_gw = (ip == self._known_gateway_ip)
                    sev = "critical" if is_gw else "high"
                    label = "GATEWAY" if is_gw else "host"
                    self._emit(EavesdropEvent(
                        category="arp_poison",
                        severity=sev,
                        message=(f"ARP cache poisoning on {label} {ip}: "
                                 f"MAC changed {prev} → {mac}"),
                        detail=(f"IP {ip} previously mapped to {prev}, "
                                f"now maps to {mac}. "
                                + ("Gateway hijacked — all your traffic may be intercepted!" if is_gw
                                   else "Possible MITM attack.")),
                        attacker_mac=mac,
                        attacker_ip=ip,
                    ))
                self._arp_table[ip] = mac
            time.sleep(self.POLL_INTERVAL)

    # ── Route watcher — detect gateway IP change ──────────────────────────────
    def _route_watcher(self):
        while not self._stop_flag.is_set():
            gw = self._get_gateway_ip()
            if gw and gw != self._known_gateway_ip and self._known_gateway_ip:
                self._emit(EavesdropEvent(
                    category="gw_change",
                    severity="critical",
                    message=(f"Default gateway changed: "
                             f"{self._known_gateway_ip} → {gw}"),
                    detail="Possible rogue DHCP server or ICMP redirect attack redirecting all traffic.",
                    attacker_ip=gw,
                ))
                self._known_gateway_ip = gw
            time.sleep(self.POLL_INTERVAL)

    # ── Scapy packet sniffer ──────────────────────────────────────────────────
    def _pkt_sniffer(self):
        """Sniff ARP + TCP/HTTP in short bursts."""
        if not _SCAPY_OK:
            return
        bpf = "arp or (tcp and (port 80 or port 8080 or port 21 or port 23))"
        while not self._stop_flag.is_set():
            try:
                sniff(
                    iface=self._iface or None,
                    filter=bpf,
                    prn=self._handle_pkt,
                    timeout=self.SNIFF_TIMEOUT,
                    store=False,
                )
            except Exception as e:
                log.debug(f"[Eavesdrop] sniff error: {e}")
                time.sleep(5)

    def _handle_pkt(self, pkt):
        try:
            if pkt.haslayer(ARP):
                self._handle_arp_pkt(pkt)
            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                self._handle_tcp_pkt(pkt)
        except Exception:
            pass

    def _handle_arp_pkt(self, pkt):
        arp = pkt[ARP]
        # Gratuitous ARP: sender IP == target IP (op 2 = reply)
        if arp.op == 2 and arp.psrc == arp.pdst:
            mac = arp.hwsrc
            ts_list = self._garp_counts.setdefault(mac, [])
            now = time.time()
            ts_list.append(now)
            # Keep only last 5 seconds
            ts_list[:] = [t for t in ts_list if now - t < 5]
            if len(ts_list) >= self.GARP_THRESHOLD:
                self._emit(EavesdropEvent(
                    category="garp_flood",
                    severity="high",
                    message=(f"Gratuitous ARP flood from {mac} — "
                             f"{len(ts_list)} GARPs in 5 sec"),
                    detail="Continuous ARP poisoning attack detected. Attacker is re-poisoning constantly.",
                    attacker_mac=mac,
                    attacker_ip=arp.psrc,
                ))
                self._garp_counts[mac] = []    # reset counter

    def _handle_tcp_pkt(self, pkt):
        if not pkt.haslayer(TCP):
            return
        try:
            payload = bytes(pkt[TCP].payload)
        except Exception:
            return
        if not payload:
            return

        # Cleartext credentials
        for pattern in self._CRED_PATTERNS:
            m = pattern.search(payload)
            if m:
                src = pkt[IP].src
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                self._emit(EavesdropEvent(
                    category="cleartext",
                    severity="critical",
                    message=(f"Cleartext credentials detected in HTTP traffic "
                             f"from {src}:{sport} → port {dport}"),
                    detail=("Login credentials are being transmitted without encryption. "
                            "Switch to HTTPS-only sites and enable VPN immediately."),
                    attacker_ip=src,
                ))
                break   # one alert per packet is enough

        # SSL strip hint: HTTP redirect to plain HTTP
        if self._HTTP_REDIRECT.search(payload):
            self._emit(EavesdropEvent(
                category="ssl_strip",
                severity="high",
                message="SSL stripping hint: server redirected to plain HTTP",
                detail=("A server is redirecting you back to HTTP (not HTTPS). "
                        "This may indicate an SSL strip MITM attack."),
            ))

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _emit(self, ev: EavesdropEvent):
        with self._lock:
            # Deduplicate: don't repeat same category+message in < 60 s
            now = time.time()
            for old in self._events[-20:]:
                if old.category == ev.category and old.message == ev.message:
                    if now - old.ts < 60:
                        return
            self._events.append(ev)
        self._print(f"  [!] {ev.summary()}")
        self._send_alert(ev)

    def _send_alert(self, ev: EavesdropEvent):
        if self._on_event:
            try:
                self._on_event(ev)
            except Exception:
                pass
        try:
            from core.monitor_utils import ALERTS
            ALERTS.emit_alert(ev.severity, "eavesdrop", ev.message, ev.detail,
                              signals=["eavesdrop"])
        except Exception:
            pass

    @staticmethod
    def _read_arp_table() -> Dict[str, str]:
        """Read OS ARP cache: ip → mac."""
        table: Dict[str, str] = {}
        try:
            import platform
            if platform.system() == "Windows":
                out = subprocess.check_output(["arp", "-a"], text=True, timeout=5)
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0].strip()
                        mac = parts[1].strip().replace("-", ":").lower()
                        try:
                            ipaddress.ip_address(ip)
                            if len(mac) == 17:
                                table[ip] = mac
                        except ValueError:
                            pass
            else:
                out = subprocess.check_output(["arp", "-n"], text=True, timeout=5)
                for line in out.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 3 and ":" in parts[2]:
                        table[parts[0]] = parts[2].lower()
        except Exception as e:
            log.debug(f"[Eavesdrop] arp table error: {e}")
        return table

    @staticmethod
    def _get_gateway_ip() -> str:
        try:
            import platform
            if platform.system() == "Windows":
                out = subprocess.check_output(
                    ["route", "print", "0.0.0.0"], text=True, timeout=5)
                for line in out.splitlines():
                    parts = line.split()
                    if parts and parts[0] == "0.0.0.0" and len(parts) >= 3:
                        return parts[2]
            else:
                out = subprocess.check_output(
                    ["ip", "route", "show", "default"], text=True, timeout=5)
                m = re.search(r"default via ([\d.]+)", out)
                if m:
                    return m.group(1)
        except Exception as e:
            log.debug(f"[Eavesdrop] gateway lookup: {e}")
        return ""

    @staticmethod
    def _resolve_mac(ip: str) -> str:
        try:
            import platform
            if platform.system() == "Windows":
                out = subprocess.check_output(["arp", "-a", ip], text=True, timeout=3)
            else:
                out = subprocess.check_output(["arp", "-n", ip], text=True, timeout=3)
            for line in out.splitlines():
                parts = line.split()
                for p in parts:
                    if re.match(r"([0-9a-f]{2}[:\-]){5}[0-9a-f]{2}", p, re.I):
                        return p.lower().replace("-", ":")
        except Exception:
            pass
        return ""

    def _print(self, msg: str):
        if self._verbose:
            log.info(msg)
