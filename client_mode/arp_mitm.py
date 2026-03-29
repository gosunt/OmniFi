"""
OmniFi — ARP MITM Detector
=============================
Detects ARP-based Man-in-the-Middle attacks by monitoring:
  1. Gateway MAC change      — someone poisoned the ARP cache
  2. IP/MAC conflicts        — two MACs claim same IP
  3. ARP reply flood         — high frequency = active poisoning tool running
  4. Gratuitous ARP spam     — unsolicited ARPs updating entries

Requirements: pip install scapy
"""

import time
import sqlite3
import os
import platform
import subprocess
import re
import datetime
from collections import defaultdict

try:
    from scapy.all import sniff, ARP, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

DB_PATH          = os.path.join(os.path.dirname(__file__), "..", "db", "omnifi.db")
CAPTURE_SECONDS  = 30
ARP_FLOOD_THRESH = 15    # ARP replies per second = flood


def _get_conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS arp_baseline (
            ip   TEXT PRIMARY KEY,
            mac  TEXT NOT NULL,
            seen TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


class ARPMITMDetector:

    def __init__(self, interface="wlan0", verbose=True):
        self.interface     = interface
        self.verbose       = verbose
        self.conn          = _get_conn()
        self.alerts        = []
        self._arp_times    = []            # timestamps of ARP replies
        self._ip_mac_map: dict[str,str] = {}  # ip → mac seen this session

    def run(self) -> dict:
        self._print("\n[OmniFi] ARP MITM Detector...\n")

        # Check 1: static ARP table snapshot (no Scapy needed)
        result = self._check_arp_table()

        # Check 2: passive Scapy sniff (if available)
        if SCAPY_AVAILABLE:
            self._print(f"  Sniffing ARP packets for {CAPTURE_SECONDS}s...")
            try:
                sniff(iface=self.interface,
                      filter="arp",
                      prn=self._handle_arp,
                      timeout=CAPTURE_SECONDS,
                      store=False)
            except Exception as e:
                self._print(f"  [!] Sniff error: {e}  (requires root)")

            self._check_flood()
        else:
            self._print("  [i] Scapy not available — running static ARP check only.")

        result["alerts"] = self.alerts
        return result

    # ── Static ARP table check ────────────────────────────────────────────────

    def _check_arp_table(self) -> dict:
        result = {"gateway_mac_stable": True, "conflicts": [], "attack_detected": False}

        arp_table = self._read_arp_table()
        gateway   = self._get_gateway_ip()

        if not arp_table:
            self._print("  [i] ARP table empty or unreadable.")
            return result

        self._print(f"  ARP table — {len(arp_table)} entries\n")

        for ip, mac in arp_table.items():
            # Check against stored baseline
            cur = self.conn.cursor()
            cur.execute("SELECT mac FROM arp_baseline WHERE ip=?", (ip,))
            row = cur.fetchone()

            if row:
                stored_mac = row[0].upper()
                if mac.upper() != stored_mac:
                    msg = (f"ARP entry changed: {ip} was {stored_mac}, "
                           f"now {mac.upper()}.")
                    if ip == gateway:
                        msg += " GATEWAY MAC CHANGED — likely ARP poisoning!"
                        result["gateway_mac_stable"] = False
                        result["attack_detected"]    = True
                        self._alert(msg, "critical")
                    else:
                        self._alert(msg, "high")
                    result["conflicts"].append(msg)
                    self._print(f"  [{'!!!' if ip==gateway else '!!'}] {msg}")
                else:
                    self._print(f"  [+]  {ip:<16}  {mac}  stable")
            else:
                # First time seeing this — store as baseline
                now = datetime.datetime.now().isoformat()
                self.conn.execute(
                    "INSERT OR REPLACE INTO arp_baseline (ip, mac, seen) VALUES (?,?,?)",
                    (ip, mac.upper(), now)
                )
                self.conn.commit()
                self._print(f"  [i]  {ip:<16}  {mac}  (new — stored)")

        return result

    # ── Scapy ARP packet handler ──────────────────────────────────────────────

    def _handle_arp(self, pkt):
        if not pkt.haslayer(ARP):
            return

        arp      = pkt[ARP]
        op       = arp.op         # 1=request, 2=reply
        src_ip   = arp.psrc
        src_mac  = arp.hwsrc.upper()
        dst_ip   = arp.pdst

        # Track ARP reply timestamps for flood detection
        if op == 2:
            self._arp_times.append(time.time())

        # Detect IP/MAC conflict in this session
        if src_ip in self._ip_mac_map:
            if self._ip_mac_map[src_ip] != src_mac:
                msg = (f"IP/MAC conflict: {src_ip} claimed by both "
                       f"{self._ip_mac_map[src_ip]} and {src_mac}. "
                       f"ARP poisoning likely!")
                self._alert(msg, "critical")
                self._print(f"  [!!!] {msg}")
        else:
            self._ip_mac_map[src_ip] = src_mac

        # Detect gratuitous ARP (src_ip == dst_ip, op=2)
        if op == 2 and src_ip == dst_ip:
            gateway = self._get_gateway_ip()
            if src_ip == gateway:
                msg = (f"Gratuitous ARP from gateway {src_ip} ({src_mac}) — "
                       f"verify this is the legitimate router.")
                self._alert(msg, "medium")

    def _check_flood(self):
        if len(self._arp_times) < 2:
            return
        window    = self._arp_times[-1] - self._arp_times[0]
        rate      = len(self._arp_times) / max(window, 1)
        if rate >= ARP_FLOOD_THRESH:
            msg = (f"ARP flood detected: {rate:.1f} replies/sec "
                   f"(threshold {ARP_FLOOD_THRESH}). "
                   f"Active ARP poisoning tool likely running.")
            self._alert(msg, "critical")
            self._print(f"  [!!!] {msg}")
        else:
            self._print(f"  [+]  ARP rate: {rate:.1f}/sec — normal.")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _read_arp_table(self) -> dict:
        """Read OS ARP table. Returns ip → mac dict."""
        try:
            if platform.system() == "Windows":
                out = subprocess.check_output(["arp", "-a"], text=True,
                                              stderr=subprocess.DEVNULL)
                pattern = r"([\d.]+)\s+([\w-]{17})"
                sep     = "-"
            else:
                out = subprocess.check_output(["arp", "-n"], text=True,
                                              stderr=subprocess.DEVNULL)
                pattern = r"([\d.]+)\s+\S+\s+([\w:]{17})"
                sep     = ":"

            entries = {}
            for m in re.finditer(pattern, out):
                ip  = m.group(1)
                mac = m.group(2).replace("-", ":").upper()
                if mac not in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
                    entries[ip] = mac
            return entries
        except Exception:
            return {}

    def _get_gateway_ip(self) -> str:
        try:
            if platform.system() == "Windows":
                out = subprocess.check_output(["ipconfig"], text=True,
                                              stderr=subprocess.DEVNULL)
                m   = re.search(r"Default Gateway.*?:\s*([\d.]+)", out)
            else:
                out = subprocess.check_output(["ip", "route"], text=True,
                                              stderr=subprocess.DEVNULL)
                m   = re.search(r"default via ([\d.]+)", out)
            return m.group(1) if m else ""
        except Exception:
            return ""

    def _alert(self, msg, level="medium"):
        self.alerts.append({"level": level, "message": msg})

    def _print(self, msg):
        if self.verbose: print(msg)


if __name__ == "__main__":
    ARPMITMDetector().run()
