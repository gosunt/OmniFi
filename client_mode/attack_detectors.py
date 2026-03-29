"""
OmniFi — Network Attack Detectors
====================================
Three passive detection modules:

1. DHCP rogue server detection
   - Listens for DHCP OFFER packets from multiple sources
   - Multiple DHCP servers = rogue server attack

2. ICMP redirect attack detection
   - Passive Scapy sniff for unexpected ICMP type 5 (redirect) messages
   - Completely invisible without this check

3. Beacon interval anomaly detection
   - Measures beacon frame timing — rogue APs often use non-standard intervals
   - Standard interval: 100ms (±5ms tolerance)
"""

import time
import threading
import platform
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from collections import defaultdict

try:
    from scapy.all import (
        sniff, DHCP, BOOTP, IP, ICMP, Dot11, Dot11Beacon,
        Dot11Elt, conf as scapy_conf
    )
    scapy_conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


RESET = "\033[0m"
RED   = "\033[91m"
YELLOW= "\033[93m"
GREEN = "\033[92m"
BOLD  = "\033[1m"


# ─────────────────────────────────────────────────────────────────────────────
# 1. DHCP Rogue Server Detector
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DHCPAlert:
    server_ip:    str
    server_mac:   str
    detail:       str
    severity:     str = "critical"
    timestamp:    str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


class RogueDHCPDetector:
    """
    Passively sniffs DHCP OFFER packets. On a legitimate network
    exactly one server should respond. More than one = rogue DHCP server.
    """

    SNIFF_TIMEOUT = 30   # seconds to listen

    def __init__(self, interface: str = None, verbose: bool = True):
        self.interface = interface
        self.verbose   = verbose
        self.dhcp_servers: dict[str, str] = {}   # ip → mac
        self.alerts: list[DHCPAlert] = []

    def run(self) -> list[DHCPAlert]:
        if not SCAPY_AVAILABLE:
            print("  [!] Scapy not installed — DHCP rogue detection unavailable.")
            return []

        print(f"\n[OmniFi] DHCP Rogue Server Detector (listening {self.SNIFF_TIMEOUT}s)...")

        try:
            sniff(
                filter="udp and (port 67 or port 68)",
                prn=self._packet_handler,
                timeout=self.SNIFF_TIMEOUT,
                iface=self.interface,
                store=False
            )
        except Exception as e:
            print(f"  [!] Sniff error: {e}")

        self._analyse_results()
        return self.alerts

    def _packet_handler(self, pkt):
        if not (DHCP in pkt and BOOTP in pkt):
            return

        # Look for DHCP OFFER or ACK (type 2 or 5)
        dhcp_type = None
        for opt in pkt[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == "message-type":
                dhcp_type = opt[1]
                break

        if dhcp_type not in (2, 5):   # OFFER or ACK
            return

        server_ip  = pkt[IP].src if IP in pkt else "unknown"
        server_mac = pkt.src

        if server_ip not in self.dhcp_servers:
            self.dhcp_servers[server_ip] = server_mac
            self._print(f"  [*] DHCP server seen: {server_ip} ({server_mac})")

    def _analyse_results(self):
        count = len(self.dhcp_servers)
        if count == 0:
            self._print("  [*] No DHCP servers observed (no new leases during capture).")
        elif count == 1:
            ip, mac = list(self.dhcp_servers.items())[0]
            self._print(f"  {GREEN}[+] Single DHCP server: {ip} ({mac}) — normal.{RESET}")
        else:
            self._print(f"  {RED}{BOLD}[!!!] {count} DHCP servers detected — ROGUE SERVER LIKELY!{RESET}")
            for ip, mac in self.dhcp_servers.items():
                alert = DHCPAlert(
                    server_ip=ip, server_mac=mac,
                    detail=(
                        f"Multiple DHCP servers on network. Server: {ip} ({mac}). "
                        f"A rogue DHCP server can redirect all traffic through the attacker."
                    )
                )
                self.alerts.append(alert)
                self._print(f"      {RED}[!] {alert.detail}{RESET}")

    def _print(self, msg):
        if self.verbose:
            print(msg)


# ─────────────────────────────────────────────────────────────────────────────
# 2. ICMP Redirect Attack Detector
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ICMPRedirectAlert:
    src_ip:      str
    redirect_gw: str
    target_ip:   str
    detail:      str
    severity:    str = "critical"
    timestamp:   str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


class ICMPRedirectDetector:
    """
    Detects forged ICMP redirect messages (type 5).
    These silently reroute traffic through the attacker's machine
    without touching ARP — completely invisible without this check.
    """

    SNIFF_TIMEOUT = 60

    def __init__(self, interface: str = None, verbose: bool = True):
        self.interface = interface
        self.verbose   = verbose
        self.alerts: list[ICMPRedirectAlert] = []

    def run(self) -> list[ICMPRedirectAlert]:
        if not SCAPY_AVAILABLE:
            print("  [!] Scapy not installed — ICMP redirect detection unavailable.")
            return []

        print(f"\n[OmniFi] ICMP Redirect Detector (listening {self.SNIFF_TIMEOUT}s)...")

        try:
            sniff(
                filter="icmp",
                prn=self._packet_handler,
                timeout=self.SNIFF_TIMEOUT,
                iface=self.interface,
                store=False
            )
        except Exception as e:
            print(f"  [!] Sniff error: {e}")

        if not self.alerts:
            self._print(f"  {GREEN}[+] No ICMP redirect attacks detected.{RESET}")

        return self.alerts

    def _packet_handler(self, pkt):
        if not (IP in pkt and ICMP in pkt):
            return

        icmp_type = pkt[ICMP].type
        icmp_code = pkt[ICMP].code

        # ICMP Type 5 = Redirect
        if icmp_type != 5:
            return

        src_ip      = pkt[IP].src
        redirect_gw = pkt[ICMP].gw if hasattr(pkt[ICMP], "gw") else "unknown"
        target_ip   = pkt[IP].dst

        code_meaning = {
            0: "Redirect for network",
            1: "Redirect for host",
            2: "Redirect for TOS and network",
            3: "Redirect for TOS and host",
        }.get(icmp_code, "Unknown redirect type")

        detail = (
            f"ICMP Redirect (type 5, code {icmp_code} — {code_meaning}) "
            f"from {src_ip}. New gateway: {redirect_gw}. "
            f"Target: {target_ip}. Traffic may be silently rerouted through attacker."
        )

        alert = ICMPRedirectAlert(
            src_ip=src_ip,
            redirect_gw=str(redirect_gw),
            target_ip=target_ip,
            detail=detail
        )
        self.alerts.append(alert)
        self._print(f"  {RED}{BOLD}[!!!] ICMP Redirect detected!{RESET}")
        self._print(f"        {detail}")

    def _print(self, msg):
        if self.verbose:
            print(msg)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Beacon Interval Anomaly Detector
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class BeaconAnomalyAlert:
    ssid:             str
    bssid:            str
    measured_interval_ms: float
    expected_ms:      float = 100.0
    detail:           str   = ""
    severity:         str   = "medium"
    timestamp:        str   = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


class BeaconAnomalyDetector:
    """
    Measures beacon frame timing for each AP.
    Standard interval: 100ms (802.11 TU = 1024 µs).
    Rogue APs / evil twins created by hostapd-wpe etc. often deviate.
    Requires monitor mode interface.
    """

    SNIFF_TIMEOUT   = 20    # seconds
    TOLERANCE_MS    = 15    # ±15ms tolerance
    MIN_SAMPLES     = 5     # minimum beacons per AP to score

    def __init__(self, monitor_interface: str = "wlan0mon", verbose: bool = True):
        self.interface  = monitor_interface
        self.verbose    = verbose
        self.beacons: dict[str, list[float]] = defaultdict(list)  # bssid → timestamps
        self.alerts: list[BeaconAnomalyAlert] = []

    def run(self) -> list[BeaconAnomalyAlert]:
        if not SCAPY_AVAILABLE:
            print("  [!] Scapy not installed — beacon anomaly detection unavailable.")
            return []

        print(f"\n[OmniFi] Beacon Interval Anomaly Detector "
              f"(interface: {self.interface}, {self.SNIFF_TIMEOUT}s)...")
        print(f"  [*] Requires monitor mode: sudo airmon-ng start wlan0")

        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                timeout=self.SNIFF_TIMEOUT,
                store=False
            )
        except Exception as e:
            print(f"  [!] Monitor mode sniff error: {e}")
            print(f"  [*] Ensure interface is in monitor mode.")
            return []

        self._analyse_intervals()
        return self.alerts

    def _packet_handler(self, pkt):
        if not (pkt.haslayer(Dot11Beacon)):
            return
        bssid = pkt[Dot11].addr3 if pkt.haslayer(Dot11) else None
        if bssid:
            self.beacons[bssid].append(time.time())

    def _analyse_intervals(self):
        self._print(f"\n  Analysed {len(self.beacons)} APs:")

        for bssid, timestamps in self.beacons.items():
            if len(timestamps) < self.MIN_SAMPLES:
                continue

            # Calculate average interval between consecutive beacons
            intervals_ms = [
                (timestamps[i+1] - timestamps[i]) * 1000
                for i in range(len(timestamps) - 1)
            ]
            avg_ms = sum(intervals_ms) / len(intervals_ms)

            deviation = abs(avg_ms - 100.0)
            status = "normal" if deviation <= self.TOLERANCE_MS else "ANOMALOUS"
            color  = GREEN if status == "normal" else RED

            self._print(f"  {color}[{status}]{RESET} BSSID {bssid}: "
                        f"avg interval {avg_ms:.1f}ms (expected ~100ms)")

            if deviation > self.TOLERANCE_MS:
                alert = BeaconAnomalyAlert(
                    ssid="",   # will be filled from history tracker
                    bssid=bssid,
                    measured_interval_ms=avg_ms,
                    detail=(
                        f"BSSID {bssid} beacon interval {avg_ms:.1f}ms deviates "
                        f"{deviation:.1f}ms from standard 100ms. "
                        f"Possible rogue AP or evil twin (hostapd-wpe / airbase-ng)."
                    ),
                    severity="medium" if deviation < 50 else "high"
                )
                self.alerts.append(alert)
                self._print(f"        {YELLOW}[!] {alert.detail}{RESET}")

        if not self.alerts:
            self._print(f"  {GREEN}[+] All beacon intervals within normal range.{RESET}")

    def _print(self, msg):
        if self.verbose:
            print(msg)


# ─────────────────────────────────────────────────────────────────────────────
# Combined runner
# ─────────────────────────────────────────────────────────────────────────────

class NetworkAttackDetectors:
    """Run all three detectors in sequence or parallel threads."""

    def __init__(self, interface: str = None,
                 monitor_iface: str = "wlan0mon",
                 verbose: bool = True):
        self.dhcp_detector   = RogueDHCPDetector(interface, verbose)
        self.icmp_detector   = ICMPRedirectDetector(interface, verbose)
        self.beacon_detector = BeaconAnomalyDetector(monitor_iface, verbose)

    def run_all(self) -> dict:
        results = {
            "dhcp_alerts":   self.dhcp_detector.run(),
            "icmp_alerts":   self.icmp_detector.run(),
            "beacon_alerts": [],   # requires monitor mode — run separately
        }
        return results

    def run_dhcp_only(self) -> list[DHCPAlert]:
        return self.dhcp_detector.run()

    def run_icmp_only(self) -> list[ICMPRedirectAlert]:
        return self.icmp_detector.run()

    def run_beacon_only(self) -> list[BeaconAnomalyAlert]:
        return self.beacon_detector.run()


if __name__ == "__main__":
    import sys
    if "--dhcp" in sys.argv:
        RogueDHCPDetector().run()
    elif "--icmp" in sys.argv:
        ICMPRedirectDetector().run()
    elif "--beacon" in sys.argv:
        iface = sys.argv[sys.argv.index("--beacon") + 1] if len(sys.argv) > 2 else "wlan0mon"
        BeaconAnomalyDetector(monitor_interface=iface).run()
    else:
        print("Usage: python attack_detectors.py [--dhcp | --icmp | --beacon <iface>]")
