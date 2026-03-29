"""
OmniFi — DHCP Rogue Server Detector
=====================================
A legitimate network has exactly one DHCP server.
Multiple DHCP OFFERs for the same client = rogue DHCP server present.
A rogue DHCP server can redirect all traffic by providing a malicious
default gateway or DNS server.

Detection method:
  Passively sniff DHCP OFFER packets (UDP port 67→68) using Scapy.
  Collect the 'siaddr' (server IP) field from each OFFER.
  If more than one unique server IP is seen → rogue server alert.

Requirements:
  - Scapy  (pip install scapy)
  - Root / sudo privileges (raw socket sniffing)
"""

import time
from collections import defaultdict

try:
    from scapy.all import sniff, DHCP, BOOTP, Ether, IP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

CAPTURE_SECONDS = 30


class DHCPRogueDetector:
    def __init__(self, interface="wlan0", verbose=True):
        self.interface       = interface
        self.verbose         = verbose
        self.dhcp_servers    = {}     # server_ip → list of offer timestamps
        self.alerts          = []

    def run(self) -> dict:
        if not SCAPY_AVAILABLE:
            self._print("[!] Scapy not installed. Run: pip install scapy")
            return {}

        self._print(f"\n[OmniFi] DHCP Rogue Server Detector — sniffing {CAPTURE_SECONDS}s...\n")

        try:
            sniff(iface=self.interface,
                  filter="udp and (port 67 or port 68)",
                  prn=self._handle_packet,
                  timeout=CAPTURE_SECONDS,
                  store=False)
        except Exception as e:
            self._print(f"  [!] Sniff error: {e}  (requires root)")
            return {}

        return self._analyse()

    def _handle_packet(self, pkt):
        if not (pkt.haslayer(DHCP) and pkt.haslayer(BOOTP)):
            return

        dhcp_options = {opt[0]: opt[1] for opt in pkt[DHCP].options
                        if isinstance(opt, tuple)}

        msg_type = dhcp_options.get("message-type")
        # DHCP OFFER = type 2
        if msg_type == 2:
            server_ip = pkt[BOOTP].siaddr
            if server_ip and server_ip != "0.0.0.0":
                if server_ip not in self.dhcp_servers:
                    self.dhcp_servers[server_ip] = []
                    self._print(f"  [i] DHCP OFFER from server: {server_ip}")
                self.dhcp_servers[server_ip].append(time.time())

    def _analyse(self) -> dict:
        result = {
            "servers_detected": list(self.dhcp_servers.keys()),
            "rogue_detected":   False,
            "alerts":           self.alerts,
        }

        if len(self.dhcp_servers) == 0:
            self._print("  [i] No DHCP offers captured in window.")

        elif len(self.dhcp_servers) == 1:
            server = list(self.dhcp_servers.keys())[0]
            self._print(f"  [+] Single DHCP server detected: {server} — clean.")

        else:
            result["rogue_detected"] = True
            servers = list(self.dhcp_servers.keys())
            msg = (f"ROGUE DHCP SERVER DETECTED: Multiple servers responding — "
                   f"{', '.join(servers)}. One may be redirecting traffic through an attacker.")
            self._alert(msg, "critical")
            self._print(f"\n  [!!!] {msg}")
            self._print("        Recommendation: Disconnect and switch to mobile data.")

        return result

    def _alert(self, msg, level="critical"):
        self.alerts.append({"level": level, "message": msg})

    def _print(self, msg):
        if self.verbose: print(msg)


if __name__ == "__main__":
    DHCPRogueDetector().run()
