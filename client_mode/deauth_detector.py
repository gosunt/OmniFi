"""
OmniFi — Deauth Attack Detector
==================================
Detects Wi-Fi deauthentication / disassociation flood attacks.
These attacks disconnect clients by sending forged management frames
and are the basis of most evil twin setups.

Detection:
  - Sniffs 802.11 management frames (type=0) in monitor mode
  - Subtype 0x0C = Deauthentication, 0x0A = Disassociation
  - Counts frames per source MAC per second
  - Burst above threshold → alert

Client-mode response (no router access needed):
  - Alert user immediately
  - Log attacker MAC
  - Advise VPN or switching network
  - Trigger VPN auto-launch if configured

Requirements:
  - Scapy         (pip install scapy)
  - Monitor-mode adapter
  - Root / sudo
"""

import time
import collections
from dataclasses import dataclass, field

try:
    from scapy.all import sniff, Dot11, Dot11Deauth, Dot11Disas, RadioTap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

CAPTURE_SECONDS    = 30
DEAUTH_BURST_THRESH = 10    # frames per second from same source = attack
FRAME_WINDOW_SEC   = 2.0    # sliding window for rate calculation

# 802.11 management frame subtypes
DEAUTH_SUBTYPE    = 12     # 0x0C
DISASSOC_SUBTYPE  = 10     # 0x0A


@dataclass
class DeauthEvent:
    src_mac:     str
    dst_mac:     str
    frame_type:  str    # deauth / disassoc
    reason_code: int
    timestamp:   float


class DeauthDetector:

    def __init__(self, interface="wlan0mon", verbose=True):
        self.interface   = interface
        self.verbose     = verbose
        self.events:     list[DeauthEvent]         = []
        self.rate_window: dict[str, list[float]]   = collections.defaultdict(list)
        self.alerts:     list[dict]                = []
        self._alerted:   set                       = set()   # MACs already alerted

    def run(self) -> dict:
        if not SCAPY_AVAILABLE:
            self._print("[!] Scapy not installed. Run: pip install scapy")
            return {}

        self._print(f"\n[OmniFi] Deauth Attack Detector — sniffing {CAPTURE_SECONDS}s "
                    f"on {self.interface}...")
        self._print("  Requires monitor mode: airmon-ng start wlan0\n")

        try:
            sniff(iface=self.interface,
                  prn=self._handle_packet,
                  timeout=CAPTURE_SECONDS,
                  store=False,
                  monitor=True)
        except Exception as e:
            self._print(f"  [!] Sniff error: {e}")
            self._print("      Ensure adapter is in monitor mode and run as root.")

        return self._analyse()

    # ── Packet handler ────────────────────────────────────────────────────────

    def _handle_packet(self, pkt):
        if not pkt.haslayer(Dot11):
            return

        dot11 = pkt[Dot11]

        # Management frames: type=0
        if dot11.type != 0:
            return

        subtype    = dot11.subtype
        frame_type = None

        if subtype == DEAUTH_SUBTYPE:
            frame_type  = "deauth"
            reason_code = pkt[Dot11Deauth].reason if pkt.haslayer(Dot11Deauth) else 0
        elif subtype == DISASSOC_SUBTYPE:
            frame_type  = "disassoc"
            reason_code = pkt[Dot11Disas].reason if pkt.haslayer(Dot11Disas) else 0
        else:
            return

        src_mac = dot11.addr2 or "unknown"
        dst_mac = dot11.addr1 or "unknown"
        now     = time.time()

        event = DeauthEvent(
            src_mac=src_mac, dst_mac=dst_mac,
            frame_type=frame_type, reason_code=reason_code,
            timestamp=now
        )
        self.events.append(event)

        # Update sliding window for this source MAC
        self.rate_window[src_mac].append(now)
        # Prune old entries outside window
        self.rate_window[src_mac] = [
            t for t in self.rate_window[src_mac]
            if now - t <= FRAME_WINDOW_SEC
        ]

        # Check burst threshold
        rate = len(self.rate_window[src_mac]) / FRAME_WINDOW_SEC
        if rate >= DEAUTH_BURST_THRESH and src_mac not in self._alerted:
            self._alerted.add(src_mac)
            msg = (
                f"DEAUTH ATTACK from {src_mac} — "
                f"{rate:.0f} frames/sec (threshold {DEAUTH_BURST_THRESH}). "
                f"Your Wi-Fi connection is being disrupted intentionally. "
                f"Attacker may be setting up an evil twin."
            )
            self._alert(msg, "critical")
            self._print(f"\n  [!!!] {msg}")
            self._print(f"        Target: {dst_mac}")
            self._print(f"        Recommendation: Enable VPN or switch to mobile data.\n")

        elif self.verbose and len(self.events) % 5 == 0:
            self._print(f"  [i] {frame_type} frame: {src_mac} → {dst_mac}  "
                        f"(reason {reason_code})  rate={rate:.1f}/s")

    # ── Summary ───────────────────────────────────────────────────────────────

    def _analyse(self) -> dict:
        total_deauth   = sum(1 for e in self.events if e.frame_type == "deauth")
        total_disassoc = sum(1 for e in self.events if e.frame_type == "disassoc")
        attackers      = list(self._alerted)

        result = {
            "attack_detected":   len(attackers) > 0,
            "attacker_macs":     attackers,
            "total_deauth":      total_deauth,
            "total_disassoc":    total_disassoc,
            "total_frames":      len(self.events),
            "alerts":            self.alerts,
        }

        self._print(f"\n  Summary: {len(self.events)} management frames captured")
        self._print(f"           Deauth: {total_deauth}  |  "
                    f"Disassoc: {total_disassoc}  |  "
                    f"Attackers: {len(attackers)}")

        if not attackers:
            self._print("  [+] No deauth attack detected.")

        return result

    def _alert(self, msg, level="critical"):
        self.alerts.append({"level": level, "message": msg})

    def _print(self, msg):
        if self.verbose: print(msg)


if __name__ == "__main__":
    DeauthDetector(interface="wlan0mon").run()
