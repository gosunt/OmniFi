"""
OmniFi — Beacon Interval Anomaly Detector
==========================================
Legitimate APs send beacon frames every ~100ms (configurable but consistent).
Rogue APs created by tools like hostapd-wpe often use non-standard or
irregular intervals. This detector captures beacon frames using Scapy
in monitor mode and flags APs with statistically anomalous timing.

Requirements:
  - Monitor-mode capable Wi-Fi adapter
  - Scapy  (pip install scapy)
  - Root / sudo privileges
"""

import time
import statistics
from collections import defaultdict

try:
    from scapy.all import sniff, Dot11Beacon, Dot11
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Beacon interval thresholds
STANDARD_INTERVAL_MS   = 100     # most APs use 100ms
TOLERANCE_MS           = 30      # allow ±30ms variance
MIN_BEACONS_TO_JUDGE   = 10      # need at least 10 beacons before scoring
CAPTURE_SECONDS        = 20      # how long to sniff


class BeaconAnomalyDetector:
    def __init__(self, interface="wlan0mon", verbose=True):
        self.interface  = interface
        self.verbose    = verbose
        self.beacon_times: dict[str, list[float]] = defaultdict(list)
        self.results    = []
        self.alerts     = []

    def run(self) -> list:
        if not SCAPY_AVAILABLE:
            self._print("[!] Scapy not installed. Run: pip install scapy")
            return []

        self._print(f"\n[OmniFi] Beacon Anomaly Detector — sniffing {CAPTURE_SECONDS}s on {self.interface}...")
        self._print("  Requires monitor mode interface (e.g. airmon-ng start wlan0)\n")

        try:
            sniff(iface=self.interface,
                  prn=self._handle_packet,
                  timeout=CAPTURE_SECONDS,
                  store=False,
                  monitor=True)
        except Exception as e:
            self._print(f"  [!] Sniff error: {e}")
            self._print("      Ensure adapter is in monitor mode and run as root.")
            return []

        return self._analyse()

    def _handle_packet(self, pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr2
            if bssid:
                self.beacon_times[bssid].append(time.time())

    def _analyse(self) -> list:
        self._print("\n  Analysing beacon timing patterns...\n")
        results = []

        for bssid, times in self.beacon_times.items():
            if len(times) < MIN_BEACONS_TO_JUDGE:
                continue

            # Calculate inter-beacon intervals in milliseconds
            intervals_ms = [(times[i+1] - times[i]) * 1000
                            for i in range(len(times)-1)]

            mean_ms   = statistics.mean(intervals_ms)
            stdev_ms  = statistics.stdev(intervals_ms) if len(intervals_ms) > 1 else 0
            declared  = self._get_declared_interval(bssid)

            is_anomalous = False
            reason       = ""

            # Check 1: mean interval deviates from 100ms standard
            if abs(mean_ms - STANDARD_INTERVAL_MS) > TOLERANCE_MS:
                is_anomalous = True
                reason = (f"Mean beacon interval {mean_ms:.1f}ms deviates from "
                          f"standard {STANDARD_INTERVAL_MS}ms by "
                          f"{abs(mean_ms-STANDARD_INTERVAL_MS):.1f}ms.")

            # Check 2: high variance — irregular timing
            if stdev_ms > 25:
                is_anomalous = True
                reason += f" High timing variance (σ={stdev_ms:.1f}ms) — irregular beacon pattern."

            entry = {
                "bssid":          bssid,
                "beacon_count":   len(times),
                "mean_interval":  round(mean_ms, 2),
                "stdev_interval": round(stdev_ms, 2),
                "declared_interval": declared,
                "is_anomalous":   is_anomalous,
                "reason":         reason.strip(),
            }
            results.append(entry)

            if is_anomalous:
                self._alert(f"Beacon anomaly on {bssid}: {reason}", "high")
                self._print(f"  [!!] {bssid}  mean={mean_ms:.1f}ms  σ={stdev_ms:.1f}ms  ANOMALOUS")
            else:
                self._print(f"  [+]  {bssid}  mean={mean_ms:.1f}ms  σ={stdev_ms:.1f}ms  Normal")

        self.results = results
        return results

    def _get_declared_interval(self, bssid: str) -> int:
        """
        Declared beacon interval is in the beacon frame itself (field at offset 8, 2 bytes).
        We approximate here — full implementation would parse the raw frame bytes.
        """
        return STANDARD_INTERVAL_MS

    def _alert(self, msg, level="high"):
        self.alerts.append({"level": level, "message": msg})

    def _print(self, msg):
        if self.verbose: print(msg)


if __name__ == "__main__":
    BeaconAnomalyDetector(interface="wlan0mon").run()
