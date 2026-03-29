"""
OmniFi — Rogue Access Point Detector
======================================
Cross-references every scanned SSID/BSSID pair against:
  1. The local trusted-BSSID SQLite history (bssid_history.py table)
  2. OUI vendor lookup — flags APs whose vendor ≠ the expected vendor for
     that SSID (e.g. a "JioFiber" SSID served by a TP-Link OUI when every
     prior record shows Jio OUIs).
  3. Duplicate SSID with different BSSID appearing simultaneously — classic
     rogue / evil-twin scenario.
  4. Signal anomaly — legitimate APs on the same SSID cluster near the same
     RSSI; a sudden new AP that is much stronger is suspicious.

All alerts are emitted via the shared AlertBridge so the UI picks them up.
"""
from __future__ import annotations

import logging
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

log = logging.getLogger("OmniFi.RogueAP")

# ── OUI prefix → vendor shortname (top Indian ISP AP vendors) ─────────────────
_OUI_VENDOR_MAP: Dict[str, str] = {
    # Jio (Sagemcom / Sercomm / Kaon)
    "00:25:9c": "jio", "e4:8d:8c": "jio", "b0:72:bf": "jio",
    "00:1a:2b": "jio", "f0:b4:29": "jio", "c8:d7:19": "jio",
    # Airtel (Huawei / ZTE / Nokia)
    "00:18:82": "airtel", "00:1e:10": "airtel", "88:e3:ab": "airtel",
    "f4:9f:f3": "airtel", "5c:e5:0c": "airtel", "00:9a:cd": "airtel",
    # BSNL (ZTE / Beetel / Huawei)
    "00:1a:64": "bsnl", "00:25:68": "bsnl", "b4:b5:2f": "bsnl",
    "d4:6a:6a": "bsnl", "c8:d7:19": "bsnl",
    # TP-Link
    "50:c7:bf": "tplink", "a0:f3:c1": "tplink", "ec:08:6b": "tplink",
    "30:de:4b": "tplink", "18:d6:c7": "tplink", "f4:ec:38": "tplink",
    # Netgear
    "20:4e:7f": "netgear", "a0:21:b7": "netgear", "c0:ff:d4": "netgear",
    # D-Link
    "b0:c5:54": "dlink", "1c:7e:e5": "dlink", "84:c9:b2": "dlink",
    # Asus
    "04:d9:f5": "asus", "2c:4d:54": "asus", "10:c3:7b": "asus",
    # Oppo / realme / Xiaomi (mobile hotspots)
    "ac:2b:6e": "xiaomi", "fc:64:ba": "xiaomi", "28:6c:07": "xiaomi",
}


def _oui(mac: str) -> str:
    """Return lower-case 8-char OUI prefix from a MAC address."""
    return mac.lower().replace("-", ":")[: 8]


def _oui_vendor(mac: str) -> str:
    return _OUI_VENDOR_MAP.get(_oui(mac), "unknown")


# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class APRecord:
    ssid: str
    bssid: str
    signal_dbm: int = -80
    channel: int = 0
    auth_protocol: str = "unknown"
    vendor: str = field(init=False)

    def __post_init__(self):
        self.vendor = _oui_vendor(self.bssid)


@dataclass
class RogueAPAlert:
    ssid: str
    bssid: str
    reason: str
    severity: str = "high"          # low / medium / high / critical
    detail: str = ""

    def summary(self) -> str:
        return f"[RogueAP] {self.ssid} ({self.bssid}) — {self.reason}"


# ─────────────────────────────────────────────────────────────────────────────
# Rogue AP Detector
# ─────────────────────────────────────────────────────────────────────────────
class RogueAPDetector:
    """
    Pass a list of APRecord objects (from a fresh Wi-Fi scan) and optionally
    a trusted-BSSID SQLite db path.  Call  run()  to get a list of alerts.
    """

    _DB_NAME = "bssid_history.db"

    def __init__(self,
                 db_path: Optional[str] = None,
                 rssi_spike_threshold: int = 15,
                 verbose: bool = True):
        self._db_path = db_path or str(
            Path(__file__).parent.parent / "db" / self._DB_NAME)
        self._rssi_spike = rssi_spike_threshold
        self._verbose = verbose
        self._alerts: List[RogueAPAlert] = []

    # ── Public ───────────────────────────────────────────────────────────────
    def run(self, aps: List[APRecord]) -> List[RogueAPAlert]:
        self._alerts = []
        if not aps:
            return []

        # Group by SSID
        by_ssid: Dict[str, List[APRecord]] = {}
        for ap in aps:
            by_ssid.setdefault(ap.ssid, []).append(ap)

        for ssid, group in by_ssid.items():
            self._check_duplicate_ssid(ssid, group)
            self._check_vendor_mismatch(ssid, group)
            self._check_history_mismatch(ssid, group)
            self._check_signal_spike(ssid, group)

        for a in self._alerts:
            self._alert(a.summary(), a.severity, a.detail)

        return self._alerts

    # ── Checks ────────────────────────────────────────────────────────────────
    def _check_duplicate_ssid(self, ssid: str, group: List[APRecord]):
        """Multiple APs with identical SSID but different BSSIDs seen simultaneously."""
        if len(group) < 2:
            return
        bssids = [ap.bssid for ap in group]
        self._alerts.append(RogueAPAlert(
            ssid=ssid,
            bssid=", ".join(bssids),
            reason="Multiple BSSIDs for same SSID visible simultaneously — possible evil-twin",
            severity="high",
            detail=(f"{len(group)} APs advertising '{ssid}': "
                    + " | ".join(f"{ap.bssid}({ap.signal_dbm}dBm)" for ap in group)),
        ))

    def _check_vendor_mismatch(self, ssid: str, group: List[APRecord]):
        """AP OUI vendor doesn't match expected vendor for this SSID."""
        expected = self._expected_vendor_for_ssid(ssid)
        if expected == "unknown":
            return
        for ap in group:
            if ap.vendor not in ("unknown", expected):
                self._alerts.append(RogueAPAlert(
                    ssid=ssid,
                    bssid=ap.bssid,
                    reason=(f"OUI vendor mismatch: SSID suggests '{expected}' "
                            f"but hardware OUI is '{ap.vendor}'"),
                    severity="high",
                    detail=(f"BSSID {ap.bssid} → OUI vendor={ap.vendor}, "
                            f"expected={expected} for SSID '{ssid}'"),
                ))

    def _check_history_mismatch(self, ssid: str, group: List[APRecord]):
        """SSID seen before with different BSSID(s) — unknown AP appeared."""
        known = self._get_known_bssids(ssid)
        if not known:
            return           # never seen before; can't compare
        for ap in group:
            if ap.bssid not in known:
                self._alerts.append(RogueAPAlert(
                    ssid=ssid,
                    bssid=ap.bssid,
                    reason="New unknown BSSID for a previously-seen SSID — possible rogue AP",
                    severity="critical",
                    detail=(f"SSID '{ssid}' was previously always seen with BSSIDs "
                            f"{known}. New BSSID {ap.bssid} has never been recorded."),
                ))

    def _check_signal_spike(self, ssid: str, group: List[APRecord]):
        """An AP with the same SSID is significantly stronger than all others."""
        if len(group) < 2:
            return
        signals = [ap.signal_dbm for ap in group]
        max_s = max(signals)
        others = [s for s in signals if s != max_s]
        avg_others = sum(others) / len(others) if others else max_s
        if max_s - avg_others > self._rssi_spike:
            suspect = next(ap for ap in group if ap.signal_dbm == max_s)
            self._alerts.append(RogueAPAlert(
                ssid=ssid,
                bssid=suspect.bssid,
                reason=(f"Signal spike: {suspect.bssid} is {max_s - int(avg_others)} dBm "
                        f"stronger than other APs with same SSID — possible evil twin nearby"),
                severity="medium",
                detail=(f"Strongest: {max_s} dBm, others avg: {avg_others:.1f} dBm"),
            ))

    # ── Helpers ───────────────────────────────────────────────────────────────
    @staticmethod
    def _expected_vendor_for_ssid(ssid: str) -> str:
        s = ssid.lower()
        if any(k in s for k in ("jio", "jiowifi", "jiofiber")):
            return "jio"
        if any(k in s for k in ("airtel", "xstream")):
            return "airtel"
        if any(k in s for k in ("bsnl", "bharat")):
            return "bsnl"
        if "tplink" in s or "tp-link" in s:
            return "tplink"
        if "netgear" in s:
            return "netgear"
        if "dlink" in s or "d-link" in s:
            return "dlink"
        if "asus" in s:
            return "asus"
        return "unknown"

    def _get_known_bssids(self, ssid: str) -> set:
        try:
            con = sqlite3.connect(self._db_path, timeout=3)
            cur = con.execute(
                "SELECT bssid FROM bssid_history WHERE ssid=?", (ssid,))
            rows = {r[0] for r in cur.fetchall()}
            con.close()
            return rows
        except Exception as e:
            log.debug(f"[RogueAP] DB read error: {e}")
            return set()

    def _alert(self, msg: str, level: str = "high", detail: str = ""):
        self._print(f"  [!] {msg}")
        try:
            from core.monitor_utils import ALERTS
            ALERTS.emit_alert(level, "rogue_ap", msg, detail,
                              signals=["rogue_ap"])
        except Exception:
            pass

    def _print(self, msg: str):
        if self._verbose:
            log.info(msg)


# ─────────────────────────────────────────────────────────────────────────────
# Convenience: build APRecord list from scan_wifi() output
# ─────────────────────────────────────────────────────────────────────────────
def ap_records_from_scan(scan_results: list) -> List[APRecord]:
    """
    Convert raw scan_wifi() dicts to APRecord objects.
    scan_results is the list returned by core.backend.scan_wifi().
    """
    records = []
    for net in scan_results:
        bssid = net.get("bssid") or net.get("mac") or ""
        if not bssid:
            continue
        records.append(APRecord(
            ssid=net.get("ssid", ""),
            bssid=bssid,
            signal_dbm=net.get("signal_dbm", -80),
            channel=net.get("channel", 0),
            auth_protocol=net.get("auth_protocol", "unknown"),
        ))
    return records
