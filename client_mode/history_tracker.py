"""
OmniFi — SSID/BSSID History Tracker
======================================
Maintains a persistent SQLite history of every SSID+BSSID pair ever seen.
If a known SSID appears with a new BSSID never recorded before — even when
only one AP is visible — OmniFi raises an alert immediately.

This catches evil twins that appear when the legitimate AP is offline or
out of range, which beacon-only comparison cannot detect.

DB schema:
  networks(ssid, bssid, first_seen, last_seen, times_seen, trusted, flagged)
  alerts(id, ssid, bssid, alert_type, detail, timestamp)
"""

import sqlite3
import time
import os
import re
import subprocess
import platform
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


DB_PATH = os.path.join(os.path.dirname(__file__), "..", "db", "network_history.db")


@dataclass
class HistoryAlert:
    ssid:       str
    bssid:      str
    alert_type: str   # new_bssid / bssid_change / flagged_return
    detail:     str
    severity:   str   # low / medium / high / critical


class NetworkHistoryTracker:
    """
    Persistent tracker for SSID+BSSID pairs.
    Detects new or changed BSSIDs for known SSIDs — primary evil twin signal.
    """

    def __init__(self, db_path: str = DB_PATH, verbose: bool = True):
        self.verbose  = verbose
        self.db_path  = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    # ── DB setup ──────────────────────────────────────────────────────────────

    def _init_db(self):
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS networks (
                    ssid        TEXT NOT NULL,
                    bssid       TEXT NOT NULL,
                    first_seen  TEXT NOT NULL,
                    last_seen   TEXT NOT NULL,
                    times_seen  INTEGER DEFAULT 1,
                    trusted     INTEGER DEFAULT 0,
                    flagged     INTEGER DEFAULT 0,
                    PRIMARY KEY (ssid, bssid)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS history_alerts (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    ssid        TEXT,
                    bssid       TEXT,
                    alert_type  TEXT,
                    detail      TEXT,
                    timestamp   TEXT
                )
            """)

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    # ── Public API ────────────────────────────────────────────────────────────

    def record_scan(self, scan_results: list[dict]) -> list[HistoryAlert]:
        """
        Record a list of {ssid, bssid} dicts from a scan.
        Returns list of alerts for any suspicious changes.
        """
        alerts = []
        now    = datetime.now().isoformat()

        with self._conn() as conn:
            for net in scan_results:
                ssid  = net.get("ssid", "").strip()
                bssid = net.get("bssid", "").upper().strip()
                if not ssid or not bssid or ssid == "(hidden)":
                    continue

                existing_bssids = self._get_bssids_for_ssid(conn, ssid)

                if not existing_bssids:
                    # First time seeing this SSID — record as new, no alert
                    self._insert_network(conn, ssid, bssid, now)
                    self._print(f"  [+] New network recorded: '{ssid}' ({bssid})")

                elif bssid in existing_bssids:
                    # Known SSID + known BSSID — update last_seen
                    conn.execute("""
                        UPDATE networks
                        SET last_seen=?, times_seen=times_seen+1
                        WHERE ssid=? AND bssid=?
                    """, (now, ssid, bssid))

                    # Was this BSSID previously flagged?
                    row = conn.execute("""
                        SELECT flagged FROM networks WHERE ssid=? AND bssid=?
                    """, (ssid, bssid)).fetchone()
                    if row and row[0]:
                        alert = HistoryAlert(
                            ssid=ssid, bssid=bssid,
                            alert_type="flagged_return",
                            detail=f"Previously flagged BSSID for '{ssid}' has reappeared.",
                            severity="high"
                        )
                        alerts.append(alert)
                        self._save_alert(conn, alert, now)

                else:
                    # Known SSID — NEW BSSID never seen before
                    known_str = ", ".join(existing_bssids)
                    detail = (
                        f"SSID '{ssid}' seen with new BSSID {bssid}. "
                        f"Previously known BSSID(s): {known_str}. "
                        f"Possible evil twin or legitimate AP change."
                    )
                    alert = HistoryAlert(
                        ssid=ssid, bssid=bssid,
                        alert_type="new_bssid",
                        detail=detail,
                        severity="high"
                    )
                    alerts.append(alert)
                    self._save_alert(conn, alert, now)
                    self._insert_network(conn, ssid, bssid, now)
                    self._print(f"  [!!!] New BSSID for known SSID '{ssid}': {bssid}")
                    self._print(f"        Known: {known_str}")

        return alerts

    def trust_network(self, ssid: str, bssid: str):
        """Mark a specific SSID+BSSID as permanently trusted."""
        with self._conn() as conn:
            conn.execute("""
                UPDATE networks SET trusted=1 WHERE ssid=? AND bssid=?
            """, (ssid, bssid))
        self._print(f"  [+] Trusted: '{ssid}' ({bssid})")

    def flag_network(self, ssid: str, bssid: str):
        """Flag a BSSID as malicious — alert if it reappears."""
        with self._conn() as conn:
            conn.execute("""
                UPDATE networks SET flagged=1 WHERE ssid=? AND bssid=?
            """, (ssid, bssid))
        self._print(f"  [!] Flagged as malicious: '{ssid}' ({bssid})")

    def is_trusted(self, ssid: str, bssid: str) -> bool:
        with self._conn() as conn:
            row = conn.execute("""
                SELECT trusted FROM networks WHERE ssid=? AND bssid=?
            """, (ssid, bssid)).fetchone()
            return bool(row and row[0])

    def get_all_networks(self) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT ssid, bssid, first_seen, last_seen,
                       times_seen, trusted, flagged
                FROM networks ORDER BY last_seen DESC
            """).fetchall()
            return [
                {
                    "ssid": r[0], "bssid": r[1],
                    "first_seen": r[2], "last_seen": r[3],
                    "times_seen": r[4], "trusted": bool(r[5]),
                    "flagged": bool(r[6])
                }
                for r in rows
            ]

    def get_history_alerts(self, limit: int = 50) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT ssid, bssid, alert_type, detail, timestamp
                FROM history_alerts ORDER BY timestamp DESC LIMIT ?
            """, (limit,)).fetchall()
            return [
                {"ssid": r[0], "bssid": r[1], "alert_type": r[2],
                 "detail": r[3], "timestamp": r[4]}
                for r in rows
            ]

    def print_history(self):
        networks = self.get_all_networks()
        if not networks:
            print("  No network history yet.")
            return
        print(f"\n  {'SSID':<30} {'BSSID':<20} {'Seen':<5} {'Status'}")
        print("  " + "─" * 70)
        for n in networks:
            status = "TRUSTED" if n["trusted"] else ("FLAGGED" if n["flagged"] else "")
            print(f"  {n['ssid'][:28]:<30} {n['bssid']:<20} "
                  f"{n['times_seen']:<5} {status}")

    # ── Private helpers ───────────────────────────────────────────────────────

    def _get_bssids_for_ssid(self, conn, ssid: str) -> list[str]:
        rows = conn.execute(
            "SELECT bssid FROM networks WHERE ssid=?", (ssid,)
        ).fetchall()
        return [r[0] for r in rows]

    def _insert_network(self, conn, ssid: str, bssid: str, now: str):
        conn.execute("""
            INSERT OR IGNORE INTO networks
            (ssid, bssid, first_seen, last_seen, times_seen, trusted, flagged)
            VALUES (?, ?, ?, ?, 1, 0, 0)
        """, (ssid, bssid, now, now))

    def _save_alert(self, conn, alert: HistoryAlert, now: str):
        conn.execute("""
            INSERT INTO history_alerts (ssid, bssid, alert_type, detail, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """, (alert.ssid, alert.bssid, alert.alert_type, alert.detail, now))

    def _print(self, msg: str):
        if self.verbose:
            print(msg)


if __name__ == "__main__":
    tracker = NetworkHistoryTracker(verbose=True)

    # Demo: simulate two scans
    print("\n--- First scan ---")
    alerts = tracker.record_scan([
        {"ssid": "HomeNetwork_5G",     "bssid": "AA:BB:CC:DD:EE:01"},
        {"ssid": "JioFiber_7A2B",      "bssid": "AA:BB:CC:DD:EE:02"},
        {"ssid": "Airtel_Xstream_4563","bssid": "AA:BB:CC:DD:EE:03"},
    ])

    print("\n--- Second scan (evil twin appears) ---")
    alerts = tracker.record_scan([
        {"ssid": "HomeNetwork_5G",     "bssid": "FF:EE:DD:CC:BB:99"},  # NEW BSSID!
        {"ssid": "JioFiber_7A2B",      "bssid": "AA:BB:CC:DD:EE:02"},
    ])
    for a in alerts:
        print(f"\n  ALERT [{a.severity.upper()}]: {a.detail}")

    print("\n--- Network history ---")
    tracker.print_history()
