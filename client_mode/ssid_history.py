"""
OmniFi — SSID / BSSID History Tracker
========================================
Maintains a local SQLite database of every SSID + BSSID pair ever seen.
Detects evil twins that appear when the legitimate AP is out of range —
a scenario the live scan comparison cannot catch.

Logic:
  - First time an SSID is seen       → store BSSID as trusted baseline
  - Same SSID, same BSSID            → clean, update last_seen timestamp
  - Same SSID, NEW BSSID             → ALERT — possible evil twin
  - Same SSID, multiple BSSIDs known → normal (mesh / repeater) if previously approved
"""

import sqlite3
import datetime
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "db", "omnifi.db")


def _get_conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ssid_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ssid        TEXT NOT NULL,
            bssid       TEXT NOT NULL,
            first_seen  TEXT NOT NULL,
            last_seen   TEXT NOT NULL,
            trusted     INTEGER DEFAULT 1,
            UNIQUE(ssid, bssid)
        )
    """)
    conn.commit()
    return conn


class SSIDBSSIDTracker:
    def __init__(self, verbose=True):
        self.verbose = verbose
        self.conn    = _get_conn()
        self.alerts  = []

    def check_network(self, ssid: str, bssid: str) -> dict:
        """
        Check a single SSID/BSSID pair against history.
        Returns dict with is_new, is_suspicious, message.
        """
        bssid = bssid.upper().strip()
        now   = datetime.datetime.now().isoformat()
        cur   = self.conn.cursor()

        # Get all known BSSIDs for this SSID
        cur.execute("SELECT bssid, trusted FROM ssid_history WHERE ssid=?", (ssid,))
        known = {row[0].upper(): row[1] for row in cur.fetchall()}

        result = {"ssid": ssid, "bssid": bssid, "is_new": False,
                  "is_suspicious": False, "message": ""}

        if not known:
            # First time seeing this SSID — store as trusted baseline
            cur.execute("""
                INSERT OR IGNORE INTO ssid_history (ssid, bssid, first_seen, last_seen, trusted)
                VALUES (?,?,?,?,1)
            """, (ssid, bssid, now, now))
            self.conn.commit()
            result["is_new"] = True
            result["message"] = f"New network '{ssid}' recorded with BSSID {bssid}."
            self._print(f"  [i] New network stored: {ssid} ({bssid})")

        elif bssid in known:
            # Known BSSID — update last_seen
            cur.execute("UPDATE ssid_history SET last_seen=? WHERE ssid=? AND bssid=?",
                        (now, ssid, bssid))
            self.conn.commit()
            result["message"] = f"Known network '{ssid}' — BSSID verified."
            self._print(f"  [+] Known network verified: {ssid} ({bssid})")

        else:
            # New BSSID for a known SSID — suspicious
            result["is_suspicious"] = True
            trusted_bssids = [b for b, t in known.items() if t]
            result["message"] = (
                f"ALERT: '{ssid}' seen with new BSSID {bssid}. "
                f"Known trusted BSSID(s): {', '.join(trusted_bssids)}. "
                f"Possible evil twin — even if it is the only AP visible."
            )
            self._print(f"  [!!!] New BSSID for known SSID: {ssid}")
            self._print(f"        New:     {bssid}")
            self._print(f"        Trusted: {', '.join(trusted_bssids)}")
            self.alerts.append({"level": "critical", "message": result["message"]})

            # Store as untrusted for record
            cur.execute("""
                INSERT OR IGNORE INTO ssid_history (ssid, bssid, first_seen, last_seen, trusted)
                VALUES (?,?,?,?,0)
            """, (ssid, bssid, now, now))
            self.conn.commit()

        return result

    def check_all(self, networks: list) -> list:
        """Check a list of dicts with 'ssid' and 'bssid' keys."""
        results = []
        for net in networks:
            if net.get("ssid") and net.get("bssid"):
                results.append(self.check_network(net["ssid"], net["bssid"]))
        return results

    def approve_bssid(self, ssid: str, bssid: str):
        """Mark a BSSID as trusted (admin approves a new AP / mesh node)."""
        self.conn.execute(
            "UPDATE ssid_history SET trusted=1 WHERE ssid=? AND bssid=?",
            (ssid, bssid.upper())
        )
        self.conn.commit()
        self._print(f"  [+] BSSID {bssid} for '{ssid}' marked as trusted.")

    def get_history(self) -> list:
        cur = self.conn.cursor()
        cur.execute("SELECT ssid, bssid, first_seen, last_seen, trusted FROM ssid_history ORDER BY last_seen DESC")
        return [{"ssid":r[0],"bssid":r[1],"first_seen":r[2],"last_seen":r[3],"trusted":bool(r[4])} for r in cur.fetchall()]

    def _print(self, msg):
        if self.verbose: print(msg)


if __name__ == "__main__":
    tracker = SSIDBSSIDTracker()
    # Demo
    tracker.check_network("HomeNetwork_5G", "AA:BB:CC:DD:EE:01")
    tracker.check_network("HomeNetwork_5G", "AA:BB:CC:DD:EE:01")   # same — clean
    tracker.check_network("HomeNetwork_5G", "FF:EE:DD:CC:BB:99")   # new BSSID — alert
