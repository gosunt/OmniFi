"""
OmniFi — SSID / BSSID History Tracker
========================================
Maintains a persistent SQLite history of every SSID + BSSID pair ever
seen. Detects evil twins even when the legitimate AP is out of range —
if a known SSID appears with a BSSID never previously recorded, OmniFi
raises an alert immediately.

DB schema:
  ssid_history(ssid, bssid, first_seen, last_seen, times_seen, trusted)
"""

import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "../db/bssid_history.db")


class BSSIDHistoryTracker:
    def __init__(self, verbose=True):
        self.verbose = verbose
        self.alerts  = []
        self._init_db()

    def _init_db(self):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ssid_history (
                ssid       TEXT NOT NULL,
                bssid      TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen  TEXT NOT NULL,
                times_seen INTEGER DEFAULT 1,
                trusted    INTEGER DEFAULT 0,
                PRIMARY KEY (ssid, bssid)
            )
        """)
        conn.commit()
        conn.close()

    def check_and_update(self, ssid: str, bssid: str) -> dict:
        """
        Check if this SSID+BSSID pair is known.
        Returns a result dict with new/known/suspicious status.
        """
        if not ssid or ssid == "(hidden)":
            return {"status":"skipped","ssid":ssid,"bssid":bssid}

        now  = datetime.now().isoformat()
        conn = sqlite3.connect(DB_PATH)

        # Get all known BSSIDs for this SSID
        known = conn.execute(
            "SELECT bssid, trusted, times_seen FROM ssid_history WHERE ssid=?",
            (ssid,)
        ).fetchall()

        known_bssids   = {row[0] for row in known}
        trusted_bssids = {row[0] for row in known if row[1]==1}

        result = {"ssid":ssid,"bssid":bssid,"status":"","alerts":[]}

        if not known_bssids:
            # First time seeing this SSID — record it
            conn.execute("""
                INSERT INTO ssid_history(ssid,bssid,first_seen,last_seen,times_seen,trusted)
                VALUES(?,?,?,?,1,0)
            """, (ssid, bssid, now, now))
            result["status"] = "new_ssid"
            self._print(f"  [+] New SSID recorded: '{ssid}' ({bssid})")

        elif bssid in known_bssids:
            # Known SSID + BSSID — update last_seen
            conn.execute("""
                UPDATE ssid_history SET last_seen=?, times_seen=times_seen+1
                WHERE ssid=? AND bssid=?
            """, (now, ssid, bssid))
            result["status"] = "known"
            self._print(f"  [+] Known network: '{ssid}' ({bssid})")

        else:
            # Known SSID but NEW BSSID — suspicious
            conn.execute("""
                INSERT INTO ssid_history(ssid,bssid,first_seen,last_seen,times_seen,trusted)
                VALUES(?,?,?,?,1,0)
            """, (ssid, bssid, now, now))
            msg = (f"SSID '{ssid}' seen with NEW BSSID {bssid}. "
                   f"Previously known BSSIDs: {', '.join(known_bssids)}. "
                   f"Possible evil twin attack.")
            result["status"]  = "suspicious"
            result["known_bssids"] = list(known_bssids)
            result["alerts"].append({"level":"critical","message":msg})
            self._alert(msg, "critical")

        conn.commit()
        conn.close()
        return result


    def check_current_network(self) -> dict:
        """
        Check the currently connected SSID+BSSID against history.
        Returns {evil_twin: bool, message: str, ssid: str, bssid: str}.
        """
        import subprocess, platform, re as _re
        ssid = ""; bssid = ""
        try:
            if platform.system() == "Windows":
                o = subprocess.check_output(
                    ["netsh","wlan","show","interfaces"],
                    text=True, encoding="utf-8", errors="ignore",
                    stderr=subprocess.DEVNULL)
                sm = _re.search(r"^\s*SSID\s+:\s(.+)$", o, _re.MULTILINE)
                bm = _re.search(r"BSSID\s+:\s*([\w:]+)", o)
                ssid  = sm.group(1).strip() if sm else ""
                bssid = bm.group(1).strip().upper() if bm else ""
            else:
                for cmd in [
                    ["iwgetid","-r"],
                    ["nmcli","-t","-f","active,ssid","dev","wifi"],
                ]:
                    try:
                        o = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
                        if cmd[0] == "iwgetid":
                            ssid = o.strip()
                        else:
                            for line in o.splitlines():
                                if line.startswith("yes:"):
                                    ssid = line.split(":",1)[1].strip()
                        break
                    except Exception:
                        pass
                try:
                    o2 = subprocess.check_output(
                        ["iwconfig"], text=True, stderr=subprocess.DEVNULL)
                    bm = _re.search(r"Access Point:\s*([\w:]+)", o2)
                    bssid = bm.group(1).upper() if bm else ""
                except Exception:
                    pass
        except Exception as e:
            return {"evil_twin": False, "message": f"Could not read network info: {e}",
                    "ssid": "", "bssid": ""}

        if not ssid or not bssid:
            return {"evil_twin": False, "message": "Not connected to any network",
                    "ssid": ssid, "bssid": bssid}

        result = self.check_and_update(ssid, bssid)
        evil   = result.get("status") == "suspicious"
        return {
            "evil_twin": evil,
            "message":   result["alerts"][0]["message"] if result.get("alerts") else
                         f"Network '{ssid}' ({bssid}) — {'NEW BSSID suspicious' if evil else 'OK'}",
            "ssid":  ssid,
            "bssid": bssid,
        }

    def mark_trusted(self, ssid: str, bssid: str):
        conn = sqlite3.connect(DB_PATH)
        conn.execute("UPDATE ssid_history SET trusted=1 WHERE ssid=? AND bssid=?",
                     (ssid, bssid))
        conn.commit()
        conn.close()
        self._print(f"  [+] Marked as trusted: '{ssid}' ({bssid})")

    def get_history(self, ssid: str = None) -> list:
        conn = sqlite3.connect(DB_PATH)
        if ssid:
            rows = conn.execute(
                "SELECT * FROM ssid_history WHERE ssid=? ORDER BY last_seen DESC",
                (ssid,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM ssid_history ORDER BY last_seen DESC"
            ).fetchall()
        conn.close()
        return rows

    def clear_history(self):
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DELETE FROM ssid_history")
        conn.commit()
        conn.close()
        self._print("  [*] BSSID history cleared.")

    def _alert(self, msg, level="medium"):
        self.alerts.append({"level":level,"message":msg})
        icon = {"critical":"[!!!]","high":"[!!]","medium":"[!]","low":"[i]"}.get(level,"[i]")
        self._print(f"  {icon} {msg}")

    def _print(self, msg):
        if self.verbose: print(msg)


if __name__ == "__main__":
    t = BSSIDHistoryTracker()
    # Simulate seeing a known network then a twin
    t.check_and_update("HomeNetwork", "AA:BB:CC:DD:EE:01")
    t.check_and_update("HomeNetwork", "AA:BB:CC:DD:EE:01")  # same — ok
    t.check_and_update("HomeNetwork", "FF:EE:DD:CC:BB:99")  # different — alert!
    print("\nHistory:")
    for row in t.get_history("HomeNetwork"):
        print(" ", row)
