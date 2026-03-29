"""
OmniFi — Trusted Network Whitelist + MAC Randomisation Checker
================================================================
Two focused client-mode security features:

1. TrustedNetworkManager
   Lets users mark SSID+BSSID pairs as permanently trusted (home, office).
   On trusted networks, OmniFi runs a lightweight integrity check instead
   of a full scan — verifying BSSID + DNS only.

2. MACRandomisationChecker
   Checks whether the client's own Wi-Fi adapter is using a randomised
   (locally administered) MAC before connecting. If not, alerts the user
   that their real hardware MAC is being broadcast — enabling cross-network
   physical tracking. On Linux, can trigger macchanger automatically.
"""

import os
import sqlite3
import subprocess
import platform
import re
import socket

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "db", "omnifi.db")


def _get_conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS trusted_networks (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ssid       TEXT NOT NULL,
            bssid      TEXT NOT NULL,
            label      TEXT DEFAULT '',
            added_at   TEXT NOT NULL,
            UNIQUE(ssid, bssid)
        )
    """)
    conn.commit()
    return conn


# ─────────────────────────────────────────────────────────────────────────────
# Trusted network manager
# ─────────────────────────────────────────────────────────────────────────────

class TrustedNetworkManager:

    def __init__(self, verbose=True):
        self.verbose = verbose
        self.conn    = _get_conn()

    def is_trusted(self, ssid: str, bssid: str) -> bool:
        cur = self.conn.cursor()
        cur.execute("SELECT 1 FROM trusted_networks WHERE ssid=? AND bssid=?",
                    (ssid, bssid.upper()))
        return cur.fetchone() is not None

    def add(self, ssid: str, bssid: str, label: str = "") -> bool:
        import datetime
        try:
            self.conn.execute("""
                INSERT OR IGNORE INTO trusted_networks (ssid, bssid, label, added_at)
                VALUES (?,?,?,?)
            """, (ssid, bssid.upper(), label, datetime.datetime.now().isoformat()))
            self.conn.commit()
            self._print(f"  [+] '{ssid}' ({bssid}) added to trusted networks.")
            return True
        except Exception as e:
            self._print(f"  [!] Could not add trusted network: {e}")
            return False

    def remove(self, ssid: str, bssid: str) -> bool:
        self.conn.execute("DELETE FROM trusted_networks WHERE ssid=? AND bssid=?",
                          (ssid, bssid.upper()))
        self.conn.commit()
        self._print(f"  [*] '{ssid}' ({bssid}) removed from trusted networks.")
        return True

    def list_all(self) -> list:
        cur = self.conn.cursor()
        cur.execute("SELECT ssid, bssid, label, added_at FROM trusted_networks")
        return [{"ssid":r[0],"bssid":r[1],"label":r[2],"added_at":r[3]}
                for r in cur.fetchall()]

    def quick_integrity_check(self, ssid: str, bssid: str) -> dict:
        """
        Lightweight check for trusted networks — skips full scan.
        Just verifies BSSID match and runs a single DNS probe.
        """
        result = {"trusted": False, "bssid_ok": False, "dns_ok": False,
                  "alerts": []}

        if not self.is_trusted(ssid, bssid):
            result["alerts"].append({"level":"medium",
                "message": f"'{ssid}' not in trusted list — running full scan."})
            return result

        result["trusted"]  = True
        result["bssid_ok"] = True
        self._print(f"  [+] '{ssid}' is trusted — running lightweight integrity check.")

        # Quick DNS check
        try:
            ip = socket.gethostbyname("google.com")
            result["dns_ok"] = bool(ip)
            self._print(f"  [+] DNS resolves correctly ({ip}).")
        except Exception:
            result["dns_ok"] = False
            result["alerts"].append({"level":"high",
                "message": "DNS resolution failed on trusted network — possible spoofing."})

        return result

    def _print(self, msg):
        if self.verbose: print(msg)


# ─────────────────────────────────────────────────────────────────────────────
# MAC randomisation checker
# ─────────────────────────────────────────────────────────────────────────────

class MACRandomisationChecker:

    def __init__(self, verbose=True):
        self.verbose   = verbose
        self.alerts    = []

    def check(self, interface: str = None) -> dict:
        """
        Check if the Wi-Fi adapter is using a randomised (locally administered) MAC.
        The locally administered bit is bit 1 of the first octet.
        e.g. MAC starting with 02, 06, 0A, 0E, 12... = randomised.
        """
        self._print("\n[OmniFi] MAC Randomisation Check...")

        iface = interface or self._detect_wifi_interface()
        mac   = self._get_mac(iface)

        if not mac:
            self._print(f"  [!] Could not read MAC for interface {iface}.")
            return {"interface": iface, "mac": None, "randomised": False,
                    "alerts": self.alerts}

        is_randomised = self._is_locally_administered(mac)
        result = {
            "interface":   iface,
            "mac":         mac,
            "randomised":  is_randomised,
            "alerts":      self.alerts,
        }

        if is_randomised:
            self._print(f"  [+] {iface} MAC {mac} is randomised (locally administered bit set).")
            self._print("      Your real hardware MAC is NOT being broadcast. Good.")
        else:
            self._print(f"  [!] {iface} MAC {mac} is your REAL hardware MAC.")
            self._print("      You can be tracked across networks by this identifier.")
            self._alert(
                f"Real hardware MAC {mac} exposed on {iface}. "
                "Enable MAC randomisation in OS settings or use macchanger.",
                "medium"
            )
            # Offer to randomise on Linux
            if platform.system() == "Linux":
                self._offer_randomise(iface)

        return result

    def randomise(self, interface: str) -> bool:
        """Attempt to randomise MAC using macchanger (Linux)."""
        if platform.system() != "Linux":
            self._print("  [i] Automatic MAC randomisation only supported on Linux.")
            return False
        try:
            subprocess.run(["ip","link","set",interface,"down"], check=True,
                           capture_output=True)
            result = subprocess.run(["macchanger","-r",interface],
                                    capture_output=True, text=True)
            subprocess.run(["ip","link","set",interface,"up"], check=True,
                           capture_output=True)
            if result.returncode == 0:
                m = re.search(r"New MAC:\s+([\w:]+)", result.stdout)
                new_mac = m.group(1) if m else "unknown"
                self._print(f"  [+] MAC randomised to {new_mac}.")
                return True
            else:
                self._print(f"  [!] macchanger failed: {result.stderr.strip()}")
                self._print("      Install with: sudo apt install macchanger")
                return False
        except FileNotFoundError:
            self._print("  [!] macchanger not found. Install: sudo apt install macchanger")
            return False
        except Exception as e:
            self._print(f"  [!] Randomisation error: {e}")
            return False

    def _offer_randomise(self, interface: str):
        try:
            ans = input(clr_yellow("  Randomise MAC now? [y/N]: ")).strip().lower()
            if ans == "y":
                self.randomise(interface)
        except (EOFError, KeyboardInterrupt):
            pass

    def _is_locally_administered(self, mac: str) -> bool:
        first_octet = int(mac.split(":")[0].replace("-",""), 16)
        return bool(first_octet & 0x02)   # bit 1 set = locally administered

    def _get_mac(self, interface: str) -> str:
        try:
            if platform.system() == "Windows":
                out = subprocess.check_output(
                    ["getmac","/FO","CSV","/NH"], text=True, stderr=subprocess.DEVNULL)
                m = re.search(r"([\w-]{17})", out)
                return m.group(1).replace("-",":").upper() if m else ""
            else:
                path = f"/sys/class/net/{interface}/address"
                if os.path.exists(path):
                    with open(path) as f:
                        return f.read().strip().upper()
                out = subprocess.check_output(
                    ["ip","link","show",interface], text=True, stderr=subprocess.DEVNULL)
                m = re.search(r"link/ether\s+([\w:]+)", out)
                return m.group(1).upper() if m else ""
        except Exception:
            return ""

    def _detect_wifi_interface(self) -> str:
        try:
            if platform.system() == "Linux":
                out = subprocess.check_output(["iw","dev"], text=True,
                                              stderr=subprocess.DEVNULL)
                m = re.search(r"Interface\s+(\w+)", out)
                return m.group(1) if m else "wlan0"
            elif platform.system() == "Windows":
                return "Wi-Fi"
            else:
                return "en0"
        except Exception:
            return "wlan0"

    def _alert(self, msg, level="medium"):
        self.alerts.append({"level": level, "message": msg})

    def _print(self, msg):
        if self.verbose: print(msg)


def clr_yellow(s): return f"\033[93m{s}\033[0m"


if __name__ == "__main__":
    MACRandomisationChecker().check()
