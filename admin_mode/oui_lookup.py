"""
OmniFi — OUI Vendor Lookup + Device Classification
====================================================
For every device on the network, look up the first 3 bytes of the MAC
address against the IEEE OUI registry to identify the manufacturer.

Flag devices whose OUI doesn't match their DHCP hostname or advertised
device type — a classic MAC spoofing indicator.

Data source:
  Local OUI database bundled from https://maclookup.app/downloads/csv-database
  Falls back to HTTPS API lookup if local DB is unavailable.
"""

import os
import csv
import re
import sqlite3
import requests

DB_PATH       = os.path.join(os.path.dirname(__file__), "..", "db", "omnifi.db")
OUI_CSV_PATH  = os.path.join(os.path.dirname(__file__), "..", "db", "oui.csv")
OUI_API       = "https://api.maclookup.app/v2/macs/{mac}/company/name"

# Suspicious patterns: OUI vendor vs hostname mismatch signals
VENDOR_DEVICE_HINTS = {
    "apple":    ["iphone", "macbook", "ipad", "mac", "apple"],
    "samsung":  ["samsung", "galaxy", "sm-"],
    "xiaomi":   ["xiaomi", "redmi", "mi "],
    "oneplus":  ["oneplus"],
    "realme":   ["realme"],
    "oppo":     ["oppo"],
    "huawei":   ["huawei", "honor"],
    "intel":    ["laptop", "desktop", "pc", "intel"],
    "raspberrypi": ["raspberry", "pi"],
}


def _init_oui_db(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS oui_cache (
            oui      TEXT PRIMARY KEY,
            vendor   TEXT NOT NULL
        )
    """)
    conn.commit()


def _load_oui_csv(conn):
    """Load OUI CSV into SQLite cache if not already done."""
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM oui_cache")
    if cur.fetchone()[0] > 0:
        return  # already loaded

    if not os.path.exists(OUI_CSV_PATH):
        return  # CSV not bundled — will use API fallback

    with open(OUI_CSV_PATH, newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        batch  = []
        for row in reader:
            if len(row) >= 2:
                oui    = row[0].strip().upper().replace("-", ":").replace(" ", "")[:8]
                vendor = row[1].strip()
                batch.append((oui, vendor))
            if len(batch) >= 1000:
                conn.executemany(
                    "INSERT OR IGNORE INTO oui_cache (oui, vendor) VALUES (?,?)", batch)
                conn.commit()
                batch = []
        if batch:
            conn.executemany(
                "INSERT OR IGNORE INTO oui_cache (oui, vendor) VALUES (?,?)", batch)
            conn.commit()


class OUILookup:
    def __init__(self, verbose=True):
        self.verbose = verbose
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        self.conn    = sqlite3.connect(DB_PATH)
        _init_oui_db(self.conn)
        _load_oui_csv(self.conn)
        self.alerts  = []

    def lookup(self, mac: str) -> str:
        """Return vendor name for a MAC address."""
        mac = mac.upper().replace("-", ":").strip()
        oui = ":".join(mac.split(":")[:3])

        # Check local cache first
        cur = self.conn.cursor()
        cur.execute("SELECT vendor FROM oui_cache WHERE oui=?", (oui,))
        row = cur.fetchone()
        if row:
            return row[0]

        # API fallback
        try:
            r = requests.get(OUI_API.format(mac=mac.replace(":", "")),
                             timeout=4)
            if r.status_code == 200:
                vendor = r.text.strip()
                if vendor and vendor.lower() not in ("private", "unknown", ""):
                    self.conn.execute(
                        "INSERT OR IGNORE INTO oui_cache (oui, vendor) VALUES (?,?)",
                        (oui, vendor))
                    self.conn.commit()
                    return vendor
        except Exception:
            pass

        return "Unknown"

    def classify_device(self, mac: str, hostname: str = "",
                        dhcp_fingerprint: str = "") -> dict:
        """
        Look up OUI, classify device type, and check for MAC spoofing indicators.
        """
        vendor   = self.lookup(mac)
        is_local = self._is_locally_administered(mac)

        result = {
            "mac":              mac,
            "vendor":           vendor,
            "hostname":         hostname,
            "locally_admin":    is_local,
            "spoof_suspected":  False,
            "spoof_reason":     "",
            "device_type":      self._guess_device_type(vendor, hostname),
        }

        # Flag 1: locally administered MAC = either randomised or spoofed
        if is_local:
            result["spoof_suspected"] = True
            result["spoof_reason"]    = (
                "Locally administered bit set — MAC is randomised or manually spoofed.")
            self._alert(
                f"Device {mac} ({hostname}): locally administered MAC detected.",
                "medium"
            )

        # Flag 2: vendor/hostname mismatch
        if vendor and hostname:
            mismatch = self._check_vendor_hostname_mismatch(vendor, hostname)
            if mismatch:
                result["spoof_suspected"] = True
                result["spoof_reason"] += f" Vendor/hostname mismatch: {mismatch}"
                self._alert(
                    f"Device {mac}: OUI vendor '{vendor}' doesn't match "
                    f"hostname '{hostname}' — possible MAC spoofing.",
                    "high"
                )

        if self.verbose:
            flag = "[!!]" if result["spoof_suspected"] else "[+]"
            print(f"  {flag} {mac}  Vendor: {vendor:30s}  "
                  f"Host: {hostname:20s}  Type: {result['device_type']}")

        return result

    def classify_all(self, devices: list) -> list:
        """
        Classify a list of devices.
        Each device is a dict with 'mac' and optionally 'hostname'.
        """
        return [self.classify_device(d.get("mac",""),
                                     d.get("hostname",""),
                                     d.get("dhcp_fingerprint",""))
                for d in devices if d.get("mac")]

    def _is_locally_administered(self, mac: str) -> bool:
        try:
            first = int(mac.split(":")[0].replace("-",""), 16)
            return bool(first & 0x02)
        except Exception:
            return False

    def _check_vendor_hostname_mismatch(self, vendor: str, hostname: str) -> str:
        v = vendor.lower()
        h = hostname.lower()
        for brand, hints in VENDOR_DEVICE_HINTS.items():
            vendor_match   = brand in v
            hostname_match = any(hint in h for hint in hints)
            # Vendor strongly implies one brand but hostname implies another
            if vendor_match and hostname and not hostname_match:
                other_brand = next(
                    (b for b, hs in VENDOR_DEVICE_HINTS.items()
                     if b != brand and any(hh in h for hh in hs)), None)
                if other_brand:
                    return f"OUI says {brand} but hostname suggests {other_brand}"
        return ""

    def _guess_device_type(self, vendor: str, hostname: str) -> str:
        v = vendor.lower()
        h = hostname.lower()
        combined = v + " " + h
        if any(x in combined for x in ["iphone","ipad","android","samsung","xiaomi","realme","oppo","oneplus","redmi"]):
            return "smartphone/tablet"
        if any(x in combined for x in ["macbook","laptop","thinkpad","dell","hp","lenovo","asus","acer"]):
            return "laptop"
        if any(x in combined for x in ["raspberry","arduino","esp32","esp8266"]):
            return "embedded/IoT"
        if any(x in combined for x in ["tv","smart-tv","chromecast","firetv","roku"]):
            return "smart TV / streaming"
        if any(x in combined for x in ["router","gateway","ap","access"]):
            return "network device"
        if any(x in combined for x in ["printer","print"]):
            return "printer"
        return "unknown"

    def _alert(self, msg, level="medium"):
        self.alerts.append({"level": level, "message": msg})


if __name__ == "__main__":
    oui = OUILookup()
    # Demo devices
    devices = [
        {"mac": "AA:BB:CC:DD:EE:01", "hostname": "John-iPhone"},
        {"mac": "02:11:22:33:44:55", "hostname": "unknown-device"},  # locally admin MAC
        {"mac": "B8:27:EB:12:34:56", "hostname": "raspberrypi"},     # Raspberry Pi
    ]
    print("\n  MAC Classification Results:")
    print("  " + "─" * 60)
    oui.classify_all(devices)
