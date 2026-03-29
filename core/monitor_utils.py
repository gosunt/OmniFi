"""
OmniFi — Background Monitor + Alert Timeline + QR Generator
=============================================================
Three core UX features:

1. BackgroundMonitor
   Runs as a background daemon thread, polling every 60 seconds.
   Checks: new devices, BSSID changes, ARP shifts, DNS anomalies.
   Fires desktop notifications via plyer when anything changes.

2. AlertTimeline
   Stores all alerts in SQLite with timestamps.
   Provides scrollable history for the dashboard.

3. QRCodeGenerator
   Generates Wi-Fi QR code using WIFI:T:WPA;S:SSID;P:password;; format.
   Displays in terminal + saves as PNG for dashboard.
"""

import os
import time
import sqlite3
import datetime
import threading
import socket
import platform
import subprocess
import re

try:
    from plyer import notification as plyer_notify
    PLYER_AVAILABLE = True
except ImportError:
    PLYER_AVAILABLE = False

try:
    import qrcode
    QRCODE_AVAILABLE = True
except ImportError:
    QRCODE_AVAILABLE = False

DB_PATH    = os.path.join(os.path.dirname(__file__), "..", "db", "omnifi.db")
REPORT_DIR = os.path.join(os.path.dirname(__file__), "..", "reports")


# ─────────────────────────────────────────────────────────────────────────────
# Alert Timeline
# ─────────────────────────────────────────────────────────────────────────────

class AlertTimeline:
    """Persistent alert store with timestamp, severity, and message."""

    def __init__(self):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS alert_timeline (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                level     TEXT NOT NULL,
                source    TEXT NOT NULL,
                message   TEXT NOT NULL
            )
        """)
        self.conn.commit()

    def add(self, level: str, message: str, source: str = "omnifi"):
        self.conn.execute("""
            INSERT INTO alert_timeline (timestamp, level, source, message)
            VALUES (?,?,?,?)
        """, (datetime.datetime.now().isoformat(), level, source, message))
        self.conn.commit()

    def get_recent(self, hours: int = 24, limit: int = 100) -> list:
        since = (datetime.datetime.now() -
                 datetime.timedelta(hours=hours)).isoformat()
        cur = self.conn.cursor()
        cur.execute("""
            SELECT timestamp, level, source, message
            FROM alert_timeline
            WHERE timestamp > ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (since, limit))
        return [{"timestamp":r[0],"level":r[1],"source":r[2],"message":r[3]}
                for r in cur.fetchall()]

    def get_all(self, limit: int = 200) -> list:
        cur = self.conn.cursor()
        cur.execute("""
            SELECT timestamp, level, source, message
            FROM alert_timeline
            ORDER BY timestamp DESC LIMIT ?
        """, (limit,))
        return [{"timestamp":r[0],"level":r[1],"source":r[2],"message":r[3]}
                for r in cur.fetchall()]

    def print_timeline(self, hours: int = 24):
        alerts  = self.get_recent(hours)
        icons   = {"critical":"[!!!]","high":"[!!]","medium":"[!]","low":"[i]"}
        colors  = {
            "critical":"\033[91m","high":"\033[91m",
            "medium":"\033[93m","low":"\033[92m"
        }
        RST = "\033[0m"
        print(f"\n  Alert Timeline — last {hours}h ({len(alerts)} events)\n")
        print(f"  {'Time':<22} {'Level':<10} {'Source':<15} Message")
        print("  " + "─" * 72)
        for a in alerts:
            ts    = a["timestamp"][:19].replace("T"," ")
            level = a["level"]
            c     = colors.get(level,"")
            print(f"  {ts:<22} {c}{icons.get(level,'[i]')} {level:<7}{RST}"
                  f"  {a['source']:<15} {a['message'][:50]}")
        if not alerts:
            print("  No alerts in the last 24 hours.")
        print()

    def clear(self):
        self.conn.execute("DELETE FROM alert_timeline")
        self.conn.commit()


# ─────────────────────────────────────────────────────────────────────────────
# Background Monitor
# ─────────────────────────────────────────────────────────────────────────────

class BackgroundMonitor:
    """
    Polls network security state every POLL_INTERVAL seconds.
    Fires desktop notifications when anomalies are detected.
    Runs in a daemon thread — does not block the main application.
    """

    POLL_INTERVAL = 60   # seconds

    def __init__(self, verbose=False):
        self.verbose      = verbose
        self.running      = False
        self._thread      = None
        self.timeline     = AlertTimeline()
        self._last_gateway_mac  = None
        self._last_dns_ip       = None
        self._known_devices: set = set()

    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        print("  [+] OmniFi background monitor started (polling every "
              f"{self.POLL_INTERVAL}s).")

    def stop(self):
        self.running = False
        print("  [*] Background monitor stopped.")

    def _loop(self):
        while self.running:
            try:
                self._check_gateway_mac()
                self._check_dns()
                self._check_new_devices()
            except Exception as e:
                if self.verbose:
                    print(f"  [!] Monitor error: {e}")
            time.sleep(self.POLL_INTERVAL)

    # ── Individual checks ─────────────────────────────────────────────────────

    def _check_gateway_mac(self):
        """Detect gateway MAC address change — ARP MITM indicator."""
        gw  = self._get_gateway_ip()
        if not gw:
            return
        mac = self._get_arp_mac(gw)
        if not mac:
            return

        if self._last_gateway_mac is None:
            self._last_gateway_mac = mac
            return

        if mac != self._last_gateway_mac:
            msg = (f"Gateway MAC changed: {self._last_gateway_mac} → {mac}. "
                   "Possible ARP spoofing / MITM attack!")
            self._fire_alert("critical", msg, "arp_monitor")
            self._last_gateway_mac = mac

    def _check_dns(self):
        """Detect DNS answer change for a well-known domain."""
        try:
            ip = socket.gethostbyname("google.com")
            if self._last_dns_ip is None:
                self._last_dns_ip = ip
                return
            if ip != self._last_dns_ip:
                msg = (f"DNS answer for google.com changed: "
                       f"{self._last_dns_ip} → {ip}. Possible DNS spoofing!")
                self._fire_alert("high", msg, "dns_monitor")
                self._last_dns_ip = ip
        except Exception:
            pass

    def _check_new_devices(self):
        """Detect new devices on the subnet via ARP scan."""
        devices = self._arp_scan()
        new_devs = devices - self._known_devices
        if new_devs and self._known_devices:
            for dev in new_devs:
                msg = f"New device joined the network: {dev}"
                self._fire_alert("medium", msg, "device_monitor")
        self._known_devices.update(devices)

    # ── Notification + timeline ───────────────────────────────────────────────

    def _fire_alert(self, level: str, message: str, source: str):
        self.timeline.add(level, message, source)

        if self.verbose:
            icons = {"critical":"[!!!]","high":"[!!]","medium":"[!]","low":"[i]"}
            print(f"\n  {icons.get(level,'[i]')} {message}")

        self._desktop_notify(level, message)

    def _desktop_notify(self, level: str, message: str):
        if not PLYER_AVAILABLE:
            return
        titles = {"critical":"OmniFi — Critical Alert!",
                  "high":    "OmniFi — High Alert",
                  "medium":  "OmniFi — Warning",
                  "low":     "OmniFi — Notice"}
        try:
            plyer_notify.notify(
                title   = titles.get(level, "OmniFi"),
                message = message[:200],
                app_name= "OmniFi",
                timeout  = 8,
            )
        except Exception:
            pass

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get_gateway_ip(self) -> str:
        try:
            if platform.system() == "Windows":
                out = subprocess.check_output(["ipconfig"], text=True,
                                              stderr=subprocess.DEVNULL)
                m   = re.search(r"Default Gateway.*?:\s*([\d.]+)", out)
            else:
                out = subprocess.check_output(["ip","route"], text=True,
                                              stderr=subprocess.DEVNULL)
                m   = re.search(r"default via ([\d.]+)", out)
            return m.group(1) if m else ""
        except Exception:
            return ""

    def _get_arp_mac(self, ip: str) -> str:
        try:
            if platform.system() == "Windows":
                out = subprocess.check_output(["arp","-a",ip], text=True,
                                              stderr=subprocess.DEVNULL)
            else:
                out = subprocess.check_output(["arp","-n",ip], text=True,
                                              stderr=subprocess.DEVNULL)
            m = re.search(
                r"([\da-f]{2}[:\-][\da-f]{2}[:\-][\da-f]{2}[:\-]"
                r"[\da-f]{2}[:\-][\da-f]{2}[:\-][\da-f]{2})",
                out, re.IGNORECASE)
            return m.group(1).upper() if m else ""
        except Exception:
            return ""

    def _arp_scan(self) -> set:
        """Return set of IP addresses visible via ARP table."""
        try:
            if platform.system() == "Windows":
                out = subprocess.check_output(["arp","-a"], text=True,
                                              stderr=subprocess.DEVNULL)
            else:
                out = subprocess.check_output(["arp","-n"], text=True,
                                              stderr=subprocess.DEVNULL)
            ips = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", out)
            return set(ips)
        except Exception:
            return set()


# ─────────────────────────────────────────────────────────────────────────────
# QR Code Generator
# ─────────────────────────────────────────────────────────────────────────────

class QRCodeGenerator:
    """
    Generate Wi-Fi QR code in WIFI:T:WPA;S:SSID;P:password;; format.
    Scan with any Android or iOS camera app to connect instantly.
    """

    def __init__(self, verbose=True):
        self.verbose = verbose

    def generate(self, ssid: str, password: str,
                 security: str = "WPA",
                 hidden: bool  = False,
                 filename: str = None) -> str:
        """
        Generate and save Wi-Fi QR code PNG.
        Returns path to saved PNG file.

        security: WPA | WEP | nopass
        """
        if not QRCODE_AVAILABLE:
            self._print("[!] qrcode not installed. Run: pip install qrcode[pil]")
            return ""

        os.makedirs(REPORT_DIR, exist_ok=True)
        if not filename:
            safe_ssid = re.sub(r'[^\w]', '_', ssid)
            filename  = os.path.join(REPORT_DIR, f"wifi_qr_{safe_ssid}.png")

        # Escape special chars in SSID and password per Wi-Fi QR spec
        def escape(s):
            return s.replace("\\","\\\\").replace(";","\\;").replace(",","\\,")\
                    .replace('"','\\"').replace("'","\\'")

        ssid_esc = escape(ssid)
        pass_esc = escape(password)
        hidden_s = "true" if hidden else "false"

        if security.upper() == "NOPASS":
            wifi_str = f"WIFI:T:nopass;S:{ssid_esc};H:{hidden_s};;"
        else:
            wifi_str = (f"WIFI:T:{security.upper()};"
                        f"S:{ssid_esc};"
                        f"P:{pass_esc};"
                        f"H:{hidden_s};;")

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=10,
            border=4,
        )
        qr.add_data(wifi_str)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        img.save(filename)

        self._print(f"\n  [+] Wi-Fi QR code saved: {filename}")
        self._print(f"  SSID     : {ssid}")
        self._print(f"  Security : {security.upper()}")
        self._print(f"  Scan with phone camera to connect — no password needed.\n")

        # Also print ASCII QR to terminal
        self._print_ascii_qr(qr)
        return filename

    def _print_ascii_qr(self, qr):
        """Print a compact ASCII version of the QR to terminal."""
        try:
            matrix = qr.get_matrix()
            self._print("")
            for row in matrix:
                line = "".join("██" if cell else "  " for cell in row)
                print(f"  {line}")
            self._print("")
        except Exception:
            pass

    def _print(self, msg):
        if self.verbose: print(msg)


# ─────────────────────────────────────────────────────────────────────────────
# CLI demos
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if "--timeline" in sys.argv:
        tl = AlertTimeline()
        tl.add("critical", "Default credentials work on JioFiber router", "router_audit")
        tl.add("high",     "Evil twin detected: HomeNetwork_5G",          "network_scan")
        tl.add("medium",   "New device AA:BB:CC:11:22:33 joined network", "device_monitor")
        tl.add("low",      "Signal strength dropped below -80dBm",         "wifi_monitor")
        tl.print_timeline()

    elif "--qr" in sys.argv:
        QRCodeGenerator().generate(
            ssid="HomeNetwork_5G",
            password="MySecurePass@2024",
            security="WPA"
        )

    elif "--monitor" in sys.argv:
        monitor = BackgroundMonitor(verbose=True)
        monitor.start()
        print("  Background monitor running. Press Ctrl+C to stop.")
        try:
            while True: time.sleep(1)
        except KeyboardInterrupt:
            monitor.stop()
