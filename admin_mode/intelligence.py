"""
OmniFi — Admin Intelligence Modules
======================================
Five intelligence features for admin mode:

1. OUI vendor lookup + device classification
2. Device behaviour baseline + Z-score anomaly detection
3. CVE lookup via NIST NVD API for detected firmware
4. Gateway port scanner (top 20 ports, pure Python sockets)
5. Passive OS fingerprinting via TCP SYN analysis
"""

import os
import re
import csv
import json
import math
import time
import socket
import struct
import sqlite3
import platform
import subprocess
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from collections import defaultdict
from statistics import mean, stdev

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from scapy.all import sniff, IP, TCP, conf as scapy_conf
    scapy_conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


RESET  = "\033[0m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"
DIM    = "\033[2m"

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "db", "omnifi.db")
OUI_CSV = os.path.join(os.path.dirname(__file__), "..", "db", "oui.csv")


# ─────────────────────────────────────────────────────────────────────────────
# Shared DB helper
# ─────────────────────────────────────────────────────────────────────────────

def get_conn() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    return sqlite3.connect(DB_PATH)


# ─────────────────────────────────────────────────────────────────────────────
# 1. OUI Vendor Lookup + Device Classification
# ─────────────────────────────────────────────────────────────────────────────

class OUILookup:
    """
    Looks up the first 3 bytes (OUI) of a MAC address against the
    IEEE registry to identify the hardware manufacturer.
    Bundles a local CSV so no internet lookup is needed at runtime.
    """

    # Minimal embedded OUI table for common Indian market devices
    # Full table: download from https://regauth.standards.ieee.org/standards-ra-web/pub/view.html#registries
    BUILTIN_OUI = {
        "00:50:F2": "Microsoft",
        "00:1A:11": "Google",
        "B8:27:EB": "Raspberry Pi",
        "DC:A6:32": "Raspberry Pi",
        "00:0C:29": "VMware",
        "00:50:56": "VMware",
        "28:6F:7F": "Amazon (Echo/FireTV)",
        "FC:65:DE": "Amazon",
        "74:DA:38": "Edimax (IoT)",
        "00:1B:63": "Apple",
        "00:1C:B3": "Apple",
        "00:1D:4F": "Apple",
        "00:1E:52": "Apple",
        "00:1F:5B": "Apple",
        "00:21:E9": "Apple",
        "00:22:41": "Apple",
        "00:23:12": "Apple",
        "00:23:32": "Apple",
        "00:23:6C": "Apple",
        "00:24:36": "Apple",
        "00:25:00": "Apple",
        "00:25:4B": "Apple",
        "00:25:BC": "Apple",
        "00:26:08": "Apple",
        "00:26:4A": "Apple",
        "00:26:B0": "Apple",
        "00:26:BB": "Apple",
        "00:30:65": "Apple",
        "00:3E:E1": "Apple",
        "00:50:E4": "Apple",
        "00:56:CD": "Apple",
        "00:61:71": "Apple",
        "00:6D:52": "Apple",
        "00:88:65": "Apple",
        "28:CF:DA": "Apple",
        "3C:07:54": "Apple",
        "70:3E:AC": "Apple",
        "F4:F1:5A": "Apple",
        "18:65:90": "Apple",
        "AC:BC:32": "Apple",
        "04:4B:ED": "Xiaomi",
        "0C:1D:AF": "Xiaomi",
        "10:2A:B3": "Xiaomi",
        "14:F6:5A": "Xiaomi",
        "18:59:36": "Xiaomi",
        "20:82:C0": "Xiaomi",
        "28:6C:07": "Xiaomi",
        "34:80:B3": "Xiaomi",
        "50:EC:50": "Xiaomi",
        "58:44:98": "Xiaomi",
        "64:09:80": "Xiaomi",
        "74:23:44": "Xiaomi",
        "78:11:DC": "Xiaomi",
        "8C:BE:BE": "Xiaomi",
        "9C:99:A0": "Xiaomi",
        "A0:86:C6": "Xiaomi",
        "AC:C1:EE": "Xiaomi",
        "B0:E2:35": "Xiaomi",
        "C4:0B:CB": "Xiaomi",
        "D4:97:0B": "Xiaomi",
        "F0:B4:29": "Xiaomi",
        "F8:A4:5F": "Xiaomi",
        "10:BF:48": "Samsung",
        "1C:AF:05": "Samsung",
        "20:64:32": "Samsung",
        "28:BA:B5": "Samsung",
        "30:07:4D": "Samsung",
        "34:AA:8B": "Samsung",
        "38:AA:3C": "Samsung",
        "3C:BD:D8": "Samsung",
        "40:0E:85": "Samsung",
        "44:F4:59": "Samsung",
        "4C:BC:98": "Samsung",
        "54:88:0E": "Samsung",
        "5C:F6:DC": "Samsung",
        "60:A4:D0": "Samsung",
        "6C:2F:2C": "Samsung",
        "70:F9:27": "Samsung",
        "78:40:E4": "Samsung",
        "8C:71:F8": "Samsung",
        "90:18:7C": "Samsung",
        "94:76:B7": "Samsung",
        "A0:75:91": "Samsung",
        "B0:47:BF": "Samsung",
        "CC:07:AB": "Samsung",
        "E4:92:FB": "Samsung",
        "F4:7B:5E": "Samsung",
        "4C:5E:0C": "TP-Link",
        "50:C7:BF": "TP-Link",
        "54:AF:97": "TP-Link",
        "60:32:B1": "TP-Link",
        "6C:5G:AB": "TP-Link",
        "70:4F:57": "TP-Link",
        "74:DA:DA": "TP-Link",
        "90:F6:52": "TP-Link",
        "A0:F3:C1": "TP-Link",
        "B0:BE:76": "TP-Link",
        "C0:4A:00": "TP-Link",
        "E8:DE:27": "TP-Link",
        "F8:1A:67": "TP-Link",
        "00:90:4C": "Huawei",
        "04:BD:70": "Huawei",
        "18:C5:8A": "Huawei",
        "20:F3:A3": "Huawei",
        "2C:AB:00": "Huawei",
        "30:87:30": "Huawei",
        "34:6B:D3": "Huawei",
        "38:F8:89": "Huawei",
        "40:4D:8E": "Huawei",
        "48:46:FB": "Huawei",
        "4C:1F:CC": "Huawei",
        "54:51:1B": "Huawei",
        "58:2A:F7": "Huawei",
        "5C:7D:5E": "Huawei",
        "68:89:C1": "Huawei",
        "70:72:CF": "Huawei",
        "80:71:7A": "Huawei",
        "84:A8:E4": "Huawei",
        "8C:34:FD": "Huawei",
        "90:17:AC": "Huawei",
        "94:04:9C": "Huawei",
        "98:E7:F4": "Huawei",
        "A4:C6:4F": "Huawei",
        "AC:E2:15": "Huawei",
        "B4:15:13": "Huawei",
        "C8:51:95": "Huawei",
        "CC:96:A0": "Huawei",
        "D4:94:E8": "Huawei",
        "E0:19:54": "Huawei",
        "E8:CD:2D": "Huawei",
        "F4:55:9C": "Huawei",
        "F8:3D:FF": "Huawei",
    }

    _cache: dict = {}

    def lookup(self, mac: str) -> str:
        """Return vendor name for a given MAC address."""
        mac = mac.upper().replace("-", ":").strip()
        oui = ":".join(mac.split(":")[:3])

        if oui in self._cache:
            return self._cache[oui]

        # 1. Built-in table
        vendor = self.BUILTIN_OUI.get(oui)

        # 2. Local CSV (if available)
        if not vendor and os.path.exists(OUI_CSV):
            vendor = self._lookup_csv(oui)

        # 3. Locally administered / randomised
        first_byte = int(oui.split(":")[0], 16)
        if first_byte & 0x02:
            vendor = "Randomised MAC"

        vendor = vendor or "Unknown"
        self._cache[oui] = vendor
        return vendor

    def _lookup_csv(self, oui: str) -> Optional[str]:
        target = oui.replace(":", "").upper()
        try:
            with open(OUI_CSV, newline="", encoding="utf-8", errors="ignore") as f:
                reader = csv.reader(f)
                for row in reader:
                    if row and row[0].upper().replace("-", "")[:6] == target[:6]:
                        return row[2] if len(row) > 2 else row[1]
        except Exception:
            pass
        return None

    def classify_device(self, mac: str, hostname: str = "") -> str:
        """
        Classify device type from vendor + hostname hints.
        Returns: phone / laptop / iot / router / unknown
        """
        vendor   = self.lookup(mac).lower()
        hostname = hostname.lower()

        phone_vendors  = ["apple", "samsung", "xiaomi", "oneplus", "oppo", "vivo",
                          "realme", "motorola", "nokia", "huawei"]
        laptop_vendors = ["dell", "hp", "lenovo", "asus", "acer", "microsoft",
                          "intel", "toshiba"]
        iot_vendors    = ["espressif", "tuya", "shenzhen", "amazon", "google",
                          "raspberry", "edimax"]
        router_vendors = ["tp-link", "netgear", "asus", "d-link", "cisco",
                          "ubiquiti", "huawei", "zyxel"]

        for v in phone_vendors:
            if v in vendor or v in hostname:
                return "phone"
        for v in laptop_vendors:
            if v in vendor or v in hostname:
                return "laptop"
        for v in iot_vendors:
            if v in vendor or v in hostname:
                return "iot"
        for v in router_vendors:
            if v in vendor or v in hostname:
                return "router"

        if any(k in hostname for k in ["phone", "iphone", "android", "pixel"]):
            return "phone"
        if any(k in hostname for k in ["laptop", "desktop", "pc", "mac"]):
            return "laptop"

        return "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# 2. Device Behaviour Baseline + Anomaly Detection
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class BehaviourAnomaly:
    mac:         str
    metric:      str
    current_val: float
    baseline:    float
    z_score:     float
    severity:    str
    detail:      str


class DeviceBehaviourBaseline:
    """
    Records per-device behaviour metrics over 24hr baseline period.
    After baseline, uses Z-score to flag statistical deviations.

    Metrics tracked per device:
      - bytes_per_hour (bandwidth)
      - connection_hour (typical connection times, 0–23)
      - ports_accessed (number of unique ports)
      - packets_per_min (packet rate)
    """

    BASELINE_HOURS   = 24
    Z_SCORE_THRESHOLD = 2.5   # flag if deviation > 2.5 std deviations
    MIN_SAMPLES       = 5

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self._init_db()

    def _init_db(self):
        with get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS device_baseline (
                    mac         TEXT NOT NULL,
                    metric      TEXT NOT NULL,
                    value       REAL NOT NULL,
                    timestamp   TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_dev_bl
                ON device_baseline(mac, metric)
            """)

    def record(self, mac: str, metric: str, value: float):
        """Record a single metric observation."""
        now = datetime.now().isoformat()
        with get_conn() as conn:
            conn.execute("""
                INSERT INTO device_baseline (mac, metric, value, timestamp)
                VALUES (?, ?, ?, ?)
            """, (mac, metric, value, now))

    def record_batch(self, observations: list[dict]):
        """Record multiple observations at once."""
        now = datetime.now().isoformat()
        with get_conn() as conn:
            conn.executemany("""
                INSERT INTO device_baseline (mac, metric, value, timestamp)
                VALUES (:mac, :metric, :value, :ts)
            """, [{**o, "ts": now} for o in observations])

    def check_anomaly(self, mac: str, metric: str,
                      current_value: float) -> Optional[BehaviourAnomaly]:
        """
        Compare current_value against historical baseline using Z-score.
        Returns anomaly if Z-score exceeds threshold, else None.
        """
        samples = self._get_samples(mac, metric)
        if len(samples) < self.MIN_SAMPLES:
            return None

        baseline_mean = mean(samples)
        baseline_std  = stdev(samples) if len(samples) > 1 else 0

        if baseline_std == 0:
            return None

        z = abs((current_value - baseline_mean) / baseline_std)
        if z < self.Z_SCORE_THRESHOLD:
            return None

        severity = "critical" if z > 4 else "high" if z > 3 else "medium"

        return BehaviourAnomaly(
            mac=mac,
            metric=metric,
            current_val=current_value,
            baseline=baseline_mean,
            z_score=round(z, 2),
            severity=severity,
            detail=(
                f"Device {mac}: {metric} is {current_value:.1f} "
                f"(baseline avg: {baseline_mean:.1f}, Z-score: {z:.1f}). "
                f"Statistically anomalous behaviour detected."
            )
        )

    def check_all_metrics(self, mac: str,
                          current: dict) -> list[BehaviourAnomaly]:
        """
        Check all metrics for a device at once.
        current = {"bytes_per_hour": 1024, "ports_accessed": 5, ...}
        """
        anomalies = []
        for metric, value in current.items():
            a = self.check_anomaly(mac, metric, value)
            if a:
                anomalies.append(a)
                self._print(f"  {YELLOW}[!] Behaviour anomaly [{a.severity.upper()}]: "
                            f"{a.detail}{RESET}")
        return anomalies

    def _get_samples(self, mac: str, metric: str) -> list[float]:
        with get_conn() as conn:
            rows = conn.execute("""
                SELECT value FROM device_baseline
                WHERE mac=? AND metric=?
                ORDER BY timestamp DESC LIMIT 500
            """, (mac, metric)).fetchall()
        return [r[0] for r in rows]

    def _print(self, msg):
        if self.verbose:
            print(msg)


# ─────────────────────────────────────────────────────────────────────────────
# 3. CVE Lookup via NIST NVD API
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CVEEntry:
    cve_id:       str
    description:  str
    cvss_score:   float
    severity:     str
    published:    str
    references:   list = field(default_factory=list)


class CVELookup:
    """
    Queries NIST NVD API for CVEs matching a router model + firmware version.
    Endpoint: https://services.nvd.nist.gov/rest/json/cves/2.0
    """

    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    RESULTS_PER_PAGE = 10

    def __init__(self, verbose: bool = True):
        self.verbose = verbose

    def search(self, router_model: str, firmware: str = "") -> list[CVEEntry]:
        """
        Search for CVEs matching a router model.
        Returns list of CVEEntry sorted by CVSS score descending.
        """
        if not REQUESTS_AVAILABLE:
            self._print("  [!] requests not installed — CVE lookup unavailable.")
            return []

        query = router_model
        if firmware:
            query += f" {firmware}"

        self._print(f"\n[OmniFi] CVE lookup for: {query}")

        try:
            params = {
                "keywordSearch": query,
                "resultsPerPage": self.RESULTS_PER_PAGE,
                "startIndex": 0,
            }
            r = requests.get(self.NVD_API, params=params, timeout=10)
            r.raise_for_status()
            data = r.json()

            cves = []
            for vuln in data.get("vulnerabilities", []):
                cve_data = vuln.get("cve", {})
                cve_id   = cve_data.get("id", "")

                # Description
                descs = cve_data.get("descriptions", [])
                desc  = next((d["value"] for d in descs
                               if d.get("lang") == "en"), "No description")

                # CVSS score
                metrics  = cve_data.get("metrics", {})
                cvss3    = metrics.get("cvssMetricV31", []) or \
                           metrics.get("cvssMetricV30", [])
                cvss2    = metrics.get("cvssMetricV2", [])

                if cvss3:
                    score    = cvss3[0]["cvssData"]["baseScore"]
                    severity = cvss3[0]["cvssData"]["baseSeverity"]
                elif cvss2:
                    score    = cvss2[0]["cvssData"]["baseScore"]
                    severity = cvss2[0].get("baseSeverity", "UNKNOWN")
                else:
                    score, severity = 0.0, "UNKNOWN"

                published = cve_data.get("published", "")[:10]
                refs = [r["url"] for r in cve_data.get("references", [])[:3]]

                cves.append(CVEEntry(
                    cve_id=cve_id,
                    description=desc[:200],
                    cvss_score=float(score),
                    severity=severity,
                    published=published,
                    references=refs
                ))

            cves.sort(key=lambda c: c.cvss_score, reverse=True)

            if cves:
                self._print_cves(cves, router_model)
            else:
                self._print(f"  {GREEN}[+] No CVEs found for '{router_model}'.{RESET}")

            return cves

        except requests.RequestException as e:
            self._print(f"  {RED}[!] CVE API error: {e}{RESET}")
            return []

    def _print_cves(self, cves: list[CVEEntry], model: str):
        print(f"\n  CVEs found for {model} ({len(cves)} results):\n")
        for cve in cves:
            color = (RED if cve.cvss_score >= 7.0 else
                     YELLOW if cve.cvss_score >= 4.0 else RESET)
            print(f"  {color}{BOLD}{cve.cve_id}{RESET}  "
                  f"CVSS: {color}{cve.cvss_score}{RESET}  "
                  f"[{cve.severity}]  {cve.published}")
            print(f"    {DIM}{cve.description}{RESET}")
            for ref in cve.references[:1]:
                print(f"    {DIM}{ref}{RESET}")
            print()

    def _print(self, msg):
        if self.verbose:
            print(msg)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Gateway Port Scanner
# ─────────────────────────────────────────────────────────────────────────────

# Top 20 ports most relevant for router/gateway security
SCAN_PORTS = {
    21:   ("FTP",     "critical", "File Transfer Protocol — unencrypted, should be closed"),
    22:   ("SSH",     "info",     "Secure Shell — if open, ensure strong password or key auth"),
    23:   ("Telnet",  "critical", "Telnet — plaintext remote access, immediately close this"),
    25:   ("SMTP",    "high",     "Mail relay — should not be open on a home router"),
    53:   ("DNS",     "medium",   "DNS resolver — check if open to internet (DNS amplification risk)"),
    80:   ("HTTP",    "medium",   "Admin panel on HTTP — credentials sent unencrypted"),
    443:  ("HTTPS",   "info",     "Admin panel on HTTPS — acceptable"),
    161:  ("SNMP",    "high",     "SNMP — information disclosure risk if default community string"),
    443:  ("HTTPS",   "low",      "HTTPS web admin"),
    500:  ("IKE",     "info",     "IPSec VPN — expected if VPN enabled"),
    554:  ("RTSP",    "high",     "Video stream — should not be exposed"),
    1194: ("OpenVPN", "info",     "OpenVPN — expected if VPN configured"),
    1900: ("UPnP",    "high",     "UPnP — major security risk, disable on router"),
    4567: ("Alt-HTTP","medium",   "Alternate HTTP port"),
    7547: ("CWMP",    "critical", "TR-069 ISP remote management — ISP has admin access"),
    8080: ("HTTP-alt","medium",   "Alternate HTTP — check if admin panel exposed"),
    8443: ("HTTPS-alt","info",    "Alternate HTTPS admin panel"),
    8888: ("HTTP-alt","medium",   "Alternate HTTP port"),
    51413:("BitTorrent","medium", "BitTorrent — if open, check if expected"),
}


@dataclass
class PortScanResult:
    port:       int
    service:    str
    state:      str    # open / closed / filtered
    risk_level: str
    notes:      str


class GatewayPortScanner:
    """
    Lightweight port scanner using pure Python sockets.
    No nmap required. Scans top 20 security-relevant ports on the gateway.
    """

    CONNECT_TIMEOUT = 1.5
    MAX_THREADS     = 20

    def __init__(self, verbose: bool = True):
        self.verbose = verbose

    def scan(self, target_ip: str) -> list[PortScanResult]:
        self._print(f"\n[OmniFi] Port scan on gateway {target_ip}...")
        results = []
        lock    = threading.Lock()

        def probe(port: int):
            state = self._probe_port(target_ip, port)
            service, risk, notes = SCAN_PORTS.get(port, ("unknown", "info", ""))
            result = PortScanResult(port=port, service=service,
                                    state=state, risk_level=risk, notes=notes)
            with lock:
                results.append(result)

        threads = []
        for port in SCAN_PORTS:
            t = threading.Thread(target=probe, args=(port,), daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join(timeout=5)

        open_ports = [r for r in results if r.state == "open"]
        open_ports.sort(key=lambda r: r.port)

        self._print_results(open_ports, target_ip)
        return open_ports

    def _probe_port(self, ip: str, port: int) -> str:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.CONNECT_TIMEOUT)
            result = sock.connect_ex((ip, port))
            sock.close()
            return "open" if result == 0 else "closed"
        except Exception:
            return "filtered"

    def _print_results(self, open_ports: list[PortScanResult], ip: str):
        if not open_ports:
            self._print(f"  {GREEN}[+] No unexpected open ports found on {ip}.{RESET}")
            return

        print(f"\n  Open ports on {ip}:")
        print(f"  {'Port':<8} {'Service':<12} {'Risk':<10} Notes")
        print("  " + "─" * 65)
        for r in open_ports:
            color = (RED if r.risk_level == "critical" else
                     YELLOW if r.risk_level in ("high", "medium") else
                     GREEN if r.risk_level == "low" else "")
            print(f"  {color}{r.port:<8} {r.service:<12} {r.risk_level:<10}{RESET} "
                  f"{DIM}{r.notes[:40]}{RESET}")

    def _print(self, msg):
        if self.verbose:
            print(msg)


# ─────────────────────────────────────────────────────────────────────────────
# 5. Passive OS Fingerprinting
# ─────────────────────────────────────────────────────────────────────────────

# OS signatures based on TCP SYN TTL + window size + options
OS_SIGNATURES = [
    # (ttl_range, window_size_range, os_name, confidence)
    (64,  64,  5840,  5840,  "Linux 2.4/2.6",       "high"),
    (64,  64,  29200, 29200, "Linux 3.x/4.x",        "high"),
    (64,  64,  65535, 65535, "Linux modern",          "medium"),
    (128, 128, 65535, 65535, "Windows 10/11",         "high"),
    (128, 128, 8192,  8192,  "Windows XP/Vista",      "medium"),
    (128, 128, 64240, 64240, "Windows 7/8",           "high"),
    (255, 255, 65535, 65535, "iOS / macOS",           "high"),
    (64,  64,  14600, 14600, "Android",               "high"),
    (64,  64,  16384, 16384, "Android/Linux",         "medium"),
    (255, 255, 4128,  4128,  "Cisco IOS router",      "high"),
    (64,  64,  5720,  5720,  "OpenWrt router",        "high"),
]


@dataclass
class OSFingerprint:
    src_ip:       str
    src_mac:      str = ""
    os_guess:     str = "Unknown"
    confidence:   str = "low"
    ttl:          int = 0
    window_size:  int = 0
    timestamp:    str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


class PassiveOSFingerprinter:
    """
    Passively sniffs TCP SYN packets and fingerprints each device's OS
    from TTL, TCP window size, and options — without sending any probe.
    """

    SNIFF_TIMEOUT = 60
    _seen: dict[str, OSFingerprint] = {}

    def __init__(self, interface: str = None, verbose: bool = True):
        self.interface = interface
        self.verbose   = verbose

    def run(self, timeout: int = None) -> dict[str, OSFingerprint]:
        if not SCAPY_AVAILABLE:
            self._print("  [!] Scapy not installed — OS fingerprinting unavailable.")
            return {}

        t = timeout or self.SNIFF_TIMEOUT
        self._print(f"\n[OmniFi] Passive OS Fingerprinter (sniffing {t}s)...")
        self._print(f"  [*] Waiting for TCP SYN packets from local devices...\n")

        try:
            sniff(
                filter="tcp[tcpflags] & tcp-syn != 0",
                prn=self._packet_handler,
                timeout=t,
                iface=self.interface,
                store=False
            )
        except Exception as e:
            self._print(f"  [!] Sniff error: {e}")

        self._print_results()
        return self._seen

    def _packet_handler(self, pkt):
        if not (IP in pkt and TCP in pkt):
            return

        # Only interested in SYN (not SYN-ACK)
        if pkt[TCP].flags != 0x02:
            return

        src_ip      = pkt[IP].src
        ttl         = pkt[IP].ttl
        window_size = pkt[TCP].window

        if src_ip in self._seen:
            return   # already fingerprinted

        os_guess, confidence = self._match_signature(ttl, window_size)
        mac = pkt.src if hasattr(pkt, "src") else ""

        fp = OSFingerprint(
            src_ip=src_ip,
            src_mac=mac,
            os_guess=os_guess,
            confidence=confidence,
            ttl=ttl,
            window_size=window_size
        )
        self._seen[src_ip] = fp

        self._print(f"  {CYAN}[OS]{RESET} {src_ip:<18} TTL={ttl:<4} "
                    f"Win={window_size:<8} → {BOLD}{os_guess}{RESET} "
                    f"({confidence} confidence)")

    def _match_signature(self, ttl: int, window: int) -> tuple[str, str]:
        for (ttl_lo, ttl_hi, win_lo, win_hi, os_name, conf) in OS_SIGNATURES:
            if ttl_lo <= ttl <= ttl_hi and win_lo <= window <= win_hi:
                return os_name, conf

        # Fuzzy TTL match
        if 60 <= ttl <= 70:
            return "Linux/Android (approx)", "low"
        if 120 <= ttl <= 135:
            return "Windows (approx)", "low"
        if 250 <= ttl <= 255:
            return "iOS/macOS/Cisco (approx)", "low"

        return "Unknown", "none"

    def _print_results(self):
        if not self._seen:
            self._print("  No TCP SYN packets observed.")
            return
        print(f"\n  OS Fingerprints ({len(self._seen)} devices):")
        print(f"  {'IP':<18} {'OS':<30} {'Confidence':<12} TTL   Window")
        print("  " + "─" * 72)
        for ip, fp in self._seen.items():
            print(f"  {ip:<18} {fp.os_guess:<30} {fp.confidence:<12} "
                  f"{fp.ttl:<6} {fp.window_size}")

    def _print(self, msg):
        if self.verbose:
            print(msg)


if __name__ == "__main__":
    import sys
    if "--oui" in sys.argv and len(sys.argv) > 2:
        oui = OUILookup()
        mac = sys.argv[sys.argv.index("--oui") + 1]
        print(f"  Vendor: {oui.lookup(mac)}")
        print(f"  Device type: {oui.classify_device(mac)}")
    elif "--cve" in sys.argv and len(sys.argv) > 2:
        model = sys.argv[sys.argv.index("--cve") + 1]
        CVELookup().search(model)
    elif "--ports" in sys.argv and len(sys.argv) > 2:
        ip = sys.argv[sys.argv.index("--ports") + 1]
        GatewayPortScanner().scan(ip)
    elif "--osfingerprint" in sys.argv:
        PassiveOSFingerprinter().run()
    else:
        print("Usage: python intelligence.py "
              "[--oui <mac> | --cve <model> | --ports <ip> | --osfingerprint]")
