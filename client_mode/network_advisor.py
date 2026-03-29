"""
OmniFi — Network Advisor
=========================
Scans all visible Wi-Fi networks and scores each one across 7 security
vectors to recommend which network is safest to connect to.

Scoring vectors (total 100 pts):
  1. Encryption protocol   — 30 pts  (WPA3 > WPA2 > WPA > WEP > Open)
  2. No rogue / evil twin  — 20 pts  (unique BSSID per SSID)
  3. Signal strength       — 15 pts  (RSSI -50dBm=15, -90dBm=2)
  4. PMF / 802.11w         — 10 pts  (management frame protection)
  5. WPS disabled          — 10 pts  (WPS IE absent in beacon)
  6. No DNS anomaly        —  8 pts  (post-join only)
  7. No ARP anomaly        —  7 pts  (post-join only)

Pre-join  : vectors 1–5 scored (max 85 pts → scaled to 100)
Post-join : all 7 vectors scored (full 100 pts)
"""

import re
import time
import socket
import subprocess
import platform
from dataclasses import dataclass, field
from typing import Optional
import concurrent.futures

# Optional imports — gracefully handled if not installed
try:
    import pywifi
    from pywifi import const as wifi_const
    PYWIFI_AVAILABLE = True
except ImportError:
    PYWIFI_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class NetworkProfile:
    ssid:            str   = ""
    bssid:           str   = ""
    signal_dbm:      int   = -100
    frequency_mhz:   int   = 0
    channel:         int   = 0

    # Security properties (parsed from scan)
    auth_protocol:   str   = "unknown"   # wpa3 / wpa2 / wpa / wep / open
    pmf_enabled:     bool  = False
    wps_enabled:     bool  = False
    is_hidden:       bool  = False

    # Threat flags
    is_evil_twin:    bool  = False
    evil_twin_of:    str   = ""          # SSID this is a twin of
    is_rogue_ap:     bool  = False

    # Scores (0–100)
    score_encryption:  int = 0
    score_evil_twin:   int = 0
    score_signal:      int = 0
    score_pmf:         int = 0
    score_wps:         int = 0
    score_dns:         int = 0   # post-join only
    score_arp:         int = 0   # post-join only

    total_score:       int = 0
    verdict:           str = ""   # safe / acceptable / caution / avoid / evil_twin
    issues:            list = field(default_factory=list)
    recommendations:   list = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Score bands
# ─────────────────────────────────────────────────────────────────────────────

SCORE_BANDS = [
    (80, 100, "safe",        "Safe to connect"),
    (60,  79, "acceptable",  "Acceptable — use VPN for sensitive tasks"),
    (40,  59, "caution",     "Use with caution — VPN strongly advised"),
    (0,   39, "avoid",       "Avoid — high security risk"),
]

VERDICT_COLORS = {
    "safe":       "\033[92m",   # green
    "acceptable": "\033[94m",   # blue
    "caution":    "\033[93m",   # yellow
    "avoid":      "\033[91m",   # red
    "evil_twin":  "\033[91m",   # red
}

RESET = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
CYAN  = "\033[96m"
YELLOW= "\033[93m"


# ─────────────────────────────────────────────────────────────────────────────
# Main advisor class
# ─────────────────────────────────────────────────────────────────────────────

class NetworkAdvisor:
    """
    Scans visible Wi-Fi networks, scores each on security vectors,
    and recommends the safest network to connect to.
    """

    def __init__(self, verbose: bool = True, post_join_checks: bool = False):
        self.verbose          = verbose
        self.post_join_checks = post_join_checks
        self.networks: list[NetworkProfile] = []

    # ── Public entry point ────────────────────────────────────────────────────

    def run(self) -> list[NetworkProfile]:
        self._print("\n[OmniFi] Network Advisor — scanning visible networks...\n")

        # Step 1 — scan all visible networks
        raw_networks = self._scan_networks()
        if not raw_networks:
            self._print("[!] No networks found. Check that Wi-Fi is enabled.")
            return []

        self._print(f"  Found {len(raw_networks)} network(s).\n")

        # Step 2 — detect evil twins / rogue APs across scan results
        raw_networks = self._detect_evil_twins(raw_networks)

        # Step 3 — score each network
        for net in raw_networks:
            self._score_network(net)

        # Step 4 — optional post-join checks (DNS + ARP)
        # These only run if caller specifies post_join_checks=True
        # and the user is already connected to one of these networks
        if self.post_join_checks:
            self._run_post_join_checks(raw_networks)

        # Step 5 — sort by score descending
        raw_networks.sort(key=lambda n: n.total_score, reverse=True)
        self.networks = raw_networks

        # Step 6 — display results
        self._display_results()

        return self.networks

    # ── Step 1 : scan ─────────────────────────────────────────────────────────

    def _scan_networks(self) -> list[NetworkProfile]:
        """Try pywifi first, fall back to OS commands."""
        if PYWIFI_AVAILABLE:
            nets = self._scan_pywifi()
            if nets:
                return nets

        return self._scan_os_command()

    def _scan_pywifi(self) -> list[NetworkProfile]:
        try:
            wifi = pywifi.PyWiFi()
            iface = wifi.interfaces()[0]
            iface.scan()
            time.sleep(2.5)   # wait for scan results
            results = iface.scan_results()

            networks = []
            for ap in results:
                net = NetworkProfile()
                net.ssid       = ap.ssid or "(hidden)"
                net.bssid      = ap.bssid or ""
                net.signal_dbm = ap.signal
                net.is_hidden  = not bool(ap.ssid)

                # Auth protocol from pywifi akm list
                if hasattr(ap, 'akm') and ap.akm:
                    akm = ap.akm[0]
                    if akm == wifi_const.AKM_TYPE_WPA2PSK:
                        net.auth_protocol = "wpa2"
                    elif akm == wifi_const.AKM_TYPE_WPAPSK:
                        net.auth_protocol = "wpa"
                    elif akm == wifi_const.AKM_TYPE_NONE:
                        net.auth_protocol = "open"
                    else:
                        net.auth_protocol = "wpa2"   # default assumption

                networks.append(net)
            return networks
        except Exception:
            return []

    def _scan_os_command(self) -> list[NetworkProfile]:
        """OS-level scan fallback."""
        system = platform.system()
        if system == "Linux":
            return self._scan_linux()
        elif system == "Windows":
            return self._scan_windows()
        elif system == "Darwin":
            return self._scan_macos()
        return []

    def _scan_linux(self) -> list[NetworkProfile]:
        networks = []
        try:
            # Try nmcli (NetworkManager)
            out = subprocess.check_output(
                ["nmcli", "-t", "-f",
                 "SSID,BSSID,SIGNAL,SECURITY,FREQ",
                 "dev", "wifi", "list", "--rescan", "yes"],
                text=True, stderr=subprocess.DEVNULL
            )
            for line in out.strip().splitlines():
                parts = line.split(":")
                if len(parts) < 4:
                    continue
                net = NetworkProfile()
                net.ssid       = parts[0].strip() or "(hidden)"
                net.bssid      = parts[1].strip().replace("\\:", ":")
                net.signal_dbm = self._signal_percent_to_dbm(int(parts[2])) if parts[2].isdigit() else -80
                security       = parts[3].strip().lower()
                net.auth_protocol = self._parse_security_string(security)
                net.frequency_mhz = int(parts[4].replace("MHz","").strip()) if len(parts) > 4 and parts[4].strip().replace("MHz","").isdigit() else 0
                net.wps_enabled   = "wps" in security
                networks.append(net)

        except (subprocess.CalledProcessError, FileNotFoundError):
            try:
                # Fallback: iwlist scan
                iface = self._get_wifi_interface_linux()
                out = subprocess.check_output(
                    ["sudo", "iwlist", iface, "scan"],
                    text=True, stderr=subprocess.DEVNULL
                )
                networks = self._parse_iwlist_output(out)
            except Exception:
                pass
        return networks

    def _parse_iwlist_output(self, raw: str) -> list[NetworkProfile]:
        networks = []
        current = None
        for line in raw.splitlines():
            line = line.strip()
            if "Cell" in line and "Address" in line:
                if current:
                    networks.append(current)
                current = NetworkProfile()
                m = re.search(r"Address:\s*([\w:]+)", line)
                if m:
                    current.bssid = m.group(1)
            if not current:
                continue
            if "ESSID:" in line:
                m = re.search(r'ESSID:"(.*?)"', line)
                current.ssid = m.group(1) if m else "(hidden)"
            elif "Signal level=" in line:
                m = re.search(r"Signal level=(-?\d+)", line)
                if m:
                    current.signal_dbm = int(m.group(1))
            elif "Frequency:" in line:
                m = re.search(r"Frequency:([\d.]+)", line)
                if m:
                    current.frequency_mhz = int(float(m.group(1)) * 1000)
            elif "Encryption key:" in line:
                if "off" in line.lower():
                    current.auth_protocol = "open"
            elif "WPA2" in line:
                current.auth_protocol = "wpa2"
            elif "WPA" in line and current.auth_protocol != "wpa2":
                current.auth_protocol = "wpa"
            elif "WPS" in line:
                current.wps_enabled = True
            elif "IEEE 802.11w" in line or "MFP" in line:
                current.pmf_enabled = True

        if current:
            networks.append(current)
        return networks

    def _scan_windows(self) -> list[NetworkProfile]:
        networks = []
        try:
            out = subprocess.check_output(
                ["netsh", "wlan", "show", "networks", "mode=Bssid"],
                text=True, stderr=subprocess.DEVNULL
            )
            blocks = re.split(r"SSID \d+ :", out)[1:]
            for block in blocks:
                net = NetworkProfile()
                m = re.search(r"^\s*(.+)", block)
                net.ssid = m.group(1).strip() if m else "(hidden)"
                m = re.search(r"BSSID\s+:\s*([\w:]+)", block)
                if m:
                    net.bssid = m.group(1)
                m = re.search(r"Signal\s*:\s*(\d+)%", block)
                if m:
                    net.signal_dbm = self._signal_percent_to_dbm(int(m.group(1)))
                auth = re.search(r"Authentication\s*:\s*(.+)", block)
                if auth:
                    net.auth_protocol = self._parse_security_string(auth.group(1).strip().lower())
                networks.append(net)
        except Exception:
            pass
        return networks

    def _scan_macos(self) -> list[NetworkProfile]:
        networks = []
        try:
            airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
            out = subprocess.check_output([airport, "-s"],
                                          text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines()[1:]:
                parts = line.split()
                if len(parts) < 3:
                    continue
                net = NetworkProfile()
                net.ssid       = parts[0]
                net.bssid      = parts[1]
                net.signal_dbm = int(parts[2]) if parts[2].lstrip("-").isdigit() else -80
                security       = " ".join(parts[6:]).lower() if len(parts) > 6 else ""
                net.auth_protocol = self._parse_security_string(security)
                networks.append(net)
        except Exception:
            pass
        return networks

    # ── Step 2 : evil twin detection ─────────────────────────────────────────

    def _detect_evil_twins(self, networks: list[NetworkProfile]) -> list[NetworkProfile]:
        """
        Flag networks where the same SSID appears with multiple BSSIDs.
        The one with weaker signal or newer appearance is flagged as suspect.
        """
        ssid_map: dict[str, list[NetworkProfile]] = {}
        for net in networks:
            if net.ssid and net.ssid != "(hidden)":
                ssid_map.setdefault(net.ssid, []).append(net)

        for ssid, nets in ssid_map.items():
            if len(nets) > 1:
                # Sort by signal — strongest is likely the legitimate AP
                nets.sort(key=lambda n: n.signal_dbm, reverse=True)
                legitimate = nets[0]
                for suspect in nets[1:]:
                    suspect.is_evil_twin = True
                    suspect.evil_twin_of = ssid
                    suspect.issues.append(
                        f"Possible evil twin — same SSID '{ssid}' with different BSSID "
                        f"({suspect.bssid} vs legitimate {legitimate.bssid})"
                    )

        return networks

    # ── Step 3 : score each network ───────────────────────────────────────────

    def _score_network(self, net: NetworkProfile):

        # ── Evil twin — override all scoring ─────────────────────────────────
        if net.is_evil_twin:
            net.total_score = 5
            net.verdict     = "evil_twin"
            net.issues.append("Do NOT connect — this is likely a deception attack.")
            net.recommendations.append(
                "Connect to the legitimate AP with BSSID: " + net.evil_twin_of
            )
            return

        # ── Vector 1 : encryption (30 pts) ───────────────────────────────────
        enc_map = {"wpa3": 30, "wpa2": 20, "wpa": 8, "wep": 2, "open": 0}
        net.score_encryption = enc_map.get(net.auth_protocol, 10)

        if net.auth_protocol == "open":
            net.issues.append("No encryption — all traffic visible to anyone nearby.")
            net.recommendations.append("Avoid or use VPN for all traffic.")
        elif net.auth_protocol == "wep":
            net.issues.append("WEP encryption — crackable in minutes. Treat as open network.")
            net.recommendations.append("Use VPN. Ask admin to upgrade to WPA2/WPA3.")
        elif net.auth_protocol == "wpa":
            net.issues.append("WPA (TKIP) — outdated. Vulnerable to several known attacks.")
        elif net.auth_protocol == "wpa2":
            pass  # acceptable
        elif net.auth_protocol == "wpa3":
            net.recommendations.append("WPA3 — strongest available encryption.")

        # ── Vector 2 : no rogue / evil twin (20 pts) ─────────────────────────
        net.score_evil_twin = 0 if net.is_evil_twin or net.is_rogue_ap else 20

        # ── Vector 3 : signal strength (15 pts) ──────────────────────────────
        # RSSI -50 dBm = excellent, -90 dBm = very weak
        rssi = net.signal_dbm
        if rssi >= -55:
            net.score_signal = 15
        elif rssi >= -65:
            net.score_signal = 12
        elif rssi >= -75:
            net.score_signal = 8
        elif rssi >= -85:
            net.score_signal = 4
        else:
            net.score_signal = 1
            net.issues.append(f"Very weak signal ({rssi} dBm) — unstable connection likely.")

        # ── Vector 4 : PMF / 802.11w (10 pts) ────────────────────────────────
        net.score_pmf = 10 if net.pmf_enabled else 0
        if not net.pmf_enabled:
            net.issues.append("PMF (802.11w) not detected — deauthentication attacks possible.")
            net.recommendations.append("Prefer networks with WPA3 or PMF enabled.")

        # ── Vector 5 : WPS disabled (10 pts) ─────────────────────────────────
        net.score_wps = 0 if net.wps_enabled else 10
        if net.wps_enabled:
            net.issues.append("WPS is enabled — PIN brute-force attack possible.")
            net.recommendations.append("Ask admin to disable WPS in router settings.")

        # ── Vectors 6 & 7 : DNS + ARP (post-join, default 0) ─────────────────
        # These are set by _run_post_join_checks() if post_join_checks=True
        # Pre-join: scale 85 pts to 100
        pre_join_raw = (
            net.score_encryption +
            net.score_evil_twin  +
            net.score_signal     +
            net.score_pmf        +
            net.score_wps
        )
        if not self.post_join_checks:
            net.total_score = int((pre_join_raw / 85) * 100)
        else:
            net.total_score = min(100,
                pre_join_raw + net.score_dns + net.score_arp
            )

        # ── Assign verdict ────────────────────────────────────────────────────
        for low, high, label, _ in SCORE_BANDS:
            if low <= net.total_score <= high:
                net.verdict = label
                break

    # ── Step 4 : post-join checks ─────────────────────────────────────────────

    def _run_post_join_checks(self, networks: list[NetworkProfile]):
        """
        DNS spoofing and ARP checks — only meaningful for the
        currently connected network.
        """
        current_ssid = self._get_current_ssid()
        if not current_ssid:
            return

        for net in networks:
            if net.ssid == current_ssid:
                self._print(f"  Running post-join checks on '{net.ssid}'...")
                net.score_dns = self._check_dns(net)
                net.score_arp = self._check_arp(net)

    def _check_dns(self, net: NetworkProfile) -> int:
        """Compare local DNS answer vs DoH (Cloudflare). Returns 0–8."""
        if not REQUESTS_AVAILABLE:
            return 4  # neutral if requests not available

        test_domain = "google.com"
        try:
            # Local DNS resolution
            local_ip = socket.gethostbyname(test_domain)

            # DoH query via Cloudflare
            r = requests.get(
                f"https://cloudflare-dns.com/dns-query?name={test_domain}&type=A",
                headers={"Accept": "application/dns-json"},
                timeout=4
            )
            doh_data = r.json()
            doh_ips = [a["data"] for a in doh_data.get("Answer", [])
                       if a.get("type") == 1]

            if local_ip in doh_ips:
                self._print(f"    [+] DNS check passed — local and DoH answers match.")
                return 8
            else:
                net.issues.append(
                    f"DNS anomaly: local resolution of {test_domain} → {local_ip}, "
                    f"DoH returns {doh_ips}. Possible DNS spoofing."
                )
                net.recommendations.append("Switch to DoH/DoT resolver (1.1.1.1 or 8.8.8.8).")
                self._print(f"    [!] DNS mismatch detected!")
                return 0

        except Exception:
            return 4   # neutral on error

    def _check_arp(self, net: NetworkProfile) -> int:
        """Check gateway MAC consistency. Returns 0–7."""
        try:
            gw_ip = self._get_gateway_ip()
            if not gw_ip:
                return 4

            # ARP table lookup
            if platform.system() == "Windows":
                out = subprocess.check_output(["arp", "-a", gw_ip],
                                              text=True, stderr=subprocess.DEVNULL)
            else:
                out = subprocess.check_output(["arp", "-n", gw_ip],
                                              text=True, stderr=subprocess.DEVNULL)

            mac_matches = re.findall(
                r"([0-9a-f]{2}[:\-][0-9a-f]{2}[:\-][0-9a-f]{2}[:\-]"
                r"[0-9a-f]{2}[:\-][0-9a-f]{2}[:\-][0-9a-f]{2})",
                out, re.IGNORECASE
            )

            if not mac_matches:
                return 4

            # Check for multiple MACs for gateway IP — ARP poisoning indicator
            unique_macs = set(m.upper() for m in mac_matches)
            if len(unique_macs) > 1:
                net.issues.append(
                    f"ARP anomaly: multiple MACs for gateway {gw_ip} — "
                    f"possible ARP poisoning / MITM attack."
                )
                net.recommendations.append(
                    "Do not conduct sensitive activities on this network."
                )
                self._print(f"    [!] ARP anomaly detected for gateway {gw_ip}!")
                return 0

            self._print(f"    [+] ARP check passed — gateway MAC consistent.")
            return 7

        except Exception:
            return 4

    # ── Display ────────────────────────────────────────────────────────────────

    def _display_results(self):
        print("\n" + "─" * 64)
        print(f"  {BOLD}OmniFi — Network Security Advisor{RESET}")
        print("─" * 64)

        if not self.networks:
            print("  No networks to display.\n")
            return

        best = self.networks[0]

        for i, net in enumerate(self.networks):
            color   = VERDICT_COLORS.get(net.verdict, "")
            bar_len = net.total_score // 5   # max 20 chars
            bar     = "█" * bar_len + "░" * (20 - bar_len)
            freq_band = "5GHz" if net.frequency_mhz >= 5000 else "2.4GHz" if net.frequency_mhz > 0 else ""

            print(f"\n  {BOLD}{i+1}. {net.ssid}{RESET}"
                  f"  {DIM}{net.bssid}  {freq_band}  {net.signal_dbm}dBm{RESET}")
            print(f"     {color}{bar}  {net.total_score}/100  {net.verdict.upper()}{RESET}")
            print(f"     Protocol: {net.auth_protocol.upper()}"
                  f"  |  PMF: {'Yes' if net.pmf_enabled else 'No'}"
                  f"  |  WPS: {'ON' if net.wps_enabled else 'Off'}")

            if net.issues:
                for issue in net.issues[:2]:
                    print(f"     {YELLOW}[!] {issue}{RESET}")

        print("\n" + "─" * 64)

        # Recommendation
        if best.verdict in ("safe", "acceptable"):
            print(f"\n  {BOLD}Recommended:{RESET} Connect to "
                  f"{CYAN}{best.ssid}{RESET} "
                  f"(score {best.total_score}/100 — {best.verdict})")
        elif best.verdict == "caution":
            print(f"\n  {YELLOW}{BOLD}Caution:{RESET} Best available is "
                  f"{CYAN}{best.ssid}{RESET} "
                  f"(score {best.total_score}/100). Use VPN for all traffic.")
        else:
            print(f"\n  {BOLD}\033[91mWarning:{RESET} No safe network found. "
                  f"Consider using mobile data instead.")

        # Score breakdown for top network
        print(f"\n  Score breakdown — {best.ssid}:")
        print(f"    Encryption  : {best.score_encryption}/30")
        print(f"    No evil twin: {best.score_evil_twin}/20")
        print(f"    Signal      : {best.score_signal}/15")
        print(f"    PMF         : {best.score_pmf}/10")
        print(f"    WPS off     : {best.score_wps}/10")
        if self.post_join_checks:
            print(f"    DNS clean   : {best.score_dns}/8")
            print(f"    ARP clean   : {best.score_arp}/7")
        print()

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _parse_security_string(self, s: str) -> str:
        s = s.lower()
        if "wpa3" in s or "sae"  in s:  return "wpa3"
        if "wpa2" in s or "rsn"  in s:  return "wpa2"
        if "wpa"  in s:                  return "wpa"
        if "wep"  in s:                  return "wep"
        if "open" in s or "none" in s:   return "open"
        return "unknown"

    def _signal_percent_to_dbm(self, percent: int) -> int:
        """Convert Windows/nmcli 0–100% signal to approximate dBm."""
        percent = max(0, min(100, percent))
        return int((percent / 2) - 100)

    def _get_gateway_ip(self) -> Optional[str]:
        try:
            if platform.system() == "Windows":
                out = subprocess.check_output(["ipconfig"], text=True,
                                              stderr=subprocess.DEVNULL)
                m = re.search(r"Default Gateway.*?:\s*([\d.]+)", out)
                return m.group(1) if m else None
            else:
                out = subprocess.check_output(["ip", "route"], text=True,
                                              stderr=subprocess.DEVNULL)
                m = re.search(r"default via ([\d.]+)", out)
                return m.group(1) if m else None
        except Exception:
            return None

    def _get_wifi_interface_linux(self) -> str:
        try:
            out = subprocess.check_output(["iw", "dev"], text=True,
                                          stderr=subprocess.DEVNULL)
            m = re.search(r"Interface\s+(\w+)", out)
            return m.group(1) if m else "wlan0"
        except Exception:
            return "wlan0"

    def _get_current_ssid(self) -> str:
        try:
            if platform.system() == "Windows":
                out = subprocess.check_output(
                    ["netsh", "wlan", "show", "interfaces"],
                    text=True, stderr=subprocess.DEVNULL)
                m = re.search(r"SSID\s+:\s(.+)", out)
                return m.group(1).strip() if m else ""
            else:
                out = subprocess.check_output(
                    ["iwgetid", "-r"], text=True, stderr=subprocess.DEVNULL)
                return out.strip()
        except Exception:
            return ""

    def _print(self, msg: str):
        if self.verbose:
            print(msg)


# ─────────────────────────────────────────────────────────────────────────────
# Quick demo — add mock networks for testing without real Wi-Fi scan
# ─────────────────────────────────────────────────────────────────────────────

def _demo_mode():
    """Demo with mock networks for testing scoring logic."""
    print("\n[OmniFi] Running in demo mode with mock network data...\n")

    mock_networks = [
        NetworkProfile(ssid="HomeNetwork_5G",    bssid="AA:BB:CC:DD:EE:01",
                       signal_dbm=-58, auth_protocol="wpa3",
                       pmf_enabled=True,  wps_enabled=False,
                       frequency_mhz=5180),
        NetworkProfile(ssid="JioFiber_7A2B",     bssid="AA:BB:CC:DD:EE:02",
                       signal_dbm=-71, auth_protocol="wpa2",
                       pmf_enabled=False, wps_enabled=True,
                       frequency_mhz=2437),
        NetworkProfile(ssid="Airtel_Xstream_4563", bssid="AA:BB:CC:DD:EE:03",
                       signal_dbm=-65, auth_protocol="wpa2",
                       pmf_enabled=False, wps_enabled=False,
                       frequency_mhz=5240),
        NetworkProfile(ssid="CafeWiFi_Free",     bssid="AA:BB:CC:DD:EE:04",
                       signal_dbm=-55, auth_protocol="open",
                       pmf_enabled=False, wps_enabled=False,
                       frequency_mhz=2412),
        # Evil twin of HomeNetwork
        NetworkProfile(ssid="HomeNetwork_5G",    bssid="FF:EE:DD:CC:BB:05",
                       signal_dbm=-48, auth_protocol="wpa2",
                       pmf_enabled=False, wps_enabled=False,
                       frequency_mhz=2437),
    ]

    advisor = NetworkAdvisor(verbose=True, post_join_checks=False)
    mock_networks = advisor._detect_evil_twins(mock_networks)
    for net in mock_networks:
        advisor._score_network(net)
    mock_networks.sort(key=lambda n: n.total_score, reverse=True)
    advisor.networks = mock_networks
    advisor._display_results()
    return mock_networks


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    if "--demo" in sys.argv:
        _demo_mode()
    else:
        advisor = NetworkAdvisor(verbose=True, post_join_checks=False)
        advisor.run()
