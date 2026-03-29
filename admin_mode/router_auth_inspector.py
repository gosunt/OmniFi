"""
OmniFi — Router Auth Inspector
================================
Purpose : Detect the connected router's ISP/brand, probe its admin
          panel, attempt known default credentials, and if those fail,
          ask the admin for their credentials — all in service of
          auditing the router's security posture.

Ethical scope : This module only targets the gateway IP of the network
                the device is CURRENTLY connected to.  It is an auditor,
                not an attacker.  Default-credential attempts are done
                solely to alert the owner that their router is insecure.

Usage:
    from admin_mode.router_auth_inspector import RouterAuthInspector
    inspector = RouterAuthInspector()
    result    = inspector.run()
"""

import re
import time
import socket
import subprocess
import platform
import getpass
from dataclasses import dataclass, field
from typing import Optional

import requests
from bs4 import BeautifulSoup

# Suppress InsecureRequestWarning for self-signed router certs
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)


# ─────────────────────────────────────────────────────────────────────────────
# India ISP / Router hardware database
# ─────────────────────────────────────────────────────────────────────────────

INDIA_ISP_DB = {

    # ── Fiber ISPs ────────────────────────────────────────────────────────────

    "jiofiber": {
        "name": "JioFiber",
        "gateways": ["192.168.29.1", "192.168.31.1"],
        "hostnames": [],
        "ports": [80, 8080],
        "fingerprints": ["Jio Centrum", "JioCentrum", "jiocentrum", "jio centrum"],
        "default_creds": [("admin", "Jiocentrum"), ("admin", "admin")],
        "auth_type": "form",
        "login_fields": {"username": "username", "password": "password"},
        "login_url_hint": "/login.html",
        "notes": "Newer firmware forces password change on first login via JioHome app"
    },
    "jioairfiber": {
        "name": "JioAirFiber",
        "gateways": ["192.168.31.1"],
        "hostnames": [],
        "ports": [80],
        "fingerprints": ["JioAirFiber", "Jio Air Fiber", "airfiber"],
        "default_creds": [],
        "auth_type": "form",
        "login_fields": {"username": "username", "password": "password"},
        "login_url_hint": "/login.html",
        "notes": "Password set via JioHome app on first boot; no known default"
    },
    "jiofi_dongle": {
        "name": "JioFi MiFi Dongle",
        "gateways": ["192.168.1.1"],
        "hostnames": ["jiofi.local.html"],
        "ports": [80],
        "fingerprints": ["JioFi", "jiofi", "JIO Fi"],
        "default_creds": [
            ("admin", "admin"),
            ("administrator", "administrator"),
            ("admin", ""),
        ],
        "auth_type": "form",
        "login_fields": {"username": "username", "password": "password"},
        "login_url_hint": "/",
        "notes": "Dedicated 4G MiFi dongle; web panel always exposed on HTTP"
    },
    "airtel": {
        "name": "Airtel Xstream Fiber",
        "gateways": ["192.168.1.1", "192.168.0.1", "10.0.0.1"],
        "hostnames": [],
        "ports": [80, 8080],
        "fingerprints": [
            "HG8145", "HG8240", "HG8145V5", "HG8145X6",
            "G-240W", "G-010G", "EchoLife",
            "Airtel", "Xstream",
            "Nokia", "Huawei",
        ],
        "default_creds": [
            ("admin",       "admin"),
            ("telecomadmin","admintelecom"),
            ("admin",       ""),
            ("user",        "user"),
        ],
        "auth_type": "form",
        "login_fields": {"username": "Username", "password": "Password"},
        "login_url_hint": "/",
        "notes": "ONT hardware is Huawei or Nokia; model determines exact panel"
    },
    "bsnl_ftth": {
        "name": "BSNL FTTH",
        "gateways": ["192.168.1.1", "192.168.0.1"],
        "hostnames": [],
        "ports": [80],
        "fingerprints": ["Netlink", "NETLINK", "BSNL", "DASAN", "Zhone", "Syrotech", "stdONU"],
        "default_creds": [
            ("admin",  "admin"),
            ("admin",  "stdONU101"),
            ("admin",  "bsnl@1234"),
            ("admin",  "12345678"),
            ("admin",  "1234"),
        ],
        "auth_type": "form_or_basic",
        "login_fields": {"username": "username", "password": "password"},
        "login_url_hint": "/",
        "notes": "Netlink is most common ONT; password printed on back sticker"
    },
    "bsnl_adsl": {
        "name": "BSNL ADSL / WiMAX (Legacy)",
        "gateways": ["192.168.1.1", "192.168.0.1"],
        "hostnames": [],
        "ports": [80],
        "fingerprints": ["ADSL", "BSNL Broadband", "DSL Modem", "Broadband Router"],
        "default_creds": [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "1234"),
        ],
        "auth_type": "http_basic",
        "login_fields": {},
        "login_url_hint": "/",
        "notes": "HTTP Basic Auth — credentials sent as Base64, highest risk"
    },
    "act": {
        "name": "ACT Fibernet",
        "gateways": ["192.168.1.1", "192.168.0.1", "10.0.0.10"],
        "hostnames": ["tplinkwifi.net"],
        "ports": [80, 8080],
        "fingerprints": ["ACT Fibernet", "tplinkwifi", "TP-LINK", "TP-Link", "D-Link", "Tenda"],
        "default_creds": [
            ("admin", "admin"),
            ("admin", ""),
        ],
        "auth_type": "form",
        "login_fields": {"username": "username", "password": "password"},
        "login_url_hint": "/",
        "notes": "Uses TP-Link/D-Link/Tenda hardware; brand varies by city"
    },
    "tataplay": {
        "name": "Tata Play Fiber",
        "gateways": ["192.168.1.254", "192.168.1.1"],
        "hostnames": [],
        "ports": [80],
        "fingerprints": ["Tata Play", "Tata Sky Broadband", "Tata Play Fiber"],
        "default_creds": [
            ("admin", "admin"),
            ("admin", "password"),
        ],
        "auth_type": "form",
        "login_fields": {"username": "username", "password": "password"},
        "login_url_hint": "/",
        "notes": "192.168.1.254 gateway is a distinctive Tata Play identifier"
    },
    "hathway": {
        "name": "Hathway",
        "gateways": ["192.168.1.1", "192.168.100.1"],
        "hostnames": [],
        "ports": [80],
        "fingerprints": ["Hathway"],
        "default_creds": [
            ("admin", "admin"),
            ("admin", "password"),
        ],
        "auth_type": "form",
        "login_fields": {"username": "username", "password": "password"},
        "login_url_hint": "/",
        "notes": "Cable ISP; 192.168.100.1 used on older cable installations"
    },
    "excitel": {
        "name": "Excitel",
        "gateways": ["192.168.0.1", "192.168.1.1", "10.0.0.1"],
        "hostnames": [],
        "ports": [80],
        "fingerprints": ["excitel", "Excitel"],
        "default_creds": [
            ("excitel", "exc@123"),
            ("excitel", "[email protected]"),
            ("admin",   "admin"),
        ],
        "auth_type": "form",
        "login_fields": {"username": "username", "password": "password"},
        "login_url_hint": "/",
        "notes": "Two-tier: user-level login vs ISP super-admin (TR-069 retained)"
    },
    "railwire": {
        "name": "RailWire (RAILTEL)",
        "gateways": ["192.168.1.1"],
        "hostnames": [],
        "ports": [80],
        "fingerprints": ["RailWire", "RAILTEL", "Rail Wire", "Railwire"],
        "default_creds": [
            ("admin", "admin"),
        ],
        "auth_type": "form",
        "login_fields": {"username": "username", "password": "password"},
        "login_url_hint": "/",
        "notes": "Railway broadband; mostly standard ONT hardware"
    },
    "you_broadband": {
        "name": "YOU Broadband",
        "gateways": ["192.168.1.1", "192.168.0.1"],
        "hostnames": [],
        "ports": [80],
        "fingerprints": ["YOU Broadband", "you broadband", "YouBroadband"],
        "default_creds": [
            ("admin", "admin"),
        ],
        "auth_type": "form",
        "login_fields": {"username": "username", "password": "password"},
        "login_url_hint": "/",
        "notes": "Gujarat/Maharashtra; acquired by Vodafone Idea"
    },
    "spectranet": {
        "name": "Spectranet",
        "gateways": ["192.168.1.1", "10.1.1.1"],
        "hostnames": [],
        "ports": [80],
        "fingerprints": ["Spectranet"],
        "default_creds": [
            ("admin", "admin"),
        ],
        "auth_type": "form",
        "login_fields": {"username": "username", "password": "password"},
        "login_url_hint": "/",
        "notes": "NCR/enterprise focus; 10.x gateway is distinctive"
    },
    "tikona": {
        "name": "Tikona Digital Networks",
        "gateways": ["192.168.1.1"],
        "hostnames": [],
        "ports": [80],
        "fingerprints": ["Tikona", "Tikona Digital"],
        "default_creds": [
            ("admin", "admin"),
        ],
        "auth_type": "form_or_basic",
        "login_fields": {"username": "username", "password": "password"},
        "login_url_hint": "/",
        "notes": "Fixed wireless ISP; some older CPE models use HTTP Basic"
    },
    "mtnl": {
        "name": "MTNL (Delhi / Mumbai)",
        "gateways": ["192.168.1.1", "192.168.0.1"],
        "hostnames": [],
        "ports": [80],
        "fingerprints": ["MTNL", "Triband", "mtnl"],
        "default_creds": [
            ("admin", "admin"),
            ("admin", "password"),
        ],
        "auth_type": "http_basic",
        "login_fields": {},
        "login_url_hint": "/",
        "notes": "Very old firmware common; HTTP Basic most frequent auth method"
    },

    # ── Mobile hotspots ───────────────────────────────────────────────────────

    "android_hotspot": {
        "name": "Android Phone Hotspot",
        "gateways": ["192.168.43.1", "192.168.49.1"],
        "hostnames": [],
        "ports": [],                        # no web panel
        "fingerprints": [],
        "default_creds": [],
        "auth_type": "none",
        "login_fields": {},
        "login_url_hint": "",
        "notes": "No admin panel; managed via Android Settings only — low risk"
    },
    "ios_hotspot": {
        "name": "iPhone Personal Hotspot",
        "gateways": ["172.20.10.1"],
        "hostnames": [],
        "ports": [],                        # no web panel
        "fingerprints": [],
        "default_creds": [],
        "auth_type": "none",
        "login_fields": {},
        "login_url_hint": "",
        "notes": "172.20.10.x subnet uniquely identifies iOS hotspot — low risk"
    },
    "airtel_dongle": {
        "name": "Airtel 4G Hotspot Dongle",
        "gateways": ["192.168.1.1"],
        "hostnames": [],
        "ports": [80],
        "fingerprints": ["Airtel 4G", "Airtel Hotspot", "airtel hotspot"],
        "default_creds": [
            ("admin", "admin"),
        ],
        "auth_type": "form",
        "login_fields": {"username": "username", "password": "password"},
        "login_url_hint": "/",
        "notes": "Dedicated 4G dongle; panel always HTTP, always exposed"
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RouterInfo:
    gateway_ip:        str             = ""
    isp_key:           str             = "unknown"
    isp_name:          str             = "Unknown"
    admin_url:         str             = ""
    auth_type:         str             = "unknown"
    uses_https:        bool            = False
    panel_reachable:   bool            = False
    open_panel:        bool            = False
    default_creds_work: bool           = False
    working_creds:     tuple           = ()
    admin_creds:       tuple           = ()
    alerts:            list = field(default_factory=list)
    risk_level:        str             = "low"     # low / medium / high / critical
    trust_score:       int             = 0
    session:           Optional[object] = None
    page_title:        str             = ""
    server_header:     str             = ""
    notes:             str             = ""


# ─────────────────────────────────────────────────────────────────────────────
# Main inspector class
# ─────────────────────────────────────────────────────────────────────────────

class RouterAuthInspector:
    """
    Detects the current router's ISP/brand, audits its admin panel auth
    mechanism, tries default credentials, and if those fail prompts the
    admin for credentials — then performs a full security audit.
    """

    TIMEOUT = 4       # seconds per HTTP request
    MAX_CRED_ATTEMPTS = 5   # rate-limit default-cred tries

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.info = RouterInfo()

    # ── public entry point ────────────────────────────────────────────────────

    def run(self) -> RouterInfo:
        self._print("\n[OmniFi] Router Auth Inspector starting...\n")

        # Step 1 — get gateway + identify provider
        self._step1_detect_provider()
        if not self.info.gateway_ip:
            self._alert("Could not determine gateway IP. Are you connected to Wi-Fi?", "high")
            return self.info

        # Step 2 — probe admin panel
        self._step2_probe_panel()
        if not self.info.panel_reachable:
            profile = INDIA_ISP_DB.get(self.info.isp_key, {})
            if not profile.get("ports"):
                self._print("[*] No web admin panel detected (phone hotspot). Low risk.")
            else:
                self._print("[*] Admin panel not reachable on standard ports.")
            return self.info

        # Step 3 — try default credentials
        self._step3_try_default_creds()

        # Step 4 — if default creds failed, ask admin
        if not self.info.default_creds_work and not self.info.open_panel:
            self._step4_ask_admin_creds()

        # Step 5 — full audit if we have access
        if self.info.default_creds_work or self.info.open_panel or self.info.admin_creds:
            self._step5_full_audit()

        self._compute_trust_score()
        self._print_summary()
        return self.info

    # ── Step 1 : detect provider ──────────────────────────────────────────────

    def _step1_detect_provider(self):
        self._print("[Step 1] Detecting gateway and ISP provider...")

        gw = self._get_gateway_ip()
        if not gw:
            return
        self.info.gateway_ip = gw
        self._print(f"  Gateway IP : {gw}")

        # Match gateway IP to ISP profile
        for key, profile in INDIA_ISP_DB.items():
            if gw in profile["gateways"]:
                self.info.isp_key  = key
                self.info.isp_name = profile["name"]
                self.info.notes    = profile.get("notes", "")
                self._print(f"  ISP match  : {profile['name']} (by gateway IP)")
                return

        # iOS hotspot subnet — 172.20.10.x
        if gw.startswith("172.20.10."):
            self.info.isp_key  = "ios_hotspot"
            self.info.isp_name = "iPhone Personal Hotspot"
            self._print("  ISP match  : iPhone Personal Hotspot (172.20.10.x subnet)")
            return

        self._print(f"  ISP match  : Unknown provider (will fingerprint via HTTP)")

    # ── Step 2 : probe admin panel ────────────────────────────────────────────

    def _step2_probe_panel(self):
        self._print("\n[Step 2] Probing admin panel...")

        profile = INDIA_ISP_DB.get(self.info.isp_key, {})
        ports   = profile.get("ports", [80, 8080, 443, 8443])

        if not ports:
            self._print("  No web panel expected for this network type.")
            return

        # Try hostnames first (e.g. jiofi.local.html, tplinkwifi.net)
        candidates = []
        for hostname in profile.get("hostnames", []):
            candidates += [(scheme, hostname, 80)
                           for scheme in ("http",)]
        for port in ports:
            for scheme in ("https", "http"):
                candidates.append((scheme, self.info.gateway_ip, port))

        for scheme, host, port in candidates:
            url = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"
            try:
                r = requests.get(url, timeout=self.TIMEOUT,
                                 verify=False, allow_redirects=True)

                self.info.panel_reachable = True
                self.info.admin_url       = url
                self.info.uses_https      = scheme == "https"
                self.info.server_header   = r.headers.get("Server", "")

                # Parse page title
                soup = BeautifulSoup(r.text, "html.parser")
                if soup.title:
                    self.info.page_title = soup.title.string or ""

                self._print(f"  Panel found : {url}")
                self._print(f"  Title       : {self.info.page_title}")
                self._print(f"  Server      : {self.info.server_header}")
                self._print(f"  HTTPS       : {self.info.uses_https}")

                # Fingerprint ISP from page content if still unknown
                if self.info.isp_key == "unknown":
                    self._fingerprint_from_page(r.text, r.headers)

                # Detect auth mechanism
                self._detect_auth_type(r, soup)
                return

            except (requests.ConnectionError, requests.Timeout):
                continue

    def _fingerprint_from_page(self, page_text: str, headers):
        combined = page_text + str(dict(headers))
        for key, profile in INDIA_ISP_DB.items():
            for fp in profile.get("fingerprints", []):
                if fp.lower() in combined.lower():
                    self.info.isp_key  = key
                    self.info.isp_name = profile["name"]
                    self.info.notes    = profile.get("notes", "")
                    self._print(f"  ISP refined : {profile['name']} (by page fingerprint: '{fp}')")
                    return

    def _detect_auth_type(self, response, soup):
        www_auth = response.headers.get("WWW-Authenticate", "")

        if "Basic" in www_auth:
            self.info.auth_type = "http_basic"
            self._alert("HTTP Basic Auth detected — password is Base64 encoded, trivially reversible!", "critical")

        elif "Digest" in www_auth:
            self.info.auth_type = "http_digest"
            self._alert("HTTP Digest Auth — MD5-based challenge-response. Weak by modern standards.", "medium")

        elif soup.find("input", {"type": "password"}):
            self.info.auth_type = "form"

            # Check if served over HTTP
            if not self.info.uses_https:
                self._alert("Admin panel uses form login over plain HTTP — credentials sent unencrypted!", "critical")

        else:
            # 200 with no challenge — open panel
            if response.status_code == 200:
                self.info.open_panel = True
                self._alert("CRITICAL: Router admin panel is accessible with NO authentication!", "critical")

        # Cookie flag checks
        for cookie in response.cookies:
            if not cookie.secure:
                self._alert(f"Session cookie '{cookie.name}' missing Secure flag.", "medium")

        self._print(f"  Auth type   : {self.info.auth_type}")

    # ── Step 3 : try default credentials ─────────────────────────────────────

    def _step3_try_default_creds(self):
        if self.info.open_panel:
            return

        profile = INDIA_ISP_DB.get(self.info.isp_key, {})
        creds   = profile.get("default_creds", [])

        if not creds:
            self._print("\n[Step 3] No known default credentials for this provider. Skipping.")
            return

        self._print(f"\n[Step 3] Trying {len(creds)} known default credential(s) for {self.info.isp_name}...")

        for i, (user, passwd) in enumerate(creds):
            if i >= self.MAX_CRED_ATTEMPTS:
                break
            time.sleep(0.5)   # polite rate-limit
            success = self._attempt_login(user, passwd)
            if success:
                self.info.default_creds_work = True
                self.info.working_creds      = (user, passwd)
                display_pass = "*" * len(passwd) if passwd else "(blank)"
                self._alert(
                    f"Default credentials WORK: username='{user}' password='{display_pass}'. "
                    f"Change your router password immediately!",
                    "critical"
                )
                self._print(f"  [!] Login succeeded with default creds: {user} / {display_pass}")
                return
            else:
                self._print(f"  [-] {user} / {'(blank)' if not passwd else '***'} — failed")

        self._print("  [+] Default credentials do not work. Good — password has been changed.")

    # ── Step 4 : ask admin for credentials ───────────────────────────────────

    def _step4_ask_admin_creds(self):
        self._print("\n[Step 4] Default credentials failed.")
        self._print(f"         To perform a full security audit of your {self.info.isp_name} router,")
        self._print(f"         OmniFi needs your router admin credentials.")
        self._print(f"         (These are the username/password for {self.info.admin_url})")
        self._print(f"         Your credentials are used locally only — never sent anywhere.\n")

        try:
            username = input("  Enter router admin username (or press Enter to skip): ").strip()
            if not username:
                self._print("  [*] Skipping admin credential entry. Full audit unavailable.")
                return

            password = getpass.getpass("  Enter router admin password: ")

            self._print("\n  Verifying credentials...")
            success = self._attempt_login(username, password)

            if success:
                self.info.admin_creds = (username, password)
                self._print("  [+] Credentials verified. Proceeding to full audit.")
            else:
                self._alert("Provided credentials did not work. Cannot perform full audit.", "low")
                self._print("  [-] Login failed with provided credentials.")

        except (KeyboardInterrupt, EOFError):
            self._print("\n  [*] Credential entry cancelled.")

    # ── Step 5 : full audit ───────────────────────────────────────────────────

    def _step5_full_audit(self):
        self._print("\n[Step 5] Running full router security audit...")

        url     = self.info.admin_url
        session = self.info.session or requests.Session()

        try:
            r = session.get(url, timeout=self.TIMEOUT, verify=False)
            content = r.text.lower()

            # ── WPS check ────────────────────────────────────────────────────
            if "wps" in content:
                if any(x in content for x in ["wps enable", "wps=1", "wps_enabled"]):
                    self._alert("WPS is ENABLED — vulnerable to Pixie Dust and brute-force attacks. Disable WPS.", "critical")
                else:
                    self._print("  [*] WPS settings found in panel (state unclear — manual check advised).")

            # ── Encryption / security mode ────────────────────────────────────
            if "wep" in content:
                self._alert("WEP encryption detected — WEP is completely broken. Upgrade to WPA2/WPA3.", "critical")
            if "wpa3" in content:
                self._print("  [+] WPA3 support detected.")
            elif "wpa2" in content:
                self._print("  [*] WPA2 in use — acceptable, but WPA3 is recommended.")

            # ── PMF / 802.11w ─────────────────────────────────────────────────
            if "802.11w" in content or "pmf" in content or "management frame" in content:
                if "disable" in content or "pmf=0" in content:
                    self._alert("Protected Management Frames (802.11w/PMF) is DISABLED — vulnerable to deauth attacks.", "high")
                else:
                    self._print("  [+] PMF / 802.11w is configured.")
            else:
                self._alert("PMF / 802.11w setting not found — deauth attack protection may be inactive.", "medium")

            # ── Remote management ─────────────────────────────────────────────
            if any(x in content for x in ["remote management", "wan access", "remote access"]):
                self._alert("Remote management may be enabled — allows router access from the internet.", "high")

            # ── DNS settings ──────────────────────────────────────────────────
            if "8.8.8.8" in r.text or "1.1.1.1" in r.text:
                self._print("  [+] Public DNS servers (Google/Cloudflare) configured.")
            elif "dns" in content:
                self._print("  [*] Custom DNS settings found — verify they point to trusted resolvers.")

            # ── Firmware version ──────────────────────────────────────────────
            fw_match = re.search(r'firmware[^\d]*(\d+\.\d+[\.\d]*)', r.text, re.IGNORECASE)
            if fw_match:
                self._print(f"  [*] Firmware version detected: {fw_match.group(1)} — check vendor site for updates.")

            # ── Guest network ─────────────────────────────────────────────────
            if "guest" in content:
                self._print("  [*] Guest network settings found — ensure it is properly isolated.")

        except Exception as e:
            self._print(f"  [!] Audit error during panel scrape: {e}")

    # ── Login attempt ─────────────────────────────────────────────────────────

    def _attempt_login(self, username: str, password: str) -> bool:
        """
        Try to log in using the detected auth method.
        Returns True if login appears successful.
        """
        url     = self.info.admin_url
        profile = INDIA_ISP_DB.get(self.info.isp_key, {})
        fields  = profile.get("login_fields", {"username": "username", "password": "password"})

        session = requests.Session()

        try:
            # ── HTTP Basic Auth ───────────────────────────────────────────────
            if self.info.auth_type == "http_basic":
                r = session.get(url, auth=(username, password),
                                timeout=self.TIMEOUT, verify=False)
                if r.status_code == 200:
                    self.info.session = session
                    return True
                return False

            # ── Form-based login ──────────────────────────────────────────────
            # First fetch the login page to grab CSRF token if present
            r0 = session.get(url, timeout=self.TIMEOUT, verify=False)
            soup = BeautifulSoup(r0.text, "html.parser")

            # Build POST payload from form fields
            payload = {}
            form = soup.find("form")
            if form:
                # Include all hidden inputs (CSRF tokens, etc.)
                for hidden in form.find_all("input", {"type": "hidden"}):
                    payload[hidden.get("name", "")] = hidden.get("value", "")
                # Detect actual field names from form
                for inp in form.find_all("input"):
                    inp_type = inp.get("type", "").lower()
                    inp_name = inp.get("name", "")
                    if inp_type == "text" or inp_type == "email":
                        payload[inp_name] = username
                    elif inp_type == "password":
                        payload[inp_name] = password

            # Fallback to profile-defined field names
            if not payload:
                payload = {
                    fields.get("username", "username"): username,
                    fields.get("password", "password"): password,
                }

            # Determine POST action URL
            action = url
            if form and form.get("action"):
                action_path = form.get("action")
                if action_path.startswith("http"):
                    action = action_path
                else:
                    action = f"{url.rstrip('/')}/{action_path.lstrip('/')}"

            r1 = session.post(action, data=payload,
                              timeout=self.TIMEOUT, verify=False,
                              allow_redirects=True)

            # Heuristic success detection
            success_signals = ["logout", "sign out", "dashboard", "status",
                                "connected devices", "wireless", "reboot"]
            fail_signals    = ["invalid", "incorrect", "wrong password",
                                "login failed", "error", "try again"]

            content_lower = r1.text.lower()

            if any(s in content_lower for s in success_signals):
                self.info.session = session
                return True
            if any(s in content_lower for s in fail_signals):
                return False

            # Status-code fallback
            if r1.status_code == 200 and len(r1.text) > len(r0.text):
                self.info.session = session
                return True

        except Exception:
            pass

        return False

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get_gateway_ip(self) -> Optional[str]:
        """Read the default gateway IP from the OS routing table."""
        system = platform.system()
        try:
            if system == "Windows":
                out = subprocess.check_output(
                    ["ipconfig"], text=True, stderr=subprocess.DEVNULL)
                match = re.search(r"Default Gateway.*?:\s*([\d.]+)", out)
                return match.group(1) if match else None
            else:
                out = subprocess.check_output(
                    ["ip", "route"], text=True, stderr=subprocess.DEVNULL)
                match = re.search(r"default via ([\d.]+)", out)
                return match.group(1) if match else None
        except Exception:
            try:
                # Fallback: connect to external host and read local gateway
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
                # Assume gateway = first IP in subnet (common for home routers)
                parts = local_ip.split(".")
                parts[-1] = "1"
                return ".".join(parts)
            except Exception:
                return None

    def _compute_trust_score(self):
        """Map collected alerts to a 0-100 trust score (higher = more risk)."""
        score = 0
        for alert in self.info.alerts:
            lvl = alert.get("level", "low")
            score += {"critical": 30, "high": 20, "medium": 10, "low": 5}.get(lvl, 0)
        self.info.trust_score = min(score, 100)

        if self.info.trust_score >= 75:
            self.info.risk_level = "critical"
        elif self.info.trust_score >= 50:
            self.info.risk_level = "high"
        elif self.info.trust_score >= 25:
            self.info.risk_level = "medium"
        else:
            self.info.risk_level = "low"

    def _alert(self, message: str, level: str = "medium"):
        entry = {"level": level, "message": message}
        self.info.alerts.append(entry)
        icon = {"critical": "[!!!]", "high": "[!!]",
                "medium": "[!]", "low": "[i]"}.get(level, "[i]")
        if self.verbose:
            print(f"  {icon} {message}")

    def _print(self, msg: str):
        if self.verbose:
            print(msg)

    def _print_summary(self):
        info = self.info
        self._print("\n" + "=" * 60)
        self._print("  OmniFi Router Audit Summary")
        self._print("=" * 60)
        self._print(f"  ISP / Provider  : {info.isp_name}")
        self._print(f"  Gateway IP      : {info.gateway_ip}")
        self._print(f"  Admin URL       : {info.admin_url or 'N/A'}")
        self._print(f"  Auth type       : {info.auth_type}")
        self._print(f"  HTTPS           : {info.uses_https}")
        self._print(f"  Open panel      : {info.open_panel}")
        self._print(f"  Default creds   : {'WORK — change immediately!' if info.default_creds_work else 'Do not work (good)'}")
        self._print(f"  Risk level      : {info.risk_level.upper()}")
        self._print(f"  Trust score     : {info.trust_score}/100")
        self._print(f"\n  Alerts ({len(info.alerts)}):")
        for a in info.alerts:
            icon = {"critical": "[!!!]", "high": "[!!]",
                    "medium": "[!]", "low": "[i]"}.get(a["level"], "[i]")
            self._print(f"    {icon} {a['message']}")
        if info.notes:
            self._print(f"\n  Notes : {info.notes}")
        self._print("=" * 60 + "\n")


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    inspector = RouterAuthInspector(verbose=True)
    result    = inspector.run()
