"""
OmniFi — Session Hijacking Detector
=====================================
Monitors for conditions that enable session hijacking on the current network:

1. HTTP cookie flag checker
   Scans responses from sites visited for Set-Cookie headers missing
   Secure and HttpOnly flags.

2. Passive cleartext credential sniffer (Scapy)
   On open/WEP networks, passively sniffs HTTP POST bodies for common
   credential field names (username, password, email, login).
   NEVER logs the actual credentials — only alerts that cleartext
   credentials were observed in transit.

3. HTTP vs HTTPS enforcement check
   Checks whether common sites (banking, mail, shopping) are being
   served over HTTP when they should force HTTPS.
"""

import re

try:
    from scapy.all import sniff, TCP, Raw, IP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Common credential field names in HTML forms
CREDENTIAL_PATTERNS = [
    r"(?:username|user|email|login|userid)\s*=\s*[^&\s]{3,}",
    r"(?:password|passwd|pwd|pass)\s*=\s*[^&\s]{3,}",
]

# Sites that should always redirect to HTTPS
HTTPS_EXPECTED_SITES = [
    "http://www.sbi.co.in",
    "http://www.hdfcbank.com",
    "http://www.icicibank.com",
    "http://www.axisbank.com",
    "http://www.gmail.com",
    "http://www.facebook.com",
    "http://www.instagram.com",
    "http://www.amazon.in",
    "http://www.flipkart.com",
]

CAPTURE_SECONDS = 20


class SessionHijackDetector:
    def __init__(self, interface="wlan0", verbose=True):
        self.interface    = interface
        self.verbose      = verbose
        self.alerts       = []
        self._cred_seen   = False   # flag only, never store actual creds

    # ── Public entry point ────────────────────────────────────────────────────

    def run(self) -> dict:
        self._print("\n[OmniFi] Session Hijacking Detector...\n")
        results = {
            "cleartext_creds_observed": False,
            "insecure_cookie_sites":    [],
            "http_when_https_expected": [],
            "alerts":                   self.alerts,
        }

        # Check 1: HTTPS enforcement on high-value sites
        results["http_when_https_expected"] = self._check_https_enforcement()

        # Check 2: Passive sniff for cleartext credentials
        if SCAPY_AVAILABLE:
            cred_found = self._sniff_for_cleartext_creds()
            results["cleartext_creds_observed"] = cred_found
        else:
            self._print("  [i] Scapy not available — skipping passive credential sniff.")

        return results

    def check_response_cookies(self, url: str) -> list:
        """
        Check cookies returned by a specific URL for missing security flags.
        Used by the dashboard to audit sites the user visits.
        """
        if not REQUESTS_AVAILABLE:
            return []
        issues = []
        try:
            r = requests.get(url, timeout=4, verify=True, allow_redirects=True)
            for cookie in r.cookies:
                if not cookie.secure:
                    issues.append(f"{url}: Cookie '{cookie.name}' missing Secure flag.")
                    self._alert(f"Cookie '{cookie.name}' on {url} missing Secure flag.", "medium")
                if "httponly" not in str(cookie._rest).lower():
                    issues.append(f"{url}: Cookie '{cookie.name}' missing HttpOnly flag.")
        except Exception:
            pass
        return issues

    # ── Check 1: HTTPS enforcement ────────────────────────────────────────────

    def _check_https_enforcement(self) -> list:
        if not REQUESTS_AVAILABLE:
            return []
        issues = []
        self._print("  Checking HTTPS enforcement on high-value sites...")
        for url in HTTPS_EXPECTED_SITES:
            try:
                r = requests.get(url, timeout=4, allow_redirects=True, verify=True)
                if r.url.startswith("http://"):
                    issues.append(url)
                    self._alert(
                        f"{url} did not redirect to HTTPS — "
                        "session data may be interceptable on this network.",
                        "high"
                    )
                    self._print(f"  [!!] {url} → still HTTP after redirect!")
                else:
                    self._print(f"  [+]  {url} → redirects to HTTPS correctly.")
            except Exception:
                pass
        return issues

    # ── Check 2: Passive cleartext credential sniff ───────────────────────────

    def _sniff_for_cleartext_creds(self) -> bool:
        self._print(f"\n  Passive sniff for cleartext credentials ({CAPTURE_SECONDS}s)...")
        self._print("  (OmniFi never records actual credential values — only detects their presence)\n")

        try:
            sniff(iface=self.interface,
                  filter="tcp port 80",
                  prn=self._inspect_packet,
                  timeout=CAPTURE_SECONDS,
                  store=False)
        except Exception as e:
            self._print(f"  [!] Sniff error: {e}  (requires root)")

        return self._cred_seen

    def _inspect_packet(self, pkt):
        if self._cred_seen:
            return   # already alerted — no need to process more
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return

        payload = pkt[Raw].load
        try:
            text = payload.decode("utf-8", errors="ignore")
        except Exception:
            return

        # Only inspect HTTP POST bodies
        if "POST" not in text:
            return

        src_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"

        for pat in CREDENTIAL_PATTERNS:
            if re.search(pat, text, re.IGNORECASE):
                self._cred_seen = True
                self._alert(
                    f"Cleartext credentials observed in HTTP POST from {src_ip}. "
                    "Username/password transmitted without encryption on this network.",
                    "critical"
                )
                self._print(f"  [!!!] Cleartext credentials detected in HTTP POST from {src_ip}!")
                self._print("        The actual values are NOT logged — only this alert is recorded.")
                break

    def _alert(self, msg, level="medium"):
        self.alerts.append({"level": level, "message": msg})

    def _print(self, msg):
        if self.verbose: print(msg)


if __name__ == "__main__":
    SessionHijackDetector().run()
