"""
OmniFi — Captive Portal Fingerprinting
========================================
Detects captive portals (hotel/airport/cafe Wi-Fi) and audits:
  - HTTP vs HTTPS login page
  - JavaScript injection into responses
  - HTTPS redirect hijacking (MITM-capable infrastructure)
  - Cookie security flags on portal session
"""

import re
import requests
requests.packages.urllib3.disable_warnings()

PROBE_URLS = [
    "http://connectivitycheck.gstatic.com/generate_204",
    "http://captive.apple.com/hotspot-detect.html",
    "http://www.msftconnecttest.com/connecttest.txt",
    "http://neverssl.com",
]

class CaptivePortalDetector:
    def __init__(self, verbose=True):
        self.verbose = verbose
        self.result  = {
            "detected":      False,
            "portal_url":    "",
            "uses_https":    False,
            "js_injection":  False,
            "https_hijack":  False,
            "cookie_secure": True,
            "risk_level":    "low",
            "alerts":        [],
        }

    def run(self) -> dict:
        self._print("\n[OmniFi] Captive Portal Detector...\n")
        for url in PROBE_URLS:
            try:
                r = requests.get(url, timeout=4, allow_redirects=True, verify=False)
                if r.url != url or r.status_code not in (200, 204):
                    self.result["detected"]   = True
                    self.result["portal_url"] = r.url
                    self._print(f"  [!] Captive portal detected → {r.url}")
                    self._audit_portal(r)
                    break
            except Exception:
                continue

        if not self.result["detected"]:
            self._print("  [+] No captive portal detected.")
        self._assign_risk()
        return self.result

    def _audit_portal(self, response):
        url = response.url
        self.result["uses_https"] = url.startswith("https")

        if not self.result["uses_https"]:
            self._alert("Portal login served over HTTP — credentials sent in cleartext.", "critical")

        if "https" in getattr(response.request, "url", "") and not url.startswith("https"):
            self.result["https_hijack"] = True
            self._alert("Portal hijacked an HTTPS request — MITM-capable infrastructure.", "critical")

        js_patterns = [r"<script[^>]*>.*?(captive|portal|redirect)", r"document\.write\(", r"window\.location\s*="]
        for pat in js_patterns:
            if re.search(pat, response.text, re.IGNORECASE | re.DOTALL):
                self.result["js_injection"] = True
                self._alert("JavaScript injection detected in portal response.", "high")
                break

        for cookie in response.cookies:
            if not cookie.secure:
                self.result["cookie_secure"] = False
                self._alert(f"Cookie '{cookie.name}' missing Secure flag.", "medium")

    def _assign_risk(self):
        levels = [a["level"] for a in self.result["alerts"]]
        if "critical" in levels:   self.result["risk_level"] = "critical"
        elif "high" in levels:     self.result["risk_level"] = "high"
        elif levels:               self.result["risk_level"] = "medium"

    def _alert(self, msg, level="medium"):
        self.result["alerts"].append({"level": level, "message": msg})
        if self.verbose:
            icons = {"critical":"[!!!]","high":"[!!]","medium":"[!]","low":"[i]"}
            print(f"  {icons.get(level,'[i]')} {msg}")

    def _print(self, msg):
        if self.verbose: print(msg)

if __name__ == "__main__":
    CaptivePortalDetector().run()
