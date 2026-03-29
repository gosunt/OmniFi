"""
OmniFi — CVE Lookup for Router Firmware
=========================================
Queries the NIST National Vulnerability Database (NVD) API v2.0 for
known CVEs matching the detected router model and firmware version.

API endpoint: https://services.nvd.nist.gov/rest/json/cves/2.0
Free, no API key required for basic use (rate limited to 5 req/30s).

Output per CVE:
  - CVE ID and description
  - CVSS v3 score and severity
  - Published date
  - Whether a patch is available
"""

import requests
import time
import re

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_DELAY = 6   # seconds between requests (NVD rate limit: 5 req/30s)

SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[91m",
    "MEDIUM":   "\033[93m",
    "LOW":      "\033[92m",
    "NONE":     "\033[0m",
}
RESET = "\033[0m"


class CVELookup:

    def __init__(self, verbose=True):
        self.verbose  = verbose
        self.alerts   = []
        self._last_req = 0

    def lookup(self, router_model: str, firmware_version: str = "") -> list:
        """
        Search NVD for CVEs matching the router model.
        Returns list of CVE dicts sorted by CVSS score descending.
        """
        self._print(f"\n[OmniFi] CVE Lookup: {router_model} {firmware_version}")
        self._print("  Querying NIST NVD API...\n")

        # Build search keywords — try specific then broad
        queries = self._build_queries(router_model, firmware_version)
        all_cves = {}

        for keyword in queries:
            cves = self._query_nvd(keyword)
            for cve in cves:
                cve_id = cve.get("id","")
                if cve_id and cve_id not in all_cves:
                    all_cves[cve_id] = cve

        results = sorted(all_cves.values(),
                         key=lambda c: c.get("cvss_score", 0), reverse=True)

        self._display(results, router_model)
        self._generate_alerts(results)
        return results

    def _build_queries(self, model: str, firmware: str) -> list:
        queries = []
        # Specific: model + firmware
        if firmware:
            queries.append(f"{model} {firmware}")
        # Model only
        queries.append(model)
        # Extract base model number (e.g. "HG8145V5" → "HG8145")
        base = re.sub(r'[Vv]\d+$', '', model).strip()
        if base != model:
            queries.append(base)
        return queries

    def _query_nvd(self, keyword: str) -> list:
        # Respect rate limit
        elapsed = time.time() - self._last_req
        if elapsed < REQUEST_DELAY:
            time.sleep(REQUEST_DELAY - elapsed)

        try:
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": 20,
                "startIndex": 0,
            }
            r = requests.get(NVD_API, params=params, timeout=10)
            self._last_req = time.time()

            if r.status_code != 200:
                self._print(f"  [!] NVD API error {r.status_code} for '{keyword}'")
                return []

            data = r.json()
            cves = []
            for item in data.get("vulnerabilities", []):
                cve_data = item.get("cve", {})
                cve_id   = cve_data.get("id", "")

                # Description (English)
                desc = next(
                    (d["value"] for d in cve_data.get("descriptions",[])
                     if d.get("lang") == "en"),
                    "No description available."
                )

                # CVSS v3 score
                cvss_score    = 0.0
                cvss_severity = "NONE"
                metrics = cve_data.get("metrics", {})
                for key in ("cvssMetricV31", "cvssMetricV30"):
                    if key in metrics and metrics[key]:
                        m = metrics[key][0].get("cvssData", {})
                        cvss_score    = m.get("baseScore", 0.0)
                        cvss_severity = m.get("baseSeverity", "NONE")
                        break

                # Published date
                published = cve_data.get("published", "")[:10]

                # Patch info — check for references mentioning patch/advisory
                refs = [r.get("url","") for r in cve_data.get("references",[])]
                has_patch = any(
                    kw in " ".join(refs).lower()
                    for kw in ["patch","fix","update","advisory","vendor"]
                )

                cves.append({
                    "id":           cve_id,
                    "description":  desc[:300] + ("..." if len(desc)>300 else ""),
                    "cvss_score":   cvss_score,
                    "cvss_severity":cvss_severity,
                    "published":    published,
                    "has_patch":    has_patch,
                    "references":   refs[:3],
                })

            return cves

        except requests.Timeout:
            self._print(f"  [!] NVD API timeout for '{keyword}'")
            return []
        except Exception as e:
            self._print(f"  [!] NVD query error: {e}")
            return []

    def _display(self, cves: list, model: str):
        if not cves:
            self._print(f"  [+] No CVEs found for {model}. ")
            return

        self._print(f"  Found {len(cves)} CVE(s) for {model}:\n")
        self._print(f"  {'CVE ID':<18} {'Score':>6}  {'Severity':<10} {'Published':<12} {'Patch':<6}")
        self._print("  " + "─" * 62)

        for c in cves[:15]:   # show top 15
            color = SEVERITY_COLORS.get(c["cvss_severity"], "")
            patch = "Yes" if c["has_patch"] else "No"
            print(f"  {color}{c['id']:<18} {c['cvss_score']:>6.1f}  "
                  f"{c['cvss_severity']:<10} {c['published']:<12} {patch:<6}{RESET}")
            self._print(f"  {c['description'][:80]}...")
            self._print("")

    def _generate_alerts(self, cves: list):
        critical = [c for c in cves if c["cvss_score"] >= 9.0]
        high     = [c for c in cves if 7.0 <= c["cvss_score"] < 9.0]

        if critical:
            msg = (f"{len(critical)} CRITICAL CVE(s) found for this router model. "
                   f"Update firmware immediately. "
                   f"Highest: {critical[0]['id']} (CVSS {critical[0]['cvss_score']})")
            self._alert(msg, "critical")

        if high:
            msg = (f"{len(high)} HIGH severity CVE(s) found. "
                   f"Firmware update strongly recommended.")
            self._alert(msg, "high")

    def _alert(self, msg, level="high"):
        self.alerts.append({"level": level, "message": msg})
        icons = {"critical":"[!!!]","high":"[!!]","medium":"[!]","low":"[i]"}
        self._print(f"  {icons.get(level,'[i]')} {msg}")

    def _print(self, msg):
        if self.verbose: print(msg)


if __name__ == "__main__":
    # Demo — look up CVEs for a Huawei router (common in Airtel installs)
    lookup = CVELookup()
    lookup.lookup("HG8145", "V300R019")
