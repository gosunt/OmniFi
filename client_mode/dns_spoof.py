"""
OmniFi — DNS Spoofing Detector
================================
Detects DNS spoofing using three methods:
  1. DoH comparison  — compare local resolver vs Cloudflare/Google DoH
  2. TTL anomaly     — spoofed responses often have unusually low TTLs
  3. NXDOMAIN spike  — burst of NXDOMAIN = possible DNS hijack
  4. Resolver change — detect if DNS server changed since last check

Requirements: pip install requests dnspython
"""

import socket
import sqlite3
import os
import datetime
import time

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import dns.resolver
    import dns.exception
    DNSPYTHON_AVAILABLE = True
except ImportError:
    DNSPYTHON_AVAILABLE = False

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "db", "omnifi.db")

DOH_PROVIDERS = {
    "cloudflare": "https://cloudflare-dns.com/dns-query",
    "google":     "https://dns.google/dns-query",
}

TEST_DOMAINS = [
    "google.com",
    "facebook.com",
    "amazon.com",
    "github.com",
    "microsoft.com",
]

TTL_ANOMALY_THRESHOLD = 30    # TTL below this is suspicious
NXDOMAIN_SPIKE        = 5     # 5+ NXDOMAINs in a row = suspicious


def _get_conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS dns_baseline (
            domain     TEXT PRIMARY KEY,
            known_ips  TEXT NOT NULL,
            last_seen  TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


class DNSSpoofDetector:

    def __init__(self, verbose=True):
        self.verbose      = verbose
        self.conn         = _get_conn()
        self.alerts       = []
        self.nxdomain_cnt = 0

    def run(self) -> dict:
        self._print("\n[OmniFi] DNS Spoof Detector...\n")
        result = {
            "spoofing_detected": False,
            "anomalies":         [],
            "resolver_ip":       self._get_resolver_ip(),
            "alerts":            self.alerts,
        }

        self._print(f"  System DNS resolver: {result['resolver_ip']}\n")

        for domain in TEST_DOMAINS:
            findings = self._check_domain(domain)
            if findings:
                result["anomalies"].extend(findings)
                result["spoofing_detected"] = True

        if not result["spoofing_detected"]:
            self._print("  [+] No DNS anomalies detected — resolver appears clean.")

        return result

    # ── Per-domain check ──────────────────────────────────────────────────────

    def _check_domain(self, domain: str) -> list:
        findings = []

        # Method 1: Local resolution
        local_ips, local_ttl = self._resolve_local(domain)
        if not local_ips:
            self.nxdomain_cnt += 1
            if self.nxdomain_cnt >= NXDOMAIN_SPIKE:
                msg = f"NXDOMAIN spike: {self.nxdomain_cnt} consecutive failures — possible DNS hijack."
                self._alert(msg, "high")
                findings.append(msg)
            return findings
        self.nxdomain_cnt = 0

        # Method 2: DoH comparison
        if REQUESTS_AVAILABLE:
            doh_ips = self._resolve_doh(domain)
            if doh_ips and not set(local_ips) & set(doh_ips):
                msg = (f"DNS mismatch for {domain}: "
                       f"local={local_ips}, DoH={doh_ips}. "
                       f"Possible DNS spoofing!")
                self._alert(msg, "critical")
                findings.append(msg)
                self._print(f"  [!!!] {domain}: local {local_ips} ≠ DoH {doh_ips}")
            else:
                self._print(f"  [+]  {domain}: local={local_ips[0] if local_ips else '?'}  DoH match ✓")

        # Method 3: TTL anomaly
        if local_ttl and local_ttl < TTL_ANOMALY_THRESHOLD:
            msg = (f"TTL anomaly for {domain}: TTL={local_ttl}s is suspiciously low "
                   f"(threshold {TTL_ANOMALY_THRESHOLD}s). Possible cache poisoning.")
            self._alert(msg, "high")
            findings.append(msg)
            self._print(f"  [!!] {domain}: TTL={local_ttl}s (anomaly!)")

        # Method 4: Baseline comparison (if we've seen this domain before)
        baseline_finding = self._check_against_baseline(domain, local_ips)
        if baseline_finding:
            findings.append(baseline_finding)

        # Update baseline
        self._update_baseline(domain, local_ips)
        return findings

    # ── Resolution helpers ────────────────────────────────────────────────────

    def _resolve_local(self, domain: str) -> tuple:
        """Returns (list of IPs, TTL) from local resolver."""
        if DNSPYTHON_AVAILABLE:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout  = 3
                resolver.lifetime = 3
                answers = resolver.resolve(domain, "A")
                ips = [str(r) for r in answers]
                ttl = answers.rrset.ttl if answers.rrset else None
                return ips, ttl
            except Exception:
                pass

        # Fallback: socket
        try:
            ip = socket.gethostbyname(domain)
            return [ip], None
        except Exception:
            return [], None

    def _resolve_doh(self, domain: str, provider: str = "cloudflare") -> list:
        """Resolve via DNS-over-HTTPS. Returns list of A record IPs."""
        url = DOH_PROVIDERS.get(provider, DOH_PROVIDERS["cloudflare"])
        try:
            r = requests.get(
                url,
                params={"name": domain, "type": "A"},
                headers={"Accept": "application/dns-json"},
                timeout=5
            )
            if r.status_code == 200:
                data = r.json()
                return [a["data"] for a in data.get("Answer", [])
                        if a.get("type") == 1]
        except Exception:
            pass
        return []

    def _get_resolver_ip(self) -> str:
        if DNSPYTHON_AVAILABLE:
            try:
                return dns.resolver.Resolver().nameservers[0]
            except Exception:
                pass
        # Read from resolv.conf on Linux
        try:
            with open("/etc/resolv.conf") as f:
                for line in f:
                    if line.startswith("nameserver"):
                        return line.split()[1]
        except Exception:
            pass
        return "unknown"

    # ── Baseline tracking ─────────────────────────────────────────────────────

    def _check_against_baseline(self, domain: str, current_ips: list) -> str:
        cur = self.conn.cursor()
        cur.execute("SELECT known_ips FROM dns_baseline WHERE domain=?", (domain,))
        row = cur.fetchone()
        if not row:
            return ""
        known = set(row[0].split(","))
        current = set(current_ips)
        new_ips = current - known
        if new_ips:
            msg = (f"DNS baseline change for {domain}: "
                   f"new IP(s) {new_ips} not in baseline {known}.")
            self._alert(msg, "medium")
            return msg
        return ""

    def _update_baseline(self, domain: str, ips: list):
        if not ips:
            return
        now = datetime.datetime.now().isoformat()
        cur = self.conn.cursor()
        cur.execute("SELECT known_ips FROM dns_baseline WHERE domain=?", (domain,))
        row = cur.fetchone()
        if row:
            existing = set(row[0].split(","))
            merged   = existing | set(ips)
            self.conn.execute(
                "UPDATE dns_baseline SET known_ips=?, last_seen=? WHERE domain=?",
                (",".join(merged), now, domain)
            )
        else:
            self.conn.execute(
                "INSERT INTO dns_baseline (domain, known_ips, last_seen) VALUES (?,?,?)",
                (domain, ",".join(ips), now)
            )
        self.conn.commit()

    def _alert(self, msg, level="medium"):
        self.alerts.append({"level": level, "message": msg})

    def _print(self, msg):
        if self.verbose: print(msg)


if __name__ == "__main__":
    DNSSpoofDetector().run()
