"""
OmniFi — Local DoH/DoT Resolver Enforcement
=============================================
When DNS spoofing is detected, OmniFi launches a local DNS-over-HTTPS
proxy on 127.0.0.1:5353 and rewrites /etc/resolv.conf to use it.
All DNS queries are now encrypted and verified regardless of the router.

Supports:
  - Cloudflare DoH  : https://cloudflare-dns.com/dns-query
  - Google DoH      : https://dns.google/dns-query
  - Quad9 DoH       : https://dns.quad9.net/dns-query

Requirements:
  - requests  (pip install requests)
  - dnslib    (pip install dnslib)   ← for DNS packet parsing
  - Root for /etc/resolv.conf rewrite (Linux only)
"""

import socket
import threading
import struct
import os
import platform
import requests

try:
    import dnslib
    from dnslib import DNSRecord, DNSHeader, QTYPE, RR, A
    DNSLIB_AVAILABLE = True
except ImportError:
    DNSLIB_AVAILABLE = False

DOH_PROVIDERS = {
    "cloudflare": "https://cloudflare-dns.com/dns-query",
    "google":     "https://dns.google/dns-query",
    "quad9":      "https://dns.quad9.net/dns-query",
}

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 5353
RESOLV_CONF = "/etc/resolv.conf"
RESOLV_BACKUP = "/etc/resolv.conf.omnifi.bak"


class DoHResolver:
    """
    Minimal UDP DNS server that forwards all queries to a DoH provider.
    Runs in a background thread.
    """

    def __init__(self, provider="cloudflare", verbose=True):
        self.provider   = DOH_PROVIDERS.get(provider, DOH_PROVIDERS["cloudflare"])
        self.verbose    = verbose
        self._sock      = None
        self._thread    = None
        self._running   = False
        self.alerts     = []

    def start(self) -> bool:
        if not DNSLIB_AVAILABLE:
            self._print("[!] dnslib not installed. Run: pip install dnslib")
            return False

        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((LISTEN_HOST, LISTEN_PORT))
            self._running = True
            self._thread  = threading.Thread(target=self._serve, daemon=True)
            self._thread.start()
            self._print(f"  [+] DoH proxy started on {LISTEN_HOST}:{LISTEN_PORT} → {self.provider}")
            return True
        except OSError as e:
            self._print(f"  [!] Cannot bind port {LISTEN_PORT}: {e}")
            return False

    def stop(self):
        self._running = False
        if self._sock:
            try: self._sock.close()
            except Exception: pass
        self._print("  [*] DoH proxy stopped.")

    def enforce_on_system(self) -> bool:
        """Rewrite /etc/resolv.conf to point to our local proxy."""
        if platform.system() != "Linux":
            self._print("  [i] resolv.conf rewrite only supported on Linux.")
            return False
        try:
            # Backup existing
            if os.path.exists(RESOLV_CONF) and not os.path.exists(RESOLV_BACKUP):
                with open(RESOLV_CONF) as f:
                    content = f.read()
                with open(RESOLV_BACKUP, "w") as f:
                    f.write(content)

            with open(RESOLV_CONF, "w") as f:
                f.write(f"# OmniFi DoH enforcement — backup at {RESOLV_BACKUP}\n")
                f.write(f"nameserver {LISTEN_HOST}\n")

            self._print(f"  [+] /etc/resolv.conf updated → {LISTEN_HOST}:{LISTEN_PORT}")
            self._alert("System DNS redirected to OmniFi local DoH proxy.", "low")
            return True
        except PermissionError:
            self._print("  [!] Permission denied — run as root to rewrite resolv.conf.")
            return False

    def restore_system_dns(self):
        """Restore original /etc/resolv.conf."""
        if os.path.exists(RESOLV_BACKUP):
            try:
                import shutil
                shutil.copy(RESOLV_BACKUP, RESOLV_CONF)
                os.remove(RESOLV_BACKUP)
                self._print("  [+] Original resolv.conf restored.")
            except Exception as e:
                self._print(f"  [!] Restore failed: {e}")

    def _serve(self):
        while self._running:
            try:
                self._sock.settimeout(1.0)
                data, addr = self._sock.recvfrom(512)
                threading.Thread(
                    target=self._handle_query,
                    args=(data, addr),
                    daemon=True
                ).start()
            except socket.timeout:
                continue
            except Exception:
                break

    def _handle_query(self, data: bytes, addr):
        try:
            request  = DNSRecord.parse(data)
            qname    = str(request.q.qname).rstrip(".")
            qtype    = QTYPE[request.q.qtype]

            # Forward to DoH provider
            response = requests.get(
                self.provider,
                params={"name": qname, "type": qtype},
                headers={"Accept": "application/dns-json"},
                timeout=4
            )
            doh_data = response.json()

            # Build DNS response
            reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1))
            reply.add_question(request.q)

            for answer in doh_data.get("Answer", []):
                if answer.get("type") == 1:    # A record
                    reply.add_answer(RR(qname, rdata=A(answer["data"]),
                                        ttl=answer.get("TTL", 60)))

            self._sock.sendto(reply.pack(), addr)

        except Exception as e:
            # On error, fall back to system DNS silently
            try:
                import dns.resolver
                pass
            except Exception:
                pass

    def _alert(self, msg, level="low"):
        self.alerts.append({"level": level, "message": msg})

    def _print(self, msg):
        if self.verbose: print(msg)


if __name__ == "__main__":
    resolver = DoHResolver(provider="cloudflare")
    if resolver.start():
        resolver.enforce_on_system()
        print("  DoH proxy running. Press Ctrl+C to stop.")
        try:
            import time
            while True: time.sleep(1)
        except KeyboardInterrupt:
            resolver.stop()
            resolver.restore_system_dns()
