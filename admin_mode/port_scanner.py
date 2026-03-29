"""
OmniFi — Gateway Port Scanner + Passive OS Fingerprinting
===========================================================
Two admin-mode intelligence features:

1. PortScanner
   Lightweight pure-Python socket scan of the router gateway.
   Checks top 20 ports for unexpected open services.
   No nmap required — uses socket.connect_ex().

2. PassiveOSFingerprinter
   Uses Scapy to passively analyse TCP SYN packets from devices.
   TTL + window size + TCP options → OS identification.
   Zero probe packets sent — completely passive.
"""

import socket
import platform
import concurrent.futures
from dataclasses import dataclass

try:
    from scapy.all import sniff, TCP, IP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ── Top ports to scan on the gateway ─────────────────────────────────────────

GATEWAY_PORTS = {
    21:   ("FTP",      "critical", "FTP on router — credentials sent in cleartext!"),
    22:   ("SSH",      "medium",   "SSH open — ensure strong password or key-only auth."),
    23:   ("Telnet",   "critical", "Telnet on router — completely unencrypted! Disable immediately."),
    25:   ("SMTP",     "high",     "SMTP open — router may be used for spam relay."),
    53:   ("DNS",      "low",      "DNS service open — expected on routers."),
    80:   ("HTTP",     "medium",   "HTTP admin panel open — use HTTPS if available."),
    443:  ("HTTPS",    "low",      "HTTPS admin panel — good."),
    445:  ("SMB",      "critical", "SMB open on router — unusual, possible vulnerability."),
    1900: ("UPnP",     "high",     "UPnP enabled — allows devices to open ports automatically."),
    7547: ("TR-069",   "high",     "TR-069 (CWMP) port open — ISP remote management port."),
    8080: ("HTTP-alt", "medium",   "Alternate HTTP port — check if admin panel is accessible."),
    8443: ("HTTPS-alt","low",      "Alternate HTTPS port."),
    8888: ("HTTP-alt", "medium",   "Alternate HTTP port open."),
    4567: ("HTTP",     "medium",   "Unusual port with HTTP — check what service is running."),
    5000: ("HTTP",     "medium",   "Port 5000 open — some routers expose API here."),
    6789: ("HTTP",     "low",      "Non-standard port open."),
    49152:("UPnP",     "high",     "UPnP IGD port — device can self-configure port forwarding."),
    1234: ("Custom",   "medium",   "Non-standard port — investigate."),
    9000: ("HTTP",     "medium",   "Port 9000 — some router management interfaces use this."),
    2222: ("SSH-alt",  "medium",   "Alternate SSH port open."),
}


# ── Port Scanner ──────────────────────────────────────────────────────────────

class PortScanner:

    def __init__(self, timeout=1.0, max_workers=20, verbose=True):
        self.timeout     = timeout
        self.max_workers = max_workers
        self.verbose     = verbose
        self.alerts      = []

    def scan_gateway(self, gateway_ip: str) -> dict:
        self._print(f"\n[OmniFi] Port Scanner → {gateway_ip}\n")
        open_ports  = {}
        results     = {"gateway": gateway_ip, "open_ports": {}, "alerts": self.alerts}

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {ex.submit(self._probe, gateway_ip, port): port
                       for port in GATEWAY_PORTS}
            for future in concurrent.futures.as_completed(futures):
                port   = futures[future]
                is_open = future.result()
                if is_open:
                    info = GATEWAY_PORTS.get(port, ("Unknown", "low", ""))
                    svc, level, note = info
                    open_ports[port] = {"service": svc, "risk": level, "note": note}
                    icon = {"critical":"[!!!]","high":"[!!]",
                            "medium":"[!]","low":"[i]"}.get(level,"[i]")
                    self._print(f"  {icon} Port {port:5d}  {svc:<10}  {level:<8}  {note}")
                    if level in ("critical", "high"):
                        self._alert(f"Port {port} ({svc}) open on {gateway_ip}: {note}", level)

        if not open_ports:
            self._print("  [+] No unexpected ports open on gateway.")
        else:
            self._print(f"\n  Total open ports: {len(open_ports)}")

        results["open_ports"] = open_ports
        return results

    def _probe(self, host: str, port: int) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                return s.connect_ex((host, port)) == 0
        except Exception:
            return False

    def _alert(self, msg, level="medium"):
        self.alerts.append({"level": level, "message": msg})

    def _print(self, msg):
        if self.verbose: print(msg)


# ── Passive OS Fingerprinter ──────────────────────────────────────────────────

# OS fingerprint database: (ttl, window_size) → OS family
# Source: p0f database, Nmap OS detection signatures
OS_SIGNATURES = [
    # (ttl_min, ttl_max, win_min, win_max, os_label)
    (60,  65,  5840,  5840,  "Linux 2.6.x"),
    (60,  65,  14600, 14600, "Linux 3.x / Android"),
    (60,  65,  29200, 29200, "Linux 4.x / Android"),
    (60,  65,  65535, 65535, "Linux / FreeBSD"),
    (124, 129, 8192,  8192,  "Windows XP"),
    (124, 129, 65535, 65535, "Windows Vista / 7"),
    (124, 129, 64240, 64240, "Windows 8 / 10 / 11"),
    (124, 129, 8192,  8192,  "Windows Server 2008"),
    (60,  65,  65535, 65535, "macOS / iOS / FreeBSD"),
    (250, 255, 4096,  65535, "Cisco IOS / embedded"),
    (250, 255, 4128,  4128,  "Cisco router"),
]

CAPTURE_SECONDS = 30


@dataclass
class DeviceOS:
    ip:         str = ""
    mac:        str = ""
    ttl:        int = 0
    win_size:   int = 0
    os_label:   str = "unknown"
    confidence: str = "low"


class PassiveOSFingerprinter:

    def __init__(self, interface="wlan0", verbose=True):
        self.interface  = interface
        self.verbose    = verbose
        self.seen: dict[str, DeviceOS] = {}   # ip → DeviceOS
        self.alerts     = []

    def run(self) -> dict[str, DeviceOS]:
        if not SCAPY_AVAILABLE:
            self._print("[!] Scapy not available. Run: pip install scapy")
            return {}

        self._print(f"\n[OmniFi] Passive OS Fingerprinter — sniffing {CAPTURE_SECONDS}s...")
        self._print("  No probe packets sent — completely passive.\n")

        try:
            sniff(iface=self.interface,
                  filter="tcp",
                  prn=self._handle_packet,
                  timeout=CAPTURE_SECONDS,
                  store=False)
        except Exception as e:
            self._print(f"  [!] Sniff error: {e}  (requires root)")

        self._display()
        return self.seen

    def _handle_packet(self, pkt):
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
            return
        # Only analyse SYN packets (flags=0x02) — most reliable for OS fingerprinting
        if pkt[TCP].flags != 0x02:
            return

        ip      = pkt[IP].src
        ttl     = pkt[IP].ttl
        win     = pkt[TCP].window

        if ip in self.seen:
            return   # already fingerprinted this host

        os_label    = self._match_os(ttl, win)
        confidence  = "medium" if os_label != "unknown" else "low"

        self.seen[ip] = DeviceOS(
            ip=ip, ttl=ttl, win_size=win,
            os_label=os_label, confidence=confidence
        )

        self._print(f"  [i] {ip:16s}  TTL={ttl:<4} WIN={win:<7}  → {os_label}")

    def _match_os(self, ttl: int, win: int) -> str:
        for t_min, t_max, w_min, w_max, label in OS_SIGNATURES:
            if t_min <= ttl <= t_max and w_min <= win <= w_max:
                return label
        # Broad TTL match
        if 60 <= ttl <= 65:   return "Linux / Android (approx)"
        if 124 <= ttl <= 129: return "Windows (approx)"
        if 250 <= ttl <= 255: return "Cisco / embedded (approx)"
        return "unknown"

    def _display(self):
        if not self.seen:
            self._print("  [i] No TCP SYN packets captured.")
            return
        self._print(f"\n  Fingerprinted {len(self.seen)} device(s):")
        self._print(f"  {'IP Address':<18} {'TTL':<6} {'Window':<8} {'OS Guess'}")
        self._print("  " + "─" * 56)
        for ip, dev in sorted(self.seen.items()):
            print(f"  {dev.ip:<18} {dev.ttl:<6} {dev.win_size:<8} {dev.os_label}")

    def _print(self, msg):
        if self.verbose: print(msg)


if __name__ == "__main__":
    import sys
    if "--portscan" in sys.argv:
        import subprocess, re, platform
        try:
            if platform.system() == "Windows":
                out = subprocess.check_output(["ipconfig"], text=True)
                m   = re.search(r"Default Gateway.*?:\s*([\d.]+)", out)
            else:
                out = subprocess.check_output(["ip","route"], text=True)
                m   = re.search(r"default via ([\d.]+)", out)
            gw = m.group(1) if m else "192.168.1.1"
        except Exception:
            gw = "192.168.1.1"
        PortScanner().scan_gateway(gw)
    else:
        PassiveOSFingerprinter().run()
