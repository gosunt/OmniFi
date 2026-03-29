"""
OmniFi — ICMP Redirect Attack Detector
=========================================
Attackers can send forged ICMP Redirect (type 5) messages to silently
reroute a client's traffic through their machine — no ARP poisoning
needed. This is rare but completely invisible without detection.

ICMP Redirect type 5 codes:
  0 = Redirect for network
  1 = Redirect for host        ← most commonly abused
  2 = Redirect for TOS+network
  3 = Redirect for TOS+host

Detection:
  Scapy passively captures ICMP type 5 packets.
  Any ICMP redirect from a source OTHER than the legitimate gateway
  is flagged as a likely attack.

Requirements:
  - Scapy  (pip install scapy)
  - Root / sudo privileges
"""

import subprocess, platform, re, time

try:
    from scapy.all import sniff, ICMP, IP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

CAPTURE_SECONDS = 30
CODE_NAMES = {0:"Net redirect", 1:"Host redirect", 2:"TOS+net redirect", 3:"TOS+host redirect"}


class ICMPRedirectDetector:
    def __init__(self, interface="wlan0", verbose=True):
        self.interface    = interface
        self.verbose      = verbose
        self.gateway_ip   = self._get_gateway()
        self.redirects    = []
        self.alerts       = []

    def run(self) -> dict:
        if not SCAPY_AVAILABLE:
            self._print("[!] Scapy not installed. Run: pip install scapy")
            return {}

        self._print(f"\n[OmniFi] ICMP Redirect Detector — sniffing {CAPTURE_SECONDS}s...")
        self._print(f"  Legitimate gateway: {self.gateway_ip}\n")

        try:
            sniff(iface=self.interface,
                  filter="icmp",
                  prn=self._handle_packet,
                  timeout=CAPTURE_SECONDS,
                  store=False)
        except Exception as e:
            self._print(f"  [!] Sniff error: {e}  (requires root)")
            return {}

        return self._analyse()

    def _handle_packet(self, pkt):
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 5:
            src   = pkt[IP].src
            code  = pkt[ICMP].code
            gw    = pkt[ICMP].gw if hasattr(pkt[ICMP], "gw") else "unknown"
            entry = {
                "src":        src,
                "code":       code,
                "code_name":  CODE_NAMES.get(code, "unknown"),
                "new_gw":     str(gw),
                "timestamp":  time.time(),
                "suspicious": src != self.gateway_ip,
            }
            self.redirects.append(entry)
            marker = "[!!!]" if entry["suspicious"] else "[i]"
            self._print(f"  {marker} ICMP Redirect from {src} → new gateway {gw}  "
                        f"({CODE_NAMES.get(code,'')})"
                        f"{'  ← NOT from legitimate gateway!' if entry['suspicious'] else ''}")

    def _analyse(self) -> dict:
        suspicious = [r for r in self.redirects if r["suspicious"]]
        result = {
            "redirects_total":      len(self.redirects),
            "redirects_suspicious": len(suspicious),
            "suspicious_sources":   list({r["src"] for r in suspicious}),
            "attack_detected":      len(suspicious) > 0,
            "alerts":               self.alerts,
        }

        if not self.redirects:
            self._print("  [+] No ICMP redirects detected — clean.")
        elif suspicious:
            msg = (f"ICMP Redirect attack detected! {len(suspicious)} redirect(s) "
                   f"from {result['suspicious_sources']} — NOT the legitimate gateway "
                   f"({self.gateway_ip}). Traffic may be silently rerouted.")
            self._alert(msg, "critical")
            self._print(f"\n  [!!!] {msg}")
        else:
            self._print(f"  [i] {len(self.redirects)} ICMP redirect(s) from legitimate gateway only — normal.")

        return result


    def check_static(self) -> dict:
        """
        Static ICMP redirect check that doesn't require Scapy or root.
        On Linux: checks /proc/sys/net/ipv4/conf/*/accept_redirects
        On Windows: checks registry via netsh
        Also probes OS route table for unexpected gateway changes.
        """
        result = {
            "redirects_total": 0, "redirects_suspicious": 0,
            "suspicious_sources": [], "attack_detected": False,
            "alerts": self.alerts,
        }
        import platform, subprocess, re as _re

        if platform.system() == "Linux":
            # Check if ICMP redirect acceptance is enabled (a risk in itself)
            try:
                import os, glob
                for path in glob.glob("/proc/sys/net/ipv4/conf/*/accept_redirects"):
                    val = open(path).read().strip()
                    if val == "1":
                        iface = path.split("/")[6]
                        msg = (f"ICMP redirect acceptance ENABLED on {iface} "
                               f"(/proc/sys/net/ipv4/conf/{iface}/accept_redirects=1). "
                               "System will silently accept redirect attacks.")
                        self._alert(msg, "high")
                if not self.alerts:
                    self._print("  [+] ICMP redirect acceptance disabled — protected.")
            except Exception as e:
                self._print(f"  [i] Could not check redirect settings: {e}")

        elif platform.system() == "Windows":
            try:
                out = subprocess.check_output(
                    ["netsh","interface","ipv4","show","global"],
                    text=True, encoding="utf-8", errors="ignore",
                    stderr=subprocess.DEVNULL)
                if "EnableICMPRedirect" in out:
                    m = _re.search(r"EnableICMPRedirect\s*:\s*(\w+)", out, _re.IGNORECASE)
                    if m and m.group(1).lower() not in ("no","false","disabled","0"):
                        self._alert(
                            "ICMP redirect acceptance enabled in Windows IPv4 stack. "
                            "Run: netsh interface ipv4 set global icmpredirects=disabled",
                            "medium")
                    else:
                        self._print("  [+] Windows ICMP redirects disabled — protected.")
            except Exception as e:
                self._print(f"  [i] Could not check Windows ICMP settings: {e}")

        # Cross-platform: check for unexpected default gateway changes
        try:
            current_gw = self._get_gateway()
            if current_gw and current_gw != self.gateway_ip and self.gateway_ip != "unknown":
                msg = (f"Default gateway changed: was {self.gateway_ip}, "
                       f"now {current_gw}. Possible ICMP redirect attack redirected routing.")
                self._alert(msg, "critical")
                result["attack_detected"] = True
                result["suspicious_sources"].append(current_gw)
        except Exception:
            pass

        result["alerts"] = self.alerts
        return result

    def _get_gateway(self) -> str:
        try:
            if platform.system() == "Windows":
                out = subprocess.check_output(["ipconfig"], text=True, stderr=subprocess.DEVNULL)
                m   = re.search(r"Default Gateway.*?:\s*([\d.]+)", out)
            else:
                out = subprocess.check_output(["ip","route"], text=True, stderr=subprocess.DEVNULL)
                m   = re.search(r"default via ([\d.]+)", out)
            return m.group(1) if m else "unknown"
        except Exception:
            return "unknown"

    def _alert(self, msg, level="critical"):
        self.alerts.append({"level": level, "message": msg})

    def _print(self, msg):
        if self.verbose: print(msg)


if __name__ == "__main__":
    ICMPRedirectDetector().run()
