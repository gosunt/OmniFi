"""
OmniFi — OS Compatibility Layer
=================================
Abstracts every OS-specific command so all detection modules can call
a single API and run on both Windows and Linux without conditionals.

Usage:
    from core.compatibility import OS
    gw  = OS.gateway_ip()
    arp = OS.arp_table()
    OS.set_dns("8.8.8.8")
    OS.flush_dns()
"""
import os
import platform
import re
import socket
import subprocess
import logging
import ipaddress
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("OmniFi.Compat")

PLATFORM = platform.system()
WINDOWS  = PLATFORM == "Windows"
LINUX    = PLATFORM == "Linux"
MACOS    = PLATFORM == "Darwin"
IS_ROOT  = (not WINDOWS) and (os.geteuid() == 0)


def _run(cmd: List[str], timeout: int = 10, encoding: str = "utf-8") -> Tuple[int, str, str]:
    """Run a subprocess and return (returncode, stdout, stderr)."""
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True,
            encoding=encoding, errors="ignore", timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "Timeout"
    except Exception as e:
        return 1, "", str(e)


class _OSCompat:
    """Singleton OS compatibility wrapper."""

    # ── Network info ──────────────────────────────────────────────────────────

    def gateway_ip(self) -> str:
        try:
            if WINDOWS:
                rc, out, _ = _run(["ipconfig"])
                m = re.search(r"Default Gateway[.\s]+:\s*([\d.]+)", out)
                return m.group(1) if m else ""
            else:
                rc, out, _ = _run(["ip", "route", "show", "default"])
                m = re.search(r"default via ([\d.]+)", out)
                if m: return m.group(1)
                # Fallback
                rc, out, _ = _run(["route", "-n"])
                m = re.search(r"^0\.0\.0\.0\s+([\d.]+)", out, re.MULTILINE)
                return m.group(1) if m else ""
        except Exception as e:
            log.debug(f"gateway_ip: {e}")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]; s.close()
            parts = ip.split("."); parts[-1] = "1"
            return ".".join(parts)
        except Exception:
            return ""

    def local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]; s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def connected_ssid(self) -> str:
        try:
            if WINDOWS:
                rc, out, _ = _run(
                    ["netsh", "wlan", "show", "interfaces"],
                    encoding="utf-8")
                m = re.search(r"^\s*SSID\s+:\s(.+)$", out, re.MULTILINE)
                return m.group(1).strip() if m else ""
            else:
                for cmd in [["iwgetid", "-r"],
                            ["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"]]:
                    rc, out, _ = _run(cmd)
                    if rc == 0 and out.strip():
                        if cmd[0] == "iwgetid":
                            return out.strip()
                        for line in out.splitlines():
                            if line.startswith("yes:"):
                                return line.split(":", 1)[1].strip()
        except Exception as e:
            log.debug(f"connected_ssid: {e}")
        return ""

    def arp_table(self) -> Dict[str, str]:
        """Return {ip: mac} for all ARP entries."""
        result: Dict[str, str] = {}
        try:
            if WINDOWS:
                rc, out, _ = _run(["arp", "-a"], encoding="utf-8")
                for m in re.finditer(r"([\d.]+)\s+([\w-]{17})", out):
                    mac = m.group(2).replace("-", ":").upper()
                    if mac not in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
                        result[m.group(1)] = mac
            else:
                # Try /proc/net/arp first (fastest)
                try:
                    with open("/proc/net/arp") as f:
                        for line in f.readlines()[1:]:
                            parts = line.split()
                            if len(parts) >= 4:
                                ip  = parts[0]
                                mac = parts[3].upper()
                                if mac not in ("00:00:00:00:00:00",
                                               "FF:FF:FF:FF:FF:FF"):
                                    result[ip] = mac
                except Exception:
                    rc, out, _ = _run(["arp", "-n"])
                    for m in re.finditer(r"([\d.]+)\s+\S+\s+([\w:]{17})", out):
                        mac = m.group(2).upper()
                        if mac not in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
                            result[m.group(1)] = mac
        except Exception as e:
            log.debug(f"arp_table: {e}")
        return result

    def interfaces(self) -> List[Dict[str, str]]:
        """Return list of {name, mac, ip, is_wireless} dicts."""
        ifaces: List[Dict[str, str]] = []
        try:
            if WINDOWS:
                rc, out, _ = _run(
                    ["netsh", "wlan", "show", "interfaces"],
                    encoding="utf-8")
                for blk in re.split(r"\n\s*Name\s+:", "\n" + out)[1:]:
                    nm  = blk.splitlines()[0].strip()
                    mac = re.search(r"Physical Address\s+:\s*([\w:]+)", blk)
                    ip  = re.search(r"IPv4 Address\s+:\s*([\d.]+)", blk)
                    ifaces.append({
                        "name":       nm,
                        "mac":        mac.group(1).upper() if mac else "",
                        "ip":         ip.group(1) if ip else "",
                        "is_wireless":True,
                    })
            else:
                rc, out, _ = _run(["iw", "dev"])
                for blk in re.split(r"Interface\s+", out)[1:]:
                    name = blk.split()[0].strip()
                    addr = re.search(r"addr\s+([\w:]+)", blk)
                    ip_  = self._linux_iface_ip(name)
                    ifaces.append({
                        "name":       name,
                        "mac":        addr.group(1).upper() if addr else "",
                        "ip":         ip_,
                        "is_wireless":True,
                    })
        except Exception as e:
            log.debug(f"interfaces: {e}")
        return ifaces

    def _linux_iface_ip(self, iface: str) -> str:
        try:
            rc, out, _ = _run(["ip", "addr", "show", iface])
            m = re.search(r"inet ([\d.]+)/", out)
            return m.group(1) if m else ""
        except Exception:
            return ""

    # ── DNS management ────────────────────────────────────────────────────────

    def get_dns_servers(self) -> List[str]:
        """Return current system DNS servers."""
        servers: List[str] = []
        try:
            if WINDOWS:
                rc, out, _ = _run(
                    ["netsh", "interface", "ip", "show", "dns"],
                    encoding="utf-8")
                servers = re.findall(r"(\d+\.\d+\.\d+\.\d+)", out)
            else:
                # Try systemd-resolved first
                rc, out, _ = _run(["resolvectl", "status"])
                if rc == 0:
                    servers = re.findall(r"DNS Servers?:\s+([\d. ]+)", out)
                    servers = [ip.strip() for s in servers for ip in s.split()]
                if not servers:
                    try:
                        with open("/etc/resolv.conf") as f:
                            servers = re.findall(
                                r"^nameserver\s+([\d.]+)", f.read(), re.MULTILINE)
                    except Exception:
                        pass
        except Exception as e:
            log.debug(f"get_dns_servers: {e}")
        return [s for s in servers if self._is_valid_ip(s)]

    def set_dns(self, server: str, iface: str = "") -> bool:
        """Set primary DNS server."""
        try:
            if WINDOWS:
                iface = iface or "Wi-Fi"
                rc, _, _ = _run([
                    "netsh", "interface", "ip", "set", "dns",
                    f"name={iface}", "static", server])
                return rc == 0
            else:
                # Write resolv.conf
                existing = self.get_dns_servers()
                entries  = [server] + [s for s in existing if s != server]
                lines    = "\n".join(f"nameserver {s}" for s in entries[:3])
                with open("/etc/resolv.conf", "w") as f:
                    f.write(f"# OmniFi DoH enforcement\n{lines}\n")
                return True
        except Exception as e:
            log.debug(f"set_dns: {e}")
            return False

    def flush_dns(self) -> bool:
        """Flush the system DNS cache."""
        try:
            if WINDOWS:
                rc, _, _ = _run(["ipconfig", "/flushdns"])
                return rc == 0
            else:
                for cmd in [
                    ["systemd-resolve", "--flush-caches"],
                    ["resolvectl", "flush-caches"],
                    ["service", "nscd", "restart"],
                    ["killall", "-HUP", "dnsmasq"],
                ]:
                    rc, _, _ = _run(cmd)
                    if rc == 0:
                        return True
        except Exception as e:
            log.debug(f"flush_dns: {e}")
        return False

    def resolve_hostname(self, ip: str, timeout: float = 0.4) -> str:
        """Reverse DNS lookup with timeout."""
        try:
            socket.setdefaulttimeout(timeout)
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ""
        finally:
            socket.setdefaulttimeout(None)

    # ── Monitor mode ──────────────────────────────────────────────────────────

    def is_monitor_mode(self, iface: str) -> bool:
        if WINDOWS:
            return False
        rc, out, _ = _run(["iw", "dev", iface, "info"])
        return "type monitor" in out.lower()

    def enable_monitor_mode(self, iface: str) -> Tuple[bool, str]:
        if WINDOWS:
            return False, "Monitor mode requires Npcap on Windows"
        try:
            _run(["ip",  "link", "set", iface, "down"])
            _run(["iw",  "dev",  iface, "set", "type", "monitor"])
            _run(["ip",  "link", "set", iface, "up"])
            if self.is_monitor_mode(iface):
                return True, f"{iface} is now in monitor mode"
            return False, "Mode switch failed"
        except Exception as e:
            return False, str(e)

    def disable_monitor_mode(self, iface: str) -> Tuple[bool, str]:
        if WINDOWS:
            return False, "N/A"
        try:
            _run(["ip",  "link", "set", iface, "down"])
            _run(["iw",  "dev",  iface, "set", "type", "managed"])
            _run(["ip",  "link", "set", iface, "up"])
            return True, f"{iface} restored to managed mode"
        except Exception as e:
            return False, str(e)

    # ── Firewall ──────────────────────────────────────────────────────────────

    def block_ip(self, ip: str) -> bool:
        if WINDOWS:
            name = f"OmniFi_block_{ip.replace('.','_')}"
            rc, _, _ = _run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={name}", "dir=in", "action=block",
                f"remoteip={ip}"])
            return rc == 0
        else:
            rc, _, _ = _run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
            return rc == 0

    def unblock_ip(self, ip: str) -> bool:
        if WINDOWS:
            name = f"OmniFi_block_{ip.replace('.','_')}"
            rc, _, _ = _run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={name}"])
            return rc == 0
        else:
            rc, _, _ = _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
            return rc == 0

    # ── Process ───────────────────────────────────────────────────────────────

    def is_elevated(self) -> bool:
        if WINDOWS:
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False
        return IS_ROOT

    def open_url(self, url: str):
        import webbrowser
        webbrowser.open(url)

    # ── Validation ────────────────────────────────────────────────────────────

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False


# ── Singleton ─────────────────────────────────────────────────────────────────
OS = _OSCompat()
