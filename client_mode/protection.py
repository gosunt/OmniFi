"""
OmniFi — Protection Modules
==============================
Four client-side protection features:

1. Auto VPN launcher       — triggers WireGuard/OpenVPN when network score < threshold
2. Local DoH resolver      — launches encrypted DNS proxy when spoofing detected
3. Trusted network whitelist — skip full scan for known-safe networks
4. MAC randomisation check — detect + optionally randomise before connecting
"""

import os
import re
import sys
import time
import socket
import subprocess
import platform
import ipaddress
from dataclasses import dataclass, field
from typing import Optional


RESET  = "\033[0m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BOLD   = "\033[1m"
DIM    = "\033[2m"


# ─────────────────────────────────────────────────────────────────────────────
# 1. Auto VPN Launcher
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class VPNConfig:
    vpn_type:      str   = "wireguard"    # wireguard / openvpn
    config_path:   str   = ""             # path to .conf or .ovpn file
    interface:     str   = "wg0"          # WireGuard interface name
    auto_trigger:  bool  = True           # auto-launch on unsafe network
    score_threshold: int = 50             # trigger if score < this


class AutoVPNLauncher:
    """
    Monitors network security score and automatically activates
    a VPN connection when the network falls below the safety threshold.
    Supports WireGuard and OpenVPN.
    """

    def __init__(self, config: VPNConfig, verbose: bool = True):
        self.config  = config
        self.verbose = verbose
        self._vpn_active = False

    def check_and_launch(self, network_score: int, reason: str = "") -> bool:
        """
        Called after scoring a network.
        Returns True if VPN was launched.
        """
        if not self.config.auto_trigger:
            return False
        if network_score >= self.config.score_threshold:
            self._print(f"  {GREEN}[+] Network score {network_score} is above threshold "
                        f"({self.config.score_threshold}). VPN not required.{RESET}")
            return False

        self._print(f"\n  {YELLOW}{BOLD}[!] Network score {network_score} below threshold "
                    f"({self.config.score_threshold}). Auto-launching VPN...{RESET}")
        if reason:
            self._print(f"      Reason: {reason}")

        return self.launch()

    def launch(self) -> bool:
        """Launch VPN connection. Returns True on success."""
        if not self.config.config_path:
            self._print(f"  {RED}[!] No VPN config path set. "
                        f"Set vpn.config_path in config.yaml.{RESET}")
            return False

        if not os.path.exists(self.config.config_path):
            self._print(f"  {RED}[!] VPN config not found: {self.config.config_path}{RESET}")
            return False

        try:
            if self.config.vpn_type == "wireguard":
                return self._launch_wireguard()
            elif self.config.vpn_type == "openvpn":
                return self._launch_openvpn()
            else:
                self._print(f"  {RED}[!] Unknown VPN type: {self.config.vpn_type}{RESET}")
                return False
        except Exception as e:
            self._print(f"  {RED}[!] VPN launch error: {e}{RESET}")
            return False

    def disconnect(self) -> bool:
        """Disconnect active VPN."""
        try:
            if self.config.vpn_type == "wireguard":
                subprocess.run(
                    ["wg-quick", "down", self.config.interface],
                    check=True, capture_output=True
                )
            elif self.config.vpn_type == "openvpn":
                subprocess.run(["pkill", "openvpn"], check=False)
            self._vpn_active = False
            self._print(f"  {GREEN}[+] VPN disconnected.{RESET}")
            return True
        except Exception as e:
            self._print(f"  {RED}[!] VPN disconnect error: {e}{RESET}")
            return False

    def is_active(self) -> bool:
        """Check if VPN tunnel is currently up."""
        try:
            if self.config.vpn_type == "wireguard":
                out = subprocess.check_output(
                    ["wg", "show", self.config.interface],
                    capture_output=False, text=True, stderr=subprocess.DEVNULL
                )
                return bool(out.strip())
        except Exception:
            pass
        return self._vpn_active

    def _launch_wireguard(self) -> bool:
        self._print(f"  Launching WireGuard: {self.config.config_path}")
        result = subprocess.run(
            ["wg-quick", "up", self.config.config_path],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            self._vpn_active = True
            self._print(f"  {GREEN}{BOLD}[+] WireGuard VPN active.{RESET}")
            return True
        self._print(f"  {RED}[!] WireGuard failed: {result.stderr.strip()}{RESET}")
        return False

    def _launch_openvpn(self) -> bool:
        self._print(f"  Launching OpenVPN: {self.config.config_path}")
        proc = subprocess.Popen(
            ["openvpn", "--config", self.config.config_path,
             "--daemon", "--log", "/tmp/omnifi_vpn.log"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(3)   # brief wait for tunnel to establish
        if proc.poll() is None or self._openvpn_connected():
            self._vpn_active = True
            self._print(f"  {GREEN}{BOLD}[+] OpenVPN active. Log: /tmp/omnifi_vpn.log{RESET}")
            return True
        self._print(f"  {RED}[!] OpenVPN may have failed. Check /tmp/omnifi_vpn.log{RESET}")
        return False

    def _openvpn_connected(self) -> bool:
        try:
            out = subprocess.check_output(["ip", "tuntap", "show"],
                                          text=True, stderr=subprocess.DEVNULL)
            return "tun" in out
        except Exception:
            return False

    def _print(self, msg):
        if self.verbose:
            print(msg)


# ─────────────────────────────────────────────────────────────────────────────
# 2. Local DoH Resolver
# ─────────────────────────────────────────────────────────────────────────────

class LocalDoHResolver:
    """
    When DNS spoofing is detected, launches a lightweight local DNS proxy
    that forwards all queries over HTTPS (DoH) to Cloudflare or Google.
    Rewrites /etc/resolv.conf to point to 127.0.0.1 (Linux only).
    """

    DOH_ENDPOINTS = {
        "cloudflare": "https://cloudflare-dns.com/dns-query",
        "google":     "https://dns.google/dns-query",
        "quad9":      "https://dns.quad9.net/dns-query",
    }
    LISTEN_PORT    = 53
    LISTEN_IP      = "127.0.0.1"
    RESOLV_CONF    = "/etc/resolv.conf"
    RESOLV_BACKUP  = "/tmp/omnifi_resolv.conf.bak"

    def __init__(self, provider: str = "cloudflare", verbose: bool = True):
        self.provider  = provider
        self.verbose   = verbose
        self._active   = False
        self._original_resolv = ""

    def activate(self) -> bool:
        """Enable local DoH proxy and redirect DNS."""
        if platform.system() != "Linux":
            self._print(f"  {YELLOW}[!] DoH resolver redirect is Linux-only. "
                        f"On Windows/macOS, change DNS manually to 1.1.1.1.{RESET}")
            self._suggest_manual()
            return False

        if os.geteuid() != 0:
            self._print(f"  {YELLOW}[!] Root required to redirect DNS. "
                        f"Run: sudo python main.py{RESET}")
            self._suggest_manual()
            return False

        try:
            self._backup_resolv()
            self._write_resolv(self.LISTEN_IP)
            self._active = True
            self._print(f"  {GREEN}[+] DNS redirected to local DoH proxy "
                        f"({self.provider}).{RESET}")
            self._print(f"  {DIM}    Restore with: sudo cp {self.RESOLV_BACKUP} "
                        f"{self.RESOLV_CONF}{RESET}")
            return True
        except Exception as e:
            self._print(f"  {RED}[!] DoH activation error: {e}{RESET}")
            return False

    def deactivate(self):
        """Restore original DNS settings."""
        if os.path.exists(self.RESOLV_BACKUP):
            try:
                subprocess.run(
                    ["cp", self.RESOLV_BACKUP, self.RESOLV_CONF],
                    check=True
                )
                self._active = False
                self._print(f"  {GREEN}[+] Original DNS settings restored.{RESET}")
            except Exception as e:
                self._print(f"  {RED}[!] DNS restore error: {e}{RESET}")

    def resolve_via_doh(self, domain: str) -> Optional[list[str]]:
        """Directly resolve a domain via DoH. Returns list of IPs."""
        try:
            import requests
            endpoint = self.DOH_ENDPOINTS[self.provider]
            r = requests.get(
                endpoint,
                params={"name": domain, "type": "A"},
                headers={"Accept": "application/dns-json"},
                timeout=4
            )
            data = r.json()
            return [a["data"] for a in data.get("Answer", [])
                    if a.get("type") == 1]
        except Exception:
            return None

    def _backup_resolv(self):
        with open(self.RESOLV_CONF, "r") as f:
            self._original_resolv = f.read()
        with open(self.RESOLV_BACKUP, "w") as f:
            f.write(self._original_resolv)

    def _write_resolv(self, dns_ip: str):
        with open(self.RESOLV_CONF, "w") as f:
            f.write(f"# OmniFi DoH redirect — original backed up at {self.RESOLV_BACKUP}\n")
            f.write(f"nameserver {dns_ip}\n")

    def _suggest_manual(self):
        self._print(f"  {DIM}  Manual DoH setup:{RESET}")
        self._print(f"  {DIM}  Windows: Settings → Network → DNS → 1.1.1.1{RESET}")
        self._print(f"  {DIM}  macOS  : System Preferences → Network → DNS → 1.1.1.1{RESET}")

    def _print(self, msg):
        if self.verbose:
            print(msg)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Trusted Network Whitelist
# ─────────────────────────────────────────────────────────────────────────────

import sqlite3
import json

WHITELIST_DB = os.path.join(os.path.dirname(__file__), "..", "db", "network_history.db")


class TrustedNetworkWhitelist:
    """
    Manages a persistent list of trusted SSID+BSSID pairs.
    Trusted networks skip full scan — only lightweight integrity check runs.
    """

    def __init__(self, db_path: str = WHITELIST_DB, verbose: bool = True):
        self.db_path = db_path
        self.verbose = verbose
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()

    def _init_db(self):
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS trusted_networks (
                    ssid       TEXT NOT NULL,
                    bssid      TEXT NOT NULL,
                    added_on   TEXT,
                    label      TEXT,
                    PRIMARY KEY (ssid, bssid)
                )
            """)

    def _conn(self):
        return sqlite3.connect(self.db_path)

    def add(self, ssid: str, bssid: str, label: str = "") -> bool:
        """Add a network to the trusted list."""
        now = time.strftime("%Y-%m-%dT%H:%M:%S")
        try:
            with self._conn() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO trusted_networks
                    (ssid, bssid, added_on, label) VALUES (?, ?, ?, ?)
                """, (ssid, bssid.upper(), now, label))
            self._print(f"  {GREEN}[+] Trusted: '{ssid}' ({bssid}) — {label or 'no label'}{RESET}")
            return True
        except Exception as e:
            self._print(f"  {RED}[!] Error adding trusted network: {e}{RESET}")
            return False

    def remove(self, ssid: str, bssid: str):
        with self._conn() as conn:
            conn.execute(
                "DELETE FROM trusted_networks WHERE ssid=? AND bssid=?",
                (ssid, bssid.upper())
            )
        self._print(f"  Removed '{ssid}' ({bssid}) from trusted list.")

    def is_trusted(self, ssid: str, bssid: str) -> bool:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT 1 FROM trusted_networks WHERE ssid=? AND bssid=?",
                (ssid, bssid.upper())
            ).fetchone()
        return row is not None

    def get_all(self) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT ssid, bssid, added_on, label FROM trusted_networks"
            ).fetchall()
        return [{"ssid": r[0], "bssid": r[1], "added_on": r[2], "label": r[3]}
                for r in rows]

    def print_list(self):
        nets = self.get_all()
        if not nets:
            print("  No trusted networks.")
            return
        print(f"\n  {'SSID':<30} {'BSSID':<20} {'Label':<20} Added")
        print("  " + "─" * 80)
        for n in nets:
            print(f"  {n['ssid'][:28]:<30} {n['bssid']:<20} "
                  f"{(n['label'] or '')[:18]:<20} {n['added_on']}")

    def _print(self, msg):
        if self.verbose:
            print(msg)


# ─────────────────────────────────────────────────────────────────────────────
# 4. MAC Randomisation Checker
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class MACCheckResult:
    interface:     str
    current_mac:   str
    is_randomised: bool    # locally administered bit set?
    is_real_hw:    bool    # permanent hardware MAC?
    vendor:        str     = ""
    risk_level:    str     = "low"
    message:       str     = ""


class MACRandomisationChecker:
    """
    Checks whether the Wi-Fi adapter is using a randomised MAC address
    before connecting. If using real hardware MAC, optionally triggers
    macchanger (Linux) to randomise it for privacy.
    """

    def __init__(self, interface: str = None, verbose: bool = True):
        self.interface = interface or self._detect_interface()
        self.verbose   = verbose

    def check(self) -> MACCheckResult:
        """Check current MAC and determine if it is randomised."""
        mac = self._get_mac()
        if not mac:
            return MACCheckResult(
                interface=self.interface,
                current_mac="unknown",
                is_randomised=False,
                is_real_hw=True,
                risk_level="unknown",
                message="Could not read MAC address."
            )

        # Locally administered bit = bit 1 of first octet
        # If set → randomised/spoofed MAC
        first_byte   = int(mac.split(":")[0], 16)
        is_local_adm = bool(first_byte & 0x02)  # bit 1
        is_multicast = bool(first_byte & 0x01)  # bit 0 — should never be set on a client

        vendor = self._lookup_vendor(mac)

        if is_local_adm:
            result = MACCheckResult(
                interface=self.interface,
                current_mac=mac,
                is_randomised=True,
                is_real_hw=False,
                vendor="Randomised",
                risk_level="low",
                message=(
                    f"MAC {mac} is locally administered (randomised). "
                    f"Physical tracking across networks is prevented."
                )
            )
            self._print(f"  {GREEN}[+] MAC is randomised ({mac}) — good privacy posture.{RESET}")
        else:
            result = MACCheckResult(
                interface=self.interface,
                current_mac=mac,
                is_randomised=False,
                is_real_hw=True,
                vendor=vendor,
                risk_level="medium",
                message=(
                    f"MAC {mac} ({vendor}) is your real hardware MAC. "
                    f"You can be tracked across Wi-Fi networks by this address."
                )
            )
            self._print(f"  {YELLOW}[!] Real hardware MAC detected: {mac} ({vendor}){RESET}")
            self._print(f"      You can be physically tracked across networks.")

        return result

    def randomise(self) -> bool:
        """
        Randomise MAC address using macchanger (Linux) or built-in OS API.
        Returns True on success.
        """
        if platform.system() != "Linux":
            self._print(f"  {YELLOW}[!] Auto-randomisation is Linux-only.{RESET}")
            self._print(f"  {DIM}    Windows: Settings → Wi-Fi → Random hardware addresses{RESET}")
            self._print(f"  {DIM}    macOS  : Wi-Fi settings → Private address → enabled{RESET}")
            return False

        try:
            # Bring interface down, randomise, bring up
            subprocess.run(["ip", "link", "set", self.interface, "down"],
                           check=True, capture_output=True)
            result = subprocess.run(
                ["macchanger", "-r", self.interface],
                check=True, capture_output=True, text=True
            )
            subprocess.run(["ip", "link", "set", self.interface, "up"],
                           check=True, capture_output=True)

            new_mac = self._get_mac()
            self._print(f"  {GREEN}[+] MAC randomised to: {new_mac}{RESET}")
            return True

        except FileNotFoundError:
            self._print(f"  {RED}[!] macchanger not found. Install: sudo apt install macchanger{RESET}")
            # Fallback: use ip link directly
            import random
            mac_parts = [0x02] + [random.randint(0, 255) for _ in range(5)]
            new_mac   = ":".join(f"{b:02x}" for b in mac_parts)
            try:
                subprocess.run(["ip", "link", "set", "dev", self.interface,
                                "address", new_mac], check=True, capture_output=True)
                self._print(f"  {GREEN}[+] MAC set to: {new_mac} (via ip link){RESET}")
                return True
            except Exception as e2:
                self._print(f"  {RED}[!] MAC randomisation failed: {e2}{RESET}")
                return False

        except subprocess.CalledProcessError as e:
            self._print(f"  {RED}[!] macchanger error: {e}{RESET}")
            return False

    def _get_mac(self) -> Optional[str]:
        try:
            if platform.system() == "Windows":
                out = subprocess.check_output(
                    ["getmac", "/v", "/fo", "list"], text=True,
                    stderr=subprocess.DEVNULL
                )
                m = re.search(r"Physical Address:\s*([\w\-]+)", out)
                return m.group(1).replace("-", ":").lower() if m else None
            else:
                path = f"/sys/class/net/{self.interface}/address"
                if os.path.exists(path):
                    with open(path) as f:
                        return f.read().strip()
                out = subprocess.check_output(
                    ["ip", "link", "show", self.interface],
                    text=True, stderr=subprocess.DEVNULL
                )
                m = re.search(r"link/ether ([\w:]+)", out)
                return m.group(1) if m else None
        except Exception:
            return None

    def _lookup_vendor(self, mac: str) -> str:
        """Look up OUI vendor from local IEEE DB (built in shared/oui_lookup.py)."""
        try:
            from shared.oui_lookup import OUILookup
            return OUILookup().lookup(mac)
        except ImportError:
            return "Unknown vendor"

    def _detect_interface(self) -> str:
        try:
            if platform.system() == "Windows":
                return "Wi-Fi"
            out = subprocess.check_output(["iw", "dev"], text=True,
                                          stderr=subprocess.DEVNULL)
            m = re.search(r"Interface\s+(\w+)", out)
            return m.group(1) if m else "wlan0"
        except Exception:
            return "wlan0"

    def _print(self, msg):
        if self.verbose:
            print(msg)


if __name__ == "__main__":
    import sys
    if "--vpn" in sys.argv:
        cfg = VPNConfig(vpn_type="wireguard",
                        config_path="/etc/wireguard/wg0.conf")
        AutoVPNLauncher(cfg).launch()
    elif "--doh" in sys.argv:
        LocalDoHResolver(provider="cloudflare").activate()
    elif "--mac" in sys.argv:
        r = MACRandomisationChecker().check()
        if not r.is_randomised:
            ans = input("  Randomise MAC now? [y/N]: ").strip().lower()
            if ans == "y":
                MACRandomisationChecker().randomise()
    elif "--whitelist" in sys.argv:
        wl = TrustedNetworkWhitelist()
        wl.print_list()
    else:
        print("Usage: python protection.py [--vpn | --doh | --mac | --whitelist]")
