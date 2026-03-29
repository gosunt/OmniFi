"""
OmniFi — Automatic VPN Launcher
==================================
When OmniFi detects an unsafe network (score < 50) or an active attack
(DNS spoof, ARP MITM, evil twin), automatically trigger a VPN connection.

Supported VPN types:
  - WireGuard  : wg-quick up <profile>
  - OpenVPN    : openvpn --config <file> --daemon
  - Custom     : any shell command defined in config.yaml

Config in config.yaml:
  vpn:
    type: wireguard          # wireguard | openvpn | custom
    profile: wg0             # WireGuard interface name OR OpenVPN .ovpn path
    auto_trigger_score: 50   # trigger VPN if network score < this
    auto_trigger_attacks:    # trigger VPN on these attack detections
      - dns_spoof
      - arp_mitm
      - evil_twin
      - rogue_dhcp
"""

import subprocess
import platform
import os
import time

# Default config — overridden by config.yaml in production
DEFAULT_CONFIG = {
    "type":                  "wireguard",
    "profile":               "wg0",
    "auto_trigger_score":    50,
    "auto_trigger_attacks":  ["dns_spoof", "arp_mitm", "evil_twin", "rogue_dhcp"],
}


class VPNLauncher:
    def __init__(self, config: dict = None, verbose=True):
        self.config  = config or DEFAULT_CONFIG
        self.verbose = verbose
        self.active  = False
        self.alerts  = []

    # ── Public methods ────────────────────────────────────────────────────────

    def check_and_trigger(self, network_score: int = 100,
                          detected_attacks: list = None) -> bool:
        """
        Evaluate current network state and trigger VPN if necessary.
        Returns True if VPN was launched.
        """
        detected_attacks = detected_attacks or []
        threshold  = self.config.get("auto_trigger_score", 50)
        watch_atks = self.config.get("auto_trigger_attacks", [])

        trigger_reason = ""

        if network_score < threshold:
            trigger_reason = f"Network score {network_score}/100 is below threshold {threshold}"

        for atk in detected_attacks:
            if atk in watch_atks:
                trigger_reason = f"Attack detected: {atk}"
                break

        if trigger_reason:
            self._print(f"\n  [!] VPN auto-trigger: {trigger_reason}")
            return self.connect()

        return False

    def connect(self) -> bool:
        """Launch the configured VPN."""
        vpn_type = self.config.get("type", "wireguard")
        profile  = self.config.get("profile", "wg0")

        self._print(f"\n[OmniFi] Launching VPN ({vpn_type} / {profile})...")

        if vpn_type == "wireguard":
            return self._connect_wireguard(profile)
        elif vpn_type == "openvpn":
            return self._connect_openvpn(profile)
        elif vpn_type == "custom":
            return self._connect_custom(profile)
        else:
            self._print(f"  [!] Unknown VPN type: {vpn_type}")
            return False

    def disconnect(self) -> bool:
        """Disconnect the active VPN."""
        vpn_type = self.config.get("type", "wireguard")
        profile  = self.config.get("profile", "wg0")

        self._print(f"\n[OmniFi] Disconnecting VPN ({vpn_type})...")

        if vpn_type == "wireguard":
            return self._run(["wg-quick", "down", profile])
        elif vpn_type == "openvpn":
            return self._run(["pkill", "openvpn"])
        return False

    def status(self) -> dict:
        """Check if VPN is currently active."""
        vpn_type = self.config.get("type", "wireguard")
        profile  = self.config.get("profile", "wg0")

        try:
            if vpn_type == "wireguard":
                out = subprocess.check_output(["wg", "show", profile],
                                              text=True, stderr=subprocess.DEVNULL)
                is_up = "interface:" in out.lower()
            elif vpn_type == "openvpn":
                out = subprocess.check_output(["pgrep", "openvpn"],
                                              text=True, stderr=subprocess.DEVNULL)
                is_up = bool(out.strip())
            else:
                is_up = False
        except Exception:
            is_up = False

        self.active = is_up
        return {"active": is_up, "type": vpn_type, "profile": profile}

    # ── Private methods ───────────────────────────────────────────────────────

    def _connect_wireguard(self, profile: str) -> bool:
        if platform.system() == "Windows":
            # WireGuard on Windows uses a different CLI
            return self._run(["wireguard", "/installtunnelservice", profile])
        return self._run(["wg-quick", "up", profile])

    def _connect_openvpn(self, profile: str) -> bool:
        if not os.path.isfile(profile):
            self._print(f"  [!] OpenVPN config file not found: {profile}")
            return False
        return self._run(["openvpn", "--config", profile, "--daemon"])

    def _connect_custom(self, command: str) -> bool:
        return self._run(command.split())

    def _run(self, cmd: list) -> bool:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                self.active = True
                self._print(f"  [+] VPN connected successfully.")
                return True
            else:
                self._print(f"  [!] VPN command failed: {result.stderr.strip()}")
                self._alert(f"VPN launch failed: {result.stderr.strip()}", "high")
                return False
        except FileNotFoundError:
            self._print(f"  [!] VPN binary not found. Install WireGuard or OpenVPN.")
            self._alert("VPN binary not found on this system.", "medium")
            return False
        except subprocess.TimeoutExpired:
            self._print(f"  [!] VPN connection timed out.")
            return False

    def _alert(self, msg, level="medium"):
        self.alerts.append({"level": level, "message": msg})

    def _print(self, msg):
        if self.verbose: print(msg)


if __name__ == "__main__":
    launcher = VPNLauncher()
    # Demo: trigger on low score
    launcher.check_and_trigger(network_score=35, detected_attacks=["dns_spoof"])
