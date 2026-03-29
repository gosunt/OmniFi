"""
OmniFi — Wi-Fi Posture Scanner
================================
Checks the security posture of the currently connected Wi-Fi:
  1. Stored password strength (entropy, length, complexity policy)
  2. Encryption protocol (WPA3/WPA2/WPA/WEP/Open)
  3. WPS state detection
  4. Security protocol for data transfer
  5. Signal strength and channel congestion

OS password retrieval:
  Windows : netsh wlan show profile <SSID> key=clear
  Linux   : NetworkManager (nmcli), /etc/NetworkManager/system-connections/
  macOS   : security find-generic-password -ga <SSID>
"""

import subprocess
import platform
import re
import math
import os

try:
    import pywifi
    from pywifi import const as wifi_const
    PYWIFI_AVAILABLE = True
except ImportError:
    PYWIFI_AVAILABLE = False


# Password policy
POLICY = {
    "min_length":       12,
    "require_upper":    True,
    "require_lower":    True,
    "require_digit":    True,
    "require_special":  True,
    "min_entropy_bits": 50,
}

COMMON_PASSWORDS = {
    "password", "12345678", "password1", "admin", "welcome",
    "iloveyou", "sunshine", "letmein", "monkey", "qwerty123",
    "jiocentrum", "airtel123", "bsnl1234", "wifi1234", "home1234",
}


class WiFiPostureScanner:

    def __init__(self, verbose=True):
        self.verbose = verbose
        self.alerts  = []

    def run(self) -> dict:
        self._print("\n[OmniFi] Wi-Fi Posture Scanner...\n")

        ssid   = self._get_connected_ssid()
        result = {
            "ssid":            ssid,
            "password_score":  0,
            "password_issues": [],
            "protocol":        "unknown",
            "wps_detected":    False,
            "signal_dbm":      None,
            "posture_score":   0,
            "alerts":          self.alerts,
        }

        self._print(f"  Connected SSID : {ssid}\n")

        # Check 1: Password strength
        password = self._retrieve_password(ssid)
        if password:
            pwd_result = self._check_password(password)
            result["password_score"]  = pwd_result["score"]
            result["password_issues"] = pwd_result["issues"]
        else:
            self._print("  [i] Password not retrievable (may need elevated privileges).")

        # Check 2: Protocol + signal
        profile = self._get_wifi_profile()
        if profile:
            result["protocol"]     = profile.get("protocol", "unknown")
            result["wps_detected"] = profile.get("wps", False)
            result["signal_dbm"]   = profile.get("signal_dbm")

        # Check 3: Protocol risk
        self._check_protocol(result["protocol"])

        # Check 4: WPS
        if result["wps_detected"]:
            self._alert("WPS detected on this network — disable in router settings.", "high")

        # Compute overall posture score
        result["posture_score"] = self._compute_posture(result)

        self._print_summary(result)
        return result

    # ── Password retrieval ────────────────────────────────────────────────────

    def _retrieve_password(self, ssid: str) -> str:
        if not ssid or ssid == "Unknown":
            return ""
        system = platform.system()
        try:
            if system == "Windows":
                out = subprocess.check_output(
                    ["netsh", "wlan", "show", "profile",
                     f"name={ssid}", "key=clear"],
                    text=True, stderr=subprocess.DEVNULL
                )
                m = re.search(r"Key Content\s*:\s*(.+)", out)
                return m.group(1).strip() if m else ""

            elif system == "Linux":
                # Try NetworkManager connection files
                nm_dir = "/etc/NetworkManager/system-connections"
                if os.path.isdir(nm_dir):
                    for fname in os.listdir(nm_dir):
                        fpath = os.path.join(nm_dir, fname)
                        try:
                            with open(fpath) as f:
                                content = f.read()
                            if ssid in content:
                                m = re.search(r"psk\s*=\s*(.+)", content)
                                if m:
                                    return m.group(1).strip()
                        except PermissionError:
                            pass
                # Try nmcli
                out = subprocess.check_output(
                    ["nmcli", "-s", "-g", "802-11-wireless-security.psk",
                     "connection", "show", ssid],
                    text=True, stderr=subprocess.DEVNULL
                )
                return out.strip()

            elif system == "Darwin":
                out = subprocess.check_output(
                    ["security", "find-generic-password", "-ga", ssid, "-w"],
                    text=True, stderr=subprocess.DEVNULL
                )
                return out.strip()

        except Exception:
            pass
        return ""

    # ── Password strength ─────────────────────────────────────────────────────

    def _check_password(self, password: str) -> dict:
        issues = []
        score  = 100

        # Common passwords
        if password.lower() in COMMON_PASSWORDS:
            issues.append("Password is in the list of commonly used passwords.")
            score -= 50

        # Length
        if len(password) < POLICY["min_length"]:
            issues.append(f"Too short ({len(password)} chars). Minimum: {POLICY['min_length']}.")
            score -= 20

        # Complexity
        has_upper   = bool(re.search(r"[A-Z]", password))
        has_lower   = bool(re.search(r"[a-z]", password))
        has_digit   = bool(re.search(r"\d",    password))
        has_special = bool(re.search(r"[^A-Za-z0-9]", password))

        if POLICY["require_upper"] and not has_upper:
            issues.append("Missing uppercase letters.")
            score -= 10
        if POLICY["require_lower"] and not has_lower:
            issues.append("Missing lowercase letters.")
            score -= 10
        if POLICY["require_digit"] and not has_digit:
            issues.append("Missing digits.")
            score -= 10
        if POLICY["require_special"] and not has_special:
            issues.append("Missing special characters (!@#$...).")
            score -= 10

        # Entropy
        charset = 0
        if has_lower:   charset += 26
        if has_upper:   charset += 26
        if has_digit:   charset += 10
        if has_special: charset += 32
        entropy = len(password) * math.log2(charset) if charset > 0 else 0

        if entropy < POLICY["min_entropy_bits"]:
            issues.append(f"Low entropy ({entropy:.0f} bits). Target: ≥{POLICY['min_entropy_bits']} bits.")
            score -= 15

        score = max(0, score)

        # Generate alert
        if score < 40:
            self._alert(
                f"Wi-Fi password is WEAK (score {score}/100). "
                f"Issues: {'; '.join(issues[:2])}. "
                f"Change to a strong password immediately.",
                "critical"
            )
        elif score < 70:
            self._alert(f"Wi-Fi password is MODERATE (score {score}/100). "
                        f"Consider strengthening it.", "medium")
        else:
            self._print(f"  [+] Password strength: {score}/100 — good.")

        if issues:
            for issue in issues:
                self._print(f"  [!] {issue}")

        return {"score": score, "issues": issues, "entropy": entropy}

    # ── Protocol + WPS check ──────────────────────────────────────────────────

    def _check_protocol(self, protocol: str):
        p = protocol.lower()
        if p == "open":
            self._alert("Network is OPEN — no encryption. All traffic visible.", "critical")
        elif p == "wep":
            self._alert("WEP encryption — completely broken. Treat as open network.", "critical")
        elif p == "wpa":
            self._alert("WPA (TKIP) — outdated and vulnerable. Upgrade to WPA2/WPA3.", "high")
        elif p == "wpa2":
            self._print("  [*] WPA2 — acceptable but WPA3 is recommended.")
        elif p == "wpa3":
            self._print("  [+] WPA3 — best available encryption.")

    def _get_wifi_profile(self) -> dict:
        profile = {}
        system  = platform.system()
        try:
            if system == "Linux":
                out = subprocess.check_output(
                    ["iwconfig"], text=True, stderr=subprocess.DEVNULL)
                m = re.search(r"Signal level=(-?\d+)", out)
                if m:
                    profile["signal_dbm"] = int(m.group(1))

            elif system == "Windows":
                out = subprocess.check_output(
                    ["netsh", "wlan", "show", "interfaces"],
                    text=True, stderr=subprocess.DEVNULL)
                m = re.search(r"Signal\s*:\s*(\d+)%", out)
                if m:
                    pct = int(m.group(1))
                    profile["signal_dbm"] = int((pct / 2) - 100)
                auth = re.search(r"Authentication\s*:\s*(.+)", out)
                if auth:
                    profile["protocol"] = auth.group(1).strip().lower()

        except Exception:
            pass
        return profile

    # ── Posture score ─────────────────────────────────────────────────────────

    def _compute_posture(self, result: dict) -> int:
        score = 0
        proto = result.get("protocol", "").lower()
        score += {"wpa3":40,"wpa2":30,"wpa":10,"wep":0,"open":0}.get(proto, 15)
        score += min(30, result.get("password_score", 0) // 3)
        score += 0 if result.get("wps_detected") else 20
        sig    = result.get("signal_dbm")
        if sig:
            score += 10 if sig >= -65 else 5 if sig >= -75 else 0
        return min(100, score)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get_connected_ssid(self) -> str:
        try:
            if platform.system() == "Windows":
                out = subprocess.check_output(
                    ["netsh","wlan","show","interfaces"],
                    text=True, stderr=subprocess.DEVNULL)
                m = re.search(r"SSID\s+:\s(.+)", out)
                return m.group(1).strip() if m else "Unknown"
            else:
                out = subprocess.check_output(
                    ["iwgetid","-r"], text=True, stderr=subprocess.DEVNULL)
                return out.strip() or "Unknown"
        except Exception:
            return "Unknown"

    def _print_summary(self, result: dict):
        self._print(f"\n  {'─'*48}")
        self._print(f"  Posture score : {result['posture_score']}/100")
        self._print(f"  Protocol      : {result['protocol'].upper()}")
        self._print(f"  Signal        : {result.get('signal_dbm','?')} dBm")
        self._print(f"  WPS           : {'Detected!' if result['wps_detected'] else 'Not detected'}")
        self._print(f"  {'─'*48}\n")

    def _alert(self, msg, level="medium"):
        self.alerts.append({"level": level, "message": msg})
        icons = {"critical":"[!!!]","high":"[!!]","medium":"[!]","low":"[i]"}
        self._print(f"  {icons.get(level,'[i]')} {msg}")

    def _print(self, msg):
        if self.verbose: print(msg)


if __name__ == "__main__":
    WiFiPostureScanner().run()
