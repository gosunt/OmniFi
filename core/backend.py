"""
OmniFi — Backend Glue Layer
==============================
Wraps all existing detection modules into a single clean API
consumed by the PyQt6 UI. Owns the AlertEngine singleton and
the PolicyEngine. Provides every callable the UI needs.

All heavy work runs in QThread workers — this class itself
never blocks the GUI thread.
"""
import sys, os, re, json, math, time, socket, hashlib, secrets
import subprocess, platform, datetime, threading, logging, warnings

# Suppress Scapy TripleDES deprecation warning
warnings.filterwarnings("ignore", message=".*TripleDES.*")
warnings.filterwarnings("ignore", category=DeprecationWarning, module=".*scapy.*")
try:
    from cryptography.utils import CryptographyDeprecationWarning as _CDW
    warnings.filterwarnings("ignore", category=_CDW)
except Exception:
    pass

from PyQt6.QtCore import QObject

# ── Make omnifi/ package importable ──────────────────────────────────────────
_PKG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "..", "omnifi")
_PKG = os.path.normpath(_PKG)
if _PKG not in sys.path:
    sys.path.insert(0, os.path.dirname(_PKG))

# ── Optional heavy imports (graceful fallback) ────────────────────────────────
try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAVE_REQ = True
except ImportError:
    HAVE_REQ = False

try:
    import pywifi
    HAVE_WIFI = True
except ImportError:
    HAVE_WIFI = False

try:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        import scapy.all  # noqa
    HAVE_SCAPY = True
except Exception:
    HAVE_SCAPY = False

WINDOWS = platform.system() == "Windows"
LINUX   = platform.system() == "Linux"
IS_ROOT = (not WINDOWS) and (os.geteuid() == 0)

log = logging.getLogger("OmniFi.Backend")


# ─────────────────────────────────────────────────────────────────────────────
# PBKDF2-SHA256 credential hashing
# ─────────────────────────────────────────────────────────────────────────────
def hash_cred(password: str) -> dict:
    salt = secrets.token_bytes(16)
    dk   = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return {"hash": dk.hex(), "salt": salt.hex(), "algo": "PBKDF2-SHA256-100k"}

def verify_cred(password: str, stored: dict) -> bool:
    salt = bytes.fromhex(stored["salt"])
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, 100_000).hex() == stored["hash"]


# ─────────────────────────────────────────────────────────────────────────────
# Password strength scorer (inline — no extra import)
# ─────────────────────────────────────────────────────────────────────────────
_COMMON = {
    "password","12345678","admin","welcome","letmein","qwerty123",
    "jiocentrum","airtel123","bsnl1234","wifi1234","home1234",
    "password1","iloveyou","sunshine","monkey","123456","123456789",
    "admin123","router","network","internet","broadband","excitel",
    "stdonu101","admintelecom","00000000","11111111","jio@123",
    "jiofi","bsnl@1234","tataplay","hathway","railwire","mtnl1234",
}

def score_password(pwd: str) -> dict:
    if not pwd:
        return {"score":0,"issues":["No password — open network"],"entropy":0.0}
    issues, score = [], 100
    if pwd.lower() in _COMMON:
        issues.append("Known default password — change immediately!"); score -= 60
    if len(pwd) < 12:
        issues.append(f"Too short ({len(pwd)} chars). Min 12."); score -= 20
    has_u = bool(re.search(r"[A-Z]", pwd))
    has_l = bool(re.search(r"[a-z]", pwd))
    has_d = bool(re.search(r"\d", pwd))
    has_s = bool(re.search(r"[^A-Za-z0-9]", pwd))
    if not has_u: issues.append("No uppercase letters."); score -= 8
    if not has_l: issues.append("No lowercase letters."); score -= 8
    if not has_d: issues.append("No digits."); score -= 8
    if not has_s: issues.append("No special characters."); score -= 8
    cs      = (26 if has_l else 0)+(26 if has_u else 0)+(10 if has_d else 0)+(32 if has_s else 0)
    entropy = len(pwd)*math.log2(cs) if cs > 0 else 0.0
    if entropy < 50:
        issues.append(f"Low entropy ({entropy:.0f} bits). Target ≥50."); score -= 12
    return {"score": max(0,min(100,score)), "issues": issues, "entropy": round(entropy,1)}

def mask_pwd(p: str) -> str:
    if not p: return ""
    return p[:2]+"*"*max(0,len(p)-4)+p[-2:] if len(p)>4 else "****"


# ─────────────────────────────────────────────────────────────────────────────
# OS helpers
# ─────────────────────────────────────────────────────────────────────────────
def gateway_ip() -> str:
    try:
        if WINDOWS:
            o = subprocess.check_output(["ipconfig"], text=True,
                encoding="utf-8", errors="ignore", stderr=subprocess.DEVNULL)
            m = re.search(r"Default Gateway[.\s]+:\s*([\d.]+)", o)
            return m.group(1) if m else ""
        o = subprocess.check_output(["ip","route"], text=True, stderr=subprocess.DEVNULL)
        m = re.search(r"default via ([\d.]+)", o)
        return m.group(1) if m else ""
    except Exception:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8",80)); ip=s.getsockname()[0]; s.close()
            p=ip.split("."); p[-1]="1"; return ".".join(p)
        except Exception:
            return ""

def connected_ssid() -> str:
    try:
        if WINDOWS:
            o = subprocess.check_output(
                ["netsh","wlan","show","interfaces"], text=True,
                encoding="utf-8", errors="ignore", stderr=subprocess.DEVNULL)
            m = re.search(r"^\s*SSID\s+:\s(.+)$", o, re.MULTILINE)
            return m.group(1).strip() if m else ""
        for cmd in [["iwgetid","-r"],["nmcli","-t","-f","active,ssid","dev","wifi"]]:
            try:
                o = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
                if cmd[0]=="iwgetid": return o.strip()
                for line in o.splitlines():
                    if line.startswith("yes:"): return line.split(":",1)[1].strip()
            except Exception: pass
    except Exception: pass
    return ""

def arp_table(iface: str = "") -> dict:
    """
    Read ARP table, optionally scoped to the subnet of a specific interface.
    Filters out virtual/loopback addresses and 169.254.x.x (APIPA).
    """
    result = {}
    try:
        if WINDOWS:
            # On Windows, scope via interface name if provided
            cmd = ["arp", "-a"]
            if iface and iface != "auto":
                cmd += ["-N", _iface_ip(iface)]
            o = subprocess.check_output(cmd, text=True,
                encoding="utf-8", errors="ignore", stderr=subprocess.DEVNULL)
            for m in re.finditer(r"([\d.]+)\s+([\w-]{17})", o):
                ip  = m.group(1)
                mac = m.group(2).replace("-", ":").upper()
                if _valid_arp_entry(ip, mac):
                    result[ip] = mac
        else:
            cmd = ["arp", "-n"]
            if iface and iface != "auto":
                cmd += ["-i", iface]
            o = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
            for m in re.finditer(r"([\d.]+)\s+\S+\s+([\w:]{17})", o):
                ip  = m.group(1)
                mac = m.group(2).upper()
                if _valid_arp_entry(ip, mac):
                    result[ip] = mac
    except Exception: pass
    return result


def _iface_ip(iface: str) -> str:
    """Get the IP address of a named interface (Windows helper)."""
    try:
        out = subprocess.check_output(
            ["netsh", "interface", "ip", "show", "address", iface],
            text=True, encoding="utf-8", errors="ignore", stderr=subprocess.DEVNULL)
        m = re.search(r"IP Address:\s*([\d.]+)", out)
        return m.group(1) if m else ""
    except Exception:
        return ""


def _valid_arp_entry(ip: str, mac: str) -> bool:
    """Filter out broadcast, APIPA, multicast, and virtual MAC entries."""
    BAD_MACS = {"FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"}
    if mac in BAD_MACS: return False
    if ip.startswith("169.254."): return False   # APIPA — link-local only
    if ip.startswith("224.") or ip.startswith("239."): return False  # multicast
    # Filter VMware / VirtualBox / Hyper-V virtual MACs
    VIRTUAL_OUIS = {"00:50:56","00:0C:29","08:00:27","52:54:00","00:15:5D","00:1C:14"}
    oui = ":".join(mac.split(":")[:3])
    if oui in VIRTUAL_OUIS: return False
    return True


# ─────────────────────────────────────────────────────────────────────────────
# Saved passwords reader
# ─────────────────────────────────────────────────────────────────────────────
def read_saved_passwords() -> list:
    results = []
    if WINDOWS:
        try:
            out = subprocess.check_output(
                ["netsh","wlan","show","profiles"], text=True,
                encoding="utf-8", errors="ignore", stderr=subprocess.DEVNULL)
            for ssid in re.findall(r"All User Profile\s+:\s+(.+)", out):
                ssid = ssid.strip()
                try:
                    detail = subprocess.check_output(
                        ["netsh","wlan","show","profile",
                         f"name={ssid}","key=clear"],
                        text=True, encoding="utf-8", errors="ignore",
                        stderr=subprocess.DEVNULL)
                    pm  = re.search(r"Key Content\s+:\s+(.+)", detail)
                    am  = re.search(r"Authentication\s+:\s+(.+)", detail)
                    pwd   = pm.group(1).strip() if pm else ""
                    proto = am.group(1).strip() if am else "Unknown"
                    sc    = score_password(pwd)
                    results.append({
                        "ssid": ssid, "password": pwd,
                        "password_masked": mask_pwd(pwd),
                        "proto": proto, **sc,
                    })
                except Exception:
                    pass
        except Exception as e:
            log.error(f"Win pwd read: {e}")
    elif LINUX:
        nm = "/etc/NetworkManager/system-connections"
        if os.path.isdir(nm):
            for fname in os.listdir(nm):
                try:
                    txt = open(os.path.join(nm,fname),
                               encoding="utf-8", errors="ignore").read()
                    sm = re.search(r"^ssid\s*=\s*(.+)$",     txt, re.MULTILINE)
                    pm = re.search(r"^psk\s*=\s*(.+)$",      txt, re.MULTILINE)
                    am = re.search(r"^key-mgmt\s*=\s*(.+)$", txt, re.MULTILINE)
                    if not sm: continue
                    ssid  = sm.group(1).strip()
                    pwd   = pm.group(1).strip() if pm else ""
                    proto = am.group(1).strip().upper() if am else "Unknown"
                    sc    = score_password(pwd)
                    results.append({
                        "ssid": ssid, "password": pwd,
                        "password_masked": mask_pwd(pwd),
                        "proto": proto, **sc,
                    })
                except PermissionError:
                    log.warning(f"Permission denied: {fname}")
                except Exception as e:
                    log.debug(f"NM profile {fname}: {e}")
    return results




# ─────────────────────────────────────────────────────────────────────────────
# Wi-Fi connect / disconnect
# ─────────────────────────────────────────────────────────────────────────────

def wifi_connect(ssid: str, password: str = "", iface: str = "") -> dict:
    """
    Connect to a Wi-Fi network. Uses saved OS profile if password is empty.
    Returns {ok, message}.
    Works on Windows (netsh) and Linux (nmcli/iwconfig).
    """
    try:
        if WINDOWS:
            if password:
                # Create a temporary profile XML and connect
                profile_xml = _make_win_profile_xml(ssid, password)
                import tempfile, os as _os
                tmp = tempfile.NamedTemporaryFile(suffix=".xml", delete=False, mode="w", encoding="utf-8")
                tmp.write(profile_xml); tmp.close()
                try:
                    subprocess.check_output(
                        ["netsh","wlan","add","profile",f"filename={tmp.name}"],
                        text=True, encoding="utf-8", stderr=subprocess.DEVNULL)
                finally:
                    _os.unlink(tmp.name)
            cmd = ["netsh","wlan","connect",f"name={ssid}"]
            if iface and iface != "auto":
                cmd += [f"interface={iface}"]
            out = subprocess.check_output(cmd, text=True, encoding="utf-8",
                                          errors="ignore", stderr=subprocess.DEVNULL)
            ok = "successfully" in out.lower() or "connection request was completed" in out.lower()
            return {"ok": ok, "message": out.strip()[:120]}
        else:
            # Linux: prefer nmcli
            try:
                if password:
                    cmd = ["nmcli","dev","wifi","connect",ssid,"password",password]
                    if iface and iface != "auto":
                        cmd += ["ifname", iface]
                else:
                    cmd = ["nmcli","con","up",ssid]
                    if iface and iface != "auto":
                        cmd += ["ifname", iface]
                out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT, timeout=30)
                ok = "successfully" in out.lower() or "connection successfully activated" in out.lower()
                return {"ok": ok, "message": out.strip()[:120]}
            except subprocess.CalledProcessError as e:
                return {"ok": False, "message": e.output.strip()[:120] if e.output else str(e)}
    except Exception as e:
        return {"ok": False, "message": str(e)}


def wifi_disconnect(iface: str = "") -> dict:
    """Disconnect current Wi-Fi connection."""
    try:
        if WINDOWS:
            cmd = ["netsh","wlan","disconnect"]
            if iface and iface != "auto":
                cmd += [f"interface={iface}"]
            out = subprocess.check_output(cmd, text=True, encoding="utf-8",
                                          errors="ignore", stderr=subprocess.DEVNULL)
            return {"ok": True, "message": out.strip()[:80]}
        else:
            try:
                out = subprocess.check_output(
                    ["nmcli","dev","disconnect", iface or "wifi"],
                    text=True, stderr=subprocess.STDOUT, timeout=10)
                return {"ok": True, "message": out.strip()[:80]}
            except subprocess.CalledProcessError as e:
                return {"ok": False, "message": e.output.strip()[:80] if e.output else str(e)}
    except Exception as e:
        return {"ok": False, "message": str(e)}


def wifi_saved_password(ssid: str) -> str:
    """Retrieve saved password for a known SSID from OS profile store."""
    try:
        if WINDOWS:
            out = subprocess.check_output(
                ["netsh","wlan","show","profile",f"name={ssid}","key=clear"],
                text=True, encoding="utf-8", errors="ignore", stderr=subprocess.DEVNULL)
            m = re.search(r"Key Content\s+:\s+(.+)", out)
            return m.group(1).strip() if m else ""
        else:
            nm_path = f"/etc/NetworkManager/system-connections/{ssid}.nmconnection"
            if not os.path.exists(nm_path):
                # Try legacy path
                nm_path = f"/etc/NetworkManager/system-connections/{ssid}"
            if os.path.exists(nm_path):
                txt = open(nm_path, encoding="utf-8", errors="ignore").read()
                pm = re.search(r"^psk\s*=\s*(.+)$", txt, re.MULTILINE)
                return pm.group(1).strip() if pm else ""
    except Exception:
        pass
    return ""


def _make_win_profile_xml(ssid: str, password: str) -> str:
    """Generate a minimal Windows WLAN profile XML for WPA2-Personal."""
    import html as _html
    ssid_esc = _html.escape(ssid)
    pass_esc  = _html.escape(password)
    return f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>{ssid_esc}</name>
  <SSIDConfig><SSID><name>{ssid_esc}</name></SSID></SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>manual</connectionMode>
  <MSM><security>
    <authEncryption>
      <authentication>WPA2PSK</authentication>
      <encryption>AES</encryption>
      <useOneX>false</useOneX>
    </authEncryption>
    <sharedKey>
      <keyType>passPhrase</keyType>
      <protected>false</protected>
      <keyMaterial>{pass_esc}</keyMaterial>
    </sharedKey>
  </security></MSM>
</WLANProfile>"""

# ─────────────────────────────────────────────────────────────────────────────
# Network scanning + 8-vector pre-join scoring
# ─────────────────────────────────────────────────────────────────────────────
from core.constants import ISP_DB, CORR_RULES, SPIKE_THR

def detect_isp(gw: str = "", ssid: str = "") -> tuple:
    gw = gw or gateway_ip()
    if gw.startswith("172.20.10."): return "ios_hs", ISP_DB["ios_hs"]
    for key, p in ISP_DB.items():
        if gw in p.get("gw",[]): return key, p
    s = ssid.lower()
    for kw, key in [("jio","jiofiber"),("airtel","airtel"),("bsnl","bsnl"),
                    ("act","act"),("tata","tataplay"),("hathway","hathway"),
                    ("excitel","excitel"),("railwire","railwire"),("mtnl","mtnl")]:
        if kw in s: return key, ISP_DB[key]
    return "unknown", {"name":"Unknown","risk":0,"creds":[]}

def _channel_congestion(channel: int, freq: int, all_nets: list) -> int:
    """
    Score 0-5: penalise heavily used channels.
    Based on Wi-Fi Alliance / IEEE 802.11 non-overlapping channel guidance.
    """
    if freq >= 6000:  # 6 GHz — all channels non-overlapping
        same = sum(1 for n in all_nets if n.get("channel") == channel and n.get("freq",0) >= 6000)
        return max(0, 5 - same)
    if freq >= 5000:  # 5 GHz — mostly non-overlapping
        same = sum(1 for n in all_nets if n.get("channel") == channel and 5000 <= n.get("freq",0) < 6000)
        return max(0, 5 - same)
    # 2.4 GHz: only ch 1, 6, 11 are non-overlapping (IEEE standard)
    NON_OVERLAP = {1, 6, 11}
    overlap = [n for n in all_nets if abs(n.get("channel",6) - channel) < 5
               and n.get("freq",2437) < 5000 and n.get("channel") != channel]
    if channel not in NON_OVERLAP:
        return 0  # overlapping channel — worst
    return max(0, 5 - len(overlap))


def score_network(net: dict, all_nets: list) -> dict:
    """
    Enhanced 11-vector scoring.
    Based on: WPA3 spec (IEEE 802.11ax/i), NIST SP 800-153 WLAN guidelines,
    Wi-Fi Alliance security certification criteria, CVSS-inspired weighting.

    Max base score: 100 pts
    Vectors:
      Encryption       30 — WPA3/SAE/OWE highest; WEP/Open = 0
      Evil Twin        20 — BSSID/SSID history mismatch
      Signal           10 — RSSI quality (reduced from 15 to fit new vectors)
      PMF/802.11w       8 — Management frame protection (NIST SP 800-153)
      WPS               8 — WPS disabled = no brute-force exposure
      Band              7 — 6 GHz > 5 GHz > 2.4 GHz
      SSID Visibility   4 — broadcast vs hidden
      ISP Risk          3 — known-safe ISP OUI
      Channel Congestion 5 — non-overlapping, low interference
      Key Rotation      3 — Enterprise EAP (rotating session keys)
      OUI Reputation    2 — known-good AP vendor MAC
      Total:          100
    """
    ENC = {
        "WPA3-SAE": 30, "WPA3":30, "WPA3-EAP":30, "SAE":30,
        "OWE":27,                             # Opportunistic Wireless Encryption (RFC 8110)
        "WPA2-E":28, "WPA2-EAP":28, "WPA2-ENTERPRISE":28,
        "WPA2":20,
        "WPA":8, "WEP":2, "OPEN":0, "NONE":0,
    }
    # Known-good AP vendor OUI prefixes (Wi-Fi Alliance certified)
    GOOD_OUI = {
        "00:50:F2","00:0C:E7","00:17:F2","DC:A9:04","48:A9:D2",
        "F4:39:09","3C:37:86","60:38:E0","18:64:72","9C:B6:D0",
    }

    v, total = {}, 0
    ssid   = net.get("ssid","")
    bssid  = net.get("bssid","")
    evil   = bool(net.get("evil"))
    proto  = net.get("proto","OPEN").upper()
    freq   = net.get("freq", 2437)
    chan   = net.get("channel", 6)

    # ── Vector 1: Encryption (30 pts) ─────────────────────────────────────────
    ep = ENC.get(proto, 10)
    v["enc"] = {"label":"Encryption","pts":ep,"max":30,
        "status":"pass" if ep>=28 else "warn" if ep>=20 else "fail",
        "detail": proto}
    total += ep

    # ── Vector 2: Evil Twin (20 pts) ──────────────────────────────────────────
    dups = [n for n in all_nets if n.get("ssid")==ssid and n.get("bssid")!=bssid and ssid]
    ep2  = 0 if evil else (10 if dups else 20)
    v["eviltwin"] = {"label":"No evil twin","pts":ep2,"max":20,
        "status":"fail" if evil else "warn" if dups else "pass",
        "detail":"⚠ IS evil twin" if evil else (f"{len(dups)} duplicate(s)" if dups else "Clean")}
    total += ep2

    # ── Vector 3: Signal strength (10 pts) ────────────────────────────────────
    rssi = net.get("sig", -90)
    sp   = 10 if rssi>=-50 else 8 if rssi>=-60 else 5 if rssi>=-70 else 2 if rssi>=-80 else 0
    v["signal"] = {"label":"Signal","pts":sp,"max":10,
        "status":"pass" if sp>=8 else "warn" if sp>=4 else "fail",
        "detail":f"{rssi} dBm"}
    total += sp

    # ── Vector 4: PMF / 802.11w (8 pts) — NIST SP 800-153 requirement ─────────
    pp = 8 if net.get("pmf") else 0
    v["pmf"] = {"label":"PMF/802.11w","pts":pp,"max":8,
        "status":"pass" if pp else "fail",
        "detail":"Enabled (NIST req.)" if pp else "Disabled"}
    total += pp

    # ── Vector 5: WPS disabled (8 pts) ────────────────────────────────────────
    wp = 0 if net.get("wps") else 8
    v["wps"] = {"label":"WPS","pts":wp,"max":8,
        "status":"fail" if net.get("wps") else "pass",
        "detail":"Enabled — Pixie Dust risk" if net.get("wps") else "Off"}
    total += wp

    # ── Vector 6: Band / frequency (7 pts) ────────────────────────────────────
    if   freq >= 6000: bp, bd = 7, "6 GHz (best)"
    elif freq >= 5000: bp, bd = 5, "5 GHz"
    else:              bp, bd = 2, "2.4 GHz"
    v["band"] = {"label":"Band","pts":bp,"max":7,
        "status":"pass" if bp>=5 else "warn", "detail":bd}
    total += bp

    # ── Vector 7: SSID visibility (4 pts) ─────────────────────────────────────
    hp = 2 if net.get("hidden") else 4
    v["hidden"] = {"label":"SSID visible","pts":hp,"max":4,
        "status":"warn" if net.get("hidden") else "pass",
        "detail":"Hidden SSID" if net.get("hidden") else "Broadcast"}
    total += hp

    # ── Vector 8: ISP / gateway risk (3 pts) ──────────────────────────────────
    ikey, iprof = detect_isp(ssid=ssid)
    ip3 = max(0, 3 + iprof.get("risk", 0))
    v["isp"] = {"label":"ISP risk","pts":ip3,"max":3,
        "status":"pass" if ip3==3 else "warn" if ip3>0 else "fail",
        "detail": iprof.get("name","Unknown")}
    total += ip3

    # ── Vector 9: Channel congestion (5 pts) ──────────────────────────────────
    cp = _channel_congestion(chan, freq, all_nets)
    v["congestion"] = {"label":"Channel","pts":cp,"max":5,
        "status":"pass" if cp>=4 else "warn" if cp>=2 else "fail",
        "detail":f"Ch {chan} — {'clear' if cp>=4 else 'congested'}"}
    total += cp

    # ── Vector 10: Enterprise key rotation (3 pts) ────────────────────────────
    is_ent = "EAP" in proto or "ENTERPRISE" in proto or proto in ("WPA2-E","WPA3-EAP")
    kp = 3 if is_ent else 0
    v["keymgmt"] = {"label":"Key rotation","pts":kp,"max":3,
        "status":"pass" if kp else "info",
        "detail":"Enterprise EAP" if kp else "PSK (personal)"}
    total += kp

    # ── Vector 11: OUI reputation (2 pts) ─────────────────────────────────────
    oui = ":".join(bssid.upper().split(":")[:3]) if bssid else ""
    op  = 2 if oui in GOOD_OUI else 1
    v["oui"] = {"label":"AP vendor","pts":op,"max":2,
        "status":"pass" if op==2 else "info",
        "detail": oui or "Unknown"}
    total += op

    total = min(100, max(0, total))
    if evil: total = min(total, 10)

    verdict = ("evil_twin" if evil else "safe" if total>=80 else
               "acceptable" if total>=60 else "caution" if total>=40 else "avoid")
    return {
        "score": total, "verdict": verdict,
        "color": {"safe":"#22d3a0","acceptable":"#38bdf8","caution":"#fbbf24",
                  "avoid":"#fb7c3e","evil_twin":"#f43f5e"}[verdict],
        "rec":   {"safe":"Safe to connect.",
                  "acceptable":"Acceptable. Use VPN for sensitive tasks.",
                  "caution":"Caution — VPN strongly advised.",
                  "avoid":"Avoid — use mobile data instead.",
                  "evil_twin":"DO NOT CONNECT — this is a deception AP."}[verdict],
        "vectors":v, "isp":ikey, "isp_name":iprof.get("name","Unknown"),
    }

def scan_wifi() -> list:
    """
    Scan Wi-Fi using the existing NetworkAdvisor, then convert
    NetworkProfile dataclass objects to scored dicts for the UI.
    Falls back to OS netsh/nmcli if NetworkAdvisor is unavailable.
    """
    raw = []
    try:
        sys.path.insert(0, _PKG)
        from omnifi.client_mode.network_advisor import NetworkAdvisor
        adv  = NetworkAdvisor(verbose=False, post_join_checks=False)
        nets = adv.run()
        for n in nets:
            raw.append({
                "ssid":   n.ssid,
                "bssid":  n.bssid,
                "proto":  n.auth_protocol.upper() if n.auth_protocol else "OPEN",
                "sig":    n.signal_dbm,
                "freq":   n.frequency_mhz,
                "pmf":    n.pmf_enabled,
                "wps":    n.wps_enabled,
                "hidden": n.is_hidden,
                "channel":n.channel,
                "evil":   n.is_evil_twin,
            })
    except Exception as e:
        log.debug(f"NetworkAdvisor: {e}")
        raw = _fallback_scan()

    # Evil-twin detection by SSID duplication
    from collections import defaultdict
    by_ssid = defaultdict(list)
    for n in raw:
        if n.get("ssid"): by_ssid[n["ssid"]].append(n)
    for group in by_ssid.values():
        if len(group) > 1:
            group.sort(key=lambda x: x.get("sig",0))
            for n in group[:-1]: n["evil"] = True

    # SSID/BSSID history check
    now = datetime.datetime.now().isoformat()
    try:
        from core.database import dbq, dbx
        for n in raw:
            if not (n.get("ssid") and n.get("bssid")): continue
            row = dbq("SELECT bssid FROM ssid_history WHERE ssid=?",(n["ssid"],))
            if row:
                if row[0]["bssid"].upper() != n["bssid"].upper():
                    n["evil"] = True
            else:
                dbx("INSERT OR IGNORE INTO ssid_history "
                    "(ssid,bssid,first_seen,last_seen,trusted) VALUES(?,?,?,?,1)",
                    (n["ssid"],n["bssid"],now,now))
    except Exception: pass

    scored = [{**n, **score_network(n, raw)} for n in raw]
    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored



# ─────────────────────────────────────────────────────────────────────────────
# Wireless interface detection
# ─────────────────────────────────────────────────────────────────────────────
def list_wireless_interfaces() -> list:
    """
    Returns list of dicts: {name, mac, connected_ssid, is_active}
    Works on Windows and Linux.
    """
    ifaces = []
    try:
        if WINDOWS:
            o = subprocess.check_output(
                ["netsh", "wlan", "show", "interfaces"],
                text=True, encoding="utf-8", errors="ignore",
                stderr=subprocess.DEVNULL)
            blocks = re.split(r"(?=\n\s*Name\s+:)", "\n" + o)[1:]
            if not blocks:
                # single interface — treat whole output as one block
                blocks = [o]
            for blk in blocks:
                nm = re.search(r"^\s*Name\s+:\s*(.+)$",  blk, re.MULTILINE)
                mc = re.search(r"MAC Address\s+:\s*([\w:.-]+)", blk)
                ss = re.search(r"^\s*SSID\s+:\s*(.+)$",  blk, re.MULTILINE)
                st = re.search(r"State\s+:\s*(.+)",        blk)
                if nm:
                    ifaces.append({
                        "name": nm.group(1).strip(),
                        "mac":  mc.group(1).strip().upper() if mc else "",
                        "connected_ssid": ss.group(1).strip() if ss else "",
                        "is_active": (st.group(1).strip().lower() == "connected") if st else False,
                    })
        else:
            # Linux: use iw or ip link to find wireless interfaces
            iw_out = ""
            try:
                iw_out = subprocess.check_output(
                    ["iw", "dev"], text=True, stderr=subprocess.DEVNULL)
            except Exception:
                pass
            if iw_out:
                for blk in re.split(r"Interface\s+", iw_out)[1:]:
                    iname = blk.split()[0].strip() if blk.split() else ""
                    if not iname: continue
                    mac_m = re.search(r"addr\s+([\w:]+)", blk)
                    ssid_m = re.search(r"ssid\s+(.+)", blk)
                    type_m = re.search(r"type\s+(\w+)", blk)
                    mac  = mac_m.group(1).upper() if mac_m else ""
                    ssid = ssid_m.group(1).strip() if ssid_m else ""
                    active = bool(ssid) or (type_m and type_m.group(1) == "managed")
                    ifaces.append({
                        "name": iname, "mac": mac,
                        "connected_ssid": ssid,
                        "is_active": active and bool(ssid),
                    })
            else:
                # Fallback: parse /sys/class/net
                net_path = "/sys/class/net"
                if os.path.isdir(net_path):
                    for iname in os.listdir(net_path):
                        wireless = os.path.exists(f"{net_path}/{iname}/wireless") or \
                                   os.path.exists(f"{net_path}/{iname}/phy80211")
                        if not wireless: continue
                        mac = ""
                        try:
                            mac = open(f"{net_path}/{iname}/address").read().strip().upper()
                        except Exception: pass
                        ssid = ""
                        try:
                            o2 = subprocess.check_output(
                                ["iwgetid", iname, "-r"], text=True, stderr=subprocess.DEVNULL)
                            ssid = o2.strip()
                        except Exception: pass
                        ifaces.append({
                            "name": iname, "mac": mac,
                            "connected_ssid": ssid, "is_active": bool(ssid),
                        })
    except Exception as e:
        log.debug(f"list_wireless_interfaces: {e}")

    # Filter out virtual / software adapters
    VIRTUAL_PREFIXES = (
        "vmware", "vmnet", "virtualbox", "vbox", "docker", "loopback",
        "bluetooth", "vpn", "tun", "tap", "veth", "br-", "virbr",
        "hamachi", "zerotier", "npcap", "pseudo", "isatap", "teredo",
    )
    real = []
    for i in ifaces:
        nm_lower = i.get("name","").lower()
        mac = i.get("mac","")
        # Skip virtual MAC prefixes used by VMware / VirtualBox
        VIRTUAL_MACS = {"00:50:56","00:0C:29","08:00:27","52:54:00","00:15:5D"}
        oui = ":".join(mac.upper().split(":")[:3]) if mac else ""
        if any(nm_lower.startswith(vp) for vp in VIRTUAL_PREFIXES):
            continue
        if oui in VIRTUAL_MACS:
            continue
        real.append(i)
    ifaces = real if real else ifaces  # keep all if all filtered out

    # Always return at least a placeholder so the UI doesn't break
    if not ifaces:
        ifaces = [{"name": "auto", "mac": "", "connected_ssid": "", "is_active": True}]
    return ifaces


def resolve_hostname(ip: str, timeout: float = 0.4) -> str:
    """Fast reverse-DNS + NetBIOS/mDNS hostname resolution."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        pass
    # Try NetBIOS name query on Windows
    if WINDOWS:
        try:
            o = subprocess.check_output(
                ["nbtstat", "-A", ip], text=True, encoding="utf-8",
                errors="ignore", stderr=subprocess.DEVNULL, timeout=2)
            m = re.search(r"^\s*(\S+)\s+<00>.*UNIQUE", o, re.MULTILINE)
            if m: return m.group(1).strip()
        except Exception:
            pass
    return ""

def _fallback_scan() -> list:
    """OS-level scan when NetworkAdvisor is unavailable."""
    raw = []
    if WINDOWS:
        try:
            o = subprocess.check_output(
                ["netsh","wlan","show","networks","mode=Bssid"],
                text=True, encoding="utf-8", errors="ignore",
                stderr=subprocess.DEVNULL, timeout=15)
            for block in re.split(r"SSID \d+ :", o)[1:]:
                sm  = re.search(r"^\s*(.+)", block)
                bm  = re.search(r"BSSID\s+:\s*([\w:]+)", block)
                sgm = re.search(r"Signal\s*:\s*(\d+)%", block)
                am  = re.search(r"Authentication\s*:\s*(.+)", block)
                chm = re.search(r"Channel\s*:\s*(\d+)", block)
                ssid  = sm.group(1).strip() if sm else ""
                bssid = bm.group(1).upper()  if bm else ""
                sig   = int((int(sgm.group(1))/2)-100) if sgm else -80
                auth  = am.group(1).strip().lower() if am else ""
                chan  = int(chm.group(1)) if chm else 6
                proto = ("WPA3" if "wpa3" in auth else "WPA2" if "wpa2" in auth else
                         "WPA"  if "wpa"  in auth else "WEP"  if "wep"  in auth else "OPEN")
                raw.append({"ssid":ssid,"bssid":bssid,"proto":proto,"sig":sig,
                    "freq":5000 if chan>14 else 2437,"pmf":False,"wps":False,
                    "hidden":not bool(ssid),"channel":chan,"evil":False})
        except Exception as e:
            log.debug(f"netsh scan: {e}")
    elif LINUX:
        try:
            o = subprocess.check_output(
                ["nmcli","-t","-f","SSID,BSSID,SIGNAL,SECURITY,FREQ,CHAN",
                 "dev","wifi","list","--rescan","yes"],
                text=True, stderr=subprocess.DEVNULL, timeout=15)
            for line in o.strip().splitlines():
                p = line.split(":")
                if len(p)<5: continue
                ssid  = p[0].strip()
                bssid = p[1].strip().replace("\\:",":").upper()
                sig   = int((int(p[2])/2)-100) if p[2].isdigit() else -80
                sec   = p[3].strip().lower()
                freq  = int(re.sub(r"[^\d]","",p[4])) if p[4] else 2437
                chan  = int(p[5]) if len(p)>5 and p[5].isdigit() else 6
                proto = ("WPA3" if "wpa3" in sec else "WPA2" if "wpa2" in sec else
                         "WPA"  if "wpa"  in sec else "WEP"  if "wep"  in sec else "OPEN")
                raw.append({"ssid":ssid,"bssid":bssid,"proto":proto,"sig":sig,
                    "freq":freq,"pmf":"802.11w" in sec,"wps":"wps" in sec,
                    "hidden":not bool(ssid),"channel":chan,"evil":False})
        except Exception as e:
            log.debug(f"nmcli scan: {e}")
    return raw


# ─────────────────────────────────────────────────────────────────────────────
# Port scanner (pure Python TCP connect)
# ─────────────────────────────────────────────────────────────────────────────
_PORT_DB = {
    21:("FTP","critical","Cleartext file transfer"),
    22:("SSH","medium","Verify key-only auth"),
    23:("Telnet","critical","Completely unencrypted"),
    53:("DNS","low","Expected on router"),
    80:("HTTP","medium","Admin panel without HTTPS"),
    443:("HTTPS","low","Good"),
    1900:("UPnP","high","Allows self port-opening"),
    7547:("TR-069","high","ISP remote management"),
    8080:("HTTP-alt","medium","Alternate HTTP"),
}

def port_scan(host: str, timeout: float = 0.8) -> list:
    results = []
    def _probe(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((host,port))==0:
                    svc,risk,note=_PORT_DB.get(port,("Unknown","medium","Non-standard"))
                    results.append({"port":port,"service":svc,"risk":risk,"note":note})
        except Exception: pass
    ts=[threading.Thread(target=_probe,args=(p,)) for p in _PORT_DB]
    for t in ts: t.start()
    for t in ts: t.join()
    return sorted(results, key=lambda x: x["port"])


# ─────────────────────────────────────────────────────────────────────────────
# CVE lookup
# ─────────────────────────────────────────────────────────────────────────────
def cve_lookup(model: str, firmware: str = "") -> list:
    try:
        sys.path.insert(0, _PKG)
        from omnifi.admin_mode.cve_lookup import CVELookup
        c = CVELookup(verbose=False)
        return c.lookup(model, firmware)
    except Exception:
        pass
    if not HAVE_REQ: return []
    found = {}
    for kw in [f"{model} {firmware}".strip(), model]:
        try:
            time.sleep(6)
            r = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch":kw,"resultsPerPage":15}, timeout=12)
            if r.status_code != 200: continue
            for item in r.json().get("vulnerabilities",[]):
                cv  = item.get("cve",{}); cid=cv.get("id","")
                if not cid or cid in found: continue
                desc= next((d["value"] for d in cv.get("descriptions",[])
                            if d.get("lang")=="en"),"")
                score,sev = 0.0,"NONE"
                for k2 in ("cvssMetricV31","cvssMetricV30"):
                    if k2 in cv.get("metrics",{}) and cv["metrics"][k2]:
                        m2=cv["metrics"][k2][0].get("cvssData",{})
                        score=m2.get("baseScore",0.0); sev=m2.get("baseSeverity","NONE"); break
                refs=[ref.get("url","") for ref in cv.get("references",[])]
                found[cid]={"id":cid,"score":score,"severity":sev,
                    "desc":desc[:220]+("…" if len(desc)>220 else ""),
                    "published":cv.get("published","")[:10],
                    "patch":any(k3 in " ".join(refs).lower()
                                for k3 in ["patch","fix","update","advisory"])}
        except Exception as e:
            log.debug(f"CVE: {e}")
    return sorted(found.values(), key=lambda c: c["score"], reverse=True)


# ─────────────────────────────────────────────────────────────────────────────
# Policy engine
# ─────────────────────────────────────────────────────────────────────────────
class PolicyEngine:
    def add(self, mac:str, ptype:str, reason:str="", expiry_min:int=0):
        try:
            from core.database import add_policy
            add_policy(mac, ptype, reason, expiry_min)
            log.info(f"[policy] {ptype} → {mac}")
        except Exception as e:
            log.error(f"Policy add: {e}")

    def remove(self, mac:str, ptype:str):
        try:
            from core.database import remove_policy
            remove_policy(mac, ptype)
        except Exception as e:
            log.error(f"Policy remove: {e}")

    def all_items(self) -> list:
        try:
            from core.database import get_policy
            return get_policy()
        except Exception:
            return []

    def clean_expired(self):
        try:
            from core.database import clean_expired_policy
            clean_expired_policy()
        except Exception: pass


# ─────────────────────────────────────────────────────────────────────────────
# Alert bridge (wraps AlertEngine so MonitorThread can call it)
# ─────────────────────────────────────────────────────────────────────────────
class AlertBridge:
    """
    Thin wrapper that the monitor thread uses to emit alerts.
    The AlertEngine must be initialised before any calls here.
    """
    def __init__(self):
        self._ae = None   # set after QApplication init

    def set_engine(self, ae):
        self._ae = ae
        # expose sub-objects the MonitorThread needs
        self.corr  = ae._AlertEngine__dict__.get("_corr")  if hasattr(ae,"_AlertEngine__dict__") else None
        self.spike = ae._AlertEngine__dict__.get("_spike") if hasattr(ae,"_AlertEngine__dict__") else None
        # Simpler attribute access
        try:
            self.corr  = ae._corr
            self.spike = ae._spike
        except Exception:
            pass

    def emit_alert(self, level, source, message, detail="",
                   actions=None, signals=None, **kw) -> dict:
        if self._ae:
            return self._ae.emit(level, source, message, detail,
                                  actions, signals, **kw)
        log.info(f"[{level}][{source}] {message}")
        return {}


# ─────────────────────────────────────────────────────────────────────────────
# Router inspector wrapper
# ─────────────────────────────────────────────────────────────────────────────
class RouterWrapper:
    def __init__(self):
        self._creds_hash: dict = {}
        self._last_info = None   # RouterInfo from last audit

    def run_audit(self, username: str = "", password: str = "") -> dict:
        try:
            sys.path.insert(0, _PKG)
            from omnifi.admin_mode.router_auth_inspector import RouterAuthInspector
            inspector = RouterAuthInspector(verbose=False)
            if username and password:
                inspector.info.admin_creds = (username, password)
            ri = inspector.run()
            self._last_info = ri   # stored so enforcer can reuse session
            return {
                "ok":                 True,
                "gateway":            ri.gateway_ip,
                "isp_name":           ri.isp_name,
                "panel_url":          ri.admin_url,
                "auth_type":          ri.auth_type,
                "uses_https":         ri.uses_https,
                "default_creds_work": ri.default_creds_work,
                "working_creds":      ri.working_creds,
                "open_panel":         ri.open_panel,
                "trust_score":        ri.trust_score,
                "alerts":             ri.alerts,
                "isp_key":            getattr(ri, "isp_key", "unknown"),
                "session":            ri.session,
            }
        except Exception as e:
            log.error(f"RouterInspector: {e}")
            return {"ok": False, "error": str(e)}

    def creds_info(self) -> dict:
        if self._creds_hash:
            return {"stored":True, "algo":self._creds_hash.get("algo",""),
                    "prefix":self._creds_hash.get("hash","")[:8]+"…"}
        return {"stored": False}

    def auto_detect(self) -> dict:
        gw      = gateway_ip()
        ikey, iprof = detect_isp(gw)
        return {
            "gateway":      gw,
            "isp_name":     iprof.get("name","Unknown"),
            "default_url":  f"http://{gw}",
            "default_user": iprof.get("creds",[[""]])[0][0] if iprof.get("creds") else "",
            "default_pass": iprof.get("creds",[[""]])[0][1] if iprof.get("creds") else "",
        }


# ─────────────────────────────────────────────────────────────────────────────
# Main Backend class  (owned by MainWindow)
# ─────────────────────────────────────────────────────────────────────────────
class Backend(QObject):
    """
    Single object passed to MainWindow and all panels.
    All public methods are non-blocking; heavy work lives in QThreads.
    """

    def __init__(self):
        super().__init__()
        self.monitor   = AlertBridge()
        self.router    = RouterWrapper()
        self.policy    = PolicyEngine()
        self.mode      = "client"
        self.safe_mode = True
        self._verified = False
        self._creds:   dict = {}
        self.caps = {
            "scapy":     HAVE_SCAPY,
            "pywifi":    HAVE_WIFI,
            "requests":  HAVE_REQ,
            "root":      IS_ROOT,
            "platform":  platform.system(),
        }
        self.selected_iface  = "auto"
        # Enforcement policy preferences (set by SettingsPanel)
        self.action_policies: dict = {
            "blacklist":  "Blacklist (router MAC filter)",
            "whitelist":  "Whitelist (suppress all alerts)",
            "isolated":   "All tiers",
            "exception":  "Suppress all alerts for this device",
            "guest":      "Log + allow — no restriction",
            "auto_block": "Block immediately when threshold met",
        }
        self.auto_threshold: int = 80   # confidence % for auto-enforce
        # Real enforcement engine — pushes rules to router + OS firewall
        from core.enforcer      import EnforcementEngine
        from core.trust_score   import get_trust_engine, TrustScoreEngine
        from core.policy_engine import PolicyEngine as AutoPolicyEngine
        from core.telemetry     import get_telemetry
        self.enforcer    = EnforcementEngine()
        # Trust score engine
        self.trust_engine: TrustScoreEngine = get_trust_engine()
        # Auto-policy engine
        self.auto_policy  = AutoPolicyEngine()
        self.auto_policy.attach_alert(self.monitor.emit_alert)
        # Telemetry
        self.telemetry    = get_telemetry()
        self.telemetry.attach_trust(lambda: self.trust_engine.current().score)
        self.telemetry.start()

    def init_alert_engine(self, ae) -> None:
        """Call from main.py after QApplication is created."""
        self.monitor.set_engine(ae)

    # ── auth ──────────────────────────────────────────────────────────────────
    def login_admin(self, url: str, user: str, pwd: str) -> dict:
        self._creds = hash_cred(pwd)
        result = self.router.run_audit(user, pwd)
        if result.get("ok") and (
            result.get("working_creds") or result.get("open_panel")
        ):
            self._verified = True; self.mode = "admin"
            # Wire authenticated router session into enforcement engine
            try:
                ri = self.router._last_info
                if ri and ri.session:
                    isp = getattr(ri, "isp_key", "unknown")
                    self.enforcer.set_router(ri.session, url, isp)
                    log.info(f"Enforcer armed: {url} [{isp}]")
            except Exception as e:
                log.debug(f"Enforcer session setup: {e}")
            self.monitor.emit_alert("low","auth",
                f"Admin mode activated — {url}",
                f"User:{user}  ISP:{result.get('isp_name','?')}")
        return result

    def is_admin(self) -> bool:
        return self.mode == "admin" and self._verified

    def set_safe_mode(self, v: bool) -> None:
        self.safe_mode = v
        self.monitor.emit_alert("low","safe_mode",
            f"Safe mode {'ENABLED' if v else 'DISABLED'}",
            "Auto-enforcement " + ("suspended." if v else "active."))

    def auto_detect_router(self) -> dict:
        return self.router.auto_detect()

    # ── scanning ──────────────────────────────────────────────────────────────
    def scan_now(self) -> list:
        return scan_wifi()

    def get_passwords(self) -> list:
        return read_saved_passwords()

    def wifi_connect(self, ssid: str, password: str = "", iface: str = "") -> dict:
        """Connect to a Wi-Fi network. Uses saved OS password if none provided."""
        pw = password or wifi_saved_password(ssid)
        return wifi_connect(ssid, pw, iface or self.selected_iface)

    def wifi_disconnect(self) -> dict:
        """Disconnect the currently active Wi-Fi interface."""
        return wifi_disconnect(self.selected_iface)

    def wifi_saved_password(self, ssid: str) -> str:
        """Return saved OS password for this SSID, or empty string."""
        return wifi_saved_password(ssid)

    # ── policy ────────────────────────────────────────────────────────────────
    def apply_policy(self, mac: str, ptype: str,
                     reason: str = "", exp: int = 0) -> dict:
        if not self.is_admin():
            return {"ok": False, "error": "Admin mode required."}
        if self.safe_mode:
            return {"ok": False, "safe_mode": True,
                    "action": f"{ptype}: {mac}", "requires_confirm": True}
        return self._do_enforce(mac, ptype, reason, exp)

    def confirm_action(self, mac: str, ptype: str,
                       reason: str = "", exp: int = 0) -> dict:
        """Called when user confirms a safe-mode action."""
        if not self.is_admin():
            return {"ok": False, "error": "Admin mode required."}
        result = self._do_enforce(mac, ptype, reason, exp)
        if result.get("ok"):
            self.monitor.emit_alert("low", "policy",
                f"Confirmed & applied: {ptype} → {mac}",
                result.get("method", ""))
        return result

    def remove_policy(self, mac: str, ptype: str) -> dict:
        """Remove a policy and push reversal to router/OS."""
        if not self.is_admin():
            return {"ok": False, "error": "Admin mode required."}
        return self._do_enforce(mac, f"remove_{ptype}", "", 0)

    def _do_enforce(self, mac: str, ptype: str,
                    reason: str, exp: int) -> dict:
        """
        Execute real enforcement: router push → OS firewall → DB write.
        Returns dict with ok, tier, method, detail.
        """
        gw = gateway_ip()
        # Resolve IP from ARP table
        try:
            from core.enforcer import OSEnforcer
            ip = OSEnforcer._mac_to_ip(mac)
        except Exception:
            ip = ""

        from core.enforcer import EnforceResult
        res: EnforceResult = self.enforcer.enforce(
            mac=mac, action=ptype, ip=ip, reason=reason, gateway_ip=gw)

        # Also write expiry to DB if set
        if exp > 0 and res.db_ok:
            try:
                from core.database import add_policy
                add_policy(mac, ptype, reason, exp)
            except Exception:
                pass

        # Emit audit alert regardless of tier
        tier_str = res.tier or "db_only"
        self.monitor.emit_alert(
            "low", "enforcement",
            f"{ptype.upper()} → {mac}",
            f"Tier: {tier_str} | {res.method or res.detail[:120]}"
        )

        return {
            "ok":     res.ok,
            "tier":   tier_str,
            "method": res.method,
            "detail": res.detail,
            "router": res.router_ok,
            "os":     res.os_ok,
            "arp":    res.arp_ok,
            "db":     res.db_ok,
            "error":  res.error,
        }

    def get_policy(self) -> list:
        return self.policy.all_items()

    # ── admin tools ───────────────────────────────────────────────────────────
    def run_router_audit(self) -> dict:
        if not self.is_admin():
            return {"ok": False, "error": "Admin mode required."}
        audit = self.router.run_audit()
        ports = port_scan(gateway_ip())
        return {"ok": True, "audit": audit, "ports": ports}

    def cve_lookup(self, model: str, firmware: str = "") -> list:
        return cve_lookup(model, firmware)

    def creds_info(self) -> dict:
        return self.router.creds_info()

    # ── queries ───────────────────────────────────────────────────────────────
    def get_devices(self) -> list:
        tbl = arp_table(self.selected_iface); now = datetime.datetime.now().isoformat()
        # Resolve hostnames in parallel
        _cache = {}
        _threads = []
        def _resolve(ip):
            _cache[ip] = resolve_hostname(ip)
        for ip in tbl:
            t = threading.Thread(target=_resolve, args=(ip,), daemon=True)
            t.start(); _threads.append(t)
        for t in _threads: t.join(timeout=0.5)

        try:
            from core.database import upsert_device, get_devices as db_devs
            for ip, mac in tbl.items():
                la = bool(int(mac.split(":")[0].replace("-",""),16) & 0x02)
                hn = _cache.get(ip, "")
                upsert_device(mac, ip, hostname=hn, status="suspect" if la else "unknown")
            devs = db_devs()
            # Patch resolved hostnames in
            ip_to_hn = {ip: _cache.get(ip,"") for ip in tbl}
            for d in devs:
                if not d.get("hostname"):
                    d["hostname"] = ip_to_hn.get(d.get("ip",""), "")
            return devs
        except Exception:
            return [{"mac":m,"ip":ip,
                     "vendor":"","hostname":_cache.get(ip,""),
                     "device_type":"","os_guess":"","status":"unknown"}
                    for ip,m in tbl.items()]

    def get_alerts(self, hours: int = 24) -> list:
        try:
            from core.database import get_alerts
            return get_alerts(hours)
        except Exception:
            return []

    def get_trust_history(self, n: int = 60) -> list:
        return self.trust_engine.history(n)

    def get_telemetry_history(self, n: int = 60) -> list:
        return self.telemetry.latest(n)

    def stop(self) -> None:
        pass  # MonitorThread.stop_mon() called by MainWindow.closeEvent
