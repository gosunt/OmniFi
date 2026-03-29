"""
OmniFi — Shared constants, colour tokens, level weights.
Import this everywhere instead of scattering magic values.
"""
import platform, os

# ── Platform ──────────────────────────────────────────────────────────────────
WINDOWS = platform.system() == "Windows"
LINUX   = platform.system() == "Linux"
IS_ROOT = (not WINDOWS) and (os.geteuid() == 0)
PLATFORM = platform.system()

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH     = os.path.join(BASE_DIR, "db",      "omnifi.db")
LOG_PATH    = os.path.join(BASE_DIR, "logs",    "omnifi.log")
CONFIG_PATH = os.path.join(BASE_DIR, "config",  "config.yaml")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

for _d in (os.path.dirname(DB_PATH), os.path.dirname(LOG_PATH),
           os.path.dirname(CONFIG_PATH), REPORTS_DIR):
    os.makedirs(_d, exist_ok=True)

# ── Alert levels ──────────────────────────────────────────────────────────────
class Level:
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    OK       = "ok"
    INFO     = "info"

LEVEL_WEIGHT = {
    Level.CRITICAL: 30,
    Level.HIGH:     20,
    Level.MEDIUM:   10,
    Level.LOW:       5,
    Level.OK:        0,
    Level.INFO:      0,
}

LEVEL_COLOR = {
    Level.CRITICAL: "#f43f5e",
    Level.HIGH:     "#fb7c3e",
    Level.MEDIUM:   "#fbbf24",
    Level.LOW:      "#38bdf8",
    Level.OK:       "#22d3a0",
    Level.INFO:     "#8896b3",
}

# ── Verdict colours ───────────────────────────────────────────────────────────
VERDICT_COLOR = {
    "safe":       "#22d3a0",
    "acceptable": "#38bdf8",
    "caution":    "#fbbf24",
    "avoid":      "#fb7c3e",
    "evil_twin":  "#f43f5e",
}

# ── Design tokens ─────────────────────────────────────────────────────────────
C = {
    # Backgrounds
    "bg0": "#07080d", "bg1": "#0c0e16", "bg2": "#10121c",
    "bg3": "#161928", "bg4": "#1c2035",
    # Borders
    "b1":  "#1e2440", "b2":  "#2a3258", "b3":  "#3a4470",
    # Accents
    "acc": "#38bdf8", "acc2":"#0ea5e9",
    # Semantic
    "red": "#f43f5e", "grn": "#22d3a0",
    "ylw": "#fbbf24", "org": "#fb7c3e", "pur": "#a78bfa",
    # Text
    "t1":  "#e8edf8", "t2":  "#8896b3", "t3":  "#4a5572", "t4":  "#2a3252",
}

# ── Font families ─────────────────────────────────────────────────────────────
MONO_FONT = "Consolas"       if WINDOWS else "JetBrains Mono"
SANS_FONT = "Segoe UI"       if WINDOWS else "Ubuntu"
EMOJI_FONT= "Segoe UI Emoji" if WINDOWS else "Noto Color Emoji"

# ── Polling intervals (seconds) ───────────────────────────────────────────────
POLL_ARP     = 30
POLL_DNS     = 120
POLL_DEVICES = 60
POLL_NETS    = 180
POLL_STATUS  = 5

# ── Correlation rules (shared with CorrEngine) ────────────────────────────────
CORR_RULES = [
    {"id":"mitm",       "signals":["dns_spoof","arp_mitm"],
     "result":"HIGH CONFIDENCE MITM ATTACK",        "level":Level.CRITICAL,"conf":92,
     "desc":"DNS spoofing + gateway ARP change — attacker intercepting all traffic."},
    {"id":"evil_coord", "signals":["evil_twin","deauth"],
     "result":"COORDINATED EVIL TWIN ATTACK",        "level":Level.CRITICAL,"conf":88,
     "desc":"Evil twin AP + deauth flood — forcing clients onto rogue network."},
    {"id":"rogue_net",  "signals":["evil_twin","rogue_dhcp"],
     "result":"ROGUE NETWORK INFRASTRUCTURE",        "level":Level.HIGH,   "conf":80,
     "desc":"Evil twin + rogue DHCP — complete fake network detected."},
    {"id":"mac_bypass", "signals":["la_mac","new_device"],
     "result":"LA-MAC DEVICE BYPASS",                "level":Level.HIGH,   "conf":75,
     "desc":"Locally-administered MAC joined — possible ACL bypass."},
    {"id":"dns_redir",  "signals":["dns_spoof","icmp_redirect"],
     "result":"DNS REDIRECT ATTACK",                 "level":Level.HIGH,   "conf":85,
     "desc":"ICMP redirect + DNS anomaly — layer-3 traffic rerouting."},
    {"id":"cred_hvst",  "signals":["evil_twin","session_hijack"],
     "result":"CREDENTIAL HARVEST ATTEMPT",          "level":Level.CRITICAL,"conf":90,
     "desc":"Evil twin + cleartext credentials observed — active harvesting."},
    {"id":"arp_flood",  "signals":["arp_spike","arp_mitm"],
     "result":"ARP FLOOD POISONING",                 "level":Level.HIGH,   "conf":83,
     "desc":"ARP spike + MAC change — active poisoning tool running."},
    {"id":"recon",      "signals":["beacon_anomaly","new_device"],
     "result":"NETWORK RECONNAISSANCE",              "level":Level.MEDIUM, "conf":65,
     "desc":"Beacon anomaly + unknown device — passive network mapping."},
]

# ── Time-spike thresholds ────────────────────────────────────────────────────
SPIKE_THR = {
    "arp":    {"warn": 5, "crit": 10},
    "deauth": {"warn": 3, "crit": 8},
    "dns":    {"warn": 4, "crit": 8},
    "device": {"warn": 2, "crit": 5},
}

# ── Password policy ───────────────────────────────────────────────────────────
MIN_PWD_LEN    = 12
MIN_ENTROPY    = 50.0
COMMON_PWDS = {
    "password","12345678","admin","welcome","letmein","qwerty123",
    "jiocentrum","airtel123","bsnl1234","wifi1234","home1234","password1",
    "iloveyou","sunshine","monkey","123456","123456789","admin123",
    "router","network","internet","broadband","excitel","stdonu101",
    "admintelecom","00000000","11111111","jio@123","jiofi","bsnl@1234",
    "tataplay","hathway","railwire","mtnl1234","actfibernet",
}

# ── India ISP database ────────────────────────────────────────────────────────
ISP_DB = {
    "jiofiber":   {"name":"JioFiber",        "gw":["192.168.29.1","192.168.31.1"],
                   "risk":-3, "creds":[("admin","Jiocentrum"),("admin","admin")]},
    "jioairfiber":{"name":"JioAirFiber",     "gw":["192.168.31.1"],
                   "risk":-2, "creds":[("admin","admin")]},
    "jiofi":      {"name":"JioFi MiFi",      "gw":["192.168.1.1"],
                   "risk":-3, "creds":[("admin","admin")]},
    "airtel":     {"name":"Airtel Xstream",  "gw":["192.168.1.1","192.168.0.1"],
                   "risk":-2, "creds":[("admin","admin"),("telecomadmin","admintelecom")]},
    "bsnl":       {"name":"BSNL",            "gw":["192.168.1.1"],
                   "risk":-4, "creds":[("admin","admin"),("admin","stdONU101"),("admin","bsnl@1234")]},
    "act":        {"name":"ACT Fibernet",    "gw":["192.168.0.1","192.168.1.1"],
                   "risk":-1, "creds":[("admin","admin")]},
    "tataplay":   {"name":"Tata Play Fiber", "gw":["192.168.1.254"],
                   "risk":-1, "creds":[("admin","admin")]},
    "hathway":    {"name":"Hathway",         "gw":["192.168.100.1","192.168.1.1"],
                   "risk":-2, "creds":[("admin","admin")]},
    "excitel":    {"name":"Excitel",         "gw":["192.168.0.1","192.168.1.1"],
                   "risk":-2, "creds":[("excitel","exc@123"),("admin","admin")]},
    "railwire":   {"name":"RailWire",        "gw":["192.168.1.1"],
                   "risk":-1, "creds":[("admin","admin")]},
    "mtnl":       {"name":"MTNL",            "gw":["192.168.1.1"],
                   "risk":-4, "creds":[("admin","admin")]},
    "android_hs": {"name":"Android Hotspot", "gw":["192.168.43.1","192.168.49.1"],
                   "risk": 0, "creds":[]},
    "ios_hs":     {"name":"iPhone Hotspot",  "gw":["172.20.10.1"],
                   "risk": 0, "creds":[]},
}
