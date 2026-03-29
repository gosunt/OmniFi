"""
OmniFi Panel — About
Full technical reference: module descriptions · scoring vectors ·
architecture notes · credential security · system requirements.
All detail moved here to keep other panels clean.
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QScrollArea,
    QFrame, QGroupBox, QGridLayout,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui  import QFont

from ui.theme import (
    BG1, BG2, BG3, B1, T1, T2, T3, T4,
    ACC, GRN, YLW, RED, ORG, PUR, PINK,
    rgba, mf, sf,
)


def _section(title: str) -> QGroupBox:
    g = QGroupBox(title)
    g.setStyleSheet(
        f"QGroupBox {{ color:{T1}; font-weight:600; font-size:11px;"
        f"border:1px solid {B1}; border-radius:6px; margin-top:8px; padding-top:8px; }}"
        f"QGroupBox::title {{ subcontrol-origin:margin; left:10px; }}")
    return g


def _row(label: str, detail: str, label_color: str = T2) -> QHBoxLayout:
    h = QHBoxLayout(); h.setSpacing(10)
    lbl = QLabel(label); lbl.setFont(sf(9, bold=True))
    lbl.setStyleSheet(f"color:{label_color};"); lbl.setFixedWidth(180)
    lbl.setAlignment(Qt.AlignmentFlag.AlignTop)
    det = QLabel(detail); det.setFont(mf(9))
    det.setStyleSheet(f"color:{T3};"); det.setWordWrap(True)
    h.addWidget(lbl); h.addWidget(det, 1)
    return h


class AboutPanel(QWidget):
    """
    Full technical reference for OmniFi.
    Descriptions hidden from main panels are surfaced here.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build()

    def _build(self):
        outer = QVBoxLayout(self); outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(28, 20, 28, 28)
        lay.setSpacing(18)

        # ── Header ─────────────────────────────────────────────────────────────
        hdr = QHBoxLayout(); hdr.setSpacing(16)
        logo = QLabel("⬡"); logo.setFont(QFont("Segoe UI Emoji", 32))
        logo.setStyleSheet(f"color:{ACC};")
        hdr.addWidget(logo)
        titles = QVBoxLayout()
        t = QLabel("OmniFi"); t.setFont(sf(20, bold=True))
        t.setStyleSheet(f"color:{T1};")
        s = QLabel("Hybrid Wi-Fi Security System  ·  Technical Reference")
        s.setFont(mf(10)); s.setStyleSheet(f"color:{T3};")
        titles.addWidget(t); titles.addWidget(s)
        hdr.addLayout(titles, 1)
        lay.addLayout(hdr)

        div = QFrame(); div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet(f"color:{B1};"); lay.addWidget(div)

        # ── Detection Modules ──────────────────────────────────────────────────
        mg = _section("Detection Modules"); ml = QVBoxLayout(mg)
        ml.setSpacing(10)

        MODULES = [
            ("⚠", "ARP / MITM", RED,
             "Gateway MAC watch, ARP flood detection, IP-MAC conflicts. "
             "Detects active poisoning without Scapy. Polls every 30 s."),
            ("🌐", "DNS Spoof", YLW,
             "DoH comparison against Cloudflare/Google, TTL anomaly, "
             "NXDOMAIN spike detection. Polls every 120 s."),
            ("👥", "Evil Twin", RED,
             "BSSID/SSID mismatch, beacon analysis, BSSID history "
             "cross-check for rogue AP detection."),
            ("⚡", "Deauth Detector", ORG,
             "Scapy monitor-mode frame burst counting. "
             "Detects 802.11 deauthentication floods. Requires root/admin."),
            ("📡", "Beacon Anomaly", YLW,
             "Irregular beacon timing = rogue AP signal. "
             "Passive scan only — no active probe. Requires root/admin."),
            ("🖧", "Rogue DHCP", ORG,
             "Multiple DHCP servers = traffic hijack. "
             "Listens for DHCP offers on the subnet. Requires root/admin."),
            ("↩", "ICMP Redirect", YLW,
             "Forged ICMP type-5 silent rerouting detection. "
             "Monitors for unsolicited redirects."),
            ("🏨", "Captive Portal", ACC,
             "Hotel/cafe portal HTTPS + JS injection check. "
             "Detects credential-harvesting login pages."),
            ("🍪", "Session Hijack", RED,
             "Cleartext credentials + cookie flag check. "
             "Scans for unencrypted auth traffic. Requires root/admin."),
            ("🔐", "Wi-Fi Posture", GRN,
             "Protocol, WPS state, signal quality, saved password strength. "
             "Full posture assessment of the connected network."),
            ("🔌", "Open Ports", ORG,
             "Nmap or raw-socket port scan of gateway. "
             "Flags risky services on the router. Requires admin mode."),
            ("📋", "Device Baseline", PUR,
             "Snapshot of ARP table, flags new or changed devices. "
             "Detects unauthorized network additions. Requires admin mode."),
        ]

        grid = QGridLayout(); grid.setSpacing(8); grid.setContentsMargins(4,4,4,4)
        for i, (icon, name, color, desc) in enumerate(MODULES):
            card = QFrame()
            card.setStyleSheet(
                f"QFrame {{ background:{BG2}; border:1px solid {B1};"
                f"border-left:3px solid {color}; border-radius:6px; }}")
            cl = QVBoxLayout(card); cl.setContentsMargins(10,8,10,8); cl.setSpacing(3)
            nh = QHBoxLayout(); nh.setSpacing(6)
            ic = QLabel(icon); ic.setFont(QFont("Segoe UI Emoji", 13))
            ic.setStyleSheet(f"color:{color};")
            nm = QLabel(name); nm.setFont(sf(10, bold=True))
            nm.setStyleSheet(f"color:{T1};")
            nh.addWidget(ic); nh.addWidget(nm); nh.addStretch()
            cl.addLayout(nh)
            dl = QLabel(desc); dl.setFont(mf(8))
            dl.setStyleSheet(f"color:{T3};"); dl.setWordWrap(True)
            cl.addWidget(dl)
            grid.addWidget(card, i // 2, i % 2)
        ml.addLayout(grid)
        lay.addWidget(mg)

        # ── Scoring Vectors ────────────────────────────────────────────────────
        sg = _section("Network Security Scoring (100 pts)"); sl = QVBoxLayout(sg)
        sl.setSpacing(6)

        intro = QLabel(
            "Each visible network is scored across 11 pre-join security vectors (max 100 pts). "
            "Scoring is based on IEEE 802.11i/ax, NIST SP 800-153, and Wi-Fi Alliance security "
            "certification criteria. Saved password strength is shown separately.")
        intro.setFont(mf(9)); intro.setStyleSheet(f"color:{T3};")
        intro.setWordWrap(True); sl.addWidget(intro)

        VECTORS = [
            ("Encryption",        "30 pts", "WPA3/SAE=30 · WPA2-Enterprise=28 · OWE=27 · WPA2=20 · WPA=8 · WEP=2 · Open=0 (IEEE 802.11i/ax)"),
            ("Evil Twin",         "20 pts", "BSSID/SSID history mismatch = 0; duplicates = 10; clean = 20"),
            ("Signal",            "10 pts", "RSSI ≥−50=10 · ≥−60=8 · ≥−70=5 · ≥−80=2 · <−80=0"),
            ("PMF / 802.11w",     " 8 pts", "Protected Management Frames enabled (NIST SP 800-153 requirement)"),
            ("WPS",               " 8 pts", "WPS disabled = 8; WPS active = 0 (Pixie Dust / Reaver exposure)"),
            ("Band",              " 7 pts", "6 GHz=7 · 5 GHz=5 · 2.4 GHz=2 (Wi-Fi 6E / IEEE 802.11ax)"),
            ("SSID Visibility",   " 4 pts", "Broadcast SSID = 4; hidden SSID = 2"),
            ("ISP Risk",          " 3 pts", "Known-safe ISP / OUI = 3; flagged = 0"),
            ("Channel Congestion"," 5 pts", "Non-overlapping channel (ch 1/6/11 for 2.4 GHz), low peer count = higher score"),
            ("Key Rotation",      " 3 pts", "Enterprise EAP (dynamic session keys) = 3; PSK = 0"),
            ("AP Vendor OUI",     " 2 pts", "Known-good Wi-Fi Alliance certified vendor OUI = 2"),
            ("Password",          "bonus",  "Saved Wi-Fi password strength score (on top of base, shown separately)"),
        ]

        vg = QGridLayout(); vg.setSpacing(6)
        for i, (vec, pts, note) in enumerate(VECTORS):
            vl = QLabel(vec); vl.setFont(sf(9, bold=True))
            vl.setStyleSheet(f"color:{T2};"); vl.setFixedWidth(120)
            pl = QLabel(pts); pl.setFont(mf(9))
            pl.setStyleSheet(f"color:{ACC}; font-weight:600;"); pl.setFixedWidth(50)
            nl = QLabel(note); nl.setFont(mf(9))
            nl.setStyleSheet(f"color:{T3};")
            vg.addWidget(vl, i, 0); vg.addWidget(pl, i, 1); vg.addWidget(nl, i, 2)
        sl.addLayout(vg)
        lay.addWidget(sg)

        # ── Threat Correlation Engine ──────────────────────────────────────────
        cg = _section("Attack Correlation Engine"); cl2 = QVBoxLayout(cg)
        for h2, body in [
            ("Multi-signal correlation",
             "Correlates signals from ARP, DNS, BSSID, and timing detectors "
             "into high-confidence attack findings. 8 rule templates with "
             "confidence scoring — results visible in the Dashboard."),
            ("Time-based spike detection",
             "Sliding 60-second window counts alert frequency per source. "
             "A sudden burst triggers a spike alert even if individual events "
             "are rated low severity."),
            ("Confidence scoring",
             "Each correlation rule weights signals differently. "
             "Findings are only surfaced when confidence exceeds a configurable "
             "threshold to minimise false positives."),
        ]:
            cl2.addLayout(_row(h2, body))
        lay.addWidget(cg)

        # ── Credential & Auth Security ─────────────────────────────────────────
        credog = _section("Credential & Auth Security"); credl = QVBoxLayout(credog)
        for h2, body in [
            ("Password hashing",
             "Router password is hashed with PBKDF2-SHA256 (100,000 iterations, "
             "16-byte random salt) on login. Never written to disk as plaintext."),
            ("Saved Wi-Fi passwords",
             "OS password profiles are read only for SSIDs that appeared in the "
             "current scan — no full password dump. Passwords are immediately "
             "scored and masked; never logged."),
            ("Admin mode",
             "Admin credentials are used solely to authenticate against the "
             "router management interface. The session token is held in memory "
             "and cleared on logout or mode switch."),
        ]:
            credl.addLayout(_row(h2, body))
        lay.addWidget(credog)

        # ── System Requirements ────────────────────────────────────────────────
        rg = _section("System Requirements & Capabilities"); rl = QVBoxLayout(rg)
        for h2, body, color in [
            ("Root / Administrator",
             "Required for Scapy packet capture (Deauth, Beacon, DHCP, Session "
             "Hijack modules), raw socket access, and reading Wi-Fi passwords "
             "from NetworkManager on Linux.",
             YLW),
            ("Scapy",
             "Optional Python library for monitor-mode frame capture. "
             "Without it, packet-level modules fall back to passive ARP/DNS checks.",
             ACC),
            ("pywifi",
             "Optional library for direct Wi-Fi interface control on Linux/Windows. "
             "Enables richer SSID scanning beyond nmcli/netsh.",
             ACC),
            ("nmap",
             "Optional: used by the Open Ports module for gateway port scanning. "
             "Falls back to raw-socket scanning if nmap is unavailable.",
             ACC),
            ("Platform",
             "Tested on Windows 10/11 and Ubuntu 22.04+. "
             "macOS support is partial — Scapy monitor mode requires additional "
             "driver configuration.",
             T3),
        ]:
            rl.addLayout(_row(h2, body, color))
        lay.addWidget(rg)

        # ── Architecture ───────────────────────────────────────────────────────
        ag = _section("Architecture Overview"); al = QVBoxLayout(ag)
        for h2, body in [
            ("Signal flow",
             "Detection modules → AlertMonitor shim → ALERTS AlertEngine singleton "
             "(Qt signals: new_alert, trust_changed) → UI panels."),
            ("Monitor thread",
             "Continuous polling thread with per-module intervals: "
             "ARP 30 s · DNS 120 s · Devices 60 s · Networks 180 s. "
             "All I/O is off the main thread."),
            ("Policy engine",
             "Blacklist / Whitelist / Quarantine / Exception rules with optional "
             "expiry timers. Policies are applied via the router management API "
             "in admin mode. Safe mode requires confirmation for every action."),
            ("Scanner",
             "Pre-join assessment: scores every visible AP on 8 vectors, "
             "reads saved OS passwords only for SSIDs found in the current scan, "
             "injects password score into the network card for inline display."),
        ]:
            al.addLayout(_row(h2, body))
        lay.addWidget(ag)
        lay.addStretch()

        scroll.setWidget(w); outer.addWidget(scroll)
