"""
OmniFi — Dashboard Panel  (production)
Includes:
  • Stat cards (threats / correlations / devices / uptime)
  • Live trust score graph (rolling 30-min history)
  • Posture vector breakdown bars
  • Module status dots
  • Network topology map
  • Attack timeline
  • Event log
"""
import datetime
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QProgressBar, QGroupBox, QSplitter, QScrollArea, QTextEdit,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui  import QFont

from ui.theme import (
    BG0, BG2, BG4, B1, T1, T2, T3, T4,
    GRN, YLW, RED, ORG, PUR, ACC,
    LVL_C, VDT_C, rgba, mf, sf,
)
from ui.widgets.score_ring       import ScoreRing
from ui.widgets.trust_graph      import TrustGraphWidget
from ui.widgets.timeline_widget  import TimelineWidget
from ui.widgets.network_map_widget import NetworkMapWidget

_VEC_TIPS = {
    "Encryption":    "WPA3=30  WPA2=20  WPA=8  WEP=2  Open=0",
    "No evil twin":  "Unique BSSID per SSID checked against history database",
    "Signal":        "RSSI ≥ -50 = 15 pts  /  -80 = 5 pts  /  -90 = 2 pts",
    "PMF / 802.11w": "Management Frame Protection prevents deauth attacks",
    "WPS off":       "WPS enabled allows PIN brute-force in hours",
    "DNS clean":     "Local DNS matches Cloudflare DoH answer",
    "ARP clean":     "Gateway MAC unchanged since baseline",
}

MODS = [
    ("ARP / MITM",     "active", "Gateway MAC watch + ARP flood detection"),
    ("DNS Spoof",      "active", "DoH comparison + NXDOMAIN spike"),
    ("Evil Twin",      "active", "SSID/BSSID history + duplicate AP"),
    ("Device Monitor", "active", "New device alerts + LA-MAC detection"),
    ("Deauth",         "warn",   "Monitor-mode required (Scapy)"),
    ("Beacon Anomaly", "off",    "Monitor-mode required (Scapy)"),
    ("DHCP Rogue",     "active", "Multiple DHCP server detection"),
    ("Session Hijack", "active", "Cleartext credential sniffing"),
    ("Correlation",    "active", "8 multi-signal attack rules"),
    ("Time-based",     "active", "60 s sliding window spike detection"),
]


class DashboardPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent); self._build()

    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12); lay.setSpacing(10)

        # ── Row 1: stat cards ─────────────────────────────────────────────────
        sg = QHBoxLayout(); sg.setSpacing(8)
        self._cards = []
        for label, val, color, tip in [
            ("Threats",      "0",     RED, "Critical + high alerts in last hour"),
            ("Correlations", "0",     PUR, "Multi-signal attack patterns"),
            ("Devices",      "0",     YLW, "Unique devices on this network"),
            ("Uptime",       "00:00", GRN, "Monitoring session duration"),
        ]:
            card = self._stat_card(label, val, color, tip)
            self._cards.append(card); sg.addWidget(card)
        lay.addLayout(sg)

        # ── Row 2: trust graph | posture ring | modules ───────────────────────
        r2 = QHBoxLayout(); r2.setSpacing(10)

        # Trust graph
        tg_grp = QGroupBox("Trust Score — 30 min history"); tgl = QVBoxLayout(tg_grp)
        self.trust_graph = TrustGraphWidget()
        self.trust_graph.setMinimumHeight(120)
        tgl.addWidget(self.trust_graph)
        r2.addWidget(tg_grp, 3)

        # Posture ring + bars
        pg = QGroupBox("Posture"); pl = QVBoxLayout(pg)
        pr = QHBoxLayout(); pr.setSpacing(12)
        self._ring = ScoreRing(76); self._ring.set_score_instant(100,"safe")
        pr.addWidget(self._ring)
        sbr = QVBoxLayout(); sbr.setSpacing(4)
        self._vbars = {}
        for lbl, pts, mx, c in [
            ("Encryption",   20, 30, YLW),
            ("No evil twin", 20, 20, GRN),
            ("Signal",       12, 15, GRN),
            ("PMF / 802.11w", 0, 10, RED),
            ("WPS off",      10, 10, GRN),
            ("DNS clean",     8,  8, GRN),
            ("ARP clean",     2,  7, RED),
        ]:
            rr = QHBoxLayout(); rr.setSpacing(5)
            nl = QLabel(lbl); nl.setFont(mf(8))
            nl.setStyleSheet(f"color:{T2};"); nl.setFixedWidth(78)
            nl.setToolTip(_VEC_TIPS.get(lbl,""))
            pb = QProgressBar(); pb.setRange(0,mx); pb.setValue(pts)
            pb.setTextVisible(False); pb.setFixedHeight(4)
            pb.setStyleSheet(
                f"QProgressBar{{background:{BG4};border:none;border-radius:2px;}}"
                f"QProgressBar::chunk{{background:{c};border-radius:2px;}}")
            vl = QLabel(f"{pts}/{mx}"); vl.setFont(mf(7))
            vl.setStyleSheet(f"color:{T1};"); vl.setFixedWidth(30)
            vl.setAlignment(Qt.AlignmentFlag.AlignRight)
            rr.addWidget(nl); rr.addWidget(pb,1); rr.addWidget(vl)
            sbr.addLayout(rr); self._vbars[lbl] = (pb, vl, mx, c)
        pr.addLayout(sbr); pl.addLayout(pr)
        self._vdict = QLabel("SAFE"); self._vdict.setFont(mf(9,bold=True))
        self._vdict.setStyleSheet(
            f"color:{GRN}; background:{rgba(GRN,0.1)}; border-radius:4px; padding:2px 8px;")
        self._vdict.setAlignment(Qt.AlignmentFlag.AlignCenter)
        pl.addWidget(self._vdict)
        r2.addWidget(pg, 2)

        # Modules
        mg = QGroupBox("Modules"); ml = QVBoxLayout(mg); ml.setSpacing(3)
        self._mod_rows = {}
        for name, st, tip in MODS:
            rr = QHBoxLayout(); rr.setSpacing(6)
            c = GRN if st=="active" else YLW if st=="warn" else T3
            dot = QLabel("●"); dot.setFont(mf(8)); dot.setFixedWidth(10)
            dot.setStyleSheet(f"color:{c};"); dot.setToolTip(tip)
            nl = QLabel(name); nl.setFont(mf(8)); nl.setStyleSheet(f"color:{T2};")
            nl.setToolTip(tip)
            sl = QLabel(st.upper()); sl.setFont(mf(7)); sl.setStyleSheet(f"color:{c};")
            rr.addWidget(dot); rr.addWidget(nl,1); rr.addWidget(sl)
            ml.addLayout(rr); self._mod_rows[name] = (dot,nl,sl)
        r2.addWidget(mg, 1)
        lay.addLayout(r2)

        # ── Row 3: network map | timeline ─────────────────────────────────────
        spl = QSplitter(Qt.Orientation.Horizontal)
        spl.setHandleWidth(1)
        spl.setStyleSheet(f"QSplitter::handle{{background:{B1};}}")

        nm_grp = QGroupBox("Network Map"); nml = QVBoxLayout(nm_grp)
        self.network_map = NetworkMapWidget()
        self.network_map.setMinimumHeight(180)
        nml.addWidget(self.network_map)
        spl.addWidget(nm_grp)

        tl_grp = QGroupBox("Attack Timeline"); tll = QVBoxLayout(tl_grp)
        self.timeline = TimelineWidget()
        self.timeline.setMinimumHeight(180)
        tll.addWidget(self.timeline)
        spl.addWidget(tl_grp)

        spl.setSizes([500, 360])
        lay.addWidget(spl, 1)

        # ── Row 4: event log ──────────────────────────────────────────────────
        lg = QGroupBox("Event Log"); lgl = QVBoxLayout(lg)
        self._log = QTextEdit(); self._log.setReadOnly(True)
        self._log.setFont(mf(9)); self._log.setFixedHeight(100)
        self._log.setStyleSheet(f"background:{BG0}; border:none;")
        lgl.addWidget(self._log)
        lay.addWidget(lg)

    # ── Helpers ────────────────────────────────────────────────────────────────
    def _stat_card(self, label, val, color, tip):
        f = QFrame(); f.setToolTip(tip)
        f.setStyleSheet(
            f"background:{BG2}; border:1px solid {B1}; border-radius:8px;"
            f"border-bottom:3px solid {color};")
        fl = QVBoxLayout(f); fl.setContentsMargins(14,10,14,10); fl.setSpacing(3)
        ll = QLabel(label); ll.setFont(mf(8)); ll.setStyleSheet(f"color:{T3};")
        vl = QLabel(val); vl.setFont(mf(26,bold=True)); vl.setStyleSheet(f"color:{color};")
        fl.addWidget(ll); fl.addWidget(vl); return f

    def _card_val(self, idx):
        return [c for c in self._cards[idx].children() if isinstance(c,QLabel)][1]

    # ── Public update API ──────────────────────────────────────────────────────
    def update_trust(self, score, verdict):
        self._ring.set_score(score, verdict)
        self.trust_graph.add_point(score)
        c = VDT_C.get(verdict, T2)
        self._vdict.setText(verdict.upper())
        self._vdict.setStyleSheet(
            f"color:{c}; background:{rgba(c,0.1)}; border-radius:4px; padding:2px 8px;")

    def update_uptime(self, s):
        h=s//3600; m=(s%3600)//60; sec=s%60
        self._card_val(3).setText(f"{h:02d}:{m:02d}:{sec:02d}")

    def update_device_count(self, n): self._card_val(2).setText(str(n))
    def update_threat_count(self, n): self._card_val(0).setText(str(n))
    def update_corr_count(self, n):   self._card_val(1).setText(str(n))

    def set_module_status(self, name, status):
        if name not in self._mod_rows: return
        dot,nl,sl = self._mod_rows[name]
        c = GRN if status=="active" else YLW if status=="warn" else T3
        dot.setStyleSheet(f"color:{c};")
        sl.setText(status.upper()); sl.setStyleSheet(f"color:{c};")

    def add_device_to_map(self, mac, ip="", hostname="", status="unknown"):
        self.network_map.add_device(mac, ip, hostname, status)

    def update_device_on_map(self, mac, status):
        self.network_map.update_device_status(mac, status)

    def load_devices_on_map(self, devs):
        self.network_map.load_devices(devs)

    def log_event(self, level, source, message):
        ts   = datetime.datetime.now().strftime("%H:%M:%S")
        c    = LVL_C.get(level, T2)
        html = (f'<span style="color:{T4}">{ts} </span>'
                f'<span style="color:{c}">[{source}]</span> '
                f'<span style="color:{T2}">{message}</span><br>')
        cur  = self._log.textCursor()
        cur.movePosition(cur.MoveOperation.Start); cur.insertHtml(html)
        # Also push to timeline
        self.timeline.add_event(level, source, message)
