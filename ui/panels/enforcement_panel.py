"""
OmniFi — Enforcement Panel
===========================
Replaces the manual-run threat scan panel.

Shows live detected threats from the continuous monitor grouped by attack
vector. Each threat has instant enforcement buttons:
  Block · Quarantine · Whitelist · VPN · Dismiss

Auto-enforce fires automatically when the policy engine confidence threshold
is met (configurable in Settings → Enforcement Mode).

No manual "Run" buttons. Detection is always running in the background.
"""
import datetime
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QFrame, QGroupBox, QSplitter,
)
from PyQt6.QtCore  import Qt, QTimer, pyqtSignal
from PyQt6.QtGui   import QColor, QFont

from ui.theme import (
    BG0, BG1, BG2, BG3, BG4, B1, B2,
    T1, T2, T3, T4,
    ACC, GRN, YLW, RED, ORG, PUR,
    LVL_C, rgba, mf, sf,
)
from ui.widgets.trust_graph   import TrustGraphWidget
from ui.widgets.timeline_widget import TimelineWidget


# ── Threat severity colour ────────────────────────────────────────────────────
_SEV_C = {"critical": RED, "high": ORG, "medium": YLW, "low": ACC, "ok": GRN}

# ── Attack vector → human label + icon + recommended action ──────────────────
_VECTOR_META = {
    "arp_mitm":       ("ARP / MITM",        "⚠",  "critical", "block"),
    "dns_spoof":      ("DNS Spoof",          "🌐", "critical", "vpn"),
    "evil_twin":      ("Evil Twin AP",       "👥", "critical", "block"),
    "deauth":         ("Deauth Flood",       "⚡", "high",     "block"),
    "beacon_anomaly": ("Beacon Anomaly",     "📡", "high",     "block"),
    "rogue_dhcp":     ("Rogue DHCP",         "🖧",  "high",    "block"),
    "icmp_redirect":  ("ICMP Redirect",      "↩",  "medium",  "block"),
    "captive_portal": ("Captive Portal",     "🏨", "medium",   "vpn"),
    "session_hijack": ("Session Hijack",     "🍪", "high",     "vpn"),
    "port_scan":      ("Open Port Risk",     "🔍", "medium",   "block"),
    "device_baseline":("Device Anomaly",     "📊", "medium",   "block"),
    "correlation":    ("Correlated Attack",  "🔗", "critical", "block"),
    "password_checker":("Weak Password",     "🔐", "high",     "change_password"),
    "monitor":        ("Monitor",            "ℹ",  "low",      "ignore"),
    "safe_mode":      ("Safe Mode",          "🛡",  "low",     "ignore"),
    "auth":           ("Auth",               "🔑",  "low",     "ignore"),
    "interface_monitor":("Interface",        "📡", "low",      "ignore"),
    "monitor_mode":   ("Monitor Mode",       "📡", "low",      "ignore"),
}


class ThreatCard(QFrame):
    """
    Single detected threat card with enforcement buttons.
    Emits enforce_sig(action, alert_dict) when user clicks an action.
    Emits dismiss_sig(alert_id) to remove from view.
    """
    enforce_sig = pyqtSignal(str, dict)
    dismiss_sig = pyqtSignal(int)

    _ACTION_BTNS = [
        ("block",           "🚫 Block",       "danger"),
        ("isolated",        "🔒 Quarantine",  "warn"),
        ("whitelist",       "✅ Trust",        "success"),
        ("vpn",             "🔒 VPN",          "purple"),
        ("change_password", "🔐 Fix Password", "warn"),
    ]

    def __init__(self, alert: dict, is_admin: bool, parent=None):
        super().__init__(parent)
        self._alert    = alert
        self._is_admin = is_admin
        self._build()

    def _build(self):
        src    = self._alert.get("source", "monitor")
        level  = self._alert.get("level",  "low")
        msg    = self._alert.get("message","")
        detail = self._alert.get("detail", "")
        ts     = self._alert.get("ts","")[:19].replace("T"," ")
        actions= self._alert.get("actions", [])

        meta   = _VECTOR_META.get(src, ("Threat", "⚠", level, "block"))
        vname, icon, _, recommended = meta
        lc     = _SEV_C.get(level, T2)

        self.setObjectName("ThreatCard")
        self.setStyleSheet(f"""
            #ThreatCard {{
                background:{BG2}; border:1px solid {B1};
                border-left:4px solid {lc}; border-radius:7px;
                margin-bottom:5px;
            }}
        """)

        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 10, 0); root.setSpacing(0)

        # Severity bar
        bar = QFrame(); bar.setFixedWidth(4)
        bar.setStyleSheet(f"background:{lc}; border-radius:4px 0 0 4px;")
        root.addWidget(bar)

        body = QVBoxLayout()
        body.setContentsMargins(12, 9, 6, 9); body.setSpacing(5)

        # Header row
        hr = QHBoxLayout(); hr.setSpacing(6)

        # Vector icon + level pill
        ic_lbl = QLabel(icon)
        ic_lbl.setFont(QFont("Segoe UI Emoji", 13))
        hr.addWidget(ic_lbl)

        for txt, bg, fg in [
            (level.upper(),                    lc,  "#000"),
            (vname,                            BG3, T3),
            (ts,                               BG3, T4),
        ]:
            chip = QLabel(txt); chip.setFont(mf(8))
            rc,gc,bc = QColor(bg).red(), QColor(bg).green(), QColor(bg).blue()
            chip.setStyleSheet(
                f"color:{fg if fg != T3 and fg != T4 else fg};"
                f"background:{bg}; border:1px solid {rgba(lc,0.3) if bg==lc else B1};"
                f"border-radius:3px; padding:1px 7px;")
            hr.addWidget(chip)
        hr.addStretch()

        # Dismiss X
        dm = QPushButton("✕"); dm.setFont(mf(9)); dm.setFixedSize(24, 20)
        dm.setStyleSheet(
            f"QPushButton{{background:none;color:{T3};border:none;}}"
            f"QPushButton:hover{{color:{RED};}}")
        dm.clicked.connect(
            lambda: self.dismiss_sig.emit(self._alert.get("id", 0)))
        hr.addWidget(dm)
        body.addLayout(hr)

        # Message
        ml = QLabel(msg); ml.setFont(sf(11))
        ml.setStyleSheet(f"color:{T1};"); ml.setWordWrap(True)
        body.addWidget(ml)

        # Detail (only if non-empty and not from low-priority sources)
        if detail and self._alert.get("level") not in ("low","info"):
            dl = QLabel(detail); dl.setFont(mf(8)); dl.setWordWrap(True)
            dl.setStyleSheet(
                f"color:{T3}; background:{BG3}; border-radius:4px; padding:3px 8px;")
            body.addWidget(dl)

        # Correlation chain if present
        if self._alert.get("corr_data"):
            cd   = self._alert["corr_data"]
            sigs = " + ".join(cd.get("signals",[]))
            conf = cd.get("conf", 0)
            cl   = QLabel(f"⚡ {conf}% confidence  ·  signals: {sigs}")
            cl.setFont(mf(8))
            cl.setStyleSheet(
                f"color:{PUR}; background:{rgba(PUR,0.07)};"
                f"border:1px solid {rgba(PUR,0.2)}; border-radius:4px; padding:3px 8px;")
            body.addWidget(cl)

        # Action buttons — only for actionable threats
        if self._alert.get("level") not in ("low","info") or actions:
            ar = QHBoxLayout(); ar.setSpacing(5)
            shown_actions = actions or [recommended, "ignore"]

            for action_key, btn_label, btn_cls in self._ACTION_BTNS:
                if action_key not in shown_actions:
                    continue
                if not self._is_admin and action_key in ("block","isolated","whitelist"):
                    continue   # client mode: no enforcement buttons
                b = QPushButton(btn_label)
                b.setFont(mf(9)); b.setFixedHeight(26)
                b.setProperty("cls", btn_cls)
                b.clicked.connect(
                    lambda _, a=action_key: self.enforce_sig.emit(a, self._alert))
                ar.addWidget(b)

            if not self._is_admin:
                adv = QLabel("💡 Use VPN or switch network")
                adv.setFont(mf(8))
                adv.setStyleSheet(
                    f"color:{ACC}; background:{rgba(ACC,0.06)};"
                    f"border:1px solid {rgba(ACC,0.18)}; border-radius:4px; padding:2px 8px;")
                ar.addWidget(adv)

            ar.addStretch()
            body.addLayout(ar)

        root.addLayout(body)


class EnforcementPanel(QWidget):
    """
    Live enforcement panel.

    Receives threats from the continuous monitor (via add_threat() called
    from MainWindow._on_alert). No manual run buttons anywhere.

    Provides:
      • Grouped threat cards with one-click enforcement
      • Auto-enforce indicator (fires when confidence ≥ threshold)
      • Trust graph + attack timeline
      • Module status row (always-running indicator dots)
    """
    enforce_sig = pyqtSignal(str, dict)   # action, alert

    # Which alert sources are actionable (shown as threat cards)
    _ACTIONABLE = {
        "arp_mitm", "dns_spoof", "evil_twin", "deauth",
        "beacon_anomaly", "rogue_dhcp", "dhcp_rogue",
        "icmp_redirect", "captive_portal", "session_hijack",
        "port_scan", "device_baseline", "correlation_engine",
        "correlation", "password_checker",
    }

    def __init__(self, is_admin_fn, safe_mode_fn, parent=None):
        super().__init__(parent)
        self._is_admin_fn  = is_admin_fn
        self._safe_mode_fn = safe_mode_fn
        self._threats      = []     # list of alert dicts
        self._dismissed    = set()  # dismissed alert ids
        self._build()

    def _build(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0); outer.setSpacing(0)

        # ── Top bar ───────────────────────────────────────────────────────────
        tb = QFrame(); tb.setFixedHeight(44)
        tb.setStyleSheet(f"background:{BG1}; border-bottom:1px solid {B1};")
        tbl = QHBoxLayout(tb)
        tbl.setContentsMargins(16, 0, 16, 0); tbl.setSpacing(10)

        tit = QLabel("Enforcement"); tit.setFont(sf(12, bold=True))
        tbl.addWidget(tit)

        self._cnt = QLabel("0"); self._cnt.setFont(mf(9))
        self._cnt.setStyleSheet(
            f"color:{T3}; background:{BG3}; border:1px solid {B1};"
            f"border-radius:3px; padding:1px 8px;")
        self._cnt.setToolTip("Active threats requiring attention")
        tbl.addWidget(self._cnt)

        # Auto-enforce indicator
        self._ae_chip = QLabel("⚡ AUTO-ENFORCE OFF")
        self._ae_chip.setFont(mf(8))
        self._ae_chip.setStyleSheet(
            f"color:{T4}; background:{BG3}; border:1px solid {B1};"
            f"border-radius:3px; padding:1px 8px;")
        tbl.addWidget(self._ae_chip)

        tbl.addStretch()

        # Module status dots (always running)
        for name, st, tip in [
            ("ARP",  GRN, "ARP/MITM — always running"),
            ("DNS",  GRN, "DNS spoof — always running"),
            ("Twin", GRN, "Evil twin — always running"),
            ("Dev",  GRN, "Device monitor — always running"),
            ("Auth", YLW, "Deauth — monitor mode required"),
            ("DHCP", GRN, "Rogue DHCP — always running"),
        ]:
            d = QLabel(f"● {name}"); d.setFont(mf(8))
            d.setStyleSheet(f"color:{st};")
            d.setToolTip(tip); tbl.addWidget(d)

        clr = QPushButton("Clear"); clr.setFont(mf(9)); clr.setFixedHeight(26)
        clr.setToolTip("Dismiss all shown threats")
        clr.clicked.connect(self._clear_all)
        tbl.addWidget(clr)
        outer.addWidget(tb)

        # ── Body split: threats | graph+timeline ─────────────────────────────
        spl = QSplitter(Qt.Orientation.Horizontal)
        spl.setHandleWidth(1)
        spl.setStyleSheet(f"QSplitter::handle{{background:{B1};}}")

        # Left: threat cards
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(12, 8, 6, 8); ll.setSpacing(0)

        # Filter row
        fr = QHBoxLayout(); fr.setSpacing(5)
        fr.addWidget(self._small("Filter:"))
        self._filt_btns = {}
        for lvl, tip in [
            ("all",      "Show all threats"),
            ("critical", "Critical only"),
            ("high",     "High only"),
            ("medium",   "Medium + above"),
        ]:
            b = QPushButton(lvl.title() if lvl != "all" else "All")
            b.setFont(mf(9)); b.setFixedHeight(24); b.setCheckable(True)
            b.setChecked(lvl == "all"); b.setToolTip(tip)
            b.clicked.connect(lambda _, l=lvl: self._set_filt(l))
            fr.addWidget(b); self._filt_btns[lvl] = b
        fr.addStretch()
        ll.addLayout(fr)

        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._cards_w = QWidget()
        self._cards_l = QVBoxLayout(self._cards_w)
        self._cards_l.setContentsMargins(0, 4, 0, 4); self._cards_l.setSpacing(0)
        self._empty = QLabel("✓  No active threats — monitoring continuously")
        self._empty.setFont(mf(10)); self._empty.setStyleSheet(f"color:{T3};")
        self._empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._cards_l.addWidget(self._empty)
        self._cards_l.addStretch()
        scroll.setWidget(self._cards_w)
        ll.addWidget(scroll, 1)
        spl.addWidget(left)

        # Right: trust graph + timeline
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(6, 8, 12, 8); rl.setSpacing(8)

        tg_grp = QGroupBox("Trust Score")
        tgl = QVBoxLayout(tg_grp)
        self.trust_graph = TrustGraphWidget()
        self.trust_graph.setMinimumHeight(110)
        tgl.addWidget(self.trust_graph)
        rl.addWidget(tg_grp)

        tl_grp = QGroupBox("Timeline")
        tll = QVBoxLayout(tl_grp)
        self.timeline = TimelineWidget()
        tll.addWidget(self.timeline)
        rl.addWidget(tl_grp, 1)
        spl.addWidget(right)

        spl.setSizes([580, 300])
        outer.addWidget(spl, 1)

        self._filt = "all"

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _small(self, txt):
        l = QLabel(txt); l.setFont(mf(9))
        l.setStyleSheet(f"color:{T3};"); return l

    # ── Public API ────────────────────────────────────────────────────────────
    def add_threat(self, alert: dict):
        """Called by MainWindow._on_alert for every incoming alert."""
        src = alert.get("source","")
        # Only render actionable threats as cards
        if src not in self._ACTIONABLE and alert.get("level") in ("low","info"):
            # Still add to timeline
            self.timeline.add_event(
                alert["level"], src, alert.get("message",""))
            return

        self._threats.insert(0, alert)
        self._cnt.setText(str(len(self._threats)))
        self._empty.setVisible(False)
        self.timeline.add_event(
            alert["level"], src, alert.get("message",""))

        if self._filt == "all" or alert.get("level") == self._filt or (
            self._filt == "medium" and alert.get("level") in ("medium","high","critical")
        ):
            self._prepend_card(alert)

    def load_history(self, alerts: list):
        for a in reversed(alerts):
            self.add_threat(a)

    def update_trust(self, score: int):
        self.trust_graph.add_point(score)

    def update_auto_enforce(self, enabled: bool, threshold: int = 80):
        if enabled:
            self._ae_chip.setText(f"⚡ AUTO ≥{threshold}%")
            self._ae_chip.setStyleSheet(
                f"color:{RED}; background:{rgba(RED,0.08)};"
                f"border:1px solid {rgba(RED,0.2)}; border-radius:3px; padding:1px 8px;")
        else:
            self._ae_chip.setText("🖐 MANUAL")
            self._ae_chip.setStyleSheet(
                f"color:{YLW}; background:{rgba(YLW,0.08)};"
                f"border:1px solid {rgba(YLW,0.2)}; border-radius:3px; padding:1px 8px;")

    # ── Internals ─────────────────────────────────────────────────────────────
    def _prepend_card(self, alert: dict):
        card = ThreatCard(alert, self._is_admin_fn())
        card.enforce_sig.connect(self.enforce_sig)
        card.dismiss_sig.connect(self._dismiss)
        self._cards_l.insertWidget(0, card)

    def _dismiss(self, alert_id: int):
        self._dismissed.add(alert_id)
        self._threats = [a for a in self._threats if a.get("id") != alert_id]
        self._cnt.setText(str(len(self._threats)))
        self._rebuild()

    def _clear_all(self):
        self._dismissed.update(a.get("id",0) for a in self._threats)
        self._threats.clear()
        self._cnt.setText("0")
        self._rebuild()

    def _set_filt(self, lvl: str):
        self._filt = lvl
        for l, b in self._filt_btns.items(): b.setChecked(l == lvl)
        self._rebuild()

    def _rebuild(self):
        while self._cards_l.count() > 2:
            item = self._cards_l.takeAt(0)
            if item.widget(): item.widget().deleteLater()

        shown = self._threats
        if self._filt == "critical":
            shown = [a for a in shown if a.get("level") == "critical"]
        elif self._filt == "high":
            shown = [a for a in shown if a.get("level") in ("critical","high")]
        elif self._filt == "medium":
            shown = [a for a in shown if a.get("level") in ("critical","high","medium")]

        for a in shown:
            if a.get("id",0) not in self._dismissed:
                self._prepend_card(a)

        self._empty.setVisible(len(self._threats) == 0)
