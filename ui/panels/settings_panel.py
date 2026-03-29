"""
OmniFi — Settings Panel  (v9)
Safe mode is now a full Enforcement Policy section with:
  • Manual vs Automatic mode
  • Per-action type overrides (blacklist, whitelist, quarantine, exception, guest)
  • Confidence threshold slider for auto-enforcement
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QCheckBox,
    QGroupBox, QLabel, QScrollArea, QFrame, QPushButton,
    QComboBox, QSlider, QSpinBox,
)
from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtGui  import QFont
from ui.theme import (
    BG2, BG3, B1, T1, T2, T3, T4,
    GRN, YLW, RED, ORG, ACC, PUR,
    rgba, mf, sf,
)


class SettingsPanel(QWidget):
    safe_mode_changed         = pyqtSignal(bool)
    enforce_mode_changed      = pyqtSignal(str)    # "manual" | "auto"
    action_policy_changed     = pyqtSignal(str, str)  # action_type, policy_name
    auto_threshold_changed    = pyqtSignal(int)    # confidence % 0-100

    def __init__(self, backend, parent=None):
        super().__init__(parent)
        self._b = backend
        self._build()

    def _build(self):
        # Outer layout owns self — must be assigned first so Qt retains it
        outer = QVBoxLayout(self); outer.setContentsMargins(0,0,0,0)

        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        w = QWidget(); lay = QVBoxLayout(w)
        lay.setContentsMargins(22,16,22,16); lay.setSpacing(16)

        # ── 1. Enforcement Mode ───────────────────────────────────────────────
        eg = QGroupBox("Enforcement Mode"); el = QVBoxLayout(eg); el.setSpacing(10)

        # Manual / Auto toggle row
        mode_row = QHBoxLayout(); mode_row.setSpacing(8)
        self._manual_btn = QPushButton("🖐  Manual")
        self._auto_btn   = QPushButton("⚡  Automatic")
        _style = (f"QPushButton{{background:{BG3};border:1px solid {rgba(T3,0.3)};"
                  f"border-radius:6px;padding:7px 18px;font-size:11px;}}"
                  f"QPushButton:checked{{background:{rgba(ACC,0.12)};"
                  f"border-color:{ACC};color:{ACC};}}"
                  f"QPushButton:hover:!checked{{background:{BG2};}}")
        for b in (self._manual_btn, self._auto_btn):
            b.setCheckable(True); b.setStyleSheet(_style)
        self._manual_btn.setChecked(True)
        self._manual_btn.setToolTip(
            "Manual: every enforcement action requires explicit confirmation\n"
            "(same as Safe Mode ON)")
        self._auto_btn.setToolTip(
            "Automatic: enforcement actions are applied immediately\n"
            "when the confidence threshold is met")
        self._manual_btn.clicked.connect(lambda: self._set_enforce_mode("manual"))
        self._auto_btn.clicked.connect(lambda:   self._set_enforce_mode("auto"))
        mode_row.addWidget(self._manual_btn); mode_row.addWidget(self._auto_btn)
        mode_row.addStretch()

        # Status badge
        self._mode_badge = QLabel("🖐  MANUAL — confirmation required for all actions")
        self._mode_badge.setFont(mf(9))
        self._mode_badge.setStyleSheet(
            f"color:{YLW}; background:{rgba(YLW,0.09)}; border:1px solid {rgba(YLW,0.22)};"
            f"border-radius:4px; padding:4px 10px;")
        el.addLayout(mode_row)
        el.addWidget(self._mode_badge)

        # Auto-threshold (shown only when auto mode)
        self._thresh_frame = QFrame(); self._thresh_frame.setVisible(False)
        tf = QVBoxLayout(self._thresh_frame); tf.setContentsMargins(0,4,0,0); tf.setSpacing(6)
        th_row = QHBoxLayout(); th_row.setSpacing(10)
        th_lbl = QLabel("Auto-enforce when confidence ≥")
        th_lbl.setFont(mf(9)); th_lbl.setStyleSheet(f"color:{T2};")
        self._thresh_slider = QSlider(Qt.Orientation.Horizontal)
        self._thresh_slider.setRange(50, 100); self._thresh_slider.setValue(80)
        self._thresh_slider.setFixedWidth(160)
        self._thresh_slider.setToolTip(
            "Only fire automatic enforcement when the correlation engine\n"
            "reports confidence ≥ this threshold")
        self._thresh_val = QLabel("80%")
        self._thresh_val.setFont(mf(9, bold=True)); self._thresh_val.setStyleSheet(f"color:{ACC};")
        self._thresh_val.setFixedWidth(36)
        self._thresh_slider.valueChanged.connect(
            lambda v: (self._thresh_val.setText(f"{v}%"),
                       self.auto_threshold_changed.emit(v)))
        th_row.addWidget(th_lbl); th_row.addWidget(self._thresh_slider)
        th_row.addWidget(self._thresh_val); th_row.addStretch()
        tf.addLayout(th_row)
        note = QLabel(
            "Automatic enforcement runs without prompting when an attack "
            "correlation rule fires at or above this confidence level.")
        note.setFont(mf(8)); note.setWordWrap(True); note.setStyleSheet(f"color:{T3};")
        tf.addWidget(note)
        el.addWidget(self._thresh_frame)
        lay.addWidget(eg)

        # ── 2. Per-Action Policy ──────────────────────────────────────────────
        ag = QGroupBox("Per-Action Policy"); al = QVBoxLayout(ag); al.setSpacing(8)
        hint = QLabel(
            "Configure what happens when each action type is triggered — "
            "both manually from alerts and automatically by the correlation engine.")
        hint.setFont(mf(9)); hint.setWordWrap(True); hint.setStyleSheet(f"color:{T3};")
        al.addWidget(hint)

        ACTION_CONFIGS = [
            ("blacklist",  "🚫  Block",
             ["Blacklist (router MAC filter)",
              "OS firewall rule only",
              "ARP isolation only",
              "All three tiers",
              "Log only (no enforcement)"],
             0,
             "Block the device at the router, OS firewall, and ARP level"),

            ("whitelist",  "✅  Trust",
             ["Whitelist (suppress all alerts)",
              "Exception (suppress anomaly alerts only)",
              "Log only"],
             0,
             "Mark device as trusted — suppress alerts"),

            ("isolated",   "🔒  Quarantine",
             ["VLAN 99 isolation (router)",
              "OS firewall — LAN block",
              "ARP isolation",
              "All tiers",
              "Log only"],
             0,
             "Isolate device to quarantine VLAN — internet blocked"),

            ("exception",  "⚡  Exception",
             ["Suppress all alerts for this device",
              "Suppress anomaly alerts only",
              "Whitelist + suppress"],
             0,
             "Create an exception rule — useful for known-safe devices"),

            ("guest",      "👤  Guest",
             ["Rate-limit bandwidth (if supported)",
              "Isolate to guest VLAN",
              "Log + allow — no restriction"],
             2,
             "Apply guest network policy — limited access, monitored"),

            ("auto_block", "🤖  Auto-block (correlation)",
             ["Block immediately when threshold met",
              "Block + notify",
              "Notify only — no block",
              "Log only"],
             2,
             "What to do when the correlation engine fires an auto-block"),
        ]

        self._action_combos = {}
        for key, label, options, default, tip in ACTION_CONFIGS:
            row = QHBoxLayout(); row.setSpacing(10)
            lbl = QLabel(label); lbl.setFont(sf(10, bold=True))
            lbl.setFixedWidth(150); lbl.setToolTip(tip)
            combo = QComboBox(); combo.addItems(options); combo.setCurrentIndex(default)
            combo.setFont(mf(9)); combo.setToolTip(tip)
            combo.currentTextChanged.connect(
                lambda txt, k=key: self.action_policy_changed.emit(k, txt))
            row.addWidget(lbl); row.addWidget(combo, 1); al.addLayout(row)
            self._action_combos[key] = combo

        lay.addWidget(ag)

        # ── 3. Safe Mode (legacy toggle, kept for backward compat) ────────────
        sg = QGroupBox("Safe Mode (legacy)"); sl = QVBoxLayout(sg); sl.setSpacing(8)
        sc_row = QHBoxLayout(); sc_row.setSpacing(10)
        self._sc = QCheckBox("Require confirmation for all enforcement actions")
        self._sc.setFont(sf(10))
        self._sc.setChecked(getattr(self._b,"safe_mode",True))
        self._sc.setToolTip(
            "When ON: every enforcement action shows a confirmation dialog.\n"
            "This is equivalent to 'Manual' mode above.\n"
            "Kept for backward compatibility — use Enforcement Mode section above.")
        self._sc.toggled.connect(self._on_safe_toggle)
        sc_row.addWidget(self._sc, 1)
        self._safe_badge = QLabel()
        self._safe_badge.setFont(mf(9)); self._safe_badge.setFixedHeight(24)
        sc_row.addWidget(self._safe_badge)
        dis_btn = QPushButton("Off"); dis_btn.setFixedHeight(26); dis_btn.setFont(mf(9))
        dis_btn.setProperty("cls","danger")
        dis_btn.clicked.connect(lambda: self._sc.setChecked(False))
        en_btn  = QPushButton("On");  en_btn.setFixedHeight(26);  en_btn.setFont(mf(9))
        en_btn.setProperty("cls","success")
        en_btn.clicked.connect(lambda: self._sc.setChecked(True))
        sc_row.addWidget(dis_btn); sc_row.addWidget(en_btn)
        sl.addLayout(sc_row)
        lay.addWidget(sg)
        self._refresh_safe_badge(getattr(self._b,"safe_mode",True))

        # ── 4. Detection Modules ──────────────────────────────────────────────
        dg = QGroupBox("Detection Modules"); dl = QVBoxLayout(dg); dl.setSpacing(4)
        MODULES = [
            ("ARP / MITM Monitor",       True,  "Gateway MAC watch + ARP flood detection (30 s)"),
            ("DNS Spoof Detection",       True,  "DoH comparison + TTL anomaly + NXDOMAIN spike (120 s)"),
            ("Evil Twin Detection",       True,  "SSID/BSSID history + duplicate AP detection"),
            ("Attack Correlation Engine", True,  "8 multi-signal rules, confidence-scored"),
            ("Frequency Spike Detector",  True,  "Sliding 60 s window for sudden activity surges"),
            ("Wi-Fi Password Audit",      True,  "Score saved passwords for discovered networks"),
            ("Deauth Detector",           False, "Requires monitor-mode adapter (Scapy)"),
            ("Beacon Anomaly Monitor",    False, "Requires monitor-mode adapter (Scapy)"),
            ("Rogue DHCP Detection",      True,  "Multiple DHCP server detection"),
            ("ICMP Redirect Detector",    True,  "Forged ICMP type-5 silent rerouting"),
            ("Captive Portal Inspector",  True,  "HTTPS redirect + JS injection check"),
            ("Session Hijack Monitor",    True,  "Cleartext credentials + unset cookie flags"),
            ("VPN Auto-launcher",         True,  "Trigger WireGuard/OpenVPN on critical alert"),
            ("DoH Resolver Enforcement",  True,  "Local DoH proxy + resolv.conf enforcement"),
        ]
        for name, chk, tip in MODULES:
            c = QCheckBox(name); c.setFont(sf(10))
            c.setChecked(chk); c.setToolTip(tip); dl.addWidget(c)
        lay.addWidget(dg)

        # ── 5. Credential Security ────────────────────────────────────────────
        cg = QGroupBox("Credential Security"); cf = QFormLayout(cg)
        info = self._b.creds_info() if hasattr(self._b,"creds_info") else {}
        if info.get("stored"):
            for k,v in [("Algorithm:", info.get("algo","")),
                        ("Hash:", info.get("prefix","…"))]:
                l = QLabel(v); l.setFont(mf(9)); cf.addRow(k, l)
        else:
            lbl = QLabel("No credentials stored")
            lbl.setFont(mf(9)); lbl.setStyleSheet(f"color:{T3};")
            lbl.setToolTip("PBKDF2-SHA256 · 100 000 iterations · 16-byte salt · never stored in plaintext")
            cf.addRow(lbl)
        lay.addWidget(cg)

        # ── 6. System Capabilities ────────────────────────────────────────────
        capg = QGroupBox("System"); capf = QFormLayout(capg)
        TIPS = {
            "scapy":     "Packet capture — ARP, deauth, session hijack",
            "pywifi":    "Wi-Fi scanning on Windows and Linux",
            "requests":  "HTTP for DoH, CVE lookups, router login",
            "root":      "Root/Admin — required for full ARP and packet capture",
        }
        caps = getattr(self._b,"caps",{})
        for k,v in caps.items():
            if k == "platform": continue
            icon = "✓" if v else "✗"
            lbl = QLabel(icon); lbl.setFont(mf(9))
            lbl.setStyleSheet(f"color:{GRN if v else RED};")
            lbl.setToolTip(TIPS.get(k,k)); capf.addRow(f"{k}:", lbl)
        if not caps.get("root"):
            root_hint = QLabel("⚠  Run as Administrator / sudo for full features")
            root_hint.setFont(mf(9)); root_hint.setStyleSheet(f"color:{YLW};")
            root_hint.setWordWrap(True)
            root_hint.setToolTip("ARP monitoring, Scapy capture, password reading from NetworkManager")
            capf.addRow(root_hint)
        lay.addWidget(capg)
        lay.addStretch()

        scroll.setWidget(w); outer.addWidget(scroll)

    # ── Internals ─────────────────────────────────────────────────────────────
    def _set_enforce_mode(self, mode: str):
        self._manual_btn.setChecked(mode == "manual")
        self._auto_btn.setChecked(mode   == "auto")
        self._thresh_frame.setVisible(mode == "auto")
        if mode == "manual":
            self._mode_badge.setText("🖐  MANUAL — confirmation required for all actions")
            self._mode_badge.setStyleSheet(
                f"color:{YLW}; background:{rgba(YLW,0.09)}; border:1px solid {rgba(YLW,0.22)};"
                f"border-radius:4px; padding:4px 10px;")
            # Keep safe_mode consistent
            self._b.safe_mode = True
            self._sc.blockSignals(True); self._sc.setChecked(True); self._sc.blockSignals(False)
            self._refresh_safe_badge(True)
        else:
            thresh = self._thresh_slider.value()
            self._mode_badge.setText(
                f"⚡  AUTOMATIC — apply when confidence ≥ {thresh}%")
            self._mode_badge.setStyleSheet(
                f"color:{RED}; background:{rgba(RED,0.09)}; border:1px solid {rgba(RED,0.22)};"
                f"border-radius:4px; padding:4px 10px;")
            self._b.safe_mode = False
            self._sc.blockSignals(True); self._sc.setChecked(False); self._sc.blockSignals(False)
            self._refresh_safe_badge(False)
        self.enforce_mode_changed.emit(mode)
        self.safe_mode_changed.emit(mode == "manual")

    def _on_safe_toggle(self, v: bool):
        # If user flips the legacy checkbox, sync enforcement mode
        self._set_enforce_mode("manual" if v else "auto")

    def _refresh_safe_badge(self, on: bool):
        if on:
            self._safe_badge.setText("● ON")
            self._safe_badge.setStyleSheet(
                f"color:{GRN}; background:{rgba(GRN,0.1)}; border:1px solid {rgba(GRN,0.25)};"
                f"border-radius:4px; padding:2px 8px;")
        else:
            self._safe_badge.setText("● OFF")
            self._safe_badge.setStyleSheet(
                f"color:{RED}; background:{rgba(RED,0.1)}; border:1px solid {rgba(RED,0.25)};"
                f"border-radius:4px; padding:2px 8px;")
