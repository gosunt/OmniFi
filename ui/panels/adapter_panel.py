"""
OmniFi — Adapter Panel
=======================
Wi-Fi adapter selector with full capability detection.

For each detected adapter shows:
  • Name / MAC / connected SSID
  • Monitor mode support (detected via iw or netsh)
  • Current mode (managed / monitor / AP)
  • One-click: Set as active · Enable monitor mode · Disable monitor mode

On selection the adapter is stored in backend.selected_iface and all
monitor-mode capable features are enabled automatically.
"""
import platform, subprocess, re
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QFrame, QGroupBox,
)
from PyQt6.QtCore  import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui   import QFont, QColor

from ui.theme import (
    BG1, BG2, BG3, BG4, B1, B2,
    T1, T2, T3, T4,
    ACC, GRN, YLW, RED, ORG,
    rgba, mf, sf,
)

WIN = platform.system() == "Windows"


# ── Capability probe (runs in background thread) ──────────────────────────────
class _ProbeThread(QThread):
    done = pyqtSignal(list)   # list of enriched iface dicts

    def run(self):
        from core.backend import list_wireless_interfaces
        try:
            ifaces = list_wireless_interfaces()
        except Exception:
            ifaces = []

        enriched = []
        for iface in ifaces:
            name = iface.get("name","")
            info = dict(iface)
            info["monitor_supported"] = False
            info["in_monitor_mode"]   = False
            info["current_mode"]      = "managed"
            info["chipset"]           = ""

            if WIN:
                # On Windows probe via Npcap availability
                info["monitor_supported"] = _win_monitor_capable(name)
                info["current_mode"] = "managed"
            else:
                try:
                    out = subprocess.check_output(
                        ["iw","dev",name,"info"],
                        text=True, stderr=subprocess.DEVNULL)
                    mode_m = re.search(r"type\s+(\w+)", out)
                    if mode_m:
                        info["current_mode"] = mode_m.group(1)
                        info["in_monitor_mode"] = (mode_m.group(1) == "monitor")
                    info["monitor_supported"] = True   # iw exists → likely supports it
                except Exception:
                    pass
                # Try to read chipset from /sys
                try:
                    drv = open(f"/sys/class/net/{name}/device/uevent").read()
                    dm  = re.search(r"DRIVER=(\S+)", drv)
                    if dm: info["chipset"] = dm.group(1)
                except Exception:
                    pass

            enriched.append(info)
        self.done.emit(enriched)


def _win_monitor_capable(name: str) -> bool:
    """Check if Npcap is installed (prerequisite for monitor mode on Windows)."""
    try:
        out = subprocess.check_output(
            ["sc","query","npcap"], text=True,
            encoding="utf-8", errors="ignore",
            stderr=subprocess.DEVNULL)
        return "RUNNING" in out
    except Exception:
        return False


# ── Mode-switch thread ────────────────────────────────────────────────────────
class _ModeThread(QThread):
    done = pyqtSignal(bool, str)   # success, message

    def __init__(self, iface: str, target_mode: str):
        super().__init__()
        self._iface = iface
        self._mode  = target_mode   # "monitor" | "managed"

    def run(self):
        from ui.dialogs_monitor import enable_monitor_mode, disable_monitor_mode
        if self._mode == "monitor":
            ok, msg = enable_monitor_mode(self._iface)
        else:
            ok, msg = disable_monitor_mode(self._iface)
        self.done.emit(ok, msg)


# ── Single adapter card ────────────────────────────────────────────────────────
class AdapterCard(QFrame):
    select_sig        = pyqtSignal(dict)   # iface dict
    enable_mon_sig    = pyqtSignal(str)    # iface name
    disable_mon_sig   = pyqtSignal(str)    # iface name

    def __init__(self, iface: dict, is_active: bool, parent=None):
        super().__init__(parent)
        self._iface     = iface
        self._is_active = is_active
        self._build()

    def _build(self):
        name    = self._iface.get("name","?")
        mac     = self._iface.get("mac","")
        ssid    = self._iface.get("connected_ssid","")
        active  = self._iface.get("is_active", False)
        mon_sup = self._iface.get("monitor_supported", False)
        in_mon  = self._iface.get("in_monitor_mode", False)
        mode    = self._iface.get("current_mode","managed")
        chipset = self._iface.get("chipset","")

        border  = ACC if self._is_active else B1
        self.setObjectName("AdapterCard")
        self.setStyleSheet(f"""
            #AdapterCard {{
                background:{BG2}; border:1px solid {border};
                border-left:4px solid {ACC if self._is_active else B2};
                border-radius:8px; margin-bottom:6px;
            }}
        """)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12); lay.setSpacing(8)

        # ── Header ────────────────────────────────────────────────────────────
        hdr = QHBoxLayout(); hdr.setSpacing(8)
        nm  = QLabel(name); nm.setFont(sf(12, bold=True))
        nm.setStyleSheet(f"color:{ACC if self._is_active else T1};")
        hdr.addWidget(nm)

        # Active badge
        if self._is_active:
            ab = self._chip("⬤ ACTIVE", ACC)
            hdr.addWidget(ab)

        # Connection badge
        if ssid:
            sb = self._chip(ssid, GRN)
            hdr.addWidget(sb)
        elif active:
            hdr.addWidget(self._chip("Connected", GRN))

        # Monitor mode badge
        if in_mon:
            hdr.addWidget(self._chip("MONITOR", RED))
        elif mon_sup:
            hdr.addWidget(self._chip("Mon. capable", YLW))
        else:
            hdr.addWidget(self._chip("Managed only", T3))

        hdr.addStretch()
        lay.addLayout(hdr)

        # ── Details row ───────────────────────────────────────────────────────
        dr = QHBoxLayout(); dr.setSpacing(16)
        for lbl, val in [
            ("MAC",     mac   or "—"),
            ("Mode",    mode.title()),
            ("Chipset", chipset or ("Npcap" if WIN else "—")),
        ]:
            col = QVBoxLayout(); col.setSpacing(1)
            kl = QLabel(lbl); kl.setFont(mf(8)); kl.setStyleSheet(f"color:{T4};")
            vl = QLabel(val); vl.setFont(mf(9)); vl.setStyleSheet(f"color:{T2};")
            col.addWidget(kl); col.addWidget(vl)
            dr.addLayout(col)
        dr.addStretch()
        lay.addLayout(dr)

        # ── Monitor mode capabilities info ────────────────────────────────────
        if mon_sup:
            cap_row = QHBoxLayout(); cap_row.setSpacing(4)
            enabled_feats = [
                "Deauth detection", "Beacon anomaly",
                "Passive capture", "DHCP sniff", "Session hijack",
            ]
            for feat in enabled_feats:
                fc = self._chip(f"✓ {feat}", GRN)
                cap_row.addWidget(fc)
            cap_row.addStretch()
            lay.addLayout(cap_row)
        elif WIN:
            nl = QLabel("Install Npcap for monitor mode features")
            nl.setFont(mf(8)); nl.setStyleSheet(f"color:{T3};")
            lay.addWidget(nl)

        # ── Action buttons ────────────────────────────────────────────────────
        ar = QHBoxLayout(); ar.setSpacing(6)

        if not self._is_active:
            sel = QPushButton("⬤  Use this adapter")
            sel.setProperty("cls","primary"); sel.setFixedHeight(30)
            sel.setFont(mf(9))
            sel.clicked.connect(lambda: self.select_sig.emit(self._iface))
            ar.addWidget(sel)

        if mon_sup and not in_mon:
            em = QPushButton("📡  Enable monitor mode")
            em.setFixedHeight(30); em.setFont(mf(9)); em.setProperty("cls","warn")
            em.setToolTip("Switch adapter to 802.11 monitor mode — enables deauth/beacon detection")
            em.clicked.connect(lambda: self.enable_mon_sig.emit(name))
            ar.addWidget(em)
        elif in_mon:
            dm = QPushButton("↩  Restore managed mode")
            dm.setFixedHeight(30); dm.setFont(mf(9))
            dm.setToolTip("Switch back to managed mode for normal Wi-Fi connectivity")
            dm.clicked.connect(lambda: self.disable_mon_sig.emit(name))
            ar.addWidget(dm)

        ar.addStretch()
        self._status_lbl = QLabel("")
        self._status_lbl.setFont(mf(8))
        ar.addWidget(self._status_lbl)
        lay.addLayout(ar)

    def set_status(self, msg: str, color: str):
        self._status_lbl.setText(msg)
        self._status_lbl.setStyleSheet(f"color:{color};")

    @staticmethod
    def _chip(text: str, color: str) -> QLabel:
        rc, gc, bc = QColor(color).red(), QColor(color).green(), QColor(color).blue()
        l = QLabel(text); l.setFont(mf(8))
        l.setStyleSheet(
            f"color:{color}; background:rgba({rc},{gc},{bc},0.12);"
            f"border:1px solid rgba({rc},{gc},{bc},0.3);"
            f"border-radius:3px; padding:1px 6px;")
        return l


# ── Panel ─────────────────────────────────────────────────────────────────────
class AdapterPanel(QWidget):
    """
    Wi-Fi Adapter panel.
    Signals:
      adapter_selected(iface_dict)  — user chose a different adapter
      monitor_enabled(iface_name)   — monitor mode was successfully enabled
      monitor_disabled(iface_name)  — restored to managed mode
    """
    adapter_selected  = pyqtSignal(dict)
    monitor_enabled   = pyqtSignal(str)
    monitor_disabled  = pyqtSignal(str)

    def __init__(self, backend, parent=None):
        super().__init__(parent)
        self._b       = backend
        self._ifaces  = []
        self._cards   = {}
        self._threads = {}
        self._build()

    def _build(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0); outer.setSpacing(0)

        # Toolbar
        tb = QFrame(); tb.setFixedHeight(44)
        tb.setStyleSheet(f"background:{BG1}; border-bottom:1px solid {B1};")
        tbl = QHBoxLayout(tb)
        tbl.setContentsMargins(16, 0, 16, 0); tbl.setSpacing(10)
        tit = QLabel("Adapters"); tit.setFont(sf(12, bold=True))
        tbl.addWidget(tit)
        self._active_lbl = QLabel("")
        self._active_lbl.setFont(mf(9))
        self._active_lbl.setStyleSheet(
            f"color:{ACC}; background:{rgba(ACC,0.08)};"
            f"border:1px solid {rgba(ACC,0.2)}; border-radius:3px; padding:1px 8px;")
        tbl.addWidget(self._active_lbl)
        tbl.addStretch()
        ref = QPushButton("↻  Scan")
        ref.setProperty("cls","primary"); ref.setFixedHeight(30); ref.setFont(mf(9))
        ref.clicked.connect(self.refresh)
        tbl.addWidget(ref)
        outer.addWidget(tb)

        # Summary: auto-enabled features
        self._feat_bar = QFrame()
        self._feat_bar.setStyleSheet(
            f"background:{rgba(GRN,0.04)}; border-bottom:1px solid {B1};")
        self._feat_bar.setFixedHeight(32)
        fbl = QHBoxLayout(self._feat_bar)
        fbl.setContentsMargins(16, 0, 16, 0); fbl.setSpacing(8)
        self._feat_lbl = QLabel("No adapter selected")
        self._feat_lbl.setFont(mf(8)); self._feat_lbl.setStyleSheet(f"color:{T4};")
        fbl.addWidget(self._feat_lbl); fbl.addStretch()
        outer.addWidget(self._feat_bar)

        # Adapter cards
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._cards_w = QWidget()
        self._cards_l = QVBoxLayout(self._cards_w)
        self._cards_l.setContentsMargins(16, 12, 16, 12); self._cards_l.setSpacing(0)
        self._loading = QLabel("Scanning for Wi-Fi adapters…")
        self._loading.setFont(mf(10))
        self._loading.setStyleSheet(f"color:{T3};")
        self._loading.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._cards_l.addWidget(self._loading)
        self._cards_l.addStretch()
        scroll.setWidget(self._cards_w)
        outer.addWidget(scroll, 1)

        # Npcap/iw note for Windows
        if WIN:
            note = QFrame()
            note.setStyleSheet(
                f"background:{rgba(YLW,0.05)}; border-top:1px solid {B1};")
            nl = QHBoxLayout(note); nl.setContentsMargins(16, 6, 16, 6)
            lbl = QLabel(
                "Windows: monitor mode requires Npcap  ·  "
                "Install from npcap.com with 'WinPcap-compatible mode' enabled")
            lbl.setFont(mf(8)); lbl.setStyleSheet(f"color:{T3};")
            nl.addWidget(lbl)
            act = QPushButton("Open npcap.com")
            act.setFont(mf(8)); act.setFixedHeight(24)
            act.clicked.connect(lambda: __import__("webbrowser").open("https://npcap.com"))
            nl.addWidget(act)
            outer.addWidget(note)

    # ── Public ────────────────────────────────────────────────────────────────
    def refresh(self):
        self._loading.setText("Scanning adapters…"); self._loading.setVisible(True)
        t = _ProbeThread(); t.done.connect(self._on_probed); t.start()
        self._threads["probe"] = t

    def _on_probed(self, ifaces: list):
        self._ifaces = ifaces
        self._loading.setVisible(False)
        # Clear old cards
        while self._cards_l.count() > 2:
            item = self._cards_l.takeAt(0)
            if item.widget(): item.widget().deleteLater()
        self._cards.clear()

        active_name = getattr(self._b, "selected_iface", "auto")

        for iface in ifaces:
            name = iface.get("name","")
            is_active = (name == active_name)
            card = AdapterCard(iface, is_active)
            card.select_sig.connect(self._on_select)
            card.enable_mon_sig.connect(self._on_enable_mon)
            card.disable_mon_sig.connect(self._on_disable_mon)
            self._cards_l.insertWidget(0, card)
            self._cards[name] = card

        self._update_feat_bar(active_name)
        if active_name and active_name != "auto":
            self._active_lbl.setText(f"Active: {active_name}")

    def _on_select(self, iface: dict):
        name = iface.get("name","")
        self._b.selected_iface = name
        self.adapter_selected.emit(iface)
        self._on_probed(self._ifaces)   # re-render with new active

    def _on_enable_mon(self, name: str):
        card = self._cards.get(name)
        if card: card.set_status("Enabling monitor mode…", ACC)
        t = _ModeThread(name, "monitor")
        t.done.connect(lambda ok, msg, n=name: self._on_mon_done(n, ok, msg, True))
        t.start(); self._threads[f"mon_{name}"] = t

    def _on_disable_mon(self, name: str):
        card = self._cards.get(name)
        if card: card.set_status("Restoring managed mode…", YLW)
        t = _ModeThread(name, "managed")
        t.done.connect(lambda ok, msg, n=name: self._on_mon_done(n, ok, msg, False))
        t.start(); self._threads[f"dis_{name}"] = t

    def _on_mon_done(self, name: str, ok: bool, msg: str, enabled: bool):
        card = self._cards.get(name)
        if card:
            card.set_status(msg[:60], GRN if ok else RED)
        if ok:
            # Re-probe to update badge
            QTimer.singleShot(800, self.refresh)
            if enabled:
                self.monitor_enabled.emit(name)
            else:
                self.monitor_disabled.emit(name)

    def _update_feat_bar(self, active_name: str):
        if not active_name or active_name == "auto":
            self._feat_lbl.setText("No adapter selected")
            return
        iface = next((i for i in self._ifaces if i.get("name") == active_name), None)
        if not iface:
            return
        mon_sup = iface.get("monitor_supported", False)
        in_mon  = iface.get("in_monitor_mode", False)

        always = ["ARP/MITM", "DNS Spoof", "Evil Twin", "ICMP Redirect", "Captive Portal"]
        mon_feats = ["Deauth", "Beacon Anomaly", "DHCP Sniff", "Session Hijack"] if in_mon else []

        parts = [f"✓ {f}" for f in always] + [f"✓ {f}" for f in mon_feats]
        if mon_sup and not in_mon:
            parts.append("⚡ Enable monitor mode for more")
        self._feat_lbl.setText("  ·  ".join(parts))
        self._feat_lbl.setStyleSheet(f"color:{GRN if in_mon else T3};")
