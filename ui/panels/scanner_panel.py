"""
OmniFi — Wi-Fi Scanner Panel  (v9)

Two-tab layout:
  Tab 0 "Scan Networks"  — the existing scored AP card list
  Tab 1 "Connected"      — posture of the currently connected network

After selecting a network → connect flow:
  1. "Connect" button shows ConnectModeDialog (client vs admin choice + router creds)
  2. On confirm → emit proceed_sig(net, mode, url, user, pass)
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QFrame, QProgressBar, QTabWidget, QLineEdit,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui  import QFont, QColor

from ui.theme import (
    BG1, BG2, BG3, BG4, B1, B2, T1, T2, T3, T4,
    ACC, GRN, YLW, RED, ORG, VDT_C, rgba, mf, sf,
)
from ui.widgets.network_card import NetworkCard
from ui.widgets.score_ring   import ScoreRing


class _ScanThread(QThread):
    done = pyqtSignal(list)
    def __init__(self, fn): super().__init__(); self._fn = fn
    def run(self):
        try:    self.done.emit(self._fn())
        except: self.done.emit([])


class _PwdThread(QThread):
    done = pyqtSignal(list)
    def __init__(self, fn, ssids):
        super().__init__(); self._fn = fn; self._wanted = ssids
    def run(self):
        try:
            self.done.emit([p for p in self._fn()
                            if p.get("ssid","") in self._wanted])
        except: self.done.emit([])


# ── Inline connect-mode chooser (shown in the bottom bar after selection) ────
class _ConnectBar(QFrame):
    """
    Bottom action bar in the scanner.
    Client mode: one-click connect.
    Admin mode:  opens RouterLoginDialog (auto-detects gateway + ISP defaults,
                 tests credentials, enables admin on success).
    """
    connect_sig = pyqtSignal(str, str, str, str)  # mode, url, user, pass

    def __init__(self, auto_detect_fn=None, login_fn=None, parent=None):
        super().__init__(parent)
        self._auto_fn  = auto_detect_fn
        self._login_fn = login_fn
        self._build()

    def _build(self):
        self.setStyleSheet(f"background:{BG1}; border-top:1px solid {B1};")
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 8, 14, 8); root.setSpacing(6)

        r1 = QHBoxLayout(); r1.setSpacing(8)
        self._net_lbl = QLabel("Select a network above")
        self._net_lbl.setFont(mf(10)); self._net_lbl.setStyleSheet(f"color:{T3};")
        r1.addWidget(self._net_lbl, 1)

        self._client_btn = QPushButton("\U0001f4e1  Client")
        self._admin_btn  = QPushButton("\U0001f6e1  Admin")
        _st = (f"QPushButton{{background:{BG3};border:1px solid {B2};"
               f"border-radius:5px;padding:4px 12px;}}"
               f"QPushButton:checked{{background:{rgba(ACC,0.12)};"
               f"border-color:{ACC};color:{ACC};}}"
               f"QPushButton:hover:!checked{{background:{BG4};}}")
        for b in (self._client_btn, self._admin_btn):
            b.setFixedHeight(28); b.setFont(mf(9))
            b.setCheckable(True); b.setStyleSheet(_st)
        self._client_btn.setChecked(True)
        self._client_btn.setToolTip("Monitor any Wi-Fi — detection and alerts only")
        self._admin_btn.setToolTip(
            "Own this router — opens router login dialog\n"
            "Gateway IP is auto-detected as the router URL")
        self._client_btn.clicked.connect(lambda: self._set_mode("client"))
        self._admin_btn.clicked.connect(lambda:  self._set_mode("admin"))
        r1.addWidget(self._client_btn); r1.addWidget(self._admin_btn)

        skip = QPushButton("Skip")
        skip.setFixedHeight(28); skip.setFont(mf(9))
        skip.setToolTip("Skip — use current connection in client mode")
        skip.clicked.connect(lambda: self.connect_sig.emit("client","","",""))
        r1.addWidget(skip)
        root.addLayout(r1)

        self._admin_hint = QFrame(); self._admin_hint.setVisible(False)
        ah = QHBoxLayout(self._admin_hint)
        ah.setContentsMargins(0,0,0,0); ah.setSpacing(6)
        hint_lbl = QLabel(
            "Gateway IP will be auto-detected as router URL  \u00b7  "
            "ISP default credentials pre-filled  \u00b7  credentials tested before connecting")
        hint_lbl.setFont(mf(8)); hint_lbl.setStyleSheet(f"color:{T3};")
        ah.addWidget(hint_lbl, 1)
        root.addWidget(self._admin_hint)

        r2 = QHBoxLayout(); r2.setSpacing(8); r2.addStretch()
        self._connect_btn = QPushButton("Connect  \u2192")
        self._connect_btn.setProperty("cls","primary")
        self._connect_btn.setFixedHeight(32)
        self._connect_btn.setEnabled(False)
        self._connect_btn.clicked.connect(self._on_connect)
        r2.addWidget(self._connect_btn)
        root.addLayout(r2)

    def _set_mode(self, mode: str):
        self._client_btn.setChecked(mode == "client")
        self._admin_btn.setChecked(mode  == "admin")
        self._admin_hint.setVisible(mode == "admin")

    def set_network(self, net: dict):
        evil      = net.get("evil", False)
        color     = net.get("color", T2)
        ssid      = net.get("ssid", "?")
        score     = net.get("score", 0)
        ps        = net.get("pwd_score")
        has_saved = net.get("pwd_found", False)
        txt       = f"{ssid}  \u00b7  {score}/100"
        if has_saved and ps is not None:
            txt += f"  \u00b7  \U0001f511 Saved ({ps}/100)"
        elif has_saved:
            txt += "  \u00b7  \U0001f511 Saved"
        self._net_lbl.setText(txt)
        self._net_lbl.setStyleSheet(f"color:{color}; font-family:Consolas; font-size:10px;")
        self._connect_btn.setEnabled(not evil)
        if evil:
            self._connect_btn.setText("Evil twin \u2014 blocked")
        elif has_saved:
            self._connect_btn.setText("Connect (saved)  \u2192")
            self._connect_btn.setToolTip("Saved password found — connects without asking credentials")
        else:
            self._connect_btn.setText("Connect  \u2192")
            self._connect_btn.setToolTip("")

    def clear_selection(self):
        self._net_lbl.setText("Select a network above")
        self._net_lbl.setStyleSheet(f"color:{T3};")
        self._connect_btn.setEnabled(False)

    def _on_connect(self):
        mode = "admin" if self._admin_btn.isChecked() else "client"
        if mode == "admin":
            from ui.dialogs import RouterLoginDialog
            from PyQt6.QtWidgets import QDialog
            dlg = RouterLoginDialog(
                auto_detect_fn=self._auto_fn,
                login_fn=self._login_fn,
                parent=self.window(),
            )
            if dlg.exec() == QDialog.DialogCode.Accepted:
                self.connect_sig.emit(
                    "admin", dlg.result_url, dlg.result_user, dlg.result_pass)
            else:
                # User chose "Continue as Client"
                self.connect_sig.emit("client", "", "", "")
        else:
            self.connect_sig.emit("client", "", "", "")


# ── Connected network posture tab ─────────────────────────────────────────────
class _ConnectedTab(QWidget):
    """Shows posture of the currently connected network (post-join scores)."""

    def __init__(self, parent=None):
        super().__init__(parent); self._build()

    def _build(self):
        lay = QVBoxLayout(self); lay.setContentsMargins(20,16,20,16); lay.setSpacing(12)

        hdr = QHBoxLayout()
        self._ssid_lbl = QLabel("Not connected")
        self._ssid_lbl.setFont(sf(13, bold=True)); self._ssid_lbl.setStyleSheet(f"color:{T1};")
        hdr.addWidget(self._ssid_lbl, 1)
        ref = QPushButton("↻  Refresh"); ref.setProperty("cls","primary")
        ref.setFixedHeight(28); ref.clicked.connect(self._refresh)
        hdr.addWidget(ref); lay.addLayout(hdr)

        # Score ring + summary
        mid = QHBoxLayout(); mid.setSpacing(20)
        self._ring = ScoreRing(80); self._ring.set_score_instant(0,"avoid")
        mid.addWidget(self._ring)
        self._summary = QLabel("Run a scan to see your connected network's security posture.")
        self._summary.setFont(mf(9)); self._summary.setWordWrap(True)
        self._summary.setStyleSheet(f"color:{T2};"); mid.addWidget(self._summary,1)
        lay.addLayout(mid)

        # Vector chips row
        self._chips_row = QHBoxLayout(); self._chips_row.setSpacing(4)
        self._chips_row.addStretch(); lay.addLayout(self._chips_row)

        # Post-join checks
        checks_frame = QFrame()
        checks_frame.setStyleSheet(f"background:{BG2}; border:1px solid {B1}; border-radius:7px;")
        cf = QVBoxLayout(checks_frame); cf.setContentsMargins(14,10,14,10); cf.setSpacing(6)
        self._check_rows = {}
        for name, tip in [
            ("ARP gateway", "Gateway MAC matches recorded baseline"),
            ("DNS clean",   "Local DNS matches Cloudflare DoH"),
            ("Captive portal","No captive portal injection detected"),
            ("DHCP server", "Single DHCP server on subnet"),
        ]:
            rr = QHBoxLayout(); rr.setSpacing(8)
            dot = QLabel("○"); dot.setFont(mf(9)); dot.setFixedWidth(14)
            dot.setStyleSheet(f"color:{T4};"); dot.setToolTip(tip)
            lbl = QLabel(name); lbl.setFont(mf(9)); lbl.setStyleSheet(f"color:{T3};")
            lbl.setToolTip(tip)
            st  = QLabel("—"); st.setFont(mf(9)); st.setStyleSheet(f"color:{T4};")
            rr.addWidget(dot); rr.addWidget(lbl,1); rr.addWidget(st)
            cf.addLayout(rr); self._check_rows[name] = (dot, st)
        lay.addWidget(checks_frame); lay.addStretch()

    def _refresh(self):
        """Placeholder — wired by MainWindow to run post-join checks."""
        pass

    def update(self, net: dict):
        """Called when a network is selected or monitoring starts."""
        if not net:
            self._ssid_lbl.setText("Not connected"); return
        ssid    = net.get("ssid","?")
        score   = net.get("score",0)
        verdict = net.get("verdict","avoid")
        color   = net.get("color",T2)
        self._ssid_lbl.setText(ssid)
        self._ssid_lbl.setStyleSheet(f"color:{color};")
        self._ring.set_score(score, verdict)
        self._summary.setText(net.get("rec",""))

        # Rebuild chips
        while self._chips_row.count(): self._chips_row.takeAt(0)
        for key, v in net.get("vectors",{}).items():
            st = v.get("status","na")
            vc = GRN if st=="pass" else RED if st=="fail" else YLW
            vr,vg,vb = QColor(vc).red(), QColor(vc).green(), QColor(vc).blue()
            c2 = QLabel(f"{v.get('label','?')}")
            c2.setFont(mf(8))
            c2.setToolTip(f"{v.get('label')}: {v.get('detail')} ({v.get('pts')}/{v.get('max')} pts)")
            c2.setStyleSheet(
                f"color:{vc}; background:rgba({vr},{vg},{vb},0.08);"
                f"border:1px solid rgba({vr},{vg},{vb},0.25); border-radius:3px; padding:1px 5px;")
            self._chips_row.addWidget(c2)
        self._chips_row.addStretch()


# ── Main Panel ────────────────────────────────────────────────────────────────
class ScannerPanel(QWidget):
    """
    Tab 0: Scan Networks  — scored AP card list
    Tab 1: Connected      — posture of current connection

    proceed_sig(net_dict, mode, url, user, password) emitted on Connect.
    """
    proceed_sig  = pyqtSignal(dict, str, str, str, str)
    nets_ready   = pyqtSignal(list)   # emitted after every scan+password read
    connect_done = pyqtSignal(bool, str)   # ok, message
    disconnect_done = pyqtSignal(bool, str)

    def __init__(self, scan_fn, pwd_fn, on_weak_pwd=None,
                 auto_detect_fn=None, login_fn=None,
                 connect_fn=None, disconnect_fn=None,
                 saved_pw_fn=None, parent=None):
        super().__init__(parent)
        self._scan_fn     = scan_fn
        self._pwd_fn      = pwd_fn
        self._on_weak     = on_weak_pwd
        self._auto_fn     = auto_detect_fn
        self._login_fn    = login_fn
        self._connect_fn  = connect_fn
        self._disconnect_fn = disconnect_fn
        self._saved_pw_fn = saved_pw_fn
        self._nets        = []
        self._sel         = None
        self._sort        = "score"
        self._filt        = "all"
        self._pv          = 0
        self._iface       = "auto"
        self._wifi_thread = None
        self._build()

    def _build(self):
        root = QVBoxLayout(self); root.setContentsMargins(0,0,0,0); root.setSpacing(0)

        # ── Tab widget ────────────────────────────────────────────────────────
        self._tabs = QTabWidget()
        self._tabs.setDocumentMode(True)
        self._tabs.setStyleSheet(f"""
            QTabBar::tab {{
                background:{BG2}; color:{T3}; border:none;
                padding:8px 20px; font-family:Consolas; font-size:10px;
            }}
            QTabBar::tab:selected {{ color:{ACC}; border-bottom:2px solid {ACC}; background:{BG1}; }}
            QTabBar::tab:hover:!selected {{ color:{T2}; background:{BG3}; }}
            QTabWidget::pane {{ border:none; background:{BG1}; }}
        """)

        # ── Tab 0: Scan Networks ──────────────────────────────────────────────
        scan_tab = QWidget()
        stl = QVBoxLayout(scan_tab)
        stl.setContentsMargins(20,14,20,0); stl.setSpacing(8)

        # Header
        hdr = QHBoxLayout(); hdr.setSpacing(10)
        logo = QLabel("OMNIFI"); logo.setFont(mf(16,bold=True))
        logo.setStyleSheet(f"color:{ACC}; letter-spacing:5px;"); hdr.addWidget(logo)
        self._iface_lbl = QLabel("")
        self._iface_lbl.setFont(mf(8))
        self._iface_lbl.setStyleSheet(
            f"color:{T3}; background:{BG3}; border:1px solid {B1};"
            f"border-radius:3px; padding:1px 8px;")
        self._iface_lbl.setVisible(False); hdr.addWidget(self._iface_lbl)
        hdr.addStretch()
        self._status_lbl = QLabel("Ready")
        self._status_lbl.setFont(mf(9)); self._status_lbl.setStyleSheet(f"color:{ACC};")
        hdr.addWidget(self._status_lbl)
        self._scan_btn = QPushButton("↻  Scan")
        self._scan_btn.setProperty("cls","primary"); self._scan_btn.setFixedHeight(30)
        self._scan_btn.clicked.connect(self.start_scan); hdr.addWidget(self._scan_btn)

        self._disc_btn = QPushButton("✕  Disconnect")
        self._disc_btn.setFixedHeight(30); self._disc_btn.setFont(mf(9))
        self._disc_btn.setToolTip("Disconnect from current Wi-Fi network")
        self._disc_btn.setVisible(False)
        self._disc_btn.clicked.connect(self.disconnect_current)
        hdr.addWidget(self._disc_btn)
        stl.addLayout(hdr)

        # Progress
        self._prog = QProgressBar(); self._prog.setRange(0,100); self._prog.setValue(0)
        self._prog.setFixedHeight(3); self._prog.setTextVisible(False)
        self._prog.setStyleSheet(
            f"QProgressBar{{background:{BG3};border:none;border-radius:2px;}}"
            f"QProgressBar::chunk{{background:{ACC};border-radius:2px;}}")
        stl.addWidget(self._prog)
        self._phase_lbl = QLabel("Click Scan to discover nearby Wi-Fi networks")
        self._phase_lbl.setFont(mf(9)); self._phase_lbl.setStyleSheet(f"color:{T2};")
        stl.addWidget(self._phase_lbl)

        # Sort / filter
        sf_row = QHBoxLayout(); sf_row.setSpacing(6)
        self._sort_btns = {}
        for mode, lbl, tip in [
            ("score",  "Score ↓", "Sort by security score"),
            ("signal", "Signal",  "Sort by signal strength"),
            ("ssid",   "Name",    "Sort alphabetically by SSID"),
        ]:
            b = QPushButton(lbl); b.setFont(mf(9)); b.setFixedHeight(26)
            b.setCheckable(True); b.setChecked(mode=="score"); b.setToolTip(tip)
            b.clicked.connect(lambda _, m=mode: self._do_sort(m))
            sf_row.addWidget(b); self._sort_btns[mode] = b
        sf_row.addSpacing(8)
        self._flt_btns = {}
        for mode, lbl, tip in [
            ("all",   "All",      "Show all networks"),
            ("safe",  "Safe",     "Show only safe / acceptable networks"),
            ("saved", "Known",    "Show only networks with a saved password"),
            ("hide",  "No evil",  "Hide detected evil twin access points"),
        ]:
            b = QPushButton(lbl); b.setFont(mf(9)); b.setFixedHeight(26)
            b.setCheckable(True); b.setChecked(mode=="all"); b.setToolTip(tip)
            b.clicked.connect(lambda _, m=mode: self._do_filter(m))
            sf_row.addWidget(b); self._flt_btns[mode] = b
        sf_row.addStretch()
        self._cnt_lbl = QLabel(""); self._cnt_lbl.setFont(mf(9))
        self._cnt_lbl.setStyleSheet(f"color:{T4};"); sf_row.addWidget(self._cnt_lbl)
        stl.addLayout(sf_row)

        # Card scroll area
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._cards_w = QWidget(); self._cards_l = QVBoxLayout(self._cards_w)
        self._cards_l.setContentsMargins(0,0,0,0); self._cards_l.setSpacing(0)
        self._cards_l.addStretch()
        scroll.setWidget(self._cards_w); stl.addWidget(scroll,1)

        # ── Connect bar (bottom, inside scan tab) ─────────────────────────────
        self._connect_bar = _ConnectBar(auto_detect_fn=self._auto_fn, login_fn=self._login_fn)
        self._connect_bar.connect_sig.connect(self._on_connect)
        stl.addWidget(self._connect_bar)

        self._tabs.addTab(scan_tab, "  Scan Networks  ")

        # ── Tab 1: Connected ──────────────────────────────────────────────────
        self._connected_tab = _ConnectedTab()
        self._tabs.addTab(self._connected_tab, "  Connected  ")

        root.addWidget(self._tabs, 1)

    # ── Public API ────────────────────────────────────────────────────────────
    def set_interface(self, iface_name: str):
        self._iface = iface_name
        if iface_name and iface_name != "auto":
            self._iface_lbl.setText(f"📡  {iface_name}")
            self._iface_lbl.setVisible(True)

    def show_connected_tab(self, net: dict):
        """Switch to Connected tab with the given network's posture."""
        self._connected_tab.update(net)
        self._tabs.setCurrentIndex(1)

    # ── Wi-Fi Connect / Disconnect ─────────────────────────────────────────────
    def connect_to_network(self, net: dict, password: str = ""):
        """
        Connect to a scanned network using OS Wi-Fi commands.
        Uses saved password automatically if available and none provided.
        Emits connect_done(ok, message) when finished.
        """
        if not self._connect_fn:
            self.connect_done.emit(False, "No connect function registered")
            return
        ssid = net.get("ssid", "")
        pw   = password
        if not pw and self._saved_pw_fn:
            pw = self._saved_pw_fn(ssid) or ""

        class _ConnThread(QThread):
            done = pyqtSignal(bool, str)
            def __init__(self_, fn, ssid, pw, iface):
                super().__init__(); self_._fn=fn; self_._s=ssid
                self_._p=pw; self_._i=iface
            def run(self_):
                r = self_._fn(self_._s, self_._p, self_._i)
                self_.done.emit(r.get("ok", False), r.get("message", ""))

        t = _ConnThread(self._connect_fn, ssid, pw, self._iface)
        t.done.connect(self.connect_done)
        t.done.connect(lambda ok, msg, n=net: self._on_connect_result(ok, msg, n))
        t.start()
        self._wifi_thread = t
        self._status_lbl.setText(f"Connecting to {ssid}…")
        self._status_lbl.setStyleSheet(f"color:{ACC};")

    def disconnect_current(self):
        """Disconnect the current Wi-Fi interface. Emits disconnect_done(ok, message)."""
        if not self._disconnect_fn:
            self.disconnect_done.emit(False, "No disconnect function registered")
            return

        class _DisThread(QThread):
            done = pyqtSignal(bool, str)
            def __init__(self_, fn): super().__init__(); self_._fn = fn
            def run(self_):
                r = self_._fn()
                self_.done.emit(r.get("ok", False), r.get("message", ""))

        def _hide_disc(ok, msg):
            if hasattr(self, "_disc_btn"):
                self._disc_btn.setVisible(not ok)
            self._status_lbl.setText("Disconnected" if ok else f"Disconnect failed: {msg[:40]}")
            self._status_lbl.setStyleSheet(f"color:{GRN if ok else RED};")

        t = _DisThread(self._disconnect_fn)
        t.done.connect(self.disconnect_done)
        t.done.connect(_hide_disc)
        t.start()
        self._wifi_thread = t
        self._status_lbl.setText("Disconnecting…")
        self._status_lbl.setStyleSheet(f"color:{YLW};")

    def _on_connect_result(self, ok: bool, msg: str, net: dict):
        ssid = net.get("ssid", "")
        if ok:
            self._status_lbl.setText(f"Connected to {ssid}")
            self._status_lbl.setStyleSheet(f"color:{GRN};")
            if hasattr(self, "_disc_btn"):
                self._disc_btn.setVisible(True)
        else:
            self._status_lbl.setText(f"Failed: {msg[:55]}")
            self._status_lbl.setStyleSheet(f"color:{RED};")

    # ── Scan flow ─────────────────────────────────────────────────────────────
    def start_scan(self):
        self._scan_btn.setEnabled(False)
        self._status_lbl.setText("Scanning…")
        self._phase_lbl.setText("Probing Wi-Fi bands…")
        self._prog.setValue(5); self._pv = 5
        self._ptimer = QTimer(self); self._ptimer.timeout.connect(self._tick)
        self._ptimer.start(200)
        self._scan_thr = _ScanThread(self._scan_fn)
        self._scan_thr.done.connect(self._on_scan_done)
        self._scan_thr.start()

    def _tick(self):
        self._pv = min(90, self._pv + 8); self._prog.setValue(self._pv)
        phases = ["Probing 2.4 GHz…","Probing 5 GHz…","Fingerprinting APs…",
                  "Evil twin check…","BSSID history check…",
                  "Scoring 8 vectors…","Reading saved passwords…"]
        self._phase_lbl.setText(phases[min(len(phases)-1, (self._pv-5)//14)])

    def _on_scan_done(self, nets):
        self._ptimer.stop(); self._prog.setValue(92)
        self._phase_lbl.setText("Reading saved passwords for discovered networks…")
        self._nets = nets
        ssids = {n.get("ssid","") for n in nets if n.get("ssid")}
        self._pwd_thr = _PwdThread(self._pwd_fn, ssids)
        self._pwd_thr.done.connect(self._on_pwds_done)
        self._pwd_thr.start()

    def _on_pwds_done(self, pwds):
        pwd_map = {p["ssid"]: p for p in pwds if p.get("ssid")}
        for net in self._nets:
            ssid = net.get("ssid","")
            if ssid in pwd_map:
                p = pwd_map[ssid]
                net.update({"pwd_found":True, "pwd_score":p.get("score",0),
                            "pwd_issues":p.get("issues",[]),
                            "pwd_entropy":p.get("entropy",0.0),
                            "pwd_masked":p.get("password_masked","****")})
                if p.get("score",100) < 50 and self._on_weak:
                    self._on_weak(ssid, p["score"], p.get("issues",[]))
            else:
                net["pwd_found"] = False
        self._scan_btn.setEnabled(True); self._prog.setValue(100)
        n_pwd = sum(1 for n in self._nets if n.get("pwd_found"))
        self._status_lbl.setText(
            f"{len(self._nets)} networks"
            + (f"  ·  {n_pwd} with saved password" if n_pwd else ""))
        self._phase_lbl.setText("Click a card to select. Expand for vector breakdown.")
        self._render()
        self.nets_ready.emit(self._nets)

    def _render(self):
        while self._cards_l.count() > 1:
            item = self._cards_l.takeAt(0)
            if item.widget(): item.widget().deleteLater()
        nets = self._sf()
        self._cnt_lbl.setText(f"{len(nets)}")
        for i, net in enumerate(nets):
            card = NetworkCard(net, i)
            card.selected.connect(self._on_net_selected)
            self._cards_l.insertWidget(i, card)

    def _sf(self):
        n = list(self._nets)
        if   self._filt == "safe":  n = [x for x in n if x.get("verdict") in ("safe","acceptable")]
        elif self._filt == "saved": n = [x for x in n if x.get("pwd_found")]
        elif self._filt == "hide":  n = [x for x in n if not x.get("evil")]
        if   self._sort == "score":  n.sort(key=lambda x: x.get("score",0), reverse=True)
        elif self._sort == "signal": n.sort(key=lambda x: x.get("sig",0),   reverse=True)
        elif self._sort == "ssid":   n.sort(key=lambda x: x.get("ssid",""))
        return n

    def _do_sort(self, m):
        self._sort = m
        for k,b in self._sort_btns.items(): b.setChecked(k==m)
        if self._nets: self._render()

    def _do_filter(self, m):
        self._filt = m
        for k,b in self._flt_btns.items(): b.setChecked(k==m)
        if self._nets: self._render()

    def _on_net_selected(self, net):
        self._sel = net
        self._connect_bar.set_network(net)

    def _on_connect(self, mode, url, user, pwd):
        net = self._sel or {}
        if net.get("evil"): return
        # In client mode: also initiate OS-level Wi-Fi connection
        if mode == "client" and net.get("ssid") and self._connect_fn:
            self.connect_to_network(net)
        self.proceed_sig.emit(net, mode, url, user, pwd)
