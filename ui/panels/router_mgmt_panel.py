"""
OmniFi — Router Management Panel
==================================
Full router configuration GUI for admin mode.
All actions go through RouterConfigManager which handles vendor differences.

Sections:
  Security     — WPS · PMF · Remote management · Password policy
  Access       — MAC blacklist · Whitelist · Quarantine · Max clients · Bandwidth
  Network      — SSID · Password · Band · Channel · DNS
  Monitoring   — Device list · Parental controls · Firewall rules
  Advanced     — Reboot · Router capabilities
"""
import datetime
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QGroupBox, QLineEdit, QSpinBox,
    QComboBox, QTabWidget, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QMessageBox, QCheckBox,
    QProgressBar, QSplitter, QTextEdit,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui  import QFont, QColor

from ui.theme import (
    BG0, BG1, BG2, BG3, BG4, B1, B2, T1, T2, T3, T4,
    ACC, GRN, YLW, RED, ORG, PUR,
    LVL_C, rgba, mf, sf,
)

import platform
WIN = platform.system() == "Windows"


class _ActionThread(QThread):
    done = pyqtSignal(dict)
    def __init__(self, fn): super().__init__(); self._fn = fn
    def run(self):
        try:    self.done.emit(self._fn())
        except Exception as e: self.done.emit({"ok":False,"detail":str(e)})


class RouterMgmtPanel(QWidget):
    """
    Router configuration panel. Only fully functional in admin mode.
    """
    action_sig = pyqtSignal(str, dict)  # capability_id, kwargs

    def __init__(self, backend, parent=None):
        super().__init__(parent)
        self._b      = backend
        self._caps   = []        # capabilities detected from router
        self._threads = {}
        self._build()

    def _build(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0); outer.setSpacing(0)

        # Header
        hdr = QFrame(); hdr.setFixedHeight(44)
        hdr.setStyleSheet(f"background:{BG1}; border-bottom:1px solid {B1};")
        hl  = QHBoxLayout(hdr); hl.setContentsMargins(16,0,16,0); hl.setSpacing(10)
        tit = QLabel("Router Management"); tit.setFont(sf(12, bold=True))
        hl.addWidget(tit)
        self._mode_lbl = QLabel("Client mode")
        self._mode_lbl.setFont(mf(9))
        self._mode_lbl.setStyleSheet(
            f"color:{T3}; background:{BG3}; border:1px solid {B1};"
            f"border-radius:3px; padding:1px 8px;")
        hl.addWidget(self._mode_lbl); hl.addStretch()
        ref = QPushButton("↻  Refresh")
        ref.setProperty("cls","primary"); ref.setFixedHeight(28)
        ref.clicked.connect(self._refresh_caps)
        hl.addWidget(ref)
        outer.addWidget(hdr)

        # Not-admin placeholder
        self._not_admin = QFrame()
        nal = QVBoxLayout(self._not_admin); nal.setContentsMargins(24,24,24,24)
        ic = QLabel("🔐"); ic.setFont(QFont("Segoe UI Emoji",32))
        ic.setAlignment(Qt.AlignmentFlag.AlignCenter)
        nal.addStretch(); nal.addWidget(ic)
        lbl = QLabel("Router Management requires Admin mode.\n\n"
                     "Select a network → Connect → choose Admin and enter\n"
                     "your router credentials to unlock all management features.")
        lbl.setFont(mf(10)); lbl.setStyleSheet(f"color:{T3};")
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter); lbl.setWordWrap(True)
        nal.addWidget(lbl); nal.addStretch()
        outer.addWidget(self._not_admin, 1)

        # Tabs (hidden until admin)
        self._tabs_frame = QFrame()
        self._tabs_frame.setVisible(False)
        tfl = QVBoxLayout(self._tabs_frame)
        tfl.setContentsMargins(0,0,0,0); tfl.setSpacing(0)

        tabs = QTabWidget()
        tabs.setDocumentMode(True)
        tabs.setStyleSheet(f"""
            QTabBar::tab {{
                background:{BG2}; color:{T3}; border:none;
                padding:7px 18px; font-size:10px;
            }}
            QTabBar::tab:selected {{ color:{ACC}; border-bottom:2px solid {ACC}; background:{BG1}; }}
            QTabBar::tab:hover:!selected {{ color:{T2}; background:{BG3}; }}
            QTabWidget::pane {{ border:none; background:{BG1}; }}
        """)

        tabs.addTab(self._build_security_tab(), "🔒  Security")
        tabs.addTab(self._build_access_tab(),   "🛡  Access Control")
        tabs.addTab(self._build_network_tab(),   "📡  Network")
        tabs.addTab(self._build_devices_tab(),   "▦  Devices")
        tabs.addTab(self._build_advanced_tab(),  "⚙  Advanced")

        tfl.addWidget(tabs)

        # Action log strip at bottom
        log_f = QFrame(); log_f.setFixedHeight(100)
        log_f.setStyleSheet(f"background:{BG1}; border-top:1px solid {B1};")
        log_l = QVBoxLayout(log_f); log_l.setContentsMargins(10,6,10,6)
        log_hdr = QHBoxLayout()
        log_hdr.addWidget(QLabel("Action log")); log_hdr.addStretch()
        clr = QPushButton("Clear"); clr.setFont(mf(8)); clr.setFixedHeight(20)
        clr.clicked.connect(lambda: self._action_log.clear())
        log_hdr.addWidget(clr); log_l.addLayout(log_hdr)
        self._action_log = QTextEdit(); self._action_log.setReadOnly(True)
        self._action_log.setFont(mf(8))
        self._action_log.setStyleSheet(f"background:{BG0}; border:none;")
        log_l.addWidget(self._action_log)
        tfl.addWidget(log_f)
        outer.addWidget(self._tabs_frame, 1)

    # ── Tab builders ──────────────────────────────────────────────────────────

    def _build_security_tab(self) -> QWidget:
        w = QWidget(); lay = QVBoxLayout(w)
        lay.setContentsMargins(16,14,16,14); lay.setSpacing(12)

        # WPS
        wps_g = QGroupBox("WPS (Wi-Fi Protected Setup)"); wl = QVBoxLayout(wps_g)
        wps_lbl = QLabel("WPS allows brute-force PIN attacks (Reaver/Pixie Dust). "
                         "Disable unless required.")
        wps_lbl.setFont(mf(9)); wps_lbl.setStyleSheet(f"color:{T3};"); wps_lbl.setWordWrap(True)
        wl.addWidget(wps_lbl)
        wps_btn = QPushButton("🛡  Disable WPS on router")
        wps_btn.setProperty("cls","danger"); wps_btn.setFixedHeight(32)
        wps_btn.clicked.connect(lambda: self._exec("wps_disable"))
        wl.addWidget(wps_btn); lay.addWidget(wps_g)

        # PMF
        pmf_g = QGroupBox("PMF / 802.11w (Management Frame Protection)"); pl = QVBoxLayout(pmf_g)
        pmf_lbl = QLabel("PMF prevents deauthentication flood attacks. Required by WPA3. "
                         "Enable for all networks.")
        pmf_lbl.setFont(mf(9)); pmf_lbl.setStyleSheet(f"color:{T3};"); pmf_lbl.setWordWrap(True)
        pl.addWidget(pmf_lbl)
        pmf_btn = QPushButton("✅  Enable PMF / 802.11w")
        pmf_btn.setProperty("cls","success"); pmf_btn.setFixedHeight(32)
        pmf_btn.clicked.connect(lambda: self._exec("pmf_enable"))
        pl.addWidget(pmf_btn); lay.addWidget(pmf_g)

        # Remote management
        rm_g = QGroupBox("Remote Management"); rl = QVBoxLayout(rm_g)
        rm_lbl = QLabel("Remote management exposes your router to the internet. "
                         "Disable unless you specifically need it.")
        rm_lbl.setFont(mf(9)); rm_lbl.setStyleSheet(f"color:{T3};"); rm_lbl.setWordWrap(True)
        rl.addWidget(rm_lbl)
        rm_btn = QPushButton("🚫  Disable remote management")
        rm_btn.setProperty("cls","danger"); rm_btn.setFixedHeight(32)
        rm_btn.clicked.connect(lambda: self._exec("remote_mgmt"))
        rl.addWidget(rm_btn); lay.addWidget(rm_g)

        # DNS hardening
        dns_g = QGroupBox("DNS Security"); dl = QVBoxLayout(dns_g)
        dns_lbl = QLabel("Set router DNS to trusted resolvers. "
                         "Prevents ISP DNS hijacking and spoofing.")
        dns_lbl.setFont(mf(9)); dns_lbl.setStyleSheet(f"color:{T3};"); dns_lbl.setWordWrap(True)
        dl.addWidget(dns_lbl)
        dr = QHBoxLayout(); dr.setSpacing(8)
        self._dns1 = QLineEdit("1.1.1.1"); self._dns1.setFixedHeight(28); self._dns1.setFont(mf(9))
        self._dns2 = QLineEdit("8.8.8.8"); self._dns2.setFixedHeight(28); self._dns2.setFont(mf(9))
        dr.addWidget(QLabel("Primary:")); dr.addWidget(self._dns1)
        dr.addWidget(QLabel("Secondary:")); dr.addWidget(self._dns2)
        dns_btn = QPushButton("Apply DNS"); dns_btn.setProperty("cls","primary")
        dns_btn.setFixedHeight(28)
        dns_btn.clicked.connect(lambda: self._exec("dns_override",
            dns1=self._dns1.text().strip(), dns2=self._dns2.text().strip()))
        dr.addWidget(dns_btn); dl.addLayout(dr); lay.addWidget(dns_g)

        lay.addStretch(); return w

    def _build_access_tab(self) -> QWidget:
        w = QWidget(); lay = QVBoxLayout(w)
        lay.setContentsMargins(16,14,16,14); lay.setSpacing(12)

        # MAC block
        mb_g = QGroupBox("MAC Blacklist — Block a device"); mbl = QVBoxLayout(mb_g)
        mbr = QHBoxLayout(); mbr.setSpacing(8)
        self._block_mac = QLineEdit(); self._block_mac.setPlaceholderText("XX:XX:XX:XX:XX:XX")
        self._block_mac.setFixedHeight(28); self._block_mac.setFont(mf(9))
        blk_btn = QPushButton("🚫  Block MAC"); blk_btn.setProperty("cls","danger")
        blk_btn.setFixedHeight(28)
        blk_btn.clicked.connect(lambda: self._exec("mac_block", mac=self._block_mac.text().strip()))
        mbr.addWidget(QLabel("MAC:")); mbr.addWidget(self._block_mac,1); mbr.addWidget(blk_btn)
        mbl.addLayout(mbr); lay.addWidget(mb_g)

        # MAC allow
        ma_g = QGroupBox("MAC Whitelist — Allow a device"); mal = QVBoxLayout(ma_g)
        mar = QHBoxLayout(); mar.setSpacing(8)
        self._allow_mac = QLineEdit(); self._allow_mac.setPlaceholderText("XX:XX:XX:XX:XX:XX")
        self._allow_mac.setFixedHeight(28); self._allow_mac.setFont(mf(9))
        alw_btn = QPushButton("✅  Allow MAC"); alw_btn.setProperty("cls","success")
        alw_btn.setFixedHeight(28)
        alw_btn.clicked.connect(lambda: self._exec("mac_allow", mac=self._allow_mac.text().strip()))
        mar.addWidget(QLabel("MAC:")); mar.addWidget(self._allow_mac,1); mar.addWidget(alw_btn)
        mal.addLayout(mar); lay.addWidget(ma_g)

        # Parental / quarantine
        pq_g = QGroupBox("Parental Control / Quarantine"); pql = QVBoxLayout(pq_g)
        pqr = QHBoxLayout(); pqr.setSpacing(8)
        self._quarantine_mac = QLineEdit(); self._quarantine_mac.setPlaceholderText("XX:XX:XX:XX:XX:XX")
        self._quarantine_mac.setFixedHeight(28); self._quarantine_mac.setFont(mf(9))
        qtn_btn = QPushButton("🔒  Quarantine (block all)"); qtn_btn.setProperty("cls","warn")
        qtn_btn.setFixedHeight(28)
        qtn_btn.clicked.connect(lambda: self._exec("parental_block",
                                                    mac=self._quarantine_mac.text().strip()))
        pqr.addWidget(QLabel("MAC:")); pqr.addWidget(self._quarantine_mac,1); pqr.addWidget(qtn_btn)
        pql.addLayout(pqr); lay.addWidget(pq_g)

        # Max clients
        mc_g = QGroupBox("Maximum Connected Clients"); mcl = QVBoxLayout(mc_g)
        mcr = QHBoxLayout(); mcr.setSpacing(8)
        self._max_clients = QSpinBox(); self._max_clients.setRange(1,128); self._max_clients.setValue(20)
        self._max_clients.setFixedHeight(28); self._max_clients.setFixedWidth(80)
        mc_btn = QPushButton("Apply"); mc_btn.setProperty("cls","primary"); mc_btn.setFixedHeight(28)
        mc_btn.clicked.connect(lambda: self._exec("max_clients", n=self._max_clients.value()))
        mcr.addWidget(QLabel("Max clients:"))
        mcr.addWidget(self._max_clients); mcr.addWidget(mc_btn); mcr.addStretch()
        mcl.addLayout(mcr); lay.addWidget(mc_g)

        # Bandwidth limit
        bw_g = QGroupBox("Bandwidth Limit per Device"); bwl = QVBoxLayout(bw_g)
        bwr = QHBoxLayout(); bwr.setSpacing(8)
        self._bw_mac   = QLineEdit(); self._bw_mac.setPlaceholderText("XX:XX:XX:XX:XX:XX")
        self._bw_mac.setFixedHeight(28); self._bw_mac.setFont(mf(9))
        self._bw_down  = QSpinBox(); self._bw_down.setRange(0,100000); self._bw_down.setValue(5000)
        self._bw_down.setSuffix(" kbps"); self._bw_down.setFixedHeight(28)
        self._bw_up    = QSpinBox(); self._bw_up.setRange(0,100000); self._bw_up.setValue(2000)
        self._bw_up.setSuffix(" kbps"); self._bw_up.setFixedHeight(28)
        bw_btn = QPushButton("Set limit"); bw_btn.setProperty("cls","warn"); bw_btn.setFixedHeight(28)
        bw_btn.clicked.connect(lambda: self._exec("bandwidth_limit",
            mac=self._bw_mac.text().strip(),
            down_kbps=self._bw_down.value(), up_kbps=self._bw_up.value()))
        bwr.addWidget(QLabel("MAC:")); bwr.addWidget(self._bw_mac,1)
        bwr.addWidget(QLabel("↓")); bwr.addWidget(self._bw_down)
        bwr.addWidget(QLabel("↑")); bwr.addWidget(self._bw_up)
        bwr.addWidget(bw_btn); bwl.addLayout(bwr); lay.addWidget(bw_g)

        lay.addStretch(); return w

    def _build_network_tab(self) -> QWidget:
        w = QWidget(); lay = QVBoxLayout(w)
        lay.setContentsMargins(16,14,16,14); lay.setSpacing(12)

        # Wi-Fi name
        ssid_g = QGroupBox("Wi-Fi Name (SSID)"); sl = QVBoxLayout(ssid_g)
        sr = QHBoxLayout(); sr.setSpacing(8)
        self._ssid_inp = QLineEdit(); self._ssid_inp.setPlaceholderText("Enter new SSID")
        self._ssid_inp.setFixedHeight(28); self._ssid_inp.setFont(mf(9))
        band_cb = QComboBox(); band_cb.addItems(["Both bands","2.4 GHz","5 GHz"])
        band_cb.setFixedHeight(28); band_cb.setFont(mf(9))
        ssid_btn = QPushButton("Apply"); ssid_btn.setProperty("cls","primary"); ssid_btn.setFixedHeight(28)
        ssid_btn.clicked.connect(lambda: self._exec("wifi_ssid",
            ssid=self._ssid_inp.text().strip(),
            band=["both","2.4","5"][band_cb.currentIndex()]))
        sr.addWidget(QLabel("SSID:")); sr.addWidget(self._ssid_inp,1)
        sr.addWidget(QLabel("Band:")); sr.addWidget(band_cb); sr.addWidget(ssid_btn)
        sl.addLayout(sr); lay.addWidget(ssid_g)

        # Wi-Fi password
        pw_g = QGroupBox("Wi-Fi Password"); pwl = QVBoxLayout(pw_g)
        pwr = QHBoxLayout(); pwr.setSpacing(8)
        self._pw_inp = QLineEdit(); self._pw_inp.setPlaceholderText("New Wi-Fi password (min 12 chars)")
        self._pw_inp.setEchoMode(QLineEdit.EchoMode.Password)
        self._pw_inp.setFixedHeight(28); self._pw_inp.setFont(mf(9))
        show_cb = QCheckBox("Show"); show_cb.setFont(mf(9))
        show_cb.toggled.connect(lambda v: self._pw_inp.setEchoMode(
            QLineEdit.EchoMode.Normal if v else QLineEdit.EchoMode.Password))
        pw_band = QComboBox(); pw_band.addItems(["Both bands","2.4 GHz","5 GHz"])
        pw_band.setFixedHeight(28); pw_band.setFont(mf(9))
        pw_btn = QPushButton("Change password")
        pw_btn.setProperty("cls","primary"); pw_btn.setFixedHeight(28)
        pw_btn.clicked.connect(lambda: self._validate_and_change_password(
            self._pw_inp.text(),
            ["both","2.4","5"][pw_band.currentIndex()]))
        pwr.addWidget(QLabel("Password:")); pwr.addWidget(self._pw_inp,1)
        pwr.addWidget(show_cb); pwr.addWidget(QLabel("Band:")); pwr.addWidget(pw_band)
        pwr.addWidget(pw_btn); pwl.addLayout(pwr)
        # Password strength bar
        self._pw_strength = QProgressBar(); self._pw_strength.setRange(0,100)
        self._pw_strength.setValue(0); self._pw_strength.setFixedHeight(6)
        self._pw_strength.setTextVisible(False)
        self._pw_inp.textChanged.connect(self._update_pw_strength)
        pwl.addWidget(self._pw_strength); lay.addWidget(pw_g)

        lay.addStretch(); return w

    def _build_devices_tab(self) -> QWidget:
        w = QWidget(); lay = QVBoxLayout(w)
        lay.setContentsMargins(12,10,12,10); lay.setSpacing(8)

        hdr = QHBoxLayout()
        tit = QLabel("Connected Devices (from router)"); tit.setFont(sf(10, bold=True))
        hdr.addWidget(tit); hdr.addStretch()
        ref = QPushButton("↻  Refresh"); ref.setProperty("cls","primary"); ref.setFixedHeight(26)
        ref.clicked.connect(self._load_device_list)
        hdr.addWidget(ref); lay.addLayout(hdr)

        self._dev_tbl = QTableWidget(); self._dev_tbl.setColumnCount(4)
        self._dev_tbl.setHorizontalHeaderLabels(["IP","MAC","Hostname","Action"])
        hdr2 = self._dev_tbl.horizontalHeader()
        hdr2.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        hdr2.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._dev_tbl.verticalHeader().setVisible(False)
        self._dev_tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._dev_tbl.setAlternatingRowColors(True)
        lay.addWidget(self._dev_tbl, 1); return w

    def _build_advanced_tab(self) -> QWidget:
        w = QWidget(); lay = QVBoxLayout(w)
        lay.setContentsMargins(16,14,16,14); lay.setSpacing(12)

        # Capabilities
        cap_g = QGroupBox("Detected Router Capabilities"); cl = QVBoxLayout(cap_g)
        self._cap_lbl = QLabel("Not detected — click Refresh in header")
        self._cap_lbl.setFont(mf(9)); self._cap_lbl.setStyleSheet(f"color:{T3};")
        self._cap_lbl.setWordWrap(True)
        cl.addWidget(self._cap_lbl); lay.addWidget(cap_g)

        # Reboot
        rb_g = QGroupBox("Router Reboot"); rl = QVBoxLayout(rb_g)
        rb_lbl = QLabel("Reboots the router remotely. "
                        "All connected devices will be disconnected for ~60 seconds.")
        rb_lbl.setFont(mf(9)); rb_lbl.setStyleSheet(f"color:{T3};"); rb_lbl.setWordWrap(True)
        rl.addWidget(rb_lbl)
        rb_btn = QPushButton("⚡  Reboot router")
        rb_btn.setProperty("cls","danger"); rb_btn.setFixedHeight(32)
        rb_btn.clicked.connect(self._confirm_reboot)
        rl.addWidget(rb_btn); lay.addWidget(rb_g)

        lay.addStretch(); return w

    # ── Public ────────────────────────────────────────────────────────────────

    def set_admin_mode(self, is_admin: bool):
        """Called when admin mode is enabled/disabled."""
        self._not_admin.setVisible(not is_admin)
        self._tabs_frame.setVisible(is_admin)
        if is_admin:
            self._mode_lbl.setText("Admin mode")
            self._mode_lbl.setStyleSheet(
                f"color:{GRN}; background:{rgba(GRN,0.1)};"
                f"border:1px solid {rgba(GRN,0.25)}; border-radius:3px; padding:1px 8px;")
            QTimer.singleShot(500, self._refresh_caps)
        else:
            self._mode_lbl.setText("Client mode")
            self._mode_lbl.setStyleSheet(
                f"color:{T3}; background:{BG3}; border:1px solid {B1};"
                f"border-radius:3px; padding:1px 8px;")

    # ── Internals ─────────────────────────────────────────────────────────────

    def _refresh_caps(self):
        try:
            mgr = self._b.enforcer.get_config_manager()
            if not mgr:
                self._cap_lbl.setText("No router session — login as admin first")
                return
            caps = mgr.get_capabilities()
            self._caps = caps
            self._cap_lbl.setText("  ·  ".join(f"✓ {c}" for c in caps))
            self._cap_lbl.setStyleSheet(f"color:{GRN};")
        except Exception as e:
            self._cap_lbl.setText(f"Error: {e}")

    def _exec(self, capability: str, **kwargs):
        """Execute a router capability and log result."""
        if not self._b.is_admin():
            self._log("Admin mode required", RED)
            return
        def _run():
            return self._b.enforcer.apply_router_setting(capability, **kwargs)
        t = _ActionThread(_run)
        t.done.connect(lambda r, cap=capability: self._on_action_done(cap, r))
        t.start(); self._threads[capability] = t
        self._log(f"Executing: {capability}  {kwargs}", ACC)

    def _on_action_done(self, cap: str, result: dict):
        ok = result.get("ok", False)
        detail = result.get("detail","")
        color  = GRN if ok else RED
        self._log(f"{'✓' if ok else '✗'} {cap}: {detail}", color)
        self.action_sig.emit(cap, result)

    def _validate_and_change_password(self, pw: str, band: str):
        if len(pw) < 8:
            QMessageBox.warning(self, "Weak password",
                "Password must be at least 8 characters. 12+ strongly recommended.")
            return
        self._exec("wifi_password", password=pw, band=band)

    def _update_pw_strength(self, pw: str):
        score = min(100, len(pw) * 6)
        if any(c.isupper() for c in pw): score += 10
        if any(c.isdigit() for c in pw): score += 10
        if any(not c.isalnum() for c in pw): score += 10
        score = min(100, score)
        self._pw_strength.setValue(score)
        c = GRN if score >= 70 else YLW if score >= 40 else RED
        self._pw_strength.setStyleSheet(
            f"QProgressBar{{background:{BG4};border:none;border-radius:3px;}}"
            f"QProgressBar::chunk{{background:{c};border-radius:3px;}}")

    def _load_device_list(self):
        self._log("Loading device list from router...", ACC)
        def _run():
            try:
                mgr = self._b.enforcer.get_config_manager()
                return {"ok": True, "data": mgr.get_device_list()} if mgr else \
                       {"ok": False, "detail": "No router session"}
            except Exception as e:
                return {"ok": False, "detail": str(e)}
        t = _ActionThread(_run)
        t.done.connect(self._populate_device_list)
        t.start(); self._threads["dev_list"] = t

    def _populate_device_list(self, result: dict):
        devs = result.get("data", [])
        if not isinstance(devs, list):
            devs = []
        self._dev_tbl.setRowCount(len(devs))
        for row, d in enumerate(devs):
            ip  = str(d.get("ip","") or d.get("IPAddress","") or "—")
            mac = str(d.get("mac","") or d.get("MACAddress","") or "—")
            hn  = str(d.get("hostname","") or d.get("HostName","") or "—")
            for col, val in enumerate([ip, mac, hn]):
                item = QTableWidgetItem(val); item.setFont(mf(9))
                self._dev_tbl.setItem(row, col, item)
            bw = QWidget(); bl = QHBoxLayout(bw)
            bl.setContentsMargins(4,2,4,2); bl.setSpacing(4)
            blk = QPushButton("Block"); blk.setFont(mf(8)); blk.setFixedHeight(20)
            blk.setProperty("cls","danger")
            blk.clicked.connect(lambda _, m=mac: self._exec("mac_block", mac=m))
            bl.addWidget(blk)
            bwl = QPushButton("Limit BW"); bwl.setFont(mf(8)); bwl.setFixedHeight(20)
            bwl.clicked.connect(lambda _, m=mac: (
                self._bw_mac.setText(m),))
            bl.addWidget(bwl); bl.addStretch()
            self._dev_tbl.setCellWidget(row, 3, bw)
        self._dev_tbl.resizeRowsToContents()
        self._log(f"Loaded {len(devs)} devices from router", GRN)

    def _confirm_reboot(self):
        r = QMessageBox.warning(self, "Confirm reboot",
            "This will reboot the router. All connections will drop for ~60 seconds.\n\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel)
        if r == QMessageBox.StandardButton.Yes:
            self._exec("reboot")

    def _log(self, msg: str, color: str = T2):
        ts  = datetime.datetime.now().strftime("%H:%M:%S")
        html = (f'<span style="color:{T4};">{ts}</span> '
                f'<span style="color:{color};">{msg}</span><br>')
        cur = self._action_log.textCursor()
        cur.movePosition(cur.MoveOperation.Start)
        cur.insertHtml(html)
