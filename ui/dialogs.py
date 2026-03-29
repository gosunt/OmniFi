"""
OmniFi — UI Dialogs
LoginDialog      : mode selector + admin credential form with PBKDF2 note
SafeModeConfirm  : confirmation gate for every enforcement action
"""
import platform
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QGroupBox, QFormLayout, QApplication,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui  import QFont
from ui.theme     import (
    BG2, BG3, B1, B2, T1, T2, T3, T4,
    ACC, GRN, YLW, RED,
    rgba, mf, sf,
)

WIN = platform.system() == "Windows"


# ─────────────────────────────────────────────────────────────────────────────
# Login / Mode selector dialog
# ─────────────────────────────────────────────────────────────────────────────
class LoginDialog(QDialog):
    """
    Mode selector shown before monitoring starts.
    .result_mode : "admin" | "client"
    .result_url  : router URL (admin only)
    .result_user : username  (admin only)
    .result_pass : plaintext password — hashed by backend, never stored
    """

    def __init__(self, auto_detect_fn=None, parent=None):
        """auto_detect_fn : callable() → dict{gateway, isp_name, default_url, default_user, default_pass}"""
        super().__init__(parent)
        self.result_mode = "client"
        self.result_url  = ""
        self.result_user = ""
        self.result_pass = ""
        self._auto_fn    = auto_detect_fn
        self.setWindowTitle("OmniFi — Connect")
        self.setFixedWidth(500)
        self._build()

    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(28, 24, 28, 24)
        lay.setSpacing(16)

        # Logo
        logo = QLabel("OMNIFI"); logo.setFont(mf(18, bold=True))
        logo.setStyleSheet(f"color:{ACC}; letter-spacing:5px;")
        lay.addWidget(logo)

        sub = QLabel("Hybrid Wi-Fi Security System")
        sub.setFont(mf(9)); sub.setStyleSheet(f"color:{T3};")
        lay.addWidget(sub)

        # Mode buttons
        mr = QHBoxLayout(); mr.setSpacing(10)
        self._ab = QPushButton("🛡  Admin mode")
        self._cb = QPushButton("📡  Client mode")
        _btn_style = (
            f"QPushButton{{background:{BG3};border:1px solid {B2};"
            f"border-radius:9px;text-align:left;padding:10px 16px;font-size:12px;}}"
            f"QPushButton:checked{{background:{rgba(ACC,0.09)};"
            f"border-color:{ACC};color:{ACC};}}"
            f"QPushButton:hover:!checked{{background:{BG2};}}"
        )
        for b in (self._ab, self._cb):
            b.setCheckable(True); b.setFixedHeight(62)
            b.setStyleSheet(_btn_style)
        self._cb.setChecked(True)
        self._ab.clicked.connect(lambda: self._sel("admin"))
        self._cb.clicked.connect(lambda: self._sel("client"))
        mr.addWidget(self._ab); mr.addWidget(self._cb)
        lay.addLayout(mr)

        # Admin fields (hidden in client mode)
        self._ag = QGroupBox("Router Credentials"); self._ag.setVisible(False)
        af = QFormLayout(self._ag); af.setSpacing(9)

        self._url  = QLineEdit("http://192.168.29.1"); self._url.setFixedHeight(32)
        self._user = QLineEdit(); self._user.setPlaceholderText("admin")
        self._user.setFixedHeight(32)
        self._pass = QLineEdit(); self._pass.setEchoMode(QLineEdit.EchoMode.Password)
        self._pass.setPlaceholderText("••••••••"); self._pass.setFixedHeight(32)
        self._pass.textChanged.connect(self._show_hash_note)

        self._hn = QLabel("🔐  PBKDF2-SHA256 · 100 000 iterations · plaintext never stored")
        self._hn.setFont(mf(8)); self._hn.setStyleSheet(f"color:{GRN};")
        self._hn.setVisible(False)

        auto = QPushButton("Auto-detect ISP"); auto.setFixedHeight(28)
        auto.clicked.connect(self._auto_detect)

        af.addRow("Router URL:", self._url)
        af.addRow("Username:",   self._user)
        af.addRow("Password:",   self._pass)
        af.addRow("",            self._hn)
        af.addRow("",            auto)
        lay.addWidget(self._ag)

        # Error label
        self._err = QLabel(""); self._err.setFont(mf(9))
        self._err.setStyleSheet(f"color:{RED};")
        lay.addWidget(self._err)
        lay.addStretch()

        # Proceed button
        proc = QPushButton("Start monitoring  →")
        proc.setProperty("cls","primary"); proc.setFixedHeight(42)
        proc.setFont(sf(12, bold=True)); proc.clicked.connect(self._proceed)
        lay.addWidget(proc)

        note = QLabel("Credentials are hashed locally — plaintext is never stored on disk.")
        note.setFont(mf(8)); note.setStyleSheet(f"color:{T4};")
        note.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(note)

    # ── internals ─────────────────────────────────────────────────────────────
    def _sel(self, mode: str):
        self._ab.setChecked(mode == "admin")
        self._cb.setChecked(mode == "client")
        self._ag.setVisible(mode == "admin")
        self.adjustSize()

    def _show_hash_note(self):
        self._hn.setVisible(bool(self._pass.text()))

    def _auto_detect(self):
        if not self._auto_fn: return
        try:
            info = self._auto_fn()
            self._url.setText(info.get("default_url",""))
            self._user.setText(info.get("default_user",""))
            self._pass.setText(info.get("default_pass",""))
            self._err.setText(
                f"Detected: {info.get('isp_name','Unknown')} on {info.get('gateway','')}")
            self._err.setStyleSheet(f"color:{YLW};")
        except Exception as e:
            self._err.setText(str(e))

    def _proceed(self):
        if self._ab.isChecked():
            u = self._user.text().strip()
            p = self._pass.text()
            if not u or not p:
                self._err.setText("Username and password are required.")
                return
            self._err.setText("Hashing credentials (PBKDF2-SHA256)…")
            self._err.setStyleSheet(f"color:{ACC};")
            QApplication.processEvents()
            self.result_mode = "admin"
            self.result_url  = self._url.text().strip()
            self.result_user = u
            self.result_pass = p
        else:
            self.result_mode = "client"
        self.accept()


# ─────────────────────────────────────────────────────────────────────────────
# Safe-mode confirmation dialog
# ─────────────────────────────────────────────────────────────────────────────
class SafeModeConfirm(QDialog):
    """
    Intercepts every enforcement action when safe mode is ON.
    .exec() == Accepted  → user confirmed → apply action
    .exec() == Rejected  → user cancelled → do nothing
    """

    def __init__(self, action: str, mac: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("OmniFi — Safe mode confirmation")
        self.setFixedWidth(400)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 22, 24, 22)
        lay.setSpacing(12)

        ti = QLabel("⚠️  Safe mode — confirmation required")
        ti.setFont(mf(11, bold=True)); ti.setStyleSheet(f"color:{YLW};")
        lay.addWidget(ti)

        bd = QLabel(
            "Auto-enforcement is disabled. This action requires your explicit "
            "approval before it is applied to the router.")
        bd.setFont(sf(10)); bd.setStyleSheet(f"color:{T2};"); bd.setWordWrap(True)
        lay.addWidget(bd)

        al = QLabel(f"{action.replace('_',' ').title()}:  {mac}")
        al.setFont(mf(11))
        al.setStyleSheet(
            f"color:{YLW}; background:{rgba(YLW,0.09)};"
            f"border:1px solid {rgba(YLW,0.25)}; border-radius:5px; padding:7px 12px;")
        lay.addWidget(al)
        lay.addStretch()

        br = QHBoxLayout()
        ok = QPushButton("Confirm — apply now"); ok.setProperty("cls","danger")
        ok.setFixedHeight(36); ok.clicked.connect(self.accept)
        ca = QPushButton("Cancel"); ca.setFixedHeight(36)
        ca.clicked.connect(self.reject)
        br.addWidget(ok); br.addWidget(ca)
        lay.addLayout(br)


# ─────────────────────────────────────────────────────────────────────────────
# Wireless Interface Selector
# ─────────────────────────────────────────────────────────────────────────────
class InterfaceDialog(QDialog):
    """
    Shown at startup when multiple wireless interfaces are detected.
    .selected_iface : dict {name, mac, connected_ssid, is_active}
    """

    def __init__(self, ifaces: list, parent=None):
        super().__init__(parent)
        self.setWindowTitle("OmniFi — Select Interface")
        self.setFixedWidth(440)
        self.selected_iface = ifaces[0] if ifaces else {"name": "auto"}
        self._ifaces = ifaces
        self._build()

    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 22, 24, 22)
        lay.setSpacing(14)

        title = QLabel("Select Wi-Fi Interface")
        title.setFont(sf(12, bold=True))
        title.setStyleSheet(f"color:{T1};")
        lay.addWidget(title)

        sub = QLabel("Multiple wireless interfaces detected. Choose which to use for scanning.")
        sub.setFont(mf(9)); sub.setStyleSheet(f"color:{T3};"); sub.setWordWrap(True)
        lay.addWidget(sub)

        _card_base = (
            f"QPushButton{{background:{BG3};border:1px solid {B1};"
            f"border-radius:8px;text-align:left;padding:10px 14px;font-size:11px;}}"
            f"QPushButton:checked{{background:{rgba(ACC,0.08)};"
            f"border-color:{ACC};color:{ACC};}}"
            f"QPushButton:hover:!checked{{background:{BG2};border-color:{B2};}}"
        )

        self._btns = []
        for iface in self._ifaces:
            name   = iface.get("name", "?")
            mac    = iface.get("mac", "")
            ssid   = iface.get("connected_ssid", "")
            active = iface.get("is_active", False)

            status = f"  ·  Connected: {ssid}" if ssid else ("  ·  Active" if active else "  ·  Not connected")
            label  = f"📡  {name}    {mac}{status}"

            b = QPushButton(label)
            b.setCheckable(True)
            b.setFixedHeight(54)
            b.setStyleSheet(_card_base)
            b.clicked.connect(lambda _, i=iface, btn=b: self._select(i, btn))
            self._btns.append(b)
            lay.addWidget(b)

        # Auto-select the active one, or first
        active_ifaces = [i for i in self._ifaces if i.get("is_active")]
        default = active_ifaces[0] if active_ifaces else self._ifaces[0]
        default_idx = self._ifaces.index(default)
        self._btns[default_idx].setChecked(True)
        self.selected_iface = default

        lay.addStretch()

        br = QHBoxLayout(); br.setSpacing(8)
        ok = QPushButton("Use selected  →")
        ok.setProperty("cls", "primary"); ok.setFixedHeight(38)
        ok.setFont(sf(11, bold=True)); ok.clicked.connect(self.accept)
        auto = QPushButton("Auto-detect")
        auto.setFixedHeight(38); auto.clicked.connect(self._use_auto)
        br.addWidget(auto); br.addWidget(ok)
        lay.addLayout(br)

    def _select(self, iface: dict, btn):
        self.selected_iface = iface
        for b in self._btns:
            b.setChecked(b is btn)

    def _use_auto(self):
        self.selected_iface = {"name": "auto"}
        self.accept()


# ─────────────────────────────────────────────────────────────────────────────
# Router Login Dialog
# Shown when user selects Admin mode in the scanner.
# Auto-detects gateway + ISP defaults, lets user test before connecting.
# ─────────────────────────────────────────────────────────────────────────────
class RouterLoginDialog(QDialog):
    """
    Step 1 — detects gateway IP and ISP defaults automatically.
    Step 2 — user confirms / edits credentials.
    Step 3 — "Test connection" verifies creds (non-blocking spinner).
    Step 4 — on success, accept(); on failure, show error + allow retry.

    .result_url, .result_user, .result_pass  set on accept().
    """

    def __init__(self, auto_detect_fn, login_fn, parent=None):
        """
        auto_detect_fn : callable() → {gateway, isp_name, default_url,
                                        default_user, default_pass}
        login_fn       : callable(url, user, pwd) → {ok, isp_name, ...}
        """
        super().__init__(parent)
        self._auto_fn  = auto_detect_fn
        self._login_fn = login_fn
        self.result_url  = ""
        self.result_user = ""
        self.result_pass = ""
        self._login_thread = None
        self.setWindowTitle("OmniFi — Router Login")
        self.setFixedWidth(480)
        self.setModal(True)
        self._build()
        # Auto-detect immediately on open
        from PyQt6.QtCore import QTimer
        QTimer.singleShot(0, self._auto_fill)

    def _build(self):
        from PyQt6.QtWidgets import QLineEdit, QProgressBar, QTextEdit
        from PyQt6.QtCore    import Qt
        from PyQt6.QtGui     import QFont
        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 22, 26, 22); lay.setSpacing(14)

        # ── Header ────────────────────────────────────────────────────────────
        hdr = QHBoxLayout(); hdr.setSpacing(10)
        ic = QLabel("🛡")
        ic.setFont(QFont("Segoe UI Emoji" if WIN else "Noto Color Emoji", 22))
        hdr.addWidget(ic)
        vt = QVBoxLayout(); vt.setSpacing(2)
        t = QLabel("Router Admin Login"); t.setFont(sf(13, bold=True))
        t.setStyleSheet(f"color:{T1};")
        self._sub = QLabel("Detecting gateway…")
        self._sub.setFont(mf(9)); self._sub.setStyleSheet(f"color:{T3};")
        vt.addWidget(t); vt.addWidget(self._sub)
        hdr.addLayout(vt, 1); lay.addLayout(hdr)

        # ── ISP / gateway chip ─────────────────────────────────────────────
        self._isp_chip = QLabel("")
        self._isp_chip.setFont(mf(9))
        self._isp_chip.setStyleSheet(
            f"color:{ACC}; background:{rgba(ACC,0.08)}; border:1px solid {rgba(ACC,0.2)};"
            f"border-radius:4px; padding:4px 12px;")
        self._isp_chip.setVisible(False)
        lay.addWidget(self._isp_chip)

        # ── Credential fields ─────────────────────────────────────────────
        form = QFormLayout(); form.setSpacing(9); form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        self._url  = QLineEdit(); self._url.setFixedHeight(32); self._url.setFont(mf(10))
        self._url.setPlaceholderText("http://192.168.1.1")
        self._user = QLineEdit(); self._user.setFixedHeight(32); self._user.setFont(mf(10))
        self._user.setPlaceholderText("admin")
        self._pass = QLineEdit(); self._pass.setFixedHeight(32); self._pass.setFont(mf(10))
        self._pass.setEchoMode(QLineEdit.EchoMode.Password)
        self._pass.setPlaceholderText("password")
        self._pass.setToolTip("Hashed with PBKDF2-SHA256 — never stored in plaintext")
        # Show/hide password toggle
        self._show_pw = QPushButton("👁"); self._show_pw.setFixedSize(32, 32)
        self._show_pw.setCheckable(True)
        self._show_pw.setFont(QFont("Segoe UI Emoji" if WIN else "Noto Color Emoji", 12))
        self._show_pw.setStyleSheet(f"QPushButton{{background:{BG3};border:1px solid {B2};border-radius:5px;}}"
                                    f"QPushButton:checked{{background:{rgba(ACC,0.12)};border-color:{ACC};}}")
        self._show_pw.toggled.connect(
            lambda on: self._pass.setEchoMode(
                QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password))
        pw_row = QHBoxLayout(); pw_row.setSpacing(4)
        pw_row.addWidget(self._pass, 1); pw_row.addWidget(self._show_pw)
        form.addRow("Router URL:", self._url)
        form.addRow("Username:",   self._user)
        form.addRow("Password:",   pw_row)
        lay.addLayout(form)

        # PBKDF2 note
        ph_note = QLabel("🔐  Password is hashed with PBKDF2-SHA256 and never stored in plaintext")
        ph_note.setFont(mf(8)); ph_note.setStyleSheet(f"color:{T4};"); ph_note.setWordWrap(True)
        lay.addWidget(ph_note)

        # ── Progress / result area ─────────────────────────────────────────
        self._prog = QProgressBar(); self._prog.setRange(0, 0)  # indeterminate
        self._prog.setFixedHeight(3); self._prog.setTextVisible(False)
        self._prog.setVisible(False)
        lay.addWidget(self._prog)

        self._result_lbl = QLabel("")
        self._result_lbl.setFont(mf(9)); self._result_lbl.setWordWrap(True)
        self._result_lbl.setVisible(False)
        lay.addWidget(self._result_lbl)

        lay.addStretch()

        # ── Buttons ────────────────────────────────────────────────────────
        br = QHBoxLayout(); br.setSpacing(8)

        self._client_btn = QPushButton("Continue as Client instead")
        self._client_btn.setFont(mf(9)); self._client_btn.setFixedHeight(34)
        self._client_btn.setToolTip("Start monitoring without admin access")
        self._client_btn.clicked.connect(self._use_client)
        br.addWidget(self._client_btn)
        br.addStretch()

        self._test_btn = QPushButton("Test connection  →")
        self._test_btn.setProperty("cls", "primary"); self._test_btn.setFixedHeight(34)
        self._test_btn.setEnabled(False)
        self._test_btn.clicked.connect(self._test_login)
        br.addWidget(self._test_btn)
        lay.addLayout(br)

        # Enable Test button when fields are filled
        self._url.textChanged.connect(self._check_ready)
        self._user.textChanged.connect(self._check_ready)
        self._pass.textChanged.connect(self._check_ready)

    # ── Auto-fill ─────────────────────────────────────────────────────────────
    def _auto_fill(self):
        try:
            info = self._auto_fn()
            gw   = info.get("gateway", "")
            isp  = info.get("isp_name", "Unknown")
            self._url.setText(info.get("default_url",  f"http://{gw}" if gw else ""))
            self._user.setText(info.get("default_user", "admin"))
            self._pass.setText(info.get("default_pass", ""))
            self._sub.setText(f"Gateway: {gw}" if gw else "Could not detect gateway")
            if isp != "Unknown":
                self._isp_chip.setText(f"  {isp}  —  ISP detected, default credentials pre-filled")
                self._isp_chip.setVisible(True)
            self._check_ready()
        except Exception as e:
            self._sub.setText(f"Auto-detect failed: {e}")

    def _check_ready(self):
        self._test_btn.setEnabled(
            bool(self._url.text().strip()) and
            bool(self._user.text().strip()) and
            bool(self._pass.text()))

    # ── Test login (non-blocking) ─────────────────────────────────────────────
    def _test_login(self):
        from PyQt6.QtCore import QThread, pyqtSignal as _sig

        url  = self._url.text().strip()
        user = self._user.text().strip()
        pwd  = self._pass.text()

        self._test_btn.setEnabled(False)
        self._prog.setVisible(True)
        self._result_lbl.setVisible(False)

        class _LoginThread(QThread):
            done = _sig(dict)
            def __init__(self, fn, u, us, pw):
                super().__init__(); self._fn=fn; self._u=u; self._us=us; self._pw=pw
            def run(self):
                try:   self.done.emit(self._fn(self._u, self._us, self._pw))
                except Exception as e: self.done.emit({"ok": False, "error": str(e)})

        self._login_thread = _LoginThread(self._login_fn, url, user, pwd)
        self._login_thread.done.connect(self._on_login_result)
        self._login_thread.start()

    def _on_login_result(self, result: dict):
        self._prog.setVisible(False)
        self._result_lbl.setVisible(True)

        if result.get("ok"):
            # Success — show summary then accept
            isp = result.get("isp_name", "")
            dc  = result.get("default_creds_work", False)
            https = result.get("uses_https", False)

            lines = [f"✓  Admin mode activated"]
            if isp: lines.append(f"   ISP: {isp}")
            if dc:  lines.append(f"   ⚠  Default credentials work — please change them!")
            if not https: lines.append(f"   ⚠  Admin panel uses HTTP (not HTTPS)")

            self._result_lbl.setText("\n".join(lines))
            self._result_lbl.setStyleSheet(
                f"color:{GRN}; background:{rgba(GRN,0.07)}; border:1px solid {rgba(GRN,0.2)};"
                f"border-radius:5px; padding:8px 12px;")
            self.result_url  = self._url.text().strip()
            self.result_user = self._user.text().strip()
            self.result_pass = self._pass.text()

            # Auto-close after 1.5 s
            from PyQt6.QtCore import QTimer
            QTimer.singleShot(1500, self.accept)
        else:
            err = result.get("error", "Login failed")
            self._result_lbl.setText(
                f"✗  Could not verify admin credentials\n   {err}\n\n"
                f"   Check the URL, username, and password then try again.\n"
                f"   Or click  'Continue as Client'  for monitoring without admin access.")
            self._result_lbl.setStyleSheet(
                f"color:{RED}; background:{rgba(RED,0.07)}; border:1px solid {rgba(RED,0.2)};"
                f"border-radius:5px; padding:8px 12px;")
            self._test_btn.setEnabled(True)
            self._test_btn.setText("Retry  →")

    def _use_client(self):
        """Reject dialog → caller falls back to client mode."""
        self.result_url = self.result_user = self.result_pass = ""
        self.reject()
