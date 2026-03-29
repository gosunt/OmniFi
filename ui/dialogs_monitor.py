"""
OmniFi — Monitor Mode & Interface Hotplug Dialogs

MonitorModeDialog  : shown when a test needing monitor mode is triggered.
                     Explains what it does, tries to enable it, reports result.
NewInterfacePopup  : non-modal toast shown when a new wireless interface appears.
InterfaceHotplug   : QThread that polls for interface changes every 5 s.
"""
import platform, subprocess, re, time
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QProgressBar, QWidget,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QPropertyAnimation, QEasingCurve
from PyQt6.QtGui  import QFont

from ui.theme import (
    BG1, BG2, BG3, B1, B2, T1, T2, T3, T4,
    ACC, GRN, YLW, RED, ORG, PUR, rgba, mf, sf,
)

WIN = platform.system() == "Windows"


# ─────────────────────────────────────────────────────────────────────────────
# Monitor mode helpers
# ─────────────────────────────────────────────────────────────────────────────
def check_monitor_mode(iface: str) -> bool:
    """Return True if interface is already in monitor mode."""
    try:
        if WIN:
            return False          # Windows: monitor mode via Npcap only
        out = subprocess.check_output(
            ["iw", "dev", iface, "info"],
            text=True, stderr=subprocess.DEVNULL)
        return "type monitor" in out.lower()
    except Exception:
        return False


def enable_monitor_mode(iface: str) -> tuple:
    """
    Attempt to switch iface to monitor mode.
    Returns (success: bool, message: str)
    """
    if WIN:
        return (False,
                "Monitor mode on Windows requires Npcap with WinPcap-compatible "
                "mode enabled.\n\nInstall Npcap from https://npcap.com and use "
                "the  Raw 802.11  option in your capture tool.")
    try:
        subprocess.run(["ip",  "link", "set", iface, "down"],  check=True,
                       stderr=subprocess.DEVNULL)
        subprocess.run(["iw",  "dev",  iface, "set",  "type", "monitor"],
                       check=True, stderr=subprocess.DEVNULL)
        subprocess.run(["ip",  "link", "set", iface, "up"],    check=True,
                       stderr=subprocess.DEVNULL)
        # Verify
        if check_monitor_mode(iface):
            return (True, f"Interface  {iface}  is now in monitor mode.")
        return (False, "Command ran but mode was not confirmed. Try: sudo iw dev <iface> set type monitor")
    except subprocess.CalledProcessError as e:
        return (False, f"Failed: {e}\nRun as root (sudo) to switch interface modes.")
    except FileNotFoundError:
        return (False, "iw not found. Install with:  sudo apt install iw")


def disable_monitor_mode(iface: str) -> tuple:
    """Switch back to managed mode."""
    if WIN:
        return (False, "Not applicable on Windows.")
    try:
        subprocess.run(["ip",  "link", "set", iface, "down"], check=True, stderr=subprocess.DEVNULL)
        subprocess.run(["iw",  "dev",  iface, "set",  "type", "managed"], check=True, stderr=subprocess.DEVNULL)
        subprocess.run(["ip",  "link", "set", iface, "up"],   check=True, stderr=subprocess.DEVNULL)
        return (True, f"Interface  {iface}  restored to managed mode.")
    except Exception as e:
        return (False, str(e))


# ─────────────────────────────────────────────────────────────────────────────
# Monitor Mode Dialog
# ─────────────────────────────────────────────────────────────────────────────
class MonitorModeDialog(QDialog):
    """
    Shown when user wants to run a test that requires monitor mode
    (deauth detector, beacon anomaly, passive packet capture).

    mode_enabled(iface_name) signal emitted if user enables monitor mode.
    """
    mode_enabled = pyqtSignal(str)

    # What each test needs monitor mode for
    TEST_INFO = {
        "deauth":  ("Deauth Attack Detector",
                    "Detect 802.11 deauthentication frame floods.\n"
                    "Requires monitor mode to capture raw 802.11 management frames."),
        "beacon":  ("Beacon Anomaly Monitor",
                    "Detect irregular beacon timing from rogue APs.\n"
                    "Requires monitor mode to see all nearby beacons."),
        "passive": ("Passive Packet Capture",
                    "Capture and analyse raw 802.11 frames.\n"
                    "Requires monitor mode to receive frames not directed at this device."),
    }

    def __init__(self, iface: str, test_key: str = "deauth", parent=None):
        super().__init__(parent)
        self._iface    = iface
        self._test_key = test_key
        self._enabled  = False
        self.setWindowTitle("OmniFi — Monitor Mode Required")
        self.setFixedWidth(480)
        self.setModal(True)
        self._build()

    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 22, 26, 22)
        lay.setSpacing(14)

        # Header
        hdr = QHBoxLayout(); hdr.setSpacing(12)
        ic = QLabel("📡")
        ic.setFont(QFont("Segoe UI Emoji" if WIN else "Noto Color Emoji", 24))
        hdr.addWidget(ic)
        vt = QVBoxLayout(); vt.setSpacing(3)
        test_name, test_desc = self.TEST_INFO.get(
            self._test_key,
            ("Monitor Mode Required", "This feature requires a monitor-mode adapter."))
        t = QLabel(f"Monitor mode required"); t.setFont(sf(12, bold=True))
        t.setStyleSheet(f"color:{T1};")
        s = QLabel(test_name); s.setFont(mf(9))
        s.setStyleSheet(f"color:{ACC};")
        vt.addWidget(t); vt.addWidget(s)
        hdr.addLayout(vt, 1); lay.addLayout(hdr)

        # Test description box
        desc_frame = QFrame()
        desc_frame.setStyleSheet(
            f"background:{BG3}; border:1px solid {B1}; border-radius:6px;")
        df = QVBoxLayout(desc_frame); df.setContentsMargins(14, 10, 14, 10)
        dl = QLabel(test_desc); dl.setFont(mf(9))
        dl.setStyleSheet(f"color:{T2};"); dl.setWordWrap(True)
        df.addWidget(dl)
        lay.addWidget(desc_frame)

        # Current status
        already = check_monitor_mode(self._iface)
        self._status_lbl = QLabel()
        self._status_lbl.setFont(mf(9)); self._status_lbl.setWordWrap(True)
        self._set_status(already)
        lay.addWidget(self._status_lbl)

        # Interface chip
        if self._iface and self._iface != "auto":
            iface_row = QHBoxLayout(); iface_row.setSpacing(8)
            iface_row.addWidget(QLabel("Interface:"))
            ic2 = QLabel(self._iface); ic2.setFont(mf(10, bold=True))
            ic2.setStyleSheet(
                f"color:{ACC}; background:{rgba(ACC,0.08)}; border:1px solid {rgba(ACC,0.2)};"
                f"border-radius:4px; padding:2px 10px;")
            iface_row.addWidget(ic2); iface_row.addStretch()
            lay.addLayout(iface_row)

        # Windows note
        if WIN:
            win_note = QLabel(
                "⚠  Windows: monitor mode requires Npcap with WinPcap-compatible mode.\n"
                "   Install from https://npcap.com — enable the 'raw 802.11' option.")
            win_note.setFont(mf(9)); win_note.setWordWrap(True)
            win_note.setStyleSheet(
                f"color:{YLW}; background:{rgba(YLW,0.07)}; border:1px solid {rgba(YLW,0.2)};"
                f"border-radius:5px; padding:8px 12px;")
            lay.addWidget(win_note)

        # Progress/result area (hidden initially)
        self._prog_frame = QFrame(); self._prog_frame.setVisible(False)
        pfl = QVBoxLayout(self._prog_frame); pfl.setContentsMargins(0,0,0,0); pfl.setSpacing(6)
        self._prog = QProgressBar(); self._prog.setRange(0,0)  # indeterminate
        self._prog.setFixedHeight(4); self._prog.setTextVisible(False)
        pfl.addWidget(self._prog)
        self._result_lbl = QLabel(); self._result_lbl.setFont(mf(9))
        self._result_lbl.setWordWrap(True); pfl.addWidget(self._result_lbl)
        lay.addWidget(self._prog_frame)

        lay.addStretch()

        # Buttons
        br = QHBoxLayout(); br.setSpacing(8)

        self._skip_btn = QPushButton("Skip — run without monitor mode")
        self._skip_btn.setFixedHeight(34); self._skip_btn.setFont(mf(9))
        self._skip_btn.clicked.connect(self._on_skip); br.addWidget(self._skip_btn)
        br.addStretch()

        if already:
            ok_btn = QPushButton("✓  Already enabled — Continue")
            ok_btn.setProperty("cls", "success"); ok_btn.setFixedHeight(34)
            ok_btn.clicked.connect(self._on_continue_enabled); br.addWidget(ok_btn)
        elif WIN:
            ok_btn = QPushButton("Open Npcap website")
            ok_btn.setFixedHeight(34)
            ok_btn.clicked.connect(lambda: __import__("webbrowser").open("https://npcap.com"))
            br.addWidget(ok_btn)
        else:
            self._enable_btn = QPushButton("Enable monitor mode  →")
            self._enable_btn.setProperty("cls", "primary"); self._enable_btn.setFixedHeight(34)
            self._enable_btn.clicked.connect(self._on_enable); br.addWidget(self._enable_btn)

        lay.addLayout(br)

    def _set_status(self, enabled: bool):
        if enabled:
            self._status_lbl.setText("✓  Interface is already in monitor mode.")
            self._status_lbl.setStyleSheet(
                f"color:{GRN}; background:{rgba(GRN,0.08)}; border:1px solid {rgba(GRN,0.2)};"
                f"border-radius:5px; padding:6px 12px;")
        else:
            self._status_lbl.setText("✗  Interface is in managed mode — monitor mode needed for this test.")
            self._status_lbl.setStyleSheet(
                f"color:{YLW}; background:{rgba(YLW,0.08)}; border:1px solid {rgba(YLW,0.2)};"
                f"border-radius:5px; padding:6px 12px;")

    def _on_enable(self):
        self._enable_btn.setEnabled(False)
        self._prog_frame.setVisible(True)
        self._result_lbl.setText("Enabling monitor mode…")
        self._result_lbl.setStyleSheet(f"color:{T2};")

        class _T(QThread):
            done = pyqtSignal(bool, str)
            def __init__(self, iface): super().__init__(); self._i = iface
            def run(self): self.done.emit(*enable_monitor_mode(self._i))

        self._t = _T(self._iface); self._t.done.connect(self._on_done); self._t.start()

    def _on_done(self, ok: bool, msg: str):
        self._prog.setRange(0, 100); self._prog.setValue(100)
        self._result_lbl.setText(msg)
        self._result_lbl.setStyleSheet(f"color:{GRN if ok else RED};")
        if ok:
            self._enabled = True
            self._enable_btn.setText("✓  Enabled — Continue")
            self._enable_btn.setProperty("cls", "success")
            self._enable_btn.setEnabled(True)
            self._enable_btn.clicked.disconnect()
            self._enable_btn.clicked.connect(self._on_continue_enabled)

    def _on_continue_enabled(self):
        self.mode_enabled.emit(self._iface)
        self.accept()

    def _on_skip(self):
        self.reject()


# ─────────────────────────────────────────────────────────────────────────────
# New Interface Toast (non-modal)
# ─────────────────────────────────────────────────────────────────────────────
class NewInterfaceToast(QWidget):
    """
    Floating notification that slides in from the bottom-right when a new
    wireless interface is detected.
    Provides: Analyze · Enable monitor mode · Dismiss
    """
    analyze_sig      = pyqtSignal(dict)    # iface dict
    monitor_mode_sig = pyqtSignal(dict)    # iface dict

    def __init__(self, iface: dict, parent=None):
        super().__init__(parent, Qt.WindowType.ToolTip | Qt.WindowType.FramelessWindowHint)
        self._iface = iface
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self._build()
        self._start_timer()

    def _build(self):
        lay = QVBoxLayout(self); lay.setContentsMargins(0,0,0,0)

        card = QFrame()
        card.setStyleSheet(
            f"background:{BG2}; border:1px solid {B2}; border-radius:10px;")
        card.setFixedWidth(340)
        cl = QVBoxLayout(card); cl.setContentsMargins(16,14,16,14); cl.setSpacing(10)

        # Title row
        tr = QHBoxLayout(); tr.setSpacing(8)
        ic = QLabel("📡")
        ic.setFont(QFont("Segoe UI Emoji" if WIN else "Noto Color Emoji", 14))
        tr.addWidget(ic)
        vt = QVBoxLayout(); vt.setSpacing(2)
        t = QLabel("New wireless interface detected")
        t.setFont(sf(10, bold=True)); t.setStyleSheet(f"color:{T1};")
        n = self._iface.get("name","?")
        m = self._iface.get("mac","")
        s = QLabel(f"{n}  {m}"); s.setFont(mf(9)); s.setStyleSheet(f"color:{ACC};")
        vt.addWidget(t); vt.addWidget(s); tr.addLayout(vt,1); cl.addLayout(tr)

        # Connection status
        ssid = self._iface.get("connected_ssid","")
        if ssid:
            sl = QLabel(f"Connected to: {ssid}"); sl.setFont(mf(9))
            sl.setStyleSheet(f"color:{GRN};"); cl.addWidget(sl)

        # Auto-analyse note
        al = QLabel("Auto-analysing this interface for threats…")
        al.setFont(mf(8)); al.setStyleSheet(f"color:{T3};"); cl.addWidget(al)

        # Buttons
        br = QHBoxLayout(); br.setSpacing(6)
        a = QPushButton("Analyze"); a.setProperty("cls","primary")
        a.setFixedHeight(28); a.setFont(mf(9))
        a.clicked.connect(lambda: (self.analyze_sig.emit(self._iface), self.close()))
        br.addWidget(a)

        mm = QPushButton("Monitor mode"); mm.setFixedHeight(28); mm.setFont(mf(9))
        mm.setProperty("cls","warn")
        mm.setToolTip("Enable monitor mode to test deauth / beacon attacks")
        mm.clicked.connect(lambda: (self.monitor_mode_sig.emit(self._iface), self.close()))
        br.addWidget(mm)

        br.addStretch()
        dm = QPushButton("✕"); dm.setFixedHeight(28); dm.setFixedWidth(28); dm.setFont(mf(9))
        dm.clicked.connect(self.close); br.addWidget(dm)
        cl.addLayout(br)

        # Auto-dismiss bar
        self._dismiss_bar = QProgressBar(); self._dismiss_bar.setRange(0,100)
        self._dismiss_bar.setValue(100); self._dismiss_bar.setTextVisible(False)
        self._dismiss_bar.setFixedHeight(3)
        self._dismiss_bar.setStyleSheet(
            f"QProgressBar{{background:{BG4};border:none;border-radius:2px;}}"
            f"QProgressBar::chunk{{background:{ACC};border-radius:2px;}}")
        cl.addWidget(self._dismiss_bar)

        lay.addWidget(card)

    def _start_timer(self):
        self._countdown = 120   # 12 seconds at 100ms ticks
        self._timer = QTimer(self); self._timer.timeout.connect(self._tick)
        self._timer.start(100)

    def _tick(self):
        self._countdown -= 1
        self._dismiss_bar.setValue(int(self._countdown / 120 * 100))
        if self._countdown <= 0:
            self._timer.stop(); self.close()


# ─────────────────────────────────────────────────────────────────────────────
# Interface Hotplug Monitor Thread
# ─────────────────────────────────────────────────────────────────────────────
class InterfaceHotplugThread(QThread):
    """
    Polls for new wireless interfaces every 5 seconds.
    Emits new_iface(dict) when a previously unseen interface appears.
    """
    new_iface = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self._run   = False
        self._known: set = set()

    def run(self):
        self._run = True
        # Seed known set without emitting
        try:
            from core.backend import list_wireless_interfaces
            for i in list_wireless_interfaces():
                self._known.add(i["name"])
        except Exception:
            pass

        while self._run:
            self.msleep(5000)
            try:
                from core.backend import list_wireless_interfaces
                current = list_wireless_interfaces()
                for iface in current:
                    if iface["name"] not in self._known and iface["name"] != "auto":
                        self._known.add(iface["name"])
                        self.new_iface.emit(iface)
            except Exception:
                pass

    def stop(self):
        self._run = False; self.quit(); self.wait(2000)
