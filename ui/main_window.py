"""
OmniFi — Main Window (fixed)
All signal wiring goes through the ALERTS AlertEngine singleton,
not through backend.monitor which is a plain Python shim with no Qt signals.
"""
import sys, os, platform, re, datetime

import warnings
warnings.filterwarnings("ignore", message=".*TripleDES.*")
warnings.filterwarnings("ignore", category=DeprecationWarning, module=".*scapy.*")
try:
    from cryptography.utils import CryptographyDeprecationWarning as _CDW
    warnings.filterwarnings("ignore", category=_CDW)
except Exception:
    pass

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QStackedWidget, QFrame, QStatusBar, QDialog, QToolButton, QMessageBox,
    QApplication, QButtonGroup,
)
from PyQt6.QtCore  import Qt, QTimer, QThread, pyqtSignal, QSize, QPropertyAnimation, QEasingCurve
from PyQt6.QtGui   import QFont, QColor

from ui.theme import (
    APP_QSS, BG0, BG1, BG2, BG3, BG4, B1, B2, B3,
    ACC, ACC2, GRN, YLW, RED, ORG, PUR,
    T1, T2, T3, T4, LVL_C, VDT_C, rgba, mf, sf,
)
from ui.widgets.pulsing_badge import PulsingBadge, ModuleChip
from ui.widgets.score_ring    import ScoreRing
from ui.dialogs               import LoginDialog, SafeModeConfirm

from ui.panels.scanner_panel   import ScannerPanel
from ui.panels.feed_panel      import FeedPanel
from ui.panels.dashboard_panel import DashboardPanel
from ui.panels.devices_panel   import DevicesPanel
from ui.panels.policy_panel    import PolicyPanel
from ui.panels.router_panel    import RouterPanel
from ui.panels.settings_panel  import SettingsPanel
from ui.panels.about_panel       import AboutPanel
from ui.panels.router_mgmt_panel import RouterMgmtPanel
from ui.panels.enforcement_panel import EnforcementPanel
from ui.panels.adapter_panel     import AdapterPanel
from ui.panels.nac_panel         import NACPanel
from ui.panels.threat_scan_panel import ThreatScanPanel
from ui.panels.eavesdrop_panel   import EavesdropPanel
from ui.panels.dashboard_patch   import patch_dashboard
from ui.dialogs               import InterfaceDialog

WIN = platform.system() == "Windows"

# ── Monitor mode / hotplug imports ───────────────────────────────────────────
from ui.dialogs_monitor import (
    MonitorModeDialog, NewInterfaceToast, InterfaceHotplugThread,
)


# ── Sidebar nav button ────────────────────────────────────────────────────────
class NavBtn(QToolButton):
    def __init__(self, icon: str, tooltip: str, parent=None):
        super().__init__(parent)
        self.setText(icon); self.setToolTip(tooltip)
        # NOT checkable — we control active state manually via set_active()
        # so Qt never auto-toggles the button off when clicked again
        self.setCheckable(False)
        self.setFixedSize(46, 42)
        self.setFont(QFont("Segoe UI Emoji" if WIN else "Noto Color Emoji", 15))
        self.set_active(False)

    def set_active(self, v: bool):
        """Explicitly set the visual active state — called only by _goto."""
        if v:
            self.setStyleSheet(
                f"QToolButton{{background:{rgba(ACC,0.13)};color:{ACC};"
                f"border:none;border-radius:7px;"
                f"border-left:3px solid {ACC};}}")
        else:
            self.setStyleSheet(
                f"QToolButton{{background:none;color:{T3};"
                f"border:none;border-radius:7px;}}"
                f"QToolButton:hover{{background:{BG3};color:{T2};}}")


# ── Monitor thread ─────────────────────────────────────────────────────────────
class MonitorThread(QThread):
    """
    Adaptive continuous monitoring thread.
    - Polls each detector at its configured interval using time-based gating
    - Backs off to longer intervals when no threats are active (low-power mode)
    - Each detector runs only if its dependencies are available
    - No blocking: all calls are exception-safe with instant timeouts
    """
    devices_sig = pyqtSignal(list)
    status_sig  = pyqtSignal(dict)

    # Base poll intervals (seconds). Under threat → halved. Idle → doubled.
    # All 8 required attack-type detectors + infrastructure pollers
    # Intervals in seconds — adaptive multiplier applies at runtime
    BASE_POLL = {
        "arp":      30,   # ARP MITM
        "dns":     120,   # DNS Spoof
        "evil":     60,   # Evil Twin — BSSID history check
        "captive":  90,   # Captive Portal
        "icmp":    180,   # ICMP Redirect (static check)
        "mac":     300,   # MAC Spoof — changes rarely
        "dhcp":    150,   # Rogue DHCP — scans for multiple DHCP servers
        "devices":  60,   # Device inventory
        "nets":    180,   # Network rescan
        "rogue_ap":240,   # Rogue AP — OUI/BSSID/signal cross-check
    }

    def __init__(self, backend):
        super().__init__()
        self._b         = backend
        self._run       = False
        self._t0        = 0
        self._threat_ct = 0   # recent threat count — adjusts poll speed

    def run(self):
        import time
        self._run = True
        self._t0  = time.time()
        timers    = {k: 0.0 for k in self.BASE_POLL}  # 0 = run immediately

        self._b.monitor.emit_alert(
            "low", "monitor", "OmniFi monitoring active",
            f"Platform:{platform.system()}  "
            f"scapy:{self._b.caps.get('scapy',False)}  "
            f"pywifi:{self._b.caps.get('pywifi',False)}")

        while self._run:
            now = time.time()
            # Adaptive multiplier: threats → faster, idle → slower
            mult = 0.5 if self._threat_ct > 2 else (2.0 if self._threat_ct == 0 else 1.0)

            for key, base in self.BASE_POLL.items():
                interval = max(10, base * mult)
                if now - timers[key] >= interval:
                    timers[key] = now
                    getattr(self, f"_do_{key}")()

            self._b.policy.clean_expired()
            self.status_sig.emit({
                "uptime": int(time.time() - self._t0),
                "rates":  self._b.monitor.spike.rates(),
                "corr":   len(self._b.monitor.corr.all_found()),
            })
            # Adaptive sleep: shorter under threat, longer when idle
            sleep_ms = 3000 if self._threat_ct > 0 else 8000
            self.msleep(sleep_ms)

    def stop_mon(self):
        self._run = False; self.wait(3000)

    def _inc_threat(self):
        self._threat_ct = min(10, self._threat_ct + 1)

    def _dec_threat(self):
        self._threat_ct = max(0, self._threat_ct - 1)

    # ── detection calls ───────────────────────────────────────────────────────
    def _do_arp(self):
        try:
            from client_mode.arp_mitm import ARPMITMDetector
            det = ARPMITMDetector(verbose=False)
            res = det.run()
            alerts = res.get("alerts", [])
            if alerts: self._inc_threat()
            else:      self._dec_threat()
            for alert in alerts:
                self._b.monitor.emit_alert(
                    alert.get("level","high"), "arp_monitor",
                    alert.get("message","ARP anomaly"),
                    alert.get("detail",""),
                    ["block","vpn","investigate","ignore"],
                    signals=["arp_mitm"])
        except Exception as e:
            self._b.monitor.emit_alert("low","arp_monitor",f"ARP check skipped: {e}")

    def _do_dns(self):
        try:
            from client_mode.dns_spoof import DNSSpoofDetector
            det = DNSSpoofDetector(verbose=False)
            res = det.run()
            alerts = res.get("alerts", [])
            if alerts: self._inc_threat()
            else:      self._dec_threat()
            for alert in alerts:
                self._b.monitor.emit_alert(
                    alert.get("level","high"), "dns_spoof",
                    alert.get("message","DNS anomaly"),
                    alert.get("detail",""),
                    ["vpn","investigate","ignore"],
                    signals=["dns_spoof"])
        except Exception as e:
            self._b.monitor.emit_alert("low","dns_spoof",f"DNS check skipped: {e}")

    def _do_evil(self):
        """Evil Twin — BSSID/SSID history cross-check. No root needed."""
        try:
            from client_mode.bssid_history import BSSIDHistoryTracker
            t = BSSIDHistoryTracker(verbose=False)
            r = t.check_current_network()
            if r.get("evil_twin"):
                self._inc_threat()
                self._b.monitor.emit_alert(
                    "critical", "evil_twin",
                    r.get("message", "Evil twin detected"),
                    f"SSID:{r.get('ssid','')}  BSSID:{r.get('bssid','')}",
                    ["vpn","investigate","ignore"],
                    signals=["evil_twin"])
            else:
                self._dec_threat()
        except Exception as e:
            self._b.monitor.emit_alert("low","evil_twin",f"Evil twin check skipped: {e}")

    def _do_captive(self):
        """Captive Portal — HTTP probe. Works anywhere without root."""
        try:
            from client_mode.captive_portal import CaptivePortalDetector
            d = CaptivePortalDetector(verbose=False)
            r = d.run()
            alerts = r.get("alerts", [])
            if alerts:
                self._inc_threat()
                for a in alerts:
                    self._b.monitor.emit_alert(
                        a.get("level","high"), "captive_portal",
                        a.get("message","Captive portal anomaly"),
                        "", ["vpn","investigate","ignore"],
                        signals=["captive_portal"])
            else:
                self._dec_threat()
        except Exception as e:
            self._b.monitor.emit_alert("low","captive_portal",f"Captive check skipped: {e}")

    def _do_icmp(self):
        """ICMP Redirect — static OS-level check. No root needed."""
        try:
            from client_mode.icmp_redirect import ICMPRedirectDetector
            d = ICMPRedirectDetector(verbose=False)
            r = d.check_static()
            alerts = r.get("alerts", [])
            if alerts:
                self._inc_threat()
                for a in alerts:
                    self._b.monitor.emit_alert(
                        a.get("level","high"), "icmp_redirect",
                        a.get("message","ICMP redirect detected"),
                        "", ["vpn","investigate","ignore"],
                        signals=["icmp_redirect"])
            else:
                self._dec_threat()
        except Exception as e:
            self._b.monitor.emit_alert("low","icmp_redirect",f"ICMP check skipped: {e}")

    def _do_mac(self):
        """MAC Spoof — check adapter broadcasts real hardware MAC. No root."""
        try:
            from client_mode.mac_privacy import MACRandomisationChecker
            c = MACRandomisationChecker(verbose=False)
            r = c.check()
            for a in r.get("alerts", []):
                self._b.monitor.emit_alert(
                    a.get("level","medium"), "mac_privacy",
                    a.get("message","Real hardware MAC exposed"),
                    "", ["investigate","ignore"],
                    signals=["la_mac"])
        except Exception as e:
            self._b.monitor.emit_alert("low","mac_privacy",f"MAC check skipped: {e}")

    def _do_dhcp(self):
        """Rogue DHCP — passive check without long Scapy capture.
        Uses quick ARP + gateway comparison to detect gateway mismatch."""
        try:
            import subprocess, platform as _plt, re as _re
            result = {}
            gw = ""
            if _plt.system() == "Windows":
                o = subprocess.check_output(
                    ["ipconfig"], text=True, encoding="utf-8",
                    errors="ignore", stderr=subprocess.DEVNULL)
                m = _re.search(r"Default Gateway.*?:\s*([\d.]+)", o)
                gw = m.group(1) if m else ""
                # Check DHCP server field
                dm = _re.search(r"DHCP Server.*?:\s*([\d.]+)", o)
                dhcp_srv = dm.group(1) if dm else ""
            else:
                try:
                    o = subprocess.check_output(
                        ["ip","route"], text=True, stderr=subprocess.DEVNULL)
                    m = _re.search(r"default via ([\d.]+)", o)
                    gw = m.group(1) if m else ""
                    # Try nmcli for DHCP server
                    o2 = subprocess.check_output(
                        ["nmcli","dev","show"], text=True, stderr=subprocess.DEVNULL)
                    dm = _re.search(r"IP4\.GATEWAY:\s*([\d.]+)", o2)
                    dhcp_srv = dm.group(1) if dm else ""
                except Exception:
                    gw = ""; dhcp_srv = ""
            if dhcp_srv and gw and dhcp_srv != gw:
                msg = (f"DHCP server ({dhcp_srv}) differs from default gateway "
                       f"({gw}) — possible rogue DHCP server!")
                self._inc_threat()
                self._b.monitor.emit_alert(
                    "critical", "dhcp_rogue", msg,
                    f"DHCP={dhcp_srv}  GW={gw}",
                    ["vpn","investigate","ignore"],
                    signals=["rogue_dhcp"])
            else:
                self._dec_threat()
        except Exception as e:
            self._b.monitor.emit_alert("low","dhcp_rogue",f"DHCP check skipped: {e}")

    def _do_devices(self):
        devs = []
        # Try OUI-enriched scan first
        try:
            from admin_mode.oui_lookup import OUILookup
            lookup = OUILookup()
            table  = self._arp_table()
            for ip, mac in table.items():
                vendor = lookup.lookup(mac) if hasattr(lookup,'lookup') else ""
                la     = bool(int(mac.split(":")[0].replace("-",""),16) & 0x02)
                devs.append({"mac":mac,"ip":ip,"vendor":vendor,
                             "status":"suspect" if la else "unknown",
                             "hostname":"","device_type":"","os_guess":""})
        except Exception:
            # Plain ARP table fallback
            try:
                table = self._arp_table()
                for ip, mac in table.items():
                    la = bool(int(mac.split(":")[0].replace("-",""),16) & 0x02)
                    devs.append({"mac":mac,"ip":ip,"vendor":"",
                                 "status":"suspect" if la else "unknown",
                                 "hostname":"","device_type":"","os_guess":""})
            except Exception:
                pass
        if devs:
            self.devices_sig.emit(devs)

    def _do_nets(self):
        try:
            nets = self._b.scan_now()
            # Nets go via scanner panel's own refresh, not a direct signal here
            # (scanner calls scan_now on its own thread)
        except Exception:
            pass

    def _do_rogue_ap(self):
        try:
            from client_mode.rogue_ap import RogueAPDetector, ap_records_from_scan
            from core.backend import scan_wifi
            nets = scan_wifi()
            if nets:
                records = ap_records_from_scan(nets)
                RogueAPDetector().run(records)
        except Exception as _e:
            pass

    @staticmethod
    def _arp_table() -> dict:
        import subprocess, re as _re
        result = {}
        try:
            if platform.system() == "Windows":
                o = subprocess.check_output(
                    ["arp","-a"], text=True, encoding="utf-8",
                    errors="ignore", stderr=subprocess.DEVNULL)
                for m in _re.finditer(r"([\d.]+)\s+([\w-]{17})", o):
                    mac = m.group(2).replace("-",":").upper()
                    if mac not in ("FF:FF:FF:FF:FF:FF","00:00:00:00:00:00"):
                        result[m.group(1)] = mac
            else:
                o = subprocess.check_output(
                    ["arp","-n"], text=True, stderr=subprocess.DEVNULL)
                for m in _re.finditer(r"([\d.]+)\s+\S+\s+([\w:]{17})", o):
                    mac = m.group(2).upper()
                    if mac not in ("FF:FF:FF:FF:FF:FF","00:00:00:00:00:00"):
                        result[m.group(1)] = mac
        except Exception:
            pass
        return result


# ── Main Window ────────────────────────────────────────────────────────────────
class MainWindow(QMainWindow):
    def __init__(self, backend):
        super().__init__()
        self._b       = backend
        self._uptime  = 0
        self._threats = 0
        self._monitor = MonitorThread(backend)

        self.setWindowTitle("OmniFi — Hybrid Wi-Fi Security System")
        self.setMinimumSize(1200, 720)
        self.resize(1420, 840)
        self.setStyleSheet(APP_QSS)

        self._build_ui()
        self._build_menu()
        self._wire_signals()
        # Inject Bandwidth + Password Strength into dashboard
        try:
            patch_dashboard(self._dash, self._b)
        except Exception as _pe:
            log.debug(f'[MW] dashboard patch: {_pe}')

        self._ut = QTimer(self)
        self._ut.timeout.connect(self._tick_uptime)
        self._ut.start(1000)

        self._stack.setCurrentIndex(0)
        # No nav button for scanner (idx 0) — clear all highlights at start
        for b in self._nav_btns.values():
            b.set_active(False)
        QTimer.singleShot(200, self._detect_interfaces)
        # Start interface hotplug watcher
        self._hotplug = InterfaceHotplugThread()
        self._hotplug.new_iface.connect(self._on_new_iface)
        self._hotplug.start()

    # ══════════════════════════════════════════════════════════════════════════
    # Build UI
    # ══════════════════════════════════════════════════════════════════════════
    def _build_ui(self):
        cw   = QWidget(); self.setCentralWidget(cw)
        root = QVBoxLayout(cw)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._mk_monbar())

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        body.addWidget(self._mk_sidebar())

        self._stack = QStackedWidget()

        # 0 Scanner | 1 Feed | 2 Dashboard | 3 Devices | 4 Enforcement
        # 5 Adapters | 6 Policy | 7 Router | 8 Settings | 9 About
        self._scanner  = ScannerPanel(
            scan_fn        = self._b.scan_now,
            pwd_fn         = self._b.get_passwords,
            on_weak_pwd    = self._on_weak_pwd,
            auto_detect_fn = getattr(self._b, "auto_detect_router", None),
            login_fn       = self._b.login_admin,
            connect_fn     = self._b.wifi_connect,
            disconnect_fn  = self._b.wifi_disconnect,
            saved_pw_fn    = self._b.wifi_saved_password,
        )
        self._feed     = FeedPanel(
            is_admin_fn  = self._b.is_admin,
            safe_mode_fn = lambda: self._b.safe_mode,
        )
        self._dash     = DashboardPanel()
        self._devices  = DevicesPanel(
            scan_fn     = self._b.get_devices,
            is_admin_fn = self._b.is_admin,
        )
        self._enforce_panel = EnforcementPanel(
            is_admin_fn  = self._b.is_admin,
            safe_mode_fn = lambda: self._b.safe_mode,
        )
        self._adapter_panel = AdapterPanel(backend=self._b)
        self._policy   = PolicyPanel(
            is_admin_fn   = self._b.is_admin,
            get_policy_fn = self._b.get_policy,
        )
        self._router   = RouterPanel(
            audit_fn    = self._b.run_router_audit,
            cve_fn      = self._b.cve_lookup,
            is_admin_fn = self._b.is_admin,
        )
        self._settings = SettingsPanel(backend=self._b)
        self._about    = AboutPanel()

        self._router_mgmt = RouterMgmtPanel(backend=self._b)
        self._threat_scan = ThreatScanPanel(backend=self._b)
        self._nac_panel = NACPanel()
        self._nac_panel.set_is_admin(self._b.is_admin)
        self._eavesdrop_panel = EavesdropPanel(
            is_admin_fn = self._b.is_admin,
        )

        for panel in (self._scanner, self._feed, self._dash, self._devices,
                      self._enforce_panel, self._adapter_panel, self._policy,
                      self._router, self._settings, self._about,
                      self._router_mgmt, self._threat_scan,
                      self._nac_panel, self._eavesdrop_panel):
            self._stack.addWidget(panel)

        body.addWidget(self._stack, 1)
        root.addLayout(body, 1)

        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage("OmniFi ready — scanning networks…")

    # ── Monitor bar ────────────────────────────────────────────────────────────
    def _mk_monbar(self) -> QFrame:
        f = QFrame(); f.setFixedHeight(28)
        f.setStyleSheet(
            f"background:{rgba(ACC,0.04)}; border-bottom:1px solid {B1};")
        fl = QHBoxLayout(f)
        fl.setContentsMargins(16, 0, 16, 0); fl.setSpacing(10)
        lbl = QLabel("Monitoring"); lbl.setFont(mf(8))
        lbl.setStyleSheet(f"color:{T4}; letter-spacing:1px;")
        fl.addWidget(lbl)
        self._mod_chips = {}
        for name, st in [
            ("ARP", "active"), ("DNS", "active"), ("BSSID", "active"),
            ("Devices", "active"), ("Deauth", "warn"), ("DHCP", "active"),
            ("Session", "active"), ("Correlation", "active"), ("Time-based", "active"),
        ]:
            chip = ModuleChip(name, st)
            fl.addWidget(chip)
            self._mod_chips[name] = chip
        fl.addStretch()
        # Safe mode compact indicator in monbar
        self._sm_chip = QLabel("🛡 SAFE")
        self._sm_chip.setFont(mf(8))
        self._sm_chip.setStyleSheet(
            f"color:{YLW}; background:{rgba(YLW,0.08)};"
            f"border:1px solid {rgba(YLW,0.2)}; border-radius:3px; padding:1px 6px;"
            )
        self._sm_chip.setToolTip("Safe mode ON — click Settings to change")
        self._sm_chip.mousePressEvent = lambda _: self._goto(6)
        fl.addWidget(self._sm_chip)
        self._upl = QLabel("↑ 00:00:00")
        self._upl.setFont(mf(8))
        self._upl.setStyleSheet(f"color:{T4};")
        fl.addWidget(self._upl)
        return f

    # ── Sidebar ────────────────────────────────────────────────────────────────
    def _mk_sidebar(self) -> QFrame:
        sb = QFrame(); sb.setFixedWidth(54)
        sb.setStyleSheet(f"background:{BG1}; border-right:1px solid {B1};")
        sl = QVBoxLayout(sb)
        sl.setContentsMargins(4, 10, 4, 10); sl.setSpacing(3)
        self._nav_btns: dict = {}
        self._badge = PulsingBadge()
        for icon, tip, idx in [
            ("📡", "Live feed",    1), ("⬡",  "Dashboard",   2),
            ("▦",  "Devices",      3), ("🚨", "Enforcement", 4),
            ("📻", "Adapters",     5), ("🛡", "Policy",      6),
            ("◎",  "Router audit", 7), ("⚙",  "Settings",   8),
            ("ℹ",  "About",        9),
        ]:
            b = NavBtn(icon, tip)
            # Use a closure-captured idx so each button always calls _goto
            # with the correct index regardless of current state
            b.clicked.connect(lambda checked=False, i=idx: self._goto(i))
            sl.addWidget(b); self._nav_btns[idx] = b
        sl.addStretch()
        self._sb_ring = ScoreRing(40)
        self._sb_ring.set_score_instant(100, "safe")
        sl.addWidget(self._sb_ring)
        return sb

    # ── Menu ───────────────────────────────────────────────────────────────────
    def _build_menu(self):
        mb = self.menuBar()
        fm = mb.addMenu("File")
        fm.addAction("Quit", self.close)
        vm = mb.addMenu("View")
        for lbl, idx in [("Live feed",1),("Dashboard",2),("Devices",3),("Enforcement",4),("Adapters",5)]:
            vm.addAction(lbl, lambda i=idx: self._goto(i))
        tm = mb.addMenu("Tools")
        tm.addAction("Run threat scan",  lambda: self._goto(11))
        tm.addAction("ARP scan now",    lambda: self._devices.refresh())
        tm.addAction("Rescan networks", lambda: self._scanner.start_scan())
        tm.addAction("Clear alert feed",lambda: self._feed.clear())
        mm = mb.addMenu("Mode")
        mm.addAction("Switch mode / re-login", self._show_login)

    # ══════════════════════════════════════════════════════════════════════════
    # Signal wiring  ← THE KEY FIX
    # AlertEngine (ALERTS singleton) has the Qt signals new_alert / trust_changed.
    # backend.monitor is an AlertMonitor shim that *routes* to ALERTS but has no
    # signals of its own.  We import ALERTS here and connect directly.
    # ══════════════════════════════════════════════════════════════════════════
    def _wire_signals(self):
        # ── Connect to the ALERTS singleton (the real Qt signal source) ───────
        from core.alert_engine import ALERTS
        if ALERTS is not None:
            ALERTS.new_alert.connect(self._on_alert)
            ALERTS.trust_changed.connect(self._on_trust)

        # ── Monitor thread → panels ───────────────────────────────────────────
        self._monitor.devices_sig.connect(self._devices.update_devices)
        self._monitor.devices_sig.connect(self._dash.load_devices_on_map)
        self._monitor.devices_sig.connect(
            lambda devs: self._dash.update_device_count(len(devs)))
        self._monitor.status_sig.connect(self._on_status)

        # ── Scanner → login flow ──────────────────────────────────────────────
        self._scanner.proceed_sig.connect(self._after_scan)
        self._scanner.nets_ready.connect(self._on_scanner_nets_ready)
        # Wire password strength widget in dashboard
        self._scanner.nets_ready.connect(
            lambda nets: getattr(self._dash, 'on_nets_for_pwd', lambda n: None)(nets))
        self._scanner.connect_done.connect(self._on_wifi_connect_done)
        self._scanner.disconnect_done.connect(self._on_wifi_disconnect_done)
        self._settings.enforce_mode_changed.connect(self._on_enforce_mode_changed)
        self._settings.action_policy_changed.connect(self._on_action_policy_changed)
        self._settings.auto_threshold_changed.connect(self._on_auto_threshold_changed)
        self._settings.safe_mode_changed.connect(self._upd_sm_chip)

        # ── Feed action buttons → enforcement ─────────────────────────────────
        self._feed.action_sig.connect(self._on_feed_action)

        # ── Policy panel ──────────────────────────────────────────────────────
        self._policy.apply_sig.connect(self._on_policy_apply)
        # Adapter panel
        self._adapter_panel.adapter_selected.connect(self._on_adapter_selected)
        self._adapter_panel.monitor_enabled.connect(self._on_monitor_enabled)
        self._adapter_panel.monitor_disabled.connect(self._on_monitor_disabled)
        self._policy.remove_sig.connect(self._on_policy_remove)

        # ── Devices panel ─────────────────────────────────────────────────────
        self._devices.action_sig.connect(self._on_device_action)
        # Threat scan panel → monitor mode dialog
        self._enforce_panel.enforce_sig.connect(self._on_feed_action)
        # Threat scan panel → monitor mode dialog
        if hasattr(self._threat_scan, "monitor_mode_needed"):
            self._threat_scan.monitor_mode_needed.connect(
                lambda iface, key: self._show_monitor_mode_dialog(iface, key))

        # ── Settings ──────────────────────────────────────────────────────────
        self._settings.safe_mode_changed.connect(self._b.set_safe_mode)

    # ══════════════════════════════════════════════════════════════════════════
    # Slots
    # ══════════════════════════════════════════════════════════════════════════
    def _on_alert(self, alert: dict):
        self._feed.add_alert(alert)
        self._enforce_panel.add_threat(alert)
        self._badge.set_count(self._badge._n + 1)
        self._dash.log_event(alert["level"], alert["source"], alert["message"])
        if alert["level"] in ("critical", "high"):
            self._threats += 1
            self._dash.update_threat_count(self._threats)
        # Route correlation findings into dashboard correlation/timeline
        if alert.get("corr_data") and hasattr(self._dash, "timeline"):
            cd = alert["corr_data"]
            self._dash.timeline.add_event(
                alert["level"], "correlation",
                f"⚡ {cd.get('result','?')} ({cd.get('conf',0)}%)")
        # Update module status dot from alert source
        _MOD_MAP = {
            "arp_monitor":        "ARP / MITM",
            "dns_spoof":          "DNS Spoof",
            "evil_twin":          "Evil Twin",
            "monitor":            "Device Monitor",
            "deauth":             "Deauth",
            "beacon_anomaly":     "Beacon Anomaly",
            "dhcp_rogue":         "DHCP Rogue",
            "session_hijack":     "Session Hijack",
            "correlation_engine": "Correlation",
            "rogue_ap":           "Rogue AP",
            "eavesdrop":          "Eavesdrop",
            "nac":                "NAC",
            "time_detection":     "Time-based",
        }
        src = alert.get("source", "")
        if src in _MOD_MAP:
            st = "warn" if alert["level"] in ("critical","high") else "active"
            self._dash.set_module_status(_MOD_MAP[src], st)

        # ── Role-aware suggestions ─────────────────────────────────────────────
        # Admin: suggest router enforcement actions; Client: suggest protective actions
        lvl = alert.get("level", "low")
        if lvl in ("critical", "high") and self._b.is_admin():
            mac = self._extract_mac(
                alert.get("detail", "") + " " + alert.get("message", ""))
            if mac and mac != "UNKNOWN:MAC" and not self._b.safe_mode:
                # Auto-enforce only when above threshold and below safe_mode
                conf = alert.get("confidence", 80)
                if conf >= self._b.auto_threshold:
                    self._b.monitor.emit_alert(
                        "low", "auto_enforce",
                        f"Auto-enforce: {src} → blacklisting {mac}",
                        f"Confidence {conf}%  threshold {self._b.auto_threshold}%")
                    self._b.apply_policy(mac, "blacklist",
                                         reason=alert.get("message","")[:120])
        elif lvl in ("critical", "high") and not self._b.is_admin():
            # Client-mode: push a VPN-recommend toast to statusbar
            self.statusBar().showMessage(
                f"  ⚠ {alert['message'][:70]}  →  Recommend: enable VPN", 10000)

        self.statusBar().showMessage(
            f"  {alert['level'].upper()}: {alert['message'][:90]}", 7000)

    def _on_trust(self, score: int, verdict: str):
        # update_trust already calls trust_graph.add_point internally
        self._dash.update_trust(score, verdict)
        self._enforce_panel.update_trust(score)
        self._sb_ring.set_score(score, verdict)

    def _on_status(self, st: dict):
        self._dash.update_uptime(st.get("uptime", 0))
        self._dash.update_corr_count(st.get("corr", 0))
        rates = st.get("rates", {})
        for etype, mod in [
            ("arp","ARP / MITM"), ("dns","DNS Spoof"),
            ("dhcp_rogue","DHCP Rogue"), ("icmp_redirect","ICMP redirect"),
        ]:
            rate = rates.get(etype, 0)
            if   rate >= 8:  self._dash.set_module_status(mod, "error")
            elif rate >= 3:  self._dash.set_module_status(mod, "warn")
            else:            self._dash.set_module_status(mod, "active")

    def _on_weak_pwd(self, ssid: str, score: int, issues: list):
        self._b.monitor.emit_alert(
            "high", "password_checker",
            f"Weak saved password: '{ssid}'  (score {score}/100)",
            "; ".join(issues[:3]),
            ["change_password", "ignore"])

    def _on_wifi_connect_done(self, ok: bool, msg: str):
        if ok:
            self.statusBar().showMessage(f"  ✓ Wi-Fi connected  — {msg[:60]}", 6000)
            self._b.monitor.emit_alert("low","wifi_connect",
                "Wi-Fi connected", msg[:80])
        else:
            self.statusBar().showMessage(f"  ✗ Connection failed: {msg[:60]}", 8000)
            self._b.monitor.emit_alert("medium","wifi_connect",
                f"Connection failed: {msg[:80]}")

    def _on_wifi_disconnect_done(self, ok: bool, msg: str):
        self.statusBar().showMessage(
            f"  {'✓ Disconnected' if ok else '✗ Disconnect failed'}: {msg[:60]}", 5000)

    def _on_scanner_nets_ready(self, nets: list):
        """Push best/connected network posture into dashboard vector bars."""
        if not nets: return
        try:
            from core.backend import connected_ssid
            cur = connected_ssid()
            net = next((n for n in nets if n.get("ssid") == cur), nets[0])
        except Exception:
            net = nets[0]
        # Update posture vector bars from live scored network
        vectors = net.get("vectors", {})
        KEY_MAP = {
            "enc": "Encryption", "eviltwin": "No evil twin", "signal": "Signal",
            "pmf": "PMF / 802.11w", "wps": "WPS off",
            "isp": "DNS clean",   # best approximation for DNS health
            "congestion": "ARP clean",
        }
        from ui.theme import BG4, GRN, YLW, RED
        for key, bar_lbl in KEY_MAP.items():
            if key not in vectors or bar_lbl not in self._dash._vbars: continue
            v = vectors[key]; pts = v.get("pts",0); mx = v.get("max",1)
            pb, vl, _, _ = self._dash._vbars[bar_lbl]
            pb.setRange(0, mx); pb.setValue(pts)
            r = pts/mx if mx else 0
            c = GRN if r>=0.85 else YLW if r>=0.5 else RED
            pb.setStyleSheet(f"QProgressBar{{background:{BG4};border:none;border-radius:2px;}}"
                             f"QProgressBar::chunk{{background:{c};border-radius:2px;}}")
            vl.setText(f"{pts}/{mx}")
        self._dash.update_trust(net.get("score",100), net.get("verdict","safe"))

    # ── after scanner proceeds ────────────────────────────────────────────────
    def _after_scan(self, net: dict, mode: str = "client",
                    url: str = "", user: str = "", pwd: str = ""):
        """
        Called from ScannerPanel.proceed_sig (5 args: net, mode, url, user, pwd).

        Admin mode: RouterLoginDialog already tested credentials and called
        login_admin() successfully before emitting proceed_sig, so we only
        need to verify is_admin() is now True.

        Client mode: just start monitoring immediately.
        """
        # Sync backend mode flag
        self._b.mode = mode

        # For admin mode the dialog already called login_admin() with verified creds.
        # Double-check and warn if something went wrong (edge case).
        if mode == "admin" and not self._b.is_admin():
            if url and user and pwd:
                # Fallback: try once more in case dialog skipped the actual call
                self._b.login_admin(url, user, pwd)
            if not self._b.is_admin():
                QMessageBox.warning(
                    self, "Admin login",
                    "Admin credentials could not be verified.\n"
                    "Continuing in client mode — enforcement actions unavailable.")
        # Advertise router capabilities in status bar when admin
        # Wire NAC engine with router client when admin
        try:
            from core.nac_engine import NACEngine
            if not hasattr(self, "_nac_engine"):
                self._nac_engine = NACEngine()
                self._nac_panel.set_nac(self._nac_engine)
                self._nac_engine.start()
        except Exception:
            pass
        if self._b.is_admin():
            try:
                mgr = self._b.enforcer.get_config_manager()
                if mgr:
                    caps = mgr.get_capabilities()
                    self._dash.log_event("low","router",
                        f"Router capabilities detected: {', '.join(caps[:6])}")
            except Exception:
                pass
            # Enable router management panel
            if hasattr(self, "_router_mgmt"):
                self._router_mgmt.set_admin_mode(True)
        elif hasattr(self, "_router_mgmt"):
            self._router_mgmt.set_admin_mode(False)

        # Update safe-mode chip to reflect current state
        self._upd_sm_chip(self._b.safe_mode)

        # Start background monitoring thread
        if not self._monitor.isRunning():
            self._monitor.start()
        # Sync auto-enforce state to enforcement panel
        sm = self._b.safe_mode
        thresh = getattr(self._b,'auto_threshold',80)
        self._enforce_panel.update_auto_enforce(not sm, thresh)
        # Auto-probe adapters
        QTimer.singleShot(400, self._adapter_panel.refresh)

        # Load recent alert history into the live feed
        self._feed.load_history(self._b.get_alerts(hours=2))

        # Load trust score history into graph
        try:
            hist = self._b.get_trust_history(60)
            if hist:
                self._dash.trust_graph.load_history(hist)
        except Exception:
            pass

        # Navigate: show connected tab if network selected, else live feed
        if net and net.get("ssid"):
            self._scanner.show_connected_tab(net)
        else:
            self._goto(1)

    # ── enforcement ────────────────────────────────────────────────────────────
    def _on_feed_action(self, action: str, alert: dict):
        enforce = {"block","quarantine","isolate","whitelist","exception"}
        if action not in enforce: return
        mac = self._extract_mac(
            alert.get("detail","") + alert.get("message",""))
        self._enforce(mac, action)

    def _on_device_action(self, mac: str, action: str):
        _TM = {"block":"blacklist","isolate":"isolated",
               "trust":"whitelist","exception":"exception"}
        self._enforce(mac, _TM.get(action, "blacklist"))

    def _on_policy_apply(self, mac: str, ptype: str, reason: str, exp: int):
        self._enforce(mac, ptype, reason, exp)

    def _on_policy_remove(self, mac: str, ptype: str):
        if not self._b.is_admin(): return
        # Use real enforcer to also remove router/OS rules
        if hasattr(self._b, "remove_policy"):
            r = self._b.remove_policy(mac, ptype)
        else:
            self._b.policy.remove(mac, ptype)
        self._policy.refresh()

    def _enforce(self, mac: str, action: str, reason: str = "", exp: int = 0):
        if not self._b.is_admin():
            QMessageBox.information(
                self, "Admin required",
                "Enforcement actions require admin mode."); return
        if self._b.safe_mode:
            dlg = SafeModeConfirm(action, mac, self)
            if dlg.exec() != QDialog.DialogCode.Accepted: return
            # Use confirm_action which bypasses safe_mode check
            r = self._b.confirm_action(mac, action, reason, exp)
        else:
            r = self._b.apply_policy(mac, action, reason, exp)

        if r.get("ok"):
            self._policy.refresh()
            tier = r.get("tier", "db")
            tier_icons = {
                "router+os_firewall+arp": "🛡+🔥+📡",
                "router+os_firewall":     "🛡+🔥",
                "router+arp":             "🛡+📡",
                "os_firewall+arp":        "🔥+📡",
                "router":                 "🛡 Router",
                "os_firewall":            "🔥 Firewall",
                "arp":                    "📡 ARP",
                "db_only":                "📋 DB only",
                "whitelist":              "✅ Whitelist",
                "removed":                "↩ Removed",
            }
            tier_label = tier_icons.get(tier, tier)
            self.statusBar().showMessage(
                f"  ✓ {action.upper()} → {mac}  [{tier_label}]", 7000)
            # Log to policy panel enforcement log
            if hasattr(self._policy, "log_enforcement"):
                self._policy.log_enforcement(action, mac, tier, True)
            # Show enforcement detail dialog for critical actions
            if action in ("blacklist", "isolated") and r.get("detail"):
                self._show_enforce_result(action, mac, r)
        else:
            err = r.get("error", "Policy failed.")
            if hasattr(self._policy, "log_enforcement"):
                self._policy.log_enforcement(action, mac, "failed", False)
            QMessageBox.warning(self, "Enforcement failed", err)

    def _show_enforce_result(self, action: str, mac: str, r: dict):
        """Show a non-blocking enforcement result summary."""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QPushButton
        from PyQt6.QtCore import QTimer
        d = QDialog(self)
        d.setWindowTitle(f"Enforcement result — {action.upper()}")
        d.setMinimumWidth(420)
        lay = QVBoxLayout(d)
        lay.setContentsMargins(16,14,16,14); lay.setSpacing(8)
        from ui.theme import ACC, GRN, YLW, RED, T1, T2, BG2, B1, mf, sf, rgba
        hdr_text = f"✓  {action.upper()} applied to {mac}" if r.get("ok") else f"⚠  Partial enforcement — {mac}"
        hdr = QLabel(hdr_text); hdr.setFont(sf(11, bold=True))
        hdr.setStyleSheet(f"color:{GRN if r.get('ok') else YLW};")
        lay.addWidget(hdr)
        # Tier breakdown
        tiers = [
            ("🛡 Router MAC filter", r.get("router", False)),
            ("🔥 OS firewall rule",  r.get("os",     False)),
            ("📡 ARP isolation",     r.get("arp",    False)),
            ("📋 Policy database",   r.get("db",     True)),
        ]
        for label, ok in tiers:
            row = QHBoxLayout(); row.setSpacing(8)
            dot = QLabel("✓" if ok else "✗")
            dot.setFont(mf(10)); dot.setFixedWidth(18)
            dot.setStyleSheet(f"color:{GRN if ok else T2};")
            lbl = QLabel(label); lbl.setFont(mf(9))
            lbl.setStyleSheet(f"color:{T1 if ok else T2};")
            row.addWidget(dot); row.addWidget(lbl); row.addStretch()
            lay.addLayout(row)
        if r.get("detail"):
            te = QTextEdit(r["detail"].strip()); te.setReadOnly(True)
            te.setMaximumHeight(80); te.setFont(mf(8))
            te.setStyleSheet(f"background:{BG2}; color:{T2}; border:1px solid {B1}; border-radius:4px;")
            lay.addWidget(te)
        ok_btn = QPushButton("OK"); ok_btn.setFixedHeight(30)
        ok_btn.setProperty("cls","primary"); ok_btn.clicked.connect(d.accept)
        lay.addWidget(ok_btn)
        d.show()
        QTimer.singleShot(8000, d.close)

    @staticmethod
    def _extract_mac(text: str) -> str:
        m = re.search(r"([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}", text)
        return m.group(0).upper() if m else "UNKNOWN:MAC"

    # ── navigation ─────────────────────────────────────────────────────────────
    def _upd_sm_chip(self, on: bool):
        if on:
            self._sm_chip.setText("🛡 SAFE")
            self._sm_chip.setStyleSheet(
                f"color:{YLW}; background:{rgba(YLW,0.08)};"
                f"border:1px solid {rgba(YLW,0.2)}; border-radius:3px; padding:1px 6px;")
            self._sm_chip.setToolTip("Safe mode ON — click Settings to change")
        else:
            self._sm_chip.setText("⚡ UNSAFE")
            self._sm_chip.setStyleSheet(
                f"color:{RED}; background:{rgba(RED,0.08)};"
                f"border:1px solid {rgba(RED,0.2)}; border-radius:3px; padding:1px 6px;")
            self._sm_chip.setToolTip("Safe mode OFF — enforcement actions apply immediately")

    def _goto(self, idx: int):
        self._stack.setCurrentIndex(idx)
        # Always sync all button states — never rely on Qt's own check logic
        for i, b in self._nav_btns.items():
            b.set_active(i == idx)

    def _detect_interfaces(self):
        """Detect wireless interfaces; show selector if >1 found."""
        from core.backend import list_wireless_interfaces
        try:
            ifaces = list_wireless_interfaces()
        except Exception:
            ifaces = []
        real = [i for i in ifaces if i.get("name") != "auto"]
        # Auto-select if 0 or 1 real interface, or exactly 1 is active
        active = [i for i in real if i.get("is_active")]
        if len(real) <= 1 or len(active) == 1:
            chosen = active[0] if active else (real[0] if real else {"name": "auto"})
        else:
            dlg = InterfaceDialog(real, parent=self)
            dlg.exec()
            chosen = dlg.selected_iface  # dict
        selected = chosen.get("name", "auto") if isinstance(chosen, dict) else str(chosen)
        self._b.selected_iface = selected
        self.statusBar().showMessage(f"  Interface: {selected}  |  OmniFi ready", 5000)
        if hasattr(self._scanner, "set_interface"):
            self._scanner.set_interface(selected)
        QTimer.singleShot(300, self._scanner.start_scan)

    def _show_login(self):
        dlg = LoginDialog(
            auto_detect_fn=getattr(self._b, "auto_detect_router", None),
            parent=self,
        )
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self._b.mode = dlg.result_mode
            if dlg.result_mode == "admin":
                self._b.login_admin(dlg.result_url, dlg.result_user, dlg.result_pass)

    # ── uptime ─────────────────────────────────────────────────────────────────
    def _tick_uptime(self):
        self._uptime += 1
        h = self._uptime // 3600
        m = (self._uptime % 3600) // 60
        s = self._uptime % 60
        self._upl.setText(f"↑ {h:02d}:{m:02d}:{s:02d}")
        self._dash.update_uptime(self._uptime)

    # ── Enforcement mode / policy hooks ──────────────────────────────────────
    def _on_enforce_mode_changed(self, mode: str):
        """Sync backend safe_mode with UI enforce mode."""
        self._b.set_safe_mode(mode == "manual")
        self._upd_sm_chip(mode == "manual")
        thresh = getattr(self._b,'auto_threshold',80)
        self._enforce_panel.update_auto_enforce(mode == 'auto', thresh)

    def _on_action_policy_changed(self, action_type: str, policy_name: str):
        """Store per-action policy preference on backend."""
        if hasattr(self._b, "action_policies"):
            self._b.action_policies[action_type] = policy_name
        self._b.monitor.emit_alert(
            "low", "settings",
            f"Policy changed: {action_type} → {policy_name}", "")

    def _on_auto_threshold_changed(self, threshold: int):
        """Store auto-enforcement confidence threshold on backend."""
        if hasattr(self._b, "auto_threshold"):
            self._b.auto_threshold = threshold
        else:
            try: self._b.auto_threshold = threshold
            except: pass

    def _on_new_iface(self, iface: dict):
        """Show toast when a new wireless interface is hot-plugged."""
        toast = NewInterfaceToast(iface, self)
        toast.analyze_sig.connect(
            lambda i: (self._b.__setattr__("selected_iface", i.get("name","auto")),
                       self._scanner.set_interface(i.get("name","auto")),
                       self._scanner.start_scan()))
        toast.monitor_mode_sig.connect(self._show_monitor_mode_dialog)
        # Position bottom-right of main window
        geo = self.geometry()
        toast.move(geo.right() - 360, geo.bottom() - 180)
        toast.show()
        self._b.monitor.emit_alert(
            "low", "interface_monitor",
            f"New wireless interface detected: {iface.get('name','?')}",
            f"MAC: {iface.get('mac','')}  SSID: {iface.get('connected_ssid','')}",
        )

    def _show_monitor_mode_dialog(self, iface_or_dict=None, test_key: str = "deauth"):
        """
        Show monitor-mode dialog for a given interface.
        Can be called from:
          - NewInterfaceToast (passes iface dict)
          - Settings / threat scan panel (passes test_key string)
        """
        if isinstance(iface_or_dict, dict):
            iface_name = iface_or_dict.get("name", self._b.selected_iface)
        else:
            iface_name = getattr(self._b, "selected_iface", "auto")
            if isinstance(iface_or_dict, str):
                test_key = iface_or_dict
        dlg = MonitorModeDialog(iface_name, test_key, self)
        dlg.mode_enabled.connect(lambda iface: (
            self._b.monitor.emit_alert(
                "low", "monitor_mode",
                f"Monitor mode enabled on  {iface}",
                "Deauth and beacon detection now active."),
            self.statusBar().showMessage(
                f"  Monitor mode active on {iface}", 8000)))
        dlg.exec()

    # ── Adapter panel handlers ─────────────────────────────────────────────
    def _on_adapter_selected(self, iface: dict):
        name = iface.get('name','')
        self._b.selected_iface = name
        if hasattr(self._scanner, 'set_interface'):
            self._scanner.set_interface(name)
        self._b.monitor.emit_alert(
            'low','adapter',f'Active adapter changed to {name}','')
        self.statusBar().showMessage(f'  Adapter: {name}', 4000)

    def _on_monitor_enabled(self, name: str):
        self._b.monitor.emit_alert(
            'low','monitor_mode',
            f'Monitor mode enabled on {name}',
            'Deauth detection, beacon anomaly, and passive capture now active.')
        # Sync enforce panel auto-enforce indicator
        sm = self._b.safe_mode
        thresh = getattr(self._b,'auto_threshold',80)
        self._enforce_panel.update_auto_enforce(not sm, thresh)
        self.statusBar().showMessage(f'  Monitor mode active: {name}', 6000)

    def _on_monitor_disabled(self, name: str):
        self._b.monitor.emit_alert(
            'low','monitor_mode',
            f'Monitor mode disabled on {name} — restored to managed mode','')

    def closeEvent(self, ev):
        if hasattr(self, "_hotplug"):
            self._hotplug.stop()
        self._monitor.stop_mon()
        if hasattr(self._b, "stop"):
            self._b.stop()
        ev.accept()
