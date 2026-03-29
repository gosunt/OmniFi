"""
OmniFi Panel — Threat Detection Modules
All 12 detection modules displayed as clickable instrument cards.
Each card shows: name · status · last result · run button.
"""
import datetime
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QFrame, QGridLayout, QTextEdit, QGroupBox,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui  import QColor, QFont
from ui.theme     import (
    BG0, BG1, BG2, BG3, BG4, B1, B2, T1, T2, T3, T4,
    ACC, GRN, YLW, RED, ORG, PUR,
    LVL_C, rgba, mf, sf,
)
try:
    from ui.theme import PINK
except ImportError:
    PINK = "#f472b6"   # fallback if PINK not in theme


# ── Detection module runner thread ────────────────────────────────────────────
class _RunThread(QThread):
    result = pyqtSignal(str, dict)   # module_id, result_dict

    def __init__(self, module_id: str, fn):
        super().__init__()
        self._id = module_id
        self._fn = fn

    def run(self):
        try:
            out = self._fn()
            self.result.emit(self._id, out if isinstance(out,dict) else {"raw":str(out)})
        except Exception as e:
            self.result.emit(self._id, {"error": str(e)})


# ── Single module card ────────────────────────────────────────────────────────
class ModuleCard(QFrame):
    """
    Instrument card for one detection module.
    Shows icon · name · description · status dot · last result line ·
    "Run now" button.
    """
    run_clicked = pyqtSignal(str)   # module_id

    STATUS_C = {"active":GRN, "warn":YLW, "off":T3, "error":RED, "running":ACC}

    def __init__(self, module_id: str, icon: str, name: str,
                 description: str, color: str = ACC,
                 requires_root: bool = False,
                 requires_admin: bool = False,
                 parent=None):
        super().__init__(parent)
        self._id     = module_id
        self._status = "off"
        self._color  = color
        self.setObjectName("ModuleCard")
        self.setStyleSheet(f"""
            #ModuleCard {{
                background:{BG2}; border:1px solid {B1};
                border-top:3px solid {color};
                border-radius:8px;
            }}
            #ModuleCard:hover {{ border-color:{B2}; background:{BG3}; }}
        """)

        self._description = description  # stored for About panel, not shown here

        lay = QVBoxLayout(self); lay.setContentsMargins(14,12,14,12); lay.setSpacing(6)

        # Header
        hdr = QHBoxLayout(); hdr.setSpacing(8)
        ic  = QLabel(icon); ic.setFont(QFont("Segoe UI Emoji",16))
        ic.setStyleSheet(f"color:{color};"); hdr.addWidget(ic)
        nm  = QLabel(name); nm.setFont(sf(11, bold=True))
        nm.setStyleSheet(f"color:{T1};"); hdr.addWidget(nm, 1)
        self._dot = QLabel("●"); self._dot.setFont(mf(10))
        self._dot.setStyleSheet(f"color:{T3};"); hdr.addWidget(self._dot)
        lay.addLayout(hdr)

        # Badges for requirements
        br = QHBoxLayout(); br.setSpacing(5)
        if requires_root:
            rb = QLabel("Root/Admin"); rb.setFont(mf(8))
            rb.setStyleSheet(f"color:{YLW};background:{rgba(YLW,0.08)};"
                             f"border:1px solid {rgba(YLW,0.25)};border-radius:3px;padding:1px 5px;")
            br.addWidget(rb)
        if requires_admin:
            ab = QLabel("Admin mode"); ab.setFont(mf(8))
            ab.setStyleSheet(f"color:{PUR};background:{rgba(PUR,0.08)};"
                             f"border:1px solid {rgba(PUR,0.25)};border-radius:3px;padding:1px 5px;")
            br.addWidget(ab)
        br.addStretch(); lay.addLayout(br)

        # Last result line
        self._result_lbl = QLabel("Not yet run"); self._result_lbl.setFont(mf(9))
        self._result_lbl.setStyleSheet(
            f"color:{T2};background:{BG3};border-radius:4px;padding:4px 8px;")
        self._result_lbl.setWordWrap(True)
        lay.addWidget(self._result_lbl)

        # Run button
        run = QPushButton("▶  Run now"); run.setFont(mf(9)); run.setFixedHeight(28)
        run.setProperty("cls","primary")
        run.clicked.connect(lambda: self.run_clicked.emit(self._id))
        lay.addWidget(run)

    def set_status(self, status: str, result_text: str = "") -> None:
        self._status = status
        c = self.STATUS_C.get(status, T3)
        self._dot.setStyleSheet(f"color:{c};")
        if result_text:
            self._result_lbl.setText(result_text)
            self._result_lbl.setStyleSheet(
                f"color:{c};background:{BG3};border-radius:4px;padding:4px 8px;")

    def set_running(self) -> None:
        self._dot.setStyleSheet(f"color:{ACC};")
        self._result_lbl.setText("Running…")
        self._result_lbl.setStyleSheet(
            f"color:{ACC};background:{BG3};border-radius:4px;padding:4px 8px;")


# ── Panel ─────────────────────────────────────────────────────────────────────
class ThreatScanPanel(QWidget):
    """
    Grid of all detection module cards.
    Wires each card's run button to its backend function.
    """
    monitor_mode_needed = pyqtSignal(str, str)  # iface_name, test_key
    def __init__(self, backend, parent=None):
        super().__init__(parent)
        self._backend  = backend
        self._cards    = {}
        self._threads  = {}
        self._build()

    # ── build ─────────────────────────────────────────────────────────────────
    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 14, 18, 14)
        lay.setSpacing(12)

        # Header
        hdr = QHBoxLayout()
        tit = QLabel("Threat Detection Modules"); tit.setFont(sf(12, bold=True))
        hdr.addWidget(tit)
        hdr.addStretch()
        run_all = QPushButton("▶▶  Run all (safe modules)")
        run_all.setProperty("cls","primary"); run_all.setFixedHeight(30)
        run_all.clicked.connect(self._run_safe_modules)
        hdr.addWidget(run_all)
        lay.addLayout(hdr)

        # Module definitions
        MODULES = [
            # (id, icon, name, description, color, requires_root, requires_admin)
            ("arp_mitm",      "⚠", "ARP / MITM",
             "Gateway MAC watch, ARP flood detection, IP-MAC conflicts. "
             "Detects active poisoning without Scapy.",
             RED, False, False),
            ("dns_spoof",     "🌐","DNS Spoof",
             "DoH comparison against Cloudflare/Google, TTL anomaly, "
             "NXDOMAIN spike detection.",
             YLW, False, False),
            ("evil_twin",     "👥","Evil Twin",
             "BSSID/SSID mismatch, beacon analysis, BSSID history "
             "cross-check for rogue AP detection.",
             RED, False, False),
            ("deauth",        "⚡","Deauth Detector",
             "Scapy monitor-mode frame burst counting. "
             "Detects 802.11 deauthentication floods.",
             ORG, True, False),
            ("beacon_anomaly","📡","Beacon Anomaly",
             "Irregular beacon timing = rogue AP signal. "
             "Passive scan only — no active probe.",
             YLW, True, False),
            ("dhcp_rogue",    "🖧","Rogue DHCP",
             "Multiple DHCP servers = traffic hijack. "
             "Listens for DHCP offers on the subnet.",
             ORG, True, False),
            ("icmp_redirect", "↩","ICMP Redirect",
             "Forged ICMP type-5 silent rerouting detection. "
             "Monitors for unsolicited redirects.",
             YLW, False, False),
            ("captive_portal","🏨","Captive Portal",
             "Hotel/cafe portal HTTPS + JS injection check. "
             "Detects credential-harvesting login pages.",
             ACC, False, False),
            ("mac_spoof",    "🎭","MAC Spoof",
             "Detects if your adapter broadcasts real hardware MAC. "
             "Checks LA-bit — real MAC enables cross-network tracking.",
             ORG, False, False),
            ("session_hijack","🍪","Session Hijack",
             "Cleartext credentials + cookie flag check. "
             "Scans for unencrypted auth traffic.",
             RED, True, False),
            ("wifi_posture",  "🔐","Wi-Fi Posture",
             "Protocol, WPS state, signal quality, saved password strength. "
             "Full posture of connected network.",
             GRN, False, False),
            ("port_scan",     "🔍","Port Scanner",
             "Pure-Python TCP connect scan on gateway. "
             "Detects FTP, Telnet, UPnP, TR-069 exposure.",
             PUR, False, True),
            ("device_baseline","📊","Device Baseline",
             "Z-score behaviour anomaly on ARP-seen devices. "
             "Flags traffic spikes vs historical baseline.",
             PUR, False, True),
        ]

        # 3-column responsive grid
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        grid_w = QWidget(); grid_l = QGridLayout(grid_w)
        grid_l.setSpacing(10)

        for i, (mid, icon, name, desc, color, req_root, req_admin) in enumerate(MODULES):
            card = ModuleCard(mid, icon, name, desc, color, req_root, req_admin)
            card.run_clicked.connect(self._run_module)
            grid_l.addWidget(card, i // 3, i % 3)
            self._cards[mid] = card

        scroll.setWidget(grid_w); lay.addWidget(scroll, 1)

        # Output log
        log_g = QGroupBox("Module Output"); log_l = QVBoxLayout(log_g)
        self._output = QTextEdit(); self._output.setReadOnly(True)
        self._output.setFont(mf(9)); self._output.setFixedHeight(150)
        self._output.setStyleSheet(f"background:{BG0}; border:none;")
        log_l.addWidget(self._output)
        lay.addWidget(log_g)

    # ── runners ───────────────────────────────────────────────────────────────
    _MONITOR_MODE_MODULES = {"deauth", "beacon_anomaly", "dhcp_rogue", "session_hijack"}

    def _run_module(self, module_id: str) -> None:
        # Modules requiring monitor mode: prompt user first
        if module_id in self._MONITOR_MODE_MODULES:
            iface = "auto"
            if self._backend and hasattr(self._backend, "selected_iface"):
                iface = self._backend.selected_iface
            # Check if already in monitor mode
            from ui.dialogs_monitor import check_monitor_mode
            in_mon = check_monitor_mode(iface)
            if not in_mon:
                self.monitor_mode_needed.emit(iface, module_id)
                self._cards[module_id].set_status(
                    "warn",
                    "Monitor mode required — click the 📡 chip in the status bar "
                    "or use the prompt that appeared.")
                return
        fn = self._get_fn(module_id)
        if fn is None:
            self._cards[module_id].set_status("warn","Module not available on this platform.")
            return
        self._cards[module_id].set_running()
        t = _RunThread(module_id, fn)
        t.result.connect(self._on_result)
        self._threads[module_id] = t
        t.start()

    def _run_safe_modules(self) -> None:
        """Run all modules that don't require root/admin."""
        safe = ["arp_mitm","dns_spoof","evil_twin","captive_portal",
                "wifi_posture","icmp_redirect"]
        for mid in safe:
            QTimer.singleShot(
                safe.index(mid)*1200,
                lambda m=mid: self._run_module(m))

    def _on_result(self, module_id: str, result: dict) -> None:
        card = self._cards.get(module_id)
        if not card: return
        if result.get("error"):
            card.set_status("error", f"Error: {result['error'][:80]}")
            self._log(module_id, "error", result["error"])
        elif result.get("alerts"):
            alerts = result["alerts"]
            a0  = alerts[0]
            msg0 = a0.get("message","?") if isinstance(a0,dict) else str(a0)
            card.set_status("warn",
                f"{len(alerts)} alert(s): {str(msg0)[:60]}")
            for a in alerts[:3]:
                self._log(module_id, a.get("level","medium"), a.get("message",""))
                # Forward to alert engine if available
                try:
                    self._backend.monitor.emit_alert(
                        a.get("level","medium"), module_id,
                        a.get("message",""), a.get("detail",""))
                except Exception:
                    pass
        else:
            card.set_status("active", "✓ Clean — no anomalies detected")
            self._log(module_id, "ok", "Clean — no anomalies detected")

    def _log(self, source: str, level: str, msg: str) -> None:
        ts   = datetime.datetime.now().strftime("%H:%M:%S")
        c    = LVL_C.get(level, T2)
        html = (f'<span style="color:{T4}">{ts} </span>'
                f'<span style="color:{c}">[{source}]</span> '
                f'<span style="color:{T2}">{msg}</span><br>')
        cur = self._output.textCursor()
        cur.movePosition(cur.MoveOperation.Start)
        cur.insertHtml(html)

    # ── module function map ───────────────────────────────────────────────────
    def _get_fn(self, module_id: str):
        import sys, os
        omnifi_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "..", "omnifi")
        omnifi_path = os.path.normpath(omnifi_path)
        parent_path = os.path.dirname(omnifi_path)
        if parent_path not in sys.path:
            sys.path.insert(0, parent_path)

        fns = {
            "arp_mitm": lambda: self._run_arp(),
            "dns_spoof": lambda: self._run_dns(),
            "evil_twin": lambda: self._run_evil_twin(),
            "deauth": lambda: self._run_deauth(),
            "beacon_anomaly": lambda: self._run_beacon(),
            "dhcp_rogue": lambda: self._run_dhcp(),
            "icmp_redirect": lambda: self._run_icmp(),
            "captive_portal": lambda: self._run_captive(),
            "mac_spoof":      lambda: self._run_mac_spoof(),
            "session_hijack": lambda: self._run_session(),
            "wifi_posture": lambda: self._run_posture(),
            "port_scan": lambda: self._run_ports(),
            "device_baseline": lambda: self._run_baseline(),
        }
        return fns.get(module_id)

    def _run_arp(self) -> dict:
        try:
            from client_mode.arp_mitm import ARPMITMDetector
            d = ARPMITMDetector(verbose=False)
            r = d._check_arp_table()
            alerts = d.alerts
            return {"alerts": alerts, "result": r}
        except Exception as e:
            return {"error": str(e)}

    def _run_dns(self) -> dict:
        try:
            from client_mode.dns_spoof import DNSSpoofDetector
            d = DNSSpoofDetector(verbose=False)
            r = d._check_doh_comparison()
            return {"alerts": d.alerts, "result": r}
        except Exception as e:
            return {"error": str(e)}

    def _run_evil_twin(self) -> dict:
        try:
            from client_mode.bssid_history import BSSIDHistoryTracker
            t = BSSIDHistoryTracker(verbose=False)
            r = t.check_current_network()
            if r.get("evil_twin"):
                alerts = [{"level":"critical",
                           "message":r.get("message","Evil twin detected")}]
            else:
                alerts = []
            return {"alerts": alerts, "result": r}
        except Exception as e:
            return {"error": str(e)}

    def _run_deauth(self) -> dict:
        try:
            from client_mode.deauth_detector import DeauthDetector
            d = DeauthDetector(verbose=False)
            r = d.run(capture_seconds=10)
            return {"alerts": d.alerts, "result": r}
        except Exception as e:
            return {"error": str(e)}

    def _run_beacon(self) -> dict:
        try:
            from client_mode.beacon_anomaly import BeaconAnomalyDetector
            d = BeaconAnomalyDetector(verbose=False)
            r = d.run(capture_seconds=10)
            return {"alerts": d.alerts, "result": r}
        except Exception as e:
            return {"error": str(e)}

    def _run_dhcp(self) -> dict:
        try:
            from client_mode.dhcp_rogue import RogueDHCPDetector
            d = RogueDHCPDetector(verbose=False)
            r = d.run(capture_seconds=15)
            return {"alerts": d.alerts, "result": r}
        except Exception as e:
            return {"error": str(e)}

    def _run_icmp(self) -> dict:
        try:
            from client_mode.icmp_redirect import ICMPRedirectDetector
            d = ICMPRedirectDetector(verbose=False)
            r = d.check_static()
            return {"alerts": d.alerts, "result": r}
        except Exception as e:
            return {"error": str(e)}

    def _run_captive(self) -> dict:
        try:
            from client_mode.captive_portal import CaptivePortalDetector
            d = CaptivePortalDetector(verbose=False)
            r = d.run()
            # alerts live inside result dict, not on the object
            return {"alerts": r.get("alerts", []), "result": r}
        except Exception as e:
            return {"error": str(e)}

    def _run_session(self) -> dict:
        try:
            from client_mode.session_hijack import SessionHijackDetector
            d = SessionHijackDetector(verbose=False)
            r = d.run(capture_seconds=10)
            return {"alerts": d.alerts, "result": r}
        except Exception as e:
            return {"error": str(e)}

    def _run_posture(self) -> dict:
        try:
            from client_mode.wifi_posture import WiFiPostureScanner
            s = WiFiPostureScanner(verbose=False)
            r = s.run()
            # alerts already List[{level,message}] — no re-wrap
            return {"alerts": r.get("alerts", []), "result": r}
        except Exception as e:
            return {"error": str(e)}

    def _run_mac_spoof(self) -> dict:
        """
        Check if client adapter is using real hardware MAC (cross-platform, no root needed).
        Locally administered bit (bit1 of first octet) = randomised/spoofed MAC.
        """
        try:
            from client_mode.mac_privacy import MACRandomisationChecker
            c = MACRandomisationChecker(verbose=False)
            r = c.check()
            return {"alerts": r.get("alerts", []), "result": r}
        except Exception as e:
            return {"error": str(e)}

    def _run_ports(self) -> dict:
        from core.backend import gateway_ip, port_scan
        gw = gateway_ip()
        if not gw:
            return {"error": "Could not determine gateway IP"}
        ports  = port_scan(gw)
        alerts = [{"level":p["risk"],"message":f"Port {p['port']} ({p['service']}): {p['note']}"}
                  for p in ports if p["risk"] in ("critical","high")]
        return {"alerts": alerts, "ports": ports}

    def _run_baseline(self) -> dict:
        try:
            from admin_mode.device_baseline import DeviceBaselineMonitor
            m = DeviceBaselineMonitor(verbose=False)
            r = m.run_snapshot()
            alerts = [{"level":"high","message":a} for a in r.get("anomalies",[])]
            return {"alerts": alerts, "result": r}
        except Exception as e:
            return {"error": str(e)}
