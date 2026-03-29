"""
OmniFi — Eavesdropping Monitor Panel
=======================================
Hosts the EavesdropMonitor as a background QThread and displays
live events in a scrolling feed.

Features shown:
  • ARP cache poisoning events
  • Gateway MAC / IP change
  • Gratuitous ARP flood
  • Cleartext credentials detected
  • SSL stripping hint
  • Start / Stop toggle button
  • Severity-coloured event rows
  • Client vs Admin advice per event
"""
from __future__ import annotations

import time
from typing import Callable, List

from PyQt6.QtCore    import Qt, QThread, QTimer, pyqtSignal, QObject, pyqtSlot
from PyQt6.QtGui     import QColor, QFont
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QListWidget, QListWidgetItem,
    QSizePolicy,
)

from client_mode.eavesdrop_monitor import EavesdropMonitor, EavesdropEvent

# ─────────────────────────────────────────────────────────────────────────────
SEV_COLORS = {
    "critical": ("#f44336", "#2a0000"),
    "high":     ("#ff9800", "#2a1400"),
    "medium":   ("#ffeb3b", "#2a2200"),
    "low":      ("#80cbc4", "#001a18"),
}

CLIENT_ADVICE = {
    "arp_poison": "Disconnect immediately. Use a VPN. Avoid entering passwords until resolved.",
    "garp_flood": "Stop all sensitive activity. Someone is aggressively poisoning your ARP cache.",
    "cleartext":  "Avoid logging into any site over this network. Use HTTPS sites only.",
    "ssl_strip":  "A MITM attack may be downgrading your HTTPS. Use a VPN immediately.",
    "gw_change":  "Your default gateway changed unexpectedly. A rogue DHCP server may be active.",
}

ADMIN_ADVICE = {
    "arp_poison": "Isolate suspect MAC via Enforcement Panel → Blacklist. Check router ARP table.",
    "garp_flood": "Block the flooding MAC at the router level. Enable Dynamic ARP Inspection (DAI).",
    "cleartext":  "Enforce HTTPS-only policy on your network. Enable HSTS. Check proxy settings.",
    "ssl_strip":  "Enable 802.11w / PMF on the router. Deploy HSTS preloading site-wide.",
    "gw_change":  "Enable DHCP snooping on managed switches. Check for unauthorised DHCP servers.",
}


class _MonitorWorker(QObject):
    event_ready = pyqtSignal(object)   # EavesdropEvent
    finished    = pyqtSignal()

    def __init__(self, iface: str):
        super().__init__()
        self._mon = EavesdropMonitor(interface=iface, verbose=True)
        self._mon._on_event = self._forward

    def start_monitor(self):
        self._mon.start()

    def stop_monitor(self):
        self._mon.stop()
        self.finished.emit()

    def _forward(self, ev: EavesdropEvent):
        self.event_ready.emit(ev)


class EavesdropPanel(QWidget):

    def __init__(self, iface: str = "", is_admin_fn: Callable[[], bool] = None,
                 parent=None):
        super().__init__(parent)
        self._iface = iface
        self._is_admin_fn = is_admin_fn or (lambda: False)
        self._running = False
        self._thread: QThread | None = None
        self._worker: _MonitorWorker | None = None
        self._build_ui()

    # ── UI ────────────────────────────────────────────────────────────────────
    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        # Header
        hdr = QHBoxLayout()
        title = QLabel("👁  Eavesdropping & MITM Monitor")
        title.setStyleSheet("color:#e0eaff; font-weight:700; font-size:14px;")
        self._btn_toggle = QPushButton("▶ Start Monitor")
        self._btn_toggle.setFixedHeight(28)
        self._btn_toggle.setStyleSheet(
            "background:#003319; color:#00e676; border:1px solid #00c853; "
            "border-radius:5px; padding:0 14px; font-weight:600;")
        self._btn_toggle.clicked.connect(self._toggle)
        hdr.addWidget(title)
        hdr.addStretch()
        hdr.addWidget(self._btn_toggle)
        root.addLayout(hdr)

        # Status bar
        self._lbl_status = QLabel("⏹  Monitor stopped.")
        self._lbl_status.setStyleSheet(
            "color:#607090; font-size:10px; background:#101520; "
            "border-radius:4px; padding:4px 10px; border:1px solid #1e2840;")
        root.addWidget(self._lbl_status)

        # Requires root note
        self._root_note = QLabel(
            "⚠  Full packet-level detection requires root / Administrator privileges "
            "and Scapy. ARP table polling works without root.")
        self._root_note.setWordWrap(True)
        self._root_note.setStyleSheet(
            "color:#ff9800; font-size:9px; background:#2a1400; "
            "border-radius:4px; padding:4px 10px; border:1px solid #ff9800;")
        root.addWidget(self._root_note)

        sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color:#2a3550;")
        root.addWidget(sep)

        # Event list
        hdr2 = QHBoxLayout()
        hdr2.addWidget(QLabel("📋  Live Events"))
        hdr2.addStretch()
        btn_clear = QPushButton("Clear")
        btn_clear.setFixedHeight(22)
        btn_clear.setStyleSheet(
            "background:#1e2840; color:#607090; border-radius:4px; padding:0 10px;")
        btn_clear.clicked.connect(self._lw.clear if hasattr(self, '_lw') else lambda: None)
        root.addLayout(hdr2)

        self._lw = QListWidget()
        self._lw.setStyleSheet("""
            QListWidget { background:#0e1320; border:none; font-size:11px; }
            QListWidget::item { padding:6px; border-bottom:1px solid #1e2840; }
            QListWidget::item:selected { background:#1e3a60; }
        """)
        self._lw.setWordWrap(True)
        root.addWidget(self._lw, 1)
        btn_clear.clicked.connect(self._lw.clear)

        # Detail area
        root.addWidget(QLabel("💡  Advice"))
        self._advice = QLabel("Select an event for recommendations.")
        self._advice.setWordWrap(True)
        self._advice.setStyleSheet(
            "color:#a0b8d0; font-size:10px; background:#101928; "
            "border-radius:4px; padding:8px 12px; border:1px solid #1e2840;")
        root.addWidget(self._advice)

        self._lw.itemSelectionChanged.connect(self._on_select)

    # ── Logic ─────────────────────────────────────────────────────────────────
    def _toggle(self):
        if self._running:
            self._stop()
        else:
            self._start()

    def _start(self):
        self._thread = QThread()
        self._worker = _MonitorWorker(self._iface)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.start_monitor)
        self._worker.event_ready.connect(self._add_event)
        self._worker.finished.connect(self._thread.quit)
        self._thread.start()
        self._running = True
        self._btn_toggle.setText("⏹ Stop Monitor")
        self._btn_toggle.setStyleSheet(
            "background:#2a0000; color:#f44336; border:1px solid #f44336; "
            "border-radius:5px; padding:0 14px; font-weight:600;")
        self._lbl_status.setText("🟢  Monitoring for eavesdropping…")
        self._lbl_status.setStyleSheet(
            "color:#00e676; font-size:10px; background:#001a10; "
            "border-radius:4px; padding:4px 10px; border:1px solid #00c853;")

    def _stop(self):
        if self._worker:
            self._worker.stop_monitor()
        if self._thread:
            self._thread.quit()
            self._thread.wait(3000)
        self._running = False
        self._btn_toggle.setText("▶ Start Monitor")
        self._btn_toggle.setStyleSheet(
            "background:#003319; color:#00e676; border:1px solid #00c853; "
            "border-radius:5px; padding:0 14px; font-weight:600;")
        self._lbl_status.setText("⏹  Monitor stopped.")
        self._lbl_status.setStyleSheet(
            "color:#607090; font-size:10px; background:#101520; "
            "border-radius:4px; padding:4px 10px; border:1px solid #1e2840;")

    @pyqtSlot(object)
    def _add_event(self, ev: EavesdropEvent):
        ts_str = time.strftime("%H:%M:%S", time.localtime(ev.ts))
        fg, bg = SEV_COLORS.get(ev.severity, ("#ffffff", "#000000"))
        text = f"[{ts_str}]  {ev.message}"
        item = QListWidgetItem(text)
        item.setForeground(QColor(fg))
        item.setBackground(QColor(bg))
        item.setData(Qt.ItemDataRole.UserRole, ev)
        self._lw.insertItem(0, item)
        # Keep list manageable
        while self._lw.count() > 200:
            self._lw.takeItem(self._lw.count() - 1)

    def _on_select(self):
        items = self._lw.selectedItems()
        if not items:
            return
        ev: EavesdropEvent = items[0].data(Qt.ItemDataRole.UserRole)
        if ev is None:
            return
        is_adm = self._is_admin_fn()
        advice_map = ADMIN_ADVICE if is_adm else CLIENT_ADVICE
        advice = advice_map.get(ev.category, "Stay alert and consider disconnecting.")
        role = "Admin" if is_adm else "Client"
        detail = ev.detail or ""
        self._advice.setText(
            f"<b>[{role} Advice]</b>  {advice}"
            + (f"<br><span style='color:#607090;font-size:9px;'>{detail}</span>"
               if detail else ""))
