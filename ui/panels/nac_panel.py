"""
OmniFi — NAC (Network Access Control) Panel
=============================================
Shows:
  • Quarantined devices awaiting admin decision
  • Full device history (approved / blocked / quarantine)
  • One-click Approve / Block / Details buttons

Admin only — hides automatically when is_admin_fn() returns False.
"""
from __future__ import annotations

import time
from typing import Callable, List, Optional

from PyQt6.QtCore    import Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui     import QColor, QFont
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QFrame, QSplitter, QTextEdit, QMessageBox, QTabWidget,
)


def _age(ts: float) -> str:
    d = time.time() - ts
    if d < 60:
        return f"{int(d)}s ago"
    if d < 3600:
        return f"{int(d/60)}m ago"
    return f"{int(d/3600)}h ago"


STATE_COLORS = {
    "quarantine": "#ff9800",
    "approved":   "#00c853",
    "blocked":    "#f44336",
    "new":        "#90a4ae",
}


class NACPanel(QWidget):
    """
    Inject  nac_engine  (core.nac_engine.NACEngine) and
             is_admin_fn (callable → bool) after construction.
    """

    device_actioned = pyqtSignal(str, str)   # mac, action

    def __init__(self, parent=None):
        super().__init__(parent)
        self._nac = None
        self._is_admin_fn: Callable[[], bool] = lambda: False
        self._build_ui()

        self._timer = QTimer(self)
        self._timer.setInterval(10_000)
        self._timer.timeout.connect(self._refresh)
        self._timer.start()

    # ── Public ───────────────────────────────────────────────────────────────
    def set_nac(self, nac_engine) -> None:
        self._nac = nac_engine
        self._refresh()

    def set_is_admin(self, fn: Callable[[], bool]) -> None:
        self._is_admin_fn = fn

    # ── UI ────────────────────────────────────────────────────────────────────
    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        # ── Header ──
        hdr = QHBoxLayout()
        title = QLabel("🔒  Network Access Control")
        title.setStyleSheet("color:#e0eaff; font-weight:700; font-size:14px;")
        self._lbl_count = QLabel("0 quarantined")
        self._lbl_count.setStyleSheet(
            "color:#ff9800; font-size:11px; background:#2a1800; "
            "border-radius:4px; padding:2px 8px;")
        btn_refresh = QPushButton("⟳ Refresh")
        btn_refresh.setFixedHeight(26)
        btn_refresh.clicked.connect(self._refresh)
        btn_refresh.setStyleSheet(
            "background:#1e3050; color:#80aaff; border-radius:4px; padding:0 10px;")
        hdr.addWidget(title)
        hdr.addStretch()
        hdr.addWidget(self._lbl_count)
        hdr.addWidget(btn_refresh)
        root.addLayout(hdr)

        # ── Info banner ──
        banner = QLabel(
            "ℹ  New devices are automatically quarantined. "
            "Admin must Approve or Block each one.")
        banner.setWordWrap(True)
        banner.setStyleSheet(
            "color:#a0b0d0; font-size:10px; background:#151c2e; "
            "border-radius:4px; padding:6px 10px; border: 1px solid #2a3550;")
        root.addWidget(banner)

        # ── Tabs ──
        self._tabs = QTabWidget()
        self._tabs.setStyleSheet("""
            QTabBar::tab { background:#1a2030; color:#607090; padding:5px 14px;
                           border-radius:4px 4px 0 0; }
            QTabBar::tab:selected { background:#1e3050; color:#80aaff; }
        """)
        self._quarantine_tab = self._make_table_tab()
        self._history_tab    = self._make_table_tab()
        self._tabs.addTab(self._quarantine_tab, "⚠  Quarantined")
        self._tabs.addTab(self._history_tab,    "📋 All Devices")
        root.addWidget(self._tabs, 1)

        # ── Action buttons ──
        act = QHBoxLayout()
        self._btn_approve = self._action_btn("✔ Approve", "#00c853", "#003319")
        self._btn_block   = self._action_btn("✖ Block",   "#f44336", "#330000")
        self._btn_approve.clicked.connect(lambda: self._act("approve"))
        self._btn_block.clicked.connect(  lambda: self._act("block"))
        act.addWidget(self._btn_approve)
        act.addWidget(self._btn_block)
        act.addStretch()
        root.addLayout(act)

        self._lbl_admin = QLabel("⚠  Admin mode required for device actions.")
        self._lbl_admin.setStyleSheet("color:#ff9800; font-size:10px;")
        self._lbl_admin.hide()
        root.addWidget(self._lbl_admin)

    def _make_table_tab(self) -> QTableWidget:
        tbl = QTableWidget()
        tbl.setColumnCount(6)
        tbl.setHorizontalHeaderLabels(
            ["MAC", "IP", "Hostname / Vendor", "State", "First Seen", "Last Seen"])
        tbl.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        tbl.setAlternatingRowColors(True)
        tbl.verticalHeader().hide()
        tbl.setStyleSheet("""
            QTableWidget { background:#11161f; color:#c0d0f0;
                           gridline-color:#1e2840; font-size:11px; }
            QTableWidget::item:selected { background:#1e3a60; }
            QHeaderView::section { background:#1a2535; color:#80a0d0;
                                   padding:4px; border:none; }
            QTableWidget::item:alternate { background:#13192a; }
        """)
        return tbl

    @staticmethod
    def _action_btn(text: str, fg: str, bg: str) -> QPushButton:
        btn = QPushButton(text)
        btn.setFixedHeight(30)
        btn.setStyleSheet(
            f"background:{bg}; color:{fg}; border:1px solid {fg}; "
            f"border-radius:5px; padding:0 16px; font-weight:600;")
        return btn

    # ── Logic ─────────────────────────────────────────────────────────────────
    def _refresh(self):
        if not self._nac:
            return
        qdevs = self._nac.get_quarantined()
        alldevs = self._nac.get_all()

        self._lbl_count.setText(f"{len(qdevs)} quarantined")
        self._populate(self._quarantine_tab, qdevs)
        self._populate(self._history_tab, alldevs)

        is_adm = self._is_admin_fn()
        self._btn_approve.setEnabled(is_adm)
        self._btn_block.setEnabled(is_adm)
        self._lbl_admin.setVisible(not is_adm)

    def _populate(self, tbl: QTableWidget, devs: list):
        tbl.setRowCount(0)
        for dev in devs:
            r = tbl.rowCount(); tbl.insertRow(r)
            host_vendor = dev.hostname or dev.vendor or "—"
            color = STATE_COLORS.get(dev.state, "#ffffff")
            for c, val in enumerate([
                dev.mac, dev.ip, host_vendor, dev.state,
                _age(dev.first_seen), _age(dev.last_seen)
            ]):
                item = QTableWidgetItem(val)
                if c == 3:   # state column
                    item.setForeground(QColor(color))
                tbl.setItem(r, c, item)

    def _act(self, action: str):
        tbl = self._quarantine_tab
        sel = tbl.selectedItems()
        if not sel:
            QMessageBox.information(self, "Select Device",
                                    "Please select a quarantined device first.")
            return
        row = tbl.currentRow()
        mac = tbl.item(row, 0).text() if tbl.item(row, 0) else ""
        if not mac or not self._nac:
            return
        if action == "approve":
            self._nac.approve(mac, "approved via UI")
        elif action == "block":
            self._nac.block(mac, "blocked via UI")
        self.device_actioned.emit(mac, action)
        QTimer.singleShot(500, self._refresh)
