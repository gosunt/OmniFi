"""
OmniFi Panel — Live Threat Feed
Continuously receives alert dicts and renders AlertItem cards.
Supports level filtering and clearing.
"""
import re
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QFrame, QDialog,
)
from PyQt6.QtCore import Qt, pyqtSignal

from ui.theme          import BG1, BG2, BG3, B1, T1, T2, T3, T4, ACC, rgba, mf, sf
from ui.widgets.alert_item import AlertItem


class FeedPanel(QWidget):
    """
    Live scrollable alert feed.
    add_alert(alert_dict) can be called from any thread via Qt signal.
    """
    # re-emitted so MainWindow can wire to enforcement logic
    action_sig = pyqtSignal(str, dict)

    def __init__(self, is_admin_fn, safe_mode_fn, parent=None):
        """
        is_admin_fn  : callable() → bool
        safe_mode_fn : callable() → bool
        """
        super().__init__(parent)
        self._is_admin_fn  = is_admin_fn
        self._safe_mode_fn = safe_mode_fn
        self._alerts       = []
        self._filt         = "all"
        self._build()

    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        # ── Toolbar ───────────────────────────────────────────────────────────
        tb = QFrame(); tb.setFixedHeight(44)
        tb.setStyleSheet(f"background:{BG2}; border-bottom:1px solid {B1};")
        tbl = QHBoxLayout(tb)
        tbl.setContentsMargins(16, 0, 16, 0); tbl.setSpacing(8)

        title = QLabel("Live Threat Feed"); title.setFont(sf(12, bold=True))
        tbl.addWidget(title)

        self._cnt = QLabel("0 events"); self._cnt.setFont(mf(9))
        self._cnt.setStyleSheet(
            f"color:{T3}; background:{BG3}; border:1px solid {B1};"
            f"border-radius:3px; padding:1px 8px;")
        tbl.addWidget(self._cnt)
        tbl.addStretch()

        # Level filter buttons
        self._fbtns = {}
        for lvl in ("all","critical","high","medium","low"):
            b = QPushButton(lvl.title()); b.setFont(mf(9))
            b.setFixedHeight(26); b.setCheckable(True); b.setChecked(lvl == "all")
            b.clicked.connect(lambda _, l=lvl: self._set_filter(l))
            tbl.addWidget(b); self._fbtns[lvl] = b

        clr = QPushButton("Clear"); clr.setFont(mf(9)); clr.setFixedHeight(26)
        clr.clicked.connect(self.clear); tbl.addWidget(clr)
        lay.addWidget(tb)

        # ── Scroll area ───────────────────────────────────────────────────────
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._fw = QWidget(); self._fl = QVBoxLayout(self._fw)
        self._fl.setContentsMargins(12, 10, 12, 10); self._fl.setSpacing(5)

        self._empty_lbl = QLabel("✓  No threats detected.  Monitoring is active.")
        self._empty_lbl.setFont(mf(10))
        self._empty_lbl.setStyleSheet(f"color:{T3};")
        self._empty_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._fl.addWidget(self._empty_lbl)
        self._fl.addStretch()

        scroll.setWidget(self._fw)
        lay.addWidget(scroll, 1)

    # ── public API ────────────────────────────────────────────────────────────
    def add_alert(self, alert: dict) -> None:
        self._alerts.insert(0, alert)
        if self._filt == "all" or alert.get("level") == self._filt:
            self._add_card(alert, prepend=True)
        self._cnt.setText(f"{len(self._alerts)} events")
        self._empty_lbl.setVisible(False)

    def load_history(self, alerts: list) -> None:
        for a in reversed(alerts):
            self.add_alert(a)

    def clear(self) -> None:
        self._alerts.clear()
        while self._fl.count() > 2:
            item = self._fl.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._empty_lbl.setVisible(True)
        self._cnt.setText("0 events")

    # ── internals ─────────────────────────────────────────────────────────────
    def _add_card(self, alert: dict, prepend: bool = False) -> None:
        card = AlertItem(
            alert,
            is_admin  = self._is_admin_fn(),
            safe_mode = self._safe_mode_fn(),
        )
        card.action_sig.connect(self._on_action)
        if prepend:
            self._fl.insertWidget(0, card)
        else:
            self._fl.addWidget(card)

    def _on_action(self, action: str, alert: dict) -> None:
        self.action_sig.emit(action, alert)

    def _set_filter(self, lvl: str) -> None:
        self._filt = lvl
        for l, b in self._fbtns.items():
            b.setChecked(l == lvl)
        # Re-render with filter
        while self._fl.count() > 2:
            item = self._fl.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        filtered = (self._alerts if lvl == "all"
                    else [a for a in self._alerts if a.get("level") == lvl])
        for a in filtered:
            self._add_card(a)
