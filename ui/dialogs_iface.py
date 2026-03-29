"""
OmniFi — Wireless Interface Selector Dialog
Shown on startup when multiple wireless adapters are detected.
Auto-selects if only one active interface exists.
"""
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QButtonGroup, QRadioButton, QWidget,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui  import QFont

from ui.theme import (
    BG1, BG2, BG3, B1, B2, T1, T2, T3, T4,
    ACC, GRN, YLW, RED, ORG, rgba, mf, sf,
)

import platform
WIN = platform.system() == "Windows"


class InterfaceSelectorDialog(QDialog):
    """
    Presents detected wireless interfaces and lets the user pick one.
    .selected_iface → str  (interface name, or "" for auto)
    """

    def __init__(self, interfaces: list, parent=None):
        super().__init__(parent)
        self.selected_iface = ""
        self._ifaces = interfaces
        self.setWindowTitle("Select Wireless Interface")
        self.setMinimumWidth(440)
        self.setModal(True)
        self.setStyleSheet(f"""
            QDialog {{
                background: {BG1};
                border: 1px solid {B2};
                border-radius: 10px;
            }}
        """)
        self._build()

    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 20, 24, 20)
        lay.setSpacing(14)

        # Header
        hdr = QHBoxLayout(); hdr.setSpacing(10)
        ic = QLabel("📡")
        ic.setFont(QFont("Segoe UI Emoji" if WIN else "Noto Color Emoji", 20))
        hdr.addWidget(ic)
        vt = QVBoxLayout()
        t = QLabel("Select Wireless Interface")
        t.setFont(sf(13, bold=True)); t.setStyleSheet(f"color:{T1};")
        s = QLabel("Multiple Wi-Fi adapters detected — choose one to use for scanning.")
        s.setFont(mf(9)); s.setStyleSheet(f"color:{T3};"); s.setWordWrap(True)
        vt.addWidget(t); vt.addWidget(s)
        hdr.addLayout(vt, 1)
        lay.addLayout(hdr)

        div = QFrame(); div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet(f"color:{B1};"); lay.addWidget(div)

        # Interface cards
        self._bg = QButtonGroup(self)
        first_active = None

        for idx, iface in enumerate(self._ifaces):
            card = QFrame()
            active = iface.get("is_active", False)
            card.setStyleSheet(f"""
                QFrame {{
                    background: {BG2};
                    border: 1px solid {B2 if not active else rgba(ACC, 0.4)};
                    border-radius: 7px;
                }}
                QFrame:hover {{
                    border-color: {ACC};
                    background: {BG3};
                }}
            """)
            cl = QHBoxLayout(card); cl.setContentsMargins(14, 10, 14, 10); cl.setSpacing(12)

            rb = QRadioButton()
            rb.setStyleSheet(f"QRadioButton::indicator {{ width:16px; height:16px; }}")
            self._bg.addButton(rb, idx)
            cl.addWidget(rb)

            # Interface info
            info = QVBoxLayout(); info.setSpacing(2)
            name_row = QHBoxLayout(); name_row.setSpacing(8)
            nm = QLabel(iface["name"]); nm.setFont(sf(11, bold=True))
            nm.setStyleSheet(f"color:{T1};")
            name_row.addWidget(nm)

            if active:
                ab = QLabel("● Active"); ab.setFont(mf(8))
                ab.setStyleSheet(
                    f"color:{GRN}; background:{rgba(GRN,0.1)};"
                    f"border:1px solid {rgba(GRN,0.25)};"
                    f"border-radius:3px; padding:1px 6px;")
                name_row.addWidget(ab)
            if iface.get("connected_ssid"):
                sb = QLabel(iface["connected_ssid"]); sb.setFont(mf(8))
                sb.setStyleSheet(
                    f"color:{ACC}; background:{rgba(ACC,0.08)};"
                    f"border:1px solid {rgba(ACC,0.2)};"
                    f"border-radius:3px; padding:1px 6px;")
                name_row.addWidget(sb)
            name_row.addStretch()
            info.addLayout(name_row)

            if iface.get("mac"):
                mac_lbl = QLabel(iface["mac"]); mac_lbl.setFont(mf(8))
                mac_lbl.setStyleSheet(f"color:{T4};")
                info.addWidget(mac_lbl)

            cl.addLayout(info, 1)

            # Click card → select radio
            card.mousePressEvent = lambda ev, b=rb: b.setChecked(True)
            lay.addWidget(card)

            if active and first_active is None:
                first_active = idx
                rb.setChecked(True)

        # If no active found, select first
        if first_active is None and self._ifaces:
            self._bg.button(0).setChecked(True)

        div2 = QFrame(); div2.setFrameShape(QFrame.Shape.HLine)
        div2.setStyleSheet(f"color:{B1};"); lay.addWidget(div2)

        # Buttons
        btns = QHBoxLayout(); btns.setSpacing(8)
        auto_btn = QPushButton("Auto-select"); auto_btn.setFont(mf(9))
        auto_btn.setFixedHeight(32)
        auto_btn.clicked.connect(self._auto_select)
        btns.addWidget(auto_btn)
        btns.addStretch()
        ok_btn = QPushButton("Use Selected Interface")
        ok_btn.setProperty("cls", "primary"); ok_btn.setFont(mf(9))
        ok_btn.setFixedHeight(32); ok_btn.clicked.connect(self._confirm)
        btns.addWidget(ok_btn)
        lay.addLayout(btns)

    def _confirm(self):
        idx = self._bg.checkedId()
        if idx >= 0 and idx < len(self._ifaces):
            self.selected_iface = self._ifaces[idx]["name"]
        self.accept()

    def _auto_select(self):
        # Pick first connected, else first in list
        for i, iface in enumerate(self._ifaces):
            if iface.get("is_active"):
                self.selected_iface = iface["name"]
                self.accept(); return
        if self._ifaces:
            self.selected_iface = self._ifaces[0]["name"]
        self.accept()
