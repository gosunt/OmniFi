"""
OmniFi Panel — Policy & Enforcement (Admin only)
Four tabs: Blacklist · Whitelist · Quarantine · Exceptions
+ Enforcement log showing what actually happened at each tier.
"""
import re, datetime
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QTabWidget, QLineEdit, QSpinBox, QMessageBox, QFrame, QTextEdit,
    QSplitter,
)
from PyQt6.QtCore import pyqtSignal, Qt, QTimer
from PyQt6.QtGui  import QColor, QFont
from ui.theme     import (
    BG1, BG2, BG3, B1, B2, T1, T2, T3, T4,
    GRN, YLW, RED, ORG, ACC, PUR,
    rgba, mf, sf,
)

_TIER_ICONS = {
    "router":              ("🛡", "Router MAC filter applied"),
    "os_firewall":         ("🔥", "OS firewall rule added"),
    "arp":                 ("📡", "ARP isolation active"),
    "db_only":             ("📋", "Policy recorded — no router session"),
    "whitelist":           ("✅", "Whitelist — blocks removed"),
    "removed":             ("↩",  "Rules removed"),
    "router+os_firewall":  ("🛡🔥", "Router + OS firewall"),
    "router+os_firewall+arp": ("🛡🔥📡", "Full enforcement"),
    "os_firewall+arp":     ("🔥📡", "OS firewall + ARP"),
}

_ACTION_COLOR = {
    "blacklist": RED,
    "isolated":  ORG,
    "whitelist": GRN,
    "exception": YLW,
}


class PolicyPanel(QWidget):
    """
    Policy management panel. Admin-only.
    Emits apply_sig(mac, policy_type, reason, expiry_min).
    Emits remove_sig(mac, policy_type).
    """
    apply_sig  = pyqtSignal(str, str, str, int)
    remove_sig = pyqtSignal(str, str)

    def __init__(self, is_admin_fn, get_policy_fn, parent=None):
        super().__init__(parent)
        self._is_admin   = is_admin_fn
        self._get_policy = get_policy_fn
        self._log_entries = []
        self._build()

    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        if not self._is_admin():
            wrapper = QWidget(); wl = QVBoxLayout(wrapper)
            wl.setContentsMargins(24, 24, 24, 24)
            icon = QLabel("🛡"); icon.setFont(QFont("Segoe UI Emoji", 32))
            icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
            wl.addStretch()
            wl.addWidget(icon)
            lbl = QLabel("Admin mode required\nto manage enforcement policy.")
            lbl.setFont(mf(11)); lbl.setStyleSheet(f"color:{T3};")
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl.setWordWrap(True)
            wl.addWidget(lbl)
            hint = QLabel("Login via  Mode → Switch mode / re-login")
            hint.setFont(mf(9)); hint.setStyleSheet(f"color:{ACC};")
            hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
            wl.addWidget(hint)
            wl.addStretch()
            lay.addWidget(wrapper, 1)
            return

        # Header bar
        hdr = QFrame(); hdr.setFixedHeight(44)
        hdr.setStyleSheet(f"background:{BG1}; border-bottom:1px solid {B1};")
        hl = QHBoxLayout(hdr); hl.setContentsMargins(16,0,16,0); hl.setSpacing(10)
        title = QLabel("Policy & Enforcement"); title.setFont(sf(12, bold=True))
        hl.addWidget(title)
        self._active_cnt = QLabel("0 rules active"); self._active_cnt.setFont(mf(9))
        self._active_cnt.setStyleSheet(
            f"color:{T3}; background:{BG3}; border:1px solid {B1};"
            f"border-radius:3px; padding:1px 8px;")
        hl.addWidget(self._active_cnt); hl.addStretch()
        ref = QPushButton("↻  Refresh"); ref.setProperty("cls","primary")
        ref.setFixedHeight(28); ref.clicked.connect(self.refresh)
        hl.addWidget(ref)
        lay.addWidget(hdr)

        # Main splitter: policy tabs | enforcement log
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(1)
        splitter.setStyleSheet(f"QSplitter::handle{{background:{B1};}}")

        # ── Left: policy tabs ────────────────────────────────────────────────
        tabs_w = QWidget(); tabs_l = QVBoxLayout(tabs_w)
        tabs_l.setContentsMargins(12, 10, 6, 10); tabs_l.setSpacing(8)

        tabs = QTabWidget()
        tabs.setStyleSheet(f"""
            QTabBar::tab {{
                background:{BG2}; color:{T3}; border:1px solid {B1};
                border-bottom:none; padding:5px 14px; border-radius:4px 4px 0 0;
                font-size:10px;
            }}
            QTabBar::tab:selected {{ background:{BG3}; color:{T1}; border-color:{B2}; }}
            QTabWidget::pane {{ border:1px solid {B1}; background:{BG2}; }}
        """)
        self._tables = {}

        for pt, label, color, cls_add in [
            ("blacklist", "🚫  Blacklist",  RED, "danger"),
            ("whitelist", "✅  Whitelist",  GRN, "success"),
            ("isolated",  "🔒  Quarantine", ORG, "warn"),
            ("exception", "⚡  Exceptions", YLW, "warn"),
        ]:
            w  = QWidget(); wl2 = QVBoxLayout(w)
            wl2.setContentsMargins(8, 8, 8, 8); wl2.setSpacing(6)

            tbl = QTableWidget(); tbl.setColumnCount(5)
            tbl.setHorizontalHeaderLabels(["MAC","Reason","Added","Expiry",""])
            hdr2 = tbl.horizontalHeader()
            hdr2.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
            hdr2.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
            hdr2.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
            tbl.setColumnWidth(4, 64)
            tbl.verticalHeader().setVisible(False)
            tbl.setAlternatingRowColors(True)
            tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            wl2.addWidget(tbl, 1)
            self._tables[pt] = tbl

            # Add row controls
            ar = QFrame(); ar.setStyleSheet(
                f"background:{BG3}; border-top:1px solid {B1}; border-radius:0 0 4px 4px;")
            arl = QHBoxLayout(ar); arl.setContentsMargins(8,6,8,6); arl.setSpacing(6)
            mi = QLineEdit(); mi.setPlaceholderText("MAC  XX:XX:XX:XX:XX:XX")
            mi.setFixedHeight(28); mi.setMaximumWidth(190)
            ri2 = QLineEdit(); ri2.setPlaceholderText("Reason (optional)")
            ri2.setFixedHeight(28)
            eb = QSpinBox(); eb.setRange(0,10080); eb.setValue(0)
            eb.setSuffix(" min"); eb.setFixedWidth(80); eb.setFixedHeight(28)
            eb.setToolTip("Expiry (0 = permanent, max 7 days)")
            ab = QPushButton(f"+ {label.split()[-1]}"); ab.setFixedHeight(28)
            ab.setProperty("cls", cls_add)
            ab.clicked.connect(lambda _, t=pt, m=mi, r=ri2, e=eb:
                               self._on_add(t, m, r, e))
            arl.addWidget(mi); arl.addWidget(ri2,1)
            arl.addWidget(QLabel("Exp:")); arl.addWidget(eb); arl.addWidget(ab)
            wl2.addWidget(ar)
            tabs.addTab(w, label)

        tabs_l.addWidget(tabs, 1)
        self._tabs = tabs
        splitter.addWidget(tabs_w)

        # ── Right: enforcement log ───────────────────────────────────────────
        log_w = QWidget(); ll = QVBoxLayout(log_w)
        ll.setContentsMargins(6, 10, 12, 10); ll.setSpacing(6)

        lhdr = QHBoxLayout(); lhdr.setSpacing(8)
        lt = QLabel("Enforcement Log"); lt.setFont(sf(10, bold=True))
        lhdr.addWidget(lt); lhdr.addStretch()
        clr = QPushButton("Clear"); clr.setFont(mf(8)); clr.setFixedHeight(24)
        clr.clicked.connect(self._clear_log)
        lhdr.addWidget(clr)
        ll.addLayout(lhdr)

        self._log_tbl = QTableWidget(); self._log_tbl.setColumnCount(4)
        self._log_tbl.setHorizontalHeaderLabels(["Time","Action","MAC","Tier"])
        lh = self._log_tbl.horizontalHeader()
        lh.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        lh.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._log_tbl.verticalHeader().setVisible(False)
        self._log_tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._log_tbl.setAlternatingRowColors(True)
        self._log_tbl.setMaximumWidth(320)
        ll.addWidget(self._log_tbl, 1)

        # Tier legend
        legend = QFrame(); legend.setStyleSheet(
            f"background:{BG3}; border:1px solid {B1}; border-radius:4px;")
        legl = QVBoxLayout(legend); legl.setContentsMargins(8,6,8,6); legl.setSpacing(3)
        QLabel_h = QLabel("Enforcement tiers:"); QLabel_h.setFont(mf(8, bold=True))
        QLabel_h.setStyleSheet(f"color:{T2};")
        legl.addWidget(QLabel_h)
        for icon, desc in [("🛡","Router MAC filter"),("🔥","OS firewall rule"),
                           ("📡","ARP isolation"),("📋","DB record only")]:
            row = QHBoxLayout(); row.setSpacing(5)
            i = QLabel(icon); i.setFont(QFont("Segoe UI Emoji",10)); i.setFixedWidth(20)
            d = QLabel(desc); d.setFont(mf(8)); d.setStyleSheet(f"color:{T3};")
            row.addWidget(i); row.addWidget(d); row.addStretch()
            legl.addLayout(row)
        ll.addWidget(legend)
        splitter.addWidget(log_w)
        splitter.setSizes([680, 300])
        lay.addWidget(splitter, 1)
        self.refresh()

    # ── public ────────────────────────────────────────────────────────────────
    def refresh(self):
        if not self._is_admin(): return
        items = self._get_policy()
        total = 0
        for pt, tbl in self._tables.items():
            fil = [p for p in items if p.get("policy_type") == pt]
            total += len(fil)
            tbl.setRowCount(len(fil))
            color = _ACTION_COLOR.get(pt, T2)
            for row, p in enumerate(fil):
                mac = p.get("mac","")
                tbl.setItem(row, 0, self._cell(mac, bold=True))
                tbl.setItem(row, 1, self._cell(p.get("reason","—")))
                tbl.setItem(row, 2, self._cell(p.get("added","")[:16]))
                exp = p.get("expiry","") or "∞"
                tbl.setItem(row, 3, self._cell(exp[:16]))
                rb = QPushButton("Remove"); rb.setFont(mf(8))
                rb.setFixedHeight(22); rb.setProperty("cls","danger")
                rb.clicked.connect(lambda _, m=mac, t=pt: self.remove_sig.emit(m, t))
                tbl.setCellWidget(row, 4, rb)
            tbl.resizeRowsToContents()
        self._active_cnt.setText(f"{total} rule{'s' if total!=1 else ''} active")

    def log_enforcement(self, action: str, mac: str, tier: str, ok: bool):
        """Called by MainWindow after each enforcement action."""
        ts   = datetime.datetime.now().strftime("%H:%M:%S")
        icon = _TIER_ICONS.get(tier, ("📋",""))[0]
        self._log_entries.append((ts, action, mac, f"{icon} {tier}", ok))
        self._refresh_log()

    # ── internals ─────────────────────────────────────────────────────────────
    def _refresh_log(self):
        entries = self._log_entries[-50:]  # show last 50
        self._log_tbl.setRowCount(len(entries))
        for row, (ts, action, mac, tier, ok) in enumerate(reversed(entries)):
            color = GRN if ok else RED
            for col, val in enumerate([ts, action.upper(), mac, tier]):
                item = QTableWidgetItem(val); item.setFont(mf(8))
                if col == 1:
                    item.setForeground(QColor(color))
                    item.setFont(mf(8, bold=True))
                self._log_tbl.setItem(row, col, item)
        self._log_tbl.resizeRowsToContents()

    def _clear_log(self):
        self._log_entries.clear(); self._log_tbl.setRowCount(0)

    def _on_add(self, pt: str, mi: QLineEdit, ri: QLineEdit, eb: QSpinBox):
        mac = mi.text().strip().upper()
        if not re.match(r"^([0-9A-F]{2}[:\-]){5}[0-9A-F]{2}$", mac):
            QMessageBox.warning(self, "Invalid MAC",
                "Enter a valid MAC address in format XX:XX:XX:XX:XX:XX")
            return
        self.apply_sig.emit(mac, pt, ri.text().strip(), eb.value())
        mi.clear(); ri.clear(); eb.setValue(0)

    @staticmethod
    def _cell(text: str, bold: bool = False) -> QTableWidgetItem:
        item = QTableWidgetItem(text or "—")
        item.setFont(mf(9, bold=bold))
        return item
