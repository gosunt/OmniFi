"""
OmniFi Panel — Device Inventory
ARP-based device discovery table.
Admin mode: Block / Isolate / Trust / Exception action buttons per row.
Client mode: read-only view only.
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QDialog, QFrame,
)
from PyQt6.QtCore    import Qt, QThread, pyqtSignal
from PyQt6.QtGui     import QColor, QFont
from ui.theme        import (
    BG1, BG2, BG3, B1, T1, T2, T3, T4,
    GRN, YLW, RED, ORG, ACC, B2,
    rgba, mf, sf,
)


class _ScanThread(QThread):
    done = pyqtSignal(list)
    def __init__(self, fn): super().__init__(); self._fn = fn
    def run(self):
        try:   self.done.emit(self._fn())
        except: self.done.emit([])


class DevicesPanel(QWidget):
    """
    Device inventory panel.
    Signals: action_sig(mac, action_name) — admin actions
    """
    action_sig = pyqtSignal(str, str)

    def __init__(self, scan_fn, is_admin_fn, parent=None):
        """
        scan_fn     : callable() → List[dict]  (each dict has mac, ip, vendor, status…)
        is_admin_fn : callable() → bool
        """
        super().__init__(parent)
        self._scan_fn    = scan_fn
        self._is_admin   = is_admin_fn
        self._build()

    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)

        # Toolbar
        tb  = QHBoxLayout(); tb.setContentsMargins(16, 10, 16, 10); tb.setSpacing(8)
        tit = QLabel("Device Inventory"); tit.setFont(sf(12, bold=True))
        tb.addWidget(tit)
        self._cnt = QLabel("0 devices"); self._cnt.setFont(mf(9))
        self._cnt.setStyleSheet(
            f"color:{T3}; background:{BG3}; border:1px solid {B1};"
            f"border-radius:3px; padding:1px 8px;")
        tb.addWidget(self._cnt); tb.addStretch()

        ref = QPushButton("↻  ARP scan now"); ref.setProperty("cls","primary")
        ref.setFixedHeight(30); ref.clicked.connect(self.refresh)
        tb.addWidget(ref)
        lay.addLayout(tb)

        # Table
        self._tbl = QTableWidget(); self._tbl.setColumnCount(8)
        self._tbl.setHorizontalHeaderLabels([
            "IP","Hostname / Name","MAC","Vendor","Type","Status","Actions",""])
        hdr = self._tbl.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)  # hostname stretches
        hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)
        self._tbl.setColumnWidth(5, 90)
        self._tbl.setColumnHidden(7, True)  # hidden spare
        self._tbl.verticalHeader().setVisible(False)
        self._tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._tbl.setAlternatingRowColors(True)
        lay.addWidget(self._tbl, 1)

    # ── public ────────────────────────────────────────────────────────────────
    def refresh(self):
        self._t = _ScanThread(self._scan_fn)
        self._t.done.connect(self._populate)
        self._t.start()

    def update_devices(self, devs: list):
        self._populate(devs)

    # ── render ────────────────────────────────────────────────────────────────
    def _populate(self, devs: list):
        STATUS_C = {
            "trusted":  GRN,
            "suspect":  RED,
            "unknown":  YLW,
            "blocked":  T3,
            "isolated": ORG,
            "la_mac":   RED,
        }
        self._tbl.setRowCount(len(devs))
        self._cnt.setText(f"{len(devs)} devices")

        # Common service name hints by hostname pattern
        _SVC_HINTS = {
            "router": "🌐 Router", "gateway": "🌐 Gateway",
            "ap": "📡 Access Point", "printer": "🖨 Printer",
            "cam": "📷 Camera", "camera": "📷 Camera",
            "tv": "📺 Smart TV", "chromecast": "📺 Chromecast",
            "echo": "🔊 Echo", "alexa": "🔊 Alexa",
            "iphone": "📱 iPhone", "android": "📱 Android",
            "macbook": "💻 MacBook", "laptop": "💻 Laptop",
            "desktop": "🖥 Desktop", "pc": "🖥 PC",
            "nas": "💾 NAS", "synology": "💾 NAS",
            "xbox": "🎮 Xbox", "playstation": "🎮 PlayStation",
            "switch": "🎮 Switch",
        }

        def _service_hint(hostname: str, dtype: str) -> str:
            h = (hostname or "").lower()
            d = (dtype or "").lower()
            for kw, label in _SVC_HINTS.items():
                if kw in h or kw in d:
                    return label
            return hostname or "—"

        for row, d in enumerate(devs):
            ip       = d.get("ip","") or "—"
            hostname = d.get("hostname","") or ""
            mac      = d.get("mac","") or "—"
            vendor   = d.get("vendor","") or "—"
            dtype    = d.get("device_type","") or ""
            display_name = _service_hint(hostname, dtype)

            for col, val in enumerate([ip, display_name, mac, vendor, dtype or "—"]):
                item = QTableWidgetItem(val)
                item.setFont(mf(9))
                if col == 1:  # hostname column — slightly brighter
                    item.setForeground(QColor(T1))
                    item.setFont(mf(9, bold=bool(hostname)))
                self._tbl.setItem(row, col, item)

            st = d.get("status","unknown")
            sc = STATUS_C.get(st, T3)
            si = QTableWidgetItem(st.upper())
            si.setFont(mf(9, bold=True))
            si.setForeground(QColor(sc))
            self._tbl.setItem(row, 5, si)

            # Action buttons — admin only
            if self._is_admin():
                bw  = QWidget(); bl = QHBoxLayout(bw)
                bl.setContentsMargins(4, 2, 4, 2); bl.setSpacing(4)
                for act, cls in [
                    ("Block",   "danger"),
                    ("Isolate", "warn"),
                    ("Trust",   "success"),
                ]:
                    b = QPushButton(act); b.setFixedHeight(22)
                    b.setFont(mf(8)); b.setProperty("cls", cls)
                    b.clicked.connect(
                        lambda _, m=mac, a=act.lower(): self.action_sig.emit(m, a))
                    bl.addWidget(b)
                bl.addStretch()
                self._tbl.setCellWidget(row, 6, bw)

        self._tbl.resizeRowsToContents()
