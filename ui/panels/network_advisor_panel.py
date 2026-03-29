"""
OmniFi Panel — Network Advisor
Ranked list of all visible APs with full 8-vector breakdown.
Differs from the scanner in that it's a persistent panel you can
return to after connecting — shows post-join scores too.
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QFrame, QSplitter, QGroupBox,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from ui.theme     import (
    BG1, BG2, BG3, B1, T1, T2, T3, T4,
    ACC, GRN, YLW, RED, ORG,
    VDT_C, rgba, mf, sf,
)
from ui.widgets.network_card import NetworkCard


class _ScanThread(QThread):
    done = pyqtSignal(list)
    def __init__(self, fn): super().__init__(); self._fn = fn
    def run(self):
        try:   self.done.emit(self._fn())
        except: self.done.emit([])


class NetworkAdvisorPanel(QWidget):
    """
    Always-available network advisor panel.
    Refreshes on demand; shows the most recent scan results.
    """

    def __init__(self, scan_fn, parent=None):
        super().__init__(parent)
        self._scan_fn = scan_fn
        self._nets    = []
        self._build()

    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 14, 18, 14)
        lay.setSpacing(10)

        # Header
        hdr = QHBoxLayout(); hdr.setSpacing(10)
        tit = QLabel("Network Advisor"); tit.setFont(sf(12, bold=True))
        hdr.addWidget(tit)
        sub = QLabel("Scored across 8 pre-join security vectors  (click any card to expand)")
        sub.setFont(mf(9)); sub.setStyleSheet(f"color:{T3};"); hdr.addWidget(sub)
        hdr.addStretch()
        self._status = QLabel("")
        self._status.setFont(mf(9)); self._status.setStyleSheet(f"color:{ACC};")
        hdr.addWidget(self._status)
        rb = QPushButton("↻  Rescan"); rb.setProperty("cls","primary")
        rb.setFixedHeight(30); rb.clicked.connect(self.refresh)
        hdr.addWidget(rb); lay.addLayout(hdr)

        # Progress bar
        from PyQt6.QtWidgets import QProgressBar
        self._prog = QProgressBar(); self._prog.setRange(0,100); self._prog.setValue(0)
        self._prog.setFixedHeight(4); self._prog.setTextVisible(False)
        self._prog.setStyleSheet(
            f"QProgressBar{{background:{BG3};border:none;border-radius:2px;}}"
            f"QProgressBar::chunk{{background:{ACC};border-radius:2px;}}")
        lay.addWidget(self._prog)

        # ── Split: left = ranked cards, right = scoring legend ────────────────
        spl = QSplitter(Qt.Orientation.Horizontal)

        # Left: card list
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._cw = QWidget(); self._cl = QVBoxLayout(self._cw)
        self._cl.setContentsMargins(0,0,0,0); self._cl.setSpacing(0)
        self._cl.addStretch()
        scroll.setWidget(self._cw)
        spl.addWidget(scroll)

        # Right: scoring legend
        legend = QGroupBox("Scoring Vectors  (100 pts total)")
        ll = QVBoxLayout(legend); ll.setSpacing(8)
        VECTORS = [
            ("Encryption protocol",  30, "WPA3=30  WPA2=20  WPA=8  WEP=2  Open=0"),
            ("No evil twin",         20, "Unique BSSID per SSID + history check"),
            ("Signal strength",      15, "-50dBm=15  -60=13  -70=9  -80=5  weaker=2"),
            ("PMF / 802.11w",        10, "Management frame protection enabled"),
            ("WPS disabled",         10, "WPS IE absent from beacon"),
            ("Frequency band",        8, "5 GHz=8  2.4 GHz=4"),
            ("SSID visible",          4, "Broadcast=4  Hidden=2"),
            ("ISP known risk",         3, "Based on India ISP default-cred database"),
        ]
        for name, pts, desc in VECTORS:
            rr = QVBoxLayout(); rr.setSpacing(2)
            nm = QHBoxLayout(); nm.setSpacing(6)
            nl = QLabel(name); nl.setFont(sf(10, bold=True))
            pl = QLabel(f"{pts} pts"); pl.setFont(mf(9))
            pl.setStyleSheet(f"color:{ACC};")
            nm.addWidget(nl,1); nm.addWidget(pl)
            dl = QLabel(desc); dl.setFont(mf(8))
            dl.setStyleSheet(f"color:{T3};"); dl.setWordWrap(True)
            rr.addLayout(nm); rr.addWidget(dl)
            f = QFrame(); f.setStyleSheet(
                f"background:{BG3};border-radius:5px;padding:2px;")
            QVBoxLayout(f).addLayout(rr)
            ll.addWidget(f)
        ll.addStretch()

        spl.addWidget(legend)
        spl.setSizes([620, 280])
        lay.addWidget(spl, 1)

    def refresh(self):
        self._prog.setValue(5)
        self._status.setText("Scanning…")
        self._pv = 5
        self._ptmr = QTimer(self); self._ptmr.timeout.connect(self._tick)
        self._ptmr.start(180)
        self._t = _ScanThread(self._scan_fn)
        self._t.done.connect(self._on_done)
        self._t.start()

    def _tick(self):
        self._pv = min(90, self._pv+10); self._prog.setValue(self._pv)

    def _on_done(self, nets: list):
        self._ptmr.stop(); self._prog.setValue(100)
        self._nets = nets
        self._status.setText(f"{len(nets)} networks scored")
        self._render()

    def _render(self):
        while self._cl.count() > 1:
            item = self._cl.takeAt(0)
            if item.widget(): item.widget().deleteLater()
        for i, net in enumerate(self._nets):
            card = NetworkCard(net, i)
            self._cl.insertWidget(i, card)

    def update_networks(self, nets: list):
        """Called by MonitorThread when new scan completes."""
        self._nets = nets
        self._status.setText(f"{len(nets)} networks")
        self._render()
