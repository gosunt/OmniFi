"""
OmniFi Panel — Router Security Audit (Admin only)
Shows: panel URL · auth type · default cred test · HTTPS status ·
       ISP fingerprint · open ports · CVE search against NIST NVD.
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QSplitter, QGroupBox, QLineEdit, QFrame, QGridLayout,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui  import QColor
from ui.theme     import (
    BG2, BG3, B1, T1, T2, T3, T4,
    GRN, YLW, RED, ORG, ACC, PUR,
    rgba, mf, sf,
)


class _AuditThread(QThread):
    done = pyqtSignal(dict)
    def __init__(self, fn): super().__init__(); self._fn = fn
    def run(self):
        try:   self.done.emit(self._fn())
        except Exception as e: self.done.emit({"ok":False,"error":str(e)})

class _CVEThread(QThread):
    done = pyqtSignal(list)
    def __init__(self, fn, model, fw): super().__init__(); self._fn=fn; self._m=model; self._f=fw
    def run(self):
        try:   self.done.emit(self._fn(self._m, self._f))
        except: self.done.emit([])


class RouterPanel(QWidget):
    """
    Router audit panel. Admin-only.
    """

    def __init__(self, audit_fn, cve_fn, is_admin_fn, parent=None):
        """
        audit_fn   : callable() → dict  (router audit results)
        cve_fn     : callable(model, fw) → List[dict]
        is_admin_fn: callable() → bool
        """
        super().__init__(parent)
        self._audit_fn  = audit_fn
        self._cve_fn    = cve_fn
        self._is_admin  = is_admin_fn
        self._build()

    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 14, 18, 14)
        lay.setSpacing(10)

        if not self._is_admin():
            lbl = QLabel("Admin mode required for router audit.")
            lbl.setFont(mf(11)); lbl.setStyleSheet(f"color:{T3};")
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lay.addWidget(lbl, 1); return

        # Header
        hdr = QHBoxLayout()
        tit = QLabel("Router Security Audit"); tit.setFont(sf(12, bold=True))
        hdr.addWidget(tit); hdr.addStretch()
        rb  = QPushButton("Run full audit"); rb.setProperty("cls","primary")
        rb.setFixedHeight(30); rb.clicked.connect(self._run_audit)
        hdr.addWidget(rb); lay.addLayout(hdr)

        # Summary cards grid
        self._grid = QGridLayout(); self._grid.setSpacing(8)
        lay.addLayout(self._grid)

        # ── Bottom split: CVEs | Ports ─────────────────────────────────────
        spl = QSplitter(Qt.Orientation.Horizontal)

        # CVE group
        cg  = QGroupBox("CVE Findings  (NIST NVD API)")
        cgl = QVBoxLayout(cg)
        self._cvt = QTableWidget(); self._cvt.setColumnCount(5)
        self._cvt.setHorizontalHeaderLabels(
            ["CVE ID","CVSS","Severity","Description","Patch"])
        h2 = self._cvt.horizontalHeader()
        h2.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        h2.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._cvt.verticalHeader().setVisible(False)
        self._cvt.setAlternatingRowColors(True)
        cgl.addWidget(self._cvt)

        # CVE search bar
        sr  = QHBoxLayout()
        self._mi = QLineEdit(); self._mi.setPlaceholderText("Router model  e.g. HG8145V5")
        self._mi.setFixedHeight(28)
        self._fi = QLineEdit(); self._fi.setPlaceholderText("Firmware (optional)")
        self._fi.setFixedHeight(28)
        sb  = QPushButton("Search CVEs"); sb.clicked.connect(self._search_cve)
        sr.addWidget(self._mi, 2); sr.addWidget(self._fi, 1); sr.addWidget(sb)
        cgl.addLayout(sr)

        # Ports group
        pg  = QGroupBox("Open Ports  (TCP connect scan)")
        pgl = QVBoxLayout(pg)
        self._pt = QTableWidget(); self._pt.setColumnCount(4)
        self._pt.setHorizontalHeaderLabels(["Port","Service","Risk","Note"])
        h3 = self._pt.horizontalHeader()
        h3.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        h3.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._pt.verticalHeader().setVisible(False)
        pgl.addWidget(self._pt)

        spl.addWidget(cg); spl.addWidget(pg)
        lay.addWidget(spl, 1)

    # ── audit ─────────────────────────────────────────────────────────────────
    def _run_audit(self):
        self._t = _AuditThread(self._audit_fn)
        self._t.done.connect(self._show_audit)
        self._t.start()

    def _show_audit(self, res: dict):
        if not res.get("ok"): return
        audit = res.get("audit", {}); ports = res.get("ports", [])

        items = [
            ("Router URL",     audit.get("panel_url","—"),
             "bad"  if not audit.get("uses_https") else "good"),
            ("Auth type",      audit.get("auth_type","none"), "warn"),
            ("Default creds",
             "WORK — change now!" if audit.get("default_creds_work") else "Changed",
             "bad" if audit.get("default_creds_work") else "good"),
            ("HTTPS",
             "Enabled" if audit.get("uses_https") else "Disabled",
             "good" if audit.get("uses_https") else "bad"),
            ("ISP",            audit.get("isp_name","?"), "info"),
            ("Open panel",
             "YES — no auth!" if audit.get("open_panel") else "No",
             "bad" if audit.get("open_panel") else "good"),
        ]

        # Clear old grid
        for i in reversed(range(self._grid.count())):
            w = self._grid.itemAt(i).widget()
            if w: w.deleteLater()

        _SC = {"good":GRN,"bad":RED,"warn":YLW,"info":ACC}
        for i, (k, v, st) in enumerate(items):
            f  = QFrame(); f.setStyleSheet(
                f"background:{BG2}; border:1px solid {B1}; border-radius:7px;")
            fl = QVBoxLayout(f); fl.setContentsMargins(11,8,11,8); fl.setSpacing(3)
            kl = QLabel(k); kl.setFont(mf(8)); kl.setStyleSheet(f"color:{T3};")
            vl = QLabel(v); vl.setFont(mf(10, bold=True))
            vl.setStyleSheet(f"color:{_SC.get(st,T2)};"); vl.setWordWrap(True)
            fl.addWidget(kl); fl.addWidget(vl)
            self._grid.addWidget(f, i // 3, i % 3)

        # Ports
        _RC = {"critical":RED,"high":ORG,"medium":YLW,"low":T3}
        self._pt.setRowCount(len(ports))
        for row, p in enumerate(ports):
            self._pt.setItem(row,0,QTableWidgetItem(str(p["port"])))
            self._pt.setItem(row,1,QTableWidgetItem(p["service"]))
            ri = QTableWidgetItem(p["risk"].upper())
            ri.setForeground(QColor(_RC.get(p["risk"],T2)))
            self._pt.setItem(row,2,ri)
            self._pt.setItem(row,3,QTableWidgetItem(p["note"]))

    # ── CVE search ────────────────────────────────────────────────────────────
    def _search_cve(self):
        model = self._mi.text().strip()
        if not model: return
        fw    = self._fi.text().strip()
        self._mi.setPlaceholderText("Searching NVD…")
        self._ct = _CVEThread(self._cve_fn, model, fw)
        self._ct.done.connect(self._show_cves)
        self._ct.start()

    def _show_cves(self, cves: list):
        self._mi.setPlaceholderText("Router model  e.g. HG8145V5")
        _SC2 = {"CRITICAL":RED,"HIGH":ORG,"MEDIUM":YLW,"LOW":T3,"NONE":T4}
        self._cvt.setRowCount(len(cves))
        for row, c in enumerate(cves):
            self._cvt.setItem(row,0,QTableWidgetItem(c["id"]))
            si = QTableWidgetItem(str(c["score"]))
            si.setForeground(QColor(_SC2.get(c["severity"],T2)))
            self._cvt.setItem(row,1,si)
            se = QTableWidgetItem(c["severity"])
            se.setForeground(QColor(_SC2.get(c["severity"],T2)))
            self._cvt.setItem(row,2,se)
            self._cvt.setItem(row,3,QTableWidgetItem(c["desc"]))
            self._cvt.setItem(row,4,QTableWidgetItem(
                "✓ Patched" if c["patch"] else "✗ No patch"))
