"""
OmniFi — Security Posture Report Generator
============================================
Generates a formatted PDF report after any audit.
Includes trust score, all findings, risk levels,
recommended mitigations — formatted for non-technical users.

Requires: pip install fpdf2
"""

import os
import datetime

try:
    from fpdf import FPDF
    FPDF_AVAILABLE = True
except ImportError:
    FPDF_AVAILABLE = False

REPORT_DIR = os.path.join(os.path.dirname(__file__), "..", "reports")

RISK_COLORS = {
    "critical": (220, 50,  50),
    "high":     (230, 120, 30),
    "medium":   (200, 160, 30),
    "low":      (50,  150, 80),
}

VERDICT_COLORS = {
    "safe":       (50,  150, 80),
    "acceptable": (30,  100, 190),
    "caution":    (200, 160, 30),
    "avoid":      (220, 50,  50),
    "evil_twin":  (220, 50,  50),
}


class ReportGenerator:

    def __init__(self, verbose=True):
        self.verbose = verbose

    def generate(self, audit_data: dict, filename: str = None) -> str:
        """
        Generate PDF report from audit_data dict.
        Returns path to generated PDF.

        audit_data keys:
          - isp_name, gateway_ip, router_url, auth_type
          - trust_score, risk_level
          - alerts (list of {level, message})
          - networks (list of NetworkProfile dicts)
          - devices (list of device dicts)
          - scan_time (ISO string)
        """
        if not FPDF_AVAILABLE:
            self._print("[!] fpdf2 not installed. Run: pip install fpdf2")
            return self._generate_text_report(audit_data, filename)

        os.makedirs(REPORT_DIR, exist_ok=True)
        if not filename:
            ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(REPORT_DIR, f"omnifi_report_{ts}.pdf")

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        self._header(pdf, audit_data)
        self._summary_box(pdf, audit_data)
        self._trust_score_section(pdf, audit_data)
        self._alerts_section(pdf, audit_data)

        if audit_data.get("networks"):
            self._networks_section(pdf, audit_data["networks"])

        if audit_data.get("devices"):
            self._devices_section(pdf, audit_data["devices"])

        self._recommendations_section(pdf, audit_data)
        self._footer(pdf)

        pdf.output(filename)
        self._print(f"\n  [+] Report saved: {filename}")
        return filename

    # ── Sections ──────────────────────────────────────────────────────────────

    def _header(self, pdf, data):
        pdf.set_font("Helvetica", "B", 20)
        pdf.set_text_color(30, 80, 160)
        pdf.cell(0, 12, "OmniFi Security Report", ln=True, align="C")

        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(100, 100, 100)
        scan_time = data.get("scan_time", datetime.datetime.now().isoformat())[:19]
        pdf.cell(0, 6, f"Generated: {scan_time}  |  "
                       f"Network: {data.get('isp_name','Unknown')}  |  "
                       f"Gateway: {data.get('gateway_ip','')}",
                 ln=True, align="C")
        pdf.ln(6)

    def _summary_box(self, pdf, data):
        risk    = data.get("risk_level", "low")
        score   = data.get("trust_score", 0)
        rc      = RISK_COLORS.get(risk, (100,100,100))

        pdf.set_fill_color(*rc)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, f"  Risk Level: {risk.upper()}   |   "
                        f"Security Score: {score}/100",
                 ln=True, fill=True)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(4)

    def _trust_score_section(self, pdf, data):
        self._section_title(pdf, "Router Audit Summary")
        rows = [
            ("ISP / Provider",   data.get("isp_name",     "Unknown")),
            ("Gateway IP",       data.get("gateway_ip",   "Unknown")),
            ("Admin URL",        data.get("router_url",   "N/A")),
            ("Auth type",        data.get("auth_type",    "Unknown")),
            ("HTTPS",            str(data.get("uses_https", False))),
            ("Default creds",    "WORK — change now!" if data.get("default_creds_work")
                                 else "Do not work (good)"),
        ]
        for label, value in rows:
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(55, 7, label + ":", border=0)
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(0, 7, str(value), border=0, ln=True)
        pdf.ln(4)

    def _alerts_section(self, pdf, data):
        alerts = data.get("alerts", [])
        if not alerts:
            return
        self._section_title(pdf, f"Findings ({len(alerts)})")
        for a in alerts:
            level = a.get("level", "low")
            rc    = RISK_COLORS.get(level, (100,100,100))
            # Coloured bullet
            pdf.set_fill_color(*rc)
            pdf.set_text_color(255,255,255)
            pdf.set_font("Helvetica","B",8)
            pdf.cell(18, 6, f" {level.upper()} ", fill=True)
            pdf.set_text_color(0,0,0)
            pdf.set_font("Helvetica","",9)
            msg = a.get("message","")
            pdf.multi_cell(0, 6, f"  {msg}")
            pdf.ln(1)
        pdf.ln(3)

    def _networks_section(self, pdf, networks):
        self._section_title(pdf, "Nearby Networks")
        pdf.set_font("Helvetica","B",9)
        pdf.set_fill_color(220,230,245)
        pdf.cell(70, 7, "SSID",         border=1, fill=True)
        pdf.cell(20, 7, "Score",        border=1, fill=True, align="C")
        pdf.cell(25, 7, "Verdict",      border=1, fill=True, align="C")
        pdf.cell(30, 7, "Protocol",     border=1, fill=True, align="C")
        pdf.cell(0,  7, "Signal (dBm)", border=1, fill=True, align="C", ln=True)
        pdf.set_font("Helvetica","",9)
        for net in networks[:10]:
            rc = VERDICT_COLORS.get(net.get("verdict",""), (100,100,100))
            pdf.cell(70, 6, str(net.get("ssid",""))[:30],  border=1)
            pdf.cell(20, 6, str(net.get("total_score","")), border=1, align="C")
            pdf.set_text_color(*rc)
            pdf.cell(25, 6, str(net.get("verdict","")).upper(), border=1, align="C")
            pdf.set_text_color(0,0,0)
            pdf.cell(30, 6, str(net.get("auth_protocol","")).upper(), border=1, align="C")
            pdf.cell(0,  6, str(net.get("signal_dbm","")), border=1, align="C", ln=True)
        pdf.ln(4)

    def _devices_section(self, pdf, devices):
        self._section_title(pdf, "Connected Devices")
        pdf.set_font("Helvetica","B",9)
        pdf.set_fill_color(220,230,245)
        pdf.cell(50, 7, "MAC Address", border=1, fill=True)
        pdf.cell(55, 7, "Vendor",      border=1, fill=True)
        pdf.cell(50, 7, "Hostname",    border=1, fill=True)
        pdf.cell(0,  7, "Type",        border=1, fill=True, ln=True)
        pdf.set_font("Helvetica","",9)
        for dev in devices[:15]:
            pdf.cell(50, 6, str(dev.get("mac",""))[:18],    border=1)
            pdf.cell(55, 6, str(dev.get("vendor",""))[:22], border=1)
            pdf.cell(50, 6, str(dev.get("hostname",""))[:20],border=1)
            pdf.cell(0,  6, str(dev.get("device_type",""))[:18], border=1, ln=True)
        pdf.ln(4)

    def _recommendations_section(self, pdf, data):
        self._section_title(pdf, "Recommendations")
        recs = self._build_recommendations(data)
        pdf.set_font("Helvetica","",10)
        for i, rec in enumerate(recs, 1):
            pdf.multi_cell(0, 7, f"{i}. {rec}")
            pdf.ln(1)

    def _build_recommendations(self, data) -> list:
        recs = []
        alerts = data.get("alerts",[])
        levels = [a.get("level") for a in alerts]

        if data.get("default_creds_work"):
            recs.append("Change your router admin password immediately from the default.")
        if not data.get("uses_https"):
            recs.append("Enable HTTPS on the router admin panel if supported.")
        if any("WPS" in a.get("message","") for a in alerts):
            recs.append("Disable WPS in router wireless settings — it can be brute-forced.")
        if any("WEP" in a.get("message","") for a in alerts):
            recs.append("Upgrade encryption from WEP to WPA2 or WPA3 immediately.")
        if any("PMF" in a.get("message","") for a in alerts):
            recs.append("Enable PMF (802.11w) in wireless settings to prevent deauth attacks.")
        if any("Telnet" in a.get("message","") for a in alerts):
            recs.append("Disable Telnet (port 23) — use SSH instead for remote management.")
        if any("DNS" in a.get("message","") for a in alerts):
            recs.append("Configure trusted DNS resolvers (1.1.1.1 or 8.8.8.8).")
        if "critical" in levels or "high" in levels:
            recs.append("Update router firmware to the latest version from the vendor website.")
        if not recs:
            recs.append("No critical issues found. Continue monitoring regularly.")
        return recs

    def _footer(self, pdf):
        pdf.set_y(-20)
        pdf.set_font("Helvetica","I",8)
        pdf.set_text_color(150,150,150)
        pdf.cell(0, 6,
                 "Generated by OmniFi — Hybrid Wi-Fi Security Tool  |  "
                 "For authorized use on your own network only.",
                 align="C")

    def _section_title(self, pdf, title):
        pdf.set_font("Helvetica","B",12)
        pdf.set_text_color(30,80,160)
        pdf.cell(0, 9, title, ln=True)
        pdf.set_draw_color(30,80,160)
        pdf.set_line_width(0.5)
        pdf.line(pdf.get_x(), pdf.get_y(), pdf.get_x()+190, pdf.get_y())
        pdf.set_text_color(0,0,0)
        pdf.ln(3)

    # ── Plain text fallback ───────────────────────────────────────────────────

    def _generate_text_report(self, data, filename) -> str:
        os.makedirs(REPORT_DIR, exist_ok=True)
        if not filename:
            ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(REPORT_DIR, f"omnifi_report_{ts}.txt")
        with open(filename, "w") as f:
            f.write("OmniFi Security Report\n")
            f.write("=" * 60 + "\n")
            f.write(f"ISP     : {data.get('isp_name','')}\n")
            f.write(f"Gateway : {data.get('gateway_ip','')}\n")
            f.write(f"Score   : {data.get('trust_score',0)}/100\n")
            f.write(f"Risk    : {data.get('risk_level','').upper()}\n\n")
            f.write("Findings:\n")
            for a in data.get("alerts",[]):
                f.write(f"  [{a['level'].upper()}] {a['message']}\n")
        self._print(f"  [+] Text report saved: {filename}")
        return filename

    def _print(self, msg):
        if self.verbose: print(msg)


if __name__ == "__main__":
    # Demo report
    sample = {
        "isp_name":           "JioFiber",
        "gateway_ip":         "192.168.29.1",
        "router_url":         "http://192.168.29.1",
        "auth_type":          "form",
        "uses_https":         False,
        "default_creds_work": True,
        "trust_score":        75,
        "risk_level":         "critical",
        "scan_time":          datetime.datetime.now().isoformat(),
        "alerts": [
            {"level":"critical","message":"Default credentials work — change immediately!"},
            {"level":"critical","message":"Admin panel served over plain HTTP."},
            {"level":"high",    "message":"WPS is enabled — brute-force attack possible."},
            {"level":"medium",  "message":"PMF not detected — deauth attacks possible."},
        ],
    }
    ReportGenerator().generate(sample)
