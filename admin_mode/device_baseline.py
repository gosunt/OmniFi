"""
OmniFi — Device Behaviour Baseline + Anomaly Scoring
======================================================
Over 24 hours, records each device's normal behaviour:
  - Typical connection times
  - Average bandwidth (bytes transferred)
  - Ports accessed
  - Packets per minute rate

After baseline is established, flags statistical deviations using
Z-score threshold. No ML needed — explainable and lightweight.

Z-score formula: z = (observed - mean) / stdev
  |z| > 2.5 → unusual
  |z| > 3.5 → alert
"""

import sqlite3
import datetime
import statistics
import os
import json

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "db", "omnifi.db")

BASELINE_HOURS   = 24
Z_WARN_THRESHOLD = 2.5
Z_ALERT_THRESHOLD= 3.5
MIN_SAMPLES      = 10     # need at least this many samples before scoring


def _get_conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS device_baseline (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            mac         TEXT NOT NULL,
            timestamp   TEXT NOT NULL,
            hour_of_day INTEGER,
            bytes_tx    INTEGER DEFAULT 0,
            bytes_rx    INTEGER DEFAULT 0,
            ports_json  TEXT DEFAULT '[]',
            pkt_rate    REAL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_mac ON device_baseline(mac);
    """)
    conn.commit()
    return conn


class DeviceBaselineMonitor:

    def __init__(self, verbose=True):
        self.verbose = verbose
        self.conn    = _get_conn()
        self.alerts  = []

    # ── Record a data point for a device ──────────────────────────────────────

    def record(self, mac: str, bytes_tx: int, bytes_rx: int,
               ports: list = None, pkt_rate: float = 0.0):
        now = datetime.datetime.now()
        self.conn.execute("""
            INSERT INTO device_baseline
                (mac, timestamp, hour_of_day, bytes_tx, bytes_rx, ports_json, pkt_rate)
            VALUES (?,?,?,?,?,?,?)
        """, (
            mac.upper(), now.isoformat(), now.hour,
            bytes_tx, bytes_rx,
            json.dumps(ports or []),
            pkt_rate
        ))
        self.conn.commit()

    # ── Score a new observation against the baseline ──────────────────────────

    def score(self, mac: str, bytes_tx: int, bytes_rx: int,
              pkt_rate: float = 0.0) -> dict:
        mac  = mac.upper()
        hist = self._get_history(mac)

        result = {
            "mac":            mac,
            "anomaly":        False,
            "z_bytes_tx":     0.0,
            "z_bytes_rx":     0.0,
            "z_pkt_rate":     0.0,
            "findings":       [],
            "alerts":         [],
        }

        if len(hist) < MIN_SAMPLES:
            result["findings"].append(
                f"Only {len(hist)} samples — need {MIN_SAMPLES} for baseline.")
            return result

        # Extract historical vectors
        hist_tx   = [h["bytes_tx"]  for h in hist]
        hist_rx   = [h["bytes_rx"]  for h in hist]
        hist_rate = [h["pkt_rate"]  for h in hist]

        # Z-score each metric
        result["z_bytes_tx"]  = self._z(bytes_tx,  hist_tx)
        result["z_bytes_rx"]  = self._z(bytes_rx,  hist_rx)
        result["z_pkt_rate"]  = self._z(pkt_rate,  hist_rate)

        # Evaluate thresholds
        checks = [
            ("Upload traffic",   bytes_tx,  result["z_bytes_tx"],  hist_tx),
            ("Download traffic", bytes_rx,  result["z_bytes_rx"],  hist_rx),
            ("Packet rate",      pkt_rate,  result["z_pkt_rate"],  hist_rate),
        ]

        for label, observed, z, hist_vals in checks:
            if abs(z) > Z_ALERT_THRESHOLD:
                result["anomaly"] = True
                msg = (f"{label} anomaly for {mac}: "
                       f"observed={observed:.0f}, "
                       f"baseline mean={statistics.mean(hist_vals):.0f}, "
                       f"z={z:.2f} (threshold ±{Z_ALERT_THRESHOLD})")
                result["findings"].append(msg)
                self._alert(msg, "high")
                result["alerts"].append({"level":"high", "message": msg})
            elif abs(z) > Z_WARN_THRESHOLD:
                msg = (f"{label} elevated for {mac}: z={z:.2f} — monitoring.")
                result["findings"].append(msg)

        if result["anomaly"] and self.verbose:
            print(f"\n  [!!] Behaviour anomaly: {mac}")
            for f in result["findings"]:
                print(f"       {f}")

        return result

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _z(self, value: float, history: list) -> float:
        if len(history) < 2:
            return 0.0
        mean  = statistics.mean(history)
        stdev = statistics.stdev(history)
        if stdev == 0:
            return 0.0
        return (value - mean) / stdev

    def _get_history(self, mac: str) -> list:
        # Use last 24h baseline
        since = (datetime.datetime.now() -
                 datetime.timedelta(hours=BASELINE_HOURS)).isoformat()
        cur = self.conn.cursor()
        cur.execute("""
            SELECT bytes_tx, bytes_rx, pkt_rate, hour_of_day
            FROM device_baseline
            WHERE mac=? AND timestamp > ?
            ORDER BY timestamp ASC
        """, (mac, since))
        return [{"bytes_tx":r[0], "bytes_rx":r[1],
                 "pkt_rate":r[2], "hour":r[3]}
                for r in cur.fetchall()]

    def get_all_baselines(self) -> dict:
        """Return summary statistics per device for dashboard display."""
        cur = self.conn.cursor()
        cur.execute("SELECT DISTINCT mac FROM device_baseline")
        macs    = [r[0] for r in cur.fetchall()]
        summary = {}
        for mac in macs:
            hist = self._get_history(mac)
            if hist:
                summary[mac] = {
                    "samples":        len(hist),
                    "avg_bytes_tx":   round(statistics.mean([h["bytes_tx"] for h in hist])),
                    "avg_bytes_rx":   round(statistics.mean([h["bytes_rx"] for h in hist])),
                    "avg_pkt_rate":   round(statistics.mean([h["pkt_rate"]  for h in hist]), 2),
                    "peak_hour":      max(set(h["hour"] for h in hist),
                                         key=lambda hr: sum(1 for h in hist if h["hour"]==hr)),
                }
        return summary

    def _alert(self, msg, level="high"):
        self.alerts.append({"level": level, "message": msg})

    def _print(self, msg):
        if self.verbose: print(msg)


if __name__ == "__main__":
    monitor = DeviceBaselineMonitor()
    mac = "AA:BB:CC:11:22:33"
    # Simulate baseline records
    import random
    for _ in range(20):
        monitor.record(mac,
                       bytes_tx=random.randint(1000, 5000),
                       bytes_rx=random.randint(5000, 20000),
                       pkt_rate=random.uniform(10, 50))
    # Score a suspicious observation (10x normal upload)
    result = monitor.score(mac, bytes_tx=80000, bytes_rx=18000, pkt_rate=45)
    print(f"\n  Anomaly detected: {result['anomaly']}")
