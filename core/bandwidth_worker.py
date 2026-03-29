"""
OmniFi — Bandwidth Worker (QThread)
=====================================
Bridges the TelemetryEngine (which stores cumulative rx/tx byte counters)
to the BandwidthMeterWidget (which needs instantaneous bps values).

Usage in MainWindow / Dashboard:
    from core.bandwidth_worker import BandwidthWorker
    bw_worker = BandwidthWorker(telemetry_engine)
    bw_worker.stats_ready.connect(bandwidth_widget.update_stats)
    bw_worker.start()

Emits  stats_ready(dict)  every INTERVAL seconds. The dict format is:
    {
      "192.168.1.10": {
          "mac": "aa:bb:cc:dd:ee:ff",
          "hostname": "Samsung TV",
          "rx_bps": 4194304.0,    # bytes/sec
          "tx_bps": 524288.0,
          "rx_total": 104857600,
          "tx_total": 5242880,
          "signal_dbm": -62,
      },
      ...
    }
"""
from __future__ import annotations

import logging
import time
from typing import Dict, List

from PyQt6.QtCore import QThread, pyqtSignal

log = logging.getLogger("OmniFi.BandwidthWorker")


class BandwidthWorker(QThread):
    """
    Periodically samples the TelemetryEngine ring-buffer, computes
    per-device bps deltas, and emits stats_ready.
    """

    stats_ready = pyqtSignal(dict)   # {ip: {mac, hostname, rx_bps, tx_bps, ...}}

    INTERVAL_SEC = 2     # emit interval
    SAMPLE_WINDOW = 4    # compare most-recent sample vs N seconds ago

    def __init__(self, telemetry_engine=None, parent=None):
        super().__init__(parent)
        self._tel = telemetry_engine
        self._run = True
        # Local prev-sample cache for delta calc
        self._prev: Dict[str, dict] = {}   # mac → {ts, rx, tx}

    # ── Public ────────────────────────────────────────────────────────────────
    def set_telemetry(self, engine) -> None:
        """Inject telemetry engine after construction (called after login)."""
        self._tel = engine

    def stop(self) -> None:
        self._run = False

    # ── Thread ────────────────────────────────────────────────────────────────
    def run(self):
        self._run = True
        while self._run:
            try:
                stats = self._compute()
                if stats:
                    self.stats_ready.emit(stats)
            except Exception as e:
                log.debug(f"[BW] worker error: {e}")
            self.msleep(self.INTERVAL_SEC * 1000)

    def _compute(self) -> Dict[str, dict]:
        """
        Pull latest samples from the telemetry ring buffer and compute
        per-device bps using simple delta from previous sample.
        """
        if self._tel is None:
            # Fallback: try to read from OS network counters directly
            return self._os_fallback()

        try:
            ring = list(self._tel._ring)   # copy the deque
        except Exception:
            return {}

        # Group latest sample per MAC
        latest: Dict[str, dict] = {}
        for sample in ring:
            d = sample.to_dict() if hasattr(sample, "to_dict") else sample
            mac = d.get("mac", "")
            if mac and mac not in latest:
                latest[mac] = d

        result: Dict[str, dict] = {}
        now = time.time()

        for mac, s in latest.items():
            rx = s.get("rx_bytes", 0) or 0
            tx = s.get("tx_bytes", 0) or 0
            ts_raw = s.get("ts", now)
            try:
                ts = float(ts_raw) if isinstance(ts_raw, (int, float)) else now
            except Exception:
                ts = now

            ip = s.get("ip", mac)
            hostname = s.get("hostname", "")
            rssi = s.get("rssi", None)

            prev = self._prev.get(mac)
            rx_bps = tx_bps = 0.0
            if prev:
                dt = max(ts - prev["ts"], 0.5)
                rx_bps = max(0.0, (rx - prev["rx"]) / dt)
                tx_bps = max(0.0, (tx - prev["tx"]) / dt)

            self._prev[mac] = {"ts": ts, "rx": rx, "tx": tx}

            result[ip] = {
                "mac":        mac,
                "hostname":   hostname,
                "rx_bps":     rx_bps,
                "tx_bps":     tx_bps,
                "rx_total":   rx,
                "tx_total":   tx,
                "signal_dbm": rssi,
            }

        return result

    def _os_fallback(self) -> Dict[str, dict]:
        """
        Read /proc/net/dev (Linux) or psutil (cross-platform) as fallback
        when TelemetryEngine is not yet wired.  Returns aggregate, not per-device.
        """
        try:
            import psutil
            ifaces = psutil.net_io_counters(pernic=True)
            result = {}
            for iface, counters in ifaces.items():
                # Skip loopback and virtual interfaces
                if iface in ("lo", "Loopback Pseudo-Interface 1"):
                    continue
                if iface.startswith(("veth", "docker", "br-", "vmnet")):
                    continue

                mac = iface   # use iface name as key when IP unavailable
                prev = self._prev.get(mac)
                rx = counters.bytes_recv
                tx = counters.bytes_sent
                now = time.time()

                rx_bps = tx_bps = 0.0
                if prev:
                    dt = max(now - prev["ts"], 0.5)
                    rx_bps = max(0.0, (rx - prev["rx"]) / dt)
                    tx_bps = max(0.0, (tx - prev["tx"]) / dt)

                self._prev[mac] = {"ts": now, "rx": rx, "tx": tx}
                result[iface] = {
                    "mac":        "",
                    "hostname":   iface,
                    "rx_bps":     rx_bps,
                    "tx_bps":     tx_bps,
                    "rx_total":   rx,
                    "tx_total":   tx,
                    "signal_dbm": None,
                }
            return result
        except Exception as e:
            log.debug(f"[BW] os_fallback error: {e}")
            return {}
