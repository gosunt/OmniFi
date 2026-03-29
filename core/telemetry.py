"""
OmniFi — Telemetry Engine
===========================
Continuously records network telemetry samples to the telemetry table.
Used by:
  • The trust score graph (last N samples)
  • The device anomaly detector (Z-score on per-device stats)
  • PDF reports (historical charts)

Each sample contains:
  ts, mac, ip, rx_bytes, tx_bytes, pkt_rate, rssi, latency_ms, dns_queries
"""
import datetime
import logging
import threading
import time
from dataclasses import dataclass, field
from typing      import Dict, List, Optional

log = logging.getLogger("OmniFi.Telemetry")


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class TelemetrySample:
    ts:          str   = field(default_factory=lambda: datetime.datetime.now().isoformat())
    mac:         str   = ""
    ip:          str   = ""
    rx_bytes:    int   = 0
    tx_bytes:    int   = 0
    pkt_rate:    float = 0.0    # packets/second
    rssi:        int   = -90    # dBm
    latency_ms:  float = 0.0    # ping to gateway
    dns_queries: int   = 0
    trust_score: int   = 100

    def to_dict(self) -> dict:
        return self.__dict__.copy()

    def to_db_tuple(self):
        return (
            self.ts, self.mac, self.ip,
            self.rx_bytes, self.tx_bytes, self.pkt_rate,
            self.rssi, self.latency_ms, self.dns_queries, self.trust_score,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Telemetry Engine
# ─────────────────────────────────────────────────────────────────────────────
class TelemetryEngine:
    """
    Gathers periodic network samples.
    Call  start()  to begin background recording every POLL_SEC seconds.
    """

    POLL_SEC       = 15
    RING_CAPACITY  = 240    # in-memory ring (240 × 15 s = 60 min)

    def __init__(self):
        self._ring:     List[TelemetrySample] = []
        self._lock      = threading.Lock()
        self._running   = False
        self._thread:   Optional[threading.Thread] = None
        self._prev_net: Optional[dict] = None    # for delta bytes
        self._trust_fn  = None    # optional callable() → int

    def attach_trust(self, fn):
        """Supply a callable that returns current trust score."""
        self._trust_fn = fn

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread  = threading.Thread(
            target=self._loop, daemon=True, name="TelemetryEngine")
        self._thread.start()
        log.info("Telemetry engine started")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    # ── Query API ─────────────────────────────────────────────────────────────

    def latest(self, n: int = 60) -> List[dict]:
        """Return last n samples as dicts (newest last)."""
        with self._lock:
            return [s.to_dict() for s in self._ring[-n:]]

    def trust_history(self, n: int = 60) -> List[tuple]:
        """Return [(ts, score), …] for the live trust graph."""
        with self._lock:
            return [(s.ts, s.trust_score) for s in self._ring[-n:]]

    def device_samples(self, mac: str, n: int = 60) -> List[dict]:
        with self._lock:
            return [s.to_dict() for s in self._ring
                    if s.mac.upper() == mac.upper()][-n:]

    def from_db(self, hours: int = 1) -> List[dict]:
        """Fetch older samples from the database."""
        try:
            from core.database import dbq
            since = (datetime.datetime.now() -
                     datetime.timedelta(hours=hours)).isoformat()
            rows  = dbq(
                "SELECT * FROM telemetry WHERE ts > ? ORDER BY ts ASC", (since,))
            return [dict(r) for r in rows]
        except Exception as e:
            log.debug(f"telemetry from_db: {e}")
            return []

    # ── Internals ─────────────────────────────────────────────────────────────

    def _loop(self):
        while self._running:
            try:
                sample = self._collect()
                self._store(sample)
            except Exception as e:
                log.debug(f"telemetry loop: {e}")
            time.sleep(self.POLL_SEC)

    def _collect(self) -> TelemetrySample:
        sample = TelemetrySample()

        # Trust score
        if self._trust_fn:
            try:
                sample.trust_score = int(self._trust_fn())
            except Exception:
                pass

        # Network stats via psutil (if available)
        try:
            import psutil
            counters = psutil.net_io_counters()
            if self._prev_net:
                dt = self.POLL_SEC
                sample.rx_bytes = int(
                    (counters.bytes_recv - self._prev_net["bytes_recv"]) / dt)
                sample.tx_bytes = int(
                    (counters.bytes_sent - self._prev_net["bytes_sent"]) / dt)
                sample.pkt_rate = round(
                    (counters.packets_recv + counters.packets_sent -
                     self._prev_net["pkts"]) / dt, 1)
            self._prev_net = {
                "bytes_recv": counters.bytes_recv,
                "bytes_sent": counters.bytes_sent,
                "pkts":       counters.packets_recv + counters.packets_sent,
            }
        except ImportError:
            pass
        except Exception as e:
            log.debug(f"telemetry psutil: {e}")

        # Gateway latency via ICMP ping
        sample.latency_ms = self._ping_gateway()

        return sample

    @staticmethod
    def _ping_gateway() -> float:
        try:
            from core.compatibility import OS
            gw = OS.gateway_ip()
            if not gw:
                return 0.0
            import platform, subprocess
            if platform.system() == "Windows":
                cmd = ["ping", "-n", "1", "-w", "500", gw]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", gw]
            p   = subprocess.run(cmd, capture_output=True, text=True,
                                 errors="ignore", timeout=3)
            m   = re.search(r"time[=<]([\d.]+)", p.stdout)
            return float(m.group(1)) if m else 0.0
        except Exception:
            return 0.0

    def _store(self, sample: TelemetrySample):
        with self._lock:
            self._ring.append(sample)
            if len(self._ring) > self.RING_CAPACITY:
                self._ring = self._ring[-self.RING_CAPACITY:]

        try:
            from core.database import dbx
            dbx(
                "INSERT INTO telemetry"
                "(ts,mac,ip,bytes_tx,bytes_rx,pkt_rate,"
                " rssi,latency_ms,dns_queries,trust_score)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                sample.to_db_tuple())
        except Exception as e:
            log.debug(f"telemetry DB write: {e}")


import re   # used by _ping_gateway

# ── Singleton ─────────────────────────────────────────────────────────────────
_INSTANCE: Optional[TelemetryEngine] = None


def get_telemetry() -> TelemetryEngine:
    global _INSTANCE
    if _INSTANCE is None:
        _INSTANCE = TelemetryEngine()
    return _INSTANCE
