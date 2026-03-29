"""
OmniFi — Alert Engine.
Central hub for emitting, persisting, and broadcasting alerts.
All detection modules call AlertEngine.emit() — never write to DB directly.
"""
import datetime, logging, threading
from typing import Callable, Dict, List, Optional

from PyQt6.QtCore import QObject, pyqtSignal

from core.constants import Level, LEVEL_WEIGHT, CORR_RULES, SPIKE_THR
from core.database  import insert_alert, get_alerts as db_get_alerts

log = logging.getLogger("OmniFi.Alerts")


class AlertEngine(QObject):
    """
    Singleton alert bus.
    Detection modules → emit() → Qt signal → all connected UI widgets.
    Also feeds the correlation engine and time-spike detector internally.
    """
    # Qt signal emitted for every new alert  (received by UI panels)
    new_alert   = pyqtSignal(dict)
    # Emitted whenever trust score changes
    trust_changed = pyqtSignal(int, str)

    def __init__(self):
        super().__init__()
        self._lock           = threading.Lock()
        self._corr           = _CorrEngine(self)
        self._spike          = _SpikeDetector(self)
        self._recent: List[dict] = []   # in-memory ring (last 500)

    # ── public API ────────────────────────────────────────────────────────────

    def emit(
        self,
        level:      str,
        source:     str,
        message:    str,
        detail:     str        = "",
        actions:    list       = None,
        signals:    list       = None,
        corr_data:  dict       = None,
        spike_data: dict       = None,
    ) -> dict:
        """Create, persist, and broadcast one alert entry."""
        ts    = datetime.datetime.now().isoformat()
        entry = {
            "id":         int(datetime.datetime.now().timestamp() * 1000),
            "ts":         ts,
            "level":      level,
            "source":     source,
            "message":    message,
            "detail":     detail,
            "actions":    actions    or [],
            "corr_data":  corr_data,
            "spike_data": spike_data,
        }

        # Persist
        try:
            insert_alert(ts, level, source, message, detail)
        except Exception as e:
            log.error(f"DB write: {e}")

        # In-memory ring
        with self._lock:
            self._recent.insert(0, entry)
            if len(self._recent) > 500:
                self._recent = self._recent[:500]

        # Broadcast to UI
        self.new_alert.emit(entry)
        log.info(f"[{level.upper():8s}][{source}] {message}")

        # Feed correlation engine + spike detector
        for sig in (signals or []):
            self._corr.add_signal(sig)
            for etype in ("arp","deauth","dns","device"):
                if etype in sig:
                    self._spike.record(etype)

        # Recompute trust
        self._recompute_trust()
        return entry

    def get_recent(self, hours: int = 24) -> List[dict]:
        return db_get_alerts(hours)

    def trust_score(self) -> tuple:
        since   = (datetime.datetime.now() -
                   datetime.timedelta(hours=1)).isoformat()
        from core.database import dbq
        rows    = dbq("SELECT level FROM alerts WHERE ts>?", (since,))
        penalty = sum(LEVEL_WEIGHT.get(r["level"], 0) for r in rows)
        score   = max(0, min(100, 100 - penalty))
        verdict = "safe" if score >= 80 else "caution" if score >= 60 else "critical"
        return score, verdict

    # ── internal ─────────────────────────────────────────────────────────────

    def _recompute_trust(self):
        score, verdict = self.trust_score()
        self.trust_changed.emit(score, verdict)


# ─────────────────────────────────────────────────────────────────────────────
# Correlation engine  (internal to AlertEngine)
# ─────────────────────────────────────────────────────────────────────────────
class _CorrEngine:
    def __init__(self, ae: AlertEngine):
        self._ae     = ae
        self._sigs:  set  = set()
        self._fired: set  = set()
        self._found: list = []

    def add_signal(self, sig: str) -> None:
        self._sigs.add(sig)
        for rule in CORR_RULES:
            if rule["id"] in self._fired: continue
            if all(s in self._sigs for s in rule["signals"]):
                self._fired.add(rule["id"])
                entry = {**rule, "ts": datetime.datetime.now().isoformat()}
                self._found.append(entry)
                self._ae.emit(
                    rule["level"], "correlation_engine",
                    f"⚡ Correlation: {rule['result']}",
                    f"{rule['desc']} | Signals: {' + '.join(rule['signals'])} "
                    f"| Confidence: {rule['conf']}%",
                    ["vpn","block","investigate","ignore"],
                    corr_data=rule,
                )
                from core.database import dbx
                import json
                try:
                    dbx("INSERT INTO correlations(rule_id,result,signals,confidence,ts) "
                        "VALUES(?,?,?,?,?)",
                        (rule["id"], rule["result"],
                         json.dumps(rule["signals"]), rule["conf"],
                         entry["ts"]))
                except Exception:
                    pass

    def all_found(self) -> list:
        return list(self._found)

    def reset(self):
        self._sigs.clear(); self._fired.clear(); self._found.clear()


# ─────────────────────────────────────────────────────────────────────────────
# Time-spike detector  (internal to AlertEngine)
# ─────────────────────────────────────────────────────────────────────────────
import time
from collections import deque

class _SpikeDetector:
    def __init__(self, ae: AlertEngine):
        self._ae  = ae
        self._win: Dict[str, deque] = {k: deque() for k in SPIKE_THR}

    def record(self, etype: str) -> None:
        if etype not in self._win: return
        now = time.time()
        self._win[etype].append(now)
        while self._win[etype] and now - self._win[etype][0] > 60:
            self._win[etype].popleft()
        rate = len(self._win[etype])
        thr  = SPIKE_THR[etype]
        if   rate >= thr["crit"]:
            self._ae.emit(
                Level.CRITICAL, "time_detection",
                f"Frequency spike: {etype.upper()} = {rate}/60 s "
                f"(critical >{thr['crit']})",
                "Sudden activity surge — possible active attack.",
                ["investigate","block","ignore"],
                signals=[f"{etype}_spike"],
                spike_data={"type":etype,"rate":rate,"threshold":thr["crit"]},
            )
        elif rate >= thr["warn"]:
            log.info(f"[time_detection] {etype} elevated: {rate}/{thr['warn']} warn")

    def rates(self) -> Dict[str, int]:
        now = time.time()
        return {k: sum(1 for t in v if now-t < 60) for k, v in self._win.items()}

    def bins(self, etype: str, n: int = 60) -> list:
        now = time.time(); b = [0]*n
        for t in self._win.get(etype, []):
            idx = min(n-1, int(now-t))
            if 0 <= idx < n: b[n-1-idx] += 1
        return b


# ── Module-level singleton ────────────────────────────────────────────────────
# Imported as: from core.alert_engine import ALERTS
ALERTS: Optional[AlertEngine] = None

def init_alerts() -> AlertEngine:
    """Call once from main.py after QApplication exists."""
    global ALERTS
    ALERTS = AlertEngine()
    return ALERTS
