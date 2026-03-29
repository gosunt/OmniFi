"""
OmniFi — Trust Score Engine
=============================
Computes an explainable, weighted trust score (0–100) from all active
detection signals. Every score change produces a full explanation dict:

    {
        "score":      72,
        "delta":      -18,
        "verdict":    "caution",
        "components": [
            {"type": "arp_mitm",  "weight": 30, "confidence": 0.9,
             "explain": "Gateway MAC changed: AA:BB → CC:DD"},
            ...
        ],
        "recommendation": "Use VPN for all traffic.",
    }
"""
import datetime
import logging
import math
import threading
from dataclasses    import dataclass, field
from typing         import Dict, List, Optional, Tuple

log = logging.getLogger("OmniFi.TrustScore")


# ─────────────────────────────────────────────────────────────────────────────
# Signal definitions  — weight = max score penalty for that signal
# ─────────────────────────────────────────────────────────────────────────────
SIGNAL_WEIGHTS: Dict[str, int] = {
    # Critical  (can alone tank the score)
    "gateway_mac_change":   30,
    "evil_twin_confirmed":  28,
    "dns_spoof_confirmed":  25,
    "credential_harvest":   25,
    "deauth_flood":         20,
    "rogue_dhcp":           18,
    "icmp_redirect":        16,

    # High
    "arp_flood":            14,
    "bssid_mismatch":       12,
    "dns_ttl_anomaly":      10,
    "beacon_anomaly":       10,
    "session_hijack":       10,

    # Medium
    "nxdomain_spike":        7,
    "new_unknown_device":    5,
    "la_mac_device":         5,
    "weak_password":         4,
    "wps_enabled":           4,
    "no_pmf":                3,
    "open_encryption":       8,
    "wep_encryption":       10,

    # Low
    "high_congestion":       2,
    "captive_portal":        3,
    "signal_rssi_low":       1,
}

# Confidence thresholds: below this, signal counts at half weight
CONFIDENCE_HALF = 0.5

# Verdict bands
VERDICT_BANDS = [
    (90,  "safe",         "Network appears secure. Continue normal use."),
    (70,  "acceptable",   "Minor risk indicators. Use HTTPS and avoid sensitive tasks."),
    (50,  "caution",      "Moderate threat detected. Use a VPN for all traffic."),
    (25,  "elevated",     "Active attack indicators. Disconnect and use mobile data."),
    (0,   "critical",     "Critical attack confirmed. Disconnect immediately."),
]


@dataclass
class ScoreComponent:
    """One contributing factor to the trust score."""
    signal_type:  str
    weight:       int
    confidence:   float        # 0.0–1.0
    applied:      int          # actual penalty applied (weight × confidence)
    explain:      str
    ts:           str = field(default_factory=lambda: datetime.datetime.now().isoformat())

    def to_dict(self) -> dict:
        return {
            "type":       self.signal_type,
            "weight":     self.weight,
            "confidence": round(self.confidence, 2),
            "applied":    self.applied,
            "explain":    self.explain,
            "ts":         self.ts,
        }


@dataclass
class TrustResult:
    """Full scored result snapshot."""
    score:          int
    prev_score:     int
    verdict:        str
    recommendation: str
    components:     List[ScoreComponent] = field(default_factory=list)
    ts:             str = field(default_factory=lambda: datetime.datetime.now().isoformat())

    @property
    def delta(self) -> int:
        return self.score - self.prev_score

    def to_dict(self) -> dict:
        return {
            "score":          self.score,
            "prev_score":     self.prev_score,
            "delta":          self.delta,
            "verdict":        self.verdict,
            "recommendation": self.recommendation,
            "components":     [c.to_dict() for c in self.components],
            "ts":             self.ts,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Trust Score Engine
# ─────────────────────────────────────────────────────────────────────────────
class TrustScoreEngine:
    """
    Stateful scoring engine.  Detection modules call  add_signal()
    to register a threat; the engine recomputes the trust score and
    returns a TrustResult.

    Signals decay over time (default 10 minutes) to allow recovery
    when a threat is resolved.
    """

    DECAY_MINUTES = 10   # signal penalty halves every 10 min past expiry

    def __init__(self):
        self._lock    = threading.Lock()
        self._signals: Dict[str, dict] = {}   # signal_type → {confidence, explain, ts, expiry}
        self._history: List[TrustResult] = []
        self._prev_score = 100

    # ── Public API ────────────────────────────────────────────────────────────

    def add_signal(
        self,
        signal_type:  str,
        confidence:   float = 1.0,
        explain:      str   = "",
        expiry_min:   int   = 5,
    ) -> TrustResult:
        """
        Register a threat signal.  Recomputes score and returns TrustResult.

        Parameters
        ----------
        signal_type : key from SIGNAL_WEIGHTS
        confidence  : 0.0–1.0 (how confident the detector is)
        explain     : human-readable explanation string
        expiry_min  : minutes before this signal starts decaying
        """
        confidence = max(0.0, min(1.0, confidence))
        now        = datetime.datetime.now()
        expiry     = now + datetime.timedelta(minutes=expiry_min)

        with self._lock:
            existing = self._signals.get(signal_type)
            # Keep whichever confidence is higher
            if existing is None or confidence >= existing["confidence"]:
                self._signals[signal_type] = {
                    "confidence": confidence,
                    "explain":    explain or signal_type.replace("_", " ").title(),
                    "ts":         now.isoformat(),
                    "expiry":     expiry,
                }
            result = self._compute(now)
        self._history.append(result)
        log.info(f"[trust] signal={signal_type} conf={confidence:.2f} "
                 f"→ score={result.score} ({result.verdict})")
        return result

    def clear_signal(self, signal_type: str) -> TrustResult:
        """Remove a signal (threat resolved)."""
        with self._lock:
            self._signals.pop(signal_type, None)
            result = self._compute(datetime.datetime.now())
        self._history.append(result)
        return result

    def clear_all(self) -> TrustResult:
        """Reset — full trust restored."""
        with self._lock:
            self._signals.clear()
            result = self._compute(datetime.datetime.now())
        self._history.append(result)
        return result

    def current(self) -> TrustResult:
        """Return the latest computed score without adding a new signal."""
        with self._lock:
            return self._compute(datetime.datetime.now())

    def history(self, last_n: int = 60) -> List[dict]:
        """Return last N score snapshots as dicts (for graph rendering)."""
        return [r.to_dict() for r in self._history[-last_n:]]

    def score_for_alert(self, level: str) -> Tuple[str, float]:
        """
        Map an alert level to a (signal_type, confidence) pair for auto-ingestion.
        Called by AlertEngine after every new alert.
        """
        MAPPING = {
            "critical": [("gateway_mac_change", 0.95), ("evil_twin_confirmed", 0.90)],
            "high":     [("bssid_mismatch",     0.80), ("arp_flood",          0.75)],
            "medium":   [("new_unknown_device",  0.70), ("dns_ttl_anomaly",   0.60)],
            "low":      [("signal_rssi_low",     0.40)],
        }
        pairs = MAPPING.get(level, [("signal_rssi_low", 0.30)])
        return pairs[0]

    # ── Internals ─────────────────────────────────────────────────────────────

    def _compute(self, now: datetime.datetime) -> TrustResult:
        """Recompute score from all active signals (must hold _lock)."""
        components: List[ScoreComponent] = []
        total_penalty = 0

        for sig_type, info in list(self._signals.items()):
            base_weight = SIGNAL_WEIGHTS.get(sig_type, 5)
            confidence  = info["confidence"]
            expiry      = info["expiry"]

            # Apply time-decay for expired signals
            if now > expiry:
                minutes_past = (now - expiry).total_seconds() / 60
                decay_factor = math.exp(-0.693 * minutes_past / self.DECAY_MINUTES)
                confidence   = confidence * decay_factor
                if confidence < 0.05:
                    # Fully decayed — remove
                    del self._signals[sig_type]
                    continue

            # Half-weight if below confidence threshold
            if confidence < CONFIDENCE_HALF:
                effective_weight = base_weight * 0.5
            else:
                effective_weight = base_weight

            applied = int(effective_weight * confidence)
            total_penalty += applied

            components.append(ScoreComponent(
                signal_type=sig_type,
                weight=base_weight,
                confidence=confidence,
                applied=applied,
                explain=info["explain"],
                ts=info["ts"],
            ))

        # Sort by applied penalty descending
        components.sort(key=lambda c: c.applied, reverse=True)

        score = max(0, min(100, 100 - total_penalty))
        verdict, recommendation = self._verdict(score)
        result = TrustResult(
            score=score,
            prev_score=self._prev_score,
            verdict=verdict,
            recommendation=recommendation,
            components=components,
        )
        self._prev_score = score
        return result

    @staticmethod
    def _verdict(score: int) -> Tuple[str, str]:
        for threshold, verdict, recommendation in VERDICT_BANDS:
            if score >= threshold:
                return verdict, recommendation
        return "critical", VERDICT_BANDS[-1][2]


# ─────────────────────────────────────────────────────────────────────────────
# Module-level singleton
# ─────────────────────────────────────────────────────────────────────────────
TRUST_ENGINE: Optional[TrustScoreEngine] = None


def get_trust_engine() -> TrustScoreEngine:
    global TRUST_ENGINE
    if TRUST_ENGINE is None:
        TRUST_ENGINE = TrustScoreEngine()
    return TRUST_ENGINE
