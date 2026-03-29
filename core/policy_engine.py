"""
OmniFi — Policy Engine
=======================
Translates trust score thresholds into automated responses:

    Score < 50  → Hard mitigation   (quarantine + blacklist + DNS enforce)
    Score 50–74 → Soft mitigation   (alert + VPN prompt + notify)
    Score ≥ 75  → Alert only        (log + desktop notification)

Includes:
    • Expiry timers — hard mitigations auto-roll back after configured TTL
    • Cooldown — prevents hammering the same MAC repeatedly
    • Manual override — admin can promote/demote any mitigation level
    • Full audit trail (writes to responses table)
"""
import datetime
import logging
import threading
import time
from dataclasses import dataclass, field
from typing      import Callable, Dict, List, Optional

log = logging.getLogger("OmniFi.PolicyEngine")


# ─────────────────────────────────────────────────────────────────────────────
# Response levels
# ─────────────────────────────────────────────────────────────────────────────
class ResponseLevel:
    ALERT_ONLY = "alert_only"    # ≥ 75
    SOFT       = "soft"          # 50–74
    HARD       = "hard"          # < 50


@dataclass
class PolicyAction:
    mac:          str
    ip:           str
    level:        str            # ResponseLevel constant
    reason:       str
    score:        int
    auto:         bool           # True = triggered automatically
    ts:           str = field(default_factory=lambda: datetime.datetime.now().isoformat())
    expiry:       Optional[str]  = None
    rolled_back:  bool           = False
    rollback_ts:  Optional[str]  = None

    def to_dict(self) -> dict:
        return {
            "mac":        self.mac,
            "ip":         self.ip,
            "level":      self.level,
            "reason":     self.reason,
            "score":      self.score,
            "auto":       self.auto,
            "ts":         self.ts,
            "expiry":     self.expiry,
            "rolled_back":self.rolled_back,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Policy Engine
# ─────────────────────────────────────────────────────────────────────────────
class PolicyEngine:
    """
    Stateful policy engine.
    attach_enforcement(fn) to hook in the EnforcementEngine.
    attach_alert(fn)       to hook in the AlertBridge.
    attach_vpn(fn)         to hook in VPNLauncher.
    """

    # Defaults (overridable per-instance)
    SCORE_HARD       = 50    # < 50  → hard
    SCORE_SOFT       = 75    # < 75  → soft
    COOLDOWN_SEC     = 120   # don't re-trigger same MAC within this window
    HARD_EXPIRY_MIN  = 30    # auto-rollback hard mitigation after N minutes
    SOFT_EXPIRY_MIN  = 10    # auto-rollback soft mitigation

    def __init__(self):
        self._lock        = threading.Lock()
        self._active:     Dict[str, PolicyAction]   = {}   # mac → active action
        self._history:    List[PolicyAction]        = []
        self._cooldown:   Dict[str, float]          = {}   # mac → last_trigger_ts

        # Hooks (set by caller)
        self._enforce_fn:  Optional[Callable] = None  # fn(mac, action, ip) → dict
        self._alert_fn:    Optional[Callable] = None  # fn(level, source, msg, detail)
        self._vpn_fn:      Optional[Callable] = None  # fn(score)

        # Rollback timer
        self._timer = threading.Thread(target=self._rollback_loop, daemon=True)
        self._timer.start()

    # ── Hooks ─────────────────────────────────────────────────────────────────
    def attach_enforcement(self, fn: Callable): self._enforce_fn = fn
    def attach_alert(self, fn: Callable):       self._alert_fn   = fn
    def attach_vpn(self, fn: Callable):         self._vpn_fn     = fn

    # ── Core API ──────────────────────────────────────────────────────────────
    def evaluate(
        self,
        score:   int,
        mac:     str = "",
        ip:      str = "",
        reason:  str = "",
        auto:    bool = True,
    ) -> Optional[PolicyAction]:
        """
        Evaluate trust score and fire policy action if warranted.
        Returns the PolicyAction created, or None if no action taken.
        """
        if not mac:
            return None

        mac_upper = mac.upper()

        # Cooldown check
        now_ts = time.time()
        with self._lock:
            last = self._cooldown.get(mac_upper, 0)
            if now_ts - last < self.COOLDOWN_SEC:
                log.debug(f"[policy] cooldown active for {mac_upper}")
                return None

        level = self._score_to_level(score)
        action = self._create_action(mac_upper, ip, level, reason, score, auto)

        with self._lock:
            self._cooldown[mac_upper] = now_ts
            self._active[mac_upper]   = action
            self._history.append(action)

        self._execute(action)
        return action

    def manual_override(
        self,
        mac:    str,
        level:  str,
        ip:     str   = "",
        reason: str   = "Manual override",
    ) -> PolicyAction:
        """Admin-triggered forced action regardless of score."""
        mac_upper = mac.upper()
        action    = self._create_action(
            mac_upper, ip, level, reason, score=0, auto=False)
        with self._lock:
            self._active[mac_upper] = action
            self._history.append(action)
        self._execute(action)
        return action

    def rollback(self, mac: str, reason: str = "Manual rollback") -> bool:
        """Immediately roll back mitigation for a MAC."""
        mac_upper = mac.upper()
        with self._lock:
            action = self._active.pop(mac_upper, None)
        if not action:
            return False
        self._do_rollback(action, reason)
        return True

    def active_actions(self) -> List[dict]:
        with self._lock:
            return [a.to_dict() for a in self._active.values()]

    def history(self, last_n: int = 100) -> List[dict]:
        return [a.to_dict() for a in self._history[-last_n:]]

    # ── Score threshold ───────────────────────────────────────────────────────
    def _score_to_level(self, score: int) -> str:
        if score < self.SCORE_HARD:
            return ResponseLevel.HARD
        if score < self.SCORE_SOFT:
            return ResponseLevel.SOFT
        return ResponseLevel.ALERT_ONLY

    # ── Action creation ───────────────────────────────────────────────────────
    def _create_action(
        self, mac: str, ip: str, level: str,
        reason: str, score: int, auto: bool,
    ) -> PolicyAction:
        now    = datetime.datetime.now()
        expiry = None
        if level == ResponseLevel.HARD:
            expiry = (now + datetime.timedelta(
                minutes=self.HARD_EXPIRY_MIN)).isoformat()
        elif level == ResponseLevel.SOFT:
            expiry = (now + datetime.timedelta(
                minutes=self.SOFT_EXPIRY_MIN)).isoformat()
        return PolicyAction(
            mac=mac, ip=ip, level=level, reason=reason,
            score=score, auto=auto, expiry=expiry)

    # ── Execution ─────────────────────────────────────────────────────────────
    def _execute(self, action: PolicyAction):
        log.info(f"[policy] {action.level.upper()} → {action.mac}  score={action.score}  reason={action.reason}")

        # Write to DB
        try:
            from core.database import dbx
            dbx(
                "INSERT OR REPLACE INTO responses"
                "(mac, action, reason, score, auto_triggered, ts, expiry, rolled_back) "
                "VALUES(?,?,?,?,?,?,?,0)",
                (action.mac, action.level, action.reason,
                 action.score, 1 if action.auto else 0,
                 action.ts, action.expiry or ""))
        except Exception as e:
            log.debug(f"[policy] DB write: {e}")

        if action.level == ResponseLevel.ALERT_ONLY:
            self._do_alert(action, "low")
            return

        if action.level == ResponseLevel.SOFT:
            self._do_alert(action, "medium")
            self._do_soft(action)
            return

        if action.level == ResponseLevel.HARD:
            self._do_alert(action, "critical")
            self._do_hard(action)

    def _do_alert(self, action: PolicyAction, level: str):
        if self._alert_fn:
            try:
                self._alert_fn(
                    level, "policy_engine",
                    f"Policy response: {action.level.replace('_',' ').title()} → {action.mac}",
                    action.reason)
            except Exception as e:
                log.debug(f"[policy] alert hook: {e}")

    def _do_soft(self, action: PolicyAction):
        """Soft mitigation: prompt VPN, log, notify."""
        if self._vpn_fn:
            try:
                self._vpn_fn(action.score)
            except Exception as e:
                log.debug(f"[policy] vpn hook: {e}")
        log.warning(
            f"[policy:soft] {action.mac}  score={action.score}  "
            f"reason={action.reason}")

    def _do_hard(self, action: PolicyAction):
        """Hard mitigation: quarantine + blacklist + DNS enforce."""
        # 1. Quarantine via enforcement engine
        if self._enforce_fn:
            try:
                r = self._enforce_fn(action.mac, "blacklist", action.ip)
                log.info(f"[policy:hard] enforce result: {r}")
            except Exception as e:
                log.error(f"[policy:hard] enforce: {e}")

        # 2. Trigger VPN
        if self._vpn_fn:
            try:
                self._vpn_fn(0)   # score=0 → force connect
            except Exception as e:
                log.debug(f"[policy:hard] vpn: {e}")

    # ── Rollback ──────────────────────────────────────────────────────────────
    def _do_rollback(self, action: PolicyAction, reason: str = "Expired"):
        action.rolled_back  = True
        action.rollback_ts  = datetime.datetime.now().isoformat()
        log.info(f"[policy:rollback] {action.mac}  reason={reason}")
        try:
            from core.database import dbx
            dbx("UPDATE responses SET rolled_back=1 WHERE mac=? AND ts=?",
                (action.mac, action.ts))
        except Exception as e:
            log.debug(f"[policy] rollback DB: {e}")

        if self._enforce_fn and action.level == ResponseLevel.HARD:
            try:
                self._enforce_fn(action.mac, "remove_blacklist", action.ip)
            except Exception as e:
                log.debug(f"[policy] rollback enforce: {e}")

    def _rollback_loop(self):
        """Background thread — checks expiry timers every 60 s."""
        while True:
            time.sleep(60)
            try:
                now = datetime.datetime.now().isoformat()
                with self._lock:
                    expired = [
                        a for a in list(self._active.values())
                        if a.expiry and a.expiry < now
                    ]
                for action in expired:
                    with self._lock:
                        self._active.pop(action.mac, None)
                    self._do_rollback(action, "Auto-expiry")
            except Exception as e:
                log.debug(f"[policy] rollback loop: {e}")
