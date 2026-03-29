"""
OmniFi — Network Access Control (NAC) Engine
===============================================
Implements the "quarantine-first" device onboarding flow:

  Phase 1 — Quarantine
  ─────────────────────
  When a NEW device is detected on the network (MAC never seen before):
    • Immediately put it on the quarantine VLAN / guest network via the
      router API (openwrt_client or router_sitemap).
    • Record the device in the NAC database with state = "quarantine".
    • Fire an alert so the admin is notified.

  Phase 2 — Admin Review
  ───────────────────────
  The admin sees the quarantined device in the Live-Device panel.
  They can:
    ✔ Approve → whitelist the MAC, call release_quarantine(), move to main net.
    ✗ Block   → blacklist the MAC, device stays off.
    ? Ignore  → device stays in quarantine indefinitely.

  Phase 3 — Promotion
  ────────────────────
  On approval:
    • Move device from quarantine VLAN to main VLAN.
    • Add MAC to persistent whitelist.
    • Log the decision + approver timestamp.

Non-admin (client) mode:
  • NAC engine still tracks new devices and alerts the user, but cannot
    perform router-level quarantine. Instead it uses local firewall rules
    (iptables / netsh) if available.

The engine runs as a background thread polling ARP table changes.
"""
from __future__ import annotations

import logging
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

log = logging.getLogger("OmniFi.NAC")

_DB_PATH = str(Path(__file__).parent.parent / "db" / "nac.db")

# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class NACDevice:
    mac: str
    ip: str = ""
    hostname: str = ""
    vendor: str = ""
    state: str = "new"          # new / quarantine / approved / blocked
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    approved_by: str = ""
    notes: str = ""


# ─────────────────────────────────────────────────────────────────────────────
class NACEngine:
    """
    Instantiate once and call  start()  to begin ARP polling.
    Inject  router_client  (openwrt_client.OpenWRTClient or None) after
    admin login so the engine can perform actual VLAN moves.
    """

    POLL_SEC = 15      # ARP poll interval
    AUTO_QUARANTINE = True   # set False to alert-only without router push

    def __init__(self,
                 db_path: str = _DB_PATH,
                 on_new_device: Optional[Callable[[NACDevice], None]] = None,
                 verbose: bool = True):
        self._db_path = db_path
        self._on_new = on_new_device
        self._verbose = verbose
        self._stop = threading.Event()
        self._router = None          # injected later
        self._lock = threading.Lock()
        self._approved_macs: set = set()
        self._blocked_macs:  set = set()
        self._init_db()
        self._load_known_macs()

    # ── Public ───────────────────────────────────────────────────────────────
    def set_router(self, router_client) -> None:
        """Inject an authenticated openwrt_client or sitemap-based client."""
        self._router = router_client

    def start(self) -> None:
        self._stop.clear()
        t = threading.Thread(target=self._poll_loop, daemon=True, name="NAC-poll")
        t.start()
        self._print("NAC engine started.")

    def stop(self) -> None:
        self._stop.set()

    def approve(self, mac: str, admin_note: str = "") -> bool:
        """Admin approves device → moves from quarantine to main network."""
        mac = mac.lower().strip()
        ok = self._release_quarantine(mac)
        self._set_state(mac, "approved", admin_note)
        with self._lock:
            self._approved_macs.add(mac)
            self._blocked_macs.discard(mac)
        self._alert(f"Device {mac} approved by admin — moved to main network.", "low")
        return ok

    def block(self, mac: str, reason: str = "") -> bool:
        """Admin blocks a device permanently."""
        mac = mac.lower().strip()
        ok = self._push_block(mac)
        self._set_state(mac, "blocked", reason)
        with self._lock:
            self._blocked_macs.add(mac)
            self._approved_macs.discard(mac)
        self._alert(f"Device {mac} blocked by admin.", "medium")
        return ok

    def get_quarantined(self) -> List[NACDevice]:
        return self._query_state("quarantine")

    def get_all(self) -> List[NACDevice]:
        return self._query_all()

    def is_known(self, mac: str) -> bool:
        mac = mac.lower().strip()
        with self._lock:
            return mac in self._approved_macs or mac in self._blocked_macs

    # ── Background poll ───────────────────────────────────────────────────────
    def _poll_loop(self):
        while not self._stop.is_set():
            try:
                arp = self._read_arp()
                for ip, mac in arp.items():
                    mac = mac.lower().strip()
                    if not self.is_known(mac):
                        self._handle_new_device(mac, ip)
            except Exception as e:
                log.debug(f"[NAC] poll error: {e}")
            time.sleep(self.POLL_SEC)

    def _handle_new_device(self, mac: str, ip: str):
        """First time we see this MAC — quarantine it."""
        vendor = self._oui_vendor(mac)
        hostname = self._resolve_hostname(ip)
        dev = NACDevice(mac=mac, ip=ip, hostname=hostname, vendor=vendor,
                        state="quarantine")
        self._save_device(dev)
        with self._lock:
            # Mark as "seen" to avoid re-triggering on next poll
            self._approved_macs.add(mac)   # prevents loop; state is DB-tracked
        msg = (f"New device detected: MAC={mac} IP={ip} "
               f"vendor={vendor} — auto-quarantined.")
        self._alert(msg, "high")
        self._print(f"  [NAC] {msg}")

        if self._on_new:
            try:
                self._on_new(dev)
            except Exception:
                pass

        if self.AUTO_QUARANTINE and self._router:
            try:
                ok = self._router.quarantine_mac(mac)
                self._print(f"  [NAC] Router quarantine push: {'OK' if ok else 'FAILED'}")
            except Exception as e:
                log.debug(f"[NAC] router quarantine error: {e}")

    # ── Router actions ────────────────────────────────────────────────────────
    def _release_quarantine(self, mac: str) -> bool:
        if self._router:
            try:
                return bool(self._router.release_quarantine(mac))
            except Exception as e:
                log.debug(f"[NAC] release_quarantine error: {e}")
        return False

    def _push_block(self, mac: str) -> bool:
        if self._router:
            try:
                ok, _ = self._router.block_mac(mac)
                return ok
            except Exception as e:
                log.debug(f"[NAC] block_mac error: {e}")
        return False

    # ── Database ──────────────────────────────────────────────────────────────
    def _init_db(self):
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self._db_path) as con:
            con.execute("""
                CREATE TABLE IF NOT EXISTS nac_devices (
                    mac TEXT PRIMARY KEY,
                    ip TEXT,
                    hostname TEXT,
                    vendor TEXT,
                    state TEXT DEFAULT 'quarantine',
                    first_seen REAL,
                    last_seen  REAL,
                    approved_by TEXT,
                    notes TEXT
                )""")
            con.commit()

    def _load_known_macs(self):
        try:
            with sqlite3.connect(self._db_path) as con:
                rows = con.execute(
                    "SELECT mac, state FROM nac_devices").fetchall()
            with self._lock:
                for mac, state in rows:
                    if state == "approved":
                        self._approved_macs.add(mac)
                    elif state == "blocked":
                        self._blocked_macs.add(mac)
                    # quarantine MACs are re-evaluated on each run
        except Exception as e:
            log.debug(f"[NAC] load known macs: {e}")

    def _save_device(self, dev: NACDevice):
        try:
            with sqlite3.connect(self._db_path) as con:
                con.execute("""
                    INSERT OR REPLACE INTO nac_devices
                    (mac,ip,hostname,vendor,state,first_seen,last_seen,approved_by,notes)
                    VALUES (?,?,?,?,?,?,?,?,?)
                """, (dev.mac, dev.ip, dev.hostname, dev.vendor,
                      dev.state, dev.first_seen, dev.last_seen,
                      dev.approved_by, dev.notes))
                con.commit()
        except Exception as e:
            log.debug(f"[NAC] save_device error: {e}")

    def _set_state(self, mac: str, state: str, notes: str = ""):
        try:
            with sqlite3.connect(self._db_path) as con:
                con.execute(
                    "UPDATE nac_devices SET state=?, notes=?, last_seen=? WHERE mac=?",
                    (state, notes, time.time(), mac))
                con.commit()
        except Exception as e:
            log.debug(f"[NAC] set_state error: {e}")

    def _query_state(self, state: str) -> List[NACDevice]:
        try:
            with sqlite3.connect(self._db_path) as con:
                rows = con.execute(
                    "SELECT mac,ip,hostname,vendor,state,first_seen,last_seen,approved_by,notes "
                    "FROM nac_devices WHERE state=?", (state,)).fetchall()
            return [NACDevice(*r) for r in rows]
        except Exception:
            return []

    def _query_all(self) -> List[NACDevice]:
        try:
            with sqlite3.connect(self._db_path) as con:
                rows = con.execute(
                    "SELECT mac,ip,hostname,vendor,state,first_seen,last_seen,approved_by,notes "
                    "FROM nac_devices ORDER BY last_seen DESC").fetchall()
            return [NACDevice(*r) for r in rows]
        except Exception:
            return []

    # ── Helpers ───────────────────────────────────────────────────────────────
    @staticmethod
    def _read_arp() -> Dict[str, str]:
        """Return {ip: mac} from OS ARP table."""
        import subprocess, re as _re, platform
        table: Dict[str, str] = {}
        try:
            if platform.system() == "Windows":
                out = subprocess.check_output(["arp", "-a"], text=True, timeout=5)
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 2:
                        ip, mac = parts[0], parts[1].replace("-", ":")
                        if _re.match(r"\d+\.\d+\.\d+\.\d+", ip) and len(mac) == 17:
                            table[ip] = mac
            else:
                out = subprocess.check_output(["arp", "-n"], text=True, timeout=5)
                for line in out.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 3 and ":" in parts[2]:
                        table[parts[0]] = parts[2]
        except Exception as e:
            log.debug(f"[NAC] arp read error: {e}")
        return table

    @staticmethod
    def _resolve_hostname(ip: str) -> str:
        try:
            import socket
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ""

    @staticmethod
    def _oui_vendor(mac: str) -> str:
        try:
            from admin_mode.oui_lookup import OUILookup
            return OUILookup().lookup(mac)
        except Exception:
            return mac[:8].upper()

    def _alert(self, msg: str, level: str = "high"):
        try:
            from core.monitor_utils import ALERTS
            ALERTS.emit_alert(level, "nac", msg, signals=["nac_event"])
        except Exception:
            pass

    def _print(self, msg: str):
        if self._verbose:
            log.info(msg)
