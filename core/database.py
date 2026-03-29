"""
OmniFi — Database layer (SQLite).
Thread-safe wrapper around a single connection.
All other modules call dbx() / dbq() from here.
"""
import sqlite3, threading, json, datetime, logging
from typing import Any, Dict, List, Optional
from core.constants import DB_PATH

log = logging.getLogger("OmniFi.DB")

_CONN: Optional[sqlite3.Connection] = None
_LOCK = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts(
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT    NOT NULL,
    level   TEXT    NOT NULL,
    source  TEXT    NOT NULL,
    message TEXT    NOT NULL,
    detail  TEXT    DEFAULT ''
);
CREATE TABLE IF NOT EXISTS devices(
    mac         TEXT PRIMARY KEY,
    vendor      TEXT DEFAULT '',
    hostname    TEXT DEFAULT '',
    device_type TEXT DEFAULT '',
    ip          TEXT DEFAULT '',
    os_guess    TEXT DEFAULT '',
    status      TEXT DEFAULT 'unknown',
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policy(
    mac         TEXT NOT NULL,
    policy_type TEXT NOT NULL,
    reason      TEXT DEFAULT '',
    added       TEXT NOT NULL,
    expiry      TEXT DEFAULT '',
    PRIMARY KEY (mac, policy_type)
);
CREATE TABLE IF NOT EXISTS ssid_history(
    ssid       TEXT NOT NULL,
    bssid      TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    trusted    INTEGER DEFAULT 1,
    PRIMARY KEY (ssid, bssid)
);
CREATE TABLE IF NOT EXISTS arp_baseline(
    ip   TEXT PRIMARY KEY,
    mac  TEXT NOT NULL,
    seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dns_baseline(
    domain    TEXT PRIMARY KEY,
    known_ips TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS saved_networks(
    ssid            TEXT PRIMARY KEY,
    password_masked TEXT DEFAULT '',
    pwd_score       INTEGER DEFAULT 0,
    pwd_issues      TEXT    DEFAULT '[]',
    proto           TEXT    DEFAULT '',
    entropy         REAL    DEFAULT 0,
    last_seen       TEXT    NOT NULL
);
CREATE TABLE IF NOT EXISTS correlations(
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id    TEXT NOT NULL,
    result     TEXT NOT NULL,
    signals    TEXT NOT NULL,
    confidence INTEGER DEFAULT 0,
    ts         TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS device_telemetry(
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    mac      TEXT NOT NULL,
    ts       TEXT NOT NULL,
    bytes_tx INTEGER DEFAULT 0,
    bytes_rx INTEGER DEFAULT 0,
    pkt_rate REAL    DEFAULT 0
);
CREATE TABLE IF NOT EXISTS telemetry(
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT    NOT NULL,
    mac         TEXT    DEFAULT '',
    ip          TEXT    DEFAULT '',
    bytes_tx    INTEGER DEFAULT 0,
    bytes_rx    INTEGER DEFAULT 0,
    pkt_rate    REAL    DEFAULT 0,
    rssi        INTEGER DEFAULT -90,
    latency_ms  REAL    DEFAULT 0,
    dns_queries INTEGER DEFAULT 0,
    trust_score INTEGER DEFAULT 100
);
CREATE TABLE IF NOT EXISTS responses(
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    mac             TEXT    NOT NULL,
    action          TEXT    NOT NULL,
    reason          TEXT    DEFAULT '',
    score           INTEGER DEFAULT 0,
    auto_triggered  INTEGER DEFAULT 0,
    ts              TEXT    NOT NULL,
    expiry          TEXT    DEFAULT '',
    rolled_back     INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS trust_history(
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    ts    TEXT    NOT NULL,
    score INTEGER NOT NULL,
    verdict TEXT  DEFAULT '',
    signals TEXT  DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts    ON alerts(ts DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry    ON device_telemetry(mac, ts DESC);
CREATE INDEX IF NOT EXISTS idx_tel_ts       ON telemetry(ts DESC);
CREATE INDEX IF NOT EXISTS idx_responses_ts ON responses(ts DESC);
"""


def _conn() -> sqlite3.Connection:
    global _CONN
    if _CONN is None:
        _CONN = sqlite3.connect(DB_PATH, check_same_thread=False)
        _CONN.row_factory = sqlite3.Row
        _CONN.executescript(SCHEMA)
        _CONN.commit()
        log.info(f"Database opened: {DB_PATH}")
    return _CONN


def dbx(sql: str, params: tuple = ()) -> None:
    """Execute a write statement."""
    with _LOCK:
        _conn().execute(sql, params)
        _conn().commit()


def dbq(sql: str, params: tuple = ()) -> List[sqlite3.Row]:
    """Execute a read query and return all rows."""
    with _LOCK:
        return _conn().execute(sql, params).fetchall()


def dbq1(sql: str, params: tuple = ()) -> Optional[sqlite3.Row]:
    """Execute a read query and return the first row or None."""
    with _LOCK:
        return _conn().execute(sql, params).fetchone()


# ── Convenience helpers ───────────────────────────────────────────────────────

def insert_alert(ts: str, level: str, source: str,
                 message: str, detail: str = "") -> int:
    with _LOCK:
        cur = _conn().execute(
            "INSERT INTO alerts(ts,level,source,message,detail) VALUES(?,?,?,?,?)",
            (ts, level, source, message, detail))
        _conn().commit()
        return cur.lastrowid


def get_alerts(hours: int = 24, limit: int = 500) -> List[dict]:
    since = (datetime.datetime.now() -
             datetime.timedelta(hours=hours)).isoformat()
    rows  = dbq("SELECT * FROM alerts WHERE ts>? ORDER BY ts DESC LIMIT ?",
                (since, limit))
    return [dict(r) for r in rows]


def get_devices() -> List[dict]:
    return [dict(r) for r in dbq("SELECT * FROM devices ORDER BY last_seen DESC")]


def upsert_device(mac: str, ip: str, vendor: str = "",
                  hostname: str = "", status: str = "unknown") -> None:
    now = datetime.datetime.now().isoformat()
    row = dbq1("SELECT mac FROM devices WHERE mac=?", (mac,))
    if row:
        dbx("UPDATE devices SET ip=?,last_seen=?,vendor=COALESCE(NULLIF(?,vendor),vendor) "
            "WHERE mac=?", (ip, now, vendor, mac))
    else:
        dbx("INSERT INTO devices(mac,vendor,hostname,device_type,ip,"
            "os_guess,status,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?)",
            (mac, vendor, hostname, "", ip, "", status, now, now))


def get_policy() -> List[dict]:
    return [dict(r) for r in dbq("SELECT * FROM policy ORDER BY added DESC")]


def add_policy(mac: str, ptype: str, reason: str = "",
               expiry_min: int = 0) -> None:
    now    = datetime.datetime.now().isoformat()
    expiry = ""
    if expiry_min > 0:
        expiry = (datetime.datetime.now() +
                  datetime.timedelta(minutes=expiry_min)).isoformat()
    dbx("INSERT OR REPLACE INTO policy(mac,policy_type,reason,added,expiry) "
        "VALUES(?,?,?,?,?)", (mac.upper(), ptype, reason, now, expiry))


def remove_policy(mac: str, ptype: str) -> None:
    dbx("DELETE FROM policy WHERE mac=? AND policy_type=?", (mac.upper(), ptype))


def clean_expired_policy() -> None:
    dbx("DELETE FROM policy WHERE expiry!='' AND expiry<?",
        (datetime.datetime.now().isoformat(),))


def persist_saved_network(ssid: str, pwd_masked: str, score: int,
                          issues: list, proto: str, entropy: float) -> None:
    now = datetime.datetime.now().isoformat()
    dbx("INSERT OR REPLACE INTO saved_networks "
        "(ssid,password_masked,pwd_score,pwd_issues,proto,entropy,last_seen) "
        "VALUES(?,?,?,?,?,?,?)",
        (ssid, pwd_masked, score, json.dumps(issues), proto, entropy, now))


def get_saved_networks() -> List[dict]:
    return [dict(r) for r in dbq(
        "SELECT * FROM saved_networks ORDER BY pwd_score ASC")]
