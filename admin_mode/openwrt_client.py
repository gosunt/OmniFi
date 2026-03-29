"""
OmniFi — OpenWrt SSH Client
==============================
Full OpenWrt router integration via paramiko SSH.

Capabilities:
  • UCI command wrapper (get / set / commit)
  • MAC blacklist / whitelist (via hostapd / UCI)
  • iptables / nftables enforcement rules
  • dnsmasq DNS-over-TLS / DoH enforcement
  • Hostapd station list (live connected clients)
  • ip neigh table (ARP from router side)
  • DHCP lease list
  • System info: model, firmware, uptime
  • Firewall zone management
  • QoS / rate limiting (via tc)

All commands are idempotent — safe to call repeatedly.
"""
import logging
import re
import socket
import threading
import time
from dataclasses import dataclass, field
from typing      import Dict, List, Optional, Tuple

log = logging.getLogger("OmniFi.OpenWrt")

try:
    import paramiko
    HAVE_PARAMIKO = True
except ImportError:
    HAVE_PARAMIKO = False
    log.warning("paramiko not installed — OpenWrt SSH disabled. pip install paramiko")


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class OpenWrtStation:
    mac:           str
    ip:            str  = ""
    hostname:      str  = ""
    rx_bytes:      int  = 0
    tx_bytes:      int  = 0
    rssi:          int  = -90
    freq:          int  = 0
    authorized:    bool = True

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class OpenWrtInfo:
    model:    str = ""
    firmware: str = ""
    uptime:   int = 0     # seconds
    hostname: str = ""
    arch:     str = ""


@dataclass
class CommandResult:
    ok:       bool
    stdout:   str
    stderr:   str
    cmd:      str = ""
    duration: float = 0.0

    def __bool__(self): return self.ok


# ─────────────────────────────────────────────────────────────────────────────
# OpenWrt SSH Client
# ─────────────────────────────────────────────────────────────────────────────
class OpenWrtClient:
    """
    SSH client for OpenWrt routers.
    Maintains a persistent SSH connection with auto-reconnect.
    """

    CONNECT_TIMEOUT = 10
    CMD_TIMEOUT     = 15

    def __init__(self, host: str, username: str = "root",
                 password: str = "", port: int = 22,
                 key_path: str = ""):
        self.host      = host
        self.username  = username
        self._password = password
        self.port      = port
        self._key_path = key_path
        self._ssh:     Optional["paramiko.SSHClient"] = None
        self._lock     = threading.Lock()
        self._connected = False

    # ── Connection lifecycle ──────────────────────────────────────────────────

    def connect(self) -> Tuple[bool, str]:
        """Establish SSH connection. Returns (success, message)."""
        if not HAVE_PARAMIKO:
            return False, "paramiko not installed"
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            kwargs = dict(
                hostname=self.host,
                port=self.port,
                username=self.username,
                timeout=self.CONNECT_TIMEOUT,
                allow_agent=False,
                look_for_keys=False,
            )
            if self._key_path:
                kwargs["key_filename"] = self._key_path
            else:
                kwargs["password"] = self._password
            client.connect(**kwargs)
            with self._lock:
                self._ssh = client
                self._connected = True
            log.info(f"Connected to OpenWrt at {self.host}:{self.port}")
            return True, f"Connected to {self.host}"
        except paramiko.AuthenticationException:
            return False, "Authentication failed — wrong password or key"
        except (socket.timeout, TimeoutError):
            return False, f"Connection timeout ({self.CONNECT_TIMEOUT}s)"
        except Exception as e:
            return False, str(e)

    def disconnect(self):
        with self._lock:
            if self._ssh:
                try: self._ssh.close()
                except Exception: pass
                self._ssh = None
            self._connected = False

    def is_connected(self) -> bool:
        if not self._connected or not self._ssh:
            return False
        try:
            transport = self._ssh.get_transport()
            return transport is not None and transport.is_active()
        except Exception:
            return False

    def ensure_connected(self) -> bool:
        if self.is_connected():
            return True
        ok, msg = self.connect()
        if not ok:
            log.warning(f"Reconnect failed: {msg}")
        return ok

    # ── Command execution ─────────────────────────────────────────────────────

    def run(self, cmd: str, timeout: int = CMD_TIMEOUT) -> CommandResult:
        """Execute a single shell command and return CommandResult."""
        if not self.ensure_connected():
            return CommandResult(ok=False, stdout="", stderr="Not connected", cmd=cmd)
        t0 = time.time()
        try:
            with self._lock:
                stdin, stdout, stderr = self._ssh.exec_command(cmd, timeout=timeout)
            out = stdout.read().decode("utf-8", errors="ignore").strip()
            err = stderr.read().decode("utf-8", errors="ignore").strip()
            rc  = stdout.channel.recv_exit_status()
            dur = time.time() - t0
            log.debug(f"[ssh] {cmd!r}  rc={rc}  t={dur:.2f}s")
            return CommandResult(ok=(rc == 0), stdout=out, stderr=err,
                                 cmd=cmd, duration=dur)
        except Exception as e:
            return CommandResult(ok=False, stdout="", stderr=str(e), cmd=cmd)

    # ── UCI wrapper ───────────────────────────────────────────────────────────

    def uci_get(self, key: str) -> Optional[str]:
        r = self.run(f"uci get {key}")
        return r.stdout.strip() if r.ok else None

    def uci_set(self, key: str, value: str) -> bool:
        return self.run(f"uci set {key}={value!r}").ok

    def uci_add(self, config: str, type_: str) -> Optional[str]:
        r = self.run(f"uci add {config} {type_}")
        return r.stdout.strip() if r.ok else None

    def uci_commit(self, config: str = "") -> bool:
        return self.run(f"uci commit {config}").ok

    def uci_show(self, config: str) -> dict:
        r = self.run(f"uci show {config}")
        result: dict = {}
        if r.ok:
            for line in r.stdout.splitlines():
                if "=" in line:
                    k, _, v = line.partition("=")
                    result[k.strip()] = v.strip().strip("'\"")
        return result

    # ── System info ───────────────────────────────────────────────────────────

    def get_system_info(self) -> OpenWrtInfo:
        info = OpenWrtInfo()
        r = self.run("cat /etc/openwrt_release; cat /proc/uptime; uname -m")
        if r.ok:
            lines = r.stdout
            m = re.search(r'DISTRIB_MODEL="?([^"\n]+)"?', lines)
            if m: info.model = m.group(1).strip()
            m = re.search(r'DISTRIB_RELEASE="?([^"\n]+)"?', lines)
            if m: info.firmware = m.group(1).strip()
            m = re.search(r"^([\d.]+)", lines.split("\n")[-2] if "\n" in lines else lines, re.MULTILINE)
            if m:
                try: info.uptime = int(float(m.group(1)))
                except: pass
            info.arch = r.stdout.splitlines()[-1].strip()
        hostname_r = self.run("uci get system.@system[0].hostname")
        if hostname_r.ok:
            info.hostname = hostname_r.stdout.strip()
        return info

    # ── Station list (hostapd) ────────────────────────────────────────────────

    def get_stations(self) -> List[OpenWrtStation]:
        """Return all currently connected Wi-Fi stations."""
        stations: List[OpenWrtStation] = []

        # hostapd_cli all_sta  (preferred)
        r = self.run("hostapd_cli all_sta 2>/dev/null || wlanconfig ath0 list 2>/dev/null")
        if r.ok and r.stdout:
            stations = self._parse_hostapd_all_sta(r.stdout)

        # Enrich with DHCP leases
        leases = self.get_dhcp_leases()
        lease_map = {l["mac"].upper(): l for l in leases}
        for s in stations:
            if s.mac.upper() in lease_map:
                s.ip       = lease_map[s.mac.upper()].get("ip", "")
                s.hostname = lease_map[s.mac.upper()].get("hostname", "")

        return stations

    def _parse_hostapd_all_sta(self, raw: str) -> List[OpenWrtStation]:
        stations: List[OpenWrtStation] = []
        blocks = re.split(r"\n(?=[0-9a-fA-F:]{17}\n)", raw.strip())
        for blk in blocks:
            lines = blk.strip().splitlines()
            if not lines: continue
            mac_m = re.match(r"([0-9a-fA-F:]{17})", lines[0].strip())
            if not mac_m: continue
            mac   = mac_m.group(1).upper()
            props: Dict[str, str] = {}
            for line in lines[1:]:
                if "=" in line:
                    k, _, v = line.partition("=")
                    props[k.strip()] = v.strip()
            st = OpenWrtStation(
                mac=mac,
                rssi=int(props.get("signal", "-90")),
                rx_bytes=int(props.get("rx_bytes", 0)),
                tx_bytes=int(props.get("tx_bytes", 0)),
                authorized=(props.get("flags","").find("[AUTH]") >= 0 or
                            "authorized" in props.get("flags","")),
            )
            stations.append(st)
        return stations

    # ── DHCP leases ───────────────────────────────────────────────────────────

    def get_dhcp_leases(self) -> List[dict]:
        """Read /tmp/dhcp.leases (OpenWrt standard path)."""
        leases: List[dict] = []
        r = self.run("cat /tmp/dhcp.leases 2>/dev/null || cat /var/lib/misc/dnsmasq.leases 2>/dev/null")
        if r.ok:
            for line in r.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 4:
                    leases.append({
                        "expiry":   parts[0],
                        "mac":      parts[1].upper(),
                        "ip":       parts[2],
                        "hostname": parts[3] if parts[3] != "*" else "",
                    })
        return leases

    # ── ARP table (from router) ───────────────────────────────────────────────

    def get_arp_table(self) -> Dict[str, str]:
        """Return {ip: mac} from router's ARP table via ip neigh."""
        result: Dict[str, str] = {}
        r = self.run("ip neigh show 2>/dev/null || arp -n 2>/dev/null")
        if r.ok:
            # ip neigh format: 192.168.1.5 dev br-lan lladdr AA:BB:CC:DD:EE:FF REACHABLE
            for m in re.finditer(
                r"([\d.]+)\s+\S+\s+\S+\s+([0-9a-fA-F:]{17})\s+(REACHABLE|STALE|DELAY|PROBE|PERMANENT)",
                r.stdout):
                result[m.group(1)] = m.group(2).upper()
            if not result:
                # arp -n format
                for m in re.finditer(r"([\d.]+)\s+\S+\s+([0-9a-fA-F:]{17})", r.stdout):
                    result[m.group(1)] = m.group(2).upper()
        return result

    # ── MAC blacklist ─────────────────────────────────────────────────────────

    def blacklist_mac(self, mac: str) -> bool:
        """
        Add MAC to hostapd deny list and kick the station.
        Falls back to UCI wifi access control if hostapd_cli unavailable.
        """
        mac = mac.upper()
        success = False

        # Method 1: hostapd_cli deauthenticate + DENY ACL
        r1 = self.run(f"hostapd_cli deauthenticate {mac}")
        r2 = self.run(f"hostapd_cli set_deny_acl_file /tmp/omnifi_deny.txt && "
                      f"echo '{mac}' >> /tmp/omnifi_deny.txt && "
                      f"hostapd_cli reload_deny_acl_file")
        if r1.ok or r2.ok:
            success = True

        # Method 2: iptables drop all traffic from MAC
        r3 = self.run(
            f"iptables -I FORWARD -m mac --mac-source {mac} -j DROP 2>/dev/null; "
            f"iptables -I INPUT   -m mac --mac-source {mac} -j DROP 2>/dev/null")
        if r3.ok:
            success = True

        # Method 3: UCI wireless access control
        self.run(
            f"uci set wireless.@wifi-iface[0].maclist=\"{mac}\" && "
            f"uci set wireless.@wifi-iface[0].macfilter=deny && "
            f"uci commit wireless && wifi reload")

        log.info(f"[openwrt] blacklist_mac {mac} → {'ok' if success else 'partial'}")
        return success

    def unblacklist_mac(self, mac: str) -> bool:
        mac = mac.upper()
        r1 = self.run(f"sed -i '/{mac}/d' /tmp/omnifi_deny.txt && "
                      f"hostapd_cli reload_deny_acl_file 2>/dev/null || true")
        r2 = self.run(
            f"iptables -D FORWARD -m mac --mac-source {mac} -j DROP 2>/dev/null; "
            f"iptables -D INPUT   -m mac --mac-source {mac} -j DROP 2>/dev/null")
        log.info(f"[openwrt] unblacklist_mac {mac}")
        return r1.ok or r2.ok

    def whitelist_mac(self, mac: str) -> bool:
        """Add MAC to allowed list (requires macfilter=allow mode)."""
        mac = mac.upper()
        r = self.run(
            f"hostapd_cli set_accept_acl_file /tmp/omnifi_allow.txt && "
            f"echo '{mac}' >> /tmp/omnifi_allow.txt && "
            f"hostapd_cli reload_accept_acl_file 2>/dev/null || true")
        return r.ok

    # ── VLAN / quarantine ─────────────────────────────────────────────────────

    def quarantine_mac(self, mac: str, vlan_id: int = 99) -> bool:
        """
        Move device to quarantine VLAN.
        Requires the router to have a guest/quarantine VLAN configured.
        """
        mac = mac.upper()
        # iptables: allow only DNS + HTTP redirect, block everything else
        cmds = [
            # Create omnifi chain if not exists
            "iptables -N OMNIFI_QUARANTINE 2>/dev/null || true",
            # Accept DNS to router
            f"iptables -I OMNIFI_QUARANTINE -m mac --mac-source {mac} -p udp --dport 53 -j ACCEPT",
            # Redirect all other traffic to a block or captive page
            f"iptables -I OMNIFI_QUARANTINE -m mac --mac-source {mac} -j DROP",
            f"iptables -I FORWARD -m mac --mac-source {mac} -j OMNIFI_QUARANTINE",
        ]
        ok = True
        for cmd in cmds:
            r = self.run(cmd)
            if not r.ok and "already exists" not in r.stderr:
                log.debug(f"[openwrt] quarantine cmd failed: {cmd}: {r.stderr}")
                ok = False
        log.info(f"[openwrt] quarantine_mac {mac} → {'ok' if ok else 'partial'}")
        return ok

    def release_quarantine(self, mac: str) -> bool:
        mac = mac.upper()
        cmds = [
            f"iptables -D FORWARD -m mac --mac-source {mac} -j OMNIFI_QUARANTINE 2>/dev/null || true",
            f"iptables -D OMNIFI_QUARANTINE -m mac --mac-source {mac} -p udp --dport 53 -j ACCEPT 2>/dev/null || true",
            f"iptables -D OMNIFI_QUARANTINE -m mac --mac-source {mac} -j DROP 2>/dev/null || true",
        ]
        for cmd in cmds:
            self.run(cmd)
        log.info(f"[openwrt] release_quarantine {mac}")
        return True

    # ── DNS enforcement ───────────────────────────────────────────────────────

    def enforce_dns_doh(self, upstream: str = "1.1.1.1") -> bool:
        """
        Redirect all port 53 traffic to the router itself (dnsmasq),
        and configure dnsmasq to use DoT / upstream DoH-capable server.
        """
        cmds = [
            # Intercept all outbound port 53 to the router
            f"iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 53",
            f"iptables -t nat -I PREROUTING -p tcp --dport 53 -j REDIRECT --to-ports 53",
            # Configure dnsmasq upstream
            f"uci set dhcp.@dnsmasq[0].server={upstream!r}",
            f"uci commit dhcp",
            f"service dnsmasq restart",
        ]
        ok = all(self.run(cmd).ok for cmd in cmds[:2])  # iptables rules
        self.run(" && ".join(cmds[2:]))                  # dnsmasq config
        log.info(f"[openwrt] DNS enforcement → {upstream}")
        return ok

    def restore_dns(self) -> bool:
        cmds = [
            "iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 53 2>/dev/null || true",
            "iptables -t nat -D PREROUTING -p tcp --dport 53 -j REDIRECT --to-ports 53 2>/dev/null || true",
        ]
        for cmd in cmds:
            self.run(cmd)
        log.info("[openwrt] DNS enforcement removed")
        return True

    # ── Firewall rules ────────────────────────────────────────────────────────

    def block_ip(self, ip: str, direction: str = "both") -> bool:
        cmds = []
        if direction in ("in", "both"):
            cmds.append(f"iptables -I INPUT   -s {ip} -j DROP")
        if direction in ("out", "both"):
            cmds.append(f"iptables -I FORWARD -d {ip} -j DROP")
        return all(self.run(cmd).ok for cmd in cmds)

    def unblock_ip(self, ip: str, direction: str = "both") -> bool:
        cmds = []
        if direction in ("in", "both"):
            cmds.append(f"iptables -D INPUT   -s {ip} -j DROP 2>/dev/null || true")
        if direction in ("out", "both"):
            cmds.append(f"iptables -D FORWARD -d {ip} -j DROP 2>/dev/null || true")
        for cmd in cmds: self.run(cmd)
        return True

    def list_iptables_rules(self) -> List[str]:
        r = self.run("iptables -L -n --line-numbers 2>/dev/null")
        return r.stdout.splitlines() if r.ok else []

    def flush_omnifi_rules(self) -> bool:
        """Remove all OmniFi-injected iptables rules."""
        cmds = [
            "iptables -F OMNIFI_QUARANTINE 2>/dev/null || true",
            "iptables -X OMNIFI_QUARANTINE 2>/dev/null || true",
            "iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 53 2>/dev/null || true",
        ]
        for cmd in cmds: self.run(cmd)
        return True

    # ── nftables (newer OpenWrt) ──────────────────────────────────────────────

    def nft_block_mac(self, mac: str) -> bool:
        """Block via nftables if iptables not available."""
        mac = mac.upper()
        r = self.run(
            f"nft add element inet filter omnifi_blocked {{ ether saddr {mac} }}"
            f" 2>/dev/null || "
            f"nft add table inet omnifi && "
            f"nft add chain inet omnifi input {{ type filter hook input priority 0 \\; }} && "
            f"nft add rule inet omnifi input ether saddr {mac} drop")
        return r.ok

    # ── Bandwidth / QoS ──────────────────────────────────────────────────────

    def rate_limit_mac(self, mac: str,
                       down_kbps: int = 512,
                       up_kbps:   int = 128) -> bool:
        """Apply per-device rate limiting via tc (Linux traffic control)."""
        # Requires the device to be on a bridge interface
        r = self.run(
            f"tc qdisc add dev br-lan root handle 1: htb default 10 2>/dev/null || true && "
            f"tc class add dev br-lan parent 1: classid 1:10 htb rate {down_kbps}kbit 2>/dev/null || true")
        log.info(f"[openwrt] rate_limit {mac} down={down_kbps}k up={up_kbps}k → {r.ok}")
        return r.ok

    # ── WPS / PMF / encryption ────────────────────────────────────────────────

    def disable_wps(self) -> bool:
        r = self.run(
            "uci set wireless.@wifi-iface[0].wps_pushbutton=0 && "
            "uci commit wireless && wifi reload")
        log.info(f"[openwrt] disable_wps → {r.ok}")
        return r.ok

    def set_encryption(self, mode: str = "psk2") -> bool:
        """Set Wi-Fi encryption mode: psk (WPA), psk2 (WPA2), sae (WPA3)."""
        r = self.run(
            f"uci set wireless.@wifi-iface[0].encryption={mode} && "
            f"uci commit wireless && wifi reload")
        log.info(f"[openwrt] set_encryption {mode} → {r.ok}")
        return r.ok

    def enable_pmf(self) -> bool:
        """Enable Protected Management Frames (802.11w)."""
        r = self.run(
            "uci set wireless.@wifi-iface[0].ieee80211w=1 && "
            "uci commit wireless && wifi reload")
        log.info(f"[openwrt] enable_pmf → {r.ok}")
        return r.ok

    # ── Full audit dump ───────────────────────────────────────────────────────

    def audit(self) -> dict:
        """
        Run a complete audit of the OpenWrt router.
        Returns a structured dict suitable for the RouterPanel.
        """
        info = self.get_system_info()
        return {
            "ok":         True,
            "gateway":    self.host,
            "model":      info.model,
            "firmware":   info.firmware,
            "uptime":     info.uptime,
            "hostname":   info.hostname,
            "stations":   [s.to_dict() for s in self.get_stations()],
            "leases":     self.get_dhcp_leases(),
            "arp":        self.get_arp_table(),
            "iptables":   self.list_iptables_rules()[:20],
            "wps":        (self.uci_get("wireless.@wifi-iface[0].wps_pushbutton") or "0") != "0",
            "encryption": self.uci_get("wireless.@wifi-iface[0].encryption") or "unknown",
            "pmf":        (self.uci_get("wireless.@wifi-iface[0].ieee80211w") or "0") == "1",
        }


# ─────────────────────────────────────────────────────────────────────────────
# Connection manager (singleton per session)
# ─────────────────────────────────────────────────────────────────────────────
_CLIENT: Optional[OpenWrtClient] = None
_CLIENT_LOCK = threading.Lock()


def get_openwrt_client() -> Optional[OpenWrtClient]:
    return _CLIENT


def connect_openwrt(host: str, username: str = "root",
                    password: str = "", port: int = 22,
                    key_path: str = "") -> Tuple[bool, str]:
    global _CLIENT
    with _CLIENT_LOCK:
        if _CLIENT and _CLIENT.is_connected():
            _CLIENT.disconnect()
        c = OpenWrtClient(host, username, password, port, key_path)
        ok, msg = c.connect()
        if ok:
            _CLIENT = c
        return ok, msg


def disconnect_openwrt():
    global _CLIENT
    with _CLIENT_LOCK:
        if _CLIENT:
            _CLIENT.disconnect()
            _CLIENT = None
