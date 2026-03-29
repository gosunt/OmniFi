"""
OmniFi — Enforcement Engine
============================
Translates policy decisions (blacklist / whitelist / isolate / exception)
into real network-level actions:

  Tier 1 — Router push  : MAC filter / ACL via router admin panel HTTP API
  Tier 2 — OS firewall  : iptables (Linux) / netsh advfirewall (Windows)
  Tier 3 — ARP block    : Gratuitous ARP poison to isolate a device
  Tier 4 — DB record    : Always written regardless of tier 1–3 success

Each action returns an EnforceResult so the UI can report exactly what
happened and at which tier.
"""
import re, socket, subprocess, threading, logging, platform, os
import datetime
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger("OmniFi.Enforcer")

WINDOWS = platform.system() == "Windows"
LINUX   = platform.system() == "Linux"
IS_ROOT = (not WINDOWS) and os.geteuid() == 0


# ─────────────────────────────────────────────────────────────────────────────
# Result object
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class EnforceResult:
    ok:           bool   = False
    action:       str    = ""
    mac:          str    = ""
    tier:         str    = ""       # "router" | "os_firewall" | "arp" | "db_only"
    method:       str    = ""       # human-readable description of what was done
    router_ok:    bool   = False
    os_ok:        bool   = False
    arp_ok:       bool   = False
    db_ok:        bool   = False
    error:        str    = ""
    detail:       str    = ""
    timestamp:    str    = field(default_factory=lambda: datetime.datetime.now().isoformat())

    def summary(self) -> str:
        tiers = []
        if self.router_ok: tiers.append("Router MAC filter")
        if self.os_ok:     tiers.append("OS firewall")
        if self.arp_ok:    tiers.append("ARP isolation")
        if self.db_ok:     tiers.append("Policy DB")
        if not tiers:      return f"Failed: {self.error}"
        return f"{self.action.upper()} applied via: {' + '.join(tiers)}"


# ─────────────────────────────────────────────────────────────────────────────
# Router enforcement  — HTTP API push
# ─────────────────────────────────────────────────────────────────────────────
class RouterEnforcer:
    """
    Pushes MAC filter rules to the router admin panel.
    Works on most ISP-issued routers by:
      1. Probing for known MAC filter / ACL endpoints
      2. Parsing the current filter list from the page
      3. POSTing the updated list with the new entry

    Falls back gracefully if the router panel is not reachable or
    the endpoint is unrecognised.
    """

    # Known MAC filter endpoint patterns (path fragments, tried in order)
    _MAC_FILTER_PATHS = [
        "/goform/WifiMacFilter",       # Tenda / many Chinese OEM
        "/apply.cgi",                  # dd-wrt style
        "/cgi-bin/luci/admin/network/wireless",  # OpenWRT / LEDE
        "/setup/adv_mac_filter",       # Netgear
        "/wlmacfilter.asp",            # Linksys WRT
        "/MAC_FILTER.HTM",             # Huawei HG series
        "/mac_filter.asp",             # TP-Link older
        "/userRpm/AccessCtrlAccessRulesRpm.htm",  # TP-Link newer
        "/api/v1/access-control",      # Asus Merlin / asuswrt
        "/cgi-bin/cgiSrv.cgi",         # ZTE F670 (JioFiber)
        "/RgAccessControl.asp",        # Technicolor / Compal
        "/wifi_access_control.html",   # Sercomm / JioFi
        "/LAN_mac_filter.asp",         # Various
        "/network/mac_filter",         # Various OpenWRT
    ]

    def __init__(self, session, base_url: str, isp_key: str = "unknown"):
        self._session  = session
        self._base     = base_url.rstrip("/")
        self._isp_key  = isp_key
        self._timeout  = 5

    def block_mac(self, mac: str) -> tuple[bool, str]:
        """Add MAC to router blacklist. Returns (success, method_desc)."""
        mac = mac.upper()

        # Strategy 1: ISP-specific known API
        ok, desc = self._isp_specific_block(mac)
        if ok: return True, desc

        # Strategy 2: probe generic filter endpoints
        for path in self._MAC_FILTER_PATHS:
            try:
                url = self._base + path
                r   = self._session.get(url, timeout=self._timeout, verify=False)
                if r.status_code == 200 and len(r.text) > 100:
                    ok2, desc2 = self._parse_and_push_filter(mac, url, r.text, "deny")
                    if ok2: return True, f"MAC filter via {path}"
            except Exception as e:
                log.debug(f"Probe {path}: {e}")

        return False, "Router MAC filter endpoint not found"

    def unblock_mac(self, mac: str) -> tuple[bool, str]:
        """Remove MAC from router blacklist."""
        mac = mac.upper()
        ok, desc = self._isp_specific_unblock(mac)
        if ok: return True, desc
        return False, "Router unblock: endpoint not found"

    def isolate_mac(self, mac: str) -> tuple[bool, str]:
        """Block internet but allow LAN — if router supports guest VLAN isolation."""
        # Most consumer routers don't support per-device VLAN isolation from
        # the standard panel, so we block at router level (same as blacklist)
        # and supplement with OS firewall
        return self.block_mac(mac)

    # ── ISP-specific methods ──────────────────────────────────────────────────

    def _isp_specific_block(self, mac: str) -> tuple[bool, str]:
        if self._isp_key in ("jiofiber", "jioairfiber"):
            return self._jio_mac_block(mac)
        if self._isp_key in ("airtel",):
            return self._airtel_mac_block(mac)
        if self._isp_key in ("tplink",):
            return self._tplink_mac_block(mac)
        return False, ""

    def _isp_specific_unblock(self, mac: str) -> tuple[bool, str]:
        if self._isp_key in ("jiofiber", "jioairfiber"):
            return self._jio_mac_unblock(mac)
        return False, ""

    def _jio_mac_block(self, mac: str) -> tuple[bool, str]:
        """JioFiber ZTE F670 / H2-series — CGI endpoint."""
        try:
            endpoints = [
                f"{self._base}/cgi-bin/cgiSrv.cgi",
                f"{self._base}/goform/setSecurity",
                f"{self._base}/wifiMacFilter",
            ]
            for ep in endpoints:
                try:
                    payload = {
                        "cmd":     "SET_MAC_FILTER",
                        "mac":     mac,
                        "action":  "block",
                        "enable":  "1",
                    }
                    r = self._session.post(ep, data=payload,
                                          timeout=self._timeout, verify=False)
                    if r.status_code in (200, 204):
                        return True, f"Jio MAC filter: {ep}"
                except Exception:
                    pass
        except Exception as e:
            log.debug(f"Jio block: {e}")
        return False, ""

    def _jio_mac_unblock(self, mac: str) -> tuple[bool, str]:
        try:
            r = self._session.post(
                f"{self._base}/cgi-bin/cgiSrv.cgi",
                data={"cmd": "SET_MAC_FILTER", "mac": mac, "action": "allow"},
                timeout=self._timeout, verify=False)
            if r.status_code in (200, 204):
                return True, "Jio MAC filter removed"
        except Exception:
            pass
        return False, ""

    def _airtel_mac_block(self, mac: str) -> tuple[bool, str]:
        """Airtel Xstream / Huawei HG8145V5."""
        try:
            ep = f"{self._base}/api/ntwk/mac_filter"
            r  = self._session.post(ep, json={
                "mac":    mac,
                "enable": True,
                "type":   "black",
            }, timeout=self._timeout, verify=False)
            if r.status_code in (200, 201):
                return True, "Airtel MAC blacklist"
        except Exception as e:
            log.debug(f"Airtel block: {e}")
        return False, ""

    def _tplink_mac_block(self, mac: str) -> tuple[bool, str]:
        """TP-Link home routers — classic stok API."""
        try:
            # Get stok token first
            stok_r = self._session.get(
                f"{self._base}/cgi-bin/luci/;stok=/login",
                timeout=self._timeout, verify=False)
            stok_m = re.search(r'"stok":"([^"]+)"', stok_r.text)
            if not stok_m: return False, ""
            stok = stok_m.group(1)
            ep   = f"{self._base}/cgi-bin/luci/;stok={stok}/admin/wireless"
            r    = self._session.post(ep, json={
                "method": "add",
                "params": {"mac": mac, "type": "black"},
            }, timeout=self._timeout, verify=False)
            if r.status_code == 200:
                return True, "TP-Link MAC filter"
        except Exception as e:
            log.debug(f"TP-Link block: {e}")
        return False, ""

    def _parse_and_push_filter(self, mac: str, url: str,
                                page_html: str, mode: str) -> tuple[bool, str]:
        """
        Generic: parse the current MAC filter list from the page,
        add our MAC, and POST back.
        Works on many dd-wrt / OpenWRT / Tomato style panels.
        """
        try:
            from bs4 import BeautifulSoup
            soup  = BeautifulSoup(page_html, "html.parser")
            form  = soup.find("form")
            if not form: return False, ""

            payload = {}
            for inp in form.find_all("input"):
                iname = inp.get("name", "")
                ival  = inp.get("value", "")
                if iname: payload[iname] = ival

            # Common field names for MAC filter entries
            for field_name in ["mac_addr", "macaddr", "mac_address", "filtermac",
                                "wl_macaddr", "mac", "block_mac"]:
                if field_name in payload or any(field_name in k for k in payload):
                    payload[field_name] = mac
                    break
            else:
                payload["mac_addr"] = mac

            # Set filter mode if present
            for mode_field in ["filter_mode", "mac_filter_mode", "wl_macmode",
                                "mode", "action"]:
                if mode_field in payload:
                    payload[mode_field] = "deny" if mode == "deny" else "allow"

            action_url = url
            if form.get("action"):
                act = form["action"]
                action_url = act if act.startswith("http") else \
                    self._base + "/" + act.lstrip("/")

            r = self._session.post(action_url, data=payload,
                                   timeout=self._timeout, verify=False)
            success = r.status_code in (200, 302) and \
                "error" not in r.text.lower()[:200]
            return success, f"Generic form POST to {action_url}"
        except Exception as e:
            log.debug(f"_parse_and_push_filter: {e}")
        return False, ""


# ─────────────────────────────────────────────────────────────────────────────
# OS-level enforcement
# ─────────────────────────────────────────────────────────────────────────────
class OSEnforcer:
    """
    Uses the host OS firewall to block / allow traffic by MAC or IP.
    Windows : netsh advfirewall + arp -s (static ARP)
    Linux   : iptables / nftables + arptables (if available)
    """

    def block_mac(self, mac: str, ip: str = "") -> tuple[bool, str]:
        mac = mac.upper()
        if WINDOWS:
            return self._win_block(mac, ip)
        elif LINUX:
            return self._linux_block(mac, ip)
        return False, f"OS enforcement not supported on {platform.system()}"

    def unblock_mac(self, mac: str, ip: str = "") -> tuple[bool, str]:
        mac = mac.upper()
        if WINDOWS:
            return self._win_unblock(mac, ip)
        elif LINUX:
            return self._linux_unblock(mac, ip)
        return False, ""

    def _win_block(self, mac: str, ip: str) -> tuple[bool, str]:
        """Windows: block by IP via netsh advfirewall if IP known."""
        if not ip:
            ip = self._mac_to_ip(mac)
        methods = []
        ok      = False
        if ip:
            try:
                rule_name = f"OmniFi_Block_{mac.replace(':','')}"
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", "dir=in", "action=block",
                    f"remoteip={ip}", "protocol=any",
                ], check=True, capture_output=True, timeout=5)
                # Also block outbound
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}_out", "dir=out", "action=block",
                    f"remoteip={ip}", "protocol=any",
                ], check=True, capture_output=True, timeout=5)
                methods.append(f"netsh firewall block {ip}")
                ok = True
            except Exception as e:
                log.debug(f"netsh block: {e}")
        # Static ARP poison — prevent host from routing to this MAC
        if ip and mac:
            try:
                mac_fmt = mac.replace(":", "-")
                subprocess.run(
                    ["arp", "-s", ip, mac_fmt],
                    capture_output=True, timeout=3)
                methods.append("static ARP entry")
                ok = True
            except Exception:
                pass
        return ok, "; ".join(methods) if methods else "No IP resolved for MAC"

    def _win_unblock(self, mac: str, ip: str) -> tuple[bool, str]:
        if not ip:
            ip = self._mac_to_ip(mac)
        rule_name = f"OmniFi_Block_{mac.replace(':','')}"
        try:
            subprocess.run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}",
            ], capture_output=True, timeout=5)
            subprocess.run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}_out",
            ], capture_output=True, timeout=5)
            if ip:
                subprocess.run(["arp", "-d", ip], capture_output=True, timeout=3)
            return True, "netsh rule removed"
        except Exception as e:
            return False, str(e)

    def _linux_block(self, mac: str, ip: str) -> tuple[bool, str]:
        if not IS_ROOT:
            return False, "Root required for iptables"
        if not ip:
            ip = self._mac_to_ip(mac)
        ok, methods = False, []

        # iptables by MAC (layer 2 — works regardless of IP)
        try:
            subprocess.run([
                "iptables", "-I", "FORWARD", "-m", "mac",
                "--mac-source", mac, "-j", "DROP",
            ], check=True, capture_output=True, timeout=5)
            subprocess.run([
                "iptables", "-I", "INPUT", "-m", "mac",
                "--mac-source", mac, "-j", "DROP",
            ], check=True, capture_output=True, timeout=5)
            methods.append(f"iptables MAC DROP {mac}")
            ok = True
        except Exception as e:
            log.debug(f"iptables MAC: {e}")

        # Also block by IP if known
        if ip:
            try:
                subprocess.run([
                    "iptables", "-I", "FORWARD",
                    "-s", ip, "-j", "DROP",
                ], check=True, capture_output=True, timeout=5)
                methods.append(f"iptables IP DROP {ip}")
                ok = True
            except Exception:
                pass

        # arptables if available
        try:
            subprocess.run([
                "arptables", "-A", "INPUT",
                "--source-mac", mac, "-j", "DROP",
            ], check=True, capture_output=True, timeout=5)
            methods.append("arptables DROP")
            ok = True
        except Exception:
            pass

        return ok, "; ".join(methods) if methods else "iptables failed"

    def _linux_unblock(self, mac: str, ip: str) -> tuple[bool, str]:
        if not IS_ROOT:
            return False, "Root required"
        try:
            subprocess.run([
                "iptables", "-D", "FORWARD", "-m", "mac",
                "--mac-source", mac, "-j", "DROP",
            ], capture_output=True, timeout=5)
            subprocess.run([
                "iptables", "-D", "INPUT", "-m", "mac",
                "--mac-source", mac, "-j", "DROP",
            ], capture_output=True, timeout=5)
            if ip:
                subprocess.run([
                    "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP",
                ], capture_output=True, timeout=5)
            subprocess.run([
                "arptables", "-D", "INPUT",
                "--source-mac", mac, "-j", "DROP",
            ], capture_output=True, timeout=5)
            return True, "iptables rules removed"
        except Exception as e:
            return False, str(e)

    @staticmethod
    def _mac_to_ip(mac: str) -> str:
        """Look up IP for a MAC from the local ARP table."""
        try:
            if WINDOWS:
                o = subprocess.check_output(
                    ["arp", "-a"], text=True, encoding="utf-8",
                    errors="ignore", stderr=subprocess.DEVNULL)
                for line in o.splitlines():
                    if mac.upper().replace(":", "-") in line.upper() or \
                       mac.upper() in line.upper():
                        m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                        if m: return m.group(1)
            else:
                o = subprocess.check_output(
                    ["arp", "-n"], text=True, stderr=subprocess.DEVNULL)
                for line in o.splitlines():
                    if mac.upper() in line.upper():
                        m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                        if m: return m.group(1)
        except Exception:
            pass
        return ""


# ─────────────────────────────────────────────────────────────────────────────
# ARP-based isolation (no root via scapy if available)
# ─────────────────────────────────────────────────────────────────────────────
class ARPIsolator:
    """
    Sends a gratuitous ARP to poison the target's gateway entry,
    causing the device to lose internet routing without being kicked.
    Requires Scapy.
    """

    def isolate(self, victim_ip: str, gateway_ip: str) -> tuple[bool, str]:
        try:
            from scapy.all import ARP, Ether, sendp, get_if_hwaddr, conf
            iface = conf.iface
            our_mac = get_if_hwaddr(iface)
            # Poison victim: tell victim that gateway MAC = our MAC
            pkt_victim = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                         ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwsrc=our_mac)
            # Poison gateway: tell gateway that victim MAC = our MAC
            pkt_gw = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                     ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwsrc=our_mac)
            sendp([pkt_victim, pkt_gw], iface=iface, verbose=False, count=5)
            return True, f"ARP isolation: {victim_ip} ↔ {gateway_ip} poisoned"
        except ImportError:
            return False, "Scapy not available"
        except Exception as e:
            return False, f"ARP isolate error: {e}"

    def restore(self, victim_ip: str, victim_mac: str,
                gateway_ip: str, gateway_mac: str) -> tuple[bool, str]:
        try:
            from scapy.all import ARP, Ether, sendp
            pkt_v = Ether(dst=victim_mac) / \
                    ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwdst=victim_mac, hwsrc=gateway_mac)
            pkt_g = Ether(dst=gateway_mac) / \
                    ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwdst=gateway_mac, hwsrc=victim_mac)
            sendp([pkt_v, pkt_g], verbose=False, count=3)
            return True, "ARP table restored"
        except Exception as e:
            return False, str(e)


# ─────────────────────────────────────────────────────────────────────────────
# Main enforcement orchestrator
# ─────────────────────────────────────────────────────────────────────────────
class EnforcementEngine:
    """
    Central enforcement object owned by Backend.
    Coordinates router push → OS firewall → ARP isolation → DB write.
    Thread-safe: each call is non-blocking (runs in the calling thread,
    so callers should run in a QThread worker).
    """

    def __init__(self):
        self._router_enf: Optional[RouterEnforcer] = None
        self._config_mgr = None
        self._os_enf     = OSEnforcer()
        self._arp_iso    = ARPIsolator()
        self._lock       = threading.Lock()

    def set_router(self, session, base_url: str, isp_key: str = "unknown"):
        """Called after successful admin login."""
        with self._lock:
            self._router_enf = RouterEnforcer(session, base_url, isp_key)
            # Also set up the high-level config manager for advanced enforcement
            try:
                from admin_mode.router_sitemap import RouterConfigManager
                self._config_mgr = RouterConfigManager(session, base_url, isp_key)
            except Exception as e:
                self._config_mgr = None
                log.debug(f"RouterConfigManager init: {e}")
        log.info(f"EnforcementEngine: router set → {base_url} [{isp_key}]")

    def get_config_manager(self):
        """Return the RouterConfigManager if router is authenticated, else None."""
        return getattr(self, "_config_mgr", None)

    def apply_router_setting(self, capability: str, **kwargs) -> dict:
        """
        Apply any router configuration setting by capability ID.
        Delegates to RouterConfigManager which handles all vendor differences.
        """
        mgr = self.get_config_manager()
        if not mgr:
            return {"ok": False, "detail": "No authenticated router session"}
        try:
            fn_map = {
                "mac_block":      lambda: mgr.mac_block(kwargs.get("mac","")),
                "mac_allow":      lambda: mgr.mac_allow(kwargs.get("mac","")),
                "wifi_password":  lambda: mgr.set_wifi_password(kwargs.get("password",""),
                                              kwargs.get("band","both")),
                "wifi_ssid":      lambda: mgr.set_wifi_ssid(kwargs.get("ssid",""),
                                              kwargs.get("band","both")),
                "wps_disable":    lambda: mgr.disable_wps(),
                "pmf_enable":     lambda: mgr.enable_pmf(),
                "dns_override":   lambda: mgr.set_dns(kwargs.get("dns1","1.1.1.1"),
                                              kwargs.get("dns2","8.8.8.8")),
                "remote_mgmt":    lambda: mgr.disable_remote_mgmt(),
                "max_clients":    lambda: mgr.set_max_clients(kwargs.get("n",10)),
                "bandwidth_limit":lambda: mgr.set_bandwidth_limit(
                                              kwargs.get("mac",""),
                                              kwargs.get("down_kbps",0),
                                              kwargs.get("up_kbps",0)),
                "firewall_rule":  lambda: mgr.add_firewall_rule(
                                              kwargs.get("mac",""),
                                              kwargs.get("action","DROP")),
                "parental_block": lambda: mgr.parental_block(kwargs.get("mac","")),
                "reboot":         lambda: mgr.reboot(),
                "device_list":    lambda: {"ok":True,"data":mgr.get_device_list()},
                "capabilities":   lambda: {"ok":True,"data":mgr.get_capabilities()},
            }
            fn = fn_map.get(capability)
            if not fn:
                return {"ok": False, "detail": f"Unknown capability: {capability}"}
            return fn()
        except Exception as e:
            return {"ok": False, "detail": str(e)}

    def clear_router(self):
        with self._lock:
            self._router_enf = None

    def enforce(self, mac: str, action: str, ip: str = "",
                reason: str = "", gateway_ip: str = "") -> EnforceResult:
        """
        Apply a policy action.
        action ∈ {"blacklist","whitelist","isolated","exception","remove_blacklist",
                  "remove_whitelist","remove_isolated"}
        Returns EnforceResult with full tier breakdown.
        """
        mac    = mac.upper().strip()
        result = EnforceResult(action=action, mac=mac)

        if not ip:
            ip = OSEnforcer._mac_to_ip(mac)

        log.info(f"[enforce] {action} → {mac} (ip={ip or '?'})")

        try:
            if action == "blacklist":
                self._do_block(result, mac, ip, gateway_ip)
            elif action == "whitelist":
                self._do_whitelist(result, mac, ip)
            elif action == "isolated":
                self._do_isolate(result, mac, ip, gateway_ip)
            elif action == "exception":
                self._do_exception(result, mac)
            elif action in ("remove_blacklist", "remove_isolated"):
                self._do_unblock(result, mac, ip, gateway_ip)
            elif action == "remove_whitelist":
                result.ok = True; result.tier = "db_only"
                result.method = "Whitelist entry removed from DB"
            else:
                result.error = f"Unknown action: {action}"
                return result

            # DB write always happens
            self._db_write(result, mac, action, reason, ip)

        except Exception as e:
            result.error = str(e)
            log.error(f"enforce error: {e}")

        result.ok = any([result.router_ok, result.os_ok,
                         result.arp_ok, result.db_ok])
        return result

    # ── action implementations ────────────────────────────────────────────────

    def _do_block(self, r: EnforceResult, mac: str, ip: str, gw: str):
        # Tier 1: router
        if self._router_enf:
            ok1, desc1 = self._router_enf.block_mac(mac)
            r.router_ok = ok1
            r.detail += f"[Router] {desc1}\n"

        # Tier 2: OS firewall
        ok2, desc2 = self._os_enf.block_mac(mac, ip)
        r.os_ok    = ok2
        r.detail  += f"[OS] {desc2}\n"

        # Tier 3: ARP isolation if IP + GW known
        if ip and gw:
            ok3, desc3 = self._arp_iso.isolate(ip, gw)
            r.arp_ok   = ok3
            r.detail  += f"[ARP] {desc3}\n"

        tier_parts = []
        if r.router_ok: tier_parts.append("router")
        if r.os_ok:     tier_parts.append("os_firewall")
        if r.arp_ok:    tier_parts.append("arp")
        r.tier   = "+".join(tier_parts) or "db_only"
        r.method = r.summary()

    def _do_isolate(self, r: EnforceResult, mac: str, ip: str, gw: str):
        # Isolation = block at router/OS + ARP poison to cut internet
        self._do_block(r, mac, ip, gw)
        r.action = "isolated"

    def _do_whitelist(self, r: EnforceResult, mac: str, ip: str):
        # Remove from any block rules
        ok2, desc2 = self._os_enf.unblock_mac(mac, ip)
        r.os_ok    = ok2
        r.detail  += f"[OS] {desc2}\n"
        if self._router_enf:
            ok1, desc1 = self._router_enf.unblock_mac(mac)
            r.router_ok = ok1
            r.detail   += f"[Router] {desc1}\n"
        r.tier   = "whitelist"
        r.method = "Whitelisted: existing blocks removed"

    def _do_exception(self, r: EnforceResult, mac: str):
        # Exceptions are policy-DB-only markers (no firewall changes needed)
        r.tier   = "db_only"
        r.method = "Exception recorded in policy DB"

    def _do_unblock(self, r: EnforceResult, mac: str, ip: str, gw: str):
        # Remove all blocking rules
        if self._router_enf:
            ok1, desc1 = self._router_enf.unblock_mac(mac)
            r.router_ok = ok1
            r.detail   += f"[Router] {desc1}\n"
        ok2, desc2 = self._os_enf.unblock_mac(mac, ip)
        r.os_ok    = ok2
        r.detail  += f"[OS] {desc2}\n"
        r.tier     = "removed"
        r.method   = "Block rules removed"

    # ── DB persistence ────────────────────────────────────────────────────────

    @staticmethod
    def _db_write(r: EnforceResult, mac: str, action: str,
                  reason: str, ip: str):
        try:
            from core.database import add_policy, remove_policy, upsert_device
            if action.startswith("remove_"):
                pt = action[len("remove_"):]
                remove_policy(mac, pt)
            else:
                add_policy(mac, action, reason, 0)
            if ip:
                upsert_device(mac, ip, status=_STATUS_MAP.get(action, "unknown"))
            r.db_ok = True
        except Exception as e:
            log.error(f"DB write: {e}")
            r.db_ok  = False
            r.detail += f"[DB] Error: {e}\n"


_STATUS_MAP = {
    "blacklist": "blocked",
    "isolated":  "isolated",
    "whitelist": "trusted",
    "exception": "exception",
}
