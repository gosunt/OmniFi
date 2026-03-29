"""
OmniFi — Router Configuration Sitemap & Multi-Vendor Enforcement
=================================================================
Maintains a per-ISP/vendor sitemap of router configuration endpoints
so the enforcement engine can navigate directly to any setting page
without having to scrape every time.

Supports:
  JioFiber (ZTE F670/H2)  · JioFi MiFi  · Airtel (Huawei HG8145)
  BSNL (Netlink/Syrotech/DASAN)  · ACT (TP-Link/D-Link/Tenda)
  Tata Play  · Hathway  · Excitel  · RailWire  · MTNL
  Generic OpenWRT/DD-WRT/Tomato fallback

Each ISP entry maps capability → (endpoint_path, method, payload_template)
so the EnforcementEngine can push any setting directly.
"""

import re
import logging
import requests

requests.packages.urllib3.disable_warnings()
log = logging.getLogger("OmniFi.RouterSitemap")

# ─────────────────────────────────────────────────────────────────────────────
# Capability identifiers (used as keys by EnforcementEngine)
# ─────────────────────────────────────────────────────────────────────────────
CAP_MAC_BLOCK     = "mac_block"
CAP_MAC_ALLOW     = "mac_allow"
CAP_WIFI_PASSWORD = "wifi_password"
CAP_WIFI_SSID     = "wifi_ssid"
CAP_WIFI_BAND     = "wifi_band"
CAP_WIFI_CHANNEL  = "wifi_channel"
CAP_WIFI_PROTOCOL = "wifi_protocol"    # WPA2/WPA3
CAP_PMF           = "pmf_enable"
CAP_WPS           = "wps_disable"
CAP_MAX_CLIENTS   = "max_clients"
CAP_GUEST_NET     = "guest_network"
CAP_DNS_OVERRIDE  = "dns_override"
CAP_REMOTE_MGMT   = "remote_mgmt"
CAP_FIREWALL      = "firewall_rule"
CAP_REBOOT        = "reboot"
CAP_DEVICE_LIST   = "device_list"
CAP_QUARANTINE    = "quarantine"
CAP_PARENTAL      = "parental_control"
CAP_BANDWIDTH     = "bandwidth_limit"


# ─────────────────────────────────────────────────────────────────────────────
# Per-vendor sitemap definitions
# Format: cap_id → {path, method, content_type, payload_fn(args) → dict/str}
# ─────────────────────────────────────────────────────────────────────────────

SITEMAPS = {

    # ── JioFiber (ZTE F670 / H2-series) ──────────────────────────────────────
    "jiofiber": {
        "panel_paths": ["/login.html", "/main.html", "/wireless.html"],
        CAP_MAC_BLOCK: {
            "paths": ["/cgi-bin/cgiSrv.cgi", "/goform/setSecurity"],
            "method": "POST",
            "ct": "form",
            "payload": lambda mac, **_: {"cmd":"SET_MAC_FILTER","mac":mac,"action":"block","enable":"1"},
        },
        CAP_MAC_ALLOW: {
            "paths": ["/cgi-bin/cgiSrv.cgi"],
            "method": "POST",
            "ct": "form",
            "payload": lambda mac, **_: {"cmd":"SET_MAC_FILTER","mac":mac,"action":"allow"},
        },
        CAP_WIFI_PASSWORD: {
            "paths": ["/goform/setWifi", "/cgi-bin/cgiSrv.cgi"],
            "method": "POST",
            "ct": "form",
            "payload": lambda pw, band="2.4", **_: {
                "cmd":"SET_WIFI_PASS","wifiPwd":pw,
                "wifiIndex":"0" if band=="2.4" else "1"},
        },
        CAP_WIFI_SSID: {
            "paths": ["/goform/setWifi"],
            "method": "POST",
            "ct": "form",
            "payload": lambda ssid, band="2.4", **_: {
                "cmd":"SET_WIFI_SSID","wifiSSID":ssid,
                "wifiIndex":"0" if band=="2.4" else "1"},
        },
        CAP_WPS: {
            "paths": ["/goform/setWps", "/cgi-bin/cgiSrv.cgi"],
            "method": "POST",
            "ct": "form",
            "payload": lambda **_: {"cmd":"SET_WPS","wpsEnable":"0"},
        },
        CAP_REBOOT: {
            "paths": ["/cgi-bin/cgiSrv.cgi"],
            "method": "POST",
            "ct": "form",
            "payload": lambda **_: {"cmd":"REBOOT"},
        },
        CAP_DEVICE_LIST: {
            "paths": ["/cgi-bin/cgiSrv.cgi"],
            "method": "POST",
            "ct": "form",
            "payload": lambda **_: {"cmd":"GET_DEVICE_LIST"},
        },
        CAP_MAX_CLIENTS: {
            "paths": ["/goform/setWifi"],
            "method": "POST",
            "ct": "form",
            "payload": lambda n, **_: {"cmd":"SET_MAX_CLIENTS","maxClients":str(n)},
        },
    },

    # ── JioAirFiber ───────────────────────────────────────────────────────────
    "jioairfiber": {
        "panel_paths": ["/login.html"],
        CAP_MAC_BLOCK: {
            "paths": ["/cgi-bin/cgiSrv.cgi"],
            "method": "POST", "ct": "form",
            "payload": lambda mac, **_: {"cmd":"SET_MAC_FILTER","mac":mac,"action":"block","enable":"1"},
        },
        CAP_MAC_ALLOW: {
            "paths": ["/cgi-bin/cgiSrv.cgi"],
            "method": "POST", "ct": "form",
            "payload": lambda mac, **_: {"cmd":"SET_MAC_FILTER","mac":mac,"action":"allow"},
        },
        CAP_REBOOT: {
            "paths": ["/cgi-bin/cgiSrv.cgi"],
            "method": "POST", "ct": "form",
            "payload": lambda **_: {"cmd":"REBOOT"},
        },
    },

    # ── Airtel (Huawei HG8145V5 / HG8240 / Nokia G-240W) ─────────────────────
    "airtel": {
        "panel_paths": ["/", "/html/index.html"],
        CAP_MAC_BLOCK: {
            "paths": ["/api/ntwk/mac_filter", "/html/amp/api/mac_filter"],
            "method": "POST", "ct": "json",
            "payload": lambda mac, **_: {"mac":mac,"enable":True,"type":"black"},
        },
        CAP_MAC_ALLOW: {
            "paths": ["/api/ntwk/mac_filter"],
            "method": "DELETE", "ct": "json",
            "payload": lambda mac, **_: {"mac":mac},
        },
        CAP_WIFI_PASSWORD: {
            "paths": ["/api/ntwk/wlanbasic"],
            "method": "PUT", "ct": "json",
            "payload": lambda pw, band="2.4", **_: {
                "WifiBasicInfo":{"PreSharedKey":pw},
                "InstanceID":"1" if band=="2.4" else "5"},
        },
        CAP_WIFI_SSID: {
            "paths": ["/api/ntwk/wlanbasic"],
            "method": "PUT", "ct": "json",
            "payload": lambda ssid, band="2.4", **_: {
                "WifiBasicInfo":{"SSID":ssid},
                "InstanceID":"1" if band=="2.4" else "5"},
        },
        CAP_PMF: {
            "paths": ["/api/ntwk/wlansecurity"],
            "method": "PUT", "ct": "json",
            "payload": lambda enable=True, **_: {"ManagementFrameProtect":"2" if enable else "0"},
        },
        CAP_WPS: {
            "paths": ["/api/ntwk/wps"],
            "method": "PUT", "ct": "json",
            "payload": lambda **_: {"WPSEnable":False},
        },
        CAP_GUEST_NET: {
            "paths": ["/api/ntwk/guestnetwork"],
            "method": "PUT", "ct": "json",
            "payload": lambda enable=True, ssid="OmniFi-Guest", **_: {
                "GuestNetworkEnabled":enable,"SSID":ssid,"MaxClients":5},
        },
        CAP_DNS_OVERRIDE: {
            "paths": ["/api/ntwk/dns"],
            "method": "PUT", "ct": "json",
            "payload": lambda dns1="1.1.1.1", dns2="8.8.8.8", **_: {
                "PrimaryDNS":dns1,"SecondaryDNS":dns2},
        },
        CAP_DEVICE_LIST: {
            "paths": ["/api/ntwk/hostinfo"],
            "method": "GET", "ct": "json",
            "payload": lambda **_: None,
        },
        CAP_BANDWIDTH: {
            "paths": ["/api/ntwk/qos"],
            "method": "PUT", "ct": "json",
            "payload": lambda mac, down_kbps=0, up_kbps=0, **_: {
                "MACAddress":mac,"DownloadRate":down_kbps,"UploadRate":up_kbps},
        },
        CAP_REBOOT: {
            "paths": ["/api/ntwk/reboot"],
            "method": "POST", "ct": "json",
            "payload": lambda **_: {},
        },
        CAP_REMOTE_MGMT: {
            "paths": ["/api/ntwk/remotemanage"],
            "method": "PUT", "ct": "json",
            "payload": lambda enable=False, **_: {"RemoteManageEnable":enable},
        },
    },

    # ── BSNL (Netlink / Syrotech / DASAN ONT) ────────────────────────────────
    "bsnl_ftth": {
        "panel_paths": ["/", "/userRpm/index.htm"],
        CAP_MAC_BLOCK: {
            "paths": ["/userRpm/WlanMacFilterRpm.htm",
                      "/cgi-bin/macsec.cgi",
                      "/apply.cgi"],
            "method": "POST", "ct": "form",
            "payload": lambda mac, **_: {
                "mac_addr":mac,"filter_type":"deny",
                "action":"add","submit_button":"Save"},
        },
        CAP_WIFI_PASSWORD: {
            "paths": ["/userRpm/WlanSecurityRpm.htm", "/cgi-bin/wlsecurity.cgi"],
            "method": "POST", "ct": "form",
            "payload": lambda pw, **_: {"wpapsk":pw,"wpa2psk":pw,"submit_button":"Save"},
        },
        CAP_WPS: {
            "paths": ["/userRpm/WlanWpsRpm.htm"],
            "method": "POST", "ct": "form",
            "payload": lambda **_: {"wps_enable":"0","submit_button":"Save"},
        },
        CAP_REBOOT: {
            "paths": ["/userRpm/SysRebootRpm.htm","/cgi-bin/reboot.cgi"],
            "method": "POST", "ct": "form",
            "payload": lambda **_: {"submit_button":"Reboot"},
        },
        CAP_DNS_OVERRIDE: {
            "paths": ["/userRpm/WanDynamicIpCfgRpm.htm"],
            "method": "POST", "ct": "form",
            "payload": lambda dns1="1.1.1.1", dns2="8.8.8.8", **_: {
                "dns1":dns1,"dns2":dns2,"submit_button":"Save"},
        },
    },

    # ── ACT Fibernet (TP-Link / D-Link / Tenda) ───────────────────────────────
    "act": {
        "panel_paths": ["/", "/cgi-bin/luci/"],
        # TP-Link stok-based
        CAP_MAC_BLOCK: {
            "paths": ["/cgi-bin/luci/;stok={stok}/admin/wireless",
                      "/userRpm/AccessCtrlAccessRulesRpm.htm"],
            "method": "POST", "ct": "json",
            "payload": lambda mac, stok="", **_: {
                "method":"add","params":{"mac":mac,"type":"black"}},
        },
        CAP_WIFI_PASSWORD: {
            "paths": ["/cgi-bin/luci/;stok={stok}/admin/wireless"],
            "method": "POST", "ct": "json",
            "payload": lambda pw, stok="", **_: {
                "method":"set","params":{"wireless":{"psk":pw}}},
        },
        CAP_WPS: {
            "paths": ["/cgi-bin/luci/;stok={stok}/admin/wireless"],
            "method": "POST", "ct": "json",
            "payload": lambda stok="", **_: {
                "method":"set","params":{"wps":{"wps_state":"0"}}},
        },
        CAP_REBOOT: {
            "paths": ["/cgi-bin/luci/;stok={stok}/admin/reboot"],
            "method": "POST", "ct": "json",
            "payload": lambda stok="", **_: {"method":"set","params":{}},
        },
        CAP_MAX_CLIENTS: {
            "paths": ["/cgi-bin/luci/;stok={stok}/admin/wireless"],
            "method": "POST", "ct": "json",
            "payload": lambda n, stok="", **_: {
                "method":"set","params":{"wireless":{"max_sta":n}}},
        },
        CAP_DNS_OVERRIDE: {
            "paths": ["/cgi-bin/luci/;stok={stok}/admin/network"],
            "method": "POST", "ct": "json",
            "payload": lambda dns1, dns2, stok="", **_: {
                "method":"set","params":{"dns":{"dns1":dns1,"dns2":dns2}}},
        },
        CAP_DEVICE_LIST: {
            "paths": ["/cgi-bin/luci/;stok={stok}/admin/wireless"],
            "method": "POST", "ct": "json",
            "payload": lambda stok="", **_: {"method":"get","params":{"hosts_info":{}}},
        },
    },

    # ── Generic OpenWRT / LuCI ────────────────────────────────────────────────
    "openwrt": {
        "panel_paths": ["/cgi-bin/luci/"],
        CAP_MAC_BLOCK: {
            "paths": ["/cgi-bin/luci/admin/network/wireless"],
            "method": "POST", "ct": "json",
            "payload": lambda mac, **_: {"method":"add","params":{"mac":mac,"type":"block"}},
        },
        CAP_WIFI_PASSWORD: {
            "paths": ["/cgi-bin/luci/admin/network/wireless"],
            "method": "POST", "ct": "json",
            "payload": lambda pw, **_: {"method":"set","params":{"key":pw}},
        },
        CAP_WPS: {
            "paths": ["/cgi-bin/luci/admin/network/wireless"],
            "method": "POST", "ct": "json",
            "payload": lambda **_: {"method":"set","params":{"wps":{"enabled":False}}},
        },
        CAP_REBOOT: {
            "paths": ["/cgi-bin/luci/admin/system/reboot"],
            "method": "POST", "ct": "form",
            "payload": lambda **_: {"reboot":"Perform reboot"},
        },
        CAP_FIREWALL: {
            "paths": ["/cgi-bin/luci/admin/network/firewall/rules"],
            "method": "POST", "ct": "form",
            "payload": lambda mac, action="DROP", **_: {
                "src_mac":mac,"target":action,"submit":"Save"},
        },
        CAP_DNS_OVERRIDE: {
            "paths": ["/cgi-bin/luci/admin/network/dhcp"],
            "method": "POST", "ct": "form",
            "payload": lambda dns1, dns2="", **_: {
                "dns":f"{dns1},{dns2}".rstrip(","),"submit":"Save"},
        },
        CAP_PARENTAL: {
            "paths": ["/cgi-bin/luci/admin/network/parental"],
            "method": "POST", "ct": "form",
            "payload": lambda mac, deny_all=True, **_: {
                "mac":mac,"deny":str(deny_all).lower(),"submit":"Save"},
        },
    },

    # ── Generic DD-WRT ────────────────────────────────────────────────────────
    "ddwrt": {
        "panel_paths": ["/"],
        CAP_MAC_BLOCK: {
            "paths": ["/apply.cgi"],
            "method": "POST", "ct": "form",
            "payload": lambda mac, **_: {
                "action":"ApplyTake","submit_button":"WL_FilterTable",
                "mac_addr":mac,"filter_mode":"deny"},
        },
        CAP_WIFI_PASSWORD: {
            "paths": ["/apply.cgi"],
            "method": "POST", "ct": "form",
            "payload": lambda pw, **_: {
                "action":"ApplyTake","submit_button":"Wireless_WPA",
                "wl_wpa_psk":pw},
        },
        CAP_WPS: {
            "paths": ["/apply.cgi"],
            "method": "POST", "ct": "form",
            "payload": lambda **_: {
                "action":"ApplyTake","submit_button":"WL_WPS","wps_enable":"0"},
        },
        CAP_REBOOT: {
            "paths": ["/apply.cgi"],
            "method": "POST", "ct": "form",
            "payload": lambda **_: {"action":"Reboot"},
        },
    },
}

# Aliases
SITEMAPS["jiofi_dongle"] = SITEMAPS["jiofiber"]
SITEMAPS["bsnl_adsl"]    = SITEMAPS["bsnl_ftth"]
SITEMAPS["hathway"]      = SITEMAPS["ddwrt"]
SITEMAPS["excitel"]      = SITEMAPS["act"]
SITEMAPS["railwire"]     = SITEMAPS["bsnl_ftth"]
SITEMAPS["mtnl"]         = SITEMAPS["bsnl_ftth"]
SITEMAPS["tataplay"]     = SITEMAPS["act"]


# ─────────────────────────────────────────────────────────────────────────────
# RouterConfigManager — executes capabilities against a live session
# ─────────────────────────────────────────────────────────────────────────────

class RouterConfigManager:
    """
    High-level router configuration interface.
    Given an authenticated session + base URL + ISP key, exposes one
    method per capability that handles endpoint discovery, stok tokens,
    retries, and result normalisation.
    """

    def __init__(self, session, base_url: str, isp_key: str):
        self._s      = session
        self._base   = base_url.rstrip("/")
        self._isp    = isp_key.lower()
        self._map    = SITEMAPS.get(self._isp, SITEMAPS.get("openwrt", {}))
        self._stok   = ""
        self._timeout = 6
        log.info(f"RouterConfigManager: {isp_key} @ {base_url}")

    # ── Public API ─────────────────────────────────────────────────────────────

    def mac_block(self, mac: str) -> dict:
        return self._exec(CAP_MAC_BLOCK, mac=mac.upper())

    def mac_allow(self, mac: str) -> dict:
        return self._exec(CAP_MAC_ALLOW, mac=mac.upper())

    def set_wifi_password(self, password: str, band: str = "both") -> dict:
        bands = ["2.4", "5"] if band == "both" else [band]
        results = []
        for b in bands:
            results.append(self._exec(CAP_WIFI_PASSWORD, pw=password, band=b))
        return results[0] if len(results) == 1 else {
            "ok": all(r.get("ok") for r in results),
            "detail": "; ".join(r.get("detail","") for r in results)}

    def set_wifi_ssid(self, ssid: str, band: str = "both") -> dict:
        bands = ["2.4", "5"] if band == "both" else [band]
        results = [self._exec(CAP_WIFI_SSID, ssid=ssid, band=b) for b in bands]
        return results[0] if len(results) == 1 else {
            "ok": all(r.get("ok") for r in results),
            "detail": "; ".join(r.get("detail","") for r in results)}

    def disable_wps(self) -> dict:
        return self._exec(CAP_WPS)

    def enable_pmf(self) -> dict:
        return self._exec(CAP_PMF, enable=True)

    def set_dns(self, dns1: str = "1.1.1.1", dns2: str = "8.8.8.8") -> dict:
        return self._exec(CAP_DNS_OVERRIDE, dns1=dns1, dns2=dns2)

    def disable_remote_mgmt(self) -> dict:
        return self._exec(CAP_REMOTE_MGMT, enable=False)

    def set_max_clients(self, n: int) -> dict:
        return self._exec(CAP_MAX_CLIENTS, n=n)

    def set_bandwidth_limit(self, mac: str, down_kbps: int, up_kbps: int) -> dict:
        return self._exec(CAP_BANDWIDTH, mac=mac.upper(),
                          down_kbps=down_kbps, up_kbps=up_kbps)

    def add_firewall_rule(self, mac: str, action: str = "DROP") -> dict:
        return self._exec(CAP_FIREWALL, mac=mac.upper(), action=action)

    def parental_block(self, mac: str) -> dict:
        return self._exec(CAP_PARENTAL, mac=mac.upper(), deny_all=True)

    def get_device_list(self) -> list:
        r = self._exec(CAP_DEVICE_LIST)
        return r.get("data", [])

    def reboot(self) -> dict:
        return self._exec(CAP_REBOOT)

    def get_capabilities(self) -> list:
        """Return list of capability IDs supported by this router."""
        return [k for k in self._map if k != "panel_paths"]

    # ── Token management ───────────────────────────────────────────────────────

    def _ensure_stok(self) -> str:
        """Refresh TP-Link stok token if needed."""
        if self._stok:
            return self._stok
        try:
            r = self._s.get(
                f"{self._base}/cgi-bin/luci/;stok=/login",
                timeout=self._timeout, verify=False)
            m = re.search(r'"stok":"([^"]+)"', r.text)
            if m:
                self._stok = m.group(1)
        except Exception:
            pass
        return self._stok

    # ── Execution engine ───────────────────────────────────────────────────────

    def _exec(self, cap_id: str, **kwargs) -> dict:
        cap = self._map.get(cap_id)
        if not cap:
            return {"ok": False, "detail": f"Capability '{cap_id}' not supported for {self._isp}"}

        # Inject stok if path needs it
        stok = self._ensure_stok() if "{stok}" in str(cap.get("paths","")) else ""
        kwargs["stok"] = stok

        payload_fn = cap.get("payload")
        payload    = payload_fn(**kwargs) if payload_fn else None
        method     = cap.get("method","POST")
        ct         = cap.get("ct","form")

        last_error = ""
        for raw_path in cap["paths"]:
            path = raw_path.format(stok=stok)
            url  = self._base + path
            try:
                if method == "GET":
                    resp = self._s.get(url, timeout=self._timeout, verify=False)
                elif ct == "json":
                    resp = self._s.request(method, url, json=payload,
                                           timeout=self._timeout, verify=False)
                elif ct == "form":
                    resp = self._s.request(method, url, data=payload,
                                           timeout=self._timeout, verify=False)
                else:
                    resp = self._s.request(method, url, data=payload,
                                           timeout=self._timeout, verify=False)

                ok = resp.status_code in (200, 201, 204, 302)
                # Invalidate stok on 403 (token expired)
                if resp.status_code == 403:
                    self._stok = ""
                if ok:
                    data = {}
                    try:
                        data = resp.json()
                    except Exception:
                        pass
                    return {"ok": True, "detail": f"{cap_id} via {path}",
                            "status": resp.status_code, "data": data}
                last_error = f"HTTP {resp.status_code}"
            except Exception as e:
                last_error = str(e)
                log.debug(f"{cap_id} @ {url}: {e}")

        return {"ok": False, "detail": f"{cap_id} failed ({last_error})", "tried": cap["paths"]}
