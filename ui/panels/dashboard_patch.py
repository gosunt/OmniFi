"""
OmniFi — Enhanced Dashboard Panel Additions
=============================================
These are *drop-in patches* that extend the existing DashboardPanel with:

  1. A live Bandwidth Meter tab (BandwidthMeterWidget)
  2. A Password Strength overview card (mini version)
  3. Signal strength badge per network

Import this module after DashboardPanel; call  patch_dashboard(dash, backend)
to wire everything in.

This approach avoids re-writing the entire DashboardPanel — it simply
injects the new widgets into the existing tab structure.
"""
from __future__ import annotations

import logging
from typing import Callable, Optional

from PyQt6.QtCore    import QTimer
from PyQt6.QtWidgets import QTabWidget, QWidget, QVBoxLayout, QLabel

log = logging.getLogger("OmniFi.DashPatch")


def patch_dashboard(dash, backend) -> None:
    """
    Call once after MainWindow builds its DashboardPanel.

    dash    — the DashboardPanel instance
    backend — the Backend instance
    """
    try:
        _inject_bandwidth_tab(dash, backend)
    except Exception as e:
        log.warning(f"[DashPatch] bandwidth tab: {e}")

    try:
        _inject_pwd_strength_tab(dash, backend)
    except Exception as e:
        log.warning(f"[DashPatch] password strength tab: {e}")


# ─────────────────────────────────────────────────────────────────────────────
def _inject_bandwidth_tab(dash, backend) -> None:
    """Add a Bandwidth tab to the dashboard if it has a QTabWidget."""
    from ui.widgets.bandwidth_meter import BandwidthMeterWidget
    from core.bandwidth_worker import BandwidthWorker

    # Find the first QTabWidget in the dashboard
    tab_widget = _find_tab_widget(dash)
    if tab_widget is None:
        # Create one if dashboard has no tabs (add at bottom)
        bw = BandwidthMeterWidget(dash)
        if hasattr(dash, "layout") and dash.layout():
            dash.layout().addWidget(bw)
        else:
            log.debug("[DashPatch] No layout found to inject bandwidth meter")
        dash._bw_widget = bw
    else:
        bw = BandwidthMeterWidget()
        tab_widget.addTab(bw, "📊 Bandwidth")
        dash._bw_widget = bw

    # Wire bandwidth worker
    tel = getattr(backend, "telemetry", None)
    worker = BandwidthWorker(telemetry_engine=tel)
    worker.stats_ready.connect(bw.update_stats)
    worker.start()
    dash._bw_worker = worker


def _inject_pwd_strength_tab(dash, backend) -> None:
    """Add a Password Strength mini-view to the dashboard."""
    from ui.widgets.password_strength_widget import PasswordStrengthWidget
    from core.backend import score_password

    tab_widget = _find_tab_widget(dash)
    if tab_widget is None:
        return

    pwd_widget = PasswordStrengthWidget(
        score_fn=score_password,
        is_admin_fn=backend.is_admin,
        change_fn=None,   # no direct change from dashboard
    )
    tab_widget.addTab(pwd_widget, "🔐 Passwords")
    dash._pwd_strength_widget = pwd_widget

    # Refresh password list whenever new scan results arrive
    def _on_nets(nets: list):
        try:
            pwd_widget.update_networks(nets)
        except Exception as e:
            log.debug(f"[DashPatch] pwd_strength update: {e}")

    # Store callback so caller can wire it to scanner signal
    dash.on_nets_for_pwd = _on_nets


def _find_tab_widget(widget: QWidget) -> Optional[QTabWidget]:
    """Recursively find the first QTabWidget child."""
    for child in widget.findChildren(QTabWidget):
        return child
    return None
