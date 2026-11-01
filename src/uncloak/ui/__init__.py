"""
UI subsystem exports for Uncloak.
"""

from typing import Any

__all__ = ["run_cockpit", "launch_desktop", "build_cockpit_layout", "CockpitState", "FlowEntry"]


def __getattr__(name: str) -> Any:
    if name == "run_cockpit":
        from uncloak.ui.cockpit import run_cockpit
        return run_cockpit
    if name == "launch_desktop":
        from uncloak.ui.desktop import launch_desktop
        return launch_desktop
    if name in ("CockpitState", "FlowEntry", "build_cockpit_layout"):
        import uncloak.ui.layout as layout
        return getattr(layout, name)
    raise AttributeError(f"module 'uncloak.ui' has no attribute '{name}'")
