"""
Uncloak: Autonomous C2 Stealth Jitter Detection & Win32 Socket Attribution Engine.
"""

__version__ = "0.1.0"
__author__ = "Uncloak Core Team"
__license__ = "MIT"

from uncloak.core.models import FlowSession, PacketEvent, ThreatAlert

__all__ = ["__version__", "PacketEvent", "FlowSession", "ThreatAlert"]
