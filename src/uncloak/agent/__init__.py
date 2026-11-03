"""
Uncloak Endpoint Agent Subsystem.
Lightweight background service for local socket polling, cadence calculation, and kernel eviction.
"""

from uncloak.agent.service import UncloakAgentService

__all__ = ["UncloakAgentService"]
