"""
Governance & 3-Tier Active Directory Policy Engine for Uncloak Enterprise.
Implements hierarchical policy resolution:
  1. Fleet Global Thresholds (FlowFeaturesV1 detection & autonomous containment limits)
  2. Active Directory Tier Policies (Tier-0 Domain Controllers, Tier-1 Servers, Tier-2 Workstations)
  3. Per-Endpoint Surgical Overrides (Host tier reassignment, containment override, maintenance mode)
"""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any, Optional

DEFAULT_POLICY_PATH = Path.home() / ".uncloak" / "policy.json"

VALID_MODES = {
    "audit_p1": "Audit + P1 SIEM Escalation",
    "quorum": "Require 2-Analyst Quorum Sever",
    "prompt_analyst": "Hold Socket + Analyst Prompt",
    "auto_sever": "Autonomous SetTcpEntry RST",
    "auto_wfp": "Autonomous SetTcpEntry + WFP Block",
    "audit_only": "Passive Telemetry Only",
    "inherit": "Inherit Tier Policy",
}

VALID_TIERS = {"0": "Tier-0", "1": "Tier-1", "2": "Tier-2", "Tier-0": "Tier-0", "Tier-1": "Tier-1", "Tier-2": "Tier-2"}


def default_policy_state() -> dict[str, Any]:
    """Returns the baseline enterprise governance policy configuration."""
    return {
        "revision": 1,
        "tier_policies": {
            "Tier-0": "audit_p1",
            "Tier-1": "prompt_analyst",
            "Tier-2": "auto_wfp",
        },
        "thresholds": {
            "alert_confidence": 0.850,
            "block_confidence": 0.900,
            "max_mad_ratio": 0.180,
            "min_bursts": 8,
        },
        "host_overrides": {},
    }


class PolicyManager:
    """Manages hierarchical fleet, tier, and host-level containment policies."""

    def __init__(self, policy_path: Optional[Path] = None) -> None:
        self.policy_path = Path(policy_path) if policy_path else DEFAULT_POLICY_PATH
        self.state: dict[str, Any] = self.load()

    def load(self) -> dict[str, Any]:
        """Loads persisted policy configuration or initializes defaults."""
        if self.policy_path.exists():
            try:
                data = json.loads(self.policy_path.read_text(encoding="utf-8"))
                base = default_policy_state()
                base.update({k: v for k, v in data.items() if k in base})
                return base
            except (OSError, json.JSONDecodeError):
                pass
        return default_policy_state()

    def save(self) -> None:
        """Persists current policy state to disk atomically."""
        self.policy_path.parent.mkdir(parents=True, exist_ok=True)
        self.state["revision"] = int(self.state.get("revision", 0)) + 1
        tmp_path = self.policy_path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(self.state, indent=2), encoding="utf-8")
        tmp_path.replace(self.policy_path)

    def set_tier_policies(
        self,
        tier0: Optional[str] = None,
        tier1: Optional[str] = None,
        tier2: Optional[str] = None,
    ) -> dict[str, str]:
        """Updates containment mode for one or more AD tiers."""
        tiers = self.state.setdefault("tier_policies", {})
        if tier0 and tier0 in VALID_MODES:
            tiers["Tier-0"] = tier0
        if tier1 and tier1 in VALID_MODES:
            tiers["Tier-1"] = tier1
        if tier2 and tier2 in VALID_MODES:
            tiers["Tier-2"] = tier2
        self.save()
        return dict(tiers)

    def set_thresholds(
        self,
        alert_confidence: Optional[float] = None,
        block_confidence: Optional[float] = None,
        max_mad_ratio: Optional[float] = None,
        min_bursts: Optional[int] = None,
    ) -> dict[str, Any]:
        """Updates FlowFeaturesV1 detection and autonomous containment thresholds."""
        thresh = self.state.setdefault("thresholds", {})
        if alert_confidence is not None:
            if not 0.10 <= alert_confidence <= 0.99:
                raise ValueError("alert_confidence must be between 0.10 and 0.99")
            thresh["alert_confidence"] = round(float(alert_confidence), 3)
        if block_confidence is not None:
            if not 0.50 <= block_confidence <= 0.99:
                raise ValueError("block_confidence must be between 0.50 and 0.99")
            thresh["block_confidence"] = round(float(block_confidence), 3)
        if max_mad_ratio is not None:
            if not 0.01 <= max_mad_ratio <= 0.80:
                raise ValueError("max_mad_ratio must be between 0.01 and 0.80")
            thresh["max_mad_ratio"] = round(float(max_mad_ratio), 3)
        if min_bursts is not None:
            if not 2 <= min_bursts <= 50:
                raise ValueError("min_bursts must be between 2 and 50")
            thresh["min_bursts"] = int(min_bursts)
        self.save()
        return dict(thresh)

    def set_host_override(
        self,
        host_id: Optional[str] = None,
        tier: Optional[str] = None,
        mode: Optional[str] = None,
        maintenance_mode: Optional[bool] = None,
    ) -> dict[str, Any]:
        """Sets or clears a surgical host-level AD tier or containment override."""
        target_host = host_id or f"host-{socket.gethostname().lower()}"
        overrides = self.state.setdefault("host_overrides", {})
        entry = overrides.get(target_host, {})

        if tier is not None:
            norm_tier = VALID_TIERS.get(str(tier))
            if not norm_tier:
                raise ValueError(f"Invalid tier '{tier}'. Expected 0, 1, 2 or Tier-0/1/2.")
            entry["tier"] = norm_tier

        if mode is not None:
            if mode == "inherit":
                entry.pop("mode", None)
            elif mode in VALID_MODES:
                entry["mode"] = mode
            else:
                raise ValueError(f"Invalid mode '{mode}'.")

        if maintenance_mode is not None:
            entry["maintenance_mode"] = bool(maintenance_mode)

        if not entry:
            overrides.pop(target_host, None)
        else:
            overrides[target_host] = entry

        self.save()
        return dict(entry)

    def get_effective_policy(self, host_id: str, default_tier: str = "Tier-2") -> dict[str, Any]:
        """Resolves the effective policy for a host using the 3-level inheritance chain."""
        overrides = self.state.get("host_overrides", {}).get(host_id, {})
        effective_tier = overrides.get("tier", default_tier)
        if effective_tier not in ("Tier-0", "Tier-1", "Tier-2"):
            effective_tier = "Tier-2"

        tier_mode = self.state.get("tier_policies", {}).get(effective_tier, "prompt_analyst")
        effective_mode = overrides.get("mode", tier_mode)
        if overrides.get("maintenance_mode"):
            effective_mode = "audit_only"

        return {
            "host_id": host_id,
            "effective_tier": effective_tier,
            "effective_mode": effective_mode,
            "mode_label": VALID_MODES.get(effective_mode, effective_mode),
            "maintenance_mode": bool(overrides.get("maintenance_mode", False)),
            "has_override": bool(overrides),
            "thresholds": dict(self.state.get("thresholds", {})),
        }
