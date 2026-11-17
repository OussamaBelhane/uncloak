"""Unit tests for the hierarchical 3-Tier PolicyManager governance engine."""

import tempfile
from pathlib import Path
from uncloak.core.policy import PolicyManager


def test_policy_manager_inheritance_and_overrides() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        pol_path = Path(tmpdir) / "policy.json"
        pm = PolicyManager(policy_path=pol_path)

        # 1. Default Tier inheritance
        eff_t0 = pm.get_effective_policy("dc01", default_tier="Tier-0")
        assert eff_t0["effective_tier"] == "Tier-0"
        assert eff_t0["effective_mode"] == "audit_p1"
        assert eff_t0["has_override"] is False

        # 2. Threshold tuning
        th = pm.set_thresholds(alert_confidence=0.75, block_confidence=0.92, max_mad_ratio=0.15, min_bursts=10)
        assert th["alert_confidence"] == 0.75
        assert th["block_confidence"] == 0.92
        assert th["max_mad_ratio"] == 0.15
        assert th["min_bursts"] == 10

        # 3. Surgical host override (reassign tier + mode)
        pm.set_host_override(host_id="ws-04", tier="1", mode="prompt_analyst")
        eff_ws = pm.get_effective_policy("ws-04", default_tier="Tier-2")
        assert eff_ws["effective_tier"] == "Tier-1"
        assert eff_ws["effective_mode"] == "prompt_analyst"
        assert eff_ws["has_override"] is True

        # 4. Maintenance mode forces audit_only
        pm.set_host_override(host_id="ws-04", maintenance_mode=True)
        eff_maint = pm.get_effective_policy("ws-04", default_tier="Tier-2")
        assert eff_maint["maintenance_mode"] is True
        assert eff_maint["effective_mode"] == "audit_only"

        # 5. Persistence across reload
        pm2 = PolicyManager(policy_path=pol_path)
        assert pm2.state["thresholds"]["alert_confidence"] == 0.75
        assert pm2.get_effective_policy("ws-04")["maintenance_mode"] is True
