"""Tests for Phase 2 adaptive multi-turn scanner."""

from aist.config import AISTConfig
from aist.evidence.collector import Evidence
from aist.recon.adaptive import AgentProfile
from aist.scanner.adaptive_multiturn import MultiTurnScanner


def test_select_scenarios_scope_bypass():
    """Scope bypass selected when boundaries exist."""
    profile = AgentProfile(
        scope_boundaries=["other teams"],
    )
    scanner = MultiTurnScanner(
        config=AISTConfig(),
        phase1_findings=[],
        agent_profile=profile,
        side_effects_monitor=None,
    )
    scenarios = scanner.select_scenarios()
    assert "scope_bypass" in scenarios


def test_select_scenarios_data_exfiltration():
    """Data exfiltration when email tool available."""
    profile = AgentProfile(tools_available=["email"])
    scanner = MultiTurnScanner(
        config=AISTConfig(),
        phase1_findings=[],
        agent_profile=profile,
        side_effects_monitor=None,
    )
    scenarios = scanner.select_scenarios()
    assert "data_exfiltration" in scenarios


def test_phase1_bypassed_scope():
    """Phase 1 bypass detected from findings."""
    profile = AgentProfile(
        scope_boundaries=["restricted zone"],
    )
    finding = Evidence(
        payload_id="C1",
        payload_category="C",
        prompt_sent="x",
        response_received="restricted zone data here",
        response_hash="h",
        string_match_success=True,
    )
    scanner = MultiTurnScanner(
        config=AISTConfig(),
        phase1_findings=[finding],
        agent_profile=profile,
        side_effects_monitor=None,
    )
    assert scanner.phase1_bypassed_scope() is True
    assert "scope_bypass" not in scanner.select_scenarios()
