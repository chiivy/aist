"""Tests for Phase 2 adaptive multi-turn scanner."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

from aist.config import AISTConfig
from aist.evidence.collector import Evidence
from aist.recon.adaptive import AgentProfile
from aist.scanner.adaptive_multiturn import (
    MultiTurnScanner,
    derive_base_url,
    derive_direct_endpoint_candidates,
    infer_main_agent_name,
    response_contains_sensitive_data,
)


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


def test_select_scenarios_connected_agent_pivot():
    """Pivot scenario when connected agents exist."""
    profile = AgentProfile(
        connected_agents=["ConsultAI"],
    )
    scanner = MultiTurnScanner(
        config=AISTConfig(),
        phase1_findings=[],
        agent_profile=profile,
        side_effects_monitor=None,
    )
    assert "connected_agent_pivot" in scanner.select_scenarios()


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


def test_derive_base_url():
    """Chat endpoint strips to service base URL."""
    assert derive_base_url(
        "http://localhost:5002/chat"
    ) == "http://localhost:5002"


def test_derive_direct_endpoint_candidates():
    """Candidate URLs include common specialist paths."""
    urls = derive_direct_endpoint_candidates(
        "http://localhost:5002/chat",
        [{"agent": "ConsultAI", "endpoint": "/specialist"}],
    )
    assert "http://localhost:5002/specialist" in urls
    assert "http://localhost:5002/consult" in urls
    assert "http://localhost:5002/api/specialist" in urls


def test_response_contains_sensitive_data_json():
    """JSON record payloads count as sensitive data."""
    body = json.dumps({
        "records": [{"id": "R-1", "status": "active"}],
    })
    assert response_contains_sensitive_data(body)


def test_response_contains_sensitive_data_refusal():
    """Refusals are not treated as data leaks."""
    assert not response_contains_sensitive_data(
        "Access denied. You are not authorized."
    )


def test_probe_direct_connected_agents_finding():
    """Direct endpoint access creates Critical MA finding."""
    profile = AgentProfile(
        connected_agents=["ConsultAI"],
    )
    config = AISTConfig()
    config.target.endpoint = "http://localhost:5002/chat"

    scanner = MultiTurnScanner(
        config=config,
        phase1_findings=[],
        agent_profile=profile,
        side_effects_monitor=None,
    )

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = json.dumps({
        "records": [
            {"id": "R-1", "details": "restricted data"},
        ],
        "count": 1,
    })

    async def run_probe():
        with patch(
            "aist.scanner.adaptive_multiturn.httpx.AsyncClient"
        ) as mock_client:
            instance = mock_client.return_value.__aenter__
            instance.return_value.post = AsyncMock(
                return_value=mock_response
            )
            return await scanner.probe_direct_connected_agents()

    evidence, probe_log = asyncio.run(run_probe())

    assert evidence is not None
    assert evidence.payload_id == "MA-PIVOT-DIRECT"
    assert "without authentication" in (
        evidence.llm_judge_reasoning or ""
    )
    assert probe_log


def test_infer_main_agent_name():
    """Main agent name defaults when purpose unknown."""
    profile = AgentProfile()
    assert infer_main_agent_name(profile) == "MainAgent"
