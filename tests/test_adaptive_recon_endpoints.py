"""Tests for adaptive recon endpoint probing."""

import asyncio
from unittest.mock import AsyncMock, patch

from aist.config import AISTConfig
from aist.recon.adaptive import AdaptiveRecon, AgentProfile


def test_probe_agent_endpoint():
    """Endpoint probe asks how to contact connected agent."""
    config = AISTConfig()
    config.llm.enabled = False

    recon = AdaptiveRecon(config)
    profile = AgentProfile()
    conversation: list = []

    async def run_probe():
        with patch.object(
            recon,
            "send",
            new=AsyncMock(
                return_value=(
                    "You can reach ConsultAI at /specialist"
                )
            ),
        ):
            with patch.object(
                recon,
                "extract_learnings",
                new=AsyncMock(return_value={
                    "connected_agent_endpoints": [{
                        "agent": "ConsultAI",
                        "endpoint": "/specialist",
                    }],
                }),
            ):
                await recon._probe_agent_endpoint(
                    "ConsultAI",
                    profile,
                    conversation,
                )

    asyncio.run(run_probe())

    assert len(conversation) == 1
    assert "ConsultAI" in conversation[0]["sent"]
    assert profile.connected_agent_endpoints


def test_profile_merges_connected_agent_endpoints():
    """Endpoint entries merge by agent name."""
    profile = AgentProfile()
    profile.update({
        "connected_agent_endpoints": [{
            "agent": "AgentA",
            "endpoint": "/consult",
        }],
    })
    profile.update({
        "connected_agent_endpoints": [{
            "agent": "AgentA",
            "endpoint": "/specialist",
        }],
    })
    assert len(profile.connected_agent_endpoints) == 1
    assert profile.connected_agent_endpoints[0][
        "endpoint"
    ] == "/specialist"
