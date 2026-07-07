"""Tests for automatic agent profile synthesis."""

import asyncio
from types import SimpleNamespace

from aist.config import AISTConfig
from aist.scanner.payload_generator import synthesise_agent_profile


def test_synthesise_returns_empty_without_llm() -> None:
    """Profile synthesis is skipped when LLM is disabled."""
    config = AISTConfig()
    recon = SimpleNamespace(
        system_prompt_response="I help with orders.",
        tool_disclosure_response="",
        discovered_tools=[],
    )
    discovery = SimpleNamespace(
        connected_agents_response="",
        ssrf_response="",
    )

    result = asyncio.run(
        synthesise_agent_profile(config, recon, discovery)
    )

    assert result == ""


def test_synthesise_returns_empty_without_recon_data() -> None:
    """Profile synthesis needs recon responses to proceed."""
    config = AISTConfig()
    config.llm.enabled = True
    config.llm.api_key = "test-key"

    recon = SimpleNamespace(
        system_prompt_response="",
        tool_disclosure_response="",
        discovered_tools=[],
    )
    discovery = SimpleNamespace(
        connected_agents_response="",
        ssrf_response="",
    )

    result = asyncio.run(
        synthesise_agent_profile(config, recon, discovery)
    )

    assert result == ""
