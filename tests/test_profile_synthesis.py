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
        domain_mapping_responses=[],
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
        domain_mapping_responses=[],
    )
    discovery = SimpleNamespace(
        connected_agents_response="",
        ssrf_response="",
    )

    result = asyncio.run(
        synthesise_agent_profile(config, recon, discovery)
    )

    assert result == ""


def test_synthesise_includes_domain_mapping_in_prompt(
    monkeypatch,
) -> None:
    """Domain mapping responses are passed into synthesis."""
    config = AISTConfig()
    config.llm.enabled = True
    config.llm.api_key = "test-key"
    config.llm.model = "claude-test"

    recon = SimpleNamespace(
        system_prompt_response="",
        tool_disclosure_response="",
        discovered_tools=[],
        domain_mapping_responses=[
            "I can query customer orders and invoices.",
            "Roles: customer, agent, admin.",
        ],
    )
    discovery = SimpleNamespace(
        connected_agents_response="",
        ssrf_response="",
    )

    captured = {}

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {
                "content": [
                    {"text": "Agent handles orders."}
                ]
            }

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, url, headers=None, json=None,
                       timeout=None):
            captured["prompt"] = json["messages"][0][
                "content"
            ]
            return FakeResponse()

    monkeypatch.setattr(
        "aist.scanner.payload_generator.httpx.AsyncClient",
        FakeClient,
    )

    result = asyncio.run(
        synthesise_agent_profile(config, recon, discovery)
    )

    assert result == "Agent handles orders."
    assert "Domain mapping response 1:" in captured["prompt"]
    assert "customer orders and invoices" in captured[
        "prompt"
    ]
    assert "Domain mapping response 2:" in captured["prompt"]
    assert "Roles: customer, agent, admin." in captured[
        "prompt"
    ]
