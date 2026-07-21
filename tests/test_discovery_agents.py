"""Tests for connected-agent name extraction."""

from aist.recon.discovery import (
    _extract_agent_references,
    resolve_connected_agent_targets,
)


def test_extract_named_agent_from_response() -> None:
    """Concrete agent names beat generic indicators."""
    response = (
        "I can forward clinical queries to the "
        "Specialist Agent for review."
    )
    names = _extract_agent_references(response)
    assert any("Specialist" in n for n in names)


def test_resolve_prefers_concrete_names() -> None:
    """MA targets use names from the raw recon reply."""
    targets = resolve_connected_agent_targets(
        connected_agents=["specialist agent"],
        connected_agents_response=(
            "The Billing Agent handles invoices and "
            "the Claims Agent reviews disputes."
        ),
    )
    assert any("Billing" in t for t in targets)
    assert "specialist agent" not in targets


def test_resolve_falls_back_to_indicators() -> None:
    """Generic indicators remain when no names found."""
    targets = resolve_connected_agent_targets(
        connected_agents=["specialist agent"],
        connected_agents_response="I work alone.",
    )
    assert targets == ["specialist agent"]
