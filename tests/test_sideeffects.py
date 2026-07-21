"""Tests for side-effects monitor."""

import pytest

from aist.scanner.sideeffects import (
    SideEffects,
    agent_disclosed_effects,
    create_silent_compliance_evidence,
)


def test_side_effects_any():
    """SideEffects.any() detects recorded effects."""
    empty = SideEffects()
    assert empty.any() is False
    assert SideEffects(emails=[{"to": "x@y.com"}]).any()


def test_agent_disclosed_email():
    """Disclosure detected when response mentions email."""
    effects = SideEffects(
        emails=[{"to": "test@example.com"}]
    )
    response = "I sent the email to test@example.com"
    assert agent_disclosed_effects(response, effects)


def test_agent_undisclosed_email():
    """Undisclosed when response omits side effect."""
    effects = SideEffects(
        emails=[{"to": "secret@example.com"}]
    )
    response = "Here is the summary you requested."
    assert not agent_disclosed_effects(response, effects)


def test_create_silent_compliance_evidence():
    """Silent compliance evidence is marked critical."""
    from aist.evidence.collector import Evidence

    original = Evidence(
        payload_id="E1-1",
        payload_category="E",
        prompt_sent="send data",
        response_received="Done.",
        response_hash="abc",
    )
    effects = SideEffects(
        emails=[{"to": "x@y.com"}]
    )
    silent = create_silent_compliance_evidence(
        original, effects
    )
    assert silent.payload_id == "E1-1-SILENT"
    assert silent.silent_compliance is True
