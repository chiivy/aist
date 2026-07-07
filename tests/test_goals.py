"""Tests for goal-oriented testing configuration."""

from aist.config import (
    GOAL_CATEGORY_MAP,
    apply_goals_to_config,
    resolve_goals_to_categories,
    AISTConfig,
)


def test_resolve_single_goal() -> None:
    """A single goal maps to its payload categories."""
    assert resolve_goals_to_categories(["exfiltrate"]) == [
        "C",
        "D",
        "I",
    ]


def test_resolve_multiple_goals_deduplicates() -> None:
    """Overlapping goals merge categories without duplicates."""
    result = resolve_goals_to_categories(
        ["exfiltrate", "reconnaissance"]
    )
    assert result == ["C", "D", "GEN", "I"]


def test_resolve_full_goal_returns_none() -> None:
    """The full goal runs every category."""
    assert resolve_goals_to_categories(["full"]) is None


def test_apply_goals_sets_scan_config() -> None:
    """Goals are stored on config for reporting."""
    config = AISTConfig()
    apply_goals_to_config(config, "exfiltrate,abuse-tools")
    assert config.scan.goals == ["exfiltrate", "abuse-tools"]
    assert config.scan.categories == [
        "BL",
        "C",
        "D",
        "E",
        "H",
        "I",
    ]


def test_goal_map_covers_all_descriptions() -> None:
    """Every mapped goal has a human-readable description."""
    assert set(GOAL_CATEGORY_MAP) == {
        "exfiltrate",
        "abuse-tools",
        "bypass-controls",
        "business-logic",
        "multi-agent",
        "infrastructure",
        "reconnaissance",
        "full",
    }
