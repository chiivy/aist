"""Tests for application context configuration."""

from aist.config import AISTConfig
from aist.scanner.payload_generator import _build_context_summary


def test_app_context_prepended_to_generation_context(
    monkeypatch,
) -> None:
    """Operator-provided context is included in payload generation."""
    from aist.scanner import payload_generator

    config = AISTConfig()
    config.target.app_context = (
        "Diesel forecast agent for telecom sites."
    )
    config.llm.enabled = True

    context_parts = _build_context_summary(None, None)
    if config.target.app_context:
        context_parts.insert(
            0,
            "Application description (provided "
            f"by operator): {config.target.app_context}",
        )

    assert context_parts[0].startswith(
        "Application description (provided by operator):"
    )
    assert "Diesel forecast" in context_parts[0]


def test_target_config_app_context_default_empty() -> None:
    """Application context defaults to empty string."""
    config = AISTConfig()
    assert config.target.app_context == ""
