"""Tests for scan profile presets."""

import asyncio

from aist.config import AISTConfig
from aist.scan_profiles import (
    apply_profile_to_config,
    category_label,
    get_completion_disclaimer,
    get_profile_banner,
    get_profile_spec,
)
from aist.scanner.orchestrator import build_scanner_tasks
from aist.scanner.generated_scanner import run_generated_scanner
from aist.scanner.payload_generator import GeneratedPayload


def test_quick_profile_settings():
    """Quick profile disables adaptive recon, multiturn, GEN."""
    spec = get_profile_spec("quick")
    assert spec.adaptive_recon is False
    assert spec.multiturn is False
    assert spec.gen_enabled is False
    assert "B" in spec.categories
    assert spec.payload_summary == "~45"


def test_deep_profile_enables_multiturn():
    """Deep profile enables Phase 2 multi-turn."""
    spec = get_profile_spec("deep")
    assert spec.adaptive_recon is True
    assert spec.multiturn is True
    assert spec.gen_enabled is True


def test_apply_profile_to_config():
    """Profile fields are applied onto scan config."""
    config = AISTConfig()
    apply_profile_to_config(
        config,
        profile_name="targeted",
        categories_override=["G", "D"],
    )
    assert config.scan.profile == "targeted"
    assert config.scan.adaptive_recon is True
    assert config.scan.multiturn_enabled is True
    assert config.scan.categories == ["G", "D"]
    assert config.scan.gen_enabled is True


def test_quick_profile_disables_gen():
    """Quick profile sets gen_enabled False on config."""
    config = AISTConfig()
    apply_profile_to_config(config, profile_name="quick")
    assert config.scan.gen_enabled is False


def test_quick_profile_excludes_gen_scanner_task():
    """Quick profile must not schedule GEN scanner work."""
    config = AISTConfig()
    apply_profile_to_config(config, profile_name="quick")
    task_names = [name for name, _ in build_scanner_tasks(config)]
    assert "generated" not in task_names


def test_quick_profile_produces_zero_gen_findings():
    """GEN scanner returns no evidence when gen is disabled."""
    config = AISTConfig()
    apply_profile_to_config(config, profile_name="quick")
    assert config.scan.gen_enabled is False

    payloads = [
        GeneratedPayload(
            payload_id="GEN-1",
            category="GEN",
            prompt="test",
            rationale="test",
            sensitivity="high",
            success_indicators=[],
        )
    ]
    evidence, results = asyncio.run(
        run_generated_scanner(
            config,
            payloads,
            canary_token="token",
        )
    )

    assert evidence == []
    assert results == {}
    gen_findings = [
        item for item in evidence
        if getattr(item, "payload_category", None) == "GEN"
    ]
    assert gen_findings == []


def test_no_adaptive_recon_override():
    """--no-adaptive-recon disables adaptive recon."""
    config = AISTConfig()
    apply_profile_to_config(
        config,
        profile_name="standard",
        no_adaptive_recon=True,
    )
    assert config.scan.adaptive_recon is False


def test_category_label():
    """Category codes map to human-readable labels."""
    assert category_label("B") == "Persona Injection"
    assert category_label("GEN") == "Context-Aware Attacks"


def test_profile_banner_quick():
    """Quick profile banner shows payload count and tests."""
    line1, line2 = get_profile_banner("quick")
    assert "Payloads: ~45" in line1
    assert "Persona Injection" in line2


def test_completion_disclaimer_quick():
    """Quick profile shows tested and not tested categories."""
    text = get_completion_disclaimer("quick")
    assert "Quick scan complete" in text
    assert "Persona Injection" in text
    assert "Context-Aware Attacks" in text
    assert "--profile standard" in text
