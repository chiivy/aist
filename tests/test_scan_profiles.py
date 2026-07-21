"""Tests for scan profile presets."""

from aist.config import AISTConfig
from aist.scan_profiles import (
    apply_profile_to_config,
    get_profile_spec,
)


def test_quick_profile_settings():
    """Quick profile disables adaptive recon and multiturn."""
    spec = get_profile_spec("quick")
    assert spec.adaptive_recon is False
    assert spec.multiturn is False
    assert "B" in spec.categories


def test_deep_profile_enables_multiturn():
    """Deep profile enables Phase 2 multi-turn."""
    spec = get_profile_spec("deep")
    assert spec.adaptive_recon is True
    assert spec.multiturn is True


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


def test_no_adaptive_recon_override():
    """--no-adaptive-recon disables adaptive recon."""
    config = AISTConfig()
    apply_profile_to_config(
        config,
        profile_name="standard",
        no_adaptive_recon=True,
    )
    assert config.scan.adaptive_recon is False
