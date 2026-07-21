"""
Scan profile presets for AIST.

Profiles control adaptive recon, category scope,
and Phase 2 multi-turn scenarios without changing
Phase 1 scanner implementations.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ScanProfileSpec:
    """Resolved settings for a named scan profile."""

    name: str
    adaptive_recon: bool
    categories: Optional[list]
    multiturn: bool
    estimated_time: str


PROFILE_SPECS: dict[str, ScanProfileSpec] = {
    "quick": ScanProfileSpec(
        name="quick",
        adaptive_recon=False,
        categories=["B", "C", "D", "E"],
        multiturn=False,
        estimated_time="5-10 minutes",
    ),
    "standard": ScanProfileSpec(
        name="standard",
        adaptive_recon=True,
        categories=None,
        multiturn=False,
        estimated_time="30-45 minutes",
    ),
    "deep": ScanProfileSpec(
        name="deep",
        adaptive_recon=True,
        categories=None,
        multiturn=True,
        estimated_time="60-90 minutes",
    ),
    "targeted": ScanProfileSpec(
        name="targeted",
        adaptive_recon=True,
        categories=None,
        multiturn=True,
        estimated_time="10-20 minutes",
    ),
}


def get_profile_spec(name: str) -> ScanProfileSpec:
    """Return profile spec, defaulting to standard."""
    return PROFILE_SPECS.get(name, PROFILE_SPECS["standard"])


def apply_profile_to_config(
    config,
    profile_name: str,
    categories_override: Optional[list] = None,
    no_adaptive_recon: bool = False,
    no_multiturn: bool = False,
) -> ScanProfileSpec:
    """
    Apply profile preset fields onto config.scan.

    Args:
        config:              AISTConfig instance
        profile_name:        quick|standard|deep|targeted
        categories_override: CLI --categories list
        no_adaptive_recon:   Force static recon
        no_multiturn:        Skip Phase 2 scenarios

    Returns:
        Resolved ScanProfileSpec
    """
    spec = get_profile_spec(profile_name)
    config.scan.profile = spec.name
    config.scan.adaptive_recon = (
        spec.adaptive_recon and not no_adaptive_recon
    )
    config.scan.multiturn_enabled = (
        spec.multiturn and not no_multiturn
    )
    config.scan.estimated_time = spec.estimated_time

    if profile_name == "targeted" and categories_override:
        config.scan.categories = categories_override
    elif spec.categories is not None:
        config.scan.categories = list(spec.categories)
    elif categories_override:
        config.scan.categories = categories_override

    return spec
