"""
Scan profile presets for AIST.

Profiles control adaptive recon, category scope,
and Phase 2 multi-turn scenarios without changing
Phase 1 scanner implementations.
"""

from dataclasses import dataclass
from typing import Optional


CATEGORY_LABELS: dict[str, str] = {
    "B": "Persona Injection",
    "C": "Objective Hijacking",
    "D": "System Prompt Leakage",
    "E": "Tool Abuse",
    "H": "Infrastructure Probing",
    "I": "Indirect Injection",
    "BL": "Business Logic Bypass",
    "MA": "Multi-Agent Traversal",
    "GEN": "Context-Aware Attacks",
    "S": "Multi-Turn Sequences",
    "J": "Infrastructure Security",
    "A": "Role Override",
    "F": "Output Manipulation",
    "G": "Guardrail Bypass",
    "INDIRECT": "Indirect Injection",
    "SILENT": "Silent Compliance",
}


@dataclass(frozen=True)
class ScanProfileSpec:
    """Resolved settings for a named scan profile."""

    name: str
    adaptive_recon: bool
    categories: Optional[list]
    multiturn: bool
    payload_summary: str
    gen_enabled: bool = True


PROFILE_SPECS: dict[str, ScanProfileSpec] = {
    "quick": ScanProfileSpec(
        name="quick",
        adaptive_recon=False,
        categories=["B", "C", "D", "E"],
        multiturn=False,
        payload_summary="~45",
        gen_enabled=False,
    ),
    "standard": ScanProfileSpec(
        name="standard",
        adaptive_recon=True,
        categories=None,
        multiturn=False,
        payload_summary="~100",
        gen_enabled=True,
    ),
    "deep": ScanProfileSpec(
        name="deep",
        adaptive_recon=True,
        categories=None,
        multiturn=True,
        payload_summary="~100 + adaptive scenarios",
        gen_enabled=True,
    ),
    "targeted": ScanProfileSpec(
        name="targeted",
        adaptive_recon=True,
        categories=None,
        multiturn=True,
        payload_summary="varies",
        gen_enabled=True,
    ),
}


def category_label(code: str) -> str:
    """Return human-readable label for a category code."""
    normalised = (code or "").upper()
    if normalised in CATEGORY_LABELS:
        return CATEGORY_LABELS[normalised]
    if normalised.startswith("GEN"):
        return CATEGORY_LABELS["GEN"]
    return code


def format_category_list(codes: list[str]) -> str:
    """Format category codes as a comma-separated label list."""
    labels = [category_label(c) for c in codes]
    return ", ".join(labels)


def get_profile_spec(name: str) -> ScanProfileSpec:
    """Return profile spec, defaulting to standard."""
    return PROFILE_SPECS.get(name, PROFILE_SPECS["standard"])


def get_testing_summary(
    profile_name: str,
    categories: Optional[list] = None,
) -> str:
    """Human-readable testing scope for a profile."""
    if profile_name == "standard":
        return "All vulnerability categories"
    if profile_name == "deep":
        return "All categories + Multi-Turn Attack Scenarios"
    if profile_name == "targeted":
        if categories:
            return format_category_list(categories)
        return "Selected categories"
    spec = get_profile_spec(profile_name)
    if categories:
        return format_category_list(categories)
    if spec.categories:
        return format_category_list(spec.categories)
    return "All vulnerability categories"


def get_profile_banner(
    profile_name: str,
    categories: Optional[list] = None,
) -> tuple[str, str]:
    """
    Return profile banner lines for console output.

    Returns:
        (profile_line, testing_line)
    """
    spec = get_profile_spec(profile_name)
    profile_line = (
        f"Profile: {profile_name} | "
        f"Payloads: {spec.payload_summary}"
    )
    testing = get_testing_summary(profile_name, categories)
    testing_line = f"Testing: {testing}"
    return profile_line, testing_line


def get_untested_category_labels(
    tested_codes: list[str],
) -> list[str]:
    """Category labels not covered by the tested code list."""
    tested = {c.upper() for c in tested_codes}
    untested: list[str] = []
    for code, label in CATEGORY_LABELS.items():
        if code in ("A", "F", "G", "INDIRECT", "SILENT"):
            continue
        if code not in tested:
            untested.append(label)
    return untested


def get_completion_disclaimer(
    profile_name: str,
    categories: Optional[list] = None,
) -> Optional[str]:
    """
    Optional post-scan disclaimer for partial profiles.

    Returns:
        Disclaimer text, or None when not applicable.
    """
    if profile_name == "quick":
        spec = get_profile_spec("quick")
        tested = format_category_list(spec.categories or [])
        not_tested = format_category_list([
            "BL", "H", "I", "MA", "GEN",
        ])
        return (
            "Quick scan complete.\n"
            f" Tested: {tested}\n"
            f" Not tested: {not_tested}\n"
            " Run --profile standard for complete coverage."
        )

    if profile_name == "targeted" and categories:
        tested = format_category_list(categories)
        return (
            "Targeted scan complete.\n"
            f" Tested: {tested}\n"
            " Other vulnerability categories were not tested."
        )

    return None


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
    config.scan.payload_summary = spec.payload_summary
    config.scan.gen_enabled = spec.gen_enabled

    if profile_name == "targeted" and categories_override:
        config.scan.categories = categories_override
    elif spec.categories is not None:
        config.scan.categories = list(spec.categories)
    elif categories_override:
        config.scan.categories = categories_override

    return spec
