"""
Category-to-scanner routing registry for AIST.

Single source of truth for which payload category
codes are handled by which scanner module.
"""

from typing import Optional

# Categories loaded from YAML by the direct injection scanner.
DIRECT_CATEGORIES: frozenset[str] = frozenset({
    "A", "B", "C", "D", "E", "F", "BL",
})

# Maps payload category code -> orchestrator scanner task name.
REGISTERED_CATEGORY_SCANNERS: dict[str, str] = {
    "A": "direct",
    "B": "direct",
    "C": "direct",
    "D": "direct",
    "E": "direct",
    "F": "direct",
    "BL": "direct",
    "G": "guardrail",
    "H": "toolparam",
    "I": "indirect",
    "INDIRECT": "indirect",
    "S": "multiturn",
    "J": "infrastructure",
    "MA": "multiagent",
    "GEN": "generated",
}

# Category I output-manipulation YAML runs via the output scanner
# task even though profile routing treats I as indirect injection.
OUTPUT_CATEGORY = "I"


def is_registered_category(category: str) -> bool:
    """Return True when a category has a registered scanner."""
    return category.upper() in REGISTERED_CATEGORY_SCANNERS


def get_scanner_for_category(category: str) -> Optional[str]:
    """Return orchestrator scanner task name for a category."""
    return REGISTERED_CATEGORY_SCANNERS.get(category.upper())


def filter_direct_categories(
    categories: Optional[list],
    safe_mode: bool = False,
) -> list[str]:
    """
    Return direct-scanner category codes from a request list.

    Args:
        categories: Requested categories, or None for all direct.
        safe_mode:  When True, exclude category E.

    Returns:
        List of category codes for run_direct_scanner.
    """
    direct = sorted(DIRECT_CATEGORIES)
    if safe_mode:
        direct = [c for c in direct if c != "E"]

    if categories is None:
        return direct

    return [
        c for c in categories
        if c in DIRECT_CATEGORIES and c in direct
    ]


def should_run_direct_scanner(
    categories: Optional[list],
) -> bool:
    """Return True when the direct scanner should execute."""
    if not categories:
        return True
    return any(c in DIRECT_CATEGORIES for c in categories)


def scanner_registry_summary(
    requested_categories: Optional[list] = None,
) -> tuple[str, list[str]]:
    """
    Build console lines for registered vs missing categories.

    Returns:
        (registered_line, missing_category_codes)
    """
    registered = sorted(REGISTERED_CATEGORY_SCANNERS.keys())
    registered_line = (
        f"Registered scanners: {', '.join(registered)}"
    )

    missing: list[str] = []
    if requested_categories:
        missing = sorted([
            c for c in requested_categories
            if not is_registered_category(c)
        ])

    return registered_line, missing
