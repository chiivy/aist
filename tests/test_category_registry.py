"""Tests for payload category routing and registry."""

import asyncio
from unittest.mock import patch

import pytest

from aist.compliance.mappings import get_compliance_mapping
from aist.config import AISTConfig
from aist.remediation.generic import get_generic_guidance
from aist.scanner.category_registry import (
    REGISTERED_CATEGORY_SCANNERS,
    filter_direct_categories,
    get_scanner_for_category,
    scanner_registry_summary,
    should_run_direct_scanner,
)
from aist.scanner.direct import run_direct_scanner


HANDLED_CATEGORIES = [
    "B", "C", "D", "E", "H", "I", "S", "J", "MA", "GEN", "INDIRECT", "G",
]


@pytest.mark.parametrize("category", HANDLED_CATEGORIES)
def test_all_handled_categories_have_scanner(category: str) -> None:
    """Each standard category maps to an orchestrator scanner."""
    assert get_scanner_for_category(category) is not None


@pytest.mark.parametrize("category", HANDLED_CATEGORIES)
def test_direct_scanner_no_unknown_category_warning(
    category: str,
) -> None:
    """Specialized categories must not trigger unknown_category."""
    config = AISTConfig()
    config.target.endpoint = "http://localhost:5000/chat"

    with patch(
        "aist.scanner.direct.load_payload_file",
        return_value={"payloads": []},
    ), patch("aist.scanner.direct.log") as log_mock:
        asyncio.run(
            run_direct_scanner(
                config,
                categories=[category],
            )
        )

    unknown_calls = [
        call
        for call in log_mock.warning.call_args_list
        if call.args and call.args[0] == "unknown_category"
    ]
    assert unknown_calls == []


def test_direct_scanner_empty_categories_skips_without_fallback() -> None:
    """Empty category list must not fall back to all direct payloads."""
    config = AISTConfig()
    config.target.endpoint = "http://localhost:5000/chat"

    with patch(
        "aist.scanner.direct.load_payload_file",
    ) as load_mock:
        evidence, results = asyncio.run(
            run_direct_scanner(config, categories=[])
        )

    load_mock.assert_not_called()
    assert evidence == []
    assert results == {}


def test_filter_direct_categories_respects_safe_mode() -> None:
    """Safe mode excludes category E from direct routing."""
    filtered = filter_direct_categories(
        ["A", "E", "G", "H"],
        safe_mode=True,
    )
    assert filtered == ["A"]
    assert "E" not in filtered
    assert "G" not in filtered


def test_should_run_direct_scanner_only_for_direct_codes() -> None:
    """Direct scanner runs only when direct categories are requested."""
    assert should_run_direct_scanner(["G", "H", "I"]) is False
    assert should_run_direct_scanner(["B", "G"]) is True
    assert should_run_direct_scanner(None) is True


def test_indirect_and_i_map_to_indirect_scanner() -> None:
    """Categories I and INDIRECT route to the indirect scanner."""
    assert get_scanner_for_category("I") == "indirect"
    assert get_scanner_for_category("INDIRECT") == "indirect"


def test_scanner_registry_summary_lists_missing() -> None:
    """Startup summary lists categories with no registered scanner."""
    registered_line, missing = scanner_registry_summary(
        ["B", "H", "UNKNOWN"],
    )
    assert "Registered scanners:" in registered_line
    assert "B" in registered_line
    assert missing == ["UNKNOWN"]


@pytest.mark.parametrize("category", ["GEN"])
def test_gen_compliance_mapping_no_warning(category: str) -> None:
    """GEN category has compliance mappings without warnings."""
    with patch("aist.compliance.mappings.log") as log_mock:
        mapping = get_compliance_mapping(category)

    assert mapping.get("owasp_llm", {}).get("id") == "LLM01:2025"
    assert mapping.get("owasp_agentic", {}).get("id") == "AGEN01:2025"
    compliance_warnings = [
        call
        for call in log_mock.warning.call_args_list
        if call.args and call.args[0] == "no_compliance_mapping"
    ]
    assert compliance_warnings == []


@pytest.mark.parametrize("category", ["GEN"])
def test_gen_generic_guidance_no_warning(category: str) -> None:
    """GEN category has generic remediation guidance."""
    with patch("aist.remediation.generic.log") as log_mock:
        guidance = get_generic_guidance(category)

    assert "Context-aware attacks" in guidance["summary"]
    guidance_warnings = [
        call
        for call in log_mock.warning.call_args_list
        if call.args and call.args[0] == "no_generic_guidance"
    ]
    assert guidance_warnings == []


def test_registered_categories_cover_standard_scan_set() -> None:
    """Registry includes all categories from the user fix list."""
    for category in HANDLED_CATEGORIES:
        assert category in REGISTERED_CATEGORY_SCANNERS
