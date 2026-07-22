"""Tests for browser discovery findings in reports."""

from types import SimpleNamespace

from aist.auth.profile import (
    build_discovery_block,
    make_discovery_finding,
    merge_discovery_findings,
)
from aist.reporting.executive import discovery_executive_paragraph
from aist.reporting.json_report import generate_json_report


def _base_scan_evidence(**overrides):
    data = {
        "target": "https://app.example.com/chat",
        "total_payloads_sent": 1,
        "total_responses_received": 1,
        "canary_triggered": False,
        "errors": [],
        "evidence_items": [],
        "discovered_artifacts": {},
        "artifact_sources": {},
        "validation_results": {},
        "infrastructure_findings": [],
        "discovery": {},
    }
    data.update(overrides)
    return SimpleNamespace(**data)


def _base_config():
    return SimpleNamespace(
        scan=SimpleNamespace(
            expose_evidence=False,
            local_judge=False,
            local_judge_model="llama3.1:8b",
        ),
        target=SimpleNamespace(
            mode="active",
            tools=[],
            app_context="",
        ),
        llm=SimpleNamespace(enabled=False, model="none"),
        canary=SimpleNamespace(enabled=False),
    )


def test_build_discovery_block_from_observation() -> None:
    """Discovery findings are built from labels and JS secrets."""
    block = build_discovery_block(
        discovered_endpoints=["/api/chat", "/api/config"],
        endpoint_labels={
            "/api/config": {
                "severity": "Medium",
                "label": "Config endpoint exposed",
            }
        },
        js_files_scanned=3,
        js_secrets=["AWS key: AKIAIOSFODNN7EXAMPLE"],
        js_extra_endpoints=["API endpoint: /api/tools"],
    )
    assert block["stats"]["total_endpoints"] == 2
    assert block["stats"]["js_files_scanned"] == 3
    assert block["stats"]["findings_count"] == 3
    types = {item["type"] for item in block["findings"]}
    assert "endpoint_discovered" in types
    assert "js_secret" in types
    assert "js_endpoint" in types
    secret = next(
        item for item in block["findings"] if item["type"] == "js_secret"
    )
    assert "****" in secret["evidence"]


def test_merge_discovery_findings_updates_count() -> None:
    """Merging auth findings increments findings_count."""
    base = build_discovery_block(
        discovered_endpoints=["/api/chat"],
        endpoint_labels={},
        js_files_scanned=0,
    )
    merged = merge_discovery_findings(
        base,
        [
            make_discovery_finding(
                "endpoint_auth_issue",
                "Endpoint accessible without auth",
                "GET /api/config returned 200",
                "high",
                evidence="HTTP 200 with no auth",
            )
        ],
    )
    assert merged["stats"]["findings_count"] == 1
    assert merged["findings"][0]["type"] == "endpoint_auth_issue"


def _base_recon():
    return SimpleNamespace(
        target="https://app.example.com/chat",
        model_hint="",
        model_detected="",
        declared_tools=[],
        discovered_tools=[],
        discovery_evidence={},
        has_memory=False,
        system_prompt_exposed=False,
    )


def _base_discovery():
    return SimpleNamespace(
        discovered_tools=[],
        external_endpoints=[],
        connected_agents=[],
        rag_detected=False,
        ssrf_potential=False,
        severity_multiplier=1.0,
        discovered_agent_endpoints={},
    )


def test_json_report_includes_discovery_when_present() -> None:
    """JSON report includes discovery block when findings exist."""
    discovery = build_discovery_block(
        discovered_endpoints=["/api/chat", "/admin"],
        endpoint_labels={
            "/admin": {
                "severity": "High",
                "label": "Admin endpoint exposed",
            }
        },
        js_files_scanned=2,
        js_secrets=[],
    )
    evidence = _base_scan_evidence(discovery=discovery)
    report = generate_json_report(
        scan_evidence=evidence,
        recon_report=_base_recon(),
        discovery_result=_base_discovery(),
        severity_scores=[],
        confidence_scores=[],
        config=_base_config(),
    )
    assert "discovery" in report
    assert report["discovery"]["stats"]["findings_count"] == 1
    assert report["discovery"]["findings"][0]["type"] == (
        "endpoint_discovered"
    )


def test_json_report_omits_discovery_without_browser_data() -> None:
    """JSON report omits discovery when browser auth was not used."""
    evidence = _base_scan_evidence(discovery={})
    report = generate_json_report(
        scan_evidence=evidence,
        recon_report=_base_recon(),
        discovery_result=_base_discovery(),
        severity_scores=[],
        confidence_scores=[],
        config=_base_config(),
    )
    assert "discovery" not in report


def test_discovery_executive_paragraph() -> None:
    """Executive paragraph only appears when findings exist."""
    assert discovery_executive_paragraph({}) is None
    assert discovery_executive_paragraph(
        {"findings": [], "stats": {"findings_count": 0}}
    ) is None
    text = discovery_executive_paragraph(
        {
            "findings": [{"type": "js_secret"}],
            "stats": {
                "findings_count": 4,
                "total_endpoints": 12,
                "js_files_scanned": 3,
            },
        }
    )
    assert text is not None
    assert "4 security findings" in text
    assert "12 observed endpoints" in text
    assert "3 JavaScript files" in text
