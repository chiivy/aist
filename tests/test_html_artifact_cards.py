"""Smoke test: HTML report renders artifact cards without TypeError."""
from types import SimpleNamespace
from datetime import datetime, timezone

from aist.reporting.html import generate_html_report


def test_html_report_with_artifact_cards() -> None:
    scan_evidence = SimpleNamespace(
        target="http://localhost:5000/chat",
        total_payloads_sent=1,
        total_responses_received=1,
        canary_triggered=False,
        errors=[],
        evidence_items=[],
        discovered_artifacts={
            "endpoints": ["http://example.com"],
        },
        artifact_sources={"http://example.com": "D1"},
        validation_results={},
        infrastructure_findings=[],
    )
    config = SimpleNamespace(
        scan=SimpleNamespace(
            expose_evidence=False,
            operator="test",
            organisation="test-org",
        ),
    )
    html = generate_html_report(
        scan_evidence=scan_evidence,
        recon_report=None,
        discovery_result=None,
        severity_scores=[],
        confidence_scores=[],
        config=config,
        scan_started_at=datetime.now(timezone.utc),
        scan_completed_at=datetime.now(timezone.utc),
    )
    assert "http://example.com" in html
    assert "artifact-card" in html
