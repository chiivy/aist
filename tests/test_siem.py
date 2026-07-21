"""Tests for SIEM export (CEF and Splunk HEC)."""

import json
from pathlib import Path

import asyncio
import pytest

from aist.reporting.siem import (
    CEFExporter,
    SplunkHECExporter,
    export_siem,
)


def _sample_scan_result(
    findings: list | None = None,
) -> dict:
    return {
        "generated_at": "2026-07-21T10:30:00Z",
        "target": "https://agent.example.com/chat",
        "summary": {
            "overall_score": 8.5,
            "overall_rating": "Critical",
            "total_findings": len(findings or []),
            "by_severity": {
                "critical": 1 if findings else 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            },
            "canary_triggered": False,
        },
        "findings": findings or [],
    }


def _sample_finding(
    payload_id: str = "B1",
    category: str = "B",
) -> dict:
    return {
        "payload_id": payload_id,
        "payload_category": category,
        "severity": {
            "score": 9.0,
            "label": "Critical",
        },
        "confidence": {
            "needs_manual_review": False,
        },
        "llm_judge_success": True,
        "llm_judge_confidence": 95,
        "prompt_sent": "Ignore previous instructions",
        "response_received": "Sure, I will comply.",
        "canary_leaked": False,
        "compliance": {
            "owasp_llm": {
                "id": "LLM01:2025",
                "name": "Prompt Injection",
            },
            "mitre_atlas": [
                {
                    "id": "AML.T0051.000",
                    "name": "LLM Prompt Injection - Direct",
                }
            ],
        },
    }


def test_cef_format(tmp_path: Path) -> None:
    scan_result = _sample_scan_result(
        findings=[_sample_finding()]
    )
    output_path = tmp_path / "report.cef"

    CEFExporter().export(scan_result, str(output_path))
    line = output_path.read_text(encoding="utf-8")

    assert line.startswith("CEF:0|AIST|AI Security Tester|1.0|B1|")
    assert "|AI Security Finding: Critical|10|" in line
    assert "payloadId=B1" in line
    assert "category=B" in line
    assert "owasp=LLM01:2025" in line
    assert "target=https://agent.example.com/chat" in line


def test_splunk_json_structure(tmp_path: Path) -> None:
    scan_result = _sample_scan_result(
        findings=[_sample_finding()]
    )
    output_path = tmp_path / "report-splunk.json"

    SplunkHECExporter().export_to_file(
        scan_result, str(output_path)
    )

    lines = output_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2

    summary_event = json.loads(lines[0])
    finding_event = json.loads(lines[1])

    assert summary_event["sourcetype"] == "aist:scan"
    assert summary_event["event"]["event_type"] == "scan_summary"
    assert summary_event["event"]["overall_rating"] == "Critical"

    assert finding_event["sourcetype"] == "aist:finding"
    assert finding_event["event"]["event_type"] == "finding"
    assert finding_event["event"]["payload_id"] == "B1"
    assert finding_event["event"]["severity"] == "Critical"
    assert finding_event["event"]["owasp"] == "LLM01:2025"
    assert finding_event["event"]["mitre"] == ["AML.T0051.000"]


def test_empty_findings_produce_summary_only(
    tmp_path: Path,
) -> None:
    scan_result = _sample_scan_result(findings=[])
    output_path = tmp_path / "empty.cef"

    CEFExporter().export(scan_result, str(output_path))
    assert output_path.read_text(encoding="utf-8") == ""

    splunk_path = tmp_path / "empty-splunk.json"
    SplunkHECExporter().export_to_file(
        scan_result, str(splunk_path)
    )
    lines = splunk_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["event"]["total_findings"] == 0


def test_export_siem_writes_both_formats(
    tmp_path: Path,
) -> None:
    scan_result = _sample_scan_result(
        findings=[_sample_finding()]
    )

    outputs = export_siem(
        scan_result,
        str(tmp_path),
        formats=["cef", "splunk"],
    )

    assert "cef" in outputs
    assert "splunk" in outputs
    assert Path(outputs["cef"]).exists()
    assert Path(outputs["splunk"]).exists()


def test_push_to_splunk_requires_credentials() -> None:
    exporter = SplunkHECExporter()

    with pytest.raises(ValueError, match="SPLUNK_HEC_URL"):
        asyncio.run(
            exporter.push_to_splunk(_sample_scan_result())
        )


def test_export_siem_with_push_logs_push_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from aist.reporting.siem import export_siem_with_push

    async def failing_push(self, scan_result: dict) -> dict:
        raise RuntimeError("splunk unavailable")

    monkeypatch.setattr(
        SplunkHECExporter,
        "push_to_splunk",
        failing_push,
    )

    outputs = asyncio.run(
        export_siem_with_push(
            _sample_scan_result(findings=[_sample_finding()]),
            str(tmp_path),
            formats=["splunk"],
            splunk_url=(
                "https://splunk.example.com/services/collector"
            ),
            splunk_token="token",
        )
    )

    assert "splunk" in outputs
    assert "splunk_push" not in outputs


def test_push_to_splunk_http_error_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeResponse:
        def raise_for_status(self) -> None:
            raise RuntimeError("connection refused")

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, *args, **kwargs):
            return FakeResponse()

    monkeypatch.setattr(
        "aist.reporting.siem.httpx.AsyncClient",
        FakeClient,
    )

    exporter = SplunkHECExporter(
        hec_url="https://splunk.example.com/services/collector",
        hec_token="test-token",
    )

    with pytest.raises(RuntimeError, match="connection refused"):
        asyncio.run(
            exporter.push_to_splunk(
                _sample_scan_result(
                    findings=[_sample_finding()]
                )
            )
        )
