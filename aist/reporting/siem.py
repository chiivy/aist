"""
SIEM export formats for AIST scan results.

Supports CEF (ArcSight, QRadar, etc.) and Splunk HEC.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

import httpx

from aist.logger import get_logger

log = get_logger(__name__)


class CEFExporter:
    """
    Common Event Format (CEF) exporter.
    Used by ArcSight, QRadar, and most SIEMs.
    One CEF event per finding.
    """

    CEF_VERSION = "CEF:0"
    VENDOR = "AIST"
    PRODUCT = "AI Security Tester"
    VERSION = "1.0"

    SEVERITY_MAP = {
        "Critical": 10,
        "High": 7,
        "Medium": 5,
        "Low": 3,
    }

    def export(
        self,
        scan_result: dict,
        output_path: str,
    ) -> str:
        """
        Write CEF events to file.
        Returns path to written file.
        """
        lines = []
        target = scan_result.get("target", "unknown")
        scan_date = scan_result.get("generated_at", "")

        for finding in scan_result.get("findings", []):
            line = self._finding_to_cef(
                finding, target, scan_date
            )
            lines.append(line)

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines), encoding="utf-8")
        return str(path)

    def _finding_to_cef(
        self,
        finding: dict,
        target: str,
        scan_date: str,
    ) -> str:
        severity_label = (
            finding.get("severity", {}).get("label")
            or "Unknown"
        )
        cef_severity = self.SEVERITY_MAP.get(
            severity_label, 5
        )

        payload_id = finding.get("payload_id", "")
        category = finding.get("payload_category", "")
        score = finding.get("severity", {}).get("score", 0)
        confidence = finding.get("llm_judge_confidence") or 0
        owasp = (
            finding.get("compliance", {})
            .get("owasp_llm", {})
            .get("id", "")
        )

        ext = (
            f"target={target} "
            f"payloadId={payload_id} "
            f"category={category} "
            f"riskScore={score} "
            f"confidence={confidence} "
            f"owasp={owasp} "
            f"scanDate={scan_date}"
        )

        return (
            f"{self.CEF_VERSION}"
            f"|{self.VENDOR}"
            f"|{self.PRODUCT}"
            f"|{self.VERSION}"
            f"|{payload_id}"
            f"|AI Security Finding: {severity_label}"
            f"|{cef_severity}"
            f"|{ext}"
        )


class SplunkHECExporter:
    """
    Splunk HTTP Event Collector exporter.
    Two modes:
    1. File export: JSON file for manual upload
    2. Direct push: POST to Splunk HEC endpoint
    """

    def __init__(
        self,
        hec_url: Optional[str] = None,
        hec_token: Optional[str] = None,
    ) -> None:
        self.hec_url = hec_url
        self.hec_token = hec_token

    def export_to_file(
        self,
        scan_result: dict,
        output_path: str,
    ) -> str:
        """
        Write Splunk HEC JSON to file.
        File can be uploaded manually or via Splunk forwarder.
        """
        events = self._build_events(scan_result)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with path.open("w", encoding="utf-8") as handle:
            for event in events:
                handle.write(json.dumps(event) + "\n")

        return str(path)

    async def push_to_splunk(
        self,
        scan_result: dict,
    ) -> dict:
        """
        POST events directly to Splunk HEC.
        Requires hec_url and hec_token.
        Returns {"success": bool, "events_sent": int, ...}
        """
        if not self.hec_url or not self.hec_token:
            raise ValueError(
                "SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN "
                "required for direct push. "
                "Set in .env or use export_to_file()."
            )

        events = self._build_events(scan_result)
        headers = {
            "Authorization": f"Splunk {self.hec_token}",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient() as client:
            for event in events:
                response = await client.post(
                    self.hec_url,
                    json=event,
                    headers=headers,
                    timeout=10,
                )
                response.raise_for_status()

        return {
            "success": True,
            "events_sent": len(events),
            "endpoint": self.hec_url,
        }

    def _build_events(self, scan_result: dict) -> list[dict]:
        target = scan_result.get("target", "")
        scan_date = scan_result.get("generated_at", "")
        summary = scan_result.get("summary", {})

        events = [
            {
                "time": scan_date,
                "source": "aist",
                "sourcetype": "aist:scan",
                "index": "ai_security",
                "event": {
                    "event_type": "scan_summary",
                    "target": target,
                    "overall_score": summary.get(
                        "overall_score"
                    ),
                    "overall_rating": summary.get(
                        "overall_rating"
                    ),
                    "critical": summary.get(
                        "by_severity", {}
                    ).get("critical", 0),
                    "high": summary.get(
                        "by_severity", {}
                    ).get("high", 0),
                    "medium": summary.get(
                        "by_severity", {}
                    ).get("medium", 0),
                    "low": summary.get(
                        "by_severity", {}
                    ).get("low", 0),
                    "total_findings": summary.get(
                        "total_findings", 0
                    ),
                    "canary_triggered": summary.get(
                        "canary_triggered", False
                    ),
                },
            }
        ]

        for finding in scan_result.get("findings", []):
            severity = finding.get("severity", {})
            compliance = finding.get("compliance", {})

            events.append({
                "time": scan_date,
                "source": "aist",
                "sourcetype": "aist:finding",
                "index": "ai_security",
                "event": {
                    "event_type": "finding",
                    "target": target,
                    "payload_id": finding.get("payload_id"),
                    "category": finding.get("payload_category"),
                    "severity": severity.get("label"),
                    "score": severity.get("score"),
                    "confidence": finding.get(
                        "llm_judge_confidence"
                    ),
                    "validated": finding.get(
                        "llm_judge_success"
                    ),
                    "canary_triggered": finding.get(
                        "canary_leaked", False
                    ),
                    "owasp": (
                        compliance.get("owasp_llm", {})
                        .get("id", "")
                    ),
                    "mitre": [
                        technique.get("id")
                        for technique in compliance.get(
                            "mitre_atlas", []
                        )
                        if technique.get("id")
                    ],
                    "payload_preview": finding.get(
                        "prompt_sent", ""
                    )[:200],
                    "response_preview": finding.get(
                        "response_received", ""
                    )[:200],
                    "needs_manual_review": finding.get(
                        "confidence", {}
                    ).get("needs_manual_review", False),
                },
            })

        return events


def _safe_target_slug(scan_result: dict) -> str:
    return (
        scan_result.get("target", "scan")
        .replace("://", "-")
        .replace("/", "-")
        .replace(":", "-")
    )


def export_siem(
    scan_result: dict,
    output_dir: str,
    formats: Optional[list[str]] = None,
    splunk_url: Optional[str] = None,
    splunk_token: Optional[str] = None,
) -> dict:
    """
    Export scan results to SIEM formats.
    formats: list of "cef", "splunk"
    Returns dict of format -> output path.
    """
    if formats is None:
        formats = ["cef", "splunk"]

    outputs: dict[str, str] = {}
    target_safe = _safe_target_slug(scan_result)
    timestamp = scan_result.get("generated_at", "")[:10]

    if "cef" in formats:
        cef_path = os.path.join(
            output_dir,
            f"aist-{timestamp}-{target_safe}.cef",
        )
        CEFExporter().export(scan_result, cef_path)
        outputs["cef"] = cef_path

    if "splunk" in formats:
        splunk_path = os.path.join(
            output_dir,
            f"aist-{timestamp}-{target_safe}-splunk.json",
        )
        exporter = SplunkHECExporter(
            splunk_url, splunk_token
        )
        exporter.export_to_file(scan_result, splunk_path)
        outputs["splunk"] = splunk_path

    return outputs


async def export_siem_with_push(
    scan_result: dict,
    output_dir: str,
    formats: Optional[list[str]] = None,
    splunk_url: Optional[str] = None,
    splunk_token: Optional[str] = None,
) -> dict:
    """
    Export SIEM files and optionally push to Splunk HEC.

    Splunk push failures are logged but do not raise.
    """
    outputs = export_siem(
        scan_result=scan_result,
        output_dir=output_dir,
        formats=formats,
        splunk_url=splunk_url,
        splunk_token=splunk_token,
    )

    if (
        splunk_url
        and splunk_token
        and formats
        and "splunk" in formats
    ):
        exporter = SplunkHECExporter(
            splunk_url, splunk_token
        )
        try:
            push_result = await exporter.push_to_splunk(
                scan_result
            )
            outputs["splunk_push"] = push_result
            log.info(
                "splunk_hec_push_complete",
                events_sent=push_result["events_sent"],
                endpoint=splunk_url,
            )
        except Exception as exc:
            log.warning(
                "splunk_hec_push_failed",
                error=str(exc),
                error_type=type(exc).__name__,
            )

    return outputs
