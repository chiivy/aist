"""
AIST JSON Report Generator

Produces a machine-readable JSON report for
pipeline integration, SIEM ingestion, and
programmatic processing.

Mirrors the HTML report structure in a format
suitable for automated tooling and integration.
Reports are signed with a hash at generation.
"""

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from aist.logger import get_logger
from aist.compliance.mappings import (
    get_compliance_mapping,
    get_compliance_summary,
)
from aist.remediation.generic import get_generic_guidance
from aist.evidence.masking import mask_for_report
from aist.evidence.collector import is_genuine_finding

log = get_logger(__name__)


def generate_json_report(
    scan_evidence,
    recon_report,
    discovery_result,
    severity_scores: list,
    confidence_scores: list,
    config,
) -> dict:
    """
    Generate a complete JSON report from scan results.

    Args:
        scan_evidence:     All evidence from the scan
        recon_report:      Results from recon phase
        discovery_result:  Attack surface map
        severity_scores:   List of SeverityScore objects
        confidence_scores: List of ConfidenceScore objects
        config:            AIST configuration

    Returns:
        Complete report as a dictionary
    """
    log.info(
        "generating_json_report",
        target=scan_evidence.target,
        total_findings=len(severity_scores),
    )

    expose = config.scan.expose_evidence

    severity_map = {
        s.payload_id: s for s in severity_scores
    }
    confidence_map = {
        c.payload_id: c for c in confidence_scores
    }

    findings = _build_findings(
        scan_evidence,
        severity_map,
        confidence_map,
        expose,
    )

    summary = _build_summary(findings, scan_evidence)

    finding_categories = [
        f["payload_category"]
        for f in findings
    ]
    compliance_summary = get_compliance_summary(
        finding_categories
    )

    attack_surface = _build_attack_surface(
        recon_report,
        discovery_result,
    )

    infrastructure_findings = [
        {
            "payload_id": f.payload_id,
            "check_id": f.check_id,
            "name": f.name,
            "severity": f.severity,
            "description": f.description,
            "evidence": f.evidence,
            "recommendation": f.recommendation,
        }
        for f in (
            getattr(scan_evidence, "infrastructure_findings", [])
            or []
        )
    ]
    infra_counts = {
        "critical": 0, "high": 0, "medium": 0, "low": 0,
    }
    for f in infrastructure_findings:
        sev = f.get("severity", "medium").lower()
        if sev in infra_counts:
            infra_counts[sev] += 1
    infrastructure_summary = {
        "total": len(infrastructure_findings),
        **infra_counts,
    }

    report = {
        "aist_version": "1.0",
        "report_type": "full_scan",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "target": scan_evidence.target,
        "contains_sensitive_values": expose,
        "summary": summary,
        "attack_surface": attack_surface,
        "findings": findings,
        "infrastructure": {
            "summary": infrastructure_summary,
            "findings": infrastructure_findings,
        },
        "compliance_summary": compliance_summary,
        "scan_metadata": {
            "total_payloads_sent": (
                scan_evidence.total_payloads_sent
            ),
            "total_responses": (
                scan_evidence.total_responses_received
            ),
            "canary_triggered": scan_evidence.canary_triggered,
            "errors": scan_evidence.errors,
            "mode": config.target.mode,
            "tools_declared": config.target.tools,
            "llm_judge_enabled": config.llm.enabled,
            "canary_enabled": config.canary.enabled,
            "app_context": config.target.app_context or "",
            "app_context_source": getattr(
                scan_evidence, "app_context_source", ""
            ),
        },
        "report_hash": "PLACEHOLDER",
    }

    report_str = json.dumps(report, sort_keys=True)
    report_hash = hashlib.sha256(
        report_str.encode("utf-8")
    ).hexdigest()[:16]

    report["report_hash"] = report_hash

    log.info(
        "json_report_generated",
        hash=report_hash,
        findings_count=len(findings),
    )

    return report


def save_json_report(
    report: dict,
    output_path: str,
) -> str:
    """
    Save JSON report to file.

    Args:
        report:      Report dictionary
        output_path: File path to save to

    Returns:
        Absolute path of saved file
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    log.info(
        "json_report_saved",
        path=str(path.absolute()),
    )

    return str(path.absolute())


def _build_findings(
    scan_evidence,
    severity_map: dict,
    confidence_map: dict,
    expose: bool,
) -> list:
    """Build findings list for JSON report."""
    findings = []

    for evidence in scan_evidence.evidence_items:
        severity = severity_map.get(evidence.payload_id)
        confidence = confidence_map.get(evidence.payload_id)

        if not severity or not confidence:
            continue

        if not is_genuine_finding(evidence):
            continue

        if evidence.payload_category == "J":
            continue

        compliance = get_compliance_mapping(
            evidence.payload_category
        )
        generic = get_generic_guidance(
            evidence.payload_category
        )

        finding = {
            "payload_id": evidence.payload_id,
            "payload_category": evidence.payload_category,
            "severity": {
                "score": severity.final_score,
                "label": severity.severity_label,
                "cvss_vector": severity.cvss_vector,
                "breakdown": severity.score_breakdown,
                "tool_context": severity.tool_context,
            },
            "confidence": {
                "score": confidence.confidence_score,
                "label": confidence.confidence_label,
                "success_rate": confidence.success_rate,
                "needs_manual_review": (
                    confidence.needs_manual_review
                ),
                "total_runs": confidence.total_runs,
                "successful_runs": confidence.successful_runs,
            },
            "llm_judge_success": evidence.llm_judge_success,
            "llm_judge_confidence": evidence.llm_judge_confidence,
            "llm_judge_reasoning": evidence.llm_judge_reasoning,
            "llm_judge_partial": evidence.llm_judge_partial,
            "string_match_success": evidence.string_match_success,
            "string_matches_found": evidence.string_matches_found,
            "response_received": mask_for_report(
                evidence.response_received, expose
            ),
            "prompt_sent": mask_for_report(
                evidence.prompt_sent, expose
            ),
            "canary_leaked": evidence.canary_leaked,
            "credentials_detected": evidence.credentials_detected,
            "disclosure_depth": evidence.disclosure_depth,
            "sensitive_patterns": evidence.sensitive_patterns,
            "detection": {
                "canary_leaked": evidence.canary_leaked,
                "credentials_detected": (
                    evidence.credentials_detected
                ),
                "pii_detected": evidence.pii_detected,
                "system_prompt_detected": (
                    evidence.system_prompt_detected
                ),
                "tool_invocation_detected": (
                    evidence.tool_invocation_detected
                ),
                "write_action_confirmed": (
                    evidence.write_action_confirmed
                ),
                "token_smuggling_risk": (
                    evidence.token_smuggling_risk
                ),
                "sensitive_patterns": (
                    evidence.sensitive_patterns
                ),
                "string_match_success": (
                    evidence.string_match_success
                ),
                "string_matches": (
                    evidence.string_matches_found
                ),
                "llm_judge_success": (
                    evidence.llm_judge_success
                ),
                "llm_judge_confidence": (
                    evidence.llm_judge_confidence
                ),
                "llm_judge_reasoning": (
                    evidence.llm_judge_reasoning
                ),
                "llm_judge_partial": evidence.llm_judge_partial,
                "disclosure_depth": evidence.disclosure_depth,
            },
            "evidence": {
                "prompt_sent": mask_for_report(
                    evidence.prompt_sent, expose
                ),
                "response_received": mask_for_report(
                    evidence.response_received, expose
                ),
                "response_hash": evidence.response_hash,
                "was_streaming": evidence.was_streaming,
                "was_truncated": evidence.was_truncated,
                "response_size_kb": evidence.response_size_kb,
            },
            "compliance": {
                "owasp_llm": compliance.get("owasp_llm"),
                "owasp_agentic": compliance.get(
                    "owasp_agentic"
                ),
                "mitre_atlas": compliance.get("mitre_atlas"),
                "nist_ai_rmf": compliance.get("nist_ai_rmf"),
                "eu_ai_act": compliance.get("eu_ai_act"),
                "soc2": compliance.get("soc2"),
                "iso_27001": compliance.get("iso_27001"),
            },
            "remediation": {
                "summary": generic.get("summary"),
                "steps": generic.get("steps"),
                "owasp_control": generic.get(
                    "owasp_control"
                ),
                "atlas_mitigation": generic.get(
                    "atlas_mitigation"
                ),
                "references": generic.get("references"),
            },
        }

        findings.append(finding)

    findings.sort(
        key=lambda x: x["severity"]["score"],
        reverse=True,
    )

    return findings


def _build_summary(
    findings: list,
    scan_evidence,
) -> dict:
    """Build summary statistics for JSON report."""
    critical = sum(
        1 for f in findings
        if f["severity"]["label"] == "Critical"
    )
    high = sum(
        1 for f in findings
        if f["severity"]["label"] == "High"
    )
    medium = sum(
        1 for f in findings
        if f["severity"]["label"] == "Medium"
    )
    low = sum(
        1 for f in findings
        if f["severity"]["label"] == "Low"
    )

    overall_score = (
        max(f["severity"]["score"] for f in findings)
        if findings else 0
    )

    if critical > 0:
        overall_rating = "Critical"
    elif high > 0:
        overall_rating = "High"
    elif medium > 0:
        overall_rating = "Medium"
    elif low > 0:
        overall_rating = "Low"
    else:
        overall_rating = "No Findings"

    return {
        "overall_rating": overall_rating,
        "overall_score": overall_score,
        "total_findings": len(findings),
        "by_severity": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
        },
        "canary_triggered": scan_evidence.canary_triggered,
        "needs_immediate_action": (
            critical > 0 or
            scan_evidence.canary_triggered
        ),
    }


def _build_attack_surface(
    recon_report,
    discovery_result,
) -> dict:
    """Build attack surface data for JSON report."""
    if not recon_report:
        return {}

    return {
        "target": recon_report.target,
        "model_detected": (
            getattr(recon_report, "model_detected", "")
            or recon_report.model_hint
        ),
        "declared_tools": recon_report.declared_tools,
        "discovered_tools": getattr(
            discovery_result,
            "discovered_tools",
            recon_report.discovered_tools,
        ),
        "has_memory": recon_report.has_memory,
        "system_prompt_exposed": (
            recon_report.system_prompt_exposed
        ),
        "external_endpoints": getattr(
            discovery_result, "external_endpoints", []
        ),
        "connected_agents": getattr(
            discovery_result, "connected_agents", []
        ),
        "rag_detected": getattr(
            discovery_result, "rag_detected", False
        ),
        "ssrf_potential": getattr(
            discovery_result, "ssrf_potential", False
        ),
        "severity_multiplier": getattr(
            discovery_result, "severity_multiplier", 1.0
        ),
        "auth_mechanism": getattr(
            discovery_result, "auth_mechanism", "unknown"
        ),
        "session_type": getattr(
            discovery_result, "session_type", "unknown"
        ),
    }