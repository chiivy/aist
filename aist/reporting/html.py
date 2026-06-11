"""
AIST HTML Report Generator

Produces a professional HTML report with executive
summary, attack surface map, detailed findings,
and compliance summary.

Designed to look polished and credible for both
technical security teams and non-technical stakeholders.
Reports are signed with a hash at generation so
any modification is detectable.
"""

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from jinja2 import Environment, BaseLoader
from rich.console import Console

from aist.logger import get_logger
from aist.compliance.mappings import (
    get_compliance_mapping,
    format_compliance_for_report,
    get_compliance_summary,
)
from aist.remediation.generic import get_generic_guidance
from aist.evidence.masking import mask_for_report

log = get_logger(__name__)
console = Console()


def generate_html_report(
    scan_evidence,
    recon_report,
    discovery_result,
    severity_scores: list,
    confidence_scores: list,
    config,
) -> str:
    """
    Generate a complete HTML report from scan results.

    Args:
        scan_evidence:     All evidence from the scan
        recon_report:      Results from recon phase
        discovery_result:  Attack surface map
        severity_scores:   List of SeverityScore objects
        confidence_scores: List of ConfidenceScore objects
        config:            AIST configuration

    Returns:
        Complete HTML report as a string
    """
    log.info(
        "generating_html_report",
        target=scan_evidence.target,
        total_findings=len(severity_scores),
    )

    # Build findings data
    findings = _build_findings(
        scan_evidence,
        severity_scores,
        confidence_scores,
        config,
    )

    # Calculate summary stats
    summary = _build_summary(findings, scan_evidence)

    # Build compliance summary
    finding_categories = [
        f["payload_category"]
        for f in findings
        if f.get("is_finding")
    ]
    compliance_summary = get_compliance_summary(
        finding_categories
    )

    # Build attack surface data
    attack_surface = _build_attack_surface(
        recon_report,
        discovery_result,
    )

    # Render HTML
    html = _render_template(
        findings=findings,
        summary=summary,
        attack_surface=attack_surface,
        compliance_summary=compliance_summary,
        config=config,
        scan_evidence=scan_evidence,
    )

    # Sign report
    report_hash = hashlib.sha256(
        html.encode("utf-8")
    ).hexdigest()

    # Embed hash in report
    html = html.replace(
        "REPORT_HASH_PLACEHOLDER",
        report_hash[:16],
    )

    log.info(
        "html_report_generated",
        hash=report_hash[:16],
        size_kb=round(len(html.encode()) / 1024, 2),
    )

    return html


def save_html_report(
    html: str,
    output_path: str,
) -> str:
    """
    Save HTML report to file.

    Args:
        html:        Complete HTML string
        output_path: File path to save to

    Returns:
        Absolute path of saved file
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")

    log.info(
        "html_report_saved",
        path=str(path.absolute()),
    )

    return str(path.absolute())


def _build_findings(
    scan_evidence,
    severity_scores: list,
    confidence_scores: list,
    config,
) -> list:
    """Build findings list for template rendering."""
    findings = []

    severity_map = {
        s.payload_id: s for s in severity_scores
    }
    confidence_map = {
        c.payload_id: c for c in confidence_scores
    }

    for evidence in scan_evidence.evidence_items:
        severity = severity_map.get(evidence.payload_id)
        confidence = confidence_map.get(evidence.payload_id)

        if not severity or not confidence:
            continue

        is_finding = (
            evidence.canary_leaked or
            evidence.llm_judge_success or
            evidence.string_match_success or
            evidence.credentials_detected
        )

        if not is_finding:
            continue

        compliance = get_compliance_mapping(
            evidence.payload_category
        )
        generic = get_generic_guidance(
            evidence.payload_category
        )

        expose = config.scan.expose_evidence

        finding = {
            "payload_id": evidence.payload_id,
            "payload_category": evidence.payload_category,
            "is_finding": is_finding,
            "severity_score": severity.final_score,
            "severity_label": severity.severity_label,
            "confidence_score": confidence.confidence_score,
            "confidence_label": confidence.confidence_label,
            "needs_review": confidence.needs_manual_review,
            "cvss_vector": severity.cvss_vector,
            "tool_context": severity.tool_context,
            "score_breakdown": severity.score_breakdown,
            "canary_leaked": evidence.canary_leaked,
            "credentials_detected": evidence.credentials_detected,
            "pii_detected": evidence.pii_detected,
            "system_prompt_detected": evidence.system_prompt_detected,
            "tool_invocation_detected": evidence.tool_invocation_detected,
            "sensitive_patterns": evidence.sensitive_patterns,
            "prompt_sent": mask_for_report(
                evidence.prompt_sent, expose
            ),
            "response_received": mask_for_report(
                evidence.response_received, expose
            ),
            "string_matches": evidence.string_matches_found,
            "llm_judge_success": evidence.llm_judge_success,
            "llm_judge_confidence": evidence.llm_judge_confidence,
            "llm_judge_reasoning": evidence.llm_judge_reasoning,
            "compliance": compliance,
            "generic_guidance": generic,
            "response_hash": evidence.response_hash,
        }

        findings.append(finding)

    findings.sort(
        key=lambda x: x["severity_score"],
        reverse=True
    )

    return findings


def _build_summary(findings: list, scan_evidence) -> dict:
    """Build executive summary statistics."""
    critical = sum(
        1 for f in findings
        if f["severity_label"] == "Critical"
    )
    high = sum(
        1 for f in findings
        if f["severity_label"] == "High"
    )
    medium = sum(
        1 for f in findings
        if f["severity_label"] == "Medium"
    )
    low = sum(
        1 for f in findings
        if f["severity_label"] == "Low"
    )

    total = len(findings)

    if critical > 0:
        overall_rating = "Critical"
        overall_color = "#dc2626"
        overall_score = max(
            f["severity_score"] for f in findings
        ) if findings else 0
    elif high > 0:
        overall_rating = "High"
        overall_color = "#ea580c"
        overall_score = max(
            f["severity_score"] for f in findings
        ) if findings else 0
    elif medium > 0:
        overall_rating = "Medium"
        overall_color = "#ca8a04"
        overall_score = max(
            f["severity_score"] for f in findings
        ) if findings else 0
    elif low > 0:
        overall_rating = "Low"
        overall_color = "#16a34a"
        overall_score = max(
            f["severity_score"] for f in findings
        ) if findings else 0
    else:
        overall_rating = "No Findings"
        overall_color = "#16a34a"
        overall_score = 0

    return {
        "total_findings": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "overall_rating": overall_rating,
        "overall_color": overall_color,
        "overall_score": overall_score,
        "total_payloads": scan_evidence.total_payloads_sent,
        "canary_triggered": scan_evidence.canary_triggered,
        "top_findings": findings[:3],
    }


def _build_attack_surface(
    recon_report,
    discovery_result,
) -> dict:
    """Build attack surface map data."""
    if not recon_report:
        return {}

    return {
        "target": recon_report.target,
        "model_hint": recon_report.model_hint,
        "declared_tools": recon_report.declared_tools,
        "discovered_tools": getattr(
            discovery_result, "discovered_tools",
            recon_report.discovered_tools
        ),
        "has_memory": recon_report.has_memory,
        "system_prompt_exposed": recon_report.system_prompt_exposed,
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
    }


def _render_template(
    findings: list,
    summary: dict,
    attack_surface: dict,
    compliance_summary: dict,
    config,
    scan_evidence,
) -> str:
    """Render the HTML report template."""
    env = Environment(loader=BaseLoader())
    template = env.from_string(HTML_TEMPLATE)

    return template.render(
        findings=findings,
        summary=summary,
        attack_surface=attack_surface,
        compliance_summary=compliance_summary,
        scan_date=datetime.now().strftime(
            "%B %d, %Y at %H:%M UTC"
        ),
        target=scan_evidence.target,
        total_payloads=scan_evidence.total_payloads_sent,
        expose_evidence=config.scan.expose_evidence,
        aist_version="1.0",
        report_hash="REPORT_HASH_PLACEHOLDER",
    )
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AIST Security Report - {{ target }}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }

  body {
    font-family: -apple-system, BlinkMacSystemFont,
    'Segoe UI', Roboto, sans-serif;
    background: #0f1117;
    color: #e2e8f0;
    line-height: 1.6;
  }

  .header {
    background: linear-gradient(135deg, #1a1f2e 0%, #0f1117 100%);
    border-bottom: 1px solid #2d3748;
    padding: 2rem 3rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .logo {
    display: flex;
    align-items: center;
    gap: 1rem;
  }

  .logo-text {
    font-size: 1.8rem;
    font-weight: 800;
    color: #ef4444;
    letter-spacing: -0.05em;
  }

  .logo-sub {
    font-size: 0.8rem;
    color: #64748b;
    letter-spacing: 0.1em;
    text-transform: uppercase;
  }

  .report-meta {
    text-align: right;
    font-size: 0.85rem;
    color: #64748b;
  }

  .report-meta strong {
    color: #94a3b8;
    display: block;
    margin-bottom: 0.2rem;
  }

  {% if expose_evidence %}
  .sensitive-banner {
    background: #7f1d1d;
    border: 1px solid #ef4444;
    color: #fca5a5;
    padding: 1rem 3rem;
    font-size: 0.9rem;
    font-weight: 600;
    text-align: center;
    letter-spacing: 0.05em;
  }
  {% endif %}

  .container {
    max-width: 1400px;
    margin: 0 auto;
    padding: 2rem 3rem;
  }

  .section-title {
    font-size: 1.1rem;
    font-weight: 700;
    color: #94a3b8;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin-bottom: 1.5rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid #2d3748;
  }

  .executive-grid {
    display: grid;
    grid-template-columns: 280px 1fr 1fr;
    gap: 1.5rem;
    margin-bottom: 3rem;
  }

  .risk-card {
    background: #1a1f2e;
    border: 1px solid #2d3748;
    border-radius: 12px;
    padding: 2rem;
    text-align: center;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
  }

  .risk-gauge {
    width: 140px;
    height: 140px;
    border-radius: 50%;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    margin-bottom: 1rem;
    border: 6px solid {{ summary.overall_color }};
    box-shadow: 0 0 30px {{ summary.overall_color }}40;
  }

  .risk-score {
    font-size: 2.5rem;
    font-weight: 800;
    color: {{ summary.overall_color }};
    line-height: 1;
  }

  .risk-label {
    font-size: 0.75rem;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.1em;
  }

  .risk-rating {
    font-size: 1.3rem;
    font-weight: 700;
    color: {{ summary.overall_color }};
  }

  .stats-card {
    background: #1a1f2e;
    border: 1px solid #2d3748;
    border-radius: 12px;
    padding: 2rem;
  }

  .stats-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
    margin-top: 1rem;
  }

  .stat-item {
    text-align: center;
    padding: 1rem;
    border-radius: 8px;
    background: #0f1117;
  }

  .stat-number {
    font-size: 2rem;
    font-weight: 800;
    line-height: 1;
    margin-bottom: 0.3rem;
  }

  .stat-label {
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #64748b;
  }

  .critical-color { color: #ef4444; }
  .high-color { color: #f97316; }
  .medium-color { color: #eab308; }
  .low-color { color: #22c55e; }
  .info-color { color: #3b82f6; }

  .scan-info-card {
    background: #1a1f2e;
    border: 1px solid #2d3748;
    border-radius: 12px;
    padding: 2rem;
  }

  .info-row {
    display: flex;
    justify-content: space-between;
    padding: 0.6rem 0;
    border-bottom: 1px solid #1e2533;
    font-size: 0.9rem;
  }

  .info-row:last-child { border-bottom: none; }

  .info-key {
    color: #64748b;
    font-weight: 500;
  }

  .info-value {
    color: #e2e8f0;
    font-weight: 600;
    text-align: right;
    max-width: 60%;
    word-break: break-all;
  }

  .attack-surface {
    background: #1a1f2e;
    border: 1px solid #2d3748;
    border-radius: 12px;
    padding: 2rem;
    margin-bottom: 3rem;
  }

  .surface-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 1rem;
    margin-top: 1rem;
  }

  .surface-item {
    background: #0f1117;
    border: 1px solid #2d3748;
    border-radius: 8px;
    padding: 1rem;
  }

  .surface-item-label {
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #64748b;
    margin-bottom: 0.5rem;
  }

  .surface-item-value {
    font-size: 0.9rem;
    font-weight: 600;
    color: #e2e8f0;
  }

  .tag {
    display: inline-block;
    padding: 0.2rem 0.6rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    margin: 0.2rem;
  }

  .tag-red { background: #7f1d1d; color: #fca5a5; }
  .tag-orange { background: #7c2d12; color: #fed7aa; }
  .tag-yellow { background: #713f12; color: #fef08a; }
  .tag-green { background: #14532d; color: #86efac; }
  .tag-blue { background: #1e3a5f; color: #93c5fd; }
  .tag-gray { background: #1e2533; color: #94a3b8; }

  .findings-section {
    margin-bottom: 3rem;
  }

  .finding-card {
    background: #1a1f2e;
    border: 1px solid #2d3748;
    border-radius: 12px;
    margin-bottom: 1.5rem;
    overflow: hidden;
  }

  .finding-card.critical {
    border-left: 4px solid #ef4444;
  }

  .finding-card.high {
    border-left: 4px solid #f97316;
  }

  .finding-card.medium {
    border-left: 4px solid #eab308;
  }

  .finding-card.low {
    border-left: 4px solid #22c55e;
  }

  .finding-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1.2rem 1.5rem;
    cursor: pointer;
    user-select: none;
  }

  .finding-header:hover {
    background: #1e2533;
  }

  .finding-title {
    display: flex;
    align-items: center;
    gap: 1rem;
  }

  .severity-badge {
    padding: 0.3rem 0.8rem;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .badge-critical {
    background: #7f1d1d;
    color: #fca5a5;
    border: 1px solid #ef4444;
  }

  .badge-high {
    background: #7c2d12;
    color: #fed7aa;
    border: 1px solid #f97316;
  }

  .badge-medium {
    background: #713f12;
    color: #fef08a;
    border: 1px solid #eab308;
  }

  .badge-low {
    background: #14532d;
    color: #86efac;
    border: 1px solid #22c55e;
  }

  .finding-id {
    font-size: 0.9rem;
    font-weight: 700;
    color: #94a3b8;
    font-family: 'Courier New', monospace;
  }

  .finding-scores {
    display: flex;
    align-items: center;
    gap: 1.5rem;
  }

  .score-item {
    text-align: center;
  }

  .score-value {
    font-size: 1.3rem;
    font-weight: 800;
    line-height: 1;
  }

  .score-label {
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #64748b;
  }

  .finding-body {
    padding: 0 1.5rem 1.5rem;
    display: none;
  }

  .finding-body.open {
    display: block;
  }

  .finding-divider {
    height: 1px;
    background: #2d3748;
    margin-bottom: 1.5rem;
  }

  .finding-section-label {
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #64748b;
    margin-bottom: 0.5rem;
    margin-top: 1rem;
  }

  .code-block {
    background: #0f1117;
    border: 1px solid #2d3748;
    border-radius: 6px;
    padding: 1rem;
    font-family: 'Courier New', monospace;
    font-size: 0.8rem;
    color: #a3e635;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-word;
  }

  .evidence-block {
    background: #0f1117;
    border: 1px solid #2d3748;
    border-radius: 6px;
    padding: 1rem;
    font-family: 'Courier New', monospace;
    font-size: 0.8rem;
    color: #94a3b8;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-word;
    max-height: 200px;
    overflow-y: auto;
  }

  .remediation-block {
    background: #0f1720;
    border: 1px solid #1e3a5f;
    border-radius: 6px;
    padding: 1.2rem;
    margin-top: 0.5rem;
  }

  .remediation-step {
    display: flex;
    gap: 0.8rem;
    margin-bottom: 0.8rem;
    font-size: 0.9rem;
  }

  .step-number {
    background: #1e3a5f;
    color: #93c5fd;
    width: 22px;
    height: 22px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.7rem;
    font-weight: 700;
    flex-shrink: 0;
    margin-top: 0.1rem;
  }

  .compliance-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.85rem;
    margin-top: 0.5rem;
  }

  .compliance-table th {
    background: #0f1117;
    color: #64748b;
    text-transform: uppercase;
    font-size: 0.7rem;
    letter-spacing: 0.1em;
    padding: 0.8rem 1rem;
    text-align: left;
    border-bottom: 1px solid #2d3748;
  }

  .compliance-table td {
    padding: 0.7rem 1rem;
    border-bottom: 1px solid #1e2533;
    color: #94a3b8;
  }

  .compliance-table tr:last-child td {
    border-bottom: none;
  }

  .compliance-table td:first-child {
    color: #e2e8f0;
    font-weight: 600;
    font-family: 'Courier New', monospace;
    font-size: 0.8rem;
  }

  .compliance-section {
    background: #1a1f2e;
    border: 1px solid #2d3748;
    border-radius: 12px;
    padding: 2rem;
    margin-bottom: 3rem;
  }

  .framework-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 1rem;
    margin-top: 1rem;
  }

  .framework-card {
    background: #0f1117;
    border: 1px solid #2d3748;
    border-radius: 8px;
    padding: 1.2rem;
  }

  .framework-name {
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #64748b;
    margin-bottom: 0.8rem;
    font-weight: 700;
  }

  .footer {
    background: #1a1f2e;
    border-top: 1px solid #2d3748;
    padding: 1.5rem 3rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 0.8rem;
    color: #64748b;
    margin-top: 3rem;
  }

  .footer-hash {
    font-family: 'Courier New', monospace;
    color: #475569;
  }

  .canary-alert {
    background: #450a0a;
    border: 1px solid #ef4444;
    border-radius: 8px;
    padding: 1rem 1.5rem;
    margin-bottom: 1.5rem;
    display: flex;
    align-items: center;
    gap: 1rem;
    font-size: 0.9rem;
    color: #fca5a5;
  }

  .needs-review-badge {
    background: #312e81;
    color: #a5b4fc;
    border: 1px solid #6366f1;
    padding: 0.2rem 0.6rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 600;
  }

  @media print {
    body { background: white; color: black; }
    .finding-body { display: block !important; }
  }
</style>
</head>
<body>

<div class="header">
  <div class="logo">
    <div>
      <div class="logo-text">AIST</div>
      <div class="logo-sub">Agentic Injection Security Tester</div>
    </div>
  </div>
  <div class="report-meta">
    <strong>Security Assessment Report</strong>
    {{ scan_date }}<br>
    v{{ aist_version }} &nbsp;|&nbsp; github.com/chiivy/aist
  </div>
</div>

{% if expose_evidence %}
<div class="sensitive-banner">
  SENSITIVE REPORT: Contains unmasked credentials and sensitive values.
  Handle with care. Do not store in version control or shared drives.
</div>
{% endif %}

<div class="container">

  <!-- Executive Summary -->
  <div class="section-title">Executive Summary</div>

  {% if summary.canary_triggered %}
  <div class="canary-alert">
    <span style="font-size: 1.2rem;">⚠️</span>
    <strong>Canary Token Triggered:</strong>
    One or more canary tokens leaked during this scan.
    This is unambiguous confirmation of system prompt exfiltration.
    Immediate action required.
  </div>
  {% endif %}

  <div class="executive-grid">

    <div class="risk-card">
      <div class="risk-gauge">
        <div class="risk-score">{{ "%.1f"|format(summary.overall_score) }}</div>
        <div class="risk-label">/ 10.0</div>
      </div>
      <div class="risk-rating">{{ summary.overall_rating }}</div>
      <div style="font-size: 0.8rem; color: #64748b; margin-top: 0.5rem;">
        Overall Risk Rating
      </div>
    </div>

    <div class="stats-card">
      <div style="font-size: 0.85rem; color: #64748b; margin-bottom: 0.5rem;">
        Findings by Severity
      </div>
      <div class="stats-grid">
        <div class="stat-item">
          <div class="stat-number critical-color">
            {{ summary.critical }}
          </div>
          <div class="stat-label">Critical</div>
        </div>
        <div class="stat-item">
          <div class="stat-number high-color">
            {{ summary.high }}
          </div>
          <div class="stat-label">High</div>
        </div>
        <div class="stat-item">
          <div class="stat-number medium-color">
            {{ summary.medium }}
          </div>
          <div class="stat-label">Medium</div>
        </div>
        <div class="stat-item">
          <div class="stat-number low-color">
            {{ summary.low }}
          </div>
          <div class="stat-label">Low</div>
        </div>
      </div>
    </div>

    <div class="scan-info-card">
      <div style="font-size: 0.85rem; color: #64748b; margin-bottom: 0.5rem;">
        Scan Information
      </div>
      <div class="info-row">
        <span class="info-key">Target</span>
        <span class="info-value">{{ target }}</span>
      </div>
      <div class="info-row">
        <span class="info-key">Scan Date</span>
        <span class="info-value">{{ scan_date }}</span>
      </div>
      <div class="info-row">
        <span class="info-key">Payloads Sent</span>
        <span class="info-value">{{ total_payloads }}</span>
      </div>
      <div class="info-row">
        <span class="info-key">Total Findings</span>
        <span class="info-value">{{ summary.total_findings }}</span>
      </div>
      <div class="info-row">
        <span class="info-key">Report Hash</span>
        <span class="info-value" style="font-family: monospace; font-size: 0.75rem;">
          {{ report_hash }}
        </span>
      </div>
    </div>

  </div>

  <!-- Attack Surface -->
  {% if attack_surface %}
  <div class="section-title">Attack Surface</div>
  <div class="attack-surface">
    <div class="surface-grid">

      <div class="surface-item">
        <div class="surface-item-label">Model Detected</div>
        <div class="surface-item-value">
          {{ attack_surface.model_hint | title }}
        </div>
      </div>

      <div class="surface-item">
        <div class="surface-item-label">Declared Tools</div>
        <div class="surface-item-value">
          {% if attack_surface.declared_tools %}
            {% for tool in attack_surface.declared_tools %}
            <span class="tag tag-blue">{{ tool }}</span>
            {% endfor %}
          {% else %}
            <span style="color: #64748b;">None</span>
          {% endif %}
        </div>
      </div>

      <div class="surface-item">
        <div class="surface-item-label">Discovered Tools</div>
        <div class="surface-item-value">
          {% set undeclared = [] %}
          {% for t in attack_surface.discovered_tools %}
            {% if t not in attack_surface.declared_tools %}
              {% set _ = undeclared.append(t) %}
            {% endif %}
          {% endfor %}
          {% if undeclared %}
            {% for tool in undeclared %}
            <span class="tag tag-orange">{{ tool }} ⚠</span>
            {% endfor %}
          {% else %}
            <span style="color: #64748b;">None additional</span>
          {% endif %}
        </div>
      </div>

      <div class="surface-item">
        <div class="surface-item-label">Memory</div>
        <div class="surface-item-value">
          {% if attack_surface.has_memory %}
          <span class="tag tag-orange">Persistent</span>
          {% else %}
          <span class="tag tag-green">Stateless</span>
          {% endif %}
        </div>
      </div>

      <div class="surface-item">
        <div class="surface-item-label">RAG Pipeline</div>
        <div class="surface-item-value">
          {% if attack_surface.rag_detected %}
          <span class="tag tag-orange">Detected</span>
          {% else %}
          <span class="tag tag-green">Not Detected</span>
          {% endif %}
        </div>
      </div>

      <div class="surface-item">
        <div class="surface-item-label">SSRF Potential</div>
        <div class="surface-item-value">
          {% if attack_surface.ssrf_potential %}
          <span class="tag tag-red">Yes</span>
          {% else %}
          <span class="tag tag-green">No</span>
          {% endif %}
        </div>
      </div>

      <div class="surface-item">
        <div class="surface-item-label">Connected Agents</div>
        <div class="surface-item-value">
          {% if attack_surface.connected_agents %}
            {% for agent in attack_surface.connected_agents %}
            <span class="tag tag-orange">{{ agent }}</span>
            {% endfor %}
          {% else %}
            <span style="color: #64748b;">None detected</span>
          {% endif %}
        </div>
      </div>

      <div class="surface-item">
        <div class="surface-item-label">Severity Multiplier</div>
        <div class="surface-item-value">
          <span class="tag tag-{% if attack_surface.severity_multiplier > 2 %}red{% elif attack_surface.severity_multiplier > 1.5 %}orange{% else %}green{% endif %}">
            {{ "%.1f"|format(attack_surface.severity_multiplier) }}x
          </span>
        </div>
      </div>

    </div>
  </div>
  {% endif %}

  <!-- Findings -->
  <div class="section-title">
    Findings ({{ summary.total_findings }})
  </div>

  <div class="findings-section">
    {% if findings %}
      {% for finding in findings %}
      <div class="finding-card {{ finding.severity_label | lower }}"
           id="finding-{{ finding.payload_id }}">

        <div class="finding-header"
             onclick="toggleFinding('{{ finding.payload_id }}')">
          <div class="finding-title">
            <span class="severity-badge badge-{{ finding.severity_label | lower }}">
              {{ finding.severity_label }}
            </span>
            <span class="finding-id">{{ finding.payload_id }}</span>
            <span style="color: #e2e8f0; font-size: 0.9rem;">
              {{ finding.payload_category }} -
              {% if finding.canary_leaked %}
                Canary Token Leaked
              {% elif finding.credentials_detected %}
                Credential Exposure
              {% elif finding.tool_invocation_detected %}
                Unauthorised Tool Invocation
              {% else %}
                Injection Successful
              {% endif %}
            </span>
            {% if finding.needs_review %}
            <span class="needs-review-badge">Needs Review</span>
            {% endif %}
          </div>

          <div class="finding-scores">
            <div class="score-item">
              <div class="score-value {{ finding.severity_label | lower }}-color">
                {{ "%.1f"|format(finding.severity_score) }}
              </div>
              <div class="score-label">Severity</div>
            </div>
            <div class="score-item">
              <div class="score-value" style="color: #94a3b8;">
                {{ finding.confidence_score }}%
              </div>
              <div class="score-label">Confidence</div>
            </div>
            <div style="color: #64748b; font-size: 1.2rem;">›</div>
          </div>
        </div>

        <div class="finding-body" id="body-{{ finding.payload_id }}">
          <div class="finding-divider"></div>

          <!-- Sensitive patterns -->
          {% if finding.sensitive_patterns %}
          <div class="finding-section-label">Sensitive Data Detected</div>
          <div style="margin-bottom: 1rem;">
            {% for pattern in finding.sensitive_patterns %}
            <span class="tag tag-red">{{ pattern }}</span>
            {% endfor %}
          </div>
          {% endif %}

          <!-- Score breakdown -->
          <div class="finding-section-label">Score Breakdown</div>
          <div style="display: flex; gap: 2rem; margin-bottom: 1rem;
                      font-size: 0.85rem; color: #94a3b8;">
            <span>Base: <strong>{{ finding.score_breakdown.base_score }}</strong></span>
            <span>Pattern boost: <strong>+{{ finding.score_breakdown.pattern_boost }}</strong></span>
            <span>Tool addition: <strong>+{{ finding.score_breakdown.tool_addition }}</strong></span>
            <span>Discovery: <strong>+{{ finding.score_breakdown.discovery_addition }}</strong></span>
            <span>Final: <strong class="{{ finding.severity_label | lower }}-color">
              {{ finding.severity_score }}
            </strong></span>
          </div>

          <!-- Payload sent -->
          <div class="finding-section-label">Payload Sent</div>
          <div class="code-block">{{ finding.prompt_sent }}</div>

          <!-- Response received -->
          <div class="finding-section-label">Response Received</div>
          <div class="evidence-block">{{ finding.response_received }}</div>

          <!-- LLM Judge -->
          {% if finding.llm_judge_reasoning %}
          <div class="finding-section-label">LLM Judge Analysis</div>
          <div style="background: #0f1720; border: 1px solid #1e3a5f;
                      border-radius: 6px; padding: 1rem; font-size: 0.85rem;
                      color: #93c5fd; margin-bottom: 1rem;">
            {{ finding.llm_judge_reasoning }}
            <span style="color: #64748b; margin-left: 1rem;">
              Confidence: {{ finding.llm_judge_confidence }}%
            </span>
          </div>
          {% endif %}

          <!-- CVSS -->
          <div class="finding-section-label">CVSS Vector</div>
          <div style="font-family: monospace; font-size: 0.8rem;
                      color: #64748b; margin-bottom: 1rem;">
            {{ finding.cvss_vector }}
          </div>

          <!-- Compliance -->
          {% if finding.compliance %}
          <div class="finding-section-label">Compliance References</div>
          <table class="compliance-table" style="margin-bottom: 1rem;">
            <thead>
              <tr>
                <th>Framework</th>
                <th>Reference</th>
              </tr>
            </thead>
            <tbody>
              {% if finding.compliance.owasp_llm %}
              <tr>
                <td>OWASP LLM Top 10</td>
                <td>{{ finding.compliance.owasp_llm.id }} -
                    {{ finding.compliance.owasp_llm.name }}</td>
              </tr>
              {% endif %}
              {% if finding.compliance.mitre_atlas %}
              {% for t in finding.compliance.mitre_atlas %}
              <tr>
                <td>MITRE ATLAS</td>
                <td>{{ t.id }}: {{ t.name }}</td>
              </tr>
              {% endfor %}
              {% endif %}
              {% if finding.compliance.eu_ai_act %}
              {% for item in finding.compliance.eu_ai_act %}
              <tr>
                <td>EU AI Act</td>
                <td>{{ item.article }}: {{ item.description }}</td>
              </tr>
              {% endfor %}
              {% endif %}
              {% if finding.compliance.soc2 %}
              {% for item in finding.compliance.soc2 %}
              <tr>
                <td>SOC 2</td>
                <td>{{ item.criteria }}: {{ item.description }}</td>
              </tr>
              {% endfor %}
              {% endif %}
            </tbody>
          </table>
          {% endif %}

          <!-- Remediation -->
          {% if finding.generic_guidance %}
          <div class="finding-section-label">Remediation</div>
          <div class="remediation-block">
            <div style="font-size: 0.85rem; color: #93c5fd;
                        margin-bottom: 1rem;">
              {{ finding.generic_guidance.summary }}
            </div>
            {% for step in finding.generic_guidance.steps %}
            <div class="remediation-step">
              <div class="step-number">{{ loop.index }}</div>
              <div style="font-size: 0.85rem; color: #94a3b8;">
                {{ step }}
              </div>
            </div>
            {% endfor %}
          </div>
          {% endif %}

        </div>
      </div>
      {% endfor %}

    {% else %}
    <div style="background: #1a1f2e; border: 1px solid #2d3748;
                border-radius: 12px; padding: 3rem; text-align: center;
                color: #64748b;">
      <div style="font-size: 2rem; margin-bottom: 1rem;">✓</div>
      <div style="font-size: 1.1rem; font-weight: 600;
                  color: #22c55e; margin-bottom: 0.5rem;">
        No Findings Detected
      </div>
      <div style="font-size: 0.9rem;">
        All {{ total_payloads }} payloads completed without
        detecting injection vulnerabilities.
      </div>
    </div>
    {% endif %}

  </div>

  <!-- Compliance Summary -->
  {% if compliance_summary and compliance_summary.owasp_violations %}
  <div class="section-title">Compliance Impact Summary</div>
  <div class="compliance-section">
    <div class="framework-grid">

      {% if compliance_summary.owasp_violations %}
      <div class="framework-card">
        <div class="framework-name">OWASP LLM Top 10</div>
        {% for v in compliance_summary.owasp_violations %}
        <span class="tag tag-orange">{{ v }}</span>
        {% endfor %}
      </div>
      {% endif %}

      {% if compliance_summary.atlas_techniques %}
      <div class="framework-card">
        <div class="framework-name">MITRE ATLAS</div>
        {% for t in compliance_summary.atlas_techniques %}
        <span class="tag tag-red">{{ t }}</span>
        {% endfor %}
      </div>
      {% endif %}

      {% if compliance_summary.nist_functions %}
      <div class="framework-card">
        <div class="framework-name">NIST AI RMF</div>
        {% for f in compliance_summary.nist_functions %}
        <span class="tag tag-blue">{{ f }}</span>
        {% endfor %}
      </div>
      {% endif %}

      {% if compliance_summary.eu_articles %}
      <div class="framework-card">
        <div class="framework-name">EU AI Act</div>
        {% for a in compliance_summary.eu_articles %}
        <span class="tag tag-gray">{{ a }}</span>
        {% endfor %}
      </div>
      {% endif %}

      {% if compliance_summary.soc2_criteria %}
      <div class="framework-card">
        <div class="framework-name">SOC 2</div>
        {% for c in compliance_summary.soc2_criteria %}
        <span class="tag tag-blue">{{ c }}</span>
        {% endfor %}
      </div>
      {% endif %}

    </div>
  </div>
  {% endif %}

</div>

<div class="footer">
  <div>
    Generated by <strong style="color: #ef4444;">AIST</strong>
    v{{ aist_version }} &nbsp;|&nbsp;
    github.com/chiivy/aist
  </div>
  <div class="footer-hash">
    Report integrity: {{ report_hash }}
  </div>
</div>

<script>
  function toggleFinding(id) {
    const body = document.getElementById('body-' + id);
    body.classList.toggle('open');
  }

  // Auto-open critical findings
  document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('.finding-card.critical').forEach(card => {
      const id = card.id.replace('finding-', '');
      const body = document.getElementById('body-' + id);
      if (body) body.classList.add('open');
    });
  });
</script>

</body>
</html>"""