"""
AIST Scan Orchestrator

Coordinates all scan phases in the correct order
and collects results for reporting.

Phases:
    1. Recon and discovery
    2. Canary token generation
    3. Scanner execution
    4. Scoring
    5. Report generation
"""

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
)
from rich.panel import Panel

from aist.logger import get_logger
from aist.config import AISTConfig
from aist.evidence.collector import ScanEvidence, is_genuine_finding
from aist.recon.probe import run_recon
from aist.recon.discovery import run_discovery
from aist.recon.fingerprint import run_fingerprinting
from aist.recon.streaming import truncate_if_oversized
from aist.scanner.canary import (
    generate_canary_token,
    run_canary_check,
    run_semantic_canary_baseline,
)
from aist.scanner.direct import run_direct_scanner
from aist.scanner.indirect import run_indirect_scanner
from aist.scanner.multiturn import run_multiturn_scanner
from aist.scanner.guardrail import run_guardrail_scanner
from aist.scanner.toolparam import run_toolparam_scanner
from aist.scanner.output import run_output_scanner
from aist.scoring.severity import (
    calculate_severity,
    get_owasp_reference,
)
from aist.scoring.confidence import (
    calculate_confidence,
    aggregate_scan_confidence,
)
from aist.remediation.contextual import get_contextual_guidance
from aist.reporting.html import (
    generate_html_report,
    save_html_report,
)
from aist.reporting.json_report import (
    generate_json_report,
    save_json_report,
)
from aist.reporting.sarif import (
    generate_sarif_report,
    save_sarif_report,
)

log = get_logger(__name__)
console = Console()


async def run_full_scan(
    config: AISTConfig,
    output_path: str = "reports/aist-report.html",
) -> dict:
    """
    Run a complete AIST security scan.

    Orchestrates all phases from recon through
    reporting and returns a summary of results.

    Args:
        config:      AIST configuration
        output_path: Path for HTML report output

    Returns:
        Dictionary with scan results summary
    """
    scan_start = datetime.utcnow()

    scan_evidence = ScanEvidence(
        target=config.target.endpoint
    )

    console.print(
        f"\n[bold]Starting scan against:[/bold] "
        f"[cyan]{config.target.endpoint}[/cyan]\n"
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:

        # Phase 1: Recon
        recon_task = progress.add_task(
            "[cyan]Recon phase...", total=3
        )

        console.print("[dim]Running basic probes...[/dim]")
        recon_report = await run_recon(config)
        progress.advance(recon_task)

        console.print(
            "[dim]Mapping attack surface...[/dim]"
        )
        discovery_result = await run_discovery(
            config, recon_report
        )
        progress.advance(recon_task)

        console.print(
            "[dim]Fingerprinting model...[/dim]"
        )
        fingerprint = await run_fingerprinting(
            config,
            initial_hint=recon_report.model_hint,
        )
        progress.advance(recon_task)

        config.target.tools = list(set(
            config.target.tools +
            recon_report.discovered_tools
        ))

        _print_recon_summary(
            recon_report,
            discovery_result,
            fingerprint,
        )

        # Phase 2: Canary token
        canary_token = generate_canary_token()
        log.info(
            "canary_token_generated",
            token_preview=canary_token[:12] + "...",
        )

        await run_semantic_canary_baseline(config)

        # Phase 3: Run scanners
        categories = config.scan.categories

        scanner_tasks = [
            ("direct", "Direct injection (A-F)"),
            ("indirect", "Indirect injection"),
            ("multiturn", "Multi-turn sequences"),
            ("guardrail", "Guardrail bypass (G)"),
            ("toolparam", "Tool parameter injection (H)"),
            ("output", "Output manipulation (I)"),
            ("canary", "Canary token check"),
        ]

        scan_task = progress.add_task(
            "[red]Running scanners...",
            total=len(scanner_tasks),
        )

        all_evidence = []
        all_run_results = {}

        for scanner_name, description in scanner_tasks:
            progress.update(
                scan_task,
                description=f"[red]{description}..."
            )

            if scanner_name == "direct":
                if not categories or any(
                    c in ["A", "B", "C", "D", "E", "F"]
                    for c in (categories or [])
                ):
                    evidence, results = (
                        await run_direct_scanner(
                            config,
                            canary_token,
                            categories,
                        )
                    )
                    all_evidence.extend(evidence)
                    all_run_results.update(results)

            elif scanner_name == "indirect":
                if not categories or "INDIRECT" in (
                    categories or []
                ):
                    evidence, results = (
                        await run_indirect_scanner(
                            config, canary_token
                        )
                    )
                    all_evidence.extend(evidence)
                    all_run_results.update(results)

            elif scanner_name == "multiturn":
                if not categories or "S" in (
                    categories or []
                ):
                    evidence, results = (
                        await run_multiturn_scanner(
                            config, canary_token
                        )
                    )
                    all_evidence.extend(evidence)
                    all_run_results.update(results)

            elif scanner_name == "guardrail":
                if not categories or "G" in (
                    categories or []
                ):
                    evidence, results = (
                        await run_guardrail_scanner(
                            config, canary_token
                        )
                    )
                    all_evidence.extend(evidence)
                    all_run_results.update(results)

            elif scanner_name == "toolparam":
                if not categories or "H" in (
                    categories or []
                ):
                    evidence, results = (
                        await run_toolparam_scanner(
                            config, canary_token
                        )
                    )
                    all_evidence.extend(evidence)
                    all_run_results.update(results)

            elif scanner_name == "output":
                if not categories or "I" in (
                    categories or []
                ):
                    evidence, results = (
                        await run_output_scanner(
                            config, canary_token
                        )
                    )
                    all_evidence.extend(evidence)
                    all_run_results.update(results)

            elif scanner_name == "canary":
                evidence, results = await run_canary_check(
                    config, canary_token
                )
                all_evidence.extend(evidence)
                all_run_results.update(results)

            progress.advance(scan_task)

        scan_evidence.evidence_items = all_evidence
        scan_evidence.total_payloads_sent = len(all_evidence)
        scan_evidence.total_responses_received = len(
            all_evidence
        )
        scan_evidence.canary_triggered = any(
            e.canary_leaked for e in all_evidence
        )

        # Phase 4: Scoring
        score_task = progress.add_task(
            "[yellow]Scoring findings...",
            total=len(all_evidence),
        )

        severity_scores = []
        confidence_scores = []

        for evidence in all_evidence:
            run_results = all_run_results.get(
                evidence.payload_id, []
            )

            severity = calculate_severity(
                payload_id=evidence.payload_id,
                payload_severity_base=_get_severity_base(
                    evidence.payload_id
                ),
                pattern_boost=sum(
                    _get_pattern_boost(p)
                    for p in evidence.sensitive_patterns
                ),
                declared_tools=config.target.tools,
                discovered_tools=(
                    recon_report.discovered_tools
                    if recon_report else []
                ),
                discovery_multiplier=getattr(
                    discovery_result,
                    "severity_multiplier",
                    1.0,
                ),
                canary_leaked=evidence.canary_leaked,
                credentials_detected=(
                    evidence.credentials_detected
                ),
            )

            confidence = calculate_confidence(
                payload_id=evidence.payload_id,
                run_results=run_results,
            )

            severity_scores.append(severity)
            confidence_scores.append(confidence)

            progress.advance(score_task)

        # Filter to genuine findings only.
        # This MUST match the same logic used by
        # html.py, json_report.py, and sarif.py
        # so console output, exit codes, and reports
        # always agree with each other.
        genuine_severity_scores = [
            s for s, e in zip(severity_scores, all_evidence)
            if is_genuine_finding(e)
        ]

        # Phase 5: Reports
        report_task = progress.add_task(
            "[green]Generating reports...",
            total=3,
        )

        html = generate_html_report(
            scan_evidence=scan_evidence,
            recon_report=recon_report,
            discovery_result=discovery_result,
            severity_scores=severity_scores,
            confidence_scores=confidence_scores,
            config=config,
        )
        html_path = save_html_report(html, output_path)
        progress.advance(report_task)

        json_output_path = output_path.replace(
            ".html", ".json"
        )
        json_report = generate_json_report(
            scan_evidence=scan_evidence,
            recon_report=recon_report,
            discovery_result=discovery_result,
            severity_scores=severity_scores,
            confidence_scores=confidence_scores,
            config=config,
        )
        save_json_report(json_report, json_output_path)
        progress.advance(report_task)

        sarif_output_path = output_path.replace(
            ".html", ".sarif"
        )
        sarif_report = generate_sarif_report(
            scan_evidence=scan_evidence,
            severity_scores=severity_scores,
            confidence_scores=confidence_scores,
            config=config,
        )
        save_sarif_report(sarif_report, sarif_output_path)
        progress.advance(report_task)

    scan_duration = (
        datetime.utcnow() - scan_start
    ).total_seconds()

    _print_scan_summary(
        scan_evidence,
        genuine_severity_scores,
        confidence_scores,
        html_path,
        scan_duration,
    )

    return {
        "target": config.target.endpoint,
        "total_findings": len(genuine_severity_scores),
        "critical": sum(
            1 for s in genuine_severity_scores
            if s.severity_label == "Critical"
        ),
        "high": sum(
            1 for s in genuine_severity_scores
            if s.severity_label == "High"
        ),
        "medium": sum(
            1 for s in genuine_severity_scores
            if s.severity_label == "Medium"
        ),
        "low": sum(
            1 for s in genuine_severity_scores
            if s.severity_label == "Low"
        ),
        "canary_triggered": (
            scan_evidence.canary_triggered
        ),
        "html_report": html_path,
        "json_report": json_output_path,
        "sarif_report": sarif_output_path,
        "duration_seconds": scan_duration,
    }


def _print_recon_summary(
    recon_report,
    discovery_result,
    fingerprint,
) -> None:
    """Print recon results to console."""
    console.print("\n[bold]Recon Results:[/bold]")
    console.print(
        f"  Model detected:    "
        f"[cyan]{recon_report.model_hint}[/cyan]"
    )
    console.print(
        f"  Declared tools:    "
        f"[cyan]{', '.join(recon_report.declared_tools) or 'none'}[/cyan]"
    )

    undeclared = [
        t for t in recon_report.discovered_tools
        if t not in recon_report.declared_tools
    ]
    if undeclared:
        console.print(
            f"  [yellow]Undeclared tools found: "
            f"{', '.join(undeclared)}[/yellow]"
        )

    if recon_report.system_prompt_exposed:
        console.print(
            "  [red]System prompt exposed during recon[/red]"
        )

    if getattr(discovery_result, "rag_detected", False):
        console.print(
            "  [yellow]RAG pipeline detected[/yellow]"
        )

    if getattr(discovery_result, "ssrf_potential", False):
        console.print(
            "  [red]SSRF potential detected[/red]"
        )

    multiplier = getattr(
        discovery_result, "severity_multiplier", 1.0
    )
    if multiplier > 1.0:
        console.print(
            f"  Severity multiplier: "
            f"[yellow]{multiplier}x[/yellow]"
        )

    console.print()


def _print_scan_summary(
    scan_evidence,
    severity_scores,
    confidence_scores,
    html_path,
    duration,
) -> None:
    """
    Print final scan summary to console.

    severity_scores here should be genuine_severity_scores
    (already filtered by is_genuine_finding) so the
    console counts match the HTML/JSON/SARIF reports.
    """
    critical = sum(
        1 for s in severity_scores
        if s.severity_label == "Critical"
    )
    high = sum(
        1 for s in severity_scores
        if s.severity_label == "High"
    )
    medium = sum(
        1 for s in severity_scores
        if s.severity_label == "Medium"
    )
    low = sum(
        1 for s in severity_scores
        if s.severity_label == "Low"
    )

    console.print(
        Panel.fit(
            f"[bold]Scan Complete[/bold] "
            f"in {round(duration, 1)}s\n\n"
            f"[red]Critical: {critical}[/red]  "
            f"[orange1]High: {high}[/orange1]  "
            f"[yellow]Medium: {medium}[/yellow]  "
            f"[green]Low: {low}[/green]\n\n"
            f"[bold]Reports saved:[/bold]\n"
            f"  HTML:  {html_path}\n"
            f"  JSON:  {html_path.replace('.html', '.json')}\n"
            f"  SARIF: {html_path.replace('.html', '.sarif')}",
            border_style="green" if not critical else "red",
        )
    )

    if scan_evidence.canary_triggered:
        console.print(
            "\n[bold red]WARNING: Canary token triggered.[/bold red]\n"
            "System prompt exfiltration confirmed.\n"
            "Immediate remediation required."
        )


def _get_severity_base(payload_id: str) -> str:
    """
    Get base severity for a payload from its ID.

    Maps payload ID patterns to base severity levels.
    Falls back to medium if pattern not recognised.
    """
    critical_patterns = ["C3", "E1", "E2", "E3", "E4",
                         "H4", "H6", "I5", "CANARY"]
    high_patterns = ["A1", "A2", "A3", "B1", "B2", "B3",
                     "B5", "B6", "C1", "C2", "C4", "D1",
                     "E5", "F1", "F2", "F3", "G1", "G2",
                     "G5", "G6", "G10", "H1", "H2", "H3",
                     "H5", "H8", "I1", "I2", "I3", "I6"]
    low_patterns = ["D4", "G9"]

    for pattern in critical_patterns:
        if pattern in payload_id:
            return "critical"

    for pattern in high_patterns:
        if pattern in payload_id:
            return "high"

    for pattern in low_patterns:
        if pattern in payload_id:
            return "low"

    return "medium"


def _get_pattern_boost(pattern_name: str) -> float:
    """
    Get severity boost value for a detected pattern.
    """
    boosts = {
        "openai_api_key": 2.0,
        "anthropic_api_key": 2.0,
        "google_api_key": 2.0,
        "bearer_token": 2.0,
        "password_in_response": 2.0,
        "secret_in_response": 1.5,
        "database_url": 2.5,
        "email_address": 1.5,
        "phone_number": 1.0,
        "credit_card": 3.0,
        "system_prompt_fragment": 1.5,
        "email_tool_invocation": 2.5,
        "file_tool_invocation": 2.0,
        "code_execution": 2.5,
        "ip_address": 0.5,
        "aws_metadata": 3.0,
        "azure_metadata": 3.0,
        "gcp_metadata": 3.0,
    }
    return boosts.get(pattern_name, 0.5)