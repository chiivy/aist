"""
AIST Command Line Interface

Entry point for all AIST commands.

Commands:
    aist scan       Run a full security scan
    aist discover   Run attack surface discovery only
"""

import sys
import click
from rich.console import Console
from rich.panel import Panel

from aist.config import load_config
from aist.logger import get_logger, setup_logging

console = Console()
log = get_logger(__name__)


def print_banner():
    """Print AIST startup banner."""
    console.print(Panel.fit(
        "[bold red]AIST[/bold red] "
        "[white]Agentic Injection Security Tester[/white]\n"
        "[dim]github.com/chiivy/aist[/dim]",
        border_style="red"
    ))


def confirm_expose_evidence() -> bool:
    """
    Prompt user to explicitly confirm they want
    unmasked sensitive values in their report.

    Returns:
        True if user confirmed, False otherwise
    """
    from aist.evidence.masking import EXPOSE_CONFIRMATION_WARNING
    console.print(
        f"\n[bold red]{EXPOSE_CONFIRMATION_WARNING}[/bold red]"
    )
    confirmation = input().strip()
    if confirmation == "CONFIRM":
        console.print(
            "[yellow]Proceeding with unmasked report. "
            "Handle output with care.[/yellow]\n"
        )
        return True
    console.print(
        "[green]Cancelled. Standard masked report "
        "will be generated.[/green]\n"
    )
    return False


@click.group()
def main():
    """
    AIST: Agentic Injection Security Tester

    Open source AI agent security testing framework.
    Tests agents for prompt injection vulnerabilities
    and scores findings based on what the agent can do.

    All data stays on your machine.
    No accounts required. No telemetry.
    """
    pass


@main.command()
@click.option(
    "--target", "-t",
    required=True,
    help="Target agent endpoint URL"
)
@click.option(
    "--tools", "-T",
    default="",
    help="Comma-separated list of agent tools "
         "e.g. email,files,database"
)
@click.option(
    "--output", "-o",
    default="reports/aist-report.html",
    help="Output file path for HTML report"
)
@click.option(
    "--mode", "-m",
    default="active",
    type=click.Choice(["active", "passive"]),
    help="Scan mode. Active probes aggressively. "
         "Passive observes natural behaviour."
)
@click.option(
    "--runs", "-r",
    default=3,
    type=int,
    help="Number of times to run each payload "
         "for reproducibility scoring"
)
@click.option(
    "--log-level", "-l",
    default="INFO",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    help="Logging verbosity"
)
@click.option(
    "--siem",
    default=None,
    help="Optional SIEM endpoint URL for log shipping"
)
@click.option(
    "--expose-evidence",
    is_flag=True,
    default=False,
    help="Include unmasked sensitive values in report. "
         "Requires confirmation. Handle output with care."
)
@click.option(
    "--executive",
    is_flag=True,
    default=False,
    help="Generate executive summary report only. "
         "No technical details. Safe for non-technical stakeholders."
)
@click.option(
    "--categories",
    default="all",
    help="Comma-separated payload categories to run. "
         "e.g. A,B,G or 'all' for everything. "
         "Default: all"
)
def scan(
    target, tools, output, mode, runs,
    log_level, siem, expose_evidence,
    executive, categories
):
    """
    Run a full injection security scan against a target agent.

    Example:

        aist scan --target https://agent.example.com
                  --tools email,files,database
                  --output report.html

    With expose mode for remediation:

        aist scan --target https://agent.example.com
                  --expose-evidence
    """
    setup_logging(log_level=log_level)
    print_banner()

    # Handle expose evidence confirmation
    if expose_evidence:
        expose_evidence = confirm_expose_evidence()

    tools_list = [t.strip() for t in tools.split(",") if t.strip()]

    categories_list = (
        None if categories == "all"
        else [c.strip().upper() for c in categories.split(",")]
    )

    console.print(f"\n[bold]Target:[/bold] {target}")
    console.print(
        f"[bold]Tools declared:[/bold] "
        f"{', '.join(tools_list) if tools_list else 'none'}"
    )
    console.print(f"[bold]Mode:[/bold] {mode}")
    console.print(f"[bold]Payload runs:[/bold] {runs}")
    console.print(
        f"[bold]Categories:[/bold] "
        f"{categories if categories == 'all' else categories_list}"
    )
    console.print(f"[bold]Output:[/bold] {output}")
    console.print(
        f"[bold]Expose evidence:[/bold] {expose_evidence}"
    )
    console.print(f"[bold]Executive mode:[/bold] {executive}\n")

    config = load_config(
        target_endpoint=target,
        tools=tools_list,
        mode=mode,
        runs=runs,
        log_level=log_level,
        siem_endpoint=siem,
        expose_evidence=expose_evidence,
        executive_mode=executive,
        categories=categories_list,
    )

    log.info(
        "scan_started",
        target=target,
        tools=tools_list,
        mode=mode,
        runs=runs,
        expose_evidence=expose_evidence,
        executive=executive,
    )

    console.print(
        "[yellow]Scan engine coming in v1.0[/yellow]"
    )
    console.print(
        "[dim]Core modules: recon, scanner, "
        "evidence, scoring, reporting[/dim]"
    )


@main.command()
@click.option(
    "--target", "-t",
    required=True,
    help="Target agent endpoint URL"
)
@click.option(
    "--mode", "-m",
    default="passive",
    type=click.Choice(["active", "passive"]),
    help="Discovery mode. Passive is safer for "
         "production agents."
)
@click.option(
    "--output", "-o",
    default="reports/aist-surface-map.html",
    help="Output file path for surface map report"
)
@click.option(
    "--log-level", "-l",
    default="INFO",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    help="Logging verbosity"
)
def discover(target, mode, output, log_level):
    """
    Run attack surface discovery against a target agent.

    Maps what the agent is connected to without
    running any injection test payloads.
    Safe to run against production agents in passive mode.

    Example:

        aist discover --target https://agent.example.com
                      --mode passive
                      --output surface-map.html
    """
    setup_logging(log_level=log_level)
    print_banner()

    console.print(f"\n[bold]Target:[/bold] {target}")
    console.print(f"[bold]Mode:[/bold] {mode}")
    console.print(f"[bold]Output:[/bold] {output}\n")

    config = load_config(
        target_endpoint=target,
        mode=mode,
        log_level=log_level,
    )

    log.info(
        "discovery_started",
        target=target,
        mode=mode,
    )

    console.print(
        "[yellow]Discovery engine coming in v1.0[/yellow]"
    )


if __name__ == "__main__":
    main()