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
         "(e.g. email,files,database)"
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
def scan(target, tools, output, mode, runs, log_level, siem):
    """
    Run a full injection security scan against a target agent.

    Example:

        aist scan --target https://agent.example.com
                  --tools email,files,database
                  --output report.html
    """
    setup_logging(log_level=log_level)
    print_banner()

    tools_list = [t.strip() for t in tools.split(",") if t.strip()]

    console.print(
        f"\n[bold]Target:[/bold] {target}"
    )
    console.print(
        f"[bold]Tools declared:[/bold] "
        f"{', '.join(tools_list) if tools_list else 'none'}"
    )
    console.print(f"[bold]Mode:[/bold] {mode}")
    console.print(f"[bold]Payload runs:[/bold] {runs}")
    console.print(f"[bold]Output:[/bold] {output}\n")

    config = load_config(
        target_endpoint=target,
        tools=tools_list,
        mode=mode,
        runs=runs,
        log_level=log_level,
        siem_endpoint=siem,
    )

    log.info(
        "scan_started",
        target=target,
        tools=tools_list,
        mode=mode,
        runs=runs,
    )

    # Scan orchestration -- implemented in v1.0
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

    console.print(
        f"\n[bold]Target:[/bold] {target}"
    )
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

    # Discovery orchestration -- implemented in v1.0
    console.print(
        "[yellow]Discovery engine coming in v1.0[/yellow]"
    )


if __name__ == "__main__":
    main()