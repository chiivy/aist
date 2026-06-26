"""
AIST Command Line Interface

Entry point for all AIST commands.

Commands:
    aist scan       Run a full security scan
    aist discover   Run attack surface discovery only
"""

import asyncio
import re
import sys
from datetime import datetime

import click
from rich.console import Console
from rich.panel import Panel

from aist.config import load_config
from aist.logger import get_logger, setup_logging

console = Console()
log = get_logger(__name__)


def print_banner():
    """Print AIST startup banner."""
    import pyfiglet

    ascii_art = pyfiglet.figlet_format(
        "AIST",
        font="slant",
    )

    console.print(
        f"[bold red]{ascii_art}[/bold red]",
        end="",
    )

    console.print(
        "[bold white]Agentic Injection Security Tester[/bold white]"
    )
    console.print(
        "[dim red]" + "─" * 50 + "[/dim red]"
    )
    console.print(
        "[dim]  github.com/chiivy/aist[/dim]"
        "[dim]  |  v1.0  |  [/dim]"
        "[cyan]inject. detect. report.[/cyan]"
    )
    console.print(
        "[dim red]" + "─" * 50 + "[/dim red]\n"
    )


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


def run_interactive_wizard() -> dict:
    """
    Walk the user through scan setup interactively.

    Returns:
        Dictionary of scan parameters, or
        {"proceed": False} if the user cancels.
    """
    console.print(
        "\n[bold cyan]AIST Interactive Setup Wizard[/bold cyan]\n"
    )

    target = click.prompt(
        "Target agent URL",
        default="http://localhost:5000/chat",
    )

    auth_type = click.prompt(
        "Authentication type",
        type=click.Choice([
            "none", "bearer", "basic",
            "apikey", "sso", "cookie",
        ]),
        default="none",
    )

    auth_token = None
    auth_header = "Authorization"
    auth_username = None
    auth_password = None
    auth_login_url = None
    auth_tenant_id = None
    auth_client_id = None
    auth_cookie_name = "session"
    auth_cookie_value = None

    if auth_type == "bearer":
        auth_token = click.prompt(
            "Bearer token", hide_input=True
        )
    elif auth_type == "basic":
        auth_username = click.prompt("Username")
        auth_password = click.prompt(
            "Password", hide_input=True
        )
        auth_login_url = click.prompt("Login URL")
    elif auth_type == "apikey":
        auth_token = click.prompt(
            "API key value", hide_input=True
        )
        auth_header = click.prompt(
            "Header name", default="Authorization"
        )
    elif auth_type == "sso":
        auth_tenant_id = click.prompt("Azure AD tenant ID")
        auth_client_id = click.prompt("Azure AD client ID")
    elif auth_type == "cookie":
        auth_cookie_name = click.prompt(
            "Cookie name", default="session"
        )
        auth_cookie_value = click.prompt(
            "Cookie value", hide_input=True
        )

    tools = click.prompt(
        "Tools declared on this agent "
        "(comma separated, or leave blank)",
        default="",
    )

    run_all = click.confirm(
        "Run all payload categories?",
        default=True,
    )
    if run_all:
        categories = "all"
    else:
        categories = click.prompt(
            "Categories to run (comma separated, e.g. A,B,G)",
            default="A,B,C,D",
        )

    safe_mode = click.confirm(
        "Enable safe mode? "
        "(recommended for production systems)",
        default=False,
    )

    operator = click.prompt(
        "Your name or handle",
        default="unknown",
    )

    tools_list = [
        t.strip() for t in tools.split(",") if t.strip()
    ]
    categories_display = (
        "all" if categories == "all"
        else categories
    )

    console.print("\n[bold]Scan summary:[/bold]")
    console.print(f"  Target:       {target}")
    console.print(f"  Auth:         {auth_type}")
    console.print(
        f"  Tools:        "
        f"{', '.join(tools_list) if tools_list else 'none'}"
    )
    console.print(f"  Categories:   {categories_display}")
    console.print(
        f"  Safe mode:    {'yes' if safe_mode else 'no'}"
    )
    console.print(f"  Operator:     {operator}\n")

    if not click.confirm("Start scan?", default=True):
        console.print("[yellow]Scan cancelled.[/yellow]")
        return {"proceed": False}

    return {
        "proceed": True,
        "target": target,
        "tools": tools,
        "categories": categories,
        "safe_mode": safe_mode,
        "operator": operator,
        "auth_type": auth_type,
        "auth_token": auth_token,
        "auth_header": auth_header,
        "auth_username": auth_username,
        "auth_password": auth_password,
        "auth_login_url": auth_login_url,
        "auth_tenant_id": auth_tenant_id,
        "auth_client_id": auth_client_id,
        "auth_cookie_name": auth_cookie_name,
        "auth_cookie_value": auth_cookie_value,
    }


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
    default=None,
    help="Target agent endpoint URL. "
         "Omit to launch interactive setup wizard."
)
@click.option(
    "--tools", "-T",
    default="",
    help="Comma-separated list of agent tools "
         "e.g. email,files,database"
)
@click.option(
    "--output", "-o",
    default=None,
    help="Output file path for HTML report. "
         "Default: auto-generated timestamped filename."
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
    default="WARNING",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    help="Logging verbosity. Default: WARNING "
         "keeps console clean."
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
         "No technical details. Safe for non-technical "
         "stakeholders."
)
@click.option(
    "--categories",
    default="all",
    help="Comma-separated payload categories to run. "
         "e.g. A,B,G or 'all' for everything. "
         "Default: all"
)
@click.option(
    "--operator",
    default=None,
    help="Name or handle of person running the scan. "
         "Appears in report for audit purposes. "
         "Can also be set via AIST_OPERATOR in .env"
)
@click.option("--auth-type", default="none",
    help="Auth type: none, bearer, basic, apikey, sso, cookie")
@click.option("--auth-token", default=None,
    help="Bearer token or API key value")
@click.option("--auth-header", default="Authorization",
    help="Header name for token or apikey")
@click.option("--auth-username", default=None,
    help="Username for basic auth")
@click.option("--auth-password", default=None,
    help="Password for basic auth")
@click.option("--auth-login-url", default=None,
    help="Login endpoint URL for basic auth")
@click.option("--auth-tenant-id", default=None,
    help="Azure AD tenant ID for SSO")
@click.option("--auth-client-id", default=None,
    help="Azure AD client ID for SSO")
@click.option("--safe-mode", is_flag=True, default=False,
    help="Skip payload categories that could trigger "
         "real actions. Use on production systems.")
def scan(
    target, tools, output, mode, runs,
    log_level, siem, expose_evidence,
    executive, categories, operator,
    auth_type, auth_token, auth_header,
    auth_username, auth_password, auth_login_url,
    auth_tenant_id, auth_client_id, safe_mode,
):
    """
    Run a full injection security scan against
    a target agent.

    Example:

        aist scan --target https://agent.example.com
                  --tools email,files,database
                  --operator chiivy

    With expose mode for remediation:

        aist scan --target https://agent.example.com
                  --expose-evidence
    """
    setup_logging(log_level=log_level)
    print_banner()

    auth_cookie_name = None
    auth_cookie_value = None

    if target is None:
        wizard = run_interactive_wizard()
        if not wizard.get("proceed", False):
            sys.exit(0)
        target = wizard["target"]
        tools = wizard["tools"]
        categories = wizard["categories"]
        safe_mode = wizard["safe_mode"]
        operator = wizard["operator"]
        auth_type = wizard["auth_type"]
        auth_token = wizard["auth_token"]
        auth_header = wizard["auth_header"]
        auth_username = wizard["auth_username"]
        auth_password = wizard["auth_password"]
        auth_login_url = wizard["auth_login_url"]
        auth_tenant_id = wizard["auth_tenant_id"]
        auth_client_id = wizard["auth_client_id"]
        auth_cookie_name = wizard["auth_cookie_name"]
        auth_cookie_value = wizard["auth_cookie_value"]

    if expose_evidence:
        expose_evidence = confirm_expose_evidence()

    tools_list = [
        t.strip() for t in tools.split(",") if t.strip()
    ]

    categories_list = (
        None if categories == "all"
        else [
            c.strip().upper()
            for c in categories.split(",")
        ]
    )

    if output is None:
        timestamp = datetime.now().strftime(
            "%Y-%m-%d-%H-%M"
        )
        safe_target = re.sub(
            r'[^\w]', '-', target
        )[:30].strip("-")
        output = (
            f"reports/aist-{timestamp}-{safe_target}.html"
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
        f"[bold]Operator:[/bold] "
        f"{operator or 'Not specified'}\n"
    )

    if expose_evidence:
        console.print(
            "[bold red]Expose evidence mode active. "
            "Report will contain unmasked values.[/bold red]\n"
        )

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
        operator=operator,
    )

    config.auth.auth_type = auth_type
    config.auth.token = auth_token
    config.auth.header_name = auth_header or "Authorization"
    config.auth.username = auth_username
    config.auth.password = auth_password
    config.auth.login_url = auth_login_url
    config.auth.tenant_id = auth_tenant_id
    config.auth.client_id = auth_client_id
    if auth_cookie_value:
        config.auth.cookie_name = auth_cookie_name or "session"
        config.auth.cookie_value = auth_cookie_value
    config.scan.safe_mode = safe_mode

    log.info(
        "scan_command_started",
        target=target,
        tools=tools_list,
        mode=mode,
        runs=runs,
        operator=operator or "not_specified",
    )

    from aist.scanner.orchestrator import run_full_scan

    try:
        results = asyncio.run(
            run_full_scan(
                config=config,
                output_path=output,
            )
        )

        log.info(
            "scan_command_complete",
            total_findings=results["total_findings"],
            critical=results["critical"],
            canary_triggered=results["canary_triggered"],
            duration=results["duration_seconds"],
        )

        if results["critical"] > 0 or \
                results["canary_triggered"]:
            sys.exit(1)

    except KeyboardInterrupt:
        console.print(
            "\n[yellow]Scan interrupted by user.[/yellow]"
        )
        sys.exit(130)

    except Exception as e:
        console.print(
            f"\n[bold red]Scan failed:[/bold red] "
            f"{type(e).__name__}: {e}"
        )
        log.error(
            "scan_command_failed",
            error_type=type(e).__name__,
            error=str(e),
        )
        sys.exit(1)


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
    default=None,
    help="Output file path for surface map report."
)
@click.option(
    "--log-level", "-l",
    default="WARNING",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    help="Logging verbosity."
)
@click.option(
    "--operator",
    default=None,
    help="Name or handle of person running discovery."
)
@click.option("--auth-type",
    default="none",
    help="Auth type: none, bearer, basic, "
         "apikey, sso, cookie")
@click.option("--auth-token",
    default=None,
    help="Bearer token or API key")
@click.option("--auth-header",
    default="Authorization",
    help="Header name for token/apikey")
@click.option("--auth-username",
    default=None,
    help="Username for basic auth")
@click.option("--auth-password",
    default=None,
    help="Password for basic auth")
@click.option("--auth-login-url",
    default=None,
    help="Login endpoint for basic auth")
@click.option("--auth-tenant-id",
    default=None,
    help="Azure AD tenant ID for SSO")
@click.option("--auth-client-id",
    default=None,
    help="Azure AD client ID for SSO")
@click.option("--safe-mode",
    is_flag=True,
    default=False,
    help="Skip payload categories that "
         "could trigger real actions "
         "(E, H, V). Use on production "
         "or critical infrastructure.")

def discover(target, mode, output, log_level, operator):
    """
    Run attack surface discovery against a target
    agent without running any injection payloads.

    Safe to run against production agents in
    passive mode.

    Example:

        aist discover --target https://agent.example.com
                      --mode passive
    """
    setup_logging(log_level=log_level)
    print_banner()

    if output is None:
        timestamp = datetime.now().strftime(
            "%Y-%m-%d-%H-%M"
        )
        safe_target = re.sub(
            r'[^\w]', '-', target
        )[:30].strip("-")
        output = (
            f"reports/aist-discovery-"
            f"{timestamp}-{safe_target}.html"
        )

    console.print(f"\n[bold]Target:[/bold] {target}")
    console.print(f"[bold]Mode:[/bold] {mode}")
    console.print(f"[bold]Output:[/bold] {output}")
    console.print(
        f"[bold]Operator:[/bold] "
        f"{operator or 'Not specified'}\n"
    )

    config = load_config(
        target_endpoint=target,
        mode=mode,
        log_level=log_level,
        operator=operator,
    )

    log.info(
        "discover_command_started",
        target=target,
        mode=mode,
        operator=operator or "not_specified",
    )

    async def run_discovery_only():
        from aist.recon.probe import run_recon
        from aist.recon.discovery import run_discovery
        from aist.recon.fingerprint import run_fingerprinting

        console.print(
            "[dim]Running recon probes...[/dim]"
        )
        recon_report = await run_recon(config)

        console.print(
            "[dim]Mapping attack surface...[/dim]"
        )
        discovery_result = await run_discovery(
            config, recon_report
        )

        console.print(
            "[dim]Fingerprinting model...[/dim]"
        )
        fingerprint = await run_fingerprinting(
            config,
            initial_hint=recon_report.model_hint,
        )

        return recon_report, discovery_result, fingerprint

    try:
        recon_report, discovery_result, fingerprint = (
            asyncio.run(run_discovery_only())
        )

        console.print(
            "\n[bold]Attack Surface Map:[/bold]\n"
        )
        console.print(f"  Target:           {target}")
        console.print(
            f"  Model detected:   "
            f"{recon_report.model_hint}"
        )
        console.print(
            f"  Declared tools:   "
            f"{', '.join(recon_report.declared_tools) or 'none'}"
        )
        console.print(
            f"  Discovered tools: "
            f"{', '.join(recon_report.discovered_tools) or 'none'}"
        )
        console.print(
            f"  Has memory:       {recon_report.has_memory}"
        )
        console.print(
            f"  RAG detected:     "
            f"{getattr(discovery_result, 'rag_detected', False)}"
        )
        console.print(
            f"  SSRF potential:   "
            f"{getattr(discovery_result, 'ssrf_potential', False)}"
        )
        console.print(
            f"  Connected agents: "
            f"{getattr(discovery_result, 'connected_agents', [])}"
        )
        console.print(
            f"  Severity multiplier: "
            f"{getattr(discovery_result, 'severity_multiplier', 1.0)}x"
        )
        if operator:
            console.print(f"  Operator:         {operator}")

        log.info(
            "discover_command_complete",
            target=target,
            model=recon_report.model_hint,
            tools=recon_report.discovered_tools,
        )

    except KeyboardInterrupt:
        console.print(
            "\n[yellow]Discovery interrupted.[/yellow]"
        )
        sys.exit(130)

    except Exception as e:
        console.print(
            f"\n[bold red]Discovery failed:[/bold red] "
            f"{type(e).__name__}: {e}"
        )
        log.error(
            "discover_command_failed",
            error_type=type(e).__name__,
            error=str(e),
        )
        sys.exit(1)


if __name__ == "__main__":
    main()