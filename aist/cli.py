"""
AIST Command Line Interface

Entry point for all AIST commands.

Commands:
    aist scan       Run a full security scan
    aist discover   Run attack surface discovery only
"""

import asyncio
import json as _json
import re
import sys
from datetime import datetime
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel

from aist.config import (
    GOAL_CATEGORY_MAP,
    GOAL_DESCRIPTIONS,
    load_config,
)
from aist.logger import get_logger, setup_logging

console = Console()
log = get_logger(__name__)


def print_testing_goals(goal_list: list[str]) -> None:
    """Print a summary of attack goals and mapped categories."""
    console.print("\n[bold]Testing Goals:[/bold]")
    for goal in goal_list:
        if goal in GOAL_DESCRIPTIONS:
            cats = GOAL_CATEGORY_MAP.get(goal, [])
            cat_str = (
                "all categories"
                if cats is None
                else f"categories {', '.join(cats)}"
            )
            console.print(
                f"  [cyan]{goal}[/cyan]: "
                f"{GOAL_DESCRIPTIONS[goal]} "
                f"[dim]({cat_str})[/dim]"
            )
    console.print()


def apply_cli_goals(
    config,
    goals_str: str,
) -> None:
    """Resolve CLI goals and warn about unknown goal names."""
    goal_list = [
        g.strip() for g in goals_str.split(",") if g.strip()
    ]
    resolved_categories: Optional[set[str]] = set()

    for goal in goal_list:
        if goal in GOAL_CATEGORY_MAP:
            cats = GOAL_CATEGORY_MAP[goal]
            if cats is None:
                config.scan.categories = None
                config.scan.goals = goal_list
                print_testing_goals(goal_list)
                return
            resolved_categories.update(cats)
        else:
            console.print(
                f"[yellow]Unknown goal: {goal}. "
                f"Valid goals: "
                f"{', '.join(GOAL_CATEGORY_MAP.keys())}"
                f"[/yellow]"
            )

    config.scan.goals = goal_list
    if resolved_categories is not None:
        config.scan.categories = sorted(resolved_categories)

    print_testing_goals(goal_list)


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

    console.print("""
Authentication options:
  none    - No authentication required
  bearer  - Paste a Bearer token
  basic   - Username and password
  apikey  - API key in header
  sso     - Azure AD device code flow
  cookie  - Session cookie
  browser - Log in via browser (recommended
            for SSO, MFA, complex auth)
""")

    auth_type = click.prompt(
        "Authentication type",
        type=click.Choice([
            "none", "bearer", "basic",
            "apikey", "sso", "cookie", "browser",
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
    elif auth_type == "browser":
        auth_login_url = click.prompt(
            "App URL to open in browser",
            default=target,
        )
        console.print(
            "[dim]A browser will open when "
            "the scan starts. Log in and send "
            "one test message, then return here.[/dim]"
        )

    message_field = "message"
    custom_body_fields: dict = {}
    custom_headers: dict = {}
    response_field = ""

    does_app_need_custom_format = click.confirm(
        "\nDoes the target app require a specific "
        "request format beyond the standard "
        '{"message": "..."} body?',
        default=False,
    )

    if does_app_need_custom_format:
        console.print(
            """
[dim]
Some enterprise apps require additional fields
in the request body. For example:
  {"message": "...", "session_id": "abc",
   "username": "Ivy", "token": "xyz"}

You can find these by checking the Network tab
in browser DevTools while using the app.
Click on a chat request and look at the
Payload tab to see all required fields.
[/dim]
"""
        )

        message_field = click.prompt(
            "What is the field name for the message?",
            default="message",
            show_default=True,
        )
        console.print(
            "[dim]Common values: message, query, "
            "input, prompt, content, text[/dim]"
        )

        extra_fields_json = click.prompt(
            "\nAny extra body fields? "
            "Enter as JSON or leave blank",
            default="",
        )

        if extra_fields_json.strip():
            try:
                custom_body_fields = _json.loads(
                    extra_fields_json
                )
                console.print(
                    f"[green]✓ Extra fields configured: "
                    f"{list(custom_body_fields.keys())}[/green]"
                )
            except _json.JSONDecodeError:
                console.print(
                    "[yellow]Could not parse JSON. "
                    "Skipping extra fields.[/yellow]"
                )

        custom_headers_json = click.prompt(
            "\nAny extra request headers? "
            "Enter as JSON or leave blank",
            default="",
        )

        if custom_headers_json.strip():
            try:
                custom_headers = _json.loads(
                    custom_headers_json
                )
                console.print(
                    f"[green]✓ Custom headers configured: "
                    f"{list(custom_headers.keys())}[/green]"
                )
            except _json.JSONDecodeError:
                console.print(
                    "[yellow]Could not parse JSON. "
                    "Skipping custom headers.[/yellow]"
                )

        response_field = click.prompt(
            "What JSON field contains the response? "
            "(leave blank to auto-detect)",
            default="",
        )
        if response_field.strip():
            console.print(
                f"[green]✓ Will read response "
                f"from '{response_field}' field[/green]"
            )
        else:
            response_field = ""

        streams_response = click.confirm(
            "Does the app stream its responses? "
            "(Server-Sent Events / SSE format)",
            default=False,
        )
        if streams_response:
            console.print(
                "[dim]AIST will automatically detect "
                "and parse streamed responses.[/dim]"
            )

    tools = click.prompt(
        "Tools declared on this agent "
        "(comma separated, or leave blank)",
        default="",
    )

    console.print("""
[dim]
Providing a description of your AI agent
helps AIST generate more targeted and
relevant test payloads.

Example descriptions:
  "Customer service agent for AcmeCorp.
   Handles order queries and refunds up to $500.
   Should never reveal other customers' data."

  "Diesel forecast agent for telecom infrastructure.
   Has read access to fuel data for 2000+ sites.
   Should only return data for authorised regions."

  "Internal HR assistant. Has access to employee
   records, salaries, and performance reviews.
   Should only show the requesting employee's data."
[/dim]
""")

    app_context = click.prompt(
        "Describe what this agent does (optional)",
        default="",
    )

    if app_context:
        console.print(
            "[green]✓ Application context saved. "
            "AIST will generate targeted payloads "
            "based on this description.[/green]"
        )

    testing_mode = click.prompt(
        "\nTesting approach",
        type=click.Choice(["goals", "categories", "all"]),
        default="goals",
    )
    goals = None

    if testing_mode == "goals":
        console.print("""
[dim]Available goals:
  exfiltrate      Exfiltrate sensitive internal data
  abuse-tools     Abuse external tool integrations
  bypass-controls Override system and safety controls
  business-logic  Manipulate business logic
  multi-agent     Exploit multi-agent architectures
  infrastructure  Infrastructure misconfigurations
  reconnaissance  Map attack surface
  full            Complete assessment[/dim]
""")
        goals = click.prompt(
            "Goals to test (comma separated)",
            default="full",
        )
        goal_list = [g.strip() for g in goals.split(",")]
        resolved: Optional[set[str]] = set()
        for goal in goal_list:
            if goal not in GOAL_CATEGORY_MAP:
                console.print(
                    f"[yellow]Unknown goal: {goal}. "
                    f"Valid goals: "
                    f"{', '.join(GOAL_CATEGORY_MAP.keys())}"
                    f"[/yellow]"
                )
                continue
            cats = GOAL_CATEGORY_MAP[goal]
            if cats is None:
                resolved = None
                break
            resolved.update(cats)

        if resolved is not None:
            categories = ",".join(sorted(resolved))
        else:
            categories = "all"

    elif testing_mode == "categories":
        run_all = click.confirm(
            "Run all payload categories?",
            default=True,
        )
        if run_all:
            categories = "all"
        else:
            categories = click.prompt(
                "Categories to run (comma separated)",
                default="D",
            )

    else:
        categories = "all"

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
    goals_display = goals if goals else None

    console.print("\n[bold]Scan summary:[/bold]")
    console.print(f"  Target:       {target}")
    console.print(f"  Auth:         {auth_type}")
    if message_field != "message":
        console.print(
            f"  Message field:  "
            f"[cyan]{message_field}[/cyan]"
        )
    if custom_body_fields:
        console.print(
            f"  Extra fields:   "
            f"[cyan]{list(custom_body_fields.keys())}[/cyan]"
        )
    if custom_headers:
        console.print(
            f"  Custom headers: "
            f"[cyan]{list(custom_headers.keys())}[/cyan]"
        )
    if response_field:
        console.print(
            f"  Response field: "
            f"[cyan]{response_field}[/cyan]"
        )
    console.print(
        f"  Tools:        "
        f"{', '.join(tools_list) if tools_list else 'none'}"
    )
    if app_context:
        preview = (
            app_context[:60] + "..."
            if len(app_context) > 60
            else app_context
        )
        console.print(f"  App context:  {preview}")
    if goals_display:
        console.print(f"  Goals:        {goals_display}")
    else:
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
        "goals": goals,
        "app_context": app_context,
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
        "message_field": message_field,
        "custom_body_fields": custom_body_fields,
        "custom_headers": custom_headers,
        "response_field": response_field,
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
         "Omit to launch interactive setup wizard, "
         "or when using --auth-type browser to capture "
         "the endpoint from your browser session."
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
    "--goals",
    default=None,
    help="Attack goals to test. Comma separated. "
         "Options: exfiltrate, abuse-tools, "
         "bypass-controls, business-logic, "
         "multi-agent, infrastructure, "
         "reconnaissance, full. "
         "Alternative to --categories for "
         "goal-oriented testing.",
)
@click.option(
    "--operator",
    default=None,
    help="Name or handle of person running the scan. "
         "Appears in report for audit purposes. "
         "Can also be set via AIST_OPERATOR in .env"
)
@click.option(
    "--auth-type",
    default="none",
    type=click.Choice([
        "none", "bearer", "basic",
        "apikey", "sso", "cookie", "browser",
    ]),
    help="Auth type. Use 'browser' for SSO, "
         "MFA, or any browser-based login. "
         "AIST opens a browser for you to "
         "log in normally.",
)
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
@click.option(
    "--message-field",
    default=None,
    help="Request body field name for the message. "
         "Default: message. Some apps use: "
         "query, input, prompt, content, text.",
)
@click.option(
    "--body-fields",
    default=None,
    help="Additional request body fields as JSON. "
         "Example: "
         '{\"session_id\": \"abc\", '
         '\"username\": \"test\"}',
)
@click.option(
    "--custom-headers",
    default=None,
    help="Additional request headers as JSON. "
         "Example: "
         '{\"X-Tenant-ID\": \"abc\"}',
)
@click.option(
    "--response-field",
    default=None,
    help="JSON field containing agent response. "
         "Auto-detected if not specified. "
         "Common values: response, answer, "
         "message, content, output, text",
)
@click.option(
    "--no-followup",
    is_flag=True,
    default=False,
    help="Disable iterative follow-up probing. "
         "Follow-up is enabled by default and "
         "pursues partial findings up to 3 turns.",
)
@click.option(
    "--app-context",
    default=None,
    help="Optional description of the target "
         "agent: its purpose, data access, "
         "and what it should protect. "
         "Improves payload targeting accuracy. "
         'Example: "Diesel forecast agent for '
         "telecom sites. Has database access "
         "to fuel levels for 2000+ sites. "
         'Should only show data for authorised sites."',
)
@click.option(
    "--reuse-session",
    is_flag=True,
    default=False,
    help="Reuse the last saved browser session "
         "without opening a new browser window. "
         "Session must not have expired.",
)
@click.option(
    "--session-file",
    default=".aist_session.json",
    help="Path to saved session file. "
         "Default: .aist_session.json",
)
@click.option(
    "--ai-review",
    is_flag=True,
    default=False,
    help="Generate a sanitised AI review report "
         "alongside the main report. Masks emails, "
         "tokens, names, and internal IPs. Safe "
         "for sharing with AI assistants or "
         "third-party reviewers.",
)
def scan(
    target, tools, output, mode, runs,
    log_level, siem, expose_evidence,
    executive, categories, goals, operator,
    auth_type, auth_token, auth_header,
    auth_username, auth_password, auth_login_url,
    auth_tenant_id, auth_client_id, safe_mode,
    message_field, body_fields, custom_headers,
    response_field, no_followup, app_context,
    reuse_session, session_file, ai_review,
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
    wizard_message_field = None
    wizard_body_fields = None
    wizard_custom_headers = None
    wizard_response_field = None
    wizard_goals = None
    wizard_app_context = None

    if target is None and auth_type != "browser":
        wizard = run_interactive_wizard()
        if not wizard.get("proceed", False):
            sys.exit(0)
        target = wizard["target"]
        tools = wizard["tools"]
        categories = wizard["categories"]
        wizard_goals = wizard.get("goals")
        wizard_app_context = wizard.get("app_context")
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
        wizard_message_field = wizard.get("message_field")
        wizard_body_fields = wizard.get("custom_body_fields")
        wizard_custom_headers = wizard.get("custom_headers")
        wizard_response_field = wizard.get("response_field")
    elif target is None and auth_type == "browser":
        console.print(
            "\n[bold]Browser authentication mode[/bold]"
        )
        console.print(
            "[dim]Target endpoint will be captured from "
            "your browser session after login.[/dim]\n"
        )

    if expose_evidence:
        expose_evidence = confirm_expose_evidence()

    effective_goals = goals or wizard_goals

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
            r'[^\w]', '-', target or "browser-captured"
        )[:30].strip("-")
        output = (
            f"reports/aist-{timestamp}-{safe_target}.html"
        )

    if target:
        console.print(f"\n[bold]Target:[/bold] {target}")
    else:
        console.print(
            "\n[bold]Target:[/bold] "
            "[dim](captured from browser session)[/dim]"
        )
    console.print(
        f"[bold]Tools declared:[/bold] "
        f"{', '.join(tools_list) if tools_list else 'none'}"
    )
    console.print(f"[bold]Mode:[/bold] {mode}")
    console.print(f"[bold]Payload runs:[/bold] {runs}")
    if effective_goals:
        console.print(f"[bold]Goals:[/bold] {effective_goals}")
    else:
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
        categories=(
            None if effective_goals and categories == "all"
            else categories_list
        ),
        goals=None,
        operator=operator,
    )

    if effective_goals and not categories_list:
        apply_cli_goals(config, effective_goals)
    elif wizard_goals:
        config.scan.goals = [
            g.strip() for g in wizard_goals.split(",") if g.strip()
        ]

    config.auth.auth_type = auth_type
    config.auth.token = auth_token
    config.auth.header_name = auth_header or "Authorization"
    config.auth.username = auth_username
    config.auth.password = auth_password
    config.auth.login_url = auth_login_url
    config.auth.tenant_id = auth_tenant_id
    config.auth.client_id = auth_client_id
    if auth_type == "browser":
        config.auth.browser_target_url = (
            auth_login_url or target or ""
        )

    if reuse_session:
        config.auth.reuse_session = True
        config.auth.session_file = session_file
        config.auth.auth_type = "browser"

    if auth_cookie_value:
        config.auth.cookie_name = auth_cookie_name or "session"
        config.auth.cookie_value = auth_cookie_value
    config.scan.safe_mode = safe_mode

    if no_followup:
        config.scan.followup_enabled = False

    if ai_review:
        config.scan.ai_review_mode = True

    effective_app_context = app_context or wizard_app_context
    if effective_app_context:
        config.target.app_context = effective_app_context

    if message_field:
        config.target.message_field = message_field
    elif wizard_message_field:
        config.target.message_field = wizard_message_field

    if body_fields:
        try:
            config.target.custom_body_fields = (
                _json.loads(body_fields)
            )
        except _json.JSONDecodeError:
            console.print(
                "[red]Invalid JSON in --body-fields. "
                "Use format: "
                '{\"key\": \"value\"}[/red]'
            )
    elif wizard_body_fields:
        config.target.custom_body_fields = wizard_body_fields

    if custom_headers:
        try:
            config.target.custom_headers = (
                _json.loads(custom_headers)
            )
        except _json.JSONDecodeError:
            console.print(
                "[red]Invalid JSON in --custom-headers. "
                "Use format: "
                '{\"key\": \"value\"}[/red]'
            )
    elif wizard_custom_headers:
        config.target.custom_headers = wizard_custom_headers

    if response_field:
        config.target.response_field = response_field
    elif wizard_response_field:
        config.target.response_field = wizard_response_field

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