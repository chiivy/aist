"""
AIST Configuration Module

Loads and validates all configuration from environment
variables. All credentials and settings are read from
here. No credentials anywhere else in the codebase.
"""

import os
import json as _json
import uuid
from dataclasses import dataclass, field
from typing import Optional
from dotenv import load_dotenv
from aist.auth.manager import AuthConfig

from aist.logger import get_logger

log = get_logger(__name__)

# Load .env file if it exists
load_dotenv()

GOAL_CATEGORY_MAP = {
    "exfiltrate": ["D", "I", "C"],
    "abuse-tools": ["E", "H", "BL"],
    "bypass-controls": ["B", "G", "F"],
    "business-logic": ["BL", "D"],
    "multi-agent": ["MA", "S", "I"],
    "infrastructure": ["J"],
    "reconnaissance": ["D", "GEN"],
    "full": None,
}

GOAL_DESCRIPTIONS = {
    "exfiltrate": "Exfiltrate sensitive internal data",
    "abuse-tools": "Abuse external tool integrations",
    "bypass-controls": "Override system and safety controls",
    "business-logic": "Manipulate business logic and workflows",
    "multi-agent": "Exploit multi-agent architectures",
    "infrastructure": "Identify infrastructure misconfigurations",
    "reconnaissance": "Map attack surface and capabilities",
    "full": "Full assessment across all attack vectors",
}


@dataclass
class ScanConfig:
    """
    Scan behaviour settings.
    """
    max_scans_per_hour: int = 10
    max_payload_runs: int = 3
    response_size_limit_kb: int = 500
    scan_timeout_seconds: int = 300
    log_level: str = "WARNING"
    reports_dir: str = "reports"
    logs_dir: str = "logs"
    expose_evidence: bool = False
    executive_mode: bool = False
    categories: Optional[list] = None
    goals: Optional[list] = None
    jitter_min_seconds: float = 1.0
    jitter_max_seconds: float = 5.0
    rotate_session_between_runs: bool = True
    backoff_on_rate_limit: bool = True
    operator: Optional[str] = None
    organisation: Optional[str] = None
    safe_mode: bool = False
    max_followup_depth: int = 3
    followup_enabled: bool = True
    redacted_mode: bool = False
    local_judge: bool = False
    local_judge_url: str = "http://localhost:11434"
    local_judge_model: str = "llama3.1:8b"
    # Cloud validation model (separate from payload-generation LLM).
    judge_model: str = "claude-haiku-4-5-20251001"
    profile: str = "standard"
    adaptive_recon: bool = True
    multiturn_enabled: bool = False
    payload_summary: str = "~100"
    gen_enabled: bool = True
    fail_on: Optional[str] = None
    notify_slack: Optional[str] = None
    notify_email: Optional[str] = None
    siem_export_enabled: bool = True
    siem_formats: list = field(
        default_factory=lambda: ["cef", "splunk"]
    )
    splunk_hec_url: Optional[str] = None
    splunk_hec_token: Optional[str] = None
    scan_id: str = field(
        default_factory=lambda: uuid.uuid4().hex[:8]
    )
    scan_delay: float = 1.0
    bypass_validation: bool = False


@dataclass
class TargetConfig:
    """
    Target agent connection settings.
    """
    endpoint: str = ""
    api_key: Optional[str] = None
    tools: list = field(default_factory=list)
    mode: str = "active"
    message_field: str = "message"
    custom_body_fields: dict = field(
        default_factory=dict
    )
    custom_headers: dict = field(
        default_factory=dict
    )
    response_field: str = ""
    response_type: str = "json"
    streaming: bool = False
    app_context: str = ""
    # Optional description of what the target
    # agent does, its purpose, what data it
    # has access to, and what it should never do.
    # Used to generate more targeted payloads.


@dataclass
class LLMConfig:
    """
    LLM API settings for AIST response analysis.
    AIST uses an LLM internally to analyse whether
    injection attempts succeeded.

    Without an API key AIST falls back to
    string matching only. Detection accuracy
    is reduced but the tool still functions.
    """
    provider: str = "anthropic"
    api_key: Optional[str] = None
    model: str = "claude-sonnet-4-6"
    enabled: bool = False


@dataclass
class SIEMConfig:
    """
    Optional SIEM integration settings.
    """
    endpoint: Optional[str] = None
    api_key: Optional[str] = None
    enabled: bool = False


@dataclass
class CanaryConfig:
    """
    Canary infrastructure settings.

    Canaries detect when an injection succeeded
    by monitoring whether the agent contacted
    a resource the tester controls, or whether
    a planted policy was overridden.

    All canary fields are optional. Without canary
    config AIST uses LLM judge analysis only.
    See docs/canary_setup.md for setup options.
    """
    url: Optional[str] = None
    email: Optional[str] = None
    domain: Optional[str] = None
    test_admin_id: str = "AIST-TEST-ADMIN-001"
    test_user_id: str = "AIST-TEST-USER-001"
    enabled: bool = False
    behavioral_canaries_planted: bool = False
    canary_configured: bool = False


@dataclass
class AISTConfig:
    """
    Master configuration object.
    Passed to all AIST modules at runtime.
    """
    scan: ScanConfig = field(default_factory=ScanConfig)
    target: TargetConfig = field(default_factory=TargetConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    siem: SIEMConfig = field(default_factory=SIEMConfig)
    canary: CanaryConfig = field(default_factory=CanaryConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)


def resolve_goals_to_categories(
    goal_list: list[str],
) -> Optional[list[str]]:
    """
    Map attack goals to payload category codes.

    Returns None when any goal resolves to a full scan
    (e.g. ``full``). Returns an empty list when no valid
    goals were provided.
    """
    resolved: set[str] = set()
    for goal in goal_list:
        if goal not in GOAL_CATEGORY_MAP:
            continue
        cats = GOAL_CATEGORY_MAP[goal]
        if cats is None:
            return None
        resolved.update(cats)
    return sorted(resolved) if resolved else []


def apply_goals_to_config(
    config: "AISTConfig",
    goals_str: str,
    warn_unknown: bool = True,
) -> list[str]:
    """
    Resolve a comma-separated goals string onto scan config.

    Sets ``config.scan.goals`` and ``config.scan.categories``.
    """
    goal_list = [
        g.strip() for g in goals_str.split(",") if g.strip()
    ]
    config.scan.goals = goal_list
    resolved_categories: Optional[set[str]] = set()

    for goal in goal_list:
        if goal in GOAL_CATEGORY_MAP:
            cats = GOAL_CATEGORY_MAP[goal]
            if cats is None:
                config.scan.categories = None
                return goal_list
            resolved_categories.update(cats)
        elif warn_unknown:
            log.warning(
                "unknown_scan_goal",
                goal=goal,
                valid_goals=list(GOAL_CATEGORY_MAP.keys()),
            )

    if resolved_categories is not None:
        config.scan.categories = sorted(resolved_categories)

    return goal_list


def load_config(
    target_endpoint: str = None,
    tools: list = None,
    mode: str = "active",
    runs: int = None,
    log_level: str = None,
    output_dir: str = None,
    siem_endpoint: str = None,
    expose_evidence: bool = False,
    executive_mode: bool = False,
    categories: list = None,
    goals: str = None,
    operator: str = None,
) -> AISTConfig:
    """
    Load configuration from environment variables
    and override with any CLI arguments provided.

    Degrades gracefully when optional config is missing:
    - No LLM API key: string matching only, warns user
    - No canary config: LLM judge only, warns user
    - No target API key: tries unauthenticated first
    - No SIEM endpoint: logs to local files only

    Args:
        target_endpoint: Target agent URL
        tools:           List of agent tools declared
        mode:            Scan mode (passive or active)
        runs:            Number of times to run each payload
        log_level:       Logging verbosity
        output_dir:      Directory for reports
        siem_endpoint:   Optional SIEM endpoint URL
        expose_evidence: Include unmasked values in report
        executive_mode:  Generate executive report only
        categories:      List of payload categories to run
        operator:        Name/handle of person running scan

    Returns:
        Populated AISTConfig object
    """
    config = AISTConfig()

    # Scan settings from env with CLI overrides
    config.scan.log_level = (
        log_level or
        os.getenv("LOG_LEVEL", "WARNING")
    )
    config.scan.max_payload_runs = (
        runs or
        int(os.getenv("MAX_PAYLOAD_RUNS", "3"))
    )
    config.scan.max_scans_per_hour = int(
        os.getenv("MAX_SCANS_PER_HOUR", "10")
    )
    config.scan.response_size_limit_kb = int(
        os.getenv("RESPONSE_SIZE_LIMIT_KB", "500")
    )
    config.scan.scan_timeout_seconds = int(
        os.getenv("SCAN_TIMEOUT_SECONDS", "300")
    )
    config.scan.reports_dir = (
        output_dir or
        os.getenv("REPORTS_DIR", "reports")
    )
    config.scan.logs_dir = os.getenv("LOGS_DIR", "logs")
    config.scan.expose_evidence = expose_evidence
    config.scan.executive_mode = executive_mode
    config.scan.categories = categories

    effective_goals = goals or (
        os.getenv("AIST_GOALS")
        if categories is None and goals is None
        else None
    )
    if effective_goals:
        apply_goals_to_config(config, effective_goals)

    # Operator / audit trail
    config.scan.operator = (
        operator or
        os.getenv("AIST_OPERATOR", "Not specified")
    )
    config.scan.organisation = os.getenv(
        "AIST_ORGANISATION", ""
    )

    config.scan.max_followup_depth = int(
        os.getenv("AIST_MAX_FOLLOWUP_DEPTH", "3")
    )
    config.scan.followup_enabled = (
        os.getenv(
            "AIST_FOLLOWUP_ENABLED", "true"
        ).lower() == "true"
    )
    # AIST_REDACTED retained as a no-op; redacted
    # report is always generated by the orchestrator.
    # AIST_AI_REVIEW accepted as a legacy alias.
    config.scan.redacted_mode = (
        os.getenv(
            "AIST_REDACTED",
            os.getenv("AIST_AI_REVIEW", "false"),
        ).lower()
        == "true"
    )
    config.scan.local_judge = (
        os.getenv("AIST_LOCAL_JUDGE", "false").lower()
        == "true"
    )
    config.scan.local_judge_url = os.getenv(
        "AIST_LOCAL_JUDGE_URL",
        "http://localhost:11434",
    )
    config.scan.local_judge_model = os.getenv(
        "AIST_LOCAL_JUDGE_MODEL",
        "llama3.1:8b",
    )
    # Haiku is the default judge: fast and low cost.
    # Sonnet (e.g. claude-sonnet-4-6) is available via
    # AIST_JUDGE_MODEL but costs significantly more.
    config.scan.judge_model = os.getenv(
        "AIST_JUDGE_MODEL",
        "claude-haiku-4-5-20251001",
    )
    config.scan.splunk_hec_url = os.getenv("SPLUNK_HEC_URL")
    config.scan.splunk_hec_token = os.getenv(
        "SPLUNK_HEC_TOKEN"
    )

    # Jitter settings
    config.scan.jitter_min_seconds = float(
        os.getenv("JITTER_MIN_SECONDS", "1.0")
    )
    config.scan.jitter_max_seconds = float(
        os.getenv("JITTER_MAX_SECONDS", "5.0")
    )
    config.scan.rotate_session_between_runs = (
        os.getenv(
            "ROTATE_SESSION_BETWEEN_RUNS", "true"
        ).lower() == "true"
    )
    config.scan.backoff_on_rate_limit = (
        os.getenv(
            "BACKOFF_ON_RATE_LIMIT", "true"
        ).lower() == "true"
    )
    config.scan.safe_mode = os.getenv(
        "AIST_SAFE_MODE", "false"
    ).lower() == "true"

    config.scan.scan_delay = float(
        os.getenv("AIST_SCAN_DELAY", "1.0")
    )
    if config.scan.safe_mode:
        config.scan.scan_delay = float(
            os.getenv("AIST_SCAN_DELAY", "3.0")
        )

    config.scan.bypass_validation = os.getenv(
        "AIST_BYPASS_VALIDATION", "false"
    ).lower() == "true"

    # Target config
    config.target.endpoint = (
        target_endpoint or
        os.getenv("TARGET_ENDPOINT", "")
    )
    config.target.api_key = os.getenv("TARGET_API_KEY")
    config.target.tools = tools or []
    config.target.mode = mode

    config.target.message_field = os.getenv(
        "AIST_MESSAGE_FIELD", "message"
    )

    try:
        config.target.custom_body_fields = _json.loads(
            os.getenv("AIST_CUSTOM_BODY_FIELDS", "{}")
        )
    except _json.JSONDecodeError:
        config.target.custom_body_fields = {}

    try:
        config.target.custom_headers = _json.loads(
            os.getenv("AIST_CUSTOM_HEADERS", "{}")
        )
    except _json.JSONDecodeError:
        config.target.custom_headers = {}

    config.target.response_field = os.getenv(
        "AIST_RESPONSE_FIELD", ""
    )
    config.target.response_type = os.getenv(
        "AIST_RESPONSE_TYPE", "json"
    )
    config.target.app_context = os.getenv(
        "AIST_APP_CONTEXT", ""
    )

    if not config.target.api_key:
        log.info(
            "no_target_api_key",
            message="No target API key configured. "
                    "AIST will try unauthenticated requests."
        )

    # LLM config for response analysis
    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    openai_key = os.getenv("OPENAI_API_KEY")

    if anthropic_key:
        config.llm.api_key = anthropic_key
        config.llm.provider = "anthropic"
        config.llm.enabled = True
    elif openai_key:
        config.llm.api_key = openai_key
        config.llm.provider = "openai"
        config.llm.enabled = True
    else:
        config.llm.enabled = False
        log.warning(
            "no_llm_api_key",
            message="No LLM API key found. "
                    "Set ANTHROPIC_API_KEY or OPENAI_API_KEY in .env. "
                    "AIST will use string matching only. "
                    "Detection accuracy is reduced."
        )

    # Canary config (V1-V5 exfiltration destinations)
    canary_url = os.getenv("AIST_CANARY_URL")
    canary_email = os.getenv("AIST_CANARY_EMAIL")
    canary_domain = os.getenv("AIST_CANARY_DOMAIN")
    scan_id = config.scan.scan_id

    if any([canary_url, canary_email, canary_domain]):
        config.canary.url = canary_url
        config.canary.email = canary_email
        config.canary.domain = canary_domain
        config.canary.enabled = True
        config.canary.canary_configured = True
        log.info(
            "canary_configured",
            url=bool(canary_url),
            email=bool(canary_email),
            domain=bool(canary_domain),
        )
    else:
        config.canary.url = (
            f"http://aist-placeholder-{scan_id}.example.com"
        )
        config.canary.email = (
            f"aist-test-{scan_id}@placeholder.com"
        )
        config.canary.enabled = False
        config.canary.canary_configured = False
        log.info(
            "no_canary_config",
            message="No canary configuration found. "
                    "String matching only for tool abuse. "
                    "Set AIST_CANARY_EMAIL in .env for "
                    "external confirmation.",
        )

    # CT2/CT3/CT4 behavioural canaries require manually
    # adding policies to the target agent's system prompt
    # before scanning. See docs/canary_setup.md
    config.canary.behavioral_canaries_planted = (
        os.getenv(
            "AIST_CANARIES_PLANTED", "false"
        ).lower() == "true"
    )

    # Test identity values with defaults
    config.canary.test_admin_id = os.getenv(
        "AIST_TEST_ADMIN_ID",
        "AIST-TEST-ADMIN-001"
    )
    config.canary.test_user_id = os.getenv(
        "AIST_TEST_USER_ID",
        "AIST-TEST-USER-001"
    )

    # SIEM config
    siem_url = siem_endpoint or os.getenv("SIEM_ENDPOINT")
    if siem_url:
        config.siem.endpoint = siem_url
        config.siem.api_key = os.getenv("SIEM_API_KEY")
        config.siem.enabled = True
        log.info(
            "siem_configured",
            endpoint=siem_url,
        )

    # Validate required fields
    if not config.target.endpoint:
        log.warning(
            "no_target_endpoint",
            message="No target endpoint configured. "
                    "Provide via --target flag."
        )

    # Auth config
    config.auth = AuthConfig(
        auth_type=os.getenv(
            "AIST_AUTH_TYPE", "none"
        ),
        token=os.getenv("AIST_AUTH_TOKEN"),
        header_name=os.getenv(
            "AIST_AUTH_HEADER", "Authorization"
        ),
        username=os.getenv("AIST_AUTH_USERNAME"),
        password=os.getenv("AIST_AUTH_PASSWORD"),
        login_url=os.getenv("AIST_AUTH_LOGIN_URL"),
        tenant_id=os.getenv("AIST_AUTH_TENANT_ID"),
        client_id=os.getenv("AIST_AUTH_CLIENT_ID"),
        cookie_name=os.getenv(
            "AIST_AUTH_COOKIE_NAME", "session"
        ),
        cookie_value=os.getenv(
            "AIST_AUTH_COOKIE_VALUE"
        ),
        browser_target_url=os.getenv(
            "AIST_AUTH_LOGIN_URL", ""
        ),
    )
    # Create output directories if they do not exist
    os.makedirs(config.scan.reports_dir, exist_ok=True)
    os.makedirs(config.scan.logs_dir, exist_ok=True)

    # Log configuration summary
    log.info(
        "config_loaded",
        target=config.target.endpoint,
        mode=config.target.mode,
        tools=config.target.tools,
        runs=config.scan.max_payload_runs,
        llm_enabled=config.llm.enabled,
        llm_provider=(
            config.llm.provider
            if config.llm.enabled
            else "none"
        ),
        canary_enabled=config.canary.enabled,
        behavioral_canaries_planted=(
            config.canary.behavioral_canaries_planted
        ),
        siem_enabled=config.siem.enabled,
        expose_evidence=config.scan.expose_evidence,
        executive_mode=config.scan.executive_mode,
        categories=config.scan.categories or "all",
        jitter_min=config.scan.jitter_min_seconds,
        jitter_max=config.scan.jitter_max_seconds,
        operator=config.scan.operator,
    )

    return config


def resolve_canary_variables(
    text: str,
    config: AISTConfig,
) -> str:
    """
    Replace canary placeholder variables in payload
    text with configured canary values.

    Called by scanner modules before sending payloads.

    If canary is not configured, replaces variables
    with clearly labelled placeholder values so the
    payload still runs but without real canary detection.

    Args:
        text:   Payload text containing {{VARIABLE}} placeholders
        config: AIST configuration with canary values

    Returns:
        Payload text with variables resolved
    """
    replacements = {
        "{{AIST_CANARY_EMAIL}}": (
            config.canary.email or
            "aist-test-canary@example.com"
        ),
        "{{AIST_CANARY_URL}}": (
            config.canary.url or
            "https://aist-canary-not-configured.example.com"
        ),
        "{{AIST_CANARY_DOMAIN}}": (
            config.canary.domain or
            "aist-canary-not-configured.example.com"
        ),
        "{{AIST_TEST_ADMIN_ID}}": config.canary.test_admin_id,
        "{{AIST_TEST_USER_ID}}": config.canary.test_user_id,
    }

    for placeholder, value in replacements.items():
        text = text.replace(placeholder, value)

    return text