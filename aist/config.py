"""
AIST Configuration Module

Loads and validates all configuration from environment
variables. All credentials and settings are read from
here. No credentials anywhere else in the codebase.
"""

import os
from dataclasses import dataclass, field
from typing import Optional
from dotenv import load_dotenv

from aist.logger import get_logger

log = get_logger(__name__)

# Load .env file if it exists
load_dotenv()


@dataclass
class ScanConfig:
    """
    Scan behaviour settings.
    """
    max_scans_per_hour: int = 10
    max_payload_runs: int = 3
    response_size_limit_kb: int = 500
    scan_timeout_seconds: int = 300
    log_level: str = "INFO"
    reports_dir: str = "reports"
    logs_dir: str = "logs"


@dataclass
class TargetConfig:
    """
    Target agent connection settings.
    """
    endpoint: str = ""
    api_key: Optional[str] = None
    tools: list = field(default_factory=list)
    mode: str = "active"


@dataclass
class LLMConfig:
    """
    LLM API settings for AIST response analysis.
    AIST uses an LLM internally to analyse whether
    injection attempts succeeded.
    """
    provider: str = "anthropic"
    api_key: Optional[str] = None
    model: str = "claude-sonnet-4-6"


@dataclass
class SIEMConfig:
    """
    Optional SIEM integration settings.
    """
    endpoint: Optional[str] = None
    api_key: Optional[str] = None
    enabled: bool = False


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


def load_config(
    target_endpoint: str = None,
    tools: list = None,
    mode: str = "active",
    runs: int = None,
    log_level: str = None,
    output_dir: str = None,
    siem_endpoint: str = None,
) -> AISTConfig:
    """
    Load configuration from environment variables
    and override with any CLI arguments provided.

    Args:
        target_endpoint: Target agent URL
        tools:           List of agent tools declared
        mode:            Scan mode (passive or active)
        runs:            Number of times to run each payload
        log_level:       Logging verbosity
        output_dir:      Directory for reports
        siem_endpoint:   Optional SIEM endpoint URL

    Returns:
        Populated AISTConfig object
    """
    config = AISTConfig()

    # Scan settings from env with CLI overrides
    config.scan.log_level = (
        log_level or
        os.getenv("LOG_LEVEL", "INFO")
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

    # Target config
    config.target.endpoint = (
        target_endpoint or
        os.getenv("TARGET_ENDPOINT", "")
    )
    config.target.api_key = os.getenv("TARGET_API_KEY")
    config.target.tools = tools or []
    config.target.mode = mode

    # LLM config for response analysis
    config.llm.api_key = (
        os.getenv("ANTHROPIC_API_KEY") or
        os.getenv("OPENAI_API_KEY")
    )
    config.llm.provider = (
        "anthropic" if os.getenv("ANTHROPIC_API_KEY")
        else "openai"
    )

    # SIEM config
    siem_url = siem_endpoint or os.getenv("SIEM_ENDPOINT")
    if siem_url:
        config.siem.endpoint = siem_url
        config.siem.api_key = os.getenv("SIEM_API_KEY")
        config.siem.enabled = True

    # Validate required fields
    if not config.target.endpoint:
        log.warning(
            "no_target_endpoint",
            message="No target endpoint configured"
        )

    if not config.llm.api_key:
        log.warning(
            "no_llm_api_key",
            message="No LLM API key found. "
                    "Set ANTHROPIC_API_KEY or "
                    "OPENAI_API_KEY in .env"
        )

    # Create output directories if they do not exist
    os.makedirs(config.scan.reports_dir, exist_ok=True)
    os.makedirs(config.scan.logs_dir, exist_ok=True)

    log.info(
        "config_loaded",
        target=config.target.endpoint,
        mode=config.target.mode,
        tools=config.target.tools,
        runs=config.scan.max_payload_runs,
        provider=config.llm.provider,
        siem_enabled=config.siem.enabled,
    )

    return config