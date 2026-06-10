"""
AIST Structured Logger

Provides JSON-structured logging with automatic
secret masking for all AIST modules.
Logs are SIEM-ready from day one.
"""

import re
import logging
import structlog
from typing import Any


# Patterns that indicate sensitive data
# These get masked before any log is written
SENSITIVE_PATTERNS = [
    (re.compile(r'sk-[a-zA-Z0-9]{20,}'), '***MASKED-OPENAI-KEY***'),
    (re.compile(r'sk-ant-[a-zA-Z0-9\-]{20,}'), '***MASKED-ANTHROPIC-KEY***'),
    (re.compile(r'AIza[0-9A-Za-z\-_]{35}'), '***MASKED-GOOGLE-KEY***'),
    (re.compile(r'Bearer\s+[a-zA-Z0-9\-._~+/]+=*'), 'Bearer ***MASKED-TOKEN***'),
    (re.compile(r'(?i)password\s*[:=]\s*\S+'), 'password=***MASKED***'),
    (re.compile(r'(?i)secret\s*[:=]\s*\S+'), 'secret=***MASKED***'),
    (re.compile(r'(?i)api_key\s*[:=]\s*\S+'), 'api_key=***MASKED***'),
    (re.compile(r'(?i)token\s*[:=]\s*\S+'), 'token=***MASKED***'),
]


def mask_secrets(value: str) -> str:
    """
    Mask sensitive patterns in a string.
    Called automatically on all log values
    before any log entry is written.

    Args:
        value: String to mask

    Returns:
        String with sensitive values replaced
    """
    if not isinstance(value, str):
        return value
    for pattern, replacement in SENSITIVE_PATTERNS:
        value = pattern.sub(replacement, value)
    return value


def mask_processor(
    logger: Any,
    method: str,
    event_dict: dict
) -> dict:
    """
    Structlog processor that masks secrets
    in all event dict values before the
    log entry is written.

    Runs automatically on every log call.
    """
    for key, value in event_dict.items():
        if isinstance(value, str):
            event_dict[key] = mask_secrets(value)
    return event_dict


def setup_logging(
    log_level: str = "INFO",
    log_file: str = None
) -> None:
    """
    Configure structured JSON logging for AIST.
    Call once at startup from cli.py.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        log_file:  Optional file path to write logs to
                   in addition to console output
    """
    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        mask_processor,
        structlog.processors.JSONRenderer(),
    ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelName(log_level)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.BoundLogger:
    """
    Get a named logger for a module.

    Usage:
        from aist.logger import get_logger
        log = get_logger(__name__)
        log.info("scan_started",
                 target="https://agent.example.com",
                 mode="active")

    Args:
        name: Module name, pass __name__

    Returns:
        Configured structlog logger instance
    """
    return structlog.get_logger(name)