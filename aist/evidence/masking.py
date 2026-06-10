"""
AIST Secret Masking

Masks sensitive values before content is logged,
stored, or included in reports.

Three masking modes:

    Log masking (full):
        Used for audit logs and SIEM output.
        Full replacement -- logs never contain
        sensitive values.

    Report masking (partial):
        Used in standard HTML and JSON reports.
        Shows enough to verify the finding is real
        without exposing the full value.
        Example: sk-abc***MASKED***k9p

    Expose mode (none):
        Used when --expose-evidence flag is set.
        Full values shown for security engineers
        doing remediation on their own systems.
        Requires explicit CLI confirmation.
        Report is marked sensitive throughout.

This is a mandatory security control from the
AIST threat model (Information Disclosure section).
"""

import re
from typing import Any

from aist.logger import get_logger

log = get_logger(__name__)


# Full masking rules for logs and SIEM output
# Complete replacement -- no partial values

FULL_MASKING_RULES = [
    (
        re.compile(r'sk-[a-zA-Z0-9]{20,}'),
        '***MASKED-OPENAI-KEY***'
    ),
    (
        re.compile(r'sk-ant-[a-zA-Z0-9\-]{20,}'),
        '***MASKED-ANTHROPIC-KEY***'
    ),
    (
        re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
        '***MASKED-GOOGLE-KEY***'
    ),
    (
        re.compile(r'Bearer\s+[a-zA-Z0-9\-._~+/]{20,}=*'),
        'Bearer ***MASKED-TOKEN***'
    ),
    (
        re.compile(r'(?i)(password\s*[:=]\s*)[^\s]{4,}'),
        r'\1***MASKED***'
    ),
    (
        re.compile(r'(?i)(secret\s*[:=]\s*)[^\s]{4,}'),
        r'\1***MASKED***'
    ),
    (
        re.compile(r'(?i)(api_key\s*[:=]\s*)[^\s]{4,}'),
        r'\1***MASKED***'
    ),
    (
        re.compile(r'(?i)(token\s*[:=]\s*)[^\s]{4,}'),
        r'\1***MASKED***'
    ),
    (
        re.compile(
            r'(?i)(postgres|mysql|mongodb|redis)'
            r'://[^\s]+'
        ),
        r'\1://***MASKED-CONNECTION-STRING***'
    ),
    (
        re.compile(
            r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'
        ),
        '***MASKED-CARD-NUMBER***'
    ),
    (
        re.compile(r'eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+'
                   r'(\.[a-zA-Z0-9\-_]+)?'),
        '***MASKED-JWT***'
    ),
    (
        re.compile(r'\b[a-f0-9]{32,}\b'),
        '***MASKED-HEX-VALUE***'
    ),
]


# Partial masking rules for standard reports
# Shows enough to verify the finding
# Not enough to use or abuse the value

PARTIAL_MASKING_RULES = [
    (
        re.compile(r'(sk-[a-zA-Z0-9]{3})[a-zA-Z0-9]+'
                   r'([a-zA-Z0-9]{4})'),
        r'\1***MASKED***\2 [OpenAI API key]'
    ),
    (
        re.compile(r'(sk-ant-[a-zA-Z0-9\-]{3})[a-zA-Z0-9\-]+'
                   r'([a-zA-Z0-9]{4})'),
        r'\1***MASKED***\2 [Anthropic API key]'
    ),
    (
        re.compile(r'(AIza[0-9A-Za-z]{3})[0-9A-Za-z\-_]+'
                   r'([0-9A-Za-z]{4})'),
        r'\1***MASKED***\2 [Google API key]'
    ),
    (
        re.compile(
            r'(?i)(password\s*[:=]\s*)([^\s]{3})[^\s]+'
        ),
        r'\1\2***MASKED*** [password]'
    ),
    (
        re.compile(
            r'(?i)(secret\s*[:=]\s*)([^\s]{3})[^\s]+'
        ),
        r'\1\2***MASKED*** [secret]'
    ),
    (
        re.compile(
            r'(?i)(postgres|mysql|mongodb|redis)'
            r'://([^:]+):([^@]{3})[^@]+@([^\s]+)'
        ),
        r'\1://\2:***MASKED***@\4 [database URL]'
    ),
    (
        re.compile(
            r'\b(\d{4})[- ]?\d{4}[- ]?\d{4}[- ]?(\d{4})\b'
        ),
        r'\1 **** **** \2 [card number]'
    ),
    (
        re.compile(
            r'(eyJ[a-zA-Z0-9\-_]{6})[a-zA-Z0-9\-_.]+'
        ),
        r'\1***MASKED*** [JWT token]'
    ),
]


def mask_for_log(value: str) -> str:
    """
    Full masking for audit logs and SIEM output.
    Complete replacement of sensitive values.
    Logs should never contain sensitive data.

    Args:
        value: String to fully mask

    Returns:
        String with sensitive values fully replaced
    """
    if not isinstance(value, str):
        return value

    for pattern, replacement in FULL_MASKING_RULES:
        value = pattern.sub(replacement, value)

    return value


def mask_for_storage(text: str) -> str:
    """
    Alias for mask_for_log.
    Used when storing evidence internally.

    Args:
        text: Text to mask for storage

    Returns:
        Fully masked text
    """
    return mask_for_log(text)


def mask_for_report(
    text: str,
    expose: bool = False,
) -> str:
    """
    Masking for HTML and JSON reports.

    Standard mode (expose=False):
        Partial masking -- shows enough to verify
        the finding without exposing full values.

    Expose mode (expose=True):
        No masking -- full values shown.
        Only used when --expose-evidence flag is set.
        Caller is responsible for confirming user
        acknowledged the security warning.

    Args:
        text:   Text to mask for report
        expose: If True skip masking entirely

    Returns:
        Appropriately masked text for report
    """
    if not text:
        return text

    if expose:
        return text

    masked = text
    for pattern, replacement in PARTIAL_MASKING_RULES:
        masked = pattern.sub(replacement, masked)

    return masked


def partial_mask_value(
    value: str,
    show_start: int = 3,
    show_end: int = 4,
    label: str = "",
) -> str:
    """
    Partially mask a single known-sensitive value.
    Shows first and last few characters.

    Used when we know a value is sensitive and want
    to show just enough for verification.

    Args:
        value:      Sensitive value to partially mask
        show_start: Number of characters to show at start
        show_end:   Number of characters to show at end
        label:      Optional label e.g. [API key]

    Returns:
        Partially masked value

    Example:
        sk-abcdefghijklmnop1234 becomes
        sk-abc***MASKED***1234 [API key]
    """
    if not value:
        return "***MASKED***"

    if len(value) <= show_start + show_end:
        return "***MASKED***"

    masked = (
        value[:show_start] +
        "***MASKED***" +
        value[-show_end:]
    )

    if label:
        masked += f" [{label}]"

    return masked


def mask_dict(
    data: dict,
    expose: bool = False,
) -> dict:
    """
    Recursively mask sensitive values in a dictionary.
    Used before logging structured data.

    Args:
        data:   Dictionary to mask
        expose: If True use expose mode

    Returns:
        Dictionary with sensitive values masked
    """
    masked = {}
    for key, value in data.items():
        if is_sensitive_key(key) and not expose:
            if isinstance(value, str):
                masked[key] = partial_mask_value(value)
            else:
                masked[key] = "***MASKED***"
        elif isinstance(value, str):
            masked[key] = mask_for_report(value, expose)
        elif isinstance(value, dict):
            masked[key] = mask_dict(value, expose)
        elif isinstance(value, list):
            masked[key] = mask_list(value, expose)
        else:
            masked[key] = value
    return masked


def mask_list(
    data: list,
    expose: bool = False,
) -> list:
    """
    Mask sensitive values in a list.

    Args:
        data:   List to mask
        expose: If True use expose mode

    Returns:
        List with sensitive values masked
    """
    masked = []
    for item in data:
        if isinstance(item, str):
            masked.append(mask_for_report(item, expose))
        elif isinstance(item, dict):
            masked.append(mask_dict(item, expose))
        elif isinstance(item, list):
            masked.append(mask_list(item, expose))
        else:
            masked.append(item)
    return masked


def is_sensitive_key(key: str) -> bool:
    """
    Check if a dictionary key name suggests
    the value is sensitive.

    Used to proactively mask values before
    even checking the content.

    Args:
        key: Dictionary key name to check

    Returns:
        True if key suggests sensitive content
    """
    sensitive_key_patterns = [
        "password", "passwd", "pwd",
        "secret", "api_key", "apikey",
        "token", "auth", "credential",
        "private_key", "access_key",
        "connection_string", "database_url",
    ]

    key_lower = key.lower()
    return any(
        pattern in key_lower
        for pattern in sensitive_key_patterns
    )


SENSITIVE_REPORT_BANNER = """
╔══════════════════════════════════════════════════╗
║  SENSITIVE: This report contains unmasked        ║
║  credentials and sensitive values.               ║
║  Handle with care. Do not store in version       ║
║  control or shared drives. Do not share.         ║
╚══════════════════════════════════════════════════╝
"""


EXPOSE_CONFIRMATION_WARNING = """
WARNING: You are about to generate a report containing
unmasked sensitive values including credentials and PII.

This report should be handled like a password file:
- Do not store in version control
- Do not store in shared or cloud drives
- Do not email or share without encryption
- Delete after remediation is complete

Type CONFIRM to proceed or anything else to cancel:
"""