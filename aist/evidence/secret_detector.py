"""Secret and sensitive data detection in HTTP responses."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "jwt",
        re.compile(r"eyJ[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+"),
        "High",
    ),
    (
        "aws_key",
        re.compile(r"AKIA[A-Z0-9]{16}"),
        "High",
    ),
    (
        "private_key",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY"),
        "High",
    ),
    (
        "internal_ip",
        re.compile(
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
            r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
            r"192\.168\.\d{1,3}\.\d{1,3})\b"
        ),
        "Medium",
    ),
    (
        "stack_trace",
        re.compile(r"\bat [A-Za-z0-9_./\\-]+"),
        "Low",
    ),
    (
        "file_path",
        re.compile(
            r"(?:[A-Za-z]:\\|/var/|/app/|/home/)[^\s\"']+"
        ),
        "Medium",
    ),
    (
        "sql_error",
        re.compile(
            r"(?i)syntax error|mysql_fetch|ORA-\d+|pg_query|sqlite_"
        ),
        "Medium",
    ),
]


@dataclass
class SecretFinding:
    """Detected secret in a response body."""

    pattern: str
    severity: str
    match_preview: str


def scan_response_secrets(body: str) -> list[SecretFinding]:
    """Scan response text for sensitive patterns."""
    findings: list[SecretFinding] = []
    if not body:
        return findings
    for name, pattern, severity in SECRET_PATTERNS:
        match = pattern.search(body)
        if match:
            findings.append(
                SecretFinding(
                    pattern=name,
                    severity=severity,
                    match_preview=match.group(0)[:80],
                )
            )
    return findings
