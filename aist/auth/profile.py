"""
Request profile capture and persistence.

Stores endpoint format, response parsing hints,
and discovered endpoints separately from auth.
"""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

from aist.logger import get_logger

log = get_logger(__name__)

DEFAULT_PROFILE_FILE = ".aist_request_profile.json"

STANDARD_HTTP_HEADERS = frozenset({
    "content-type",
    "content-length",
    "host",
    "connection",
    "accept",
    "accept-encoding",
    "accept-language",
    "origin",
    "referer",
    "user-agent",
    "cookie",
    "authorization",
})

DANGEROUS_ENDPOINT_PATTERNS: list[tuple[str, str, str]] = [
    (r"/admin", "High", "Admin endpoint exposed"),
    (r"/debug", "High", "Debug endpoint exposed"),
    (r"/config", "Medium", "Config endpoint exposed"),
    (r"/logs", "Medium", "Log endpoint exposed"),
    (r"/metrics", "Low", "Metrics endpoint exposed"),
    (r"/swagger", "Low", "API docs exposed"),
    (r"/docs", "Low", "API docs exposed"),
    (r"/health", "Low", "Health endpoint exposed"),
    (r"/\.well-known", "Low", "Discovery endpoint exposed"),
]

JS_SECRET_PATTERNS: list[tuple[str, str]] = [
    (r"AKIA[A-Z0-9]{16}", "AWS key"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY", "Private key"),
    (r"eyJ[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+\.", "JWT token"),
    (r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "Internal IP"),
    (r"\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b", "Internal IP"),
    (r"\b192\.168\.\d{1,3}\.\d{1,3}\b", "Internal IP"),
    (r"[a-zA-Z0-9_-]+\.(?:internal|local)\b", "Internal hostname"),
    (r"/api/[a-zA-Z0-9_/-]+", "API endpoint"),
]


def _utc_iso(ts: Optional[float] = None) -> str:
    ts = ts or time.time()
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def extract_custom_headers(headers: dict) -> dict[str, str]:
    """Return non-standard headers excluding auth/cookie."""
    return {
        key: value
        for key, value in (headers or {}).items()
        if key.lower() not in STANDARD_HTTP_HEADERS
    }


def detect_message_field(body: dict) -> tuple[str, dict]:
    """Find message field and body template from captured POST body."""
    for key, value in body.items():
        if isinstance(value, str) and len(value.strip()) > 3:
            template = dict(body)
            template[key] = ""
            return key, template
    return "message", {**body, "message": ""}


def detect_response_field(body: Any) -> str:
    """Find response text field in JSON body."""
    if not isinstance(body, dict):
        return ""
    for key, value in body.items():
        if isinstance(value, str) and len(value) > 20:
            return key
    return ""


def detect_response_type(
    content_type: str,
    request_headers: Optional[dict] = None,
) -> tuple[str, bool]:
    """Return (response_type, streaming)."""
    lower = (content_type or "").lower()
    if "text/event-stream" in lower:
        return "sse", True
    if "application/x-ndjson" in lower:
        return "ndjson", True
    req_headers = {k.lower(): v for k, v in (request_headers or {}).items()}
    if req_headers.get("upgrade", "").lower() == "websocket":
        return "websocket", True
    return "json", False


def classify_endpoint(path: str) -> Optional[tuple[str, str]]:
    """Return (severity, label) if path matches dangerous pattern."""
    for pattern, severity, label in DANGEROUS_ENDPOINT_PATTERNS:
        if re.search(pattern, path, re.IGNORECASE):
            return severity, label
    return None


def scan_js_content(content: str) -> dict[str, list[str]]:
    """Scan JavaScript for secrets and endpoints."""
    findings: dict[str, list[str]] = {
        "secrets": [],
        "endpoints": [],
    }
    for pattern, label in JS_SECRET_PATTERNS:
        for match in re.finditer(pattern, content):
            value = match.group(0)
            bucket = "endpoints" if label == "API endpoint" else "secrets"
            if value not in findings[bucket]:
                findings[bucket].append(f"{label}: {value[:120]}")
    for todo in re.finditer(
        r"(?i)(TODO|FIXME).{0,80}(password|secret|token|auth|key)",
        content,
    ):
        note = todo.group(0).strip()
        if note not in findings["secrets"]:
            findings["secrets"].append(f"Security comment: {note[:120]}")
    return findings


def path_from_url(url: str) -> str:
    parsed = urlparse(url)
    return parsed.path or "/"


def save_request_profile(
    profile: dict[str, Any],
    filepath: str = DEFAULT_PROFILE_FILE,
) -> None:
    """Persist request profile to disk."""
    if "captured_at" not in profile:
        profile["captured_at"] = _utc_iso()
    with open(filepath, "w", encoding="utf-8") as handle:
        json.dump(profile, handle, indent=2)


def load_request_profile(
    filepath: str = DEFAULT_PROFILE_FILE,
) -> Optional[dict[str, Any]]:
    """Load saved request profile."""
    try:
        with open(filepath, encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return None
    except Exception as exc:
        log.warning("profile_load_error", error=str(exc))
        return None


def apply_profile_to_target(profile: dict, target) -> None:
    """Apply profile fields onto TargetConfig."""
    if profile.get("primary_endpoint"):
        target.endpoint = profile["primary_endpoint"]
    if profile.get("message_field"):
        target.message_field = profile["message_field"]
    if profile.get("response_field"):
        target.response_field = profile["response_field"]
    if profile.get("response_type"):
        target.response_type = profile["response_type"]
    template = profile.get("body_template") or {}
    msg_field = profile.get("message_field", "message")
    target.custom_body_fields = {
        k: v for k, v in template.items() if k != msg_field
    }
    if profile.get("custom_headers"):
        target.custom_headers.update(profile["custom_headers"])
