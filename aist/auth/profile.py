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


def _mask_secret_preview(value: str) -> str:
    """Redact sensitive preview text for discovery evidence."""
    text = (value or "").strip()
    if len(text) <= 8:
        return "****"
    return f"{text[:4]}****{text[-4:]}"


def make_discovery_finding(
    finding_type: str,
    title: str,
    detail: str,
    severity: str,
    evidence: str = "",
) -> dict[str, Any]:
    """
    Build one discovery finding.

    Schema is fixed to five fields; ``type`` values
    are open-ended so new discovery kinds need no
    report-code changes.
    """
    return {
        "type": finding_type,
        "title": title,
        "detail": detail,
        "severity": (severity or "low").lower(),
        "evidence": evidence or "",
    }


def build_discovery_block(
    *,
    discovered_endpoints: Optional[list] = None,
    endpoint_labels: Optional[dict] = None,
    js_files_scanned: int = 0,
    js_secrets: Optional[list] = None,
    js_extra_endpoints: Optional[list] = None,
    websocket_detected: bool = False,
    extra_findings: Optional[list] = None,
) -> dict[str, Any]:
    """
    Assemble a flexible discovery block for the profile.

    Findings are built from HTTP/JS observation only --
    no LLM classification.
    """
    findings: list[dict[str, Any]] = []
    endpoints = list(discovered_endpoints or [])
    labels = endpoint_labels or {}

    for path, meta in labels.items():
        if isinstance(meta, dict):
            severity = meta.get("severity", "medium")
            label = meta.get("label", "Sensitive endpoint exposed")
        elif isinstance(meta, (list, tuple)) and len(meta) >= 2:
            severity, label = meta[0], meta[1]
        else:
            severity, label = "medium", "Sensitive endpoint exposed"
        findings.append(
            make_discovery_finding(
                "endpoint_discovered",
                label,
                str(path),
                severity,
                evidence=f"Endpoint observed during browser session: {path}",
            )
        )

    for secret in js_secrets or []:
        preview = str(secret)
        # "Label: value" from scan_js_content
        if ": " in preview:
            label, raw = preview.split(": ", 1)
            evidence = f"{label}: {_mask_secret_preview(raw)}"
            title = f"Secret found in JavaScript ({label})"
            detail = f"Possible {label.lower()} in downloaded JavaScript"
        else:
            evidence = _mask_secret_preview(preview)
            title = "Secret found in JavaScript file"
            detail = "Sensitive pattern matched in JavaScript content"
        findings.append(
            make_discovery_finding(
                "js_secret",
                title,
                detail,
                "high",
                evidence=evidence,
            )
        )

    for endpoint in js_extra_endpoints or []:
        path = str(endpoint)
        if ": " in path:
            path = path.split(": ", 1)[-1]
        findings.append(
            make_discovery_finding(
                "js_endpoint",
                "API endpoint referenced in JavaScript",
                path,
                "low",
                evidence=f"Found in JS source: {path}",
            )
        )

    if websocket_detected:
        findings.append(
            make_discovery_finding(
                "websocket_detected",
                "WebSocket transport detected",
                "Application appears to use WebSocket for chat traffic",
                "medium",
                evidence="Upgrade/WebSocket signal during session capture",
            )
        )

    for item in extra_findings or []:
        if not isinstance(item, dict):
            continue
        findings.append(
            make_discovery_finding(
                str(item.get("type", "discovery")),
                str(item.get("title", "Discovery finding")),
                str(item.get("detail", "")),
                str(item.get("severity", "low")),
                evidence=str(item.get("evidence", "")),
            )
        )

    return {
        "findings": findings,
        "stats": {
            "total_endpoints": len(endpoints),
            "js_files_scanned": int(js_files_scanned or 0),
            "findings_count": len(findings),
        },
    }


def merge_discovery_findings(
    discovery: dict[str, Any],
    new_findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Append findings into an existing discovery block."""
    block = dict(discovery or {})
    findings = list(block.get("findings") or [])
    for item in new_findings:
        findings.append(
            make_discovery_finding(
                str(item.get("type", "discovery")),
                str(item.get("title", "Discovery finding")),
                str(item.get("detail", "")),
                str(item.get("severity", "low")),
                evidence=str(item.get("evidence", "")),
            )
        )
    stats = dict(block.get("stats") or {})
    stats["findings_count"] = len(findings)
    stats.setdefault("total_endpoints", 0)
    stats.setdefault("js_files_scanned", 0)
    block["findings"] = findings
    block["stats"] = stats
    return block


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
