"""
Session file handling for browser auth.

Auth data lives in .aist_session.json.
Request format lives in .aist_request_profile.json.
Legacy single-file sessions remain supported.
"""

from __future__ import annotations

import base64
import json
import re
import time
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

from aist.logger import get_logger

log = get_logger(__name__)

DEFAULT_SESSION_FILE = ".aist_session.json"
DEFAULT_PROFILE_FILE = ".aist_request_profile.json"

JWT_PATTERN = re.compile(
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
)
EMAIL_PATTERN = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
)


def _utc_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _format_duration(seconds: int) -> str:
    if seconds < 0:
        return "expired"
    hours, rem = divmod(seconds, 3600)
    minutes = rem // 60
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def calculate_cookie_expiry(cookies: list) -> tuple[Optional[float], str]:
    """
    Compute session expiry from cookie attributes.

    Returns:
        (expires_at_unix, expiry_type) where expiry_type is
        'expires', 'max-age', 'session', or 'unknown'.
    """
    now = time.time()
    expiries: list[float] = []
    has_session_cookie = False

    for cookie in cookies or []:
        if not isinstance(cookie, dict):
            continue
        expires = cookie.get("expires")
        if expires and expires > 0:
            expiries.append(float(expires))
            continue
        max_age = cookie.get("maxAge") or cookie.get("max_age")
        if max_age is not None:
            try:
                expiries.append(now + float(max_age))
            except (TypeError, ValueError):
                pass
            continue
        has_session_cookie = True

    if expiries:
        return min(expiries), "expires"
    if has_session_cookie:
        return None, "session"
    return now + 7200, "unknown"


def decode_jwt_payload(token: str) -> dict[str, Any]:
    """Decode JWT payload without verification."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1]
        padding = "=" * (-len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload + padding)
        return json.loads(decoded.decode("utf-8"))
    except Exception:
        return {}


def extract_operator_identity(
    auth_headers: dict,
    agent_response: str = "",
) -> dict[str, Any]:
    """
    Extract operator identity from JWT or agent greeting.
    """
    identity: dict[str, Any] = {
        "username": "",
        "role": "",
        "tenant_id": "",
        "scope": "",
        "source": "",
    }

    for key, value in (auth_headers or {}).items():
        if key.lower() != "authorization":
            continue
        match = JWT_PATTERN.search(str(value))
        if not match:
            continue
        payload = decode_jwt_payload(match.group(0))
        identity["username"] = (
            payload.get("email")
            or payload.get("preferred_username")
            or payload.get("sub")
            or payload.get("username")
            or ""
        )
        roles = payload.get("roles")
        if isinstance(roles, list) and roles:
            identity["role"] = str(roles[0])
        else:
            identity["role"] = payload.get("role") or ""
        identity["tenant_id"] = (
            payload.get("tenant_id")
            or payload.get("tid")
            or payload.get("tenant")
            or ""
        )
        identity["scope"] = payload.get("scope") or payload.get("scp") or ""
        identity["source"] = "jwt_decode"
        break

    if not identity["username"] and agent_response:
        email_match = EMAIL_PATTERN.search(agent_response)
        if email_match:
            identity["username"] = email_match.group(0)
            identity["source"] = "agent_response"

        role_match = re.search(
            r"(?i)(?:role|as a)\s*[:\-]?\s*([a-z_ ]{3,40})",
            agent_response,
        )
        if role_match and not identity["role"]:
            identity["role"] = role_match.group(1).strip()
            identity["source"] = identity["source"] or "agent_response"

    return identity


def save_auth_session(
    cookies: list,
    auth_headers: dict,
    operator_identity: Optional[dict] = None,
    filepath: str = DEFAULT_SESSION_FILE,
) -> dict[str, Any]:
    """Save auth-only session file."""
    expires_at, expiry_type = calculate_cookie_expiry(cookies)
    captured_at = time.time()
    data: dict[str, Any] = {
        "cookies": cookies,
        "auth_headers": auth_headers,
        "captured_at": _utc_iso(captured_at),
        "expiry_type": expiry_type,
    }
    if expires_at:
        data["expires_at"] = _utc_iso(expires_at)
        data["expires_in_seconds"] = max(0, int(expires_at - captured_at))
    else:
        data["expires_at"] = None
        data["expires_in_seconds"] = None
    if operator_identity:
        data["operator_identity"] = operator_identity

    with open(filepath, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
    return data


def _parse_expires_at(data: dict) -> Optional[float]:
    if data.get("expires_at"):
        try:
            raw = data["expires_at"]
            if isinstance(raw, (int, float)):
                return float(raw)
            return datetime.fromisoformat(
                str(raw).replace("Z", "+00:00")
            ).timestamp()
        except (TypeError, ValueError):
            pass
    legacy = data.get("expires_estimate")
    if legacy:
        return float(legacy)
    return None


def check_session_expiry(
    data: dict,
    *,
    warn_minutes: int = 30,
) -> tuple[bool, Optional[str], Optional[str]]:
    """
    Check session expiry state.

    Returns:
        (is_valid, error_message, warning_message)
    """
    expires_at = _parse_expires_at(data)
    expiry_type = data.get("expiry_type", "")

    if expiry_type == "session" or expires_at is None:
        return True, None, None

    now = time.time()
    if expires_at < now:
        return (
            False,
            f"Session expired at {_utc_iso(expires_at)}. "
            "Run with --auth-type browser to re-authenticate.",
            None,
        )

    remaining = int(expires_at - now)
    if remaining < warn_minutes * 60:
        return (
            True,
            None,
            f"Session expires in {_format_duration(remaining)}. "
            "This may expire during a deep scan. "
            "Consider re-authenticating first.",
        )
    return True, None, None


def load_auth_session(
    filepath: str = DEFAULT_SESSION_FILE,
) -> Optional[dict[str, Any]]:
    """
    Load auth session data with expiry validation.

    Supports legacy combined session files.
    """
    try:
        with open(filepath, encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return None
    except Exception as exc:
        log.warning("session_load_error", error=str(exc))
        return None

    valid, error, warning = check_session_expiry(data)
    if not valid:
        log.error("session_expired", message=error)
        raise ValueError(error or "Session expired")
    if warning:
        log.warning("session_expiring_soon", message=warning)

    return data


def legacy_session_to_auth(data: dict) -> dict[str, Any]:
    """Normalise legacy single-file session to auth fields."""
    headers = data.get("auth_headers") or data.get("headers") or {}
    return {
        "cookies": data.get("cookies", []),
        "auth_headers": headers,
        "captured_at": data.get("captured_at"),
        "expires_at": data.get("expires_at"),
        "expires_estimate": data.get("expires_estimate"),
        "expires_in_seconds": data.get("expires_in_seconds"),
        "operator_identity": data.get("operator_identity", {}),
        "expiry_type": data.get("expiry_type", "unknown"),
    }


def legacy_session_to_profile(data: dict) -> dict[str, Any]:
    """Extract profile fields from legacy combined session file."""
    if not data.get("chat_endpoint") and not data.get("primary_endpoint"):
        return {}
    return {
        "primary_endpoint": data.get("chat_endpoint")
        or data.get("primary_endpoint", ""),
        "message_field": data.get("message_field", "message"),
        "response_field": data.get("response_field", ""),
        "response_type": data.get("response_type", "json"),
        "streaming": data.get("streaming", False),
        "body_template": {
            **data.get("extra_body_fields", {}),
            data.get("message_field", "message"): "",
        },
        "custom_headers": data.get("custom_headers", {}),
        "discovered_endpoints": data.get("discovered_endpoints", []),
        "baseline_request": data.get("baseline_request", {}),
        "captured_at": data.get("captured_at"),
    }
