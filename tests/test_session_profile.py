"""Tests for split session/profile files and expiry detection."""

import asyncio
import base64
import json
import time

import pytest

from aist.auth.browser import BrowserSession, load_session, save_session
from aist.auth.session import (
    calculate_cookie_expiry,
    check_session_expiry,
    decode_jwt_payload,
    extract_operator_identity,
    format_utc_iso,
    load_auth_session,
    save_auth_session,
    validate_session_at_scan_start,
)


def _make_jwt(payload: dict) -> str:
    header = base64.urlsafe_b64encode(
        b'{"alg":"none"}'
    ).decode().rstrip("=")
    body = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).decode().rstrip("=")
    return f"{header}.{body}.sig"


def test_calculate_cookie_expiry_from_max_age() -> None:
    """Max-Age cookies produce a future expiry timestamp."""
    now = time.time()
    cookies = [{"name": "sid", "value": "x", "maxAge": 3600}]
    expires_at, expiry_type = calculate_cookie_expiry(cookies)
    assert expiry_type == "expires"
    assert expires_at is not None
    assert expires_at > now


def test_calculate_cookie_expiry_session_cookie() -> None:
    """Cookies without expiry are marked as session cookies."""
    cookies = [{"name": "sid", "value": "x"}]
    expires_at, expiry_type = calculate_cookie_expiry(cookies)
    assert expiry_type == "session"
    assert expires_at is None


def test_check_session_expiry_expired() -> None:
    """Expired sessions return an error message."""
    past = format_utc_iso(time.time() - 60)
    valid, error, warning = check_session_expiry(
        {"expires_at": past, "expiry_type": "expires"}
    )
    assert valid is False
    assert error is not None
    assert "expired" in error.lower()


def test_check_session_expiry_soon_warning() -> None:
    """Sessions expiring within 30 minutes warn."""
    soon = format_utc_iso(time.time() + 600)
    valid, error, warning = check_session_expiry(
        {"expires_at": soon, "expiry_type": "expires"}
    )
    assert valid is True
    assert error is None
    assert warning is not None


def test_save_auth_session_expires_at_iso_string(tmp_path) -> None:
    """expires_at is stored as a human-readable ISO string."""
    path = str(tmp_path / "session.json")
    cookies = [{"name": "sid", "value": "x", "maxAge": 3600}]
    save_auth_session(cookies=cookies, auth_headers={}, filepath=path)

    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)

    assert isinstance(data["expires_at"], str)
    assert "+00:00" in data["expires_at"]
    assert data["expires_at"].endswith("+00:00")


def test_validate_session_at_scan_start_exits_when_expired(
    tmp_path,
    monkeypatch,
) -> None:
    """Scan start validation exits when session is expired."""
    path = str(tmp_path / "session.json")
    expired = format_utc_iso(time.time() - 120)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(
            {"expires_at": expired, "expiry_type": "expires"},
            handle,
        )

    exit_code = {"value": None}

    def fake_exit(code: int) -> None:
        exit_code["value"] = code
        raise SystemExit(code)

    monkeypatch.setattr("sys.exit", fake_exit)

    with pytest.raises(SystemExit):
        validate_session_at_scan_start(path)

    assert exit_code["value"] == 1


def test_decode_jwt_payload_extracts_email() -> None:
    """JWT payload decodes without verification."""
    token = _make_jwt(
        {"email": "ivy@company.com", "role": "personal_banker"}
    )
    payload = decode_jwt_payload(token)
    assert payload["email"] == "ivy@company.com"
    assert payload["role"] == "personal_banker"


def test_extract_operator_identity_from_jwt() -> None:
    """Identity is extracted from Authorization header JWT."""
    token = _make_jwt(
        {
            "email": "ivy@company.com",
            "role": "personal_banker",
            "tenant_id": "meridian-bank",
        }
    )
    identity = extract_operator_identity(
        {"Authorization": f"Bearer {token}"}
    )
    assert identity["username"] == "ivy@company.com"
    assert identity["role"] == "personal_banker"
    assert identity["tenant_id"] == "meridian-bank"
    assert identity["source"] == "jwt_decode"


def test_split_session_save_and_load(tmp_path) -> None:
    """Auth and profile are stored in separate files."""
    session_path = str(tmp_path / ".aist_session.json")
    profile_path = str(tmp_path / ".aist_request_profile.json")
    session = BrowserSession(
        chat_endpoint="https://app.example.com/api/chat",
        message_field="query",
        response_field="answer",
        response_type="sse",
        cookies=[{"name": "sid", "value": "123", "maxAge": 7200}],
        headers={"Authorization": "Bearer test"},
        extra_body_fields={"session_id": "abc"},
        operator_identity={"username": "ivy@company.com"},
        request_profile={
            "discovered_endpoints": ["/api/chat", "/api/config"],
        },
    )
    assert asyncio.run(
        save_session(session, session_path, profile_path)
    ) is True

    with open(session_path, encoding="utf-8") as handle:
        auth_raw = json.load(handle)
    assert "chat_endpoint" not in auth_raw
    assert auth_raw["auth_headers"]["Authorization"] == "Bearer test"

    with open(profile_path, encoding="utf-8") as handle:
        profile_raw = json.load(handle)
    assert profile_raw["primary_endpoint"] == session.chat_endpoint
    assert profile_raw["message_field"] == "query"

    loaded = asyncio.run(load_session(session_path, profile_path))
    assert loaded is not None
    assert loaded.chat_endpoint == session.chat_endpoint
    assert loaded.message_field == "query"


def test_legacy_session_still_loads(tmp_path) -> None:
    """Legacy combined session files remain supported."""
    path = str(tmp_path / "legacy.json")
    legacy = {
        "chat_endpoint": "https://app.example.com/chat",
        "message_field": "message",
        "extra_body_fields": {},
        "headers": {"Authorization": "Bearer old"},
        "cookies": [],
        "expires_estimate": time.time() + 7200,
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(legacy, handle)

    loaded = asyncio.run(load_session(path))
    assert loaded is not None
    assert loaded.chat_endpoint == legacy["chat_endpoint"]


def test_load_auth_session_raises_when_expired(tmp_path) -> None:
    """load_auth_session rejects expired auth files."""
    path = str(tmp_path / "expired.json")
    save_auth_session(
        cookies=[],
        auth_headers={},
        filepath=path,
    )
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    data["expires_at"] = "2020-01-01T00:00:00+00:00"
    data["expiry_type"] = "expires"
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle)

    with pytest.raises(ValueError, match="expired"):
        load_auth_session(path)
