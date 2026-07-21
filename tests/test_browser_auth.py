"""Tests for browser auth helpers and redacted report sanitisation."""

from aist.auth.browser import (
    _is_auth_response,
    _is_auth_url,
    load_session,
    save_session,
    BrowserSession,
)
from aist.reporting.html import sanitise_for_sharing


def test_is_auth_url_filters_login_endpoints() -> None:
    """Auth-related URLs are excluded from chat capture."""
    assert _is_auth_url("https://app.example.com/api/auth/login")
    assert not _is_auth_url("https://app.example.com/api/chat")


def test_is_auth_response_detects_token_payload() -> None:
    """Auth JSON responses are rejected."""
    body = (
        '{"token": "abc", "email": "a@b.com", "role": "admin"}'
    )
    assert _is_auth_response(body) is True


def test_is_auth_response_allows_chat_payload() -> None:
    """Normal chat responses are not treated as auth."""
    body = '{"response": "Hello! How can I help you?"}'
    assert _is_auth_response(body) is False


def test_sanitise_for_sharing_redacts_email() -> None:
    """Emails are replaced in redacted output."""
    html = "<body><p>Contact user@example.com</p></body>"
    result = sanitise_for_sharing(html)
    assert "user@example.com" not in result
    assert "[EMAIL REDACTED]" in result
    assert "REDACTED VERSION" in result

def test_session_save_and_load(tmp_path) -> None:
    """Saved sessions can be loaded before expiry."""
    import asyncio
    import os

    path = str(tmp_path / "session.json")
    session = BrowserSession(
        chat_endpoint="https://app.example.com/chat",
        cookies=[{"name": "sid", "value": "123"}],
    )
    assert asyncio.run(save_session(session, path)) is True
    loaded = asyncio.run(load_session(path))
    assert loaded is not None
    assert loaded.chat_endpoint == session.chat_endpoint
    os.remove(path)
