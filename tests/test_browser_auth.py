"""Tests for browser auth helpers and redacted report sanitisation."""

from aist.auth.browser import (
    CHAT_INPUT_SELECTORS,
    _is_auth_response,
    _is_auth_url,
    _looks_like_chat_post_body,
    _rank_chat_candidates,
    _score_chat_candidate,
    _should_capture_chat_post,
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


def test_looks_like_chat_post_body() -> None:
    """Message-like JSON bodies are recognised."""
    assert _looks_like_chat_post_body({"query": "hello there"})
    assert not _should_capture_chat_post(
        "https://app.example.com/telemetry",
        {"event": "click"},
    )


def test_should_capture_chat_post_by_url_or_body() -> None:
    """Chat POSTs match URL keywords or message-shaped bodies."""
    assert _should_capture_chat_post(
        "https://app.example.com/api/completion",
        {},
    )
    assert _should_capture_chat_post(
        "https://app.example.com/v1/run",
        {"prompt": "What can you help with?"},
    )


def test_rank_chat_candidates_prefers_message_posts() -> None:
    """Highest-scored candidate should look most like chat."""
    candidates = [
        {
            "url": "https://app.example.com/telemetry",
            "body": {"event": "click"},
            "response_preview": "ok",
        },
        {
            "url": "https://app.example.com/api/chat",
            "body": {"query": "What is the fuel level?"},
            "response_preview": '{"answer": "Tank is at 80%"}',
        },
    ]
    ranked = _rank_chat_candidates(candidates)
    assert ranked[0]["url"].endswith("/api/chat")
    assert _score_chat_candidate(ranked[0]) > _score_chat_candidate(
        candidates[0]
    )


def test_chat_input_selectors_defined() -> None:
    """Common chat input selectors are configured."""
    assert len(CHAT_INPUT_SELECTORS) >= 10


def test_session_save_and_load(tmp_path) -> None:
    """Saved sessions can be loaded before expiry."""
    import asyncio

    session_path = str(tmp_path / "session.json")
    profile_path = str(tmp_path / "profile.json")
    session = BrowserSession(
        chat_endpoint="https://app.example.com/chat",
        cookies=[{"name": "sid", "value": "123", "maxAge": 7200}],
        headers={"Authorization": "Bearer test"},
    )
    assert asyncio.run(
        save_session(session, session_path, profile_path)
    ) is True
    loaded = asyncio.run(load_session(session_path, profile_path))
    assert loaded is not None
    assert loaded.chat_endpoint == session.chat_endpoint
