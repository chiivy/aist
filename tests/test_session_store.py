"""Tests for named session storage under ~/.aist/."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from aist.auth import store
from aist.auth.session import save_auth_session
from aist.auth.profile import save_request_profile


@pytest.fixture
def aist_dirs(tmp_path, monkeypatch):
    """Isolate ~/.aist under a temp directory."""
    home = tmp_path / "aist-home"
    monkeypatch.setenv("AIST_HOME", str(home))
    store.ensure_store_dirs()
    return home


def test_slug_generation_with_nonstandard_port() -> None:
    """Hostname first label + non-standard port + stamp."""
    when = datetime(2026, 7, 22, 10, 55, tzinfo=timezone.utc)
    slug = store.generate_session_slug(
        "https://app.company.com:8443/api/chat",
        when=when,
    )
    assert slug == "app-8443-20260722-1055"


def test_slug_generation_without_port() -> None:
    """Standard HTTPS port is omitted from slug."""
    when = datetime(2026, 7, 22, 10, 55, tzinfo=timezone.utc)
    slug = store.generate_session_slug(
        "https://agent.internal.com/chat",
        when=when,
    )
    assert slug == "agent-20260722-1055"


def test_slug_generation_localhost_port() -> None:
    """Localhost non-standard port is included."""
    when = datetime(2026, 7, 22, 10, 55, tzinfo=timezone.utc)
    slug = store.generate_session_slug(
        "http://localhost:5002/chat",
        when=when,
    )
    assert slug == "localhost-5002-20260722-1055"


def test_slug_omits_standard_http_port() -> None:
    """Port 80 on http is not included."""
    when = datetime(2026, 7, 22, 10, 55, tzinfo=timezone.utc)
    slug = store.generate_session_slug(
        "http://demo.example.com:80/chat",
        when=when,
    )
    assert slug == "demo-20260722-1055"


def test_save_and_load_by_name(aist_dirs) -> None:
    """Named sessions save under ~/.aist and resolve by name."""
    when = datetime(2026, 7, 22, 10, 55)
    paths = store.resolve_save_paths(
        "https://app.company.com:8443/chat",
        when=when,
    )
    assert paths.session_name == "app-8443-20260722-1055"
    assert paths.session_file.endswith(
        "sessions/app-8443-20260722-1055.json"
    ) or paths.session_file.endswith(
        "sessions\\app-8443-20260722-1055.json"
    )

    save_auth_session(
        cookies=[{
            "name": "sid",
            "value": "x",
            "expires": datetime.now(timezone.utc).timestamp() + 3600,
        }],
        auth_headers={"Authorization": "Bearer t"},
        filepath=paths.session_file,
    )
    save_request_profile(
        {"primary_endpoint": "https://app.company.com:8443/chat"},
        paths.profile_file,
    )

    loaded = store.resolve_load_paths(
        session_name="app-8443-20260722-1055"
    )
    assert loaded.session_name == "app-8443-20260722-1055"
    assert Path(loaded.session_file).is_file()
    assert Path(loaded.profile_file).is_file()


def test_prefix_matches_most_recent(aist_dirs) -> None:
    """Prefix loads the newest matching timestamped session."""
    older = "app-8443-20260721-0900"
    newer = "app-8443-20260722-1055"
    for name in (older, newer):
        store.ensure_store_dirs()
        save_auth_session(
            cookies=[{"name": "sid", "value": "x", "maxAge": 3600}],
            auth_headers={},
            filepath=str(store.session_path(name)),
        )
        save_request_profile(
            {"primary_endpoint": "https://x/chat"},
            str(store.profile_path(name)),
        )

    resolved = store.resolve_session_name("app-8443")
    assert resolved == newer
    paths = store.resolve_load_paths(session_name="app-8443")
    assert paths.session_name == newer


def test_list_sessions_with_expiry(aist_dirs) -> None:
    """list_sessions includes expiry and profile presence."""
    future = datetime.now(timezone.utc).timestamp() + 3600
    name = "agent-20260722-1055"
    save_auth_session(
        cookies=[{
            "name": "sid",
            "value": "x",
            "expires": future,
        }],
        auth_headers={},
        filepath=str(store.session_path(name)),
    )
    save_request_profile(
        {"primary_endpoint": "https://agent/chat"},
        str(store.profile_path(name)),
    )

    rows = store.list_sessions()
    assert len(rows) == 1
    assert rows[0]["name"] == name
    assert rows[0]["profile"] is True
    assert "h" in rows[0]["expires"] or "m" in rows[0]["expires"]
    assert rows[0]["expires"] != "expired"


def test_list_sessions_shows_expired(aist_dirs) -> None:
    """Expired sessions are labelled expired."""
    name = "agent-20260721-0900"
    past = datetime.now(timezone.utc).timestamp() - 10
    path = store.session_path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({
            "cookies": [],
            "auth_headers": {},
            "expires_at": datetime.fromtimestamp(
                past, tz=timezone.utc
            ).isoformat(),
        }),
        encoding="utf-8",
    )
    rows = store.list_sessions()
    assert rows[0]["expires"] == "expired"
    assert rows[0]["profile"] is False


def test_clear_session_and_all(aist_dirs) -> None:
    """clear_session and clear_all_sessions remove files."""
    name = "localhost-5002-20260722-1055"
    save_auth_session(
        cookies=[{"name": "sid", "value": "x", "maxAge": 60}],
        auth_headers={},
        filepath=str(store.session_path(name)),
    )
    save_request_profile({}, str(store.profile_path(name)))
    assert store.clear_session("localhost-5002") is True
    assert not store.session_path(name).exists()
    assert not store.profile_path(name).exists()

    save_auth_session(
        cookies=[{"name": "sid", "value": "x", "maxAge": 60}],
        auth_headers={},
        filepath=str(store.session_path(name)),
    )
    assert store.clear_all_sessions() >= 1
    assert store.list_sessions() == []


def test_legacy_file_fallback(tmp_path, monkeypatch, aist_dirs) -> None:
    """Cwd legacy session is used with a warning."""
    monkeypatch.chdir(tmp_path)
    legacy = tmp_path / store.LEGACY_SESSION_FILE
    legacy.write_text(
        json.dumps({
            "cookies": [],
            "auth_headers": {"Authorization": "Bearer x"},
            "expires_at": None,
        }),
        encoding="utf-8",
    )
    (tmp_path / store.LEGACY_PROFILE_FILE).write_text(
        json.dumps({"primary_endpoint": "https://legacy/chat"}),
        encoding="utf-8",
    )

    paths = store.resolve_load_paths()
    assert paths.legacy is True
    assert paths.warning is not None
    assert "legacy" in paths.warning.lower()
    assert Path(paths.session_file) == legacy


def test_explicit_paths_skip_named_store(aist_dirs, tmp_path) -> None:
    """Custom --session-file paths are preserved."""
    custom = tmp_path / "custom_session.json"
    custom_profile = tmp_path / "custom_profile.json"
    paths = store.resolve_save_paths(
        "https://app.example.com/chat",
        session_file=str(custom),
        profile_file=str(custom_profile),
    )
    assert paths.session_file == str(custom)
    assert paths.session_name is None


def test_format_expiry_remaining() -> None:
    """Expiry formatter returns human durations."""
    now = 1_000_000.0
    assert store.format_expiry_remaining(
        now - 10,
        now=now,
    ) == "expired"
    assert store.format_expiry_remaining(
        now + 90 * 60,
        now=now,
    ) == "1h 30m"
    assert store.format_expiry_remaining(None) == "session"
