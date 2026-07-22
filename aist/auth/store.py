"""
Named session and profile storage under ~/.aist/.

Sessions:  ~/.aist/sessions/{slug}.json
Profiles:  ~/.aist/profiles/{slug}.json

Legacy cwd files (.aist_session.json) remain a
load-time fallback with a warning.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from aist.logger import get_logger

log = get_logger(__name__)

LEGACY_SESSION_FILE = ".aist_session.json"
LEGACY_PROFILE_FILE = ".aist_request_profile.json"

TIMESTAMP_SUFFIX = re.compile(r"^(.+)-(\d{8})-(\d{4})$")


def aist_home() -> Path:
    """Return the AIST home directory (~/.aist)."""
    override = os.getenv("AIST_HOME")
    if override:
        return Path(override).expanduser().resolve()
    return Path.home() / ".aist"


def sessions_dir() -> Path:
    """Directory for named auth session files."""
    return aist_home() / "sessions"


def profiles_dir() -> Path:
    """Directory for named request profile files."""
    return aist_home() / "profiles"


def ensure_store_dirs() -> None:
    """Create ~/.aist/sessions and profiles if needed."""
    sessions_dir().mkdir(parents=True, exist_ok=True)
    profiles_dir().mkdir(parents=True, exist_ok=True)


def is_legacy_default_path(filepath: str) -> bool:
    """True when path is the legacy cwd default filename."""
    name = Path(filepath).name
    return name in {LEGACY_SESSION_FILE, LEGACY_PROFILE_FILE}


def generate_session_slug(
    target_url: str,
    when: Optional[datetime] = None,
) -> str:
    """
    Build a short session slug from a target URL.

    Rules:
    1. hostname from URL
    2. first label only (before first dot)
    3. port if non-standard (not 80/443)
    4. append YYYYMMDD-HHMM (local time)
    """
    parsed = urlparse((target_url or "").strip())
    host = (parsed.hostname or "").lower().strip(".")
    if not host:
        # Bare hostname or path-only fallback
        raw = (target_url or "session").strip()
        host = raw.split("/")[0].split(":")[0].lower() or "session"

    first = host.split(".", 1)[0] or "session"
    # Keep alphanumerics and hyphens only
    first = re.sub(r"[^a-z0-9-]+", "-", first).strip("-") or "session"

    parts = [first]
    port = parsed.port
    if port is None and "://" not in (target_url or ""):
        # urlparse may miss port without scheme
        maybe = (target_url or "").split("/")[0]
        if ":" in maybe:
            try:
                port = int(maybe.rsplit(":", 1)[-1])
            except ValueError:
                port = None

    scheme = (parsed.scheme or "https").lower()
    standard = {80, 443}
    if scheme == "http":
        standard = {80}
    elif scheme == "https":
        standard = {443}
    if port is not None and port not in standard:
        parts.append(str(port))

    stamp = when or datetime.now().astimezone()
    parts.append(stamp.strftime("%Y%m%d-%H%M"))
    return "-".join(parts)


def session_path(name: str) -> Path:
    """Absolute path for a named session file."""
    return sessions_dir() / f"{name}.json"


def profile_path(name: str) -> Path:
    """Absolute path for a named profile file."""
    return profiles_dir() / f"{name}.json"


def list_session_names() -> list[str]:
    """Return saved session names (newest first)."""
    directory = sessions_dir()
    if not directory.is_dir():
        return []
    names = [
        path.stem
        for path in directory.glob("*.json")
        if path.is_file()
    ]
    return sorted(names, key=_name_sort_key, reverse=True)


def _name_sort_key(name: str) -> tuple:
    """Sort key: timestamp suffix then name."""
    match = TIMESTAMP_SUFFIX.match(name)
    if match:
        return (match.group(2), match.group(3), name)
    path = session_path(name)
    mtime = path.stat().st_mtime if path.exists() else 0.0
    return ("00000000", "0000", f"{mtime:020.0f}-{name}")


def resolve_session_name(name: str) -> Optional[str]:
    """
    Resolve a session name to an exact stored name.

    Exact match wins; otherwise the most recent session
    whose name equals the query or starts with ``query-``.
    """
    query = (name or "").strip()
    if not query:
        return None
    names = list_session_names()
    if query in names:
        return query
    matches = [
        item
        for item in names
        if item == query or item.startswith(f"{query}-")
    ]
    if not matches:
        return None
    return sorted(matches, key=_name_sort_key, reverse=True)[0]


@dataclass
class ResolvedPaths:
    """Resolved session/profile filesystem paths."""

    session_file: str
    profile_file: str
    session_name: Optional[str] = None
    legacy: bool = False
    warning: Optional[str] = None


def paths_for_named_session(name: str) -> ResolvedPaths:
    """Build paths for an exact named session."""
    ensure_store_dirs()
    return ResolvedPaths(
        session_file=str(session_path(name)),
        profile_file=str(profile_path(name)),
        session_name=name,
    )


def resolve_load_paths(
    *,
    session_name: Optional[str] = None,
    session_file: str = LEGACY_SESSION_FILE,
    profile_file: str = LEGACY_PROFILE_FILE,
) -> ResolvedPaths:
    """
    Resolve which session/profile files to load.

    Priority:
    1. --session-name (exact or most recent prefix)
    2. Explicit non-legacy --session-file / --profile-file
    3. Legacy cwd files with warning
    4. Provided paths as-is
    """
    if session_name:
        resolved = resolve_session_name(session_name)
        if not resolved:
            raise FileNotFoundError(
                f"No saved session matching '{session_name}'. "
                "Run: aist scan --list-sessions"
            )
        return paths_for_named_session(resolved)

    # Explicit custom paths (not the legacy default names)
    if (
        session_file != LEGACY_SESSION_FILE
        or profile_file != LEGACY_PROFILE_FILE
    ):
        return ResolvedPaths(
            session_file=session_file,
            profile_file=profile_file,
        )

    legacy_session = Path.cwd() / LEGACY_SESSION_FILE
    if legacy_session.is_file():
        warning = (
            "Using legacy session file. "
            "Re-authenticate to use named sessions."
        )
        log.warning("legacy_session_file", path=str(legacy_session))
        return ResolvedPaths(
            session_file=str(legacy_session),
            profile_file=str(Path.cwd() / LEGACY_PROFILE_FILE),
            legacy=True,
            warning=warning,
        )

    return ResolvedPaths(
        session_file=session_file,
        profile_file=profile_file,
    )


def resolve_save_paths(
    target_url: str,
    *,
    session_file: str = LEGACY_SESSION_FILE,
    profile_file: str = LEGACY_PROFILE_FILE,
    when: Optional[datetime] = None,
) -> ResolvedPaths:
    """
    Resolve where to save a newly captured session.

    Uses ~/.aist named storage unless the operator
    passed explicit non-legacy file paths.
    """
    if (
        session_file != LEGACY_SESSION_FILE
        or profile_file != LEGACY_PROFILE_FILE
    ):
        return ResolvedPaths(
            session_file=session_file,
            profile_file=profile_file,
        )

    slug = generate_session_slug(target_url, when=when)
    ensure_store_dirs()
    return paths_for_named_session(slug)


def format_expiry_remaining(
    expires_at: Any,
    *,
    now: Optional[float] = None,
) -> str:
    """Human-readable remaining time or 'expired'."""
    if not expires_at:
        return "session"
    try:
        if isinstance(expires_at, (int, float)):
            expiry = float(expires_at)
        else:
            text = str(expires_at).replace("Z", "+00:00")
            expiry = datetime.fromisoformat(text).timestamp()
    except (TypeError, ValueError):
        return "unknown"

    current = now if now is not None else time.time()
    remaining = expiry - current
    if remaining <= 0:
        return "expired"
    total_minutes = int(remaining // 60)
    hours, minutes = divmod(total_minutes, 60)
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def list_sessions() -> list[dict[str, Any]]:
    """
    List saved sessions for CLI display.

    Each row: name, expires display, has_profile.
    """
    rows: list[dict[str, Any]] = []
    for name in list_session_names():
        path = session_path(name)
        expires_display = "unknown"
        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
            expires_display = format_expiry_remaining(
                data.get("expires_at")
            )
        except Exception as exc:
            log.info("session_list_read_error", name=name, error=str(exc))
            expires_display = "error"
        rows.append({
            "name": name,
            "expires": expires_display,
            "profile": profile_path(name).is_file(),
            "session_file": str(path),
            "profile_file": str(profile_path(name)),
        })
    return rows


def clear_session(name: str) -> bool:
    """
    Delete a named session and its profile.

    ``name`` may be an exact name or prefix.
    Returns True if at least one file was removed.
    """
    resolved = resolve_session_name(name)
    if not resolved:
        return False
    removed = False
    for path in (session_path(resolved), profile_path(resolved)):
        if path.is_file():
            path.unlink()
            removed = True
            log.info("session_cleared", path=str(path))
    return removed


def clear_all_sessions() -> int:
    """Delete all named sessions and profiles. Returns count."""
    removed = 0
    for directory in (sessions_dir(), profiles_dir()):
        if not directory.is_dir():
            continue
        for path in directory.glob("*.json"):
            try:
                path.unlink()
                removed += 1
            except OSError as exc:
                log.warning(
                    "session_clear_failed",
                    path=str(path),
                    error=str(exc),
                )
    return removed


def print_sessions_table(rows: Optional[list[dict]] = None) -> None:
    """Print a Rich table of saved sessions."""
    from rich.console import Console
    from rich.table import Table

    console = Console()
    data = rows if rows is not None else list_sessions()
    if not data:
        console.print("[dim]No saved sessions in ~/.aist/sessions/[/dim]")
        return

    table = Table(title="Saved sessions (~/.aist)")
    table.add_column("NAME", style="cyan", no_wrap=True)
    table.add_column("EXPIRES")
    table.add_column("PROFILE")
    for row in data:
        expires = row["expires"]
        if expires == "expired":
            expires_display = "[red]expired[/red]"
        else:
            expires_display = expires
        table.add_row(
            row["name"],
            expires_display,
            "yes" if row["profile"] else "no",
        )
    console.print(table)
