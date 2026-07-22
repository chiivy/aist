"""
AIST Browser-Based Authentication

Launches a real browser window for the user
to log in normally. AIST captures the resulting
session cookies, tokens, and request format
automatically.

This handles any authentication method:
- SSO / Azure AD / Okta
- Username and password
- MFA (user completes it manually)
- Certificate-based auth
- Any other browser-based login

No manual token capture needed.
Session stays fresh for the duration
of the scan.
"""

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx

from aist.auth.profile import (
    DEFAULT_PROFILE_FILE,
    apply_profile_to_target,
    load_request_profile,
    save_request_profile,
)
from aist.auth.session import (
    DEFAULT_SESSION_FILE,
    calculate_cookie_expiry,
    check_session_expiry,
    extract_operator_identity,
    legacy_session_to_auth,
    legacy_session_to_profile,
    load_auth_session,
    save_auth_session,
)
from aist.auth.traffic_observer import TrafficObserver
from aist.logger import get_logger

log = get_logger(__name__)

_MESSAGE_FIELD_CANDIDATES = (
    "message",
    "query",
    "input",
    "prompt",
    "content",
    "text",
)

_AUTH_HEADER_KEYS = frozenset({
    "authorization",
    "x-auth-token",
    "x-api-key",
})

_CHAT_URL_KEYWORDS = (
    "chat",
    "message",
    "query",
    "assist",
    "stream",
    "api",
)

_AUTH_URL_KEYWORDS = (
    "login",
    "auth",
    "token",
    "signin",
    "session",
    "authenticate",
    "oauth",
    "callback",
    "refresh",
)

_AUTH_RESPONSE_PATTERNS = (
    "authentication successful",
    "access_token",
    "authentication_token",
)


@dataclass
class BrowserSession:
    """
    Captured browser session data.
    Contains everything needed to make
    authenticated requests to the target.
    """

    cookies: list = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    storage_state: dict = field(default_factory=dict)
    request_format: dict = field(default_factory=dict)
    response_format: str = ""
    response_type: str = "json"
    response_field: str = ""
    base_url: str = ""
    chat_endpoint: str = ""
    message_field: str = "message"
    extra_body_fields: dict = field(default_factory=dict)
    operator_identity: dict = field(default_factory=dict)
    request_profile: dict = field(default_factory=dict)
    expires_at: Optional[str] = None
    expires_in_seconds: Optional[int] = None


def _detect_message_field(body: dict) -> str:
    """Pick the message field name from a captured request body."""
    for candidate in _MESSAGE_FIELD_CANDIDATES:
        if candidate in body:
            return candidate
    return "message"


def _is_auth_url(url: str) -> bool:
    """Return True if the URL looks like an auth endpoint."""
    lower = url.lower()
    return any(keyword in lower for keyword in _AUTH_URL_KEYWORDS)


def _is_auth_response(
    response_text: str,
    request_body: Optional[dict] = None,
) -> bool:
    """Return True if the response looks like an auth response."""
    lower = response_text.lower()
    if any(pattern in lower for pattern in _AUTH_RESPONSE_PATTERNS):
        return True

    try:
        data = json.loads(response_text)
        if isinstance(data, dict):
            keys = {str(key).lower() for key in data.keys()}
            if (
                "token" in keys
                and "email" in keys
                and "role" in keys
            ):
                return True
    except (json.JSONDecodeError, TypeError):
        pass

    return False


def _cookies_to_dict(cookies: list) -> dict[str, str]:
    """Convert Playwright cookie list to a dict for httpx."""
    result: dict[str, str] = {}
    for cookie in cookies:
        if isinstance(cookie, dict) and cookie.get("name"):
            result[cookie["name"]] = cookie["value"]
    return result


async def verify_chat_endpoint(
    url: str,
    headers: dict,
    cookies: dict,
    body_template: dict,
    message_field: str = "message",
) -> tuple[Optional[bool], str]:
    """
    Send a simple test message to the captured
    endpoint and verify it responds like a chat
    interface not an auth endpoint.

    Returns (is_valid, response_preview) where
    is_valid is True, False, or None if ambiguous.
    """
    test_body = dict(body_template)
    test_body[message_field] = "hello"

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                json=test_body,
                headers=headers,
                cookies=cookies,
                timeout=15,
            )

            body = response.text[:500]

            auth_signals = [
                "authentication successful",
                "access_token",
                "signin",
                "bearer",
            ]
            if any(
                signal in body.lower()
                for signal in auth_signals
            ):
                return False, body[:100]

            chat_signals = [
                "data:",
                "response",
                "message",
                "answer",
                "hello",
                "help",
                "assist",
            ]
            if any(
                signal in body.lower()
                for signal in chat_signals
            ):
                return True, body[:100]

            return None, body[:100]

    except Exception as exc:
        return False, str(exc)


async def save_session(
    session: BrowserSession,
    filepath: str = DEFAULT_SESSION_FILE,
    profile_filepath: str = DEFAULT_PROFILE_FILE,
) -> bool:
    """
    Save captured browser session to disk.

    Auth data -> .aist_session.json
    Request format -> .aist_request_profile.json
    """
    auth_headers = session.headers
    save_auth_session(
        cookies=session.cookies,
        auth_headers=auth_headers,
        operator_identity=session.operator_identity or None,
        filepath=filepath,
    )

    if session.chat_endpoint or session.request_profile:
        profile = dict(session.request_profile)
        profile.setdefault("primary_endpoint", session.chat_endpoint)
        profile.setdefault("message_field", session.message_field)
        profile.setdefault("response_field", session.response_field)
        profile.setdefault("response_type", session.response_type or "json")
        profile.setdefault("streaming", profile.get("streaming", False))
        if session.extra_body_fields:
            template = dict(session.extra_body_fields)
            template[session.message_field] = ""
            profile.setdefault("body_template", template)
        save_request_profile(profile, profile_filepath)

    return True


async def load_session(
    filepath: str = DEFAULT_SESSION_FILE,
    profile_filepath: str = DEFAULT_PROFILE_FILE,
) -> Optional[BrowserSession]:
    """
    Load a previously saved browser session.

    Supports legacy single-file sessions and
    split auth/profile files.
    """
    try:
        with open(filepath, encoding="utf-8") as handle:
            raw = json.load(handle)
    except FileNotFoundError:
        return None
    except Exception as exc:
        log.warning("session_load_error", error=str(exc))
        return None

    # Legacy combined file has chat_endpoint inline
    is_legacy = bool(raw.get("chat_endpoint"))
    if is_legacy:
        auth_data = legacy_session_to_auth(raw)
        profile_data = legacy_session_to_profile(raw)
    else:
        try:
            auth_data = load_auth_session(filepath)
        except ValueError:
            return None
        profile_data = load_request_profile(profile_filepath) or {}

    valid, error, warning = check_session_expiry(
        auth_data if is_legacy else raw
    )
    if not valid:
        return None
    if warning:
        log.warning("session_expiring_soon", message=warning)

    headers = auth_data.get("auth_headers") or auth_data.get("headers") or {}
    cookies = auth_data.get("cookies", [])
    chat_endpoint = (
        profile_data.get("primary_endpoint")
        or raw.get("chat_endpoint", "")
    )
    message_field = profile_data.get(
        "message_field",
        raw.get("message_field", "message"),
    )
    template = profile_data.get("body_template") or {}
    extra_body_fields = {
        k: v
        for k, v in template.items()
        if k != message_field
    }
    if not extra_body_fields:
        extra_body_fields = raw.get("extra_body_fields", {})

    session = BrowserSession(
        chat_endpoint=chat_endpoint,
        message_field=message_field,
        extra_body_fields=extra_body_fields,
        headers=headers,
        cookies=cookies,
        base_url=raw.get("base_url", ""),
        response_field=profile_data.get("response_field", ""),
        response_type=profile_data.get("response_type", "json"),
        operator_identity=auth_data.get("operator_identity", {}),
        request_profile=profile_data,
        expires_at=auth_data.get("expires_at"),
        expires_in_seconds=auth_data.get("expires_in_seconds"),
    )

    remaining_msg = ""
    expires_at = auth_data.get("expires_at") or auth_data.get("expires_estimate")
    if expires_at:
        try:
            from datetime import datetime, timezone

            if isinstance(expires_at, (int, float)):
                remaining = int(expires_at - time.time())
            else:
                ts = datetime.fromisoformat(
                    str(expires_at).replace("Z", "+00:00")
                ).timestamp()
                remaining = int(ts - time.time())
            remaining_msg = f", expires_in_minutes={remaining // 60}"
        except (TypeError, ValueError):
            pass

    log.info(
        "session_loaded",
        endpoint=session.chat_endpoint,
        message=remaining_msg or "loaded",
    )
    return session


def _build_session_from_candidate(
    candidate: dict,
    cookies: list,
    base_url: str,
) -> BrowserSession:
    """Build a BrowserSession from a verified capture candidate."""
    session = BrowserSession(base_url=base_url)
    session.cookies = cookies
    session.chat_endpoint = candidate["url"]
    session.request_format = candidate["body"]

    auth_headers = {
        key: value
        for key, value in candidate["headers"].items()
        if key.lower() in _AUTH_HEADER_KEYS
    }
    session.headers = auth_headers

    body = candidate["body"]
    session.message_field = _detect_message_field(body)
    session.extra_body_fields = {
        key: value
        for key, value in body.items()
        if key != session.message_field
    }

    return session


async def _select_verified_endpoint(
    captured_requests: list,
    cookies: list,
    console,
) -> Optional[dict]:
    """Verify captured requests and return the best chat endpoint."""
    import click

    cookie_dict = _cookies_to_dict(cookies)

    for candidate in reversed(captured_requests):
        message_field = _detect_message_field(candidate["body"])
        is_valid, preview = await verify_chat_endpoint(
            url=candidate["url"],
            headers=candidate["headers"],
            cookies=cookie_dict,
            body_template=candidate["body"],
            message_field=message_field,
        )

        if is_valid is True:
            log.info(
                "chat_endpoint_verified",
                url=candidate["url"],
            )
            return candidate

        if is_valid is False:
            log.info(
                "chat_endpoint_rejected",
                url=candidate["url"],
                reason="verification_failed",
            )
            continue

        console.print(f"""
[yellow]Ambiguous endpoint captured:[/yellow]
  URL: {candidate["url"]}
  Response preview: {preview}

Does this look like a chat interface response?
""")
        if click.confirm("Use this endpoint?", default=True):
            return candidate

    return None


async def capture_browser_session(
    target_url: str,
    headless: bool = False,
    session_file: str = DEFAULT_SESSION_FILE,
    profile_file: str = DEFAULT_PROFILE_FILE,
    capture_profile: bool = True,
) -> Optional[BrowserSession]:
    """
    Launch a browser for the user to log in.
    Captures the session after login completes.

    Args:
        target_url:   The app URL to open
        headless:     False = visible browser (default)
        session_file: Path to save session for reuse

    Returns:
        BrowserSession with captured auth data
        or None if capture failed
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        log.error(
            "playwright_not_installed",
            message="Run: pip install playwright && "
                    "playwright install chromium",
        )
        return None

    from rich.console import Console

    console = Console()

    console.print("""
[bold cyan]Browser Authentication[/bold cyan]

AIST will open a browser window.
Please:
  1. Log in to the application normally
  2. Navigate to the AI chat interface
  3. Send ONE test message to the agent
  4. Return here and press Enter

AIST will capture your session automatically.
""")

    session = BrowserSession(base_url=target_url)
    captured_requests: list = []
    observer = TrafficObserver()

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            headless=headless,
            args=["--no-sandbox"],
        )

        context = await browser.new_context(
            viewport={"width": 1280, "height": 800},
        )

        page = await context.new_page()

        async def handle_response(response) -> None:
            request = response.request
            if capture_profile:
                await observer.on_response(response)

            if request.method != "POST":
                return

            url = request.url
            if _is_auth_url(url):
                return

            if not any(
                keyword in url.lower()
                for keyword in _CHAT_URL_KEYWORDS
            ):
                return

            try:
                post_data = request.post_data
                if not post_data:
                    return
                body_json = json.loads(post_data)
            except json.JSONDecodeError:
                return
            except Exception:
                return

            try:
                response_text = await response.text()
            except Exception:
                response_text = ""

            if _is_auth_response(response_text, body_json):
                log.info(
                    "auth_response_skipped",
                    url=url,
                )
                return

            captured_requests.append({
                "url": url,
                "headers": dict(request.headers),
                "body": body_json,
                "response_preview": response_text[:200],
            })
            log.info(
                "chat_request_captured",
                url=url,
                fields=list(body_json.keys()),
            )

        page.on("response", handle_response)
        if capture_profile:
            page.on("request", observer.on_request)

        await page.goto(target_url)

        console.print(
            "[dim]Browser is open. "
            "Please log in and send a test message...[/dim]"
        )

        await asyncio.to_thread(
            input,
            "\nPress Enter when done...",
        )

        cookies = await context.cookies()
        storage = await context.storage_state()

        session.cookies = cookies
        session.storage_state = storage

        if captured_requests:
            verified = await _select_verified_endpoint(
                captured_requests,
                cookies,
                console,
            )

            if not verified:
                console.print(
                    "[yellow]No verified chat endpoint found. "
                    "Captured requests may be auth endpoints. "
                    "Try sending a message in the chat UI.[/yellow]"
                )
                await browser.close()
                return None

            session = _build_session_from_candidate(
                verified,
                cookies,
                target_url,
            )

            if capture_profile:
                profile = observer.build_profile(session.chat_endpoint)
                session.request_profile = profile
                session.response_type = profile.get(
                    "response_type", "json"
                )
                session.response_field = profile.get(
                    "response_field", ""
                )
                if profile.get("message_field"):
                    session.message_field = profile["message_field"]
                template = profile.get("body_template") or {}
                session.extra_body_fields = {
                    k: v
                    for k, v in template.items()
                    if k != session.message_field
                }
                if observer.data.websocket_detected:
                    console.print(
                        "[yellow]WebSocket detected. AIST does not "
                        "currently support WebSocket scanning. "
                        "The scan will attempt HTTP requests which "
                        "may fail. Some findings may be missed.[/yellow]"
                    )

            expires_at, expiry_type = calculate_cookie_expiry(cookies)
            if expires_at:
                from datetime import datetime, timezone

                session.expires_at = datetime.fromtimestamp(
                    expires_at, tz=timezone.utc
                ).strftime("%Y-%m-%dT%H:%M:%SZ")
                session.expires_in_seconds = max(
                    0, int(expires_at - time.time())
                )

            response_preview = verified.get("response_preview", "")
            session.operator_identity = extract_operator_identity(
                session.headers,
                agent_response=response_preview,
            )

            _print_capture_summary(console, session, observer)
        else:
            console.print(
                "[yellow]No chat requests detected. "
                "Make sure you sent a message "
                "in the chat interface.[/yellow]"
            )
            await browser.close()
            return None

        await browser.close()

    if session.chat_endpoint:
        await save_session(
            session,
            session_file,
            profile_file,
        )
        console.print(
            "[dim]Session saved. Reuse with "
            "--reuse-session and --reuse-profile.[/dim]"
        )

    return session if session.chat_endpoint else None


def _print_capture_summary(
    console,
    session: BrowserSession,
    observer: TrafficObserver,
) -> None:
    """Print session and request profile capture summary."""
    identity = session.operator_identity or {}
    username = identity.get("username") or "unknown"
    role = identity.get("role") or "unknown"

    expiry_line = "session cookie (no fixed expiry)"
    if session.expires_in_seconds is not None:
        hours, rem = divmod(session.expires_in_seconds, 3600)
        minutes = rem // 60
        expiry_line = f"{hours}h {minutes}m"
        if session.expires_at:
            expiry_line += f" ({session.expires_at})"

    console.print(
        f"\n[bold green]Session captured:[/bold green]\n"
        f"  Logged in as: {username}\n"
        f"  Role: {role}\n"
        f"  Session expires: {expiry_line}\n"
    )

    profile = session.request_profile or {}
    extra_fields = [
        k for k in session.extra_body_fields.keys()
    ]
    custom_headers = profile.get("custom_headers") or {}
    resp_type = session.response_type or "json"
    streaming = profile.get("streaming", False)
    resp_label = resp_type.upper()
    if streaming:
        resp_label += " (streaming)"

    console.print(
        f"[bold green]Request profile captured:[/bold green]\n"
        f"  Endpoint: {session.chat_endpoint}\n"
        f"  Message field: {session.message_field}\n"
        f"  Response field: {session.response_field or 'auto'}\n"
        f"  Response type: {resp_label}\n"
        f"  Extra required fields: "
        f"{', '.join(extra_fields) or 'none'}\n"
        f"  Custom headers: "
        f"{', '.join(custom_headers.keys()) or 'none'}\n"
    )

    endpoints = profile.get("discovered_endpoints") or []
    labels = profile.get("endpoint_labels") or {}
    if endpoints:
        console.print(
            f"[bold]Discovered endpoints:[/bold] {len(endpoints)}"
        )
        for path in endpoints[:12]:
            suffix = ""
            if path in labels:
                meta = labels[path]
                suffix = (
                    f" ({meta.get('severity')}: "
                    f"{meta.get('label')})"
                )
            if session.chat_endpoint.endswith(path):
                suffix = " (primary)" + suffix
            console.print(f"  {path}{suffix}")

    if observer.data.js_files_scanned:
        console.print(
            f"\n[bold]JS files scanned:[/bold] "
            f"{observer.data.js_files_scanned}\n"
            f"  Secrets found: {len(observer.data.js_secrets)}\n"
            f"  Additional endpoints found: "
            f"{len(observer.data.js_endpoints)}"
        )

    console.print(
        f"\n[green]✓ Auth headers:[/green] "
        f"{list(session.headers.keys())}\n"
        f"[green]✓ Cookies captured:[/green] {len(session.cookies)}"
    )


async def refresh_browser_session(
    session: BrowserSession,
    target_url: str,
) -> Optional[BrowserSession]:
    """
    Re-capture session when token expires.
    Opens browser again for re-login.
    """
    del session
    log.info(
        "browser_session_refresh",
        message="Session may have expired. "
                "Re-launching browser for re-login.",
    )
    return await capture_browser_session(target_url)
