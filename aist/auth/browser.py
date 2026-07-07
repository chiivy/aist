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

from aist.logger import get_logger

log = get_logger(__name__)

DEFAULT_SESSION_FILE = ".aist_session.json"

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
    base_url: str = ""
    chat_endpoint: str = ""
    message_field: str = "message"
    extra_body_fields: dict = field(default_factory=dict)


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
) -> bool:
    """
    Save captured browser session to disk
    for reuse within the token expiry window.

    Saves: cookies, headers, body format,
    endpoint, expiry estimate.

    File is saved in the current directory.
    """
    session_data = {
        "captured_at": time.time(),
        "expires_estimate": time.time() + 7200,
        "chat_endpoint": session.chat_endpoint,
        "message_field": session.message_field,
        "extra_body_fields": session.extra_body_fields,
        "headers": session.headers,
        "cookies": session.cookies,
        "base_url": session.base_url,
    }

    try:
        with open(filepath, "w", encoding="utf-8") as handle:
            json.dump(session_data, handle, indent=2)
        return True
    except Exception as exc:
        log.warning("session_save_error", error=str(exc))
        return False


async def load_session(
    filepath: str = DEFAULT_SESSION_FILE,
) -> Optional[BrowserSession]:
    """
    Load a previously saved browser session.
    Returns None if session file does not exist
    or session has expired.
    """
    try:
        with open(filepath, encoding="utf-8") as handle:
            data = json.load(handle)

        expires = data.get("expires_estimate", 0)
        if time.time() > expires:
            log.info(
                "session_expired",
                message="Saved session has expired. "
                        "Re-authentication required.",
            )
            return None

        session = BrowserSession(
            chat_endpoint=data["chat_endpoint"],
            message_field=data.get("message_field", "message"),
            extra_body_fields=data.get("extra_body_fields", {}),
            headers=data.get("headers", {}),
            cookies=data.get("cookies", []),
            base_url=data.get("base_url", ""),
        )

        remaining = int((expires - time.time()) / 60)
        log.info(
            "session_loaded",
            endpoint=session.chat_endpoint,
            expires_in_minutes=remaining,
        )

        return session

    except FileNotFoundError:
        return None
    except Exception as exc:
        log.warning("session_load_error", error=str(exc))
        return None


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

            console.print(f"""
[green]✓ Chat endpoint verified:[/green]
  {session.chat_endpoint}

[green]✓ Message field:[/green] {session.message_field}
[green]✓ Extra body fields:[/green] {list(session.extra_body_fields.keys())}
[green]✓ Auth headers:[/green] {list(session.headers.keys())}
[green]✓ Cookies captured:[/green] {len(cookies)}
""")
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
        await save_session(session, session_file)
        console.print(
            "[dim]Session saved. Reuse with "
            "--reuse-session within 2 hours.[/dim]"
        )

    return session if session.chat_endpoint else None


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
