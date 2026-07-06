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
from dataclasses import dataclass, field
from typing import Optional

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


async def capture_browser_session(
    target_url: str,
    headless: bool = False,
) -> Optional[BrowserSession]:
    """
    Launch a browser for the user to log in.
    Captures the session after login completes.

    Args:
        target_url: The app URL to open
        headless:   False = visible browser (default)
                    True = hidden (for CI/CD)

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

        async def handle_request(request) -> None:
            url = request.url
            method = request.method

            if method != "POST":
                return

            if not any(
                keyword in url.lower()
                for keyword in _CHAT_URL_KEYWORDS
            ):
                return

            try:
                body = request.post_data
                if not body:
                    return
                body_json = json.loads(body)
                captured_requests.append({
                    "url": url,
                    "headers": dict(request.headers),
                    "body": body_json,
                })
                log.info(
                    "chat_request_captured",
                    url=url,
                    fields=list(body_json.keys()),
                )
            except json.JSONDecodeError:
                pass
            except Exception:
                pass

        page.on("request", handle_request)

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
            latest = captured_requests[-1]

            session.chat_endpoint = latest["url"]
            session.request_format = latest["body"]

            auth_headers = {
                key: value
                for key, value in latest["headers"].items()
                if key.lower() in _AUTH_HEADER_KEYS
            }
            session.headers = auth_headers

            body = latest["body"]
            session.message_field = _detect_message_field(body)
            session.extra_body_fields = {
                key: value
                for key, value in body.items()
                if key != session.message_field
            }

            console.print(f"""
[green]✓ Session captured successfully[/green]

  Chat endpoint: {session.chat_endpoint}
  Message field: {session.message_field}
  Extra fields:  {list(session.extra_body_fields.keys())}
  Auth headers:  {list(auth_headers.keys())}
  Cookies:       {len(cookies)} captured
""")
        else:
            console.print(
                "[yellow]No chat requests detected. "
                "Make sure you sent a message "
                "in the chat interface.[/yellow]"
            )

        await browser.close()

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
