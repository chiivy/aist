"""
AIST Authentication Manager

Handles all authentication methods for
scanning protected AI agent endpoints.

Supported methods:
    bearer  -- Pre-captured Bearer token
    basic   -- Username/password login
    sso     -- Azure AD device code flow
    apikey  -- API key in header
    cookie  -- Session cookie
    browser -- Interactive browser login (SSO/MFA)
    none    -- No authentication (default)
"""

import httpx
import time
from typing import TYPE_CHECKING, Any, Optional
from dataclasses import dataclass, field
from aist.logger import get_logger

if TYPE_CHECKING:
    from aist.auth.browser import BrowserSession
    from aist.config import TargetConfig

log = get_logger(__name__)


@dataclass
class AuthConfig:
    """Authentication configuration."""
    auth_type: str = "none"
    token: Optional[str] = None
    header_name: str = "Authorization"
    username: Optional[str] = None
    password: Optional[str] = None
    login_url: Optional[str] = None
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    cookie_name: Optional[str] = None
    cookie_value: Optional[str] = None
    token_expiry: Optional[int] = None
    browser_target_url: str = ""
    browser_session: Optional[Any] = None


class AuthManager:
    """
    Single entry point for all auth methods.
    Call get_headers() to get auth headers
    to attach to every scan request.
    """

    def __init__(
        self,
        config: AuthConfig,
        target_config: Optional["TargetConfig"] = None,
    ):
        self.config = config
        self.target_config = target_config
        self._token: Optional[str] = None
        self._cookies: dict = {}
        self._token_expires_at: Optional[float] = None
        self._browser_session: Optional["BrowserSession"] = None
        self._browser_headers: dict = {}

    async def authenticate(self) -> bool:
        """
        Run authentication flow based on
        configured auth_type.

        Returns True if authentication succeeded.
        """
        auth_type = self.config.auth_type.lower()

        if auth_type == "none":
            log.info("auth_skipped",
                message="No authentication configured.")
            return True

        elif auth_type == "bearer":
            return await self._setup_bearer()

        elif auth_type == "apikey":
            return await self._setup_apikey()

        elif auth_type == "basic":
            return await self._login_basic()

        elif auth_type == "sso":
            return await self._login_sso()

        elif auth_type == "cookie":
            return await self._setup_cookie()

        elif auth_type == "browser":
            return await self._login_browser()

        else:
            log.warning("unknown_auth_type",
                auth_type=auth_type)
            return False

    def get_headers(self) -> dict:
        """
        Return auth headers to attach to
        every scan request.
        """
        if not self._token and not self._cookies:
            return {}

        headers = {}
        if self._browser_headers:
            headers.update(self._browser_headers)
        if self._token:
            headers[self.config.header_name] = self._token
        return headers

    def get_cookies(self) -> dict:
        """
        Return auth cookies to attach to
        every scan request.
        """
        return self._cookies

    def get_browser_session(self) -> Optional["BrowserSession"]:
        """Return captured browser session, if any."""
        return self._browser_session

    def apply_browser_session_to_target(self) -> None:
        """Apply captured request format to target config."""
        session = self._browser_session
        target = self.target_config
        if not session or not target:
            return

        if session.message_field:
            target.message_field = session.message_field
        if session.extra_body_fields:
            target.custom_body_fields = dict(
                session.extra_body_fields
            )

    def is_token_expired(self) -> bool:
        """Check if token is expired or expiring soon."""
        if not self._token_expires_at:
            return False
        return time.time() > (self._token_expires_at - 300)

    async def refresh_token_if_needed(self) -> bool:
        """Refresh token before expiry if supported."""
        if not self.is_token_expired():
            return True

        log.info(
            "token_refresh_needed",
            message="Token expiring soon, refreshing...",
        )

        auth_type = self.config.auth_type.lower()
        if auth_type == "sso":
            return await self._refresh_sso_token()
        elif auth_type == "basic":
            return await self._login_basic()
        elif auth_type == "browser":
            return await self._login_browser()
        else:
            log.warning(
                "token_refresh_not_supported",
                auth_type=auth_type,
                message="Cannot auto-refresh this token type. "
                        "Re-run scan with fresh token.",
            )
            return False

    async def _refresh_sso_token(self) -> bool:
        """Silently refresh SSO token using cached credentials."""
        try:
            import msal
        except ImportError:
            log.error(
                "msal_not_installed",
                message="Run: pip install msal",
            )
            return False

        try:
            app = msal.PublicClientApplication(
                client_id=self.config.client_id,
                authority=(
                    f"https://login.microsoftonline.com/"
                    f"{self.config.tenant_id}"
                ),
            )
            accounts = app.get_accounts()
            if accounts:
                result = app.acquire_token_silent(
                    scopes=[
                        "openid", "profile", "offline_access",
                    ],
                    account=accounts[0],
                )
                if result and "access_token" in result:
                    self._token = (
                        f"Bearer {result['access_token']}"
                    )
                    expires_in = result.get("expires_in", 3600)
                    self._token_expires_at = (
                        time.time() + expires_in
                    )
                    log.info("token_refreshed_silently")
                    return True

            log.warning(
                "silent_refresh_failed",
                message="No cached account found. "
                        "Re-authenticate with --auth-type sso",
            )
            return False
        except Exception as e:
            log.error("token_refresh_error", error=str(e))
            return False

    async def _setup_bearer(self) -> bool:
        """Use pre-captured Bearer token."""
        if not self.config.token:
            log.error("bearer_token_missing",
                message="--auth-token required "
                        "for bearer auth type.")
            return False

        token = self.config.token
        if not token.startswith("Bearer "):
            token = f"Bearer {token}"

        self._token = token
        self._token_expires_at = time.time() + 3600
        log.info("auth_bearer_configured",
            token_preview=token[:20] + "...")
        return True

    async def _setup_apikey(self) -> bool:
        """Use API key in custom header."""
        if not self.config.token:
            log.error("apikey_missing",
                message="--auth-token required "
                        "for apikey auth type.")
            return False

        self._token = self.config.token
        log.info("auth_apikey_configured",
            header=self.config.header_name)
        return True

    async def _setup_cookie(self) -> bool:
        """Use pre-captured session cookie."""
        if not self.config.cookie_value:
            log.error("cookie_missing",
                message="--auth-cookie required "
                        "for cookie auth type.")
            return False

        self._cookies = {
            self.config.cookie_name: (
                self.config.cookie_value
            )
        }
        log.info("auth_cookie_configured",
            cookie_name=self.config.cookie_name)
        return True

    async def _login_browser(self) -> bool:
        """
        Launch a browser for interactive login and
        capture session cookies, headers, and format.
        """
        from aist.auth.browser import capture_browser_session

        url = (
            self.config.browser_target_url
            or self.config.login_url
            or ""
        )

        if not url:
            log.error(
                "browser_auth_no_url",
                message="Provide --auth-login-url "
                        "for browser auth",
            )
            return False

        session = await capture_browser_session(url)

        if not session:
            return False

        if session.headers:
            self._browser_headers = dict(session.headers)
            auth_header = (
                session.headers.get("authorization")
                or session.headers.get("Authorization")
            )
            if auth_header:
                self._token = auth_header
                if auth_header.lower().startswith("bearer "):
                    self.config.header_name = "Authorization"

        if session.cookies:
            self._cookies = {
                cookie["name"]: cookie["value"]
                for cookie in session.cookies
            }

        self._browser_session = session
        self.config.browser_session = session
        self.apply_browser_session_to_target()

        if session.chat_endpoint:
            log.info(
                "browser_auth_endpoint_captured",
                endpoint=session.chat_endpoint,
            )

        log.info(
            "browser_auth_success",
            endpoint=session.chat_endpoint,
            cookies=len(session.cookies),
            headers=list(session.headers.keys()),
        )

        return True

    async def _login_basic(self) -> bool:
        """
        Login with username/password.
        POSTs to login endpoint and extracts
        token from response.
        """
        if not all([
            self.config.username,
            self.config.password,
            self.config.login_url,
        ]):
            log.error("basic_auth_missing",
                message="--auth-username, "
                        "--auth-password, and "
                        "--auth-login-url required "
                        "for basic auth type.")
            return False

        log.info("auth_basic_attempting",
            url=self.config.login_url,
            username=self.config.username)

        try:
            async with httpx.AsyncClient() as client:
                # Try JSON login first
                response = await client.post(
                    self.config.login_url,
                    json={
                        "username": self.config.username,
                        "password": self.config.password,
                    },
                    timeout=30,
                )

                if response.status_code == 200:
                    data = response.json()

                    # Try common token field names
                    token = (
                        data.get("access_token") or
                        data.get("token") or
                        data.get("accessToken") or
                        data.get("jwt") or
                        data.get("id_token")
                    )

                    if token:
                        self._token = f"Bearer {token}"
                        self._token_expires_at = (
                            time.time() + 3600
                        )
                        log.info(
                            "auth_basic_success",
                            token_preview=(
                                self._token[:20] + "..."
                            )
                        )
                        return True

                    # Check for session cookie
                    if response.cookies:
                        self._cookies = dict(
                            response.cookies
                        )
                        log.info(
                            "auth_basic_cookie_success",
                            cookies=list(
                                self._cookies.keys()
                            )
                        )
                        return True

                log.error("auth_basic_failed",
                    status_code=response.status_code)
                return False

        except Exception as e:
            log.error("auth_basic_error",
                error=str(e))
            return False

    async def _login_sso(self) -> bool:
        """
        Azure AD device code flow.
        Prints a URL and code for the user
        to authenticate in their browser.
        Microsoft issues the token automatically.
        """
        if not all([
            self.config.tenant_id,
            self.config.client_id,
        ]):
            log.error("sso_config_missing",
                message="--auth-tenant-id and "
                        "--auth-client-id required "
                        "for sso auth type.")
            return False

        try:
            import msal
        except ImportError:
            log.error("msal_not_installed",
                message="Run: pip install msal")
            return False

        app = msal.PublicClientApplication(
            client_id=self.config.client_id,
            authority=(
                f"https://login.microsoftonline.com/"
                f"{self.config.tenant_id}"
            ),
        )

        # Start device code flow
        flow = app.initiate_device_flow(
            scopes=["openid", "profile",
                    "offline_access"]
        )

        if "user_code" not in flow:
            log.error("sso_flow_failed",
                error=flow.get("error_description"))
            return False

        # Show the user what to do
        print("\n" + "="*50)
        print("AIST SSO Authentication Required")
        print("="*50)
        print(f"\nGo to: {flow['verification_uri']}")
        print(f"Enter code: {flow['user_code']}")
        print("\nWaiting for you to authenticate...")
        print("="*50 + "\n")

        # Wait for authentication
        result = app.acquire_token_by_device_flow(flow)

        if "access_token" in result:
            self._token = (
                f"Bearer {result['access_token']}"
            )
            expires_in = result.get("expires_in", 3600)
            self._token_expires_at = time.time() + expires_in
            log.info("auth_sso_success",
                token_preview=self._token[:20] + "...")
            return True

        log.error("auth_sso_failed",
            error=result.get("error_description"))
        return False