"""Shared HTTP client helpers: scan delay and rate limits."""

from __future__ import annotations

import asyncio
from typing import Optional

import httpx

from aist.logger import get_logger

log = get_logger(__name__)


async def apply_scan_delay(scan_delay: float) -> None:
    """Sleep between scan requests when configured."""
    if scan_delay and scan_delay > 0:
        await asyncio.sleep(scan_delay)


def retry_after_seconds(response: httpx.Response) -> int:
    """Read Retry-After header or default to 60 seconds."""
    header = response.headers.get("Retry-After", "")
    if header.isdigit():
        return int(header)
    return 60


async def handle_rate_limit(
    response: httpx.Response,
    *,
    attempt: int,
    max_retries: int = 5,
) -> bool:
    """
    Pause on 429 and indicate whether to retry.

    Returns True if caller should retry same request.
    """
    if response.status_code != 429:
        return False
    if attempt >= max_retries:
        log.warning("rate_limited_exhausted", attempts=attempt)
        return False
    wait_time = retry_after_seconds(response)
    log.warning(
        "rate_limited",
        waiting_seconds=wait_time,
        attempt=attempt + 1,
    )
    await asyncio.sleep(wait_time)
    return True


def warn_auth_failure(status_code: int) -> None:
    """Log session expiry warning on 401/403."""
    if status_code in (401, 403):
        log.warning(
            "auth_response_received",
            status=status_code,
            message=(
                f"Received {status_code}. Session may have expired. "
                "If scan produces no findings, re-authenticate with "
                "--auth-type browser."
            ),
        )
