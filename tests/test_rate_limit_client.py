"""Tests for scan delay and rate-limit handling."""

import asyncio
from unittest.mock import AsyncMock, patch

import httpx

from aist.http.client import (
    apply_scan_delay,
    handle_rate_limit,
    retry_after_seconds,
)


def test_retry_after_header_parsed() -> None:
    """Retry-After numeric header is respected."""
    request = httpx.Request("GET", "https://example.com")
    response = httpx.Response(
        429,
        headers={"Retry-After": "30"},
        request=request,
    )
    assert retry_after_seconds(response) == 30


def test_retry_after_defaults_to_sixty() -> None:
    """Missing Retry-After defaults to 60 seconds."""
    request = httpx.Request("GET", "https://example.com")
    response = httpx.Response(429, request=request)
    assert retry_after_seconds(response) == 60


def test_apply_scan_delay_sleeps() -> None:
    """Scan delay invokes asyncio.sleep."""
    with patch("aist.http.client.asyncio.sleep", new=AsyncMock()) as sleep:
        asyncio.run(apply_scan_delay(1.5))
        sleep.assert_awaited_once_with(1.5)


def test_handle_rate_limit_pauses_and_retries() -> None:
    """429 responses trigger a pause and retry signal."""
    request = httpx.Request("GET", "https://example.com")
    response = httpx.Response(
        429,
        headers={"Retry-After": "1"},
        request=request,
    )
    with patch("aist.http.client.asyncio.sleep", new=AsyncMock()) as sleep:
        should_retry = asyncio.run(
            handle_rate_limit(
                response,
                attempt=0,
                max_retries=3,
            )
        )
    assert should_retry is True
    sleep.assert_awaited_once_with(1)
