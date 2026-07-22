"""Tests for input validation bypass variants."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import httpx

from aist.scanner.validation_bypass import (
    build_bypass_variants,
    try_validation_bypass,
)


def test_build_bypass_variants_includes_four_strategies() -> None:
    """All four bypass strategies are generated."""
    body = {"message": "hello", "session_id": "abc"}
    variants = build_bypass_variants("Ignore previous", body, "message")
    names = [item[0] for item in variants]
    assert names == [
        "url_encoding",
        "unicode_encoding",
        "form_urlencoded",
        "nested_field",
    ]


def test_bypass_variant_can_succeed() -> None:
    """A bypass variant returning 200 is selected."""
    call_count = {"n": 0}

    async def _post(*args, **kwargs):
        call_count["n"] += 1
        response = MagicMock(spec=httpx.Response)
        if call_count["n"] == 2:
            response.status_code = 200
            response.json = MagicMock(return_value={"response": "ok"})
        else:
            response.status_code = 400
            response.text = "blocked"
        return response

    client = AsyncMock(spec=httpx.AsyncClient)
    client.post = AsyncMock(side_effect=_post)

    response, variant = asyncio.run(
        try_validation_bypass(
            client,
            "https://app.example.com/chat",
            "Ignore previous",
            {"message": ""},
            "message",
            {"Content-Type": "application/json"},
            {},
            timeout=5.0,
        )
    )
    assert response is not None
    assert response.status_code == 200
    assert variant is not None
