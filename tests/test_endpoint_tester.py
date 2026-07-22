"""Tests for safe endpoint auth enforcement testing."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from aist.scanner.endpoint_tester import check_endpoint_auth


def _mock_response(status: int, text: str = "", headers: dict | None = None):
    response = MagicMock(spec=httpx.Response)
    response.status_code = status
    response.text = text
    response.headers = headers or {}
    return response


def test_unauthenticated_endpoint_flagged_high() -> None:
    """200 response without auth creates a high finding."""
    mock_client = AsyncMock()
    mock_client.request = AsyncMock(
        return_value=_mock_response(
            200,
            headers={"Allow": "GET,HEAD"},
        )
    )
    mock_client.get = AsyncMock(
        side_effect=[
            _mock_response(200, "secret config data"),
            _mock_response(401, "denied"),
        ]
    )

    with patch(
        "aist.scanner.endpoint_tester.httpx.AsyncClient"
    ) as client_cls:
        client_cls.return_value.__aenter__.return_value = mock_client
        findings = asyncio.run(
            check_endpoint_auth(
                "https://app.example.com/api/chat",
                "/api/config",
                auth_headers={"Authorization": "Bearer valid"},
                auth_cookies={},
                scan_delay=0,
            )
        )

    assert any(f.check == "no_auth_required" for f in findings)
    assert any(f.severity == "High" for f in findings)


def test_dangerous_method_allowed() -> None:
    """OPTIONS exposing DELETE yields medium finding."""
    mock_client = AsyncMock()
    mock_client.request = AsyncMock(
        return_value=_mock_response(
            200,
            headers={"Allow": "GET,DELETE,OPTIONS"},
        )
    )
    mock_client.get = AsyncMock(
        return_value=_mock_response(401, "denied")
    )

    with patch(
        "aist.scanner.endpoint_tester.httpx.AsyncClient"
    ) as client_cls:
        client_cls.return_value.__aenter__.return_value = mock_client
        findings = asyncio.run(
            check_endpoint_auth(
                "https://app.example.com/api/chat",
                "/api/admin",
                auth_headers={"Authorization": "Bearer valid"},
                auth_cookies={},
                scan_delay=0,
            )
        )

    assert any(f.check == "dangerous_method" for f in findings)
