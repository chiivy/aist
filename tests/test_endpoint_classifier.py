"""Tests for smart AI endpoint classification."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from aist.scanner.endpoint_classifier import (
    EndpointClassifier,
    apply_classified_endpoint_to_target,
    select_ai_targets,
)


def _mock_response(
    status: int = 200,
    json_body=None,
    text: str = "",
):
    response = MagicMock(spec=httpx.Response)
    response.status_code = status
    response.text = text
    if json_body is None:
        response.json.side_effect = ValueError("not json")
    else:
        response.json.return_value = json_body
    return response


def test_excluded_domain_filtering() -> None:
    """Third-party domains are excluded without probing."""
    classifier = EndpointClassifier()
    assert classifier.is_excluded_domain(
        "https://login.microsoftonline.com/oauth"
    )
    assert classifier.is_excluded_domain(
        "https://www.google-analytics.com/collect"
    )
    assert not classifier.is_excluded_domain(
        "https://app.example.com/api/chat"
    )


def test_natural_language_detection() -> None:
    """Long NL response field classifies as AI agent."""
    classifier = EndpointClassifier()
    body = {
        "answer": (
            "I can help you check fuel levels, "
            "maintenance schedules, and site status."
        )
    }
    hit = classifier._find_natural_language_field(body)
    assert hit is not None
    assert hit[0] == "answer"


def test_structured_data_detection() -> None:
    """Structured-only responses are treated as APIs."""
    classifier = EndpointClassifier()

    async def run() -> dict:
        response = _mock_response(
            200,
            json_body={"data": [], "count": 0, "status": "ok"},
        )
        client = AsyncMock()
        client.post = AsyncMock(return_value=response)
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)

        with patch(
            "aist.scanner.endpoint_classifier.httpx.AsyncClient",
            return_value=client,
        ):
            return await classifier._probe(
                "https://app.example.com/api/sites",
                {},
                {},
            )

    result = asyncio.run(run())
    assert result["type"] == "api"
    assert "Structured fields" in result["evidence"]


def test_two_probe_comparison_detects_ai() -> None:
    """Changing responses across probes classify as AI."""
    classifier = EndpointClassifier()

    first = _mock_response(
        200,
        json_body={"status": "ok", "payload": "a"},
    )
    second = _mock_response(
        200,
        json_body={
            "answer": (
                "I can help with fuel levels and "
                "maintenance schedules for sites."
            )
        },
    )

    async def run() -> dict:
        client = AsyncMock()
        client.post = AsyncMock(side_effect=[first, second])
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)

        with patch(
            "aist.scanner.endpoint_classifier.httpx.AsyncClient",
            return_value=client,
        ):
            return await classifier._probe(
                "https://app.example.com/api/assistant",
                {},
                {},
            )

    result = asyncio.run(run())
    assert result["type"] == "ai_agent"
    assert result["confidence"] == 70
    assert "varies" in result["evidence"]


def test_auth_and_error_status_codes() -> None:
    """401/403 map to auth; 404 maps to error."""
    classifier = EndpointClassifier()

    async def probe_status(status: int) -> dict:
        response = _mock_response(status, json_body={})
        client = AsyncMock()
        client.post = AsyncMock(return_value=response)
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)
        with patch(
            "aist.scanner.endpoint_classifier.httpx.AsyncClient",
            return_value=client,
        ):
            return await classifier._probe(
                "https://app.example.com/api/x",
                {},
                {},
            )

    assert asyncio.run(probe_status(401))["type"] == "auth"
    assert asyncio.run(probe_status(404))["type"] == "error"


def test_full_classification_flow() -> None:
    """classify_endpoints buckets AI, API, excluded, errors."""
    classifier = EndpointClassifier()

    async def run() -> dict:
        ai_response = _mock_response(
            200,
            json_body={
                "response": (
                    "Hello! I am the site assistant and I "
                    "can answer questions about fuel."
                )
            },
        )
        api_response = _mock_response(
            200,
            json_body={"data": [], "count": 0, "status": "ok"},
        )
        error_response = _mock_response(404, json_body={})

        client = AsyncMock()
        client.post = AsyncMock(
            side_effect=[
                ai_response,
                api_response,
                api_response,  # second probe comparison
                error_response,
            ]
        )
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)

        with patch(
            "aist.scanner.endpoint_classifier.httpx.AsyncClient",
            return_value=client,
        ):
            with patch(
                "aist.scanner.endpoint_classifier.apply_scan_delay",
                new=AsyncMock(),
            ):
                return await classifier.classify_endpoints(
                    endpoints=[
                        "/api/assistant",
                        "/api/sites",
                        "/api/missing",
                        "https://login.microsoftonline.com/token",
                    ],
                    base_url="https://app.example.com/chat",
                    auth_headers={"Authorization": "Bearer x"},
                    cookies={},
                    scan_delay=0,
                )

    results = asyncio.run(run())
    assert len(results["ai_agents"]) == 1
    assert results["ai_agents"][0]["confidence"] == 85
    assert len(results["apis"]) == 1
    assert len(results["excluded"]) == 1
    assert len(results["errors"]) == 1


def test_select_ai_targets_respects_multi_endpoint() -> None:
    """Without multi_endpoint only the top agent is selected."""
    classification = {
        "ai_agents": [
            {"url": "https://a", "confidence": 90},
            {"url": "https://b", "confidence": 70},
        ]
    }
    single = select_ai_targets(classification, multi_endpoint=False)
    assert len(single) == 1
    assert single[0]["url"] == "https://a"

    multi = select_ai_targets(classification, multi_endpoint=True)
    assert len(multi) == 2


def test_apply_classified_endpoint_to_target() -> None:
    """Target config is updated from classification result."""
    target = MagicMock()
    apply_classified_endpoint_to_target(
        target,
        {
            "url": "https://app.example.com/api/chat",
            "message_field": "query",
            "response_field": "answer",
        },
    )
    assert target.endpoint == "https://app.example.com/api/chat"
    assert target.message_field == "query"
    assert target.response_field == "answer"
