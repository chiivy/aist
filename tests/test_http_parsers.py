"""Tests for HTTP response parsers."""

import json

import httpx

from aist.http.parsers import (
    JsonResponseParser,
    NdjsonResponseParser,
    SseResponseParser,
    get_parser,
)


def _response(content: bytes, content_type: str) -> httpx.Response:
    request = httpx.Request("POST", "https://example.com/chat")
    return httpx.Response(
        200,
        content=content,
        headers={"content-type": content_type},
        request=request,
    )


def test_json_parser_uses_response_field() -> None:
    """JSON parser returns configured response field."""
    body = {"answer": "Hello from the agent assistant"}
    response = _response(
        json.dumps(body).encode(),
        "application/json",
    )
    parser = JsonResponseParser(response_field="answer")
    assert "Hello from the agent" in parser.parse(response)


def test_sse_parser_assembles_chunks() -> None:
    """SSE parser joins data chunks."""
    payload = (
        "data: {\"content\": \"Hello \"}\n\n"
        "data: {\"content\": \"world\"}\n\n"
        "data: [DONE]\n\n"
    )
    response = _response(
        payload.encode(),
        "text/event-stream",
    )
    text = SseResponseParser().parse(response)
    assert text == "Hello world"


def test_ndjson_parser_assembles_lines() -> None:
    """NDJSON parser joins newline-delimited objects."""
    payload = (
        "{\"text\": \"Line one with enough chars\"}\n"
        "{\"text\": \" and more\"}\n"
    )
    response = _response(
        payload.encode(),
        "application/x-ndjson",
    )
    text = NdjsonResponseParser().parse(response)
    assert "Line one" in text
    assert "and more" in text


def test_get_parser_returns_expected_type() -> None:
    """get_parser selects parser by response type."""
    assert isinstance(get_parser("json"), JsonResponseParser)
    assert isinstance(get_parser("sse"), SseResponseParser)
    assert isinstance(get_parser("ndjson"), NdjsonResponseParser)
