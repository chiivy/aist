"""HTTP response parsers for agent endpoints."""

from __future__ import annotations

import json
from typing import Any, Optional

import httpx


class JsonResponseParser:
    """Parse standard JSON chat responses."""

    def __init__(self, response_field: str = ""):
        self.response_field = response_field

    def parse(self, response: httpx.Response) -> str:
        try:
            body = response.json()
        except json.JSONDecodeError:
            return response.text
        if self.response_field and isinstance(body, dict):
            value = body.get(self.response_field, "")
            if isinstance(value, str):
                return value
        if isinstance(body, dict):
            for key, value in body.items():
                if isinstance(value, str) and len(value) > 20:
                    return value
        return str(body)


class SseResponseParser:
    """Parse Server-Sent Events streaming responses."""

    def parse(self, response: httpx.Response) -> str:
        chunks: list[str] = []
        for line in response.iter_lines():
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                break
            try:
                obj = json.loads(data)
                chunk = (
                    obj.get("content")
                    or obj.get("text")
                    or obj.get("response")
                    or obj.get("delta", {}).get("content")
                    or (
                        obj.get("choices", [{}])[0]
                        .get("delta", {})
                        .get("content", "")
                    )
                )
                if chunk:
                    chunks.append(str(chunk))
            except json.JSONDecodeError:
                chunks.append(data)
        return "".join(chunks)


class NdjsonResponseParser:
    """Parse newline-delimited JSON streaming responses."""

    def parse(self, response: httpx.Response) -> str:
        chunks: list[str] = []
        for line in response.iter_lines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                chunk = (
                    obj.get("content")
                    or obj.get("text")
                    or obj.get("response")
                    or ""
                )
                if chunk:
                    chunks.append(str(chunk))
            except json.JSONDecodeError:
                pass
        return "".join(chunks)


class WebSocketParser:
    """WebSocket responses are not supported."""

    def parse(self, response: httpx.Response) -> str:
        raise NotImplementedError(
            "WebSocket scanning not supported. "
            "Use --response-type json if the app "
            "has a REST fallback endpoint."
        )


def get_parser(
    response_type: str,
    response_field: str = "",
) -> JsonResponseParser | SseResponseParser | NdjsonResponseParser:
    """Return parser instance for response type."""
    parsers = {
        "json": JsonResponseParser,
        "sse": SseResponseParser,
        "ndjson": NdjsonResponseParser,
        "websocket": WebSocketParser,
    }
    parser_cls = parsers.get(response_type, JsonResponseParser)
    if parser_cls is JsonResponseParser:
        return JsonResponseParser(response_field=response_field)
    return parser_cls()


def extract_response_text(
    response: httpx.Response,
    response_type: str = "json",
    response_field: str = "",
) -> str:
    """Parse agent response body to plain text."""
    parser = get_parser(response_type, response_field)
    return parser.parse(response)
