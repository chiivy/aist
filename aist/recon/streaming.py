"""
AIST Streaming Response Handler

Handles both streaming and non-streaming agent responses
so the rest of AIST does not need to handle both cases
separately.

Assembles complete responses from streamed chunks and
strips metadata tokens before passing content to the
evidence collector.
"""

import json
import httpx
from dataclasses import dataclass
from typing import Optional

from aist.logger import get_logger

log = get_logger(__name__)


# Metadata tokens that appear in streamed responses
# and need to be stripped before analysis
STREAM_METADATA_TOKENS = [
    "[DONE]",
    "<|end|>",
    "<|im_end|>",
    "<|endoftext|>",
    "</s>",
    "[END]",
    "data: [DONE]",
]

COMMON_RESPONSE_FIELDS = [
    "response",
    "answer",
    "message",
    "content",
    "output",
    "result",
    "text",
    "reply",
    "completion",
    "generated_text",
    "choices",
]


@dataclass
class AssembledResponse:
    """
    A fully assembled response from either
    streaming or non-streaming source.
    """
    content: str
    was_streaming: bool
    chunk_count: int = 0
    token_smuggling_risk: bool = False
    raw_chunks: list = None

    def __post_init__(self):
        if self.raw_chunks is None:
            self.raw_chunks = []


def extract_response_text(
    data: dict,
    configured_field: str = "",
) -> str:
    """
    Extract agent response text from a JSON object.

    Uses the configured field when set, otherwise
    auto-detects common response field names.

    Args:
        data:              Parsed JSON response body
        configured_field:  Explicit field name, or empty
                           for auto-detection

    Returns:
        Extracted response text
    """
    if configured_field and configured_field in data:
        return str(data[configured_field])

    for field in COMMON_RESPONSE_FIELDS:
        if field not in data:
            continue
        value = data[field]
        if field == "choices" and isinstance(value, list):
            if value and isinstance(value[0], dict):
                message = value[0].get("message", {})
                if isinstance(message, dict):
                    return str(message.get("content", ""))
                return str(message)
        return str(value)

    return str(data)


def _is_sse_format(content_type: str, text: str) -> bool:
    """Return True if the response body looks like SSE."""
    return (
        "text/event-stream" in content_type.lower()
        or text.strip().startswith("data:")
    )


def _parse_sse_response(text: str) -> str:
    """
    Parse Server-Sent Events response format.

    Extracts and assembles text from SSE data lines.

    Args:
        text: Raw SSE response body

    Returns:
        Assembled response text
    """
    lines = text.strip().split("\n")
    assembled = []

    for line in lines:
        line = line.strip()

        if not line or line.startswith(":"):
            continue

        if not line.startswith("data:"):
            continue

        data_str = line[5:].strip()

        if data_str == "[DONE]":
            continue

        try:
            data = json.loads(data_str)

            if "choices" in data and isinstance(data["choices"], list):
                if data["choices"]:
                    delta = data["choices"][0].get("delta", {})
                    if "content" in delta:
                        assembled.append(delta["content"])
            elif "token" in data:
                assembled.append(str(data["token"]))
            elif "content" in data:
                assembled.append(str(data["content"]))
            elif "text" in data:
                assembled.append(str(data["text"]))
            elif "response" in data:
                assembled.append(str(data["response"]))

        except json.JSONDecodeError:
            if data_str:
                assembled.append(data_str)

    return "".join(assembled)


async def collect_streaming_response(
    response: httpx.Response,
    response_field: str = "",
) -> AssembledResponse:
    """
    Collect and assemble a streaming HTTP response.

    Buffers all chunks, strips metadata tokens,
    and assembles into a complete response string.

    Args:
        response:        httpx streaming response object
        response_field:  Configured JSON field for responses

    Returns:
        AssembledResponse with complete content
    """
    chunks = []
    raw_chunks = []

    async for chunk in response.aiter_text():
        raw_chunks.append(chunk)
        clean_chunk = _strip_metadata(chunk)
        if clean_chunk:
            chunks.append(clean_chunk)

    full_raw = "".join(raw_chunks)
    content_type = response.headers.get("content-type", "")

    if _is_sse_format(content_type, full_raw):
        parsed = _parse_sse_response(full_raw)
        if parsed:
            log.info(
                "sse_response_parsed",
                original_length=len(full_raw),
                parsed_length=len(parsed),
            )
            full_content = parsed
        else:
            full_content = "".join(chunks)
    else:
        full_content = "".join(chunks)

    token_smuggling_risk = _check_token_smuggling(
        raw_chunks,
        full_content,
    )

    if token_smuggling_risk:
        log.warning(
            "token_smuggling_risk_detected",
            chunk_count=len(chunks),
            content_preview=full_content[:100],
        )

    log.info(
        "streaming_response_assembled",
        chunk_count=len(chunks),
        content_length=len(full_content),
        token_smuggling_risk=token_smuggling_risk,
    )

    return AssembledResponse(
        content=full_content,
        was_streaming=True,
        chunk_count=len(chunks),
        token_smuggling_risk=token_smuggling_risk,
        raw_chunks=raw_chunks,
    )


async def collect_response(
    response: httpx.Response,
    response_field: str = "",
) -> AssembledResponse:
    """
    Collect response from either streaming or
    non-streaming HTTP response transparently.

    The rest of AIST calls this function and does
    not need to know which type it received.

    Args:
        response:        httpx response object
        response_field:  Configured JSON field for responses

    Returns:
        AssembledResponse with complete content
    """
    content_type = response.headers.get(
        "content-type", ""
    ).lower()

    is_streaming = (
        "text/event-stream" in content_type
        or "application/stream" in content_type
        or response.headers.get("transfer-encoding") == "chunked"
    )

    if is_streaming:
        log.info("streaming_response_detected")
        return await collect_streaming_response(
            response,
            response_field=response_field,
        )

    response_text = response.text

    if _is_sse_format(content_type, response_text):
        parsed = _parse_sse_response(response_text)
        if parsed:
            log.info(
                "sse_response_parsed",
                original_length=len(response_text),
                parsed_length=len(parsed),
            )
            return AssembledResponse(
                content=parsed,
                was_streaming=False,
                chunk_count=1,
            )

    try:
        data = response.json()
        if isinstance(data, dict):
            content = extract_response_text(
                data,
                configured_field=response_field,
            )
        else:
            content = str(data)
    except json.JSONDecodeError:
        content = response_text

    log.info(
        "standard_response_collected",
        content_length=len(content),
    )

    return AssembledResponse(
        content=content,
        was_streaming=False,
        chunk_count=1,
    )


def _strip_metadata(chunk: str) -> str:
    """
    Strip streaming metadata tokens from a chunk.

    Handles both raw token strings and
    server-sent event format (data: {...})

    Args:
        chunk: Raw chunk from stream

    Returns:
        Clean content string or empty string
    """
    chunk = chunk.strip()

    if not chunk:
        return ""

    for token in STREAM_METADATA_TOKENS:
        if chunk == token:
            return ""

    if chunk.startswith("data: "):
        chunk = chunk[6:].strip()
        if chunk in ["[DONE]", ""]:
            return ""
        try:
            data = json.loads(chunk)
            choices = data.get("choices", [])
            if choices:
                delta = choices[0].get("delta", {})
                return delta.get("content", "")
            delta = data.get("delta", {})
            return delta.get("text", "")
        except json.JSONDecodeError:
            return chunk

    return chunk


def _check_token_smuggling(
    raw_chunks: list,
    assembled_content: str,
) -> bool:
    """
    Detect potential token smuggling attempts.

    Token smuggling crafts content that appears
    safe chunk by chunk but assembles into
    policy-violating or injection content.

    Checks for:
    - Instruction keywords split across chunks
    - Encoded content that decodes to injections
    - Unusual chunk boundaries around sensitive words

    Args:
        raw_chunks:        Raw chunks from stream
        assembled_content: Fully assembled response

    Returns:
        True if token smuggling risk detected
    """
    if not raw_chunks or not assembled_content:
        return False

    injection_keywords = [
        "ignore previous",
        "ignore all",
        "disregard",
        "new instruction",
        "system override",
        "you are now",
        "forget your",
    ]

    assembled_lower = assembled_content.lower()
    for keyword in injection_keywords:
        if keyword in assembled_lower:
            keyword_in_single_chunk = any(
                keyword in chunk.lower()
                for chunk in raw_chunks
            )
            if not keyword_in_single_chunk:
                return True

    return False


def truncate_if_oversized(
    response: AssembledResponse,
    limit_kb: int,
) -> AssembledResponse:
    """
    Truncate response content if it exceeds
    the configured size limit.

    Prevents memory exhaustion from hostile
    agents returning oversized responses.

    Args:
        response:  AssembledResponse to check
        limit_kb:  Size limit in kilobytes

    Returns:
        AssembledResponse, truncated if needed
    """
    limit_bytes = limit_kb * 1024
    content_bytes = len(response.content.encode("utf-8"))

    if content_bytes > limit_bytes:
        log.warning(
            "response_truncated",
            original_size_kb=round(content_bytes / 1024, 2),
            limit_kb=limit_kb,
        )
        truncated = response.content.encode("utf-8")[:limit_bytes]
        response.content = truncated.decode("utf-8", errors="ignore")
        response.content += (
            "\n[TRUNCATED BY AIST: RESPONSE EXCEEDED SIZE LIMIT]"
        )

    return response
