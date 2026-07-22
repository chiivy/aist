"""Input validation bypass variants for blocked payloads."""

from __future__ import annotations

import json
import urllib.parse
from typing import Any, Optional

import httpx

from aist.logger import get_logger

log = get_logger(__name__)

# Per-category active validation bypass variant
_active_bypass_variants: dict[str, str] = {}


def get_active_bypass(category: str) -> Optional[str]:
    """Return active bypass variant name for a category."""
    return _active_bypass_variants.get(category)


def set_active_bypass(category: str, variant_name: str) -> None:
    """Remember a working bypass variant for a category."""
    _active_bypass_variants[category] = variant_name


def reset_bypass_variants() -> None:
    """Clear cached bypass variants (for tests)."""
    _active_bypass_variants.clear()


def _unicode_escape(text: str) -> str:
    escaped = ""
    for char in text:
        if char in "<>\"'&":
            escaped += f"\\u{ord(char):04x}"
        else:
            escaped += char
    return escaped


def build_bypass_variants(
    payload: str,
    body: dict,
    message_field: str,
) -> list[tuple[str, dict, dict, str]]:
    """
    Build bypass attempt variants for a blocked payload.

    Returns list of (variant_name, body, headers_override, content_type).
    """
    variants: list[tuple[str, dict, dict, str]] = []

    encoded = urllib.parse.quote(payload)
    body1 = dict(body)
    body1[message_field] = encoded
    variants.append(("url_encoding", body1, {}, "application/json"))

    body2 = dict(body)
    body2[message_field] = _unicode_escape(payload)
    variants.append(("unicode_encoding", body2, {}, "application/json"))

    form_body = urllib.parse.urlencode({message_field: payload})
    variants.append(
        (
            "form_urlencoded",
            form_body,
            {"Content-Type": "application/x-www-form-urlencoded"},
            "application/x-www-form-urlencoded",
        )
    )

    body4 = dict(body)
    body4[message_field] = {"text": payload}
    variants.append(("nested_field", body4, {}, "application/json"))

    return variants


async def try_validation_bypass(
    client: httpx.AsyncClient,
    url: str,
    payload: str,
    body: dict,
    message_field: str,
    headers: dict,
    cookies: dict,
    timeout: float,
    variant_filter: Optional[str] = None,
) -> tuple[Optional[httpx.Response], Optional[str]]:
    """
    Attempt bypass variants after a 400 response.

    Returns (response, winning_variant_name) or (None, None).
    """
    variants = build_bypass_variants(payload, body, message_field)
    if variant_filter:
        variants = [
            item for item in variants if item[0] == variant_filter
        ]

    for name, variant_body, header_override, content_type in variants:
        req_headers = dict(headers)
        req_headers.update(header_override)
        if content_type:
            req_headers["Content-Type"] = content_type
        try:
            if isinstance(variant_body, str):
                response = await client.post(
                    url,
                    content=variant_body,
                    headers=req_headers,
                    cookies=cookies,
                    timeout=timeout,
                )
            else:
                response = await client.post(
                    url,
                    json=variant_body,
                    headers=req_headers,
                    cookies=cookies,
                    timeout=timeout,
                )
            if response.status_code == 200:
                log.info(
                    "validation_bypass_success",
                    variant=name,
                )
                return response, name
        except Exception as exc:
            log.info(
                "validation_bypass_failed",
                variant=name,
                error=str(exc),
            )
    return None, None
