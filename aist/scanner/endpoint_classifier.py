"""
Classify discovered endpoints as AI agents vs APIs.

Runs after browser auth / traffic discovery and
before the main injection scan.
"""

from __future__ import annotations

from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import httpx

from aist.http.client import apply_scan_delay
from aist.logger import get_logger

log = get_logger(__name__)

TYPE_TO_BUCKET = {
    "ai_agent": "ai_agents",
    "api": "apis",
    "auth": "excluded",
    "excluded": "excluded",
    "error": "errors",
}


class EndpointClassifier:
    """
    Probe endpoints and classify AI vs structured API.
    """

    NATURAL_LANGUAGE_RESPONSE_FIELDS = [
        "response",
        "answer",
        "reply",
        "output",
        "result",
        "message",
        "text",
        "content",
        "completion",
        "generated_text",
        "explanation",
    ]

    STRUCTURED_DATA_FIELDS = [
        "data",
        "items",
        "count",
        "status",
        "id",
        "list",
        "records",
        "total",
        "code",
        "error",
        "success",
    ]

    EXCLUDED_DOMAINS = [
        "microsoft.com",
        "microsoftonline.com",
        "live.com",
        "google-analytics.com",
        "events.data.microsoft.com",
        "login.microsoftonline.com",
        "google.com",
        "facebook.com",
        "twitter.com",
        "linkedin.com",
        "doubleclick.net",
    ]

    PROBE_MESSAGE_FIELD_CANDIDATES = [
        "message",
        "query",
        "input",
        "prompt",
        "text",
        "content",
    ]

    async def classify_endpoints(
        self,
        endpoints: list[str],
        base_url: str,
        auth_headers: dict,
        cookies: dict,
        scan_delay: float = 1.0,
        message_field: str = "message",
    ) -> dict[str, list[dict[str, Any]]]:
        """
        Probe each endpoint and classify as AI agent or API.

        Returns:
            {
              "ai_agents": [...],
              "apis": [...],
              "excluded": [...],
              "errors": [...],
            }
        """
        results: dict[str, list[dict[str, Any]]] = {
            "ai_agents": [],
            "apis": [],
            "excluded": [],
            "errors": [],
        }

        seen: set[str] = set()
        for endpoint in endpoints:
            if not endpoint:
                continue
            normalised = endpoint.strip()
            if normalised in seen:
                continue
            seen.add(normalised)

            if self.is_excluded_domain(normalised):
                results["excluded"].append({
                    "endpoint": normalised,
                    "url": normalised,
                    "response_field": None,
                    "message_field": message_field,
                    "confidence": 100,
                    "evidence": "Third-party domain",
                })
                continue

            url = self._build_url(base_url, normalised)
            classification = await self._probe(
                url,
                auth_headers,
                cookies,
                message_field=message_field,
            )
            bucket = TYPE_TO_BUCKET.get(
                classification["type"],
                "errors",
            )
            results[bucket].append({
                "endpoint": normalised,
                "url": url,
                "response_field": classification.get(
                    "response_field"
                ),
                "message_field": classification.get(
                    "message_field",
                    message_field,
                ),
                "confidence": classification.get(
                    "confidence",
                    0,
                ),
                "evidence": classification.get(
                    "evidence",
                    "",
                ),
            })
            await apply_scan_delay(scan_delay)

        results["ai_agents"].sort(
            key=lambda item: item.get("confidence", 0),
            reverse=True,
        )
        return results

    def is_excluded_domain(self, endpoint: str) -> bool:
        """Return True if endpoint belongs to a third-party domain."""
        host = ""
        if "://" in endpoint:
            host = (urlparse(endpoint).hostname or "").lower()
        else:
            host = endpoint.lower()
        return any(domain in host for domain in self.EXCLUDED_DOMAINS)

    def _build_url(self, base_url: str, endpoint: str) -> str:
        if endpoint.startswith("http://") or endpoint.startswith(
            "https://"
        ):
            return endpoint
        if not base_url:
            return endpoint
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        return urljoin(origin + "/", endpoint.lstrip("/"))

    async def _probe(
        self,
        url: str,
        auth_headers: dict,
        cookies: dict,
        message_field: str = "message",
    ) -> dict[str, Any]:
        """Send probe messages and classify the endpoint."""
        if self.is_excluded_domain(url):
            return {
                "type": "excluded",
                "confidence": 100,
                "evidence": "Third-party domain",
            }

        body = {message_field: "Hello"}
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    url,
                    json=body,
                    headers=auth_headers or {},
                    cookies=cookies or {},
                )
        except Exception as exc:
            log.info(
                "endpoint_probe_error",
                url=url,
                error=str(exc),
            )
            return {"type": "error", "evidence": str(exc)}

        if response.status_code == 404:
            return {
                "type": "error",
                "evidence": "HTTP 404",
            }
        if response.status_code in (401, 403):
            return {
                "type": "auth",
                "confidence": 90,
                "evidence": f"HTTP {response.status_code}",
            }

        try:
            body_json = response.json()
        except Exception:
            if response.status_code == 200:
                text = response.text or ""
                if len(text) > 50:
                    return {
                        "type": "ai_agent",
                        "response_field": None,
                        "message_field": message_field,
                        "confidence": 40,
                        "evidence": "Non-JSON text response",
                    }
            return {
                "type": "error",
                "evidence": f"HTTP {response.status_code}",
            }

        if not isinstance(body_json, dict):
            return {
                "type": "api",
                "confidence": 60,
                "evidence": "Non-object JSON response",
            }

        nl_hit = self._find_natural_language_field(body_json)
        if nl_hit:
            field, value = nl_hit
            return {
                "type": "ai_agent",
                "response_field": field,
                "message_field": message_field,
                "confidence": 85,
                "evidence": (
                    f"Natural language in '{field}' field"
                ),
            }

        comparison = await self._compare_probes(
            url,
            auth_headers,
            cookies,
            message_field,
            body_json,
        )
        if comparison:
            return comparison

        structured_fields = [
            key
            for key in body_json.keys()
            if str(key).lower() in self.STRUCTURED_DATA_FIELDS
        ]
        if structured_fields:
            return {
                "type": "api",
                "confidence": 75,
                "evidence": (
                    f"Structured fields: {structured_fields}"
                ),
            }

        return {
            "type": "api",
            "confidence": 30,
            "evidence": "Could not determine type",
        }

    def _find_natural_language_field(
        self,
        body: dict,
    ) -> Optional[tuple[str, str]]:
        """Return (field, value) for a long natural-language string."""
        for field in self.NATURAL_LANGUAGE_RESPONSE_FIELDS:
            value = body.get(field)
            if isinstance(value, str) and len(value) > 30:
                return field, value
        return None

    async def _compare_probes(
        self,
        url: str,
        auth_headers: dict,
        cookies: dict,
        message_field: str,
        first_body: dict,
    ) -> Optional[dict[str, Any]]:
        """
        Second probe with different text.

        Changing response suggests dynamic / AI behaviour.
        """
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response2 = await client.post(
                    url,
                    json={message_field: "What can you do?"},
                    headers=auth_headers or {},
                    cookies=cookies or {},
                )
                body2 = response2.json()
        except Exception:
            return None

        if not isinstance(body2, dict):
            return None
        if body2 == first_body:
            return None

        for field in self.NATURAL_LANGUAGE_RESPONSE_FIELDS:
            if field in body2:
                return {
                    "type": "ai_agent",
                    "response_field": field,
                    "message_field": message_field,
                    "confidence": 70,
                    "evidence": "Response varies with input",
                }

        # Response changed but no NL field — still dynamic
        return {
            "type": "ai_agent",
            "response_field": None,
            "message_field": message_field,
            "confidence": 55,
            "evidence": "Response varies with input",
        }


def select_ai_targets(
    classification: dict[str, list[dict[str, Any]]],
    *,
    multi_endpoint: bool = False,
) -> list[dict[str, Any]]:
    """
    Choose which AI agent endpoints to scan.

    Highest confidence first. Without multi_endpoint,
    only the top agent is returned.
    """
    agents = list(classification.get("ai_agents") or [])
    agents.sort(
        key=lambda item: item.get("confidence", 0),
        reverse=True,
    )
    if not agents:
        return []
    if multi_endpoint:
        return agents
    return agents[:1]


def apply_classified_endpoint_to_target(
    target,
    agent: dict[str, Any],
) -> None:
    """Apply a classified AI agent onto TargetConfig."""
    if agent.get("url"):
        target.endpoint = agent["url"]
    if agent.get("message_field"):
        target.message_field = agent["message_field"]
    if agent.get("response_field"):
        target.response_field = agent["response_field"]
