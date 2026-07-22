"""
Traffic observation during browser auth capture.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

from aist.auth.profile import (
    build_discovery_block,
    classify_endpoint_detail,
    detect_message_field,
    detect_response_field,
    detect_response_type,
    extract_custom_headers,
    path_from_url,
    scan_js_content,
)
from aist.logger import get_logger

log = get_logger(__name__)


def _default_endpoint_record(path: str, full_url: str) -> dict[str, Any]:
    """Build a discovery record for a non-flagged path."""
    return {
        "path": path,
        "full_url": full_url or path,
        "classification": "observed",
        "severity": "info",
        "reason": "Observed during browser session",
        "auth_enforced": None,
    }


@dataclass
class TrafficObservation:
    """Collected browser traffic metadata."""

    # path -> rich endpoint record
    discovered_endpoints: dict[str, dict[str, Any]] = field(
        default_factory=dict
    )
    js_files_scanned: list[str] = field(default_factory=list)
    js_secrets: list[dict[str, Any]] = field(default_factory=list)
    js_endpoints: list[str] = field(default_factory=list)
    primary_capture: Optional[dict[str, Any]] = None
    baseline_request: dict[str, Any] = field(default_factory=dict)
    response_type: str = "json"
    streaming: bool = False
    response_field: str = ""
    message_field: str = "message"
    body_template: dict[str, Any] = field(default_factory=dict)
    custom_headers: dict[str, str] = field(default_factory=dict)
    websocket_detected: bool = False

    def register_path(self, url: str) -> None:
        """Record a URL as a discovered endpoint with classification."""
        path = path_from_url(url)
        if not path or path == "/":
            return
        detail = classify_endpoint_detail(path, full_url=url)
        if detail:
            existing = self.discovered_endpoints.get(path)
            # Prefer classified records over generic observed ones
            if not existing or existing.get("classification") == "observed":
                self.discovered_endpoints[path] = detail
            return
        if path not in self.discovered_endpoints:
            self.discovered_endpoints[path] = _default_endpoint_record(
                path,
                url,
            )


class TrafficObserver:
    """Playwright request/response observer."""

    def __init__(self) -> None:
        self.data = TrafficObservation()
        self._js_urls: set[str] = set()
        self._secret_keys: set[str] = set()

    async def on_request(self, request) -> None:
        self.data.register_path(request.url)
        if request.method == "POST":
            await self._maybe_capture_post(request)

    async def on_response(self, response) -> None:
        request = response.request
        self.data.register_path(request.url)

        url_lower = request.url.lower()
        if url_lower.endswith(".js") or "javascript" in (
            response.headers.get("content-type", "").lower()
        ):
            await self._scan_js(response)

        if request.method != "POST":
            return
        await self._maybe_capture_post_response(request, response)

    async def _scan_js(self, response) -> None:
        url = response.url
        if url in self._js_urls:
            return
        self._js_urls.add(url)
        try:
            content = await response.text()
        except Exception:
            return
        self.data.js_files_scanned.append(url)
        findings = scan_js_content(content[:500_000], file_url=url)
        for secret in findings.get("secrets", [])[:20]:
            key = (
                f"{secret.get('secret_type')}:"
                f"{secret.get('preview')}:"
                f"{secret.get('file_url')}"
            )
            if key in self._secret_keys:
                continue
            self._secret_keys.add(key)
            self.data.js_secrets.append(secret)
        for endpoint in findings.get("endpoints", []):
            if endpoint not in self.data.js_endpoints:
                self.data.js_endpoints.append(endpoint)
                path_match = endpoint.split(": ", 1)[-1]
                if path_match.startswith("/"):
                    parsed = urlparse(url)
                    base = f"{parsed.scheme}://{parsed.netloc}"
                    self.data.register_path(f"{base}{path_match}")

    async def _maybe_capture_post(self, request) -> None:
        try:
            post_data = request.post_data
            if not post_data:
                return
            body = json.loads(post_data)
        except Exception:
            return
        msg_field, template = detect_message_field(body)
        self.data.message_field = msg_field
        self.data.body_template = template
        self.data.custom_headers = extract_custom_headers(dict(request.headers))

    async def _maybe_capture_post_response(
        self,
        request,
        response,
    ) -> None:
        content_type = response.headers.get("content-type", "")
        resp_type, streaming = detect_response_type(
            content_type,
            dict(request.headers),
        )
        if resp_type == "websocket":
            self.data.websocket_detected = True

        try:
            text = await response.text()
        except Exception:
            text = ""

        response_body: Any = {}
        if "json" in content_type.lower() and text:
            try:
                response_body = json.loads(text)
            except json.JSONDecodeError:
                response_body = {}
        elif text:
            response_body = {"raw": text[:500]}

        response_field = detect_response_field(response_body)
        try:
            post_body = json.loads(request.post_data or "{}")
        except json.JSONDecodeError:
            post_body = {}

        capture = {
            "url": request.url,
            "headers": dict(request.headers),
            "body": post_body,
            "response_preview": text[:500],
            "response_type": resp_type,
            "streaming": streaming,
            "response_field": response_field,
        }
        self.data.primary_capture = capture
        self.data.response_type = resp_type
        self.data.streaming = streaming
        self.data.response_field = response_field
        self.data.baseline_request = {
            "message": post_body.get(self.data.message_field, ""),
            "response": text[:500],
        }

    def build_profile(self, primary_endpoint: str) -> dict[str, Any]:
        endpoints = list(self.data.discovered_endpoints.values())
        endpoints.sort(key=lambda item: item.get("path", ""))
        if primary_endpoint:
            primary_path = path_from_url(primary_endpoint)
            if primary_path and primary_path not in (
                self.data.discovered_endpoints
            ):
                detail = classify_endpoint_detail(
                    primary_path,
                    full_url=primary_endpoint,
                ) or _default_endpoint_record(
                    primary_path,
                    primary_endpoint,
                )
                endpoints.insert(0, detail)
                self.data.discovered_endpoints[primary_path] = detail

        endpoint_labels = {
            item["path"]: {
                "severity": item.get("severity", "info"),
                "label": item.get("label") or item.get("reason", ""),
            }
            for item in endpoints
            if item.get("classification") not in (None, "observed")
        }
        discovery = build_discovery_block(
            discovered_endpoints=endpoints,
            endpoint_labels=endpoint_labels,
            js_files_scanned=self.data.js_files_scanned,
            js_secrets=self.data.js_secrets,
            js_extra_endpoints=self.data.js_endpoints[:20],
            websocket_detected=self.data.websocket_detected,
        )
        return {
            "primary_endpoint": primary_endpoint,
            "message_field": self.data.message_field,
            "response_field": self.data.response_field,
            "response_type": self.data.response_type,
            "streaming": self.data.streaming,
            "body_template": self.data.body_template,
            "custom_headers": self.data.custom_headers,
            "discovered_endpoints": endpoints,
            "baseline_request": self.data.baseline_request,
            "js_files_scanned": list(self.data.js_files_scanned),
            "js_secrets": list(self.data.js_secrets),
            "js_secrets_found": len(self.data.js_secrets),
            "js_extra_endpoints": self.data.js_endpoints[:20],
            "endpoint_labels": endpoint_labels,
            "discovery": discovery,
        }
