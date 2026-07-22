"""
Traffic observation during browser auth capture.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

from aist.auth.profile import (
    classify_endpoint,
    detect_message_field,
    detect_response_field,
    detect_response_type,
    extract_custom_headers,
    path_from_url,
    scan_js_content,
)
from aist.logger import get_logger

log = get_logger(__name__)


@dataclass
class TrafficObservation:
    """Collected browser traffic metadata."""

    discovered_endpoints: set[str] = field(default_factory=set)
    endpoint_labels: dict[str, tuple[str, str]] = field(default_factory=dict)
    js_files_scanned: int = 0
    js_secrets: list[str] = field(default_factory=list)
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
        path = path_from_url(url)
        if path and path != "/":
            self.discovered_endpoints.add(path)
            label = classify_endpoint(path)
            if label:
                self.endpoint_labels[path] = label


class TrafficObserver:
    """Playwright request/response observer."""

    def __init__(self) -> None:
        self.data = TrafficObservation()
        self._js_urls: set[str] = set()

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
        self.data.js_files_scanned += 1
        findings = scan_js_content(content[:500_000])
        self.data.js_secrets.extend(findings.get("secrets", [])[:20])
        for endpoint in findings.get("endpoints", []):
            if endpoint not in self.data.js_endpoints:
                self.data.js_endpoints.append(endpoint)
                path_match = endpoint.split(": ", 1)[-1]
                if path_match.startswith("/"):
                    self.data.register_path(
                        f"https://placeholder.local{path_match}"
                    )

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
        endpoints = sorted(self.data.discovered_endpoints)
        if primary_endpoint:
            primary_path = path_from_url(primary_endpoint)
            if primary_path not in endpoints:
                endpoints.insert(0, primary_path)
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
            "js_files_scanned": self.data.js_files_scanned,
            "js_secrets_found": len(self.data.js_secrets),
            "js_extra_endpoints": self.data.js_endpoints[:20],
            "endpoint_labels": {
                path: {"severity": sev, "label": label}
                for path, (sev, label) in self.data.endpoint_labels.items()
            },
        }
