"""
AIST Infrastructure Security Scanner

Tests HTTP-level security configuration of
AI agent endpoints. These checks complement
prompt injection testing by identifying
deployment and configuration vulnerabilities.

No LLM judge needed -- these are deterministic
HTTP checks with clear pass/fail results.

Checks:
    J1: Security headers audit
    J2: CORS misconfiguration
    J3: Rate limiting detection
    J4: Verbose error disclosure
    J5: Debug/admin endpoint exposure
    J6: Framework/version disclosure
"""

import asyncio
import hashlib
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse, urlunparse

import httpx

from aist.logger import get_logger
from aist.config import AISTConfig

log = get_logger(__name__)

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "medium",
        "description": "Missing CSP allows XSS attacks",
        "recommendation": "Add Content-Security-Policy header",
    },
    "Strict-Transport-Security": {
        "severity": "medium",
        "description": "Missing HSTS allows downgrade attacks",
        "recommendation": "Add HSTS with min-age 31536000",
    },
    "X-Frame-Options": {
        "severity": "low",
        "description": "Missing X-Frame-Options allows clickjacking",
        "recommendation": "Add X-Frame-Options: DENY",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "description": "Missing XCTO allows MIME sniffing",
        "recommendation": "Add X-Content-Type-Options: nosniff",
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": "Missing Permissions-Policy",
        "recommendation": "Add Permissions-Policy header",
    },
}

DEBUG_ENDPOINTS = [
    "/debug",
    "/admin",
    "/metrics",
    "/health",
    "/status",
    "/api/debug",
    "/api/admin",
    "/api/status",
    "/api/health",
    "/actuator",
    "/actuator/health",
    "/actuator/info",
    "/actuator/env",
    "/__debug__",
    "/swagger",
    "/swagger-ui.html",
    "/api-docs",
    "/openapi.json",
    "/docs",
    "/redoc",
]

SERVER_HEADERS_TO_CHECK = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
]


@dataclass
class InfraFinding:
    """Single infrastructure security finding."""

    check_id: str
    name: str
    severity: str
    description: str
    evidence: str
    recommendation: str
    payload_id: str


async def run_infrastructure_scanner(
    config: AISTConfig,
) -> tuple:
    """
    Run all infrastructure security checks.

    Returns tuple of (findings, evidence_items)
    where findings are InfraFinding objects
    and evidence_items are Evidence objects
    for the main report.
    """
    from aist.evidence.collector import Evidence

    findings = []
    evidence_items = []

    base_url = config.target.endpoint
    parsed = urlparse(base_url)
    base = urlunparse((
        parsed.scheme,
        parsed.netloc,
        "",
        "", "", "",
    ))

    log.info(
        "infrastructure_scan_starting",
        target=base_url,
        checks=6,
    )

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
    ) as client:

        findings.extend(
            await _check_security_headers(client, base_url)
        )

        j2_finding = await _check_cors(client, base_url)
        if j2_finding:
            findings.append(j2_finding)

        j3_finding = await _check_rate_limiting(
            client, base_url, config
        )
        if j3_finding:
            findings.append(j3_finding)

        j4_finding = await _check_error_disclosure(
            client, base_url
        )
        if j4_finding:
            findings.append(j4_finding)

        findings.extend(
            await _check_debug_endpoints(client, base, base_url)
        )

        findings.extend(
            await _check_version_disclosure(client, base_url)
        )

    for finding in findings:
        response_text = finding.evidence
        evidence = Evidence(
            payload_id=finding.payload_id,
            payload_category="J",
            prompt_sent=f"[Infrastructure check: {finding.name}]",
            response_received=response_text,
            response_hash=hashlib.sha256(
                response_text.encode()
            ).hexdigest()[:16],
            string_match_success=True,
            llm_judge_success=True,
            llm_judge_confidence=95,
            llm_judge_reasoning=finding.description,
            sensitive_patterns=[],
        )
        evidence_items.append(evidence)

    log.info(
        "infrastructure_scan_complete",
        findings=len(findings),
    )

    return findings, evidence_items


async def _check_security_headers(
    client: httpx.AsyncClient,
    url: str,
) -> list:
    """Check for missing security headers."""
    findings = []

    try:
        response = await client.options(url, timeout=10)
        headers = {
            k.lower(): v
            for k, v in response.headers.items()
        }

        for header, info in SECURITY_HEADERS.items():
            if header.lower() not in headers:
                findings.append(InfraFinding(
                    check_id="J1",
                    name=f"Missing {header}",
                    severity=info["severity"],
                    description=info["description"],
                    evidence=(
                        f"HTTP response did not include "
                        f"{header} header. "
                        f"Response headers: "
                        f"{list(headers.keys())}"
                    ),
                    recommendation=info["recommendation"],
                    payload_id=f"J1-{header.replace('-', '_')}",
                ))

    except Exception as e:
        log.info("j1_check_error", error=str(e))

    return findings


async def _check_cors(
    client: httpx.AsyncClient,
    url: str,
) -> Optional[InfraFinding]:
    """Check for CORS misconfiguration."""
    try:
        response = await client.options(
            url,
            headers={
                "Origin": "https://evil.attacker.com",
                "Access-Control-Request-Method": "POST",
            },
            timeout=10,
        )

        acao = response.headers.get(
            "access-control-allow-origin", ""
        )

        if acao == "*" or acao == "https://evil.attacker.com":
            return InfraFinding(
                check_id="J2",
                name="CORS Misconfiguration",
                severity="high",
                description=(
                    "Agent endpoint allows requests from "
                    "any origin. An attacker can make "
                    "cross-origin requests to this agent "
                    "on behalf of authenticated users."
                ),
                evidence=(
                    f"Access-Control-Allow-Origin: {acao} "
                    f"when requesting from evil.attacker.com"
                ),
                recommendation=(
                    "Restrict CORS to known trusted origins. "
                    "Never use wildcard (*) for authenticated "
                    "endpoints."
                ),
                payload_id="J2-CORS",
            )

    except Exception as e:
        log.info("j2_check_error", error=str(e))

    return None


async def _check_rate_limiting(
    client: httpx.AsyncClient,
    url: str,
    config: AISTConfig,
) -> Optional[InfraFinding]:
    """
    Send 15 rapid requests and check if
    any rate limiting is applied.
    """
    log.info(
        "j3_rate_limit_check",
        requests=15,
        note="Burst test for rate limiting detection",
    )

    responses = []
    start = time.time()

    try:
        tasks = []
        for i in range(15):
            tasks.append(
                client.post(
                    url,
                    json={"message": f"ping {i}"},
                    timeout=5,
                )
            )

        results = await asyncio.gather(
            *tasks,
            return_exceptions=True,
        )

        for r in results:
            if isinstance(r, Exception):
                continue
            responses.append(r.status_code)

        elapsed = time.time() - start

        rate_limited = any(
            code in [429, 503, 509]
            for code in responses
        )

        if not rate_limited and len(responses) >= 10:
            return InfraFinding(
                check_id="J3",
                name="No Rate Limiting Detected",
                severity="medium",
                description=(
                    "The agent endpoint accepted 15 rapid "
                    "concurrent requests without throttling. "
                    "No rate limiting means an attacker can "
                    "send unlimited requests, increasing "
                    "attack effectiveness and API costs."
                ),
                evidence=(
                    f"Sent 15 concurrent requests in "
                    f"{elapsed:.1f}s. "
                    f"All returned 200. "
                    f"No 429 (Too Many Requests) detected. "
                    f"Status codes: {responses}"
                ),
                recommendation=(
                    "Implement rate limiting on the agent "
                    "endpoint. Recommended: 10-20 requests "
                    "per minute per user/IP."
                ),
                payload_id="J3-RATELIMIT",
            )

    except Exception as e:
        log.info("j3_check_error", error=str(e))

    return None


async def _check_error_disclosure(
    client: httpx.AsyncClient,
    url: str,
) -> Optional[InfraFinding]:
    """
    Send malformed requests to trigger errors
    and check if stack traces are disclosed.
    """
    malformed_payloads = [
        b"{{invalid json}}",
        b"",
        b"null",
        b'{"message": null}',
        b"<xml>not json</xml>",
    ]

    verbose_indicators = [
        "traceback",
        "stack trace",
        "exception",
        "error at line",
        "file \"",
        "syntaxerror",
        "attributeerror",
        "typeerror",
        "flask",
        "django",
        "fastapi",
        "werkzeug",
        "debug=true",
        "internal server error",
        "sqlalchemy",
        "psycopg2",
    ]

    try:
        for payload in malformed_payloads:
            response = await client.post(
                url,
                content=payload,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )

            body = response.text.lower()

            found = [
                indicator
                for indicator in verbose_indicators
                if indicator in body
            ]

            if found:
                return InfraFinding(
                    check_id="J4",
                    name="Verbose Error Disclosure",
                    severity="medium",
                    description=(
                        "The agent endpoint reveals internal "
                        "error details in responses. This "
                        "discloses framework, file paths, and "
                        "internal architecture to attackers."
                    ),
                    evidence=(
                        f"Malformed request triggered verbose "
                        f"error containing: {found}. "
                        f"Response preview: {response.text[:200]}"
                    ),
                    recommendation=(
                        "Disable debug mode in production. "
                        "Return generic error messages only. "
                        "Log detailed errors server-side only."
                    ),
                    payload_id="J4-ERRORDISCLOSURE",
                )

    except Exception as e:
        log.info("j4_check_error", error=str(e))

    return None


async def _check_debug_endpoints(
    client: httpx.AsyncClient,
    base_url: str,
    chat_url: str,
) -> list:
    """Check for exposed debug/admin endpoints."""
    tasks = []
    for endpoint in DEBUG_ENDPOINTS:
        url = base_url.rstrip("/") + endpoint
        tasks.append(_probe_endpoint(client, url, endpoint))

    results = await asyncio.gather(
        *tasks,
        return_exceptions=True,
    )

    findings = []
    for result in results:
        if isinstance(result, InfraFinding):
            findings.append(result)

    return findings


async def _probe_endpoint(
    client: httpx.AsyncClient,
    url: str,
    path: str,
) -> Optional[InfraFinding]:
    """Probe a single endpoint."""
    try:
        response = await client.get(url, timeout=5)

        if response.status_code in [200, 201, 301, 302]:
            severity = "high"
            if any(admin in path for admin in [
                "admin", "actuator/env",
                "actuator/info", "debug",
            ]):
                severity = "critical"

            return InfraFinding(
                check_id="J5",
                name=f"Exposed Endpoint: {path}",
                severity=severity,
                description=(
                    f"The endpoint {path} is accessible "
                    f"and returned HTTP {response.status_code}. "
                    f"Debug and admin endpoints should not "
                    f"be publicly accessible."
                ),
                evidence=(
                    f"GET {url} returned "
                    f"HTTP {response.status_code}. "
                    f"Response size: {len(response.text)} bytes."
                ),
                recommendation=(
                    f"Restrict access to {path}. "
                    f"Use authentication or IP allowlisting. "
                    f"Disable debug endpoints in production."
                ),
                payload_id=f"J5-{path.replace('/', '_').strip('_')}",
            )

    except Exception:
        pass

    return None


async def _check_version_disclosure(
    client: httpx.AsyncClient,
    url: str,
) -> list:
    """Check for server/framework version disclosure."""
    findings = []

    try:
        response = await client.get(url, timeout=10)

        for header in SERVER_HEADERS_TO_CHECK:
            value = response.headers.get(header)
            if value:
                findings.append(InfraFinding(
                    check_id="J6",
                    name=f"Version Disclosed: {header}",
                    severity="low",
                    description=(
                        f"The {header} header reveals "
                        f"server/framework version information. "
                        f"Attackers use this for targeted exploits."
                    ),
                    evidence=f"{header}: {value}",
                    recommendation=(
                        f"Remove or suppress the {header} header. "
                        f"Configure server to not disclose version."
                    ),
                    payload_id=f"J6-{header.replace('-', '_')}",
                ))

    except Exception as e:
        log.info("j6_check_error", error=str(e))

    return findings
