"""Safe endpoint auth enforcement testing (GET/OPTIONS/HEAD only)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

from aist.http.client import apply_scan_delay
from aist.logger import get_logger

log = get_logger(__name__)

DANGEROUS_METHODS = frozenset({"DELETE", "PUT", "PATCH", "POST"})


@dataclass
class EndpointFinding:
    """Finding from endpoint security test."""

    endpoint: str
    check: str
    severity: str
    description: str
    evidence: str = ""


def _base_url(primary_endpoint: str) -> str:
    parsed = urlparse(primary_endpoint)
    return f"{parsed.scheme}://{parsed.netloc}"


async def check_endpoint_auth(
    primary_endpoint: str,
    path: str,
    auth_headers: dict,
    auth_cookies: dict,
    *,
    scan_delay: float = 1.0,
) -> list[EndpointFinding]:
    """
    Run safe auth enforcement tests on one endpoint.

    Uses GET and OPTIONS only. Never writes.
    """
    findings: list[EndpointFinding] = []
    base = _base_url(primary_endpoint)
    url = urljoin(base + "/", path.lstrip("/"))

    async with httpx.AsyncClient(timeout=15.0) as client:
        await apply_scan_delay(scan_delay)
        try:
            options_resp = await client.request("OPTIONS", url)
            if options_resp.status_code == 429:
                await asyncio.sleep(60)
                options_resp = await client.request("OPTIONS", url)
            allowed = options_resp.headers.get("Allow", "")
            for method in allowed.split(","):
                method = method.strip().upper()
                if method in DANGEROUS_METHODS:
                    findings.append(
                        EndpointFinding(
                            endpoint=path,
                            check="dangerous_method",
                            severity="Medium",
                            description=(
                                f"Dangerous HTTP method {method} allowed "
                                f"on {path}. Not tested to avoid "
                                "unintended modifications."
                            ),
                            evidence=allowed,
                        )
                    )
        except Exception as exc:
            log.info("endpoint_options_failed", path=path, error=str(exc))

        await apply_scan_delay(scan_delay)
        try:
            unauth = await client.get(url)
            if unauth.status_code == 429:
                await asyncio.sleep(60)
                unauth = await client.get(url)
            if unauth.status_code == 200 and unauth.text:
                findings.append(
                    EndpointFinding(
                        endpoint=path,
                        check="no_auth_required",
                        severity="High",
                        description=(
                            f"Endpoint {path} accessible without "
                            f"authentication. Returned "
                            f"{len(unauth.text)} bytes."
                        ),
                        evidence=unauth.text[:200],
                    )
                )
        except Exception as exc:
            log.info("endpoint_unauth_failed", path=path, error=str(exc))

        await apply_scan_delay(scan_delay)
        try:
            bad_headers = {
                k: ("Bearer invalid-token-test" if k.lower() == "authorization" else v)
                for k, v in auth_headers.items()
            }
            bad_resp = await client.get(
                url,
                headers=bad_headers,
                cookies=auth_cookies,
            )
            if bad_resp.status_code == 429:
                await asyncio.sleep(60)
                bad_resp = await client.get(
                    url,
                    headers=bad_headers,
                    cookies=auth_cookies,
                )
            if bad_resp.status_code == 200 and bad_resp.text:
                findings.append(
                    EndpointFinding(
                        endpoint=path,
                        check="invalid_auth_accepted",
                        severity="Critical",
                        description=(
                            f"Endpoint {path} does not validate "
                            "authentication token."
                        ),
                        evidence=bad_resp.text[:200],
                    )
                )
        except Exception as exc:
            log.info("endpoint_bad_auth_failed", path=path, error=str(exc))

    return findings


async def test_discovered_endpoints(
    primary_endpoint: str,
    discovered_endpoints: list[str],
    auth_headers: dict,
    auth_cookies: dict,
    *,
    scan_delay: float = 1.0,
) -> list[EndpointFinding]:
    """Test all discovered endpoints for auth enforcement."""
    all_findings: list[EndpointFinding] = []
    seen: set[str] = set()
    for path in discovered_endpoints:
        normalised = path if path.startswith("/") else f"/{path}"
        if normalised in seen:
            continue
        seen.add(normalised)
        findings = await check_endpoint_auth(
            primary_endpoint,
            normalised,
            auth_headers,
            auth_cookies,
            scan_delay=scan_delay,
        )
        all_findings.extend(findings)
    return all_findings
