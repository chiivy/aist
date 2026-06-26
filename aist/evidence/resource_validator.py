"""
AIST Passive Resource Validator

Confirms discovered resources are real and
accessible without reading any data.

PASSIVE ONLY:
- HTTP endpoints: HEAD request only
- Databases: TCP port check only
- Never reads data, authenticates, or queries
"""

import asyncio
import socket
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import httpx

from aist.logger import get_logger

log = get_logger(__name__)


@dataclass
class ValidationResult:
    """Result of passive resource validation."""

    resource: str
    resource_type: str
    is_accessible: bool
    status_code: Optional[int] = None
    port_open: Optional[bool] = None
    response_time_ms: Optional[float] = None
    error: Optional[str] = None
    note: str = (
        "Passive validation only. "
        "No data was read or credentials used."
    )


async def validate_endpoint_passive(
    url: str,
    timeout: float = 5.0,
) -> ValidationResult:
    """
    Send HTTP HEAD request to discovered endpoint.
    HEAD = no response body returned.
    """
    start = time.time()

    try:
        async with httpx.AsyncClient() as client:
            response = await client.head(
                url,
                timeout=timeout,
                follow_redirects=True,
            )
            elapsed = (time.time() - start) * 1000

            return ValidationResult(
                resource=url,
                resource_type="http_endpoint",
                is_accessible=True,
                status_code=response.status_code,
                response_time_ms=round(elapsed, 1),
            )

    except httpx.ConnectError:
        return ValidationResult(
            resource=url,
            resource_type="http_endpoint",
            is_accessible=False,
            error="Connection refused or host unreachable",
        )
    except httpx.TimeoutException:
        return ValidationResult(
            resource=url,
            resource_type="http_endpoint",
            is_accessible=False,
            error=f"Timeout after {timeout}s",
        )
    except Exception as e:
        return ValidationResult(
            resource=url,
            resource_type="http_endpoint",
            is_accessible=False,
            error=str(e),
        )


async def validate_database_passive(
    connection_string: str,
    timeout: float = 3.0,
) -> ValidationResult:
    """
    TCP port probe only.
    Does NOT connect, authenticate, or query.
    """
    import re

    try:
        host = None
        port = None
        scheme = "postgresql"

        parsed = urlparse(connection_string)
        if parsed.hostname and parsed.hostname != "****":
            host = parsed.hostname
            port = parsed.port
            scheme = parsed.scheme.lower() or scheme
        else:
            host_match = re.search(
                r'@([a-zA-Z0-9.-]+)(?::(\d+))?',
                connection_string,
            )
            if host_match:
                host = host_match.group(1)
                port = (
                    int(host_match.group(2))
                    if host_match.group(2)
                    else None
                )
            scheme_match = re.match(
                r'^([a-zA-Z0-9+]+)://',
                connection_string,
            )
            if scheme_match:
                scheme = scheme_match.group(1).lower()

        default_ports = {
            "postgresql": 5432,
            "postgres": 5432,
            "mysql": 3306,
            "mongodb": 27017,
            "redis": 6379,
            "mssql": 1433,
            "oracle": 1521,
        }

        port = port or default_ports.get(scheme, 5432)

        if not host:
            return ValidationResult(
                resource=connection_string[:50],
                resource_type="database",
                is_accessible=False,
                error="Could not parse host from connection string",
            )

        start = time.time()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()

        elapsed = (time.time() - start) * 1000
        port_open = result == 0

        return ValidationResult(
            resource=f"{host}:{port} ({scheme})",
            resource_type="database",
            is_accessible=port_open,
            port_open=port_open,
            response_time_ms=round(elapsed, 1),
            error=None if port_open else (
                f"Port {port} closed or filtered"
            ),
        )

    except Exception as e:
        return ValidationResult(
            resource=connection_string[:50],
            resource_type="database",
            is_accessible=False,
            error=str(e),
        )


async def validate_all_artifacts(
    artifacts: dict,
    timeout: float = 5.0,
) -> dict:
    """
    Run passive validation on all discovered
    artifacts concurrently.

    Returns dict of resource -> ValidationResult
    """
    validation_tasks = []
    resource_keys = []

    for url in artifacts.get("endpoints", []):
        validation_tasks.append(
            validate_endpoint_passive(url, timeout)
        )
        resource_keys.append(url)

    for url in artifacts.get("internal_urls", []):
        validation_tasks.append(
            validate_endpoint_passive(url, timeout)
        )
        resource_keys.append(url)

    for db_str in artifacts.get("database_strings", []):
        validation_tasks.append(
            validate_database_passive(db_str, timeout)
        )
        resource_keys.append(db_str)

    if not validation_tasks:
        return {}

    log.info(
        "passive_validation_starting",
        resources=len(validation_tasks),
        note="HEAD requests and TCP port checks only. No data read.",
    )

    results = await asyncio.gather(
        *validation_tasks,
        return_exceptions=True,
    )

    validation_results = {}
    accessible_count = 0

    for key, result in zip(resource_keys, results):
        if isinstance(result, Exception):
            validation_results[key] = ValidationResult(
                resource=key,
                resource_type="unknown",
                is_accessible=False,
                error=str(result),
            )
        else:
            validation_results[key] = result
            if result.is_accessible:
                accessible_count += 1
                log.warning(
                    "resource_confirmed_accessible",
                    resource=key[:50],
                    type=result.resource_type,
                    note="Passive validation only",
                )

    log.info(
        "passive_validation_complete",
        total=len(validation_tasks),
        accessible=accessible_count,
    )

    return validation_results
