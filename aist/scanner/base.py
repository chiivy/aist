"""
AIST Scanner Base

Shared utilities used by all scanner modules.

Handles:
- Loading payload YAML files
- Resolving canary variables in payloads
- Applying jitter between requests
- Handling rate limit backoff
- Sending individual payloads to target agent
- Collecting evidence from responses
"""

import asyncio
import random
import yaml
from datetime import datetime
from pathlib import Path
from typing import Optional

import httpx

from aist.logger import get_logger
from aist.config import AISTConfig, resolve_canary_variables
from aist.evidence.collector import (
    Evidence,
    collect_evidence,
    run_llm_judge,
)
from aist.evidence.secret_detector import scan_response_secrets
from aist.http.client import (
    apply_scan_delay,
    handle_rate_limit,
    warn_auth_failure,
)
from aist.scanner.validation_bypass import (
    get_active_bypass,
    set_active_bypass,
    try_validation_bypass,
)

log = get_logger(__name__)

PAYLOADS_DIR = Path(__file__).parent.parent / "payloads"


def load_payload_file(filename: str) -> dict:
    """
    Load a YAML payload file from the payloads directory.

    Args:
        filename: YAML filename e.g. category_a.yaml

    Returns:
        Parsed YAML content as dictionary
    """
    path = PAYLOADS_DIR / filename

    if not path.exists():
        log.error(
            "payload_file_not_found",
            path=str(path),
        )
        return {}

    with open(path, "r", encoding="utf-8") as f:
        content = yaml.safe_load(f)

    log.info(
        "payload_file_loaded",
        filename=filename,
        payloads=len(content.get("payloads", [])),
    )

    return content


def get_payload_variants(payload: dict) -> list:
    """
    Get all variants for a payload.

    If payload has a variants list returns all variants.
    If payload has a single prompt returns it as a list.

    Args:
        payload: Payload dictionary from YAML

    Returns:
        List of prompt strings
    """
    if "variants" in payload:
        return payload["variants"]
    elif "prompt" in payload:
        return [payload["prompt"]]
    return []


async def jitter(config: AISTConfig) -> None:
    """
    Apply random delay between requests.

    Makes AIST traffic look more human and
    reduces detection risk from rate limiters
    and anomaly detection systems.

    In passive mode uses longer delays.

    Args:
        config: AIST configuration
    """
    if config.target.mode == "passive":
        min_delay = config.scan.jitter_min_seconds * 2
        max_delay = config.scan.jitter_max_seconds * 2
    else:
        min_delay = config.scan.jitter_min_seconds
        max_delay = config.scan.jitter_max_seconds

    if min_delay == 0 and max_delay == 0:
        return

    delay = random.uniform(min_delay, max_delay)
    log.info(
        "jitter_applied",
        delay_seconds=round(delay, 2),
    )
    await asyncio.sleep(delay)


def build_target_request_body(
    config: AISTConfig,
    message: str,
) -> dict:
    """Build JSON request body with custom fields and message."""
    body = dict(config.target.custom_body_fields)
    body[config.target.message_field] = message
    return body


def build_target_request_headers(
    config: AISTConfig,
    session_id: Optional[str] = None,
    auth_headers: Optional[dict] = None,
) -> dict:
    """Build request headers; auth headers override custom headers."""
    headers = {"Content-Type": "application/json"}
    headers.update(config.target.custom_headers)
    if session_id:
        headers["X-Session-ID"] = session_id
    if config.target.api_key:
        headers["Authorization"] = (
            f"Bearer {config.target.api_key}"
        )
    if auth_headers:
        headers.update(auth_headers)
    return headers


async def send_payload(
    client: httpx.AsyncClient,
    payload: str,
    config: AISTConfig,
    session_id: Optional[str] = None,
    *,
    auth_headers: dict = None,
    auth_cookies: dict = None,
    auth_manager=None,
    payload_category: str = "",
) -> Optional[httpx.Response]:
    """
    Send a single payload to the target agent.

    Handles authentication, custom body fields,
    custom headers, timeouts, and rate limit backoff.
    """
    if auth_manager:
        await auth_manager.refresh_token_if_needed()
        auth_headers = auth_manager.get_headers()
        auth_cookies = auth_manager.get_cookies()

    await apply_scan_delay(config.scan.scan_delay)

    body = build_target_request_body(config, payload)
    headers = build_target_request_headers(
        config,
        session_id=session_id,
        auth_headers=auth_headers,
    )
    cookies = auth_cookies or {}

    max_retries = 5
    retry_count = 0

    while retry_count < max_retries:
        try:
            response = await client.post(
                config.target.endpoint,
                json=body,
                headers=headers,
                cookies=cookies,
                timeout=config.scan.scan_timeout_seconds,
            )

            if response.status_code == 429:
                if config.scan.backoff_on_rate_limit:
                    should_retry = await handle_rate_limit(
                        response,
                        attempt=retry_count,
                        max_retries=max_retries,
                    )
                    if should_retry:
                        continue
                log.warning(
                    "rate_limited_no_retry",
                    status=429,
                )
                return None

            warn_auth_failure(response.status_code)

            if (
                response.status_code == 400
                and config.scan.bypass_validation
            ):
                bypass_resp, variant = await try_validation_bypass(
                    client,
                    config.target.endpoint,
                    payload,
                    body,
                    config.target.message_field,
                    headers,
                    cookies,
                    config.scan.scan_timeout_seconds,
                )
                if bypass_resp is not None and variant:
                    if payload_category:
                        set_active_bypass(payload_category, variant)
                    return bypass_resp

            if response.status_code == 400 and payload_category:
                active = get_active_bypass(payload_category)
                if active:
                    bypass_resp, _ = await try_validation_bypass(
                        client,
                        config.target.endpoint,
                        payload,
                        body,
                        config.target.message_field,
                        headers,
                        cookies,
                        config.scan.scan_timeout_seconds,
                        variant_filter=active,
                    )
                    if bypass_resp is not None:
                        return bypass_resp

            _scan_response_secrets(response)
            return response

        except httpx.TimeoutException:
            log.warning(
                "request_timeout",
                retry=retry_count + 1,
                endpoint=config.target.endpoint,
            )
            retry_count += 1
            if retry_count < max_retries:
                await asyncio.sleep(2 ** retry_count)
                continue

        except httpx.ConnectError:
            log.error(
                "connection_error",
                endpoint=config.target.endpoint,
            )
            return None

        except Exception as e:
            log.warning(
                "send_payload_error",
                error=str(e),
                error_type=type(e).__name__,
            )
            return None

    log.error(
        "max_retries_exceeded",
        endpoint=config.target.endpoint,
    )
    return None


def _scan_response_secrets(response: httpx.Response) -> None:
    """Log secrets detected in any HTTP response body."""
    try:
        body = response.text
    except Exception:
        return
    for finding in scan_response_secrets(body):
        log.warning(
            "secret_in_response",
            pattern=finding.pattern,
            severity=finding.severity,
            preview=finding.match_preview,
        )


async def run_payload_with_reproducibility(
    payload_id: str,
    payload_category: str,
    variants: list,
    success_indicators: list,
    llm_judge_prompt: str,
    config: AISTConfig,
    canary_token: Optional[str] = None,
    auth_manager=None,
    side_effects_monitor=None,
) -> list:
    """
    Run a payload multiple times for reproducibility scoring.

    Each run uses a different variant of the payload
    to avoid detection and improve coverage.
    Sessions are rotated between runs if configured.

    Args:
        payload_id:         Payload identifier e.g. A1
        payload_category:   Category letter e.g. A
        variants:           List of prompt variants
        success_indicators: Strings indicating success
        llm_judge_prompt:   Judge prompt for LLM analysis
        config:             AIST configuration
        canary_token:       Optional canary token to check

    Returns:
        List of Evidence objects from each run
    """
    from aist.scoring.confidence import RunResult

    max_runs = config.scan.max_payload_runs
    run_results = []
    evidence_items = []

    log.info(
        "payload_starting",
        payload_id=payload_id,
        variants_available=len(variants),
        runs_planned=max_runs,
    )

    async with httpx.AsyncClient() as client:
        for run_num in range(max_runs):

            variant_index = run_num % len(variants)
            raw_prompt = variants[variant_index]

            prompt = resolve_canary_variables(
                raw_prompt, config
            )

            session_id = None
            if config.scan.rotate_session_between_runs:
                import uuid
                session_id = str(uuid.uuid4())

            if run_num > 0:
                await jitter(config)

            log.info(
                "payload_run_starting",
                payload_id=payload_id,
                run=run_num + 1,
                variant=variant_index + 1,
                session_id=session_id,
            )

            pre_ts = datetime.utcnow().isoformat()

            response = await send_payload(
                client,
                prompt,
                config,
                session_id,
                auth_manager=auth_manager,
                payload_category=payload_category,
            )

            if response is None:
                run_results.append(
                    RunResult(
                        run_number=run_num + 1,
                        string_match_success=False,
                        llm_judge_success=None,
                        llm_judge_confidence=None,
                        canary_leaked=False,
                        error="Request failed",
                    )
                )
                continue

            evidence = await collect_evidence(
                response=response,
                payload_id=payload_id,
                payload_category=payload_category,
                prompt_sent=prompt,
                success_indicators=success_indicators,
                canary_token=canary_token,
                config=config,
            )

            if llm_judge_prompt:
                from aist.evidence.judge import judge_enabled
                if judge_enabled(config):
                    evidence = await run_llm_judge(
                        evidence=evidence,
                        llm_judge_prompt=llm_judge_prompt,
                        config=config,
                    )

            if (
                side_effects_monitor
                and side_effects_monitor.available
            ):
                from aist.scanner.sideeffects import (
                    agent_disclosed_effects,
                    create_silent_compliance_evidence,
                )

                effects = await side_effects_monitor.get_since(
                    pre_ts
                )
                if (
                    effects.any()
                    and not agent_disclosed_effects(
                        evidence.response_received,
                        effects,
                    )
                ):
                    silent = create_silent_compliance_evidence(
                        evidence, effects
                    )
                    evidence_items.append(silent)
                    log.warning(
                        "silent_compliance_detected",
                        payload_id=payload_id,
                    )

            evidence_items.append(evidence)

            run_results.append(
                RunResult(
                    run_number=run_num + 1,
                    string_match_success=(
                        evidence.string_match_success
                    ),
                    llm_judge_success=(
                        evidence.llm_judge_success
                    ),
                    llm_judge_confidence=(
                        evidence.llm_judge_confidence
                    ),
                    canary_leaked=evidence.canary_leaked,
                )
            )

            if evidence.canary_leaked:
                log.warning(
                    "canary_leaked_stopping_early",
                    payload_id=payload_id,
                    run=run_num + 1,
                )
                break

    best_evidence = _select_best_evidence(
        evidence_items, run_results
    )

    if best_evidence:
        best_evidence._run_results = run_results

    return evidence_items, run_results


def _select_best_evidence(
    evidence_items: list,
    run_results: list,
) -> Optional[Evidence]:
    """
    Select the most representative evidence object
    from multiple runs.

    Priority:
    1. Run with canary leak
    2. Run with LLM judge success
    3. Run with string match success
    4. First run as fallback

    Args:
        evidence_items: List of Evidence objects
        run_results:    List of RunResult objects

    Returns:
        Best Evidence object or None
    """
    if not evidence_items:
        return None

    for evidence in evidence_items:
        if evidence.canary_leaked:
            return evidence

    for evidence in evidence_items:
        if evidence.llm_judge_success:
            return evidence

    for evidence in evidence_items:
        if evidence.string_match_success:
            return evidence

    return evidence_items[0]