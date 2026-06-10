"""
AIST Evidence Collector

Captures and structures all evidence from
scan interactions for use in scoring and
reporting.

All agent responses are treated as untrusted
input. Secrets are masked before any evidence
is stored or logged.
"""

import hashlib
from dataclasses import dataclass, field
from typing import Optional
import httpx

from aist.logger import get_logger
from aist.config import AISTConfig
from aist.recon.streaming import collect_response, truncate_if_oversized

log = get_logger(__name__)


@dataclass
class Evidence:
    """
    Structured evidence from a single payload interaction.
    Passed to scoring modules for severity calculation.
    """
    payload_id: str
    payload_category: str
    prompt_sent: str
    response_received: str
    response_hash: str
    was_streaming: bool = False
    token_smuggling_risk: bool = False

    # Pattern detection results
    credentials_detected: bool = False
    pii_detected: bool = False
    system_prompt_detected: bool = False
    tool_invocation_detected: bool = False
    canary_leaked: bool = False
    sensitive_patterns: list = field(default_factory=list)

    # Success determination
    string_match_success: bool = False
    string_matches_found: list = field(default_factory=list)
    llm_judge_success: Optional[bool] = None
    llm_judge_partial: Optional[bool] = None
    llm_judge_confidence: Optional[int] = None
    llm_judge_reasoning: Optional[str] = None

    # Metadata
    response_size_kb: float = 0.0
    was_truncated: bool = False
    error: Optional[str] = None


@dataclass
class ScanEvidence:
    """
    All evidence collected during a complete scan.
    Passed to reporting modules.
    """
    target: str
    total_payloads_sent: int = 0
    total_responses_received: int = 0
    evidence_items: list = field(default_factory=list)
    canary_triggered: bool = False
    errors: list = field(default_factory=list)


async def collect_evidence(
    response: httpx.Response,
    payload_id: str,
    payload_category: str,
    prompt_sent: str,
    success_indicators: list,
    canary_token: Optional[str],
    config: AISTConfig,
) -> Evidence:
    """
    Collect and structure evidence from a single
    payload interaction.

    Args:
        response:           httpx response from target agent
        payload_id:         Payload identifier e.g. A1
        payload_category:   Category letter e.g. A
        prompt_sent:        The prompt that was sent
        success_indicators: String patterns indicating success
        canary_token:       Canary token to check for leakage
        config:             AIST configuration

    Returns:
        Structured Evidence object
    """
    from aist.evidence.patterns import detect_patterns
    from aist.evidence.masking import mask_for_storage

    # Step 1: Assemble response handling streaming
    assembled = await collect_response(response)

    # Step 2: Enforce size limits
    assembled = truncate_if_oversized(
        assembled,
        config.scan.response_size_limit_kb
    )

    response_text = assembled.content
    response_size_kb = round(
        len(response_text.encode("utf-8")) / 1024, 2
    )

    # Step 3: Hash response for integrity
    response_hash = hashlib.sha256(
        response_text.encode("utf-8")
    ).hexdigest()[:16]

    log.info(
        "response_collected",
        payload_id=payload_id,
        response_size_kb=response_size_kb,
        was_streaming=assembled.was_streaming,
        was_truncated=assembled.content.endswith(
            "[TRUNCATED BY AIST: RESPONSE EXCEEDED SIZE LIMIT]"
        ),
    )

    # Step 4: Detect sensitive patterns
    pattern_results = detect_patterns(response_text)

    # Step 5: Check canary token leakage
    canary_leaked = False
    if canary_token and canary_token in response_text:
        canary_leaked = True
        log.warning(
            "canary_token_leaked",
            payload_id=payload_id,
            canary_preview=canary_token[:8] + "...",
        )

    # Step 6: String match against success indicators
    string_matches = []
    response_lower = response_text.lower()
    for indicator in success_indicators:
        if indicator.lower() in response_lower:
            string_matches.append(indicator)

    string_match_success = len(string_matches) > 0

    if string_match_success:
        log.info(
            "string_match_success",
            payload_id=payload_id,
            matches=string_matches,
        )

    # Step 7: Mask sensitive content before storage
    safe_response = mask_for_storage(response_text)
    safe_prompt = mask_for_storage(prompt_sent)

    evidence = Evidence(
        payload_id=payload_id,
        payload_category=payload_category,
        prompt_sent=safe_prompt,
        response_received=safe_response,
        response_hash=response_hash,
        was_streaming=assembled.was_streaming,
        token_smuggling_risk=assembled.token_smuggling_risk,
        credentials_detected=pattern_results.get(
            "credentials", False
        ),
        pii_detected=pattern_results.get("pii", False),
        system_prompt_detected=pattern_results.get(
            "system_prompt", False
        ),
        tool_invocation_detected=pattern_results.get(
            "tool_invocation", False
        ),
        canary_leaked=canary_leaked,
        sensitive_patterns=pattern_results.get("patterns_found", []),
        string_match_success=string_match_success,
        string_matches_found=string_matches,
        response_size_kb=response_size_kb,
        was_truncated=assembled.content.endswith(
            "[TRUNCATED BY AIST: RESPONSE EXCEEDED SIZE LIMIT]"
        ),
    )

    return evidence


async def run_llm_judge(
    evidence: Evidence,
    llm_judge_prompt: str,
    config: AISTConfig,
) -> Evidence:
    """
    Run LLM judge analysis on collected evidence.

    Sends the response to the configured LLM with
    the payload-specific judge prompt and parses
    the structured verdict.

    Only runs if LLM API key is configured.
    Falls back gracefully if not available.

    Args:
        evidence:         Evidence object to analyse
        llm_judge_prompt: Payload-specific judge prompt
        config:           AIST configuration

    Returns:
        Evidence object updated with LLM judge results
    """
    import json

    if not config.llm.enabled:
        log.info(
            "llm_judge_skipped",
            reason="No LLM API key configured",
            payload_id=evidence.payload_id,
        )
        return evidence

    full_prompt = f"""
{llm_judge_prompt}

Agent response to analyse:
---
{evidence.response_received}
---

Respond only in valid JSON. No other text.
"""

    try:
        if config.llm.provider == "anthropic":
            verdict = await _call_anthropic(
                full_prompt, config
            )
        else:
            verdict = await _call_openai(
                full_prompt, config
            )

        if verdict:
            evidence.llm_judge_success = verdict.get(
                "success",
                verdict.get("canary_leaked",
                verdict.get("canary_breached", False))
            )
            evidence.llm_judge_partial = verdict.get(
                "partial", False
            )
            evidence.llm_judge_confidence = verdict.get(
                "confidence", 0
            )
            evidence.llm_judge_reasoning = verdict.get(
                "reasoning",
                verdict.get("notes", "")
            )

            log.info(
                "llm_judge_complete",
                payload_id=evidence.payload_id,
                success=evidence.llm_judge_success,
                confidence=evidence.llm_judge_confidence,
            )

    except Exception as e:
        log.warning(
            "llm_judge_error",
            payload_id=evidence.payload_id,
            error_type=type(e).__name__,
        )

    return evidence


async def _call_anthropic(
    prompt: str,
    config: AISTConfig,
) -> Optional[dict]:
    """
    Call Anthropic API for LLM judge analysis.
    """
    import json

    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": config.llm.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": config.llm.model,
                "max_tokens": 500,
                "messages": [
                    {"role": "user", "content": prompt}
                ],
            },
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        text = data["content"][0]["text"]
        return json.loads(text)


async def _call_openai(
    prompt: str,
    config: AISTConfig,
) -> Optional[dict]:
    """
    Call OpenAI API for LLM judge analysis.
    """
    import json

    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {config.llm.api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": "gpt-4o",
                "max_tokens": 500,
                "messages": [
                    {"role": "user", "content": prompt}
                ],
            },
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        text = data["choices"][0]["message"]["content"]
        return json.loads(text)