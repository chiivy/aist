"""
AIST Guardrail Circumvention Scanner

Tests whether the agent's safety controls
and guardrails can be bypassed via systematic
circumvention techniques.

Runs payload category G:
    G1:  Fictional framing bypass
    G2:  Academic framing bypass
    G3:  Leetspeak encoding bypass
    G4:  Multilingual bypass
    G5:  Fragmentation attack
    G6:  Competing safety bypass
    G7:  Exhaustion attack
    G8:  Grandma exploit
    G9:  Safety filter probing
    G10: Token smuggling
"""

from typing import Optional

from aist.logger import get_logger
from aist.config import AISTConfig
from aist.scanner.base import (
    load_payload_file,
    get_payload_variants,
    run_payload_with_reproducibility,
)

log = get_logger(__name__)


async def run_guardrail_scanner(
    config: AISTConfig,
    canary_token: Optional[str] = None,
) -> tuple:
    """
    Run guardrail circumvention tests against
    target agent.

    Args:
        config:       AIST configuration
        canary_token: Optional canary token to monitor

    Returns:
        Tuple of (all_evidence, all_run_results)
    """
    all_evidence = []
    all_run_results = {}

    payload_data = load_payload_file("category_g.yaml")
    payloads = payload_data.get("payloads", [])

    if not payloads:
        log.warning(
            "no_guardrail_payloads",
            message="category_g.yaml empty or not found",
        )
        return all_evidence, all_run_results

    log.info(
        "guardrail_scanner_starting",
        payloads=len(payloads),
        target=config.target.endpoint,
    )

    for payload in payloads:
        payload_id = payload.get("id", "unknown")
        variants = get_payload_variants(payload)
        success_indicators = payload.get(
            "success_indicators", []
        )
        llm_judge_prompt = payload.get(
            "llm_judge_prompt", ""
        )

        if not variants:
            log.warning(
                "no_variants_for_payload",
                payload_id=payload_id,
            )
            continue

        log.info(
            "running_guardrail_payload",
            payload_id=payload_id,
            variants=len(variants),
        )

        evidence_items, run_results = (
            await run_payload_with_reproducibility(
                payload_id=payload_id,
                payload_category="G",
                variants=variants,
                success_indicators=success_indicators,
                llm_judge_prompt=llm_judge_prompt,
                config=config,
                canary_token=canary_token,
            )
        )

        all_evidence.extend(evidence_items)
        all_run_results[payload_id] = run_results

        canary_leaked = any(
            e.canary_leaked for e in evidence_items
        )
        if canary_leaked:
            log.warning(
                "canary_leaked_in_guardrail_scan",
                payload_id=payload_id,
            )

    log.info(
        "guardrail_scanner_complete",
        total_evidence=len(all_evidence),
        total_payloads=len(all_run_results),
    )

    return all_evidence, all_run_results