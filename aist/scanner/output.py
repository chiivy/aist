"""
AIST Output Manipulation Scanner

Tests whether agent-generated output can carry
malicious content that affects downstream systems
or users consuming the agent responses.

Runs payload category I:
    I1: XML injection in generated output
    I2: JSON injection in generated output
    I3: Code generation attacks
    I4: Markdown injection
    I5: Downstream prompt injection
    I6: Report and document poisoning

Findings here indicate the agent can be used
as a vehicle to attack systems that consume
its output, including downstream AI agents.
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


async def run_output_scanner(
    config: AISTConfig,
    canary_token: Optional[str] = None,
    auth_manager=None,
) -> tuple:
    """
    Run output manipulation tests against
    target agent.

    Args:
        config:       AIST configuration
        canary_token: Optional canary token to monitor

    Returns:
        Tuple of (all_evidence, all_run_results)
    """
    all_evidence = []
    all_run_results = {}

    payload_data = load_payload_file("category_i.yaml")
    payloads = payload_data.get("payloads", [])

    if not payloads:
        log.warning(
            "no_output_payloads",
            message="category_i.yaml empty or not found",
        )
        return all_evidence, all_run_results

    log.info(
        "output_scanner_starting",
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
            "running_output_payload",
            payload_id=payload_id,
            variants=len(variants),
        )

        evidence_items, run_results = (
            await run_payload_with_reproducibility(
                payload_id=payload_id,
                payload_category="I",
                variants=variants,
                success_indicators=success_indicators,
                llm_judge_prompt=llm_judge_prompt,
                config=config,
                canary_token=canary_token,
                auth_manager=auth_manager,
            )
        )

        all_evidence.extend(evidence_items)
        all_run_results[payload_id] = run_results

        canary_leaked = any(
            e.canary_leaked for e in evidence_items
        )
        if canary_leaked:
            log.warning(
                "canary_leaked_in_output_scan",
                payload_id=payload_id,
            )

    log.info(
        "output_scanner_complete",
        total_evidence=len(all_evidence),
        total_payloads=len(all_run_results),
    )

    return all_evidence, all_run_results