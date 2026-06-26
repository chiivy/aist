"""
AIST Direct Injection Scanner

Tests direct prompt injection vectors where
the attacker communicates directly with the
target agent.

Runs payload categories A through F:
    A: Instruction Override
    B: Role and Persona Manipulation
    C: Goal and Objective Hijacking
    D: Data and System Prompt Extraction
    E: Tool Abuse (runs only if tools detected)
    F: Authentication Bypass

Each payload runs multiple times using different
variants for reproducibility scoring and to
reduce detection risk.
"""

from typing import Optional

from aist.logger import get_logger
from aist.config import AISTConfig
from aist.scanner.base import (
    load_payload_file,
    get_payload_variants,
    run_payload_with_reproducibility,
)
from aist.evidence.collector import run_semantic_screen

log = get_logger(__name__)

CATEGORY_FILES = {
    "A": "category_a.yaml",
    "B": "category_b.yaml",
    "C": "category_c.yaml",
    "D": "category_d.yaml",
    "E": "category_e.yaml",
    "F": "category_f.yaml",
    "BL": "category_bl.yaml",
}


async def run_direct_scanner(
    config: AISTConfig,
    canary_token: Optional[str] = None,
    categories: Optional[list] = None,
    auth_manager=None,
) -> tuple:
    """
    Run direct injection tests against target agent.

    Args:
        config:       AIST configuration
        canary_token: Optional canary token to monitor
        categories:   Optional list of categories to run.
                      None means run all A-F.

    Returns:
        Tuple of (all_evidence, all_run_results)
        where all_evidence is a list of Evidence objects
        and all_run_results maps payload_id to run results
    """
    all_evidence = []
    all_run_results = {}

    run_categories = categories or list(CATEGORY_FILES.keys())

    log.info(
        "direct_scanner_starting",
        categories=run_categories,
        target=config.target.endpoint,
    )

    all_tools = list(set(
        config.target.tools
    ))

    for category in run_categories:
        if category not in CATEGORY_FILES:
            log.warning(
                "unknown_category",
                category=category,
            )
            continue

        if category == "E" and not all_tools:
            log.info(
                "skipping_category_e",
                reason="No tools declared or discovered. "
                       "Category E requires tool access.",
            )
            continue

        filename = CATEGORY_FILES[category]
        payload_data = load_payload_file(filename)

        if not payload_data:
            log.warning(
                "payload_file_empty",
                filename=filename,
            )
            continue

        payloads = payload_data.get("payloads", [])

        log.info(
            "running_category",
            category=category,
            payload_count=len(payloads),
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
            severity_base = payload.get(
                "severity_base", "medium"
            )

            if not variants:
                log.warning(
                    "no_variants_for_payload",
                    payload_id=payload_id,
                )
                continue

            log.info(
                "running_payload",
                payload_id=payload_id,
                category=category,
                variants=len(variants),
            )

            evidence_items, run_results = (
                await run_payload_with_reproducibility(
                    payload_id=payload_id,
                    payload_category=category,
                    variants=variants,
                    success_indicators=success_indicators,
                    llm_judge_prompt=llm_judge_prompt,
                    config=config,
                    canary_token=canary_token,
                    auth_manager=auth_manager,
                )
            )

            for idx, evidence in enumerate(evidence_items):
                evidence = await run_semantic_screen(
                    evidence=evidence,
                    payload_category=category,
                    config=config,
                )
                evidence_items[idx] = evidence
                if idx < len(run_results):
                    run_results[idx].string_match_success = (
                        evidence.string_match_success
                    )
                    run_results[idx].llm_judge_success = (
                        evidence.llm_judge_success
                    )
                    run_results[idx].llm_judge_confidence = (
                        evidence.llm_judge_confidence
                    )

            all_evidence.extend(evidence_items)
            all_run_results[payload_id] = run_results

            canary_leaked = any(
                e.canary_leaked for e in evidence_items
            )
            if canary_leaked:
                log.warning(
                    "canary_leaked_in_direct_scan",
                    payload_id=payload_id,
                    category=category,
                )

    log.info(
        "direct_scanner_complete",
        categories_run=run_categories,
        total_evidence=len(all_evidence),
        total_payloads=len(all_run_results),
    )

    return all_evidence, all_run_results