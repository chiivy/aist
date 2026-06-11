"""
AIST Tool Parameter Injection Scanner

Tests whether agent tool calls can be manipulated
via injection into the parameters passed to tools.

Bridges prompt injection with traditional injection
attack classes including SQL injection, command
injection, path traversal, and SSRF.

Runs payload category H:
    H1: SQL injection via database tools
    H2: Command injection via shell tools
    H3: Path traversal via file tools
    H4: SSRF via web browsing tools
    H5: LDAP injection via directory tools
    H6: Environment variable extraction
    H7: OS and architecture probing
    H8: XML injection via data tools

Only runs when tools are declared or discovered.
All payloads use read-only or non-destructive
variants. No DROP, DELETE, or destructive commands.
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


async def run_toolparam_scanner(
    config: AISTConfig,
    canary_token: Optional[str] = None,
) -> tuple:
    """
    Run tool parameter injection tests against
    target agent.

    Skipped entirely if no tools are declared
    or discovered during recon.

    Args:
        config:       AIST configuration
        canary_token: Optional canary token to monitor

    Returns:
        Tuple of (all_evidence, all_run_results)
    """
    all_evidence = []
    all_run_results = {}

    all_tools = list(set(config.target.tools))

    if not all_tools:
        log.info(
            "skipping_toolparam_scanner",
            reason="No tools declared or discovered. "
                   "Category H requires tool access.",
        )
        return all_evidence, all_run_results

    payload_data = load_payload_file("category_h.yaml")
    payloads = payload_data.get("payloads", [])

    if not payloads:
        log.warning(
            "no_toolparam_payloads",
            message="category_h.yaml empty or not found",
        )
        return all_evidence, all_run_results

    log.info(
        "toolparam_scanner_starting",
        payloads=len(payloads),
        tools_available=all_tools,
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
            "running_toolparam_payload",
            payload_id=payload_id,
            variants=len(variants),
        )

        evidence_items, run_results = (
            await run_payload_with_reproducibility(
                payload_id=payload_id,
                payload_category="H",
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
                "canary_leaked_in_toolparam_scan",
                payload_id=payload_id,
            )

    log.info(
        "toolparam_scanner_complete",
        total_evidence=len(all_evidence),
        total_payloads=len(all_run_results),
    )

    return all_evidence, all_run_results