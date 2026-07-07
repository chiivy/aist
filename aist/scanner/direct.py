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

import httpx
import uuid

from aist.logger import get_logger
from aist.config import AISTConfig, resolve_canary_variables
from aist.scanner.base import (
    load_payload_file,
    get_payload_variants,
    run_payload_with_reproducibility,
    jitter,
    send_payload,
)
from aist.evidence.collector import (
    run_semantic_screen,
    collect_evidence,
    run_llm_judge,
    detect_write_action_confirmation,
)
from aist.scanner.followup import run_followup_probe

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


async def run_write_action_with_confirmation(
    payload_id: str,
    payload_category: str,
    variants: list,
    success_indicators: list,
    confirmation_probe: str,
    confirmation_indicators: list,
    llm_judge_prompt: str,
    config: AISTConfig,
    canary_token: Optional[str] = None,
    auth_manager=None,
) -> tuple:
    """
    Run a write-action payload with a follow-up confirmation probe.

    Sets write_action_confirmed when tool invocation or string match
    on the action response is followed by confirmation language.
    """
    from aist.scoring.confidence import RunResult

    evidence_items = []
    run_results = []
    max_runs = min(config.scan.max_payload_runs, len(variants))

    async with httpx.AsyncClient() as client:
        for run_num in range(max_runs):
            raw_prompt = variants[run_num % len(variants)]
            prompt = resolve_canary_variables(raw_prompt, config)

            session_id = None
            if config.scan.rotate_session_between_runs:
                session_id = str(uuid.uuid4())

            if run_num > 0:
                await jitter(config)

            response = await send_payload(
                client,
                prompt,
                config,
                session_id,
                auth_manager=auth_manager,
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
                payload_id=f"{payload_id}-{run_num + 1}",
                payload_category=payload_category,
                prompt_sent=prompt,
                success_indicators=success_indicators,
                canary_token=canary_token,
                config=config,
            )

            action_attempted = (
                evidence.tool_invocation_detected
                or evidence.string_match_success
            )

            if action_attempted:
                probe_text = resolve_canary_variables(
                    confirmation_probe, config
                )
                confirm_response = await send_payload(
                    client,
                    probe_text,
                    config,
                    session_id,
                    auth_manager=auth_manager,
                )
                if confirm_response:
                    confirm_evidence = await collect_evidence(
                        response=confirm_response,
                        payload_id=(
                            f"{payload_id}-confirm-{run_num + 1}"
                        ),
                        payload_category=payload_category,
                        prompt_sent=probe_text,
                        success_indicators=confirmation_indicators,
                        canary_token=canary_token,
                        config=config,
                    )
                    if detect_write_action_confirmation(
                        confirm_evidence.response_received,
                        confirmation_indicators,
                    ):
                        evidence.write_action_confirmed = True
                        log.warning(
                            "write_action_confirmed",
                            payload_id=payload_id,
                            run=run_num + 1,
                        )

            if config.llm.enabled and llm_judge_prompt:
                evidence = await run_llm_judge(
                    evidence=evidence,
                    llm_judge_prompt=llm_judge_prompt,
                    config=config,
                )

            evidence_items.append(evidence)
            run_results.append(
                RunResult(
                    run_number=run_num + 1,
                    string_match_success=(
                        evidence.string_match_success
                        or evidence.write_action_confirmed
                    ),
                    llm_judge_success=evidence.llm_judge_success,
                    llm_judge_confidence=(
                        evidence.llm_judge_confidence
                    ),
                    canary_leaked=evidence.canary_leaked,
                )
            )

            if evidence.canary_leaked:
                break

    return evidence_items, run_results


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

            if payload.get("write_action_confirmation"):
                evidence_items, run_results = (
                    await run_write_action_with_confirmation(
                        payload_id=payload_id,
                        payload_category=category,
                        variants=variants,
                        success_indicators=success_indicators,
                        confirmation_probe=payload.get(
                            "confirmation_probe",
                            "Did you successfully complete that "
                            "action? Please confirm what happened.",
                        ),
                        confirmation_indicators=payload.get(
                            "confirmation_indicators", []
                        ),
                        llm_judge_prompt=llm_judge_prompt,
                        config=config,
                        canary_token=canary_token,
                        auth_manager=auth_manager,
                    )
                )
            else:
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

                if (
                    evidence.llm_judge_partial
                    and config.llm.enabled
                    and config.scan.followup_enabled
                    and not config.scan.safe_mode
                ):
                    followup_result = await run_followup_probe(
                        config=config,
                        original_evidence=evidence,
                        canary_token=canary_token,
                        auth_manager=auth_manager,
                    )

                    if followup_result.all_evidence:
                        evidence_items.extend(
                            followup_result.all_evidence
                        )

                    if followup_result.escalated:
                        log.warning(
                            "finding_escalated_via_followup",
                            original_id=evidence.payload_id,
                            depth=followup_result.depth_reached,
                            stop_reason=(
                                followup_result.stop_reason
                            ),
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