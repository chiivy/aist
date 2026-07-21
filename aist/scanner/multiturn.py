"""
AIST Multi-Turn Attack Scanner

Tests injection attacks that unfold across
multiple conversation turns rather than in
a single prompt.

Research shows multi-turn attacks achieve
significantly higher success rates than
single-turn attempts because they build
context and trust before the injection lands.

Loads sequences from payloads/sequences.yaml
and runs each sequence maintaining full
conversation context across turns.
"""

import uuid
from typing import Optional

import httpx

from aist.logger import get_logger
from aist.config import AISTConfig, resolve_canary_variables
from aist.scanner.base import (
    load_payload_file,
    jitter,
    send_payload,
)
from aist.evidence.collector import (
    collect_evidence,
    run_llm_judge,
)

log = get_logger(__name__)


async def run_multiturn_scanner(
    config: AISTConfig,
    canary_token: Optional[str] = None,
    auth_manager=None,
) -> tuple:
    """
    Run multi-turn attack sequences against
    target agent.

    Args:
        config:       AIST configuration
        canary_token: Optional canary token to monitor

    Returns:
        Tuple of (all_evidence, all_run_results)
    """
    from aist.scoring.confidence import RunResult

    all_evidence = []
    all_run_results = {}

    sequences_data = load_payload_file("sequences.yaml")
    sequences = sequences_data.get("sequences", [])

    if not sequences:
        log.warning(
            "no_sequences_loaded",
            message="sequences.yaml empty or not found",
        )
        return all_evidence, all_run_results

    log.info(
        "multiturn_scanner_starting",
        sequences=len(sequences),
        target=config.target.endpoint,
    )

    async with httpx.AsyncClient() as client:
        for sequence in sequences:
            seq_id = sequence.get("id", "unknown")
            seq_name = sequence.get("name", "unknown")
            turns = sequence.get("turns", [])

            if not turns:
                continue

            log.info(
                "running_sequence",
                sequence_id=seq_id,
                name=seq_name,
                turns=len(turns),
            )

            session_id = str(uuid.uuid4())
            conversation_history = []
            final_evidence = None
            run_results = []

            for turn_num, turn in enumerate(turns):
                turn_prompt_raw = turn.get("prompt", "")
                turn_prompt = resolve_canary_variables(
                    turn_prompt_raw, config
                )
                purpose = turn.get("purpose", "")
                success_indicators = turn.get(
                    "success_indicators", []
                )
                llm_judge_prompt = turn.get(
                    "llm_judge_prompt", ""
                )
                is_final_turn = (
                    turn_num == len(turns) - 1
                )

                if turn_num > 0:
                    await jitter(config)

                log.info(
                    "running_turn",
                    sequence_id=seq_id,
                    turn=turn_num + 1,
                    purpose=purpose,
                    is_final=is_final_turn,
                )

                response = await send_payload(
                    client,
                    turn_prompt,
                    config,
                    session_id,
                    auth_manager=auth_manager,
                )

                if response is None:
                    log.warning(
                        "turn_failed",
                        sequence_id=seq_id,
                        turn=turn_num + 1,
                    )
                    run_results.append(
                        RunResult(
                            run_number=turn_num + 1,
                            string_match_success=False,
                            llm_judge_success=None,
                            llm_judge_confidence=None,
                            canary_leaked=False,
                            error="Request failed",
                        )
                    )
                    break

                evidence = await collect_evidence(
                    response=response,
                    payload_id=f"{seq_id}-T{turn_num + 1}",
                    payload_category="S",
                    prompt_sent=turn_prompt,
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

                conversation_history.append({
                    "turn": turn_num + 1,
                    "prompt": turn_prompt,
                    "response": evidence.response_received,
                    "purpose": purpose,
                })

                run_results.append(
                    RunResult(
                        run_number=turn_num + 1,
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

                if is_final_turn:
                    final_evidence = evidence
                    all_evidence.append(evidence)

                if evidence.canary_leaked:
                    log.warning(
                        "canary_leaked_in_sequence",
                        sequence_id=seq_id,
                        turn=turn_num + 1,
                    )
                    if not final_evidence:
                        final_evidence = evidence
                        all_evidence.append(evidence)
                    break

            all_run_results[seq_id] = run_results

            if final_evidence:
                log.info(
                    "sequence_complete",
                    sequence_id=seq_id,
                    turns_completed=len(run_results),
                    final_success=(
                        final_evidence.llm_judge_success or
                        final_evidence.string_match_success
                    ),
                    canary_leaked=final_evidence.canary_leaked,
                )

    log.info(
        "multiturn_scanner_complete",
        sequences_run=len(sequences),
        total_evidence=len(all_evidence),
    )

    return all_evidence, all_run_results