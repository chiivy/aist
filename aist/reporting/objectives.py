"""
Attacker objective mapping for AIST reports.

Groups confirmed findings by what an external attacker
could achieve, rather than by payload category alone.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

OBJECTIVES: dict[str, dict[str, Any]] = {
    "data_exfiltration": {
        "name": "Data Exfiltration",
        "description": (
            "Attacker can extract sensitive data from the "
            "agent or its connected systems"
        ),
        "categories": ["D", "E", "I", "GEN"],
        "finding_ids": [],
        "severity": None,
        "owasp": "LLM02:2025",
        "business_impact": (
            "Sensitive data including credentials, user "
            "records, and internal configuration can be "
            "extracted by an unauthorised user."
        ),
    },
    "access_control_bypass": {
        "name": "Access Control Bypass",
        "description": (
            "Attacker can access data or functions beyond "
            "their authorised scope"
        ),
        "categories": ["BL", "F", "GEN"],
        "owasp": "LLM01:2025",
        "business_impact": (
            "Scope and role restrictions can be bypassed, "
            "allowing users to access data or perform "
            "actions they are not authorised for."
        ),
    },
    "agent_hijacking": {
        "name": "Agent Hijacking",
        "description": (
            "Attacker can redirect the agent to serve "
            "attacker objectives instead of legitimate "
            "user goals"
        ),
        "categories": ["B", "C"],
        "owasp": "LLM01:2025",
        "business_impact": (
            "The agent can be reprogrammed mid-conversation "
            "to adopt a different persona, reveal its "
            "configuration, or execute attacker-controlled "
            "instructions."
        ),
    },
    "tool_abuse": {
        "name": "Tool Abuse",
        "description": (
            "Attacker can trigger the agent to invoke tools "
            "in unauthorised ways including sending emails, "
            "fetching URLs, or reading files"
        ),
        "categories": ["E", "H"],
        "owasp": "LLM08:2025",
        "business_impact": (
            "Agent tools can be weaponised to exfiltrate "
            "data via email, conduct SSRF attacks, access "
            "restricted files, or enumerate internal "
            "infrastructure."
        ),
    },
    "multi_agent_compromise": {
        "name": "Multi-Agent Compromise",
        "description": (
            "Attacker can pivot from the target agent to "
            "connected downstream agents"
        ),
        "categories": ["MA"],
        "owasp": "LLM01:2025",
        "business_impact": (
            "Connected agents can be reached directly or via "
            "injection, bypassing the primary agent's "
            "controls entirely."
        ),
    },
    "persistent_manipulation": {
        "name": "Persistent Manipulation",
        "description": (
            "Attacker can inject standing instructions that "
            "persist across future interactions"
        ),
        "categories": ["C", "I"],
        "owasp": "LLM01:2025",
        "business_impact": (
            "Injected instructions can affect future users "
            "of the same agent session, enabling phishing, "
            "data collection, or behaviour modification "
            "at scale."
        ),
    },
}

SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Unknown": 4,
}


def _finding_category(finding: dict) -> str:
    return (finding.get("payload_category") or "").upper()


def _finding_severity_score(finding: dict) -> float:
    severity = finding.get("severity")
    if isinstance(severity, dict):
        return float(severity.get("score", 0) or 0)
    return float(finding.get("severity_score", 0) or 0)


def _finding_severity_label(finding: dict) -> str:
    severity = finding.get("severity")
    if isinstance(severity, dict):
        return severity.get("label", "Unknown") or "Unknown"
    return finding.get("severity_label", "Unknown") or "Unknown"


def _is_confirmed_finding(finding: dict) -> bool:
    return finding.get("llm_judge_success") is True


def map_findings_to_objectives(findings: list) -> list[dict]:
    """
    Map confirmed findings to attacker objectives.

    Only findings with ``llm_judge_success=True`` are
    considered. Objectives with no matching findings are
    omitted. Results are sorted by highest severity first.
    """
    achieved: list[dict] = []

    for obj_id, obj in OBJECTIVES.items():
        categories = {
            category.upper()
            for category in obj["categories"]
        }
        matching = [
            finding
            for finding in findings
            if _finding_category(finding) in categories
            and _is_confirmed_finding(finding)
        ]

        if not matching:
            continue

        highest_severity = max(
            matching,
            key=_finding_severity_score,
        )

        achieved.append({
            "objective_id": obj_id,
            "name": obj["name"],
            "description": obj["description"],
            "business_impact": obj["business_impact"],
            "owasp": obj["owasp"],
            "achieved": True,
            "severity": _finding_severity_label(
                highest_severity
            ),
            "severity_score": _finding_severity_score(
                highest_severity
            ),
            "supporting_findings": [
                finding["payload_id"] for finding in matching
            ],
            "finding_count": len(matching),
        })

    achieved.sort(
        key=lambda objective: (
            SEVERITY_ORDER.get(objective["severity"], 4),
            -objective.get("severity_score", 0),
        )
    )
    return achieved


def objectives_for_json(objectives: list[dict]) -> list[dict]:
    """Return the attacker-objectives slice for JSON export."""
    return [
        {
            "objective_id": objective["objective_id"],
            "name": objective["name"],
            "severity": objective["severity"],
            "finding_count": objective["finding_count"],
            "supporting_findings": objective[
                "supporting_findings"
            ],
            "business_impact": objective["business_impact"],
            "owasp": objective["owasp"],
        }
        for objective in objectives
    ]


def get_objective_definitions() -> dict[str, dict[str, Any]]:
    """Return a copy of objective definitions for tests/docs."""
    return deepcopy(OBJECTIVES)
