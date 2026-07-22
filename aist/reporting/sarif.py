"""
AIST SARIF Report Generator

Produces Static Analysis Results Interchange Format
(SARIF 2.1.0) output for native display in:
    GitHub Security tab
    VS Code Problems panel
    Azure DevOps
    Any SARIF-compatible tool

Enables developers to see AIST findings directly
in their development environment without leaving
their workflow.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from aist.logger import get_logger
from aist.compliance.mappings import get_compliance_mapping
from aist.evidence.collector import is_genuine_finding

log = get_logger(__name__)

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/"
    "sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
AIST_TOOL_URI = "https://github.com/chiivy/aist"


def generate_sarif_report(
    scan_evidence,
    severity_scores: list,
    confidence_scores: list,
    config,
) -> dict:
    """
    Generate a SARIF 2.1.0 report from scan results.

    Args:
        scan_evidence:     All evidence from the scan
        severity_scores:   List of SeverityScore objects
        confidence_scores: List of ConfidenceScore objects
        config:            AIST configuration

    Returns:
        Complete SARIF report as a dictionary
    """
    log.info(
        "generating_sarif_report",
        target=scan_evidence.target,
    )

    severity_map = {
        s.payload_id: s for s in severity_scores
    }
    confidence_map = {
        c.payload_id: c for c in confidence_scores
    }

    rules = _build_rules()
    results = _build_results(
        scan_evidence,
        severity_map,
        confidence_map,
        config,
    )

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AIST",
                        "fullName": (
                            "Agentic Injection Security Tester"
                        ),
                        "version": "1.0",
                        "informationUri": AIST_TOOL_URI,
                        "rules": rules,
                        "properties": {
                            "tags": [
                                "security",
                                "prompt-injection",
                                "ai-security",
                                "llm-security",
                            ],
                        },
                    }
                },
                "results": results,
                "properties": {
                    "target": scan_evidence.target,
                    "scanDate": (
                        datetime.now(timezone.utc)
                        .isoformat()
                        .replace("+00:00", "Z")
                    ),
                    "totalPayloads": (
                        scan_evidence.total_payloads_sent
                    ),
                },
            }
        ],
    }

    log.info(
        "sarif_report_generated",
        results_count=len(results),
        rules_count=len(rules),
    )

    return sarif


def save_sarif_report(
    sarif: dict,
    output_path: str,
) -> str:
    """
    Save SARIF report to file.

    Args:
        sarif:       SARIF report dictionary
        output_path: File path to save to

    Returns:
        Absolute path of saved file
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        json.dumps(sarif, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    log.info(
        "sarif_report_saved",
        path=str(path.absolute()),
    )

    return str(path.absolute())


def _build_rules() -> list:
    """
    Build SARIF rule definitions for all
    AIST payload categories.

    Each rule maps to a payload category and
    includes OWASP and MITRE ATLAS references.
    """
    categories = {
        "AIST-A": {
            "name": "Instruction Override",
            "short": "Direct prompt injection via "
                     "instruction override",
            "full": (
                "The agent followed injected instructions "
                "that attempted to override its original "
                "directives. This indicates a prompt "
                "injection vulnerability where user input "
                "can alter the agent's behaviour."
            ),
            "help": (
                "Implement input validation and system "
                "prompt hardening. Add explicit resistance "
                "instructions and consider a prompt "
                "injection firewall."
            ),
            "owasp": "LLM01:2025",
            "atlas": "AML.T0051.000",
        },
        "AIST-B": {
            "name": "Role and Persona Manipulation",
            "short": "Agent adopted an injected persona "
                     "bypassing safety controls",
            "full": (
                "The agent adopted an alternate persona "
                "or entered a special mode that bypassed "
                "its original safety controls. This "
                "indicates vulnerability to jailbreak "
                "techniques."
            ),
            "help": (
                "Add explicit anti-persona instructions "
                "to your system prompt. Implement "
                "jailbreak pattern detection."
            ),
            "owasp": "LLM01:2025",
            "atlas": "AML.T0054",
        },
        "AIST-C": {
            "name": "Goal and Objective Hijacking",
            "short": "Agent's primary objective was "
                     "replaced or manipulated",
            "full": (
                "The agent's primary objective was "
                "successfully replaced or manipulated "
                "via injected instructions. This "
                "indicates vulnerability to goal "
                "hijacking attacks."
            ),
            "help": (
                "Define objectives explicitly and "
                "immutably. Implement intent verification "
                "and output monitoring."
            ),
            "owasp": "LLM01:2025",
            "atlas": "AML.T0080",
        },
        "AIST-D": {
            "name": "Data and System Prompt Extraction",
            "short": "System prompt or sensitive data "
                     "was extracted",
            "full": (
                "The agent revealed its system prompt "
                "or other sensitive internal information "
                "in response to extraction attempts. "
                "This exposes operational details and "
                "potentially credentials."
            ),
            "help": (
                "Add non-disclosure instructions to "
                "your system prompt. Implement output "
                "filtering and canary tokens."
            ),
            "owasp": "LLM06:2025",
            "atlas": "AML.T0057",
        },
        "AIST-E": {
            "name": "Tool Abuse",
            "short": "Agent tools were invoked with "
                     "attacker-controlled parameters",
            "full": (
                "The agent's tools were successfully "
                "invoked with attacker-controlled "
                "parameters. This indicates excessive "
                "agency vulnerability where the agent "
                "can be manipulated to take unauthorised "
                "actions."
            ),
            "help": (
                "Implement tool access controls and "
                "intent verification. Apply least "
                "privilege to all tools."
            ),
            "owasp": "LLM08:2025",
            "atlas": "AML.T0085.001",
        },
        "AIST-F": {
            "name": "Authentication Bypass",
            "short": "Authentication controls bypassed "
                     "via identity claim injection",
            "full": (
                "The agent granted elevated access or "
                "special privileges based on unverified "
                "identity claims injected through "
                "conversation. Authentication should "
                "never be handled within the LLM layer."
            ),
            "help": (
                "Implement authentication outside the "
                "LLM layer. Never grant elevated access "
                "based on conversational claims."
            ),
            "owasp": "LLM01:2025",
            "atlas": "AML.T0054",
        },
        "AIST-G": {
            "name": "Guardrail Circumvention",
            "short": "Safety controls bypassed via "
                     "systematic techniques",
            "full": (
                "The agent's safety controls were "
                "bypassed using systematic circumvention "
                "techniques including fictional framing, "
                "encoding, multilingual input, or "
                "fragmentation attacks."
            ),
            "help": (
                "Implement multi-layer safety architecture. "
                "Use semantic safety classification not "
                "just keyword matching."
            ),
            "owasp": "LLM01:2025",
            "atlas": "AML.T0054",
        },
        "AIST-H": {
            "name": "Tool Parameter Injection",
            "short": "Traditional injection via agent "
                     "tool parameters",
            "full": (
                "Agent tool parameters accepted "
                "unsanitised input enabling traditional "
                "injection attacks including SQL injection, "
                "command injection, path traversal, or "
                "SSRF via tool interfaces."
            ),
            "help": (
                "Sanitise all tool parameters. Use "
                "parameterised queries. Restrict file "
                "and network access to approved resources."
            ),
            "owasp": "LLM08:2025",
            "atlas": "AML.T0085.001",
        },
        "AIST-I": {
            "name": "Output Manipulation",
            "short": "Agent output contains malicious "
                     "content affecting downstream systems",
            "full": (
                "The agent generated output containing "
                "malicious content that could affect "
                "downstream systems or users, including "
                "injected XML, JSON, code with attacker "
                "behaviour, or downstream prompt injection."
            ),
            "help": (
                "Sanitise all agent output before "
                "downstream consumption. Validate "
                "structured output formats."
            ),
            "owasp": "LLM02:2025",
            "atlas": "AML.T0051.001",
        },
        "AIST-S": {
            "name": "Multi-Turn Attack",
            "short": "Injection succeeded via multi-turn "
                     "conversation manipulation",
            "full": (
                "A multi-turn attack sequence successfully "
                "manipulated the agent by building context "
                "and trust across multiple conversation "
                "turns before executing the injection."
            ),
            "help": (
                "Implement conversation-level monitoring. "
                "Set maximum conversation lengths. "
                "Monitor for intent drift."
            ),
            "owasp": "LLM01:2025",
            "atlas": "AML.T0051.000",
        },
        "AIST-CANARY": {
            "name": "Canary Token Leak",
            "short": "Canary token leaked confirming "
                     "system prompt exfiltration",
            "full": (
                "A canary token planted in the agent's "
                "system prompt appeared in a response. "
                "This is unambiguous confirmation of "
                "system prompt exfiltration. The entire "
                "system prompt should be treated as "
                "compromised."
            ),
            "help": (
                "Treat system prompt as compromised. "
                "Rotate all credentials. Redesign system "
                "prompt with no sensitive information."
            ),
            "owasp": "LLM06:2025",
            "atlas": "AML.T0057",
        },
    }

    rules = []
    for rule_id, rule_def in categories.items():
        rule = {
            "id": rule_id,
            "name": rule_def["name"],
            "shortDescription": {
                "text": rule_def["short"],
            },
            "fullDescription": {
                "text": rule_def["full"],
            },
            "helpUri": AIST_TOOL_URI,
            "help": {
                "text": rule_def["help"],
                "markdown": rule_def["help"],
            },
            "properties": {
                "tags": [
                    "security",
                    "ai-security",
                    rule_def["owasp"],
                    rule_def["atlas"],
                ],
                "owasp": rule_def["owasp"],
                "mitre_atlas": rule_def["atlas"],
            },
        }
        rules.append(rule)

    return rules


def _build_results(
    scan_evidence,
    severity_map: dict,
    confidence_map: dict,
    config,
) -> list:
    """
    Build SARIF result objects from scan evidence.
    """
    results = []

    for evidence in scan_evidence.evidence_items:
        severity = severity_map.get(evidence.payload_id)
        confidence = confidence_map.get(evidence.payload_id)

        if not severity or not confidence:
            continue

        if not is_genuine_finding(evidence):
            continue

        rule_id = (
            "AIST-CANARY"
            if evidence.canary_leaked
            else f"AIST-{evidence.payload_category}"
        )

        sarif_level = _severity_to_sarif_level(
            severity.severity_label
        )

        message_text = _build_message(
            evidence,
            severity,
            confidence,
        )

        result = {
            "ruleId": rule_id,
            "level": sarif_level,
            "message": {
                "text": message_text,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": scan_evidence.target,
                            "uriBaseId": "TARGET",
                        },
                    },
                    "logicalLocations": [
                        {
                            "name": evidence.payload_id,
                            "kind": "payloadCategory",
                            "fullyQualifiedName": (
                                f"Category "
                                f"{evidence.payload_category}"
                                f"/{evidence.payload_id}"
                            ),
                        }
                    ],
                }
            ],
            "properties": {
                "severity_score": severity.final_score,
                "severity_label": severity.severity_label,
                "confidence_score": confidence.confidence_score,
                "confidence_label": confidence.confidence_label,
                "needs_manual_review": (
                    confidence.needs_manual_review
                ),
                "canary_leaked": evidence.canary_leaked,
                "credentials_detected": (
                    evidence.credentials_detected
                ),
                "tool_context": severity.tool_context,
                "cvss_vector": severity.cvss_vector,
                "response_hash": evidence.response_hash,
            },
        }

        results.append(result)

    return results


def _severity_to_sarif_level(severity_label: str) -> str:
    """
    Convert AIST severity label to SARIF level.

    SARIF levels: error, warning, note, none

    Args:
        severity_label: AIST severity label

    Returns:
        SARIF level string
    """
    mapping = {
        "Critical": "error",
        "High": "error",
        "Medium": "warning",
        "Low": "note",
        "Informational": "note",
    }
    return mapping.get(severity_label, "warning")


def _build_message(
    evidence,
    severity,
    confidence,
) -> str:
    """
    Build human-readable SARIF result message.

    Args:
        evidence:   Evidence object
        severity:   SeverityScore object
        confidence: ConfidenceScore object

    Returns:
        Formatted message string
    """
    parts = []

    if evidence.canary_leaked:
        parts.append(
            "CRITICAL: Canary token leaked confirming "
            "system prompt exfiltration."
        )
    elif evidence.credentials_detected:
        parts.append(
            "Sensitive credentials detected in "
            "agent response."
        )
    elif evidence.tool_invocation_detected:
        parts.append(
            "Unauthorised tool invocation detected."
        )
    else:
        parts.append(
            f"Prompt injection vulnerability detected "
            f"via payload {evidence.payload_id}."
        )

    parts.append(
        f"Severity: {severity.severity_label} "
        f"({severity.final_score}/10.0). "
        f"Confidence: {confidence.confidence_label} "
        f"({confidence.confidence_score}%)."
    )

    if severity.tool_context:
        parts.append(
            f"Tools at risk: "
            f"{', '.join(severity.tool_context)}."
        )

    if confidence.needs_manual_review:
        parts.append(
            "This finding has low confidence and "
            "requires manual review before actioning."
        )

    return " ".join(parts)