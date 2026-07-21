"""
AIST Compliance Mappings

Maps AIST finding types to compliance framework
controls and requirements.

Frameworks covered:
    OWASP LLM Top 10 (2025)
    OWASP Agentic AI Top 10
    MITRE ATLAS techniques
    NIST AI Risk Management Framework
    EU AI Act (relevant articles)
    SOC2 (relevant trust service criteria)
    ISO 27001 (relevant controls)
"""

from aist.logger import get_logger

log = get_logger(__name__)


COMPLIANCE_MAPPINGS = {

    "A": {
        "title": "Instruction Override",
        "owasp_llm": {
            "id": "LLM01:2025",
            "name": "Prompt Injection",
            "url": "https://genai.owasp.org/llmrisk/"
                   "llm01-prompt-injection/",
        },
        "owasp_agentic": {
            "id": "AGEN01:2025",
            "name": "Prompt Injection in Agentic Systems",
        },
        "mitre_atlas": [
            {
                "id": "AML.T0051.000",
                "name": "LLM Prompt Injection - Direct",
                "url": "https://atlas.mitre.org/techniques/"
                       "AML.T0051/000",
            },
        ],
        "nist_ai_rmf": [
            {
                "function": "GOVERN",
                "category": "1.1",
                "description": "Policies and processes for "
                               "AI risk management",
            },
            {
                "function": "MANAGE",
                "category": "2.2",
                "description": "Mechanisms to respond to "
                               "AI risks",
            },
        ],
        "eu_ai_act": [
            {
                "article": "Article 9",
                "description": "Risk management system "
                               "for high-risk AI",
            },
            {
                "article": "Article 15",
                "description": "Accuracy, robustness and "
                               "cybersecurity",
            },
        ],
        "soc2": [
            {
                "criteria": "CC6.1",
                "description": "Logical and physical access "
                               "controls",
            },
            {
                "criteria": "CC7.2",
                "description": "Monitor system components "
                               "for anomalies",
            },
        ],
        "iso_27001": [
            {
                "control": "A.8.2",
                "description": "Information classification",
            },
            {
                "control": "A.8.28",
                "description": "Secure coding",
            },
        ],
    },

    "B": {
        "title": "Role and Persona Manipulation",
        "owasp_llm": {
            "id": "LLM01:2025",
            "name": "Prompt Injection",
            "url": "https://genai.owasp.org/llmrisk/"
                   "llm01-prompt-injection/",
        },
        "owasp_agentic": {
            "id": "AGEN01:2025",
            "name": "Prompt Injection in Agentic Systems",
        },
        "mitre_atlas": [
            {
                "id": "AML.T0054",
                "name": "LLM Jailbreak",
                "url": "https://atlas.mitre.org/techniques/"
                       "AML.T0054",
            },
        ],
        "nist_ai_rmf": [
            {
                "function": "GOVERN",
                "category": "1.1",
                "description": "Policies for AI risk management",
            },
        ],
        "eu_ai_act": [
            {
                "article": "Article 15",
                "description": "Accuracy, robustness and "
                               "cybersecurity",
            },
        ],
        "soc2": [
            {
                "criteria": "CC6.1",
                "description": "Logical access controls",
            },
        ],
        "iso_27001": [
            {
                "control": "A.8.28",
                "description": "Secure coding",
            },
        ],
    },

    "C": {
        "title": "Goal and Objective Hijacking",
        "owasp_llm": {
            "id": "LLM01:2025",
            "name": "Prompt Injection",
            "url": "https://genai.owasp.org/llmrisk/"
                   "llm01-prompt-injection/",
        },
        "owasp_agentic": {
            "id": "AGEN02:2025",
            "name": "Excessive Agency",
        },
        "mitre_atlas": [
            {
                "id": "AML.T0080",
                "name": "AI Agent Context Poisoning",
                "url": "https://atlas.mitre.org/techniques/"
                       "AML.T0080",
            },
        ],
        "nist_ai_rmf": [
            {
                "function": "MAP",
                "category": "1.1",
                "description": "Context and scope of AI system",
            },
            {
                "function": "MANAGE",
                "category": "2.2",
                "description": "Mechanisms to respond to risks",
            },
        ],
        "eu_ai_act": [
            {
                "article": "Article 9",
                "description": "Risk management system",
            },
        ],
        "soc2": [
            {
                "criteria": "CC7.2",
                "description": "Monitor for anomalies",
            },
        ],
        "iso_27001": [
            {
                "control": "A.8.2",
                "description": "Information classification",
            },
        ],
    },

    "D": {
        "title": "Data and System Prompt Extraction",
        "owasp_llm": {
            "id": "LLM06:2025",
            "name": "Sensitive Information Disclosure",
            "url": "https://genai.owasp.org/llmrisk/"
                   "llm06-sensitive-information-disclosure/",
        },
        "owasp_agentic": {
            "id": "AGEN06:2025",
            "name": "Sensitive Information Disclosure",
        },
        "mitre_atlas": [
            {
                "id": "AML.T0057",
                "name": "LLM Data Leakage",
                "url": "https://atlas.mitre.org/techniques/"
                       "AML.T0057",
            },
        ],
        "nist_ai_rmf": [
            {
                "function": "GOVERN",
                "category": "6.1",
                "description": "Policies for data privacy",
            },
        ],
        "eu_ai_act": [
            {
                "article": "Article 10",
                "description": "Data governance",
            },
            {
                "article": "Article 15",
                "description": "Cybersecurity requirements",
            },
        ],
        "soc2": [
            {
                "criteria": "CC6.1",
                "description": "Logical access controls",
            },
            {
                "criteria": "P6.1",
                "description": "Personal information retention "
                               "and disposal",
            },
        ],
        "iso_27001": [
            {
                "control": "A.8.2",
                "description": "Information classification",
            },
            {
                "control": "A.5.34",
                "description": "Privacy and protection of PII",
            },
        ],
    },

    "E": {
        "title": "Tool Abuse",
        "owasp_llm": {
            "id": "LLM08:2025",
            "name": "Excessive Agency",
            "url": "https://genai.owasp.org/llmrisk/"
                   "llm08-excessive-agency/",
        },
        "owasp_agentic": {
            "id": "AGEN02:2025",
            "name": "Excessive Agency",
        },
        "mitre_atlas": [
            {
                "id": "AML.T0085.001",
                "name": "Abuse AI Agent Tools",
                "url": "https://atlas.mitre.org/techniques/"
                       "AML.T0085/001",
            },
        ],
        "nist_ai_rmf": [
            {
                "function": "MANAGE",
                "category": "2.2",
                "description": "Mechanisms to respond to risks",
            },
        ],
        "eu_ai_act": [
            {
                "article": "Article 9",
                "description": "Risk management system",
            },
        ],
        "soc2": [
            {
                "criteria": "CC6.3",
                "description": "Role-based access control",
            },
            {
                "criteria": "CC6.6",
                "description": "Logical access security "
                               "measures",
            },
        ],
        "iso_27001": [
            {
                "control": "A.8.2",
                "description": "Information classification",
            },
            {
                "control": "A.5.15",
                "description": "Access control",
            },
        ],
    },

    "F": {
        "title": "Authentication Bypass",
        "owasp_llm": {
            "id": "LLM01:2025",
            "name": "Prompt Injection",
            "url": "https://genai.owasp.org/llmrisk/"
                   "llm01-prompt-injection/",
        },
        "owasp_agentic": {
            "id": "AGEN01:2025",
            "name": "Prompt Injection in Agentic Systems",
        },
        "mitre_atlas": [
            {
                "id": "AML.T0054",
                "name": "LLM Jailbreak",
                "url": "https://atlas.mitre.org/techniques/"
                       "AML.T0054",
            },
        ],
        "nist_ai_rmf": [
            {
                "function": "GOVERN",
                "category": "1.1",
                "description": "Policies for AI risk management",
            },
        ],
        "eu_ai_act": [
            {
                "article": "Article 15",
                "description": "Cybersecurity requirements",
            },
        ],
        "soc2": [
            {
                "criteria": "CC6.1",
                "description": "Logical access controls",
            },
            {
                "criteria": "CC6.2",
                "description": "Authentication controls",
            },
        ],
        "iso_27001": [
            {
                "control": "A.5.15",
                "description": "Access control",
            },
            {
                "control": "A.5.17",
                "description": "Authentication information",
            },
        ],
    },

    "G": {
        "title": "Guardrail Circumvention",
        "owasp_llm": {
            "id": "LLM01:2025",
            "name": "Prompt Injection",
            "url": "https://genai.owasp.org/llmrisk/"
                   "llm01-prompt-injection/",
        },
        "owasp_agentic": {
            "id": "AGEN01:2025",
            "name": "Prompt Injection in Agentic Systems",
        },
        "mitre_atlas": [
            {
                "id": "AML.T0054",
                "name": "LLM Jailbreak",
                "url": "https://atlas.mitre.org/techniques/"
                       "AML.T0054",
            },
        ],
        "nist_ai_rmf": [
            {
                "function": "GOVERN",
                "category": "1.1",
                "description": "Policies for AI risk management",
            },
            {
                "function": "MEASURE",
                "category": "2.5",
                "description": "AI risk measurement",
            },
        ],
        "eu_ai_act": [
            {
                "article": "Article 15",
                "description": "Accuracy, robustness and "
                               "cybersecurity",
            },
        ],
        "soc2": [
            {
                "criteria": "CC7.2",
                "description": "Monitor for anomalies",
            },
        ],
        "iso_27001": [
            {
                "control": "A.8.28",
                "description": "Secure coding",
            },
        ],
    },

    "H": {
        "title": "Tool Parameter Injection",
        "owasp_llm": {
            "id": "LLM08:2025",
            "name": "Excessive Agency",
            "url": "https://genai.owasp.org/llmrisk/"
                   "llm08-excessive-agency/",
        },
        "owasp_agentic": {
            "id": "AGEN02:2025",
            "name": "Excessive Agency",
        },
        "mitre_atlas": [
            {
                "id": "AML.T0085.001",
                "name": "Abuse AI Agent Tools",
                "url": "https://atlas.mitre.org/techniques/"
                       "AML.T0085/001",
            },
        ],
        "nist_ai_rmf": [
            {
                "function": "MANAGE",
                "category": "1.3",
                "description": "Responses to identified risks",
            },
        ],
        "eu_ai_act": [
            {
                "article": "Article 15",
                "description": "Cybersecurity requirements",
            },
        ],
        "soc2": [
            {
                "criteria": "CC8.1",
                "description": "Change management controls",
            },
        ],
        "iso_27001": [
            {
                "control": "A.8.28",
                "description": "Secure coding",
            },
            {
                "control": "A.8.9",
                "description": "Configuration management",
            },
        ],
    },

    "I": {
        "title": "Output Manipulation",
        "owasp_llm": {
            "id": "LLM02:2025",
            "name": "Insecure Output Handling",
            "url": "https://genai.owasp.org/llmrisk/"
                   "llm02-insecure-output-handling/",
        },
        "owasp_agentic": {
            "id": "AGEN03:2025",
            "name": "Insecure Output Handling",
        },
        "mitre_atlas": [
            {
                "id": "AML.T0051.001",
                "name": "LLM Prompt Injection - Indirect",
                "url": "https://atlas.mitre.org/techniques/"
                       "AML.T0051/001",
            },
        ],
        "nist_ai_rmf": [
            {
                "function": "MANAGE",
                "category": "1.3",
                "description": "Responses to identified risks",
            },
        ],
        "eu_ai_act": [
            {
                "article": "Article 15",
                "description": "Cybersecurity requirements",
            },
        ],
        "soc2": [
            {
                "criteria": "CC7.2",
                "description": "Monitor for anomalies",
            },
        ],
        "iso_27001": [
            {
                "control": "A.8.28",
                "description": "Secure coding",
            },
        ],
    },

    "S": {
        "title": "Multi-Turn Attack Sequences",
        "owasp_llm": {
            "id": "LLM01:2025",
            "name": "Prompt Injection",
            "url": "https://genai.owasp.org/llmrisk/"
                   "llm01-prompt-injection/",
        },
        "owasp_agentic": {
            "id": "AGEN01:2025",
            "name": "Prompt Injection in Agentic Systems",
        },
        "mitre_atlas": [
            {
                "id": "AML.T0051.000",
                "name": "LLM Prompt Injection - Direct",
                "url": "https://atlas.mitre.org/techniques/"
                       "AML.T0051/000",
            },
            {
                "id": "AML.T0080",
                "name": "AI Agent Context Poisoning",
                "url": "https://atlas.mitre.org/techniques/"
                       "AML.T0080",
            },
        ],
        "nist_ai_rmf": [
            {
                "function": "GOVERN",
                "category": "1.1",
                "description": "Policies for AI risk management",
            },
        ],
        "eu_ai_act": [
            {
                "article": "Article 15",
                "description": "Cybersecurity requirements",
            },
        ],
        "soc2": [
            {
                "criteria": "CC7.2",
                "description": "Monitor for anomalies",
            },
        ],
        "iso_27001": [
            {
                "control": "A.8.28",
                "description": "Secure coding",
            },
        ],
    },

    "J": {
        "title": "Infrastructure Security",
        "owasp_llm": {
            "id": "LLM06:2025",
            "name": "Sensitive Information Disclosure",
            "url": "https://genai.owasp.org/llmrisk/"
                   "llm06-sensitive-information-disclosure/",
        },
        "owasp_agentic": {
            "id": "AGEN05:2025",
            "name": "Insecure Infrastructure",
        },
        "mitre_atlas": [
            {
                "id": "AML.T0040",
                "name": "AI Model Inference API Access",
                "url": "https://atlas.mitre.org/techniques/"
                       "AML.T0040",
            },
        ],
        "nist_ai_rmf": [
            {
                "function": "GOVERN",
                "category": "1.1",
                "description": "Policies for AI risk management",
            },
        ],
        "eu_ai_act": [
            {
                "article": "Article 15",
                "description": "Cybersecurity requirements",
            },
        ],
        "soc2": [
            {
                "criteria": "CC6.1",
                "description": "Logical and physical access "
                               "controls",
            },
        ],
        "iso_27001": [
            {
                "control": "A.8.28",
                "description": "Secure coding",
            },
        ],
    },

    "MA": {
        "title": "Multi-Agent Traversal",
        "owasp_llm": {
            "id": "LLM01:2025",
            "name": "Prompt Injection",
            "url": "https://genai.owasp.org/llmrisk/"
                   "llm01-prompt-injection/",
        },
        "owasp_agentic": {
            "id": "AGEN01:2025",
            "name": "Prompt Injection in Agentic Systems",
        },
        "mitre_atlas": [
            {
                "id": "AML.T0080",
                "name": "AI Agent Context Poisoning",
                "url": "https://atlas.mitre.org/techniques/"
                       "AML.T0080",
            },
        ],
        "nist_ai_rmf": [
            {
                "function": "GOVERN",
                "category": "1.1",
                "description": "Policies for AI risk management",
            },
        ],
        "eu_ai_act": [
            {
                "article": "Article 15",
                "description": "Cybersecurity requirements",
            },
        ],
        "soc2": [
            {
                "criteria": "CC6.1",
                "description": "Logical and physical access "
                               "controls",
            },
        ],
        "iso_27001": [
            {
                "control": "A.8.28",
                "description": "Secure coding",
            },
        ],
    },

    "INDIRECT": {
        "title": "Indirect Prompt Injection",
        "owasp_llm": {
            "id": "LLM01:2025",
            "name": "Prompt Injection",
            "url": "https://genai.owasp.org/llmrisk/"
                   "llm01-prompt-injection/",
        },
        "owasp_agentic": {
            "id": "AGEN01:2025",
            "name": "Prompt Injection in Agentic Systems",
        },
        "mitre_atlas": [
            {
                "id": "AML.T0051.001",
                "name": "LLM Prompt Injection - Indirect",
                "url": "https://atlas.mitre.org/techniques/"
                       "AML.T0051/001",
            },
        ],
        "nist_ai_rmf": [
            {
                "function": "GOVERN",
                "category": "1.1",
                "description": "Policies for AI risk management",
            },
        ],
        "eu_ai_act": [
            {
                "article": "Article 15",
                "description": "Cybersecurity requirements",
            },
        ],
        "soc2": [
            {
                "criteria": "CC6.1",
                "description": "Logical and physical access "
                               "controls",
            },
        ],
        "iso_27001": [
            {
                "control": "A.8.28",
                "description": "Secure coding",
            },
        ],
    },

    "GEN": {
        "title": "Context-Aware Generated Attacks",
        "owasp_llm": {
            "id": "LLM01:2025",
            "name": "Prompt Injection",
            "url": "https://genai.owasp.org/llmrisk/"
                   "llm01-prompt-injection/",
        },
        "owasp_agentic": {
            "id": "AGEN01:2025",
            "name": "Prompt Injection in Agentic Systems",
        },
        "mitre_atlas": [
            {
                "id": "AML.T0051.000",
                "name": "LLM Prompt Injection - Direct",
                "url": "https://atlas.mitre.org/techniques/"
                       "AML.T0051/000",
            },
        ],
        "nist_ai_rmf": [
            {
                "function": "GOVERN",
                "category": "1.1",
                "description": "Policies and processes for "
                               "AI risk management",
            },
        ],
        "eu_ai_act": [
            {
                "article": "Article 15",
                "description": "Accuracy, robustness and "
                               "cybersecurity",
            },
        ],
        "soc2": [
            {
                "criteria": "CC6.1",
                "description": "Logical and physical access "
                               "controls",
            },
        ],
        "iso_27001": [
            {
                "control": "A.8.28",
                "description": "Secure coding",
            },
        ],
    },
}


def get_compliance_mapping(
    payload_category: str,
) -> dict:
    """
    Get compliance framework mappings for a
    payload category.

    Args:
        payload_category: Single letter category e.g. A

    Returns:
        Dictionary with all framework mappings
        for that category.
    """
    mapping = COMPLIANCE_MAPPINGS.get(
        payload_category.upper()
    )

    if not mapping:
        log.warning(
            "no_compliance_mapping",
            category=payload_category,
        )
        return COMPLIANCE_MAPPINGS.get("A", {})

    return mapping


def format_compliance_for_report(
    mapping: dict,
    frameworks: list = None,
) -> str:
    """
    Format compliance mappings as markdown
    for inclusion in reports.

    Args:
        mapping:    Compliance mapping dictionary
        frameworks: List of frameworks to include.
                    None means include all.
                    Options: owasp_llm, owasp_agentic,
                    mitre_atlas, nist_ai_rmf, eu_ai_act,
                    soc2, iso_27001

    Returns:
        Formatted markdown string
    """
    if not mapping:
        return ""

    all_frameworks = [
        "owasp_llm",
        "owasp_agentic",
        "mitre_atlas",
        "nist_ai_rmf",
        "eu_ai_act",
        "soc2",
        "iso_27001",
    ]

    include = frameworks or all_frameworks
    lines = []

    if mapping.get("owasp_llm") and \
            "owasp_llm" in include:
        owasp = mapping["owasp_llm"]
        lines.append(
            f"**OWASP LLM Top 10:** "
            f"{owasp['id']} - {owasp['name']}\n"
        )

    if mapping.get("owasp_agentic") and \
            "owasp_agentic" in include:
        agentic = mapping["owasp_agentic"]
        lines.append(
            f"**OWASP Agentic AI:** "
            f"{agentic['id']} - {agentic['name']}\n"
        )

    if mapping.get("mitre_atlas") and \
            "mitre_atlas" in include:
        lines.append("**MITRE ATLAS:**\n")
        for technique in mapping["mitre_atlas"]:
            lines.append(
                f"- {technique['id']}: "
                f"{technique['name']}\n"
            )

    if mapping.get("nist_ai_rmf") and \
            "nist_ai_rmf" in include:
        lines.append("**NIST AI RMF:**\n")
        for item in mapping["nist_ai_rmf"]:
            lines.append(
                f"- {item['function']} {item['category']}: "
                f"{item['description']}\n"
            )

    if mapping.get("eu_ai_act") and \
            "eu_ai_act" in include:
        lines.append("**EU AI Act:**\n")
        for item in mapping["eu_ai_act"]:
            lines.append(
                f"- {item['article']}: "
                f"{item['description']}\n"
            )

    if mapping.get("soc2") and "soc2" in include:
        lines.append("**SOC 2:**\n")
        for item in mapping["soc2"]:
            lines.append(
                f"- {item['criteria']}: "
                f"{item['description']}\n"
            )

    if mapping.get("iso_27001") and \
            "iso_27001" in include:
        lines.append("**ISO 27001:**\n")
        for item in mapping["iso_27001"]:
            lines.append(
                f"- {item['control']}: "
                f"{item['description']}\n"
            )

    return "".join(lines)


def get_compliance_summary(
    finding_categories: list,
) -> dict:
    """
    Generate a compliance summary across all
    findings in a scan.

    Groups findings by compliance framework
    for the compliance section of the report.

    Args:
        finding_categories: List of payload category
                            letters from all findings

    Returns:
        Dictionary summarising compliance impact
    """
    owasp_violations = set()
    atlas_techniques = set()
    nist_functions = set()
    eu_articles = set()
    soc2_criteria = set()

    for category in finding_categories:
        mapping = get_compliance_mapping(category)

        if mapping.get("owasp_llm"):
            owasp_violations.add(
                mapping["owasp_llm"]["id"]
            )

        if mapping.get("mitre_atlas"):
            for t in mapping["mitre_atlas"]:
                atlas_techniques.add(t["id"])

        if mapping.get("nist_ai_rmf"):
            for item in mapping["nist_ai_rmf"]:
                nist_functions.add(
                    f"{item['function']} {item['category']}"
                )

        if mapping.get("eu_ai_act"):
            for item in mapping["eu_ai_act"]:
                eu_articles.add(item["article"])

        if mapping.get("soc2"):
            for item in mapping["soc2"]:
                soc2_criteria.add(item["criteria"])

    return {
        "owasp_violations": sorted(owasp_violations),
        "atlas_techniques": sorted(atlas_techniques),
        "nist_functions": sorted(nist_functions),
        "eu_articles": sorted(eu_articles),
        "soc2_criteria": sorted(soc2_criteria),
    }