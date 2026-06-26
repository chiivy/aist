# AIST Research Directions

Open research questions and planned future work for AIST and related tooling.

---

## 1. Adaptive Attack Generation

Current AIST uses static payload lists. The "Attacker Moves Second" study
(OpenAI, Anthropic, DeepMind, 2026) showed all published defences bypassed
above 90% under adaptive attack conditions.

Future work: An LLM red-team agent that iteratively refines payloads based on
target responses. This is the primary PhD research direction.

---

## 2. Local Semantic Similarity Scoring

See [scoring_methodology.md](scoring_methodology.md) — section *Future: Local
Semantic Similarity Scoring*.

Optional sentence-transformers integration planned for v1.2.

---

## 3. MCP Protocol Testing

Model Context Protocol (MCP) is the emerging standard for connecting AI agents
to tools and data sources. Tool poisoning and cross-server privilege escalation
via MCP are the highest-priority 2026 attack vectors not currently covered by
AIST.

Planned for v1.2.

---

## 4. Full-Stack Agent Testing

AIST currently tests the conversational interface layer only.
Agent-to-backend traffic, tool parameter validation at the API layer, and
database query injection via agent-generated queries are not tested.

Requires a proxy layer between agent and backend services. Significant
architectural addition planned for v2.0.

---

## 5. Multi-Model Judge Ensemble

Current LLM judge uses a single model (Claude or GPT). When the judge and target
are the same model family, shared reasoning patterns may create blind spots.

Future work: Use a different model family as judge when the target is detected
as the same family. For example, use GPT-4o as judge when the target is
Claude.

---

## 6. Benchmark Standardisation (AISTPet)

No standardised benchmark exists for comparing AI agent security tools.
AISTPet (planned separate repo) will provide deliberately vulnerable agents
with documented expected findings for validating detection accuracy.

---

## 7. Real-Time / Continuous Monitoring

AIST is a point-in-time scanner. Enterprise deployments need continuous
monitoring as agent prompts and tool configurations change.

Planned: `--watch` mode that rescans on a schedule and alerts on new findings.

---

## 8. Regulatory Compliance Automation

AIST maps findings to OWASP, MITRE ATLAS, NIST AI RMF, EU AI Act, and SOC2.

Future work: Generate formal compliance evidence packages suitable for audit
submission, not just informational mapping.
