# AIST: Agentic Injection Security Tester

Open source AI agent security testing framework covering prompt injection,
guardrail bypass, tool parameter injection, and output manipulation.

![Status](https://img.shields.io/badge/status-active%20development-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![OWASP](https://img.shields.io/badge/OWASP-LLM%20Top%2010-red)

---

## The Problem

AI agents have access to email, files, databases, and APIs. Prompt injection
sits at number one on both the OWASP LLM Top 10 and the OWASP Agentic AI
Top 10 because a successful attack does not just produce a bad response.
It exfiltrates data, sends emails, deletes files, and calls APIs the user
never authorised.

In April 2026, researchers confirmed that Claude Code, Gemini CLI, and
GitHub Copilot Agent were all compromised via prompt injection through
specially crafted content. The attack surface is real, active, and growing
faster than the tooling to test it.

Most existing tools test LLMs. AIST tests agents, and scores vulnerability
severity based on what the agent can actually do.

---

## What Makes AIST Different

| Feature | AIST | Promptmap | Rebuff | Pytector |
|---------|------|-----------|--------|----------|
| Tool-aware contextual severity scoring | Yes | No | No | No |
| Attack surface mapping and discovery | Yes | No | No | No |
| Agent-to-agent detection | Yes | No | No | No |
| Guardrail bypass testing | Yes | No | No | No |
| Tool parameter injection testing | Yes | No | No | No |
| Output manipulation testing | Yes | No | No | No |
| Multi-turn attack chain testing | Yes | No | No | No |
| Second order injection protection | Yes | No | No | No |
| Canary token validation | Yes | No | Yes | No |
| Session persistence testing | Yes | No | No | No |
| Streaming response support | Yes | No | No | No |
| Environment and OS probing | Yes | No | No | No |
| Adaptive testing via model fingerprinting | Yes | No | No | No |
| LLM judge analysis for accurate detection | Yes | No | No | No |
| Configurable evidence exposure modes | Yes | No | No | No |
| Local execution, no data sent to third parties | Yes | Yes | No | Yes |
| MITRE ATLAS mapped findings | Yes | No | No | No |
| SIEM-ready structured logging | Yes | No | No | No |
| Published threat model | Yes | No | No | No |

**Tool-aware scoring** means the same vulnerability scores differently
depending on what the agent can do. Prompt injection on an agent with
read-only access is a different risk than the same injection on an agent
with email, file, and database access. No existing open source tool
accounts for this.

---

## Getting Started

**Minimum setup -- runs a basic scan immediately:**

```bash
pip install aist
aist scan --target https://your-agent.com
```

**Full setup -- maximum detection accuracy:**

```bash
# Clone the repo
git clone https://github.com/chiivy/aist
cd aist

# Copy environment template
cp .env.example .env

# Edit .env with your values
# See docs/canary_setup.md for canary setup options

# Install and scan
pip install -e .
aist scan --target https://your-agent.com \
          --tools email,files,database \
          --output report.html
```

**AIST degrades gracefully based on what you configure:**

| Configuration | Detection Method | Accuracy |
|--------------|-----------------|----------|
| Full config (LLM key + canary) | LLM judge + canary trigger | Highest |
| LLM key only | LLM judge analysis | High |
| Canary only | Canary trigger + string matching | Medium |
| No config | String matching only | Basic |

See [docs/canary_setup.md](docs/canary_setup.md) for free canary options
including canarytokens.org.

---

## What AIST Tests

**Recon and Discovery**
- Attack surface mapping: endpoints, connected agents, undeclared tools
- Model fingerprinting for adaptive payload selection
- Guardrail and safety boundary detection
- Environment and OS probing
- Memory and storage architecture detection
- Streaming response handling

**Injection Testing**
- Direct prompt injection across six payload categories
- Indirect injection via poisoned documents and tool responses
- Multi-turn attack sequences that build context before striking
- Authentication bypass via role and permission injection
- Session persistence: does a successful injection survive across sessions
- Canary token exfiltration detection
- Second order injection: AIST itself is protected from hostile agent responses

**Guardrail Circumvention**
- Fictional and hypothetical framing bypasses
- Encoded bypasses via base64 and character substitution
- Multilingual safety filter evasion
- Fragmentation attacks across multiple turns
- Persona injection and jailbreak patterns
- Token smuggling via streaming

**Tool Parameter Injection**
- SQL injection via database tools
- Command injection via shell tools
- Path traversal via file tools
- SSRF via web browsing tools including AWS, Azure, and GCP metadata endpoints
- Environment variable extraction

**Output Manipulation**
- XML and JSON injection in generated output
- Code generation attacks
- Markdown injection with malicious links
- Downstream prompt injection targeting systems that consume agent output

Each finding is mapped to a MITRE ATLAS technique and scored using a
contextual severity model combining CVSS with tool-aware risk weighting.

---

## Output

Every scan produces:

- HTML report with executive summary and traffic light scoring
- JSON report for machine processing and pipeline integration
- SARIF output for native display in GitHub and VS Code
- SIEM-ready structured JSON audit log

**Three report modes:**

| Mode | Command | Use case |
|------|---------|----------|
| Standard | `aist scan --target ...` | Default. Partial masking of sensitive values |
| Sensitive | `aist scan --target ... --expose-evidence` | Full values for remediation. Requires confirmation |
| Executive | `aist scan --target ... --executive` | Traffic light only. Safe for non-technical stakeholders |

---

## Privacy and Data Sovereignty

AIST runs entirely on your machine.

Your API keys, target endpoints, and vulnerability findings never leave
your environment. AIST makes no external calls except to the agent you
are testing and the LLM API you configure for response analysis.

No accounts required. No data sent to third parties. No telemetry.
No phone home.

This matters for security teams working with sensitive agents. You have
full visibility into what is being tested and complete control over
where findings are stored.

---

## Design

AIST was designed threat-model first. Before any code was written, a full
STRIDE analysis was conducted on the tool itself, including identification
of second order prompt injection as a specific architectural threat where
security testing tools become attack targets via the responses they receive.

Read the full threat model: [docs/threat_model.md](docs/threat_model.md)

---

## Roadmap

| Version | Target | Focus |
|---------|--------|-------|
| v1.0 | June 2026 | Core scanning engine, HTML and SIEM reporting |
| v1.5 | Q3 2026 | MCP server testing, RAG pipeline injection |
| v2.0 | Q4 2026 | Bulk scanning, CI/CD native, executive dashboards |

---

## Author

Built by [@chiivy](https://github.com/chiivy)