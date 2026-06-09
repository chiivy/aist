# AIST: Agentic Injection Security Tester

Open source prompt injection testing framework built specifically for AI agents.

![Status](https://img.shields.io/badge/status-active%20development-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![OWASP](https://img.shields.io/badge/OWASP-LLM%20Top%2010-red)

---

## The Problem

AI agents have access to email, files, databases, and APIs. Prompt injection sits at number one on both the OWASP LLM Top 10 and the OWASP Agentic AI Top 10 because a successful attack does not just produce a bad response. It exfiltrates data, sends emails, deletes files, and calls APIs the user never authorised.

In April 2026, researchers confirmed that Claude Code, Gemini CLI, and GitHub Copilot Agent were all compromised via prompt injection through specially crafted content. The attack surface is real, active, and growing faster than the tooling to test it.

Most existing tools test LLMs. AIST tests agents, and scores vulnerability severity based on what the agent can actually do.

---

## What Makes AIST Different

| Feature | AIST | Promptmap | Rebuff | Pytector |
|---------|------|-----------|--------|----------|
| Tool-aware contextual severity scoring | Yes | No | No | No |
| Multi-turn attack chain testing | Yes | No | No | No |
| Second order injection protection | Yes | No | No | No |
| Canary token validation | Yes | No | Yes | No |
| MITRE ATLAS mapped findings | Yes | No | No | No |
| SIEM-ready structured logging | Yes | No | No | No |
| Published threat model | Yes | No | No | No |

**Tool-aware scoring** means the same vulnerability scores differently depending on what the agent can do. Prompt injection on an agent with read-only access is a different risk than the same injection on an agent with email, file, and database access. No existing open source tool accounts for this.

---

## Quick Start

```bash
pip install aist
```

```bash
aist scan --target https://your-agent.com \
          --tools email,files,database \
          --output report.html
```

> Note: AIST is in active development. Installation will be available at v1.0 release.

---

## What AIST Tests

- Direct prompt injection across six payload categories
- Indirect injection via poisoned documents and tool responses
- Multi-turn attack sequences that build context before striking
- Authentication bypass via role and permission injection
- Session persistence: does a successful injection survive across sessions
- Canary token exfiltration detection
- Second order injection: protection against hostile agent responses targeting AIST itself

Each finding is mapped to a MITRE ATLAS technique and scored using a contextual severity model combining CVSS with tool-aware risk weighting.

---

## Output

Every scan produces:

- HTML report with executive summary and traffic light scoring
- JSON report for machine processing and pipeline integration
- SARIF output for native display in GitHub and VS Code
- SIEM-ready structured JSON audit log

---

## Design

AIST was designed threat-model first. Before any code was written, a full STRIDE analysis was conducted on the tool itself, including identification of second order prompt injection as a specific architectural threat where security testing tools become attack targets via the responses they receive.

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
