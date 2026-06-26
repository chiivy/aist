# AIST — Agentic Injection Security Tester

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![GitHub stars](https://img.shields.io/github/stars/chiivy/aist?style=social)

**The open-source security testing tool built specifically for AI agents.**

[Repository](https://github.com/chiivy/aist) · [Canary setup](docs/canary_setup.md) · [Scoring methodology](docs/scoring_methodology.md) · [Threat model](docs/threat_model.md)

---

## What makes AIST different

Most security tools test language models in isolation. AIST tests **AI agents** — systems that send email, read files, query databases, call APIs, and delegate to other agents. The same prompt injection that scores **Low** against a read-only chatbot can score **Critical** against an agent with database and email access.

AIST quantifies that difference with **tool-aware severity scoring**: findings are weighted by declared and discovered capabilities, attack-surface complexity, and evidence patterns (credentials, canary leaks, system prompt disclosure depth). Every result maps to OWASP LLM Top 10 and MITRE ATLAS references.

---

## What AIST tests

| Category | What it tests |
|----------|---------------|
| A–F | Direct prompt injection variants (role override, jailbreak, context manipulation, extraction, tool abuse, format attacks) |
| G | Guardrail bypass including token boundary splitting (G11) |
| H | Tool parameter injection and SSRF (H4 with canary confirmation) |
| I | Indirect injection vectors (poisoned documents, tool responses, RAG-oriented probes) |
| S | Multi-turn sequence manipulation |
| BL | Business logic violation |
| J | Infrastructure security configuration (headers, CORS, rate limits, debug paths) |
| MA | Multi-agent traversal and propagation |

Recon and discovery run before scanners: passive probes map tools, endpoints, connected agents, SSRF potential, and model hints to optimise payload selection.

---

## Quick start

```bash
git clone https://github.com/chiivy/aist
cd aist
cp .env.example .env
# Edit .env — see docs/canary_setup.md for optional canary tokens

pip install -e .

aist scan --target https://your-agent.com/chat \
          --tools email,files,database \
          --operator yourname
```

**Minimum scan** (string matching only, no API keys):

```bash
pip install -e .
aist scan --target https://your-agent.com/chat
```

**Recommended** for accurate detection: configure `ANTHROPIC_API_KEY` in `.env`
for LLM judge analysis, and canary tokens for out-of-band confirmation on SSRF
and tool-abuse tests.

| Configuration | Detection method | Accuracy |
|---------------|------------------|----------|
| LLM key + canary | Judge + canary trigger | Highest |
| LLM key only | LLM judge analysis | High |
| Canary only | Canary + string matching | Medium |
| No config | String matching only | Basic |

---

## Authentication

AIST supports authenticated agents. Configure via `.env` or CLI flags.

**Bearer token** (from Burp or browser devtools):

```bash
aist scan --target https://app.example.com/api/chat \
  --auth-type bearer \
  --auth-token "eyJhbGci..."
```

**Username / password** (login flow):

```bash
aist scan --target https://app.example.com/api/chat \
  --auth-type basic \
  --auth-username user@company.com \
  --auth-password "your-password" \
  --auth-login-url https://app.example.com/api/login
```

**Azure AD SSO**:

```bash
aist scan --target https://app.example.com/api/chat \
  --auth-type sso \
  --auth-tenant-id your-tenant-id \
  --auth-client-id your-client-id
```

**API key** (custom header):

```bash
aist scan --target https://app.example.com/api/chat \
  --auth-type apikey \
  --auth-token your-api-key \
  --auth-header X-API-Key
```

**Session cookie**:

```bash
aist scan --target https://app.example.com/api/chat \
  --auth-type cookie \
  --auth-cookie-name session \
  --auth-cookie-value "abc123..."
```

---

## Safe mode

Use `--safe-mode` (or `AIST_SAFE_MODE=true`) when scanning production or
production-adjacent systems. Safe mode skips categories that could trigger
real side effects:

- **E** — tool abuse (email send, file write, etc.)
- **H** — tool parameter injection and SSRF probes
- **S** — multi-turn sequences
- **INDIRECT** — indirect injection vectors
- **MA** — multi-agent traversal

Recon, guardrail (G), output (I), infrastructure (J), and canary checks still run.

```bash
aist scan --target https://your-agent.com/chat --safe-mode
```

---

## Report output

Every scan produces:

| Format | File | Audience |
|--------|------|----------|
| **HTML** | `report.html` | Full technical report with evidence, scoring breakdown, compliance mapping |
| **HTML Executive** | `report-executive.html` | Plain-English summary with risk gauge for stakeholders |
| **JSON** | `report.json` | Machine-readable for pipelines and integrations |
| **SARIF** | `report.sarif` | Native GitHub Security tab integration |

```bash
aist scan --target https://your-agent.com/chat \
          --output reports/my-scan.html \
          --expose-evidence    # optional: show full unmasked evidence
```

<!-- Screenshot placeholder -->
> **[Screenshot of HTML report]** — *Add a screenshot of a completed scan report here.*

---

## Architecture

AIST follows a linear pipeline orchestrated by `scanner/orchestrator.py`:

**Recon** → **Canary baseline** → **Scanners** → **Artifact aggregation** →
**Passive validation** → **Scoring** → **Reports**

Evidence flows through `is_genuine_finding()` before appearing in any output.
Recon discoveries become first-class findings (`RECON-D1`, `RECON-E1`,
`RECON-H4`, `RECON-S1`) with real agent response text captured during probes.

See [docs/architecture.md](docs/architecture.md) for a detailed component
diagram and data-flow description.

---

## Research background

AIST connects operational security testing to the growing body of prompt
injection research, the [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/),
and [MITRE ATLAS](https://atlas.mitre.org/) adversarial ML techniques. It was
built to support rigorous, reproducible methodology for AI agent security
assessment — combining structured payloads, LLM-as-judge analysis, canary
confirmation, and contextual severity scoring in a single open-source toolchain
suitable for both practitioner workflows and academic evaluation.

Read the scoring model in [docs/scoring_methodology.md](docs/scoring_methodology.md).

---

## Privacy and data sovereignty

AIST runs entirely on your machine. Target endpoints, API keys, and findings
stay in your environment. The only outbound calls are to the agent under test
and the LLM provider you configure for judge analysis. No accounts, telemetry,
or phone-home.

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for
guidelines on issues, pull requests, and development setup.

---

## License

MIT — see [LICENSE](LICENSE).

---

Built by [@chiivy](https://github.com/chiivy)
