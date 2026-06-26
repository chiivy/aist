# AIST - Agentic Injection Security Tester

## What this project does

AIST is an open-source Python CLI tool that tests AI agents for prompt
injection and related security weaknesses through structured attack
payloads, reconnaissance, and evidence-based scoring. Unlike generic
LLM testers, AIST models agent capabilities (tools, connected agents,
outbound requests) when calculating severity, so the same injection can
score differently depending on what the agent can actually do. Repository:
https://github.com/chiivy/aist

## Project structure

```
aist/
  auth/          -- Authentication module (Bearer, Basic, SSO, API key, cookie)
  evidence/      -- Evidence collection, pattern detection, masking
  payloads/      -- YAML attack payload definitions (categories A–MA)
  recon/         -- Reconnaissance modules (probe, discovery, fingerprint)
  reporting/     -- HTML, JSON, SARIF report generation
  scanner/       -- Attack scanner engines and orchestrator
  scoring/       -- Severity and confidence scoring
  remediation/   -- Contextual remediation guidance
  compliance/    -- OWASP / MITRE ATLAS / NIST mapping
  cli.py         -- Click CLI entry point
  config.py      -- All configuration and environment variables
  logger.py      -- Structured JSON logging
```

Supporting directories at repo root:

- `docs/` — Threat model, canary setup, scoring methodology
- `tests/` — Pytest suite (mirrors package layout)
- `reports/` — Generated scan reports (gitignored)
- `logs/` — Structured audit logs (gitignored)

## Key architectural decisions

- All configuration flows through the `AISTConfig` dataclass in
  `config.py`, loaded from environment variables and CLI flags.
- Evidence objects flow: **collect → judge → score → report**.
- `is_genuine_finding()` in `evidence/collector.py` is the single source
  of truth for what appears in reports. The LLM judge can veto string-match
  false positives; canary leaks and credential detections are always genuine.
- Recon findings (`RECON-D1`, `RECON-E1`, `RECON-H4`, `RECON-S1`) bypass
  `tool_addition` and `discovery_multiplier` in scoring — they are the
  source of attack-surface information, not findings amplified by it.
- `auth_manager` (`AuthManager`) flows through all scanners as an optional
  keyword argument and refreshes tokens before each request when configured.
- `safe_mode` skips categories that can trigger real actions: **E, H, S,
  INDIRECT (indirect/V vectors), and MA**. Infrastructure checks (J) still run.
- Context-aware category selection (`_get_recommended_categories`) skips
  irrelevant scanners based on recon (e.g. no tools → skip E and H).
- Agent responses are untrusted input — never passed raw to LLM components
  without sanitisation; AIST protects itself from second-order injection.

## How a scan works

1. **Recon phase** — `probe.py`, `discovery.py`, `fingerprint.py`
2. **Canary generation** — semantic baseline + token for exfiltration checks
3. **Scanner phases** — direct, indirect, multiturn, guardrail, toolparam,
   output, infrastructure, multiagent, canary
4. **Artifact aggregation** — credentials, URLs, endpoints from genuine findings
5. **Passive resource validation** — HEAD/TCP checks only (no data accessed)
6. **Scoring** — `severity.py`, `confidence.py` (with disclosure depth caps)
7. **Report generation** — `html.py`, `json_report.py`, `sarif.py`

Orchestration lives in `scanner/orchestrator.py`.

## Payload categories

| Code | Focus |
|------|-------|
| A | Role override and persona injection |
| B | Jailbreak and restriction bypass |
| C | Context manipulation |
| D | System prompt extraction |
| E | Tool abuse and excessive agency |
| F | Format and output manipulation |
| G | Guardrail bypass (including G11 token boundary splitting) |
| H | Tool parameter injection (including H4 SSRF) |
| I | Indirect injection |
| S | Multi-turn sequence attacks |
| BL | Business logic violations |
| J | Infrastructure security checks |
| MA | Multi-agent traversal |

Indirect scanner payloads use sub-IDs (e.g. V3, V4 for RAG-oriented tests).

## Running a scan

```bash
py -m aist.cli scan --target http://localhost:5000/chat \
  --tools email,files \
  --runs 1 \
  --operator yourname \
  --log-level WARNING
```

Or after `pip install -e .`:

```bash
aist scan --target http://localhost:5000/chat \
  --tools email,files \
  --runs 3 \
  --operator yourname
```

Use `--safe-mode` against production-adjacent targets. Use `--categories`
to limit scope. Omit `--target` to launch the interactive wizard.

## Test agent

A deliberately vulnerable Flask test agent is maintained separately for
local development:

```bash
cd ~/aist-test-agent/
export ANTHROPIC_API_KEY="your-key"   # required by the test agent only
python agent.py
```

Point AIST at `http://localhost:5000/chat` while the agent is running.

## Environment variables

All config via `.env` file. See `.env.example` for the full list.

| Variable | Purpose |
|----------|---------|
| `ANTHROPIC_API_KEY` | LLM judge analysis (recommended) |
| `OPENAI_API_KEY` | Alternative LLM judge provider |
| `AIST_CANARY_URL` | canarytokens.org URL for SSRF confirmation |
| `AIST_CANARY_EMAIL` | canarytokens.org email for tool-abuse tests |
| `AIST_CANARY_DOMAIN` | canarytokens.org domain for DNS exfiltration |
| `AIST_CANARIES_PLANTED` | `true` after CT2–CT4 behavioural policies are added to target |
| `AIST_AUTH_TYPE` | `bearer`, `basic`, `sso`, `apikey`, `cookie`, or `none` |
| `AIST_SAFE_MODE` | `true` to skip action-triggering categories |
| `AIST_OPERATOR` | Operator name embedded in reports |

Never commit `.env` or real credentials.

## Known limitations

- Tests the conversational interface layer only (not backend APIs in isolation)
- RAG detection is linguistic, not behavioural
- Single-run scans show LLM non-determinism variance — use `--runs 3` for confidence
- Adaptive payload generation not yet implemented
- MCP protocol testing not yet implemented
- Disclosure depth heuristics may need per-model calibration

## Commit conventions

```
feat:     new feature
fix:      bug fix
docs:     documentation only
security: security fix or hardening
test:     tests only
refactor: code restructure without behaviour change
```

Always pull before starting work. Never commit `.env` files or API keys.
