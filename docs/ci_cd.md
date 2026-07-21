# Continuous AI Security Testing with AIST

Add AIST to your AI agent's CI/CD pipeline
to automatically detect security regressions
every time you deploy.

## What this does

Every time you push code to your agent
repository, AIST automatically:
1. Scans your live agent endpoint
2. Checks for prompt injection, tool abuse,
   data leakage, and other AI vulnerabilities
3. Fails the pipeline if critical issues found
4. Uploads results to GitHub Security tab
5. Saves full reports as downloadable artifacts

## Setup

### Step 1: Add secrets to your agent's GitHub repo

Settings -> Secrets and variables -> Actions

**Required:**
- `AI_AGENT_URL` — your agent's chat endpoint
- `ANTHROPIC_API_KEY` — for LLM judge validation

**Optional but recommended:**
- `AIST_CANARY_EMAIL` — canarytokens.org email
- `AIST_CANARY_URL` — canarytokens.org URL

### Step 2: Copy the workflow template

Copy `aist/templates/github-workflow.yml`
from the AIST repository to:

```
your-repo/.github/workflows/aist-scan.yml
```

### Step 3: Push and verify

Push to main. Go to your repo's Actions tab
and watch the scan run.

## Controlling when the pipeline fails

Fail on any critical finding (recommended):

```bash
--fail-on critical
```

Fail on high or above:

```bash
--fail-on high
```

Never fail, report only:

Remove `--fail-on` flag entirely

## Choosing a scan profile

For CI/CD on every push (fast):

```bash
--profile quick
```

Tests: Persona Injection, Objective Hijacking,
System Prompt Leakage, Tool Abuse

For scheduled weekly scans (thorough):

```bash
--profile standard
```

Tests: All vulnerability categories

For deep monthly assessments:

```bash
--profile deep
```

Tests: All categories + Multi-Turn Attack Scenarios

## Viewing results

**GitHub Security tab:**
SARIF results appear under Code Scanning Alerts.
Each finding links back to the specific payload
and response that triggered it.

**GitHub Artifacts:**
Full HTML, JSON, and redacted reports
downloadable from the Actions run page.
Retained for 30 days.

## Retesting a single finding

After a scan, retest one finding without
running the full suite:

```bash
aist retest \
  --report reports/2026-07-21-scan/report.json \
  --finding B5 \
  --operator "CI/CD"
```

Use this locally or in a follow-up workflow
when investigating whether a fix worked.

## Notes

- The workflow scans your **live agent endpoint**,
  not your source code. Deploy the agent (or
  point at a staging URL) before the job runs.
- Use `--profile quick` on push/PR for speed;
  reserve `--profile standard` or `deep` for
  scheduled runs.
- Without `AIST_CANARY_*` secrets, AIST still
  runs but external tool-abuse confirmation
  is string-match only.
