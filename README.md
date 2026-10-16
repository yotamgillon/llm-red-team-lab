# llm-red-team-lab

Educational defensive-security project: a deliberately vulnerable, fully synthetic LLM chatbot
("NovaBank Support") plus an automated scanner based on the OWASP Top 10 for LLM Applications (2025).

> Work in progress. Milestones 1-5 (target app, scanner, 33-attack library, reports, SECURE_MODE). See `PLAN.md`.

## Run the target (MOCK mode, no API key)

```bash
pip install -e ".[dev]"
uvicorn target.main:app --port 8000
```

Open http://127.0.0.1:8000. **Deliberately vulnerable: never expose it beyond localhost.**

### SECURE_MODE

`SECURE_MODE=true uvicorn target.main:app --port 8000` turns on the mitigations: input/output
guardrails, tool authorization and human confirmation for refunds, untrusted-document handling,
HTML escaping plus CSP, size limits and rate limiting. Pending refunds are confirmed with
`POST /api/refunds/{id}/confirm` and an `X-Staff-Token` header (set `STAFF_TOKEN`; otherwise a
random token is generated and nobody can confirm). Most controls are real code; the hardened-prompt
refusal and "summarise, don't quote" behaviour are *simulated* by the MOCK model. See the M5 notes in `PLAN.md`.

## Run the scanner (localhost targets only)

```bash
redteam validate
redteam list-attacks
redteam scan --target http://localhost:8000 --categories all   # exit 1 if any finding
redteam scan --out results/ --format md,html,json --name before   # write reports
redteam report results/before.json --out results/                 # re-render from JSON
redteam compare results/before.json results/after.json [--fail-on-regression]
```

The scanner refuses any target whose parsed hostname is not exactly `localhost`, `127.0.0.1` or
`::1`, and never follows redirects.
