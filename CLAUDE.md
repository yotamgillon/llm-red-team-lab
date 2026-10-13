# LLM Red Team Lab - project rules

## Purpose
Educational defensive-security project. A deliberately vulnerable LLM chatbot (target/) plus an automated scanner (scanner/) based on the OWASP Top 10 for LLM Applications (2025).

## Hard rules
- All data is synthetic. No real brands, people, keys or customer data.
- The scanner may only target localhost, 127.0.0.1 and ::1. Parse the URL and compare the hostname exactly. No startswith checks. Do not follow redirects to other hosts.
- The project must run fully in MOCK mode with no API key. CI runs in MOCK mode.
- MOCK responses must depend on the input. Never return one fixed answer.
- Secrets live in .env, which is never committed.

## Workflow
- Small commits with clear names, for example "feat(scanner): add canary detector".
- Before finishing any milestone: ruff check and pytest must pass.
- Every attack in the library needs a test proving its detector fires on a vulnerable response and stays quiet on a safe one.
- Typed Python, docstrings on public functions.
- Read PLAN.md at the start of each session and work only on the requested milestone.
