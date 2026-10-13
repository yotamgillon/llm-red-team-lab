# llm-red-team-lab

Educational defensive-security project: a deliberately vulnerable, fully synthetic LLM chatbot
("NovaBank Support") plus an automated scanner based on the OWASP Top 10 for LLM Applications (2025).

> Work in progress. Milestone 1 (target app) only. See `PLAN.md`.

## Run the target (MOCK mode, no API key)

```bash
pip install -e ".[dev]"
uvicorn target.main:app --port 8000
```

Open http://127.0.0.1:8000. **Deliberately vulnerable: never expose it beyond localhost.**
