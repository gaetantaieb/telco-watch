# Telco Vendor Watch

Telegram bot that polls telecom vendor security advisories every hour, stores them
in Railway Postgres and alerts a Telegram group. Hosted on Railway only.
Spec: https://claude.ai/artifact/3iSAhCK5aMBuaJNkDFvSd8

## Commands
- Run locally on the development environment: `railway run python bot.py`
- Tests: `pytest -q`   Format: `ruff format .`   Lint: `ruff check .`

## Rules
- Never commit secrets; all config comes from Railway variables (.env.example lists them).
- All database access goes through db.py; SQL is always parameterised (%s).
- Detection and alerting stay deterministic; the LLM is only used by /ask (llm.py)
  and /addvendor (onboard.py), and a vendor is stored only after an admin approves it.
- llm.py uses the read-only database role (DATABASE_URL_RO).
- Every change adds or updates a test; run ruff format, ruff check and pytest before finishing.
- Work on a branch and open a pull request; never push to main.
