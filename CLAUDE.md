# Telco Vendor Watch

Telegram bot that polls telecom vendor security advisories every hour, stores them
in Railway Postgres and alerts approved users in private chats. Hosted on Railway only.
Spec of the current version: docs/spec.md (keep it up to date with every feature change).
Original design: docs/specs.pdf. Overview and setup: README.md.

## Commands
- Run locally on the development environment: `railway run python bot.py`
- Tests: `pytest -q`   Format: `ruff format .`   Lint: `ruff check .`

## Rules
- Never commit secrets; all config comes from Railway variables (.env.example lists them).
- All database access goes through db.py; SQL is always parameterised (%s).
- Detection and alerting stay deterministic; the LLM is only used by /ask (llm.py)
  and /addvendor (onboard.py), and a vendor is stored only after an admin approves it.
- llm.py uses the read-only database role (DATABASE_URL_RO).
- Every user-visible change is described in release_notes.yaml: one entry per
  production release, 4 lines at most. Until that release, rewrite the newest entry
  in place (same version); after it, start a new entry with a new version.
- Every change adds or updates a test; run ruff format, ruff check and pytest before finishing.
- Work on a branch and open a pull request; never push to main.

## Agents (.claude/agents/)
Use these subagents for every feature, behaviour change or bug fix, in this order:
1. `product-owner` (brief): writes `docs/features/<slug>.md` with the functional
   design and numbered acceptance criteria. Ask the user its open questions before coding.
2. `architect` (plan): checks the approach against schema.sql, db.py, existing
   functions and Railway; resolve every blocker before coding.
3. Implement the change (main agent).
4. `qa`: writes tests for each acceptance criterion, runs ruff format, ruff check, pytest.
5. `architect` (diff): reviews the finished diff.
6. `product-owner` (acceptance): checks the criteria, docs/spec.md and
   release_notes.yaml; open the pull request only once it says ACCEPTED.
Trivial changes (typos, docs only) can skip steps 1, 2 and 6; QA always runs.
