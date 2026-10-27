# Telco Vendor Watch

A Telegram bot that watches the security advisories of telecom vendors (and any
other product or technology you add) and sends each approved user the ones that
matter to them, within the hour.

Every hour it collects CISA KEV, NIST NVD and the vendors' own feeds, stores
every advisory in Postgres, and sends each new one to every approved user whose
`/severity` and `/mute` settings let it through. Users talk to the bot in a
private chat; admins approve who can use it and manage what is monitored.

- Functional spec of the current version: [docs/spec.md](docs/spec.md)
- Original design document: [docs/specs.pdf](docs/specs.pdf)
- Instructions for Claude Code: [CLAUDE.md](CLAUDE.md)

## Features

- **Hourly collection** from CISA KEV, NVD (by vendor keyword, or by CPE for a
  product such as PHP) and vendor RSS, JSON or HTML sources. A failing source
  never blocks the others.
- **Alerts in private chats**, one message per advisory: severity, CVSS, vendor,
  title, CVEs, publication date (Paris time) and link. Vendor ratings ("Severity:
  High") count like a CVSS score when there is none. An old advisory that its
  source has just updated comes as a one-line update. Actively exploited (KEV)
  advisories, and those with neither a score nor a rating, are always sent.
- **Personal settings**: minimum severity (`/severity`) and muted vendors
  (`/mute`).
- **Access control**: a new user sends `/start`; admins get an Approve/Reject
  request. Groups are ignored.
- **`/ask`**: questions in plain language about the stored alerts, answered by
  Claude through read-only, parameterised queries.
- **`/addvendor`**: Claude searches the web for a vendor's or technology's
  official advisory sources; the bot tests each one and stores it only after an
  admin taps Approve.
- **Release notes**: after an update, every user gets the new version's notes
  from `release_notes.yaml` (4 lines at most), once.
- **Self-healing**: database connections are checked before use, failed commands
  answer instead of staying silent, and the command menu is set by the bot itself.

## Commands

Everyone (after approval):

| Command | Effect |
|---|---|
| `/start`, `/help` | Request access, or show the commands |
| `/status` (alias `/health`) | Last collection cycle: time, new items, failed sources |
| `/latest [vendor] [n]` | Last *n* published advisories (default 5, max 20), any severity |
| `/latest all [days]` | High and above (CVSS ≥ 7, vendor rating high or critical, or KEV) from every vendor, published in the last *days* (default 7, max 90) |
| `/vendors` | Monitored vendors and their own sources |
| `/ask <question>` | Ask about the stored alerts, e.g. `/ask anything actively exploited this week?` |
| `/severity <critical\|high\|medium\|low>` | Minimum severity of your alerts (default high) |
| `/mute <vendor>`, `/unmute <vendor>` | Stop or resume one vendor's alerts for you |

Admins (`ADMIN_USER_IDS`, plus users promoted with `/promote`):

| Command | Effect |
|---|---|
| `/checknow` | Run a collection cycle now |
| `/addvendor <name>` | Find, test and propose sources for a vendor, product or technology |
| `/removevendor <name>` | Disable a vendor and its sources; history is kept |
| `/users` | List users and their status |
| `/adduser <id>`, `/removeuser <id>` | Give or remove access |
| `/promote <id>`, `/demote <id>` | Give or take back the admin role (`ADMIN_USER_IDS` admins only) |

## Architecture

```
CISA KEV ─┐
NVD API ──┼─> collectors.py ─> bot.py (hourly cycle) ─> Postgres (items, users, …)
Vendor    │                         │                         │
feeds ────┘                         └─> Telegram: one private chat per user
                                         ├─ /ask ──────> llm.py (Claude, read-only DB role)
                                         └─ /addvendor ─> onboard.py (Claude + web search)
```

| File | Role |
|---|---|
| `bot.py` | Telegram commands, access control, hourly cycle, alerts, command menu |
| `collectors.py` | RSS, JSON, HTML, KEV and NVD fetchers; public-https URL guard |
| `db.py` | Connection pools, schema init, seeding, state |
| `schema.sql` | Tables, created or upgraded idempotently at every start |
| `seed.yaml` | The 29 initial vendors and 3 vendor feeds, loaded once into an empty database |
| `llm.py` | `/ask` assistant and its three read-only tools |
| `onboard.py` | `/addvendor` discovery, validation and source testing |
| `tests/test_bot.py` | Unit tests; no network or database needed |

## Setup

1. **Telegram**: create the bot with [@BotFather](https://t.me/BotFather) and
   keep its token. You don't need `/setcommands`: the bot sets its own menu.
   Get your Telegram user id (for example from
   `https://api.telegram.org/bot<TOKEN>/getUpdates` after messaging the bot).
2. **API keys**: an [NVD API key](https://nvd.nist.gov/developers/request-an-api-key)
   (raises the rate limit) and a Claude API key from the
   [Claude Console](https://console.anthropic.com/). Web search must be enabled
   for your organisation for `/addvendor`.
3. **Railway**: create a project from this repository, add a PostgreSQL
   database, and set the variables below on the bot service. Keep 1 replica
   and no public domain (the bot uses long polling).
4. **Read-only role for `/ask`** (production): add a variable `ASK_RO_PASSWORD`
   (a long random string) and set `DATABASE_URL_RO` to
   `postgresql://ask_ro:${{ASK_RO_PASSWORD}}@${{Postgres.PGHOST}}:${{Postgres.PGPORT}}/${{Postgres.PGDATABASE}}`.
   At every start the bot creates the `ask_ro` role (or resets its password)
   with `SELECT` on `items` and `vendors` only. No SQL to run by hand; change
   `ASK_RO_PASSWORD` to rotate it.
5. **First start**: the tables are created, `seed.yaml` is loaded, and the first
   cycle stores the backlog without sending anything. Each admin then sends
   `/start` to the bot in a private chat.

### Variables

| Variable | Value |
|---|---|
| `TELEGRAM_BOT_TOKEN` | Bot token from BotFather |
| `ADMIN_USER_IDS` | Telegram user ids of the permanent admins, comma-separated; they alone can `/promote` others |
| `DATABASE_URL` | `${{Postgres.DATABASE_URL}}` |
| `DATABASE_URL_RO` | URL of the read-only `ask_ro` role, created by the bot (in development, `${{Postgres.DATABASE_URL}}` is fine) |
| `ASK_RO_PASSWORD` | Password of `ask_ro`, referenced by `DATABASE_URL_RO` (production) |
| `NVD_API_KEY` | NVD API key |
| `ANTHROPIC_API_KEY` | Claude API key |
| `LLM_MODEL` | Model for `/ask`, e.g. `claude-haiku-5-5` |
| `ONBOARD_MODEL` | Model for `/addvendor`, e.g. `claude-sonnet-5-5` |
| `MIN_CVSS` | Default `/severity` threshold of new users, e.g. `7.0` |

Secrets live only in Railway variables, never in the repository.
`.env.example` lists the names.

## Development

Branches: work on a short-lived branch, open a pull request into `dev`.
Railway's `development` environment deploys `dev` automatically; `main` is for
production.

```sh
pip install -r requirements.txt ruff pytest
ruff format . && ruff check . && pytest -q
railway run python bot.py   # against the development environment
```

Run the bot either in Railway or locally, never both with the same token:
Telegram rejects the second instance with `409 Conflict`. A short 409 during a
deploy, while the old instance stops, is harmless.

CI (GitHub Actions) runs the format check, lint and tests on every pull request
and on pushes to `main`.

## Operations

- **Logs**: Railway → bot service → Deployments → View logs. Info goes to
  stdout, warnings and errors to stderr. Request URLs are not logged (they
  contain the bot token).
- **Source down**: admins get "⚠️ Sources failed: …" after each failing cycle,
  and `/status` shows the last cycle. If a vendor redesigned its site,
  `/removevendor <name>` then `/addvendor <name>`.
- **Too many alerts**: raise your `/severity`, `/mute` noisy vendors, or make a
  vendor's NVD keyword more specific (`UPDATE vendors SET nvd_keyword = …`).
- **Database growing**: `DELETE FROM items WHERE seen_at < now() - interval '12 months'`.
- **Bad release**: roll back in Railway (Deployments → previous → Rollback),
  then revert the commit through a pull request.
