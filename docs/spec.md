# Telco Vendor Watch: functional spec (current version)

This document describes what the bot does today. The original design is
[specs.pdf](specs.pdf); section 8 lists what it describes that is not built yet.

## 1. Purpose

Every hour the bot collects the security advisories of the monitored vendors,
stores every new one, and sends it to each approved user whose settings let it
through. It is a watch tool for security and network operations teams; it never
touches network equipment.

Objectives:
- an advisory reaches the user within 60 minutes of its publication (plus the
  source's own delay);
- one place, a private Telegram chat per user, where all vendor advisories land,
  filtered and ranked;
- the most important ones stand out: critical CVSS scores and known exploitation
  (CISA KEV).

## 2. Scope

**Vendors.** `seed.yaml` loads the 29 vendors of the original design (spec
section 2.2) into an empty database: 8 tier 1 (Cisco, Juniper, Nokia, Ericsson,
Huawei, ZTE, Fortinet, Palo Alto Networks), 9 tier 2 and 12 tier 3. After that,
admins manage vendors from Telegram; the file is not read again.

**Products and technologies.** `/addvendor` also accepts a product or technology
(PHP, OpenSSL, Kubernetes…). These are matched in NVD by CPE so that CVEs that
merely mention them are not collected (section 3.2).

## 3. Collection

### 3.1 The hourly cycle

A job runs 10 s after start, then every hour. Each cycle:

1. reads the enabled vendors and their enabled sources from Postgres, so a vendor
   added from Telegram is collected from the next cycle without a redeploy;
2. fetches CISA KEV, NVD, then each vendor source; a failing source is logged
   and named in the cycle status, and never stops the others;
3. stores every item not already in the database (section 4);
4. records `last_run` and the status line shown by `/status`;
5. sends each new item to every active user who wants it (section 5): a full
   alert, or a one-line update when the item was published more than a day before
   the previous cycle (section 5.2), then
   "⚠️ Sources failed: …" to the admins if any source failed.

On the very first cycle (no `last_run`), the backlog is stored and nothing is
sent. NVD is queried from `last_run` (or the last 24 h on the first run), so an
outage is caught up on the next cycle.

### 3.2 Sources

| Source | How it is matched |
|---|---|
| CISA KEV catalogue (JSON) | Whole-word match of the vendor's `nvd_keyword` on the KEV vendor and product, so "PHP" matches PHP but not phpMyAdmin. Every KEV item is flagged as actively exploited. |
| NVD API 2.0 | `virtualMatchString` with the vendor's `nvd_cpe` when it has one (e.g. `cpe:2.3:a:php:php`), else `keywordSearch` with its `nvd_keyword`; changes since the last cycle. CVSS is read from v4.0, else v3.1, else v3.0. The title is the English description, shortened (section 5.2). Throttled to the NVD rate limit. |
| Vendor RSS/Atom | Every entry. |
| Vendor JSON API | Configurable list path and field names (id, title, url, date, optional updated); at most 100 entries. |
| Vendor HTML page | CSS selectors for the advisory row, title and link; at most 50 rows. |

The seeded vendor feeds are Cisco PSIRT RSS, FortiGuard RSS and Palo Alto
Networks RSS. The other seeded vendors are covered by KEV and NVD until an admin
adds their own sources.

Every outgoing request, redirects included, goes through a guard that only
allows public `https` addresses (no private IPs, `.internal`, `.local` or
`localhost`). Each request has a 30 s timeout (60 s for NVD).

## 4. Storage

Railway Postgres; `schema.sql` runs at every start and only creates or adds what
is missing.

| Table | Content |
|---|---|
| `vendors` | name, `nvd_keyword`, optional `nvd_cpe`, enabled, added_at |
| `sources` | vendor, type (`rss`, `json`, `html`), url, parsing config, enabled, approving admin (`added_by`), added_at |
| `items` | key = sha256(vendor + advisory id), vendor, title, url, CVEs, CVSS, KEV flag, publication date as given by the source, `published_at` (parsed from it, else the collection time), `updated_at` (the source's last change: NVD `lastModified`, RSS/Atom `updated`, JSON `updated` field), `seen_at` |
| `users` | Telegram id, name, status (`pending`, `active`, `blocked`), `min_cvss`, muted vendors, approving admin, added_at |
| `state` | `last_run`, `last_status` |

Every item is stored whatever its score. An item is stored once: the same
advisory is never sent twice, across cycles and redeploys. Dates are parsed once,
when the item is stored (ISO 8601, RFC 2822); rows stored before `published_at`
existed are backfilled at start-up.

## 5. Alerts

### 5.1 Who gets what

Each new item goes to every active user, unless:
- its vendor is in the user's `/mute` list, or
- it has a CVSS score below the user's `/severity` threshold.

KEV items and items without a CVSS score (typically vendor advisories) are always
sent to users who have not muted the vendor. A user who blocked the bot is logged
and skipped. The bot pauses about 1 s between alerts (Telegram rate limit).

### 5.2 Format

```
🔴 CRITICAL · CVSS 9.8
Vendor: Cisco
Title: IOS XR SSH remote code execution
CVE: CVE-2026-XXXXX
Published: 22-10-2026 11:14 CEST
https://…
```

| Badge | Rule |
|---|---|
| 🔴 CRITICAL · ⚠️ KEV | in CISA KEV, whatever the score |
| 🔴 CRITICAL | CVSS ≥ 9.0 |
| 🟠 HIGH | 7.0 – 8.9 |
| 🟡 MEDIUM | 4.0 – 6.9 |
| ⚪ LOW | < 4.0 |
| 🔵 ADVISORY | no CVSS score |

An item published more than a day before the previous cycle is an old advisory
that its source has just changed (typically an NVD re-analysis of an old CVE),
not a new one. It is sent, with the same filters, as one line plus its link:

```
🔄 Update · 🟠 HIGH · CVSS 7.5 · Cisco · CVE-2019-1234 · <title> · published 12-03-2019 11:00 CET · last updated 27-10-2026 09:12 CET
https://…
```

"Last updated" is the source's update date, else the collection time.

Dates are shown as `dd-mm-yyyy HH:MM` in Paris time, labelled CET or CEST
(summer time). A source date without a time (CISA KEV) is shown as `dd-mm-yyyy`
only; a date that cannot be parsed is shown as the source gave it.

Long titles are shortened without an LLM: a title that fits is kept as is,
else its first sentence is used, cut at the last whole word with "…" if it is
still too long (200 characters for NVD titles, 120 in compact lists).

## 6. Users and access

The bot only works in private chats; it ignores groups.

- A new user sends `/start`: they are stored as *pending* and every admin gets
  "Access request from <name> (id <id>)" with Approve and Reject buttons. A
  second `/start` while pending does not notify the admins again.
- Approve makes the user *active* and tells them, with the command list. Reject
  makes them *blocked*. A request can be decided only once.
- Admins are the Telegram ids in `ADMIN_USER_IDS`. They are active without
  approval as soon as they send `/start`, and only they can use the admin
  commands and buttons.
- Every command except `/start` and `/help` needs an active user; others are
  told they have no access yet and to send `/start`. A blocked user's `/start`
  gets no answer and sends no new request to the admins.
- Admins can also add a user by id (`/adduser`, even before that person wrote to
  the bot) and remove one (`/removeuser`).

Telegram does not let a bot message someone who has never written to it, so an
admin only receives access requests after sending `/start` once.

## 7. Commands

The bot sets its Telegram command menu itself at every start: users see the user
commands, and each admin's chat also lists the admin ones.

### 7.1 Users

| Command | Behaviour |
|---|---|
| `/start`, `/help` | Access request (section 6), or the command list for active users; admins also see the admin commands. |
| `/status`, `/health` | "<dd-mm-yyyy HH:MM CET> · N new · failed: …" for the last cycle (Paris time, section 5.2). |
| `/latest [vendor] [n]` | Last *n* stored items (default 5, max 20), newest first by publication date, optionally for vendors matching *vendor*. Any severity; personal settings do not apply. |
| `/latest all [days]` | Every item with CVSS ≥ 7 or in KEV, from all vendors, **published** in the last *days* (default 7, max 90), by `published_at`: an old advisory collected recently because its source changed it is left out. KEV first, then by score; unscored vendor advisories in a separate section. One compact list (titles shortened, section 5.2), split under Telegram's limit, capped at 40 (+20 unscored). Mutes do not apply. |
| `/vendors` | Each vendor, enabled or paused, with its number of own sources (+ KEV/NVD). |
| `/ask <question>` | Plain-language answer about the stored alerts (section 7.3). One question every 10 s per user, 500 characters max. |
| `/severity <critical\|high\|medium\|low>` | Sets the user's threshold to 9.0, 7.0, 4.0 or 0. Without an argument, shows the current one. New users start at `MIN_CVSS`. |
| `/mute <vendor>`, `/unmute <vendor>` | Adds or removes a known vendor (case-insensitive) from the user's mute list. Without an argument, lists muted vendors. |

### 7.2 Admins

| Command | Behaviour |
|---|---|
| `/checknow` | Runs a cycle now and replies with its status. |
| `/addvendor <name>` | Section 7.4. |
| `/removevendor <name>` | Disables the vendor and its sources; stored items are kept. Re-adding it with `/addvendor` enables it again. |
| `/users` | Every user with status, name and id. |
| `/adduser <id>`, `/removeuser <id>` | Makes a user active (and tells them) or blocked. |

### 7.3 `/ask`

Claude (`LLM_MODEL`) answers from three tools the bot defines; it never writes
SQL and never sees the database directly:

| Tool | Query |
|---|---|
| `search_alerts` | vendor, last N hours, minimum CVSS (KEV always included), KEV only, CVE, word in the title; at most 25 results, most critical first |
| `alert_stats` | count by vendor or by severity, optionally over the last N hours |
| `list_vendors` | vendors and whether each is enabled |

Queries are parameterised and run on the read-only connection (`DATABASE_URL_RO`,
role `ask_ro` with `SELECT` on `items` and `vendors` only). When that URL names a
different account than `DATABASE_URL`, the bot creates the role, or resets its
password, at every start, so it always matches the variable. At most 5 tool rounds;
the answer is plain text cut at 4,000 characters. "Past N days" uses the
collection time (`seen_at`), not the publication date. Alert titles are
untrusted: the system prompt tells the model to ignore instructions in them.

### 7.4 `/addvendor`

1. Claude (`ONBOARD_MODEL`, with web search, at most 5 searches) looks for the
   official advisory sources of the vendor, product or technology: RSS first,
   then a JSON API (including a project's GitHub security advisories), then an
   HTML page. It returns the official name, a KEV keyword, an optional NVD CPE,
   and up to 3 sources.
2. Everything returned is validated: allowed source types only, lengths capped,
   names cleaned, and a CPE kept only if it is well formed.
3. The bot tests each source with the production collector and shows ✅ or ❌
   with three sample titles, plus how many CVEs the proposed NVD match found in
   the last 30 days.
4. An admin taps Approve: the vendor and its working sources are stored, with the
   admin's id, and its current KEV entries and source items are stored silently
   so the next cycle does not flood users. Cancel discards the proposal.
   Proposals are kept in memory, so a redeploy expires them.

## 8. Not implemented yet

From the original design ([specs.pdf](specs.pdf)):

| Item | Original design | Today |
|---|---|---|
| Updated advisories (F4) | Re-send as "Updated" when the update date or CVSS changes | An advisory is sent once; later changes to a stored advisory are not tracked. An old advisory first collected because its source changed it gets a one-line update (section 5.2) |
| EPSS (F5) | Add the exploitation probability to each CVE | Not collected |
| Watch-list (F6) | `/watch`, `/unwatch`, "IN OUR NETWORK" tag | Not built; `/mute` is the only per-vendor filter |
| Daily digest (F7) | Medium and Low grouped in an 08:00 digest, `/digest` | No digest; `/severity` decides what is sent immediately, and `/latest all` gives a summary on demand |
| Source health (F10) | Warn after 3 failed cycles in a row | Admins are told after every failing cycle |
| Alert format (1.4) | Advisory id, affected products, vendor rating (Cisco SIR, Juniper severity) | Not extracted |
| Regional sources | CERT-FR, CISA advisories, ENISA EUVD | Not collected |
| Cisco openVuln API | OAuth2 JSON source with SIR | Cisco is collected through its public RSS feed |
| Retention | 12 months of items, 90 days of logs | Manual: see the run book in the README |

## 9. Non-functional

- **Hosting**: one Railway service and one Railway Postgres per environment.
  `development` deploys the `dev` branch; `production` is meant to deploy `main`.
- **Reliability**: sources fail independently; dead database connections are
  replaced before use; a failed command answers "Something went wrong; try again
  in a moment."
- **Security**: secrets only in Railway variables; public `https` only for every
  outgoing request; `/ask` on a read-only role; human approval before any vendor
  or source is stored; request URLs, which contain the bot token, are not logged.
- **Rate limits**: about 1 alert per second; NVD throttled to its limit (with or
  without an API key).
- **Quality**: every change comes with tests (`pytest -q`, no network or database
  needed), formatted and linted with ruff; CI runs on every pull request.
