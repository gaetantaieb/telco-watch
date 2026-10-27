CREATE TABLE IF NOT EXISTS vendors (
    name        TEXT PRIMARY KEY,
    nvd_keyword TEXT NOT NULL,                      -- word used to find its CVEs in NVD
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    added_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sources (                -- vendor-specific feeds (KEV and NVD are global)
    id       SERIAL PRIMARY KEY,
    vendor   TEXT NOT NULL REFERENCES vendors(name) ON DELETE CASCADE,
    type     TEXT NOT NULL CHECK (type IN ('rss', 'json', 'html')),
    url      TEXT NOT NULL,
    config   JSONB NOT NULL DEFAULT '{}',           -- selectors / field names for html and json
    enabled  BOOLEAN NOT NULL DEFAULT TRUE,
    added_by BIGINT,                                -- Telegram id of the approving admin
    added_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS items (
    key       TEXT PRIMARY KEY,                     -- sha256(vendor | advisory id)
    vendor    TEXT NOT NULL,
    title     TEXT,
    url       TEXT,
    cves      TEXT[] NOT NULL DEFAULT '{}',
    cvss      REAL,
    kev       BOOLEAN NOT NULL DEFAULT FALSE,
    published TEXT,
    seen_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS items_seen_at ON items (seen_at DESC);
CREATE INDEX IF NOT EXISTS items_vendor ON items (vendor);

CREATE TABLE IF NOT EXISTS state (k TEXT PRIMARY KEY, v TEXT);

CREATE TABLE IF NOT EXISTS users (                   -- people using the bot in a private chat
    chat_id     BIGINT PRIMARY KEY,                  -- Telegram user id (= their private chat id)
    name        TEXT,
    status      TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'blocked')),
    min_cvss    REAL NOT NULL DEFAULT 7.0,           -- /severity: alerts at or above this score
    muted       TEXT[] NOT NULL DEFAULT '{}',        -- /mute: vendors this user gets no alerts for
    approved_by BIGINT,                              -- Telegram id of the admin who decided
    added_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A product or technology (e.g. PHP) is matched in NVD by its CPE instead of a keyword,
-- so CVEs that only mention it ("a PHP application...") are not collected.
ALTER TABLE vendors ADD COLUMN IF NOT EXISTS nvd_cpe TEXT;     -- e.g. cpe:2.3:a:php:php

-- Parsed dates: lists sort by publication, and an old advisory that a source has just
-- changed (NVD re-analysis) is told apart from a new one. Backfilled at start-up.
ALTER TABLE items ADD COLUMN IF NOT EXISTS published_at TIMESTAMPTZ; -- else seen_at
ALTER TABLE items ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ;   -- if the source gives it
CREATE INDEX IF NOT EXISTS items_published_at ON items (published_at DESC);

-- The vendor's own rating (critical, high, medium, low) when the advisory has no CVSS
-- score; it is placed in the severity matrix at the lowest score of its level.
ALTER TABLE items ADD COLUMN IF NOT EXISTS rating TEXT;

-- /promote: admins besides the permanent ones of ADMIN_USER_IDS.
ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user'
    CHECK (role IN ('user', 'admin'));
