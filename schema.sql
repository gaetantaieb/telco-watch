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
