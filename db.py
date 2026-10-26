import os

import yaml
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

KW = {"autocommit": True, "row_factory": dict_row}
# Pools open lazily in init(), so tests can import this module without a database.
# check= tests each connection before handing it out, so connections killed by a
# database restart are replaced instead of failing the next command.
CHECK = ConnectionPool.check_connection
pool = ConnectionPool(
    os.environ.get("DATABASE_URL", ""), kwargs=KW, open=False, check=CHECK
)
ro_pool = ConnectionPool(
    os.environ.get("DATABASE_URL_RO", ""),
    kwargs=KW,
    open=False,
    min_size=1,
    max_size=2,
    check=CHECK,
)


def q(sql, params=(), one=False):
    """Run one parameterised statement; return rows (dicts), one row, or None."""
    with pool.connection() as conn:
        cur = conn.execute(sql, params)
        if cur.description is None:
            return None
        return cur.fetchone() if one else cur.fetchall()


def q_ro(sql, params=()):
    """Read-only queries for the /ask assistant (role with SELECT rights only)."""
    with ro_pool.connection() as conn:
        return conn.execute(sql, params).fetchall()


def init():
    pool.open()
    ro_pool.open()
    with open("schema.sql") as f, pool.connection() as conn:
        conn.execute(f.read())
    if q("SELECT 1 FROM vendors LIMIT 1", one=True):
        return  # already seeded
    with open("seed.yaml") as f:
        seed = yaml.safe_load(f)
    for v in seed["vendors"]:
        q(
            "INSERT INTO vendors (name, nvd_keyword) VALUES (%s, %s) ON CONFLICT DO NOTHING",
            (v["name"], v.get("nvd_keyword", v["name"])),
        )
    for s in seed["sources"]:
        q(
            "INSERT INTO sources (vendor, type, url, config) VALUES (%s, %s, %s, %s)",
            (s["vendor"], s["type"], s["url"], Jsonb(s.get("config", {}))),
        )


def get_state(k):
    row = q("SELECT v FROM state WHERE k = %s", (k,), one=True)
    return row["v"] if row else None


def set_state(k, v):
    q(
        "INSERT INTO state VALUES (%s, %s) ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v",
        (k, v),
    )
