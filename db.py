import os

import yaml
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict
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


def ensure_ro_role():
    """Create the read-only role named in DATABASE_URL_RO, or reset its password.

    It can only read the tables /ask uses. Nothing to do when both URLs use the same
    account (fine in development). Role names and passwords cannot be bound with %s
    in these statements, so they are quoted with psycopg.sql instead.
    """
    rw, ro = conninfo_to_dict(pool.conninfo), conninfo_to_dict(ro_pool.conninfo)
    user, password = ro.get("user"), ro.get("password")
    if not user or not password or user == rw.get("user"):
        return
    exists = q("SELECT 1 FROM pg_roles WHERE rolname = %s", (user,), one=True)
    role = sql.Identifier(user)
    with pool.connection() as conn:
        conn.execute(
            sql.SQL(
                "ALTER ROLE {} LOGIN PASSWORD {}"
                if exists
                else "CREATE ROLE {} LOGIN PASSWORD {}"
            ).format(role, sql.Literal(password))
        )
        conn.execute(
            sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                sql.Identifier(ro.get("dbname") or rw["dbname"]), role
            )
        )
        conn.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(role))
        conn.execute(sql.SQL("GRANT SELECT ON items, vendors TO {}").format(role))


def init():
    pool.open()
    with open("schema.sql") as f, pool.connection() as conn:
        conn.execute(f.read())
    ensure_ro_role()
    ro_pool.open()  # after the role exists, so its first connections succeed
    return load_seed()


def load_seed():
    """Add the seed.yaml vendors missing by name, with their sources; return their names.

    Runs at every start, so vendors added to the file reach an existing database. A vendor
    removed with /removevendor keeps its disabled row, so it is not brought back.
    """
    with open("seed.yaml") as f:
        seed = yaml.safe_load(f)
    # "Microsoft" first stood for Metaswitch only; it now covers all Microsoft products
    # (Metaswitch has its own entry). added_at = now(): its KEV backlog is stored silently.
    q(
        "UPDATE vendors SET nvd_keyword = %s, nvd_cpe = %s, added_at = now() "
        "WHERE name = %s AND nvd_keyword = %s",
        ("Microsoft", "cpe:2.3:*:microsoft", "Microsoft", "Metaswitch"),
    )
    added = []
    for v in seed["vendors"]:
        row = q(
            "INSERT INTO vendors (name, nvd_keyword, nvd_cpe) VALUES (%s, %s, %s) "
            "ON CONFLICT DO NOTHING RETURNING name",
            (v["name"], v.get("nvd_keyword", v["name"]), v.get("nvd_cpe")),
            one=True,
        )
        if row:
            added.append(row["name"])
    for s in seed["sources"]:
        if s["vendor"] in added:
            q(
                "INSERT INTO sources (vendor, type, url, config) VALUES (%s, %s, %s, %s)",
                (s["vendor"], s["type"], s["url"], Jsonb(s.get("config", {}))),
            )
    return added


def get_state(k):
    row = q("SELECT v FROM state WHERE k = %s", (k,), one=True)
    return row["v"] if row else None


def set_state(k, v):
    q(
        "INSERT INTO state VALUES (%s, %s) ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v",
        (k, v),
    )
