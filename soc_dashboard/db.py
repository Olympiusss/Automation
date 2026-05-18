"""
Sentrium SOC Dashboard — User Database (PostgreSQL)
Uses Railway's DATABASE_URL. Falls back to SQLite if not configured
so local development still works without a Postgres server.
"""

from __future__ import annotations
import os
import hashlib
import logging
import time
import json
from typing import Optional
from datetime import datetime, timezone

logger = logging.getLogger("soc_dashboard.db")

_DATABASE_URL = os.getenv("DATABASE_URL", "")
_USE_PG = bool(_DATABASE_URL)

# ── Connection pool (PostgreSQL) ────────────────────────────────

if _USE_PG:
    import psycopg2
    from psycopg2 import pool as pg_pool
    from psycopg2.extras import RealDictCursor

    _pool: pg_pool.ThreadedConnectionPool | None = None

    def _get_pool() -> pg_pool.ThreadedConnectionPool:
        global _pool
        if _pool is None or _pool.closed:
            _pool = pg_pool.ThreadedConnectionPool(
                minconn=1, maxconn=5, dsn=_DATABASE_URL, sslmode="require"
            )
        return _pool

    class _PgConn:
        """Context manager: borrow a connection from the pool."""
        def __enter__(self):
            self.conn = _get_pool().getconn()
            self.conn.autocommit = False
            return self.conn

        def __exit__(self, exc_type, *_):
            if exc_type:
                self.conn.rollback()
            else:
                self.conn.commit()
            _get_pool().putconn(self.conn)

    def _cursor(conn):
        return conn.cursor(cursor_factory=RealDictCursor)

else:
    # ── SQLite fallback (local dev) ─────────────────────────────
    import sqlite3
    from pathlib import Path
    _DB_PATH = Path(os.getenv("SQLITE_PATH", "/tmp/sentrium_users.db"))

    class _PgConn:  # type: ignore[no-redef]
        def __enter__(self):
            self.conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA journal_mode=WAL")
            return self.conn

        def __exit__(self, exc_type, *_):
            if exc_type:
                self.conn.rollback()
            else:
                self.conn.commit()
            self.conn.close()

    def _cursor(conn):
        return conn.cursor()


# ── Schema ──────────────────────────────────────────────────────

_PG_DDL = """
    CREATE TABLE IF NOT EXISTS sentrium_users (
        id          SERIAL PRIMARY KEY,
        username    TEXT    UNIQUE NOT NULL,
        password    TEXT    NOT NULL,
        role        TEXT    NOT NULL
            CHECK(role IN ('admin','client','analyst','thirdparty')),
        client_name TEXT,
        created_at  DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW()),
        created_by  TEXT    DEFAULT 'system',
        is_active   INTEGER DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS sentrium_access_log (
        id          SERIAL PRIMARY KEY,
        username    TEXT    NOT NULL,
        role        TEXT,
        client_name TEXT,
        action      TEXT    DEFAULT 'login',
        ip_address  TEXT,
        timestamp   DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW())
    );
"""

_SQLITE_DDL = """
    CREATE TABLE IF NOT EXISTS sentrium_users (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        username    TEXT    UNIQUE NOT NULL,
        password    TEXT    NOT NULL,
        role        TEXT    NOT NULL
            CHECK(role IN ('admin','client','analyst','thirdparty')),
        client_name TEXT,
        created_at  REAL    DEFAULT (unixepoch()),
        created_by  TEXT    DEFAULT 'system',
        is_active   INTEGER DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS sentrium_access_log (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        username    TEXT    NOT NULL,
        role        TEXT,
        client_name TEXT,
        action      TEXT    DEFAULT 'login',
        ip_address  TEXT,
        timestamp   REAL    DEFAULT (unixepoch())
    );
"""


def init_db() -> None:
    """Create tables and seed from env vars if tables are empty."""
    ddl = _PG_DDL if _USE_PG else _SQLITE_DDL
    with _PgConn() as conn:
        cur = _cursor(conn)
        # PostgreSQL requires separate statement execution
        for stmt in ddl.strip().split(";"):
            s = stmt.strip()
            if s:
                cur.execute(s)
    _seed_from_env()
    logger.info(f"DB initialised ({'PostgreSQL' if _USE_PG else 'SQLite'})")


def _seed_from_env() -> None:
    """Populate from Railway env vars only if the table is empty."""
    from config import settings

    if get_all_users():
        return  # already has users

    logger.info("Seeding users from environment variables…")
    if settings.ADMIN_USERNAME and settings.ADMIN_PASSWORD:
        upsert_user(settings.ADMIN_USERNAME, settings.ADMIN_PASSWORD,
                    "admin", None, "env")

    name_map = settings.CLIENT_NAME_MAP
    for uname, pwd in settings.CLIENT_CREDENTIALS.items():
        upsert_user(uname, pwd, "client",
                    name_map.get(uname, uname), "env")

    for uname, pwd in settings.ANALYST_CREDENTIALS.items():
        upsert_user(uname, pwd, "analyst", None, "env")

    logger.info(f"Seeded {len(get_all_users())} users")


# ── Password helpers ─────────────────────────────────────────────

def _store_password(plain: str) -> str:
    return "sha256:" + hashlib.sha256(plain.encode()).hexdigest()


def check_password(plain: str, stored: str) -> bool:
    if stored.startswith("sha256:"):
        return "sha256:" + hashlib.sha256(plain.encode()).hexdigest() == stored
    return plain == stored   # legacy plain (env-seeded)


# ── Placeholder helper ────────────────────────────────────────────

def _ph(n: int = 1) -> str:
    """Return %s for PG, ? for SQLite."""
    return "%s" if _USE_PG else "?"


def _phs(count: int) -> str:
    ph = _ph()
    return ", ".join([ph] * count)


# ── CRUD ─────────────────────────────────────────────────────────

def upsert_user(
    username: str,
    password: str,
    role: str,
    client_name: Optional[str] = None,
    created_by: str = "admin",
) -> None:
    pw = password if created_by == "env" else _store_password(password)
    ph = _ph()
    now = time.time()

    if _USE_PG:
        sql = f"""
            INSERT INTO sentrium_users
                (username, password, role, client_name, created_at, created_by)
            VALUES ({ph},{ph},{ph},{ph},{ph},{ph})
            ON CONFLICT (username) DO UPDATE SET
                password    = EXCLUDED.password,
                role        = EXCLUDED.role,
                client_name = EXCLUDED.client_name
        """
    else:
        sql = f"""
            INSERT INTO sentrium_users
                (username, password, role, client_name, created_at, created_by)
            VALUES ({ph},{ph},{ph},{ph},{ph},{ph})
            ON CONFLICT(username) DO UPDATE SET
                password    = excluded.password,
                role        = excluded.role,
                client_name = excluded.client_name
        """
    with _PgConn() as conn:
        _cursor(conn).execute(sql, (username, pw, role, client_name, now, created_by))


def delete_user(username: str) -> None:
    ph = _ph()
    with _PgConn() as conn:
        _cursor(conn).execute(
            f"DELETE FROM sentrium_users WHERE username = {ph}", (username,)
        )


def toggle_user(username: str, active: bool) -> None:
    ph = _ph()
    with _PgConn() as conn:
        _cursor(conn).execute(
            f"UPDATE sentrium_users SET is_active = {ph} WHERE username = {ph}",
            (1 if active else 0, username),
        )


def get_user(username: str) -> Optional[dict]:
    ph = _ph()
    with _PgConn() as conn:
        cur = _cursor(conn)
        cur.execute(
            f"SELECT * FROM sentrium_users WHERE username = {ph} AND is_active = 1",
            (username,),
        )
        row = cur.fetchone()
    return dict(row) if row else None


def get_all_users() -> list[dict]:
    with _PgConn() as conn:
        cur = _cursor(conn)
        cur.execute("SELECT * FROM sentrium_users ORDER BY role, username")
        return [dict(r) for r in cur.fetchall()]


def get_users_by_role(role: str) -> list[dict]:
    ph = _ph()
    with _PgConn() as conn:
        cur = _cursor(conn)
        cur.execute(
            f"SELECT * FROM sentrium_users WHERE role = {ph} AND is_active = 1 ORDER BY username",
            (role,),
        )
        return [dict(r) for r in cur.fetchall()]


# ── Auth helper ───────────────────────────────────────────────────

def verify_login(username: str, password: str) -> Optional[dict]:
    """Return user dict if credentials match, else None."""
    user = get_user(username)
    if user and check_password(password, user["password"]):
        return user

    # Env-var admin fallback (in case DB was wiped on redeploy)
    from config import settings
    if (username == settings.ADMIN_USERNAME and
            settings.ADMIN_PASSWORD and
            password == settings.ADMIN_PASSWORD):
        return {"username": username, "role": "admin", "client_name": None}

    return None


# ── Access Logging ────────────────────────────────────────────────

def log_access(
    username: str,
    role: str,
    client_name: Optional[str] = None,
    action: str = "login",
    ip_address: Optional[str] = None,
) -> None:
    ph = _ph()
    now = time.time()
    try:
        with _PgConn() as conn:
            _cursor(conn).execute(
                f"""INSERT INTO sentrium_access_log
                    (username, role, client_name, action, ip_address, timestamp)
                    VALUES ({ph},{ph},{ph},{ph},{ph},{ph})""",
                (username, role, client_name, action, ip_address, now),
            )
    except Exception as e:
        logger.error(f"access_log write failed: {e}")


def get_access_log(limit: int = 200) -> list[dict]:
    ph = _ph()
    with _PgConn() as conn:
        cur = _cursor(conn)
        cur.execute(
            f"SELECT * FROM sentrium_access_log ORDER BY timestamp DESC LIMIT {ph}",
            (limit,),
        )
        return [dict(r) for r in cur.fetchall()]


def get_last_access(username: str) -> Optional[float]:
    ph = _ph()
    with _PgConn() as conn:
        cur = _cursor(conn)
        cur.execute(
            f"""SELECT MAX(timestamp) AS last_ts FROM sentrium_access_log
                WHERE username = {ph} AND action = 'login'""",
            (username,),
        )
        row = cur.fetchone()
    if not row:
        return None
    val = row["last_ts"] if isinstance(row, dict) else row[0]
    return float(val) if val is not None else None


def get_client_login_counts() -> dict[str, int]:
    with _PgConn() as conn:
        cur = _cursor(conn)
        cur.execute(
            """SELECT client_name, COUNT(*) AS cnt
               FROM sentrium_access_log
               WHERE action = 'login' AND client_name IS NOT NULL
               GROUP BY client_name"""
        )
        return {r["client_name"] if isinstance(r, dict) else r[0]:
                r["cnt"] if isinstance(r, dict) else r[1]
                for r in cur.fetchall()}
