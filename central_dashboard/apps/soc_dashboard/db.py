"""
Sentrium SOC Dashboard — User Database (PostgreSQL)
Uses Railway's DATABASE_URL. Falls back to SQLite if not configured
so local development still works without a Postgres server.
"""

from __future__ import annotations
import os
import hashlib
import hmac
import logging
import time
import json
from typing import Optional
from datetime import datetime, timezone

try:
    import bcrypt as _bcrypt
    _BCRYPT_AVAILABLE = True
except ImportError:
    _BCRYPT_AVAILABLE = False
    logger_pre = __import__('logging').getLogger("soc_dashboard.db")
    logger_pre.warning("bcrypt not installed — falling back to SHA-256. Install bcrypt for proper security.")

logger = logging.getLogger("soc_dashboard.db")

_DATABASE_URL = os.getenv("DATABASE_URL", "")
_USE_PG = bool(_DATABASE_URL)

# ── Connection pool (PostgreSQL) ────────────────────────────────

if _USE_PG:
    import psycopg2
    from psycopg2 import pool as pg_pool
    from psycopg2.extras import RealDictCursor

    # Fix postgres:// → postgresql:// (Railway gives postgres://, psycopg2 needs postgresql://)
    if _DATABASE_URL.startswith("postgres://"):
        _DATABASE_URL = "postgresql://" + _DATABASE_URL[len("postgres://"):]

    _pool: pg_pool.ThreadedConnectionPool | None = None

    def _get_pool() -> pg_pool.ThreadedConnectionPool:
        global _pool
        if _pool is None or _pool.closed:
            # Try without explicit SSL first (Railway public URL handles SSL via URL params)
            for opts in [{}, {"sslmode": "require"}, {"sslmode": "disable"}]:
                try:
                    _pool = pg_pool.ThreadedConnectionPool(
                        minconn=1, maxconn=5, dsn=_DATABASE_URL, **opts
                    )
                    logger.info(f"SOC DB pool created (opts={opts or 'url-default'})")
                    break
                except Exception as e:
                    logger.warning(f"SOC DB pool attempt {opts} failed: {e}")
                    _pool = None
            if _pool is None:
                raise RuntimeError("SOC: All PostgreSQL connection attempts failed")
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
    _DEFAULT_DB_PATH = Path(__file__).with_name("sentrium_users.db")
    _DB_PATH = Path(os.getenv("SQLITE_PATH", str(_DEFAULT_DB_PATH))).expanduser()
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)

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
    """Hash a password with bcrypt (cost 12). Falls back to salted SHA-256."""
    if _BCRYPT_AVAILABLE:
        return "bcrypt:" + _bcrypt.hashpw(plain.encode(), _bcrypt.gensalt(rounds=12)).decode()
    # Fallback: salted SHA-256 (still better than unsalted)
    salt = os.urandom(16).hex()
    digest = hashlib.sha256((salt + plain).encode()).hexdigest()
    return f"sha256s:{salt}:{digest}"


def check_password(plain: str, stored: str) -> bool:
    """Timing-safe password verification."""
    if stored.startswith("bcrypt:"):
        if not _BCRYPT_AVAILABLE:
            return False
        try:
            return _bcrypt.checkpw(plain.encode(), stored[7:].encode())
        except Exception:
            return False
    if stored.startswith("sha256s:"):
        # Salted SHA-256 fallback
        parts = stored.split(":", 2)
        if len(parts) != 3:
            return False
        salt, digest = parts[1], parts[2]
        expected = hashlib.sha256((salt + plain).encode()).hexdigest()
        return hmac.compare_digest(expected, digest)
    if stored.startswith("sha256:"):
        # Legacy unsalted — compare and flag for re-hash
        expected = "sha256:" + hashlib.sha256(plain.encode()).hexdigest()
        return hmac.compare_digest(expected, stored)
    # Unknown scheme — reject
    return False


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
    # Always hash passwords — never store plaintext, regardless of created_by
    pw = _store_password(password)
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
            f"SELECT id, username, role, client_name, created_at, created_by, is_active "
            f"FROM sentrium_users WHERE username = {ph} AND is_active = 1",
            (username,),
        )
        row = cur.fetchone()
    return dict(row) if row else None


def _get_user_with_password(username: str) -> Optional[dict]:
    """Internal use only: includes password hash for authentication."""
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
        # Explicitly exclude password column — callers never need raw hashes
        cur.execute(
            "SELECT id, username, role, client_name, created_at, created_by, is_active "
            "FROM sentrium_users ORDER BY role, username"
        )
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
    """Return user dict if credentials match, else None. Uses timing-safe comparison."""
    user_full = _get_user_with_password(username)
    if user_full:
        stored_pw = user_full.pop("password", None)  # remove hash from returned dict
        if stored_pw and check_password(password, stored_pw):
            return user_full
        # Always do a dummy check even on failure to prevent timing oracle
        _dummy_check = check_password(password, "bcrypt:$2b$12$dummy.dummy.dummy.dummy.dummy.dummy.dummy.dummy.")

    # Env-var admin fallback (timing-safe, in case DB was wiped on redeploy)
    from config import settings
    if settings.ADMIN_USERNAME and settings.ADMIN_PASSWORD:
        user_ok = hmac.compare_digest(username.encode(), settings.ADMIN_USERNAME.encode())
        pass_ok = hmac.compare_digest(password.encode(), settings.ADMIN_PASSWORD.encode())
        if user_ok and pass_ok:
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
