"""
Sentrium Enterprise — PostgreSQL User Store
==========================================
Simple schema: email + bcrypt-hashed password + department + role.
All passwords are bcrypt-hashed before storage (min cost 12).
Handles both 'password' and 'password_hash' column names for compatibility.
"""
from __future__ import annotations
import os
import logging
import psycopg2
import psycopg2.pool
import psycopg2.extras
from contextlib import contextmanager

logger = logging.getLogger(__name__)

# Re-read DATABASE_URL on every function call so Railway env changes take effect
def _db_url() -> str:
    url = os.environ.get("DATABASE_URL", "")
    # Railway gives postgres:// but psycopg2 requires postgresql://
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    return url

_pool = None
_last_pool_error = "Not yet attempted"

# ── Connection Pool ──────────────────────────────────────────────────────────
def _get_pool():
    global _pool, _last_pool_error
    url = _db_url()
    if not url:
        _last_pool_error = "DATABASE_URL is empty"
        return None
    if _pool is not None:
        return _pool

    attempts = [
        {},
        {"sslmode": "require"},
        {"sslmode": "disable"},
    ]
    errors = []
    for opts in attempts:
        try:
            _pool = psycopg2.pool.SimpleConnectionPool(
                1, 5,
                url,
                cursor_factory=psycopg2.extras.RealDictCursor,
                **opts
            )
            logger.info(f"PostgreSQL pool created (opts={opts or 'url-default'})")
            _last_pool_error = None
            return _pool
        except Exception as e:
            msg = f"{opts or 'default'}: {type(e).__name__}: {e}"
            logger.warning(f"Pool attempt failed — {msg}")
            errors.append(msg)
            _pool = None

    _last_pool_error = " | ".join(errors)
    logger.error(f"All PostgreSQL connection attempts failed: {_last_pool_error}")
    return None


@contextmanager
def _conn():
    pool = _get_pool()
    if pool is None:
        raise RuntimeError("PostgreSQL connection unavailable")
    conn = pool.getconn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)

def is_available() -> bool:
    return bool(_db_url())

# ── Detect which password column exists ──────────────────────────────────────
_pw_col_cache = None

def _password_column(conn) -> str:
    """Return 'password' or 'password_hash' depending on what the table has."""
    global _pw_col_cache
    if _pw_col_cache:
        return _pw_col_cache
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT column_name FROM information_schema.columns
                WHERE table_name = 'sentrium_users'
                  AND column_name IN ('password', 'password_hash')
                LIMIT 1
            """)
            row = cur.fetchone()
            _pw_col_cache = row["column_name"] if row else "password"
    except Exception:
        _pw_col_cache = "password"
    return _pw_col_cache

# ── Schema Init ──────────────────────────────────────────────────────────────
def init_db():
    """Create the users table if it doesn't exist. Safe to call on every start."""
    if not is_available():
        logger.warning("DATABASE_URL not set — skipping DB init, using JSON fallback")
        return
    try:
        with _conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS sentrium_users (
                        id          SERIAL PRIMARY KEY,
                        email       VARCHAR(255) UNIQUE NOT NULL,
                        password    VARCHAR(255) NOT NULL,
                        department  VARCHAR(100) NOT NULL DEFAULT 'All',
                        role        VARCHAR(50)  NOT NULL DEFAULT 'dept_user',
                        is_active   BOOLEAN      NOT NULL DEFAULT TRUE,
                        created_at  TIMESTAMPTZ  DEFAULT NOW()
                    );
                """)
        logger.info("sentrium_users table ready")
        _seed_admin_from_env()   # create first admin if table is empty
    except Exception as e:
        logger.error(f"DB init failed: {e}")


def _seed_admin_from_env():
    """
    If the sentrium_users table is empty, create the first admin account
    from environment variables so there is always a way to log in on first deploy.

    Reads (in priority order):
      1. CENTRAL_ADMIN_EMAIL  + CENTRAL_ADMIN_PASSWORD  (central-specific)
      2. ADMIN_USERNAME       + ADMIN_PASSWORD           (shared with SOC)

    Safe to call repeatedly — does nothing if users already exist.
    """
    # Check which env vars are available
    email    = (os.environ.get("CENTRAL_ADMIN_EMAIL", "").strip() or
                os.environ.get("ADMIN_USERNAME", "").strip())
    password = (os.environ.get("CENTRAL_ADMIN_PASSWORD", "").strip() or
                os.environ.get("ADMIN_PASSWORD", "").strip())

    if not email or not password:
        logger.info("No admin seed env vars set — skipping Central admin seed.")
        return

    # Only seed if the table is completely empty
    existing = list_users()
    if existing:
        logger.info(f"Central DB already has {len(existing)} user(s) — skipping seed.")
        return

    ok, err = add_user(email, password, department="All", role="admin")
    if ok:
        logger.info(f"Central admin seeded from env vars: {email}")
    else:
        logger.warning(f"Central admin seed failed: {err}")


# ── CRUD ─────────────────────────────────────────────────────────────────────
def get_user(email: str) -> dict | None:
    """Fetch one user by email (case-insensitive). Works with both column names."""
    try:
        with _conn() as conn:
            pw_col = _password_column(conn)
            with conn.cursor() as cur:
                cur.execute(
                    f"""SELECT email, {pw_col} as password, department, role, is_active
                        FROM sentrium_users
                        WHERE LOWER(email) = LOWER(%s)""",
                    (email.strip(),)
                )
                row = cur.fetchone()
                if not row:
                    return None
                return {
                    "username":   row["email"],
                    "password":   row["password"],
                    "department": row["department"],
                    "role":       row["role"],
                    "is_active":  row["is_active"],
                }
    except Exception as e:
        logger.error(f"get_user failed: {e}")
        return None

def list_users() -> list[dict]:
    """List all users — passwords never returned."""
    try:
        with _conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT email, department, role, is_active,
                           to_char(created_at, 'YYYY-MM-DD') AS created_at
                    FROM sentrium_users ORDER BY email
                """)
                rows = cur.fetchall()
                logger.info(f"list_users: found {len(rows)} row(s)")
                return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"list_users failed: {e}")
        return []

def _hash_password(plaintext: str) -> str:
    """Return a bcrypt hash of the given plaintext password."""
    import bcrypt
    return bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt(rounds=12)).decode()

def add_user(email: str, password: str,
             department: str = "All", role: str = "dept_user") -> tuple[bool, str]:
    """Insert a new user. Password is bcrypt-hashed before storage."""
    try:
        hashed = _hash_password(password)
        with _conn() as conn:
            pw_col = _password_column(conn)
            with conn.cursor() as cur:
                cur.execute(
                    f"""INSERT INTO sentrium_users (email, {pw_col}, department, role)
                        VALUES (LOWER(%s), %s, %s, %s)""",
                    (email.strip(), hashed, department, role)
                )
        return True, ""
    except psycopg2.errors.UniqueViolation:
        return False, f"{email} already exists"
    except Exception as e:
        return False, str(e)

def update_user(email: str, department: str = None,
                role: str = None, is_active: bool = None) -> bool:
    fields, values = [], []
    if department is not None:
        fields.append("department = %s"); values.append(department)
    if role is not None:
        fields.append("role = %s"); values.append(role)
    if is_active is not None:
        fields.append("is_active = %s"); values.append(is_active)
    if not fields:
        return False
    values.append(email.strip())
    try:
        with _conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"UPDATE sentrium_users SET {', '.join(fields)} WHERE LOWER(email) = LOWER(%s)",
                    values
                )
                return cur.rowcount > 0
    except Exception as e:
        logger.error(f"update_user failed: {e}"); return False

def update_password(email: str, new_password: str) -> bool:
    """Update a user's password. New password is bcrypt-hashed before storage."""
    try:
        hashed = _hash_password(new_password)
        with _conn() as conn:
            pw_col = _password_column(conn)
            with conn.cursor() as cur:
                cur.execute(
                    f"UPDATE sentrium_users SET {pw_col} = %s WHERE LOWER(email) = LOWER(%s)",
                    (hashed, email.strip())
                )
                return cur.rowcount > 0
    except Exception as e:
        logger.error(f"update_password failed: {e}"); return False

def delete_user(email: str) -> bool:
    try:
        with _conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM sentrium_users WHERE LOWER(email) = LOWER(%s)",
                    (email.strip(),)
                )
                return cur.rowcount > 0
    except Exception as e:
        logger.error(f"delete_user failed: {e}"); return False
