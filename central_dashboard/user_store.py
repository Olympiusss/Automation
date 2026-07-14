"""
Sentrium Enterprise — Server-Side User Store
=============================================
Priority lookup:
  1. Railway PostgreSQL (DATABASE_URL set)  ← primary
  2. SENTRIUM_USERS_JSON env var            ← local dev fallback

Sessions are stored in PostgreSQL so they survive Railway redeploys.
Falls back to in-memory dict when DATABASE_URL is not set (local dev).
"""
from __future__ import annotations
import os
import json
import logging
import secrets
import time

logger = logging.getLogger(__name__)

SESSION_TTL_SECONDS = 8 * 60 * 60  # 8 hours

# ── In-memory fallback (local dev only) ──────────────────────────────────────
_sessions: dict[str, dict] = {}


# ─────────────────────────────────────────────────────────────────────────────
#  PostgreSQL session helpers
# ─────────────────────────────────────────────────────────────────────────────

def _db_available() -> bool:
    return bool(os.environ.get("DATABASE_URL", ""))


def _ensure_sessions_table():
    """Create sentrium_sessions table if it doesn't exist."""
    try:
        import db_users
        with db_users._conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS sentrium_sessions (
                        token       VARCHAR(128) PRIMARY KEY,
                        username    VARCHAR(255) NOT NULL,
                        department  VARCHAR(100) NOT NULL DEFAULT 'All',
                        role        VARCHAR(50)  NOT NULL DEFAULT 'dept_user',
                        expires_at  BIGINT       NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_sessions_expires
                        ON sentrium_sessions (expires_at);
                """)
        logger.info("sentrium_sessions table ready")
    except Exception as e:
        logger.warning(f"Could not create sessions table (using in-memory fallback): {e}")


def _db_create_session(token: str, user: dict, expires_at: float):
    try:
        import db_users
        with db_users._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO sentrium_sessions
                       (token, username, department, role, expires_at)
                       VALUES (%s, %s, %s, %s, %s)
                       ON CONFLICT (token) DO UPDATE
                       SET expires_at = EXCLUDED.expires_at""",
                    (token,
                     user.get("username", ""),
                     user.get("department", "All"),
                     user.get("role", "dept_user"),
                     int(expires_at))
                )
    except Exception as e:
        logger.error(f"DB create_session failed: {e}")


def _db_get_session(token: str) -> dict | None:
    try:
        import db_users
        with db_users._conn() as conn:
            with conn.cursor() as cur:
                now = int(time.time())
                cur.execute(
                    """SELECT username, department, role, expires_at
                       FROM sentrium_sessions
                       WHERE token = %s AND expires_at > %s""",
                    (token, now)
                )
                row = cur.fetchone()
                if not row:
                    return None
                # Slide expiry window
                new_exp = int(time.time()) + SESSION_TTL_SECONDS
                cur.execute(
                    "UPDATE sentrium_sessions SET expires_at = %s WHERE token = %s",
                    (new_exp, token)
                )
                return {
                    "username":   row["username"],
                    "department": row["department"],
                    "role":       row["role"],
                    "expires_at": new_exp,
                }
    except Exception as e:
        logger.error(f"DB get_session failed: {e}")
        return None


def _db_destroy_session(token: str):
    try:
        import db_users
        with db_users._conn() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM sentrium_sessions WHERE token = %s", (token,))
    except Exception as e:
        logger.error(f"DB destroy_session failed: {e}")


def _db_destroy_sessions_for_user(username: str) -> int:
    try:
        import db_users
        with db_users._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM sentrium_sessions WHERE LOWER(username) = LOWER(%s)",
                    (username.strip(),)
                )
                return cur.rowcount
    except Exception as e:
        logger.error(f"DB destroy_sessions_for_user failed: {e}")
        return 0


def _db_purge_expired():
    try:
        import db_users
        with db_users._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM sentrium_sessions WHERE expires_at < %s",
                    (int(time.time()),)
                )
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
#  JSON fallback (local dev, no DATABASE_URL)
# ─────────────────────────────────────────────────────────────────────────────

def _json_fallback_user(username: str) -> dict | None:
    raw = os.environ.get("SENTRIUM_USERS_JSON", "[]")
    try:
        users = json.loads(raw)
        uname_lower = username.strip().lower()
        return next(
            (u for u in users if u.get("username", "").lower() == uname_lower),
            None
        )
    except Exception:
        return None


# ── Primary lookup ────────────────────────────────────────────────────────────
def _get_user(username: str) -> dict | None:
    try:
        import db_users
        if db_users.is_available():
            return db_users.get_user(username)
    except Exception as e:
        logger.warning(f"DB lookup failed, falling back to JSON: {e}")
    return _json_fallback_user(username)


# ── Password verification ─────────────────────────────────────────────────────
def verify_password(username: str, plaintext: str) -> dict | None:
    """
    Verify a login attempt.
    - PostgreSQL: bcrypt comparison against stored hash.
    - JSON fallback: supports bcrypt hashes (from setup_credentials.py).
    """
    user = _get_user(username)
    if not user:
        return None

    if not user.get("is_active", True):
        return None

    stored = user.get("password") or user.get("hash") or ""

    # bcrypt hash (PostgreSQL primary path after migration, or JSON fallback)
    if stored.startswith("$2b$") or stored.startswith("$2a$"):
        try:
            import bcrypt
            if bcrypt.checkpw(plaintext.encode(), stored.encode()):
                return user
        except Exception:
            pass
        return None

    # Plain password comparison (legacy / pre-migration)
    if stored and stored == plaintext:
        return user

    return None


# ── Session management ─────────────────────────────────────────────────────────

def _mem_purge_expired():
    now = time.time()
    expired = [t for t, s in _sessions.items() if s["expires_at"] < now]
    for t in expired:
        del _sessions[t]


def create_session(user: dict) -> str:
    token = secrets.token_urlsafe(48)
    expires_at = time.time() + SESSION_TTL_SECONDS
    if _db_available():
        _db_create_session(token, user, expires_at)
    else:
        _mem_purge_expired()
        _sessions[token] = {
            "username":   user.get("username", ""),
            "department": user.get("department", "All"),
            "role":       user.get("role", "dept_user"),
            "expires_at": expires_at,
        }
    return token


def get_session(token: str) -> dict | None:
    if not token:
        return None
    if _db_available():
        return _db_get_session(token)
    # In-memory fallback
    _mem_purge_expired()
    session = _sessions.get(token)
    if not session:
        return None
    if session["expires_at"] < time.time():
        del _sessions[token]
        return None
    session["expires_at"] = time.time() + SESSION_TTL_SECONDS
    return session


def destroy_session(token: str):
    if _db_available():
        _db_destroy_session(token)
    else:
        _sessions.pop(token, None)


def destroy_sessions_for_user(username: str) -> int:
    """Destroy ALL active sessions for a given username (e.g. on role change)."""
    if _db_available():
        return _db_destroy_sessions_for_user(username)
    # In-memory fallback
    uname_lower = username.strip().lower()
    to_delete = [
        t for t, s in _sessions.items()
        if s.get("username", "").lower() == uname_lower
    ]
    for t in to_delete:
        del _sessions[t]
    return len(to_delete)
