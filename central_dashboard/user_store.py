"""
Sentrium Enterprise — Server-Side User Store
=============================================
Priority lookup:
  1. Railway PostgreSQL (DATABASE_URL set)  ← primary
  2. SENTRIUM_USERS_JSON env var            ← local dev fallback

Users are verified by direct password comparison against the DB value.
"""
from __future__ import annotations
import os
import json
import logging
import secrets
import time

logger = logging.getLogger(__name__)

# ── In-memory session store ─────────────────────────────────────────────────
_sessions: dict[str, dict] = {}
SESSION_TTL_SECONDS = 8 * 60 * 60  # 8 hours

# ── JSON fallback (local dev, no DATABASE_URL) ────────────────────────────────
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
    - PostgreSQL: compares plaintext directly against the stored password.
    - JSON fallback: supports bcrypt hashes (from setup_credentials.py).
    """
    user = _get_user(username)
    if not user:
        return None

    if not user.get("is_active", True):
        return None

    stored = user.get("password") or user.get("hash") or ""

    # If stored value is a bcrypt hash (JSON fallback legacy), verify with bcrypt
    if stored.startswith("$2b$") or stored.startswith("$2a$"):
        try:
            import bcrypt
            if bcrypt.checkpw(plaintext.encode(), stored.encode()):
                return user
        except Exception:
            pass
        return None

    # Plain password comparison (Railway PostgreSQL path)
    if stored and stored == plaintext:
        return user

    return None

# ── Session management ──────────────────────────────────────────────────────
def _purge_expired():
    now = time.time()
    expired = [t for t, s in _sessions.items() if s["expires_at"] < now]
    for t in expired:
        del _sessions[t]

def create_session(user: dict) -> str:
    _purge_expired()
    token = secrets.token_urlsafe(48)
    _sessions[token] = {
        "username":   user.get("username", ""),
        "department": user.get("department", "All"),
        "role":       user.get("role", "dept_user"),
        "expires_at": time.time() + SESSION_TTL_SECONDS,
    }
    return token

def get_session(token: str) -> dict | None:
    if not token:
        return None
    _purge_expired()
    session = _sessions.get(token)
    if not session:
        return None
    if session["expires_at"] < time.time():
        del _sessions[token]
        return None
    session["expires_at"] = time.time() + SESSION_TTL_SECONDS
    return session

def destroy_session(token: str):
    _sessions.pop(token, None)

def destroy_sessions_for_user(username: str) -> int:
    """
    Destroy ALL active sessions for a given username.
    Call this when a user's role or active status changes so they cannot
    retain stale elevated access.
    Returns the number of sessions destroyed.
    """
    uname_lower = username.strip().lower()
    to_delete = [
        t for t, s in _sessions.items()
        if s.get("username", "").lower() == uname_lower
    ]
    for t in to_delete:
        del _sessions[t]
    return len(to_delete)
