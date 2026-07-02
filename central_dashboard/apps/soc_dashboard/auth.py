"""
Sentrium Integrated SOC Dashboard — Authentication
Multi-role auth: Admin (TOTP), Client (password), Analyst (password).
"""

from __future__ import annotations
import secrets
import time
import logging
import hmac
from typing import Optional
import pyotp
from config import settings

logger = logging.getLogger("soc_dashboard.auth")

# Session store: { token: { "created_at": float, "last_active": float, "role": str, "client_name": str|None } }
_sessions: dict[str, dict] = {}

# ── Password verification ──────────────────────────────────────

def verify_admin_password(username: str, password: str) -> bool:
    """Verify admin credentials using timing-safe comparison."""
    user_ok = hmac.compare_digest(
        username.encode(), settings.ADMIN_USERNAME.encode()
    )
    pass_ok = hmac.compare_digest(
        password.encode(), settings.ADMIN_PASSWORD.encode()
    )
    return user_ok and pass_ok

def verify_client_password(username: str, password: str) -> bool:
    """Verify a client user's credentials using timing-safe comparison."""
    creds  = settings.CLIENT_CREDENTIALS
    stored = creds.get(username)
    if not stored:
        # Dummy compare to prevent timing oracle on username existence
        hmac.compare_digest(password.encode(), b"dummy")
        return False
    return hmac.compare_digest(password.encode(), stored.encode())

def verify_analyst_password(username: str, password: str) -> bool:
    """Verify an analyst user's credentials using timing-safe comparison."""
    creds  = settings.ANALYST_CREDENTIALS
    stored = creds.get(username)
    if not stored:
        hmac.compare_digest(password.encode(), b"dummy")
        return False
    return hmac.compare_digest(password.encode(), stored.encode())

def resolve_client_name(username: str) -> str | None:
    """Return the real client display name for this username.

    Resolution order:
    1. CLIENT_NAME_MAP env var  → maps login username to exact S1/AV display name
    2. Fall back to the username itself (works when username == client name)
    """
    if username not in settings.CLIENT_CREDENTIALS:
        return None
    name_map = settings.CLIENT_NAME_MAP
    return name_map.get(username, username)

# ── TOTP ───────────────────────────────────────────────────────

def verify_totp(code: str) -> bool:
    """Verify a 6-digit TOTP code against the configured secret."""
    if not settings.totp_configured():
        logger.critical(
            "TOTP not configured — admin login bypasses MFA. "
            "Set TOTP_SECRET env var to enable MFA."
        )
        return False  # Fail CLOSED — do not bypass auth on misconfiguration
    try:
        totp = pyotp.TOTP(settings.TOTP_SECRET)
        return totp.verify(code, valid_window=1)
    except Exception as e:
        logger.error(f"TOTP verification error: {e}")
        return False

# ── Session management ────────────────────────────────────────

def create_session(role: str = "admin", client_name: str | None = None, username: str = "") -> str:
    """Create a new session with role metadata."""
    token = secrets.token_urlsafe(48)
    _sessions[token] = {
        "created_at": time.time(),
        "last_active": time.time(),
        "role": role,
        "client_name": client_name,
        "username": username,
    }
    _cleanup_expired()
    logger.info(f"Session created: role={role}, client={client_name}, user={username}. Total: {len(_sessions)}")
    return token

def validate_session(token: Optional[str]) -> bool:
    """Check if a session token is valid and not expired."""
    if not token:
        return False
    session = _sessions.get(token)
    if not session:
        return False
    timeout_secs = settings.SESSION_TIMEOUT_MINUTES * 60
    if timeout_secs > 0:
        elapsed = time.time() - session["last_active"]
        if elapsed > timeout_secs:
            _sessions.pop(token, None)
            logger.info("Session expired due to inactivity")
            return False
    session["last_active"] = time.time()
    return True

def destroy_session(token: Optional[str]):
    """Destroy a session."""
    if token:
        _sessions.pop(token, None)
        logger.info(f"Session destroyed. Active sessions: {len(_sessions)}")

def get_session_role(token: Optional[str]) -> str | None:
    """Get the role associated with a session."""
    if not token:
        return None
    session = _sessions.get(token)
    return session.get("role") if session else None

def get_session_client(token: Optional[str]) -> str | None:
    """Get the client_name associated with a session."""
    if not token:
        return None
    session = _sessions.get(token)
    return session.get("client_name") if session else None

def get_session_username(token: Optional[str]) -> str:
    """Get the login username (email) associated with a session."""
    if not token:
        return ""
    session = _sessions.get(token)
    return (session.get("username") or "") if session else ""

# ── Internal ───────────────────────────────────────────────────

def _cleanup_expired():
    """Remove expired sessions."""
    if settings.SESSION_TIMEOUT_MINUTES <= 0:
        return
    cutoff = time.time() - (settings.SESSION_TIMEOUT_MINUTES * 60)
    expired = [k for k, v in _sessions.items() if v["last_active"] < cutoff]
    for k in expired:
        del _sessions[k]
