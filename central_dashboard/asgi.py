"""
Sentrium Enterprise — Unified ASGI Entry Point
===============================================
Runs Flask (central dashboard) AND the SOC FastAPI app
under a SINGLE uvicorn process on a SINGLE port.

  /        → Flask (login, index, all other apps)
  /soc/*   → SOC Dashboard (FastAPI)
  /api/av  → AlienVault FastAPI router (async, httpx, exact SOC stack)

Start locally:
    uvicorn asgi:application --host 0.0.0.0 --port 8080 --reload

Production (Procfile):
    web: uvicorn asgi:application --host 0.0.0.0 --port $PORT --workers 1
"""

from __future__ import annotations
import asyncio
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

# ── Ensure both apps can import their own modules ─────────────────────────────
ROOT     = Path(__file__).parent
SOC_DIR  = ROOT / "apps" / "soc_dashboard"

sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(SOC_DIR))

# ── Load SOC .env before importing config ─────────────────────────────────────
from dotenv import load_dotenv
load_dotenv(dotenv_path=SOC_DIR / ".env", override=False)

# ── Import Flask app (WSGI) ───────────────────────────────────────────────────
from server import app as flask_app  # noqa: E402

# ── Import SOC FastAPI app AND the module so we can call its internals ────────
# We temporarily add the soc_dashboard dir so its local imports work
os.chdir(str(SOC_DIR))
from app import app as soc_app       # noqa: E402
import app as _soc                   # noqa: E402  — gives access to _bg_task, aggregator, etc.
os.chdir(str(ROOT))

# ── Prefix-rewrite middleware for SOC redirects ───────────────────────────────
# FastAPI redirect responses use absolute paths ("/login", "/", etc.)
# This middleware rewrites Location headers to carry the /soc prefix so
# redirects stay within the mounted sub-app.
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

class PrefixRedirectMiddleware(BaseHTTPMiddleware):
    """Rewrites redirect Location headers to prepend /soc when missing."""

    PREFIX = "/soc"
    REDIRECT_CODES = {301, 302, 303, 307, 308}

    async def dispatch(self, request, call_next):
        # WebSocket upgrades must pass through untouched
        if request.scope.get("type") == "websocket":
            return await call_next(request)
        response = await call_next(request)
        if response.status_code in self.REDIRECT_CODES:
            location = response.headers.get("location", "")
            # Only rewrite bare absolute paths that don't already have /soc
            if (
                location.startswith("/")
                and not location.startswith(self.PREFIX)
                and not location.startswith("/static")
            ):
                response.headers["location"] = self.PREFIX + location
        return response

soc_app.add_middleware(PrefixRedirectMiddleware)

# ── Inject `soc_prefix` into every Jinja2 template context ───────────────────
# This lets templates use {{ soc_prefix }}/logout, {{ soc_prefix }}/settings, etc.
from fastapi.templating import Jinja2Templates as _J2

SOC_PREFIX = "/soc"

@soc_app.middleware("http")
async def inject_soc_prefix(request, call_next):
    """Make soc_prefix available to all templates via request.state."""
    request.state.soc_prefix = SOC_PREFIX
    return await call_next(request)

# ── Outer lifespan — explicitly starts SOC background services ───────────────
# The outer Starlette router does NOT automatically trigger FastAPI sub-app
# lifespans.  We therefore call the SOC's init functions directly here so
# the background data-fetcher runs from the very first second of deployment.

@asynccontextmanager
async def lifespan(app):
    """
    Main application lifespan.
    Explicitly runs SOC startup (DB init + background fetcher) because
    Starlette does not propagate lifespan scopes to mounted sub-apps.
    """
    # ── SOC startup ──────────────────────────────────────────────────────────
    try:
        _soc.settings.log_startup_summary()
    except Exception as _e:
        print(f"[asgi] SOC settings log: {_e}")

    try:
        _soc.user_db.init_db()
        print("[asgi] SOC DB initialised (soc_portal_users + soc_portal_access_log)")
    except Exception as _e:
        print(f"[asgi] SOC DB init (non-fatal — env-var auth still works): {_e}")

    # Start background data-fetcher task
    _soc._bg_task = asyncio.create_task(_soc._background_fetcher())
    print("[asgi] SOC background fetcher started")

    yield   # ← application runs here

    # ── SOC shutdown ─────────────────────────────────────────────────────────
    if _soc._bg_task:
        _soc._bg_task.cancel()
        try:
            await _soc._bg_task
        except asyncio.CancelledError:
            pass
    try:
        await _soc.aggregator.close()
    except Exception:
        pass
    print("[asgi] SOC background fetcher stopped")


# ── Combine: Starlette routes Flask + SOC ──────────────────────────────────────
from starlette.applications import Starlette
from starlette.routing import Mount
from starlette.middleware.wsgi import WSGIMiddleware

application = Starlette(
    lifespan=lifespan,
    routes=[
        Mount("/soc",    app=soc_app),
        Mount("/",       app=WSGIMiddleware(flask_app)),
    ]
)
