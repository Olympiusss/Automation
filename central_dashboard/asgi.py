"""
Sentrium Enterprise — Unified ASGI Entry Point
===============================================
Runs Flask (central dashboard) AND the SOC FastAPI app
under a SINGLE uvicorn process on a SINGLE port.

  /        → Flask (login, index, all other apps)
  /soc/*   → SOC Dashboard (FastAPI)

Start locally:
    uvicorn asgi:application --host 0.0.0.0 --port 8080 --reload

Production (Procfile):
    web: uvicorn asgi:application --host 0.0.0.0 --port $PORT --workers 1
"""

from __future__ import annotations
import os
import sys
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

# ── Import SOC FastAPI app ────────────────────────────────────────────────────
# We temporarily add the soc_dashboard dir so its local imports work
os.chdir(str(SOC_DIR))
from app import app as soc_app       # noqa: E402
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

_orig_response = _J2.TemplateResponse.__func__ if hasattr(_J2.TemplateResponse, "__func__") else None

SOC_PREFIX = "/soc"

@soc_app.middleware("http")
async def inject_soc_prefix(request, call_next):
    """Make soc_prefix available to all templates via request.state."""
    request.state.soc_prefix = SOC_PREFIX
    return await call_next(request)

# ── Combine: Starlette routes Flask + SOC ────────────────────────────────────
from starlette.applications import Starlette
from starlette.routing import Mount
from starlette.middleware.wsgi import WSGIMiddleware

application = Starlette(
    routes=[
        Mount("/soc",  app=soc_app),
        Mount("/",     app=WSGIMiddleware(flask_app)),
    ]
)
