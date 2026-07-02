"""
Sentrium Integrated SOC Dashboard — FastAPI Application
Multi-role: admin, client, analyst.
"""

from __future__ import annotations
import asyncio
import logging
import os
import traceback
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
import jwt as pyjwt
import uuid
import time

from config import settings
from auth import (
    verify_admin_password, verify_totp,
    verify_client_password, verify_analyst_password,
    resolve_client_name,
    create_session, validate_session, destroy_session,
    get_session_role, get_session_client, get_session_username,
)
import db as user_db
from fetcher import aggregator
from websocket_manager import ws_manager

# ── Logging ──────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(name)-28s │ %(levelname)-5s │ %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("soc_dashboard.app")

BASE_DIR = Path(__file__).parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

_bg_task: asyncio.Task | None = None

SESSION_COOKIE = "sentrium_session"


async def _background_fetcher():
    import traceback as _tb
    logger.info(f"Background fetcher started (interval: {settings.REFRESH_INTERVAL}s)")
    while True:
        try:
            # Timeout is a safety net only — clients appear via cache seed within ~20s
            # regardless.  600s gives the slow AV deployments time to fully complete.
            state = await asyncio.wait_for(aggregator.fetch_all(), timeout=600)
            await ws_manager.broadcast(state.model_dump())
            logger.info(
                f"Broadcast: {state.total_clients} clients, "
                f"{ws_manager.active_count} WS connections"
            )
        except asyncio.CancelledError:
            break
        except asyncio.TimeoutError:
            logger.error("Background fetch TIMED OUT after 600 s — resetting lock and retrying")
            # Reset the aggregator lock so next cycle isn't blocked
            aggregator._lock = asyncio.Lock()
        except Exception as e:
            logger.error(f"Background fetch error: {e}\n{_tb.format_exc()}")  # full traceback
        await asyncio.sleep(settings.REFRESH_INTERVAL)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _bg_task
    settings.log_startup_summary()          # ← prints full credential check to Railway logs
    logger.info(f"TOTP configured: {settings.totp_configured()}")
    logger.info(f"Clients configured: {len(settings.CLIENT_CREDENTIALS)}")
    logger.info(f"Analysts configured: {len(settings.ANALYST_CREDENTIALS)}")
    # Initialise user DB (seeds from env vars on first run)
    try:
        user_db.init_db()
    except Exception as _db_err:
        logger.warning(f"SOC DB init failed (auth still works via env vars): {_db_err}")
    _bg_task = asyncio.create_task(_background_fetcher())
    logger.info("═══ Sentrium SOC Dashboard started ═══")
    yield
    if _bg_task:
        _bg_task.cancel()
        try:
            await _bg_task
        except asyncio.CancelledError:
            pass
    await aggregator.close()
    logger.info("═══ Sentrium SOC Dashboard stopped ═══")


app = FastAPI(title="Sentrium Integrated SOC Dashboard", version="1.0.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


# ── Security Headers Middleware ────────────────────────────────
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"]  = "nosniff"
        response.headers["X-Frame-Options"]          = "DENY"
        response.headers["Referrer-Policy"]          = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]       = "camera=(), microphone=(), geolocation=()"
        # HSTS on Railway (always HTTPS)
        if os.environ.get("RAILWAY_ENVIRONMENT") == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

app.add_middleware(SecurityHeadersMiddleware)


# ── Brute-force tracking (per IP) ──────────────────────────────
_login_attempts: dict[str, list[float]] = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_WINDOW    = 900  # 15 minutes

def _is_rate_limited(ip: str) -> bool:
    """Return True if this IP has exceeded the login attempt limit."""
    now  = time.time()
    hist = [t for t in _login_attempts.get(ip, []) if now - t < LOCKOUT_WINDOW]
    _login_attempts[ip] = hist
    return len(hist) >= MAX_LOGIN_ATTEMPTS

def _record_failed_attempt(ip: str):
    now = time.time()
    _login_attempts.setdefault(ip, []).append(now)

def _clear_attempts(ip: str):
    _login_attempts.pop(ip, None)


# ── Global error handler — logs full traceback to Railway ──────
from fastapi import HTTPException
from fastapi.responses import JSONResponse as _JSONResponse
from starlette.requests import Request as _Request

@app.exception_handler(Exception)
async def global_exception_handler(request: _Request, exc: Exception):
    tb = traceback.format_exc()
    logger.error(f"Unhandled exception on {request.method} {request.url.path}:\n{tb}")
    # Never expose internal details to the client
    return _JSONResponse(
        status_code=500,
        content={"error": "Internal server error"},
    )


# ════════════════════════════════════════════════════════════════
#  Auth helpers — bypassed: Sentrium Central is the auth layer
# ════════════════════════════════════════════════════════════════

def _get_token(request: Request) -> str | None:
    return request.cookies.get(SESSION_COOKIE)


def _authenticated(request: Request) -> bool:
    """Return True if the request has a valid SOC session."""
    return validate_session(_get_token(request))


def _require_role(request: Request, *roles: str) -> bool:
    """Return True if the session exists and its role is one of the given roles."""
    token = _get_token(request)
    if not validate_session(token):
        return False
    if not roles:
        return True
    return get_session_role(token) in roles


def _role(request: Request) -> str | None:
    """Return the role of the current session, or None."""
    return get_session_role(_get_token(request))


def _client_name(request: Request) -> str | None:
    return get_session_client(_get_token(request))


# ════════════════════════════════════════════════════════════════
#  Routes
# ════════════════════════════════════════════════════════════════

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Show the SOC login page, or redirect if already authenticated."""
    token = _get_token(request)
    if validate_session(token):
        role = get_session_role(token)
        if role == "analyst":
            return RedirectResponse(url="/analyst", status_code=302)
        elif role == "client":
            client = get_session_client(token)
            return RedirectResponse(url=f"/client/{client}", status_code=302)
        else:
            return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse(
        request=request, name="login.html",
        context={"step": "credentials", "error": None,
                 "config_error": None, "username": ""},
    )


@app.post("/login", response_class=HTMLResponse)
async def login_submit(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
):
    """
    Authenticate with brute-force protection.
    Max 5 attempts per IP per 15 minutes. 0.8s delay on failure.
    """
    ip       = request.client.host if request.client else "unknown"
    username = username.strip()

    # Rate limit check
    if _is_rate_limited(ip):
        logger.warning(f"SOC login rate-limited: IP={ip}")
        return templates.TemplateResponse(
            request=request, name="login.html",
            context={
                "step": "credentials",
                "error": "Too many failed attempts. Please try again in 15 minutes.",
                "config_error": None, "username": "",
            },
        )

    # ── Admin ────────────────────────────────────────────────────
    if verify_admin_password(username, password):
        _clear_attempts(ip)
        token = create_session(role="admin", username=username)
        resp  = RedirectResponse(url="/", status_code=302)
        resp.set_cookie(SESSION_COOKIE, token, httponly=True,
                        samesite="lax", secure=True, max_age=8 * 60 * 60)
        logger.info(f"Admin login: {username} from {ip}")
        return resp

    # ── Analyst ──────────────────────────────────────────────────
    if verify_analyst_password(username, password):
        _clear_attempts(ip)
        token = create_session(role="analyst", username=username)
        resp  = RedirectResponse(url="/analyst", status_code=302)
        resp.set_cookie(SESSION_COOKIE, token, httponly=True,
                        samesite="lax", secure=True, max_age=8 * 60 * 60)
        logger.info(f"Analyst login: {username} from {ip}")
        return resp

    # ── Client ───────────────────────────────────────────────────
    if verify_client_password(username, password):
        _clear_attempts(ip)
        client_name = resolve_client_name(username)
        token = create_session(role="client", client_name=client_name, username=username)
        resp  = RedirectResponse(url=f"/client/{client_name}", status_code=302)
        resp.set_cookie(SESSION_COOKIE, token, httponly=True,
                        samesite="lax", secure=True, max_age=8 * 60 * 60)
        logger.info(f"Client login: {username} → {client_name} from {ip}")
        return resp

    # ── Invalid ──────────────────────────────────────────────────
    _record_failed_attempt(ip)
    logger.warning(f"Failed SOC login: username={username!r} IP={ip}")
    await asyncio.sleep(0.8)  # Blunt brute-force timing
    return templates.TemplateResponse(
        request=request, name="login.html",
        context={
            "step": "credentials",
            "error": "Invalid credentials. Please check your username and password.",
            "config_error": None,
            "username": "",  # Don't echo username back — prevents enumeration hint
        },
    )


@app.api_route("/logout", methods=["GET", "POST"])
async def logout(request: Request):
    """Destroy the SOC session and return to the login page."""
    destroy_session(_get_token(request))
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie(SESSION_COOKIE)
    return response


# ── Admin: Client Overview ─────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def client_grid(request: Request):
    """Admin-only: Client Grid overview."""
    if not _require_role(request, "admin"):
        return RedirectResponse(url="/login", status_code=302)

    host = request.headers.get("host", "localhost:8080")
    proto = request.headers.get("x-forwarded-proto", "http")
    ws_scheme = "wss" if proto == "https" else "ws"
    return templates.TemplateResponse(
        request=request, name="clients.html",
        context={"ws_url": f"{ws_scheme}://{host}/soc/ws"},
    )


# ── Client Dashboard ──────────────────────────────────────────

@app.get("/client/{client_name}", response_class=HTMLResponse)
async def client_dashboard(request: Request, client_name: str):
    """Per-client SOC dashboard. Accessible by: admin, that specific client, analyst."""
    from urllib.parse import unquote
    decoded_name = unquote(client_name)

    if not _authenticated(request):
        return RedirectResponse(url="/login", status_code=302)

    role = _role(request)

    # Admins can view any client
    if role == "admin":
        pass  # allowed
    # Clients can only view their own dashboard
    elif role == "client":
        session_client = _client_name(request)
        if session_client and session_client.lower() != decoded_name.lower():
            return RedirectResponse(url=f"/client/{session_client}", status_code=302)
    # Analysts can view any client
    elif role == "analyst":
        pass  # allowed
    else:
        return RedirectResponse(url="/login", status_code=302)

    host = request.headers.get("host", "localhost:8080")
    proto = request.headers.get("x-forwarded-proto", "http")
    ws_scheme = "wss" if proto == "https" else "ws"
    return templates.TemplateResponse(
        request=request, name="index.html",
        context={
            "refresh_interval": settings.REFRESH_INTERVAL,
            "ws_url": f"{ws_scheme}://{host}/soc/ws",
            "client_name": decoded_name,
            "role": role,
        },
    )


# ── Analyst Portal ─────────────────────────────────────────────

@app.get("/analyst", response_class=HTMLResponse)
async def analyst_portal(request: Request):
    """Analyst landing page with client dropdown."""
    if not _require_role(request, "analyst"):
        return RedirectResponse(url="/login", status_code=302)

    # Fetch available clients from cached state
    state = aggregator.cached_state
    clients = []
    if state:
        clients = [c.name for c in state.clients]

    host = request.headers.get("host", "localhost:8080")
    proto = request.headers.get("x-forwarded-proto", "http")
    ws_scheme = "wss" if proto == "https" else "ws"
    return templates.TemplateResponse(
        request=request, name="analyst.html",
        context={
            "clients": clients,
            "ws_url": f"{ws_scheme}://{host}/soc/ws",
            "sso_configured": settings.sso_configured(),
            "sso_profiles": list(settings.ANALYST_PROFILES.keys()),
        },
    )


# ── External Solution SSO ─────────────────────────────────────────────────────

# In-memory JTI replay store: jti -> expiry epoch seconds
_used_jtis: dict[str, int] = {}


@app.get("/api/sso/config")
async def sso_config(request: Request):
    """Returns SSO configuration status and available analyst profiles."""
    if not _require_role(request, "analyst", "admin"):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    profiles = [
        {"username": u, "name": p.get("name", u), "email": p.get("email", "")}
        for u, p in settings.ANALYST_PROFILES.items()
    ]
    return JSONResponse({
        "configured": settings.sso_configured(),
        "profiles": profiles,
        "tokenField": settings.EXTERNAL_SSO_TOKEN_FIELD,
    })


@app.post("/api/sso/launch")
async def sso_launch(request: Request):
    """Generates a short-lived HS256 JWT using the logged-in user's email
    and returns it for use with the external platform's SSO callback."""
    if not _require_role(request, "analyst", "admin"):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    if not settings.sso_configured():
        return JSONResponse({"error": "SSO is not configured on this server."}, status_code=503)

    # Use the currently logged-in user's email as the SSO identity
    session_token = _get_token(request)
    email = get_session_username(session_token).lower()
    if not email:
        return JSONResponse({"error": "Could not resolve session user."}, status_code=401)

    now = int(time.time())
    exp = now + settings.EXTERNAL_SSO_TOKEN_TTL
    jti = str(uuid.uuid4())

    payload = {
        "iss":   settings.EXTERNAL_SSO_ISSUER,
        "aud":   settings.EXTERNAL_SSO_AUDIENCE,
        "sub":   email,
        "email": email,
        "mfa":   True,
        "iat":   now,
        "exp":   exp,
        "jti":   jti,
    }

    try:
        token = pyjwt.encode(payload, settings.EXTERNAL_SSO_SECRET, algorithm="HS256")
    except Exception as e:
        logger.error(f"SSO JWT signing error: {e}")
        return JSONResponse({"error": "Failed to generate SSO token."}, status_code=500)

    logger.info(f"SSO token issued for '{email}' exp={exp}")
    return JSONResponse({
        "formUrl":   settings.EXTERNAL_SSO_URL,
        "fieldName": settings.EXTERNAL_SSO_TOKEN_FIELD,
        "token":     token,
    })


@app.get("/sso/relay", response_class=HTMLResponse)
async def sso_relay(request: Request):
    """Relay page: generates a JWT for the logged-in user and redirects them
    to the external platform via a GET with the token as a query parameter."""
    if not _require_role(request, "analyst", "admin"):
        return RedirectResponse("/login", status_code=302)

    if not settings.sso_configured():
        return HTMLResponse("<h2>SSO is not configured on this server.</h2>", status_code=503)

    # Use the session user's email — no separate profile mapping needed
    session_token = _get_token(request)
    email = get_session_username(session_token).lower()
    if not email:
        return HTMLResponse("<h2>Session error — please log in again.</h2>", status_code=401)

    now = int(time.time())
    exp = now + settings.EXTERNAL_SSO_TOKEN_TTL
    jti = str(uuid.uuid4())

    payload = {
        "iss":   settings.EXTERNAL_SSO_ISSUER,
        "aud":   settings.EXTERNAL_SSO_AUDIENCE,
        "sub":   email,
        "email": email,
        "mfa":   True,
        "iat":   now,
        "exp":   exp,
        "jti":   jti,
    }

    try:
        token = pyjwt.encode(payload, settings.EXTERNAL_SSO_SECRET, algorithm="HS256")
    except Exception as e:
        logger.error(f"SSO relay JWT signing error: {e}")
        return HTMLResponse("<h2>Failed to generate SSO token.</h2>", status_code=500)

    logger.info(f"SSO relay token issued for '{email}' exp={exp}")

    field  = settings.EXTERNAL_SSO_TOKEN_FIELD
    target = settings.EXTERNAL_SSO_URL
    sep    = "&" if "?" in target else "?"
    sso_url = f"{target}{sep}{field}={token}"

    # Return a page that does a GET redirect via window.location.replace().
    # - Prefetch of this relay page gets HTML but JS doesn't execute → token safe
    # - Actual page load fires window.location.replace() → exactly ONE GET to SOC Pluse
    # - No POST body, no double-request, token travels as query param (SOC Pluse expects this)
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Redirecting to External Platform…</title>
  <style>
    body{{margin:0;display:flex;align-items:center;justify-content:center;
         min-height:100vh;background:#0d1117;font-family:system-ui,sans-serif;color:#e6edf3;}}
    .card{{text-align:center;padding:40px;}}
    .spinner{{width:36px;height:36px;border:3px solid #30363d;border-top-color:#2457d6;
              border-radius:50%;animation:spin .8s linear infinite;margin:0 auto 18px;}}
    @keyframes spin{{to{{transform:rotate(360deg)}}}}
    p{{color:#8b949e;font-size:0.9rem;margin:0;}}
    a{{display:inline-block;margin-top:16px;padding:10px 24px;background:#2457d6;color:#fff;
       border-radius:8px;text-decoration:none;font-size:0.9rem;}}
  </style>
</head>
<body>
  <div class="card">
    <div class="spinner"></div>
    <p>Authenticating with External Platform…</p>
    <noscript>
      <p style="color:#f97316;margin-top:12px;">JavaScript is disabled.</p>
      <a href="{sso_url}">Click here to continue</a>
    </noscript>
  </div>
  <script>
    // Single GET redirect — window.location.replace fires exactly once on real page load.
    // Browsers do NOT execute JS during prefetch, so the token is consumed only once.
    window.location.replace({repr(sso_url)});
  </script>
</body>
</html>"""

    return HTMLResponse(
        content=html,
        status_code=200,
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        }
    )





@app.get("/api/state")
async def api_state(request: Request):
    if not _authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    role  = _role(request)
    state = aggregator.cached_state
    if not state:
        return JSONResponse({"error": "No data yet."}, status_code=503)
    # Clients only see their own data — never other clients'
    if role == "client":
        client_name = _client_name(request)
        if not client_name:
            return JSONResponse({"error": "Forbidden"}, status_code=403)
        client_obj = next(
            (c for c in state.clients if c.name.lower() == client_name.lower()), None
        )
        if not client_obj:
            return JSONResponse({"error": "No data for your account"}, status_code=404)
        # Return a state with only this client's data
        filtered = state.model_dump()
        filtered["clients"] = [client_obj.model_dump()]
        logger.info(f"RBAC: client '{client_name}' received filtered /api/state (1 client)")
        return JSONResponse(filtered)
    # Admin and Analyst see all clients
    return JSONResponse(state.model_dump())


@app.get("/api/client/{client_name}/data")
async def api_client_data(request: Request, client_name: str):
    if not _authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    from urllib.parse import unquote
    name = unquote(client_name).lower()

    role = _role(request)
    # Clients can only access their own data
    if role == "client":
        session_client = _client_name(request)
        if session_client and session_client.lower() != name:
            return JSONResponse({"error": "Forbidden"}, status_code=403)

    state = aggregator.cached_state
    if not state:
        return JSONResponse({"error": "No data yet"}, status_code=503)

    client = next((c for c in state.clients if c.name.lower() == name), None)
    if not client:
        client = next(
            (c for c in state.clients if name in c.name.lower() or c.name.lower() in name),
            None,
        )
    if not client:
        return JSONResponse({"error": f"Client '{client_name}' not found"}, status_code=404)

    return JSONResponse(client.model_dump())


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "s1_configured": settings.s1_configured(),
        "av_configured": settings.av_configured(),
        "ws_connections": ws_manager.active_count,
    }


@app.get("/api/debug/ping")
async def debug_ping(request: Request):
    """Auth diagnostic — admin only to prevent user enumeration."""
    if not _require_role(request, "admin"):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    return JSONResponse({
        "admin_password_set":  bool(settings.ADMIN_PASSWORD),
        "analyst_count":       len(settings.ANALYST_CREDENTIALS),
        "client_count":        len(settings.CLIENT_CREDENTIALS),
        "totp_required":       settings.totp_configured(),
        "session_timeout_min": settings.SESSION_TIMEOUT_MINUTES,
    })


@app.get("/api/debug/auth")
async def debug_auth(request: Request):
    """Safe auth diagnostic — shows credential counts & usernames, never passwords."""
    if not _require_role(request, "admin"):
        return JSONResponse({"error": "Admin only"}, status_code=403)
    client_creds  = settings.CLIENT_CREDENTIALS
    analyst_creds = settings.ANALYST_CREDENTIALS
    name_map      = settings.CLIENT_NAME_MAP
    return JSONResponse({
        "admin_password_set": bool(settings.ADMIN_PASSWORD),
        "totp_configured":    settings.totp_configured(),
        "client_count":       len(client_creds),
        "client_usernames":   list(client_creds.keys()),
        "client_name_map":    name_map,
        "analyst_count":      len(analyst_creds),
        "analyst_usernames":  list(analyst_creds.keys()),
    })


@app.get("/api/debug/av")
async def debug_av(request: Request):
    """AV debug — admin only."""
    if not _require_role(request, "admin"):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    try:
        deployments = await aggregator.av.fetch_deployments()
        alarms = await aggregator.av.fetch_alarms(days_back=1)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
    sample_alarms = alarms[:3] if alarms else []
    return JSONResponse({
        "deployment_count": len(deployments),
        "alarm_count": len(alarms),
        "alarm_keys": list(sample_alarms[0].keys()) if sample_alarms else [],
    })


# ════════════════════════════════════════════════════════════════
#  WebSocket
# ════════════════════════════════════════════════════════════════

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    # Authenticate via session cookie before accepting the connection
    token = ws.cookies.get(SESSION_COOKIE)
    if not validate_session(token):
        await ws.close(code=1008)  # Policy Violation — not authenticated
        logger.warning(f"WebSocket rejected: no valid session from {ws.client}")
        return

    role        = get_session_role(token)
    client_name = get_session_client(token)
    await ws_manager.connect(ws, role=role, client_name=client_name)

    # Send initial state, filtered by role (manager handles ongoing broadcasts)
    if aggregator.cached_state:
        state_data = aggregator.cached_state.model_dump()
        if role == "client" and client_name:
            # Clients only receive their own data
            client_obj = next(
                (c for c in aggregator.cached_state.clients
                 if c.name.lower() == client_name.lower()), None
            )
            if client_obj:
                state_data = {**state_data, "clients": [client_obj.model_dump()]}
            else:
                state_data = {**state_data, "clients": []}
        await ws_manager.send_to(ws, state_data)

    try:
        while True:
            data = await ws.receive_text()
            if data.startswith("select:"):
                requested_client = data[7:].strip()
                # Clients can only select themselves
                if role == "client":
                    if client_name and requested_client.lower() != client_name.lower():
                        logger.warning(
                            f"WS ESCALATION ATTEMPT: client '{client_name}' "
                            f"tried to select '{requested_client}'"
                        )
                        await ws_manager.send_to(ws, {
                            "type": "error",
                            "message": "Access denied"
                        })
                        continue
                await _send_client_detail(ws, requested_client)
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)
    except Exception:
        ws_manager.disconnect(ws)


async def _send_client_detail(ws: WebSocket, client_name: str):
    state = aggregator.cached_state
    if not state:
        return
    for client in state.clients:
        if client.name.lower() == client_name.lower():
            await ws_manager.send_to(ws, {
                "type": "client_detail",
                "client": client.model_dump(),
            })
            return
    await ws_manager.send_to(ws, {
        "type": "error",
        "message": f"Client '{client_name}' not found",
    })


# ════════════════════════════════════════════════════════════════
#  Admin Settings
# ════════════════════════════════════════════════════════════════

def _settings_context(request: Request, flash: str = "", error: str = "") -> dict:
    """Build full context for the settings template."""
    import time
    from datetime import datetime, timezone

    all_users = user_db.get_all_users()
    last_access_map = {u["username"]: user_db.get_last_access(u["username"]) for u in all_users}
    login_counts = user_db.get_client_login_counts()
    access_log_raw = user_db.get_access_log(limit=200)

    def fmt_ts(ts):
        if not ts:
            return None
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%d %b %Y %H:%M UTC")

    # Enrich users with last access
    users_enriched = []
    for u in all_users:
        la = last_access_map.get(u["username"])
        users_enriched.append({**u, "last_access": la, "last_access_fmt": fmt_ts(la)})

    # Client environments from aggregator (correct attribute: cached_state)
    state = None
    try:
        state = aggregator.cached_state
        all_clients = [c.name for c in (state.clients if state else [])]
    except Exception:
        all_clients = []

    # Also merge DB client_name values
    db_clients = {u["client_name"] for u in all_users if u.get("client_name")}
    all_client_names = sorted(set(all_clients) | db_clients)

    # Build client env summary
    client_users = {u["username"]: u for u in all_users}
    client_envs = []
    for cname in all_client_names:
        mapped_logins = [u for u in all_users if u.get("client_name") == cname and u["role"] == "client"]
        analysts = [u for u in all_users if u["role"] == "analyst"]
        # Try to get platform tags
        platforms = []
        if state:
            for c in state.clients:
                if c.name == cname:
                    platforms = c.platforms if hasattr(c, "platforms") else []
                    break
        client_envs.append({
            "name": cname,
            "login_count": len(mapped_logins),
            "analyst_count": len(analysts),
            "total_accesses": login_counts.get(cname, 0),
            "platforms": platforms,
        })

    # Stats
    stats = {
        "total": len(all_users),
        "clients": sum(1 for u in all_users if u["role"] == "client"),
        "analysts": sum(1 for u in all_users if u["role"] == "analyst"),
        "thirdparty": sum(1 for u in all_users if u["role"] == "thirdparty"),
    }

    # Access log enriched
    access_log = [
        {**e, "time_fmt": fmt_ts(e["timestamp"])}
        for e in access_log_raw
    ]

    # Export config
    import json
    active_clients = {u["username"]: u["password"] for u in all_users
                      if u["role"] == "client" and u["is_active"]}
    active_name_map = {u["username"]: u["client_name"] for u in all_users
                       if u["role"] == "client" and u["is_active"] and u.get("client_name")}
    active_analysts = {u["username"]: u["password"] for u in all_users
                       if u["role"] in ("analyst", "thirdparty") and u["is_active"]}
    export_vars = {
        "CLIENT_CREDENTIALS": json.dumps(active_clients),
        "CLIENT_NAME_MAP": json.dumps(active_name_map),
        "ANALYST_CREDENTIALS": json.dumps(active_analysts),
    }

    return {
        "users": users_enriched,
        "client_envs": client_envs,
        "access_log": access_log,
        "stats": stats,
        "export_vars": export_vars,
        "flash": flash,
        "error": error,
    }


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not validate_session(token) or get_session_role(token) != "admin":
        return RedirectResponse(url="/login", status_code=302)
    ctx = _settings_context(request)
    return templates.TemplateResponse(request=request, name="settings.html", context=ctx)


@app.post("/settings/user/create")
async def settings_create_user(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    role: str = Form("client"),
    client_name: str = Form(""),
):
    token = request.cookies.get(SESSION_COOKIE)
    if not validate_session(token) or get_session_role(token) != "admin":
        return RedirectResponse(url="/login", status_code=302)
    if not username or not password:
        ctx = _settings_context(request, error="Username and password are required.")
        return templates.TemplateResponse(request=request, name="settings.html", context=ctx)
    try:
        user_db.upsert_user(username, password, role, client_name or None)
        logger.info(f"Admin created user: {username} ({role})")
        ctx = _settings_context(request, flash=f"User '{username}' created successfully.")
    except Exception as e:
        ctx = _settings_context(request, error=str(e))
    return templates.TemplateResponse(request=request, name="settings.html", context=ctx)


@app.post("/settings/user/update")
async def settings_update_user(
    request: Request,
    original_username: str = Form(""),
    username: str = Form(""),
    password: str = Form(""),
    role: str = Form("client"),
    client_name: str = Form(""),
):
    token = request.cookies.get(SESSION_COOKIE)
    if not validate_session(token) or get_session_role(token) != "admin":
        return RedirectResponse(url="/login", status_code=302)
    try:
        existing = user_db.get_user(original_username)
        new_pw = password if password else (existing["password"] if existing else "")
        user_db.upsert_user(username, new_pw, role, client_name or None)
        # If username changed, delete the old record
        if username != original_username:
            user_db.delete_user(original_username)
        ctx = _settings_context(request, flash=f"User '{username}' updated.")
    except Exception as e:
        ctx = _settings_context(request, error=str(e))
    return templates.TemplateResponse(request=request, name="settings.html", context=ctx)


@app.post("/settings/user/delete")
async def settings_delete_user(
    request: Request,
    username: str = Form(""),
):
    token = request.cookies.get(SESSION_COOKIE)
    if not validate_session(token) or get_session_role(token) != "admin":
        return RedirectResponse(url="/login", status_code=302)
    user_db.delete_user(username)
    logger.info(f"Admin deleted user: {username}")
    ctx = _settings_context(request, flash=f"User '{username}' deleted.")
    return templates.TemplateResponse(request=request, name="settings.html", context=ctx)


@app.post("/settings/user/toggle")
async def settings_toggle_user(
    request: Request,
    username: str = Form(""),
    active: str = Form("1"),
):
    token = request.cookies.get(SESSION_COOKIE)
    if not validate_session(token) or get_session_role(token) != "admin":
        return RedirectResponse(url="/login", status_code=302)
    user_db.toggle_user(username, active == "1")
    status = "activated" if active == "1" else "deactivated"
    ctx = _settings_context(request, flash=f"User '{username}' {status}.")
    return templates.TemplateResponse(request=request, name="settings.html", context=ctx)


# ════════════════════════════════════════════════════════════════
#  Entry point
# ════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=False,
        log_level="info",
    )
