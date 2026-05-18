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

from config import settings
from auth import (
    verify_admin_password, verify_totp,
    verify_client_password, verify_analyst_password,
    resolve_client_name,
    create_session, validate_session, destroy_session,
    get_session_role, get_session_client,
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
    logger.info(f"Background fetcher started (interval: {settings.REFRESH_INTERVAL}s)")
    while True:
        try:
            state = await aggregator.fetch_all()
            await ws_manager.broadcast(state.model_dump())
            logger.info(
                f"Broadcast: {state.total_clients} clients, "
                f"{ws_manager.active_count} WS connections"
            )
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Background fetch error: {e}")
        await asyncio.sleep(settings.REFRESH_INTERVAL)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _bg_task
    logger.info(f"S1 configured : {settings.s1_configured()} | token length: {len(settings.S1_API_TOKEN)}")
    logger.info(f"AV configured : {settings.av_configured()} | client_id: '{settings.AV_CLIENT_ID}'")
    logger.info(f"TOTP configured: {settings.totp_configured()}")
    logger.info(f"Clients configured: {len(settings.CLIENT_CREDENTIALS)}")
    logger.info(f"Analysts configured: {len(settings.ANALYST_CREDENTIALS)}")
    # Initialise user DB (seeds from env vars on first run)
    user_db.init_db()
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


# ── Global error handler — logs full traceback to Railway ──────
from fastapi import HTTPException
from fastapi.responses import JSONResponse as _JSONResponse
from starlette.requests import Request as _Request

@app.exception_handler(Exception)
async def global_exception_handler(request: _Request, exc: Exception):
    tb = traceback.format_exc()
    logger.error(f"Unhandled exception on {request.method} {request.url}:\n{tb}")
    return _JSONResponse(
        status_code=500,
        content={"error": str(exc), "type": type(exc).__name__, "path": str(request.url)},
    )


# ════════════════════════════════════════════════════════════════
#  Auth helpers
# ════════════════════════════════════════════════════════════════

def _get_token(request: Request) -> str | None:
    return request.cookies.get(SESSION_COOKIE)


def _authenticated(request: Request) -> bool:
    return validate_session(_get_token(request))


def _require_role(request: Request, *roles: str) -> bool:
    """Check session exists and role is one of the allowed roles."""
    token = _get_token(request)
    if not validate_session(token):
        return False
    role = get_session_role(token)
    return role in roles


def _role(request: Request) -> str | None:
    return get_session_role(_get_token(request))


def _client_name(request: Request) -> str | None:
    return get_session_client(_get_token(request))


# ════════════════════════════════════════════════════════════════
#  Routes
# ════════════════════════════════════════════════════════════════

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Login page — unified credentials form. Admins then get a TOTP step."""
    if _authenticated(request):
        role = _role(request)
        if role == "admin":
            return RedirectResponse(url="/", status_code=302)
        elif role == "client":
            cname = _client_name(request)
            if cname:
                return RedirectResponse(url=f"/client/{cname}", status_code=302)
            return RedirectResponse(url="/", status_code=302)
        elif role == "analyst":
            return RedirectResponse(url="/analyst", status_code=302)
        return RedirectResponse(url="/", status_code=302)

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "error": None,
            "step": "credentials",
            "totp_configured": settings.totp_configured(),
        },
    )


@app.post("/login", response_class=HTMLResponse)
async def login_submit(
    request: Request,
    step: str = Form("credentials"),
    username: str = Form(""),
    password: str = Form(""),
    totp_code: str = Form(""),
):
    """Handle login — everyone starts with credentials.
    Admins proceed to a TOTP step; clients/analysts go straight through.
    """

    # ── Step 1: Credentials ─────────────────────────────────
    if step == "credentials":
        # --- TEMP DEBUG: remove after login is working ---
        cfg_user = settings.ADMIN_USERNAME
        cfg_pass = settings.ADMIN_PASSWORD
        logger.warning(
            f"[LOGIN DEBUG] submitted=({repr(username)},{repr(password)}) "
            f"cfg_admin=({repr(cfg_user)}, set={bool(cfg_pass)}) "
            f"user_match={username==cfg_user} pass_match={password==cfg_pass} "
            f"analyst_keys={list(settings.ANALYST_CREDENTIALS.keys())} "
            f"client_keys={list(settings.CLIENT_CREDENTIALS.keys())}"
        )
        # --- end debug ---

        # Guard: reject blank submissions before any credential check
        if not username or not password:
            return templates.TemplateResponse(
                request=request, name="login.html",
                context={
                    "error": "Username and password are both required.",
                    "step": "credentials",
                    "username": "",
                    "totp_configured": settings.totp_configured(),
                },
                status_code=400,
            )

        # Try admin
        if settings.ADMIN_PASSWORD and verify_admin_password(username, password):
            if settings.totp_configured():
                return templates.TemplateResponse(
                    request=request, name="login.html",
                    context={
                        "error": None,
                        "step": "totp",
                        "totp_configured": True,
                        "username": username,
                    },
                )
            else:
                # No TOTP configured — log in directly
                token = create_session(role="admin")
                ip = request.client.host if request.client else None
                user_db.log_access(username, "admin", None, "login", ip)
                response = RedirectResponse(url="/", status_code=302)
                response.set_cookie(
                    key=SESSION_COOKIE, value=token,
                    httponly=True, samesite="lax",
                    max_age=settings.SESSION_TIMEOUT_MINUTES * 60,
                )
                logger.info("Admin authenticated (no TOTP)")
                return response

        # Try client (DB first, then env-var fallback via verify_client_password)
        db_user = user_db.verify_login(username, password)
        if db_user and db_user["role"] == "client":
            cname = db_user.get("client_name") or resolve_client_name(username)
        elif verify_client_password(username, password):
            cname = resolve_client_name(username)
        else:
            cname = None
        if cname:
            ip = request.client.host if request.client else None
            user_db.log_access(username, "client", cname, "login", ip)
            token = create_session(role="client", client_name=cname)
            response = RedirectResponse(url=f"/client/{cname}", status_code=302)
            response.set_cookie(
                key=SESSION_COOKIE, value=token,
                httponly=True, samesite="lax",
                max_age=settings.SESSION_TIMEOUT_MINUTES * 60,
            )
            logger.info(f"Client '{cname}' authenticated")
            return response

        # Try analyst (DB first, then env-var fallback)
        db_user2 = user_db.verify_login(username, password)
        if (db_user2 and db_user2["role"] in ("analyst", "thirdparty")) or verify_analyst_password(username, password):
            ip = request.client.host if request.client else None
            user_db.log_access(username, "analyst", None, "login", ip)
            token = create_session(role="analyst")
            response = RedirectResponse(url="/analyst", status_code=302)
            response.set_cookie(
                key=SESSION_COOKIE, value=token,
                httponly=True, samesite="lax",
                max_age=settings.SESSION_TIMEOUT_MINUTES * 60,
            )
            logger.info(f"Analyst '{username}' authenticated")
            return response

        # No match
        return templates.TemplateResponse(
            request=request, name="login.html",
            context={
                "error": "Invalid credentials.",
                "step": "credentials",
                "totp_configured": settings.totp_configured(),
            },
        )

    # ── Step 2: TOTP (admin only) ───────────────────────────
    if step == "totp":
        if verify_totp(totp_code.strip()):
            token = create_session(role="admin")
            response = RedirectResponse(url="/", status_code=302)
            response.set_cookie(
                key=SESSION_COOKIE, value=token,
                httponly=True, samesite="lax",
                max_age=settings.SESSION_TIMEOUT_MINUTES * 60,
            )
            logger.info("Admin authenticated via TOTP")
            return response
        return templates.TemplateResponse(
            request=request, name="login.html",
            context={
                "error": "Invalid verification code.",
                "step": "totp",
                "totp_configured": True,
                "username": username,
            },
        )

    return RedirectResponse(url="/login", status_code=302)


@app.get("/logout")
async def logout(request: Request):
    """Logout and destroy session."""
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
        context={"ws_url": f"{ws_scheme}://{host}/ws"},
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
            "ws_url": f"{ws_scheme}://{host}/ws",
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
            "ws_url": f"{ws_scheme}://{host}/ws",
        },
    )


# ── REST API ───────────────────────────────────────────────────

@app.get("/api/state")
async def api_state(request: Request):
    if not _authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    state = aggregator.cached_state
    if state:
        return JSONResponse(state.model_dump())
    return JSONResponse({"error": "No data yet."}, status_code=503)


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
async def debug_ping():
    """Public — no auth needed. Shows credential config status to diagnose login failures."""
    return JSONResponse({
        "admin_username":      settings.ADMIN_USERNAME,
        "admin_password_set":  bool(settings.ADMIN_PASSWORD),
        "analyst_count":       len(settings.ANALYST_CREDENTIALS),
        "analyst_usernames":   list(settings.ANALYST_CREDENTIALS.keys()),
        "client_count":        len(settings.CLIENT_CREDENTIALS),
        "client_usernames":    list(settings.CLIENT_CREDENTIALS.keys()),
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
        "admin_username":     settings.ADMIN_USERNAME,
        "admin_password_set": bool(settings.ADMIN_PASSWORD),
        "totp_configured":    settings.totp_configured(),
        "client_count":       len(client_creds),
        "client_usernames":   list(client_creds.keys()),
        "client_name_map":    name_map,
        "analyst_count":      len(analyst_creds),
        "analyst_usernames":  list(analyst_creds.keys()),
        "raw_analyst_env":    repr(os.getenv("ANALYST_CREDENTIALS", "NOT_SET")[:80]),
        "raw_client_env":     repr(os.getenv("CLIENT_CREDENTIALS",  "NOT_SET")[:80]),
    })


@app.get("/api/debug/av")
async def debug_av(request: Request):
    if not _authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    try:
        deployments = await aggregator.av.fetch_deployments()
        alarms = await aggregator.av.fetch_alarms(days_back=1)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
    sample_alarms = alarms[:3] if alarms else []
    return JSONResponse({
        "av_base_url": aggregator.av.base_url,
        "deployment_count": len(deployments),
        "deployments_raw": deployments[:5],
        "alarm_count": len(alarms),
        "alarm_keys": list(sample_alarms[0].keys()) if sample_alarms else [],
        "alarms_sample": sample_alarms,
    })


# ════════════════════════════════════════════════════════════════
#  WebSocket
# ════════════════════════════════════════════════════════════════

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws_manager.connect(ws)
    if aggregator.cached_state:
        await ws_manager.send_to(ws, aggregator.cached_state.model_dump())
    try:
        while True:
            data = await ws.receive_text()
            if data.startswith("select:"):
                client_name = data[7:].strip()
                await _send_client_detail(ws, client_name)
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

    # Client environments from aggregator
    state = None
    try:
        state = aggregator.last_state
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
        reload=True,
        log_level="info",
    )
