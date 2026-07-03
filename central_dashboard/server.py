"""
Sentrium Enterprise Solution — Unified Flask Backend
====================================================
Single server. Single URL. All apps embedded natively.
All secrets loaded from environment variables — no hardcoded credentials.

VAPT Hardening:
  - Server-side session auth on all /api/* routes
  - Rate limiting (flask-limiter)
  - Full security headers (CSP, HSTS, X-Frame-Options, Permissions-Policy)
  - Generic error responses (no stack traces to client)
  - Proper logging
"""
from flask import (Flask, send_from_directory, abort, request,
                   jsonify, send_file, Response, make_response, redirect, g)
from functools import wraps
import os, sys, logging, time, re as _re

sys.path.insert(0, os.path.dirname(__file__))

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentrium.server")

# ── App ───────────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder='.', template_folder='templates')

_secret = os.environ.get('SECRET_KEY', '')
if not _secret:
    import secrets as _sec
    _secret = _sec.token_hex(32)
    logger.warning("SECRET_KEY env var not set — using ephemeral key. "
                   "Sessions will be lost on restart. Set SECRET_KEY in Railway.")
app.secret_key = _secret

# ── File upload limits ────────────────────────────────────────────────────────
# Reject any upload over 10 MB at the Flask/WSGI layer before touching the file
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB

_ALLOWED_ATTENDANCE_EXT = {'.xlsx', '.xls', '.csv'}
_ALLOWED_CONVERSION_EXT = {'.pdf'}

def _safe_ext(filename: str) -> str:
    """Return the lowercase file extension, or empty string if none."""
    return os.path.splitext(filename or '')[1].lower()

# ── Rate limiting ─────────────────────────────────────────────────────────────
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    # NOTE: flask-limiter uses the `limits` library which does NOT support
    # PostgreSQL as a storage backend. Use memory:// (reliable, no deps).
    # The SOC app's brute-force protection (IP tracking + lockout) is separate
    # and does not depend on this limiter.
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per minute"],
        storage_uri="memory://",
    )
    LIMITER_AVAILABLE = True
    logger.info("Rate limiter active (memory storage)")
except ImportError:
    logger.warning("flask-limiter not installed — rate limiting disabled.")
    LIMITER_AVAILABLE = False
    class _FakeLimiter:
        def limit(self, *a, **kw):
            def decorator(f): return f
            return decorator
    limiter = _FakeLimiter()


@app.errorhandler(413)
def upload_too_large(e):
    """Friendly 413 response when upload exceeds MAX_CONTENT_LENGTH."""
    return jsonify({'error': 'File too large. Maximum upload size is 10 MB.'}), 413

# ── Session auth helpers ──────────────────────────────────────────────────────
from user_store import get_session, create_session, destroy_session, verify_password
from urllib.parse import urlparse

# SSRF protection: AlienVault dep_url must be from known AV domains only
_ALLOWED_AV_DOMAINS = ('alienvault.cloud', 'alienvault.com', 'cybervergent-central.alienvault.cloud')

def _validate_av_url(url: str) -> bool:
    """Reject dep_url values that are not legitimate AlienVault HTTPS endpoints."""
    if not url:
        return True  # empty = use global fetch, always safe
    try:
        p = urlparse(url)
        if p.scheme != 'https':
            return False
        host = p.netloc.lower().split(':')[0]
        return any(host == d or host.endswith('.' + d) for d in _ALLOWED_AV_DOMAINS)
    except Exception:
        return False

# Valid departments for whitelist checks
_VALID_DEPTS = {
    'Security Testing', 'Security Operations', 'Brand & Marketing',
    'People and Culture', 'Research and Intelligence', 'IT Infrastructure',
    'Operations', 'Finance', 'Sales', 'Customer Success',
    'Security Engineering', 'Portfolio Management', 'All',
}


# ── DB init (runs on startup — creates sentrium_users table if absent) ────────
try:
    from db_users import init_db
    init_db()
except Exception as _dbe:
    logger.warning(f"DB init skipped: {_dbe}")

SESSION_COOKIE = "sentrium_token"

def _get_session_token() -> str | None:
    return request.cookies.get(SESSION_COOKIE)

def require_session(f):
    """Decorator: reject requests without a valid server-side session."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = _get_session_token()
        session = get_session(token)
        if not session:
            return jsonify({"error": "Authentication required"}), 401
        g.session = session
        return f(*args, **kwargs)
    return decorated

def require_dept(*allowed_depts):
    """
    Decorator: require session AND correct department (or admin/All-dept role).
    Prevents horizontal privilege escalation across departments.
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = _get_session_token()
            session = get_session(token)
            if not session:
                return jsonify({"error": "Authentication required"}), 401
            g.session = session
            role = session.get("role", "")
            dept = session.get("department", "")
            # Admins and All-department users bypass department checks
            if role == "admin" or dept == "All":
                return f(*args, **kwargs)
            if dept not in allowed_depts:
                logger.warning(
                    f"ESCALATION ATTEMPT blocked: user={session.get('username')!r} "
                    f"dept={dept!r} tried to access {request.method} {request.path} "
                    f"(requires dept: {allowed_depts}) from {request.remote_addr}"
                )
                return jsonify({"error": "Access denied: insufficient department permissions"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

# ── Allowed static files (credentials.js removed) ────────────────────────────
ALLOWED_STATIC = {
    'index.html', 'login.html', 'styles.css', 'auth.js', 'script.js',
    'sacred_geometry.js', 'logo.png', 'logo_transparent.png',
    'sentinelone-logo.png',
}

# ── Static files ──────────────────────────────────────────────────────────────
@app.route('/')
def root():
    nonce = getattr(g, 'csp_nonce', '')
    with open(os.path.join(os.path.dirname(__file__), 'login.html'), encoding='utf-8') as f:
        content = _inject_nonce(f.read(), nonce)
    return Response(content, mimetype='text/html')

@app.route('/<path:filename>')
def serve_static(filename):
    if filename not in ALLOWED_STATIC:
        abort(404)
    if filename.endswith('.html'):
        # Inject CSP nonce into HTML files before serving
        nonce = getattr(g, 'csp_nonce', '')
        filepath = os.path.join(os.path.dirname(__file__), filename)
        with open(filepath, encoding='utf-8') as f:
            content = _inject_nonce(f.read(), nonce)
        return Response(content, mimetype='text/html')
    return send_from_directory(os.path.dirname(__file__), filename)

# ── App HTML templates ────────────────────────────────────────────────────────
# App-to-department access map — enforced server-side
APP_DEPT_MAP = {
    'ri-alienvault':   'Research and Intelligence',
    'ri-s1-nfr':       'Research and Intelligence',
    'ri-s1-exclusive': 'Research and Intelligence',
    'ri-conversion':   'Research and Intelligence',
    'pc-attendance':   'People and Culture',
    'ops-dashboard':   'Operations',
}

ALLOWED_APPS = set(APP_DEPT_MAP.keys())

def _inject_nonce(html: str, nonce: str) -> str:
    """Inject CSP nonce into every <script> tag in an HTML document."""
    if not nonce:
        return html
    return _re.sub(r'<script(?=[ >])', f'<script nonce="{nonce}"', html)

@app.before_request
def _generate_csp_nonce():
    """Generate a unique nonce for this request — used in CSP and injected into HTML."""
    import secrets as _sec
    g.csp_nonce = _sec.token_urlsafe(16)

@app.route('/apps/<app_id>')
@require_session
def serve_app(app_id):
    if app_id == 'so-soc-dashboard':
        # SOC dashboard: Security Operations dept only
        dept = g.session.get("department", "")
        role = g.session.get("role", "")
        if role != "admin" and dept not in ("All", "Security Operations"):
            logger.warning(
                f"ESCALATION ATTEMPT: {g.session.get('username')!r} "
                f"(dept={dept!r}) tried to access SOC dashboard from {request.remote_addr}"
            )
            return jsonify({"error": "Access denied: insufficient department permissions"}), 403
        return redirect('/soc/', code=302)
    # Strict allowlist — prevents path traversal and unauth access
    if app_id not in ALLOWED_APPS:
        abort(404)
    # Server-side department check
    required_dept = APP_DEPT_MAP.get(app_id)
    dept = g.session.get("department", "")
    role = g.session.get("role", "")
    if required_dept and role != "admin" and dept not in ("All", required_dept):
        logger.warning(
            f"ESCALATION ATTEMPT: {g.session.get('username')!r} "
            f"(dept={dept!r}) tried to access app={app_id!r} "
            f"(requires dept={required_dept!r}) from {request.remote_addr}"
        )
        return jsonify({"error": "Access denied: insufficient department permissions"}), 403
    tmpl = os.path.join(os.path.dirname(__file__), 'templates', f'{app_id}.html')
    if not os.path.exists(tmpl):
        abort(404)
    nonce = getattr(g, 'csp_nonce', '')
    with open(tmpl, encoding='utf-8') as f:
        content = _inject_nonce(f.read(), nonce)
    return Response(content, mimetype='text/html')

# ════════════════════════════════════════════════════════════════════════════
#  Authentication endpoints
# ════════════════════════════════════════════════════════════════════════════

@app.route('/api/auth/verify', methods=['POST'])
@limiter.limit("5 per minute")
def auth_verify():
    """
    Server-side login. Validates username + password via bcrypt.
    On success: sets HttpOnly session cookie and returns user info.
    TOTP is disabled per security policy.
    """
    data = request.get_json(force=True, silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not username or not password:
        return jsonify({"ok": False, "error": "Username and password are required"}), 400

    user = verify_password(username, password)
    if not user:
        logger.warning(f"Failed login attempt for username: {username!r} from {request.remote_addr}")
        # Generic message — do not reveal whether username exists
        time.sleep(0.8)  # Blunt brute-force timing attacks
        return jsonify({"ok": False, "error": "Invalid credentials"}), 401

    token = create_session(user)
    logger.info(f"Successful login: {username!r} dept={user.get('department')} from {request.remote_addr}")

    resp = make_response(jsonify({
        "ok":         True,
        "username":   user["username"],
        "department": user.get("department", "All"),
        "role":       user.get("role", "dept_user"),
    }))
    resp.set_cookie(
        SESSION_COOKIE, token,
        httponly=True,
        samesite="Lax",
        secure=True,          # Always enforce Secure — Railway always serves HTTPS
        max_age=8 * 60 * 60,
        path="/",
    )
    return resp

@app.route('/api/auth/logout', methods=['POST'])
def auth_logout():
    """Destroy the server-side session and clear the cookie."""
    token = _get_session_token()
    if token:
        destroy_session(token)
    resp = make_response(jsonify({"ok": True}))
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.route('/api/auth/change-password', methods=['POST'])
@require_session
@limiter.limit("10 per hour")
def auth_change_password():
    """
    Self-service password change (session-authenticated).
    Verifies current password, updates DB, then invalidates the session
    so the user must log in again with the new password.
    """
    data             = request.get_json(silent=True) or {}
    current_password = data.get("current_password", "")
    new_password     = data.get("new_password", "")
    confirm_password = data.get("confirm_password", "")

    if not current_password or not new_password or not confirm_password:
        return jsonify({"error": "All fields are required"}), 400
    if new_password != confirm_password:
        return jsonify({"error": "New passwords do not match"}), 400
    if len(new_password) < 8:
        return jsonify({"error": "New password must be at least 8 characters"}), 400
    import re
    if not re.search(r'[A-Z]', new_password):
        return jsonify({"error": "Password must contain at least one uppercase letter"}), 400
    if not re.search(r'[0-9]', new_password):
        return jsonify({"error": "Password must contain at least one digit"}), 400
    if not re.search(r'[^A-Za-z0-9]', new_password):
        return jsonify({"error": "Password must contain at least one special character"}), 400
    if new_password == current_password:
        return jsonify({"error": "New password must differ from current password"}), 400

    username = g.session["username"]

    # Verify current password against DB
    user = verify_password(username, current_password)
    if not user:
        logger.warning(f"Failed password change for {username} from {request.remote_addr}")
        return jsonify({"error": "Current password is incorrect"}), 401

    # Update in PostgreSQL
    try:
        from db_users import update_password, is_available
        if not is_available():
            return jsonify({"error": "Password change requires database connection"}), 503
        ok = update_password(username, new_password)
        if not ok:
            return jsonify({"error": "User not found in database"}), 404
    except Exception as e:
        logger.error(f"Password change DB error for {username}: {e}")
        return jsonify({"error": "Database error. Please try again."}), 500

    # Invalidate session — user must re-login with new password
    token = _get_session_token()
    if token:
        destroy_session(token)
    resp = make_response(jsonify({"ok": True}))
    resp.delete_cookie(SESSION_COOKIE, path="/")
    logger.info(f"Password changed for {username}")
    return resp


@app.route('/api/auth/self-password', methods=['POST'])
@limiter.limit("5 per hour")
def auth_self_password():
    """
    Unauthenticated self-service password change from the login page.
    Caller must supply username + current_password (used for identity verification)
    plus new_password + confirm_password. No active session required.
    """
    data             = request.get_json(silent=True) or {}
    username         = str(data.get("username", "")).strip().lower()
    current_password = data.get("current_password", "")
    new_password     = data.get("new_password", "")
    confirm_password = data.get("confirm_password", "")

    if not username or not current_password or not new_password or not confirm_password:
        return jsonify({"error": "All fields are required"}), 400
    if new_password != confirm_password:
        return jsonify({"error": "New passwords do not match"}), 400
    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    import re
    if not re.search(r'[A-Z]', new_password):
        return jsonify({"error": "Password must contain at least one uppercase letter"}), 400
    if not re.search(r'[0-9]', new_password):
        return jsonify({"error": "Password must contain at least one digit"}), 400
    if not re.search(r'[^A-Za-z0-9]', new_password):
        return jsonify({"error": "Password must contain at least one special character"}), 400
    if new_password == current_password:
        return jsonify({"error": "New password must differ from current password"}), 400

    # Verify current credentials — this is the identity proof
    user = verify_password(username, current_password)
    if not user:
        time.sleep(0.5)   # Slow brute-force attempts
        logger.warning(f"Self-password change failed for '{username}' from {request.remote_addr}")
        return jsonify({"error": "Username or current password is incorrect"}), 401

    try:
        from db_users import update_password, is_available
        if not is_available():
            return jsonify({"error": "Password change requires database connection"}), 503
        ok = update_password(username, new_password)
        if not ok:
            return jsonify({"error": "User not found"}), 404
    except Exception as e:
        logger.error(f"Self-password DB error for '{username}': {e}")
        return jsonify({"error": "Database error. Please try again."}), 500

    logger.info(f"Self-service password changed for '{username}' from {request.remote_addr}")
    return jsonify({"ok": True, "message": "Password updated. Please log in with your new password."})

@app.route('/api/auth/me', methods=['GET'])
@limiter.limit("60 per minute")
def auth_me():
    """Return current session info (used by script.js on page load)."""
    token = _get_session_token()
    session = get_session(token)
    if not session:
        return jsonify({"authenticated": False}), 401
    return jsonify({
        "authenticated": True,
        "username":      session["username"],
        "department":    session["department"],
        "role":          session["role"],
    })

@app.route('/api/auth/status', methods=['GET'])
@require_session
def auth_status():
    """Diagnostic — admin only. Shows DB state and user count (no passwords)."""
    err = _require_admin(g.session)
    if err:
        return err
    result = {
        "database_url_set": bool(os.environ.get("DATABASE_URL")),
        "source": "unavailable",
        "users_loaded": 0,
        "error": None,
    }
    try:
        from db_users import list_users, is_available, _get_pool
        result["db_url_available"] = is_available()
        pool = _get_pool()
        result["pool_created"] = pool is not None
        if pool:
            result["source"] = "postgresql"
            users = list_users()
            result["users_loaded"] = len(users)
            result["user_count"] = len(users)
        else:
            result["source"] = "json_fallback"
            result["error"] = "PostgreSQL pool could not be created"
    except Exception:
        result["error"] = "Status check failed"
    return jsonify(result)

# ════════════════════════════════════════════════════════════════════════════
#  Admin — User Management  (admin role required)
# ════════════════════════════════════════════════════════════════════════════
def _require_admin(session):
    if session.get("role") != "admin":
        return jsonify({"error": "Admin access required"}), 403
    return None

@app.route('/api/admin/users', methods=['GET'])
@require_session
@limiter.limit("30 per minute")
def admin_list_users():
    """List all users (no passwords)."""
    err = _require_admin(g.session)
    if err: return err
    from db_users import list_users
    return jsonify(list_users())

@app.route('/api/admin/users', methods=['POST'])
@require_session
@limiter.limit("20 per minute")
def admin_add_user():
    """Add a new user."""
    err = _require_admin(g.session)
    if err: return err

    data       = request.get_json(silent=True) or {}
    email      = data.get('email', '').strip().lower()
    password   = data.get('password', '')
    department = data.get('department', 'All')
    role       = data.get('role', 'dept_user')

    if not email or '@' not in email:
        return jsonify({"error": "Valid email required"}), 400
    if not password:
        return jsonify({"error": "Password is required"}), 400
    if role not in ('dept_user', 'admin'):
        return jsonify({"error": "Role must be dept_user or admin"}), 400

    from db_users import add_user
    ok, msg = add_user(email, password, department, role)
    if not ok:
        return jsonify({"error": msg}), 409
    logger.info(f"Admin {g.session['username']} added user: {email}")
    return jsonify({"ok": True, "email": email}), 201

@app.route('/api/admin/users/<path:email>', methods=['PATCH'])
@require_session
def admin_update_user(email):
    """Update a user's password, department, role, or active status."""
    err = _require_admin(g.session)
    if err: return err

    data = request.get_json(silent=True) or {}
    from db_users import update_user, update_password

    # Validate password complexity if updating
    if 'password' in data:
        new_pw = data['password']
        if len(new_pw) < 8:
            return jsonify({"error": "Password must be at least 8 characters"}), 400
        import re
        if not re.search(r'[A-Z]', new_pw):
            return jsonify({"error": "Password must contain at least one uppercase letter"}), 400
        if not re.search(r'[0-9]', new_pw):
            return jsonify({"error": "Password must contain at least one digit"}), 400
        if not re.search(r'[^A-Za-z0-9]', new_pw):
            return jsonify({"error": "Password must contain at least one special character"}), 400
        update_password(email, new_pw)

    # Validate role if updating
    new_role = data.get('role')
    if new_role is not None and new_role not in ('dept_user', 'admin'):
        return jsonify({"error": "Role must be dept_user or admin"}), 400

    # Validate department if updating
    new_dept = data.get('department')
    if new_dept is not None and new_dept not in _VALID_DEPTS:
        return jsonify({"error": f"Invalid department value"}), 400

    ok = update_user(
        email,
        department = data.get('department'),
        role       = data.get('role'),
        is_active  = data.get('is_active'),
    )
    # Invalidate ALL active sessions for this user if role or active status changed
    # This prevents a demoted user from retaining elevated access until session expires
    if 'role' in data or 'is_active' in data:
        from user_store import destroy_sessions_for_user
        destroyed = destroy_sessions_for_user(email)
        logger.info(
            f"Admin {g.session['username']} updated user: {email} — "
            f"{destroyed} active session(s) invalidated"
        )
    else:
        logger.info(f"Admin {g.session['username']} updated user: {email}")
    return jsonify({"ok": True})

@app.route('/api/admin/users/<path:email>', methods=['DELETE'])
@require_session
@limiter.limit("10 per minute")
def admin_delete_user(email):
    """Permanently delete a user."""
    err = _require_admin(g.session)
    if err: return err
    if '@' not in email:
        return jsonify({"error": "Invalid email"}), 400
    if email.lower() == g.session['username'].lower():
        return jsonify({"error": "Cannot delete your own account"}), 400
    from db_users import delete_user
    ok = delete_user(email)
    logger.info(f"Admin {g.session['username']} deleted user: {email}")
    return jsonify({"ok": ok}), (200 if ok else 404)


# ════════════════════════════════════════════════════════════════════════════
#  Ops Agent config
# ════════════════════════════════════════════════════════════════════════════

@app.route('/api/ops/config')
@require_dept('Operations')
def ops_config():
    try:
        from apps.ops_agent.logic import get_config
        return jsonify(get_config())
    except Exception:
        logger.exception("ops_config error")
        return jsonify({"error": "Internal server error"}), 500

# ════════════════════════════════════════════════════════════════════════════
#  AlienVault routes
# ════════════════════════════════════════════════════════════════════════════

@app.route('/api/alienvault/deployments', methods=['GET'])
@require_dept('Research and Intelligence')
@limiter.limit("10 per minute")
def alienvault_deployments():
    """Return the list of AV client deployments so the UI can populate a dropdown."""
    from apps.alienvault.logic import get_deployments
    try:
        deps = get_deployments()
        # Return only the fields the UI needs
        return jsonify([
            {
                "name":        d.get("name", d.get("displayName", "Unknown")),
                "displayName": d.get("displayName", d.get("name", "Unknown")),
                "url":         d.get("_url", ""),
            }
            for d in deps
        ])
    except Exception:
        logger.exception("alienvault_deployments error")
        return jsonify({"error": "Could not load deployments"}), 500


@app.route('/api/alienvault/fetch', methods=['POST'])
@require_dept('Research and Intelligence')
@limiter.limit("30 per minute")
def alienvault_fetch():
    from apps.alienvault.logic import (
        get_token, fetch_all_parallel,
        fetch_alarms_for_deployment, fetch_events_for_deployment,
        process_alarms, process_events,
    )
    try:
        d        = request.get_json(force=True, silent=True) or {}
        dep_url  = str(d.get('dep_url', '')).strip()
        start_ms = d.get('start_ms')
        end_ms   = d.get('end_ms')
        if start_ms is None or end_ms is None:
            return jsonify({"error": "start_ms and end_ms are required"}), 400
        # SSRF protection: validate dep_url is a legitimate AlienVault endpoint
        if dep_url and not _validate_av_url(dep_url):
            logger.warning(f"SSRF attempt blocked: dep_url={dep_url!r} from {request.remote_addr}")
            return jsonify({"error": "Invalid deployment URL"}), 400
        token = get_token()
        if dep_url:
            alarms = fetch_alarms_for_deployment(dep_url, token, int(start_ms), int(end_ms))
            events = fetch_events_for_deployment(dep_url, token, int(start_ms), int(end_ms))
        else:
            headers = {'Authorization': f'Bearer {token}'}
            params  = {'timestamp_received_gte': start_ms,
                       'timestamp_received_lte': end_ms,
                       'sort': 'timestamp_received,desc', 'suppressed': False}
            alarms  = fetch_all_parallel('alarms', params, headers)
            events  = fetch_all_parallel('events',
                                         {k: v for k, v in params.items() if k != 'suppressed'},
                                         headers)
        return jsonify({
            'alarm_data':  process_alarms(alarms) if alarms else {},
            'event_data':  process_events(events) if events else {},
            'alarm_count': len(alarms),
            'event_count': len(events),
        })
    except Exception:
        logger.exception("alienvault_fetch error")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/alienvault/export', methods=['POST'])
@require_dept('Research and Intelligence')
@limiter.limit("10 per minute")
def alienvault_export():
    from apps.alienvault.logic import (
        get_token, fetch_all_parallel,
        fetch_alarms_for_deployment, fetch_events_for_deployment,
        process_alarms, process_events, export_to_excel,
    )
    d        = request.get_json(force=True, silent=True) or {}
    dep_url  = str(d.get('dep_url', '')).strip()
    start_ms = d.get('start_ms')
    end_ms   = d.get('end_ms')
    if start_ms is None or end_ms is None:
        return jsonify({"error": "start_ms and end_ms are required"}), 400
    # Type-cast and SSRF protection
    try:
        start_ms = int(start_ms)
        end_ms   = int(end_ms)
    except (TypeError, ValueError):
        return jsonify({"error": "start_ms and end_ms must be integers"}), 400
    if dep_url and not _validate_av_url(dep_url):
        logger.warning(f"SSRF attempt blocked (export): dep_url={dep_url!r} from {request.remote_addr}")
        return jsonify({"error": "Invalid deployment URL"}), 400
    try:
        token = get_token()
        if dep_url:
            alarms = fetch_alarms_for_deployment(dep_url, token, start_ms, end_ms)
            events = fetch_events_for_deployment(dep_url, token, start_ms, end_ms)
        else:
            headers = {'Authorization': f'Bearer {token}'}
            params  = {'timestamp_received_gte': start_ms,
                       'timestamp_received_lte': end_ms,
                       'sort': 'timestamp_received,desc', 'suppressed': False}
            alarms  = fetch_all_parallel('alarms', params, headers)
            events  = fetch_all_parallel('events',
                                         {k: v for k, v in params.items() if k != 'suppressed'},
                                         headers)
        buf = export_to_excel(process_alarms(alarms) if alarms else {},
                              process_events(events)  if events else {})
        return send_file(buf, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                         as_attachment=True, download_name='alienvault_report.xlsx')
    except Exception:
        logger.exception("alienvault_export error")
        return jsonify({"error": "Internal server error"}), 500


# ════════════════════════════════════════════════════════════════════════════
#  Attendance routes
# ════════════════════════════════════════════════════════════════════════════

@app.route('/api/attendance/process', methods=['POST'])
@require_dept('People and Culture')
@limiter.limit("20 per minute")
def attendance_process():
    from apps.attendance.logic import process_access_logs, compute_late_standard, compute_soc_late_absent

    # Validate all uploaded files before reading any of them
    all_uploads = list(request.files.values())
    if not all_uploads:
        return jsonify({'error': 'No files uploaded'}), 400
    for f in all_uploads:
        if _safe_ext(f.filename) not in _ALLOWED_ATTENDANCE_EXT:
            return jsonify({'error': f'Invalid file type "{_safe_ext(f.filename)}". Allowed: xlsx, xls, csv'}), 400

    logs = [{'name': f.filename, 'data': f.read()}
            for k, f in request.files.items() if k.startswith('log')]
    roster = request.files.get('roster')
    soc    = request.files.get('soc')
    roster_info = {'name': roster.filename, 'data': roster.read()} if roster else None
    soc_info    = {'name': soc.filename,    'data': soc.read()}    if soc    else None
    if not logs:
        return jsonify({'error': 'No log files uploaded'}), 400
    try:
        df_entry = process_access_logs(logs)
        return jsonify({
            'standard': compute_late_standard(df_entry, roster_info),
            'soc':      compute_soc_late_absent(df_entry, soc_info),
        })
    except Exception:
        logger.exception("attendance_process error")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/attendance/export', methods=['POST'])
@require_dept('People and Culture')
@limiter.limit("10 per minute")
def attendance_export():
    from apps.attendance.logic import export_report
    d = request.get_json(force=True)
    try:
        buf = export_report(d.get('data', {}), d.get('type', 'report'))
        return send_file(buf, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                         as_attachment=True, download_name='attendance_report.xlsx')
    except Exception:
        logger.exception("attendance_export error")
        return jsonify({"error": "Internal server error"}), 500

# ════════════════════════════════════════════════════════════════════════════
#  Conversion routes
# ════════════════════════════════════════════════════════════════════════════

@app.route('/api/conversion/convert', methods=['POST'])
@require_dept('Research and Intelligence')
@limiter.limit("20 per minute")
def conversion_convert():
    from apps.conversion.logic import convert_pdf_to_xlsx
    pdf = request.files.get('pdf')
    if not pdf:
        return jsonify({'error': 'No PDF uploaded'}), 400
    if _safe_ext(pdf.filename) not in _ALLOWED_CONVERSION_EXT:
        return jsonify({'error': 'Invalid file type. Only PDF files are accepted.'}), 400
    try:
        buf  = convert_pdf_to_xlsx(pdf.read())
        name = os.path.splitext(pdf.filename or 'file')[0]
        return send_file(buf, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                         as_attachment=True, download_name=f'{name}_converted.xlsx')
    except Exception:
        logger.exception("conversion_convert error")
        return jsonify({"error": "Internal server error"}), 500

# ════════════════════════════════════════════════════════════════════════════
#  SentinelOne NFR routes
# ════════════════════════════════════════════════════════════════════════════

@app.route('/api/sentinel-nfr/sites')
@require_dept('Research and Intelligence')
def s1_nfr_sites():
    from apps.sentinel_nfr.logic import fetch_sites
    try:
        return jsonify({'sites': [{'id': s.get('id'), 'name': s.get('name')} for s in fetch_sites()]})
    except Exception:
        logger.exception("s1_nfr_sites error")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/sentinel-nfr/fetch', methods=['POST'])
@require_dept('Research and Intelligence')
@limiter.limit("30 per minute")
def s1_nfr_fetch():
    from apps.sentinel_nfr.logic import (fetch_endpoints_for_site, fetch_threats_for_site,
        fetch_risks_for_site, fetch_blocklisted_hashes_for_site, build_site_summary)
    d = request.get_json(silent=True) or {}
    site_id    = d.get('site_id')
    start_iso  = d.get('start_iso')
    end_iso    = d.get('end_iso')
    if not site_id or not start_iso or not end_iso:
        return jsonify({'error': 'site_id, start_iso and end_iso are required'}), 400
    try:
        ep    = fetch_endpoints_for_site(site_id)
        th    = fetch_threats_for_site(site_id, start_iso, end_iso)
        ri    = fetch_risks_for_site(site_id, start_iso, end_iso)
        dh, _ = fetch_blocklisted_hashes_for_site(site_id)
        summ  = build_site_summary(d.get('site_name', ''), th, ri, ep, dh, _)
        return jsonify({k: (v.to_dict(orient='records') if hasattr(v, 'to_dict') else v)
                        for k, v in summ.items()})
    except Exception:
        logger.exception("s1_nfr_fetch error")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/sentinel-nfr/export', methods=['POST'])
@require_dept('Research and Intelligence')
@limiter.limit("10 per minute")
def s1_nfr_export():
    from apps.sentinel_nfr.logic import (fetch_endpoints_for_site, fetch_threats_for_site,
        fetch_risks_for_site, fetch_blocklisted_hashes_for_site, build_site_summary, export_site_to_excel)
    d = request.get_json(force=True)
    try:
        ep    = fetch_endpoints_for_site(d['site_id'])
        th    = fetch_threats_for_site(d['site_id'], d['start_iso'], d['end_iso'])
        ri    = fetch_risks_for_site(d['site_id'], d['start_iso'], d['end_iso'])
        dh, _ = fetch_blocklisted_hashes_for_site(d['site_id'])
        summ  = build_site_summary(d.get('site_name',''), th, ri, ep, dh, _)
        buf   = export_site_to_excel(summ)
        return send_file(buf, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                         as_attachment=True, download_name=f"s1_nfr_{d.get('site_name','')}.xlsx")
    except Exception:
        logger.exception("s1_nfr_export error")
        return jsonify({"error": "Internal server error"}), 500

# ════════════════════════════════════════════════════════════════════════════
#  SentinelOne Exclusive routes
# ════════════════════════════════════════════════════════════════════════════

@app.route('/api/sentinel-excl/sites')
@require_dept('Research and Intelligence')
def s1_excl_sites():
    from apps.sentinel_excl.logic import fetch_sites
    try:
        return jsonify({'sites': [{'id': s.get('id'), 'name': s.get('name')} for s in fetch_sites()]})
    except Exception:
        logger.exception("s1_excl_sites error")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/sentinel-excl/fetch', methods=['POST'])
@require_dept('Research and Intelligence')
@limiter.limit("30 per minute")
def s1_excl_fetch():
    from apps.sentinel_excl.logic import (fetch_endpoints_for_site, fetch_threats_for_site,
        fetch_risks_for_site, fetch_blocklisted_hashes_for_site)
    from apps.sentinel_nfr.logic import build_site_summary
    d = request.get_json(force=True)
    try:
        ep    = fetch_endpoints_for_site(d['site_id'])
        th    = fetch_threats_for_site(d['site_id'], d['start_iso'], d['end_iso'])
        ri    = fetch_risks_for_site(d['site_id'], d['start_iso'], d['end_iso'])
        dh, _ = fetch_blocklisted_hashes_for_site(d['site_id'])
        summ  = build_site_summary(d.get('site_name',''), th, ri, ep, dh, _)
        return jsonify({k: (v.to_dict(orient='records') if hasattr(v,'to_dict') else v)
                        for k, v in summ.items()})
    except Exception:
        logger.exception("s1_excl_fetch error")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/sentinel-excl/export', methods=['POST'])
@require_dept('Research and Intelligence')
@limiter.limit("10 per minute")
def s1_excl_export():
    from apps.sentinel_excl.logic import (fetch_endpoints_for_site, fetch_threats_for_site,
        fetch_risks_for_site, fetch_blocklisted_hashes_for_site)
    from apps.sentinel_nfr.logic import build_site_summary, export_site_to_excel
    d = request.get_json(force=True)
    try:
        ep    = fetch_endpoints_for_site(d['site_id'])
        th    = fetch_threats_for_site(d['site_id'], d['start_iso'], d['end_iso'])
        ri    = fetch_risks_for_site(d['site_id'], d['start_iso'], d['end_iso'])
        dh, _ = fetch_blocklisted_hashes_for_site(d['site_id'])
        summ  = build_site_summary(d.get('site_name',''), th, ri, ep, dh, _)
        buf   = export_site_to_excel(summ)
        return send_file(buf, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                         as_attachment=True, download_name=f"s1_excl_{d.get('site_name','')}.xlsx")
    except Exception:
        logger.exception("s1_excl_export error")
        return jsonify({"error": "Internal server error"}), 500

# ════════════════════════════════════════════════════════════════════════════
#  Security headers (Flask layer)
# ════════════════════════════════════════════════════════════════════════════

IS_PRODUCTION = os.environ.get("RAILWAY_ENVIRONMENT") == "production"

@app.after_request
def security_headers(response):
    # Prevent MIME sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Clickjacking protection — SAMEORIGIN allows same-origin iframe embedding
    # (used by the app viewer). Cross-origin framing is still fully blocked.
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # Referrer leakage control
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Restrict browser features
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    # Content Security Policy — nonce-based (no unsafe-inline)
    nonce = getattr(g, 'csp_nonce', '')
    response.headers['Content-Security-Policy'] = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-src 'self'; "          # allow same-origin app viewer iframe
        "frame-ancestors 'self';"     # allow same-origin framing only
    )
    # HSTS — only on Railway (HTTPS termination is handled by Railway proxy)
    if IS_PRODUCTION:
        response.headers['Strict-Transport-Security'] = (
            'max-age=31536000; includeSubDomains; preload'
        )
    # No caching for auth endpoints
    if request.path.startswith('/api/auth'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
        response.headers['Pragma'] = 'no-cache'
    return response

# ════════════════════════════════════════════════════════════════════════════
#  Error handlers
# ════════════════════════════════════════════════════════════════════════════

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(429)
def rate_limited(e):
    return jsonify({"error": "Too many requests. Please slow down."}), 429

@app.errorhandler(500)
def internal_error(e):
    logger.exception("Unhandled 500 error")
    return jsonify({"error": "Internal server error"}), 500

# ════════════════════════════════════════════════════════════════════════════
#  Entry point (local dev only — production uses uvicorn via asgi.py)
# ════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    logger.info(f'Sentrium Enterprise Server starting on http://localhost:{port}')
    app.run(host='0.0.0.0', port=port, debug=False)
