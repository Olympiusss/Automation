/**
 * Sentrium Enterprise — Auth Engine (auth.js)
 * ============================================
 * Server-side authentication via POST /api/auth/verify.
 * TOTP disabled per security policy.
 * Session managed via HttpOnly cookie (set by server).
 */

'use strict';

const SESSION_KEY = 'sentrium_session';

// ─── Session Management ───────────────────────────────────────────────────────
function getSession() {
    try { return JSON.parse(sessionStorage.getItem(SESSION_KEY)); } catch { return null; }
}

function setSession(userObj) {
    sessionStorage.setItem(SESSION_KEY, JSON.stringify({
        username:   userObj.username,
        department: userObj.department,
        role:       userObj.role,
        loginTime:  Date.now(),
    }));
}

function clearSession() {
    sessionStorage.removeItem(SESSION_KEY);
}

function isAuthenticated() {
    const s = getSession();
    if (!s) return false;
    // 8-hour client-side guard (server enforces this too via cookie TTL)
    if (Date.now() - s.loginTime > 8 * 60 * 60 * 1000) { clearSession(); return false; }
    return true;
}

// ─── Access Control ───────────────────────────────────────────────────────────
function canAccessDept(session, targetDept) {
    if (!session) return false;
    if (session.role === 'admin') return true;
    if (targetDept === 'All') return true;
    return session.department === targetDept;
}

// ─── Server-Side Login (replaces client-side SHA-256 + TOTP) ─────────────────
async function serverLogin(username, password) {
    try {
        const resp = await fetch('/api/auth/verify', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ username: username.trim(), password }),
            credentials: 'same-origin',   // ensures cookie is sent/received
        });
        const data = await resp.json();
        if (!resp.ok || !data.ok) {
            return { ok: false, error: data.error || 'Invalid credentials' };
        }
        setSession(data);
        return { ok: true, user: data };
    } catch (err) {
        return { ok: false, error: 'Network error. Please try again.' };
    }
}

// ─── Logout ───────────────────────────────────────────────────────────────────
async function serverLogout() {
    try {
        await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' });
    } catch (_) { /* best-effort */ }
    clearSession();
}

// ─── Verify server session is still live (used on page load) ─────────────────
async function verifyServerSession() {
    try {
        const resp = await fetch('/api/auth/me', { credentials: 'same-origin' });
        if (!resp.ok) { clearSession(); return false; }
        const data = await resp.json();
        if (data.authenticated) {
            // Refresh client-side session data from server
            setSession(data);
            return true;
        }
        clearSession();
        return false;
    } catch (_) {
        return false;
    }
}

// Export to global scope
window.SentriumAuth = {
    serverLogin,
    serverLogout,
    verifyServerSession,
    setSession,
    getSession,
    clearSession,
    isAuthenticated,
    canAccessDept,
    SESSION_KEY,
};
