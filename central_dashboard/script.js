/**
 * Sentrium Enterprise Solution — Main Dashboard Script
 * =====================================================
 * Handles: auth guard, tab rendering with access control,
 * card rendering, and department-level permission enforcement.
 */

'use strict';

// ─── Application Data ────────────────────────────────────────
const applications = [
    {
        id: 'ri-alienvault',
        name: 'AlienVault Reporting Solution',
        department: 'Research and Intelligence',
        description: 'Comprehensive Security Visibility on Security Alarms and Events.',
        icon: '<svg viewBox="0 0 44 44" width="44" height="44" style="border-radius:10px;display:block"><rect width="44" height="44" rx="10" fill="#0d1a40"/><g transform="translate(7,4) rotate(-18,15,17)"><rect x="0" y="0" width="9" height="29" rx="2.5" fill="#1a3aff"/><rect x="12" y="5" width="9" height="27" rx="2.5" fill="#00b4ff"/><rect x="24" y="10" width="9" height="24" rx="2.5" fill="#ccff00"/></g></svg>'
    },
    {
        id: 'ri-conversion',
        name: 'WAF Conversion Solution',
        department: 'Research and Intelligence',
        description: 'Convert WAF Intelligence Reports into structured Excel spreadsheets.',
        icon: '<img src="logo_transparent.png" width="44" height="44" style="border-radius:10px;display:block;object-fit:contain;background:#fff;" alt="Sentrium">'
    },
    {
        id: 'ri-sentinelone',
        name: 'SentinelOne Reporting Solution',
        department: 'Research and Intelligence',
        description: 'Unified interface for SentinelOne environments — choose NFR or Exclusive reporting.',
        icon: '<img src="sentinelone-logo.png" width="44" height="44" style="border-radius:10px;display:block;object-fit:contain;background:#fff;" alt="SentinelOne">',
        subApps: [
            {
                id:          'ri-s1-nfr',
                label:       'NFR',
                description: 'Standardized data aggregation and unified interface to query the S1 NFR environment.'
            },
            {
                id:          'ri-s1-exclusive',
                label:       'Exclusive',
                description: 'Standardized data aggregation and unified interface to query the S1 Exclusive environment.'
            }
        ]
    },
    {
        id: 'pc-attendance',
        name: 'Sentrium Attendance Tracker',
        department: 'People and Culture',
        description: 'Streamlined employee attendance, seamless daily check-ins, and accurate shift tracking.',
        icon: '<img src="logo_transparent.png" width="44" height="44" style="border-radius:10px;display:block;object-fit:contain;background:#fff;" alt="Sentrium">'
    },
    {
        id: 'ops-dashboard',
        name: 'Sentrium Operational Assessment Solution',
        department: 'Operations',
        description: 'An evidence-driven Operational Assessment Solution.',
        icon: '<img src="logo_transparent.png" width="44" height="44" style="border-radius:10px;display:block;object-fit:contain;background:#fff;" alt="Sentrium">'
    },
    {
        id: 'so-soc-dashboard',
        name: 'MSSP Client SOC Portal',
        department: 'Security Operations',
        description: 'Real-time client threat visibility, alert triage, and analyst oversight across all monitored environments.',
        icon: '<img src="logo_transparent.png" width="44" height="44" style="border-radius:10px;display:block;object-fit:contain;background:#fff;" alt="Sentrium">'
    }
];


const ALL_DEPTS = [
    'Security Testing', 'Security Operations', 'Brand & Marketing',
    'People and Culture', 'Research and Intelligence', 'IT Infrastructure',
    'Operations', 'Finance', 'Sales', 'Customer Success',
    'Security Engineering', 'Portfolio Management'
];

const deptColors = {
    'All':                      'blue',
    'Security Testing':         'blue',
    'Security Operations':      'gray',
    'Brand & Marketing':        'blue',
    'People and Culture':       'gray',
    'Research and Intelligence':'blue',
    'IT Infrastructure':        'gray',
    'Operations':               'blue',
    'Finance':                  'gray',
    'Sales':                    'blue',
    'Customer Success':         'gray',
    'Security Engineering':     'blue',
    'Portfolio Management':     'gray'
};

// Professional SVG icon factory (no emojis)
const SVG_ICONS = {
    globe: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
    shield: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
    chart: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>',
    users: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>',
    server: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>',
    gear: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
    star: '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="1"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>',
    building: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="2" width="16" height="20" rx="2" ry="2"/><path d="M9 22v-4h6v4"/><line x1="8" y1="6" x2="8.01" y2="6"/><line x1="16" y1="6" x2="16.01" y2="6"/><line x1="8" y1="10" x2="8.01" y2="10"/><line x1="16" y1="10" x2="16.01" y2="10"/><line x1="8" y1="14" x2="8.01" y2="14"/><line x1="16" y1="14" x2="16.01" y2="14"/></svg>'
};

const getTabIcon = dept => {
    if (dept === 'All')           return SVG_ICONS.globe;
    if (dept.includes('Security'))return SVG_ICONS.shield;
    if (dept.includes('Sales') || dept.includes('Finance') || dept.includes('Marketing')) return SVG_ICONS.chart;
    if (dept.includes('People') || dept.includes('Customer')) return SVG_ICONS.users;
    if (dept.includes('IT') || dept.includes('Portfolio')) return SVG_ICONS.server;
    return SVG_ICONS.gear;
};

// ─── State ───────────────────────────────────────────────────
let currentFilter = 'All';
let currentSession = null;

// ─── DOM refs ────────────────────────────────────────────────
const tabsContainer  = document.getElementById('tabs-container');
const appsGrid       = document.getElementById('apps-grid');
const accessModal    = document.getElementById('access-modal');
const modalDeptName  = document.getElementById('modal-dept-name');
const modalCloseBtn  = document.getElementById('modal-close-btn');
const topbarName     = document.getElementById('topbar-name');
const topbarDept     = document.getElementById('topbar-dept');
const btnLogout      = document.getElementById('btn-logout');

// ─── Auth Guard ──────────────────────────────────────────────
function authGuard() {
    if (!SentriumAuth.isAuthenticated()) {
        window.location.replace('login.html');
        return false;
    }
    currentSession = SentriumAuth.getSession();
    return true;
}

// ─── Topbar ──────────────────────────────────────────────────
function renderTopbar() {
    const s = currentSession;
    topbarName.textContent = s.username;
    topbarDept.innerHTML = s.role === 'admin'
        ? `${SVG_ICONS.star} Administrator`
        : `${SVG_ICONS.building} ${s.department}`;
    // Expose role globally so the User Management panel can show/hide the button
    window.__userRole = s.role;
}

// ─── Logout ──────────────────────────────────────────────────
btnLogout.addEventListener('click', () => {
    SentriumAuth.clearSession();
    window.location.replace('login.html');
});

// ─── Access Denied Modal ──────────────────────────────────────
function showAccessDenied(deptName) {
    modalDeptName.textContent = deptName;
    accessModal.classList.add('open');
    // Shake & bounce entrance handled by CSS animation
}

function closeModal() {
    accessModal.classList.remove('open');
}

modalCloseBtn.addEventListener('click', closeModal);
accessModal.addEventListener('click', e => { if (e.target === accessModal) closeModal(); });

// ─── Tab Rendering ───────────────────────────────────────────
function renderTabs() {
    tabsContainer.innerHTML = '';
    const deptsToRender = ['All', ...ALL_DEPTS];

    deptsToRender.forEach(dept => {
        const hasAccess = SentriumAuth.canAccessDept(currentSession, dept);
        const btn = document.createElement('button');
        btn.className = `tab ${dept === currentFilter ? 'active' : ''} ${!hasAccess ? 'tab-locked' : ''}`;
        btn.dataset.dept  = dept;
        btn.dataset.color = deptColors[dept] || 'gray';

        const icon   = getTabIcon(dept);
        const lockBadge = !hasAccess ? ' 🔒' : '';
        btn.innerHTML = `<span class="tab-icon">${icon}</span> ${dept === 'All' ? 'All Departments' : dept}${lockBadge}`;

        btn.addEventListener('click', () => {
            if (!SentriumAuth.canAccessDept(currentSession, dept)) {
                showAccessDenied(dept);
                return;
            }
            currentFilter = dept;
            updateTabStyles();
            renderCards();
            window.scrollTo({ top: 0, behavior: 'smooth' });
        });

        tabsContainer.appendChild(btn);
    });
}

function updateTabStyles() {
    document.querySelectorAll('.tab').forEach(tab => {
        tab.classList.toggle('active', tab.dataset.dept === currentFilter);
    });
}

// ─── Card Rendering ───────────────────────────────────────────
function renderCards() {
    appsGrid.style.opacity = 0;

    setTimeout(() => {
        appsGrid.innerHTML = '';

        // Determine which apps to show
        let filteredApps;
        if (currentFilter === 'All') {
            // Admin + 'All'-dept users see every app; other dept users see their own
            filteredApps = (currentSession.role === 'admin' || currentSession.department === 'All')
                ? applications
                : applications.filter(app => app.department === currentSession.department);
        } else {
            filteredApps = applications.filter(app => app.department === currentFilter);
        }

        if (filteredApps.length === 0) {
            appsGrid.innerHTML = `
                <div style="text-align:center;padding:60px 20px;color:var(--text-muted);">
                    <div style="font-size:3rem;margin-bottom:16px;">🔧</div>
                    <p style="font-size:1.1rem;font-weight:600;">No applications available for this department yet.</p>
                    <p style="font-size:0.9rem;margin-top:8px;opacity:0.7;">Contact your administrator to add application URLs.</p>
                </div>`;
        }

        filteredApps.forEach((app, index) => {
            const card = document.createElement('div');
            card.className = 'card';
            card.style.setProperty('--card-index', index);
            card.style.animationDelay = `${index * 0.12}s`;
            card.setAttribute('role', 'button');
            card.setAttribute('tabindex', '0');

            card.innerHTML = `
                <div class="card-dept">${app.department}</div>
                <div class="card-header">
                    <div class="card-icon">${app.icon}</div>
                    <h3>${app.name}</h3>
                </div>
                <p>${app.description}</p>
            `;

            card.addEventListener('click', () => {
                if (app.subApps && app.subApps.length) {
                    showSubAppPicker(app);
                } else {
                    openApp(app.id);
                }
            });
            card.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    if (app.subApps && app.subApps.length) {
                        showSubAppPicker(app);
                    } else {
                        openApp(app.id);
                    }
                }
            });

            appsGrid.appendChild(card);
        });

        appsGrid.style.transition  = 'opacity 0.35s ease';
        appsGrid.style.opacity     = 1;
    }, 150);
}

// ─── Native App Viewer (no iframes, no external URLs) ────────────────────────
let activeApp = null;

const appViewer      = document.getElementById('app-viewer');
const appViewerIcon  = document.getElementById('app-viewer-icon');
const appViewerTitle = document.getElementById('app-viewer-title');
const appViewerDept  = document.getElementById('app-viewer-dept');
const appViewerLoader= document.getElementById('app-viewer-loader');
const appIframe      = document.getElementById('app-viewer-content');  // now an <iframe>

const btnViewerBack   = document.getElementById('btn-viewer-back');

function openApp(appId) {
    // Search top-level apps first, then inside any subApps arrays
    let app = applications.find(a => a.id === appId);
    if (!app) {
        for (const parent of applications) {
            if (!parent.subApps) continue;
            const sub = parent.subApps.find(s => s.id === appId);
            if (sub) {
                // Build a virtual app entry from the parent + sub data
                app = {
                    id:          sub.id,
                    name:        parent.name.replace('Reporting Solution', '').trim() + ' ' + sub.label + ' Reporting',
                    department:  parent.department,
                    description: sub.description,
                    icon:        parent.icon,
                };
                break;
            }
        }
    }
    if (!app) return;

    if (!SentriumAuth.canAccessDept(currentSession, app.department)) {
        showAccessDenied(app.department);
        return;
    }

    // External apps (separate servers) open in a new tab
    if (app.externalUrl) {
        window.open(app.externalUrl, '_blank', 'noopener,noreferrer');
        return;
    }

    activeApp = app;
    appViewerIcon.innerHTML    = app.icon;
    appViewerTitle.textContent = app.name;
    appViewerDept.textContent  = app.department;

    // Show loader while iframe loads
    appViewerLoader.style.display = 'flex';
    appViewerLoader.style.opacity = '1';
    appViewer.classList.add('open');
    document.body.style.overflow = 'hidden';
    window.location.hash = `app=${app.id}`;

    // Pass session to iframe via localStorage so the app can read it
    try { localStorage.setItem('__sentrium_session', JSON.stringify(currentSession)); } catch {}

    // Hide loader once iframe has loaded
    appIframe.onload = () => {
        appViewerLoader.style.opacity = '0';
        setTimeout(() => { appViewerLoader.style.display = 'none'; }, 300);
    };
    appIframe.onerror = () => {
        appViewerLoader.style.display = 'none';
    };

    // Same-origin iframe — just set the src
    appIframe.src = `/apps/${app.id}`;
}

// ─── Sub-App Picker ────────────────────────────────────────────
(function injectPickerStyles() {
    const s = document.createElement('style');
    s.textContent = `
    .sp-overlay {
        display: none; position: fixed; inset: 0;
        background: rgba(15,23,42,0.6); backdrop-filter: blur(10px);
        z-index: 6000; align-items: center; justify-content: center;
    }
    .sp-overlay.open { display: flex; animation: sp-in 0.25s ease both; }
    @keyframes sp-in { from{opacity:0;transform:scale(0.94);} to{opacity:1;transform:none;} }
    .sp-box {
        background: #fff; border-radius: 24px;
        padding: 36px 32px 32px; width: 480px; max-width: 94vw;
        box-shadow: 0 32px 80px rgba(0,0,0,0.22);
        border: 1px solid rgba(0,0,0,0.06);
    }
    .sp-header { display:flex; align-items:center; gap:14px; margin-bottom:8px; }
    .sp-header-icon { width:46px; height:46px; flex-shrink:0; }
    .sp-title { font-size:1.15rem; font-weight:800; color:#0f172a; letter-spacing:-0.3px; }
    .sp-subtitle { font-size:0.85rem; color:#64748b; margin-bottom:24px; margin-top:4px; }
    .sp-options { display:flex; flex-direction:column; gap:12px; }
    .sp-option {
        display: flex; align-items: center; gap: 16px;
        padding: 18px 20px; border-radius: 16px;
        border: 1.5px solid rgba(37,99,235,0.15);
        background: #f8faff; cursor: pointer;
        transition: all 0.2s ease;
        text-align: left;
    }
    .sp-option:hover {
        border-color: #2563eb;
        background: rgba(37,99,235,0.05);
        transform: translateY(-2px);
        box-shadow: 0 8px 24px rgba(37,99,235,0.12);
    }
    .sp-option-badge {
        width: 48px; height: 48px; border-radius: 12px;
        overflow: hidden; flex-shrink: 0;
        background: #fff;
        display: flex; align-items: center; justify-content: center;
    }
    .sp-option-badge img { width:48px; height:48px; object-fit:contain; display:block; }
    .sp-option-label { font-size:1rem; font-weight:700; color:#0f172a; }
    .sp-option-desc  { font-size:0.8rem; color:#64748b; margin-top:3px; line-height:1.4; }
    .sp-option-arrow { margin-left:auto; color:#2563eb; opacity:0.6; flex-shrink:0; }
    .sp-cancel {
        margin-top:20px; width:100%; padding:11px;
        background:none; border:1px solid rgba(0,0,0,0.1);
        border-radius:12px; font-size:0.88rem; font-weight:600;
        color:#64748b; cursor:pointer; transition:all 0.15s;
    }
    .sp-cancel:hover { background:rgba(0,0,0,0.04); }
    `;
    document.head.appendChild(s);

    // Create overlay element
    const overlay = document.createElement('div');
    overlay.id = 'sp-overlay';
    overlay.className = 'sp-overlay';
    overlay.innerHTML = `
      <div class="sp-box" id="sp-box">
        <div class="sp-header">
          <div class="sp-header-icon" id="sp-hdr-icon"></div>
          <div class="sp-title" id="sp-hdr-title"></div>
        </div>
        <div class="sp-subtitle" id="sp-hdr-sub">Select which environment to open:</div>
        <div class="sp-options" id="sp-options"></div>
        <button class="sp-cancel" id="sp-cancel">Cancel</button>
      </div>`;
    document.body.appendChild(overlay);

    overlay.addEventListener('click', e => { if (e.target === overlay) closePicker(); });
    document.getElementById('sp-cancel').addEventListener('click', closePicker);
    document.addEventListener('keydown', e => { if (e.key === 'Escape') closePicker(); });
})();

function closePicker() {
    const overlay = document.getElementById('sp-overlay');
    if (overlay) overlay.classList.remove('open');
}

function showSubAppPicker(app) {
    if (!SentriumAuth.canAccessDept(currentSession, app.department)) {
        showAccessDenied(app.department);
        return;
    }
    const overlay = document.getElementById('sp-overlay');
    document.getElementById('sp-hdr-icon').innerHTML = app.icon;
    document.getElementById('sp-hdr-title').textContent = app.name;

    // Build buttons via DOM API — inline onclick is blocked by nonce-based CSP
    const optionsEl = document.getElementById('sp-options');
    optionsEl.innerHTML = '';
    app.subApps.forEach(sub => {
        const btn = document.createElement('button');
        btn.className = 'sp-option';
        btn.innerHTML = `
            <div class="sp-option-badge"><img src="sentinelone-logo.png" alt="SentinelOne"></div>
            <div>
                <div class="sp-option-label">${app.name.replace('Reporting Solution','').trim()} ${sub.label}</div>
                <div class="sp-option-desc">${sub.description}</div>
            </div>
            <svg class="sp-option-arrow" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>`;
        btn.addEventListener('click', () => {
            closePicker();
            openApp(sub.id);
        });
        optionsEl.appendChild(btn);
    });

    overlay.classList.add('open');
}

function closeApp() {
    activeApp = null;
    appViewer.classList.remove('open');
    document.body.style.overflow = '';
    appIframe.src = '';  // stops the app and frees memory
    appViewerLoader.style.display = 'none';
    if (window.location.hash.startsWith('#app=')) {
        history.replaceState(null, document.title, window.location.pathname + window.location.search);
    }
}

btnViewerBack.addEventListener('click', closeApp);

window.addEventListener('keydown', e => {
    if (e.key === 'Escape' && activeApp) closeApp();
});

function handleHashRoute() {
    const hash = window.location.hash;
    if (hash.startsWith('#app=')) {
        const appId = hash.substring(5);
        if (!activeApp || activeApp.id !== appId) openApp(appId);
    } else {
        if (activeApp) closeApp();
    }
}

window.addEventListener('hashchange', handleHashRoute);

// ─── Bootstrap ───────────────────────────────────────────────
function init() {
    if (!authGuard()) return;  // Redirect if not logged in
    renderTopbar();
    renderTabs();

    // Default filter: dept users start on their own dept tab
    if (currentSession.role !== 'admin' && currentSession.department !== 'All') {
        currentFilter = currentSession.department;
        updateTabStyles();
    }

    renderCards();
    handleHashRoute();      // Deep link support
    startSacredGeometry();  // Launch the 4D animation
}

// ═══════════════════════════════════════════════════════════════
// Sacred Geometry 4D Animation Engine
// Cycles: Cosmic Orb → Seed of Life → Flower of Life → repeat
// ═══════════════════════════════════════════════════════════════
function startSacredGeometry() {
    var canvas = document.getElementById('sacred-canvas');
    if (!canvas) return;
    var ctx = canvas.getContext('2d');
    var container = canvas.parentElement;

    var dpr = window.devicePixelRatio || 1;
    var W = 0, H = 0, cx = 0, cy = 0;

    function resize() {
        var rect = container.getBoundingClientRect();
        W = rect.width || 500;
        H = rect.height || 550;
        canvas.width = W * dpr;
        canvas.height = H * dpr;
        canvas.style.width = W + 'px';
        canvas.style.height = H + 'px';
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        cx = W / 2;
        cy = H / 2;
    }
    resize();
    window.addEventListener('resize', resize);

    // Colors (partial rgba — append alpha + ")")
    var CC = 'rgba(6,182,212,';
    var CB = 'rgba(37,99,235,';
    var CI = 'rgba(79,70,229,';
    var CL = 'rgba(96,165,250,';
    var CW = 'rgba(255,255,255,';

    var PHASES = 3, PDUR = 8000, FDUR = 2000;
    var t0 = performance.now();

    // 3D math
    function rY(x,z,a){var c=Math.cos(a),s=Math.sin(a);return{x:x*c+z*s,z:-x*s+z*c};}
    function rX(y,z,a){var c=Math.cos(a),s=Math.sin(a);return{y:y*c-z*s,z:y*s+z*c};}
    function pj(x,y,z){var s=600/(600+z);return{x:cx+x*s,y:cy+y*s,s:s};}

    // Draw a 3D ring
    function ring3D(rad,tX,tY,tm,col,al,lw){
        ctx.beginPath();
        for(var i=0;i<=72;i++){
            var a=(i/72)*Math.PI*2;
            var x=Math.cos(a)*rad,y=Math.sin(a)*rad,z=0;
            var r1=rY(x,z,tY+tm*0.2);x=r1.x;z=r1.z;
            var r2=rX(y,z,tX);y=r2.y;z=r2.z;
            var p=pj(x,y,z);
            i===0?ctx.moveTo(p.x,p.y):ctx.lineTo(p.x,p.y);
        }
        ctx.strokeStyle=col+al+')';
        ctx.lineWidth=lw;
        ctx.stroke();
    }

    // Draw a sacred circle in 3D
    function sacCirc(ox,oy,r,tm,op,col,lw){
        ctx.beginPath();
        var tX=Math.sin(tm*0.4)*0.35;
        var tY=Math.cos(tm*0.3)*0.35;
        for(var i=0;i<=60;i++){
            var a=(i/60)*Math.PI*2;
            var x=ox+Math.cos(a)*r;
            var y=oy+Math.sin(a)*r;
            var z=Math.sin(a*2+tm)*18;
            var r1=rY(x,z,tY);x=r1.x;z=r1.z;
            var r2=rX(y,z,tX);y=r2.y;z=r2.z;
            var p=pj(x,y,z);
            i===0?ctx.moveTo(p.x,p.y):ctx.lineTo(p.x,p.y);
        }
        ctx.strokeStyle=col+(op*0.85)+')';
        ctx.lineWidth=lw*op;
        ctx.stroke();
    }

    // PHASE 0: Cosmic Orb
    function drawOrb(t,op){
        var T=t*0.001;
        ring3D(130,T*0.7,T*0.5,0,CI,op*0.9,5*op);
        ring3D(100,-T*0.6,T*0.8+1,0,CC,op*0.7,3*op);
        ctx.setLineDash([8,12]);
        ring3D(75,T*0.4,-T*0.3,0,CL,op*0.6,2*op);
        ctx.setLineDash([]);
        var pulse=1+Math.sin(T*2)*0.15;
        var cR=45*pulse;
        var g=ctx.createRadialGradient(cx,cy,0,cx,cy,cR);
        g.addColorStop(0,CW+(op*0.95)+')');
        g.addColorStop(0.35,CC+(op*0.8)+')');
        g.addColorStop(0.65,CB+(op*0.7)+')');
        g.addColorStop(1,CI+(op*0.3)+')');
        ctx.beginPath();ctx.arc(cx,cy,cR,0,Math.PI*2);
        ctx.fillStyle=g;ctx.fill();
        var h=ctx.createRadialGradient(cx,cy,cR,cx,cy,cR+30);
        h.addColorStop(0,CC+(op*0.35)+')');
        h.addColorStop(1,CC+'0)');
        ctx.beginPath();ctx.arc(cx,cy,cR+30,0,Math.PI*2);
        ctx.fillStyle=h;ctx.fill();
    }

    // PHASE 1: Seed of Life (7 circles)
    function drawSeed(t,op){
        var T=t*0.001;
        var r=60*(1+Math.sin(T*1.5)*0.08);
        var rot=T*0.3;
        sacCirc(0,0,r,T,op,CB,2.5);
        for(var i=0;i<6;i++){
            var a=(i/6)*Math.PI*2+rot;
            sacCirc(Math.cos(a)*r,Math.sin(a)*r,r,T,op,CC,2);
        }
        var g=ctx.createRadialGradient(cx,cy,0,cx,cy,r*0.7);
        g.addColorStop(0,CW+(op*0.3)+')');
        g.addColorStop(1,CW+'0)');
        ctx.beginPath();ctx.arc(cx,cy,r*0.7,0,Math.PI*2);
        ctx.fillStyle=g;ctx.fill();
    }

    // PHASE 2: Flower of Life (19 circles)
    function drawFlower(t,op){
        var T=t*0.001;
        var r=42*(1+Math.sin(T*1.2)*0.06);
        var rot=T*0.2;
        sacCirc(0,0,r,T,op,CI,2);
        for(var i=0;i<6;i++){
            var a=(i/6)*Math.PI*2+rot;
            sacCirc(Math.cos(a)*r,Math.sin(a)*r,r,T,op,CB,1.8);
        }
        for(var j=0;j<6;j++){
            var a1=(j/6)*Math.PI*2+rot;
            sacCirc(Math.cos(a1)*r*2,Math.sin(a1)*r*2,r,T,op,CC,1.4);
            var a2=a1+Math.PI/6;
            var d=r*Math.sqrt(3);
            sacCirc(Math.cos(a2)*d,Math.sin(a2)*d,r,T,op,CL,1.1);
        }
        var g=ctx.createRadialGradient(cx,cy,0,cx,cy,r*1.5);
        g.addColorStop(0,CW+(op*0.2)+')');
        g.addColorStop(1,CW+'0)');
        ctx.beginPath();ctx.arc(cx,cy,r*1.5,0,Math.PI*2);
        ctx.fillStyle=g;ctx.fill();
    }

    // Floating particles
    var pts=[];
    for(var k=0;k<14;k++){
        pts.push({a:Math.random()*Math.PI*2,d:70+Math.random()*120,
            sp:0.15+Math.random()*0.4,z0:(Math.random()-0.5)*100,
            sz:1.5+Math.random()*3,ph:Math.random()*Math.PI*2});
    }
    function drawPts(t){
        var T=t*0.001;
        for(var j=0;j<pts.length;j++){
            var p=pts[j];
            var a=p.a+T*p.sp;
            var x=Math.cos(a)*p.d,y=Math.sin(a)*p.d;
            var z=p.z0+Math.sin(T*2+p.ph)*40;
            var r1=rY(x,z,T*0.15);x=r1.x;z=r1.z;
            var r2=rX(y,z,Math.sin(T*0.3)*0.2);y=r2.y;z=r2.z;
            var pr=pj(x,y,z);var s=p.sz*pr.s;
            ctx.beginPath();ctx.arc(pr.x,pr.y,s,0,Math.PI*2);
            ctx.fillStyle=CW+(0.75*pr.s)+')';ctx.fill();
            var gw=ctx.createRadialGradient(pr.x,pr.y,0,pr.x,pr.y,s*4);
            gw.addColorStop(0,CC+(0.3*pr.s)+')');
            gw.addColorStop(1,CC+'0)');
            ctx.beginPath();ctx.arc(pr.x,pr.y,s*4,0,Math.PI*2);
            ctx.fillStyle=gw;ctx.fill();
        }
    }

    // 4D Surge (screen pop-out)
    function doSurge(t){
        var T=t*0.001;
        var cyc=(T%22)/22;
        var sc=1,tx=0,ty=0;
        if(cyc>0.6&&cyc<0.72){
            var prog=(cyc-0.6)/0.12;
            var ease=Math.sin(prog*Math.PI);
            sc=1+ease*0.55;tx=Math.sin(T*3)*ease*10;ty=-ease*18;
        }
        ctx.translate(cx+tx,cy+ty);
        ctx.scale(sc,sc);
        ctx.translate(-cx,-cy);
    }

    // Main animation loop
    var drawFn=[drawOrb,drawSeed,drawFlower];
    var totalCyc=PDUR+FDUR;

    function frame(now){
        // Always schedule next frame first — never break the chain
        requestAnimationFrame(frame);
        try {
            var el=now-t0;
            // Re-apply base DPR transform (protects against resize context resets)
            ctx.setTransform(dpr,0,0,dpr,0,0);
            ctx.clearRect(0,0,W,H);
            ctx.save();
            doSurge(el);
            var cp=el%(totalCyc*PHASES);
            var pi=Math.floor(cp/totalCyc)%PHASES;
            var pt=cp%totalCyc;
            var ni=(pi+1)%PHASES;
            var co=1,no=0;
            if(pt>PDUR){var f=(pt-PDUR)/FDUR;co=1-f;no=f;}
            if(co>0.01)drawFn[pi](el,co);
            if(no>0.01)drawFn[ni](el,no);
            drawPts(el);
            ctx.restore();
        } catch(e) {
            // Silently recover — animation continues on next frame
        }
    }
    requestAnimationFrame(frame);
}

document.addEventListener('DOMContentLoaded', init);
