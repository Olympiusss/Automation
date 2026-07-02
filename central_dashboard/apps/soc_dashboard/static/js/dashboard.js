'use strict';
// Sentrium SOC — Per-Client Dashboard JS v9
// Executive theme, notifications, sparklines, skeletons

let ws = null, reconnectAttempts = 0, lastUpdateTime = null, _timer = null;
const $ = id => document.getElementById(id);

// ═══ THEME ═══
function getTheme() { return localStorage.getItem('soc-theme') || 'dark'; }
function setTheme(t) {
    document.documentElement.setAttribute('data-theme', t);
    localStorage.setItem('soc-theme', t);
    const di = document.getElementById('theme-icon-dark');
    const li = document.getElementById('theme-icon-light');
    const lb = document.getElementById('theme-label');
    if (t === 'dark') { if(di)di.style.display=''; if(li)li.style.display='none'; if(lb)lb.textContent='Dark'; }
    else { if(di)di.style.display='none'; if(li)li.style.display=''; if(lb)lb.textContent='Light'; }
}
function toggleTheme() { setTheme(getTheme() === 'dark' ? 'light' : 'dark'); }
(function initTheme() { setTheme(getTheme()); })();

// ═══ MOBILE ═══
function toggleMobileMenu() {
    const s = document.getElementById('sidebar');
    const o = document.getElementById('sidebar-overlay');
    const h = document.getElementById('hamburger');
    if (!s) return;
    s.classList.toggle('open');
    if (o) o.classList.toggle('visible');
    if (h) h.classList.toggle('active');
}
document.getElementById('sidebar-overlay')?.addEventListener('click', toggleMobileMenu);

// ═══ NOTIFICATIONS ═══
function showNotification(title, desc, type) {
    const c = document.getElementById('notification-container'); if (!c) return;
    const icons = { success: '<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>', error: '<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>', warning: '<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>', info: '<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>' };
    const t = document.createElement('div');
    t.className = 'toast toast-' + type;
    t.innerHTML = (icons[type] || icons.info) + '<div class="toast-content"><div class="toast-title">' + esc(title) + '</div>' + (desc ? '<div class="toast-desc">' + esc(desc) + '</div>' : '') + '</div><svg class="toast-close" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
    c.appendChild(t);
    t.addEventListener('click', () => { if (!t.classList.contains('toast-out')) { t.classList.add('toast-out'); setTimeout(() => t.remove(), 250); } });
    setTimeout(() => { if (!t.classList.contains('toast-out')) { t.classList.add('toast-out'); setTimeout(() => t.remove(), 250); } }, 5000);
}

// ═══ SPARKLINES ═══
function renderSparkline(elId, data, color) {
    const el = document.getElementById(elId);
    if (!el || !data || data.length < 2) { if (el) el.innerHTML = ''; return; }
    const values = data.map(d => d.value || 0);
    const w = 64, h = 34, p = 3;
    const min = Math.min(...values), max = Math.max(...values) || 1;
    const range = max - min || 1;
    const xStep = (w - p * 2) / (values.length - 1);
    const pts = values.map((v, i) => `${(i * xStep + p).toFixed(1)},${(h - p - ((v - min) / range) * (h - p * 2)).toFixed(1)}`);
    const line = pts.join(' ');
    const area = `M${pts[0]} L${pts.slice(1).join(' L')} L${pts[pts.length-1].split(',')[0]},${h - p} L${pts[0].split(',')[0]},${h - p} Z`;
    el.innerHTML = `<svg viewBox="0 0 ${w} ${h}"><defs><linearGradient id="g-${elId}" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="${color}" stop-opacity="0.2"/><stop offset="100%" stop-color="${color}" stop-opacity="0.01"/></linearGradient></defs><path class="sp-area" d="${area}" fill="url(#g-${elId})"/><path class="sp-fill" d="M${line}" stroke="${color}" fill="none" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
}

// ═══ SECTIONS ═══
function switchSection(sectionId) {
    document.querySelectorAll('.client-section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.client-nav-item').forEach(b => b.classList.remove('active'));
    const sec = $(sectionId); if (sec) sec.classList.add('active');
    const btn = document.querySelector(`.client-nav-item[data-section="${sectionId}"]`); if (btn) btn.classList.add('active');
}
document.querySelectorAll('.client-nav-item[data-section]').forEach(btn =>
    btn.addEventListener('click', () => switchSection(btn.dataset.section))
);

function applyPlatformNav(platforms) {
    const hasS1 = platforms.includes('SentinelOne');
    const hasAV = platforms.includes('AlienVault');
    const na = $('nav-alerts'); if (na) na.style.display = hasAV ? '' : 'none';
    const ne = $('nav-edr'); if (ne) ne.style.display = hasS1 ? '' : 'none';
    const as = document.querySelector('.client-section.active');
    if (as?.id === 'section-edr' && !hasS1) switchSection('section-overview');
    if (as?.id === 'section-alerts' && !hasAV) switchSection('section-overview');
}

// ═══ REST PRELOAD ═══
async function preload() {
    try { const r = await fetch(`/api/client/${encodeURIComponent(CLIENT_NAME)}/data`); if (r.ok) renderClient(await r.json()); }
    catch (e) { /* silent */ }
}

// ═══ WEBSOCKET ═══
function connectWS() {
    ws = new WebSocket(WS_URL);
    ws.onopen = () => {
        reconnectAttempts = 0;
        const o = $('reconnect-overlay'); if (o) o.classList.remove('visible');
    };
    ws.onmessage = e => {
        try {
            const d = JSON.parse(e.data);
            const client = (d.clients || []).find(c => c.name.toLowerCase() === CLIENT_NAME.toLowerCase());
            if (client) { renderClient(client); lastUpdateTime = new Date(); }
        } catch (_) { /* ignore */ }
    };
    ws.onclose = () => {
        reconnectAttempts++;
        if (reconnectAttempts > 2) { const o = $('reconnect-overlay'); if (o) o.classList.add('visible'); }
        if (reconnectAttempts === 1) showNotification('Disconnected', 'Reconnecting…', 'warning');
        setTimeout(connectWS, Math.min(reconnectAttempts * 2000, 15000));
    };
    ws.onerror = () => ws.close();
}

// ═══ MAIN RENDER ═══
function renderClient(c) {
    if (!c) return;
    const platforms = c.platforms || [];
    applyPlatformNav(platforms);

    const nameEl = $('sidebar-client-name'); if (nameEl) nameEl.textContent = c.name || CLIENT_NAME;
    const tagsEl = $('sidebar-plat-tags');
    if (tagsEl) tagsEl.innerHTML = platforms.map(p => p === 'SentinelOne' ? '<span class="cpill cpill-s1">S1</span>' : '<span class="cpill cpill-av">AV</span>').join('') || '—';

    const avTotal = c.av_total_alarms || 0;
    setKpi('kv-alarms',    avTotal,                        'No security alarms in 24h');
    setKpi('kv-threats',   c.total_threats   || 0,         'No S1 threats in 24h');
    setKpi('kv-endpoints', c.total_endpoints || 0,         '');
    setKpi('kv-hashes',    c.s1_blocklisted_hashes || 0,   'No blocklisted hashes');
    setKpi('kv-vuln-eps',  c.s1_vulnerable_endpoints || 0, 'No vulnerable endpoints');
    setKpi('kv-vuln-apps', c.s1_vulnerable_apps      || 0, 'No vulnerable apps in 24h');

    const tl = c.event_timeline || [];
    renderSparkline('spark-alarms',    tl, '#F97316');
    renderSparkline('spark-threats',   tl, '#7C8AFF');
    renderSparkline('spark-endpoints', tl, '#F43F5E');
    renderSparkline('spark-hashes',    tl, '#22D3EE');

    // Live timestamp
    const ts = document.getElementById('topbar-ts');
    if (ts) ts.textContent = 'Updated ' + new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});

    // Show / hide EDR and SIEM section headers and KPI grids
    const hasS1 = platforms.includes('SentinelOne');
    const hasAV = platforms.includes('AlienVault');

    // EDR section
    const edrHdr  = $('ov-edr-section'); if (edrHdr)  edrHdr.style.display  = hasS1 ? '' : 'none';
    const edrGrid = $('kpi-grid-edr');   if (edrGrid) edrGrid.style.display  = hasS1 ? '' : 'none';

    // SIEM section
    const siemHdr   = $('ov-siem-section'); if (siemHdr)   siemHdr.style.display   = hasAV ? '' : 'none';
    const siemGrid  = $('kpi-grid-siem');   if (siemGrid)  siemGrid.style.display   = hasAV ? '' : 'none';
    const siemCards = $('ov-siem-cards');   if (siemCards) siemCards.style.display  = hasAV ? '' : 'none';

    // Clear skeletons
    const dp = $('dash-prio'); if (dp) dp.innerHTML = '';
    const dm = $('dash-methods'); if (dm) dm.innerHTML = '';

    renderDashPrio(c.av_priority_breakdown || []);
    renderDashMethods(c.av_method_summary || []);

    // ── Derive SIEM breakdown tiles from av_priority_breakdown ──
    const prio = c.av_priority_breakdown || [];
    const findPrio = (label) => prio.find(r => (r.priority||'').toLowerCase() === label.toLowerCase());
    const highRow   = findPrio('High');
    const medRow    = findPrio('Medium');
    const avHigh    = highRow ? (highRow.total || 0) : 0;
    const avMedium  = medRow  ? (medRow.total  || 0) : 0;
    const avOpen    = prio.reduce((s, r) => s + ((r.statuses || {}).open    || 0), 0);
    const avClosed  = prio.reduce((s, r) => s + ((r.statuses || {}).closed  || 0), 0);
    setKpi('kv-av-high',   avHigh,   'No high severity alarms');
    setKpi('kv-av-medium', avMedium, 'No medium severity alarms');
    setKpi('kv-av-open',   avOpen,   'No open alarms');
    setKpi('kv-av-closed', avClosed, 'No closed alarms');

    const nb = $('nav-alerts-badge');
    if (nb && avTotal > 0) { nb.textContent = fmt(avTotal); nb.style.display = 'inline'; }

    const avLbl = $('av-total-lbl'); if (avLbl) avLbl.textContent = fmt(avTotal) + ' alarms · 24hr';

    renderSiemSection(c);
    renderTrendBars(c.av_daily_trend || []);
    renderMethTable(c.av_method_summary || []);
    renderSimpleTable('strat-tbody', c.av_top_strategies || [], 2);
    renderSimpleTable('intent-tbody', c.av_top_intents || [], 2);
    renderSensorTable(c.av_sensor_summary || []);

    const s1a = (c.recent_alerts || []).filter(a => a.platform === 'SentinelOne');
    const s1Threats = c.total_threats || 0;
    const s1l = $('s1-threat-lbl');
    if (s1l) s1l.textContent = fmt(s1Threats) + ' active threat' + (s1Threats !== 1 ? 's' : '') + ' · 24hr';
    const eb = $('nav-edr-badge');
    if (eb && s1Threats) { eb.textContent = fmt(s1Threats); eb.style.display = 'inline'; }

    // EDR KPI Strip
    animNum('ekv-endpoints', c.total_endpoints || 0);
    animNum('ekv-threats',   c.total_threats   || 0);
    animNum('ekv-vuln-eps',  c.s1_vulnerable_endpoints || 0);
    animNum('ekv-vuln-apps', c.s1_vulnerable_apps      || 0);
    animNum('ekv-alerts',    c.s1_total_alerts || c.total_alerts || 0);
    animNum('ekv-hashes',    c.s1_blocklisted_hashes || 0);

    // ── Rich S1 Telemetry ──
    renderS1ThreatIntel(c);
    renderS1Table(c);
    renderS1Vulns(c);
    renderS1Agents(c);
    renderS1Sentinels(c);
}



// ═══ OVERVIEW ═══
function renderDashPrio(rows) {
    const el = $('dash-prio'); if (!el) return;
    if (!rows.length) { el.innerHTML = '<p style="color:var(--text-muted);font-size:0.78rem;padding:6px 0;">No data.</p>'; return; }
    el.innerHTML = rows.map(r => {
        const p = r.priority.toLowerCase(), st = r.statuses || {};
        return '<div style="display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--border);">'
            + '<span class="pb pb-' + p + '" style="min-width:58px;">' + esc(r.priority) + '</span>'
            + '<span style="font-weight:700;font-size:0.9rem;min-width:30px;">' + fmt(r.total) + '</span>'
            + '<span style="font-size:0.68rem;color:var(--text-muted);flex:1;">' + (st.open||0) + ' open  ' + (st.closed||0) + ' closed' + (st.in_review ? '  ' + st.in_review + ' review' : '') + '</span></div>';
    }).join('');
}

function renderDashMethods(rows) {
    const el = $('dash-methods'); if (!el) return;
    if (!rows.length) { el.innerHTML = '<p style="color:var(--text-muted);font-size:0.78rem;padding:6px 0;">No data.</p>'; return; }
    el.innerHTML = rows.slice(0, 6).map(r => '<div style="display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid var(--border);">'
        + '<span style="font-size:0.78rem;font-weight:500;color:var(--text-primary);">' + esc(r.method) + '</span>'
        + '<span style="font-size:0.78rem;font-weight:700;color:var(--text-primary);">' + fmt(r.count) + '</span></div>').join('');
}

// ═══ TELEMETRY STRIP ═══
function renderTelemetryStrip(c) {
    const hasS1 = (c.platforms || []).includes('SentinelOne');
    const strip  = document.getElementById('tel-strip');
    if (!strip) return;
    if (!hasS1) { strip.style.display = 'none'; return; }
    strip.style.display = '';

    const vulnEps  = c.s1_vulnerable_endpoints || 0;
    const vulnApps = c.s1_vulnerable_apps      || 0;
    const total    = c.total_endpoints          || 0;
    const hashes   = c.s1_blocklisted_hashes    || 0;
    const covered  = total > 0 ? Math.round(((total - vulnEps) / total) * 100) : 100;

    const set = (id, v) => { const el = $(id); if (el) el.textContent = v; };
    set('tel-vuln-eps',  fmt(vulnEps));
    set('tel-vuln-apps', fmt(vulnApps));
    set('tel-coverage',  covered + '%');
    set('tel-hashes2',   fmt(hashes));

    const epSub = $('tel-vuln-eps-sub');
    if (epSub) epSub.textContent = vulnEps > 0
        ? vulnEps + ' of ' + total + ' endpoint' + (total > 1 ? 's' : '') + ' at risk'
        : 'No exposure detected';

    const appSub = $('tel-vuln-apps-sub');
    if (appSub) appSub.textContent = vulnApps > 0
        ? vulnApps + ' application risk' + (vulnApps > 1 ? 's' : '') + ' identified'
        : 'No app risks detected';

    const covSub = $('tel-coverage-sub');
    if (covSub) covSub.textContent = covered === 100 ? 'Fully protected' : (100 - covered) + '% exposure risk';

    // Colour the vuln tile red if exposure detected
    const vEpTile = $('tel-vuln-eps')?.closest('.tel-tile');
    if (vEpTile) vEpTile.className = 'tel-tile ' + (vulnEps > 0 ? 'tel-tile-red' : 'tel-tile-green');
    const vAppTile = $('tel-vuln-apps')?.closest('.tel-tile');
    if (vAppTile) vAppTile.className = 'tel-tile ' + (vulnApps > 0 ? 'tel-tile-purple' : 'tel-tile-green');
    const covTile = $('tel-coverage')?.closest('.tel-tile');
    if (covTile) covTile.className = 'tel-tile ' + (covered < 90 ? 'tel-tile-orange' : 'tel-tile-green');
}

// ═══ RECENT EVENTS FEED ═══
function renderRecentFeed(c) {
    const card = document.getElementById('recent-feed-card');
    const feed = document.getElementById('recent-feed');
    if (!card || !feed) return;

    const recent = (c.recent_alerts || []).slice(0, 6);
    if (!recent.length) { card.style.display = 'none'; return; }
    card.style.display = '';

    feed.innerHTML = recent.map(a => {
        const isAV  = a.platform === 'AlienVault';
        const isS1  = a.platform === 'SentinelOne';
        const label = isAV ? (a.alert_type || 'Security Alarm') : (a.alert_type || 'Threat Detected');
        const prio  = (a.confidence || a.severity || 'medium').toLowerCase();
        const prioCls = prio === 'high' || prio === 'malicious' ? 'feed-dot-red'
                      : prio === 'medium' || prio === 'suspicious' ? 'feed-dot-amber'
                      : 'feed-dot-blue';
        const platLabel = isAV ? 'SIEM' : 'EDR';
        const platCls   = isAV ? 'feed-plat-av' : 'feed-plat-s1';
        const time = a.reported_at || a.time || '';
        const sub  = isAV
            ? ((a.intent && a.strategy) ? a.intent + ' · ' + a.strategy : (a.intent || a.strategy || ''))
            : (a.status || '');
        return `<div class="feed-row">
          <span class="feed-dot ${prioCls}"></span>
          <div class="feed-body">
            <div class="feed-title">${esc(label)}</div>
            ${sub ? `<div class="feed-sub">${esc(sub)}</div>` : ''}
          </div>
          <span class="feed-plat ${platCls}">${platLabel}</span>
          <span class="feed-time">${esc(time)}</span>
        </div>`;
    }).join('');
}

// ═══ POSTURE BANNER ═══
function renderPostureBanner(c) {
    const platforms = c.platforms || [];
    const hasS1 = platforms.includes('SentinelOne');
    const hasAV = platforms.includes('AlienVault');
    const threats   = hasS1 ? (c.total_threats || 0) : 0;
    const alarms    = hasAV ? (c.av_total_alarms || 0) : 0;
    const openAlarms = (c.av_priority_breakdown || []).reduce((s,r) => s + (r.statuses?.open || 0), 0);

    const banner   = document.getElementById('posture-banner');
    const icon     = document.getElementById('posture-icon');
    const headline = document.getElementById('posture-headline');
    const sub      = document.getElementById('posture-sub');
    const badge    = document.getElementById('posture-badge');
    if (!banner) return;

    let state, hl, desc, badgeText;
    if (threats > 0 || openAlarms > 0) {
        const items = [];
        if (threats > 0)    items.push(threats + ' active threat' + (threats > 1 ? 's' : ''));
        if (openAlarms > 0) items.push(openAlarms + ' open alarm' + (openAlarms > 1 ? 's' : '') + ' requiring attention');
        state = 'critical'; hl = 'Attention Required'; desc = items.join(' · '); badgeText = 'Action Needed';
        if (icon) icon.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';
    } else if (alarms > 0) {
        state = 'warning'; hl = 'Under Monitoring'; badgeText = 'Monitoring Active';
        desc = fmt(alarms) + ' security event' + (alarms > 1 ? 's' : '') + ' logged in the last 24 hours — all resolved or in review';
        if (icon) icon.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';
    } else {
        state = 'secure'; hl = 'Environment Secure'; badgeText = 'All Clear';
        const epStr = hasS1 && c.total_endpoints > 0 ? fmt(c.total_endpoints) + ' endpoint' + (c.total_endpoints > 1 ? 's' : '') + ' protected · ' : '';
        desc = epStr + 'No active threats or open alarms detected in the last 24 hours';
        if (icon) icon.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>';
    }

    banner.className = 'posture-banner posture-' + state;
    if (headline) headline.textContent = hl;
    if (sub) sub.textContent = desc;
    if (badge) { badge.textContent = badgeText; badge.className = 'posture-badge posture-badge-' + state; }
}

// ═══ ALERTS ═══
function renderPrioTable(rows) {
    const el = $('prio-tbody'); if (!el) return;
    if (!rows.length) { el.innerHTML = '<tr><td colspan="5" class="empty-msg">No data.</td></tr>'; return; }
    el.innerHTML = rows.map(r => { const st = r.statuses || {}; return '<tr><td><span class="pb pb-' + r.priority.toLowerCase() + '">' + esc(r.priority) + '</span></td><td style="font-weight:700;">' + fmt(r.total) + '</td><td>' + (st.open ? '<span class="sc sc-open">' + st.open + '</span>' : '—') + '</td><td>' + (st.closed ? '<span class="sc sc-closed">' + st.closed + '</span>' : '—') + '</td><td>' + (st.in_review ? '<span class="sc sc-review">' + st.in_review + '</span>' : '—') + '</td></tr>'; }).join('');
}

function renderMethTable(rows) {
    const el = $('meth-tbody'); if (!el) return;
    if (!rows.length) { el.innerHTML = '<tr><td colspan="4" class="empty-msg">No data.</td></tr>'; return; }
    el.innerHTML = rows.slice(0, 5).map(r => '<tr><td style="font-weight:500;color:var(--text-primary);">' + esc(r.method) + '</td><td style="color:var(--text-muted);font-size:0.74rem;">' + esc(r.strategy || '—') + '</td><td style="color:var(--text-muted);font-size:0.74rem;">' + esc(r.intent || '—') + '</td><td style="text-align:right;font-weight:700;">' + fmt(r.count) + '</td></tr>').join('');
}

function renderAssetTable(tbodyId, rows) {
    const el = $(tbodyId); if (!el) return;
    if (!rows.length) { el.innerHTML = '<tr><td colspan="4" class="empty-msg">No data.</td></tr>'; return; }
    el.innerHTML = rows.map((r, i) => '<tr><td style="color:var(--text-muted);font-size:0.72rem;">' + (i+1) + '</td><td style="font-weight:500;color:var(--text-primary);">' + esc(r.asset) + '</td><td><span class="asset-cnt">' + fmt(r.count) + '</span></td><td style="color:var(--text-muted);font-size:0.7rem;">' + ((r.alarm_types||[]).slice(0,2).map(esc).join(', ') || '—') + '</td></tr>').join('');
}

function renderAlarmLog(all) {
    const el = $('alarm-tbody'); if (!el) return;
    const av = all.filter(a => a.platform === 'AlienVault');
    if (!av.length) { el.innerHTML = '<tr><td colspan="6" class="empty-msg">No AV alarms in 24hr window.</td></tr>'; return; }
    el.innerHTML = av.map(a => {
        const p = (a.confidence || a.severity || 'low').toLowerCase();
        const st = a.status || 'Closed';
        const sc = st === 'Open' ? 'sc-open' : st === 'In Review' ? 'sc-review' : 'sc-closed';
        return '<tr><td><div class="alarm-name">' + esc(a.alert_type||'—') + '</div><div class="alarm-sub">' + esc((a.intent&&a.strategy)?a.intent+' · '+a.strategy:(a.intent||a.strategy||'')) + '</div></td>'
            + '<td><span class="pb pb-' + p + '">' + esc(p.charAt(0).toUpperCase()+p.slice(1)) + '</span></td>'
            + '<td><span class="sc ' + sc + '">' + esc(st) + '</span></td>'
            + '<td style="font-size:0.76rem;color:var(--text-secondary);">' + esc(a.source||'—') + '</td>'
            + '<td style="font-size:0.74rem;color:var(--text-muted);">' + esc(a.destination||'—') + '</td>'
            + '<td class="alarm-time">' + esc(a.reported_at||a.time||'—') + '</td></tr>';
    }).join('');
}

// ═══ SIEM SECTION ═══
function renderSiemSection(c) {
    const prios   = c.av_priority_breakdown || [];
    const sensors = c.av_sensor_summary || [];
    const avTotal = c.av_total_alarms || 0;

    // Summary row totals
    const set = (id, v) => { const el = $(id); if (el) el.textContent = v; };
    set('siem-total', fmt(avTotal));
    set('av-total-lbl', fmt(avTotal) + ' alarms · 24hr');

    // Severity counts from priority breakdown
    let sH = 0, sM = 0, sL = 0, stOpen = 0, stInv = 0, stClosed = 0;
    prios.forEach(r => {
        const p = (r.priority || '').toLowerCase();
        const t = r.total || 0, st = r.statuses || {};
        if (p === 'high')   sH += t;
        else if (p === 'medium') sM += t;
        else sL += t;
        stOpen   += st.open   || 0;
        stInv    += st.in_review || 0;
        stClosed += st.closed || 0;
    });
    set('siem-sev-h', sH); set('siem-sev-m', sM); set('siem-sev-l', sL);
    set('siem-st-open', stOpen); set('siem-st-inv', stInv); set('siem-st-closed', stClosed);

    // Priority cards
    const container = $('siem-prio-cards');
    if (!container) return;
    const ORDER = ['High', 'Medium', 'Low'];
    const SEV_CLASS = { high: 'high', medium: 'medium', low: 'low' };
    const numCls = { open: 'open', in_review: 'inv', closed: 'closed' };

    // Build sensor chips HTML (top 4)
    const sensorChips = sensors.slice(0, 4).map(s =>
        `<span class="siem-sensor-chip">${esc(s.asset)} <span style="color:var(--text-muted);">${fmt(s.count)}</span></span>`
    ).join('');

    const cards = ORDER.map(pLabel => {
        const row = prios.find(r => r.priority?.toLowerCase() === pLabel.toLowerCase());
        if (!row) return '';
        const st = row.statuses || {};
        const open = st.open || 0, inv = st.in_review || 0, closed = st.closed || 0;
        const cls = SEV_CLASS[pLabel.toLowerCase()];
        return `
        <div class="siem-prio-card">
          <div class="siem-prio-card-header">
            <span class="siem-prio-badge ${cls}">${esc(pLabel)}</span>
            <span class="siem-prio-total">${fmt(row.total)}</span>
            <span class="siem-prio-sublabel">${fmt(open + inv + closed)} classified</span>
          </div>
          <div class="siem-status-boxes">
            <div class="siem-status-box">
              <div class="siem-status-box-num open">${fmt(open)}</div>
              <div class="siem-status-box-lbl">Open</div>
            </div>
            <div class="siem-status-box">
              <div class="siem-status-box-num inv">${fmt(inv)}</div>
              <div class="siem-status-box-lbl">In Review</div>
            </div>
            <div class="siem-status-box">
              <div class="siem-status-box-num closed">${fmt(closed)}</div>
              <div class="siem-status-box-lbl">Resolved</div>
            </div>
          </div>
        </div>`;
    }).join('');
    container.innerHTML = cards || '<p style="color:var(--text-muted);padding:12px;">No alarm data.</p>';
}

function toggleSiemAcc(btn) {
    btn.classList.toggle('open');
    const body = btn.nextElementSibling;
    if (body) body.classList.toggle('open');
}


function renderTrendBars(trend) {
    const bars  = $('av-trend-bars');  if (!bars)  return;
    const lbls  = $('av-trend-labels'); 
    if (!trend || !trend.length) { bars.innerHTML = '<span style="color:var(--text-muted);font-size:0.75rem;">No trend data.</span>'; return; }
    const max = Math.max(...trend) || 1;
    const days = ['6d','5d','4d','3d','2d','1d','Today'];
    const w = Math.floor(100 / trend.length) - 1;
    bars.innerHTML = trend.map((v, i) => {
        const h = Math.max(4, Math.round((v / max) * 52));
        const col = i === trend.length - 1 ? '#F97316' : '#5A6DFF';
        return `<div title="${days[i]}: ${v} alarms" style="flex:1;height:${h}px;background:${col};border-radius:3px 3px 0 0;opacity:${v===0?0.2:0.85};cursor:default;transition:.2s;"></div>`;
    }).join('');
    if (lbls) lbls.innerHTML = days.map((d, i) =>
        `<div style="flex:1;text-align:center;font-size:0.6rem;color:var(--text-muted);">${d}</div>`).join('');
}

function renderSimpleTable(tbodyId, rows, cols) {
    const el = $(tbodyId); if (!el) return;
    if (!rows.length) { el.innerHTML = `<tr><td colspan="${cols}" class="empty-msg">No data.</td></tr>`; return; }
    el.innerHTML = rows.slice(0, 5).map(r =>
        `<tr><td style="font-weight:500;color:var(--text-primary);">${esc(r.method)}</td>`
        + `<td style="text-align:right;font-weight:700;">${fmt(r.count)}</td></tr>`
    ).join('');
}

function renderCountryTable(rows) {
    const el = $('country-tbody'); if (!el) return;
    if (!rows.length) { el.innerHTML = '<tr><td colspan="3" class="empty-msg">No geographic data available.</td></tr>'; return; }
    el.innerHTML = rows.map((r, i) =>
        `<tr><td style="color:var(--text-muted);font-size:0.72rem;">${i+1}</td>`
        + `<td style="font-weight:500;color:var(--text-primary);">${esc(r.asset)}</td>`
        + `<td style="text-align:right;"><span class="asset-cnt">${fmt(r.count)}</span></td></tr>`
    ).join('');
}

function renderSensorTable(rows) {
    const el = $('sensor-tbody'); if (!el) return;
    if (!rows.length) { el.innerHTML = '<tr><td colspan="2" class="empty-msg">No sensor data.</td></tr>'; return; }
    el.innerHTML = rows.map(r =>
        `<tr><td style="font-weight:500;color:var(--text-primary);">${esc(r.asset)}</td>`
        + `<td style="text-align:right;font-weight:700;">${fmt(r.count)}</td></tr>`
    ).join('');
}

// ═══ EDR ═══
// ═══════════════════════════════════════════════════════════════
// S1 RICH TELEMETRY RENDERERS
// ═══════════════════════════════════════════════════════════════

/** Render a horizontal bar breakdown list into elementId */
function renderS1BarList(elementId, items, colorFn) {
    const el = $(elementId); if (!el) return;
    if (!items || !items.length) {
        el.innerHTML = '<p style="color:var(--text-muted);font-size:0.78rem;padding:8px 0;">No data available.</p>';
        return;
    }
    const max = Math.max(...items.map(i => i.count), 1);
    el.innerHTML = items.map(i => {
        const pct = Math.round((i.count / max) * 100);
        const cls = colorFn ? colorFn(i.label) : 'sev-default';
        return `<div class="s1-bar-row">
            <div class="s1-bar-label" title="${esc(i.label)}">${esc(i.label)}</div>
            <div class="s1-bar-track"><div class="s1-bar-fill ${cls}" style="width:${pct}%"></div></div>
            <div class="s1-bar-count">${fmt(i.count)}</div>
        </div>`;
    }).join('');
}

function clsColor(label) {
    const l = (label||'').toLowerCase();
    if (l.includes('malicious'))  return 'cls-malicious';
    if (l.includes('suspicious')) return 'cls-suspicious';
    if (l.includes('pup'))        return 'cls-pup';
    return 'cls-default';
}
function mitColor(label) {
    const l = (label||'').toLowerCase();
    if (l.includes('mitigated') && !l.includes('not')) return 'mit-mitigated';
    if (l.includes('not'))    return 'mit-notmit';
    return 'mit-default';
}
function sevColor(label) {
    const l = (label||'').toLowerCase();
    if (l.includes('critical'))       return 'sev-critical';
    if (l.includes('high'))           return 'sev-high';
    if (l.includes('medium'))         return 'sev-medium';
    if (l.includes('low'))            return 'sev-low';
    if (l.includes('info'))           return 'sev-info';
    return 'sev-default';
}
function attnColor(label) {
    const l = (label||'').toLowerCase();
    if (l.includes('missing'))        return 'attn-missing';
    if (l.includes('incompatible'))   return 'attn-incompatible';
    if (l.includes('unprotected'))    return 'attn-unprotected';
    if (l.includes('suppressed'))     return 'attn-suppressed';
    return 'attn-attention';
}

function renderS1ThreatIntel(c) {
    renderS1BarList('s1-threat-class', c.s1_threat_classifications, clsColor);
    renderS1BarList('s1-mitigation',   c.s1_threat_mitigations,     mitColor);
    renderS1BarList('s1-threat-files', c.s1_threat_files,           () => 'cls-default');
}

function renderS1Table(data) {
    const el = $('s1-tbody'); if (!el) return;
    // Use rich detailed threats if available, else fall back to alert items
    const rows = data.s1_recent_threats || [];
    if (!rows.length) {
        el.innerHTML = '<tr><td colspan="7" class="empty-msg">No S1 threats in 24hr window.</td></tr>';
        return;
    }
    el.innerHTML = rows.map(t => {
        const cls = (t.classification||'').toLowerCase();
        const cc = cls.includes('malicious')?'conf-mal':cls.includes('suspicious')?'conf-sus':'conf-unk';
        const mit = (t.mitigation||'').toLowerCase();
        const mc = mit.includes('mitigated')&&!mit.includes('not')?'vb-tp':mit.includes('not')?'vb-fp':'vb-pen';
        const res = (t.resolution||'').toLowerCase();
        const rc = res.includes('resolved')?'sc-closed':res.includes('progress')?'sc-review':'sc-open';
        return `<tr>
            <td><div class="alarm-name">${esc(t.file||'—')}</div></td>
            <td><span class="pb ${cc}">${esc(t.classification||'Unknown')}</span></td>
            <td><span class="vb ${mc}">${esc(t.mitigation||'—')}</span></td>
            <td><span class="sc ${rc}">${esc(t.resolution||'—')}</span></td>
            <td style="font-size:0.73rem;color:var(--text-muted);">${esc(t.verdict||'Pending')}</td>
            <td style="font-size:0.76rem;color:var(--text-secondary);">${esc(t.endpoint||'—')}</td>
            <td class="alarm-time">${esc(t.reported_at||'—')}</td>
        </tr>`;
    }).join('');
}

function renderS1Vulns(c) {
    renderS1BarList('s1-vuln-apps',     c.s1_vuln_apps,      () => 'sev-medium');
    renderS1BarList('s1-vuln-sev',      c.s1_vuln_severity,  sevColor);
    renderS1BarList('s1-vuln-eps-list', c.s1_vuln_endpoints, () => 'sev-high');
}

function renderS1Agents(c) {
    renderS1BarList('s1-agent-attn', c.s1_agents_attention, attnColor);
    renderS1BarList('s1-agent-ver',  c.s1_agent_versions,   () => 'sev-info');
}

function renderS1Sentinels(c) {
    renderS1BarList('s1-os-dist', c.s1_os_distribution, () => 'cls-default');
    const epEl = $('s1-ep-list'); if (epEl) {
        const names = c.s1_endpoint_names || [];
        epEl.innerHTML = names.length
            ? names.map(n => `<span class="s1-ep-chip">${esc(n)}</span>`).join('')
            : '<p style="color:var(--text-muted);font-size:0.78rem;">No endpoints listed.</p>';
    }
}


// ═══ HELPERS ═══
const _anims = {};
function setKpi(id, value, zeroMsg) {
    const el  = $(id);
    const nil = $(id + '-nil');
    if (!el) return;
    if (value > 0) {
        animNum(id, value);
        if (nil) nil.style.display = 'none';
    } else {
        el.textContent = '—';
        if (nil && zeroMsg) { nil.textContent = zeroMsg; nil.style.display = ''; }
        else if (nil) nil.style.display = 'none';
    }
}

function animNum(id, target) {
    const el = $(id); if (!el) return;
    const start = Number(el.dataset.val) || 0;
    el.dataset.val = target;
    if (_anims[id]) cancelAnimationFrame(_anims[id]);
    const t0 = performance.now();
    (function step(now) {
        const p = Math.min((now - t0) / 600, 1);
        el.textContent = fmt(Math.round(start + (target - start) * (1 - Math.pow(1 - p, 3))));
        if (p < 1) _anims[id] = requestAnimationFrame(step);
    })(t0);
}

function fmt(n) { n = Number(n) || 0; if (n >= 1e6) return (n/1e6).toFixed(1)+'M'; if (n >= 1e3) return (n/1e3).toFixed(1)+'k'; return String(n); }

function esc(s) { if (!s) return ''; const d = document.createElement('div'); d.textContent = String(s); return d.innerHTML; }



document.addEventListener('DOMContentLoaded', async () => {
    if (typeof initEventChart === 'function') initEventChart();
    await preload();
    connectWS();
});
