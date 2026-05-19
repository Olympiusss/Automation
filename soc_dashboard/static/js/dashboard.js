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
    animNum('kv-alarms', avTotal);
    animNum('kv-threats', c.total_threats || 0);
    animNum('kv-endpoints', c.total_endpoints || 0);
    animNum('kv-blocked', c.blocked_attempts || 0);
    animNum('kv-dfir', c.dfir_cases || 0);

    const tl = c.event_timeline || [];
    renderSparkline('spark-alarms', tl, '#F97316');
    renderSparkline('spark-threats', tl, '#7C8AFF');
    renderSparkline('spark-endpoints', tl, '#F43F5E');
    renderSparkline('spark-blocked', tl, '#22D3EE');
    renderSparkline('spark-dfir', tl, '#A78BFA');

    // Hide irrelevant KPI tiles
    const hide = (id) => { const el = $(id)?.closest('.kpi-tile'); if (el) el.style.display = 'none'; };
    const show = (id) => { const el = $(id)?.closest('.kpi-tile'); if (el) el.style.display = ''; };
    if (!platforms.includes('AlienVault')) { hide('kv-alarms'); } else { show('kv-alarms'); }
    if (!platforms.includes('SentinelOne')) { hide('kv-threats'); hide('kv-endpoints'); } else { show('kv-threats'); show('kv-endpoints'); }

    // Clear skeletons
    const dp = $('dash-prio'); if (dp) dp.innerHTML = '';
    const dm = $('dash-methods'); if (dm) dm.innerHTML = '';

    if (typeof updateEventChart === 'function') updateEventChart(tl);

    renderDashPrio(c.av_priority_breakdown || []);
    renderDashMethods(c.av_method_summary || []);

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
    const s1l = $('s1-threat-lbl'); if (s1l) s1l.textContent = fmt(s1a.length) + ' threats · 24hr';
    const eb = $('nav-edr-badge');
    if (eb && s1a.length) { eb.textContent = fmt(s1a.length); eb.style.display = 'inline'; }
    renderS1Table(s1a);
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
    const max = rows[0]?.count || 1;
    el.innerHTML = rows.slice(0, 6).map(r => '<div style="padding:6px 0;border-bottom:1px solid var(--border);">'
        + '<div style="display:flex;justify-content:space-between;margin-bottom:4px;"><span style="font-size:0.78rem;font-weight:500;color:var(--text-primary);">' + esc(r.method) + '</span><span style="font-size:0.74rem;font-weight:600;color:#F97316;">' + fmt(r.count) + '</span></div>'
        + '<div class="bar-row"><div class="bar-bg"><div class="bar-fill" style="width:' + Math.round((r.count/max)*100) + '%;"></div></div></div></div>').join('');
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
    const max = rows[0]?.count || 1;
    el.innerHTML = rows.slice(0, 15).map(r => '<tr><td style="font-weight:500;color:var(--text-primary);">' + esc(r.method) + '</td><td style="color:var(--text-muted);font-size:0.74rem;">' + esc(r.strategy || '—') + '</td><td style="color:var(--text-muted);font-size:0.74rem;">' + esc(r.intent || '—') + '</td><td style="text-align:right;"><div class="bar-row" style="justify-content:flex-end;"><div class="bar-bg" style="width:50px;"><div class="bar-fill" style="width:' + Math.round((r.count/max)*100) + '%;"></div></div><span class="bar-cnt">' + fmt(r.count) + '</span></div></td></tr>').join('');
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
              <div class="siem-status-box-lbl">Investigating</div>
            </div>
            <div class="siem-status-box">
              <div class="siem-status-box-num closed">${fmt(closed)}</div>
              <div class="siem-status-box-lbl">Closed</div>
            </div>
          </div>
          ${sensorChips ? `<div class="siem-sensor-row"><strong>Sensors:</strong>${sensorChips}</div>` : ''}
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
    const max = rows[0]?.count || 1;
    el.innerHTML = rows.map(r =>
        `<tr><td style="font-weight:500;color:var(--text-primary);">${esc(r.method)}</td>`
        + `<td style="text-align:right;"><div class="bar-row" style="justify-content:flex-end;"><div class="bar-bg" style="width:50px;"><div class="bar-fill" style="width:${Math.round((r.count/max)*100)}%;"></div></div><span class="bar-cnt">${fmt(r.count)}</span></div></td></tr>`
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
    const max = rows[0]?.count || 1;
    el.innerHTML = rows.map(r =>
        `<tr><td style="font-weight:500;color:var(--text-primary);">${esc(r.asset)}</td>`
        + `<td style="text-align:right;"><div class="bar-row" style="justify-content:flex-end;"><div class="bar-bg" style="width:60px;"><div class="bar-fill bar-fill-s1" style="width:${Math.round((r.count/max)*100)}%;"></div></div><span class="bar-cnt">${fmt(r.count)}</span></div></td></tr>`
    ).join('');
}

// ═══ EDR ═══
function renderS1Table(alerts) {
    const el = $('s1-tbody'); if (!el) return;
    if (!alerts.length) { el.innerHTML = '<tr><td colspan="6" class="empty-msg">No S1 threats in 24hr window.</td></tr>'; return; }
    el.innerHTML = alerts.map(a => {
        const conf = (a.confidence||'').toLowerCase();
        const cc = conf==='malicious'?'conf-mal':conf==='suspicious'?'conf-sus':'conf-unk';
        const vc = a.analyst_verdict==='True Positive'?'vb-tp':a.analyst_verdict==='False Positive'?'vb-fp':a.analyst_verdict?'vb-sus':'vb-pen';
        const sc = a.status==='Resolved'?'sc-closed':a.status==='In Progress'?'sc-review':'sc-open';
        return '<tr><td><div class="alarm-name">' + esc(a.alert_type||'—') + '</div><div class="alarm-sub">' + esc(a.id||'') + '</div></td>'
            + '<td><span class="pb ' + cc + '">' + esc(a.confidence||'Unknown') + '</span></td>'
            + '<td><span class="vb ' + vc + '">' + esc(a.analyst_verdict||'Pending') + '</span></td>'
            + '<td><span class="sc ' + sc + '">' + esc(a.status||'Open') + '</span></td>'
            + '<td style="font-size:0.76rem;color:var(--text-secondary);">' + esc(a.source||'—') + '</td>'
            + '<td class="alarm-time">' + esc(a.reported_at||a.time||'—') + '</td></tr>';
    }).join('');
}

// ═══ HELPERS ═══
const _anims = {};
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
