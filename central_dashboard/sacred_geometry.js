/**
 * Sentrium Enterprise — Sacred Geometry 4D Animation Engine
 * ==========================================================
 * Cycles between three sacred geometric forms in 3D perspective:
 *   1. Cosmic Orb (intersecting rings + pulsing core)
 *   2. Seed of Life (7 overlapping circles)
 *   3. Flower of Life (19 overlapping circles)
 * Each pattern evolves, rotates in 3D, and periodically surges
 * toward the viewer before transitioning to the next form.
 */

window.addEventListener('load', function () {
    const canvas = document.getElementById('sacred-canvas');
    if (!canvas) { console.error('[SacredGeometry] Canvas not found'); return; }
    const ctx = canvas.getContext('2d');
    const container = document.getElementById('animation-side');

    // Hi-DPI support
    const dpr = window.devicePixelRatio || 1;
    let W, H, cx, cy;

    function resize() {
        const rect = container ? container.getBoundingClientRect() : { width: 500, height: 550 };
        W = Math.max(rect.width, 300);
        H = Math.max(rect.height, 300);
        canvas.width  = W * dpr;
        canvas.height = H * dpr;
        canvas.style.width  = W + 'px';
        canvas.style.height = H + 'px';
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        cx = W / 2;
        cy = H / 2;
    }
    resize();
    window.addEventListener('resize', resize);

    // ── Color palette ─────────────────────────────────────────
    const C = {
        cyan:   'rgba(6,182,212,',
        blue:   'rgba(37,99,235,',
        indigo: 'rgba(79,70,229,',
        light:  'rgba(96,165,250,',
        white:  'rgba(255,255,255,',
        violet: 'rgba(139,92,246,'
    };

    // ── Phase config ──────────────────────────────────────────
    const PHASE_COUNT    = 3;
    const PHASE_DURATION = 8000;
    const FADE_DURATION  = 2000;
    const startTime      = performance.now();

    // ── 3D math ───────────────────────────────────────────────
    function rotY(x, z, a) { const c = Math.cos(a), s = Math.sin(a); return { x: x*c + z*s, z: -x*s + z*c }; }
    function rotX(y, z, a) { const c = Math.cos(a), s = Math.sin(a); return { y: y*c - z*s, z: y*s + z*c }; }
    function proj(x, y, z) { const s = 600 / (600 + z); return { x: cx + x*s, y: cy + y*s, s: s }; }

    // ── Draw a 3D ring ────────────────────────────────────────
    function drawRing3D(radius, tX, tY, time, color, alpha, lw) {
        ctx.beginPath();
        for (let i = 0; i <= 80; i++) {
            const a = (i / 80) * Math.PI * 2;
            let x = Math.cos(a) * radius, y = Math.sin(a) * radius, z = 0;
            const r1 = rotY(x, z, tY + time * 0.2); x = r1.x; z = r1.z;
            const r2 = rotX(y, z, tX); y = r2.y; z = r2.z;
            const p = proj(x, y, z);
            i === 0 ? ctx.moveTo(p.x, p.y) : ctx.lineTo(p.x, p.y);
        }
        ctx.strokeStyle = color + alpha + ')';
        ctx.lineWidth = lw;
        ctx.stroke();
    }

    // ── Draw a sacred circle in 3D ────────────────────────────
    function drawSacredCircle3D(ox, oy, r, time, opacity, color, lw) {
        ctx.beginPath();
        const tX = Math.sin(time * 0.4) * 0.35;
        const tY = Math.cos(time * 0.3) * 0.35;
        for (let i = 0; i <= 64; i++) {
            const a = (i / 64) * Math.PI * 2;
            let x = ox + Math.cos(a) * r;
            let y = oy + Math.sin(a) * r;
            let z = Math.sin(a * 2 + time) * 18;
            const r1 = rotY(x, z, tY); x = r1.x; z = r1.z;
            const r2 = rotX(y, z, tX); y = r2.y; z = r2.z;
            const p = proj(x, y, z);
            i === 0 ? ctx.moveTo(p.x, p.y) : ctx.lineTo(p.x, p.y);
        }
        ctx.strokeStyle = color + (opacity * 0.85) + ')';
        ctx.lineWidth = lw * opacity;
        ctx.stroke();
    }

    // ══════════════════════════════════════════════════════════
    // PHASE 0: COSMIC ORB
    // ══════════════════════════════════════════════════════════
    function drawOrb(t, op) {
        const T = t * 0.001;

        // Three intersecting rings
        drawRing3D(130, T*0.7, T*0.5, 0, C.indigo, op*0.9, 5*op);
        drawRing3D(100, -T*0.6, T*0.8+1, 0, C.cyan, op*0.7, 3*op);
        ctx.setLineDash([8,12]);
        drawRing3D(75, T*0.4, -T*0.3, 0, C.light, op*0.6, 2*op);
        ctx.setLineDash([]);

        // Pulsing core
        const pulse = 1 + Math.sin(T * 2) * 0.15;
        const cR = 45 * pulse;
        const g = ctx.createRadialGradient(cx, cy, 0, cx, cy, cR);
        g.addColorStop(0, C.white + (op*0.95) + ')');
        g.addColorStop(0.35, C.cyan + (op*0.8) + ')');
        g.addColorStop(0.65, C.blue + (op*0.7) + ')');
        g.addColorStop(1, C.indigo + (op*0.3) + ')');
        ctx.beginPath(); ctx.arc(cx, cy, cR, 0, Math.PI*2);
        ctx.fillStyle = g; ctx.fill();

        // Glow halo
        const h = ctx.createRadialGradient(cx, cy, cR, cx, cy, cR+30);
        h.addColorStop(0, C.cyan + (op*0.35) + ')');
        h.addColorStop(1, C.cyan + '0)');
        ctx.beginPath(); ctx.arc(cx, cy, cR+30, 0, Math.PI*2);
        ctx.fillStyle = h; ctx.fill();
    }

    // ══════════════════════════════════════════════════════════
    // PHASE 1: SEED OF LIFE (7 circles)
    // ══════════════════════════════════════════════════════════
    function drawSeedOfLife(t, op) {
        const T = t * 0.001;
        const r = 60 * (1 + Math.sin(T * 1.5) * 0.08);
        const rot = T * 0.3;

        // Center
        drawSacredCircle3D(0, 0, r, T, op, C.blue, 2.5);

        // 6 petals
        for (let i = 0; i < 6; i++) {
            const a = (i/6) * Math.PI*2 + rot;
            drawSacredCircle3D(Math.cos(a)*r, Math.sin(a)*r, r, T, op, C.cyan, 2);
        }

        // Vesica piscis glow at center
        const g = ctx.createRadialGradient(cx, cy, 0, cx, cy, r*0.7);
        g.addColorStop(0, C.white + (op*0.3) + ')');
        g.addColorStop(1, C.white + '0)');
        ctx.beginPath(); ctx.arc(cx, cy, r*0.7, 0, Math.PI*2);
        ctx.fillStyle = g; ctx.fill();
    }

    // ══════════════════════════════════════════════════════════
    // PHASE 2: FLOWER OF LIFE (19 circles)
    // ══════════════════════════════════════════════════════════
    function drawFlowerOfLife(t, op) {
        const T = t * 0.001;
        const r = 42 * (1 + Math.sin(T * 1.2) * 0.06);
        const rot = T * 0.2;

        // Center
        drawSacredCircle3D(0, 0, r, T, op, C.indigo, 2);

        // Inner ring (6)
        for (let i = 0; i < 6; i++) {
            const a = (i/6) * Math.PI*2 + rot;
            drawSacredCircle3D(Math.cos(a)*r, Math.sin(a)*r, r, T, op, C.blue, 1.8);
        }

        // Outer ring (12)
        for (let i = 0; i < 6; i++) {
            const a1 = (i/6) * Math.PI*2 + rot;
            drawSacredCircle3D(Math.cos(a1)*r*2, Math.sin(a1)*r*2, r, T, op, C.cyan, 1.4);
            const a2 = a1 + Math.PI/6;
            const d = r * Math.sqrt(3);
            drawSacredCircle3D(Math.cos(a2)*d, Math.sin(a2)*d, r, T, op, C.light, 1.1);
        }

        // Central luminance
        const g = ctx.createRadialGradient(cx, cy, 0, cx, cy, r*1.5);
        g.addColorStop(0, C.white + (op*0.2) + ')');
        g.addColorStop(1, C.white + '0)');
        ctx.beginPath(); ctx.arc(cx, cy, r*1.5, 0, Math.PI*2);
        ctx.fillStyle = g; ctx.fill();
    }

    // ── Floating particles ────────────────────────────────────
    const pts = [];
    for (let i = 0; i < 14; i++) {
        pts.push({
            a:  Math.random() * Math.PI*2,
            d:  70 + Math.random() * 120,
            sp: 0.15 + Math.random() * 0.4,
            z0: (Math.random()-0.5) * 100,
            sz: 1.5 + Math.random() * 3,
            ph: Math.random() * Math.PI*2
        });
    }

    function drawParticles(t) {
        const T = t * 0.001;
        pts.forEach(p => {
            const a = p.a + T * p.sp;
            let x = Math.cos(a) * p.d, y = Math.sin(a) * p.d;
            let z = p.z0 + Math.sin(T*2 + p.ph) * 40;
            const r1 = rotY(x, z, T*0.15); x = r1.x; z = r1.z;
            const r2 = rotX(y, z, Math.sin(T*0.3)*0.2); y = r2.y; z = r2.z;
            const pr = proj(x, y, z);
            const s = p.sz * pr.s;

            // Dot
            ctx.beginPath(); ctx.arc(pr.x, pr.y, s, 0, Math.PI*2);
            ctx.fillStyle = C.white + (0.75 * pr.s) + ')'; ctx.fill();

            // Glow
            const g = ctx.createRadialGradient(pr.x, pr.y, 0, pr.x, pr.y, s*4);
            g.addColorStop(0, C.cyan + (0.3 * pr.s) + ')');
            g.addColorStop(1, C.cyan + '0)');
            ctx.beginPath(); ctx.arc(pr.x, pr.y, s*4, 0, Math.PI*2);
            ctx.fillStyle = g; ctx.fill();
        });
    }

    // ── 4D Surge (jump-out-of-screen effect) ──────────────────
    function applySurge(t) {
        const T = t * 0.001;
        const cycle = (T % 22) / 22;
        let sc = 1, tx = 0, ty = 0;

        if (cycle > 0.6 && cycle < 0.72) {
            const prog = (cycle - 0.6) / 0.12;
            const ease = Math.sin(prog * Math.PI);
            sc = 1 + ease * 0.55;
            tx = Math.sin(T * 3) * ease * 10;
            ty = -ease * 18;
        }

        ctx.translate(cx + tx, cy + ty);
        ctx.scale(sc, sc);
        ctx.translate(-cx, -cy);
    }

    // ── Main loop ─────────────────────────────────────────────
    const drawFn = [drawOrb, drawSeedOfLife, drawFlowerOfLife];
    const totalCycle = PHASE_DURATION + FADE_DURATION;

    function frame(now) {
        const elapsed = now - startTime;
        ctx.clearRect(0, 0, W, H);
        ctx.save();

        applySurge(elapsed);

        // Phase cross-fade
        const cyclePos   = elapsed % (totalCycle * PHASE_COUNT);
        const phaseIdx   = Math.floor(cyclePos / totalCycle) % PHASE_COUNT;
        const phaseTime  = cyclePos % totalCycle;
        const nextIdx    = (phaseIdx + 1) % PHASE_COUNT;

        let curOp = 1, nxtOp = 0;
        if (phaseTime > PHASE_DURATION) {
            const fade = (phaseTime - PHASE_DURATION) / FADE_DURATION;
            curOp = 1 - fade;
            nxtOp = fade;
        }

        if (curOp > 0.01) drawFn[phaseIdx](elapsed, curOp);
        if (nxtOp > 0.01) drawFn[nextIdx](elapsed, nxtOp);

        drawParticles(elapsed);

        ctx.restore();
        requestAnimationFrame(frame);
    }

    // Kick off
    console.log('[SacredGeometry] Canvas:', W + 'x' + H, '| DPR:', dpr);
    requestAnimationFrame(frame);
});
