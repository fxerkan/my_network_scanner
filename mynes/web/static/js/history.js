/**
 * History page: scan trend, inventory breakdowns, alert activity and
 * availability - all driven by one cross-filter state (XF).
 *
 * Every chart reads XF and every chart writes it: click a device-type bar and
 * the trend, vendors, alerts and uptime strip narrow to that type; drag across
 * the trend to zoom every chart to that window; click a trend point to pin that
 * scan (the breakdowns then show that scan's own tallies). A chart never
 * filters itself by its own dimension - it keeps every bar and highlights the
 * picked one, so the user can see what they picked against the rest.
 *
 * Colours come from design-system tokens only (--chart-*, --severity-*-fg),
 * read at render time so light/dark both work. Animations are CSS transitions
 * and honour prefers-reduced-motion (history.css).
 */

let scanHistory = [];
let deviceTypes = {};
let alertsAll = [];
let inventory = [];
let invByMac = new Map();
let invByIp = new Map();

const SVGNS = 'http://www.w3.org/2000/svg';
const RANGES = { '24h': 864e5, '7d': 7 * 864e5, '30d': 30 * 864e5, all: Infinity };
const SEVERITIES = ['critical', 'high', 'warning', 'info'];

// The cross-filter state. `from`/`to` (ms) come from a trend brush and
// override `range`; `scan` is a pinned scan timestamp.
const XF = { range: '7d', from: null, to: null, type: '', vendor: '', severity: '', rule: '', status: '', scan: null };

/** Dates used to be hardcoded to tr-TR, so the English page showed Turkish. */
function pageLocale() {
    const lang = document.documentElement.lang || 'en';
    return lang === 'tr' ? 'tr-TR' : 'en-GB';
}

/** t() with a fallback, because a missing key comes back as the key itself. */
function tr(key, fallback, params) {
    const v = typeof t === 'function' ? t(key, params || {}) : '';
    if (v && v !== key) return v;
    return String(fallback).replace(/\{(\w+)\}/g, (m, k) => (params && k in params ? params[k] : m));
}

/** Vendor names come in two spellings: the raw OUI registrant in the per-scan
 *  tallies ("TP-Link Systems Inc", "Google, Inc.") and the curated name on the
 *  device ("TP-Link", "Google"). Compare them by normalised prefix so one
 *  vendor filter works across both. */
const vnorm = v => String(v || '').toLowerCase().replace(/[^a-z0-9]+/g, '');
function vendorMatch(a, b) {
    const x = vnorm(a), y = vnorm(b);
    if (!x || !y) return false;
    return x === y || (Math.min(x.length, y.length) >= 4 && (x.startsWith(y) || y.startsWith(x)));
}

const esc = v => String(v ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const token = name => getComputedStyle(document.documentElement).getPropertyValue(name).trim() || 'currentColor';
const fmtNum = n => Number(n || 0).toLocaleString(pageLocale());
const reduceMotion = () => window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
const ts = v => { const d = new Date(v); return isNaN(d) ? 0 : d.getTime(); };
const svgEl = (tag, attrs) => {
    const el = document.createElementNS(SVGNS, tag);
    for (const k in attrs || {}) el.setAttribute(k, attrs[k]);
    return el;
};

function ruleLabel(rule) {
    const fallback = {
        new_device: 'New device', device_online: 'Came online', device_offline: 'Went offline',
        ip_changed: 'IP changed', mac_changed: 'MAC changed', new_port: 'Port opened',
        port_closed: 'Port closed', high_latency: 'High latency', low_battery: 'Low battery',
        low_voltage: 'Low voltage', weak_signal: 'Weak signal', risky_port: 'Risky port open',
    }[rule] || rule;
    return tr('hx_rule_' + rule, fallback);
}
const sevLabel = s => tr(s, s.charAt(0).toUpperCase() + s.slice(1));
const sevColor = s => token(`--severity-${s}-fg`);

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

window.addEventListener('load', function () {
    readStateFromUrl();
    wireFilterBar();
    loadAll();
});

// translations.js fetches its table asynchronously, so the first render can
// beat it and paint raw keys into labels.
window.addEventListener('translationsLoaded', () => { renderAll(); loadUptime(); });

let resizeTimer = null;
window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => { renderTrend(false); renderAlertChart(false); }, 150);
});

async function getJson(url, fallback) {
    try {
        const r = await fetch(url);
        if (!r.ok) return fallback;
        return await r.json();
    } catch (e) {
        console.error('history: failed to load', url, e);
        return fallback;
    }
}

async function loadAll() {
    const [types, history, inv, a1, a2] = await Promise.all([
        getJson('/api/config/device_types', {}),
        getJson('/api/scan_history', []),
        getJson('/api/history/inventory', []),
        getJson('/api/alerts?limit=500&offset=0', { alerts: [] }),
        getJson('/api/alerts?limit=500&offset=500', { alerts: [] }),
    ]);
    deviceTypes = types || {};
    scanHistory = (Array.isArray(history) ? history : [])
        .filter(s => s && s.timestamp)
        .sort((a, b) => ts(a.timestamp) - ts(b.timestamp));
    inventory = Array.isArray(inv) ? inv : [];
    invByMac = new Map(inventory.filter(d => d.mac).map(d => [d.mac.toLowerCase(), d]));
    invByIp = new Map(inventory.filter(d => d.ip).map(d => [d.ip, d]));
    alertsAll = [...(a1.alerts || []), ...(a2.alerts || [])].filter(a => a && a.timestamp);
    fillSelects();
    renderAll(true);
    loadUptime();
}

// Refresh quietly every minute; a scheduled scan may have landed.
setInterval(() => { if (!document.hidden) loadAll(); }, 60000);

// ---------------------------------------------------------------------------
// Cross-filter state
// ---------------------------------------------------------------------------

function bounds() {
    if (XF.from != null && XF.to != null) return [XF.from, XF.to];
    const span = RANGES[XF.range] ?? RANGES['7d'];
    return span === Infinity ? [-Infinity, Infinity] : [Date.now() - span, Infinity];
}
const inRange = ms => { const [a, b] = bounds(); return ms >= a && ms <= b; };

function deviceOfAlert(a) {
    const mac = (a.mac || a.device_id || '').toLowerCase();
    const inv = (mac && invByMac.get(mac)) || (a.ip && invByIp.get(a.ip));
    if (inv) return inv;
    const det = a.details || {};
    return { device_type: det.device_type || 'Unknown', vendor: det.vendor || 'Unknown', status: '' };
}

/** Alerts in range matching every active dimension except those in `skip`. */
function alertsFiltered(skip = []) {
    return alertsAll.filter(a => {
        if (!inRange(ts(a.timestamp))) return false;
        if (XF.severity && !skip.includes('severity') && a.severity !== XF.severity) return false;
        if (XF.rule && !skip.includes('rule') && a.rule !== XF.rule) return false;
        if (XF.type || XF.vendor || XF.status) {
            const d = deviceOfAlert(a);
            if (XF.type && !skip.includes('type') && d.device_type !== XF.type) return false;
            if (XF.vendor && !skip.includes('vendor') && !vendorMatch(d.vendor, XF.vendor)) return false;
            if (XF.status && !skip.includes('status') && d.status !== XF.status) return false;
        }
        return true;
    });
}

/** Inventory rows matching every active dimension except those in `skip`.
 *  Severity/rule narrow to devices that raised such an alert in range. */
function devicesFiltered(skip = []) {
    let alertKeys = null;
    if ((XF.severity && !skip.includes('severity')) || (XF.rule && !skip.includes('rule'))) {
        alertKeys = new Set();
        alertsFiltered(['type', 'vendor', 'status']).forEach(a => {
            const d = deviceOfAlert(a);
            if (d.key) alertKeys.add(d.key);
        });
    }
    const [from] = bounds();
    return inventory.filter(d => {
        if (from > -Infinity && d.last_seen && ts(d.last_seen) && ts(d.last_seen) < from) return false;
        if (XF.type && !skip.includes('type') && d.device_type !== XF.type) return false;
        if (XF.vendor && !skip.includes('vendor') && !vendorMatch(d.vendor, XF.vendor)) return false;
        if (XF.status && !skip.includes('status') && d.status !== XF.status) return false;
        if (alertKeys && !alertKeys.has(d.key)) return false;
        return true;
    });
}

const scansInRange = () => scanHistory.filter(s => inRange(ts(s.timestamp)));
const pinnedScan = () => XF.scan ? scanHistory.find(s => s.timestamp === XF.scan) || null : null;

function setFilter(patch) {
    Object.assign(XF, patch);
    // A pinned scan that fell out of the window is no longer meaningful.
    if (XF.scan && !inRange(ts(XF.scan))) XF.scan = null;
    writeStateToUrl();
    syncFilterBar();
    renderAll(false);
    if (window.__uptimeRender) window.__uptimeRender();
}
const toggle = (dim, value) => setFilter({ [dim]: XF[dim] === value ? '' : value });

function readStateFromUrl() {
    const q = new URLSearchParams(location.search);
    if (q.get('range') && (q.get('range') in RANGES)) XF.range = q.get('range');
    ['type', 'vendor', 'severity', 'rule', 'status'].forEach(k => { if (q.get(k)) XF[k] = q.get(k); });
    if (q.get('from') && q.get('to')) { XF.from = +q.get('from'); XF.to = +q.get('to'); }
}

function writeStateToUrl() {
    const q = new URLSearchParams();
    if (XF.range !== '7d') q.set('range', XF.range);
    ['type', 'vendor', 'severity', 'rule', 'status'].forEach(k => { if (XF[k]) q.set(k, XF[k]); });
    if (XF.from != null) { q.set('from', Math.round(XF.from)); q.set('to', Math.round(XF.to)); }
    const qs = q.toString();
    history.replaceState(null, '', location.pathname + (qs ? '?' + qs : ''));
}

// ---------------------------------------------------------------------------
// Filter bar + chips
// ---------------------------------------------------------------------------

function wireFilterBar() {
    document.querySelectorAll('.hx-range__btn').forEach(btn => {
        btn.addEventListener('click', () => setFilter({ range: btn.dataset.range, from: null, to: null }));
    });
    [['hxType', 'type'], ['hxVendor', 'vendor'], ['hxSeverity', 'severity'], ['hxStatus', 'status']].forEach(([id, dim]) => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('change', () => setFilter({ [dim]: el.value }));
    });
    const reset = document.getElementById('hxReset');
    if (reset) reset.addEventListener('click', () =>
        setFilter({ range: '7d', from: null, to: null, type: '', vendor: '', severity: '', rule: '', status: '', scan: null }));
    syncFilterBar();
}

function fillSelects() {
    const fill = (id, values, label = v => v) => {
        const el = document.getElementById(id);
        if (!el) return;
        const keep = el.value;
        const first = el.options[0] ? el.options[0].outerHTML : '';
        el.innerHTML = first + values.map(v => `<option value="${esc(v)}">${esc(label(v))}</option>`).join('');
        el.value = keep;
    };
    const uniq = arr => [...new Set(arr.filter(Boolean))].sort((a, b) => a.localeCompare(b));
    fill('hxType', uniq(inventory.map(d => d.device_type)));
    fill('hxVendor', uniq(inventory.map(d => d.vendor)));
    const sevs = SEVERITIES.filter(s => alertsAll.some(a => a.severity === s));
    fill('hxSeverity', sevs, sevLabel);
    syncFilterBar();
}

function syncFilterBar() {
    const custom = XF.from != null;
    document.querySelectorAll('.hx-range__btn').forEach(btn => {
        const on = !custom && btn.dataset.range === XF.range;
        btn.classList.toggle('is-active', on);
        btn.setAttribute('aria-checked', on ? 'true' : 'false');
    });
    [['hxType', 'type'], ['hxVendor', 'vendor'], ['hxSeverity', 'severity'], ['hxStatus', 'status']].forEach(([id, dim]) => {
        const el = document.getElementById(id);
        if (!el) return;
        // A value that is not an option yet (still loading) is added so the
        // select never silently shows "All" while a filter is on.
        if (XF[dim] && ![...el.options].some(o => o.value === XF[dim])) {
            el.insertAdjacentHTML('beforeend', `<option value="${esc(XF[dim])}">${esc(XF[dim])}</option>`);
        }
        el.value = XF[dim];
        el.classList.toggle('is-filtered', !!XF[dim]);
    });

    const chips = [];
    const fmt = ms => new Date(ms).toLocaleString(pageLocale(), { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    if (custom) chips.push(['range', `${tr('hx_custom_range', 'Window')}: ${fmt(XF.from)} – ${fmt(XF.to)}`]);
    if (XF.scan) chips.push(['scan', `${tr('hx_pinned_scan', 'Pinned scan')}: ${fmt(ts(XF.scan))}`]);
    if (XF.type) chips.push(['type', `${tr('device_type', 'Device type')}: ${XF.type}`]);
    if (XF.vendor) chips.push(['vendor', `${tr('vendor', 'Vendor')}: ${XF.vendor}`]);
    if (XF.status) chips.push(['status', `${tr('status', 'Status')}: ${tr(XF.status, XF.status)}`]);
    if (XF.severity) chips.push(['severity', `${tr('hx_severity', 'Severity')}: ${sevLabel(XF.severity)}`]);
    if (XF.rule) chips.push(['rule', `${tr('hx_rule', 'Event')}: ${ruleLabel(XF.rule)}`]);

    const host = document.getElementById('hxChips');
    if (host) {
        host.innerHTML = chips.map(([dim, text]) => `
            <button type="button" class="hx-chip" data-dim="${dim}" title="${esc(tr('hx_remove_filter', 'Remove filter'))}">
                <span>${esc(text)}</span>
                <svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-x"/></svg>
            </button>`).join('');
        host.querySelectorAll('.hx-chip').forEach(chip => chip.addEventListener('click', () => {
            const dim = chip.dataset.dim;
            if (dim === 'range') setFilter({ from: null, to: null });
            else if (dim === 'scan') setFilter({ scan: null });
            else setFilter({ [dim]: '' });
        }));
    }
    const reset = document.getElementById('hxReset');
    if (reset) reset.hidden = chips.length === 0 && XF.range === '7d';
}

// ---------------------------------------------------------------------------
// Render orchestration
// ---------------------------------------------------------------------------

function renderAll(animate = false) {
    syncFilterBar();
    updateStatistics();
    renderTrend(animate);
    renderTypeChart();
    renderVendorChart();
    renderAlertChart(animate);
    renderRuleChart();
    updateHistoryTable();
    updateTimeline();
}

function animateNumber(el, value, suffix = '') {
    if (!el) return;
    const from = parseFloat(el.dataset.v || '0') || 0;
    el.dataset.v = value;
    if (reduceMotion() || from === value) { el.textContent = fmtNum(value) + suffix; return; }
    const t0 = performance.now(), dur = 420;
    const step = now => {
        const p = Math.min(1, (now - t0) / dur);
        const e = 1 - Math.pow(1 - p, 3);
        el.textContent = fmtNum(Math.round(from + (value - from) * e)) + suffix;
        if (p < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
}

function updateStatistics() {
    const scans = scansInRange();
    const devs = devicesFiltered();
    const filtered = XF.type || XF.vendor || XF.status || XF.severity || XF.rule;
    // Under a type/vendor filter the average follows that slice, like the trend.
    const avgKey = XF.type ? 'type' : XF.vendor ? 'vendor' : 'online';
    const online = scans.map(s => seriesValue(s, avgKey));
    const avgOnline = online.length ? Math.round(online.reduce((a, b) => a + b, 0) / online.length) : 0;
    const last = scans[scans.length - 1];
    animateNumber(document.getElementById('totalScans'), scans.length);
    animateNumber(document.getElementById('totalDevices'), filtered || !last ? devs.length : (last.total_devices || 0));
    animateNumber(document.getElementById('avgDevices'), avgOnline);
    animateNumber(document.getElementById('alertCount'), alertsFiltered().length);
    animateNumber(document.getElementById('lastScanDuration'), last ? Math.round(last.scan_duration || 0) : 0, 's');
    const lbl = document.getElementById('totalDevicesLabel');
    const avgLbl = document.getElementById('avgDevicesLabel');
    if (avgLbl) avgLbl.textContent = avgKey === 'online'
        ? tr('hx_avg_online', 'Avg. online per scan')
        : tr('hx_avg_slice', 'Avg. per scan: {name}', { name: XF.type || XF.vendor });
    if (lbl) lbl.textContent = filtered ? tr('hx_matching_devices', 'Matching devices') : tr('detected_unique_devices', 'Detected devices');
}

// ---------------------------------------------------------------------------
// Trend (devices over time) - line chart with crosshair, brush and pin
// ---------------------------------------------------------------------------

/** One scan -> the plotted value. With a type/vendor filter the series is
 *  that slice of each scan's own tally; otherwise total/online. */
function seriesValue(scan, key) {
    if (key === 'online') return scan.online_devices || 0;
    if (key === 'total') return scan.total_devices || 0;
    if (key === 'type') return (scan.device_types || {})[XF.type] || 0;
    if (key === 'vendor') return Object.entries(scan.vendors || {})
        .reduce((n, [v, c]) => n + (vendorMatch(v, XF.vendor) ? c : 0), 0);
    return 0;
}

const hiddenSeries = new Set();

function trendSeries() {
    if (XF.type) return [{ key: 'type', label: XF.type, color: token('--chart-1') }];
    if (XF.vendor) return [{ key: 'vendor', label: XF.vendor, color: token('--chart-1') }];
    return [
        { key: 'total', label: tr('total_devices', 'Total devices'), color: token('--chart-1') },
        { key: 'online', label: tr('online_devices', 'Online devices'), color: token('--chart-2') },
    ];
}

function niceMax(v) {
    if (v <= 4) return 4;
    if (v < 20) return Math.ceil(v / 4) * 4;   // integer ticks on small counts
    const p = Math.pow(10, Math.floor(Math.log10(v)));
    const n = v / p;
    // Steps that divide cleanly into the 4 grid intervals (no 37.5 labels).
    const step = [1, 1.2, 1.6, 2, 2.4, 3.2, 4, 4.8, 6, 8, 10].find(k => n <= k);
    return step * p;
}

function timeTicks(a, b, max = 6) {
    const span = b - a;
    const steps = [36e5, 3 * 36e5, 6 * 36e5, 12 * 36e5, 864e5, 2 * 864e5, 7 * 864e5, 14 * 864e5, 30 * 864e5];
    const step = steps.find(s => span / s <= max) || steps[steps.length - 1];
    const out = [];
    const start = new Date(a);
    if (step >= 864e5) start.setHours(0, 0, 0, 0); else start.setMinutes(0, 0, 0);
    for (let x = start.getTime(); x <= b; x += step) if (x >= a) out.push(x);
    return { ticks: out, daily: step >= 864e5 };
}

function renderTrend(animate) {
    const host = document.getElementById('trendChart');
    const legend = document.getElementById('trendLegend');
    const title = document.getElementById('trendTitle');
    if (!host) return;
    const scans = scansInRange();
    const series = trendSeries();
    if (title) title.textContent = XF.type || XF.vendor
        ? tr('hx_slice_over_time', `${XF.type || XF.vendor} over time`, { name: XF.type || XF.vendor })
        : tr('hx_devices_over_time', 'Devices over time');

    if (legend) {
        legend.innerHTML = series.length > 1 ? series.map(s => `
            <button type="button" class="hx-legend__item${hiddenSeries.has(s.key) ? ' is-off' : ''}" data-key="${s.key}" aria-pressed="${!hiddenSeries.has(s.key)}">
                <i class="hx-legend__swatch" style="background:${s.color}"></i>${esc(s.label)}
            </button>`).join('') : '';
        legend.querySelectorAll('.hx-legend__item').forEach(b => b.addEventListener('click', () => {
            const k = b.dataset.key;
            hiddenSeries.has(k) ? hiddenSeries.delete(k) : hiddenSeries.add(k);
            renderTrend(false);
        }));
    }

    host.innerHTML = '';
    if (scans.length < 2) {
        host.innerHTML = `<p class="chart-empty">${esc(scanHistory.length < 2
            ? tr('trend_needs_two_scans', 'At least two scans are needed to show a trend')
            : tr('hx_no_scans_in_range', 'No scans in this time range'))}</p>`;
        return;
    }

    const W = Math.max(320, host.clientWidth || 800), H = 300;
    const m = { top: 16, right: 16, bottom: 30, left: 40 };
    const iw = W - m.left - m.right, ih = H - m.top - m.bottom;
    const t0 = ts(scans[0].timestamp), t1 = ts(scans[scans.length - 1].timestamp) || t0 + 1;
    const visible = series.filter(s => !hiddenSeries.has(s.key));
    const vmax = niceMax(Math.max(1, ...scans.flatMap(s => visible.map(v => seriesValue(s, v.key)))));
    const x = ms => m.left + (t1 === t0 ? iw / 2 : (ms - t0) / (t1 - t0) * iw);
    const y = v => m.top + ih - v / vmax * ih;

    const svg = svgEl('svg', { viewBox: `0 0 ${W} ${H}`, class: 'hx-svg', role: 'img',
        'aria-label': tr('hx_devices_over_time', 'Devices over time') });

    // Recessive grid + y labels.
    for (let i = 0; i <= 4; i++) {
        const v = vmax * i / 4, yy = y(v);
        svg.appendChild(svgEl('line', { x1: m.left, x2: W - m.right, y1: yy, y2: yy, class: i ? 'hx-grid' : 'hx-baseline' }));
        const tx = svgEl('text', { x: m.left - 8, y: yy + 4, 'text-anchor': 'end', class: 'hx-axis' });
        tx.textContent = fmtNum(Math.round(v));
        svg.appendChild(tx);
    }
    const { ticks, daily } = timeTicks(t0, t1);
    ticks.forEach(ms => {
        const tx = svgEl('text', { x: x(ms), y: H - 8, 'text-anchor': 'middle', class: 'hx-axis' });
        tx.textContent = new Date(ms).toLocaleString(pageLocale(), daily
            ? { month: 'short', day: 'numeric' } : { hour: '2-digit', minute: '2-digit' });
        svg.appendChild(tx);
    });

    // Lines (2px) with a soft area under the first visible series only - two
    // overlapping fills would muddy each other.
    visible.forEach((s, si) => {
        const pts = scans.map(sc => [x(ts(sc.timestamp)), y(seriesValue(sc, s.key))]);
        const d = pts.map((p, i) => (i ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1)).join(' ');
        if (si === 0) {
            const area = svgEl('path', { d: `${d} L ${pts[pts.length - 1][0]} ${m.top + ih} L ${pts[0][0]} ${m.top + ih} Z`,
                fill: s.color, class: 'hx-area' });
            svg.appendChild(area);
        }
        const line = svgEl('path', { d, stroke: s.color, class: 'hx-line' });
        svg.appendChild(line);
        if (animate && !reduceMotion()) {
            requestAnimationFrame(() => {
                const len = line.getTotalLength();
                line.style.strokeDasharray = `${len}`;
                line.style.strokeDashoffset = `${len}`;
                line.getBoundingClientRect();
                line.style.transition = 'stroke-dashoffset 700ms var(--ease-out)';
                line.style.strokeDashoffset = '0';
                setTimeout(() => { line.style.strokeDasharray = ''; line.style.transition = ''; }, 760);
            });
        }
        // Direct end label on the last point (<= 4 series).
        const lp = pts[pts.length - 1];
        const lbl = svgEl('text', { x: Math.min(lp[0], W - m.right) - 4, y: lp[1] - 8, 'text-anchor': 'end', class: 'hx-endlabel' });
        lbl.textContent = fmtNum(seriesValue(scans[scans.length - 1], s.key));
        svg.appendChild(lbl);
    });

    // Pinned scan marker.
    const pin = pinnedScan();
    if (pin && inRange(ts(pin.timestamp))) {
        const px = x(ts(pin.timestamp));
        svg.appendChild(svgEl('line', { x1: px, x2: px, y1: m.top, y2: m.top + ih, class: 'hx-pin' }));
    }

    // Interaction layer: crosshair + tooltip, brush to zoom, click to pin.
    const cross = svgEl('line', { y1: m.top, y2: m.top + ih, class: 'hx-cross', visibility: 'hidden' });
    const dots = visible.map(s => svgEl('circle', { r: 4.5, fill: s.color, class: 'hx-dot', visibility: 'hidden' }));
    const brush = svgEl('rect', { y: m.top, height: ih, class: 'hx-brush', visibility: 'hidden' });
    svg.appendChild(brush);
    svg.appendChild(cross);
    dots.forEach(d => svg.appendChild(d));
    const hit = svgEl('rect', { x: m.left, y: m.top, width: iw, height: ih, class: 'hx-hit' });
    svg.appendChild(hit);

    const toSvgX = ev => {
        const r = svg.getBoundingClientRect();
        return (ev.clientX - r.left) * (W / r.width);
    };
    const nearest = sx => {
        let best = 0, bd = Infinity;
        scans.forEach((sc, i) => { const d = Math.abs(x(ts(sc.timestamp)) - sx); if (d < bd) { bd = d; best = i; } });
        return best;
    };
    let dragStart = null;
    hit.addEventListener('pointerdown', ev => { dragStart = toSvgX(ev); hit.setPointerCapture(ev.pointerId); });
    hit.addEventListener('pointermove', ev => {
        const sx = toSvgX(ev);
        if (dragStart != null && Math.abs(sx - dragStart) > 4) {
            const a = Math.max(m.left, Math.min(sx, dragStart)), b = Math.min(m.left + iw, Math.max(sx, dragStart));
            brush.setAttribute('x', a); brush.setAttribute('width', b - a); brush.setAttribute('visibility', 'visible');
            hideTooltip();
            return;
        }
        const i = nearest(sx), sc = scans[i], cx = x(ts(sc.timestamp));
        cross.setAttribute('x1', cx); cross.setAttribute('x2', cx); cross.setAttribute('visibility', 'visible');
        visible.forEach((s, k) => {
            dots[k].setAttribute('cx', cx); dots[k].setAttribute('cy', y(seriesValue(sc, s.key)));
            dots[k].setAttribute('visibility', 'visible');
        });
        showTooltip(ev, `<div class="hx-tip__title">${esc(new Date(ts(sc.timestamp)).toLocaleString(pageLocale()))}</div>` +
            visible.map(s => `<div class="hx-tip__row"><i style="background:${s.color}"></i><span>${esc(s.label)}</span><strong>${fmtNum(seriesValue(sc, s.key))}</strong></div>`).join('') +
            `<div class="hx-tip__hint">${esc(tr('hx_click_to_pin', 'Click to pin this scan · drag to zoom'))}</div>`);
    });
    const leave = () => {
        cross.setAttribute('visibility', 'hidden');
        dots.forEach(d => d.setAttribute('visibility', 'hidden'));
        hideTooltip();
    };
    hit.addEventListener('pointerleave', () => { if (dragStart == null) leave(); });
    hit.addEventListener('pointerup', ev => {
        const sx = toSvgX(ev), start = dragStart;
        dragStart = null;
        brush.setAttribute('visibility', 'hidden');
        if (start != null && Math.abs(sx - start) > 4) {
            const inv = px => t0 + (px - m.left) / iw * (t1 - t0);
            const a = inv(Math.max(m.left, Math.min(sx, start))), b = inv(Math.min(m.left + iw, Math.max(sx, start)));
            leave();
            setFilter({ from: a, to: b });
        } else {
            const sc = scans[nearest(sx)];
            setFilter({ scan: XF.scan === sc.timestamp ? null : sc.timestamp });
        }
    });

    host.appendChild(svg);
}

// ---------------------------------------------------------------------------
// Horizontal bar lists (device type, vendor, rule)
// ---------------------------------------------------------------------------

/**
 * entries: [{key, label, value, icon?}] sorted desc. `selected` dims the rest;
 * onPick(key) toggles the dimension. Bars are buttons, so keyboard and screen
 * readers get the same cross-filter as the mouse. Widths animate via CSS.
 */
function renderBars(host, entries, { selected = '', onPick, limit = 10, color, empty, same = (a, b) => a === b } = {}) {
    if (!host) return;
    if (!entries.length) {
        host.innerHTML = `<p class="chart-empty">${esc(empty || tr('no_data', 'No data'))}</p>`;
        return;
    }
    let rows = entries.slice(0, limit);
    const rest = entries.slice(limit);
    // Keep a selected key visible even when it ranks below the cut.
    if (selected && !rows.some(r => same(r.key, selected))) {
        const s = entries.find(r => same(r.key, selected));
        if (s) { rows = rows.slice(0, limit - 1).concat(s); }
    }
    if (rest.length && !rest.every(r => rows.includes(r))) {
        const other = rest.filter(r => !rows.includes(r)).reduce((n, r) => n + r.value, 0);
        if (other) rows = rows.concat({ key: '__other', label: tr('hx_other', 'Other') + ` (${rest.length})`, value: other, other: true });
    }
    const max = Math.max(1, ...rows.map(r => r.value));
    const prev = new Map([...host.querySelectorAll('.hx-bar')].map(b => [b.dataset.key, b.querySelector('.hx-bar__fill').style.width]));
    host.innerHTML = rows.map(r => {
        const on = selected && !r.other && same(r.key, selected);
        const dim = selected && !on;
        return `<button type="button" class="hx-bar${on ? ' is-selected' : ''}${dim ? ' is-dimmed' : ''}${r.other ? ' is-other' : ''}"
                    data-key="${esc(r.key)}" ${r.other ? 'disabled' : ''} aria-pressed="${on ? 'true' : 'false'}"
                    title="${esc(r.label)}: ${fmtNum(r.value)}">
                    <span class="hx-bar__label">${r.icon ? `<span class="hx-bar__icon" aria-hidden="true">${esc(r.icon)}</span>` : ''}${esc(r.label)}</span>
                    <span class="hx-bar__track"><span class="hx-bar__fill" style="width:${prev.get(r.key) || '0%'};background:${color}" data-w="${(r.value / max * 100).toFixed(2)}%"></span></span>
                    <span class="hx-bar__value">${fmtNum(r.value)}</span>
                </button>`;
    }).join('');
    requestAnimationFrame(() => host.querySelectorAll('.hx-bar__fill').forEach(f => { f.style.width = f.dataset.w; }));
    host.querySelectorAll('.hx-bar:not(.is-other)').forEach(b => {
        b.addEventListener('click', () => onPick && onPick(b.dataset.key));
        b.addEventListener('pointermove', ev => showTooltip(ev,
            `<div class="hx-tip__title">${esc(b.title)}</div><div class="hx-tip__hint">${esc(tr('hx_click_to_filter', 'Click to filter every chart'))}</div>`));
        b.addEventListener('pointerleave', hideTooltip);
    });
}

const tally = (rows, key) => {
    const out = new Map();
    rows.forEach(r => out.set(r[key] || 'Unknown', (out.get(r[key] || 'Unknown') || 0) + 1));
    return [...out.entries()].map(([k, v]) => ({ key: k, label: k, value: v })).sort((a, b) => b.value - a.value);
};

function snapshotHint(el, pin) {
    if (!el) return;
    el.textContent = pin
        ? tr('hx_from_scan', 'Counts from the pinned scan of {date}', { date: new Date(ts(pin.timestamp)).toLocaleString(pageLocale()) })
        : tr('hx_from_inventory', 'Current inventory, narrowed by the active filters');
}

function renderTypeChart() {
    const pin = pinnedScan();
    snapshotHint(document.getElementById('typeHint'), pin);
    const entries = pin
        ? Object.entries(pin.device_types || {}).map(([k, v]) => ({ key: k, label: k, value: v })).sort((a, b) => b.value - a.value)
        : tally(devicesFiltered(['type']), 'device_type');
    entries.forEach(e => { e.icon = getDeviceTypeIcon(e.key); });
    renderBars(document.getElementById('deviceTypeChart'), entries, {
        selected: XF.type, onPick: k => toggle('type', k), color: token('--chart-1'), limit: 12,
    });
}

function renderVendorChart() {
    const pin = pinnedScan();
    snapshotHint(document.getElementById('vendorHint'), pin);
    const entries = pin
        ? Object.entries(pin.vendors || {}).map(([k, v]) => ({ key: k, label: k, value: v })).sort((a, b) => b.value - a.value)
        : tally(devicesFiltered(['vendor']), 'vendor');
    renderBars(document.getElementById('vendorChart'), entries, {
        selected: XF.vendor, color: token('--chart-1'), limit: 12, same: vendorMatch,
        onPick: k => setFilter({ vendor: XF.vendor && vendorMatch(k, XF.vendor) ? '' : k }),
    });
}

function renderRuleChart() {
    const entries = tally(alertsFiltered(['rule']), 'rule').map(e => ({ ...e, label: ruleLabel(e.key) }));
    renderBars(document.getElementById('ruleChart'), entries, {
        selected: XF.rule, onPick: k => toggle('rule', k), color: token('--chart-1'), limit: 8,
        empty: tr('hx_no_alerts', 'No alerts in this range'),
    });
}

// ---------------------------------------------------------------------------
// Alerts over time - stacked columns by severity
// ---------------------------------------------------------------------------

function renderAlertChart(animate) {
    const host = document.getElementById('alertChart');
    const legend = document.getElementById('alertLegend');
    if (!host) return;
    const alerts = alertsFiltered(['severity']);
    const present = SEVERITIES.filter(s => alerts.some(a => a.severity === s));

    if (legend) {
        legend.innerHTML = present.map(s => `
            <button type="button" class="hx-legend__item${XF.severity && XF.severity !== s ? ' is-off' : ''}" data-sev="${s}" aria-pressed="${XF.severity === s}">
                <i class="hx-legend__swatch" style="background:${sevColor(s)}"></i>${esc(sevLabel(s))}
            </button>`).join('');
        legend.querySelectorAll('.hx-legend__item').forEach(b => b.addEventListener('click', () => toggle('severity', b.dataset.sev)));
    }

    host.innerHTML = '';
    if (!alerts.length) {
        host.innerHTML = `<p class="chart-empty">${esc(tr('hx_no_alerts', 'No alerts in this range'))}</p>`;
        return;
    }
    let [a, b] = bounds();
    const times = alerts.map(x => ts(x.timestamp));
    if (a === -Infinity) a = Math.min(...times);
    if (b === Infinity) b = Date.now();
    const span = Math.max(36e5, b - a);
    const bucket = [36e5, 3 * 36e5, 6 * 36e5, 12 * 36e5, 864e5, 7 * 864e5].find(s => span / s <= 48) || 7 * 864e5;
    const start = Math.floor(a / bucket) * bucket;
    const n = Math.max(1, Math.ceil((b - start) / bucket));
    const counts = Array.from({ length: n }, () => Object.fromEntries(SEVERITIES.map(s => [s, 0])));
    alerts.forEach(x => {
        const i = Math.min(n - 1, Math.max(0, Math.floor((ts(x.timestamp) - start) / bucket)));
        if (counts[i][x.severity] != null) counts[i][x.severity]++;
    });

    const W = Math.max(280, host.clientWidth || 500), H = 220;
    const m = { top: 12, right: 8, bottom: 28, left: 36 };
    const iw = W - m.left - m.right, ih = H - m.top - m.bottom;
    const totals = counts.map(c => SEVERITIES.reduce((s, k) => s + c[k], 0));
    const vmax = niceMax(Math.max(1, ...totals));
    const bw = iw / n, gap = Math.min(4, bw * 0.25);
    const y = v => m.top + ih - v / vmax * ih;
    const svg = svgEl('svg', { viewBox: `0 0 ${W} ${H}`, class: 'hx-svg', role: 'img',
        'aria-label': tr('hx_alerts_over_time', 'Alerts over time') });
    for (let i = 0; i <= 2; i++) {
        const v = vmax * i / 2;
        svg.appendChild(svgEl('line', { x1: m.left, x2: W - m.right, y1: y(v), y2: y(v), class: i ? 'hx-grid' : 'hx-baseline' }));
        const tx = svgEl('text', { x: m.left - 6, y: y(v) + 4, 'text-anchor': 'end', class: 'hx-axis' });
        tx.textContent = fmtNum(Math.round(v));
        svg.appendChild(tx);
    }
    const daily = bucket >= 864e5;
    const every = Math.ceil(n / 6);
    const g = svgEl('g', { class: animate && !reduceMotion() ? 'hx-cols hx-cols--grow' : 'hx-cols' });
    counts.forEach((c, i) => {
        const x0 = m.left + i * bw + gap / 2, w = Math.max(1, bw - gap);
        let acc = 0;
        // Stack bottom-up: info at the base, critical on top.
        [...SEVERITIES].reverse().forEach(s => {
            if (!c[s]) return;
            const y1 = y(acc + c[s]), y0 = y(acc);
            const rect = svgEl('rect', { x: x0, y: y1, width: w, height: Math.max(0, y0 - y1), fill: sevColor(s),
                class: 'hx-col' + (XF.severity && XF.severity !== s ? ' is-dimmed' : ''), 'data-sev': s });
            rect.addEventListener('pointermove', ev => showTooltip(ev,
                `<div class="hx-tip__title">${esc(new Date(start + i * bucket).toLocaleString(pageLocale(), daily ? { month: 'short', day: 'numeric' } : { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }))}</div>` +
                SEVERITIES.filter(k => c[k]).map(k => `<div class="hx-tip__row"><i style="background:${sevColor(k)}"></i><span>${esc(sevLabel(k))}</span><strong>${fmtNum(c[k])}</strong></div>`).join('') +
                `<div class="hx-tip__hint">${esc(tr('hx_click_to_filter', 'Click to filter every chart'))}</div>`));
            rect.addEventListener('pointerleave', hideTooltip);
            rect.addEventListener('click', () => toggle('severity', s));
            g.appendChild(rect);
            acc += c[s];
        });
        if (i % every === 0) {
            const tx = svgEl('text', { x: x0 + w / 2, y: H - 8, 'text-anchor': 'middle', class: 'hx-axis' });
            tx.textContent = new Date(start + i * bucket).toLocaleString(pageLocale(), daily ? { month: 'short', day: 'numeric' } : { hour: '2-digit', minute: '2-digit' });
            svg.appendChild(tx);
        }
    });
    svg.appendChild(g);
    host.appendChild(svg);
}

// ---------------------------------------------------------------------------
// Tooltip
// ---------------------------------------------------------------------------

function showTooltip(ev, html) {
    const tip = document.getElementById('hxTooltip');
    if (!tip) return;
    tip.innerHTML = html;
    tip.hidden = false;
    const pad = 14, r = tip.getBoundingClientRect();
    let left = ev.clientX + pad, top = ev.clientY + pad;
    if (left + r.width > window.innerWidth - 8) left = ev.clientX - r.width - pad;
    if (top + r.height > window.innerHeight - 8) top = ev.clientY - r.height - pad;
    tip.style.left = left + 'px';
    tip.style.top = top + 'px';
}
function hideTooltip() {
    const tip = document.getElementById('hxTooltip');
    if (tip) tip.hidden = true;
}

// ---------------------------------------------------------------------------
// Table + timeline (range-aware; a row click pins that scan)
// ---------------------------------------------------------------------------

function updateHistoryTable() {
    const body = document.getElementById('historyTableBody');
    if (!body) return;
    const scans = scansInRange();
    if (!scans.length) {
        body.innerHTML = `<tr><td colspan="6" class="hx-table-empty">${esc(tr('hx_no_scans_in_range', 'No scans in this time range'))}</td></tr>`;
        return;
    }
    let recent = scans.slice(-20);
    const pin = pinnedScan();
    if (pin && inRange(ts(pin.timestamp)) && !recent.includes(pin)) recent = [pin, ...recent.slice(1)];
    recent = recent.reverse();
    body.innerHTML = recent.map((scan, i) => {
        const prev = recent[i + 1];
        let cls = 'trend-stable', txt = tr('trend_stable', 'Stable');
        if (prev) {
            const d = (scan.total_devices || 0) - (prev.total_devices || 0);
            if (d > 0) { cls = 'trend-up'; txt = `+${d}`; } else if (d < 0) { cls = 'trend-down'; txt = `${d}`; }
        }
        const pinned = XF.scan === scan.timestamp;
        return `<tr class="hx-row${pinned ? ' is-pinned' : ''}" data-ts="${esc(scan.timestamp)}" tabindex="0">
            <td>${esc(new Date(ts(scan.timestamp)).toLocaleString(pageLocale()))}</td>
            <td>${esc(scan.ip_range || 'N/A')}</td>
            <td>${fmtNum(scan.total_devices)}</td>
            <td>${fmtNum(scan.online_devices)}</td>
            <td>${Math.round(scan.scan_duration || 0)}s</td>
            <td><span class="trend-indicator ${cls}">${esc(txt)}</span></td>
        </tr>`;
    }).join('');
    body.querySelectorAll('.hx-row').forEach(row => {
        const pick = () => setFilter({ scan: XF.scan === row.dataset.ts ? null : row.dataset.ts });
        row.addEventListener('click', pick);
        row.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); pick(); } });
    });
}

function updateTimeline() {
    const host = document.getElementById('scanTimeline');
    if (!host) return;
    const scans = scansInRange().slice(-10).reverse();
    if (!scans.length) {
        host.innerHTML = `<p class="chart-empty">${esc(tr('hx_no_scans_in_range', 'No scans in this time range'))}</p>`;
        return;
    }
    host.innerHTML = scans.map(scan => {
        const top = o => Object.entries(o || {}).sort((a, b) => b[1] - a[1])[0];
        const tt = top(scan.device_types), tv = top(scan.vendors);
        return `<div class="timeline-item">
            <div class="timeline-date">${esc(new Date(ts(scan.timestamp)).toLocaleString(pageLocale()))}</div>
            <div class="timeline-content">
                <div class="timeline-title">${fmtNum(scan.total_devices)} ${esc(tr('devices', 'devices'))} (${fmtNum(scan.online_devices)} ${esc(tr('online', 'online'))})</div>
                <div class="timeline-details">
                    <strong>${esc(tr('ip_range', 'IP range'))}:</strong> ${esc(scan.ip_range || 'N/A')}<br>
                    <strong>${esc(tr('scan_duration', 'Scan duration'))}:</strong> ${Math.round(scan.scan_duration || 0)}s<br>
                    ${tt ? `<strong>${esc(tr('top_device_type', 'Top device type'))}:</strong> ${esc(tt[0])} (${tt[1]})<br>` : ''}
                    ${tv ? `<strong>${esc(tr('top_vendor', 'Top vendor'))}:</strong> ${esc(tv[0])} (${tv[1]})` : ''}
                </div>
            </div>
        </div>`;
    }).join('');
}

// ---------------------------------------------------------------------------
// Export / clear (unchanged behaviour)
// ---------------------------------------------------------------------------

function getDeviceTypeIcon(deviceTypeName) {
    if (deviceTypes[deviceTypeName] && deviceTypes[deviceTypeName].icon) {
        return deviceTypes[deviceTypeName].icon;
    }
    const fallbackIcons = {
        'Unknown': '❓', 'Router': '🌐', 'Switch': '🔀', 'Smartphone': '📱', 'Tablet': '📃',
        'Laptop': '💻', 'Desktop': '🖥️', 'Printer': '🖨️', 'IP Camera': '📹', 'Smart TV': '📺',
        'Gaming Console': '🎮', 'Smart Speaker': '🔊', 'NAS': '💾', 'IoT Device': '🔗'
    };
    if (deviceTypeName && /docker/i.test(deviceTypeName)) return '🐳';
    return fallbackIcons[deviceTypeName] || '📦';
}

function exportHistory() {
    const dataStr = JSON.stringify(scanHistory, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `lan_scanner_history_${new Date().toISOString().split('T')[0]}.json`;
    link.click();
    URL.revokeObjectURL(url);
}

async function clearHistory() {
    if (!confirm(tr('confirm_clear_history', 'Delete the whole scan history? This cannot be undone.'))) return;
    try {
        const response = await fetch('/api/clear_history', { method: 'POST', headers: { 'Content-Type': 'application/json' } });
        const result = await response.json();
        if (result.success) {
            scanHistory = [];
            renderAll(false);
            alert(tr('history_cleared', 'History cleared'));
        } else {
            alert(tr('history_clear_error', 'Could not clear history') + ': ' + result.error);
        }
    } catch (error) {
        alert(tr('history_clear_error', 'Could not clear history') + ': ' + error.message);
    }
}

// ---------------------------------------------------------------------------
// Per-device availability strip
// ---------------------------------------------------------------------------

/** Cross-filter predicate for an uptime row (rows carry type/ip/mac but no
 *  vendor or status, so those come from the inventory). */
function uptimeRowMatches(d) {
    if (!(XF.type || XF.vendor || XF.status || XF.severity || XF.rule)) return true;
    const inv = (d.mac && invByMac.get(String(d.mac).toLowerCase())) || (d.ip && invByIp.get(d.ip)) || null;
    if (XF.type && (d.device_type || (inv && inv.device_type)) !== XF.type) return false;
    if (XF.vendor && (!inv || !vendorMatch(inv.vendor, XF.vendor))) return false;
    if (XF.status && (!inv || inv.status !== XF.status)) return false;
    if (XF.severity || XF.rule) {
        if (!inv) return false;
        return devicesFiltered(['type', 'vendor', 'status']).some(x => x.key === inv.key);
    }
    return true;
}

/*
 * Per-device availability strip. Only shown when scheduled scanning is on -
 * without it there is nothing sampling the network, so the cells would be a
 * misleading record of whenever somebody happened to press Scan.
 */
async function loadUptime() {
    const card = document.getElementById('uptimeCard');
    if (!card) return;

    let data;
    try {
        data = await (await fetch('/api/monitoring/uptime?limit=48')).json();
    } catch (error) {
        card.hidden = true;
        return;
    }

    if (!data.enabled || !data.devices || !data.devices.length) {
        card.hidden = true;
        return;
    }
    card.hidden = false;

    const esc = v => String(v ?? '').replace(/[&<>"']/g, c =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    const icon = type => (typeof getDeviceTypeIcon === 'function' ? getDeviceTypeIcon(type) : '');

    const first = data.checks[0];
    const last = data.checks[data.checks.length - 1];
    const incidents = data.devices.reduce((sum, d) => sum + d.incidents, 0);
    document.getElementById('uptimeSummary').textContent = t('uptime_summary', {
        checks: data.checks.length,
        incidents: incidents,
        from: first ? new Date(first).toLocaleString(pageLocale()) : '—',
        to: last ? new Date(last).toLocaleString(pageLocale()) : '—'
    });

    // Sort by availability %, highest first (the always-on devices at the top,
    // the one-hit-wonder rotating-MAC noise at the bottom), then IP as tie-break.
    const ipParts = ip => (ip || '').split('.').map(n => parseInt(n, 10) || 0);
    const sorted = data.devices.slice().sort(function (a, b) {
        if ((b.uptime || 0) !== (a.uptime || 0)) return (b.uptime || 0) - (a.uptime || 0);
        if (!a.ip || !b.ip) {
            if (Boolean(a.ip) !== Boolean(b.ip)) return a.ip ? -1 : 1;
            return String(a.name || '').localeCompare(String(b.name || ''));
        }
        const pa = ipParts(a.ip), pb = ipParts(b.ip);
        for (let i = 0; i < 4; i++) if (pa[i] !== pb[i]) return pa[i] - pb[i];
        return 0;
    });

    // Last non-null cell = the device's most recent known reachability.
    const lastState = d => [...d.cells].reverse().find(s => s) || null;

    const PAGE_SIZE = 60;   // rotating-MAC devices can push this into the hundreds
    let page = 0;

    const render = function () {
        const statusF = (document.getElementById('uptimeStatusFilter') || {}).value || 'all';
        const F = window.MynesFilters;
        const s = F ? F.get() : null;
        const rows = sorted.filter(function (d) {
            if (statusF === 'active' && lastState(d) !== 'up') return false;
            if (statusF === 'passive' && lastState(d) === 'up') return false;
            // Shared filters. Uptime rows carry device_type/ip/name but no
            // vendor, so the vendor dimension is intentionally skipped here.
            if (!uptimeRowMatches(d)) return false;
            if (s) {
                if (!s.showContainers && F.isContainer(d)) return false;
                if (!s.showNoIp && F.isNoIp(d)) return false;
                if (!s.showBluetooth && F.isBluetooth(d)) return false;
                if (!s.showRandomMac && F.isRandomMac(d) && !F.isContainer(d)) return false;
                if (s.types.length && !s.types.includes(d.device_type)) return false;
                if (s.q) {
                    const hay = [d.name, d.ip, d.device_type].filter(Boolean).join(' ').toLowerCase();
                    if (!hay.includes(s.q.toLowerCase())) return false;
                }
            }
            return true;
        });
        const pageCount = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
        if (page >= pageCount) page = pageCount - 1;
        const pageRows = rows.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
        document.getElementById('uptimeList').innerHTML = pageRows.map(function (d) {
            const cells = d.cells.map(function (state, i) {
                const stamp = data.checks[i] ? new Date(data.checks[i]).toLocaleString(pageLocale()) : '';
                const label = state ? t('uptime_' + state) : t('uptime_unknown');
                return '<i class="uptime-cell uptime-cell--' + (state || 'none') + '"' +
                       ' title="' + esc(stamp + ' — ' + label) + '"></i>';
            }).join('');
            const pctClass = d.uptime >= 99 ? '' : (d.uptime >= 90 ? ' is-degraded' : ' is-down');
            // Name/MAC links to the Devices page, which opens this device's edit
            // popup (?device=<ip|mac>). The rich edit modal lives on that page.
            const ident = d.ip || d.mac || '';
            // IP first (leftmost), then the name - list is IP-sorted, so the IP is the primary key.
            const inner = icon(d.device_type) +
                (d.ip ? '<span class="uptime-row__ip">' + esc(d.ip) + '</span>' : '') +
                '<span title="' + esc(d.name) + '">' + esc(d.name) + '</span>';
            const nameHtml = ident
                ? '<a class="uptime-row__link" href="/?device=' + encodeURIComponent(ident) +
                  '" title="' + esc(t('open_device_details')) + '">' + inner + '</a>'
                : inner;
            return '<div class="uptime-row">' +
                '<div class="uptime-row__name">' + nameHtml + '</div>' +
                '<div class="uptime-row__bars">' + cells + '</div>' +
                '<div class="uptime-row__pct' + pctClass + '">' + d.uptime + '%</div>' +
            '</div>';
        }).join('');
        renderPager(rows.length, pageCount);
    };

    // Prev / "page X of Y (N devices)" / Next. Only shown when it overflows one
    // page - a handful of devices needs no pager.
    function renderPager(total, pageCount) {
        const host = document.getElementById('uptimePager');
        if (!host) return;
        if (pageCount <= 1) { host.innerHTML = ''; return; }
        const info = t('uptime_page_of', { page: page + 1, pages: pageCount, total: total }) ||
            ((page + 1) + ' / ' + pageCount + ' (' + total + ')');
        host.innerHTML =
            '<button class="btn btn-small" id="uptimePrev"' + (page === 0 ? ' disabled' : '') + '>‹</button>' +
            '<span class="uptime-pager__info">' + esc(info) + '</span>' +
            '<button class="btn btn-small" id="uptimeNext"' + (page >= pageCount - 1 ? ' disabled' : '') + '>›</button>';
        const prev = document.getElementById('uptimePrev'), next = document.getElementById('uptimeNext');
        if (prev) prev.onclick = function () { if (page > 0) { page--; render(); } };
        if (next) next.onclick = function () { page++; render(); };
    }

    ['uptimeStatusFilter'].forEach(function (id) {
        const el = document.getElementById(id);
        if (el && !el.dataset.wired) { el.dataset.wired = '1'; el.addEventListener('change', function () { page = 0; render(); }); }
    });
    // Shared visibility toggles + re-render when any shared filter changes.
    if (window.MynesFilters && !card.dataset.filtersWired) {
        card.dataset.filtersWired = '1';
        MynesFilters.bindToggle(document.getElementById('toggleContainers'), 'showContainers');
        MynesFilters.bindToggle(document.getElementById('toggleNoIp'), 'showNoIp');
        MynesFilters.bindToggle(document.getElementById('toggleBluetooth'), 'showBluetooth');
        MynesFilters.bindToggle(document.getElementById('toggleRandomMac'), 'showRandomMac');
        // Same searchable Device Type multi-select as the Devices page, bound to
        // the shared 'types' filter the render above already honours. Options are
        // the types actually present in the uptime data.
        var typeEl = document.getElementById('uptimeTypeMulti');
        if (typeEl) MynesFilters.mountMulti(typeEl, {
            key: 'types', label: t('device_type'),
            options: function () {
                return [...new Set(data.devices.map(function (d) { return d.device_type; }).filter(Boolean))]
                    .sort().map(function (v) { return { value: v, label: v }; });
            }
        });
        document.addEventListener('mynes:filters', function () { page = 0; render(); });
    }
    window.__uptimeRender = function () { page = 0; render(); };
    render();
}
