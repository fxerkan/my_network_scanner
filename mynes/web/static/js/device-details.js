/*
 * Device Details panel - what MyNeS knows about one device, per tab.
 *
 * The old renderer only read `enhanced_comprehensive_info` (the deep-analysis
 * blob). Everything else MyNeS learns - the identity verdict and its reasons,
 * names from DHCP/mDNS/ONVIF/NetBIOS/Home Assistant/vendor probes, service
 * banners, OS and Wi-Fi/wired guesses, BLE advertisements, uptime, the
 * topology uplink - was never shown, so an IoT device with no open ports got
 * nine tabs of "No data" plus a "Raspberry Pi Services" box on a vacuum.
 *
 * Rules here:
 *  - render every fact the record carries, from whichever source has it;
 *  - a section that cannot apply to this device is not drawn at all (no SSH
 *    box when 22 is closed, no Raspberry Pi box on non-Pi hardware);
 *  - an empty tab says in one line what was checked, not a big empty box;
 *  - everything that reaches innerHTML goes through ddEsc().
 *
 * Context that is not on the device record (topology uplink, Home Assistant
 * URL, uptime series, CVE assessment) is fetched once per open and the
 * current tab re-renders when it arrives.
 */

const DD = { ctx: {}, seq: 0 };

function ddEsc(v) {
    return String(v == null ? '' : v).replace(/[&<>"']/g, c =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// t() with a fallback when the key is missing in the loaded locale.
function ddT(key, fallback, params) {
    const v = typeof t === 'function' ? t(key, params || {}) : key;
    if (!v || v === key) {
        let s = fallback || key;
        for (const [k, val] of Object.entries(params || {})) s = s.replace(new RegExp(`\\{${k}\\}`, 'g'), val);
        return s;
    }
    return v;
}

function ddIcon(id) {
    return `<svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#${id}"/></svg>`;
}

function ddFmtDate(ts) {
    if (!ts) return '';
    const d = new Date(ts);
    if (isNaN(d)) return String(ts);
    const lang = (typeof translationManager !== 'undefined' && translationManager.getCurrentLanguage)
        ? translationManager.getCurrentLanguage() : 'en';
    return d.toLocaleString(lang === 'tr' ? 'tr-TR' : 'en-GB');
}

function ddAgo(ts) {
    if (!ts) return '';
    const s = (Date.now() - new Date(ts).getTime()) / 1000;
    if (!isFinite(s)) return '';
    if (s < 90) return ddT('dd_just_now', 'just now');
    if (s < 5400) return ddT('dd_min_ago', '{n} min ago', { n: Math.round(s / 60) });
    if (s < 129600) return ddT('dd_h_ago', '{n} h ago', { n: Math.round(s / 3600) });
    return ddT('dd_d_ago', '{n} days ago', { n: Math.round(s / 86400) });
}

// ---------------------------------------------------------------------------
// Small layout helpers
// ---------------------------------------------------------------------------

function ddRows(rows) {
    const body = rows
        .filter(r => r && r[1] !== undefined && r[1] !== null && r[1] !== '' &&
                     !(Array.isArray(r[1]) && !r[1].length))
        .map(([label, value, raw]) => `<li><span class="details-label">${ddEsc(label)}</span>` +
            `<span class="details-value">${raw ? value : ddEsc(Array.isArray(value) ? value.join(', ') : value)}</span></li>`)
        .join('');
    return body ? `<ul class="details-list dd-list">${body}</ul>` : '';
}

function ddCard(title, icon, inner, extraClass) {
    if (!inner) return '';
    return `<div class="details-card dd-card ${extraClass || ''}">
        <h5 class="dd-card__title">${icon ? ddIcon(icon) : ''}<span>${ddEsc(title)}</span></h5>${inner}</div>`;
}

function ddSection(title, icon, inner) {
    if (!inner) return '';
    return `<div class="details-section dd-section"><h4 class="dd-section__title">${icon ? ddIcon(icon) : ''}<span>${ddEsc(title)}</span></h4>${inner}</div>`;
}

function ddNote(text, icon) {
    return `<p class="dd-note">${ddIcon(icon || 'i-info')}<span>${ddEsc(text)}</span></p>`;
}

function ddBadge(text, kind) {
    return `<span class="ds-badge ds-badge--${kind || 'info'}">${ddEsc(text)}</span>`;
}

function ddChips(items) {
    return items.length ? `<div class="dd-chips">${items.map(i => `<span class="dd-chip">${ddEsc(i)}</span>`).join('')}</div>` : '';
}

function ddCopyBtn(value) {
    if (!value) return '';
    return `<button type="button" class="dd-copy" title="${ddEsc(ddT('copy', 'Copy'))}"
        onclick="ddCopy(${ddEsc(JSON.stringify(String(value)))}, this)">${ddIcon('i-copy')}</button>`;
}

function ddCopy(value, btn) {
    const done = () => { if (typeof showToast === 'function') showToast(ddT('dd_copied', 'Copied: {v}', { v: value }), 'success'); };
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(value).then(done).catch(() => ddCopyFallback(value, done));
    } else {
        ddCopyFallback(value, done);
    }
}

function ddCopyFallback(value, done) {
    const ta = document.createElement('textarea');
    ta.value = value; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); done(); } catch (_) { /* nothing */ }
    ta.remove();
}

// ---------------------------------------------------------------------------
// Data shaping - pure functions over the device record
// ---------------------------------------------------------------------------

const DD_WEB_PORTS = new Set([80, 81, 443, 591, 3000, 5000, 5001, 7000, 8000, 8001, 8008, 8080, 8081,
    8088, 8096, 8123, 8443, 8888, 9000, 9090, 9443]);
const DD_TLS_PORTS = new Set([443, 5001, 8443, 9443]);

function ddInfo(device) {
    return device.enhanced_comprehensive_info || device.advanced_scan_summary || device.enhanced_info || {};
}

function ddPortNum(p) {
    const n = Number(p && typeof p === 'object' ? p.port : p);
    return isFinite(n) && n > 0 ? n : null;
}

// One row per open port, merging the scan list, the deep-analysis nmap table,
// the identity ports and any HTTP banner the fingerprint collected.
function ddPorts(device) {
    const info = ddInfo(device);
    const out = new Map();
    const put = (port, patch) => {
        if (!port) return;
        const row = out.get(port) || { port };
        for (const [k, v] of Object.entries(patch)) if (v && !row[k]) row[k] = v;
        out.set(port, row);
    };
    for (const p of device.open_ports || []) {
        const n = ddPortNum(p);
        if (typeof p === 'object') {
            put(n, { service: p.service && p.service !== 'unknown' ? p.service : '', description: p.description,
                     product: p.product, version: p.version, source: p.source, last_verified: p.last_verified,
                     manual: p.manual });
        } else put(n, {});
    }
    for (const [port, d] of Object.entries(info.detailed_ports || {})) {
        if (!d || typeof d !== 'object' || d.error) continue;
        const n = ddPortNum(port);
        if (d.state && d.state !== 'open') continue;
        put(n, { service: d.service, product: d.product, version: d.version, extrainfo: d.extrainfo, cpe: d.cpe });
    }
    const fp = device.fingerprint || {};
    for (const h of fp.http || []) {
        if (!h || !h.port) continue;
        put(Number(h.port), { service: h.tls ? 'https' : 'http', title: h.title, server: h.server, status: h.status });
    }
    if (fp.rtsp && fp.rtsp.port) put(Number(fp.rtsp.port), { service: 'rtsp', server: fp.rtsp.server || fp.rtsp.realm });
    if (fp.ssh) put(22, { service: 'ssh', banner: fp.ssh });
    return [...out.values()].sort((a, b) => a.port - b.port);
}

function ddWebUrl(device, port, service) {
    if (!device.ip || String(device.ip).startsWith('virtual:')) return null;
    const tls = DD_TLS_PORTS.has(port) || /https|ssl|tls/i.test(service || '');
    const web = tls || DD_WEB_PORTS.has(port) || /http|web/i.test(service || '');
    if (!web) return null;
    const scheme = tls ? 'https' : 'http';
    const def = (scheme === 'http' && port === 80) || (scheme === 'https' && port === 443);
    return `${scheme}://${device.ip}${def ? '' : ':' + port}/`;
}

// Every name any source gave this device, with where it came from.
function ddNames(device) {
    const ev = device.discovery_evidence || {};
    const fp = device.fingerprint || {};
    const info = ddInfo(device);
    const probes = ev.probes || {};
    const ha = device.home_assistant || {};
    const rows = [
        [ddT('dd_src_alias', 'Alias (shown name)'), device.alias],
        [ddT('dd_src_identity', 'MyNeS identification'), (device.identity || {}).name],
        [ddT('dd_src_dhcp', 'DHCP hostname'), ev.dhcp_hostname],
        [ddT('dd_src_mdns', 'mDNS / Bonjour'), ev.mdns_hostname],
        [ddT('dd_src_ssdp', 'UPnP / SSDP'), ev.ssdp_name],
        [ddT('dd_src_onvif', 'ONVIF camera name'), (fp.onvif || {}).name],
        [ddT('dd_src_netbios', 'NetBIOS name'), (fp.smb || {}).netbios_name],
        [ddT('dd_src_hostname', 'Hostname'), device.hostname || (info.basic_info || {}).hostname],
        [ddT('dd_src_ha', 'Home Assistant'), ha.name],
        ['Philips CoAP', (probes.philips_coap || {}).name],
    ];
    const seen = new Set();
    return rows.filter(([, v]) => {
        const k = String(v || '').trim().toLowerCase();
        if (!k || seen.has(k)) return false;
        seen.add(k);
        return true;
    });
}

function ddModel(device) {
    const ev = device.discovery_evidence || {};
    const p = ev.probes || {};
    return device.model || (device.identity || {}).model || (device.home_assistant || {}).model ||
        (p.philips_coap || {}).model || (p.tplink || {}).model || ev.model || (device.discovery || {}).model || '';
}

function ddHasSsh(device) {
    return ddPorts(device).some(p => p.port === 22 || /ssh/i.test(p.service || ''));
}

function ddIsRadio(device) {
    return !device.ip;
}

function ddIsPi(device) {
    return /raspberry/i.test(`${device.vendor || ''} ${device.device_type || ''} ${ddModel(device)}`);
}

function ddDeviceByIp(ip) {
    if (!ip || typeof devices === 'undefined') return null;
    return (devices || []).find(d => d.ip === ip) || null;
}

function ddLabel(d, fallback) {
    return (d && (d.alias || d.hostname || d.ip || d.mac)) || fallback || '';
}

// ---------------------------------------------------------------------------
// Context loading (topology, HA URL, uptime, CVE assessment)
// ---------------------------------------------------------------------------

async function ddLoadContext(device) {
    const seq = ++DD.seq;
    DD.ctx = { loading: true };
    const key = device.ip || device.mac;
    const get = url => fetch(url).then(r => (r.ok ? r.json() : null)).catch(() => null);
    const [topo, ha, uptime, sec] = await Promise.all([
        get('/api/topology'),
        get('/api/integrations/home-assistant/settings'),
        get('/api/monitoring/uptime?limit=48'),
        device.ip && !String(device.ip).startsWith('virtual:')
            ? get(`/api/security/vulnerabilities/${encodeURIComponent(device.ip)}`) : Promise.resolve(null),
    ]);
    if (seq !== DD.seq) return;            // a newer device was opened meanwhile
    const node = ((topo && topo.nodes) || []).find(n => (n.ip && n.ip === device.ip) ||
        (!n.ip && n.mac && device.mac && n.mac.toLowerCase() === device.mac.toLowerCase())) || null;
    const urow = ((uptime && uptime.devices) || []).find(u =>
        (u.ip && u.ip === device.ip) || (u.mac && device.mac && u.mac.toLowerCase() === device.mac.toLowerCase()) ||
        u.id === key) || null;
    DD.ctx = { topo: node, gateway: topo && topo.gateway, haUrl: (ha && ha.url) || '', uptime: urow, security: sec };
    if (typeof currentDevice !== 'undefined' && currentDevice && (currentDevice.ip || currentDevice.mac) === key) {
        ddRenderActions(currentDevice);
        if (typeof loadTabContent === 'function') loadTabContent(currentTab);
    }
}

// ---------------------------------------------------------------------------
// Action bar
// ---------------------------------------------------------------------------

function ddRenderActions(device) {
    const bar = document.getElementById('detailsActions');
    if (!bar) return;
    const ip = device.ip && !String(device.ip).startsWith('virtual:') ? device.ip : '';
    const key = device.ip || device.mac;
    const web = ddPorts(device).map(p => ({ p, url: ddWebUrl(device, p.port, p.service) })).filter(x => x.url);
    const ha = device.home_assistant || {};
    const haLink = DD.ctx.haUrl && ha.id ? `${DD.ctx.haUrl.replace(/\/$/, '')}/config/devices/device/${encodeURIComponent(ha.id)}` : '';
    const btn = (icon, label, onclick, extra) =>
        `<button type="button" class="btn btn-secondary btn-small dd-action" onclick="${onclick}" ${extra || ''}>${ddIcon(icon)}<span>${ddEsc(label)}</span></button>`;
    const link = (icon, label, href) =>
        `<a class="btn btn-secondary btn-small dd-action" href="${ddEsc(href)}" target="_blank" rel="noopener noreferrer">${ddIcon(icon)}<span>${ddEsc(label)}</span></a>`;
    const parts = [];
    web.slice(0, 3).forEach(({ p, url }) => parts.push(link('i-external', `${ddT('dd_open_web', 'Open web UI')} :${p.port}`, url)));
    if (haLink) parts.push(link('i-home', ddT('dd_open_ha', 'Open in Home Assistant'), haLink));
    if (ip) {
        parts.push(btn('i-radar', ddT('tool_ping', 'Ping'), `ddRunTool('ping')`));
        parts.push(btn('i-topology', ddT('tool_traceroute', 'Traceroute'), `ddRunTool('traceroute')`));
        parts.push(btn('i-globe', ddT('tool_dns_lookup', 'DNS lookup'), `ddRunTool('dns')`));
        parts.push(btn('i-plug', ddT('dd_probe_ports', 'Probe ports'), `ddProbePorts()`));
        parts.push(btn('i-microscope', ddT('dd_rescan', 'Deep analysis'),
            `ddRescan(${ddEsc(JSON.stringify(ip))})`));
    }
    if (ip && device.mac && /^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i.test(device.mac)) {
        parts.push(btn('i-play', ddT('tool_wake_on_lan', 'Wake-on-LAN'), `ddRunWol()`));
    }
    if (key) parts.push(btn('i-wrench', ddT('edit', 'Edit'),
        `closeEnhancedDetailsModal(); openEnhancedEditModal(${ddEsc(JSON.stringify(key))})`));
    bar.innerHTML = `<div class="dd-actions">${parts.join('')}</div><div id="ddActionResult" class="dd-action-result" aria-live="polite"></div>`;
}

async function ddRunTool(tool) {
    const d = currentDevice; if (!d || !d.ip) return;
    const box = document.getElementById('ddActionResult');
    box.innerHTML = `<p class="dd-note">${ddIcon('i-refresh')}<span>${ddEsc(ddT('tool_running', 'Running...'))}</span></p>`;
    try {
        const res = await fetch(`/api/diagnostics/${encodeURIComponent(d.ip)}/${tool}`);
        const data = await res.json();
        box.innerHTML = typeof renderDiagnosticResult === 'function'
            ? renderDiagnosticResult(tool, data) : `<pre class="details-code">${ddEsc(JSON.stringify(data, null, 2))}</pre>`;
    } catch (e) {
        box.innerHTML = ddNote(`${ddT('tool_error', 'Error')}: ${e.message || e}`, 'i-alert');
    }
}

async function ddProbePorts(ports) {
    const d = currentDevice; if (!d || !d.ip) return;
    const known = ddPorts(d).map(p => p.port);
    const list = ports || [...new Set([...known, 21, 22, 23, 80, 443, 554, 1883, 5000, 8080, 8443, 6668, 9100])];
    const box = document.getElementById('ddActionResult');
    box.innerHTML = `<p class="dd-note">${ddIcon('i-refresh')}<span>${ddEsc(ddT('tool_running', 'Running...'))}</span></p>`;
    try {
        const res = await fetch(`/api/diagnostics/${encodeURIComponent(d.ip)}/ports`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ports: list }),
        });
        const data = await res.json();
        box.innerHTML = typeof renderDiagnosticResult === 'function'
            ? renderDiagnosticResult('ports', data) : ddEsc(JSON.stringify(data));
    } catch (e) {
        box.innerHTML = ddNote(`${ddT('tool_error', 'Error')}: ${e.message || e}`, 'i-alert');
    }
}

async function ddRunWol() {
    const d = currentDevice; if (!d || !d.mac) return;
    const box = document.getElementById('ddActionResult');
    try {
        const res = await fetch(`/api/diagnostics/${encodeURIComponent(d.ip)}/wol`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mac: d.mac }),
        });
        const data = await res.json();
        box.innerHTML = data.success
            ? ddNote(ddT('wol_sent', 'Magic packet sent to {mac}', { mac: d.mac }), 'i-check')
            : ddNote(`${ddT('tool_error', 'Error')}: ${data.error || ''}`, 'i-alert');
    } catch (e) {
        box.innerHTML = ddNote(`${ddT('tool_error', 'Error')}: ${e.message || e}`, 'i-alert');
    }
}

function ddRescan(ip) {
    if (typeof openSingleDeviceAnalysisPage === 'function') {
        closeEnhancedDetailsModal();
        openSingleDeviceAnalysisPage(ip);
    }
}

// ---------------------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------------------

function ddOverview(device) {
    const id = device.identity || {};
    const um = device.user_modified || {};
    const typeSrc = device.device_type_source === 'user' || um.device_type
        ? ddT('dd_set_by_you', 'set by you') : (id.confidence ? ddT('dd_detected', 'detected') : '');
    const conf = id.confidence ? `${Math.round(id.confidence * 100)}%` : '';
    const reasons = (id.reasons || []).concat(((device.fingerprint || {}).reasons) || []);
    const identity = ddRows([
        [ddT('device_type', 'Device type'), `${ddEsc(device.device_type || ddT('unknown', 'Unknown'))}` +
            (typeSrc ? ` ${ddBadge(typeSrc, um.device_type ? 'success' : 'info')}` : '') +
            (conf ? ` ${ddBadge(ddT('dd_confidence', 'confidence {c}', { c: conf }), 'info')}` : ''), true],
        [ddT('vendor', 'Vendor'), device.vendor],
        [ddT('dd_model', 'Model'), ddModel(device)],
        [ddT('location', 'Location'), device.location],
        [ddT('trust_status', 'Trust'), device.trust_status && device.trust_status !== 'unknown'
            ? ddT('trust_' + device.trust_status, device.trust_status) : ''],
    ]) + (reasons.length ? `<p class="dd-sub">${ddEsc(ddT('dd_why', 'Why'))}:</p>${ddChips([...new Set(reasons)])}` : '');

    const isVirtual = device.virtual || String(device.ip || '').startsWith('virtual:');
    const addresses = ddRows([
        ['IP', isVirtual ? ddT('dd_virtual', 'none (hand-drawn infrastructure node)') :
            (device.ip ? `${ddEsc(device.ip)} ${ddCopyBtn(device.ip)}` : ddT('dd_no_ip', 'none (radio-only device)')), !isVirtual && !!device.ip],
        ['MAC', device.mac && !isVirtual ? `${ddEsc(device.mac)} ${ddCopyBtn(device.mac)}` : '', true],
        [ddT('dd_previous_ips', 'Previous IPs'), device.previous_ips || []],
        [ddT('hostname', 'Hostname'), device.hostname],
    ]);

    const names = ddNames(device);
    const namesCard = names.length > 1 ? ddRows(names) : '';

    const node = DD.ctx.topo || {};
    const parent = node.parent ? ddDeviceByIp(node.parent) : null;
    const srcLabel = { manual: ddT('dd_uplink_manual', 'set by you'), traceroute: 'traceroute',
        docker: 'Docker', host: ddT('dd_uplink_host', 'interface of the host'),
        default: ddT('dd_uplink_default', 'assumed (direct to router)'), gateway: ddT('dd_uplink_gateway', 'this is the gateway') }[node.source] || node.source;
    const medium = device.connection_medium || {};
    const connection = ddRows([
        [ddT('connected_via', 'Connected via'), node.parent ? `${ddEsc(ddLabel(parent, node.parent))}` +
            (parent ? ` <a href="#" class="dd-link" onclick="ddOpenOther(${ddEsc(JSON.stringify(node.parent))});return false;">${ddIcon('i-external')}</a>` : '') : (node.source === 'gateway' ? ddEsc(srcLabel) : ''), true],
        [ddT('dd_uplink_source', 'Uplink source'), node.parent ? srcLabel : ''],
        [ddT('dd_medium', 'Medium (guess)'), medium.medium && medium.medium !== 'unknown'
            ? `${medium.medium}${medium.confidence ? ` (${Math.round(medium.confidence * 100)}%)` : ''}` : ''],
        [ddT('dd_subnet', 'Subnet'), (node.subnet || {}).cidr],
        [ddT('dd_ble_signal', 'Bluetooth signal'), (device.attributes || {}).rssi != null ? `${device.attributes.rssi} dBm` : ''],
    ]);

    const u = DD.ctx.uptime;
    const cells = u ? `<div class="dd-uptime">${u.cells.slice(-36).map(s => `<i class="device-status__cell is-${s || 'none'}"></i>`).join('')}</div>` : '';
    const a = device.analysis_data || {};
    const activity = ddRows([
        [ddT('status', 'Status'), ddBadge(device.status === 'online' ? ddT('online', 'Online') : ddT('offline', 'Offline'),
            device.status === 'online' ? 'success' : 'warning'), true],
        [ddT('last_seen', 'Last seen'), device.last_seen ? `${ddFmtDate(device.last_seen)} · ${ddAgo(device.last_seen)}` : ''],
        [ddT('dd_availability', 'Availability'), u ? ddT('dd_uptime_line', '{u}% over {c} checks, {i} outages',
            { u: u.uptime, c: u.checks, i: u.incidents }) : ''],
        [ddT('dd_last_scan', 'Last scan'), ddFmtDate(a.last_normal_scan)],
        [ddT('dd_last_deep', 'Last deep analysis'), ddFmtDate(device.last_enhanced_analysis || a.last_enhanced_analysis)],
        [ddT('dd_last_edit', 'Last edited'), ddFmtDate(device.last_modified)],
    ]) + cells;

    const ha = device.home_assistant || {};
    const haLink = DD.ctx.haUrl && ha.id ? `${DD.ctx.haUrl.replace(/\/$/, '')}/config/devices/device/${encodeURIComponent(ha.id)}` : '';
    const haCard = ha.id || ha.name ? ddRows([
        [ddT('name', 'Name'), ha.name],
        [ddT('dd_area', 'Area'), ha.area],
        [ddT('dd_model', 'Model'), [ha.manufacturer, ha.model].filter(Boolean).join(' ')],
        [ddT('dd_integrations', 'Integrations'), ha.integrations || []],
        [ddT('protocol', 'Protocol'), ha.protocol],
        ['', haLink ? `<a class="dd-link" href="${ddEsc(haLink)}" target="_blank" rel="noopener noreferrer">${ddIcon('i-external')} ${ddEsc(ddT('dd_open_ha', 'Open in Home Assistant'))}</a>` : '', true],
    ]) : '';

    const ports = ddPorts(device);
    const portChips = ports.length ? `<div class="dd-chips">${ports.map(p => {
        const url = ddWebUrl(device, p.port, p.service);
        const label = `${p.port}${p.service ? ' ' + p.service : ''}`;
        return url ? `<a class="dd-chip dd-chip--link" href="${ddEsc(url)}" target="_blank" rel="noopener noreferrer">${ddEsc(label)} ${ddIcon('i-external')}</a>`
                   : `<span class="dd-chip">${ddEsc(label)}</span>`;
    }).join('')}</div>` : ddNote(ddIsRadio(device) ? ddT('dd_ports_radio', 'Radio-only device - it has no IP ports.')
        : ddT('dd_no_open_ports', 'No open TCP ports - normal for cloud-connected IoT devices, which only make outbound connections.'));

    return `<div class="dd-grid">
        ${ddCard(ddT('dd_identity', 'Identity'), 'i-sparkles', identity)}
        ${ddCard(ddT('dd_addresses', 'Addresses'), 'i-network', addresses)}
        ${ddCard(ddT('dd_connection', 'Connection'), 'i-topology', connection)}
        ${ddCard(ddT('dd_activity', 'Activity'), 'i-history', activity)}
        ${ddCard(ddT('dd_names_seen', 'Names seen'), 'i-search', namesCard)}
        ${ddCard('Home Assistant', 'i-home', haCard)}
    </div>
    ${ddSection(ddT('dd_open_ports', 'Open ports'), 'i-plug', portChips)}
    ${device.notes ? ddSection(ddT('notes', 'Notes'), 'i-info', `<p class="dd-notes">${ddEsc(device.notes)}</p>`) : ''}`;
}

function ddNetwork(device) {
    if (ddIsRadio(device)) {
        return ddSection(ddT('dd_net_services', 'Network services'), 'i-globe',
            ddNote(ddT('dd_net_radio', 'This device talks Bluetooth/Zigbee only; it has no IP services. See the Discovery tab for its radio data.'), 'i-bluetooth'));
    }
    const info = ddInfo(device);
    const ports = ddPorts(device);
    const web = [];
    for (const [k, d] of Object.entries(info.web_services || {})) {
        if (!d || d.error) continue;
        const port = Number((k.match(/(\d+)/) || [])[1]) || null;
        web.push({ port, status: d.status_code, title: d.title || (d.content_analysis || {}).title,
            server: d.server || (d.headers || {}).Server, tech: (d.technologies || []).join(', '),
            ctype: (d.headers || {})['Content-Type'] });
    }
    for (const p of ports) {
        if (!ddWebUrl(device, p.port, p.service) || web.some(w => w.port === p.port)) continue;
        web.push({ port: p.port, status: p.status, title: p.title || p.description, server: p.server || p.product });
    }
    const webCards = web.map(w => {
        const url = ddWebUrl(device, w.port || 80, w.port && DD_TLS_PORTS.has(w.port) ? 'https' : 'http');
        return ddCard(`${ddT('dd_web', 'Web')} :${w.port || '?'}`, 'i-globe', ddRows([
            [ddT('dd_title', 'Title'), w.title], [ddT('dd_server', 'Server'), w.server],
            [ddT('dd_http_status', 'HTTP status'), w.status], [ddT('dd_tech', 'Technologies'), w.tech],
            [ddT('dd_content_type', 'Content type'), w.ctype],
            ['', url ? `<a class="dd-link" href="${ddEsc(url)}" target="_blank" rel="noopener noreferrer">${ddIcon('i-external')} ${ddEsc(url)}</a>` : '', true],
        ]));
    }).join('');

    const ssh = (info.remote_access || {}).ssh || {};
    const sshBanner = ssh.banner || (device.fingerprint || {}).ssh;
    const sshHtml = ddHasSsh(device) ? ddRows([
        ['SSH', sshBanner || ddT('dd_ssh_open', 'port 22 open')],
        [ddT('dd_ssh_version', 'Protocol'), ssh.version],
        [ddT('dd_ssh_auth', 'Auth methods'), (ssh.auth_methods || []).join(', ')],
    ]) : '';

    const other = ports.filter(p => !ddWebUrl(device, p.port, p.service) && p.port !== 22);
    const otherHtml = other.length ? `<table class="ds-table dd-table"><thead><tr><th>${ddEsc(ddT('port', 'Port'))}</th>
        <th>${ddEsc(ddT('service', 'Service'))}</th><th>${ddEsc(ddT('dd_detail', 'Detail'))}</th></tr></thead><tbody>
        ${other.map(p => `<tr><td>${p.port}</td><td>${ddEsc(p.service || ddServiceGuess(p.port))}</td>
        <td>${ddEsc([p.product, p.version, p.server, p.description].filter(Boolean).join(' · '))}</td></tr>`).join('')}</tbody></table>` : '';

    const fs = info.file_services || {};
    const smb = (device.fingerprint || {}).smb || fs.smb || {};
    const smbHtml = smb && (smb.netbios_name || smb.workgroup || (smb.shares || []).length) ? ddRows([
        [ddT('dd_netbios', 'NetBIOS name'), smb.netbios_name], [ddT('dd_workgroup', 'Workgroup'), smb.workgroup],
        [ddT('dd_shares', 'Shares'), (smb.shares || []).map(s => s.name || s)],
    ]) : '';
    const snmp = (info.network_services || {}).snmp || {};
    const snmpHtml = Object.keys(snmp).length ? ddRows(Object.entries(snmp).map(([k, v]) => [k, typeof v === 'object' ? JSON.stringify(v) : v])) : '';
    const services = [...new Set([...(device.services || []), ...((device.discovery_evidence || {}).services || []),
        ...(((device.discovery || {}).services) || [])])];

    const body = [
        ddSection(ddT('det_web_services', 'Web services'), 'i-globe', webCards ? `<div class="dd-grid">${webCards}</div>` : ''),
        ddSection(ddT('det_remote_access', 'Remote access'), 'i-shield', sshHtml),
        ddSection(ddT('dd_other_services', 'Other services'), 'i-plug', otherHtml),
        ddSection('SMB / NetBIOS', 'i-container', smbHtml),
        ddSection('SNMP', 'i-router', snmpHtml),
        ddSection(ddT('dd_advertised', 'Advertised services (mDNS / SSDP)'), 'i-radar', ddChips(services)),
    ].join('');
    return body || ddSection(ddT('dd_net_services', 'Network services'), 'i-globe',
        ddNote(ddT('dd_net_none', 'No listening service answered (checked {n} common ports, HTTP, SSH, SMB, SNMP and mDNS/SSDP). The device only makes outbound connections.',
            { n: 30 })));
}

const DD_SERVICE_NAMES = { 21: 'ftp', 22: 'ssh', 23: 'telnet', 53: 'dns', 139: 'netbios', 445: 'smb', 554: 'rtsp',
    1883: 'mqtt', 2020: 'onvif', 3389: 'rdp', 5353: 'mdns', 5683: 'coap', 5900: 'vnc', 6668: 'tuya', 8009: 'cast',
    9100: 'printer', 9197: 'dlna' };
function ddServiceGuess(port) { return DD_SERVICE_NAMES[port] || ''; }

function ddPortsTab(device) {
    if (ddIsRadio(device)) return ddSection(ddT('det_port_analysis', 'Port analysis'), 'i-plug',
        ddNote(ddT('dd_ports_radio', 'Radio-only device - it has no IP ports.'), 'i-bluetooth'));
    const ports = ddPorts(device);
    const rtsp = device.stream_url ? ddRows([[ddT('dd_stream', 'Camera stream'),
        `<code>${ddEsc(device.stream_url)}</code> ${ddCopyBtn(device.stream_url)}`, true]]) : '';
    const table = ports.length ? `<table class="ds-table dd-table"><thead><tr>
        <th>${ddEsc(ddT('port', 'Port'))}</th><th>${ddEsc(ddT('service', 'Service'))}</th>
        <th>${ddEsc(ddT('dd_product', 'Product / version'))}</th><th>${ddEsc(ddT('dd_banner', 'Banner / title'))}</th>
        <th>${ddEsc(ddT('dd_verified', 'Verified'))}</th><th></th></tr></thead><tbody>
        ${ports.map(p => {
            const url = ddWebUrl(device, p.port, p.service);
            return `<tr><td><strong>${p.port}</strong></td>
                <td>${ddEsc(p.service || ddServiceGuess(p.port))}${p.manual ? ' ' + ddBadge(ddT('dd_manual', 'manual'), 'info') : ''}</td>
                <td>${ddEsc([p.product, p.version, p.extrainfo].filter(Boolean).join(' '))}</td>
                <td>${ddEsc(p.banner || p.title || p.server || p.description || '')}</td>
                <td>${ddEsc(p.last_verified ? ddAgo(p.last_verified) : '')}</td>
                <td>${url ? `<a class="dd-link" href="${ddEsc(url)}" target="_blank" rel="noopener noreferrer" title="${ddEsc(url)}">${ddIcon('i-external')}</a>` : ''}</td></tr>`;
        }).join('')}</tbody></table>` : ddNote(ddT('dd_no_open_ports', 'No open TCP ports - normal for cloud-connected IoT devices, which only make outbound connections.'));
    const again = `<div class="dd-inline-actions"><button type="button" class="btn btn-secondary btn-small" onclick="ddProbePorts()">${ddIcon('i-refresh')}<span>${ddEsc(ddT('dd_probe_again', 'Probe again now'))}</span></button></div>`;
    return ddSection(ddT('det_port_analysis', 'Port analysis'), 'i-plug', table + again) + ddSection(ddT('dd_stream', 'Camera stream'), 'i-play', rtsp);
}

function ddSystem(device) {
    const info = ddInfo(device);
    const os = device.os_guess || {};
    const osd = (info.system_identification || {}).os_detection || {};
    const sb = osd.service_based_os || {};
    const nmapOs = osd.nmap_os || osd.nmap || {};
    const nsi = (((device.analysis_data || {}).normal_scan_info || {}).identification_result || {}).system_info || {};
    const verdict = (device.fingerprint || {}).verdict || {};
    const osHtml = ddRows([
        [ddT('dd_os_family', 'OS family'), os.os_family && os.os_family !== 'Unknown' ? os.os_family : (nsi.os || '')],
        [ddT('dd_os_detail', 'Detail'), os.detail],
        [ddT('dd_confidence_word', 'Confidence'), os.confidence ? `${Math.round(os.confidence * 100)}%` : ''],
        ['TTL', nsi.ttl || osd.ttl],
        [ddT('dd_os_candidates', 'Service-based candidates'), Object.entries(sb.confidence_scores || {})
            .sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${Math.round(v * 100)}%`)],
        ['nmap', typeof nmapOs === 'object' ? (nmapOs.name || nmapOs.os || '') : nmapOs],
    ]) + ((os.reasons || []).length ? ddChips(os.reasons) : '') + ((sb.service_evidence || []).length ? `<p class="dd-sub">${ddEsc(ddT('dd_evidence', 'Evidence'))}:</p>${ddChips(sb.service_evidence.slice(0, 8))}` : '');

    const fpHtml = ddRows([
        [ddT('dd_fp_verdict', 'Scan verdict'), verdict.device_type ? `${verdict.device_type} (${Math.round((verdict.confidence || 0) * 100)}%)` : ''],
        [ddT('dd_is_gateway', 'Default gateway'), (device.fingerprint || {}).is_gateway ? ddT('yes', 'Yes') : ''],
    ]) + (((device.fingerprint || {}).reasons || []).length ? ddChips(device.fingerprint.reasons) : '');

    const sshSys = ((info.remote_access || {}).ssh || {}).system_info || ((info.credential_based_analysis || {}).system_info) || {};
    const sshSysHtml = Object.keys(sshSys).length ? ddRows(Object.entries(sshSys).map(([k, v]) =>
        [k.replace(/_/g, ' '), typeof v === 'object' ? JSON.stringify(v) : v])) : '';
    const sshHint = !sshSysHtml && ddHasSsh(device)
        ? ddNote(ddT('dd_ssh_creds_hint', 'SSH is open: add credentials in Edit > Access to collect kernel, CPU, memory and disk details.'), 'i-info') : '';

    const body = ddSection(ddT('det_os_detection', 'Operating system'), 'i-cpu', osHtml) +
        ddSection(ddT('dd_fingerprint', 'Service fingerprint'), 'i-search', fpHtml) +
        ddSection(ddT('det_ssh_sysinfo', 'SSH system info'), 'i-cpu', sshSysHtml || sshHint);
    return body || ddSection(ddT('det_os_detection', 'Operating system'), 'i-cpu',
        ddNote(ddIsRadio(device) ? ddT('dd_sys_radio', 'Radio-only device: no IP stack to fingerprint.')
            : ddT('dd_sys_none', 'No OS signal: the device answers no TCP service, so neither banners nor an nmap OS fingerprint are available. Run a deep analysis to try TTL/TCP-stack detection.')));
}

function ddSecurity(device) {
    if (ddIsRadio(device)) return ddSection(ddT('det_security', 'Security'), 'i-shield',
        ddNote(ddT('dd_sec_radio', 'Radio-only device: no IP attack surface to assess.'), 'i-bluetooth'));
    const sec = DD.ctx.security || (ddInfo(device).security_analysis) || {};
    if (DD.ctx.loading && !DD.ctx.security) return ddNote(ddT('loading', 'Loading...'), 'i-refresh');
    const level = sec.risk_level || 'none';
    const kind = { critical: 'critical', high: 'critical', medium: 'warning', low: 'info', none: 'success' }[level] || 'info';
    const head = `<div class="dd-risk">${ddBadge(ddT('security_risk_' + level, level.toUpperCase()), kind)}
        <span>${ddEsc(ddT('security_score', 'Score'))}: ${sec.risk_score ?? 0}/100</span></div>`;
    const item = f => `<div class="ds-disclosure"><details><summary>${ddBadge((f.severity || 'info').toUpperCase(),
        { critical: 'critical', high: 'critical', medium: 'warning', low: 'info' }[f.severity] || 'info')}
        ${ddEsc(f.cve_id ? `${f.cve_id} - ${f.title || ''}` : f.title)}</summary>
        <p>${ddEsc(f.description || '')}</p>
        ${f.reference ? `<a class="dd-link" href="${ddEsc(f.reference)}" target="_blank" rel="noopener noreferrer">${ddEsc(f.reference)}</a>` : ''}</details></div>`;
    const findings = (sec.findings || []).map(item).join('');
    const exposures = (sec.exposures || []).map(item).join('');
    const ports = ddPorts(device);
    const banners = ports.filter(p => p.product || p.version || p.banner || p.server || p.title).length;
    const checked = ddRows([
        [ddT('dd_sec_ports', 'Open ports assessed'), String(ports.length)],
        [ddT('dd_sec_banners', 'Service banners matched against CVE patterns'), String(banners)],
        [ddT('dd_sec_db', 'Vulnerability source'), ddT('dd_sec_db_val', 'MyNeS curated CVE pattern table + port exposure rules')],
        [ddT('dd_last_deep', 'Last deep analysis'), ddFmtDate(device.last_enhanced_analysis)],
    ]);
    const tips = ddSecurityTips(device, sec);
    return ddSection(ddT('det_security', 'Security'), 'i-shield', head +
            (findings || exposures ? findings + exposures
                : ddNote(ddT('dd_sec_clean', 'No known vulnerability and no risky service exposed.'), 'i-check'))) +
        ddSection(ddT('dd_sec_recommend', 'Recommendations'), 'i-info', tips) +
        ddSection(ddT('dd_sec_checked', 'What was checked'), 'i-search', checked);
}

function ddSecurityTips(device, sec) {
    const tips = [];
    const ports = new Set(ddPorts(device).map(p => p.port));
    if (ports.has(23)) tips.push(ddT('dd_tip_telnet', 'Telnet is open: disable it in the vendor app if possible, and keep this device off the internet (no port forwarding, block WAN access on the router).'));
    if (ports.has(445) || ports.has(139)) tips.push(ddT('dd_tip_smb', 'SMB is shared: make sure SMBv1 is off and shares require a password.'));
    if (ports.has(5900)) tips.push(ddT('dd_tip_vnc', 'VNC is open: require a strong password or tunnel it over SSH.'));
    if (ports.has(554)) tips.push(ddT('dd_tip_rtsp', 'RTSP camera stream: use a non-default camera account and never forward port 554.'));
    if (/iot|smart|camera|pet|vacuum|purifier|light|plug|feeder|power/i.test(device.device_type || ''))
        tips.push(ddT('dd_tip_iot', 'IoT device: keep its firmware updated in the vendor app; consider a separate guest/IoT Wi-Fi.'));
    if (device.trust_status !== 'trusted' && device.trust_status !== 'known')
        tips.push(ddT('dd_tip_trust', 'Not marked as known/trusted yet: confirm it is yours in Edit.'));
    return tips.length ? `<ul class="dd-tips">${tips.map(x => `<li>${ddEsc(x)}</li>`).join('')}</ul>` : '';
}

function ddHardware(device) {
    const info = ddInfo(device);
    const ev = device.discovery_evidence || {};
    const p = ev.probes || {};
    const attrs = device.attributes || {};
    const model = ddModel(device);
    const hw = ddRows([
        [ddT('vendor', 'Vendor'), device.vendor],
        [ddT('dd_model', 'Model'), model],
        [ddT('dd_firmware', 'Firmware'), (p.philips_coap || {}).firmware],
        [ddT('dd_hw_kind', 'Reported kind'), (p.tplink || {}).device_type],
        [ddT('dd_mesh_role', 'Mesh role'), (p.tplink || {}).role],
        [ddT('dd_device_id', 'Device ID'), (p.philips_coap || {}).device_id],
        [ddT('dd_oui', 'MAC vendor block'), device.mac ? String(device.mac).toUpperCase().replace(/-/g, ':').slice(0, 8) : ''],
        [ddT('dd_mac_kind', 'MAC type'), device.mac ? ddMacKind(device.mac) : ''],
        ['Home Assistant', [(device.home_assistant || {}).manufacturer, (device.home_assistant || {}).model].filter(Boolean).join(' ')],
    ]);
    const ble = attrs.bluetooth || attrs.rssi != null ? ddRows([
        [ddT('dd_ble_signal', 'Bluetooth signal'), attrs.rssi != null ? `${attrs.rssi} dBm` : ''],
        [ddT('dd_tx_power', 'TX power'), attrs.tx_power],
        [ddT('dd_ble_services', 'GATT service UUIDs'), attrs.service_uuids || []],
        [ddT('dd_ble_mfr', 'Manufacturer IDs'), attrs.manufacturer_ids || []],
    ]) : '';
    const rpi = info.raspberry_pi_analysis || {};
    const rpiHw = rpi.hardware || {};
    const rpiSvc = Object.entries(rpi).filter(([k, v]) => k.startsWith('service_') && v && typeof v === 'object');
    const piHtml = ddIsPi(device) ? (ddRows(Object.entries(rpiHw).map(([k, v]) => [k, v])) +
        (rpiSvc.length ? ddChips(rpiSvc.map(([k, v]) => `${k.replace('service_', ':')} ${v.title || v.indicator || ''}`)) : '')) : '';
    const sshHw = ((info.remote_access || {}).ssh || {}).hardware || {};
    const sshHwHtml = Object.keys(sshHw).length ? ddRows(Object.entries(sshHw).map(([k, v]) => [k, typeof v === 'object' ? JSON.stringify(v) : v])) : '';
    return ddSection(ddT('det_hardware', 'Hardware'), 'i-cpu', hw) +
        ddSection('Bluetooth LE', 'i-bluetooth', ble) +
        ddSection('Raspberry Pi', 'i-cpu', piHtml) +
        ddSection(ddT('dd_ssh_hw', 'Hardware via SSH'), 'i-cpu', sshHwHtml ||
            (ddHasSsh(device) && ddIsPi(device) ? ddNote(ddT('dd_ssh_creds_hint', 'SSH is open: add credentials in Edit > Access to collect kernel, CPU, memory and disk details.')) : ''));
}

function ddMacKind(mac) {
    const first = parseInt(String(mac).replace(/[^0-9a-f]/gi, '').slice(0, 2), 16);
    if (isNaN(first)) return '';
    if (first & 1) return ddT('dd_mac_multicast', 'multicast');
    return first & 2 ? ddT('dd_mac_random', 'private / randomized (no vendor)') : ddT('dd_mac_global', 'globally unique (vendor-assigned)');
}

function ddDiscovery(device) {
    const ev = device.discovery_evidence || {};
    const d = device.discovery || {};
    const sources = [...new Set([...(device.discovery_sources || []), ...(d.sources || [])])];
    const services = [...new Set([...(device.services || []), ...(ev.services || []), ...(d.services || [])])];
    const summary = ddRows([
        [ddT('dd_seen_via', 'Seen via'), sources],
        ['DHCP', ev.dhcp_hostname],
        [ddT('dd_dhcp_vclass', 'DHCP vendor class'), ev.dhcp_vendor_class],
        ['mDNS', ev.mdns_hostname],
        ['SSDP / UPnP', ev.ssdp_name],
        [ddT('dd_model', 'Model'), ev.model || d.model],
    ]) + ddChips(services);
    const probes = Object.entries(ev.probes || {}).map(([k, v]) => ddCard(k, 'i-radar',
        ddRows(Object.entries(v || {}).map(([kk, vv]) => [kk, typeof vv === 'object' ? JSON.stringify(vv) : vv])))).join('');
    const descriptions = ((d.attributes || {}).ssdp || {}).descriptions || {};
    const desc = Object.entries(descriptions).map(([url, doc]) => ddCard(url, 'i-external',
        ddRows(Object.entries(doc).map(([k, v]) => [k, Array.isArray(v) ? v.join(', ') : v])))).join('');
    const attrs = { ...(d.attributes || {}), ...(device.attributes || {}) };
    const raw = Object.keys(attrs).length ? `<pre class="details-code">${ddEsc(JSON.stringify(attrs, null, 2))}</pre>` : '';
    const body = ddSection(ddT('det_protocol_discovery', 'Protocol discovery'), 'i-radar', summary) +
        ddSection(ddT('dd_vendor_probes', 'Vendor protocol answers'), 'i-plug', probes ? `<div class="dd-grid">${probes}</div>` : '') +
        ddSection('UPnP (description.xml)', 'i-external', desc ? `<div class="dd-grid">${desc}</div>` : '') +
        ddSection(ddT('dd_raw_attrs', 'Raw discovery attributes'), 'i-info', raw);
    return body || ddSection(ddT('det_protocol_discovery', 'Protocol discovery'), 'i-radar',
        ddNote(ddT('dd_disc_none', 'Nothing announced yet over DHCP, mDNS, SSDP, ONVIF or Bluetooth. DHCP names appear when the device next renews its lease (usually within a day).')));
}

function ddOpenOther(ip) {
    const d = ddDeviceByIp(ip);
    if (d) openEnhancedDetailsModal(d);
}
