/**
 * Config Page JavaScript Functions
 * Handles configuration management, OUI database, device types, and detection rules
 */

// Global variables
let currentOuiDatabase = {};
let currentDeviceTypes = {};
let currentSettings = {};

// Page initialization
window.addEventListener('load', function() {
    loadAllSettings();
});

// Cleanup when page is unloaded
window.addEventListener('beforeunload', function() {
    cleanupDeviceTypeListeners();
});

// Cleanup when navigating away
window.addEventListener('pagehide', function() {
    cleanupDeviceTypeListeners();
});

window.addEventListener('translationsLoaded', function () {
    // translations.js fetches its table after this file has already rendered,
    // so the first paint showed raw keys like "category_network".
    if (Object.keys(currentDeviceTypes || {}).length) displayDeviceTypes();
    if (currentSettings && currentSettings.detection_rules) displayDetectionRules();
    if (Object.keys(currentOuiDatabase || {}).length) displayOuiDatabase();
    updateDetectionRuleSelects();
});

/**
 * Tab Management
 */
function switchTab(tabName) {
    // Tab butonlarını güncelle
    document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
    document.querySelector(`[onclick="switchTab('${tabName}')"]`).classList.add('active');
    
    // Tab içeriklerini güncelle
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
    document.getElementById(tabName).classList.add('active');
    
    // Seçilen tab'a göre özel yükleme işlemleri
    if (tabName === 'networks') {
        loadNetworks();
    } else if (tabName === 'docker') {
        loadDockerInfo();
    } else if (tabName === 'databases') {
        setupDatabasesTab();
    } else if (tabName === 'filters') {
        setupConfigFilters();
    } else if (tabName === 'integrations') {
        setupIntegrationsTab();
    } else if (tabName === 'logs') {
        loadLogs();
    }
}

/* Databases tab: two sub-tabs (OUI, CVE), each lazy-loaded on first open so a
 * 1.5 MB OUI fetch and the CVE endpoints only fire when actually viewed. */
function setupDatabasesTab() {
    // Default to whichever sub-tab is already marked active in the markup (OUI),
    // and load it. switchDbTab is idempotent so re-entering costs nothing.
    const active = document.querySelector('.subtab.active');
    const name = (active && active.getAttribute('onclick') || '').includes("'cve'") ? 'cve' : 'oui';
    switchDbTab(name);
}

function switchDbTab(name) {
    document.querySelectorAll('.subtab').forEach(el => el.classList.remove('active'));
    const btn = document.querySelector(`[onclick="switchDbTab('${name}')"]`);
    if (btn) btn.classList.add('active');

    document.querySelectorAll('.subtab-content').forEach(el => el.classList.remove('active'));
    const panelId = name === 'cve' ? 'dbCve' : 'dbOui';
    const panel = document.getElementById(panelId);
    if (panel) panel.classList.add('active');

    if (name === 'oui') {
        ensureOuiLoaded();
    } else if (name === 'cve') {
        setupCveDb();
    }
}

/* Integrations tab: InfluxDB2 push settings (secret token stays server-side),
 * the Prometheus scrape URL, and a live REST API catalog. */
let _integrationsMounted = false;
function setupIntegrationsTab() {
    // The scrape URL is derived from the current origin so a copy-paste works
    // from wherever the user opened MyNeS.
    const scrapeInput = document.getElementById('promScrapeUrl');
    if (scrapeInput) scrapeInput.value = window.location.origin + '/api/metrics';

    if (_integrationsMounted) return;
    _integrationsMounted = true;

    document.getElementById('influxSaveBtn').addEventListener('click', saveIntegrationsMetrics);
    document.getElementById('influxTestBtn').addEventListener('click', testIntegrationsMetrics);
    document.getElementById('catalogLoadBtn').addEventListener('click', loadApiCatalog);
    document.getElementById('openapiDownloadBtn').addEventListener('click', downloadOpenApi);
    loadIntegrationsMetrics();
}

/* CVE database card: mirrors the OUI database UX. The built-in CVE_PATTERNS is
 * the seed/fallback; a downloadable JSON overlay augments it. Status shows the
 * counts and provenance; Sync/Import refresh the overlay.
 *
 * Now lives under the Databases > CVE sub-tab, opened lazily; guard against
 * double-binding listeners each time that sub-tab is re-entered. */
let _cveDbMounted = false;
function setupCveDb() {
    if (_cveDbMounted) { loadCveDb(); return; }
    _cveDbMounted = true;
    document.getElementById('cveSyncBtn').addEventListener('click', syncCveDb);
    document.getElementById('cveSettingsBtn').addEventListener('click', saveCveSettings);
    document.getElementById('cveImportBtn').addEventListener('click',
        () => document.getElementById('cveImportFile').click());
    document.getElementById('cveImportFile').addEventListener('change', importCveDb);
    document.getElementById('cveSource').addEventListener('change', toggleCveSourceUrl);
    // CVE List V5 (official CVE Project corpus) - updatable like the OUI DB.
    document.getElementById('cveListDeltaBtn').addEventListener('click', () => updateCveList('delta'));
    document.getElementById('cveListFullBtn').addEventListener('click', () => updateCveList('full'));
    document.getElementById('cveListSearchBtn').addEventListener('click', searchCveList);
    document.getElementById('cveListSearchInput').addEventListener('keyup', e => {
        if (e.key === 'Enter') searchCveList();
    });
    loadCveDb();
    loadCveSettings();
}

// The custom native-overlay URL only matters when "Custom" is picked.
function toggleCveSourceUrl() {
    const custom = document.getElementById('cveSource').value === 'custom';
    document.getElementById('cveSourceUrlRow').style.display = custom ? '' : 'none';
}

// The value sent to the API: a provider key, or the custom URL when chosen.
function cveSourceValue() {
    const sel = document.getElementById('cveSource').value;
    return sel === 'custom' ? document.getElementById('cveSourceUrl').value.trim() : sel;
}

async function loadCveDb() {
    try {
        const s = await (await fetch('/api/security/cve-db')).json();
        document.getElementById('cveDbTotal').textContent = s.total ?? '—';
        document.getElementById('cveDbBuiltin').textContent = s.builtin_count ?? '—';
        document.getElementById('cveDbCustom').textContent = s.custom_count ?? '—';
        document.getElementById('cveDbLastUpdated').textContent =
            s.last_updated ? new Date(s.last_updated).toLocaleString() : t('never');
        // The official CVE List V5 corpus counts (0 until first update).
        document.getElementById('cveListCount').textContent =
            s.records_count != null ? s.records_count.toLocaleString() : '—';
        document.getElementById('cveListLastUpdated').textContent =
            s.records_last_updated ? new Date(s.records_last_updated).toLocaleString() : t('never');
    } catch (_) { /* leave placeholders */ }
}

/* Parse a fetch Response as JSON, but if the server answered with an error
 * page (an older build without the route, a 500, a proxy error) surface a
 * clean message instead of a "Unexpected token '<'" JSON parse crash. */
async function parseJsonOrThrow(res) {
    const body = await res.text();
    try {
        return JSON.parse(body);
    } catch (_) {
        if (!res.ok) throw new Error(`${t('endpoint_unavailable')} (HTTP ${res.status})`);
        throw new Error(t('unexpected_response'));
    }
}

/* CVE List V5: adopt the official CVE Project corpus into the reference store.
 * mode=delta is tiny (~0.1 MB, recent CVEs); mode=full is ~570 MB and must be
 * confirmed. Mirrors the OUI "download latest" flow. */
async function updateCveList(mode) {
    const status = document.getElementById('cveListStatus');
    if (mode === 'full' && !confirm(t('cve_list_full_confirm'))) return;
    status.textContent = t('cve_list_updating');
    status.style.color = 'var(--text-secondary)';
    try {
        const res = await fetch('/api/security/cve-db/update-list', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mode }),
        });
        // An older build won't have this route and returns an HTML 404/500;
        // don't blow up JSON.parse - say the endpoint is unavailable.
        const data = await parseJsonOrThrow(res);
        if (data.ok) {
            status.textContent = t('cve_list_update_ok', {
                written: (data.written ?? 0).toLocaleString(),
                total: (data.records_count ?? 0).toLocaleString(),
            });
            status.style.color = 'var(--severity-success-fg, var(--text-secondary))';
            loadCveDb();
        } else {
            status.textContent = t('cve_list_update_failed') + ' ' + (data.error || '');
            status.style.color = 'var(--severity-critical-fg, var(--text-secondary))';
        }
    } catch (e) {
        status.textContent = t('cve_list_update_failed') + ' ' + e.message;
        status.style.color = 'var(--severity-critical-fg, var(--text-secondary))';
    }
}

async function searchCveList() {
    const q = document.getElementById('cveListSearchInput').value.trim();
    const out = document.getElementById('cveListResults');
    if (!q) { out.innerHTML = ''; return; }
    out.innerHTML = `<div class="oui-count">${t('loading')}</div>`;
    try {
        const data = await parseJsonOrThrow(await fetch('/api/security/cve-db/search?q=' + encodeURIComponent(q)));
        const rows = data.results || [];
        if (!rows.length) { out.innerHTML = `<div class="oui-count">${t('no_results')}</div>`; return; }
        out.innerHTML = rows.map(r => {
            const sev = (r.severity || 'none').toLowerCase();
            const title = r.title || r.description || '';
            return `
            <div class="cve-item">
                <a class="cve-item__id" href="https://www.cve.org/CVERecord?id=${_apiEsc(r.cve_id)}" target="_blank" rel="noopener">${_apiEsc(r.cve_id)}</a>
                <span class="cve-sev cve-sev--${_apiEsc(sev)}">${_apiEsc(sev)}</span>
                <span class="cve-item__title" title="${_apiEsc(title)}">${_apiEsc(title)}</span>
            </div>`;
        }).join('');
    } catch (e) {
        out.innerHTML = `<div class="oui-count">${_apiEsc(e.message)}</div>`;
    }
}

async function loadCveSettings() {
    try {
        const c = await (await fetch('/api/security/cve-db/settings')).json();
        const src = c.cve_source || 'cveorg';
        const known = ['cveorg', 'circl'].includes(src);
        document.getElementById('cveSource').value = known ? src : 'custom';
        document.getElementById('cveSourceUrl').value = known ? '' : src;
        toggleCveSourceUrl();
        document.getElementById('cveSyncEnabled').checked = !!c.cve_sync_enabled;
        document.getElementById('cveSyncInterval').value = c.cve_sync_interval_days || 30;
    } catch (_) { /* leave defaults */ }
}

async function syncCveDb() {
    const status = document.getElementById('cveDbStatus');
    status.textContent = t('cve_db_syncing');
    const source = cveSourceValue();
    try {
        const res = await fetch('/api/security/cve-db/sync', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(source ? { source } : {}),
        });
        const data = await parseJsonOrThrow(res);
        if (data.ok) {
            // Provider sync reports enriched/failed; a custom overlay reports kept/dropped.
            const n = data.enriched ?? data.kept ?? 0;
            const bad = data.failed ?? data.dropped ?? 0;
            status.textContent = t('cve_db_sync_ok', { kept: n, dropped: bad });
            status.style.color = 'var(--severity-success-fg, var(--text-secondary))';
            loadCveDb();
        } else {
            status.textContent = t('cve_db_sync_failed') + ' ' + (data.error || '');
            status.style.color = 'var(--severity-critical-fg, var(--text-secondary))';
        }
    } catch (e) {
        status.textContent = t('cve_db_sync_failed') + ' ' + e.message;
        status.style.color = 'var(--severity-critical-fg, var(--text-secondary))';
    }
}

async function saveCveSettings() {
    const payload = {
        cve_source: cveSourceValue(),
        cve_sync_enabled: document.getElementById('cveSyncEnabled').checked,
        cve_sync_interval_days: parseInt(document.getElementById('cveSyncInterval').value, 10) || 30,
    };
    try {
        const res = await fetch('/api/security/cve-db/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        const data = await res.json();
        showAlert(data.ok ? t('settings_saved') : (data.error || t('settings_save_error')),
            data.ok ? 'success' : 'error');
    } catch (e) {
        showAlert(t('settings_save_error') + e.message, 'error');
    }
}

async function importCveDb() {
    const input = document.getElementById('cveImportFile');
    const file = input.files && input.files[0];
    if (!file) return;
    const status = document.getElementById('cveDbStatus');
    try {
        const body = JSON.parse(await file.text());
        const res = await fetch('/api/security/cve-db', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        const data = await res.json();
        if (data.ok) {
            status.textContent = t('cve_db_import_ok', { imported: data.imported ?? 0, dropped: data.dropped ?? 0 });
            status.style.color = 'var(--severity-success-fg, var(--text-secondary))';
            loadCveDb();
        } else {
            status.textContent = t('cve_db_import_failed') + ' ' + (data.error || '');
            status.style.color = 'var(--severity-critical-fg, var(--text-secondary))';
        }
    } catch (e) {
        status.textContent = t('cve_db_import_failed') + ' ' + e.message;
        status.style.color = 'var(--severity-critical-fg, var(--text-secondary))';
    } finally {
        input.value = '';
    }
}

async function downloadOpenApi() {
    try {
        const spec = await (await fetch('/api/openapi.json')).json();
        const blob = new Blob([JSON.stringify(spec, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'mynes-openapi.json';
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
    } catch (e) {
        showAlert(e.message, 'error');
    }
}

async function loadIntegrationsMetrics() {
    try {
        const cfg = await (await fetch('/api/integrations/metrics')).json();
        document.getElementById('influxUrl').value = cfg.url || '';
        document.getElementById('influxOrg').value = cfg.org || '';
        document.getElementById('influxBucket').value = cfg.bucket || '';
        document.getElementById('influxEnabled').checked = !!cfg.enabled;
        // The token is never returned; show a hint when one is already stored.
        const tok = document.getElementById('influxToken');
        tok.placeholder = cfg.token_set ? t('metrics_token_saved') : t('metrics_influx_token_placeholder');
    } catch (_) { /* leave the form blank */ }
}

async function saveIntegrationsMetrics() {
    const payload = {
        url: document.getElementById('influxUrl').value.trim(),
        org: document.getElementById('influxOrg').value.trim(),
        bucket: document.getElementById('influxBucket').value.trim(),
        token: document.getElementById('influxToken').value,
        enabled: document.getElementById('influxEnabled').checked,
    };
    try {
        const res = await fetch('/api/integrations/metrics', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        const data = await res.json();
        if (data.ok) {
            showAlert(t('metrics_saved'));
            document.getElementById('influxToken').value = '';
            loadIntegrationsMetrics();
        } else {
            showAlert(data.error || t('settings_save_error'), 'error');
        }
    } catch (e) {
        showAlert(t('settings_save_error') + e.message, 'error');
    }
}

async function testIntegrationsMetrics() {
    const status = document.getElementById('influxStatus');
    status.textContent = t('testing');
    try {
        const res = await fetch('/api/integrations/metrics/test', { method: 'POST' });
        const data = await res.json();
        status.textContent = (data.ok ? '✓ ' : '✗ ') + (data.msg || '');
        status.style.color = data.ok ? 'var(--severity-info, var(--text-secondary))' : 'var(--severity-critical, var(--text-secondary))';
    } catch (e) {
        status.textContent = '✗ ' + e.message;
        status.style.color = 'var(--severity-critical, var(--text-secondary))';
    }
}

const _apiEsc = v => String(v ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function _methodClass(method) {
    const m = String(method).toLowerCase();
    if (['get', 'post', 'delete', 'put', 'patch'].includes(m)) return 'api-method--' + m;
    return 'api-method--other';
}

/* Grouped, interactive API doc. Endpoints are grouped by tag (first path
 * segment), each a collapsible row. A GET with no path params gets a live
 * "Send" button; everything else shows a copyable curl example so mutations
 * are never fired automatically. */
async function loadApiCatalog() {
    const wrap = document.getElementById('catalogTableWrap');
    wrap.innerHTML = `<div class="oui-count">${t('loading')}</div>`;
    try {
        const data = await (await fetch('/api/catalog')).json();
        const groups = {};
        (data.routes || []).forEach(r => {
            const segs = r.path.split('/').filter(s => s && !s.startsWith('<'));
            const tag = segs.length > 1 ? segs[1] : (segs[0] || 'api');
            (groups[tag] = groups[tag] || []).push(r);
        });

        const html = Object.keys(groups).sort().map(tag => {
            const rows = groups[tag].map(r => (r.methods || []).map(method => {
                const hasParam = /<[^>]+>/.test(r.path);
                const canSend = method === 'GET' && !hasParam;
                const origin = window.location.origin;
                const action = canSend
                    ? `<button type="button" class="btn btn-small" data-api-send="${_apiEsc(r.path)}">${t('api_send')}</button>`
                    : `<div><code style="user-select:all;">curl -X ${_apiEsc(method)} ${_apiEsc(origin + r.path)}</code></div>`;
                return `
                <div class="api-endpoint">
                    <div class="api-endpoint__head" data-api-toggle>
                        <span class="api-method ${_methodClass(method)}">${_apiEsc(method)}</span>
                        <span class="api-endpoint__path">${_apiEsc(r.path)}</span>
                        <span class="api-endpoint__doc">${_apiEsc(r.doc || '')}</span>
                    </div>
                    <div class="api-endpoint__body">
                        <p style="color: var(--text-secondary); margin: 0 0 var(--space-2);">${_apiEsc(r.doc || '')}</p>
                        ${action}
                    </div>
                </div>`;
            }).join('')).join('');
            return `<div class="api-group"><div class="api-group__title">${_apiEsc(tag)}</div>${rows}</div>`;
        }).join('');

        wrap.innerHTML = html +
            `<div class="oui-count" style="margin-top: var(--space-2);">${t('api_catalog_count', { count: data.count || 0 })}</div>`;

        wrap.querySelectorAll('[data-api-toggle]').forEach(head =>
            head.addEventListener('click', () => head.closest('.api-endpoint').classList.toggle('is-open')));
        wrap.querySelectorAll('[data-api-send]').forEach(btn =>
            btn.addEventListener('click', () => sendApiRequest(btn)));
    } catch (e) {
        wrap.innerHTML = `<div class="oui-count">${_apiEsc(e.message)}</div>`;
    }
}

async function sendApiRequest(btn) {
    const path = btn.dataset.apiSend;
    const body = btn.closest('.api-endpoint__body');
    let pre = body.querySelector('pre');
    if (!pre) { pre = document.createElement('pre'); body.appendChild(pre); }
    pre.textContent = t('loading');
    try {
        const res = await fetch(path);
        const text = await res.text();
        try { pre.textContent = JSON.stringify(JSON.parse(text), null, 2); }
        catch (_) { pre.textContent = text; }
    } catch (e) {
        pre.textContent = e.message;
    }
}

/* Default-filters tab: edits the same shared MynesFilters store the Devices/
 * Alerts/History panels use. Fetches the live device list once so the type/
 * vendor multi-selects offer real options. */
let _cfgFiltersMounted = false;
async function setupConfigFilters() {
    if (!window.MynesFilters) return;
    const F = window.MynesFilters;
    if (_cfgFiltersMounted) return;
    _cfgFiltersMounted = true;

    F.bindToggle(document.getElementById('cfgToggleContainers'), 'showContainers');
    F.bindToggle(document.getElementById('cfgToggleNoIp'), 'showNoIp');
    F.bindToggle(document.getElementById('cfgToggleBluetooth'), 'showBluetooth');

    let devices = [];
    try { devices = await (await fetch('/devices')).json(); } catch (_) { devices = []; }
    const iconFor = t => (currentDeviceTypes && currentDeviceTypes[t] && currentDeviceTypes[t].icon) || '';

    F.mountMulti(document.getElementById('cfgTypeFilterMulti'), {
        key: 'types', label: t('device_type'),
        options: () => [...new Set(devices.map(d => d.device_type).filter(Boolean))].sort()
            .map(v => ({ value: v, label: v, icon: iconFor(v) })),
    });
    F.mountMulti(document.getElementById('cfgVendorFilterMulti'), {
        key: 'vendors', label: t('vendor'),
        options: () => [...new Set(devices.map(d => F.vendorOf(d)).filter(Boolean))].sort()
            .map(v => ({ value: v, label: v })),
    });
    F.mountMulti(document.getElementById('cfgStatusFilterMulti'), {
        key: 'statuses', label: t('status'),
        options: () => [{ value: 'online', label: t('online') }, { value: 'offline', label: t('offline') }],
    });
}

/*
 * The OUI database is 1.5 MB of JSON. Fetching and parsing it during page load
 * blocked every other tab behind it, which is why Settings took seconds to
 * become usable. It is now loaded the first time its own tab is opened.
 */
let ouiLoadPromise = null;

function ensureOuiLoaded() {
    if (ouiLoadPromise) return ouiLoadPromise;
    const list = document.getElementById('ouiList');
    if (list) list.innerHTML = `<div class="oui-count">${t('loading')}</div>`;
    ouiLoadPromise = fetch('/api/config/oui')
        .then(r => r.json())
        .then(data => {
            currentOuiDatabase = data;
            displayOuiDatabase();
        })
        .catch(error => {
            ouiLoadPromise = null;              // let the next visit retry
            showAlert(t('settings_load_error') + error.message, 'error');
        });
    return ouiLoadPromise;
}

/**
 * Alert System
 */
function showAlert(message, type = 'success') {
    const alertContainer = document.getElementById('alertContainer');
    const alertClass = type === 'error' ? 'alert-error' : 'alert-success';
    alertContainer.innerHTML = `<div class="alert ${alertClass}">${message}</div>`;
    
    setTimeout(() => {
        alertContainer.innerHTML = '';
    }, 5000);
}

/**
 * Data Loading Functions
 */
async function loadAllSettings() {
    try {
        // The OUI database is loaded lazily - see ensureOuiLoaded().

        // Device types
        const deviceTypesResponse = await fetch('/api/config/device_types');
        currentDeviceTypes = await deviceTypesResponse.json();
        displayDeviceTypes();

        // General settings
        const settingsResponse = await fetch('/api/config/settings');
        currentSettings = await settingsResponse.json();
        displayGeneralSettings();
        await populateIpRangeOptions();
        await populateInterfaceOptions();
        displayDetectionRules();
        displayDevicePortRules();
        
        // Update selects with device types
        updateDetectionRuleSelects();

    } catch (error) {
        showAlert(t('settings_load_error') + error.message, 'error');
    }
}

/**
 * General Settings Display
 */
function displayGeneralSettings() {
    const scanSettings = currentSettings.scan_settings || {};
    const portSettings = currentSettings.port_settings || {};

    const timeout = document.getElementById('timeout');
    const maxThreads = document.getElementById('maxThreads');
    const includeOffline = document.getElementById('includeOffline');
    const defaultPorts = document.getElementById('defaultPorts');

    // defaultIpRange is a dropdown populated from live interfaces/gateways -
    // see populateIpRangeOptions(), called by loadAllSettings after this.
    if (timeout) timeout.value = scanSettings.timeout || '';
    if (maxThreads) maxThreads.value = scanSettings.max_threads || '';
    if (includeOffline) includeOffline.checked = scanSettings.include_offline === true;
    if (defaultPorts) defaultPorts.value = (portSettings.default_ports || []).join(',');

    // Device specific ports - sadece currentDevicePortRules div'ini güncelle
    displayDevicePortRules();
}

/**
 * OUI Database Management
 */
/*
 * The IEEE database is ~40,000 entries. The old renderer built one styled DOM
 * node for every one of them on load, and the search box then walked all
 * 40,000 nodes on each keystroke - that is the freeze. Now the list renders
 * only what matches, capped, and search re-renders from the data.
 */
const OUI_PAGE_SIZE = 100;
let ouiPage = 0;

function displayOuiDatabase() {
    const ouiList = document.getElementById('ouiList');
    if (!ouiList) return;

    const term = (document.getElementById('ouiSearchInput')?.value || '').trim().toLowerCase();
    const all = Object.entries(currentOuiDatabase);
    const matches = term
        ? all.filter(([oui, vendor]) => oui.toLowerCase().includes(term) || String(vendor).toLowerCase().includes(term))
        : all;
    matches.sort(([a], [b]) => a.localeCompare(b));

    const pages = Math.max(1, Math.ceil(matches.length / OUI_PAGE_SIZE));
    ouiPage = Math.min(Math.max(0, ouiPage), pages - 1);
    const start = ouiPage * OUI_PAGE_SIZE;
    const shown = matches.slice(start, start + OUI_PAGE_SIZE);

    const esc = v => String(v ?? '').replace(/[&<>"']/g, c =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

    ouiList.innerHTML = shown.map(([oui, vendor]) => `
        <div class="oui-item">
            <span class="oui-item__code" title="${esc(oui.substring(0,2))}:${esc(oui.substring(2,4))}:${esc(oui.substring(4,6))}:XX:XX:XX">${esc(oui)}</span>
            <span class="oui-item__vendor" title="${esc(vendor)}">${esc(vendor)}</span>
            <span class="oui-item__actions">
                <button type="button" class="icon-btn" data-oui-edit="${esc(oui)}" title="${t('edit')}">
                    <svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-wrench"/></svg>
                </button>
                <button type="button" class="icon-btn icon-btn--danger" data-oui-remove="${esc(oui)}" title="${t('delete')}">
                    <svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-trash"/></svg>
                </button>
            </span>
        </div>`).join('') || `<div class="oui-count">${t('no_results')}</div>`;

    ouiList.querySelectorAll('[data-oui-edit]').forEach(btn =>
        btn.addEventListener('click', () => editOuiEntry(btn.dataset.ouiEdit, currentOuiDatabase[btn.dataset.ouiEdit])));
    ouiList.querySelectorAll('[data-oui-remove]').forEach(btn =>
        btn.addEventListener('click', () => removeOuiEntry(btn.dataset.ouiRemove)));

    renderOuiPager(matches.length, pages, start, shown.length);
}

/* Pagination rather than one endless list: 40,000 entries is far past what a
   scroll bar can address usefully. */
function renderOuiPager(total, pages, start, count) {
    const host = document.getElementById('ouiPager');
    if (!host) return;
    const from = count ? start + 1 : 0;
    host.innerHTML = `
        <button type="button" class="icon-btn" id="ouiFirst" ${ouiPage === 0 ? 'disabled' : ''} title="${t('first_page')}">«</button>
        <button type="button" class="icon-btn" id="ouiPrev" ${ouiPage === 0 ? 'disabled' : ''} title="${t('previous_page')}">‹</button>
        <span class="oui-pager__label">
            ${t('showing_range', { from: from, to: start + count, total: total })}
            <span class="oui-pager__page">${t('page_x_of_y', { page: ouiPage + 1, pages: pages })}</span>
        </span>
        <button type="button" class="icon-btn" id="ouiNext" ${ouiPage >= pages - 1 ? 'disabled' : ''} title="${t('next_page')}">›</button>
        <button type="button" class="icon-btn" id="ouiLast" ${ouiPage >= pages - 1 ? 'disabled' : ''} title="${t('last_page')}">»</button>`;

    const go = (page) => { ouiPage = page; displayOuiDatabase(); document.getElementById('ouiList').scrollTop = 0; };
    host.querySelector('#ouiFirst').addEventListener('click', () => go(0));
    host.querySelector('#ouiPrev').addEventListener('click', () => go(ouiPage - 1));
    host.querySelector('#ouiNext').addEventListener('click', () => go(ouiPage + 1));
    host.querySelector('#ouiLast').addEventListener('click', () => go(pages - 1));
}

function addOuiEntry() {
    const oui = document.getElementById('newOui').value.trim().toUpperCase();
    const vendor = document.getElementById('newVendor').value.trim();
    
    if (!oui || !vendor) {
        showAlert(t('oui_fields_required'), 'error');
        return;
    }
    
    if (oui.length !== 6) {
        showAlert(t('oui_must_be_six'), 'error');
        return;
    }
    
    currentOuiDatabase[oui] = vendor;
    displayOuiDatabase();
    
    document.getElementById('newOui').value = '';
    document.getElementById('newVendor').value = '';
    
    showAlert(t('oui_added'));
}

function removeOuiEntry(oui) {
    if (confirm(t('confirm_delete_oui', { oui: oui }))) {
        delete currentOuiDatabase[oui];
        displayOuiDatabase();
        showAlert(t('oui_removed'));
    }
}

function editOuiEntry(oui, vendor) {
    const newVendor = prompt(t('prompt_new_vendor', { oui: oui }), vendor);
    if (newVendor && newVendor.trim() !== '' && newVendor !== vendor) {
        currentOuiDatabase[oui] = newVendor.trim();
        displayOuiDatabase();
        showAlert(t('oui_updated'));
    }
}

let ouiFilterTimer = null;

function filterOuiList() {
    // Debounced, and back to page 1 - staying on page 40 of a two-page result
    // would look like the search found nothing.
    clearTimeout(ouiFilterTimer);
    ouiFilterTimer = setTimeout(() => { ouiPage = 0; displayOuiDatabase(); }, 150);
}

/**
 * Device Types Management
 */

const DEVICE_CATEGORIES = [
    'unknown', 'tech', 'network', 'smart', 'media', 'security', 'transport',
    'office', 'mobile', 'computer', 'peripheral', 'entertainment', 'appliance',
    'iot', 'storage', 'gaming', 'medical', 'industrial',
];

function categoryOptions(selected) {
    return DEVICE_CATEGORIES.map(key =>
        `<option value="${key}"${key === selected ? ' selected' : ''}>${t('category_' + key)}</option>`).join('');
}

function displayDeviceTypes() {
    const deviceTypesList = document.getElementById('deviceTypesList');
    if (!deviceTypesList) return;

    cleanupDeviceTypeListeners();
    deviceTypesList.className = 'device-types-grid';

    const esc = v => String(v ?? '').replace(/[&<>"']/g, c =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

    deviceTypesList.innerHTML = Object.entries(currentDeviceTypes).map(([typeName, typeInfo]) => {
        const slug = typeName.replace(/[^a-zA-Z0-9]/g, '_');
        return `
        <div class="device-type-card">
            <button type="button" class="device-type-card__icon" id="deviceIcon_${slug}"
                    data-icon-picker="deviceIcon_${slug}" data-device-type="${esc(typeName)}"
                    title="${t('icon_emoji')}">${esc(typeInfo.icon)}</button>
            <input type="text" class="device-type-card__name device-name-input"
                   data-device-type="${esc(typeName)}" value="${esc(typeName)}"
                   aria-label="${t('device_type_name')}">
            <div class="device-type-card__row">
                <select class="form-select device-category-select" data-device-type="${esc(typeName)}"
                        aria-label="${t('category')}">${categoryOptions(typeInfo.category)}</select>
                <button type="button" class="icon-btn icon-btn--danger device-remove-btn"
                        data-device-type="${esc(typeName)}" title="${t('delete')}">
                    <svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-trash"/></svg>
                </button>
            </div>
            <input type="hidden" class="device-icon-input" data-device-type="${esc(typeName)}" value="${esc(typeInfo.icon)}">
        </div>`;
    }).join('');

    // The icon tile is the picker trigger; it writes into the hidden input the
    // save path already reads, so nothing downstream had to change.
    deviceTypesList.querySelectorAll('[data-icon-picker]').forEach(tile => {
        tile.addEventListener('click', () => {
            const hidden = tile.parentElement.querySelector('.device-icon-input');
            hidden.id = tile.dataset.iconPicker + '_value';
            openEmojiPicker(hidden.id);
            const sync = () => { tile.textContent = hidden.value; };
            hidden.addEventListener('change', sync);
            hidden.addEventListener('input', sync);
        });
    });

    attachDeviceTypeEventListeners();
}

// Global array to track active intervals for cleanup
let activeIntervals = [];

// Cleanup function to clear all intervals and event listeners
function cleanupDeviceTypeListeners() {
    // Clear all active intervals
    activeIntervals.forEach(intervalId => {
        clearInterval(intervalId);
    });
    activeIntervals = [];
    
    // Remove existing event listeners by replacing elements
    const elementsToClean = [
        '.device-icon-input',
        '.device-name-input', 
        '.device-category-select',
        '.device-remove-btn'
    ];
    
    elementsToClean.forEach(selector => {
        document.querySelectorAll(selector).forEach(element => {
            const newElement = element.cloneNode(true);
            element.parentNode.replaceChild(newElement, element);
        });
    });
}

function attachDeviceTypeEventListeners() {
    // Clean up previous listeners and intervals
    cleanupDeviceTypeListeners();
    
    // Icon input event listeners - improved without polling
    const iconInputs = document.querySelectorAll('.device-icon-input');
    
    iconInputs.forEach(input => {
        const deviceType = input.getAttribute('data-device-type');
        
        // Use proper event delegation instead of polling
        const handleIconChange = function() {
            updateDeviceTypeIcon(deviceType, this.value);
        };
        
        // Attach events with proper cleanup tracking
        input.addEventListener('input', handleIconChange, { passive: true });
        input.addEventListener('change', handleIconChange, { passive: true });
        input.addEventListener('blur', handleIconChange, { passive: true });
        
        // Special handling for emoji picker updates
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (mutation.type === 'attributes' && mutation.attributeName === 'value') {
                    updateDeviceTypeIcon(deviceType, input.value);
                } else if (mutation.type === 'characterData' || 
                          (mutation.type === 'childList' && input.value !== input.defaultValue)) {
                    updateDeviceTypeIcon(deviceType, input.value);
                }
            });
        });
        
        observer.observe(input, {
            attributes: true,
            attributeFilter: ['value'],
            characterData: true,
            childList: true,
            subtree: true
        });
        
        // Store observer for cleanup
        input._observer = observer;
    });
    
    // Name input event listeners
    document.querySelectorAll('.device-name-input').forEach(input => {
        input.addEventListener('change', function() {
            const oldName = this.getAttribute('data-device-type');
            const newName = this.value;
            updateDeviceTypeName(oldName, newName);
        }, { passive: true });
    });
    
    // Category select event listeners
    document.querySelectorAll('.device-category-select').forEach(select => {
        select.addEventListener('change', function() {
            const deviceType = this.getAttribute('data-device-type');
            const newCategory = this.value;
            updateDeviceTypeCategory(deviceType, newCategory);
        }, { passive: true });
    });
    
    // Remove button event listeners
    document.querySelectorAll('.device-remove-btn').forEach(button => {
        button.addEventListener('click', function() {
            const deviceType = this.getAttribute('data-device-type');
            removeDeviceType(deviceType);
        });
    });
}

function updateDeviceTypeIcon(oldName, newIcon) {
    if (currentDeviceTypes[oldName]) {
        currentDeviceTypes[oldName].icon = newIcon;
    }
}

function updateDeviceTypeName(oldName, newName) {
    if (oldName !== newName && currentDeviceTypes[oldName]) {
        currentDeviceTypes[newName] = {...currentDeviceTypes[oldName]};
        delete currentDeviceTypes[oldName];
        displayDeviceTypes();
        updateDetectionRuleSelects();
    }
}

function updateDeviceTypeCategory(typeName, newCategory) {
    if (currentDeviceTypes[typeName]) {
        currentDeviceTypes[typeName].category = newCategory;
    }
}

async function addDeviceType() {
    const typeName = document.getElementById('newDeviceType').value.trim();
    const icon = document.getElementById('newDeviceIcon').value.trim();
    const category = document.getElementById('newDeviceCategory').value;

    if (!typeName || !icon) {
        showAlert(t('device_type_name_icon_required'), 'error');
        return;
    }

    currentDeviceTypes[typeName] = {
        icon: icon,
        category: category
    };

    displayDeviceTypes();
    updateDetectionRuleSelects();

    document.getElementById('newDeviceType').value = '';
    document.getElementById('newDeviceIcon').value = '';
    document.getElementById('newDeviceCategory').value = 'unknown';

    // Persist right away: a staged-only "added" that needs a separate Save was a
    // trap - the new type never reached the edit-page dropdown.
    await saveDeviceTypes();
}

function removeDeviceType(typeName) {
    if (confirm(t('confirm_delete_device_type', {type: typeName}))) {
        delete currentDeviceTypes[typeName];
        displayDeviceTypes();
        updateDetectionRuleSelects();
        showAlert(t('device_type_deleted'));
    }
}

/**
 * Detection Rules Management
 */
function deviceTypeOptions(selected) {
    return Object.entries(currentDeviceTypes)
        .map(([name, info]) => `<option value="${name}"${name === selected ? ' selected' : ''}>${info.icon || ''} ${name}</option>`)
        .join('');
}

/*
 * Each rule is "this regex means this device type". The type used to be
 * printed as plain text, so there was no way to see it as a choice or fix a
 * wrong one without deleting the rule and retyping the pattern.
 */
function renderPatternRules(container, rules, kind) {
    if (!rules.length) {
        container.innerHTML = `<div class="pattern-empty">${t('no_patterns_yet')}</div>`;
        return;
    }
    const esc = v => String(v ?? '').replace(/[&<>"']/g, c =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

    container.innerHTML = rules.map((rule, index) => `
        <div class="pattern-item">
            <input type="text" class="form-input pattern-item__pattern" value="${esc(rule.pattern)}"
                   data-pattern-index="${index}" spellcheck="false"
                   aria-label="${t('pattern')}" title="${esc(rule.pattern)}">
            <select class="form-select pattern-item__type" data-rule-kind="${kind}" data-rule-index="${index}"
                    aria-label="${t('device_type')}">${deviceTypeOptions(rule.type)}</select>
            <button type="button" class="icon-btn icon-btn--danger" data-remove-kind="${kind}" data-remove-index="${index}"
                    title="${t('delete')}">
                <svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-trash"/></svg>
            </button>
        </div>`).join('');

    // The pattern is a regex the scanner will compile, so a typo here silently
    // stops matching. Validate on edit and say so rather than saving garbage.
    container.querySelectorAll('[data-pattern-index]').forEach(input => {
        const commit = () => {
            const value = input.value.trim();
            const rule = rules[Number(input.dataset.patternIndex)];
            if (!value) {
                input.value = rule.pattern;
                input.classList.remove('is-invalid');
                return;
            }
            try {
                new RegExp(value, 'i');
            } catch (e) {
                input.classList.add('is-invalid');
                input.title = t('invalid_regex') + ' ' + e.message;
                return;
            }
            input.classList.remove('is-invalid');
            input.title = value;
            if (rule.pattern !== value) {
                rule.pattern = value;
                showAlert(t('detection_rule_updated'));
            }
        };
        input.addEventListener('change', commit);
        input.addEventListener('blur', commit);
        input.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); input.blur(); } });
    });

    container.querySelectorAll('[data-rule-kind]').forEach(select => {
        select.addEventListener('change', () => {
            rules[Number(select.dataset.ruleIndex)].type = select.value;
            showAlert(t('detection_rule_updated'));
        });
    });
    container.querySelectorAll('[data-remove-kind]').forEach(btn => {
        btn.addEventListener('click', () => {
            const i = Number(btn.dataset.removeIndex);
            if (btn.dataset.removeKind === 'hostname') removeHostnamePattern(i);
            else removeVendorPattern(i);
        });
    });
}

/**
 * Combined rules: vendor AND hostname, both required.
 *
 * A single-signal rule cannot separate a MacBook from an iPhone - the vendor
 * is "Apple" either way - which is why a laptop kept coming back as a generic
 * "Apple Device". These are evaluated before every heuristic the scanner has.
 */
function renderCombinedRules(container, rules) {
    if (!rules.length) {
        container.innerHTML = `<div class="pattern-empty">${t('no_patterns_yet')}</div>`;
        return;
    }
    const esc = v => String(v ?? '').replace(/[&<>"']/g, c =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

    container.innerHTML = rules.map((rule, index) => `
        <div class="pattern-item pattern-item--combined">
            <input type="text" class="form-input pattern-item__pattern" value="${esc(rule.vendor || '')}"
                   data-combined-index="${index}" data-combined-field="vendor" spellcheck="false"
                   placeholder="${t('vendor')}" aria-label="${t('vendor')}">
            <span class="pattern-item__and">${t('and')}</span>
            <input type="text" class="form-input pattern-item__pattern" value="${esc(rule.hostname || '')}"
                   data-combined-index="${index}" data-combined-field="hostname" spellcheck="false"
                   placeholder="${t('hostname')}" aria-label="${t('hostname')}">
            <select class="form-select pattern-item__type" data-combined-type="${index}"
                    aria-label="${t('device_type')}">${deviceTypeOptions(rule.type)}</select>
            <button type="button" class="icon-btn icon-btn--danger" data-combined-remove="${index}"
                    title="${t('delete')}">
                <svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-trash"/></svg>
            </button>
        </div>`).join('');

    container.querySelectorAll('[data-combined-index]').forEach(input => {
        const commit = () => {
            const value = input.value.trim();
            const rule = rules[Number(input.dataset.combinedIndex)];
            const field = input.dataset.combinedField;
            // An empty side means "any", which is what `.*` does in the scanner.
            if (value) {
                try {
                    new RegExp(value, 'i');
                } catch (e) {
                    input.classList.add('is-invalid');
                    input.title = t('invalid_regex') + ' ' + e.message;
                    return;
                }
            }
            input.classList.remove('is-invalid');
            input.title = value;
            if (rule[field] !== value) {
                rule[field] = value;
                showAlert(t('detection_rule_updated'));
            }
        };
        input.addEventListener('change', commit);
        input.addEventListener('blur', commit);
        input.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); input.blur(); } });
    });

    container.querySelectorAll('[data-combined-type]').forEach(select => {
        select.addEventListener('change', () => {
            rules[Number(select.dataset.combinedType)].type = select.value;
            showAlert(t('detection_rule_updated'));
        });
    });
    container.querySelectorAll('[data-combined-remove]').forEach(btn => {
        btn.addEventListener('click', () => {
            rules.splice(Number(btn.dataset.combinedRemove), 1);
            displayDetectionRules();
            showAlert(t('detection_rule_removed'));
        });
    });
}

function addCombinedRule() {
    const vendor = document.getElementById('newCombinedVendor').value.trim();
    const hostname = document.getElementById('newCombinedHostname').value.trim();
    const deviceType = document.getElementById('newCombinedDeviceType').value;

    // One of the two may be blank ("any Raspberry Pi"), but not both - a rule
    // that matches everything would swallow the whole device list.
    if ((!vendor && !hostname) || !deviceType) {
        showAlert(t('pattern_fields_required'), 'error');
        return;
    }

    if (!currentSettings.detection_rules) currentSettings.detection_rules = {};
    if (!currentSettings.detection_rules.combined_rules) currentSettings.detection_rules.combined_rules = [];
    currentSettings.detection_rules.combined_rules.push({ vendor, hostname, type: deviceType });

    document.getElementById('newCombinedVendor').value = '';
    document.getElementById('newCombinedHostname').value = '';
    document.getElementById('newCombinedDeviceType').value = '';
    displayDetectionRules();
    showAlert(t('detection_rule_added'));
}

function displayDetectionRules() {
    const hostnamePatterns = document.getElementById('hostnamePatterns');
    const vendorPatterns = document.getElementById('vendorPatterns');
    if (!hostnamePatterns || !vendorPatterns) return;

    const detectionRules = currentSettings.detection_rules || {};
    const combined = document.getElementById('combinedRules');
    if (combined) renderCombinedRules(combined, detectionRules.combined_rules || []);
    renderPatternRules(hostnamePatterns, detectionRules.hostname_patterns || [], 'hostname');
    renderPatternRules(vendorPatterns, detectionRules.vendor_patterns || [], 'vendor');
}

function addHostnamePattern() {
    const pattern = document.getElementById('newHostnamePattern').value.trim();
    const deviceType = document.getElementById('newHostnameDeviceType').value;
    
    if (!pattern || !deviceType) {
        showAlert(t('pattern_fields_required'), 'error');
        return;
    }
    
    if (!currentSettings.detection_rules) {
        currentSettings.detection_rules = {};
    }
    if (!currentSettings.detection_rules.hostname_patterns) {
        currentSettings.detection_rules.hostname_patterns = [];
    }
    
    currentSettings.detection_rules.hostname_patterns.push({
        pattern: pattern,
        type: deviceType
    });
    
    document.getElementById('newHostnamePattern').value = '';
    document.getElementById('newHostnameDeviceType').value = '';
    displayDetectionRules();
    showAlert(t('hostname_pattern_added'));
}

function addVendorPattern() {
    const pattern = document.getElementById('newVendorPattern').value.trim();
    const deviceType = document.getElementById('newVendorDeviceType').value;
    
    if (!pattern || !deviceType) {
        showAlert(t('pattern_fields_required'), 'error');
        return;
    }
    
    if (!currentSettings.detection_rules) {
        currentSettings.detection_rules = {};
    }
    if (!currentSettings.detection_rules.vendor_patterns) {
        currentSettings.detection_rules.vendor_patterns = [];
    }
    
    currentSettings.detection_rules.vendor_patterns.push({
        pattern: pattern,
        type: deviceType
    });
    
    document.getElementById('newVendorPattern').value = '';
    document.getElementById('newVendorDeviceType').value = '';
    displayDetectionRules();
    showAlert(t('vendor_pattern_added'));
}

function removeHostnamePattern(index) {
    if (currentSettings.detection_rules && currentSettings.detection_rules.hostname_patterns) {
        currentSettings.detection_rules.hostname_patterns.splice(index, 1);
        displayDetectionRules();
        showAlert(t('hostname_pattern_removed'));
    }
}

function removeVendorPattern(index) {
    if (currentSettings.detection_rules && currentSettings.detection_rules.vendor_patterns) {
        currentSettings.detection_rules.vendor_patterns.splice(index, 1);
        displayDetectionRules();
        showAlert(t('vendor_pattern_removed'));
    }
}

function saveDetectionRules() {
    fetch('/api/save_settings', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(currentSettings)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showAlert(t('detection_rules_saved'));
        } else {
            showAlert(t('save_error') + data.error, 'error');
        }
    })
    .catch(error => {
        showAlert(t('save_error') + error, 'error');
    });
}

/**
 * Port Management
 */
function displayDevicePortRules() {
    const container = document.getElementById('currentDevicePortRules');
    if (!container) return;
    
    container.innerHTML = '';
    
    const deviceSpecificPorts = currentSettings.port_settings?.device_specific_ports || {};
    if (Object.keys(deviceSpecificPorts).length > 0) {
        for (const [deviceType, ports] of Object.entries(deviceSpecificPorts)) {
            const div = document.createElement('div');
            div.className = 'port-rule';
            div.innerHTML = `
                <span><strong>${deviceType}:</strong> ${ports.join(', ')}</span>
                <button type="button" class="icon-btn icon-btn--danger" onclick="removeDevicePortRule('${deviceType}')" title="${t('delete')}">
                    <svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-trash"/></svg>
                </button>`;
            container.appendChild(div);
        }
    }
}

function addDeviceTypePorts() {
    const deviceType = document.getElementById('deviceTypePortSelect').value;
    const ports = document.getElementById('deviceTypePorts').value.trim();
    
    if (!deviceType || !ports) {
        showAlert(t('device_ports_required'), 'error');
        return;
    }
    
    if (!currentSettings.port_settings) {
        currentSettings.port_settings = {};
    }
    if (!currentSettings.port_settings.device_specific_ports) {
        currentSettings.port_settings.device_specific_ports = {};
    }
    
    currentSettings.port_settings.device_specific_ports[deviceType] = ports.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p));
    
    document.getElementById('deviceTypePorts').value = '';
    document.getElementById('deviceTypePortSelect').value = '';
    
    displayDevicePortRules();
    showAlert(t('device_port_rule_added'));
}

function removeDevicePortRule(deviceType) {
    if (currentSettings.port_settings?.device_specific_ports) {
        delete currentSettings.port_settings.device_specific_ports[deviceType];
        displayDevicePortRules();
        showAlert(t('device_port_rule_removed'));
    }
}

/**
 * Network Management
 */
/**
 * Interfaces grouped by the network range they sit on.
 *
 * A flat list hid the one fact that matters on a multi-homed box: end0 and
 * wlan0 are two doors into the *same* 192.168.1.0/24, while every br-* is its
 * own island. Grouping by range says that at a glance; the old list made you
 * compare CIDRs by eye down a page of identical cards.
 */
function renderNetworkGroups(host, networks) {
    const esc = v => String(v ?? '').replace(/[&<>"']/g, c =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

    const groups = new Map();
    (networks || []).forEach(n => {
        const key = n.network_range || n.ip || '?';
        if (!groups.has(key)) groups.set(key, []);
        groups.get(key).push(n);
    });

    if (!groups.size) {
        host.innerHTML = `<div class="pattern-empty">${t('no_networks_found')}</div>`;
        return;
    }

    // Shared ranges first - those are the ones worth a second look.
    const ordered = [...groups.entries()].sort((a, b) =>
        b[1].length - a[1].length || a[0].localeCompare(b[0]));

    host.innerHTML = ordered.map(([range, members]) => `
        <section class="net-group">
            <header class="net-group__head">
                <div>
                    <span class="net-group__range mono">${esc(range)}</span>
                    <span class="net-group__count">${members.length} ${t(members.length === 1 ? 'interface' : 'interfaces')}</span>
                </div>
                ${members.length > 1
                    ? `<span class="ds-badge ds-badge--info">${t('shared_segment')}</span>` : ''}
            </header>
            <div class="net-group__body">
                ${members.map(n => `
                    <article class="net-iface">
                        <div class="net-iface__name mono">${esc(n.interface)}</div>
                        <span class="network-type">${esc(n.type)}</span>
                        <dl class="net-iface__facts">
                            <div><dt>IP</dt><dd class="mono">${esc(n.ip)}</dd></div>
                            <div><dt>${t('netmask')}</dt><dd class="mono">${esc(n.netmask)}</dd></div>
                            ${n.description ? `<div><dt>${t('description')}</dt><dd>${esc(n.description)}</dd></div>` : ''}
                        </dl>
                    </article>`).join('')}
            </div>
        </section>`).join('');
}

/**
 * Fill the "default scan range" dropdown from live interfaces/gateways.
 * Selects the saved range, else the auto-detected gateway subnet (is_default).
 * Users with no CIDR knowledge just pick their network from the list.
 */
async function populateIpRangeOptions() {
    const sel = document.getElementById('defaultIpRange');
    if (!sel) return;

    let networks = [];
    try {
        networks = await (await fetch('/api/networks')).json();
    } catch (e) { /* keep going with whatever we have */ }

    const saved = (currentSettings.scan_settings || {}).default_ip_range || '';
    let detected = '';
    const byRange = new Map();  // range -> label, deduped
    (Array.isArray(networks) ? networks : []).forEach(n => {
        const range = n.network_range;
        if (!range || byRange.has(range)) return;
        if (n.is_default) detected = range;
        const auto = n.is_default ? ` — ${t('auto_detected')}` : '';
        byRange.set(range, `${range} (${n.interface || n.type || ''})${auto}`);
    });

    const savedIsLive = saved && byRange.has(saved);
    // The saved value might be a range no live interface reports right now -
    // keep it selectable so saving does not silently change it.
    if (saved && !byRange.has(saved)) byRange.set(saved, saved);

    // Prefer a saved range only when it matches a live interface; otherwise
    // default to the gateway subnet this app runs on (the requested behaviour).
    const chosen = (savedIsLive ? saved : (detected || saved))
        || byRange.keys().next().value || '';
    sel.innerHTML = [...byRange.entries()]
        .map(([range, label]) =>
            `<option value="${range}"${range === chosen ? ' selected' : ''}>${label}</option>`)
        .join('');
}

/**
 * Fill the scan-interface dropdown from live interfaces. "Auto" (empty) lets
 * the OS pick the route; naming one (en0/eth0/...) binds the raw ARP sweep to
 * that NIC - useful on a multi-homed host (WiFi + Ethernet).
 */
async function populateInterfaceOptions() {
    const sel = document.getElementById('scanInterface');
    if (!sel) return;

    let networks = [];
    try {
        networks = await (await fetch('/api/networks')).json();
    } catch (e) { /* keep going */ }

    const saved = (currentSettings.scan_settings || {}).interface || '';
    const byName = new Map();  // iface -> label, deduped
    (Array.isArray(networks) ? networks : []).forEach(n => {
        const name = n.interface;
        if (!name || byName.has(name)) return;
        byName.set(name, `${name}${n.network_range ? ` — ${n.network_range}` : ''}`);
    });
    if (saved && !byName.has(saved)) byName.set(saved, saved);  // keep an offline choice

    sel.innerHTML = `<option value=""${saved ? '' : ' selected'}>${t('all_interfaces_auto')}</option>`
        + [...byName.entries()]
            .map(([name, label]) => `<option value="${name}"${name === saved ? ' selected' : ''}>${label}</option>`)
            .join('');
}

async function loadNetworks() {
    try {
        const response = await fetch('/api/networks');
        const networks = await response.json();
        
        const networksList = document.getElementById('networksList');
        if (!networksList) return;
        
        renderNetworkGroups(networksList, networks);
    } catch (error) {
        showAlert(t('networks_load_error') + error.message, 'error');
    }
}

function refreshNetworks() {
    loadNetworks();
    showAlert(t('networks_refreshed'));
}

/**
 * Save Functions
 */
async function saveGeneralSettings() {
    try {
        const defaultIpRangeEl = document.getElementById('defaultIpRange');
        const timeoutEl = document.getElementById('timeout');
        const maxThreadsEl = document.getElementById('maxThreads');
        const includeOfflineEl = document.getElementById('includeOffline');
        const defaultPortsEl = document.getElementById('defaultPorts');
        
        if (!defaultIpRangeEl || !timeoutEl || !maxThreadsEl || !includeOfflineEl || !defaultPortsEl) {
            showAlert(t('form_elements_missing'), 'error');
            return;
        }
        
        const defaultPorts = defaultPortsEl.value.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p));
        
        const settingsData = {
            scan_settings: {
                default_ip_range: defaultIpRangeEl.value || '192.168.1.0/24',
                interface: (document.getElementById('scanInterface') || {}).value || '',
                timeout: parseInt(timeoutEl.value) || 3,
                max_threads: parseInt(maxThreadsEl.value) || 50,
                include_offline: includeOfflineEl.checked
            },
            port_settings: {
                default_ports: defaultPorts,
                device_specific_ports: currentSettings.port_settings?.device_specific_ports || {}
            }
        };
        
        const response = await fetch('/api/config/settings', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(settingsData)
        });
        
        const result = await response.json();
        
        if (response.ok && result.success) {
            showAlert(t('general_settings_saved'));
            currentSettings = {...currentSettings, ...settingsData};
            await loadAllSettings();
        } else {
            showAlert(t('error') + ': ' + (result.error || result.message || t('unknown_error')), 'error');
        }
        
    } catch (error) {
        showAlert(t('settings_save_error') + error.message, 'error');
    }
}

async function saveOuiDatabase() {
    try {
        const response = await fetch('/api/config/oui', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(currentOuiDatabase)
        });
        
        const result = await response.json();
        
        if (response.ok) {
            showAlert(t('oui_saved'));
        } else {
            showAlert(t('error') + ': ' + result.error, 'error');
        }
        
    } catch (error) {
        showAlert(t('oui_save_error') + error.message, 'error');
    }
}

async function saveDeviceTypes() {
    try {
        const response = await fetch('/api/config/device_types', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(currentDeviceTypes)
        });
        
        const result = await response.json();
        
        if (response.ok) {
            showAlert(t('device_types_saved'));
        } else {
            showAlert(t('error') + ': ' + result.error, 'error');
        }
        
    } catch (error) {
        showAlert(t('device_types_save_error') + error.message, 'error');
    }
}

/**
 * Import/Export Functions
 */
function exportOuiDatabase() {
    const dataStr = JSON.stringify(currentOuiDatabase, null, 2);
    const dataBlob = new Blob([dataStr], {type: 'application/json'});
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'oui_database.json';
    link.click();
    URL.revokeObjectURL(url);
}

function importOuiDatabase() {
    const file = document.getElementById('ouiImportFile').files[0];
    if (file) {
        const reader = new FileReader();
        reader.onload = function(e) {
            try {
                const importedData = JSON.parse(e.target.result);
                currentOuiDatabase = {...currentOuiDatabase, ...importedData};
                displayOuiDatabase();
                showAlert(t('oui_imported', { count: Object.keys(importedData).length }));
            } catch (error) {
                showAlert(t('import_invalid_json'), 'error');
            }
        };
        reader.readAsText(file);
    }
}

/**
 * OUI API Functions
 */
async function downloadIEEEDatabase() {
    const btn = document.getElementById('downloadIEEEBtn');
    const originalText = btn.textContent;
    
    btn.disabled = true;
    btn.textContent = t('downloading');
    
    try {
        const response = await fetch('/api/download_ieee_oui');
        const result = await response.json();
        
        if (result.success) {
            // Server message now reports real new/changed counts (idempotent),
            // so a second click reads "already up to date" instead of a
            // misleading full-count every time.
            showAlert(result.message || t('ieee_updated', { count: result.processed_count }));
            loadAllSettings();
        } else {
            showAlert(t('ieee_download_error') + result.error, 'error');
        }
    } catch (error) {
        showAlert(t('connection_error') + error.message, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = originalText;
    }
}

async function lookupVendorAPI() {
    const oui = document.getElementById('newOui').value.trim();
    
    if (!oui || oui.length !== 6) {
        showAlert(t('oui_must_be_six'), 'error');
        return;
    }
    
    const btn = document.getElementById('apiLookupBtn');
    const originalText = btn.textContent;
    
    btn.disabled = true;
    btn.textContent = t('searching');
    
    try {
        const testMac = oui + '123456';
        
        const response = await fetch(`/api/lookup_vendor/${testMac}`);
        const result = await response.json();
        
        if (result.success) {
            document.getElementById('newVendor').value = result.vendor;
            showAlert(`Vendor bulundu: ${result.vendor} (Kaynak: ${result.source})`);
        } else {
            showAlert(t('vendor_not_found') + result.error, 'error');
        }
    } catch (error) {
        showAlert(t('api_lookup_error') + error.message, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = originalText;
    }
}

/**
 * Helper Functions
 */
function updateDetectionRuleSelects() {
    const hostnameSelect = document.getElementById('newHostnameDeviceType');
    const vendorSelect = document.getElementById('newVendorDeviceType');
    const devicePortSelect = document.getElementById('deviceTypePortSelect');
    const combinedSelect = document.getElementById('newCombinedDeviceType');

    if (!hostnameSelect || !vendorSelect || !devicePortSelect) return;

    // Leading placeholder: without it the picker silently pre-selects whatever
    // sorts first, and "Add" quietly files the rule under Access Point.
    if (combinedSelect) {
        combinedSelect.innerHTML =
            `<option value="">${t('select_device_type')}</option>` + deviceTypeOptions('');
    }
    hostnameSelect.innerHTML = `<option value="">${t('select_device_type')}</option>`;
    vendorSelect.innerHTML = `<option value="">${t('select_device_type')}</option>`;
    devicePortSelect.innerHTML = `<option value="">${t('select_device_type_for_ports')}</option>`;
    
    for (const typeName of Object.keys(currentDeviceTypes)) {
        const option1 = document.createElement('option');
        option1.value = typeName;
        option1.textContent = typeName;
        hostnameSelect.appendChild(option1);
        
        const option2 = document.createElement('option');
        option2.value = typeName;
        option2.textContent = typeName;
        vendorSelect.appendChild(option2);
        
        const option3 = document.createElement('option');
        option3.value = typeName;
        // Icon + name so the searchable picker matches the rest of the app;
        // .value stays the plain type name every save path already reads.
        const icon3 = (currentDeviceTypes[typeName] || {}).icon || '';
        option3.textContent = icon3 ? `${icon3} ${typeName}` : typeName;
        devicePortSelect.appendChild(option3);
    }
}

// Initialize OUI input validation
document.addEventListener('DOMContentLoaded', function() {
    const ouiInput = document.getElementById('newOui');
    const apiBtn = document.getElementById('apiLookupBtn');
    
    if (ouiInput && apiBtn) {
        ouiInput.addEventListener('input', function() {
            const value = this.value.replace(/[^a-fA-F0-9]/g, '').toUpperCase();
            this.value = value;
            
            apiBtn.disabled = value.length !== 6;
        });
    }

    ['dockerSearch', 'dockerStackFilter', 'dockerNetworkFilter'].forEach(id => {
        const node = document.getElementById(id);
        // 'change' too: the enhanced <select> dropdowns fire change, not input.
        if (node) { node.addEventListener('input', renderDocker); node.addEventListener('change', renderDocker); }
    });
});

/**
 * Docker Management Functions
 */
async function loadDockerInfo() {
    try {
        await Promise.all([
            loadDockerStatus(),
            loadDockerNetworks(),
            loadDockerContainers(),
            loadDockerScanRanges()
        ]);
    } catch (error) {
        showAlert(t('docker_load_error') + error.message, 'error');
    }
}

async function loadDockerStatus() {
    const el = document.getElementById('dockerStatus');
    if (!el) return;
    try {
        const data = await (await fetch('/api/docker/stats')).json();
        if (!data.available) {
            el.innerHTML = `<div class="docker-status-strip__row">
                <span class="ds-badge ds-badge--critical">${t('docker_unavailable')}</span>
                <span class="docker-status-strip__hint">${dockerEsc(t('docker_unavailable_detail'))}</span></div>`;
            return;
        }
        const stat = (n, label) => `<span class="docker-status-strip__stat"><b>${n}</b> ${dockerEsc(label)}</span>`;
        el.innerHTML = `<div class="docker-status-strip__row">
            <span class="ds-badge ds-badge--success">${t('docker_active')}</span>
            ${stat(data.networks_count, t('docker_networks'))}
            ${stat(data.containers_count, t('active_containers'))}
            ${stat(data.scan_ranges_count, t('scan_ranges'))}
            <span class="ds-badge ${data.socket_available ? 'ds-badge--success' : 'ds-badge--warning'}">${t('socket_access')}: ${data.socket_available ? '✓' : '✗'}</span>
        </div>`;
    } catch (error) {
        el.innerHTML = `<div class="docker-status-strip__row"><span class="ds-badge ds-badge--critical">Docker</span>
            <span class="docker-status-strip__hint">${dockerEsc(error.message)}</span></div>`;
    }
}

/* Sub-tabs within the Docker tab, scoped to #docker so they never disturb the
   Databases sub-tabs (same .subtab classes, different section). */
function switchDockerTab(name) {
    const root = document.getElementById('docker');
    if (!root) return;
    root.querySelectorAll('.subtab').forEach(el => el.classList.remove('active'));
    const btn = root.querySelector(`[onclick="switchDockerTab('${name}')"]`);
    if (btn) btn.classList.add('active');
    root.querySelectorAll('.subtab-content').forEach(el => el.classList.remove('active'));
    const panel = document.getElementById(
        name === 'containers' ? 'dockerContainersPanel' :
        name === 'ranges' ? 'dockerRangesPanel' : 'dockerNetworksPanel');
    if (panel) panel.classList.add('active');
}

async function refreshDocker() {
    await loadDockerInfo();
    showAlert(t('docker_refreshed') || 'Docker refreshed');
}

/* One sortable table for all three Docker lists. columns: {key,label,get,cell}.
   Click a header to sort; a second click flips direction. Sort state per list. */
function dockerSort(list, col) {
    const st = dockerState.sort[list] || (dockerState.sort[list] = { col, dir: 1 });
    if (st.col === col) st.dir *= -1; else { st.col = col; st.dir = 1; }
    renderDocker();
}
function dockerTable(host, list, columns, rows, emptyMsg) {
    if (!host) return;
    if (!rows.length) { host.innerHTML = `<div class="pattern-empty">${dockerEsc(emptyMsg)}</div>`; return; }
    const st = dockerState.sort[list] || (dockerState.sort[list] = { col: columns[0].key, dir: 1 });
    const col = columns.find(c => c.key === st.col) || columns[0];
    const sorted = rows.slice().sort((a, b) => {
        const av = col.get(a), bv = col.get(b);
        if (typeof av === 'number' && typeof bv === 'number') return (av - bv) * st.dir;
        return String(av).localeCompare(String(bv), undefined, { numeric: true }) * st.dir;
    });
    const head = columns.map(c => {
        const arrow = c.key === st.col ? (st.dir > 0 ? ' ▲' : ' ▼') : '';
        return `<th class="ds-th-sort" onclick="dockerSort('${list}','${c.key}')">${dockerEsc(c.label)}${arrow}</th>`;
    }).join('');
    const body = sorted.map(r => `<tr>${columns.map(c => `<td>${c.cell(r)}</td>`).join('')}</tr>`).join('');
    host.innerHTML = `<div class="ds-table-wrap"><table class="ds-table"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
}

/*
 * Docker tab: one filter bar over both lists.
 *
 * Networks and containers were two unrelated walls of cards, each written with
 * hardcoded hex colours. They are now filtered together by text / stack /
 * network, because "which containers are in the telegram stack" was a question
 * you could only answer by scrolling.
 */
const dockerState = { networks: [], containers: [], scanRanges: [], sort: {} };

function dockerEsc(value) {
    return String(value ?? '').replace(/[&<>"']/g, c =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function dockerFilters() {
    const value = id => (document.getElementById(id) || {}).value || '';
    return {
        text: value('dockerSearch').trim().toLowerCase(),
        stack: value('dockerStackFilter'),
        network: value('dockerNetworkFilter'),
    };
}

function containerMatches(c, f) {
    if (f.stack && (c.stack || '') !== f.stack) return false;
    if (f.network && !(c.networks || []).includes(f.network)) return false;
    if (!f.text) return true;
    return [c.name, c.image, c.stack, c.service, c.id, (c.networks || []).join(' ')]
        .join(' ').toLowerCase().includes(f.text);
}

function networkMatches(n, f) {
    if (f.network && n.name !== f.network) return false;
    // A stack filter narrows networks to the ones its containers actually use.
    if (f.stack) {
        const used = dockerState.containers
            .filter(c => (c.stack || '') === f.stack)
            .some(c => (c.networks || []).includes(n.name));
        if (!used) return false;
    }
    if (!f.text) return true;
    return [n.name, n.driver, n.id, (n.subnets || []).join(' ')]
        .join(' ').toLowerCase().includes(f.text);
}

/** Rebuild the two selects from whatever the daemon currently reports. */
function refreshDockerFilterOptions() {
    const stacks = [...new Set(dockerState.containers.map(c => c.stack).filter(Boolean))].sort();
    const nets = [...new Set([
        ...dockerState.networks.map(n => n.name),
        ...dockerState.containers.flatMap(c => c.networks || []),
    ].filter(Boolean))].sort();

    const fill = (id, values, allLabel) => {
        const select = document.getElementById(id);
        if (!select) return;
        const previous = select.value;
        select.innerHTML = `<option value="">${allLabel}</option>` +
            values.map(v => `<option value="${dockerEsc(v)}">${dockerEsc(v)}</option>`).join('');
        if (values.includes(previous)) select.value = previous;
    };
    fill('dockerStackFilter', stacks, t('all_stacks'));
    fill('dockerNetworkFilter', nets, t('all_networks'));
}

function renderDockerNetworks() {
    const host = document.getElementById('dockerNetworksList');
    const shown = dockerState.networks.filter(n => networkMatches(n, dockerFilters()));
    dockerTable(host, 'networks', [
        { key: 'name', label: t('docker_network'), get: n => n.name || '',
          cell: n => `<span class="mono">${dockerEsc(n.name)}</span>${n.internal ? ` <span class="ds-badge ds-badge--critical">${t('internal')}</span>` : ''}` },
        { key: 'driver', label: t('driver') || 'Driver', get: n => n.driver || '',
          cell: n => `<span class="network-type">${dockerEsc(n.driver)}</span>` },
        { key: 'subnet', label: t('subnet'), get: n => (n.subnets || [])[0] || '',
          cell: n => `<span class="mono">${dockerEsc((n.subnets || []).join(', ') || '—')}</span>` },
        { key: 'gateway', label: 'Gateway', get: n => n.gateway || '',
          cell: n => `<span class="mono">${dockerEsc(n.gateway || '—')}</span>` },
        { key: 'count', label: t('docker_containers'), get: n => (n.containers || []).length,
          cell: n => (n.containers || []).length },
    ], shown, t('no_docker_networks'));
}

function renderDockerContainers() {
    const host = document.getElementById('dockerContainersList');
    const shown = dockerState.containers.filter(c => containerMatches(c, dockerFilters()));
    dockerTable(host, 'containers', [
        { key: 'name', label: t('name') || 'Name', get: c => c.name || '',
          cell: c => `<span class="mono">${dockerEsc(c.name)}</span>` },
        { key: 'stack', label: t('docker_stack'), get: c => c.stack || '',
          cell: c => dockerEsc(c.stack || t('no_stack')) },
        { key: 'image', label: t('docker_image'), get: c => c.image || '',
          cell: c => dockerEsc(c.image || '—') },
        { key: 'networks', label: t('docker_network'), get: c => (c.networks || [])[0] || '',
          cell: c => `<span class="mono">${dockerEsc((c.networks || []).join(', ') || '—')}</span>` },
        { key: 'ip', label: 'IP', get: c => (c.ip_addresses || []).map(a => a.ipv4).filter(Boolean)[0] || '',
          cell: c => `<span class="mono">${dockerEsc((c.ip_addresses || []).map(a => a.ipv4).filter(Boolean).join(', ') || '—')}</span>` },
        { key: 'status', label: t('status'), get: c => c.status || '',
          cell: c => `<span class="ds-badge ds-badge--success">${dockerEsc(c.status || t('running'))}</span>` },
    ], shown, t('no_docker_containers'));
}

function renderDockerScanRanges() {
    const host = document.getElementById('dockerScanRangesList');
    // Reuse the same text/network/stack filter as the other two lists.
    const f = dockerFilters();
    const shown = dockerState.scanRanges.filter(r => {
        if (f.network && r.network_name !== f.network) return false;
        if (!f.text) return true;
        return [r.network_name, r.subnet, r.scan_range, r.gateway].join(' ').toLowerCase().includes(f.text);
    });
    dockerTable(host, 'ranges', [
        { key: 'network_name', label: t('docker_network'), get: r => r.network_name || '',
          cell: r => `<span class="mono">${dockerEsc(r.network_name)}</span>` },
        { key: 'driver', label: t('driver') || 'Driver', get: r => r.driver || '',
          cell: r => `<span class="network-type">${dockerEsc(r.driver)}</span>` },
        { key: 'subnet', label: t('subnet'), get: r => r.subnet || '',
          cell: r => `<span class="mono">${dockerEsc(r.subnet || '—')}</span>` },
        { key: 'scan_range', label: t('scan_ranges'), get: r => r.scan_range || '',
          cell: r => `<code>${dockerEsc(r.scan_range || '—')}</code>` },
        { key: 'container_count', label: t('docker_containers'), get: r => r.container_count || 0,
          cell: r => r.container_count || 0 },
        { key: 'action', label: '', get: () => '',
          cell: r => `<button class="btn btn-small" onclick="addToScanRange('${dockerEsc(r.scan_range)}','${dockerEsc(r.network_name)}')"><svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-plus"/></svg> ${t('add_to_scan_range')}</button>` },
    ], shown, t('no_docker_ranges'));
}

function renderDocker() {
    renderDockerNetworks();
    renderDockerContainers();
    renderDockerScanRanges();
}

async function loadDockerNetworks() {
    const host = document.getElementById('dockerNetworksList');
    try {
        const data = await (await fetch('/api/docker/networks')).json();
        dockerState.networks = (data.success && data.networks) || [];
        refreshDockerFilterOptions();
        renderDockerNetworks();
    } catch (error) {
        if (host) host.innerHTML = `<div class="pattern-empty">Docker networks: ${dockerEsc(error.message)}</div>`;
    }
}

async function loadDockerContainers() {
    const host = document.getElementById('dockerContainersList');
    try {
        const data = await (await fetch('/api/docker/containers')).json();
        dockerState.containers = (data.success && data.containers) || [];
        refreshDockerFilterOptions();
        renderDockerContainers();
    } catch (error) {
        if (host) host.innerHTML = `<div class="pattern-empty">Docker containers: ${dockerEsc(error.message)}</div>`;
    }
}

async function loadDockerScanRanges() {
    const host = document.getElementById('dockerScanRangesList');
    try {
        const data = await (await fetch('/api/docker/scan_ranges')).json();
        dockerState.scanRanges = (data.success && data.scan_ranges) || [];
        renderDockerScanRanges();
    } catch (error) {
        if (host) host.innerHTML = `<div class="pattern-empty">Docker scan ranges: ${dockerEsc(error.message)}</div>`;
    }
}

// Refresh functions
async function refreshDockerNetworks() {
    const networksContainer = document.getElementById('dockerNetworksList');
    if (networksContainer) {
        networksContainer.innerHTML = '<div class="loading">Network bilgileri yenileniyor...</div>';
    }
    await loadDockerNetworks();
    showAlert('Docker networks yenilendi!');
}

async function refreshDockerContainers() {
    const containersContainer = document.getElementById('dockerContainersList');
    if (containersContainer) {
        containersContainer.innerHTML = '<div class="loading">Container bilgileri yenileniyor...</div>';
    }
    await loadDockerContainers();
    showAlert('Docker containers yenilendi!');
}

async function refreshDockerScanRanges() {
    const scanRangesContainer = document.getElementById('dockerScanRangesList');
    if (scanRangesContainer) {
        scanRangesContainer.innerHTML = `<div class="loading">${t('scan_ranges_loading')}</div>`;
    }
    await loadDockerScanRanges();
    showAlert(t('docker_ranges_refreshed'));
}

function addToScanRange(subnet, networkName) {
    // Genel ayarlar sekmesine geç ve IP aralığına ekle
    switchTab('general');
    
    setTimeout(() => {
        const sel = document.getElementById('defaultIpRange');
        if (sel) {
            // Scanning takes one CIDR, so pick this subnet rather than appending.
            if (![...sel.options].some(o => o.value === subnet)) {
                sel.add(new Option(subnet, subnet));
            }
            sel.value = subnet;
            showAlert(t('docker_range_added', { network: networkName, subnet: subnet }));
        }
    }, 100);
}
/* ---------------- Access control (login gate) ----------------------------
   Kept at the end of config.js so it does not disturb the existing settings
   code. Credentials themselves live in .env and are never sent from here. */
(function () {
  'use strict';

  function esc(v) { var d = document.createElement('div'); d.textContent = v == null ? '' : String(v); return d.innerHTML; }

  function render(s) {
    var box = document.getElementById('loginRequired');
    var badge = document.getElementById('authBadge');
    var hint = document.getElementById('authHint');
    if (!box) return;

    box.checked = !!s.login_required;
    // Cannot enable a gate with no key: that locks everyone out of a LAN app.
    box.disabled = !s.credentials_configured && !s.login_required;

    badge.textContent = s.active ? t('auth_sign_in_required') : t('auth_open_to_network');
    badge.className = 'ds-badge ' + (s.active ? 'ds-badge--success' : 'ds-badge--warning');

    if (!s.credentials_configured) {
      // A container has no .env the user can edit, so telling them to go add
      // one made this switch permanently dead exactly where it matters most.
      // Set the credentials here; the server stores a PBKDF2 hash.
      hint.innerHTML =
        '<div class="ds-alert ds-alert--warning">' +
          '<svg class="ds-alert__icon ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-alert"/></svg>' +
          '<div style="flex:1">' + t('auth_no_credentials') +
            '<div class="ds-row" style="margin-top:var(--space-3)">' +
              '<input class="ds-input" id="authUser" autocomplete="username" ' +
                'placeholder="' + t('auth_username_placeholder') + '">' +
              '<input class="ds-input" id="authPass" type="password" autocomplete="new-password" ' +
                'placeholder="' + t('auth_password_placeholder') + '">' +
              '<button class="ds-btn ds-btn--primary" id="authSave" type="button">' +
                t('auth_save_credentials') + '</button>' +
            '</div>' +
            '<div class="ds-dim" style="margin-top:var(--space-2)">' + t('auth_env_alternative') +
              ' <code>MYNES_AUTH_USERNAME</code> / <code>MYNES_AUTH_PASSWORD</code></div>' +
          '</div></div>';
      var save = document.getElementById('authSave');
      if (save) save.addEventListener('click', saveCredentials);
    } else {
      hint.innerHTML =
        '<div class="ds-dim">' + t('auth_signed_in_as', { user: esc(s.username) }) +
        (s.active ? ' <a href="/logout">' + t('auth_sign_out') + '</a>.' : '') + '</div>';
    }
  }

  function load() {
    return fetch('/api/auth/status').then(function (r) { return r.json(); }).then(render);
  }

  function saveCredentials() {
    var user = (document.getElementById('authUser') || {}).value || '';
    var pass = (document.getElementById('authPass') || {}).value || '';
    return fetch('/api/auth/credentials', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: user, password: pass })
    })
      .then(function (r) { return r.json(); })
      .then(function (r) {
        if (!r.ok) {
          if (window.MyNeS) window.MyNeS.toast(r.error, 'critical');
          else window.alert(r.error);
          return;
        }
        if (window.MyNeS) window.MyNeS.toast(t('auth_credentials_saved'), 'success');
        return load();
      });
  }

  function init() {
    var box = document.getElementById('loginRequired');
    if (!box) return;

    box.addEventListener('change', function () {
      fetch('/api/auth/status', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ login_required: box.checked })
      })
        .then(function (r) { return r.json(); })
        .then(function (r) {
          if (!r.ok) {
            box.checked = !box.checked;
            if (window.MyNeS) window.MyNeS.toast(r.error, 'critical');
            else window.alert(r.error);
            return;
          }
          if (window.MyNeS) {
            window.MyNeS.toast(r.login_required ? t('auth_enabled_toast') : t('auth_disabled_toast'),
              r.login_required ? 'success' : 'warning');
          }
          return load();
        });
    });

    load();
    // Same race as the rest of this page: translations.js fetches its table
    // after we have already painted, so re-render once it lands.
    window.addEventListener('translationsLoaded', load);
  }

  // Guard on readyState: if this file is served from cache after the document
  // has already parsed, a bare DOMContentLoaded listener never fires.
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();

/* ---------------- Settings > Logs tab --------------------------------------
   Live application log viewer: search + highlight, level filter, runtime level
   control, and export. Backed by /api/logs (in-memory ring + rotating file). */
function logEsc(v) {
    const d = document.createElement('div');
    d.textContent = v == null ? '' : String(v);
    return d.innerHTML;
}

function highlightLog(text, needle) {
    const safe = logEsc(text);
    if (!needle) return safe;
    try {
        const rx = new RegExp('(' + needle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'ig');
        return safe.replace(rx, '<mark>$1</mark>');
    } catch (_) { return safe; }
}

async function loadLogs() {
    const viewer = document.getElementById('logViewer');
    if (!viewer) return;
    const q = (document.getElementById('logSearch') || {}).value || '';
    const level = (document.getElementById('logLevelFilter') || {}).value || '';
    const date = (document.getElementById('logDate') || {}).value || '';
    try {
        const params = new URLSearchParams({ limit: '2000' });
        if (q) params.set('q', q);
        if (level) params.set('level', level);
        if (date) params.set('date', date);
        const data = await (await fetch('/api/logs?' + params.toString())).json();

        // Keep the runtime-level dropdown in sync with the server.
        const runtime = document.getElementById('logRuntimeLevel');
        if (runtime && data.level) runtime.value = data.level;
        populateLogDates(data.dates, date);

        const rows = (data.logs || []).map(r => {
            const lvl = (r.level || 'INFO').toLowerCase();
            const loc = r.location ? `<span class="log-loc">${logEsc(r.location)}</span>` : '';
            const code = r.code ? `<span class="log-code">${logEsc(r.code)}</span>` : '';
            return `<div class="log-line log-line--${lvl}">` +
                `<span class="log-time">${logEsc(r.time)}</span>` +
                `<span class="log-level log-level--${lvl}">${logEsc(r.level)}</span>` +
                `<span class="log-logger">${logEsc(r.logger)}</span>` + loc + code +
                `<span class="log-msg">${highlightLog(r.message, q)}</span></div>`;
        });
        viewer.innerHTML = rows.length ? rows.join('') :
            `<div class="details-no-data">${t('no_results') || '—'}</div>`;
        viewer.scrollTop = viewer.scrollHeight;
    } catch (e) {
        viewer.innerHTML = `<div class="details-no-data">${t('error')}: ${logEsc(e.message)}</div>`;
    }
}

async function setLogLevel(level) {
    try {
        await fetch('/api/logs/level', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ level })
        });
        showAlert(t('general_settings_saved') || 'OK');
        loadLogs();
    } catch (e) {
        showAlert(t('error') + ': ' + e.message, 'error');
    }
}

function downloadLogs() {
    const date = (document.getElementById('logDate') || {}).value || '';
    window.location.href = '/api/logs/download' + (date ? '?date=' + encodeURIComponent(date) : '');
}

// Fill the day picker from the server's list of available dates, keeping the
// current selection. "" = live/today (always the first option, from the DOM).
function populateLogDates(dates, selected) {
    const sel = document.getElementById('logDate');
    if (!sel || !Array.isArray(dates)) return;
    const want = (selected || '') + '|' + dates.join(',');
    if (sel.dataset.filled === want) return;  // no churn on every refresh
    sel.dataset.filled = want;
    const live = sel.options[0];  // the {{ _('log_live') }} option
    sel.innerHTML = '';
    sel.appendChild(live);
    dates.forEach(d => {
        const o = document.createElement('option');
        o.value = d; o.textContent = d;
        sel.appendChild(o);
    });
    sel.value = selected || '';
}

// Live search + filter without a button press.
document.addEventListener('DOMContentLoaded', function () {
    const s = document.getElementById('logSearch');
    const f = document.getElementById('logLevelFilter');
    const d = document.getElementById('logDate');
    let timer = null;
    if (s) s.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(loadLogs, 250); });
    if (f) f.addEventListener('change', loadLogs);
    if (d) d.addEventListener('change', loadLogs);
});
