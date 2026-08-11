/*
 * table-view.js — the device Table view. Owns everything inside #tableContainer:
 * a configurable, reorderable, resizable, freezable table + bulk actions.
 *
 * Reuses globals from main.js: `devices` (the already-filtered array at render
 * time), `deviceTypes`, and the helpers getDeviceIcon / getTranslatedDeviceType
 * / formatRelativeTime / formatDate / escHtml / t / showToast / openDevice /
 * openPort / openEnhancedEditModal / openSingleDeviceAnalysisPage /
 * openEnhancedDetailsModal / copyMacAddress / hasEnhancedInfo / loadDevices.
 *
 * ponytail: one file, one localStorage key, no framework. State is a plain
 * object persisted as JSON; the whole table re-renders on every change. Fine for
 * a home LAN's device count (tens, not thousands).
 */
(function () {
  const LS = 'mynes.table.v1';
  const MAX_PORTS = 4;

  // t() returns the key itself when a string is missing; fall back to English.
  const L = (key, fallback, params) => { const s = t(key, params || {}); return s === key ? fallback : s; };

  // Stable per-device identity: MAC survives a DHCP lease change, IP does not.
  const keyOf = (d) => (d.mac && d.mac !== 'N/A') ? d.mac : (d.ip || d.hostname || '');

  // ---- Column registry -----------------------------------------------------
  // pinned columns (select, ip, actions) are always present and never reordered
  // or hidden. Everything else lives in the movable middle.
  function baseColumns() {
    return [
      { key: 'alias',       label: () => L('alias', 'Alias'),           val: d => d.alias || '', cell: d => escHtml(d.alias || '-') },
      { key: 'vendor',      label: () => L('vendor', 'Vendor'),         val: d => d.vendor || '', cell: d => escHtml(d.vendor || L('unknown', 'Unknown')) },
      { key: 'device_type', label: () => L('device_type', 'Device Type'), val: d => d.device_type || '',
        cell: d => `<span class="device-type-badge">${getDeviceIcon(d.device_type)} ${escHtml(getTranslatedDeviceType(d.device_type))}</span>` },
      { key: 'mac',         label: () => L('mac_address', 'MAC Address'), val: d => d.mac || '', cell: macCell },
      { key: 'hostname',    label: () => L('hostname', 'Hostname'),     val: d => d.hostname || '', cell: d => escHtml(d.hostname || '-') },
      { key: 'open_ports',  label: () => L('open_ports', 'Open Ports'), val: d => (d.open_ports || []).length, cell: portsCell },
      { key: 'last_seen',   label: () => L('last_seen', 'Last Seen'),   val: d => new Date(d.last_seen || 0).getTime(),
        cell: d => `<span title="${escHtml(formatDate(d.last_seen))}">${escHtml(formatRelativeTime(d.last_seen))}</span>` },
      { key: 'trust_status', label: () => L('trust', 'Trust'),          val: d => d.trust_status || '', cell: d => escHtml(d.trust_status || '-') },
      { key: 'location',    label: () => L('location', 'Location'),     val: d => d.location || '', cell: d => escHtml(d.location || '-') },
      { key: 'notes',       label: () => L('notes', 'Notes'),           val: d => d.notes || '', cell: d => escHtml(d.notes || '-') },
      { key: 'status',      label: () => L('status', 'Status'),         val: d => d.status || '', cell: d => escHtml(d.status || '-') },
    ];
  }

  function macCell(d) {
    if (!d.mac || d.mac === 'N/A') return '<span class="mac-address">N/A</span>';
    return `<div class="mac-container"><span class="mac-address" title="${escHtml(d.mac)}">${escHtml(d.mac)}</span>` +
      `<button class="copy-mac-btn" onclick="copyMacAddress('${escHtml(d.mac)}', this); event.stopPropagation();" title="${L('copy_mac_address', 'Copy MAC')}" aria-label="${L('copy_mac_address', 'Copy MAC')}"><svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-copy"/></svg></button></div>`;
  }

  function portsCell(d) {
    const ports = d.open_ports || [];
    if (!ports.length) return '<span class="mnt-muted">-</span>';
    const shown = ports.slice(0, MAX_PORTS).map(p => {
      const num = typeof p === 'object' ? p.port : p;
      const desc = typeof p === 'object' ? (p.description || p.service || '') : '';
      return `<span class="port-badge" onclick="openPort('${escHtml(d.ip)}', ${num}, '${escHtml(desc)}'); event.stopPropagation();" title="${escHtml(desc || ('Port ' + num))}">${num}</span>`;
    }).join(' ');
    const more = ports.length > MAX_PORTS
      ? ` <span class="port-badge port-badge--more" title="${escHtml(ports.map(p => typeof p === 'object' ? p.port : p).join(', '))}">…</span>` : '';
    return `<div class="ports-cell">${shown}${more}</div>`;
  }

  // Dotted-path getter for custom (raw-JSON) columns.
  function getPath(obj, path) {
    let v = obj;
    for (const part of path.split('.')) {
      if (v == null) return undefined;
      v = v[part];
    }
    return v;
  }
  function customCell(d, path) {
    const v = getPath(d, path);
    if (v == null) return '<span class="mnt-muted">-</span>';
    const s = (typeof v === 'object') ? JSON.stringify(v) : String(v);
    return `<span title="${escHtml(s)}">${escHtml(s)}</span>`;
  }

  // ---- State ---------------------------------------------------------------
  const DEFAULT_VISIBLE = ['alias', 'vendor', 'device_type', 'mac', 'open_ports', 'last_seen'];

  function loadState() {
    let s = {};
    try { s = JSON.parse(localStorage.getItem(LS)) || {}; } catch (_) {}
    s.order = Array.isArray(s.order) ? s.order : baseColumns().map(c => c.key);
    s.hidden = Array.isArray(s.hidden) ? s.hidden : baseColumns().map(c => c.key).filter(k => !DEFAULT_VISIBLE.includes(k));
    s.widths = s.widths || {};
    s.custom = Array.isArray(s.custom) ? s.custom : []; // [{path,label}]
    s.sort = s.sort || { col: 'ip', dir: 'asc' };
    return s;
  }
  let state = loadState();
  const save = () => localStorage.setItem(LS, JSON.stringify(state));

  const selected = new Set();       // device keys
  let pickerOpen = false;

  // Full registry incl. custom columns, in the user's saved order.
  function registry() {
    const base = baseColumns();
    for (const c of state.custom) {
      base.push({ key: 'custom:' + c.path, label: () => c.label || c.path,
        val: d => { const v = getPath(d, c.path); return v == null ? '' : (typeof v === 'object' ? JSON.stringify(v) : v); },
        cell: d => customCell(d, c.path), custom: true, path: c.path });
    }
    const byKey = Object.fromEntries(base.map(c => [c.key, c]));
    // saved order first (skipping gone columns), then any new columns appended.
    const ordered = state.order.map(k => byKey[k]).filter(Boolean);
    for (const c of base) if (!ordered.includes(c)) ordered.push(c);
    state.order = ordered.map(c => c.key);
    return ordered;
  }
  const visibleCols = () => registry().filter(c => !state.hidden.includes(c.key));

  // ---- Sorting -------------------------------------------------------------
  function ipCompare(a, b) {
    if (!a.ip || !b.ip) { if (a.ip === b.ip) return 0; return a.ip ? -1 : 1; }
    const pa = a.ip.split('.').map(Number), pb = b.ip.split('.').map(Number);
    for (let i = 0; i < 4; i++) if (pa[i] !== pb[i]) return pa[i] - pb[i];
    return 0;
  }
  function sortDevs(list) {
    const { col, dir } = state.sort;
    const mul = dir === 'asc' ? 1 : -1;
    const cols = registry();
    const def = col === 'ip' ? null : cols.find(c => c.key === col);
    return [...list].sort((a, b) => {
      let r;
      if (col === 'ip' || !def) r = ipCompare(a, b);
      else {
        const av = def.val(a), bv = def.val(b);
        r = (typeof av === 'number' && typeof bv === 'number') ? av - bv : String(av).localeCompare(String(bv));
      }
      return r * mul;
    });
  }

  // ---- Render --------------------------------------------------------------
  function render() {
    const host = document.getElementById('tableContainer');
    if (!host) return;
    const cols = visibleCols();
    const list = sortDevs(devices || []);

    // prune selection to devices still present
    const present = new Set(list.map(keyOf));
    for (const k of [...selected]) if (!present.has(k)) selected.delete(k);

    // Explicit table width = sum of column widths, so table-layout:fixed honours
    // each colgroup width (and the table can exceed the wrap → horizontal scroll).
    const total = 44 + (state.widths.ip || 190) + 60 +
      cols.reduce((s, c) => s + (state.widths[c.key] || 150), 0);
    host.innerHTML = toolbar(list.length) + pickerPanel(cols) +
      `<div class="mnt-wrap"><table class="mnt" style="width:${total}px">${colgroup(cols)}${thead(cols)}${tbody(list, cols)}</table></div>`;

    wire(host, list);
  }

  function colgroup(cols) {
    let out = `<colgroup><col style="width:44px">`;              // select
    out += `<col style="width:${state.widths.ip || 190}px">`;    // ip (frozen)
    for (const c of cols) out += `<col style="width:${state.widths[c.key] || 150}px">`;
    out += `<col style="width:60px"></colgroup>`;                // actions
    return out;
  }

  function sortArrow(key) {
    if (state.sort.col !== key) return '';
    return state.sort.dir === 'asc' ? ' ↑' : ' ↓';
  }

  function thead(cols) {
    const allChecked = devices && devices.length && devices.every(d => selected.has(keyOf(d)));
    let h = `<thead><tr>`;
    h += `<th class="mnt-freeze mnt-col-select"><input type="checkbox" class="mnt-all" ${allChecked ? 'checked' : ''} aria-label="select all"></th>`;
    h += `<th class="mnt-freeze mnt-col-ip mnt-sort" data-sort="ip">🌐 ${L('ip_address', 'IP Address')}${sortArrow('ip')}<span class="mnt-resize" data-col="ip"></span></th>`;
    for (const c of cols) {
      h += `<th class="mnt-sort" draggable="true" data-key="${escHtml(c.key)}" data-sort="${escHtml(c.key)}">${escHtml(c.label())}${sortArrow(c.key)}<span class="mnt-resize" data-col="${escHtml(c.key)}"></span></th>`;
    }
    h += `<th class="mnt-col-actions"><button class="mnt-cols-btn" title="${L('columns', 'Columns')}" aria-label="${L('columns', 'Columns')}"><svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-settings"/></svg></button></th>`;
    h += `</tr></thead>`;
    return h;
  }

  function tbody(list, cols) {
    if (!list.length) {
      const span = cols.length + 3;
      return `<tbody><tr><td colspan="${span}" class="mnt-empty">📡 ${L('no_devices_message', 'No devices found yet')}</td></tr></tbody>`;
    }
    let b = '<tbody>';
    for (const d of list) {
      const k = keyOf(d);
      const sel = selected.has(k);
      b += `<tr class="mnt-row${sel ? ' mnt-row--sel' : ''}" data-key="${escHtml(k)}">`;
      b += `<td class="mnt-freeze mnt-col-select"><input type="checkbox" class="mnt-pick" ${sel ? 'checked' : ''} aria-label="select"></td>`;
      const ipInner = d.ip
        ? `<span class="device-status ${d.status === 'online' ? 'online' : 'offline'}">${d.status === 'online' ? '🟢' : '🔴'}</span> <a class="mnt-ip" onclick="openDevice('${escHtml(d.ip)}'); event.stopPropagation();">${escHtml(d.ip)}</a>`
        : `<span class="device-ip--none" title="${L('discovery_only', 'Discovery only')}">${escHtml(d.hostname || d.mac || '—')}</span>`;
      b += `<td class="mnt-freeze mnt-col-ip">${ipInner}</td>`;
      for (const c of cols) b += `<td>${c.cell(d)}</td>`;
      b += `<td class="mnt-col-actions">${kebab(d, k)}</td>`;
      b += `</tr>`;
    }
    return b + '</tbody>';
  }

  function kebab(d, k) {
    const items = [];
    if (d.ip || d.mac) items.push(`<button onclick="openEnhancedEditModal('${escHtml(d.ip || d.mac)}')"><svg class="ds-icon ds-icon--sm"><use href="#i-wrench"/></svg> ${L('edit', 'Edit')}</button>`);
    if (d.ip) items.push(`<button onclick="openSingleDeviceAnalysisPage('${escHtml(d.ip)}')"><svg class="ds-icon ds-icon--sm"><use href="#i-microscope"/></svg> ${L('detailed_analysis', 'Detailed Analysis')}</button>`);
    if (hasEnhancedInfo(d)) items.push(`<button onclick='openEnhancedDetailsModal(${JSON.stringify(d).replace(/'/g, '&#39;').replace(/"/g, '&quot;')})'><svg class="ds-icon ds-icon--sm"><use href="#i-graph"/></svg> ${L('details', 'Details')}</button>`);
    return `<div class="mnt-menu"><button class="mnt-menu-btn" aria-label="actions">⋮</button><div class="mnt-menu-list" hidden>${items.join('')}</div></div>`;
  }

  // ---- Toolbar (bulk actions + column button) ------------------------------
  // Distinct existing locations across all devices, plus the app's predefined
  // room list (read live from the edit modal's <datalist>).
  function locationOptions() {
    const set = new Set();
    document.querySelectorAll('#locationOptions option').forEach(o => o.value && set.add(o.value));
    (devices || []).forEach(d => d.location && set.add(d.location));
    return [...set].sort((a, b) => a.localeCompare(b));
  }

  function toolbar(count) {
    if (!selected.size) return '';
    // Each control is a native <select> (searchable-enhanced in wire()), with a
    // placeholder first option that doubles as the button label.
    const sel = (cls, placeholder, opts) =>
      `<select class="${cls} mnt-bulk-select"><option value="">${placeholder}…</option>${opts}</select>`;

    const typeOpts = Object.keys(deviceTypes || {})
      .map(k => `<option value="${escHtml(k)}">${getDeviceIcon(k)} ${escHtml(getTranslatedDeviceType(k))}</option>`).join('');
    const locOpts = locationOptions()
      .map(l => `<option value="${escHtml(l)}">${escHtml(l)}</option>`).join('');
    const trustOpts = ['trusted', 'known', 'unknown']
      .map(v => `<option value="${v}">${escHtml(L('trust_' + v, v))}</option>`).join('');
    const uplinkOpts = `<option value="__auto__">${L('auto_detected', 'Auto (detected)')}</option>` +
      (devices || []).filter(d => d.ip).map(d => {
        const name = d.alias || d.hostname;
        return `<option value="${escHtml(d.ip)}">${name ? escHtml(name) + ' — ' : ''}${escHtml(d.ip)}</option>`;
      }).join('');

    return `<div class="mnt-bulk">
      <span class="mnt-bulk-count">${L('selected_count', selected.size + ' selected', { count: selected.size })}</span>
      <button class="btn btn-danger btn-small mnt-bulk-del">🗑 ${L('delete', 'Delete')}</button>
      ${sel('mnt-bulk-type', L('change_type', 'Change type'), typeOpts)}
      ${sel('mnt-bulk-loc', L('change_location', 'Change location'), locOpts)}
      ${sel('mnt-bulk-trust', L('change_trust', 'Change trust'), trustOpts)}
      ${sel('mnt-bulk-uplink', L('connected_via', 'Connected via'), uplinkOpts)}
      <button class="btn btn-secondary btn-small mnt-bulk-clear">${L('clear_selection', 'Clear')}</button>
    </div>`;
  }

  function pickerPanel(_cols) {
    if (!pickerOpen) return '';
    const rows = registry().map(c =>
      `<label class="mnt-pick-row"><input type="checkbox" class="mnt-vis" data-key="${escHtml(c.key)}" ${state.hidden.includes(c.key) ? '' : 'checked'}> ${escHtml(c.label())}` +
      (c.custom ? ` <button class="mnt-rm-custom" data-path="${escHtml(c.path)}" title="remove">✕</button>` : '') + `</label>`).join('');
    return `<div class="mnt-picker">
      <div class="mnt-picker-head">
        <span class="mnt-picker-title">${L('columns', 'Columns')}</span>
        <button class="mnt-picker-close" aria-label="${L('close', 'Close')}" title="${L('close', 'Close')}">✕</button>
      </div>
      <div class="mnt-picker-list">${rows}</div>
      <div class="mnt-picker-add">
        <input type="text" class="form-input mnt-custom-path" placeholder="${L('json_field_path', 'JSON field (e.g. discovery.mdns.name)')}">
        <button class="btn btn-secondary btn-small mnt-add-custom">＋ ${L('add_column', 'Add column')}</button>
      </div>
      <div class="mnt-picker-foot">
        <button class="btn btn-secondary btn-small mnt-reset">${L('reset_layout', 'Reset layout')}</button>
        <button class="btn btn-primary btn-small mnt-picker-done">${L('done', 'Done')}</button>
      </div>
    </div>`;
  }

  // ---- Event wiring --------------------------------------------------------
  function wire(host, list) {
    const byKey = Object.fromEntries(list.map(d => [keyOf(d), d]));

    // sort
    host.querySelectorAll('.mnt-sort').forEach(th => th.addEventListener('click', e => {
      if (e.target.closest('.mnt-resize')) return;
      const col = th.getAttribute('data-sort');
      if (state.sort.col === col) state.sort.dir = state.sort.dir === 'asc' ? 'desc' : 'asc';
      else state.sort = { col, dir: 'asc' };
      save(); render();
    }));

    // select all / row pick
    const all = host.querySelector('.mnt-all');
    if (all) all.addEventListener('change', () => {
      if (all.checked) list.forEach(d => selected.add(keyOf(d)));
      else selected.clear();
      render();
    });
    host.querySelectorAll('.mnt-pick').forEach(cb => cb.addEventListener('change', e => {
      const k = e.target.closest('tr').getAttribute('data-key');
      e.target.checked ? selected.add(k) : selected.delete(k);
      render();
    }));

    // kebab menus
    host.querySelectorAll('.mnt-menu-btn').forEach(btn => btn.addEventListener('click', e => {
      e.stopPropagation();
      const listEl = btn.nextElementSibling;
      const open = listEl.hidden;
      closeMenus();
      if (open) {
        listEl.hidden = false;
        // fixed positioning: anchor to the button, flip left so it stays on-screen
        const r = btn.getBoundingClientRect();
        listEl.style.top = r.bottom + 'px';
        listEl.style.left = Math.max(8, r.right - listEl.offsetWidth) + 'px';
      }
    }));

    // column picker toggle
    const colsBtn = host.querySelector('.mnt-cols-btn');
    if (colsBtn) colsBtn.addEventListener('click', () => { pickerOpen = !pickerOpen; render(); });
    host.querySelectorAll('.mnt-vis').forEach(cb => cb.addEventListener('change', e => {
      const k = e.target.getAttribute('data-key');
      if (e.target.checked) state.hidden = state.hidden.filter(x => x !== k);
      else if (!state.hidden.includes(k)) state.hidden.push(k);
      save(); render();
    }));
    const addBtn = host.querySelector('.mnt-add-custom');
    if (addBtn) addBtn.addEventListener('click', () => {
      const path = (host.querySelector('.mnt-custom-path').value || '').trim();
      if (!path) return;
      if (!state.custom.some(c => c.path === path)) state.custom.push({ path, label: path });
      state.hidden = state.hidden.filter(x => x !== 'custom:' + path);
      save(); render();
    });
    host.querySelectorAll('.mnt-rm-custom').forEach(b => b.addEventListener('click', () => {
      const p = b.getAttribute('data-path');
      state.custom = state.custom.filter(c => c.path !== p);
      save(); render();
    }));
    const reset = host.querySelector('.mnt-reset');
    if (reset) reset.addEventListener('click', () => { localStorage.removeItem(LS); state = loadState(); render(); });
    host.querySelectorAll('.mnt-picker-close, .mnt-picker-done').forEach(b =>
      b.addEventListener('click', () => { pickerOpen = false; render(); }));

    // column resize
    host.querySelectorAll('.mnt-resize').forEach(h => h.addEventListener('mousedown', e => startResize(e, h.getAttribute('data-col'))));

    // column reorder (drag th)
    let dragKey = null;
    host.querySelectorAll('th[draggable="true"]').forEach(th => {
      th.addEventListener('dragstart', () => { dragKey = th.getAttribute('data-key'); });
      th.addEventListener('dragover', e => e.preventDefault());
      th.addEventListener('drop', e => {
        e.preventDefault();
        const target = th.getAttribute('data-key');
        if (!dragKey || dragKey === target) return;
        const order = registry().map(c => c.key);
        order.splice(order.indexOf(dragKey), 1);
        order.splice(order.indexOf(target), 0, dragKey);
        state.order = order; save(); render();
      });
    });

    // bulk actions
    const del = host.querySelector('.mnt-bulk-del');
    if (del) del.addEventListener('click', bulkDelete);
    const clr = host.querySelector('.mnt-bulk-clear');
    if (clr) clr.addEventListener('click', () => { selected.clear(); render(); });

    // Each bulk <select> becomes the app's searchable dropdown; on pick, apply
    // then reset to the placeholder so a second bulk op can follow.
    const bind = (cls, fn) => {
      const s = host.querySelector('.' + cls);
      if (!s) return;
      if (window.MynesFilters) { try { MynesFilters.enhanceSelect(s); } catch (_) {} }
      s.addEventListener('change', () => {
        const v = s.value;
        if (!v) return;
        fn(v, byKey);
        s.value = ''; if (s._ds) s._ds.refresh();
      });
    };
    bind('mnt-bulk-type', bulkType);
    bind('mnt-bulk-loc', bulkLocation);
    bind('mnt-bulk-trust', bulkTrust);
    bind('mnt-bulk-uplink', bulkUplink);
  }

  function closeMenus() {
    document.querySelectorAll('.mnt-menu-list').forEach(l => l.hidden = true);
  }
  document.addEventListener('click', closeMenus);

  function startResize(e, col) {
    e.preventDefault(); e.stopPropagation();
    const startX = e.clientX;
    const startW = state.widths[col] || (col === 'ip' ? 190 : 150);
    const onMove = ev => { state.widths[col] = Math.max(60, startW + ev.clientX - startX); applyWidth(col); };
    const onUp = () => { document.removeEventListener('mousemove', onMove); document.removeEventListener('mouseup', onUp); save(); };
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  }
  // Live-update the <col> and table width during a drag without a full re-render.
  function applyWidth(col) {
    const cols = visibleCols();
    const idx = col === 'ip' ? 1 : 2 + cols.findIndex(c => c.key === col);
    const colEl = document.querySelectorAll('.mnt colgroup col')[idx];
    if (colEl) colEl.style.width = state.widths[col] + 'px';
    const total = 44 + (state.widths.ip || 190) + 60 +
      cols.reduce((s, c) => s + (state.widths[c.key] || 150), 0);
    const tbl = document.querySelector('.mnt');
    if (tbl) tbl.style.width = total + 'px';
  }

  // ---- Bulk operations -----------------------------------------------------
  async function bulkDelete() {
    const keys = [...selected];
    if (!confirm(L('bulk_delete_confirm', 'Delete ' + keys.length + ' selected devices?', { count: keys.length }))) return;
    const targets = keys.map(k => devByKey(k)).filter(d => d && d.ip);
    const skipped = keys.length - targets.length;
    for (const d of targets) {
      try { await fetch(`/delete_device/${encodeURIComponent(d.ip)}`, { method: 'DELETE' }); } catch (_) {}
    }
    selected.clear();
    if (skipped) showToast(L('no_ip_skipped', skipped + ' device(s) without an IP were skipped', { count: skipped }), 'info');
    showToast(t('device_deleted_success'), 'success');
    await loadDevices(true);
  }

  // One field, many devices: POST the single changed key per selected device.
  async function bulkUpdateField(field, value, byKey) {
    if (value == null || value === '') return;
    const keys = [...selected];
    const targets = keys.map(k => byKey[k] || devByKey(k)).filter(d => d && d.ip);
    const skipped = keys.length - targets.length;
    for (const d of targets) {
      try {
        await fetch(`/update_device/${encodeURIComponent(d.ip)}`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ [field]: value }),
        });
      } catch (_) {}
    }
    if (skipped) showToast(L('no_ip_skipped', skipped + ' device(s) without an IP were skipped', { count: skipped }), 'info');
    showToast(t('device_updated_success'), 'success');
    await loadDevices(true);
  }
  const bulkType = (v, byKey) => bulkUpdateField('device_type', v, byKey);
  const bulkLocation = (v, byKey) => bulkUpdateField('location', v, byKey);
  const bulkTrust = (v, byKey) => bulkUpdateField('trust_status', v, byKey);

  async function bulkUplink(val, byKey) {
    if (!val) return;
    const uplinks = {};
    for (const k of selected) {
      const d = byKey[k] || devByKey(k);
      if (d && d.ip) uplinks[d.ip] = val === '__auto__' ? null : val;
    }
    if (!Object.keys(uplinks).length) return;
    try {
      await fetch('/api/topology/uplinks', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ uplinks }),
      });
      showToast(t('device_updated_success'), 'success');
    } catch (_) {}
    render();
  }

  const devByKey = (k) => (devices || []).find(d => keyOf(d) === k);

  window.MynesTable = { render };
})();
