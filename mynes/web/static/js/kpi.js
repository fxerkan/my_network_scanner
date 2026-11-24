/* Home KPI tiles are controls, not just numbers.
 *  Total    -> clear the quick filters (status / type / vendor)
 *  Online   -> show only online devices (click again to undo)
 *  Types    -> popover: every type with its count; a row filters to it
 *  Vendors  -> same, per vendor
 * Everything goes through MynesFilters, so the Filters panel, the chips and
 * every view stay in step. Counts come from the full list (`devices` is the
 * unfiltered global between renders). */
(function () {
    'use strict';
    const esc = v => String(v == null ? '' : v).replace(/[&<>"']/g, c =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    const tr = (k, fb) => { const s = typeof t === 'function' ? t(k) : k; return s && s !== k ? s : fb; };
    let pop = null;

    function all() { return (typeof devices !== 'undefined' && Array.isArray(devices)) ? devices : []; }
    function F() { return window.MynesFilters; }

    function closePop() {
        if (pop) { pop.remove(); pop = null; }
        document.querySelectorAll('.stat-item[aria-expanded="true"]').forEach(el => el.setAttribute('aria-expanded', 'false'));
    }

    function counts(keyOf) {
        const m = new Map();
        all().forEach(d => { const k = keyOf(d); if (k) m.set(k, (m.get(k) || 0) + 1); });
        return [...m.entries()].sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])));
    }

    function openPicker(tile, field, rows, label) {
        closePop();
        const active = new Set((F().get()[field]) || []);
        const max = Math.max(1, ...rows.map(r => r[1]));
        pop = document.createElement('div');
        pop.className = 'kpi-pop';
        pop.setAttribute('role', 'dialog');
        pop.setAttribute('aria-label', label);
        pop.innerHTML = `
            <div class="kpi-pop__head"><strong>${esc(label)}</strong>
              ${active.size ? `<button type="button" class="ds-btn ds-btn--sm" data-clear>${esc(tr('clear', 'Clear'))}</button>` : ''}</div>
            <input type="search" class="form-input kpi-pop__search" placeholder="${esc(tr('search', 'Search…'))}">
            <div class="kpi-pop__list" role="listbox">${rows.map(([k, n]) => `
              <button type="button" role="option" class="kpi-pop__row${active.has(k) ? ' is-active' : ''}" data-k="${esc(k)}" aria-selected="${active.has(k)}">
                <span class="kpi-pop__name">${esc(typeof getTranslatedDeviceType === 'function' && field === 'types' ? getTranslatedDeviceType(k) : k)}</span>
                <span class="kpi-pop__bar"><i style="width:${Math.round(n / max * 100)}%"></i></span>
                <span class="kpi-pop__n">${n}</span>
              </button>`).join('')}</div>`;
        document.body.appendChild(pop);
        const r = tile.getBoundingClientRect();
        const w = Math.min(380, document.documentElement.clientWidth - 16);
        pop.style.width = w + 'px';
        pop.style.left = Math.max(8, Math.min(r.left, document.documentElement.clientWidth - w - 8)) + 'px';
        pop.style.top = (r.bottom + window.scrollY + 6) + 'px';
        tile.setAttribute('aria-expanded', 'true');
        const search = pop.querySelector('.kpi-pop__search');
        search.focus({ preventScroll: true });
        search.addEventListener('input', () => {
            const q = search.value.toLowerCase();
            pop.querySelectorAll('.kpi-pop__row').forEach(b => { b.hidden = q && !b.textContent.toLowerCase().includes(q); });
        });
        pop.addEventListener('click', e => {
            if (e.target.closest('[data-clear]')) { F().set({ [field]: [] }); closePop(); return; }
            const row = e.target.closest('.kpi-pop__row');
            if (!row) return;
            const k = row.dataset.k;
            const cur = new Set(F().get()[field] || []);
            // Plain click = show only this; Ctrl/Cmd/Shift-click adds to the selection.
            const next = (e.metaKey || e.ctrlKey || e.shiftKey)
                ? (cur.has(k) ? [...cur].filter(x => x !== k) : [...cur, k])
                : (cur.size === 1 && cur.has(k) ? [] : [k]);
            F().set({ [field]: next });
            closePop();
        });
    }

    function syncActive() {
        if (!F()) return;
        const s = F().get();
        const on = (sel, v) => { const el = document.querySelector(sel); if (el) el.classList.toggle('is-active', !!v); };
        on('.stat-online', (s.statuses || []).length === 1 && s.statuses[0] === 'online');
        on('.stat-types', (s.types || []).length);
        on('.stat-vendors', (s.vendors || []).length);
        on('.stat-total', !(s.statuses || []).length && !(s.types || []).length && !(s.vendors || []).length);
    }

    function activate(tile) {
        if (!F()) return;
        const s = F().get();
        if (tile.classList.contains('stat-total')) {
            closePop();
            F().set({ statuses: [], types: [], vendors: [] });
        } else if (tile.classList.contains('stat-online')) {
            closePop();
            const onlyOnline = (s.statuses || []).length === 1 && s.statuses[0] === 'online';
            F().set({ statuses: onlyOnline ? [] : ['online'] });
        } else if (tile.classList.contains('stat-types')) {
            if (tile.getAttribute('aria-expanded') === 'true') return closePop();
            openPicker(tile, 'types', counts(d => d.device_type), tr('device_types', 'Device types'));
        } else if (tile.classList.contains('stat-vendors')) {
            if (tile.getAttribute('aria-expanded') === 'true') return closePop();
            openPicker(tile, 'vendors', counts(d => F().vendorOf(d)), tr('vendors', 'Vendors'));
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        const tiles = document.querySelectorAll('.stats-bar .stat-item');
        const hints = {
            'stat-total': tr('kpi_total_hint', 'Show all devices (clear status/type/vendor filters)'),
            'stat-online': tr('kpi_online_hint', 'Show only online devices'),
            'stat-types': tr('kpi_types_hint', 'Pick a device type to filter by'),
            'stat-vendors': tr('kpi_vendors_hint', 'Pick a vendor to filter by'),
        };
        tiles.forEach(tile => {
            tile.setAttribute('role', 'button');
            tile.setAttribute('tabindex', '0');
            const cls = [...tile.classList].find(c => hints[c]);
            if (cls) tile.title = hints[cls];
            if (tile.classList.contains('stat-types') || tile.classList.contains('stat-vendors')) {
                tile.setAttribute('aria-haspopup', 'dialog');
                tile.setAttribute('aria-expanded', 'false');
            }
            tile.addEventListener('click', () => activate(tile));
            tile.addEventListener('keydown', e => {
                if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); activate(tile); }
            });
        });
        document.addEventListener('click', e => {
            if (pop && !e.target.closest('.kpi-pop') && !e.target.closest('.stats-bar .stat-item')) closePop();
        });
        document.addEventListener('keydown', e => { if (e.key === 'Escape') closePop(); });
        window.addEventListener('resize', closePop);
        document.addEventListener('mynes:filters', syncActive);
        syncActive();
    });
})();
