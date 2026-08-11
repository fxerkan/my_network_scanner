/*
 * filters.js - one shared, persisted device filter used by every page.
 *
 * State lives in localStorage['mynes.filters'], so a choice made on the
 * Devices page (or set once as a default in Settings) sticks on every page and
 * across sessions without a server round trip - this is a single-user home-lab
 * app, so per-browser storage is the right amount of machinery.
 *   ponytail: localStorage, not a server config; move server-side only if the
 *   user ever wants the same defaults on a second device.
 *
 * match(device, state) is the entire predicate and is pure, so it is the one
 * thing worth testing - see MynesFilters._selftest() (run it from the console).
 * The UI (searchable multi-selects + toggles) only ever edits state.
 */
(function () {
    'use strict';

    const KEY = 'mynes.filters';
    const DEFAULTS = {
        q: '',
        types: [], vendors: [], statuses: [],
        showContainers: true, showNoIp: true, showBluetooth: true,
    };

    function load() {
        try { return { ...DEFAULTS, ...(JSON.parse(localStorage.getItem(KEY)) || {}) }; }
        catch (_) { return { ...DEFAULTS }; }
    }
    let state = load();

    // -- device classification (tiny + pure so match() stays testable) --------
    function isContainer(d) {
        return !!(d && (d.docker_info || /\(docker\)/i.test(d.device_type || '')));
    }
    function isNoIp(d) { return !(d && d.ip); }
    function isBluetooth(d) {
        const src = (d && d.discovery && d.discovery.sources) || [];
        return src.includes('ble') || (d && d.device_type === 'Bluetooth Device');
    }

    // Self-contained so vendor matching is identical on pages that don't load
    // main.js (Settings). Mirrors main.js normalizeVendor(); keep them in step.
    function vendorOf(d) {
        const v = (d && d.vendor) || '';
        if (!v) return '';
        if (v.toLowerCase().includes('tp-link')) return 'TP-Link Systems Inc.';
        return v.trim();
    }

    function match(d, s) {
        s = s || state;
        if (!s.showContainers && isContainer(d)) return false;
        if (!s.showNoIp && isNoIp(d)) return false;
        if (!s.showBluetooth && isBluetooth(d)) return false;
        if (s.types.length && !s.types.includes(d.device_type)) return false;
        if (s.vendors.length && !s.vendors.includes(vendorOf(d))) return false;
        if (s.statuses.length && !s.statuses.includes(d.status)) return false;
        if (s.q) {
            const q = s.q.toLowerCase();
            const hay = [d.ip, d.mac, d.hostname, d.vendor, d.device_type, d.alias]
                .filter(Boolean).join(' ').toLowerCase();
            if (!hay.includes(q)) return false;
        }
        return true;
    }

    function apply(list) { return (list || []).filter(d => match(d)); }

    function save() {
        try { localStorage.setItem(KEY, JSON.stringify(state)); } catch (_) { /* private mode */ }
        document.dispatchEvent(new CustomEvent('mynes:filters', { detail: { ...state } }));
    }
    function set(patch) { state = { ...state, ...patch }; save(); }
    function get() { return { ...state }; }
    function reset() { state = { ...DEFAULTS }; save(); }

    /** How many filters narrow the view - drives the little badge on the panel. */
    function activeCount() {
        let n = state.types.length + state.vendors.length + state.statuses.length;
        for (const k of ['showContainers', 'showNoIp', 'showBluetooth']) if (!state[k]) n++;
        if (state.q) n++;
        return n;
    }

    // -- escaping --------------------------------------------------------------
    function esc(s) {
        return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
            ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    }
    function tr(key, fallback) {
        const s = (typeof window.t === 'function') ? window.t(key) : key;
        return (s === key || s == null) ? fallback : s;
    }

    /*
     * Searchable multi-select: a button + a popover of checkboxes with a search
     * box. Built once, then only the count label and the checked state are
     * touched on change - rebuilding on every tick would slam the popover shut
     * mid-selection.
     *
     *   mount(el, {key, label, options})  binds it to state[key] (an array).
     *   options is a function returning [{value, label, icon?}].
     */
    function mountMulti(el, opts) {
        const key = opts.key;
        const optionList = () => (typeof opts.options === 'function' ? opts.options() : (opts.options || []));

        el.classList.add('ds-multi');
        el.innerHTML = `
            <button type="button" class="ds-multi__btn" aria-expanded="false">
                <span class="ds-multi__label">${esc(opts.label)}</span>
                <span class="ds-multi__count"></span>
                <svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-chevron-down"/></svg>
            </button>
            <div class="ds-multi__pop" hidden>
                <input type="search" class="ds-multi__search" placeholder="${esc(tr('search', 'Search…'))}">
                <div class="ds-multi__opts" role="group"></div>
            </div>`;

        const btn = el.querySelector('.ds-multi__btn');
        const pop = el.querySelector('.ds-multi__pop');
        const search = el.querySelector('.ds-multi__search');
        const box = el.querySelector('.ds-multi__opts');

        function syncCount() {
            const n = (state[key] || []).length;
            el.querySelector('.ds-multi__count').textContent = n ? `(${n})` : tr('all', 'All');
            btn.classList.toggle('is-active', n > 0);
        }
        function paint(q) {
            const sel = new Set(state[key] || []);
            const needle = (q || '').toLowerCase();
            box.innerHTML = optionList()
                .filter(o => !needle || String(o.label).toLowerCase().includes(needle))
                .map(o => `<label class="ds-multi__opt"><input type="checkbox" value="${esc(o.value)}" ${sel.has(o.value) ? 'checked' : ''}><span>${o.icon ? esc(o.icon) + ' ' : ''}${esc(o.label)}</span></label>`)
                .join('') || `<div class="ds-multi__empty">${esc(tr('no_results', '—'))}</div>`;
        }
        function open() {
            document.querySelectorAll('.ds-multi__pop').forEach(p => { if (p !== pop) p.setAttribute('hidden', ''); });
            pop.removeAttribute('hidden');
            btn.setAttribute('aria-expanded', 'true');
            search.value = '';
            paint('');
            search.focus();
        }
        function close() { pop.setAttribute('hidden', ''); btn.setAttribute('aria-expanded', 'false'); }

        btn.addEventListener('click', () => (pop.hasAttribute('hidden') ? open() : close()));
        search.addEventListener('input', () => paint(search.value));
        box.addEventListener('change', e => {
            if (e.target.type !== 'checkbox') return;
            const sel = new Set(state[key] || []);
            e.target.checked ? sel.add(e.target.value) : sel.delete(e.target.value);
            set({ [key]: [...sel] });      // fires mynes:filters -> pages re-render
        });

        // React to changes from elsewhere (Settings, reset) without stealing focus.
        document.addEventListener('mynes:filters', () => { syncCount(); if (!pop.hasAttribute('hidden')) paint(search.value); });
        syncCount();
        return { refresh: () => { syncCount(); if (!pop.hasAttribute('hidden')) paint(search.value); } };
    }

    /*
     * enhanceSelect(selectEl): give a native <select> the same searchable
     * popover look as the filter multi-selects, but single-select. The native
     * <select> stays the source of truth (hidden) - it keeps its <option>s,
     * optgroups and .value, so every populate/save path that already reads
     * `select.value` keeps working untouched. A MutationObserver repaints when
     * options are (re)loaded; call `select._ds.refresh()` after setting .value
     * programmatically (that fires no event to observe).
     */
    function enhanceSelect(sel) {
        if (!sel || sel._ds) return sel && sel._ds;
        sel.classList.add('ds-select-native');
        sel.style.display = 'none';        // inline so a stale cached CSS can't leave it visible
        sel.setAttribute('aria-hidden', 'true');
        sel.tabIndex = -1;

        const el = document.createElement('div');
        el.className = 'ds-multi ds-single';
        el.innerHTML = `
            <button type="button" class="ds-multi__btn" aria-expanded="false" aria-haspopup="listbox">
                <span class="ds-multi__label"></span>
                <svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-chevron-down"/></svg>
            </button>
            <div class="ds-multi__pop" hidden>
                <input type="search" class="ds-multi__search" placeholder="${esc(tr('search', 'Search…'))}">
                <div class="ds-multi__opts" role="listbox"></div>
            </div>`;
        sel.insertAdjacentElement('afterend', el);

        const btn = el.querySelector('.ds-multi__btn');
        const pop = el.querySelector('.ds-multi__pop');
        const search = el.querySelector('.ds-multi__search');
        const box = el.querySelector('.ds-multi__opts');
        const labelEl = el.querySelector('.ds-multi__label');

        function syncLabel() {
            const o = sel.selectedOptions[0];
            labelEl.textContent = o ? o.textContent : '';
            btn.classList.toggle('is-active', !!sel.value);
        }
        // Read options live so a repopulated <select> needs no rebuild. Options can
        // be direct children or nested inside <optgroup> (e.g. "Connected via" groups
        // devices) - descend into groups, and only show a group header when it has a
        // matching option under it.
        function paint(q) {
            const needle = (q || '').toLowerCase();
            const optHtml = node => {
                const text = node.textContent;
                if (needle && !text.toLowerCase().includes(needle)) return '';
                return `<button type="button" role="option" class="ds-multi__opt${node.value === sel.value ? ' is-selected' : ''}" data-value="${esc(node.value)}">${esc(text)}</button>`;
            };
            let html = '';
            for (const node of sel.children) {
                if (node.tagName === 'OPTGROUP') {
                    const inner = [...node.children].filter(o => o.tagName === 'OPTION').map(optHtml).join('');
                    if (inner) html += `<div class="ds-multi__group">${esc(node.label)}</div>` + inner;
                } else if (node.tagName === 'OPTION') {
                    html += optHtml(node);
                }
            }
            box.innerHTML = html || `<div class="ds-multi__empty">${esc(tr('no_results', '—'))}</div>`;
        }
        function open() {
            document.querySelectorAll('.ds-multi__pop').forEach(p => { if (p !== pop) p.setAttribute('hidden', ''); });
            pop.removeAttribute('hidden'); btn.setAttribute('aria-expanded', 'true');
            search.value = ''; paint(''); search.focus();
        }
        function close() { pop.setAttribute('hidden', ''); btn.setAttribute('aria-expanded', 'false'); }

        btn.addEventListener('click', () => (pop.hasAttribute('hidden') ? open() : close()));
        search.addEventListener('input', () => paint(search.value));
        box.addEventListener('click', e => {
            const opt = e.target.closest('.ds-multi__opt');
            if (!opt) return;
            sel.value = opt.dataset.value;
            syncLabel(); close();
            // Fire change so onchange="..." handlers and change listeners run,
            // exactly as if the user had used the native <select>.
            sel.dispatchEvent(new Event('change', { bubbles: true }));
        });
        // Repopulation (innerHTML/appendChild) fires childList mutations.
        new MutationObserver(() => { syncLabel(); if (!pop.hasAttribute('hidden')) paint(search.value); })
            .observe(sel, { childList: true });
        // Programmatic `sel.value = x; sel.dispatchEvent(new Event('change'))` keeps the label in sync.
        sel.addEventListener('change', () => { syncLabel(); if (!pop.hasAttribute('hidden')) paint(search.value); });

        syncLabel();
        sel._ds = { refresh: () => { syncLabel(); if (!pop.hasAttribute('hidden')) paint(search.value); } };
        return sel._ds;
    }

    /** Bind a checkbox <input> to a boolean state key, both ways. */
    function bindToggle(input, key) {
        if (!input) return;
        input.checked = !!state[key];
        input.addEventListener('change', () => set({ [key]: input.checked }));
        document.addEventListener('mynes:filters', () => { input.checked = !!state[key]; });
    }

    // Close any open popover on an outside click.
    document.addEventListener('click', e => {
        if (e.target.closest('.ds-multi')) return;
        document.querySelectorAll('.ds-multi__pop').forEach(p => p.setAttribute('hidden', ''));
        document.querySelectorAll('.ds-multi__btn').forEach(b => b.setAttribute('aria-expanded', 'false'));
    });

    // Every <select> becomes the app's searchable dropdown - native browser
    // dropdowns are the exception, not the rule. Opt a select out with
    // `data-native` (e.g. a compact width:auto control the popover would stretch),
    // and skip multi-selects (this component is single-select only).
    function autoEnhance(root = document) {
        root.querySelectorAll('select:not([data-native]):not([multiple])')
            .forEach(s => { try { enhanceSelect(s); } catch (_) { /* skip */ } });
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => autoEnhance());
    else autoEnhance();

    function _selftest() {
        const c = { device_type: 'Local Machine (Docker)', ip: '10.0.0.5', docker_info: { image: 'x' } };
        const ble = { device_type: 'Bluetooth Device', ip: '', discovery: { sources: ['ble'] } };
        const pc = { device_type: 'Laptop', ip: '10.0.0.9', vendor: 'Apple', status: 'online' };
        console.assert(match(c, { ...DEFAULTS, showContainers: false }) === false, 'container hidden');
        console.assert(match(c, DEFAULTS) === true, 'container shown by default');
        console.assert(match(ble, { ...DEFAULTS, showBluetooth: false }) === false, 'ble hidden');
        console.assert(match(ble, { ...DEFAULTS, showNoIp: false }) === false, 'no-ip hidden');
        console.assert(match(pc, { ...DEFAULTS, types: ['Laptop'] }) === true, 'type include');
        console.assert(match(pc, { ...DEFAULTS, types: ['Server'] }) === false, 'type exclude');
        console.assert(match(pc, { ...DEFAULTS, q: 'apple' }) === true, 'text match');
        console.log('MynesFilters._selftest: ok');
        return true;
    }

    window.MynesFilters = {
        match, apply, get, set, reset, activeCount,
        isContainer, isNoIp, isBluetooth, vendorOf,
        mountMulti, enhanceSelect, autoEnhance, bindToggle, _selftest,
    };
})();
