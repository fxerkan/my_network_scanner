/* Network Insights page. Everything from the API is escaped before it
 * reaches innerHTML (SSDP SERVER headers and names are device-controlled). */
(function () {
    'use strict';
    const tr = (k, fb, p) => {
        const s = (typeof window.t === 'function') ? window.t(k, p || {}) : k;
        return s && s !== k ? s : fb;
    };
    const esc = v => String(v == null ? '' : v).replace(/[&<>"']/g, c =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    const PURPOSE = {
        control: ['ds-badge--info', () => tr('insights_p_control', 'cloud control')],
        telemetry: ['ds-badge--warning', () => tr('insights_p_telemetry', 'telemetry')],
        firmware: ['ds-badge--success', () => tr('insights_p_firmware', 'firmware')],
        media: ['ds-badge--info', () => tr('insights_p_media', 'media')],
        time: ['ds-badge--info', () => tr('insights_p_time', 'time')],
    };
    let devices = [];
    let filter = 'all';
    let query = '';
    const open = new Set();

    function stat(value, label, cls) {
        return `<div class="ds-stat ${cls || ''}"><div class="ds-stat__value">${esc(value)}</div><div class="ds-stat__label">${esc(label)}</div></div>`;
    }

    function renderNetwork(r) {
        const ping = r.gateway_ping || {};
        const dns = (r.dns || [])[0] || {};
        document.getElementById('insStats').innerHTML = [
            stat(r.internet_up ? tr('online', 'Online') : tr('offline', 'Offline'), tr('insights_internet', 'Internet'),
                 r.internet_up ? 'ds-stat--online' : 'ds-stat--critical'),
            stat(ping.avg_ms != null ? `${ping.avg_ms} ms` : '—', tr('insights_gateway_rtt', 'Gateway latency')),
            stat(dns.lookup && dns.lookup.ms != null ? `${dns.lookup.ms} ms` : '—', tr('insights_dns_rtt', 'DNS lookup')),
            stat(r.public_ip || '—', tr('insights_public_ip', 'Public IP')),
            stat((r.path || {}).isp_edge || '—', tr('insights_isp_edge', 'ISP edge')),
        ].join('');

        const hops = ((r.path || {}).hops || []).map(h => `
            <li class="ins-hop${h.ip && h.ip === (r.path || {}).isp_edge ? ' ins-hop--edge' : ''}">
              <span class="ins-hop__n">${esc(h.hop)}</span>
              <span class="ins-hop__ip">${h.timed_out ? '*' : esc(h.ip)} ${h.private ? `<span class="ds-badge">${esc(tr('insights_private', 'private'))}</span>` : ''}
                ${h.ip && h.ip === (r.path || {}).isp_edge ? `<span class="ds-badge ds-badge--info">${esc(tr('insights_isp_edge', 'ISP edge'))}</span>` : ''}</span>
              <span class="ins-hop__ms">${h.rtt_ms != null ? esc(h.rtt_ms) + ' ms' : ''}</span>
            </li>`).join('');
        document.getElementById('insPath').innerHTML = hops
            ? `<ol class="ins-hops">${hops}</ol>`
            : `<p class="ds-muted">${esc(tr('insights_no_path', 'Traceroute returned no hops.'))}</p>`;

        const d = r.dhcp || {};
        const servers = (r.dns || []).map(s => `
            <dl class="ins-kv">
              <dt>${esc(tr('insights_resolver', 'Resolver'))}</dt><dd>${esc(s.server)}</dd>
              <dt>${esc(tr('insights_lookup', 'Lookup'))}</dt><dd>${s.lookup && s.lookup.ok ? esc(s.lookup.ms) + ' ms' : esc((s.lookup || {}).error || '✗')}</dd>
              <dt>${esc(tr('insights_filtering', 'Ad/tracker filtering'))}</dt>
              <dd><span class="ds-badge ${s.filtering === 'filtering' ? 'ds-badge--success' : s.filtering === 'not filtering' ? 'ds-badge--warning' : ''}">${esc(tr('insights_f_' + s.filtering.replace(' ', '_'), s.filtering))}</span>
                ${(s.tests || []).map(t => `<small class="ds-muted">${esc(t.domain)} → ${esc((t.ips || []).join(', ') || (t.rcode === 3 ? 'NXDOMAIN' : '—'))}</small>`).join(' · ')}</dd>
            </dl>`).join('');
        const dhcp = Object.keys(d).length ? `
            <dl class="ins-kv">
              <dt>${esc(tr('insights_dhcp_dns', 'DNS handed out by DHCP'))}</dt><dd>${esc((d.name_server || []).join(', ') || '—')}</dd>
              <dt>${esc(tr('insights_dhcp_router', 'Gateway'))}</dt><dd>${esc((d.router || []).join(', ') || r.gateway || '—')}</dd>
              <dt>${esc(tr('insights_dhcp_lease', 'Lease'))}</dt><dd>${d.lease_time ? esc(Math.round(d.lease_time / 3600)) + ' h' : '—'}</dd>
              <dt>${esc(tr('insights_dhcp_domain', 'Domain'))}</dt><dd>${esc(d.domain || '—')}</dd>
            </dl>` : `<p class="ds-muted">${esc(tr('insights_dhcp_pending', 'DHCP settings appear after the next lease renewal on the LAN (the passive listener records the server reply).'))}</p>`;
        document.getElementById('insDns').innerHTML = servers + dhcp;
    }

    function matches(d) {
        if (filter === 'telemetry' && !d.telemetry_expected) return false;
        if (filter === 'cloud' && !d.cloud_dependent) return false;
        if (filter === 'broadcasting' && !Object.keys(d.broadcasts || {}).length) return false;
        if (filter === 'online' && d.status !== 'online') return false;
        if (!query) return true;
        const hay = [d.name, d.ip, d.mac, d.type, d.vendor, ...(d.expected_endpoints || []).map(e => e.domain)]
            .join(' ').toLowerCase();
        return hay.includes(query);
    }

    function renderChips() {
        const counts = {
            all: devices.length,
            online: devices.filter(d => d.status === 'online').length,
            telemetry: devices.filter(d => d.telemetry_expected).length,
            cloud: devices.filter(d => d.cloud_dependent).length,
            broadcasting: devices.filter(d => Object.keys(d.broadcasts || {}).length).length,
        };
        const labels = {
            all: tr('all', 'All'), online: tr('online', 'Online'),
            telemetry: tr('insights_c_telemetry', 'Expected telemetry'),
            cloud: tr('insights_c_cloud', 'Cloud-dependent'),
            broadcasting: tr('insights_c_broadcasting', 'Broadcasting'),
        };
        document.getElementById('insChips').innerHTML = Object.keys(labels).map(k =>
            `<button type="button" class="ins-chip" data-f="${k}" aria-pressed="${filter === k}">${esc(labels[k])} · ${counts[k]}</button>`).join('');
    }

    function renderRows() {
        const rows = devices.filter(matches).map(d => {
            const key = d.ip || d.mac || '';
            const bc = Object.entries(d.broadcasts || {}).map(([p, v]) =>
                `<span class="ds-badge" title="${esc(v.server || '')}">${esc(p)} · ${esc(v.count)}</span>`).join('');
            const servers = Object.values(d.broadcasts || {}).map(v => v.server).filter(Boolean);
            const purposes = [...new Set((d.expected_endpoints || []).map(e => e.purpose))];
            const tags = purposes.map(p => `<span class="ds-badge ${(PURPOSE[p] || [''])[0]}">${esc((PURPOSE[p] || [null, () => p])[1]())}</span>`).join('');
            const list = (d.expected_endpoints || []).map(e =>
                `<li><code>${esc(e.domain)}</code> <span class="ds-badge ${(PURPOSE[e.purpose] || [''])[0]}">${esc((PURPOSE[e.purpose] || [null, () => e.purpose])[1]())}</span> <span class="ds-muted">${esc(e.note)}</span></li>`).join('');
            const isOpen = open.has(key);
            return `<tr class="${isOpen ? 'ins-row--open' : ''}" data-key="${esc(key)}">
                <td class="ins-dev"><a href="/?device=${encodeURIComponent(key)}">${esc(d.name)}</a>
                  <small>${esc(d.ip || '')} ${esc(d.mac || '')}</small>
                  <small>${esc(d.type || '')}${d.vendor ? ' · ' + esc(d.vendor) : ''}</small></td>
                <td><div class="ins-tags">${bc || `<span class="ds-muted">${esc(tr('insights_none_heard', 'nothing heard yet'))}</span>`}</div>
                  ${servers.length ? `<small class="ds-muted">${esc(servers[0])}</small>` : ''}</td>
                <td><div class="ins-tags">${tags || `<span class="ds-muted">${esc(tr('insights_no_known', 'no known vendor endpoints'))}</span>`}</div>
                  ${list ? `<ul class="ins-ep">${list}</ul>` : ''}</td>
                <td class="ins-more">${list ? `<button type="button" class="ds-btn ds-btn--sm ins-toggle" aria-expanded="${isOpen}">${esc(isOpen ? tr('hide', 'Hide') : tr('details', 'Details'))}</button>` : ''}</td>
            </tr>`;
        }).join('');
        document.getElementById('insRows').innerHTML = rows ||
            `<tr><td colspan="4" class="ds-muted">${esc(tr('no_results', 'No results'))}</td></tr>`;
    }

    async function loadNetwork(refresh) {
        try {
            const res = await fetch('/api/insights/network' + (refresh ? '?refresh=1' : ''));
            renderNetwork(await res.json());
        } catch (e) {
            document.getElementById('insPath').innerHTML = `<p class="ds-muted">${esc(e.message)}</p>`;
        }
    }

    async function loadDevices() {
        try {
            const data = await (await fetch('/api/insights/devices')).json();
            devices = data.devices || [];
            renderChips();
            renderRows();
        } catch (e) {
            document.getElementById('insRows').innerHTML = `<tr><td colspan="4">${esc(e.message)}</td></tr>`;
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        document.getElementById('insRefresh').addEventListener('click', () => loadNetwork(true));
        document.getElementById('insChips').addEventListener('click', e => {
            const b = e.target.closest('.ins-chip');
            if (!b) return;
            filter = b.dataset.f;
            renderChips(); renderRows();
        });
        document.getElementById('insSearch').addEventListener('input', e => {
            query = e.target.value.trim().toLowerCase();
            renderRows();
        });
        document.getElementById('insRows').addEventListener('click', e => {
            const b = e.target.closest('.ins-toggle');
            if (!b) return;
            const key = b.closest('tr').dataset.key;
            if (open.has(key)) open.delete(key); else open.add(key);
            renderRows();
        });
        loadNetwork(false);
        loadDevices();
    });
})();
