/*
 * views.js - the extra layouts behind the toolbar's view switch:
 *
 *   graph     force-directed cloud, subnet gateways as hubs
 *   topology  the real chain: internet -> router -> switch/AP -> group -> device
 *   home      floor plan (built in, or the user's own image) with draggable pins
 *
 * Everything here reads the global `devices` array that main.js owns, so the
 * search box and the filters keep working: filterDevices() swaps `devices`
 * before it calls displayDevices().
 */

(function () {
    'use strict';

    const SVG_NS = 'http://www.w3.org/2000/svg';

    // ---------------------------------------------------------------- groups

    /*
     * One table, three views. `types` are the values analysis/ hands us in
     * device_type (see the device_types.json in each locale); `color` picks one of
     * the six --cat-* tokens, which is why several groups share one.
     * Routers, switches and APs are NOT groups - they are the backbone the
     * topology view hangs everything else off.
     */
    const GROUPS = [
        { key: 'access_points', color: 'net',      types: ['Access Point'] },
        { key: 'switches',      color: 'net',      types: ['Switch', 'Modem'] },
        { key: 'servers',       color: 'infra',    types: ['Server', 'NAS', 'Raspberry Pi Server', 'Docker Container'] },
        { key: 'computers',     color: 'personal', types: ['Desktop', 'Laptop', 'Apple Device', 'Printer', 'Scanner'] },
        { key: 'phones',        color: 'personal', types: ['Smartphone', 'Non-Smartphone'] },
        { key: 'tablets',       color: 'personal', types: ['Tablet'] },
        { key: 'tvs',           color: 'media',    types: ['Smart TV'] },
        { key: 'medias',        color: 'media',    types: ['Smart Speaker', 'Streaming Device', 'Gaming Console', 'Game Console'] },
        { key: 'cameras',       color: 'iot',      types: ['IP Camera'] },
        { key: 'lights',        color: 'iot',      types: ['Smart Light'] },
        { key: 'climates',      color: 'iot',      types: ['Air Conditioner', 'Smart Thermostat'] },
        { key: 'vacuums',       color: 'iot',      types: ['Vacuum Cleaner'] },
        { key: 'pets',          color: 'iot',      types: ['Pet Feeder', 'Pet Water Fountain', 'Pet Toilet', 'Pet Tracker', 'Pet Camera'] },
        { key: 'sensors',       color: 'iot',      types: ['Sensor', 'Smart Sensor', 'Security System'] },
        { key: 'smart_home',    color: 'iot',      types: ['Smart Home', 'Smart Lock', 'Refrigerator', 'Dishwasher', 'Washing Machine'] },
        { key: 'iot_devices',   color: 'iot',      types: ['IoT Device'] },
        { key: 'other',         color: 'other',    types: [] },
    ];

    const GROUP_LABELS = {
        access_points: 'Access Points', switches: 'Switches', servers: 'Servers',
        computers: 'Computers', phones: 'Phones', tablets: 'Tablets', tvs: 'TVs',
        medias: 'Medias', cameras: 'Cameras', lights: 'Lights', climates: 'Climates',
        vacuums: 'Vacuums', pets: 'Pets', sensors: 'Sensors', smart_home: 'Smart Home',
        iot_devices: 'IoT Devices', other: 'Other',
    };

    const GROUP_ICONS = {
        access_points: '📶', switches: '🔀', servers: '🖥️', computers: '💻',
        phones: '📱', tablets: '📱', tvs: '📺', medias: '🔊', cameras: '📹',
        lights: '💡', climates: '🌡️', vacuums: '🧹', pets: '🐾', sensors: '📈',
        smart_home: '🏠', iot_devices: '🔗', other: '❓',
    };

    const TYPE_TO_GROUP = {};
    GROUPS.forEach(g => g.types.forEach(t => { TYPE_TO_GROUP[t.toLowerCase()] = g; }));

    const INFRA_RE = /router|switch|access point|extender|repeater|modem|gateway/i;

    function groupOf(d) {
        const type = (d.device_type || '').trim().toLowerCase();
        if (TYPE_TO_GROUP[type]) return TYPE_TO_GROUP[type];
        // A type we have not tabulated ("Smart Plug", "Pet Camera 2"): match on
        // either direction of containment before giving up on Other.
        if (type) {
            for (const g of GROUPS) {
                if (g.types.some(known => {
                    const k = known.toLowerCase();
                    return type.includes(k) || k.includes(type);
                })) return g;
            }
        }
        return GROUPS[GROUPS.length - 1];
    }

    function groupLabel(key) {
        return tr('group_' + key, GROUP_LABELS[key] || key);
    }

    /** Colour bucket for the graph and the group nodes. */
    function deviceClass(d) {
        return isInfra(d) ? 'net' : groupOf(d).color;
    }

    function isInfra(d) {
        return INFRA_RE.test(d.device_type || '') || (!!d.ip && d.ip.endsWith('.1'));
    }

    /** Split a device list into [{key, label, color, members}], biggest first. */
    function byGroup(list) {
        const buckets = new Map();
        list.forEach(d => {
            const g = groupOf(d);
            if (!buckets.has(g.key)) buckets.set(g.key, { ...g, label: groupLabel(g.key), members: [] });
            buckets.get(g.key).members.push(d);
        });
        return [...buckets.values()].sort((a, b) => b.members.length - a.members.length);
    }

    // ---------------------------------------------------------------- helpers

    /** Stable per-device key. MAC survives a DHCP lease change, IP does not. */
    function deviceKey(d) {
        return (d.mac && d.mac !== 'N/A') ? d.mac.toUpperCase() : (d.ip || d.hostname || '?');
    }

    function label(d) {
        return d.alias || d.hostname || d.ip || d.mac || '?';
    }

    function icon(d) {
        return (typeof getDeviceIcon === 'function') ? getDeviceIcon(d.device_type) : '•';
    }

    function tr(key, fallback) {
        const s = (typeof t === 'function') ? t(key) : key;
        return s === key ? fallback : s;
    }

    function esc(s) {
        return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
            ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    }

    /** Greedy word wrap for an SVG label: no <foreignObject>, no measuring. */
    function wrapLabel(text, perLine, maxLines) {
        const words = String(text || '').split(/\s+/).filter(Boolean);
        const lines = [];
        let line = '';
        for (const word of words) {
            const candidate = line ? line + ' ' + word : word;
            if (candidate.length <= perLine || !line) {
                line = candidate;
            } else {
                lines.push(line);
                line = word;
            }
            if (lines.length === maxLines) break;
        }
        if (line && lines.length < maxLines) lines.push(line);
        // A single unbroken token longer than the line budget still has to end
        // somewhere; that is the one case an ellipsis is honest.
        return lines.map(l => (l.length > perLine + 6 ? l.slice(0, perLine + 5) + '…' : l));
    }

    function clip(s, n) {
        s = String(s == null ? '' : s);
        return s.length > n ? s.slice(0, n - 1) + '…' : s;
    }

    /** First three octets, or null for a device that has no IP (BLE, Zigbee). */
    function subnetOf(d) {
        if (!d.ip || d.ip.split('.').length !== 4) return null;
        return d.ip.split('.').slice(0, 3).join('.');
    }

    function emptyState(container) {
        container.innerHTML =
            `<div class="view-empty">
                <svg class="ds-icon" aria-hidden="true"><use href="#i-network"/></svg>
                <p>${tr('no_devices_found', 'No devices yet')}</p>
                <p class="view-empty__hint">${tr('start_scan_hint', 'Run a scan to populate this view.')}</p>
            </div>`;
    }

    function el(tag, attrs, parent) {
        const node = document.createElementNS(SVG_NS, tag);
        for (const k in attrs) node.setAttribute(k, attrs[k]);
        if (parent) parent.appendChild(node);
        return node;
    }

    function openDeviceDetails(d) {
        if (typeof openEnhancedEditModal === 'function') openEnhancedEditModal(d.ip || d.mac);
    }

    // --------------------------------------------------------- subnet overlay
    //
    // A dashed CIDR-labelled box drawn behind whichever devices landed in
    // that subnet - the diagram gains an actual network boundary instead of
    // implying the LAN is one flat mesh. Positions are read from nodes the
    // caller already laid out; this never touches layout itself, so it can
    // be added to any view without risking its node placement.

    /** {x, y, r, cidr, label} entries -> one padded bounding box per cidr. */
    function subnetBoundingBoxes(entries) {
        const groups = new Map();
        entries.forEach(e => {
            if (!e.cidr || e.cidr === 'no-ip') return;
            if (!groups.has(e.cidr)) groups.set(e.cidr, { cidr: e.cidr, label: e.label, points: [] });
            groups.get(e.cidr).points.push(e);
        });
        // Draw the boundary even for a single subnet: the CIDR-labelled box is
        // the only place the graph/topology says which network these devices
        // are on, and users expect to see that grouping (not just an implicit
        // "everything is one blob"). It splits automatically once Docker/VLAN
        // CIDRs appear.
        if (groups.size < 1) return [];

        const PAD = 34;
        return [...groups.values()].map(g => {
            const xs = g.points.map(p => p.x - (p.r || 0)), xe = g.points.map(p => p.x + (p.r || 0));
            const ys = g.points.map(p => p.y - (p.r || 0)), ye = g.points.map(p => p.y + (p.r || 0));
            const x = Math.min(...xs) - PAD, y = Math.min(...ys) - PAD - 12;
            return {
                cidr: g.cidr, label: g.label,
                x, y, w: Math.max(...xe) - Math.min(...xs) + PAD * 2,
                h: Math.max(...ye) - Math.min(...ys) + PAD * 2 + 12,
            };
        });
    }

    /** Inserts the overlay as the first child of `svg`, so it paints behind
        every edge and node drawn after this call. */
    function drawSubnetOverlay(svg, boxes) {
        if (!boxes.length) return;
        const layer = el('g', { class: 'subnet-overlay' }, null);
        svg.insertBefore(layer, svg.firstChild);
        boxes.forEach(b => {
            el('rect', { class: 'subnet-overlay__rect', x: b.x, y: b.y, width: b.w, height: b.h, rx: 16 }, layer);
            const text = el('text', { class: 'subnet-overlay__label', x: b.x + 12, y: b.y + 18 }, layer);
            text.textContent = b.label;
        });
    }

    /** Pills summarising device counts per subnet - the "kırılım" the user
        gets alongside the diagram, from GET /api/topology's `subnets` (or
        GET /api/subnets directly). */
    function subnetPanel(subnetRows) {
        if (!subnetRows || !subnetRows.length) return '';
        const items = subnetRows.map(s => `
            <span class="view-subnets__item${s.known ? '' : ' view-subnets__item--guessed'}"
                  title="${esc(s.known ? tr('subnet_known', 'Detected network') : tr('subnet_guessed', 'Guessed from IP - not a confirmed interface'))}">
                <strong>${esc(s.cidr)}</strong>
                <span class="view-subnets__count">${s.device_count}</span>
            </span>`).join('');
        return `<div class="view-subnets">${items}</div>`;
    }

    /* Category visibility toggled from the legend. A category is a colour
       class (net/infra/personal/media/iot/other), which is coarser than a
       device_type - that is deliberate: the legend is the quick "mute a whole
       band" control, the filter panel is the fine one. Persisted so it sticks. */
    const HIDDEN_CATS = 'mynes.hiddenCats';
    let hiddenCats = new Set();
    try { hiddenCats = new Set(JSON.parse(localStorage.getItem(HIDDEN_CATS)) || []); } catch (_) { /* private mode */ }

    function catVisible(cls) { return !hiddenCats.has(cls); }
    function deviceCat(d) { return groupOf(d).color; }
    /** Drop devices whose category is muted in the legend. */
    function applyCatFilter(list) { return list.filter(d => catVisible(deviceCat(d))); }

    function toggleCat(cls) {
        hiddenCats.has(cls) ? hiddenCats.delete(cls) : hiddenCats.add(cls);
        try { localStorage.setItem(HIDDEN_CATS, JSON.stringify([...hiddenCats])); } catch (_) { /* private mode */ }
        // Re-run the shared filter so the active view repaints with the change.
        if (typeof window.filterDevices === 'function') window.filterDevices();
    }

    /* Interactive legend, rendered ABOVE the graph. Each colour band is a
       button that mutes/unmutes that category. `extra` is static markup
       (e.g. topology's uplink line keys) appended after the toggles. */
    function legend(extra) {
        const classes = [
            ['net', tr('network_gear', 'Network')],
            ['infra', tr('servers_storage', 'Servers & NAS')],
            ['personal', tr('personal_devices', 'Personal')],
            ['media', tr('media_devices', 'Media')],
            ['iot', tr('iot_devices', 'IoT')],
            ['other', tr('other', 'Other')],
        ];
        const box = document.createElement('div');
        box.className = 'view-legend view-legend--top';
        box.innerHTML = classes
            .map(([cls, name]) => `<button type="button" class="view-legend__item view-legend__item--btn${hiddenCats.has(cls) ? ' is-off' : ''}" data-cat="${cls}" aria-pressed="${!hiddenCats.has(cls)}"><i class="view-legend__dot view-legend__dot--${cls}"></i>${esc(name)}</button>`)
            .join('') + (extra || '');
        box.querySelectorAll('.view-legend__item--btn').forEach(btn =>
            btn.addEventListener('click', () => toggleCat(btn.dataset.cat)));
        return box;
    }

    // ------------------------------------------------------------ graph view

    /**
     * Plain O(n^2) repulsion + spring attraction, 300 fixed ticks. No d3.
     * ponytail: quadratic is fine to a few hundred devices; if a LAN ever gets
     * big enough to stutter, bucket the repulsion into a grid before reaching
     * for a physics library.
     */
    function layoutForce(nodes, links, width, height) {
        const cx = width / 2, cy = height / 2;
        nodes.forEach((n, i) => {
            const a = (i / nodes.length) * Math.PI * 2;
            n.x = cx + Math.cos(a) * (n.hub ? 80 : 260);
            n.y = cy + Math.sin(a) * (n.hub ? 80 : 260);
            n.vx = n.vy = 0;
        });

        for (let step = 0; step < 300; step++) {
            const cool = 1 - step / 300;

            for (let i = 0; i < nodes.length; i++) {
                for (let j = i + 1; j < nodes.length; j++) {
                    const a = nodes[i], b = nodes[j];
                    let dx = b.x - a.x, dy = b.y - a.y;
                    let dist = Math.hypot(dx, dy) || 0.01;
                    // Keep circles from overlapping even when the spring pulls hard.
                    const minGap = a.r + b.r + 14;
                    const force = 9000 / (dist * dist) + (dist < minGap ? (minGap - dist) * 0.6 : 0);
                    dx /= dist; dy /= dist;
                    a.vx -= dx * force; a.vy -= dy * force;
                    b.vx += dx * force; b.vy += dy * force;
                }
            }

            links.forEach(([ai, bi]) => {
                const a = nodes[ai], b = nodes[bi];
                const dx = b.x - a.x, dy = b.y - a.y;
                const dist = Math.hypot(dx, dy) || 0.01;
                const rest = a.hub && b.hub ? 260 : 150;
                const force = (dist - rest) * 0.02;
                const ux = dx / dist, uy = dy / dist;
                a.vx += ux * force; a.vy += uy * force;
                b.vx -= ux * force; b.vy -= uy * force;
            });

            nodes.forEach(n => {
                n.vx += (cx - n.x) * 0.002;   // gravity, keeps islands from drifting off
                n.vy += (cy - n.y) * 0.002;
                n.x += Math.max(-30, Math.min(30, n.vx)) * cool;
                n.y += Math.max(-30, Math.min(30, n.vy)) * cool;
                n.vx *= 0.82; n.vy *= 0.82;
            });
        }
        return nodes;
    }

    /** The machine a container runs on, when that machine is on screen too. */
    function dockerHostIp(d) {
        return (d.docker_info || {}).host_ip || null;
    }

    function buildGraphModel(list, topo) {
        const nodes = [], links = [], hubIndexes = [];
        const bySubnet = new Map();
        const radio = [];

        // Uplink parents, same source topology uses: a device plugged into a
        // switch links to that switch, not straight to the gateway hub.
        const parentIp = new Map(((topo && topo.nodes) || [])
            .filter(n => n.parent).map(n => [n.ip, n.parent]));

        // A container belongs to its host, not to whatever /24 Docker handed
        // its bridge. Hanging it off a subnet hub drew a cluster of orphans
        // next to the machine that was actually running them.
        const byIp = new Map(list.filter(d => d.ip).map(d => [d.ip, d]));
        const nodeIndexByIp = new Map();
        const memberLinks = [];            // deferred so switch parents resolve
        const hosted = new Map();          // host ip -> containers
        const containers = new Set();
        list.forEach(d => {
            const host = dockerHostIp(d);
            if (!host || host === d.ip || !byIp.has(host)) return;
            if (!hosted.has(host)) hosted.set(host, []);
            hosted.get(host).push(d);
            containers.add(d);
        });

        list.filter(d => !containers.has(d)).forEach(d => {
            const net = subnetOf(d);
            if (net === null) { radio.push(d); return; }
            if (!bySubnet.has(net)) bySubnet.set(net, []);
            bySubnet.get(net).push(d);
        });

        const segments = [...bySubnet.keys()].sort().map(net => {
            const members = bySubnet.get(net);
            const gw = members.find(isInfra) || null;
            return { name: net + '.0/24', gateway: gw, members: members.filter(d => d !== gw) };
        });
        if (radio.length) segments.push({ name: tr('radio_devices', 'Radio'), gateway: null, members: radio });

        segments.forEach(seg => {
            const hubIndex = nodes.push({
                hub: true, r: 26, cls: 'net',
                name: seg.gateway ? label(seg.gateway) : seg.name,
                sub: seg.name, device: seg.gateway,
            }) - 1;
            hubIndexes.push(hubIndex);

            if (seg.gateway && seg.gateway.ip) nodeIndexByIp.set(seg.gateway.ip, hubIndex);

            seg.members.forEach(d => {
                const idx = nodes.push({
                    hub: false,
                    r: d.status === 'online' ? 13 : 10,
                    name: label(d), sub: d.ip || d.mac || '',
                    device: d, cls: deviceClass(d), offline: d.status !== 'online',
                }) - 1;
                if (d.ip) nodeIndexByIp.set(d.ip, idx);
                memberLinks.push({ idx, hubIndex, ip: d.ip });
            });
        });

        // All member nodes exist now, so a parent that is itself a member (a
        // switch/AP) can be resolved. Fall back to the subnet hub when the
        // uplink is the gateway itself or is off screen.
        memberLinks.forEach(({ idx, hubIndex, ip }) => {
            const pIdx = ip ? nodeIndexByIp.get(parentIp.get(ip)) : undefined;
            links.push([pIdx !== undefined && pIdx !== idx ? pIdx : hubIndex, idx]);
        });

        // Containers last, so every possible host already has a node index.
        hosted.forEach((kids, hostIp) => {
            const hostIndex = nodeIndexByIp.get(hostIp);
            if (hostIndex === undefined) return;
            nodes[hostIndex].hostsContainers = true;
            kids.forEach(d => {
                const idx = nodes.push({
                    hub: false, container: true,
                    r: d.status === 'online' ? 9 : 7,
                    name: label(d), sub: d.ip || d.mac || '',
                    device: d, cls: deviceClass(d), offline: d.status !== 'online',
                }) - 1;
                links.push([hostIndex, idx]);
            });
        });

        // Hubs form a ring so separate subnets read as one network, not islands.
        for (let i = 1; i < hubIndexes.length; i++) links.push([hubIndexes[i - 1], hubIndexes[i]]);
        if (hubIndexes.length > 2) links.push([hubIndexes[hubIndexes.length - 1], hubIndexes[0]]);

        return { nodes, links };
    }

    /**
     * The card that follows the cursor. A native SVG <title> waits a second,
     * shows one unstyled line and cannot be read on a touch screen - not much
     * use when the question is "what is this dot and where does it live".
     */
    function deviceTooltipHTML(d, fallbackName) {
        if (!d) return `<div class="view-tip__title">${esc(fallbackName)}</div>`;
        const docker = d.docker_info || {};
        const rows = [
            [tr('ip_address', 'IP'), d.ip],
            [tr('mac_address', 'MAC'), d.mac && d.mac !== 'Unknown' ? d.mac : ''],
            [tr('device_type', 'Type'), d.device_type],
            [tr('vendor', 'Vendor'), d.vendor],
            [tr('status', 'Status'), d.status],
        ];
        if (docker.container_id) {
            const nets = (docker.networks && docker.networks.length)
                ? docker.networks.join(', ') : docker.network;
            rows.push(
                ['—', ''],
                [tr('docker_stack', 'Stack'), docker.stack || tr('none', '—')],
                [tr('docker_network', 'Network'), nets],
                [tr('docker_image', 'Image'), docker.image],
                [tr('docker_host', 'Host'), docker.host_ip]);
        }
        const body = rows
            .filter(([, v]) => v)
            .map(([k, v]) => `<div class="view-tip__row"><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`)
            .join('');
        return `<div class="view-tip__title">${esc(label(d))}</div><dl class="view-tip__rows">${body}</dl>`;
    }

    /** One tooltip element per view, moved around; not one per node. */
    function attachTooltip(stage) {
        const tip = document.createElement('div');
        tip.className = 'view-tip';
        tip.hidden = true;
        stage.appendChild(tip);

        const place = e => {
            const r = stage.getBoundingClientRect();
            // Flip before the card runs off the right or bottom edge.
            const w = tip.offsetWidth, h = tip.offsetHeight;
            let x = e.clientX - r.left + 14, y = e.clientY - r.top + 14;
            if (x + w > r.width) x = Math.max(0, e.clientX - r.left - w - 14);
            if (y + h > r.height) y = Math.max(0, e.clientY - r.top - h - 14);
            tip.style.transform = `translate(${x}px, ${y}px)`;
        };

        return {
            show(html, e) { tip.innerHTML = html; tip.hidden = false; place(e); },
            move: place,
            hide() { tip.hidden = true; },
        };
    }

    // The heavy lifting now lives in vis-network (vendored as a static asset,
    // no CDN - the app runs on a LAN with no internet). We keep
    // buildGraphModel() - it already resolves subnet hubs, uplink parents,
    // Docker hosts and radio devices - and hand its nodes/links to vis for the
    // physics, dragging, layout switching and neighbour highlighting the old
    // hand-rolled SVG could not do. layoutForce() stays only for _internals.

    // Persisted controls, same pattern as topoOrientation.
    let graphLayout = localStorage.getItem('mynes.graphLayout') || 'force';
    let graphDepth = localStorage.getItem('mynes.graphDepth') || 'all';
    let graphPhysics = localStorage.getItem('mynes.graphPhysics') !== 'off';
    let graphNet = null;   // live vis.Network, destroyed before each rebuild

    /** Resolve a CSS colour expression (token or literal) to a concrete rgb()
        vis can paint on its canvas - CSS vars don't survive into <canvas>. */
    function cssColor(expr, fallback) {
        const probe = document.createElement('span');
        probe.style.cssText = 'display:none;color:' + expr;
        document.body.appendChild(probe);
        const c = getComputedStyle(probe).color;
        probe.remove();
        return c || fallback || '#8a94a8';
    }

    /** BFS from the subnet hubs: the distance is the node's level (a device on a
        switch that hangs off the gateway reads as level 2), and the BFS parent
        is its next hop toward the hub - walking parents traces the full uplink
        path a selection highlights. Feeds the depth filter, the hierarchical
        layout and the "show the whole path to the router" highlight. */
    function graphLevels(nodes, links) {
        const adj = nodes.map(() => []);
        links.forEach(([a, b]) => { adj[a].push(b); adj[b].push(a); });
        const level = nodes.map(() => Infinity);
        const parent = nodes.map(() => -1);
        const q = [];
        nodes.forEach((n, i) => { if (n.hub) { level[i] = 0; q.push(i); } });
        if (!q.length) { level[0] = 0; q.push(0); }   // no hub (all radio): root the first
        for (let h = 0; h < q.length; h++) {
            const u = q[h];
            adj[u].forEach(v => { if (level[v] > level[u] + 1) { level[v] = level[u] + 1; parent[v] = u; q.push(v); } });
        }
        return { level: level.map(l => (l === Infinity ? 0 : l)), parent };
    }

    async function renderGraph(container, list) {
        if (!list.length) { if (graphNet) { graphNet.destroy(); graphNet = null; } return emptyState(container); }
        if (typeof vis === 'undefined' || !vis.Network) {
            container.innerHTML = `<div class="view-empty__hint" style="padding:var(--space-6)">${tr('graph_lib_missing', 'Graph library failed to load.')}</div>`;
            return;
        }

        container.innerHTML = '';
        container.appendChild(graphToolbar(container, list));
        container.appendChild(legend());

        const shown = applyCatFilter(list);
        if (!shown.length) {
            const note = document.createElement('div');
            note.className = 'view-empty__hint';
            note.style.padding = 'var(--space-6)';
            note.textContent = tr('all_categories_hidden', 'All categories hidden — tap a legend chip to show them.');
            container.appendChild(note);
            return;
        }

        const topo = await fetchTopology();
        const { nodes, links } = buildGraphModel(shown, topo);
        const { level: levels, parent: bfsParent } = graphLevels(nodes, links);
        const maxDepth = graphDepth === 'all' ? Infinity : parseInt(graphDepth, 10);

        const palette = {
            edge: cssColor('var(--border-strong)', '#9aa'),
            accent: cssColor('var(--focus-ring)', '#4a86e8'),
            text: cssColor('var(--text-secondary)', '#556'),
            textStrong: cssColor('var(--text-primary)', '#222'),
            // The label halo must match the canvas background (the sunken
            // surface), not --bg-surface, or it shows as a white/dark rim that
            // fights the text in dark mode.
            halo: cssColor('var(--bg-surface-sunken)', '#eef'),
            border: cssColor('var(--bg-surface)', '#fff'),
            // Dimmed nodes stay legible: a mid grey dot with muted-but-readable
            // labels, never the near-invisible --border-subtle.
            dim: cssColor('var(--border-strong)', '#9aa'),
            dimText: cssColor('var(--text-tertiary)', '#889'),
        };
        const catColor = {};
        ['net', 'infra', 'personal', 'media', 'iot', 'other'].forEach(c => { catColor[c] = cssColor('var(--cat-' + c + ')'); });

        // Keep only nodes within the chosen depth; an edge survives only if both
        // ends do, so nothing dangles.
        const keep = new Set();
        nodes.forEach((n, i) => { if (levels[i] <= maxDepth) keep.add(i); });

        const visNodes = [];
        nodes.forEach((n, i) => {
            if (!keep.has(i)) return;
            const base = catColor[n.cls] || catColor.other;
            visNodes.push({
                id: i, level: levels[i], device: n.device || null, cls: n.cls,
                label: n.hub ? n.name : clip(n.name, 22),
                title: undefined,          // native tooltip off; we use our own card
                value: n.hub ? 26 : (n.container ? 9 : 14),
                shape: n.hub ? 'hexagon' : (n.container ? 'diamond' : 'dot'),
                borderWidth: n.hub ? 3 : 2,
                opacity: n.offline ? 0.45 : 1,
                baseColor: {
                    background: base, border: palette.border,
                    highlight: { background: base, border: palette.accent },
                    hover: { background: base, border: palette.accent },
                },
                color: {
                    background: base, border: palette.border,
                    highlight: { background: base, border: palette.accent },
                    hover: { background: base, border: palette.accent },
                },
                font: { color: n.hub ? palette.textStrong : palette.text, size: n.hub ? 16 : 13, strokeWidth: 2, strokeColor: palette.halo },
            });
        });
        const visEdges = links
            .filter(([a, b]) => keep.has(a) && keep.has(b))
            .map(([a, b], i) => ({ id: 'e' + i, from: a, to: b }));

        const nodesDS = new vis.DataSet(visNodes);
        const edgesDS = new vis.DataSet(visEdges);

        const stage = document.createElement('div');
        stage.className = 'graph-net';
        container.appendChild(stage);

        if (graphNet) { graphNet.destroy(); graphNet = null; }
        graphNet = new vis.Network(stage, { nodes: nodesDS, edges: edgesDS }, graphOptions(palette));

        if (graphLayout === 'radial') { positionRadial(nodesDS, visNodes); graphNet.fit({ animation: false }); }

        // The tooltip must be attached AFTER the network is built: vis-network
        // takes over the container and clears anything already inside it.
        const tip = attachTooltip(stage);

        // vis owns the canvas pointer events and stops them bubbling, so the
        // tooltip tracks the cursor from the CAPTURE phase (fires before vis
        // can swallow it) - otherwise the hover card was stranded at (0,0).
        let lastPointer = { clientX: 0, clientY: 0 };
        stage.addEventListener('pointermove', e => { lastPointer = { clientX: e.clientX, clientY: e.clientY }; tip.move(e); }, true);

        // Selection highlight: the node, its direct neighbours (downstream
        // children) AND its whole uplink path to the router (walk BFS parents).
        // Everything else dims but stays readable, never vanishes.
        const nodeById = new Map(visNodes.map(n => [n.id, n]));
        function focusNode(id) {
            const near = new Set(graphNet.getConnectedNodes(id));
            near.add(id);
            for (let p = bfsParent[id]; p >= 0; p = bfsParent[p]) near.add(p);   // path to the hub
            const offline = n => n.device && n.device.status && n.device.status !== 'online';
            nodesDS.update(visNodes.map(n => {
                const on = near.has(n.id);
                const f = nodeById.get(n.id).font;
                return {
                    id: n.id,
                    color: on ? n.baseColor : { background: palette.dim, border: palette.halo, highlight: { background: palette.dim, border: palette.accent } },
                    font: { color: on ? f.color : palette.dimText, size: f.size, strokeWidth: 2, strokeColor: palette.halo },
                    opacity: on ? (offline(n) ? 0.45 : 1) : 0.55,
                };
            }));
            // An edge lights up when both ends are in the highlighted set - that
            // is exactly the selection's neighbours plus every hop up the path.
            edgesDS.update(visEdges.map(e => {
                const on = near.has(e.from) && near.has(e.to);
                return { id: e.id, color: on ? palette.accent : palette.dim, width: on ? 2.5 : 0.6 };
            }));
        }
        function clearFocus() {
            nodesDS.update(visNodes.map(n => ({ id: n.id, color: n.baseColor, font: nodeById.get(n.id).font, opacity: n.device && n.device.status && n.device.status !== 'online' ? 0.45 : 1 })));
            edgesDS.update(visEdges.map(e => ({ id: e.id, color: palette.edge, width: 1 })));
        }

        graphNet.on('selectNode', p => focusNode(p.nodes[0]));
        graphNet.on('selectEdge', p => {
            if (p.nodes.length) return;      // node select already fired
            const e = edgesDS.get(p.edges[0]);
            if (e) focusNode(e.from);
        });
        graphNet.on('deselectNode', clearFocus);
        graphNet.on('deselectEdge', p => { if (!p.nodes.length) clearFocus(); });

        // Double-click a device opens its edit sheet; single click stays a
        // selection so the highlight is usable.
        graphNet.on('doubleClick', p => {
            const n = p.nodes.length && nodeById.get(p.nodes[0]);
            if (n && n.device) { tip.hide(); openDeviceDetails(n.device); }
        });

        // Hover card, reused from the topology view.
        graphNet.on('hoverNode', p => {
            const n = nodeById.get(p.node);
            if (n) tip.show(deviceTooltipHTML(n.device, n.label), lastPointer);
        });
        graphNet.on('blurNode', tip.hide);

        addNetExportControl(stage, graphNet, 'mynes-graph');

        // Subnet count pills, same source as before.
        const panel = subnetPanel(topo.subnets);
        if (panel) container.insertAdjacentHTML('beforeend', panel);
    }

    /** vis-network options for the current layout/physics choice. */
    function graphOptions(palette) {
        const opts = {
            autoResize: true,
            nodes: {
                shape: 'dot',
                scaling: { min: 10, max: 46, label: { enabled: true, min: 12, max: 20 } },
                font: { face: 'inherit', color: palette.text, size: 13, strokeWidth: 2, strokeColor: palette.halo },
                borderWidth: 2, shadow: false,
            },
            edges: {
                color: { color: palette.edge, highlight: palette.accent, hover: palette.accent, opacity: 0.65 },
                width: 1, selectionWidth: 1.5, hoverWidth: 0.5,
                smooth: { enabled: true, type: 'continuous', roundness: 0.4 },
            },
            interaction: {
                hover: true, dragNodes: true, dragView: true, zoomView: true,
                multiselect: true, navigationButtons: false, keyboard: false, tooltipDelay: 999999,
            },
            physics: { enabled: false },
            layout: { improvedLayout: true, randomSeed: 7 },
        };
        if (graphLayout === 'hierarchical') {
            opts.layout.hierarchical = {
                enabled: true, direction: 'UD', sortMethod: 'directed',
                levelSeparation: 140, nodeSpacing: 130, treeSpacing: 220, blockShifting: true, edgeMinimization: true,
            };
            opts.edges.smooth = { enabled: true, type: 'cubicBezier', forceDirection: 'vertical', roundness: 0.5 };
        } else if (graphLayout === 'force') {
            opts.physics = {
                enabled: graphPhysics, solver: 'barnesHut',
                barnesHut: { gravitationalConstant: -14000, centralGravity: 0.25, springLength: 130, springConstant: 0.045, damping: 0.35, avoidOverlap: 0.7 },
                stabilization: { enabled: true, iterations: 300, updateInterval: 25 },
            };
        }
        return opts;
    }

    /** Concentric rings by BFS level - a tidy radial layout with physics off,
        so nodes stay exactly where the user drags them. */
    function positionRadial(nodesDS, visNodes) {
        const byLevel = new Map();
        visNodes.forEach(n => { if (!byLevel.has(n.level)) byLevel.set(n.level, []); byLevel.get(n.level).push(n); });
        const upd = [];
        byLevel.forEach((group, lvl) => {
            const R = lvl * 240;
            group.forEach((n, i) => {
                const a = (i / group.length) * Math.PI * 2;
                upd.push({ id: n.id, x: Math.round(Math.cos(a) * R), y: Math.round(Math.sin(a) * R), fixed: false });
            });
        });
        nodesDS.update(upd);
    }

    /** Layout / depth / physics controls, above the legend. */
    function graphToolbar(container, list) {
        const bar = document.createElement('div');
        bar.className = 'topo-toolbar';
        const layoutBtn = (val, key, fallback) =>
            `<button type="button" class="ds-segmented__btn" data-layout="${val}" aria-pressed="${graphLayout === val}">${esc(tr(key, fallback))}</button>`;
        bar.innerHTML = `
            <div class="ds-segmented" role="group" aria-label="${esc(tr('graph_layout', 'Layout'))}">
                ${layoutBtn('force', 'layout_force', 'Force')}
                ${layoutBtn('hierarchical', 'layout_hierarchical', 'Hierarchy')}
                ${layoutBtn('radial', 'layout_radial', 'Radial')}
            </div>
            <label class="graph-ctl">${esc(tr('graph_depth', 'Levels'))}
                <select class="filter-select" id="graphDepthSel">
                    <option value="all"${graphDepth === 'all' ? ' selected' : ''}>${esc(tr('depth_all', 'All'))}</option>
                    <option value="1"${graphDepth === '1' ? ' selected' : ''}>1</option>
                    <option value="2"${graphDepth === '2' ? ' selected' : ''}>2</option>
                    <option value="3"${graphDepth === '3' ? ' selected' : ''}>3</option>
                    <option value="4"${graphDepth === '4' ? ' selected' : ''}>4</option>
                </select>
            </label>
            <button type="button" class="ds-btn ds-btn--secondary ds-btn--sm" id="graphPhysicsBtn" aria-pressed="${graphPhysics}"
                    title="${esc(tr('graph_physics_hint', 'Freeze to arrange nodes by hand'))}">
                <svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-radar"/></svg>
                <span>${esc(graphPhysics ? tr('graph_physics_on', 'Physics: on') : tr('graph_physics_off', 'Physics: off'))}</span>
            </button>
            <span class="topo-hint">${esc(tr('graph_hint', 'Drag nodes to arrange. Click a node to highlight what it connects to; double-click to edit it.'))}</span>`;

        bar.querySelectorAll('[data-layout]').forEach(btn => btn.addEventListener('click', () => {
            graphLayout = btn.dataset.layout;
            try { localStorage.setItem('mynes.graphLayout', graphLayout); } catch (_) { /* private mode */ }
            renderGraph(container, list);
        }));
        bar.querySelector('#graphDepthSel').addEventListener('change', e => {
            graphDepth = e.target.value;
            try { localStorage.setItem('mynes.graphDepth', graphDepth); } catch (_) { /* private mode */ }
            renderGraph(container, list);
        });
        // Physics only matters for the force layout; the other two are static.
        const pBtn = bar.querySelector('#graphPhysicsBtn');
        pBtn.disabled = graphLayout !== 'force';
        pBtn.addEventListener('click', () => {
            graphPhysics = !graphPhysics;
            try { localStorage.setItem('mynes.graphPhysics', graphPhysics ? 'on' : 'off'); } catch (_) { /* private mode */ }
            if (graphNet) graphNet.setOptions({ physics: { enabled: graphPhysics } });
            pBtn.setAttribute('aria-pressed', graphPhysics);
            pBtn.querySelector('span').textContent = graphPhysics ? tr('graph_physics_on', 'Physics: on') : tr('graph_physics_off', 'Physics: off');
        });
        return bar;
    }

    /** PNG export straight off vis's canvas (SVG export needs the old vector
        path, which vis-network does not keep). */
    function addNetExportControl(stage, net, baseName) {
        const box = document.createElement('div');
        box.className = 'view-export';
        box.innerHTML = `<button type="button" class="view-export__btn" data-fmt="png">PNG</button>`;
        box.querySelector('button').addEventListener('click', () => {
            const canvas = stage.querySelector('canvas');
            if (!canvas) return;
            canvas.toBlob(b => downloadBlob(b, baseName + '.png'), 'image/png');
        });
        stage.appendChild(box);
    }

    // --------------------------------------------------------- topology view

    /*
     * The chain the user actually cares about: what is plugged into what.
     * The server does the inference (see core/topology.py) - an unmanaged
     * switch is invisible at layer 3, so anything it cannot prove comes back
     * as source "default" and is drawn dashed, and the user can correct it.
     */
    let topoCache = null;

    async function fetchTopology(force) {
        if (topoCache && !force) return topoCache;
        try {
            const res = await fetch('/api/topology');
            topoCache = await res.json();
        } catch (_) {
            topoCache = { gateway: null, nodes: [], uplinks: {} };
        }
        return topoCache;
    }

    // Sibling step and generation step. Horizontal needs less room between
    // siblings (they stack vertically) and more between generations, because
    // captions sit beside the node instead of under it.
    const SPACING = {
        vertical:   { across: 122, depth: 128 },
        horizontal: { across: 58,  depth: 230 },
    };
    const TOP = 52;

    // Vertical fans out sideways and needs horizontal scroll; horizontal grows
    // downwards, which is the direction a phone scrolls anyway.
    let topoOrientation = localStorage.getItem('mynes.topoOrientation') || 'vertical';

    /** Tidy tree: leaves take the next slot, parents centre over their kids.
        `across` is the sibling axis, `depth` is the generation axis; which one
        becomes x and which becomes y is decided by the orientation. */
    function layoutTree(node, depth, cursor) {
        const step = SPACING[topoOrientation] || SPACING.vertical;
        node.depth = TOP + depth * step.depth;
        if (!node.children || !node.children.length) {
            node.across = cursor.n * step.across + step.across / 2;
            cursor.n += 1;
            return;
        }
        node.children.forEach(c => layoutTree(c, depth + 1, cursor));
        node.across = (node.children[0].across + node.children[node.children.length - 1].across) / 2;
    }

    /** Project the layout onto the screen axes for the chosen orientation. */
    function applyOrientation(node) {
        if (topoOrientation === 'horizontal') {
            node.x = node.depth;
            node.y = node.across;
        } else {
            node.x = node.across;
            node.y = node.depth;
        }
        (node.children || []).forEach(applyOrientation);
    }

    function buildTopoTree(list, topo) {
        const present = new Map(list.filter(d => d.ip).map(d => [d.ip, d]));
        const meta = new Map((topo.nodes || []).map(n => [n.ip, n]));
        const gatewayIp = present.has(topo.gateway) ? topo.gateway
            : ([...present.keys()].find(ip => isInfra(present.get(ip)) && ip.endsWith('.1')) || null);

        // A device whose uplink got filtered out falls back to the gateway,
        // otherwise it would silently vanish from the diagram.
        const parentOf = ip => {
            const m = meta.get(ip);
            const p = m && m.parent;
            return (p && present.has(p) && p !== ip) ? p : (ip === gatewayIp ? null : gatewayIp);
        };
        const sourceOf = ip => {
            const m = meta.get(ip);
            if (!m) return 'default';
            if (m.source === 'gateway') return 'gateway';   // its uplink IS the internet
            return (m.parent && present.has(m.parent)) ? m.source : 'default';
        };

        const childrenOf = new Map();
        present.forEach((d, ip) => {
            if (ip === gatewayIp) return;
            const p = parentOf(ip);
            if (!childrenOf.has(p)) childrenOf.set(p, []);
            childrenOf.get(p).push(d);
        });

        const seen = new Set();
        // A branch is anything with something hanging off it. Not just infra:
        // the whole point of a manual uplink is naming a switch MyNeS could not
        // identify, and its children have to stay visible.
        const isBranch = d => isInfra(d) || (childrenOf.get(d.ip) || []).length > 0;

        function infraNode(d) {
            seen.add(d.ip);
            const kids = (childrenOf.get(d.ip) || []).filter(k => !seen.has(k.ip));
            const infraKids = kids.filter(isBranch).map(infraNode);
            const groups = byGroup(kids.filter(k => !isBranch(k))).map(g => ({
                kind: 'group', name: g.label, cls: g.color, count: g.members.length, groupKey: g.key,
                children: g.members.map(m => ({
                    kind: 'leaf', device: m, cls: g.color, source: sourceOf(m.ip), children: [],
                })),
            }));
            return {
                kind: 'infra', device: d, cls: deviceClass(d), source: sourceOf(d.ip),
                children: [...infraKids, ...groups],
            };
        }

        const roots = [];
        if (gatewayIp) roots.push(infraNode(present.get(gatewayIp)));
        // Devices with no IP (BLE, Zigbee) have no L3 parent at all - own branch.
        const radio = list.filter(d => !d.ip);
        if (radio.length) {
            roots.push({
                kind: 'infra', name: tr('radio_devices', 'Radio devices'), cls: 'other', source: 'radio',
                children: byGroup(radio).map(g => ({
                    kind: 'group', name: g.label, cls: g.color, count: g.members.length, groupKey: g.key,
                    children: g.members.map(m => ({ kind: 'leaf', device: m, cls: g.color, source: 'radio', children: [] })),
                })),
            });
        }

        return { kind: 'root', name: tr('internet', 'Internet'), cls: 'root', children: roots, gatewayIp };
    }

    function renderTopology(container, list) {
        if (!list.length) return emptyState(container);
        container.innerHTML = `<div class="view-loading">${tr('loading', 'Loading…')}</div>`;
        fetchTopology().then(topo => drawTopology(container, list, topo));
    }

    function drawTopology(container, list, topo) {
        // Legend can mute leaf categories, but never the backbone (routers/
        // switches/APs) - dropping those would orphan the tree.
        list = list.filter(d => isInfra(d) || catVisible(deviceCat(d)));
        const root = buildTopoTree(list, topo);
        const cursor = { n: 0 };
        layoutTree(root, 0, cursor);
        applyOrientation(root);

        const depth = (function maxDepth(n, d) {
            return n.children.length ? Math.max(...n.children.map(c => maxDepth(c, d + 1))) : d;
        })(root, 0);
        const step = SPACING[topoOrientation] || SPACING.vertical;
        const acrossSize = Math.max(cursor.n * step.across, 640);
        const depthSize = TOP + depth * step.depth + 120;
        const horizontal = topoOrientation === 'horizontal';
        const width = horizontal ? depthSize : acrossSize;
        const height = horizontal ? acrossSize : depthSize;

        container.innerHTML = '';
        container.appendChild(topoToolbar(container, list));
        // Interactive legend at the top, consistent with the graph view.
        container.appendChild(legend(
            `<span class="view-legend__item"><i class="view-legend__line"></i>${tr('uplink_known', 'Known uplink')}</span>
             <span class="view-legend__item"><i class="view-legend__line view-legend__line--dashed"></i>${tr('uplink_assumed', 'Assumed direct')}</span>`
        ));

        /*
         * The diagram is scaled to fit its box rather than drawn 1:1 and
         * scrolled. A 4000px-wide tree in a 390px phone viewport was simply
         * blank on first open; fit-then-zoom shows the whole network first and
         * lets the user go in from there.
         */
        const stage = document.createElement('div');
        stage.className = 'topo-stage';
        container.appendChild(stage);

        const PAD = 40;
        const box = { x: -PAD, y: -PAD, w: width + PAD * 2, h: height + PAD * 2 };
        const svg = el('svg', {
            class: 'topo-svg',
            viewBox: `${box.x} ${box.y} ${box.w} ${box.h}`,
            preserveAspectRatio: 'xMidYMid meet',
            role: 'img',
            'aria-label': tr('topology_view', 'Network topology'),
        }, stage);

        const edges = el('g', { class: 'topo-edges' }, svg);
        const nodeLayer = el('g', {}, svg);

        // Subnet boundaries: every real device (infra or leaf - a "group"
        // pill has none of its own, its children already carry theirs) gets
        // matched to the CIDR /api/topology assigned it, then boxed per CIDR.
        const subnetByIp = new Map((topo.nodes || []).filter(n => n.ip).map(n => [n.ip, n.subnet]));
        const subnetEntries = [];
        (function collect(node) {
            if (node.device && node.device.ip && subnetByIp.has(node.device.ip)) {
                subnetEntries.push({
                    x: node.x, y: node.y, r: node.kind === 'leaf' ? 16 : 22,
                    ...subnetByIp.get(node.device.ip),
                });
            }
            (node.children || []).forEach(collect);
        })(root);
        drawSubnetOverlay(svg, subnetBoundingBoxes(subnetEntries));

        const tip = attachTooltip(stage);
        (function walk(node) {
            drawTopoNode(nodeLayer, node, container, list, tip);
            node.children.forEach(child => {
                // Same elbow, rotated: the first leg runs along the generation
                // axis, the second along the sibling axis.
                const d = horizontal
                    ? (() => { const mid = (node.x + child.x) / 2;
                               return `M${node.x + 22},${node.y} H${mid} V${child.y} H${child.x - 22}`; })()
                    : (() => { const mid = (node.y + child.y) / 2;
                               return `M${node.x},${node.y + 22} V${mid} H${child.x} V${child.y - 22}`; })();
                el('path', { class: child.source === 'default' ? 'is-assumed' : '', d }, edges);
                walk(child);
            });
        })(root);

        // The stage takes the diagram's shape via aspect-ratio (min/max in the
        // stylesheet keep it usable), so a wide shallow tree is not
        // letterboxed in a tall panel with dead space above and below.
        stage.style.setProperty('--topo-ratio', `${box.w} / ${box.h}`);

        attachZoomPan(stage, svg, box);
        addExportControl(stage, svg, 'mynes-topology');
        const panel = subnetPanel(topo.subnets);
        if (panel) container.insertAdjacentHTML('beforeend', panel);
    }

    /** Zoom and pan by moving the viewBox. No library, no transform matrices. */
    function attachZoomPan(stage, svg, fitBox) {
        const view = { ...fitBox };
        const MIN_SCALE = 0.2, MAX_SCALE = 8;      // relative to the fit view

        const apply = () => svg.setAttribute('viewBox', `${view.x} ${view.y} ${view.w} ${view.h}`);

        function zoomAt(factor, cx, cy) {
            const next = Math.min(Math.max(view.w * factor, fitBox.w / MAX_SCALE), fitBox.w / MIN_SCALE);
            const k = next / view.w;
            // Keep the point under the cursor where it is.
            view.x = cx - (cx - view.x) * k;
            view.y = cy - (cy - view.y) * k;
            view.w = next;
            view.h *= k;
            apply();
        }

        const toSvg = (clientX, clientY) => {
            const r = svg.getBoundingClientRect();
            // preserveAspectRatio="meet" letterboxes, so the on-screen scale is
            // the smaller of the two ratios.
            const scale = Math.min(r.width / view.w, r.height / view.h);
            return {
                x: view.x + (clientX - r.left - (r.width - view.w * scale) / 2) / scale,
                y: view.y + (clientY - r.top - (r.height - view.h * scale) / 2) / scale,
            };
        };

        stage.addEventListener('wheel', e => {
            e.preventDefault();
            const p = toSvg(e.clientX, e.clientY);
            zoomAt(e.deltaY > 0 ? 1.15 : 1 / 1.15, p.x, p.y);
        }, { passive: false });

        let dragging = null;
        const active = new Map();          // live pointers, for pinch
        let pinch = null;

        const dist = () => {
            const [a, b] = [...active.values()];
            return Math.hypot(a.x - b.x, a.y - b.y);
        };
        const midpoint = () => {
            const [a, b] = [...active.values()];
            return toSvg((a.x + b.x) / 2, (a.y + b.y) / 2);
        };

        stage.addEventListener('pointerdown', e => {
            // A node opens its own menu, and the zoom buttons need their click
            // event - capturing the pointer here swallowed it, which is why
            // the buttons did nothing while the wheel worked.
            if (e.target.closest('.topo-node, .graph-node, .topo-zoom')) return;

            active.set(e.pointerId, { x: e.clientX, y: e.clientY });
            if (active.size === 2) {
                dragging = null;
                pinch = { distance: dist(), centre: midpoint() };
                return;
            }
            dragging = { ...toSvg(e.clientX, e.clientY) };
            stage.setPointerCapture(e.pointerId);
            stage.classList.add('is-panning');
        });

        stage.addEventListener('pointermove', e => {
            if (active.has(e.pointerId)) active.set(e.pointerId, { x: e.clientX, y: e.clientY });

            if (pinch && active.size === 2) {
                const now = dist();
                if (now > 0 && pinch.distance > 0) zoomAt(pinch.distance / now, pinch.centre.x, pinch.centre.y);
                pinch.distance = now;
                pinch.centre = midpoint();
                return;
            }
            if (!dragging) return;
            const p = toSvg(e.clientX, e.clientY);
            view.x -= p.x - dragging.x;
            view.y -= p.y - dragging.y;
            apply();
        });

        const endPointer = e => {
            active.delete(e.pointerId);
            if (active.size < 2) pinch = null;
            dragging = null;
            stage.classList.remove('is-panning');
        };
        stage.addEventListener('pointerup', endPointer);
        stage.addEventListener('pointercancel', endPointer);

        const controls = document.createElement('div');
        controls.className = 'topo-zoom';
        controls.innerHTML = `
            <button type="button" class="icon-btn" data-zoom="in" title="${esc(tr('zoom_in', 'Zoom in'))}">+</button>
            <button type="button" class="icon-btn" data-zoom="out" title="${esc(tr('zoom_out', 'Zoom out'))}">−</button>
            <button type="button" class="icon-btn" data-zoom="fit" title="${esc(tr('zoom_fit', 'Fit to screen'))}">
                <svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-scan"/></svg>
            </button>`;
        stage.appendChild(controls);
        controls.addEventListener('click', e => {
            const btn = e.target.closest('[data-zoom]');
            if (!btn) return;
            const cx = view.x + view.w / 2, cy = view.y + view.h / 2;
            if (btn.dataset.zoom === 'in') zoomAt(1 / 1.4, cx, cy);
            else if (btn.dataset.zoom === 'out') zoomAt(1.4, cx, cy);
            else { Object.assign(view, fitBox); apply(); }
        });
    }

    function drawTopoNode(layer, node, container, list, tip) {
        const isLeaf = node.kind === 'leaf';
        const d = node.device;
        const name = d ? label(d) : node.name;
        const sub = d ? (d.ip || d.mac || '') : (node.count != null ? String(node.count) : '');
        const g = el('g', {
            class: `topo-node topo-kind--${node.kind} topo-node--${node.cls}`
                + (d && d.status && d.status !== 'online' ? ' is-offline' : ''),
            transform: `translate(${node.x},${node.y})`,
        }, layer);
        if (tip) {
            const html = deviceTooltipHTML(d, name);
            g.addEventListener('pointerenter', e => tip.show(html, e));
            g.addEventListener('pointermove', tip.move);
            g.addEventListener('pointerleave', tip.hide);
        } else {
            el('title', {}, g).textContent = sub ? `${name}\n${sub}` : name;
        }
        el('circle', { cx: 0, cy: 0, r: isLeaf ? 16 : 22 }, g);
        const glyph = el('text', { class: 'topo-glyph', x: 0, y: 6, 'text-anchor': 'middle' }, g);
        // The internet node used to be 🌐 - the same glyph device_types.json
        // gives a Router, so the two were indistinguishable.
        glyph.textContent = d ? icon(d)
            : (node.kind === 'root' ? '☁️' : (GROUP_ICONS[node.groupKey] || '❓'));

        // Captions go under the node when the tree grows downwards, and to its
        // right when it grows sideways - otherwise they overlap the next row.
        const side = topoOrientation === 'horizontal';
        const capX = side ? (isLeaf ? 22 : 28) : 0;
        const capY = side ? 0 : (isLeaf ? 34 : 42);
        const anchor = side ? 'start' : 'middle';
        const cap = el('text', {
            class: 'topo-caption' + (node.kind === 'group' ? ' is-group' : ''),
            x: capX, y: capY, 'text-anchor': anchor,
        }, g);
        // Names are wrapped, not truncated: six devices called "TP-Link IoT
        // De…" are indistinguishable, which is the opposite of the point.
        const lines = wrapLabel(name, 16, 3);
        lines.forEach((line, i) => {
            const span = el('tspan', { x: capX, dy: i === 0 ? 0 : 12 }, cap);
            span.textContent = line;
        });
        if (sub) {
            const subEl = el('text', {
                class: 'topo-sub', x: capX, y: capY + 13 + (lines.length - 1) * 12,
                'text-anchor': anchor,
            }, g);
            subEl.textContent = sub;
        }
        if (d) {
            g.setAttribute('tabindex', '0');
            g.setAttribute('role', 'button');
            g.addEventListener('click', e => { e.stopPropagation(); openUplinkMenu(container, list, d, e); });
            g.addEventListener('keydown', e => { if (e.key === 'Enter') openDeviceDetails(d); });
        }
    }

    function topoToolbar(container, list) {
        const bar = document.createElement('div');
        bar.className = 'topo-toolbar';
        bar.innerHTML = `
            <button type="button" class="ds-btn ds-btn--secondary ds-btn--sm" id="topoDiscover">
                <svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-radar"/></svg>
                <span>${esc(tr('topology_discover', 'Discover uplinks'))}</span>
            </button>
            <div class="ds-segmented topo-orientation" role="group" aria-label="${esc(tr('orientation', 'Orientation'))}">
                <button type="button" class="ds-segmented__btn" data-orientation="vertical"
                        aria-pressed="${topoOrientation === 'vertical'}" title="${esc(tr('orientation_vertical', 'Vertical'))}">
                    <svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-topology"/></svg>
                </button>
                <button type="button" class="ds-segmented__btn" data-orientation="horizontal"
                        aria-pressed="${topoOrientation === 'horizontal'}" title="${esc(tr('orientation_horizontal', 'Horizontal'))}">
                    <svg class="ds-icon ds-icon--sm topo-orientation__rotated" aria-hidden="true"><use href="#i-topology"/></svg>
                </button>
            </div>
            <span class="topo-hint">${esc(tr('topology_hint',
                'Traceroute only finds routed hops. A bridged switch or access point is invisible on the wire - click a device to say what it is plugged into.'))}</span>`;
        bar.querySelectorAll('[data-orientation]').forEach(btn => {
            btn.addEventListener('click', () => {
                topoOrientation = btn.dataset.orientation;
                try { localStorage.setItem('mynes.topoOrientation', topoOrientation); } catch (_) { /* private mode */ }
                renderTopology(container, list);
            });
        });
        bar.querySelector('#topoDiscover').addEventListener('click', async e => {
            const btn = e.currentTarget;
            btn.disabled = true;
            btn.querySelector('span').textContent = tr('topology_discovering', 'Tracing…');
            try {
                await fetch('/api/topology/discover', { method: 'POST' });
                await fetchTopology(true);
                renderTopology(container, list);
            } finally {
                btn.disabled = false;
            }
        });
        return bar;
    }

    /** "Connected via" picker. The only way to record a bridged switch or AP. */
    function openUplinkMenu(container, list, device, event) {
        container.querySelectorAll('.uplink-menu').forEach(m => m.remove());
        if (!device.ip) return openDeviceDetails(device);

        const others = list.filter(d => d.ip && d.ip !== device.ip);
        const infra = others.filter(isInfra);
        // A switch MyNeS could not identify still has to be selectable, or the
        // one case this picker exists for is the one it cannot express.
        const rest = others.filter(d => !isInfra(d));
        const current = (topoCache && topoCache.uplinks && topoCache.uplinks[device.ip]) || '';
        const option = d => `<option value="${esc(d.ip)}"${d.ip === current ? ' selected' : ''}>${esc(label(d))} — ${esc(d.ip)}</option>`;
        const menu = document.createElement('div');
        menu.className = 'uplink-menu';
        menu.innerHTML = `
            <div class="uplink-menu__title">${esc(label(device))}</div>
            <label class="uplink-menu__label" for="uplinkSelect">${esc(tr('connected_via', 'Connected via'))}</label>
            <select class="filter-select" id="uplinkSelect">
                <option value="">${esc(tr('uplink_auto', 'Auto (detected)'))}</option>
                ${infra.length ? `<optgroup label="${esc(tr('network_gear', 'Network'))}">${infra.map(option).join('')}</optgroup>` : ''}
                ${rest.length ? `<optgroup label="${esc(tr('other_devices', 'Other devices'))}">${rest.map(option).join('')}</optgroup>` : ''}
            </select>
            <div class="uplink-menu__actions">
                <button type="button" class="ds-btn ds-btn--ghost ds-btn--sm" data-act="details">${esc(tr('details', 'Details'))}</button>
                <button type="button" class="ds-btn ds-btn--primary ds-btn--sm" data-act="save">${esc(tr('save', 'Save'))}</button>
            </div>`;

        const box = container.getBoundingClientRect();
        menu.style.left = Math.max(8, Math.min(event.clientX - box.left, box.width - 280)) + 'px';
        menu.style.top = (event.clientY - box.top + 12) + 'px';
        container.appendChild(menu);

        menu.querySelector('[data-act="details"]').addEventListener('click', () => {
            menu.remove();
            openDeviceDetails(device);
        });
        menu.querySelector('[data-act="save"]').addEventListener('click', async () => {
            const value = menu.querySelector('#uplinkSelect').value;
            menu.remove();
            await fetch('/api/topology/uplinks', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ uplinks: { [device.ip]: value || null } }),
            });
            // A cleared uplink has to be dropped locally too - the server keeps
            // only truthy values, so it cannot echo the deletion back.
            if (topoCache) {
                topoCache = null;
            }
            await fetchTopology(true);
            renderTopology(container, list);
        });
        // Close on a click *outside* the menu. The previous version listened
        // for any click at all, so opening the <select> closed the popover.
        setTimeout(() => {
            const onDocClick = (e) => {
                if (menu.contains(e.target)) return;
                menu.remove();
                document.removeEventListener('click', onDocClick);
            };
            document.addEventListener('click', onDocClick);
            menu.addEventListener('remove', () => document.removeEventListener('click', onDocClick));
        }, 0);
    }

    // ------------------------------------------------------------- home view

    const HOME_STORE = 'mynes.homeMap';
    const HOME_MAX_PX = 1600;   // downscale before storing: localStorage is ~5MB
    const DEFAULT_ROOMS = ['Bedroom', 'Living room', 'Office', 'Kitchen', 'Hall', 'Garage'];

    function loadHome() {
        let state;
        try {
            state = JSON.parse(localStorage.getItem(HOME_STORE)) || {};
        } catch (_) {
            state = {};
        }
        return {
            bg: state.bg || null,
            pins: state.pins || {},
            rooms: Array.isArray(state.rooms) && state.rooms.length
                ? state.rooms
                : DEFAULT_ROOMS.map((name, i) => tr('room_' + ['bedroom', 'living', 'office', 'kitchen', 'hall', 'garage'][i], name)),
            title: state.title || tr('home_network', 'Home network'),
        };
    }

    function saveHome(state) {
        try {
            localStorage.setItem(HOME_STORE, JSON.stringify(state));
            return true;
        } catch (_) {
            alert(tr('home_map_storage_full', 'Could not save the plan: browser storage is full. Try a smaller background image.'));
            return false;
        }
    }

    /** Reads a File, shrinks the long edge to HOME_MAX_PX, returns a data URL. */
    function toScaledDataUrl(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onerror = reject;
            reader.onload = () => {
                const img = new Image();
                img.onerror = reject;
                img.onload = () => {
                    const scale = Math.min(1, HOME_MAX_PX / Math.max(img.width, img.height));
                    const canvas = document.createElement('canvas');
                    canvas.width = Math.round(img.width * scale);
                    canvas.height = Math.round(img.height * scale);
                    canvas.getContext('2d').drawImage(img, 0, 0, canvas.width, canvas.height);
                    resolve(canvas.toDataURL('image/jpeg', 0.82));
                };
                img.src = reader.result;
            };
            reader.readAsDataURL(file);
        });
    }

    function renderHome(container, list) {
        const state = loadHome();
        const byKey = new Map(list.map(d => [deviceKey(d), d]));

        container.innerHTML = `
            <div class="home-toolbar">
                <label class="ds-btn ds-btn--secondary ds-btn--sm home-upload">
                    <svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-upload"/></svg>
                    <span>${esc(tr('home_upload_background', 'Background image'))}</span>
                    <input type="file" accept="image/*" hidden id="homeBgInput">
                </label>
                <button type="button" class="ds-btn ds-btn--ghost ds-btn--sm" id="homeResetBg">
                    ${esc(tr('home_default_background', 'Default plan'))}
                </button>
                <button type="button" class="ds-btn ds-btn--ghost ds-btn--sm" id="homeClearPins">
                    ${esc(tr('home_clear_pins', 'Clear pins'))}
                </button>
                <span class="home-hint">${esc(tr('home_drag_hint', 'Drag a device from the list onto the plan. Drag a pin to move it, double-click to remove it. Room names are editable.'))}</span>
            </div>
            <div class="home-layout">
                <div class="home-canvas" id="homeCanvas">
                    ${state.bg ? `<img class="home-bg" src="${esc(state.bg)}" alt="">` : defaultFloorPlan(state)}
                    <div class="home-pins" id="homePins"></div>
                </div>
                <aside class="home-tray" id="homeTray">
                    <h4>${esc(tr('home_unplaced', 'Not placed'))} <span class="ds-badge" id="homeUnplacedCount">0</span></h4>
                    <div class="home-tray__list" id="homeTrayList"></div>
                </aside>
            </div>`;

        const canvas = container.querySelector('#homeCanvas');
        const pinLayer = container.querySelector('#homePins');
        const trayList = container.querySelector('#homeTrayList');

        function persist() { saveHome(state); }

        // Room names and the plan title are the user's words; keep them.
        container.querySelectorAll('[data-room]').forEach(node => {
            node.addEventListener('blur', () => {
                const text = node.textContent.trim();
                if (node.dataset.room === 'title') state.title = text || tr('home_network', 'Home network');
                else state.rooms[+node.dataset.room] = text;
                persist();
            });
            node.addEventListener('keydown', e => {
                if (e.key === 'Enter') { e.preventDefault(); node.blur(); }
            });
        });

        function toFraction(e) {
            const rect = canvas.getBoundingClientRect();
            return {
                x: Math.min(1, Math.max(0, (e.clientX - rect.left) / rect.width)),
                y: Math.min(1, Math.max(0, (e.clientY - rect.top) / rect.height)),
            };
        }

        function redrawTray() {
            const left = list.filter(d => !(deviceKey(d) in state.pins));
            container.querySelector('#homeUnplacedCount').textContent = left.length;
            trayList.innerHTML = left.length
                ? byGroup(left).map(g => `
                    <div class="home-tray__group">
                        <div class="home-tray__heading">
                            <i class="view-legend__dot view-legend__dot--${g.color}"></i>
                            ${esc(g.label)} <span class="home-tray__count">${g.members.length}</span>
                        </div>
                        ${g.members.map(d => `
                            <button type="button" class="home-tray__item" data-key="${esc(deviceKey(d))}" title="${esc(d.ip || d.mac || '')}">
                                <span class="home-tray__icon">${icon(d)}</span>
                                <span class="home-tray__name">${esc(label(d))}</span>
                            </button>`).join('')}
                    </div>`).join('')
                : `<p class="home-tray__empty">${esc(tr('home_all_placed', 'Every device is on the plan.'))}</p>`;

            trayList.querySelectorAll('.home-tray__item').forEach(btn => {
                btn.addEventListener('pointerdown', e => {
                    e.preventDefault();
                    const key = btn.dataset.key;
                    if (!byKey.has(key)) return;
                    state.pins[key] = toFraction(e);
                    redraw();
                    const pin = pinLayer.querySelector(`[data-key="${cssEscape(key)}"]`);
                    if (pin) startDrag(e, pin, key);
                });
            });
        }

        function redrawPins() {
            pinLayer.innerHTML = Object.entries(state.pins)
                .filter(([key]) => byKey.has(key))
                .map(([key, pos]) => {
                    const d = byKey.get(key);
                    return `<button type="button" class="home-pin ${d.status === 'online' ? 'is-online' : 'is-offline'}"
                                data-key="${esc(key)}" style="left:${(pos.x * 100).toFixed(2)}%;top:${(pos.y * 100).toFixed(2)}%"
                                title="${esc(label(d))} — ${esc(d.ip || d.mac || '')}">
                                <span class="home-pin__icon">${icon(d)}</span>
                                <span class="home-pin__label">${esc(label(d))}</span>
                            </button>`;
                }).join('');
            pinLayer.querySelectorAll('.home-pin').forEach(pin => {
                pin.addEventListener('pointerdown', e => startDrag(e, pin, pin.dataset.key));
                pin.addEventListener('dblclick', () => {
                    delete state.pins[pin.dataset.key];
                    persist();
                    redraw();
                });
            });
        }

        function redraw() { redrawPins(); redrawTray(); }

        // ponytail: one pointer-based drag path for both "move an existing pin"
        // and "drop a new one from the tray". HTML5 dragstart/drop would need a
        // second one for touch.
        function startDrag(event, pin, key) {
            event.preventDefault();
            pin.classList.add('is-dragging');
            const move = e => {
                const p = toFraction(e);
                state.pins[key] = p;
                pin.style.left = (p.x * 100).toFixed(2) + '%';
                pin.style.top = (p.y * 100).toFixed(2) + '%';
            };
            const up = () => {
                pin.classList.remove('is-dragging');
                window.removeEventListener('pointermove', move);
                window.removeEventListener('pointerup', up);
                persist();
                redrawTray();
            };
            window.addEventListener('pointermove', move);
            window.addEventListener('pointerup', up);
        }

        container.querySelector('#homeBgInput').addEventListener('change', async e => {
            const file = e.target.files[0];
            if (!file) return;
            state.bg = await toScaledDataUrl(file);
            if (saveHome(state)) renderHome(container, list);
        });
        container.querySelector('#homeResetBg').addEventListener('click', () => {
            state.bg = null;
            persist();
            renderHome(container, list);
        });
        container.querySelector('#homeClearPins').addEventListener('click', () => {
            state.pins = {};
            persist();
            redraw();
        });

        redraw();
    }

    function cssEscape(s) {
        return (window.CSS && CSS.escape) ? CSS.escape(s) : s.replace(/["\\]/g, '\\$&');
    }

    /** Built-in plan so the view is useful before anyone uploads anything.
        Plain HTML, not SVG, so the room names are directly editable. */
    function defaultFloorPlan(state) {
        return `
        <div class="home-plan">
            <div class="home-plan__roof"></div>
            <div class="home-plan__title" data-room="title" contenteditable="true"
                 spellcheck="false">${esc(state.title)}</div>
            <div class="home-plan__rooms">
                ${state.rooms.map((name, i) => `
                    <div class="home-room">
                        <span class="home-room__name" data-room="${i}" contenteditable="true"
                              spellcheck="false" title="${esc(tr('home_rename_room', 'Click to rename'))}">${esc(name)}</span>
                    </div>`).join('')}
            </div>
        </div>`;
    }

    // ------------------------------------------------------------ export

    /* Export the current graph/topology SVG as a self-contained .svg or a
       rasterised .png. The live SVG is styled by external sheets, so we inline
       every same-origin rule into the clone - otherwise a standalone file (and
       the canvas raster) would lose all colour and stroke. */
    function collectCss() {
        let css = '';
        for (const sheet of document.styleSheets) {
            try { for (const rule of sheet.cssRules) css += rule.cssText + '\n'; }
            catch (_) { /* cross-origin sheet - skip */ }
        }
        return css;
    }

    function downloadBlob(blob, name) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = name;
        document.body.appendChild(a); a.click(); a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    function exportSvg(svgEl, container, baseName, asPng) {
        const vb = svgEl.viewBox.baseVal;
        const w = Math.round(vb.width || svgEl.clientWidth || 900);
        const h = Math.round(vb.height || svgEl.clientHeight || 700);

        const clone = svgEl.cloneNode(true);
        clone.setAttribute('width', w);
        clone.setAttribute('height', h);
        clone.setAttribute('xmlns', SVG_NS);

        // Opaque background so a PNG isn't transparent; use the surface colour
        // the container actually resolves to (respects light/dark).
        const bgColor = getComputedStyle(container).backgroundColor || '#ffffff';
        const bg = el('rect', { x: vb.x, y: vb.y, width: w, height: h, fill: bgColor });
        clone.insertBefore(bg, clone.firstChild);

        const style = document.createElementNS(SVG_NS, 'style');
        style.textContent = collectCss();
        clone.insertBefore(style, clone.firstChild);

        const xml = new XMLSerializer().serializeToString(clone);
        if (!asPng) {
            downloadBlob(new Blob([xml], { type: 'image/svg+xml;charset=utf-8' }), baseName + '.svg');
            return;
        }
        const img = new Image();
        img.onload = () => {
            const scale = 2;                     // crisp on hi-dpi / when zoomed
            const canvas = document.createElement('canvas');
            canvas.width = w * scale; canvas.height = h * scale;
            const ctx = canvas.getContext('2d');
            ctx.scale(scale, scale);
            ctx.drawImage(img, 0, 0);
            canvas.toBlob(b => downloadBlob(b, baseName + '.png'), 'image/png');
        };
        img.onerror = () => (typeof showToast === 'function') && showToast(tr('export_failed', 'Export failed'), 'error');
        img.src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(xml);
    }

    /** Floating SVG/PNG export control, top-right of a graph/topology stage. */
    function addExportControl(container, svgEl, baseName) {
        const box = document.createElement('div');
        box.className = 'view-export';
        box.innerHTML =
            `<button type="button" class="view-export__btn" data-fmt="png">PNG</button>` +
            `<button type="button" class="view-export__btn" data-fmt="svg">SVG</button>`;
        box.querySelectorAll('.view-export__btn').forEach(btn =>
            btn.addEventListener('click', () => exportSvg(svgEl, container, baseName, btn.dataset.fmt === 'png')));
        container.appendChild(box);
    }

    // ------------------------------------------------------------ public API

    window.MynesViews = {
        render(view, devicesList) {
            const container = document.getElementById({
                graph: 'graphContainer',
                topology: 'topologyContainer',
                home: 'homeContainer',
            }[view]);
            if (!container) return;
            if (view === 'graph') renderGraph(container, devicesList);
            else if (view === 'topology') renderTopology(container, devicesList);
            else if (view === 'home') renderHome(container, devicesList);
        },
        // exported for tests / console poking
        _internals: { groupOf, byGroup, deviceClass, deviceKey, layoutForce, layoutTree, isInfra,
                      buildTopoTree, buildGraphModel },
    };
})();
