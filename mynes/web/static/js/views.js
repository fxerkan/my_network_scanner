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
        box.className = 'view-legend';
        box.innerHTML = classes
            .map(([cls, name]) => `<span class="view-legend__item"><i class="view-legend__dot view-legend__dot--${cls}"></i>${esc(name)}</span>`)
            .join('') + (extra || '');
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

    function buildGraphModel(list) {
        const nodes = [], links = [], hubIndexes = [];
        const bySubnet = new Map();
        const radio = [];

        list.forEach(d => {
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

            seg.members.forEach(d => {
                const idx = nodes.push({
                    hub: false,
                    r: d.status === 'online' ? 13 : 10,
                    name: label(d), sub: d.ip || d.mac || '',
                    device: d, cls: deviceClass(d), offline: d.status !== 'online',
                }) - 1;
                links.push([hubIndex, idx]);
            });
        });

        // Hubs form a ring so separate subnets read as one network, not islands.
        for (let i = 1; i < hubIndexes.length; i++) links.push([hubIndexes[i - 1], hubIndexes[i]]);
        if (hubIndexes.length > 2) links.push([hubIndexes[hubIndexes.length - 1], hubIndexes[0]]);

        return { nodes, links };
    }

    function renderGraph(container, list) {
        if (!list.length) return emptyState(container);

        const { nodes, links } = buildGraphModel(list);
        layoutForce(nodes, links, 900, 700);

        const pad = 60;
        const xs = nodes.map(n => n.x), ys = nodes.map(n => n.y);
        const minX = Math.min(...xs) - pad, maxX = Math.max(...xs) + pad;
        const minY = Math.min(...ys) - pad, maxY = Math.max(...ys) + pad;

        container.innerHTML = '';
        const svg = el('svg', {
            class: 'graph-svg',
            viewBox: `${minX} ${minY} ${maxX - minX} ${maxY - minY}`,
            role: 'img',
            'aria-label': tr('graph_view', 'Network graph'),
        }, container);

        const edgeLayer = el('g', { class: 'graph-edges' }, svg);
        links.forEach(([ai, bi]) => {
            const a = nodes[ai], b = nodes[bi];
            el('line', { x1: a.x, y1: a.y, x2: b.x, y2: b.y }, edgeLayer);
        });

        const nodeLayer = el('g', {}, svg);
        nodes.forEach(n => {
            const g = el('g', {
                class: `graph-node graph-node--${n.cls}` + (n.hub ? ' is-hub' : '') + (n.offline ? ' is-offline' : ''),
                tabindex: '0', role: 'button',
            }, nodeLayer);
            el('title', {}, g).textContent = `${n.name}\n${n.sub}`;
            el('circle', { cx: n.x, cy: n.y, r: n.r }, g);
            const text = el('text', { x: n.x, y: n.y + n.r + 14, 'text-anchor': 'middle' }, g);
            text.textContent = n.hub ? n.name : clip(n.name, 16);
            if (n.device) {
                const open = () => openDeviceDetails(n.device);
                g.addEventListener('click', open);
                g.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); } });
            }
        });

        container.appendChild(legend());
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
        const root = buildTopoTree(list, topo);
        const cursor = { n: 0 };
        layoutTree(root, 0, cursor);
        applyOrientation(root);

        const depth = (function maxDepth(n, d) {
            return n.children.length ? Math.max(...n.children.map(c => maxDepth(c, d + 1))) : d;
        })(root, 0);
        const step = SPACING[topoOrientation] || SPACING.vertical;
        const acrossSize = Math.max(cursor.n * step.across, 640);
        const depthSize = TOP + depth * step.depth + 90;
        const horizontal = topoOrientation === 'horizontal';
        const width = horizontal ? depthSize + 120 : acrossSize;
        const height = horizontal ? acrossSize : depthSize;

        container.innerHTML = '';
        container.appendChild(topoToolbar(container, list));

        // Drawn 1:1 in px and scrolled horizontally - scaling a wide tree down
        // to the viewport turns every caption into a smear.
        const scroller = document.createElement('div');
        scroller.className = 'topo-scroller';
        container.appendChild(scroller);
        const svg = el('svg', {
            class: 'topo-svg', viewBox: `0 0 ${width} ${height}`, width, height,
            role: 'img', 'aria-label': tr('topology_view', 'Network topology'),
        }, scroller);

        const edges = el('g', { class: 'topo-edges' }, svg);
        const nodeLayer = el('g', {}, svg);

        (function walk(node) {
            drawTopoNode(nodeLayer, node, container, list);
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

        container.appendChild(legend(
            `<span class="view-legend__item"><i class="view-legend__line"></i>${tr('uplink_known', 'Known uplink')}</span>
             <span class="view-legend__item"><i class="view-legend__line view-legend__line--dashed"></i>${tr('uplink_assumed', 'Assumed direct')}</span>`
        ));
        scroller.classList.toggle('is-horizontal', horizontal);
        if (!horizontal) scroller.scrollLeft = (width - scroller.clientWidth) / 2;
    }

    function drawTopoNode(layer, node, container, list) {
        const isLeaf = node.kind === 'leaf';
        const d = node.device;
        const name = d ? label(d) : node.name;
        const sub = d ? (d.ip || d.mac || '') : (node.count != null ? String(node.count) : '');
        const g = el('g', {
            class: `topo-node topo-kind--${node.kind} topo-node--${node.cls}`
                + (d && d.status && d.status !== 'online' ? ' is-offline' : ''),
            transform: `translate(${node.x},${node.y})`,
        }, layer);
        el('title', {}, g).textContent = sub ? `${name}\n${sub}` : name;
        el('circle', { cx: 0, cy: 0, r: isLeaf ? 16 : 22 }, g);
        const glyph = el('text', { class: 'topo-glyph', x: 0, y: 6, 'text-anchor': 'middle' }, g);
        glyph.textContent = d ? icon(d)
            : (node.kind === 'root' ? '🌐' : (GROUP_ICONS[node.groupKey] || '❓'));

        // Captions go under the node when the tree grows downwards, and to its
        // right when it grows sideways - otherwise they overlap the next row.
        const side = topoOrientation === 'horizontal';
        const capAttrs = side
            ? { x: (isLeaf ? 22 : 28), y: 0, 'text-anchor': 'start' }
            : { x: 0, y: isLeaf ? 34 : 42, 'text-anchor': 'middle' };
        const cap = el('text', { class: 'topo-caption', ...capAttrs }, g);
        cap.textContent = clip(name, 15);
        if (sub) {
            const subAttrs = side
                ? { x: (isLeaf ? 22 : 28), y: 13, 'text-anchor': 'start' }
                : { x: 0, y: isLeaf ? 47 : 56, 'text-anchor': 'middle' };
            const s = el('text', { class: 'topo-sub', ...subAttrs }, g);
            s.textContent = clip(sub, 18);
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
        _internals: { groupOf, byGroup, deviceClass, deviceKey, layoutForce, layoutTree, isInfra, buildTopoTree },
    };
})();
