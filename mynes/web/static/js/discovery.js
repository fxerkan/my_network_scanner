/* Multi-protocol discovery page. */
(function () {
  'use strict';

  var api = window.MyNeS.api;
  var toast = window.MyNeS.toast;
  var $ = function (id) { return document.getElementById(id); };
  var lastResults = [];

  var PROTOCOL_META = {
    mdns: { label: 'mDNS / Bonjour', icon: '#i-wifi', blurb: 'Printers, NAS, Chromecast, HomeKit, Matter, Raspberry Pi' },
    ssdp: { label: 'SSDP / UPnP',    icon: '#i-router', blurb: 'Routers, smart TVs, DLNA, cameras, consoles' },
    onvif:{ label: 'ONVIF / RTSP',   icon: '#i-scan', blurb: 'IP cameras, doorbells, NVRs — name, model and stream URL' },
    dhcp: { label: 'DHCP (passive)', icon: '#i-network', blurb: 'Hostnames devices give themselves when they renew a lease' },
    mqtt: { label: 'MQTT',           icon: '#i-cpu',  blurb: 'Zigbee2MQTT, Z-Wave JS, Tasmota, Home Assistant' },
    ble:  { label: 'Bluetooth LE',   icon: '#i-bluetooth', blurb: 'Trackers, sensors, wearables, headphones' }
  };

  /* Which protocols to sweep. Empty selection = all, same as the API default. */
  var DISABLED_KEY = 'mynes.discovery.disabled';
  function disabledSet() {
    try { return new Set(JSON.parse(localStorage.getItem(DISABLED_KEY) || '[]')); }
    catch (e) { return new Set(); }
  }
  function setDisabled(name, off) {
    var s = disabledSet();
    if (off) { s.add(name); } else { s.delete(name); }
    localStorage.setItem(DISABLED_KEY, JSON.stringify(Array.from(s)));
  }

  function esc(v) { var d = document.createElement('div'); d.textContent = v == null ? '' : String(v); return d.innerHTML; }

  function renderProtocols(rows) {
    var off = disabledSet();
    $('protocolGrid').innerHTML = rows.map(function (p) {
      var meta = PROTOCOL_META[p.name] || { label: p.name, icon: '#i-plug', blurb: '' };
      var ok = p.available !== false && p.status !== 'skipped';
      return '<div class="ds-stat ds-row" style="align-items:flex-start">' +
        '<input type="checkbox" class="protocol-toggle" data-protocol="' + esc(p.name) + '"' +
          (off.has(p.name) ? '' : ' checked') + ' aria-label="Sweep ' + esc(meta.label) + '">' +
        '<svg class="ds-icon ds-icon--lg" aria-hidden="true" style="color:var(--' + (ok ? 'accent-text' : 'text-tertiary') + ')"><use href="' + meta.icon + '"/></svg>' +
        '<div style="flex:1;min-width:0">' +
          '<div class="ds-row" style="gap:var(--space-2)">' +
            '<strong>' + esc(meta.label) + '</strong>' +
            '<span class="ds-badge ds-badge--' + (ok ? 'success' : 'offline') + '">' +
              '<span class="ds-dot' + (ok ? ' ds-dot--online' : '') + '"></span>' + (ok ? 'ready' : 'unavailable') +
            '</span>' +
            (p.count != null ? '<span class="ds-badge">' + p.count + ' found</span>' : '') +
          '</div>' +
          '<div class="ds-dim" style="font-size:var(--text-xs);margin-top:var(--space-1)">' +
            esc(ok ? meta.blurb : (p.detail || '')) +
          '</div>' +
        '</div>' +
      '</div>';
    }).join('');

    Array.prototype.forEach.call($('protocolGrid').querySelectorAll('.protocol-toggle'), function (cb) {
      cb.addEventListener('change', function () { setDisabled(cb.dataset.protocol, !cb.checked); });
    });
  }

  function selectedProtocols() {
    return Array.prototype.filter.call(
      $('protocolGrid').querySelectorAll('.protocol-toggle'), function (cb) { return cb.checked; }
    ).map(function (cb) { return cb.dataset.protocol; });
  }

  function renderResults(filter) {
    var rows = lastResults;
    if (filter) {
      var q = filter.toLowerCase();
      rows = rows.filter(function (d) {
        return JSON.stringify([d.name, d.ip, d.mac, d.vendor, d.device_type, d.services]).toLowerCase().indexOf(q) > -1;
      });
    }

    $('resultCount').textContent = lastResults.length;
    $('resultCount').hidden = !lastResults.length;

    if (!rows.length) {
      $('resultHost').innerHTML = '<div class="ds-empty"><div class="ds-empty__title">No matches</div></div>';
      return;
    }

    $('resultHost').innerHTML = '<div class="ds-table-wrap"><table class="ds-table">' +
      '<thead><tr><th>Device</th><th>Address</th><th>Type</th><th>Seen via</th><th>Services</th></tr></thead><tbody>' +
      rows.map(function (d) {
        var sources = (d.sources || []).map(function (s) {
          return '<span class="ds-badge ds-badge--info">' + esc(s) + '</span>';
        }).join(' ');
        var services = (d.services || []).slice(0, 4).map(function (s) {
          return '<span class="ds-badge">' + esc(s) + '</span>';
        }).join(' ');
        var extra = (d.services || []).length > 4 ? ' <span class="ds-dim">+' + ((d.services.length) - 4) + '</span>' : '';
        var matter = d.attributes && d.attributes.matter ? ' <span class="ds-badge ds-badge--success">Matter</span>' : '';
        return '<tr>' +
          '<td><div>' + esc(d.name || '(unnamed)') + matter + '</div>' +
            (d.vendor ? '<div class="ds-dim">' + esc(d.vendor) + '</div>' : '') + '</td>' +
          '<td class="mono">' + esc(d.ip || d.mac || '—') + '</td>' +
          '<td>' + esc(d.device_type || '—') + '</td>' +
          '<td>' + sources + '</td>' +
          '<td>' + services + extra + '</td>' +
        '</tr>';
      }).join('') +
      '</tbody></table></div>';
  }

  function runSweep() {
    var btn = $('sweepBtn');
    var seconds = Number($('sweepTimeout').value);
    var chosen = selectedProtocols();
    if (!chosen.length) { toast('Pick at least one protocol.', 'warning'); return; }
    btn.disabled = true;
    btn.innerHTML = '<span class="ds-spinner"></span> Listening ' + seconds + 's…';
    $('resultHost').innerHTML = '<div class="ds-card__body ds-stack">' +
      '<div class="ds-skeleton" style="height:40px"></div>'.repeat(4) + '</div>';

    api('/api/discovery?timeout=' + seconds + '&protocols=' + encodeURIComponent(chosen.join(',')))
      .then(function (data) {
        lastResults = data.devices || [];
        $('applyBtn').disabled = !lastResults.length;
        renderProtocols(Object.keys(data.protocols || {}).map(function (name) {
          return Object.assign({ name: name }, data.protocols[name]);
        }));
        renderResults($('resultSearch').value);
        toast(lastResults.length + ' devices answered across ' + Object.keys(data.protocols).length + ' protocols.', 'success');
      })
      .catch(function (e) { toast('Sweep failed: ' + e.message, 'critical'); })
      .finally(function () {
        btn.disabled = false;
        btn.innerHTML = '<svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-radar"/></svg> Run sweep';
      });
  }

  function applyToDevices() {
    var btn = $('applyBtn');
    btn.disabled = true;
    api('/api/discovery/apply', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ devices: lastResults })
    })
      .then(function (r) {
        var created = r.created
          ? ' ' + r.created + ' radio-only devices added (BLE trackers, headphones).'
          : '';
        var extra = r.unmatched.length
          ? ' ' + r.unmatched.length + ' had no matching device (not yet scanned).'
          : '';
        toast(r.updated + ' devices enriched.' + created + extra,
              (r.updated || r.created) ? 'success' : 'info');
      })
      .catch(function (e) { toast('Save failed: ' + e.message, 'critical'); })
      .finally(function () { btn.disabled = !lastResults.length; });
  }

  function loadHomeAssistant() {
    api('/api/integrations/home-assistant').then(function (s) {
      if (!s.configured) {
        $('haBody').innerHTML = '<div class="ds-alert">' +
          '<svg class="ds-alert__icon ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-info"/></svg>' +
          '<div><strong>Not connected.</strong> Set <code>MYNES_HA_URL</code> and <code>MYNES_HA_TOKEN</code> ' +
          '(Home Assistant → profile → Security → Long-lived access tokens) to compare what HA sees ' +
          'with what MyNeS finds, including Zigbee, Z-Wave and Matter devices.</div></div>';
        return;
      }
      $('haBody').innerHTML = '<div class="ds-alert ds-alert--' + (s.ok ? 'success' : 'critical') + '">' +
        '<svg class="ds-alert__icon ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-' + (s.ok ? 'check' : 'alert') + '"/></svg>' +
        '<span>' + (s.ok ? 'Connected to ' + esc(s.location_name || s.url) + ' (' + esc(s.version || '?') + ')' : esc(s.error)) + '</span></div>';
    });
  }

  function compareWithHA() {
    var btn = $('haCompareBtn'); btn.disabled = true;
    api('/api/integrations/home-assistant/compare')
      .then(function (c) {
        $('haBody').innerHTML =
          '<div class="ds-grid ds-grid--stats" style="margin-bottom:var(--space-4)">' +
            '<div class="ds-stat"><div class="ds-stat__value">' + c.mynes_total + '</div><div class="ds-stat__label">MyNeS</div></div>' +
            '<div class="ds-stat"><div class="ds-stat__value">' + c.home_assistant_total + '</div><div class="ds-stat__label">Home Assistant</div></div>' +
            '<div class="ds-stat ds-stat--online"><div class="ds-stat__value">' + c.in_both + '</div><div class="ds-stat__label">In both</div></div>' +
            '<div class="ds-stat ds-stat--warning"><div class="ds-stat__value">' + c.only_in_home_assistant.length + '</div><div class="ds-stat__label">Only in HA</div></div>' +
          '</div>' +
          '<h3>Only Home Assistant sees these</h3>' +
          '<div class="ds-table-wrap"><table class="ds-table"><thead><tr><th>Entity</th><th>Name</th><th>State</th></tr></thead><tbody>' +
          c.only_in_home_assistant.slice(0, 100).map(function (d) {
            return '<tr><td class="mono">' + esc(d.entity_id) + '</td><td>' + esc(d.name) + '</td><td>' + esc(d.state) + '</td></tr>';
          }).join('') + '</tbody></table></div>';
      })
      .catch(function (e) { toast('Compare failed: ' + e.message, 'critical'); })
      .finally(function () { btn.disabled = false; });
  }


  /* ---------------- System setup ------------------------------------------ */
  function renderSystem(caps) {
    var priv = caps.privileges || {};
    var svc = caps.service || {};
    var rows = [];

    // Scanning depth: the single most common cause of "it only finds 3 devices".
    var rawOk = caps.raw_sockets && caps.raw_sockets.available;
    rows.push(
      '<div class="ds-alert ds-alert--' + (rawOk ? 'success' : 'warning') + '">' +
        '<svg class="ds-alert__icon ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-' + (rawOk ? 'check' : 'alert') + '"/></svg>' +
        '<div style="flex:1">' +
          '<strong>Scanning depth: ' + (rawOk ? 'full (raw ARP)' : 'limited (ping sweep)') + '</strong>' +
          '<div class="ds-muted" style="margin-top:var(--space-1)">' + esc(priv.summary || '') + '</div>' +
          (!rawOk && (priv.commands || []).length
            ? '<details style="margin-top:var(--space-2)">' +
                '<summary style="cursor:pointer">Show the commands to fix this permanently</summary>' +
                '<pre class="ds-scroll-x" style="background:var(--bg-surface-sunken);padding:var(--space-3);' +
                  'border-radius:var(--radius-md);margin-top:var(--space-2);font-size:var(--text-xs)">' +
                  esc(priv.commands.join('\n')) + '</pre>' +
                (priv.needs_logout ? '<div class="ds-dim">Takes effect after you log out and back in.</div>' : '') +
                (priv.notes || []).map(function (n) { return '<div class="ds-dim">! ' + esc(n) + '</div>'; }).join('') +
              '</details>'
            : '') +
        '</div>' +
      '</div>'
    );

    if (!caps.nmap || !caps.nmap.available) {
      rows.push(
        '<div class="ds-alert ds-alert--warning">' +
          '<svg class="ds-alert__icon ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-alert"/></svg>' +
          '<div><strong>nmap not installed.</strong> ' + esc(caps.nmap.detail) + '</div></div>'
      );
    }

    rows.push(
      '<div class="ds-row" style="padding:var(--space-3);border:1px solid var(--border-subtle);border-radius:var(--radius-md)">' +
        '<svg class="ds-icon" aria-hidden="true"><use href="#i-refresh"/></svg>' +
        '<div style="flex:1;min-width:0">' +
          '<strong>Background service</strong>' +
          '<div class="ds-muted">' + esc(svc.detail || '') + '</div>' +
          '<div class="ds-dim" style="font-size:var(--text-xs)">Keeps scheduled scanning running without a browser open.</div>' +
        '</div>' +
        '<span class="ds-badge ds-badge--' + (svc.running ? 'success' : 'offline') + '">' +
          '<span class="ds-dot' + (svc.running ? ' ds-dot--online' : '') + '"></span>' +
          (svc.running ? 'running' : svc.installed ? 'stopped' : 'not installed') + '</span>' +
        // No button where there is nothing to install into - a container has
        // no init system, and the scheduler is already running in-process.
        (svc.supported === false ? '' :
          '<button class="ds-btn ds-btn--sm" id="svcToggle">' +
          (svc.installed ? 'Uninstall' : 'Install') + '</button>') +
      '</div>'
    );

    rows.push(
      '<div class="ds-row" style="padding:var(--space-3);border:1px solid var(--border-subtle);border-radius:var(--radius-md)">' +
        '<svg class="ds-icon" aria-hidden="true"><use href="#i-network"/></svg>' +
        '<div style="flex:1;min-width:0">' +
          '<strong>Tray / menu bar icon</strong>' +
          '<div class="ds-muted">' + (caps.tray && caps.tray.available
            ? 'Available. Start it with <code>python -m mynes.tray</code>.'
            : 'Not installed. <code>pip install "mynes[tray]"</code>') + '</div>' +
        '</div>' +
        '<span class="ds-badge ds-badge--' + (caps.tray && caps.tray.available ? 'success' : 'offline') + '">' +
          (caps.tray && caps.tray.available ? 'available' : 'missing') + '</span>' +
      '</div>'
    );

    $('systemBody').innerHTML = rows.join('');

    var toggle = $('svcToggle');
    if (toggle) {
      toggle.addEventListener('click', function () {
        var action = svc.installed ? 'uninstall' : 'install';
        toggle.disabled = true;
        api('/api/platform/service/' + action, { method: 'POST' })
          .then(function (r) {
            toast(r.detail || (r.ok ? 'Done.' : 'Failed.'), r.ok ? 'success' : 'critical');
            return loadSystem();
          })
          .catch(function (e) { toast('Failed: ' + e.message, 'critical'); toggle.disabled = false; });
      });
    }
  }

  function loadSystem() {
    return api('/api/capabilities').then(renderSystem).catch(function (e) {
      $('systemBody').innerHTML = '<div class="ds-alert ds-alert--critical">' +
        '<svg class="ds-alert__icon ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-alert"/></svg>' +
        '<span>' + esc(e.message) + '</span></div>';
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    $('sweepBtn').addEventListener('click', runSweep);
    $('applyBtn').addEventListener('click', applyToDevices);
    $('haCompareBtn').addEventListener('click', compareWithHA);
    $('resultSearch').addEventListener('input', function () { renderResults(this.value); });

    api('/api/discovery/protocols').then(function (d) { renderProtocols(d.protocols); });
    loadHomeAssistant();
    loadSystem();
  });
})();
