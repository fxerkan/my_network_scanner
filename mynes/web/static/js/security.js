/* Security page. Fleet-wide risk dashboard: overall posture, severity
 * distribution, prioritised action items, and a collapsible per-device
 * drilldown with bulk acknowledge / watch / export / re-scan.
 * Talks to /api/security/*. */
(function () {
  'use strict';

  var api = window.MyNeS.api;
  var toast = window.MyNeS.toast;
  var $ = function (id) { return document.getElementById(id); };

  var overview = null;                 // last /api/security/overview response
  var selected = new Set();            // "ip key" of picked findings
  var deviceMeta = {};                 // ip -> {name, vendor, device_type} from /devices
  var expanded = new Set();            // ips whose detail row is open

  // Per-device table view state.
  var view = {
    search: '',
    sev: 'all',                        // all | critical | high | medium | low
    sortKey: 'score',                  // score | findings | device
    sortDir: 'desc',                   // asc | desc
    focusIps: null,                    // Set of ips to restrict to (action-item click)
    focusTitle: '',                    // human label of the focused finding
    focusKey: ''                       // finding key we jumped to (expand highlights it)
  };

  var CVE_RE = /^CVE-\d{4}-\d+$/i;
  // Link CVEs to CVE.org (the authoritative record). NVD detail pages have
  // been flaky (502 Bad Gateway); cve.org is the primary source anyway.
  function cveUrl(id) { return 'https://www.cve.org/CVERecord?id=' + encodeURIComponent(id); }

  function esc(v) {
    var d = document.createElement('div');
    d.textContent = v == null ? '' : String(v);
    return d.innerHTML;
  }

  // i18n: window.t() returns the key itself when a string is missing, so wrap
  // it with a fallback the same way filters.js/views.js do.
  function tr(key, fallback) {
    var s = (typeof window.t === 'function') ? window.t(key) : key;
    return (s === key || s == null) ? fallback : s;
  }

  var SEV_BADGE = { critical: 'ds-badge--critical', high: 'ds-badge--critical',
                    medium: 'ds-badge--warning', low: 'ds-badge--info', none: 'ds-badge--success' };
  var RISK_BADGE = SEV_BADGE;

  // Severity buckets, worst first - shared by the distribution bar, the legend
  // and the action-item ordering so the four colours stay consistent.
  var SEVERITIES = ['critical', 'high', 'medium', 'low'];
  var SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, none: 4 };
  // Maps a severity to the design-system token used for the gauge/score colour.
  var SEV_TOKEN = {
    critical: 'var(--severity-critical-fg)',
    high: 'var(--severity-critical-border)',
    medium: 'var(--severity-warning-fg)',
    low: 'var(--severity-info-fg)',
    none: 'var(--text-tertiary)'
  };

  var SEV_FALLBACK = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', none: 'None' };
  function sevLabel(sev) { return tr('security_sev_' + sev, SEV_FALLBACK[sev] || sev); }
  function riskLabel(level) { return sevLabel(level || 'none'); }

  function selKey(ip, key) { return ip + ' ' + key; }

  /* -------------------------------------------- fleet-level derivations --- */
  // Overall fleet risk score (0-100). Kept deliberately simple and explained
  // here: it is the worst single device (a critical host makes the whole fleet
  // critical) nudged up by how *many* hosts are at risk - one bad box vs a
  // dozen bad boxes should not read the same. worst + min(spread, 20) where
  // spread = 4 points per at-risk host beyond the first, capped so the headline
  // never runs away from the true worst-case.
  function fleetScore(devices) {
    var scored = devices.filter(function (d) { return (d.risk_score || 0) > 0; });
    if (!scored.length) return 0;
    var worst = scored.reduce(function (m, d) { return Math.max(m, d.risk_score || 0); }, 0);
    var spread = Math.min((scored.length - 1) * 4, 20);
    return Math.min(100, worst + spread);
  }

  // Reuse cve.py's documented buckets so the headline matches a device's level.
  function fleetLevel(score, devices) {
    var hasCritical = devices.some(function (d) { return d.risk_level === 'critical'; });
    if (hasCritical || score >= 70) return 'critical';
    if (score >= 40) return 'high';
    if (score >= 15) return 'medium';
    if (score > 0) return 'low';
    return 'none';
  }

  // Count active (non-acknowledged) findings + exposures by severity.
  function severityCounts(devices) {
    var counts = { critical: 0, high: 0, medium: 0, low: 0 };
    devices.forEach(function (d) {
      (d.findings || []).concat(d.exposures || []).forEach(function (it) {
        if (it.acknowledged) return;
        if (counts[it.severity] != null) counts[it.severity] += 1;
      });
    });
    return counts;
  }

  // Aggregate identical findings/exposures (by key) across devices into a
  // de-duplicated, severity-then-reach ordered "fix this first" list.
  function actionItems(devices) {
    var byKey = {};
    devices.forEach(function (d) {
      (d.findings || []).concat(d.exposures || []).forEach(function (it) {
        if (it.acknowledged) return;
        var k = it.key || it.title;
        var entry = byKey[k];
        if (!entry) {
          entry = byKey[k] = {
            key: k, title: it.title, severity: it.severity, cve_id: it.cve_id,
            description: it.description, ips: []
          };
        }
        if (entry.ips.indexOf(d.ip) === -1) entry.ips.push(d.ip);
      });
    });
    return Object.keys(byKey).map(function (k) { return byKey[k]; })
      .sort(function (a, b) {
        var s = (SEV_RANK[a.severity] || 9) - (SEV_RANK[b.severity] || 9);
        return s !== 0 ? s : b.ips.length - a.ips.length;
      });
  }

  /* -------------------------------------------------------- render ------- */
  function renderPosture(devices) {
    var score = fleetScore(devices);
    var level = fleetLevel(score, devices);
    var token = SEV_TOKEN[level] || SEV_TOKEN.none;
    var ring = $('secGaugeRing');
    ring.style.setProperty('--sec-gauge-pct', score + '%');
    ring.style.setProperty('--sec-risk-fg', token);
    ring.setAttribute('aria-label', tr('security_posture_title', 'Fleet risk posture') +
      ': ' + score + '/100 (' + riskLabel(level) + ')');
    $('secGaugeScore').textContent = score;
    $('secGaugeLevel').textContent = riskLabel(level);

    $('secStatDevices').textContent = devices.length;
    $('secStatAtRisk').textContent = overview.at_risk_count || 0;
    $('secStatFindings').textContent = overview.total_findings || 0;
    $('secStatExposures').textContent = overview.total_exposures || 0;
  }

  function renderDistribution(devices) {
    var counts = severityCounts(devices);
    var total = SEVERITIES.reduce(function (n, s) { return n + counts[s]; }, 0);
    $('secDistTotal').textContent = total
      ? tr('security_dist_total', '{n} active').replace('{n}', total)
      : '';

    var bar = $('secSegbar');
    if (!total) {
      bar.innerHTML = '';
    } else {
      bar.innerHTML = SEVERITIES.map(function (s) {
        var pct = (counts[s] / total) * 100;
        if (pct <= 0) return '';
        return '<div class="sec-segbar__seg sec-segbar__seg--' + s + '" style="flex:0 0 ' +
          pct.toFixed(2) + '%" title="' + esc(sevLabel(s) + ': ' + counts[s]) + '"></div>';
      }).join('');
    }

    $('secLegend').innerHTML = SEVERITIES.map(function (s) {
      return '<span class="sec-legend__item">' +
        '<span class="sec-legend__dot sec-legend__dot--' + s + '"></span>' +
        esc(sevLabel(s)) + ' <span class="sec-legend__count">' + counts[s] + '</span>' +
        '</span>';
    }).join('');
  }

  function renderActions(devices) {
    var items = actionItems(devices).slice(0, 8);
    $('secActionsEmpty').hidden = items.length > 0;
    $('secActions').innerHTML = items.map(function (it, i) {
      var affected = tr('security_affected', '{n} device(s)').replace('{n}', it.ips.length);
      var cveBadge = (it.cve_id && CVE_RE.test(it.cve_id)) ? ' <code>' + esc(it.cve_id) + '</code>' : '';
      // The whole item is a button that filters the per-device table down to
      // just the hosts this finding affects (see focusAction).
      return '<li class="sec-action sec-action--' + esc(it.severity) + '">' +
          '<span class="sec-action__rank">' + (i + 1) + '</span>' +
          '<button class="sec-action__body sec-action__btn" data-key="' + esc(it.key) + '"' +
            ' data-title="' + esc(it.title) + '" data-ips="' + esc(it.ips.join(',')) + '">' +
            '<div class="sec-action__title">' +
              '<span class="ds-badge ' + (SEV_BADGE[it.severity] || 'ds-badge--info') + '">' +
                esc(sevLabel(it.severity).toUpperCase()) + '</span> ' +
              esc(it.title) + cveBadge +
            '</div>' +
            (it.description ? '<div class="sec-action__desc">' + esc(it.description) + '</div>' : '') +
            '<div class="sec-action__meta">' +
              '<span class="sec-action__count">' + esc(affected) + '</span>' +
              '<svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-filter"/></svg>' +
            '</div>' +
          '</button>' +
        '</li>';
    }).join('');
  }

  /* ----------------------------------------------- device metadata ------- */
  // /api/security/overview only carries ip + risk data; join it against the
  // full device list (/devices) so the table can show a name, vendor and type.
  function metaFor(ip) { return deviceMeta[ip] || {}; }
  function deviceName(dev) {
    var m = metaFor(dev.ip);
    return m.alias || m.name || m.hostname || dev.ip;
  }
  // Pick a semantic sprite icon from the device type (emoji-as-icon is banned;
  // the device-type emoji the user picks is content, not chrome, and lives in
  // the name column text - the leading glyph here is a design-system icon).
  function deviceIconId(dev) {
    var t = (metaFor(dev.ip).device_type || '').toLowerCase();
    if (/router|gateway|firewall/.test(t)) return 'i-router';
    if (/phone|mobile|tablet|watch|wearable/.test(t)) return 'i-wifi';
    if (/bluetooth|ble/.test(t)) return 'i-bluetooth';
    if (/server|nas|pi|computer|laptop|desktop|workstation/.test(t)) return 'i-cpu';
    if (/camera|nvr|dvr|iot|sensor|smart|home|hub|plug/.test(t)) return 'i-home';
    return 'i-network';
  }

  /* --------------------------------------------- per-device table view --- */
  // The set of ips shown in the table after search + severity + focus filter,
  // in the current sort order.
  function tableDevices() {
    var devices = (overview ? overview.devices : []).filter(function (d) {
      return (d.findings || []).length || (d.exposures || []).length;
    });

    var q = view.search.trim().toLowerCase();
    if (q) {
      devices = devices.filter(function (d) {
        var m = metaFor(d.ip);
        var hay = [d.ip, m.name, m.alias, m.hostname, m.vendor, m.device_type]
          .filter(Boolean).join(' ').toLowerCase();
        return hay.indexOf(q) !== -1;
      });
    }

    if (view.sev !== 'all') {
      devices = devices.filter(function (d) {
        return (d.findings || []).concat(d.exposures || []).some(function (it) {
          return !it.acknowledged && it.severity === view.sev;
        });
      });
    }

    if (view.focusIps) {
      devices = devices.filter(function (d) { return view.focusIps.has(d.ip); });
    }

    var dir = view.sortDir === 'asc' ? 1 : -1;
    devices = devices.slice().sort(function (a, b) {
      var av, bv;
      if (view.sortKey === 'findings') {
        av = (a.findings || []).length; bv = (b.findings || []).length;
      } else if (view.sortKey === 'device') {
        return deviceName(a).localeCompare(deviceName(b)) * dir;
      } else {
        av = a.risk_score || 0; bv = b.risk_score || 0;
      }
      return (av - bv) * dir;
    });
    return devices;
  }

  function itemDetail(dev, item, highlight) {
    var sk = selKey(dev.ip, item.key);
    var checked = selected.has(sk) ? 'checked' : '';
    var sevClass = SEV_BADGE[item.severity] || 'ds-badge--info';
    var tags = '';
    if (item.acknowledged) tags += ' <span class="ds-badge ds-badge--success">' +
      esc(tr('security_tag_ack', 'acknowledged')) + '</span>';
    if (item.watched) tags += ' <span class="ds-badge ds-badge--info">' +
      esc(tr('security_tag_watched', 'watched')) + '</span>';

    // A real CVE id becomes a badge linking to CVE.org; a non-CVE exposure
    // shows its title only, no link.
    var idBadge = '';
    if (item.cve_id && CVE_RE.test(item.cve_id)) {
      idBadge = ' <a class="sec-cve" href="' + esc(cveUrl(item.cve_id)) +
        '" target="_blank" rel="noopener noreferrer" title="' +
        esc(tr('security_view_cve', 'View {id} on CVE.org').replace('{id}', item.cve_id)) + '">' +
        '<code>' + esc(item.cve_id) + '</code>' +
        '<svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-external"/></svg></a>';
    }

    var cls = 'sec-detail__item' + (item.acknowledged ? ' sec-detail__item--ack' : '') +
      (highlight ? ' sec-detail__item--focus' : '');
    return '<li class="' + cls + '">' +
        '<input type="checkbox" class="sec-item" data-ip="' + esc(dev.ip) + '" data-key="' +
             esc(item.key) + '" data-sev="' + esc(item.severity) + '" data-title="' +
             esc(item.title) + '" ' + checked + '>' +
        '<div class="sec-detail__body">' +
          '<div class="sec-detail__head">' +
            '<span class="ds-badge ' + sevClass + '">' + esc(sevLabel(item.severity).toUpperCase()) + '</span> ' +
            '<strong>' + esc(item.title) + '</strong>' + idBadge + tags +
          '</div>' +
          (item.description ?
            '<div class="sec-detail__desc">' +
              '<span class="sec-detail__label">' + esc(tr('security_suggested_action', 'Suggested action')) + '</span> ' +
              esc(item.description) +
            '</div>' : '') +
        '</div>' +
      '</li>';
  }

  function detailRow(dev) {
    var findings = dev.findings || [];
    var exposures = dev.exposures || [];
    var fk = view.focusKey;
    var sections = '';
    if (findings.length) {
      sections += '<div class="sec-detail__group"><h4 class="sec-detail__title">' +
        esc(tr('security_findings_label', 'CVE findings')) + '</h4><ul class="sec-detail__list">' +
        findings.map(function (it) { return itemDetail(dev, it, fk && it.key === fk); }).join('') +
        '</ul></div>';
    }
    if (exposures.length) {
      sections += '<div class="sec-detail__group"><h4 class="sec-detail__title">' +
        esc(tr('security_exposures_label', 'Exposures')) + '</h4><ul class="sec-detail__list">' +
        exposures.map(function (it) { return itemDetail(dev, it, fk && it.key === fk); }).join('') +
        '</ul></div>';
    }
    return '<tr class="sec-detailrow" data-ip="' + esc(dev.ip) + '">' +
        '<td colspan="7"><div class="sec-detail">' + sections + '</div></td>' +
      '</tr>';
  }

  function deviceRow(dev) {
    var isOpen = expanded.has(dev.ip);
    var isFocus = view.focusIps && view.focusIps.has(dev.ip);
    var riskClass = RISK_BADGE[dev.risk_level] || 'ds-badge--info';
    var rowChecked = deviceFullySelected(dev) ? 'checked' : '';
    var rowCls = 'sec-row' + (isOpen ? ' sec-row--open' : '') + (isFocus ? ' sec-row--focus' : '');
    return '<tr class="' + rowCls + '" data-ip="' + esc(dev.ip) + '">' +
        '<td class="sec-table__check">' +
          '<input type="checkbox" class="sec-device" data-ip="' + esc(dev.ip) + '" ' + rowChecked +
          ' aria-label="' + esc(tr('security_select_row', 'Select device')) + '"></td>' +
        '<td>' +
          '<div class="sec-devcell sec-devcell--clickable" data-ip="' + esc(dev.ip) + '"' +
            ' role="button" tabindex="0" title="' + esc(tr('security_expand', 'Show details')) + '">' +
            '<svg class="ds-icon ds-icon--sm sec-devcell__icon" aria-hidden="true"><use href="#' +
              deviceIconId(dev) + '"/></svg>' +
            '<div class="sec-devcell__text">' +
              '<span class="sec-devcell__name">' + esc(deviceName(dev)) + '</span>' +
              '<span class="sec-devcell__ip ds-muted">' + esc(dev.ip) + '</span>' +
            '</div>' +
          '</div>' +
        '</td>' +
        '<td><span class="ds-badge ' + riskClass + '">' +
          esc(riskLabel(dev.risk_level).toUpperCase()) + '</span></td>' +
        '<td class="sec-table__num">' + (dev.risk_score != null ? dev.risk_score : 0) + '</td>' +
        '<td class="sec-table__num">' + (dev.findings || []).length + '</td>' +
        '<td class="sec-table__num">' + (dev.exposures || []).length + '</td>' +
        '<td class="sec-table__details">' +
          '<button class="ds-btn ds-btn--sm sec-expand" data-ip="' + esc(dev.ip) + '"' +
            ' aria-expanded="' + (isOpen ? 'true' : 'false') + '">' +
            '<svg class="ds-icon ds-icon--sm sec-expand__chevron" aria-hidden="true"><use href="#i-chevron-down"/></svg>' +
            '<span>' + esc(isOpen ? tr('security_collapse_row', 'Hide details')
                                  : tr('security_expand', 'Show details')) + '</span>' +
          '</button>' +
        '</td>' +
      '</tr>' + (isOpen ? detailRow(dev) : '');
  }

  function renderTable() {
    var rows = tableDevices();
    var withItems = (overview ? overview.devices : []).filter(function (d) {
      return (d.findings || []).length || (d.exposures || []).length;
    });
    $('secDevicesCount').textContent = withItems.length;
    $('secEmpty').hidden = withItems.length > 0;
    $('secNoMatch').hidden = !(withItems.length > 0 && rows.length === 0);
    $('secTbody').innerHTML = rows.map(deviceRow).join('');
    syncSortHeaders();
  }

  function syncSortHeaders() {
    document.querySelectorAll('.sec-th--sortable').forEach(function (th) {
      var active = th.dataset.sort === view.sortKey;
      th.classList.toggle('sec-th--active', active);
      var arrow = th.querySelector('.sec-th__arrow');
      if (arrow) arrow.textContent = active ? (view.sortDir === 'asc' ? '▲' : '▼') : '';
    });
  }

  function renderFilterNote() {
    var note = $('secFilterNote');
    if (!view.focusIps) { note.hidden = true; return; }
    note.hidden = false;
    $('secFilterNoteText').textContent = tr('security_filtered_note',
      'Showing {n} device(s) affected by {title}.')
      .replace('{n}', view.focusIps.size).replace('{title}', view.focusTitle);
  }

  function render() {
    if (!overview) return;
    var devices = overview.devices || [];

    renderPosture(devices);
    renderDistribution(devices);
    renderActions(devices);

    renderFilterNote();
    renderTable();
    syncSelectionUI();
  }

  /* ----------------------------------------------------- selection ------- */
  function allItemKeys() {
    var out = [];
    (overview ? overview.devices : []).forEach(function (d) {
      (d.findings || []).concat(d.exposures || []).forEach(function (it) {
        out.push(selKey(d.ip, it.key));
      });
    });
    return out;
  }

  // A device row's checkbox is checked when every item of that device is picked.
  function deviceItemKeys(dev) {
    return (dev.findings || []).concat(dev.exposures || [])
      .map(function (it) { return selKey(dev.ip, it.key); });
  }
  function deviceFullySelected(dev) {
    var keys = deviceItemKeys(dev);
    return keys.length > 0 && keys.every(function (k) { return selected.has(k); });
  }

  function syncSelectionUI() {
    document.querySelectorAll('.sec-item').forEach(function (cb) {
      cb.checked = selected.has(selKey(cb.dataset.ip, cb.dataset.key));
    });
    var byIp = {};
    (overview ? overview.devices : []).forEach(function (d) { byIp[d.ip] = d; });
    document.querySelectorAll('.sec-device').forEach(function (cb) {
      var d = byIp[cb.dataset.ip];
      cb.checked = d ? deviceFullySelected(d) : false;
    });
    var n = selected.size;
    $('secSelCount').textContent = tr('security_selected', '{n} selected').replace('{n}', n);
    ['secAck', 'secUnack', 'secWatch', 'secExport', 'secRescan'].forEach(function (id) {
      $(id).disabled = n === 0;
    });
    var all = allItemKeys();
    var allChecked = all.length > 0 && n === all.length;
    $('secSelectAll').checked = allChecked;
    if ($('secSelectAllHead')) $('secSelectAllHead').checked = allChecked;
  }

  function selectedItems() {
    // resolve the picked "ip key" back to full item objects
    var byKey = {};
    (overview ? overview.devices : []).forEach(function (d) {
      (d.findings || []).concat(d.exposures || []).forEach(function (it) {
        byKey[selKey(d.ip, it.key)] = { ip: d.ip, key: it.key, title: it.title,
                                        severity: it.severity, cve_id: it.cve_id,
                                        description: it.description, device: d };
      });
    });
    return Array.from(selected).map(function (sk) { return byKey[sk]; }).filter(Boolean);
  }

  /* -------------------------------------------------------- actions ------ */
  // The overview endpoint carries only ip + risk data. Pull the full device
  // list once so the table can label rows with a name/vendor/type. A failure
  // here degrades to ip-only labels, never breaks the page.
  function loadDeviceMeta() {
    return api('/devices').then(function (data) {
      var list = Array.isArray(data) ? data : (data ? Object.keys(data).map(function (k) { return data[k]; }) : []);
      var map = {};
      list.forEach(function (d) {
        if (!d || !d.ip) return;
        map[d.ip] = { name: d.name, alias: d.alias, hostname: d.hostname,
                      vendor: d.vendor, device_type: d.device_type };
      });
      deviceMeta = map;
    }).catch(function () { deviceMeta = {}; });
  }

  function load() {
    return Promise.all([
      api('/api/security/overview'),
      loadDeviceMeta()
    ]).then(function (res) {
      overview = res[0];
      // drop stale selections
      var live = new Set(allItemKeys());
      Array.from(selected).forEach(function (k) { if (!live.has(k)) selected.delete(k); });
      // a focus filter that no longer matches anything is dropped
      if (view.focusIps) {
        var present = new Set((overview.devices || []).map(function (d) { return d.ip; }));
        var kept = Array.from(view.focusIps).filter(function (ip) { return present.has(ip); });
        if (!kept.length) clearFocus(); else view.focusIps = new Set(kept);
      }
      render();
    }).catch(function (e) { toast(tr('security_load_failed', 'Load failed') + ': ' + e.message, 'error'); });
  }

  function acknowledge(accepted) {
    var items = selectedItems().map(function (i) { return { ip: i.ip, key: i.key }; });
    if (!items.length) return;
    api('/api/security/acknowledge', { method: 'POST', body: { items: items, accepted: accepted } })
      .then(function () {
        var msg = (accepted ? tr('security_toast_acked', 'Acknowledged {n} finding(s)')
                            : tr('security_toast_unacked', 'Un-acknowledged {n} finding(s)'))
                    .replace('{n}', items.length);
        toast(msg, 'success');
        return load();
      }).catch(function (e) { toast(e.message, 'error'); });
  }

  function watch() {
    var items = selectedItems().map(function (i) {
      return { ip: i.ip, key: i.key, title: i.title, severity: i.severity };
    });
    if (!items.length) return;
    api('/api/security/watch', { method: 'POST', body: { items: items, active: true } })
      .then(function (r) {
        var msg = tr('security_toast_watching', 'Watching {n} finding(s); {a} alert(s) raised')
                    .replace('{n}', items.length).replace('{a}', r.alerts_created || 0);
        toast(msg, 'success');
        return load();
      }).catch(function (e) { toast(e.message, 'error'); });
  }

  function exportReport() {
    var rows = [['ip', 'device', 'severity', 'title', 'cve', 'suggested_action']];
    selectedItems().forEach(function (i) {
      rows.push([i.ip, deviceName(i.device), i.severity, i.title,
                 i.cve_id || '', (i.description || '').replace(/\s+/g, ' ')]);
    });
    var csv = rows.map(function (r) {
      return r.map(function (c) { return '"' + String(c == null ? '' : c).replace(/"/g, '""') + '"'; }).join(',');
    }).join('\n');
    var blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'mynes-security-report.csv';
    a.click();
    URL.revokeObjectURL(a.href);
    toast(tr('security_toast_exported', 'Exported {n} finding(s)').replace('{n}', rows.length - 1), 'success');
  }

  /* On-demand security scan: kick off a fresh network scan (which refreshes
     every device's fingerprint), show live progress, then re-run the
     assessment against the CURRENT CVE database and surface the new score.
     Progress from /progress is status+message (no %), so the bar is
     indeterminate while scanning and fills on completion. */
  var scanPoll = null;

  function setScanning(on) {
    var btn = $('secScan'), bar = $('secScanBar');
    if (btn) { btn.disabled = on; btn.classList.toggle('is-busy', on); }
    if (bar) bar.hidden = !on;
    var fill = $('secScanFill');
    if (fill) fill.classList.toggle('sec-scan__fill--busy', on);
  }

  function runScan() {
    if (scanPoll) return;                       // already running
    setScanning(true);
    $('secScanMsg').textContent = tr('security_scan_running', 'Scanning the network…');
    $('secScanCount').textContent = '';
    // Start the scan; a 400 "already scanning" is fine - we just watch it.
    api('/scan').catch(function () { /* may already be running */ }).then(pollScan);
  }

  function pollScan() {
    scanPoll = setInterval(function () {
      api('/progress').then(function (p) {
        if (p.message) $('secScanMsg').textContent = p.message;
        if (p.devices_found != null) {
          $('secScanCount').textContent = tr('security_scan_found', '{n} devices')
            .replace('{n}', p.devices_found);
        }
        if (p.status === 'completed' || p.status === 'idle' || p.status === 'stopped' || p.status === 'error') {
          clearInterval(scanPoll); scanPoll = null;
          finishScan(p.status);
        }
      }).catch(function () { clearInterval(scanPoll); scanPoll = null; finishScan('error'); });
    }, 1500);
  }

  function finishScan(status) {
    // Fill the bar, reload the assessment against the current CVE DB, then
    // report the fresh fleet score so the user can act.
    var fill = $('secScanFill');
    if (fill) { fill.classList.remove('sec-scan__fill--busy'); fill.style.width = '100%'; }
    if (status === 'error') {
      setScanning(false);
      toast(tr('security_scan_failed', 'Scan failed'), 'error');
      return;
    }
    load().then(function () {
      setScanning(false);
      if (fill) fill.style.width = '';
      var devs = (overview && overview.devices) || [];
      var score = fleetScore(devs);
      var level = sevLabel(fleetLevel(score, devs));
      var atRisk = devs.filter(function (d) { return (d.risk_score || 0) > 0; }).length;
      toast(tr('security_scan_done', 'Scan complete — fleet risk {level} ({score}/100), {n} at risk')
        .replace('{level}', level).replace('{score}', score).replace('{n}', atRisk), 'success');
    });
  }

  function rescan() {
    var ips = Array.from(new Set(selectedItems().map(function (i) { return i.ip; })));
    if (!ips.length) return;
    api('/api/security/rescan', { method: 'POST', body: { ips: ips } })
      .then(function (r) {
        toast(r.message || tr('security_toast_rescan', 'Re-scan started for {n} device(s)')
          .replace('{n}', ips.length), 'success');
        // give the background analysis a moment, then refresh
        setTimeout(load, 4000);
      }).catch(function (e) { toast(e.message, 'error'); });
  }

  /* ------------------------------------------------- focus / locate ------ */
  function deviceByIp(ip) {
    return (overview ? overview.devices : []).find(function (d) { return d.ip === ip; });
  }

  function clearFocus() {
    view.focusIps = null;
    view.focusTitle = '';
    view.focusKey = '';
  }

  // Click on a "What to fix first" item: narrow the table to just the affected
  // hosts, expand them so the relevant finding is visible + highlighted, scroll
  // the table into view.
  function focusAction(btn) {
    var ips = (btn.dataset.ips || '').split(',').filter(Boolean);
    if (!ips.length) return;
    view.focusIps = new Set(ips);
    view.focusTitle = btn.dataset.title || '';
    view.focusKey = btn.dataset.key || '';
    view.search = '';
    view.sev = 'all';
    if ($('secSearch')) $('secSearch').value = '';
    if ($('secSevFilter')) $('secSevFilter').value = 'all';
    ips.forEach(function (ip) { expanded.add(ip); });
    // make sure the collapsible section is open
    if ($('secDevicesToggle').getAttribute('aria-expanded') !== 'true') toggleDevices();
    render();
    $('secTable').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  /* ---------------------------------------------------------- wire ------- */
  // One delegated change handler for every checkbox in the table body.
  function onTableChange(e) {
    var cb = e.target;
    if (!cb.classList) return;
    if (cb.classList.contains('sec-item')) {
      var sk = selKey(cb.dataset.ip, cb.dataset.key);
      if (cb.checked) selected.add(sk); else selected.delete(sk);
      syncSelectionUI();
    } else if (cb.classList.contains('sec-device')) {
      var dev = deviceByIp(cb.dataset.ip);
      if (!dev) return;
      deviceItemKeys(dev).forEach(function (k) {
        if (cb.checked) selected.add(k); else selected.delete(k);
      });
      syncSelectionUI();
    }
  }

  // Clicks in the table: expand/collapse a device's detail row - via the
  // "Show details" button or by clicking the device name/IP cell itself.
  function onTableClick(e) {
    var trg = e.target.closest ? e.target.closest('.sec-expand, .sec-devcell[data-ip]') : null;
    if (!trg) return;
    var ip = trg.dataset.ip;
    if (expanded.has(ip)) expanded.delete(ip); else expanded.add(ip);
    renderTable();
    syncSelectionUI();
  }

  function onSortClick(e) {
    var th = e.target.closest ? e.target.closest('.sec-th--sortable') : null;
    if (!th) return;
    var key = th.dataset.sort;
    if (view.sortKey === key) {
      view.sortDir = view.sortDir === 'asc' ? 'desc' : 'asc';
    } else {
      view.sortKey = key;
      view.sortDir = key === 'device' ? 'asc' : 'desc';
    }
    renderTable();
    syncSelectionUI();
  }

  function toggleDevices() {
    var btn = $('secDevicesToggle');
    var body = $('secDevicesBody');
    var open = btn.getAttribute('aria-expanded') === 'true';
    btn.setAttribute('aria-expanded', String(!open));
    body.hidden = open;
  }

  function selectAll(checked) {
    selected = checked ? new Set(allItemKeys()) : new Set();
    syncSelectionUI();
  }

  function init() {
    $('secTbody').addEventListener('change', onTableChange);
    $('secTbody').addEventListener('click', onTableClick);
    document.querySelector('.sec-table thead').addEventListener('click', onSortClick);

    $('secSearch').addEventListener('input', function (e) {
      view.search = e.target.value || '';
      renderTable();
      syncSelectionUI();
    });
    $('secSevFilter').addEventListener('change', function (e) {
      view.sev = e.target.value || 'all';
      renderTable();
      syncSelectionUI();
    });
    $('secClearFilter').addEventListener('click', function () {
      clearFocus();
      render();
    });
    $('secActions').addEventListener('click', function (e) {
      var btn = e.target.closest ? e.target.closest('.sec-action__btn') : null;
      if (btn) focusAction(btn);
    });

    $('secScan').addEventListener('click', runScan);
    $('secRefresh').addEventListener('click', load);
    $('secDevicesToggle').addEventListener('click', toggleDevices);
    $('secSelectAll').addEventListener('change', function (e) { selectAll(e.target.checked); });
    $('secSelectAllHead').addEventListener('change', function (e) { selectAll(e.target.checked); });
    $('secAck').addEventListener('click', function () { acknowledge(true); });
    $('secUnack').addEventListener('click', function () { acknowledge(false); });
    $('secWatch').addEventListener('click', watch);
    $('secExport').addEventListener('click', exportReport);
    $('secRescan').addEventListener('click', rescan);
    load();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
