/* Alerts & monitoring page. Talks to /api/monitoring/*, /api/alerts, /api/notifications/*. */
(function () {
  'use strict';

  var api = window.MyNeS.api;
  var toast = window.MyNeS.toast;

  var settings = null;
  var $ = function (id) { return document.getElementById(id); };

  function esc(value) {
    var d = document.createElement('div');
    d.textContent = value == null ? '' : String(value);
    return d.innerHTML;
  }

  function relativeTime(iso) {
    if (!iso) return '—';
    var diff = (Date.now() - new Date(iso).getTime()) / 1000;
    if (diff < 60) return 'just now';
    if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    return Math.floor(diff / 86400) + 'd ago';
  }

  /* ---------------- Channel field definitions ---------------------------- */
  var CHANNEL_FIELDS = {
    ntfy: [
      { key: 'topic', label: 'Topic', hint: 'Subscribe to the same topic in the ntfy app.', required: true },
      { key: 'server', label: 'Server', value: 'https://ntfy.sh' },
      { key: 'token', label: 'Access token (optional)', type: 'password' }
    ],
    telegram: [
      { key: 'bot_token', label: 'Bot token', hint: 'From @BotFather.', required: true, type: 'password' },
      { key: 'chat_id', label: 'Chat ID', required: true }
    ],
    webhook: [{ key: 'url', label: 'URL', hint: 'Receives the full alert as JSON.', required: true }],
    slack:   [{ key: 'url', label: 'Incoming webhook URL', required: true }],
    discord: [{ key: 'url', label: 'Webhook URL', required: true }],
    smtp: [
      { key: 'host', label: 'SMTP host', required: true },
      { key: 'port', label: 'Port', value: '587', type: 'number' },
      { key: 'username', label: 'Username' },
      { key: 'password', label: 'Password', type: 'password' },
      { key: 'from', label: 'From address', required: true },
      { key: 'to', label: 'To address', required: true }
    ]
  };

  function renderChannelFields() {
    var fields = CHANNEL_FIELDS[$('chType').value] || [];
    $('chFields').innerHTML = fields.map(function (f) {
      return '<div class="ds-field">' +
        '<label class="ds-label" for="ch_' + f.key + '">' + esc(f.label) + '</label>' +
        '<input class="ds-input" id="ch_' + f.key + '" type="' + (f.type || 'text') + '"' +
          (f.value ? ' value="' + esc(f.value) + '"' : '') +
          (f.required ? ' required' : '') + '>' +
        (f.hint ? '<span class="ds-hint">' + esc(f.hint) + '</span>' : '') +
      '</div>';
    }).join('');
  }

  function collectChannel() {
    var type = $('chType').value;
    var cfg = { type: type, enabled: true, min_severity: $('chMinSeverity').value };
    (CHANNEL_FIELDS[type] || []).forEach(function (f) {
      var el = $('ch_' + f.key);
      if (el && el.value) cfg[f.key] = f.key === 'port' ? Number(el.value) : el.value;
    });
    return cfg;
  }

  /* ---------------- Settings --------------------------------------------- */
  function loadSettings() {
    return api('/api/monitoring/settings').then(function (data) {
      settings = data;
      $('monEnabled').checked = !!data.enabled;
      $('monEnabledLabel').textContent = data.enabled ? 'Enabled' : 'Disabled';
      $('monInterval').value = String(data.interval_minutes);
      $('monDiscovery').checked = !!data.run_discovery;
      $('monMqtt').checked = !!data.publish_to_mqtt;
      var th = data.thresholds || {};
      $('monOfflineScans').value = String(th.offline_scans || 2);
      $('monVoltage').value = th.voltage_min != null ? th.voltage_min : 4.7;
      $('monBattery').value = th.battery_percent != null ? th.battery_percent : 20;
      $('monLatency').value = th.latency_ms != null ? th.latency_ms : 500;
      renderChannels();
    });
  }

  function saveSettings() {
    var patch = {
      enabled: $('monEnabled').checked,
      interval_minutes: Number($('monInterval').value),
      run_discovery: $('monDiscovery').checked,
      publish_to_mqtt: $('monMqtt').checked,
      notify_channels: (settings && settings.notify_channels) || [],
      thresholds: Object.assign({}, (settings && settings.thresholds) || {}, {
        offline_scans: Number($('monOfflineScans').value),
        voltage_min: Number($('monVoltage').value),
        battery_percent: Number($('monBattery').value),
        latency_ms: Number($('monLatency').value)
      })
    };
    return api('/api/monitoring/settings', { method: 'POST', body: patch })
      .then(function (data) {
        settings = data;
        toast('Schedule saved.', 'success');
        return loadStatus();
      })
      .catch(function (e) { toast('Could not save: ' + e.message, 'critical'); });
  }

  function renderChannels() {
    var list = (settings && settings.notify_channels) || [];
    var host = $('channelList');
    if (!list.length) {
      host.innerHTML = '<div class="ds-empty">' +
        '<svg class="ds-icon ds-icon--xl ds-empty__icon" aria-hidden="true"><use href="#i-bell"/></svg>' +
        '<div class="ds-empty__title">No channels yet</div>' +
        '<p class="ds-muted" style="margin:0 auto">Alerts are recorded here regardless. Add a channel to get pushed to your phone, Telegram or email.</p>' +
        '</div>';
      return;
    }
    host.innerHTML = list.map(function (c, i) {
      var target = c.topic || c.url || c.chat_id || c.host || '';
      return '<div class="ds-row" style="padding:var(--space-3);border:1px solid var(--border-subtle);border-radius:var(--radius-md)">' +
        '<span class="ds-badge ' + (c.enabled === false ? '' : 'ds-badge--success') + '">' + esc(c.type) + '</span>' +
        '<span class="ds-truncate" style="max-width:32ch">' + esc(target) + '</span>' +
        '<span class="ds-dim">≥ ' + esc(c.min_severity || 'info') + '</span>' +
        '<span class="ds-spacer"></span>' +
        '<button class="ds-btn ds-btn--sm" data-test="' + i + '">Test</button>' +
        '<button class="ds-btn ds-btn--sm ds-btn--danger" data-remove="' + i + '" aria-label="Remove channel">' +
          '<svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-trash"/></svg></button>' +
      '</div>';
    }).join('');

    host.querySelectorAll('[data-test]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var cfg = settings.notify_channels[Number(btn.dataset.test)];
        btn.disabled = true;
        api('/api/notifications/test', { method: 'POST', body: cfg })
          .then(function (r) { toast(r.ok ? 'Test sent.' : 'Test failed: ' + r.error, r.ok ? 'success' : 'critical'); })
          .catch(function (e) { toast('Test failed: ' + e.message, 'critical'); })
          .finally(function () { btn.disabled = false; });
      });
    });
    host.querySelectorAll('[data-remove]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        settings.notify_channels.splice(Number(btn.dataset.remove), 1);
        saveSettings().then(renderChannels);
      });
    });
  }

  /* ---------------- Status & feed ---------------------------------------- */
  function loadStatus() {
    return api('/api/monitoring/status').then(function (s) {
      var a = s.alerts || {};
      $('statTotal').textContent = a.total || 0;
      $('statUnread').textContent = a.unread || 0;
      $('statCritical').textContent = (a.by_severity && a.by_severity.critical) || 0;
      $('statSchedule').textContent = s.enabled ? 'every ' + s.interval_minutes + ' min' : 'off';

      var line = s.running ? 'Scheduler running.' : 'Scheduler stopped.';
      if (s.last_run) line += ' Last scan ' + relativeTime(s.last_run) + '.';
      if (s.next_run_in_seconds != null) line += ' Next in ' + Math.ceil(s.next_run_in_seconds / 60) + ' min.';
      if (s.last_error) line += ' Last error: ' + s.last_error;
      $('monStatusLine').textContent = line;
    });
  }

  function loadFeed() {
    var sev = $('severityFilter').value;
    return api('/api/alerts?limit=200' + (sev ? '&severity=' + sev : '')).then(function (data) {
      var host = $('alertFeed');
      if (!data.alerts.length) {
        host.innerHTML = '<div class="ds-empty">' +
          '<svg class="ds-icon ds-icon--xl ds-empty__icon" aria-hidden="true"><use href="#i-check"/></svg>' +
          '<div class="ds-empty__title">Nothing to report</div>' +
          '<p class="ds-muted" style="margin:0 auto">No alerts recorded. That is the good outcome.</p></div>';
        return;
      }
      host.innerHTML = '<div class="ds-table-wrap"><table class="ds-table">' +
        '<thead><tr><th>Severity</th><th>Alert</th><th>Device</th><th>When</th></tr></thead><tbody>' +
        data.alerts.map(function (a) {
          return '<tr' + (a.read ? '' : ' style="font-weight:var(--weight-medium)"') + '>' +
            '<td><span class="ds-badge ds-badge--' + esc(a.severity) + '">' + esc(a.severity) + '</span></td>' +
            '<td><div>' + esc(a.title) + '</div><div class="ds-dim">' + esc(a.message) + '</div></td>' +
            '<td class="mono">' + esc(a.ip || a.mac || '—') + '</td>' +
            '<td class="ds-dim" title="' + esc(a.timestamp) + '">' + esc(relativeTime(a.timestamp)) + '</td>' +
          '</tr>';
        }).join('') +
        '</tbody></table></div>';
    });
  }

  /* ---------------- Wiring ------------------------------------------------ */
  function openModal(open) {
    $('channelModal').hidden = !open;
    if (open) { renderChannelFields(); $('chType').focus(); }
  }

  document.addEventListener('DOMContentLoaded', function () {
    $('monEnabled').addEventListener('change', function () {
      $('monEnabledLabel').textContent = this.checked ? 'Enabled' : 'Disabled';
    });
    $('saveMonBtn').addEventListener('click', saveSettings);
    $('severityFilter').addEventListener('change', loadFeed);

    $('runNowBtn').addEventListener('click', function () {
      var btn = this;
      btn.disabled = true;
      btn.innerHTML = '<span class="ds-spinner"></span> Scanning…';
      api('/api/monitoring/run', { method: 'POST' })
        .then(function (r) {
          toast('Scan done: ' + r.devices + ' devices, ' + r.alerts + ' alerts.', r.alerts ? 'warning' : 'success');
          return Promise.all([loadStatus(), loadFeed(), window.MyNeS.refreshAlertBadge()]);
        })
        .catch(function (e) { toast('Scan failed: ' + e.message, 'critical'); })
        .finally(function () {
          btn.disabled = false;
          btn.innerHTML = '<svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-play"/></svg> Run scan now';
        });
    });

    $('markReadBtn').addEventListener('click', function () {
      api('/api/alerts/read', { method: 'POST', body: {} })
        .then(function () { return Promise.all([loadFeed(), loadStatus(), window.MyNeS.refreshAlertBadge()]); });
    });

    $('clearAlertsBtn').addEventListener('click', function () {
      if (!window.confirm('Delete the whole alert history?')) return;
      api('/api/alerts', { method: 'DELETE' })
        .then(function () { return Promise.all([loadFeed(), loadStatus(), window.MyNeS.refreshAlertBadge()]); });
    });

    $('addChannelBtn').addEventListener('click', function () { openModal(true); });
    $('closeChannelModal').addEventListener('click', function () { openModal(false); });
    $('chType').addEventListener('change', renderChannelFields);
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && !$('channelModal').hidden) openModal(false);
    });

    $('testChannelBtn').addEventListener('click', function () {
      var btn = this; btn.disabled = true;
      api('/api/notifications/test', { method: 'POST', body: collectChannel() })
        .then(function (r) {
          $('chTestResult').innerHTML = '<div class="ds-alert ds-alert--' + (r.ok ? 'success' : 'critical') + '">' +
            '<svg class="ds-alert__icon ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-' + (r.ok ? 'check' : 'alert') + '"/></svg>' +
            '<span>' + esc(r.ok ? 'Delivered. Check your device.' : r.error) + '</span></div>';
        })
        .finally(function () { btn.disabled = false; });
    });

    $('saveChannelBtn').addEventListener('click', function () {
      settings.notify_channels = (settings.notify_channels || []).concat([collectChannel()]);
      saveSettings().then(function () { renderChannels(); openModal(false); $('chTestResult').innerHTML = ''; });
    });

    loadSettings().then(loadStatus).then(loadFeed);
  });
})();
