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
    mynes_push: [],
    home_assistant: [
      { key: 'service', label: 'Notify service', value: 'persistent_notification',
        hint: 'e.g. mobile_app_pixel_9. Leave as persistent_notification for the bell icon in HA.' },
      { key: 'url', label: 'Home Assistant URL (optional)', hint: 'Defaults to MYNES_HA_URL from the environment.' },
      { key: 'token', label: 'Long-lived token (optional)', type: 'password', hint: 'Defaults to MYNES_HA_TOKEN.' }
    ],
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


  // Per-type setup instructions. Written against current releases: Home
  // Assistant 2024.10+ uses the plural `triggers:`/`actions:` schema with a
  // `trigger:` key inside the list, not the legacy `trigger:`/`platform:` pair.
  var CHANNEL_GUIDES = {
    mynes_push: {
      title: 'MyNeS push — no relay',
      steps: [
        'Scroll up to <b>Notifications on this device</b> and press <b>Enable on this device</b>. Your browser asks once for permission.',
        'Repeat that on every phone, tablet or laptop that should get alerts — each device registers itself.',
        'Add this channel and pick a severity. From then on every matching alert is pushed to all registered devices.',
        'Install MyNeS to the home screen (Share → Add to Home Screen on iOS) if you want alerts while the browser is closed.'
      ],
      note: 'The alert goes from this server to your device via the browser vendor\'s push service. Nothing is stored or read by anyone else, and no account is needed. iOS only allows web push for apps added to the home screen — that is an Apple restriction, not a MyNeS one.'
    },

    home_assistant: {
      title: 'Home Assistant notify service — direct, no automation needed',
      steps: [
        'Make sure MyNeS already talks to Home Assistant: <code>MYNES_HA_URL</code> and <code>MYNES_HA_TOKEN</code> in your <code>.env</code>. Create the token in HA under your profile → <b>Security</b> → <b>Long-lived access tokens</b>.',
        'Pick the notify service. <code>persistent_notification</code> shows up under the bell icon in HA and always exists.',
        'To get it on your phone instead, use the service the HA companion app created — it looks like <code>mobile_app_&lt;device&gt;</code>. The dropdown below lists what your install actually exposes.',
        'Press <b>Send test</b>. It should arrive in Home Assistant within a second.'
      ],
      note: 'Unlike the Webhook channel, this needs no automation in Home Assistant — MyNeS calls the service directly over the REST API using the token you already have.'
    },

    ntfy: {
      title: 'ntfy — push to your phone, no account needed',
      steps: [
        'Install the <b>ntfy</b> app (App Store / Play Store / F-Droid).',
        'Invent a topic name that is hard to guess — anyone who knows it can read your alerts. Example: <code>mynes-a7f3k9</code>.',
        'In the app tap <b>+</b> and subscribe to that exact topic.',
        'Type the same topic below, then press <b>Send test</b>. The notification should arrive within a second.'
      ],
      note: 'Self-hosting ntfy? Put your own server URL in Server, and an access token if it requires auth.'
    },

    telegram: {
      title: 'Telegram bot',
      steps: [
        'Open <a href="https://t.me/BotFather" target="_blank" rel="noopener">@BotFather</a> in Telegram and send <code>/newbot</code>. Follow the two prompts (display name, then a username ending in <code>bot</code>).',
        'BotFather replies with a <b>bot token</b> like <code>123456789:AAE...</code> — paste it below.',
        'Open a chat with your new bot and send it any message. A bot cannot message you first, so this step is required.',
        'Visit <code>https://api.telegram.org/bot&lt;YOUR_TOKEN&gt;/getUpdates</code> in a browser and copy <code>result[0].message.chat.id</code> — that is your <b>Chat ID</b>.'
      ],
      note: 'For a group: add the bot to the group, send a message there, then use the chat id from getUpdates — group ids are negative, keep the minus sign.'
    },

    webhook: {
      title: 'Home Assistant webhook — two halves, both required',
      steps: [
        '<b>In Home Assistant.</b> Settings → Automations &amp; scenes → Create automation → <b>Create new automation</b>. There is no "webhook" entry in the blueprint list, so start empty, then open the ⋮ menu (top right) → <b>Edit in YAML</b> and paste the block below. Change <code>webhook_id</code> to something only you know, and save.',
        '<b>Copy the URL.</b> It is your Home Assistant address plus the id you just chose:<br><code>http://homeassistant.local:8123/api/webhook/&lt;your-webhook_id&gt;</code>',
        '<b>Back here.</b> Paste that URL in the field below and click <b>Add channel</b>. <i>This is the step that connects the two</i> — the automation does nothing until MyNeS knows where to send.',
        '<b>Check it.</b> Click <b>Send test</b>. A notification appears in Home Assistant under the bell icon within a second. From then on MyNeS POSTs to that URL every time an alert fires at or above the severity you picked above.'
      ],
      yaml: [
        'alias: MyNeS Alert',
        'description: ""',
        'mode: queued',
        'max: 25',
        'triggers:',
        '  - trigger: webhook',
        '    webhook_id: mynes-alert-CHANGE-ME',
        '    allowed_methods:',
        '      - POST',
        '    local_only: true',
        'conditions: []',
        'actions:',
        '  - action: persistent_notification.create',
        '    data:',
        '      title: "{{ trigger.json.title }}"',
        '      message: "{{ trigger.json.message }}"'
      ],
      note: 'Nothing in Home Assistant "runs" this automation — MyNeS triggers it by sending an HTTP POST to the webhook URL. The JSON body carries the whole alert, so you can also use <code>{{ trigger.json.severity }}</code>, <code>{{ trigger.json.rule }}</code>, <code>{{ trigger.json.ip }}</code> and <code>{{ trigger.json.device_name }}</code>. Swap the action for <code>notify.mobile_app_&lt;your-device&gt;</code> to get it on your phone instead of the notifications panel. There is no token or API key: the webhook_id <i>is</i> the secret, so make it long. Keep <code>local_only: true</code> and use the LAN address — with a public URL like home.example.com, local_only would reject MyNeS unless it is on the same network.'
      },

    slack: {
      title: 'Slack incoming webhook',
      steps: [
        'Go to <a href="https://api.slack.com/apps" target="_blank" rel="noopener">api.slack.com/apps</a> → <b>Create New App</b> → <b>From scratch</b>, and pick your workspace.',
        'In the sidebar open <b>Incoming Webhooks</b> and switch it <b>On</b>.',
        'Click <b>Add New Webhook to Workspace</b> and choose the channel to post in.',
        'Copy the generated <code>https://hooks.slack.com/services/...</code> URL below.'
      ]
    },

    discord: {
      title: 'Discord webhook',
      steps: [
        'Right-click the target channel → <b>Edit Channel</b>.',
        'Open <b>Integrations → Webhooks → New Webhook</b>.',
        'Click <b>Copy Webhook URL</b>.',
        'Paste it below.'
      ],
      note: 'You need the Manage Webhooks permission on that server.'
    },

    smtp: {
      title: 'Email (SMTP)',
      steps: [
        '<b>Gmail:</b> turn on 2-step verification, then create an <b>app password</b> at <a href="https://myaccount.google.com/apppasswords" target="_blank" rel="noopener">myaccount.google.com/apppasswords</a>. Host <code>smtp.gmail.com</code>, port <code>587</code>.',
        '<b>Outlook:</b> <code>smtp-mail.outlook.com</code> port <code>587</code>. <b>iCloud:</b> <code>smtp.mail.me.com</code> port <code>587</code> (also needs an app password). <b>Yandex:</b> <code>smtp.yandex.com</code> port <code>465</code>.',
        'Enter the host, port, your address as the username, and the <b>app password</b> — not your normal account password.',
        'Set From to the same mailbox you authenticated with, otherwise the provider rejects the message.'
      ],
      note: 'Port 465 means implicit TLS, 587 means STARTTLS — MyNeS picks the right mode from the port number.'
    }
  };

  function renderChannelGuide() {
    var guide = CHANNEL_GUIDES[$('chType').value];
    var host = $('chGuide');
    if (!guide) { host.innerHTML = ''; return; }

    var yaml = '';
    if (guide.yaml) {
      yaml =
        '<div style="margin-top:var(--space-3)">' +
          '<button type="button" class="ds-btn ds-btn--sm" id="copyYaml" style="float:right">Copy</button>' +
          '<pre class="ds-scroll-x" id="guideYaml" style="background:var(--bg-surface-sunken);border:1px solid var(--border-subtle);' +
            'padding:var(--space-3);border-radius:var(--radius-md);margin:0;font-size:var(--text-xs);line-height:1.5">' +
            esc(guide.yaml.join('\n')) +
          '</pre>' +
        '</div>';
    }

    host.innerHTML =
      '<div class="ds-alert" style="align-items:flex-start">' +
        '<svg class="ds-alert__icon ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-info"/></svg>' +
        '<div style="min-width:0;flex:1">' +
          '<strong>' + guide.title + '</strong>' +
          '<ol style="margin:var(--space-2) 0 0;padding-left:1.2em;line-height:1.6">' +
            guide.steps.map(function (s) { return '<li>' + s + '</li>'; }).join('') +
          '</ol>' +
          yaml +
          (guide.note ? '<div class="ds-dim" style="margin-top:var(--space-3)">' + guide.note + '</div>' : '') +
        '</div>' +
      '</div>';

    var copy = $('copyYaml');
    if (copy) {
      copy.addEventListener('click', function () {
        var text = $('guideYaml').textContent;
        (navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject())
          .then(function () { copy.textContent = 'Copied'; setTimeout(function () { copy.textContent = 'Copy'; }, 1500); })
          .catch(function () { toast('Could not copy — select the text manually.', 'warning'); });
      });
    }
  }

  /* ---------------- MyNeS's own push ------------------------------------ */
  function b64ToUint8(base64) {
    var padded = (base64 + '='.repeat((4 - base64.length % 4) % 4)).replace(/-/g, '+').replace(/_/g, '/');
    var raw = window.atob(padded);
    return Uint8Array.from(raw, function (c) { return c.charCodeAt(0); });
  }

  function pushSupported() {
    return 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;
  }

  function setPushState(state, detail) {
    var badge = $('pushBadge');
    var labels = { on: 'On', off: 'Off', blocked: 'Blocked', unsupported: 'Unsupported', unavailable: 'Unavailable' };
    badge.textContent = labels[state] || state;
    badge.className = 'ds-badge' + (state === 'on' ? ' ds-badge--success' : (state === 'blocked' ? ' ds-badge--critical' : ''));
    $('pushEnableBtn').hidden = state === 'on';
    $('pushTestBtn').hidden = state !== 'on';
    $('pushDisableBtn').hidden = state !== 'on';
    $('pushEnableBtn').disabled = state === 'blocked' || state === 'unsupported' || state === 'unavailable';
    $('pushHint').innerHTML = detail
      ? '<div class="ds-alert ds-alert--' + (state === 'on' ? 'success' : 'info') + '">' +
        '<svg class="ds-alert__icon ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-info"/></svg>' +
        '<span>' + detail + '</span></div>'
      : '';
  }

  function refreshPushState() {
    if (!pushSupported()) {
      // Browsers hide serviceWorker/PushManager entirely on an insecure
      // origin, so a plain http:// LAN address looks identical to "your
      // browser is too old". Name the actual reason - reached over http it is
      // always this one, and telling the user to buy a new browser is a lie.
      if (window.isSecureContext === false) {
        return setPushState('unsupported',
          'Web push needs a secure page. This one is served over plain http://' +
          ' — start MyNeS with MYNES_TLS=adhoc and open it over https://, or reach it' +
          ' at http://localhost:' + window.location.port + ' on the machine running it.');
      }
      return setPushState('unsupported', 'This browser cannot receive web push. On iOS, add MyNeS to the home screen first.');
    }
    if (Notification.permission === 'denied') {
      return setPushState('blocked', 'Notifications are blocked for this site in your browser settings.');
    }
    return api('/api/push/key').then(function (info) {
      if (!info.available) return setPushState('unavailable', info.detail);
      return navigator.serviceWorker.ready
        .then(function (reg) { return reg.pushManager.getSubscription(); })
        .then(function (sub) {
          setPushState(sub ? 'on' : 'off',
            sub ? 'This device is registered. Alerts arrive even with the tab closed.' : '');
        });
    }).catch(function (e) { setPushState('off', e.message); });
  }

  function enablePush() {
    var btn = $('pushEnableBtn');
    btn.disabled = true;
    return Notification.requestPermission()
      .then(function (permission) {
        if (permission !== 'granted') throw new Error('Permission was not granted.');
        return api('/api/push/key');
      })
      .then(function (info) {
        if (!info.public_key) throw new Error(info.detail || 'Push is not available on the server.');
        return navigator.serviceWorker.ready.then(function (reg) {
          return reg.pushManager.subscribe({
            userVisibleOnly: true,
            applicationServerKey: b64ToUint8(info.public_key)
          });
        });
      })
      .then(function (sub) {
        return api('/api/push/subscribe', {
          method: 'POST',
          body: { subscription: sub.toJSON(), label: navigator.platform || 'this device' }
        });
      })
      .then(function () { toast('Push enabled on this device.', 'success'); return refreshPushState(); })
      .catch(function (e) { toast('Could not enable push: ' + e.message, 'critical'); return refreshPushState(); })
      .finally(function () { btn.disabled = false; });
  }

  function disablePush() {
    return navigator.serviceWorker.ready
      .then(function (reg) { return reg.pushManager.getSubscription(); })
      .then(function (sub) {
        if (!sub) return null;
        var endpoint = sub.endpoint;
        return sub.unsubscribe().then(function () {
          return api('/api/push/unsubscribe', { method: 'POST', body: { endpoint: endpoint } });
        });
      })
      .then(function () { toast('Push turned off on this device.', 'info'); return refreshPushState(); });
  }

  function renderChannelFields() {
    var fields = CHANNEL_FIELDS[$('chType').value] || [];
    renderChannelGuide();
    $('chFields').innerHTML = fields.map(function (f) {
      return '<div class="ds-field">' +
        '<label class="ds-label" for="ch_' + f.key + '">' + esc(f.label) + '</label>' +
        '<input class="ds-input" id="ch_' + f.key + '" type="' + (f.type || 'text') + '"' +
          (f.value ? ' value="' + esc(f.value) + '"' : '') +
          (f.required ? ' required' : '') + '>' +
        (f.hint ? '<span class="ds-hint">' + esc(f.hint) + '</span>' : '') +
      '</div>';
    }).join('');

    // Guessing `notify.mobile_app_<slug>` is the step people get wrong, so ask
    // Home Assistant what it actually exposes and offer it as a datalist.
    if ($('chType').value === 'home_assistant' && $('ch_service')) {
      api('/api/integrations/home-assistant/notify-services')
        .then(function (r) {
          if (!r.services || !r.services.length) return;
          $('chFields').insertAdjacentHTML('beforeend',
            '<datalist id="haNotifyServices">' +
            r.services.map(function (n) { return '<option value="' + esc(n) + '">'; }).join('') +
            '</datalist>');
          $('ch_service').setAttribute('list', 'haNotifyServices');
        })
        .catch(function () { /* not configured yet - the plain field still works */ });
    }
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
      renderMutes();
    });
  }

  // -- muted devices ------------------------------------------------------
  // The store keeps every alert either way; muting only stops the delivery.

  var RULE_LABELS = {
    device_offline: 'Went offline',
    device_online: 'Came back online',
    new_device: 'New device',
    ip_changed: 'IP changed',
    new_port: 'New open port',
    risky_port: 'Risky port open',
    low_battery: 'Low battery',
    low_voltage: 'Low voltage',
    high_latency: 'High latency'
  };

  function mutes() {
    return (settings && settings.muted_devices) || [];
  }

  function saveMutes(list) {
    return api('/api/monitoring/settings', { method: 'POST', body: { muted_devices: list } })
      .then(function (data) { settings = data; renderMutes(); })
      .catch(function (e) { toast('Could not save: ' + e.message, 'critical'); });
  }

  function renderMutes() {
    var host = $('muteList');
    if (!host) return;
    var list = mutes();
    if (!list.length) {
      host.innerHTML = '<p class="ds-muted" style="margin:0">Nothing muted — every alert reaches your channels.</p>';
      return;
    }
    host.innerHTML = list.map(function (m, i) {
      var scope = (m.rules && m.rules.length)
        ? m.rules.map(function (r) { return RULE_LABELS[r] || r; }).join(', ')
        : 'All alert types';
      return '<div class="mute-row">' +
        '<div><strong>' + esc(m.name || m.id) + '</strong> <span class="mono ds-muted">' + esc(m.id) + '</span>' +
        '<div class="ds-muted">' + esc(scope) + '</div></div>' +
        '<button type="button" class="ds-btn ds-btn--sm ds-btn--ghost" data-unmute="' + i + '">Unmute</button>' +
        '</div>';
    }).join('');
    host.querySelectorAll('[data-unmute]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var next = mutes().slice();
        next.splice(Number(btn.dataset.unmute), 1);
        saveMutes(next);
      });
    });
  }

  /** Populate the device picker from the devices the scanner already knows. */
  function loadMuteOptions() {
    var ruleSelect = $('muteRule');
    if (ruleSelect) {
      ruleSelect.innerHTML = '<option value="">All alert types</option>' +
        Object.keys(RULE_LABELS).map(function (r) {
          return '<option value="' + r + '">' + esc(RULE_LABELS[r]) + '</option>';
        }).join('');
    }
    return fetch('/get_devices').then(function (r) { return r.json(); }).then(function (data) {
      var devices = data.devices || data || [];
      var select = $('muteDevice');
      if (!select) return;
      select.innerHTML = devices.map(function (d) {
        // MAC first: an IP is a lease, a MAC is the device.
        var id = (d.mac && d.mac !== 'Unknown') ? d.mac : d.ip;
        var name = d.alias || d.hostname || d.ip || id;
        return id ? '<option value="' + esc(id) + '" data-name="' + esc(name) + '">' +
          esc(name) + ' — ' + esc(id) + '</option>' : '';
      }).join('');
    }).catch(function () { /* the picker stays empty; the page still works */ });
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


  function fmtAbs(iso) {
    if (!iso) return '';
    try { return new Date(iso).toLocaleString(); } catch (e) { return iso; }
  }

  function fmtIn(seconds) {
    if (seconds == null) return '—';
    if (seconds < 60) return 'in ' + Math.max(0, Math.round(seconds)) + 's';
    if (seconds < 3600) return 'in ' + Math.ceil(seconds / 60) + ' min';
    return 'in ' + (seconds / 3600).toFixed(1) + ' h';
  }

  function renderTimeline(s) {
    var card = $('scheduleTimeline');
    // Nothing meaningful to show until either the schedule is on or a scan ran.
    if (!s.enabled && !s.last_run) { card.hidden = true; return; }
    card.hidden = false;

    $('tlLast').textContent = s.last_run ? relativeTime(s.last_run) : 'never';
    $('tlLastAbs').textContent = fmtAbs(s.last_run);

    var r = s.last_result;
    if (r) {
      $('tlResult').textContent = r.baseline
        ? 'baseline recorded'
        : r.devices + ' devices · ' + r.alerts + ' alerts';
      $('tlDuration').textContent = 'took ' + r.duration_seconds + 's';
    } else {
      $('tlResult').textContent = '—';
      $('tlDuration').textContent = '';
    }

    if (s.enabled && s.next_run_in_seconds != null) {
      $('tlNext').textContent = fmtIn(s.next_run_in_seconds);
      $('tlNextAbs').textContent = fmtAbs(new Date(Date.now() + s.next_run_in_seconds * 1000).toISOString());
      var total = s.interval_minutes * 60;
      var elapsed = Math.min(1, Math.max(0, (total - s.next_run_in_seconds) / total));
      $('tlProgressWrap').hidden = false;
      $('tlProgress').style.width = (elapsed * 100).toFixed(1) + '%';
    } else {
      $('tlNext').textContent = s.enabled ? 'after the next tick' : 'not scheduled';
      $('tlNextAbs').textContent = '';
      $('tlProgressWrap').hidden = true;
    }

    $('tlState').textContent = s.last_error ? 'error' : (s.running ? 'running' : 'stopped');
    $('tlBaseline').textContent = s.last_error
      ? s.last_error
      : (s.has_baseline
          ? 'Comparing against ' + s.baseline_devices + ' known devices.'
          : 'No baseline yet — the first scan records one without alerting.');
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
      renderTimeline(s);
    });
  }

  // Server-side paging: the store keeps hundreds of rows and dumping all of
  // them into one table was the reason this page felt like a wall of red.
  var FEED_PAGE = 50;
  var feedOffset = 0;
  var knownRules = [];

  function renderRuleOptions(rules) {
    if (rules.join(' ') === knownRules.join(' ')) return;
    knownRules = rules;
    var select = $('ruleFilter');
    var previous = select.value;
    select.innerHTML = '<option value="">All rules</option>' +
      rules.map(function (r) { return '<option value="' + esc(r) + '">' + esc(r) + '</option>'; }).join('');
    if (rules.indexOf(previous) !== -1) select.value = previous;
  }

  function renderPager(total) {
    var pager = $('alertPager');
    pager.hidden = total <= FEED_PAGE;
    if (pager.hidden) return;
    var from = feedOffset + 1;
    var to = Math.min(feedOffset + FEED_PAGE, total);
    $('alertPageInfo').textContent = from + '–' + to + ' of ' + total;
    $('alertPrev').disabled = feedOffset === 0;
    $('alertNext').disabled = to >= total;
  }

  function loadFeed() {
    var params = ['limit=' + FEED_PAGE, 'offset=' + feedOffset];
    var sev = $('severityFilter').value;
    var rule = $('ruleFilter').value;
    var q = $('alertSearch').value.trim();
    if (sev) params.push('severity=' + encodeURIComponent(sev));
    if (rule) params.push('rule=' + encodeURIComponent(rule));
    if (q) params.push('q=' + encodeURIComponent(q));

    return api('/api/alerts?' + params.join('&')).then(function (data) {
      var host = $('alertFeed');
      renderRuleOptions(data.rules || []);
      var total = data.total || 0;
      // A filter change can leave us past the end of the new result set.
      if (feedOffset && feedOffset >= total) { feedOffset = 0; return loadFeed(); }
      if (!data.alerts.length) {
        $('alertPager').hidden = true;
        host.innerHTML = '<div class="ds-empty">' +
          '<svg class="ds-icon ds-icon--xl ds-empty__icon" aria-hidden="true"><use href="#i-check"/></svg>' +
          '<div class="ds-empty__title">Nothing to report</div>' +
          '<p class="ds-muted" style="margin:0 auto">' +
          ((sev || rule || q) ? 'No alerts match this filter.' : 'No alerts recorded. That is the good outcome.') +
          '</p></div>';
        return;
      }
      renderPager(total);
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
    loadMuteOptions();
    $('muteAddBtn').addEventListener('click', function () {
      var select = $('muteDevice');
      var id = select.value;
      if (!id) { toast('Pick a device first.', 'warning'); return; }
      var rule = $('muteRule').value;
      var next = mutes().filter(function (m) { return m.id !== id; });
      next.push({
        id: id,
        name: select.selectedOptions[0] ? select.selectedOptions[0].dataset.name : id,
        rules: rule ? [rule] : null
      });
      saveMutes(next);
    });

    // Any filter change starts over at page one.
    ['severityFilter', 'ruleFilter'].forEach(function (id) {
      $(id).addEventListener('change', function () { feedOffset = 0; loadFeed(); });
    });
    var searchTimer = null;
    $('alertSearch').addEventListener('input', function () {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(function () { feedOffset = 0; loadFeed(); }, 250);
    });
    $('alertPrev').addEventListener('click', function () {
      feedOffset = Math.max(0, feedOffset - FEED_PAGE);
      loadFeed();
    });
    $('alertNext').addEventListener('click', function () {
      feedOffset += FEED_PAGE;
      loadFeed();
    });

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

    $('pushEnableBtn').addEventListener('click', enablePush);
    $('pushDisableBtn').addEventListener('click', disablePush);
    $('pushTestBtn').addEventListener('click', function () {
      var btn = this; btn.disabled = true;
      api('/api/push/test', { method: 'POST' })
        .then(function (r) {
          toast(r.sent ? 'Sent to ' + r.sent + ' device(s).' : (r.error || 'No device registered.'),
                r.sent ? 'success' : 'warning');
        })
        .catch(function (e) { toast('Test failed: ' + e.message, 'critical'); })
        .finally(function () { btn.disabled = false; });
    });
    refreshPushState();

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
