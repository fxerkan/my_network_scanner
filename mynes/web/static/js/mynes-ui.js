/* MyNeS shared UI runtime: theme, toasts, alert badge, remote/TV navigation.
   Vanilla ES2018, no framework, no build step - it has to run on a Smart TV
   browser and an old tablet as well as on a desktop. */
(function () {
  'use strict';

  var MyNeS = window.MyNeS || {};
  window.MyNeS = MyNeS;

  /* ---------------- Theme ------------------------------------------------ */
  var THEME_KEY = 'mynes-theme';

  function currentTheme() {
    var explicit = document.documentElement.getAttribute('data-theme');
    if (explicit === 'light' || explicit === 'dark') return explicit;
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  function applyTheme(theme) {
    if (theme === 'system') {
      document.documentElement.removeAttribute('data-theme');
      try { localStorage.removeItem(THEME_KEY); } catch (e) { /* private mode */ }
    } else {
      document.documentElement.setAttribute('data-theme', theme);
      try { localStorage.setItem(THEME_KEY, theme); } catch (e) { /* private mode */ }
    }
    syncThemeIcon();
  }

  function syncThemeIcon() {
    var isDark = currentTheme() === 'dark';
    var uses = document.querySelectorAll('[data-theme-icon] use');
    for (var i = 0; i < uses.length; i++) {
      uses[i].setAttribute('href', isDark ? '#i-sun' : '#i-moon');
    }
    var btn = document.getElementById('themeToggle');
    if (btn) btn.setAttribute('aria-pressed', String(isDark));
  }

  MyNeS.toggleTheme = function () {
    applyTheme(currentTheme() === 'dark' ? 'light' : 'dark');
  };
  MyNeS.applyTheme = applyTheme;

  /* ---------------- Toasts ----------------------------------------------- */
  var ICONS = { info: '#i-info', success: '#i-check', warning: '#i-alert', critical: '#i-alert' };

  MyNeS.toast = function (message, kind, timeout) {
    kind = kind || 'info';
    var host = document.getElementById('toastHost');
    if (!host) { console.log('[MyNeS] ' + message); return; }

    var el = document.createElement('div');
    el.className = 'ds-toast ds-toast--' + kind;
    el.innerHTML =
      '<svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="' + (ICONS[kind] || ICONS.info) + '"/></svg>' +
      '<span class="ds-spacer"></span>' +
      '<button type="button" class="ds-btn ds-btn--ghost ds-btn--sm" aria-label="Dismiss">' +
      '<svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-x"/></svg></button>';
    // textContent, not innerHTML: alert text can contain a device name from the network.
    el.querySelector('.ds-spacer').textContent = message;

    function dismiss() { el.remove(); }
    el.querySelector('button').addEventListener('click', dismiss);
    host.appendChild(el);
    if (timeout !== 0) setTimeout(dismiss, timeout || 5000);
    return el;
  };

  /* ---------------- Fetch helper ----------------------------------------- */
  MyNeS.api = function (path, options) {
    options = options || {};
    if (options.body && typeof options.body !== 'string') {
      options.body = JSON.stringify(options.body);
      options.headers = Object.assign({ 'Content-Type': 'application/json' }, options.headers || {});
    }
    return fetch(path, options).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) {
        if (!res.ok) throw new Error(data.error || (res.status + ' ' + res.statusText));
        return data;
      });
    });
  };

  /* ---------------- Alert badge ------------------------------------------ */
  var badgePoll = null;

  function refreshAlertBadge() {
    var badge = document.getElementById('alertBadge');
    if (!badge) return;
    MyNeS.api('/api/health')
      .then(function (data) {
        var unread = (data.alerts && data.alerts.unread) || 0;
        badge.textContent = unread > 99 ? '99+' : String(unread);
        badge.hidden = unread === 0;
      })
      .catch(function () { /* offline: leave the badge as-is */ });
  }
  MyNeS.refreshAlertBadge = refreshAlertBadge;

  /* ---------------- Remote / TV navigation -------------------------------- */
  /* A TV remote sends arrow keys with no pointer. Once we see that pattern we
     switch to a louder focus ring and let arrows move focus spatially. */
  var FOCUSABLE = 'a[href],button:not(:disabled),input:not(:disabled),select:not(:disabled),textarea:not(:disabled),[tabindex]:not([tabindex="-1"])';

  function markRemoteInput() {
    document.documentElement.setAttribute('data-input', 'remote');
  }

  function spatialMove(dir) {
    var active = document.activeElement;
    if (!active || active === document.body) {
      var first = document.querySelector(FOCUSABLE);
      if (first) first.focus();
      return true;
    }
    var from = active.getBoundingClientRect();
    var best = null, bestScore = Infinity;

    var candidates = document.querySelectorAll(FOCUSABLE);
    for (var i = 0; i < candidates.length; i++) {
      var el = candidates[i];
      if (el === active || el.offsetParent === null) continue;
      var r = el.getBoundingClientRect();
      var dx = (r.left + r.width / 2) - (from.left + from.width / 2);
      var dy = (r.top + r.height / 2) - (from.top + from.height / 2);

      var forward = dir === 'right' ? dx > 8 : dir === 'left' ? dx < -8
                  : dir === 'down' ? dy > 8 : dy < -8;
      if (!forward) continue;

      // Prefer the nearest element, penalising drift off the travel axis.
      var along = (dir === 'left' || dir === 'right') ? Math.abs(dx) : Math.abs(dy);
      var across = (dir === 'left' || dir === 'right') ? Math.abs(dy) : Math.abs(dx);
      var score = along + across * 2;
      if (score < bestScore) { bestScore = score; best = el; }
    }
    if (best) { best.focus(); best.scrollIntoView({ block: 'nearest', inline: 'nearest' }); return true; }
    return false;
  }

  var ARROWS = { ArrowUp: 'up', ArrowDown: 'down', ArrowLeft: 'left', ArrowRight: 'right' };

  function onKeydown(e) {
    var dir = ARROWS[e.key];
    if (!dir) return;
    var tag = (e.target.tagName || '').toLowerCase();
    // Never hijack arrows inside a text field, select, or scrollable editor.
    if (tag === 'input' || tag === 'textarea' || tag === 'select' || e.target.isContentEditable) return;
    if (!document.documentElement.hasAttribute('data-input')) markRemoteInput();
    if (spatialMove(dir)) e.preventDefault();
  }

  /* ---------------- Service worker --------------------------------------- */
  function registerServiceWorker() {
    if (!('serviceWorker' in navigator)) return;
    // Only over HTTPS or localhost - a LAN http:// origin cannot register one.
    if (location.protocol !== 'https:' && location.hostname !== 'localhost' && location.hostname !== '127.0.0.1') return;

    navigator.serviceWorker.register('/service-worker.js').then(function (reg) {
      // A waiting worker means this tab is running the previous release's code.
      // Activate it and reload once, rather than leaving the user on a stale UI
      // that only a hard reload fixes.
      function promote(worker) {
        if (!worker) return;
        worker.postMessage('skip-waiting');
      }

      if (reg.waiting) promote(reg.waiting);

      reg.addEventListener('updatefound', function () {
        var incoming = reg.installing;
        if (!incoming) return;
        incoming.addEventListener('statechange', function () {
          if (incoming.state === 'installed' && navigator.serviceWorker.controller) {
            promote(incoming);
          }
        });
      });

      var reloading = false;
      navigator.serviceWorker.addEventListener('controllerchange', function () {
        if (reloading) return;  // controllerchange can fire more than once
        reloading = true;
        window.location.reload();
      });

      // Check for a new release when the tab regains focus, so a long-lived
      // dashboard tab does not sit on yesterday's build.
      document.addEventListener('visibilitychange', function () {
        if (!document.hidden) reg.update().catch(function () {});
      });
    }).catch(function (e) {
      console.warn('[MyNeS] service worker registration failed:', e.message);
    });
  }

  // Escape hatch for support: MyNeS.resetCache() in the console.
  MyNeS.resetCache = function () {
    if (!('serviceWorker' in navigator)) return Promise.resolve();
    return navigator.serviceWorker.getRegistrations()
      .then(function (regs) { return Promise.all(regs.map(function (r) { return r.unregister(); })); })
      .then(function () { return caches.keys(); })
      .then(function (keys) { return Promise.all(keys.map(function (k) { return caches.delete(k); })); })
      .then(function () { window.location.reload(true); });
  };

  /* ---------------- Boot -------------------------------------------------- */
  function init() {
    syncThemeIcon();

    var toggle = document.getElementById('themeToggle');
    if (toggle) toggle.addEventListener('click', MyNeS.toggleTheme);

    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', syncThemeIcon);
    document.addEventListener('keydown', onKeydown);
    // A real pointer means this is not a TV; drop the amplified focus ring.
    document.addEventListener('pointerdown', function () {
      document.documentElement.removeAttribute('data-input');
    }, { once: true });

    refreshAlertBadge();
    badgePoll = setInterval(refreshAlertBadge, 60000);
    document.addEventListener('visibilitychange', function () {
      // Stop polling in a background tab; phones kill wake-locks for less.
      if (document.hidden) { clearInterval(badgePoll); badgePoll = null; }
      else if (!badgePoll) { refreshAlertBadge(); badgePoll = setInterval(refreshAlertBadge, 60000); }
    });

    registerServiceWorker();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();

/* Language switcher used by the header select (kept global for the inline handler). */
function changeLanguage(code) {
  fetch('/api/language/set', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ language: code })
  }).then(function () { window.location.reload(); });
}
