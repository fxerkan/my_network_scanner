// Footer version stamp. The footer markup itself lives in base.html - this file
// only fills in the version, so there is one footer instead of three.
(function () {
  'use strict';

  function render(info) {
    var el = document.getElementById('appVersion');
    if (!el || !info || !info.version) return;
    el.textContent = 'v' + info.version;
    el.title = [
      'Version: ' + info.version,
      info.commit_hash ? 'Commit: ' + String(info.commit_hash).slice(0, 7) : '',
      info.build_time ? 'Built: ' + new Date(info.build_time).toLocaleString() : '',
      info.is_dirty ? 'Working tree modified' : ''
    ].filter(Boolean).join('\n');
  }

  document.addEventListener('DOMContentLoaded', function () {
    fetch('/api/version')
      .then(function (r) { return r.json(); })
      .then(render)
      .catch(function () { render({ version: 'unknown' }); });
  });
})();
