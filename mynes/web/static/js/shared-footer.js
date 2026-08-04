// Footer version stamp. The footer markup itself lives in base.html - this file
// only fills in the version, so there is one footer instead of three.
(function () {
  'use strict';

  function render(info) {
    var el = document.getElementById('appVersion');
    if (!el || !info || !info.version) return;
    // Version only. Commit hash and build time stay in /api/version for
    // debugging; nobody reading a footer needs them.
    el.textContent = 'v' + info.version;
  }

  document.addEventListener('DOMContentLoaded', function () {
    fetch('/api/version')
      .then(function (r) { return r.json(); })
      .then(render)
      .catch(function () { render({ version: 'unknown' }); });
  });
})();
