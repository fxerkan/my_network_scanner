/* MyNeS service worker.

   Strategy, deliberately minimal:
   - App shell (CSS/JS/icons): stale-while-revalidate, so the UI opens instantly
     and updates in the background.
   - API and HTML: network-first with a cache fallback, because a stale device
     list is worse than a clear "you are offline" state.

   ponytail: no Workbox, no precache manifest, no build step. Bump CACHE_VERSION
   when the shell changes; move to a generated manifest only if assets multiply.
*/

const CACHE_VERSION = 'mynes-v2';
const SHELL_CACHE = CACHE_VERSION + '-shell';
const RUNTIME_CACHE = CACHE_VERSION + '-runtime';

const SHELL_ASSETS = [
  '/',
  '/static/css/design-system.css',
  '/static/js/mynes-ui.js',
  '/static/favicon.svg',
  '/static/logo_96x96.svg',
  '/manifest.webmanifest'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(SHELL_CACHE)
      .then((cache) => cache.addAll(SHELL_ASSETS))
      .then(() => self.skipWaiting())
      .catch(() => self.skipWaiting())  // a missing asset must not block install
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(
        keys.filter((k) => !k.startsWith(CACHE_VERSION)).map((k) => caches.delete(k))
      ))
      .then(() => self.clients.claim())
  );
});

function staleWhileRevalidate(request) {
  return caches.open(SHELL_CACHE).then((cache) =>
    cache.match(request).then((cached) => {
      const network = fetch(request)
        .then((response) => {
          if (response.ok) cache.put(request, response.clone());
          return response;
        })
        .catch(() => cached);
      return cached || network;
    })
  );
}

function networkFirst(request) {
  return fetch(request)
    .then((response) => {
      if (response.ok && request.method === 'GET') {
        const copy = response.clone();
        caches.open(RUNTIME_CACHE).then((cache) => cache.put(request, copy));
      }
      return response;
    })
    .catch(() =>
      caches.match(request).then((cached) =>
        cached || new Response(
          JSON.stringify({ error: 'offline', message: 'MyNeS is unreachable. Showing no data.' }),
          { status: 503, headers: { 'Content-Type': 'application/json' } }
        )
      )
    );
}

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  // Scans and discovery sweeps are long-running side effects - never replay
  // them from cache, and never cache their responses.
  if (/^\/(scan|scan_custom|stop_scan|progress|api\/discovery)/.test(url.pathname)) return;

  if (url.pathname.startsWith('/static/') || url.pathname === '/manifest.webmanifest') {
    event.respondWith(staleWhileRevalidate(request));
    return;
  }

  event.respondWith(networkFirst(request));
});
