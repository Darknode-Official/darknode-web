const CACHE = 'darknode-v30';
const STATIC = [
  '/',
  '/css/styles.css',
  '/css/pro-theme.css',
  '/css/theme-command.css',
  '/css/buttons.css',
  '/js/auth.js',
  '/js/firebase.js',
  '/js/cyber.js',
  '/js/toolkit.js',
  '/favicon.svg',
  '/logo-light.svg',
  '/logo-dark.svg',
  '/wordmark.svg'
];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(STATIC)));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET') return;
  if (url.origin !== location.origin) return;

  // SPA client-side routes (e.g. /navarch, /ai) have no file on disk. Always
  // serve the cached app shell so a direct load or reload works offline, and
  // never let respondWith resolve to undefined (that throws "Failed to convert
  // value to 'Response'").
  if (e.request.mode === 'navigate') {
    e.respondWith((async () => {
      try {
        const res = await fetch(e.request);
        if (res && res.ok) return res;           // real page (prod rewrites SPA routes to index.html)
      } catch (_) { /* offline / network error */ }
      const shell = await caches.match('/');       // SPA route with no file → serve the app shell
      return shell || (await caches.match(e.request)) || Response.error();
    })());
    return;
  }

  if (url.pathname.startsWith('/js/') || url.pathname.startsWith('/data/')) {
    e.respondWith(
      caches.open(CACHE).then(c =>
        c.match(e.request).then(cached => {
          const fetched = fetch(e.request).then(res => {
            if (res.ok) c.put(e.request, res.clone());
            return res;
          }).catch(() => cached);
          return cached || fetched;
        })
      )
    );
    return;
  }

  if (url.pathname.match(/\.(svg|png|jpg|webp|woff2|ico)$/)) {
    e.respondWith(
      caches.open(CACHE).then(c =>
        c.match(e.request).then(cached => cached || fetch(e.request).then(res => {
          if (res.ok) c.put(e.request, res.clone());
          return res;
        }))
      )
    );
    return;
  }

  e.respondWith(
    fetch(e.request).catch(() =>
      caches.match(e.request).then(cached => cached || caches.match('/') || Response.error())
    )
  );
});
