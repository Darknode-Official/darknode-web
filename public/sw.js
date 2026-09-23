const CACHE = 'darknode-v27';
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
    fetch(e.request).catch(() => caches.match(e.request))
  );
});
