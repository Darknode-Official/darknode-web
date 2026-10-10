const CACHE = 'darknode-v96';
// DI's dictionary (11.8 MB, about 4 MB on the wire) lives in its own cache so an app update
// does not download it again; its URL carries a version, so a new word list is a new entry.
const LEXICON = 'darknode-lexicon';
// Only the app shell and the always-unversioned icons are precached. CSS and JS carry ?v=
// in the page, so they are cached at their exact versioned URL on first fetch (below);
// precaching unversioned copies would never match a request and just waste ~1.5 MB.
const STATIC = [
  '/',
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
      Promise.all(keys.filter(k => k !== CACHE && k !== LEXICON && !k.startsWith('quelvra-')).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// Hosting rewrites every unknown path to index.html with a 200, so a missing /js/x.js comes
// back as HTML. Cache an asset only when its content type is what the URL promises;
// otherwise a bad module would be pinned in the cache until the next CACHE bump.
function cacheable(url, res) {
  if (!res || !res.ok) return false;
  const ct = (res.headers.get('content-type') || '').toLowerCase();
  if (url.pathname.endsWith('.js') || url.pathname.endsWith('.mjs')) return ct.includes('javascript');
  if (url.pathname.endsWith('.css')) return ct.includes('text/css');
  return !ct.includes('text/html');
}

// Stale-while-revalidate at the exact (versioned) URL: serve the cached copy at once, refresh
// it in the background, and fall back to the cache when the network fails. Never answers an
// asset request with the app shell.
function assetResponse(e, url) {
  return caches.open(CACHE).then(c =>
    c.match(e.request).then(cached => {
      const fetched = fetch(e.request).then(res => {
        if (cacheable(url, res)) c.put(e.request, res.clone());
        return res;
      }).catch(() => cached || Response.error());
      return cached || fetched;
    })
  );
}

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
      const shell = await caches.match('/') || await caches.match(e.request); // SPA route with no file → app shell
      if (shell) return shell;
      // Last resort (e.g. cache not yet populated during an update): fetch the
      // shell directly so a navigation never resolves to Response.error(), which
      // the browser logs as "FetchEvent ... resulted in a network error response".
      try { const idx = await fetch('/'); if (idx && idx.ok) return idx; } catch (_) {}
      return Response.error();
    })());
    return;
  }

  if (url.pathname === '/js/engine/lexicon.txt') {
    e.respondWith(
      caches.open(LEXICON).then(c =>
        c.match(e.request).then(cached => cached || fetch(e.request).then(res => {
          if (res.ok) {
            c.keys().then(ks => ks.forEach(k => { if (k.url !== e.request.url) c.delete(k); }));
            c.put(e.request, res.clone());
          }
          return res;
        }))
      )
    );
    return;
  }

  if (url.pathname.startsWith('/js/') || url.pathname.startsWith('/css/') || url.pathname.startsWith('/data/')) {
    e.respondWith(assetResponse(e, url));
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

  // Anything else: network, then whatever the cache has for that exact request. A
  // non-navigation request never gets the app shell as a stand-in.
  e.respondWith((async () => {
    try { return await fetch(e.request); }
    catch (_) { return (await caches.match(e.request)) || Response.error(); }
  })());
});
