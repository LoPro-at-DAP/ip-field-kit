// IP Field Kit service worker.
// Bump VERSION whenever you change any file in SHELL so installed copies pick up the update.
const VERSION = 'ipkit-v1';
const FONT_CACHE = 'ipkit-fonts';
const SHELL = [
  './',
  './index.html',
  './app.js',
  './manifest.webmanifest',
  './icons/icon-192.png',
  './icons/icon-512.png',
  './icons/icon-maskable-512.png',
  './icons/apple-touch-icon.png',
  './icons/favicon-32.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(VERSION).then((cache) => cache.addAll(SHELL)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== VERSION && k !== FONT_CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);

  // App files: serve from the cache so the app works with no signal.
  if (url.origin === self.location.origin) {
    if (req.mode === 'navigate') {
      event.respondWith(caches.match('./index.html').then((hit) => hit || fetch(req)));
    } else {
      event.respondWith(caches.match(req, { ignoreSearch: true }).then((hit) => hit || fetch(req)));
    }
    return;
  }

  // Web fonts: use the cached copy, refresh it in the background when online.
  if (url.hostname === 'fonts.googleapis.com' || url.hostname === 'fonts.gstatic.com') {
    event.respondWith(
      caches.open(FONT_CACHE).then(async (cache) => {
        const hit = await cache.match(req);
        const refresh = fetch(req)
          .then((res) => {
            if (res.ok || res.type === 'opaque') cache.put(req, res.clone());
            return res;
          })
          .catch(() => hit);
        return hit || refresh;
      })
    );
  }
  // Everything else (registry and public-IP lookups) goes straight to the network.
});
