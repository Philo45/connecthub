const CACHE_NAME = 'connecthub-cache-v1';
// Files that define the core UI (App Shell) to be cached for offline access
const urlsToCache = [
    '/',
    '/index.html',
    '/chat.html',
    // Note: Add any static assets you serve yourself (like /favicon.ico)
    // External assets for faster load
    'https://cdn.tailwindcss.com',
    'https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap',
    'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css'
];

// 1. Installation: Cache the App Shell
self.addEventListener('install', event => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(cache => {
                console.log('[Service Worker] Caching App Shell');
                return cache.addAll(urlsToCache);
            })
            .catch(err => {
                console.error('[Service Worker] Failed to cache during install:', err);
            })
    );
});

// 2. Fetch: Serve from cache first, then fallback to network
self.addEventListener('fetch', event => {
    // We only cache GET requests
    if (event.request.method !== 'GET') return;

    event.respondWith(
        caches.match(event.request)
            .then(response => {
                // Cache hit - return the response from cache
                if (response) {
                    return response;
                }
                // No cache match - fetch from network
                return fetch(event.request);
            })
            .catch(error => {
                console.error('[Service Worker] Fetch failed:', event.request.url, error);
            })
    );
});

// 3. Activation: Clean up old caches
self.addEventListener('activate', event => {
    const cacheWhitelist = [CACHE_NAME];
    event.waitUntil(
        caches.keys().then(cacheNames => {
            return Promise.all(
                cacheNames.map(cacheName => {
                    if (cacheWhitelist.indexOf(cacheName) === -1) {
                        // Delete old caches not in the whitelist
                        return caches.delete(cacheName);
                    }
                })
            );
        })
    );
});