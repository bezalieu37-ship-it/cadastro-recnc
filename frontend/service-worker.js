/*
  Service Worker para Cadastro RECNC (PWA)
  Fornece funcionalidade offline básica e cache de assets estáticos.
*/

const CACHE_NAME = 'cadastro-remc-v1.0';
const ASSETS_ESTATICOS = [
  '/',
  '/index.html',
  '/dashboard.html',
  '/lista.html',
  '/formulario.html',
  '/usuarios.html',
  '/css/style.css',
  'https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/minimal-fontawesome.min.css',
];

// Install event - cache assets
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(ASSETS_ESTATICOS))
      .then(() => self.skipWaiting())
  );
});

// Activate event - clean old caches
self.addEventListener('activate', event => {
  const cacheWhitelist = [CACHE_NAME];
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cache => {
          if (cacheWhitelist.indexOf(cache) === -1) {
            return caches.delete(cache);
          }
        })
      );
    })
    // Ensure service worker takes control
    ).then(() => self.clients.claim());
  );
});

// Fetch event - serve from cache, fall back to network
self.addEventListener('fetch', event => {
  // Ignorar requisições não-GET ou que precisam do network
  if (event.request.method !== 'GET') return;
  
  event.respondWith(
    caches.match(event.request)
      .then(response => {
        // Retornar do cache se encontrado
        if (response) return response;
        
        // Caso contrário, buscar da rede
        return fetch(event.request);
      }
    )
  );
});

// Message handler para atualizações opcionais
self.addEventListener('message', event => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});