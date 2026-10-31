// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Moved out of index.html so the page runs under a CSP without 'unsafe-inline'.
window.DARKNODE_PROXY_URL="https://darknode-proxy.darknode-ai.workers.dev/api/chat";
if('serviceWorker' in navigator&&!document.documentElement.hasAttribute('data-desktop'))addEventListener('load',function(){navigator.serviceWorker.register('/sw.js').catch(function(){})})
