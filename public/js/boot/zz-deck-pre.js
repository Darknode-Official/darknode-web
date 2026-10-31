// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Moved out of index.html so the page runs under a CSP without 'unsafe-inline'.
window.DARKNODE_PROXY_URL="https://darknode-proxy.darknode-ai.workers.dev/api/chat"; window.__errs=[]; addEventListener("error",e=>__errs.push(String(e.message)+" @"+(e.filename||"").split("/").pop()+":"+e.lineno)); addEventListener("unhandledrejection",e=>__errs.push("rej: "+String(e.reason&&e.reason.stack||e.reason).slice(0,300)));
{const u=new URLSearchParams(location.search).get("uid"); if(u) window.__dnUid=u;}
