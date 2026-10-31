// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Moved out of index.html so the page runs under a CSP without 'unsafe-inline'.
(function () {
      var pct = document.getElementById("bootpct");
      var pctPro = document.getElementById("bootpct-pro");
      var bar = document.querySelector(".boot-bar > span");
      var barPro = document.getElementById("bootbar-pro");
      var cur = 0, target = 15, raf;
      function set(p) {
        target = Math.min(100, Math.max(cur, p));
        if (!raf) raf = requestAnimationFrame(tick);
      }
      function tick() {
        raf = 0;
        if (cur < target) cur += (target - cur) * 0.15 + 0.3;
        if (cur > target) cur = target;
        var r = Math.round(cur);
        if (pct) pct.textContent = r + "%";
        if (pctPro) pctPro.textContent = r + "%";
        if (bar) bar.style.width = r + "%";
        if (barPro) barPro.style.width = r + "%";
        if (cur < target) raf = requestAnimationFrame(tick);
      }
      raf = requestAnimationFrame(tick);
      window.__boot = { set: set };
      // If the app never boots (e.g. the Firebase CDN is blocked by a network
      // filter or extension), auth.js never calls dismissBoot() and the loader
      // sits at its last percentage forever. After 14s, if #view is still empty
      // and the boot screen is still up, explain instead of spinning silently.
      setTimeout(function () {
        var v = document.getElementById("view");
        var b = document.getElementById("bootscreen");
        if (!b || (v && v.childElementCount)) return;
        b.setAttribute("data-stalled", "1");
        b.innerHTML = "<div style=\"position:absolute;inset:0;display:flex;align-items:center;justify-content:center;padding:32px;text-align:center\">" +
          "<div style=\"max-width:420px;font-family:ui-sans-serif,system-ui,-apple-system,sans-serif\">" +
          "<div style=\"font-size:1.05rem;font-weight:600;color:#e6edf3;margin-bottom:10px\">Darknode is taking too long to load</div>" +
          "<div style=\"font-size:.9rem;line-height:1.6;color:#9aa4b2;margin-bottom:20px\">This usually means the sign-in service (Firebase) was blocked by your network or a content blocker. Check your connection or disable blockers for this site, then reload.</div>" +
          "<a href=\"\" style=\"display:inline-block;padding:9px 20px;border-radius:8px;background:#00a3cc;color:#fff;font-weight:600;font-size:.9rem;text-decoration:none\">Reload</a>" +
          "</div></div>";
      }, 14000);
    })();
    (function () {
      var q = window.__errorQueue = [], seen = {};
      window.addEventListener("error", function (ev) {
        var key = (ev.message || "") + ":" + (ev.filename || "") + ":" + ev.lineno;
        if (!window.__errorQueue || seen[key] || q.length >= 20) return;
        seen[key] = 1;
        q.push({ message: String(ev.message || ""), source: ev.filename || "", line: ev.lineno, col: ev.colno, stack: ev.error && ev.error.stack ? ev.error.stack.slice(0, 2000) : "", ts: Date.now(), url: location.href, ua: navigator.userAgent });
      });
      window.addEventListener("unhandledrejection", function (ev) {
        if (!window.__errorQueue) return;
        var msg = ev.reason ? (ev.reason.message || String(ev.reason)) : "Unhandled rejection";
        var key = "promise:" + msg;
        if (seen[key] || q.length >= 20) return;
        seen[key] = 1;
        q.push({ message: msg, source: "unhandledrejection", stack: ev.reason && ev.reason.stack ? ev.reason.stack.slice(0, 2000) : "", ts: Date.now(), url: location.href, ua: navigator.userAgent });
      });
    })();
