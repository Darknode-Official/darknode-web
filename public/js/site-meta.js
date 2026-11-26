// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Title, description and canonical URL of every public page a signed-out visitor can land on.
// One table, two readers:
//   scripts/build.mjs writes dist/pages/<slug>.html (index.html with this head) and
//     firebase.json serves it at the page's path, so crawlers and link previews that do not
//     run JavaScript see the right title, description and canonical for each page;
//   landing.js applies the same values after a client-side render (a visit served the app
//     shell by the service worker, or a page reached without a reload).
// Pure data plus one DOM helper; no imports, so Node (the build and the tests) can load it.

export const SITE = "https://darknode.ai";

export const HOME = {
  title: "Darknode — Find the real risks in your domain, code and cloud",
  description: "Free domain security check in seconds, no sign-up. Then find real vulnerabilities in your code, dependencies and cloud, ranked by what attackers exploit now.",
};

// path -> { slug (the dist/pages file), title, description }
export const PAGES = {
  "/features": { slug: "features", title: "Features",
    description: "What Darknode checks: known-exploited vulnerabilities, domain and email security, attack surface, code and secrets, dependencies, and cloud and infrastructure as code, each with a fix." },
  "/pricing": { slug: "pricing", title: "Pricing",
    description: "Free: domain, email and certificate checks, the live vulnerability feed and one watched domain. Pro ($29) and Team ($79) per user a month add scanning, monitors and shared workspaces." },
  "/faq": { slug: "faq", title: "FAQ",
    description: "Answers on Darknode plans, where your code and data go, offline use, the AI models it uses, and legal use of its security checks." },
  "/nexus": { slug: "nexus", title: "Nexus, the terminal coding agent",
    description: "Nexus drives six AI engines from one terminal: Claude Code, the Gemini CLI, Codex, OpenCode, Aider and local Ollama models, with planning, memory, verification and rollback." },
  "/security-knowledge": { slug: "security-knowledge", title: "Security knowledge",
    description: "OWASP Top 10, security patterns, cheat sheets, privilege escalation and network reconnaissance, explained with the context to fix each finding." },
  "/darknode-os": { slug: "darknode-os", title: "Darknode OS",
    description: "Two editions that run in a virtual machine: a from-scratch x86 research kernel, and an Ubuntu 24.04 desktop with the Darknode CLI, Nexus and a security toolset." },
  "/government": { slug: "government", title: "Government and regulated teams",
    description: "Control mapping for NIST SP 800-53, CSF 2.0, FedRAMP, CMMC and HIPAA, vulnerability deadlines with the BOD 22-01 clock, and audit evidence built from your own findings." },
  "/crosswalk": { slug: "crosswalk", title: "GenAI Security Crosswalk",
    description: "The OWASP GenAI security risks mapped to 26 security frameworks, by risk or by framework, with coverage gaps. Free, no account needed." },
  "/terms": { slug: "terms", title: "Terms of Service",
    description: "The terms that govern your use of darknode.ai, the Deck, the Darknode CLI, Nexus, the desktop app and Darknode OS." },
  "/privacy": { slug: "privacy", title: "Privacy Policy",
    description: "What Darknode collects, where your findings and code go, what the edge proxy does and does not keep, and your rights over your data." },
  "/acceptable-use": { slug: "acceptable-use", title: "Acceptable Use Policy",
    description: "Use Darknode only on systems you own or are authorized to assess. What is not allowed, and how to report misuse." },
};

export const NOT_FOUND_TITLE = "Page not found — Darknode";

// "<page> — Darknode" (the home page has its own full title)
export const pageTitle = (p) => p.title + " — Darknode";

/**
 * Point the head at one page: title, description, canonical, Open Graph and Twitter tags.
 * meta = HOME, a PAGES entry, or null for a page that must not be indexed (not found): it
 * loses its canonical and gets robots noindex.
 */
export function applyPageMeta(path, meta, doc = document) {
  const head = doc.head;
  const set = (sel, attr, val) => { const el = head.querySelector(sel); if (el) el.setAttribute(attr, val); };
  if (!meta) {
    const c = head.querySelector('link[rel="canonical"]'); if (c) c.remove();
    let r = head.querySelector('meta[name="robots"]');
    if (!r) { r = doc.createElement("meta"); r.setAttribute("name", "robots"); head.appendChild(r); }
    r.setAttribute("content", "noindex");
    doc.title = NOT_FOUND_TITLE;
    return;
  }
  const title = meta === HOME ? HOME.title : pageTitle(meta);
  const url = SITE + (meta === HOME ? "/" : path);
  doc.title = title;
  set('meta[name="description"]', "content", meta.description);
  set('link[rel="canonical"]', "href", url);
  set('meta[property="og:title"]', "content", title);
  set('meta[property="og:description"]', "content", meta.description);
  set('meta[property="og:url"]', "content", url);
  set('meta[name="twitter:title"]', "content", title);
  set('meta[name="twitter:description"]', "content", meta.description);
}
