// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// The Deck's page table: every scene and the darknode.ai path it lives at. deck-ui.js routes
// with it, and the signed-out site uses it to tell a real page link (which shows the landing,
// then opens that page after sign-in) from a mistyped one (which shows "Page not found").
// Pure data and logic, no imports, so the landing can load it without the Deck.

// scene id -> its element in the Deck
export const SCENES = { overview: "#dkOverview", surface: "#dkSurface", threat: "#dkThreat", cloud: "#dkCloud", compliance: "#dkCompliance", invest: "#dkInvest", findings: "#dkFindings", inventory: "#dkInventory", correlations: "#dkCorrelations", monitors: "#dkMonitors", apikeys: "#dkApiKeys", device: "#dkDevice", audit: "#dkAudit", section: "#dkSection", con: "#dkCon", tools: "#dkTools", toolkit: "#dkToolkit", activity: "#dkActivity", assistant: "#dkAssistant", plans: "#dkPlans", settings: "#dkSettings", reports: "#dkReports", team: "#dkTeam", personal: "#dkPersonal", enterprise: "#dkEnterprise" };
// Every Deck page has a darknode.ai link: a page is /<scene> (the overview is /, a section is
// /area/<id>, a Personal/Organization tab is /personal/<tab>). compliance and tools are also
// tool ids, so those pages take another name.
export const SCENE_PATH = { overview: "", compliance: "compliance-center", tools: "all-tools", con: "connections", invest: "investigations" };

// Does the signed-in app open this path? `secs` is every section/tool id the app routes
// (the console catalog, retired ids and the Deck's own tools). Mirrors the routers: an old
// /console/<page> link opens <page>; hyphenated paths are camelCase secs except tool-<id>.
export function isAppPath(pathname, secs) {
  let raw = String(pathname || "").replace(/^\/+|\/+$/g, "");
  if (raw === "console" || raw.startsWith("console/")) raw = raw.slice(7).replace(/^\/+/, "");
  if (!raw || raw === "index.html") return true;
  if (/^(area|personal|enterprise)\/[\w-]+$/.test(raw)) return true;
  for (const k in SCENES) if (k !== "section" && (k === raw || SCENE_PATH[k] === raw)) return true;
  if (raw.includes("/")) return false;
  const sec = raw.startsWith("tool-") ? raw : raw.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
  return !!secs && secs.has(sec);
}
