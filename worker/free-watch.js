// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// The Free plan's domain watch. Monitoring is a Pro feature (worker/plan.js FEATURE_PLAN.monitors),
// with one exception every account gets: watch ONE domain for certificate expiry, email/DNS changes, domain
// registration and website security, with alerts sent to the account's own email. The rules are PURE and enforced on the
// server, inside the workspace's MonitorDO (so the domain count and the write are one step):
//   - only the personal workspace (handleMonitor refuses Free in a team workspace);
//   - only the cert-expiry, email-posture, domain-expiry and web-posture check types;
//   - one distinct domain across every monitor in the workspace, paused ones included;
//   - alerts by email only (Slack, Teams, Discord and webhooks stay Pro);
//   - checked at most once a day.
// Mirrors public/js/core/entitlements.js LIMITS.watchDomains and the Plans page.
import { hostOnly } from "./checks.js";

export const FREE_WATCH = Object.freeze({
  types: ["cert-expiry", "email-posture", "domain-expiry", "web-posture"],
  domains: 1,
  channels: ["email"],
  minIntervalMs: 24 * 60 * 60 * 1000,
  manualRunGapMs: 10 * 60 * 1000, // "Run now" on Free: at most once per 10 minutes
});

const TYPE_LABEL = { "kev-epss": "Known-exploited vulnerability (KEV/EPSS)" };

export const FREE_TEAM_MSG = "Continuous monitoring is part of the Pro plan. On the Free plan you can watch one domain from your personal workspace. Request an upgrade under Plans.";

// The distinct hostnames a monitor watches.
export function monitorDomains(m) {
  const list = (m && m.config && Array.isArray(m.config.domains)) ? m.config.domains : [];
  return [...new Set(list.map(hostOnly).filter(Boolean))];
}

const emailOnly = (m) => (m.channels || []).every((c) => c && c.type === "email");

// null when the Free plan allows saving `next` beside `others` (the workspace's other monitors,
// paused ones included), else the message the 402 carries.
export function freeWatchDenied(next, others = []) {
  const type = String((next && next.type) || "");
  if (!FREE_WATCH.types.includes(type)) {
    return (TYPE_LABEL[type] || "This kind of") + " monitoring is part of the Pro plan. On the Free plan you can watch one domain for its certificate, email/DNS records, registration and website security. Request an upgrade under Plans.";
  }
  if (!emailOnly(next)) return "On the Free plan, alerts go to your account email. Slack, Teams, Discord and webhook alerts are part of the Pro plan.";
  const mine = monitorDomains(next);
  if (mine.length > FREE_WATCH.domains) return "The Free plan watches one domain. Keep one domain in this watch, or request an upgrade under Plans to watch more.";
  const watched = [...new Set(others.flatMap(monitorDomains))];
  const all = new Set([...watched, ...mine]);
  if (all.size > FREE_WATCH.domains) {
    const other = watched.filter((d) => !mine.includes(d));
    return "The Free plan watches one domain, and you already watch " + other.slice(0, 3).join(", ") + (other.length > 3 ? " and " + (other.length - 3) + " more" : "")
      + ". Remove that watch under Monitors to watch " + (mine[0] || "another domain") + " instead, or request an upgrade under Plans.";
  }
  return null;
}

// The monitors that may run under the Free plan: the one-domain watch, nothing else. When a
// workspace holds more than that (monitors set up on a paid plan that has since lapsed), the
// domain of the earliest-created fitting monitor is the watched one. -> Set of monitor ids.
export function freeAllowed(mons) {
  const fits = Object.values(mons || {})
    .filter((m) => m && FREE_WATCH.types.includes(m.type) && emailOnly(m) && monitorDomains(m).length === 1)
    .sort((a, b) => (a.createdAt || 0) - (b.createdAt || 0) || String(a.id).localeCompare(String(b.id)));
  if (!fits.length) return new Set();
  const dom = monitorDomains(fits[0])[0];
  return new Set(fits.filter((m) => monitorDomains(m)[0] === dom).map((m) => m.id));
}
