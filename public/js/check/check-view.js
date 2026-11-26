// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// HTML for a domain-check result (check/domain-check.js runDomainCheck output), shared by
// the landing hero, the /check/<domain> page and the Deck's first-run block. No DOM work
// and no imports: callers set innerHTML and wire their own buttons. Styles live in
// css/domain-check.css (.dmc-*); the hero adds .dmc-dark.

const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const GROUP_ORDER = [
  ["email", "Email authentication"],
  ["https", "HTTPS"],
  ["headers", "Security headers"],
  ["dns", "DNS hardening"],
  ["disclosure", "Vulnerability disclosure"],
];
const STATUS_LABEL = { pass: "Pass", warn: "Warning", fail: "Fail", error: "Not checked", na: "Not applicable", pending: "Checking" };
const fmt = (n) => (Math.round(n * 10) / 10).toString();

function row(c, toolLabel) {
  const pts = c.status === "pending" ? "" : c.points == null ? (c.status === "error" ? "not graded" : "n/a") : `${fmt(c.points)} / ${c.weight} pts`;
  const tool = toolLabel && (c.status === "fail" || c.status === "warn") ? toolLabel(c.tool) : "";
  return `<li class="dmc-row s-${esc(c.status)}">
    <span class="dmc-st">${esc(STATUS_LABEL[c.status] || c.status)}</span>
    <div class="dmc-main"><div class="dmc-name">${esc(c.label)}<span class="dmc-w">${c.weight} pts</span></div>
      <p class="dmc-det">${c.status === "pending" ? "Checking…" : esc(c.detail)}</p>
      ${c.fix && (c.status === "fail" || c.status === "warn") ? `<p class="dmc-fix"><b>Fix:</b> ${esc(c.fix)}</p>` : ""}
      ${tool ? `<button type="button" class="dmc-tool" data-dmc-tool="${esc(c.tool)}">Open ${esc(tool)}</button>` : ""}
    </div>
    <span class="dmc-pts">${esc(pts)}</span>
  </li>`;
}

/**
 * @param {object} res runDomainCheck result (or an onProgress snapshot)
 * @param {{ running?: boolean, toolLabel?: (id: string) => string }} [o]
 *   toolLabel: name of the Deck tool for a failing check, or "" to show no button.
 */
export function renderResult(res, { running = false, toolLabel = null } = {}) {
  const checks = res.checks || [];
  const n = { pass: 0, warn: 0, fail: 0, error: 0, na: 0, pending: 0 };
  for (const c of checks) n[c.status] = (n[c.status] || 0) + 1;
  const graded = !running && n.pending === 0;
  const grade = graded ? res.grade : "";
  const parts = [`${n.pass} passed`, `${n.warn} warning${n.warn === 1 ? "" : "s"}`, `${n.fail} failed`];
  if (n.error) parts.push(`${n.error} could not be checked`);
  if (n.na) parts.push(`${n.na} not applicable`);
  const scoreLine = !graded ? "Reading public DNS records, HTTP responses and certificate logs. Each row fills in as its source answers."
    : res.score == null ? "Too few checks could run to grade this domain."
      : `${res.score} out of 100 &middot; ${parts.join(" &middot; ")}`;
  const how = `Each check is worth the points shown. A pass earns all of them, a warning half, a fail none. Checks that could not run or do not apply are left out${graded && res.possible < 100 ? `, so this grade is based on ${fmt(res.possible)} of 100 points` : ""}.`;
  const groups = GROUP_ORDER.map(([id, label]) => {
    const rows = checks.filter((c) => c.group === id);
    if (!rows.length) return "";
    const got = rows.reduce((s, c) => s + (c.points || 0), 0);
    const of = rows.reduce((s, c) => s + (c.points == null ? 0 : c.weight), 0);
    // a styled div with the heading role: the site forces every h3 to black, which the hero's dark card cannot use
    // and a div, not a section: the site's section rules draw separator lines
    return `<div class="dmc-grp" role="group" aria-label="${esc(label)}"><div class="dmc-gh" role="heading" aria-level="3">${esc(label)}<span>${of ? `${fmt(got)} / ${of} pts` : ""}</span></div><ul>${rows.map((c) => row(c, toolLabel)).join("")}</ul></div>`;
  }).join("");
  return `<div class="dmc-res${graded ? "" : " is-running"}">
    <div class="dmc-head">
      <div class="dmc-grade g-${esc(grade ? grade.replace("/", "") : "pending")}" aria-label="${grade ? "Grade " + esc(grade) : "Checking"}">${grade ? esc(grade) : '<span class="dmc-spin" aria-hidden="true"></span>'}</div>
      <div class="dmc-meta">
        <div class="dmc-dom">${esc(res.domain)}${res.webHost && res.webHost !== res.domain ? `<small>website checked at ${esc(res.webHost)}</small>` : ""}</div>
        <div class="dmc-score">${scoreLine}</div>
        <p class="dmc-how">${how}</p>
      </div>
    </div>
    <div class="dmc-groups">${groups}</div>
  </div>`;
}

// The pending shell, before the first DNS answer lands.
export function renderPending(domain) {
  return renderResult({ domain, checks: [] }, { running: true });
}

export const escapeHtml = esc;
