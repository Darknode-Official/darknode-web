// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved.
// Browser half of the findings sink: writes mapped findings into the Security
// Graph through graph-bridge.js and renders the shared "Add to Security Graph"
// button. The mapping itself lives in core/sink-map.js (pure, node-tested).

import { toEntities } from "./sink-map.js";
import { reconcileRun, expiredExceptions } from "./workflow.js";

const toast = (msg, kind) => { try { window.showToast && window.showToast(msg, kind); } catch (_) {} };
const plural = (n, one, many) => n + " " + (n === 1 ? one : many);

// Verify-fixed / regression / exception expiry after a tool run (core/workflow.js).
// Runs on the graph AFTER the write: sink-map nextStatus never reopens a resolved sink
// finding, so a fixed finding that came back is still resolved here and reconcileRun is
// the one place that reopens it (with regressed + a history entry). Regressions are
// applied automatically for any real run (a findingKey seen again is the same finding,
// whatever input it came from); "no longer present -> fixed" needs a named dataset and
// the user's confirmation. Expired exceptions are lapsed on every publish.
async function reconcileAfterRun(sg, toolId, dataset, keys, sample) {
  const res = { fixed: 0, regressed: 0, expired: 0 };
  const batch = sg.batch || ((fn) => fn());
  const findings = () => sg.listEntities({ type: ["FINDING", "VULNERABILITY"] }) || [];
  const apply = (list) => batch(() => { for (const u of list) sg.updateEntity(u.id, u.updates); });
  try {
    const now = Date.now();
    const exp = expiredExceptions(findings(), now);
    if (exp.length) {
      apply(exp);
      res.expired = exp.length;
      toast(plural(exp.length, "risk exception expired", "risk exceptions expired") + "; affected findings are back in the queue", "warning");
    }
    if (sample) return res;
    const rec = reconcileRun(toolId, dataset, findings(), keys, { now, regressOnly: !dataset });
    if (rec.regressed.length) {
      apply(rec.regressed);
      res.regressed = rec.regressed.length;
      toast(plural(rec.regressed.length, "fixed finding came back and was reopened", "fixed findings came back and were reopened"), "warning");
    }
    if (!dataset || !rec.fixed.length || typeof window.dnConfirm !== "function") return res;
    const n = rec.fixed.length;
    const ok = await window.dnConfirm("Verify fixed findings",
      `${plural(n, "finding", "findings")} from the last run of ${dataset} ${n === 1 ? "is" : "are"} no longer present. Mark ${n === 1 ? "it" : "them"} verified fixed?`,
      { submitText: "Mark fixed" });
    if (!ok) return res;
    // Recompute on the graph as it is now: the user may have triaged during the prompt.
    const fresh = reconcileRun(toolId, dataset, findings(), keys, { now: Date.now() }).fixed;
    apply(fresh);
    res.fixed = fresh.length;
    if (fresh.length) toast(plural(fresh.length, "finding", "findings") + " marked verified fixed", "success");
  } catch (_) {}
  return res;
}

/**
 * Publish findings to the Security Graph. Re-runs merge (FINDING names carry a
 * stable key) and sample data never merges into real entities.
 * @param {string} toolId
 * @param {object[]} findings common Finding shape (see sink-map.js)
 * @param {{ dataset?: string, sample?: boolean, link?: string|null, quiet?: boolean }} [o]
 * After the write (real runs only) regressions are reopened, findings missing from the
 * last run of the same named dataset are offered as verified fixed, and expired risk
 * exceptions are lapsed (see reconcileAfterRun).
 * @returns {Promise<{ created:number, updated:number, skipped:number, entities:object[], fixed:number, regressed:number, expired:number }>}
 */
export async function publishFindings(toolId, findings, { dataset, sample, link, quiet = true } = {}) {
  const gb = await import("/js/graph-bridge.js");
  const sg = await import("/js/security-graph.js");
  const { items, links } = toEntities(toolId, findings, { dataset, sample });
  const r = gb.sendToGraph(toolId, items, link, true);
  const byKey = new Map();
  for (const e of r.entities || []) byKey.set(e.type + ":" + String(e.name).toLowerCase(), e);
  const resolve = (k) => {
    const i = k.indexOf(":"), type = k.slice(0, i), name = k.slice(i + 1);
    return byKey.get(type + ":" + name.toLowerCase()) || (sg.findEntity ? sg.findEntity(type, name) : null);
  };
  gb.batchGraph(() => {
    for (const l of links) {
      const a = resolve(l.from), b = resolve(l.to);
      if (a && b) gb.linkEntities(a.id, b.id, l.rel);
    }
  });
  const out = { created: r.created || 0, updated: r.updated || 0, skipped: items.length - (r.entities || []).length, entities: r.entities || [] };
  const keys = items.filter((it) => it.type === "FINDING").map((it) => it.data && it.data.findingKey).filter(Boolean);
  Object.assign(out, await reconcileAfterRun(sg, toolId, dataset, keys, !!sample));
  if (!quiet) toast(`${out.created} added, ${out.updated} updated in Security Graph`, "success");
  try { document.dispatchEvent(new CustomEvent("dn:findings:published", { detail: { toolId, created: out.created, updated: out.updated } })); } catch (_) {}
  // Same "/js/core/bus.js" specifier as every other importer: the bus is a singleton.
  try {
    const { bus, EVENTS } = await import("/js/core/bus.js");
    bus.emit(EVENTS.TOOL_RESULT, { tool: toolId, created: out.created, updated: out.updated, entities: out.entities.length });
  } catch (_) {}
  return out;
}

/**
 * Render the shared sink button into `container`. getFindings() → { findings, sample }.
 * Returns update(): re-reads findings and refreshes the count / disabled state.
 * @param {HTMLElement} container
 * @param {() => { findings: object[], sample?: boolean }} getFindings
 * @param {string} toolId
 * @param {{ dataset?: string, allowSample?: boolean, label?: string }} [o]
 * @returns {() => void}
 */
export function attachSinkButton(container, getFindings, toolId, { dataset, allowSample = false, label } = {}) {
  if (!container) return () => {};
  const wrap = document.createElement("span");
  wrap.className = "dn-sink";
  wrap.style.cssText = "display:inline-flex;align-items:center;gap:8px;flex-wrap:wrap";
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "btn ghost sm dn-sink-btn";
  const note = document.createElement("span");
  note.className = "muted";
  note.style.cssText = "font-size:.72rem;display:none";
  wrap.append(btn, note);
  container.appendChild(wrap);

  let done = false;
  function update() {
    if (done) return;
    let findings = [], sample = false;
    try { const r = getFindings() || {}; findings = r.findings || []; sample = !!r.sample; } catch (_) {}
    const n = findings.length;
    btn.textContent = label || `Add ${n} finding${n === 1 ? "" : "s"} to Security Graph`;
    const blocked = sample && !allowSample;
    btn.disabled = blocked || n === 0;
    btn.title = blocked ? "Sample data is not written to the Security Graph" : "";
    note.textContent = blocked ? "Sample data is not written to the Security Graph" : "";
    note.style.display = blocked ? "" : "none";
  }

  btn.onclick = async () => {
    let r = {};
    try { r = getFindings() || {}; } catch (_) {}
    const findings = r.findings || [];
    if (!findings.length || (r.sample && !allowSample)) return;
    btn.disabled = true;
    try {
      const res = await publishFindings(toolId, findings, { dataset, sample: !!r.sample });
      done = true;
      btn.textContent = "Added to graph";
      toast(`Security Graph: ${res.created} added, ${res.updated} updated`, "success");
    } catch (err) {
      btn.disabled = false;
      toast((err && err.message) || "Couldn't reach the Security Graph", "error");
    }
  };

  update();
  return update;
}
