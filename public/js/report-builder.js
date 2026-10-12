// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved.
// Security Assessment Report Builder — generate professional pentest/VA reports.

const REPORT_TEMPLATES = [
  { id: "pentest", name: "Penetration Test Report", sections: ["cover", "executive_summary", "scope", "methodology", "findings", "risk_matrix", "recommendations", "appendix"] },
  { id: "va", name: "Vulnerability Assessment", sections: ["cover", "executive_summary", "scope", "scan_config", "findings", "risk_matrix", "remediation_plan", "appendix"] },
  { id: "compliance", name: "Compliance Audit Report", sections: ["cover", "executive_summary", "scope", "framework", "control_assessment", "gaps", "recommendations", "appendix"] },
  { id: "incident", name: "Incident Response Report", sections: ["cover", "executive_summary", "timeline", "root_cause", "impact", "containment", "remediation", "lessons_learned"] },
  { id: "risk", name: "Risk Assessment Report", sections: ["cover", "executive_summary", "scope", "asset_inventory", "threat_analysis", "risk_register", "treatment_plan", "appendix"] },
  { id: "architecture", name: "Security Architecture Review", sections: ["cover", "executive_summary", "scope", "architecture_overview", "findings", "threat_model", "recommendations", "appendix"] }
];

const esc = (v) => String(v == null ? "" : v).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const rbToast = (m, t) => { try { (window.dnToast || window.showToast || (() => {}))(m, t); } catch (_) {} };

const CVSS_METRICS = {
  AV: { name: "Attack Vector", values: [{ key: "N", label: "Network", score: 0.85 }, { key: "A", label: "Adjacent", score: 0.62 }, { key: "L", label: "Local", score: 0.55 }, { key: "P", label: "Physical", score: 0.2 }] },
  AC: { name: "Attack Complexity", values: [{ key: "L", label: "Low", score: 0.77 }, { key: "H", label: "High", score: 0.44 }] },
  PR: { name: "Privileges Required", values: [{ key: "N", label: "None", score: 0.85 }, { key: "L", label: "Low", score: 0.62 }, { key: "H", label: "High", score: 0.27 }] },
  UI: { name: "User Interaction", values: [{ key: "N", label: "None", score: 0.85 }, { key: "R", label: "Required", score: 0.62 }] },
  S: { name: "Scope", values: [{ key: "U", label: "Unchanged", score: 0 }, { key: "C", label: "Changed", score: 1 }] },
  C: { name: "Confidentiality", values: [{ key: "H", label: "High", score: 0.56 }, { key: "L", label: "Low", score: 0.22 }, { key: "N", label: "None", score: 0 }] },
  I: { name: "Integrity", values: [{ key: "H", label: "High", score: 0.56 }, { key: "L", label: "Low", score: 0.22 }, { key: "N", label: "None", score: 0 }] },
  A: { name: "Availability", values: [{ key: "H", label: "High", score: 0.56 }, { key: "L", label: "Low", score: 0.22 }, { key: "N", label: "None", score: 0 }] }
};

function calculateCVSS(metrics) {
  const av = metrics.AV, ac = metrics.AC, pr = metrics.PR, ui = metrics.UI;
  const s = metrics.S, c = metrics.C, i = metrics.I, a = metrics.A;
  if ([av, ac, pr, ui, s, c, i, a].some(v => v === undefined)) return null;
  const iss = 1 - ((1 - c) * (1 - i) * (1 - a));
  let impact, exploitability;
  if (s === 0) {
    impact = 6.42 * iss;
  } else {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  }
  const prAdj = s === 1 ? (pr === 0.62 ? 0.68 : pr === 0.27 ? 0.50 : pr) : pr;
  exploitability = 8.22 * av * ac * prAdj * ui;
  if (impact <= 0) return 0;
  let score;
  if (s === 0) {
    score = Math.min(impact + exploitability, 10);
  } else {
    score = Math.min(1.08 * (impact + exploitability), 10);
  }
  return Math.ceil(score * 10) / 10;
}

function severityFromScore(score) {
  if (score >= 9.0) return { label: "Critical", color: "#dc2626" };
  if (score >= 7.0) return { label: "High", color: "#f97316" };
  if (score >= 4.0) return { label: "Medium", color: "#eab308" };
  if (score >= 0.1) return { label: "Low", color: "#22c55e" };
  return { label: "None", color: "#6b7280" };
}

export function renderReportBuilder(container) {
  let findings = [];
  let selectedTemplate = REPORT_TEMPLATES[0];
  let view = "template";

  function renderTemplateSelect() {
    view = "template";
    container.innerHTML = `
      <div style="max-width:900px;margin:40px auto;padding:20px">
        <h1 style="margin:0 0 8px;font-size:1.8rem;font-weight:800;color:var(--txt,#f9fafb)">Security Report Builder</h1>
        <p style="margin:0 0 24px;font-size:.9rem;color:var(--mut,#9ca3af)">Generate professional security assessment reports. Choose a template to get started.</p>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:14px;margin-bottom:24px">
          ${REPORT_TEMPLATES.map(t => `
            <div class="tmpl-card" data-id="${t.id}" style="background:var(--surface,#111827);border:1px solid var(--border,#1f2937);border-radius:10px;padding:18px;cursor:pointer;transition:border-color .2s">
              <h3 style="margin:0 0 6px;font-size:1rem;font-weight:700;color:var(--txt,#f9fafb)">${t.name}</h3>
              <p style="margin:0;font-size:.78rem;color:var(--mut,#6b7280)">${t.sections.length} sections</p>
            </div>
          `).join("")}
        </div>
        <div style="background:var(--surface,#111827);border:1px solid var(--border,#1f2937);border-radius:10px;padding:18px">
          <div style="display:flex;justify-content:space-between;align-items:center;margin:0 0 12px">
            <h3 style="margin:0;font-size:1rem;font-weight:700;color:var(--txt,#f9fafb)">Findings (${findings.length})</h3>
            <button id="add-finding" class="btn sm">Add Finding</button>
          </div>
          <div style="display:grid;gap:8px">
            ${findings.length ? findings.map((f, i) => {
              const sev = { critical: "#dc2626", high: "#f97316", medium: "#eab308", low: "#22c55e", info: "#3b82f6" };
              return `<div style="display:flex;justify-content:space-between;align-items:center;gap:8px;padding:10px 14px;background:rgba(255,255,255,.02);border-radius:6px">
                <div><span style="font-size:.65rem;padding:2px 6px;border-radius:3px;background:${sev[f.severity]}22;color:${sev[f.severity]};border:1px solid ${sev[f.severity]}44;text-transform:uppercase;font-weight:700;margin-right:8px">${esc(f.severity)}</span><span style="font-size:.85rem;color:var(--txt,#f9fafb)">${esc(f.title)}</span></div>
                <span style="display:flex;align-items:center;gap:8px;flex-shrink:0"><span style="font-size:.8rem;color:var(--mut,#6b7280)">${f.cvss != null ? "CVSS " + f.cvss : ""}</span><button class="btn sm ghost" data-del="${i}">Remove</button></span>
              </div>`;
            }).join("") : `<p style="margin:0;padding:10px 0;font-size:.85rem;color:var(--mut,#9ca3af)">No findings yet. Add a finding.</p>`}
          </div>
        </div>
        <button id="gen-report" style="margin-top:16px;background:var(--acc,#00d4ff);color:#000;border:none;padding:12px 24px;border-radius:4px;font-size:.95rem;font-weight:700;cursor:pointer">Generate Report Preview</button>
      </div>`;
    container.querySelectorAll(".tmpl-card").forEach(card => {
      card.onmouseenter = () => card.style.borderColor = "var(--acc,#00d4ff)";
      card.onmouseleave = () => card.style.borderColor = "var(--border,#1f2937)";
      card.onclick = () => {
        container.querySelectorAll(".tmpl-card").forEach(c => c.style.borderColor = "var(--border,#1f2937)");
        card.style.borderColor = "var(--acc,#00d4ff)";
        selectedTemplate = REPORT_TEMPLATES.find(t => t.id === card.dataset.id);
      };
    });
    container.querySelector("#add-finding").onclick = addFinding;
    container.querySelectorAll("[data-del]").forEach(btn => {
      btn.onclick = () => { findings.splice(Number(btn.dataset.del), 1); renderTemplateSelect(); };
    });
    container.querySelector("#gen-report").onclick = () => {
      if (!findings.length) { rbToast("Add at least one finding first", "error"); return; }
      renderReport();
    };
  }

  async function addFinding() {
    if (!window.dnModal) { rbToast("Dialog unavailable, reload the page", "error"); return; }
    const r = await window.dnModal({
      title: "Add Finding",
      desc: "Title and severity are required. Severity: critical, high, medium, low or info.",
      fields: [
        { label: "Title", placeholder: "Finding title" },
        { label: "Severity", placeholder: "e.g. high" },
        { label: "CVSS score (optional)", placeholder: "0.0-10.0", inputType: "number" },
        { label: "CWE (optional)", placeholder: "e.g. CWE-79" },
        { label: "Description", type: "textarea", rows: 3 },
        { label: "Impact", type: "textarea", rows: 2 },
        { label: "Steps to reproduce", type: "textarea", rows: 3 },
        { label: "Evidence (optional)", type: "textarea", rows: 3 },
        { label: "Remediation", type: "textarea", rows: 3 },
        { label: "Affected systems (comma-separated)", placeholder: "/api/login, web01" }
      ],
      submitText: "Add"
    });
    if (!r) return;
    const title = r[0].trim();
    const severity = r[1].trim().toLowerCase();
    if (!title || SEVERITIES.indexOf(severity) < 0) {
      rbToast(!title ? "Finding needs a title" : "Severity must be critical, high, medium, low or info", "error");
      return;
    }
    const cvssNum = parseFloat(r[2]);
    findings.push({
      title, severity,
      cvss: isNaN(cvssNum) ? null : Math.min(10, Math.max(0, cvssNum)),
      cwe: r[3].trim(), cvss_vector: "",
      description: r[4].trim(), impact: r[5].trim(), steps_to_reproduce: r[6].trim(),
      evidence: r[7].trim(), remediation: r[8].trim(),
      affected_systems: r[9].split(",").map(x => x.trim()).filter(Boolean), references: [], status: "open"
    });
    renderTemplateSelect();
  }

  function renderReport() {
    view = "report";
    const sorted = [...findings].sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      return (order[a.severity] || 5) - (order[b.severity] || 5);
    });
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of sorted) counts[f.severity] = (counts[f.severity] || 0) + 1;
    const total = sorted.length;
    const now = new Date().toISOString().split("T")[0];
    const sev = { critical: "#dc2626", high: "#f97316", medium: "#eab308", low: "#22c55e", info: "#3b82f6" };

    container.innerHTML = `
      <div style="max-width:900px;margin:20px auto;padding:20px">
        <button id="report-back" style="background:none;border:1px solid var(--border,#374151);color:var(--txt,#f9fafb);padding:6px 14px;border-radius:4px;cursor:pointer;font-size:.82rem;margin-bottom:16px">← Back to Builder</button>

        <div style="background:var(--surface,#111827);border:1px solid var(--border,#1f2937);border-radius:12px;overflow:hidden">
          <!-- Cover Page -->
          <div style="padding:60px 40px;text-align:center;border-bottom:1px solid var(--border,#1f2937);background:linear-gradient(135deg,rgba(0,212,255,.05),rgba(124,92,255,.05))">
            <div style="font-size:.7rem;color:var(--acc,#00d4ff);text-transform:uppercase;letter-spacing:.15em;font-weight:700;margin-bottom:12px">Confidential</div>
            <h1 style="margin:0 0 8px;font-size:2rem;font-weight:800;color:var(--txt,#f9fafb)">${selectedTemplate.name}</h1>
            <p style="margin:0 0 4px;font-size:1rem;color:var(--mut,#9ca3af)">Prepared by: Darknode Security Team</p>
            <p style="margin:0;font-size:.85rem;color:var(--mut,#6b7280)">Date: ${now} | Version: 1.0</p>
          </div>

          <!-- Executive Summary -->
          <div style="padding:30px 40px;border-bottom:1px solid var(--border,#1f2937)">
            <h2 style="margin:0 0 16px;font-size:1.3rem;font-weight:700;color:var(--acc,#00d4ff)">Executive Summary</h2>
            <p style="font-size:.9rem;color:var(--mut,#d1d5db);line-height:1.7;margin:0 0 16px">
              This ${selectedTemplate.name.toLowerCase()} identified <strong style="color:var(--txt,#f9fafb)">${total} findings</strong> across the target environment.
              Of these, <strong style="color:#dc2626">${counts.critical} are critical</strong>, <strong style="color:#f97316">${counts.high} are high</strong>,
              <strong style="color:#eab308">${counts.medium} are medium</strong>, and <strong style="color:#22c55e">${counts.low} are low</strong> severity.
              Immediate attention is required for critical and high severity findings to reduce the organization's risk exposure.
            </p>
            <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px">
              ${["critical", "high", "medium", "low"].map(s => `
                <div style="text-align:center;padding:16px;border-radius:8px;border:1px solid ${sev[s]}33;background:${sev[s]}11">
                  <div style="font-size:2rem;font-weight:800;color:${sev[s]}">${counts[s]}</div>
                  <div style="font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;color:${sev[s]}">${s}</div>
                </div>
              `).join("")}
            </div>
          </div>

          <!-- Risk Matrix -->
          <div style="padding:30px 40px;border-bottom:1px solid var(--border,#1f2937)">
            <h2 style="margin:0 0 16px;font-size:1.3rem;font-weight:700;color:var(--acc,#00d4ff)">Risk Matrix</h2>
            <div style="display:grid;grid-template-columns:40px repeat(5,1fr);grid-template-rows:repeat(5,40px) 40px;gap:2px;max-width:400px">
              ${[5,4,3,2,1].map((likelihood, li) => {
                return [0,1,2,3,4,5].map(impact => {
                  if (impact === 0) return `<div style="display:flex;align-items:center;justify-content:center;font-size:.6rem;color:var(--mut,#6b7280)">${likelihood}</div>`;
                  const risk = likelihood * impact;
                  const bg = risk >= 15 ? "#dc262644" : risk >= 8 ? "#f9731644" : risk >= 4 ? "#eab30844" : "#22c55e44";
                  const findingsHere = sorted.filter(f => {
                    const s = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
                    return s[f.severity] === likelihood && impact === Math.ceil(f.cvss / 2);
                  });
                  return `<div style="background:${bg};border-radius:3px;display:flex;align-items:center;justify-content:center;font-size:.7rem;font-weight:700;color:var(--txt,#f9fafb)">${findingsHere.length || ""}</div>`;
                }).join("");
              }).join("")}
              <div></div>
              ${[1,2,3,4,5].map(i => `<div style="display:flex;align-items:center;justify-content:center;font-size:.6rem;color:var(--mut,#6b7280)">${i}</div>`).join("")}
            </div>
            <div style="margin-top:8px;font-size:.7rem;color:var(--mut,#6b7280)">Y-axis: Likelihood | X-axis: Impact</div>
          </div>

          <!-- Findings -->
          <div style="padding:30px 40px">
            <h2 style="margin:0 0 20px;font-size:1.3rem;font-weight:700;color:var(--acc,#00d4ff)">Detailed Findings</h2>
            ${sorted.map((f, i) => `
              <div style="margin-bottom:24px;padding:20px;border:1px solid ${sev[f.severity]}33;border-radius:10px;border-left:4px solid ${sev[f.severity]}">
                <div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:10px">
                  <h3 style="margin:0;font-size:1.05rem;font-weight:700;color:var(--txt,#f9fafb)">Finding ${i + 1}: ${esc(f.title)}</h3>
                  <div style="display:flex;gap:8px;flex-shrink:0">
                    <span style="font-size:.65rem;padding:3px 8px;border-radius:4px;background:${sev[f.severity]}22;color:${sev[f.severity]};border:1px solid ${sev[f.severity]}44;text-transform:uppercase;font-weight:700">${esc(f.severity)}</span>
                    ${f.cvss != null ? `<span style="font-size:.75rem;padding:3px 8px;border-radius:4px;background:rgba(255,255,255,.05);color:var(--mut,#d1d5db)">CVSS ${f.cvss}</span>` : ""}
                  </div>
                </div>
                ${f.cwe || f.cvss_vector ? `<div style="font-size:.75rem;color:var(--mut,#6b7280);margin-bottom:10px">${esc([f.cwe, f.cvss_vector].filter(Boolean).join(" | "))}</div>` : ""}
                <div style="margin-bottom:12px"><h4 style="margin:0 0 4px;font-size:.8rem;font-weight:700;color:var(--mut,#9ca3af);text-transform:uppercase;letter-spacing:.04em">Description</h4><p style="margin:0;font-size:.85rem;color:var(--mut,#d1d5db);line-height:1.6">${esc(f.description)}</p></div>
                <div style="margin-bottom:12px"><h4 style="margin:0 0 4px;font-size:.8rem;font-weight:700;color:var(--mut,#9ca3af);text-transform:uppercase;letter-spacing:.04em">Impact</h4><p style="margin:0;font-size:.85rem;color:var(--mut,#d1d5db);line-height:1.6">${esc(f.impact)}</p></div>
                <div style="margin-bottom:12px"><h4 style="margin:0 0 4px;font-size:.8rem;font-weight:700;color:var(--mut,#9ca3af);text-transform:uppercase;letter-spacing:.04em">Steps to Reproduce</h4><pre style="margin:0;font-size:.78rem;color:#c9d1d9;background:#0d1117;padding:12px;border-radius:6px;overflow-x:auto;white-space:pre-wrap">${esc(f.steps_to_reproduce)}</pre></div>
                ${f.evidence ? `<div style="margin-bottom:12px"><h4 style="margin:0 0 4px;font-size:.8rem;font-weight:700;color:var(--mut,#9ca3af);text-transform:uppercase;letter-spacing:.04em">Evidence</h4><pre style="margin:0;font-size:.75rem;color:#c9d1d9;background:#0d1117;padding:12px;border-radius:6px;overflow-x:auto;white-space:pre-wrap">${esc(f.evidence)}</pre></div>` : ""}
                <div style="margin-bottom:12px"><h4 style="margin:0 0 4px;font-size:.8rem;font-weight:700;color:#22c55e;text-transform:uppercase;letter-spacing:.04em">Remediation</h4><pre style="margin:0;font-size:.82rem;color:var(--mut,#d1d5db);background:rgba(34,197,94,.05);border:1px solid rgba(34,197,94,.15);padding:12px;border-radius:6px;white-space:pre-wrap">${esc(f.remediation)}</pre></div>
                <div style="font-size:.75rem;color:var(--mut,#6b7280)">Affected: ${esc((f.affected_systems || []).join(", ") || "-")}${(f.references || []).length ? " | References: " + esc(f.references.join(", ")) : ""}</div>
              </div>
            `).join("")}
          </div>
        </div>
      </div>`;
    container.querySelector("#report-back").onclick = renderTemplateSelect;
  }

  renderTemplateSelect();
}
