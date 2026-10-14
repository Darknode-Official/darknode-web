// Supply Chain Risk Analyzer — map and score software supply chain risk.
// Vulnerabilities come live from OSV.dev (version-accurate), typosquats from real
// edit-distance against popular names, severity from the CVSS v3 base formula.
// Pure logic lives in supply-chain-engine.js (tested); this file is the UI.
// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved.

import {
  OSV_ECOSYSTEM, autoDetectAndParse, typosquat, summarizeVuln, scoreRisk, generateSBOM,
} from "./supply-chain-engine.js";
import { osvQuery, osvVuln, pool } from "./codescan/github.js";

const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
// Severity as text colour only (no inline background: the pro-theme catch-all
// rewrites `background:#0…/#1…`, which would wash coloured chips to white).
const SEV = { critical: "#b00020", high: "#c0501b", medium: "#8a6d00", low: "var(--mut)" };
const scoreColor = (s) => (s >= 80 ? "#1b7f4d" : s >= 60 ? "#8a6d00" : s >= 40 ? "#c0501b" : "#b00020");

// ============================================================================
// SUPPLY CHAIN ATTACK INCIDENTS — documented real-world cases
// ============================================================================
const SC_INCIDENTS = [
  { name: 'SolarWinds SUNBURST', year: 2020, type: 'Build system compromise', impact: '18,000+ organizations including US government agencies', desc: 'Russian APT29 compromised SolarWinds build pipeline, inserting SUNBURST backdoor into Orion software updates. Detected by FireEye when attackers used stolen red team tools.', lesson: 'Build system integrity is critical. Implement reproducible builds and binary attestation.' },
  { name: 'Codecov Bash Uploader', year: 2021, type: 'CI/CD compromise', impact: 'Thousands of repositories had credentials exfiltrated', desc: 'Attackers modified Codecov Bash Uploader script to exfiltrate environment variables (secrets, tokens, keys) from CI/CD pipelines.', lesson: 'Pin and verify checksums of CI/CD scripts. Never trust remote scripts blindly.' },
  { name: 'event-stream (npm)', year: 2018, type: 'Maintainer takeover', impact: 'Copay Bitcoin wallet users had funds stolen', desc: 'Attacker gained maintainer access to event-stream, added flatmap-stream dependency with encrypted payload targeting Copay wallet.', lesson: 'Monitor dependency changes. Be wary of maintainer transfers on popular packages.' },
  { name: 'ua-parser-js (npm)', year: 2021, type: 'Account hijack', impact: 'Cryptominer and password stealer distributed to millions', desc: 'Attacker hijacked npm account of ua-parser-js maintainer, published versions with cryptominer (Linux) and credential stealer (Windows).', lesson: 'Enable 2FA on package registry accounts. Monitor for unexpected version bumps.' },
  { name: 'colors + faker (npm)', year: 2022, type: 'Maintainer sabotage', impact: 'Thousands of projects broken, infinite loop in production', desc: 'Maintainer Marak Squires deliberately sabotaged colors.js (infinite loop) and faker.js (deleted all code) in protest of unpaid open source work.', lesson: 'Pin dependency versions. Have a fallback plan for critical dependencies.' },
  { name: 'node-ipc protestware', year: 2022, type: 'Maintainer sabotage', impact: 'File overwrites on systems with Russian/Belarusian IPs', desc: 'Maintainer added code that checked geolocation and overwrote files on Russian/Belarusian systems with heart emojis, as protest against Ukraine invasion.', lesson: 'Protestware is a real supply chain threat. Lockfiles and version pinning help.' },
  { name: 'Log4Shell (Log4j)', year: 2021, type: 'Zero-day in ubiquitous library', impact: 'Virtually all Java applications worldwide affected', desc: 'Critical JNDI injection vulnerability in Apache Log4j 2.x allowed remote code execution via crafted log messages. Exploited within hours of disclosure.', lesson: 'Maintain an SBOM. Know what transitive dependencies you ship.' },
  { name: 'XZ Utils backdoor', year: 2024, type: 'Multi-year social engineering', impact: 'Near-compromise of SSH on most Linux distributions', desc: 'Attacker spent 2+ years building trust as xz-utils contributor, then inserted a sophisticated backdoor targeting OpenSSH sshd. Caught by Andres Freund noticing 500ms SSH latency.', lesson: 'Social engineering can target open source. Review all contributions carefully, especially to critical infrastructure.' },
  { name: 'Kaseya VSA', year: 2021, type: 'Managed service provider attack', impact: '1,500+ businesses hit with REvil ransomware', desc: 'REvil exploited zero-days in Kaseya VSA (remote management tool) to push ransomware to MSP customers downstream.', lesson: 'Supply chain attacks can cascade through service providers.' },
  { name: 'PyPI typosquatting campaign', year: 2023, type: 'Typosquatting', impact: '100,000+ downloads of malicious packages', desc: 'Multiple campaigns publishing packages with names similar to popular ones (e.g., requesrs, python-binance, beautifulsoup) containing credential stealers.', lesson: 'Verify package names carefully. Use allowlists for approved packages.' },
  { name: '3CX Supply Chain Attack', year: 2023, type: 'Build compromise via upstream', impact: '12 million+ 3CX users potentially affected', desc: 'North Korean Lazarus group compromised 3CX desktop app by first compromising Trading Technologies X_TRADER app — a supply chain attack via another supply chain attack.', lesson: 'Supply chain attacks can chain through multiple vendors.' },
  { name: 'Dependency Confusion', year: 2021, type: 'Namespace confusion', impact: 'Apple, Microsoft, PayPal, Tesla, Uber all affected', desc: 'Researcher Alex Birsan discovered that private package names could be hijacked by publishing higher-version public packages. Package managers preferred the public version.', lesson: 'Use scoped packages. Configure registries to prefer private sources.' },
  { name: 'Okta source code theft', year: 2022, type: 'Source code compromise', impact: 'Okta source code repositories accessed', desc: 'Lapsus$ group accessed Okta source code repositories via compromised contractor account, potentially enabling future supply chain attacks.', lesson: 'Contractor access should be limited and monitored.' },
  { name: 'MOVEit Transfer', year: 2023, type: 'Zero-day in file transfer', impact: '2,700+ organizations, 93M+ individuals affected', desc: 'Cl0p ransomware gang exploited zero-day SQLi in MOVEit Transfer to mass-steal data from organizations using the file transfer tool.', lesson: 'File transfer tools are high-value targets. Patch immediately, monitor for anomalies.' },
  { name: 'Polyfill.io domain takeover', year: 2024, type: 'CDN/domain takeover', impact: '100,000+ websites serving malicious code', desc: 'Chinese company acquired polyfill.io domain and CDN, then injected malicious redirects into the polyfill script served to millions of websites.', lesson: 'Self-host critical JavaScript. Never trust third-party CDNs for production code.' },
];

// ============================================================================
// BUILD PIPELINE SECURITY CHECKLIST
// ============================================================================
const PIPELINE_CHECKLIST = [
  { category: 'Source Control', item: 'Require signed commits (GPG/SSH)', priority: 'High' },
  { category: 'Source Control', item: 'Enable branch protection on main/release branches', priority: 'Critical' },
  { category: 'Source Control', item: 'Require PR reviews from CODEOWNERS', priority: 'High' },
  { category: 'Source Control', item: 'Scan commits for secrets (git-secrets, trufflehog, gitleaks)', priority: 'Critical' },
  { category: 'Source Control', item: 'Disable force push on protected branches', priority: 'High' },
  { category: 'Source Control', item: 'Audit repository access permissions quarterly', priority: 'Medium' },
  { category: 'Source Control', item: 'Enable audit logging for all repo actions', priority: 'High' },
  { category: 'Dependencies', item: 'Pin all dependency versions (lockfile committed)', priority: 'Critical' },
  { category: 'Dependencies', item: 'Run vulnerability scanner on every build (npm audit, pip-audit, trivy)', priority: 'Critical' },
  { category: 'Dependencies', item: 'Use a private registry/mirror for approved packages', priority: 'High' },
  { category: 'Dependencies', item: 'Generate and maintain SBOM for every release', priority: 'High' },
  { category: 'Dependencies', item: 'Monitor for dependency confusion (scoped packages, namespace claim)', priority: 'High' },
  { category: 'Dependencies', item: 'Review all new dependency additions in PRs', priority: 'Medium' },
  { category: 'Dependencies', item: 'Set up Dependabot/Renovate for automated updates', priority: 'Medium' },
  { category: 'Dependencies', item: 'Block packages with no license or known-bad licenses', priority: 'Low' },
  { category: 'Dependencies', item: 'Monitor for typosquat packages in your ecosystem', priority: 'Medium' },
  { category: 'CI/CD', item: 'Run CI in ephemeral, isolated containers', priority: 'Critical' },
  { category: 'CI/CD', item: 'Never expose secrets in CI logs (mask all env vars)', priority: 'Critical' },
  { category: 'CI/CD', item: 'Use short-lived, scoped CI tokens (not long-lived PATs)', priority: 'High' },
  { category: 'CI/CD', item: 'Pin CI action/plugin versions by SHA, not tag', priority: 'High' },
  { category: 'CI/CD', item: 'Separate build and deploy pipelines with approval gates', priority: 'High' },
  { category: 'CI/CD', item: 'Enable OIDC federation for cloud deployments (no static keys)', priority: 'High' },
  { category: 'CI/CD', item: 'Scan IaC templates (Terraform, CloudFormation) for misconfigs', priority: 'Medium' },
  { category: 'CI/CD', item: 'Run SAST (static analysis) on every PR', priority: 'High' },
  { category: 'CI/CD', item: 'Run DAST (dynamic analysis) on staging deployments', priority: 'Medium' },
  { category: 'CI/CD', item: 'Verify webhook signatures on CI triggers', priority: 'Medium' },
  { category: 'Artifacts', item: 'Sign all release artifacts (Sigstore/cosign, GPG)', priority: 'High' },
  { category: 'Artifacts', item: 'Publish checksums (SHA-256) for all downloadable binaries', priority: 'High' },
  { category: 'Artifacts', item: 'Use reproducible builds where possible', priority: 'Medium' },
  { category: 'Artifacts', item: 'Scan container images for vulnerabilities before pushing', priority: 'Critical' },
  { category: 'Artifacts', item: 'Use minimal base images (distroless, Alpine)', priority: 'Medium' },
  { category: 'Artifacts', item: 'Tag images with digest, not mutable tags', priority: 'High' },
  { category: 'Artifacts', item: 'Enable container image signing and verification', priority: 'Medium' },
  { category: 'Runtime', item: 'Implement runtime application self-protection (RASP)', priority: 'Low' },
  { category: 'Runtime', item: 'Monitor for anomalous dependency loading at runtime', priority: 'Medium' },
  { category: 'Runtime', item: 'Use Seccomp/AppArmor profiles for containers', priority: 'Medium' },
  { category: 'Runtime', item: 'Enable read-only container filesystems', priority: 'Medium' },
  { category: 'Governance', item: 'Maintain an approved package allowlist', priority: 'Medium' },
  { category: 'Governance', item: 'Require security review for new dependencies', priority: 'High' },
  { category: 'Governance', item: 'Document and test incident response for supply chain compromise', priority: 'High' },
];

// ============================================================================
// RENDER
// ============================================================================
export function renderSupplyChainAnalyzer(main) {
  let deps = [];          // parsed dependencies from the last analyze
  let activeTab = "analyze";

  function render() {
    main.innerHTML =
      '<h1 class="pg-h1">Supply Chain Risk Analyzer</h1>' +
      '<p class="muted pg-sub">Scan your dependencies against live OSV.dev advisories, detect typosquats, and generate an SBOM.</p>' +
      '<div class="tab-bar" style="overflow-x:auto;flex-wrap:nowrap">' +
        '<button class="tab' + (activeTab === "analyze" ? " active" : "") + '" data-tab="analyze">Analyze</button>' +
        '<button class="tab' + (activeTab === "incidents" ? " active" : "") + '" data-tab="incidents">Attack Incidents</button>' +
        '<button class="tab' + (activeTab === "checklist" ? " active" : "") + '" data-tab="checklist">Pipeline Security</button>' +
        '<button class="tab' + (activeTab === "sbom" ? " active" : "") + '" data-tab="sbom">SBOM Generator</button>' +
      '</div>' +
      '<div id="sca-content" style="margin-top:12px"></div>';

    main.querySelector(".tab-bar").onclick = (e) => {
      const b = e.target.closest(".tab");
      if (!b) return;
      activeTab = b.dataset.tab;
      render();
    };

    const content = main.querySelector("#sca-content");
    if (activeTab === "analyze") renderAnalyzeTab(content);
    else if (activeTab === "incidents") renderIncidentsTab(content);
    else if (activeTab === "checklist") renderChecklistTab(content);
    else if (activeTab === "sbom") renderSBOMTab(content);
  }

  function renderAnalyzeTab(container) {
    container.innerHTML =
      '<div style="margin-bottom:6px">' +
        '<label style="font-size:.8rem;color:var(--mut);display:block;margin-bottom:4px">Dependency manifest or lockfile</label>' +
        '<textarea class="tk-in" id="sca-input" rows="8" placeholder="Paste a dependency file here"></textarea>' +
        '<p style="font-size:.72rem;color:var(--mut);margin:4px 0 0;line-height:1.5">Supports package.json, package-lock.json, requirements.txt, Gemfile, go.mod and pom.xml. ' +
          'A lockfile (pinned versions) gives exact results; a manifest with version ranges is scanned at the lower bound of each range.</p>' +
      '</div>' +
      '<div class="tk-btns" style="margin-top:10px">' +
        '<button class="btn sm" id="sca-analyze">Analyze dependencies</button>' +
        '<button class="btn sm ghost" id="sca-sample">Load sample</button>' +
      '</div>' +
      '<div id="sca-results" style="margin-top:16px"></div>';

    container.querySelector("#sca-sample").onclick = function () {
      container.querySelector("#sca-input").value = JSON.stringify({
        name: "example-app", version: "1.0.0",
        dependencies: { express: "4.17.1", lodash: "4.17.11", moment: "2.29.1", axios: "0.21.1", minimist: "1.2.5", "node-fetch": "2.6.1", semver: "7.3.5", tar: "6.1.0" },
        devDependencies: { jest: "29.0.0", eslint: "8.0.0" },
      }, null, 2);
    };

    container.querySelector("#sca-analyze").onclick = async function () {
      const input = container.querySelector("#sca-input").value.trim();
      const results = container.querySelector("#sca-results");
      if (!input) return;
      const parsed = autoDetectAndParse(input);
      if (!parsed || parsed.length === 0) {
        results.innerHTML = '<p style="color:' + SEV.high + '">Could not parse dependencies. Check that the format is one of the supported manifests or lockfiles.</p>';
        return;
      }
      deps = parsed;
      const btn = this; btn.disabled = true;
      results.innerHTML = '<p class="muted">Querying OSV.dev for ' + deps.length + ' dependencies…</p>';

      // Build OSV queries; keep a back-reference to the rich dep on each.
      const queryable = deps.filter((d) => d.version && OSV_ECOSYSTEM[d.ecosystem]);
      const byDep = new Map(); // rich dep -> Set(vuln ids)
      let osvError = "";
      if (queryable.length) {
        try {
          const hits = await osvQuery(queryable.map((d) => ({ name: d.name, ecosystem: OSV_ECOSYSTEM[d.ecosystem], version: d.version, _ref: d })));
          for (const h of hits) {
            const d = h.dep._ref;
            if (!byDep.has(d)) byDep.set(d, new Set());
            byDep.get(d).add(h.id);
          }
        } catch (e) { osvError = (e && e.message) || "OSV.dev request failed."; }
      }

      // Fetch advisory details for every unique id (bounded concurrency, cached).
      const ids = [...new Set([].concat(...[...byDep.values()].map((s) => [...s])))];
      const details = new Map();
      await pool(ids, 8, async (id) => { const v = await osvVuln(id); if (v) details.set(id, summarizeVuln(v)); });

      // Assemble findings per dependency: real vulns + typosquat suspicion.
      const rows = []; // {dep, finding}
      for (const d of deps) {
        for (const id of byDep.get(d) || []) {
          const s = details.get(id);
          if (s) rows.push({ dep: d, f: { type: "vulnerability", severity: s.severity, cve: s.cve, id: s.id, cvss: s.cvss, desc: s.summary || s.id, fix: s.fixed ? "Upgrade to " + s.fixed : "No fixed version published" } });
        }
        const ts = typosquat(d.name, d.ecosystem);
        if (ts) rows.push({ dep: d, f: { type: "typosquat", severity: "high", desc: 'Name is edit-distance ' + ts.distance + ' from the popular package "' + ts.real + '". Confirm this is the package you intend.', fix: 'Verify, or use "' + ts.real + '"' } });
      }

      const flat = rows.map((r) => r.f);
      const riskScore = scoreRisk(flat);
      const count = { critical: 0, high: 0, medium: 0, low: 0 };
      flat.forEach((f) => { count[f.severity] = (count[f.severity] || 0) + 1; });
      const anyRange = deps.some((d) => d.version && !d.exact);
      const unversioned = deps.filter((d) => !d.version).length;

      let html = '<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px">' +
        kpi(riskScore + "/100", "RISK SCORE", scoreColor(riskScore)) +
        kpi(deps.length, "DEPENDENCIES") +
        kpi(count.critical, "CRITICAL", SEV.critical) +
        kpi(count.high, "HIGH", SEV.high) +
        kpi(count.medium, "MEDIUM", SEV.medium) +
      '</div>';

      html += '<p style="font-size:.72rem;color:var(--mut);margin:0 0 12px;line-height:1.5">Advisories from OSV.dev, matched against each version server-side. ' +
        (anyRange ? 'Some versions are ranges; those were scanned at the range lower bound — paste a lockfile for exact results. ' : "") +
        (unversioned ? unversioned + " dependency(ies) had no resolvable version and were not scanned. " : "") +
        'Typosquat suspicion is a name-similarity heuristic, not proof.</p>';

      if (osvError) html += '<p style="color:' + SEV.high + ';font-size:.78rem">Live advisory lookup failed: ' + esc(osvError) + ' Dependencies were parsed but not scanned for vulnerabilities.</p>';

      if (rows.length > 0) {
        html += '<h3 style="margin:0 0 8px;font-size:.9rem">Findings (' + rows.length + ')</h3>' +
          '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.78rem">' +
          '<thead><tr style="border-bottom:2px solid var(--line)">' +
          ["Package", "Version", "Severity", "Type", "Issue", "Fix"].map((h) => '<th style="padding:6px;text-align:left;color:var(--mut)">' + h + "</th>").join("") +
          "</tr></thead><tbody>";
        rows.sort((a, b) => sevRank(b.f.severity) - sevRank(a.f.severity));
        rows.forEach((r) => {
          const f = r.f, c = SEV[f.severity] || "var(--mut)";
          const ref = f.id ? '<a href="https://osv.dev/vulnerability/' + encodeURIComponent(f.id) + '" target="_blank" rel="noopener" style="color:var(--acc)">' + esc(f.cve || f.id) + "</a>" : "";
          html += '<tr style="border-bottom:1px solid var(--line)">' +
            '<td style="padding:6px;font-weight:600;overflow-wrap:anywhere">' + esc(r.dep.name) + "</td>" +
            '<td style="padding:6px;color:var(--mut)">' + esc(r.dep.version || "—") + (r.dep.exact ? "" : ' <span title="lower bound of a range">~</span>') + "</td>" +
            '<td style="padding:6px"><span style="color:' + c + ';font-weight:600;text-transform:uppercase;font-size:.7rem">' + esc(f.severity) + (f.cvss != null ? " " + f.cvss : "") + "</span></td>" +
            '<td style="padding:6px;font-size:.72rem">' + esc(f.type) + (ref ? " (" + ref + ")" : "") + "</td>" +
            '<td style="padding:6px;overflow-wrap:anywhere">' + esc(f.desc) + "</td>" +
            '<td style="padding:6px;color:' + SEV.low + ';overflow-wrap:anywhere">' + esc(f.fix) + "</td>" +
          "</tr>";
        });
        html += "</tbody></table></div>";
      } else if (!osvError) {
        html += '<p style="color:' + scoreColor(100) + ';font-size:.82rem">No known advisories or typosquats matched the scanned dependencies.</p>';
      }

      const withFindings = new Set(rows.map((r) => r.dep));
      const clean = deps.filter((d) => !withFindings.has(d));
      if (clean.length > 0) {
        html += '<details style="margin-top:12px"><summary style="cursor:pointer;font-size:.82rem;color:var(--mut)">' + clean.length + ' dependencies with no matched issues</summary>' +
          '<div style="margin-top:8px;font-size:.78rem;color:var(--mut);overflow-wrap:anywhere">' + clean.map((d) => esc(d.name) + "@" + esc(d.version || "?")).join(", ") + "</div></details>";
      }

      btn.disabled = false;
      results.innerHTML = html;
    };
  }

  function kpi(big, label, color) {
    return '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px 20px;min-width:110px">' +
      '<div style="font-size:1.6rem;font-weight:700' + (color ? ";color:" + color : "") + '">' + esc(big) + "</div>" +
      '<div style="font-size:.72rem;color:var(--mut)">' + esc(label) + "</div></div>";
  }
  function sevRank(s) { return { critical: 4, high: 3, medium: 2, low: 1 }[s] || 0; }

  function renderIncidentsTab(container) {
    container.innerHTML =
      '<h2 class="pg-h2">Supply Chain Attack Incidents</h2>' +
      '<p class="muted" style="margin-bottom:16px">' + SC_INCIDENTS.length + ' documented supply chain attacks with timeline, impact, and lessons learned.</p>' +
      '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:12px">' +
      SC_INCIDENTS.map(function (inc) {
        return '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px">' +
          '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">' +
            '<span style="font-weight:700;font-size:.9rem">' + esc(inc.name) + '</span>' +
            '<span style="font-size:.65rem;color:var(--acc);border:1px solid var(--acc);padding:1px 6px;border-radius:3px">' + inc.year + '</span>' +
          '</div>' +
          '<div style="font-size:.72rem;color:' + SEV.high + ';margin-bottom:4px">' + esc(inc.type) + '</div>' +
          '<div style="font-size:.78rem;color:var(--mut);margin-bottom:8px;line-height:1.5">' + esc(inc.desc) + '</div>' +
          '<div style="font-size:.75rem;margin-bottom:6px"><strong style="color:var(--txt)">Impact:</strong> <span style="color:' + SEV.critical + '">' + esc(inc.impact) + '</span></div>' +
          '<div style="font-size:.75rem;background:var(--card);border:1px solid var(--acc);border-radius:4px;padding:8px"><strong style="color:var(--acc)">Lesson:</strong> ' + esc(inc.lesson) + '</div>' +
        '</div>';
      }).join('') +
      '</div>';
  }

  function renderChecklistTab(container) {
    var saved = {};
    try { saved = JSON.parse(localStorage.getItem('sca_checklist') || '{}'); } catch (_) {}
    var categories = [];
    PIPELINE_CHECKLIST.forEach(function (item) { if (categories.indexOf(item.category) === -1) categories.push(item.category); });
    var completed = Object.keys(saved).filter(function (k) { return saved[k]; }).length;
    var total = PIPELINE_CHECKLIST.length;
    var pct = Math.round(completed / total * 100);
    var pctColor = pct >= 80 ? scoreColor(85) : pct >= 50 ? SEV.medium : SEV.high;

    container.innerHTML =
      '<h2 class="pg-h2">Build Pipeline Security Checklist</h2>' +
      '<p class="muted" style="margin-bottom:8px">' + total + ' items across ' + categories.length + ' categories. Your progress is saved locally.</p>' +
      '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:12px 16px;margin-bottom:16px;display:flex;align-items:center;gap:12px">' +
        '<div style="font-size:1.6rem;font-weight:700;color:' + pctColor + '">' + pct + '%</div>' +
        '<div style="flex:1;height:8px;background:var(--line);border-radius:4px;overflow:hidden"><div style="height:100%;width:' + pct + '%;background:' + pctColor + ';border-radius:4px;transition:width .3s"></div></div>' +
        '<div style="font-size:.78rem;color:var(--mut)">' + completed + ' / ' + total + '</div>' +
      '</div>' +
      '<div id="sca-checklist-items">' +
      categories.map(function (cat) {
        var items = PIPELINE_CHECKLIST.filter(function (i) { return i.category === cat; });
        return '<h3 style="font-size:.85rem;margin:16px 0 6px;color:var(--acc)">' + esc(cat) + '</h3>' +
          items.map(function (item, idx) {
            var key = cat + '_' + idx;
            var checked = saved[key] ? ' checked' : '';
            var prioColor = item.priority === 'Critical' ? SEV.critical : item.priority === 'High' ? SEV.high : item.priority === 'Medium' ? SEV.medium : 'var(--mut)';
            return '<label style="display:flex;align-items:flex-start;gap:8px;padding:6px 0;font-size:.8rem;cursor:pointer;border-bottom:1px solid var(--line)">' +
              '<input type="checkbox" data-key="' + esc(key) + '"' + checked + ' style="margin-top:3px">' +
              '<span' + (checked ? ' style="text-decoration:line-through;color:var(--mut)"' : '') + '>' + esc(item.item) + '</span>' +
              '<span style="margin-left:auto;font-size:.65rem;color:' + prioColor + ';font-weight:600;white-space:nowrap">' + esc(item.priority) + '</span>' +
            '</label>';
          }).join('');
      }).join('') +
      '</div>';

    container.querySelector('#sca-checklist-items').addEventListener('change', function (e) {
      if (e.target.type === 'checkbox' && e.target.dataset.key) {
        saved[e.target.dataset.key] = e.target.checked;
        try { localStorage.setItem('sca_checklist', JSON.stringify(saved)); } catch (_) {}
        render();
      }
    });
  }

  function renderSBOMTab(container) {
    if (deps.length === 0) {
      container.innerHTML = '<p class="muted" style="padding:40px;text-align:center">Analyze dependencies first (Analyze tab), then generate an SBOM.</p>';
      return;
    }
    container.innerHTML =
      '<h2 class="pg-h2">Software Bill of Materials</h2>' +
      '<p class="muted" style="margin-bottom:12px">Generate an SBOM from your ' + deps.length + ' analyzed dependencies.</p>' +
      '<div class="tk-btns">' +
        '<button class="btn sm" id="sca-cyclonedx">Generate CycloneDX (XML)</button>' +
        '<button class="btn sm ghost" id="sca-spdx">Generate SPDX</button>' +
        '<button class="btn sm ghost" id="sca-copy">Copy</button>' +
      '</div>' +
      '<pre class="tk-out" id="sca-sbom-out" style="margin-top:12px;max-height:400px;overflow:auto"></pre>';

    const out = container.querySelector('#sca-sbom-out');
    container.querySelector('#sca-cyclonedx').onclick = function () { out.textContent = generateSBOM(deps, 'cyclonedx'); };
    container.querySelector('#sca-spdx').onclick = function () { out.textContent = generateSBOM(deps, 'spdx'); };
    container.querySelector('#sca-copy').onclick = async function () {
      if (!out.textContent) return;
      try { await navigator.clipboard.writeText(out.textContent); if (window.showToast) window.showToast("SBOM copied"); }
      catch (_) { if (window.showToast) window.showToast("Copy failed", "error"); }
    };
  }

  render();
}
