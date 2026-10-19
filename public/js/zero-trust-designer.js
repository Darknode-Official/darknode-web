// Zero Trust Architecture Designer — design and assess zero trust implementations.
// Copyright (c) 2026 Darknode-Official. All rights reserved.

const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const ZT_PILLARS = [
  {
    id: 'identity', name: 'Identity', color: '#00e5ff',
    levels: ['Traditional', 'Initial', 'Advanced', 'Optimal'],
    questions: [
      { q: 'Is MFA enforced for all users?', scores: [0, 1, 2, 3], labels: ['No MFA', 'MFA for admins only', 'MFA for all users', 'Phishing-resistant MFA (FIDO2/WebAuthn)'] },
      { q: 'Is Single Sign-On (SSO) implemented?', scores: [0, 1, 2, 3], labels: ['No SSO', 'SSO for some apps', 'SSO for all cloud apps', 'SSO for all apps including on-prem'] },
      { q: 'How are identities governed?', scores: [0, 1, 2, 3], labels: ['Manual account management', 'Basic provisioning/deprovisioning', 'Automated lifecycle with access reviews', 'Continuous verification with risk-based access'] },
      { q: 'Is privileged access managed?', scores: [0, 1, 2, 3], labels: ['Shared admin accounts', 'Individual admin accounts', 'PAM solution with vaulting', 'Just-in-time access with zero standing privileges'] },
      { q: 'Is identity threat detection in place?', scores: [0, 1, 2, 3], labels: ['No monitoring', 'Basic login alerts', 'UEBA for anomaly detection', 'Real-time adaptive authentication'] },
      { q: 'Are service accounts secured?', scores: [0, 1, 2, 3], labels: ['Passwords in code/config', 'Centralized credential store', 'Managed identities/workload identity', 'Certificate-based with auto-rotation'] },
      { q: 'Is identity federation configured?', scores: [0, 1, 2, 3], labels: ['Separate identity per system', 'AD/LDAP for some', 'Federated identity (SAML/OIDC) for all', 'Cross-org federation with conditional access'] },
      { q: 'Are conditional access policies used?', scores: [0, 1, 2, 3], labels: ['No', 'Basic IP restrictions', 'Device + location + risk policies', 'Continuous evaluation with step-up auth'] },
      { q: 'Is passwordless authentication available?', scores: [0, 1, 2, 3], labels: ['Passwords only', 'Password + OTP', 'Passwordless for some users', 'Passwordless first for all'] },
      { q: 'How is offboarding handled?', scores: [0, 1, 2, 3], labels: ['Manual, often delayed', 'Ticketed process, 1-3 day SLA', 'Automated disable on HR trigger', 'Real-time revocation across all systems'] },
    ],
  },
  {
    id: 'devices', name: 'Devices', color: '#00e676',
    levels: ['Traditional', 'Initial', 'Advanced', 'Optimal'],
    questions: [
      { q: 'Is a device inventory maintained?', scores: [0, 1, 2, 3], labels: ['No inventory', 'Spreadsheet/manual', 'Automated discovery (MDM/EDR)', 'Real-time CMDB with risk scoring'] },
      { q: 'Are devices enrolled in management?', scores: [0, 1, 2, 3], labels: ['No management', 'Some devices managed', 'All corporate devices in MDM', 'All devices including BYOD with MAM'] },
      { q: 'Is device health assessed?', scores: [0, 1, 2, 3], labels: ['No health checks', 'Antivirus required', 'Compliance checks (patch, encryption, config)', 'Continuous health attestation for access'] },
      { q: 'Is endpoint protection deployed?', scores: [0, 1, 2, 3], labels: ['No EDR/AV', 'Basic antivirus', 'EDR with behavioral detection', 'XDR with automated response'] },
      { q: 'Is disk encryption enforced?', scores: [0, 1, 2, 3], labels: ['No encryption', 'Optional', 'Required on corporate devices', 'Verified before granting access'] },
      { q: 'Are unmanaged devices handled?', scores: [0, 1, 2, 3], labels: ['Full access', 'Blocked from network', 'Limited access via VDI/web', 'Risk-scored access per resource'] },
      { q: 'Is patch management automated?', scores: [0, 1, 2, 3], labels: ['Manual patching', 'Scheduled monthly', 'Automated with compliance reporting', 'Auto-patch with risk-based prioritization'] },
      { q: 'Are firmware/BIOS protections enabled?', scores: [0, 1, 2, 3], labels: ['No', 'Secure boot only', 'TPM + Secure Boot', 'Hardware root of trust + attestation'] },
      { q: 'Is mobile device security enforced?', scores: [0, 1, 2, 3], labels: ['No mobile policy', 'Basic MDM', 'App-level protection (MAM)', 'Zero-trust mobile access with MTD'] },
      { q: 'Can compromised devices be isolated?', scores: [0, 1, 2, 3], labels: ['No capability', 'Manual isolation', 'Automated network quarantine', 'Real-time isolation with remediation'] },
    ],
  },
  {
    id: 'network', name: 'Network', color: '#ffd600',
    levels: ['Traditional', 'Initial', 'Advanced', 'Optimal'],
    questions: [
      { q: 'Is network segmentation implemented?', scores: [0, 1, 2, 3], labels: ['Flat network', 'VLANs for major zones', 'Micro-segmentation between workloads', 'Identity-based micro-perimeters'] },
      { q: 'Is east-west traffic inspected?', scores: [0, 1, 2, 3], labels: ['No inspection', 'IDS at zone boundaries', 'Deep packet inspection between segments', 'Encrypted traffic analysis + behavioral'] },
      { q: 'How is remote access provided?', scores: [0, 1, 2, 3], labels: ['Full VPN to network', 'Split-tunnel VPN', 'ZTNA per-application access', 'Continuous verification per-session'] },
      { q: 'Is DNS security implemented?', scores: [0, 1, 2, 3], labels: ['No DNS filtering', 'Basic DNS filtering', 'DNS over HTTPS/TLS with threat feeds', 'DNS analytics with anomaly detection'] },
      { q: 'Are network flows logged?', scores: [0, 1, 2, 3], labels: ['No logging', 'Perimeter firewall logs', 'Full flow logs (NetFlow/VPC)', 'Real-time flow analysis with baseline'] },
      { q: 'Is lateral movement detection in place?', scores: [0, 1, 2, 3], labels: ['No detection', 'Basic IDS rules', 'Behavioral analytics for lateral', 'Deception technology + honey tokens'] },
      { q: 'Are cloud networks secured?', scores: [0, 1, 2, 3], labels: ['Default VPC config', 'Security groups configured', 'Private endpoints + no public IPs', 'Cloud-native firewalls + flow analytics'] },
      { q: 'Is TLS/encryption enforced internally?', scores: [0, 1, 2, 3], labels: ['HTTP internally', 'TLS for sensitive services', 'TLS everywhere (mutual TLS for services)', 'Certificate-based mTLS with auto-rotation'] },
      { q: 'Is a Secure Web Gateway deployed?', scores: [0, 1, 2, 3], labels: ['No', 'Proxy for web traffic', 'SWG with SSL inspection', 'CASB + SWG + DLP integrated'] },
      { q: 'Are unused ports/services disabled?', scores: [0, 1, 2, 3], labels: ['Many open services', 'Some hardening', 'Default deny with exceptions', 'Automated port scanning + remediation'] },
    ],
  },
  {
    id: 'applications', name: 'Applications', color: '#d500f9',
    levels: ['Traditional', 'Initial', 'Advanced', 'Optimal'],
    questions: [
      { q: 'Is application access controlled?', scores: [0, 1, 2, 3], labels: ['Network-level access', 'VPN + app login', 'Identity-aware proxy', 'Continuous authorization per action'] },
      { q: 'Are APIs secured?', scores: [0, 1, 2, 3], labels: ['No API security', 'API keys', 'OAuth2 + rate limiting', 'API gateway with threat detection'] },
      { q: 'Is SAST/DAST in CI/CD?', scores: [0, 1, 2, 3], labels: ['No scanning', 'Manual pen tests', 'SAST in CI pipeline', 'SAST + DAST + SCA + secrets scanning'] },
      { q: 'Are containers secured?', scores: [0, 1, 2, 3], labels: ['No container security', 'Image scanning', 'Runtime protection + admission control', 'Full CNAPP with shift-left'] },
      { q: 'Is supply chain security addressed?', scores: [0, 1, 2, 3], labels: ['No SBOM', 'Manual dependency tracking', 'Automated SCA with CVE alerting', 'SBOM + signed builds + provenance'] },
      { q: 'Are SaaS applications governed?', scores: [0, 1, 2, 3], labels: ['No SaaS visibility', 'Known SaaS list', 'CASB for sanctioned apps', 'Full SaaS security posture management'] },
      { q: 'Is least privilege applied to apps?', scores: [0, 1, 2, 3], labels: ['Full access for all', 'Role-based access', 'Attribute-based access control', 'Just-in-time app access'] },
      { q: 'Is application behavior monitored?', scores: [0, 1, 2, 3], labels: ['No monitoring', 'Error logging', 'APM + security logging', 'RASP + behavioral anomaly detection'] },
    ],
  },
  {
    id: 'data', name: 'Data', color: '#ff1744',
    levels: ['Traditional', 'Initial', 'Advanced', 'Optimal'],
    questions: [
      { q: 'Is data classified?', scores: [0, 1, 2, 3], labels: ['No classification', 'Manual labels', 'Automated classification', 'ML-driven continuous classification'] },
      { q: 'Is data loss prevention deployed?', scores: [0, 1, 2, 3], labels: ['No DLP', 'Email DLP only', 'Endpoint + cloud DLP', 'Unified DLP across all channels'] },
      { q: 'Is data encrypted at rest?', scores: [0, 1, 2, 3], labels: ['No encryption', 'Database encryption', 'Full disk + database', 'Field-level + customer-managed keys'] },
      { q: 'Is data encrypted in transit?', scores: [0, 1, 2, 3], labels: ['Some HTTP', 'TLS for external', 'TLS everywhere', 'mTLS + certificate pinning'] },
      { q: 'Are backups secured?', scores: [0, 1, 2, 3], labels: ['Unencrypted backups', 'Encrypted backups', 'Immutable + encrypted', 'Air-gapped + tested + immutable'] },
      { q: 'Is data access audited?', scores: [0, 1, 2, 3], labels: ['No auditing', 'Admin access logged', 'All access logged', 'Real-time DLP alerts on anomalous access'] },
      { q: 'Is data residency/sovereignty addressed?', scores: [0, 1, 2, 3], labels: ['Not considered', 'Aware of requirements', 'Region-locked storage', 'Automated enforcement with alerts'] },
      { q: 'Is sensitive data discovery automated?', scores: [0, 1, 2, 3], labels: ['No', 'Manual audits', 'Scheduled scans', 'Continuous real-time discovery'] },
    ],
  },
];

const ZT_VENDORS = [
  { name: 'Microsoft Entra', pillars: ['identity', 'devices', 'applications'], strengths: 'Deep Microsoft ecosystem integration, conditional access, Intune MDM', tier: 'Enterprise' },
  { name: 'Okta', pillars: ['identity'], strengths: 'Best-of-breed identity, wide SSO catalog, workforce + customer identity', tier: 'Enterprise' },
  { name: 'CrowdStrike', pillars: ['devices'], strengths: 'Leading EDR/XDR, threat intelligence, identity protection', tier: 'Enterprise' },
  { name: 'Zscaler', pillars: ['network', 'applications'], strengths: 'ZTNA, SWG, CASB as cloud-native service, no VPN needed', tier: 'Enterprise' },
  { name: 'Palo Alto Prisma', pillars: ['network', 'applications', 'data'], strengths: 'SASE, CNAPP, cloud security, network security', tier: 'Enterprise' },
  { name: 'Cloudflare Zero Trust', pillars: ['network', 'applications'], strengths: 'Free tier available, ZTNA, DNS filtering, browser isolation', tier: 'Mid-market' },
  { name: 'Google BeyondCorp', pillars: ['network', 'identity', 'devices'], strengths: 'Pioneered zero trust, Chrome Enterprise integration', tier: 'Enterprise' },
  { name: 'Tailscale', pillars: ['network'], strengths: 'Simple WireGuard mesh VPN, identity-aware, free for personal', tier: 'Startup' },
  { name: 'Duo Security (Cisco)', pillars: ['identity', 'devices'], strengths: 'Easy MFA deployment, device trust, free tier', tier: 'Mid-market' },
  { name: 'JumpCloud', pillars: ['identity', 'devices'], strengths: 'Cloud directory, cross-OS device management, SMB-friendly', tier: 'Mid-market' },
  { name: 'Netskope', pillars: ['network', 'data', 'applications'], strengths: 'CASB, DLP, SWG, ZTNA — strong data protection', tier: 'Enterprise' },
  { name: 'Illumio', pillars: ['network'], strengths: 'Micro-segmentation specialist, workload visibility', tier: 'Enterprise' },
  { name: 'HashiCorp Vault', pillars: ['identity', 'data'], strengths: 'Secrets management, dynamic credentials, encryption as a service', tier: 'Enterprise' },
  { name: 'Wiz', pillars: ['applications', 'data'], strengths: 'Cloud security posture, vulnerability prioritization, agentless', tier: 'Enterprise' },
  { name: 'SentinelOne', pillars: ['devices'], strengths: 'Autonomous EDR, AI-powered detection, cloud workload protection', tier: 'Enterprise' },
  { name: 'Fortinet', pillars: ['network'], strengths: 'FortiGate NGFW, SD-WAN, SASE, integrated security fabric', tier: 'Mid-market' },
  { name: 'Proofpoint', pillars: ['data', 'identity'], strengths: 'Email security, DLP, insider threat, security awareness', tier: 'Enterprise' },
  { name: 'Varonis', pillars: ['data'], strengths: 'Data security platform, permissions analysis, insider threat detection', tier: 'Enterprise' },
  { name: 'BeyondTrust', pillars: ['identity'], strengths: 'Privileged access management, secure remote access, endpoint privilege', tier: 'Enterprise' },
  { name: 'Keeper Security', pillars: ['identity'], strengths: 'Password manager, secrets management, connection manager, affordable', tier: 'Startup' },
];

const ZT_ROADMAP = [
  { phase: 1, title: 'Quick Wins (0-3 months)', items: ['Enable MFA for all users (start with admins)', 'Deploy SSO for top 10 applications', 'Create device inventory', 'Enable disk encryption on all endpoints', 'Implement DNS filtering', 'Review and remove excessive admin accounts', 'Enable security logging on critical systems'], cost: 'Low ($5K-25K)', impact: 'High' },
  { phase: 2, title: 'Foundation (3-6 months)', items: ['Deploy EDR/XDR on all endpoints', 'Implement conditional access policies', 'Set up PAM for privileged accounts', 'Segment network into security zones', 'Deploy SIEM with core detection rules', 'Classify sensitive data stores', 'Begin ZTNA pilot (replace VPN for 1-2 apps)'], cost: 'Medium ($25K-100K)', impact: 'High' },
  { phase: 3, title: 'Advanced (6-12 months)', items: ['Roll out ZTNA for all remote access', 'Implement micro-segmentation between workloads', 'Deploy UEBA for identity analytics', 'Implement DLP across email, endpoint, cloud', 'Deploy CASB for SaaS governance', 'Automate device compliance enforcement', 'Implement mTLS for service-to-service'], cost: 'High ($100K-500K)', impact: 'Medium' },
  { phase: 4, title: 'Optimal (12-18 months)', items: ['Continuous verification — never trust, always verify', 'Automated threat response and isolation', 'Zero standing privileges — all access is just-in-time', 'AI-driven risk scoring for every access decision', 'Complete data classification with automated enforcement', 'Deception technology throughout the environment', 'Full supply chain security with signed builds'], cost: 'High ($250K-1M+)', impact: 'Medium' },
];

function getStoredAssessment() {
  try { return JSON.parse(localStorage.getItem('zt_assessment') || 'null'); } catch (e) { return null; }
}
function saveAssessment(data) {
  try { localStorage.setItem('zt_assessment', JSON.stringify(data)); } catch (e) {}
}

export function renderZeroTrustDesigner(main) {
  var activeTab = 'assess';
  var assessment = getStoredAssessment() || {};

  function render() {
    var tabs = [
      { id: 'assess', label: 'Maturity Assessment' },
      { id: 'gaps', label: 'Gap Analysis' },
      { id: 'roadmap', label: 'Implementation Roadmap' },
      { id: 'vendors', label: 'Vendor Comparison' },
      { id: 'policies', label: 'Policy Generator' },
      { id: 'reference', label: 'NIST 800-207' },
    ];

    main.innerHTML =
      '<h1 class="pg-h1">Zero Trust Architecture Designer</h1>' +
      '<p class="muted pg-sub">Assess your zero trust maturity across 5 pillars, identify gaps, and build an implementation roadmap. Based on CISA Zero Trust Maturity Model.</p>' +
      '<div class="tab-bar" style="overflow-x:auto;flex-wrap:nowrap">' +
        tabs.map(function(t) { return '<button class="tab' + (activeTab === t.id ? ' active' : '') + '" data-tab="' + t.id + '">' + t.label + '</button>'; }).join('') +
      '</div>' +
      '<div id="zt-content" style="margin-top:12px"></div>';

    main.querySelector('.tab-bar').onclick = function(e) {
      var b = e.target.closest('.tab');
      if (b) { activeTab = b.dataset.tab; render(); }
    };

    var content = main.querySelector('#zt-content');
    if (activeTab === 'assess') renderAssessTab(content);
    else if (activeTab === 'gaps') renderGapsTab(content);
    else if (activeTab === 'roadmap') renderRoadmapTab(content);
    else if (activeTab === 'vendors') renderVendorsTab(content);
    else if (activeTab === 'policies') renderPoliciesTab(content);
    else if (activeTab === 'reference') renderReferenceTab(content);
  }

  function renderAssessTab(container) {
    var html = '<p class="muted" style="margin-bottom:16px">Answer each question honestly to assess your current zero trust maturity. Progress is saved automatically.</p>';
    ZT_PILLARS.forEach(function(pillar) {
      var pillarScores = assessment[pillar.id] || {};
      var totalScore = 0;
      var maxScore = pillar.questions.length * 3;
      pillar.questions.forEach(function(q, i) { totalScore += (pillarScores[i] || 0); });
      var pct = Math.round(totalScore / maxScore * 100);
      var level = pct < 25 ? 'Traditional' : pct < 50 ? 'Initial' : pct < 75 ? 'Advanced' : 'Optimal';

      html += '<div style="background:var(--card);border:1px solid var(--line);border-left:3px solid ' + pillar.color + ';border-radius:6px;padding:16px;margin-bottom:12px">' +
        '<div style="display:flex;align-items:center;gap:12px;margin-bottom:12px">' +
          '<div style="font-weight:700;font-size:1rem;color:' + pillar.color + '">' + esc(pillar.name) + '</div>' +
          '<div style="flex:1;background:var(--line);height:6px;border-radius:3px;overflow:hidden"><div style="height:100%;width:' + pct + '%;background:' + pillar.color + ';border-radius:3px;transition:width .3s"></div></div>' +
          '<div style="font-size:.8rem;font-weight:600;color:' + pillar.color + '">' + pct + '% — ' + level + '</div>' +
        '</div>';

      pillar.questions.forEach(function(q, qi) {
        var current = pillarScores[qi] || 0;
        html += '<div style="margin-bottom:8px;font-size:.8rem">' +
          '<div style="margin-bottom:4px;color:var(--txt)">' + esc(q.q) + '</div>' +
          '<div style="display:flex;gap:4px;flex-wrap:wrap">';
        q.labels.forEach(function(label, li) {
          var isSelected = current === li;
          html += '<button class="zt-opt" data-pillar="' + pillar.id + '" data-qi="' + qi + '" data-val="' + li + '" style="padding:4px 10px;font-size:.72rem;border-radius:4px;cursor:pointer;border:1px solid ' + (isSelected ? pillar.color : 'var(--line)') + ';background:' + (isSelected ? pillar.color + '22' : 'transparent') + ';color:' + (isSelected ? pillar.color : 'var(--mut)') + '">' + esc(label) + '</button>';
        });
        html += '</div></div>';
      });
      html += '</div>';
    });

    container.innerHTML = html;
    container.onclick = function(e) {
      var btn = e.target.closest('.zt-opt');
      if (!btn) return;
      var pillar = btn.dataset.pillar;
      var qi = parseInt(btn.dataset.qi);
      var val = parseInt(btn.dataset.val);
      if (!assessment[pillar]) assessment[pillar] = {};
      assessment[pillar][qi] = val;
      saveAssessment(assessment);
      render();
    };
  }

  function renderGapsTab(container) {
    var html = '<h2 class="pg-h2">Gap Analysis</h2>' +
      '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px;margin-bottom:16px">';

    var overallScore = 0;
    var overallMax = 0;
    ZT_PILLARS.forEach(function(pillar) {
      var pillarScores = assessment[pillar.id] || {};
      var totalScore = 0;
      var maxScore = pillar.questions.length * 3;
      pillar.questions.forEach(function(q, i) { totalScore += (pillarScores[i] || 0); });
      overallScore += totalScore;
      overallMax += maxScore;
      var pct = Math.round(totalScore / maxScore * 100);
      html += '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px;text-align:center">' +
        '<div style="font-size:2rem;font-weight:800;color:' + pillar.color + '">' + pct + '%</div>' +
        '<div style="font-size:.78rem;color:var(--mut)">' + esc(pillar.name) + '</div></div>';
    });
    var overallPct = overallMax > 0 ? Math.round(overallScore / overallMax * 100) : 0;
    html += '</div>' +
      '<div style="background:var(--card);border:1px solid var(--acc);border-radius:6px;padding:16px;margin-bottom:16px;text-align:center">' +
        '<div style="font-size:2.5rem;font-weight:800;color:var(--acc)">' + overallPct + '%</div>' +
        '<div style="font-size:.85rem;color:var(--mut)">Overall Zero Trust Maturity</div>' +
      '</div>';

    html += '<h3 style="margin:16px 0 8px">Weakest Areas (Priority Gaps)</h3>';
    var gaps = [];
    ZT_PILLARS.forEach(function(pillar) {
      var pillarScores = assessment[pillar.id] || {};
      pillar.questions.forEach(function(q, i) {
        var score = pillarScores[i] || 0;
        if (score < 2) {
          gaps.push({ pillar: pillar.name, color: pillar.color, question: q.q, current: q.labels[score], target: q.labels[3], score: score });
        }
      });
    });
    gaps.sort(function(a, b) { return a.score - b.score; });

    if (gaps.length > 0) {
      html += '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.78rem">' +
        '<thead><tr style="border-bottom:2px solid var(--line)">' +
          '<th style="padding:8px;text-align:left;color:var(--mut)">Pillar</th>' +
          '<th style="padding:8px;text-align:left;color:var(--mut)">Area</th>' +
          '<th style="padding:8px;text-align:left;color:var(--mut)">Current</th>' +
          '<th style="padding:8px;text-align:left;color:var(--mut)">Target</th>' +
        '</tr></thead><tbody>';
      gaps.slice(0, 15).forEach(function(g) {
        html += '<tr style="border-bottom:1px solid var(--line)">' +
          '<td style="padding:8px;color:' + g.color + ';font-weight:600">' + esc(g.pillar) + '</td>' +
          '<td style="padding:8px">' + esc(g.question) + '</td>' +
          '<td style="padding:8px;color:#ff9100">' + esc(g.current) + '</td>' +
          '<td style="padding:8px;color:#00e676">' + esc(g.target) + '</td>' +
        '</tr>';
      });
      html += '</tbody></table></div>';
    } else {
      html += '<p class="muted">Complete the assessment first to see gaps.</p>';
    }

    container.innerHTML = html;
  }

  function renderRoadmapTab(container) {
    var html = '<h2 class="pg-h2">Implementation Roadmap</h2>' +
      '<p class="muted" style="margin-bottom:16px">Phased approach to zero trust — quick wins first, then build the foundation.</p>';

    ZT_ROADMAP.forEach(function(phase) {
      html += '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:16px;margin-bottom:12px">' +
        '<div style="display:flex;align-items:center;gap:12px;margin-bottom:10px">' +
          '<div style="background:var(--acc);color:var(--bg);width:32px;height:32px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:.9rem">' + phase.phase + '</div>' +
          '<div><div style="font-weight:600;font-size:.95rem">' + esc(phase.title) + '</div>' +
          '<div style="font-size:.72rem;color:var(--mut)">Est. cost: ' + esc(phase.cost) + ' | Impact: ' + esc(phase.impact) + '</div></div>' +
        '</div>' +
        '<ul style="margin:0;padding-left:20px;font-size:.82rem;line-height:1.8">' +
        phase.items.map(function(item) { return '<li>' + esc(item) + '</li>'; }).join('') +
        '</ul></div>';
    });

    container.innerHTML = html;
  }

  function renderVendorsTab(container) {
    var html = '<h2 class="pg-h2">Zero Trust Vendor Comparison</h2>' +
      '<p class="muted" style="margin-bottom:16px">' + ZT_VENDORS.length + ' vendors compared by capability, pillar coverage, and market tier.</p>' +
      '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.78rem">' +
      '<thead><tr style="border-bottom:2px solid var(--line)">' +
        '<th style="padding:8px;text-align:left">Vendor</th>' +
        '<th style="padding:8px;text-align:left">Pillars</th>' +
        '<th style="padding:8px;text-align:left">Strengths</th>' +
        '<th style="padding:8px;text-align:left">Tier</th>' +
      '</tr></thead><tbody>';

    ZT_VENDORS.forEach(function(v) {
      html += '<tr style="border-bottom:1px solid var(--line)">' +
        '<td style="padding:8px;font-weight:600">' + esc(v.name) + '</td>' +
        '<td style="padding:8px">' + v.pillars.map(function(p) {
          var pillar = ZT_PILLARS.find(function(pp) { return pp.id === p; });
          return '<span style="background:' + (pillar ? pillar.color : 'var(--acc)') + '22;color:' + (pillar ? pillar.color : 'var(--acc)') + ';padding:2px 6px;border-radius:3px;font-size:.68rem;margin-right:4px">' + esc(p) + '</span>';
        }).join('') + '</td>' +
        '<td style="padding:8px;color:var(--mut)">' + esc(v.strengths) + '</td>' +
        '<td style="padding:8px"><span style="font-size:.7rem;padding:2px 6px;border:1px solid var(--line);border-radius:3px">' + esc(v.tier) + '</span></td>' +
      '</tr>';
    });
    html += '</tbody></table></div>';
    container.innerHTML = html;
  }

  function renderPoliciesTab(container) {
    var html = '<h2 class="pg-h2">Policy Generator</h2>' +
      '<p class="muted" style="margin-bottom:16px">Generate zero trust access policies based on your maturity level.</p>';

    var policies = [
      { name: 'Remote Access Policy', content: 'POLICY: Remote Access\nEffective: ' + new Date().toISOString().split('T')[0] + '\n\n1. All remote access MUST use ZTNA (Zero Trust Network Access)\n2. VPN access is DEPRECATED and will be decommissioned\n3. Each application requires individual authentication\n4. Device health compliance is REQUIRED before access\n5. Session duration: 8 hours maximum, re-authentication required\n6. MFA is MANDATORY for all remote sessions\n7. Unmanaged devices receive read-only access via browser isolation\n8. All remote sessions are logged and monitored\n9. Geographic restrictions: access only from approved countries\n10. Anomalous access patterns trigger step-up authentication' },
      { name: 'Privileged Access Policy', content: 'POLICY: Privileged Access Management\nEffective: ' + new Date().toISOString().split('T')[0] + '\n\n1. Zero standing privileges — all admin access is just-in-time\n2. Privileged sessions require MFA + manager approval\n3. Maximum session duration: 4 hours\n4. All privileged actions are recorded (video + command log)\n5. Break-glass accounts require dual approval\n6. Service accounts use managed identities (no passwords)\n7. Privileged Access Workstations (PAW) required for Tier 0\n8. Admin credentials are vaulted and rotated every 24 hours\n9. Lateral movement from privileged sessions is blocked\n10. Monthly access reviews for all privileged accounts' },
      { name: 'Data Classification Policy', content: 'POLICY: Data Classification\nEffective: ' + new Date().toISOString().split('T')[0] + '\n\nCLASSIFICATION LEVELS:\n- PUBLIC: No restrictions, freely shareable\n- INTERNAL: Business use only, no external sharing\n- CONFIDENTIAL: Need-to-know, encrypted at rest and transit\n- RESTRICTED: Highest sensitivity, additional DLP controls\n\nHANDLING REQUIREMENTS:\n- CONFIDENTIAL+: encryption required at rest (AES-256)\n- CONFIDENTIAL+: TLS 1.2+ required in transit\n- RESTRICTED: geographic restrictions apply\n- RESTRICTED: access logged and alerted\n- All levels: retention and disposal per schedule\n- All levels: backup and recovery tested quarterly' },
      { name: 'Network Segmentation Policy', content: 'POLICY: Network Micro-Segmentation\nEffective: ' + new Date().toISOString().split('T')[0] + '\n\nPRINCIPLES:\n1. Default deny — all traffic blocked unless explicitly allowed\n2. Least privilege — only required ports/protocols permitted\n3. Identity-aware — access decisions include user/device context\n\nZONES:\n- DMZ: internet-facing services only\n- APPLICATION: internal application servers\n- DATA: databases and file stores\n- MANAGEMENT: admin tools, SIEM, PAM\n- USER: workstations and endpoints\n- IOT: unmanaged devices, isolated\n\nRULES:\n- USER -> APPLICATION: HTTPS only, via identity proxy\n- APPLICATION -> DATA: specific ports, service account auth\n- No zone may communicate with MANAGEMENT except via jump host\n- IOT zone has NO access to DATA or MANAGEMENT\n- All east-west traffic logged and inspected' },
    ];

    policies.forEach(function(p) {
      html += '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px;margin-bottom:10px">' +
        '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">' +
          '<div style="font-weight:600">' + esc(p.name) + '</div>' +
          '<span style="flex:1"></span>' +
          '<button class="btn sm zt-copy-pol" data-policy="' + esc(p.name) + '">Copy</button>' +
        '</div>' +
        '<pre style="background:rgba(0,0,0,.2);padding:10px;border-radius:4px;font-size:.72rem;white-space:pre-wrap;max-height:200px;overflow-y:auto;margin:0">' + esc(p.content) + '</pre>' +
      '</div>';
    });

    container.innerHTML = html;
    container.querySelectorAll('.zt-copy-pol').forEach(function(btn) {
      btn.onclick = function() {
        var pol = policies.find(function(p) { return p.name === btn.dataset.policy; });
        if (pol) navigator.clipboard.writeText(pol.content).then(function() { btn.textContent = 'Copied!'; setTimeout(function() { btn.textContent = 'Copy'; }, 1500); });
      };
    });
  }

  function renderReferenceTab(container) {
    var tenets = [
      'All data sources and computing services are considered resources',
      'All communication is secured regardless of network location',
      'Access to individual enterprise resources is granted on a per-session basis',
      'Access to resources is determined by dynamic policy',
      'The enterprise monitors and measures the integrity and security posture of all owned and associated assets',
      'All resource authentication and authorization are dynamic and strictly enforced before access is allowed',
      'The enterprise collects as much information as possible about the current state of assets, network infrastructure and communications and uses it to improve its security posture',
    ];

    container.innerHTML = '<h2 class="pg-h2">NIST SP 800-207: Zero Trust Architecture</h2>' +
      '<p class="muted" style="margin-bottom:16px">The foundational standard for zero trust. Published by NIST in August 2020.</p>' +
      '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:16px;margin-bottom:16px">' +
        '<div style="font-weight:600;margin-bottom:10px">7 Tenets of Zero Trust</div>' +
        '<ol style="margin:0;padding-left:20px;font-size:.82rem;line-height:1.8">' +
          tenets.map(function(t) { return '<li style="margin-bottom:4px">' + esc(t) + '</li>'; }).join('') +
        '</ol>' +
      '</div>' +
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px">' +
          '<div style="font-weight:600;color:var(--acc);margin-bottom:8px">Core Components</div>' +
          '<ul style="margin:0;padding-left:16px;font-size:.8rem;line-height:1.7">' +
            '<li><strong>Policy Engine (PE)</strong> — makes access decisions</li>' +
            '<li><strong>Policy Administrator (PA)</strong> — executes decisions</li>' +
            '<li><strong>Policy Enforcement Point (PEP)</strong> — gates access</li>' +
            '<li><strong>CDM System</strong> — continuous diagnostics</li>' +
            '<li><strong>Threat Intelligence</strong> — feeds into policy</li>' +
            '<li><strong>SIEM</strong> — aggregates security data</li>' +
          '</ul>' +
        '</div>' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px">' +
          '<div style="font-weight:600;color:var(--acc);margin-bottom:8px">Deployment Models</div>' +
          '<ul style="margin:0;padding-left:16px;font-size:.8rem;line-height:1.7">' +
            '<li><strong>Enhanced Identity Governance</strong> — identity-centric</li>' +
            '<li><strong>Micro-segmentation</strong> — network-centric</li>' +
            '<li><strong>Software Defined Perimeters</strong> — app-centric</li>' +
            '<li>Most implementations combine all three</li>' +
          '</ul>' +
        '</div>' +
      '</div>';
  }

  render();
}
