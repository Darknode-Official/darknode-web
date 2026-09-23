// Darknode Project - CRUCIBLE :: Cyber Defense & Wargaming Command
// Core: shared data models, simulation engine and scoring.
// Copyright (c) 2026 Darknode-Official. All rights reserved.
//
// ============================ CONTRACT ============================
// This module is the single source of truth every CRUCIBLE pillar
// codes against. Pillars (range / autopilot / fusion / afteraction)
// import ONLY from here. Do not change the exported names or the
// shapes below without updating all pillars.
//
//   esc(s)                              -> HTML-escaped string
//   CRU                                 -> shared runtime state (singleton)
//   on(evt, fn) / off(evt, fn) / emit(evt, payload)  -> event bus
//   TACTICS                             -> ordered kill-chain tactic ids
//   TECHNIQUES  [{id,name,tactic,desc,detectability}]
//   ESTATE      {zones[], assets[], users[], crownJewels[]}
//   CAMPAIGNS   [{id,name,actor,sophistication,objective,steps[]}]
//               step: {techniqueId, targetAssetId, dwellMin, noise}
//   DETECTIONS  [{id,name,techniqueId,sensor,fidelity,coverage}]
//   POSTURES    [{id,name,mult}]        -> defensive posture options
//   ACTIONS     [{id,name,kind,cost,blocks[]}] -> containment actions
//
//   newRun(campaignId, opts)  -> run    opts:{postureId, autopilot}
//   stepRun(run)              -> {done, step, phase, events[], alerts[]}
//   resetRun(run)             -> run
//   applyAction(run, actionId, alertId?) -> {ok, note}
//   scoreRun(run)             -> {detectionRate, mttdMin, contained,
//                                 missed[], reached[], mitre{tactic:pct}, grade}
// =================================================================

export const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g,
  (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

export const uid = (p = 'id') => p + '_' + Math.random().toString(36).slice(2, 9);

// -------------------------------- event bus --------------------------------
const _bus = {};
export function on(evt, fn) { (_bus[evt] || (_bus[evt] = [])).push(fn); return () => off(evt, fn); }
export function off(evt, fn) { if (_bus[evt]) _bus[evt] = _bus[evt].filter((f) => f !== fn); }
export function emit(evt, payload) { (_bus[evt] || []).forEach((f) => { try { f(payload); } catch (_) {} }); }

// -------------------------------- shared state -----------------------------
export const CRU = {
  run: null,          // the active run
  history: [],        // completed runs
  tab: 'range',       // active pillar
  autopilot: true,    // default defender mode
};

// ------------------------------ ATT&CK model -------------------------------
// Ordered kill chain (defensive framing: earlier detection is better).
export const TACTICS = [
  { id: 'recon', name: 'Reconnaissance' },
  { id: 'initial-access', name: 'Initial Access' },
  { id: 'execution', name: 'Execution' },
  { id: 'persistence', name: 'Persistence' },
  { id: 'privilege-escalation', name: 'Privilege Escalation' },
  { id: 'defense-evasion', name: 'Defense Evasion' },
  { id: 'credential-access', name: 'Credential Access' },
  { id: 'discovery', name: 'Discovery' },
  { id: 'lateral-movement', name: 'Lateral Movement' },
  { id: 'collection', name: 'Collection' },
  { id: 'command-and-control', name: 'Command & Control' },
  { id: 'exfiltration', name: 'Exfiltration' },
  { id: 'impact', name: 'Impact' },
];
export const TACTIC_ORDER = TACTICS.reduce((m, t, i) => (m[t.id] = i, m), {});

// A representative technique library. Agent A (core) may extend this;
// keep {id,name,tactic,desc,detectability(0..1)} shape.
export const TECHNIQUES = [
  // -- Reconnaissance --
  { id: 'T1595', name: 'Active Scanning', tactic: 'recon', desc: 'Probe the perimeter for reachable services.', detectability: 0.55 },
  { id: 'T1592', name: 'Gather Victim Host Info', tactic: 'recon', desc: 'Fingerprint host software and configuration.', detectability: 0.35 },
  { id: 'T1589', name: 'Gather Victim Identity Info', tactic: 'recon', desc: 'Harvest employee emails and credentials from OSINT.', detectability: 0.25 },
  { id: 'T1590', name: 'Gather Victim Network Info', tactic: 'recon', desc: 'Map external network ranges and DNS records.', detectability: 0.3 },
  { id: 'T1598', name: 'Phishing for Information', tactic: 'recon', desc: 'Pretext outreach to elicit sensitive detail.', detectability: 0.4 },
  // -- Initial Access --
  { id: 'T1566', name: 'Phishing', tactic: 'initial-access', desc: 'Spearphishing link to harvest a foothold.', detectability: 0.45 },
  { id: 'T1190', name: 'Exploit Public-Facing App', tactic: 'initial-access', desc: 'Exploit an exposed web/service vulnerability.', detectability: 0.5 },
  { id: 'T1078', name: 'Valid Accounts', tactic: 'initial-access', desc: 'Log in with legitimate stolen credentials.', detectability: 0.3 },
  { id: 'T1195', name: 'Supply Chain Compromise', tactic: 'initial-access', desc: 'Trojanized dependency or update mechanism.', detectability: 0.25 },
  { id: 'T1133', name: 'External Remote Services', tactic: 'initial-access', desc: 'Abuse exposed VPN / RDP / remote gateway.', detectability: 0.4 },
  { id: 'T1199', name: 'Trusted Relationship', tactic: 'initial-access', desc: 'Enter via a trusted third-party connection.', detectability: 0.35 },
  // -- Execution --
  { id: 'T1059', name: 'Command & Scripting', tactic: 'execution', desc: 'Run attacker code via a shell/interpreter.', detectability: 0.6 },
  { id: 'T1053', name: 'Scheduled Task/Job', tactic: 'execution', desc: 'Execute payloads via cron / Task Scheduler.', detectability: 0.5 },
  { id: 'T1204', name: 'User Execution', tactic: 'execution', desc: 'Lure a user into opening a malicious file.', detectability: 0.45 },
  { id: 'T1569', name: 'System Services', tactic: 'execution', desc: 'Launch code through a service control manager.', detectability: 0.55 },
  { id: 'T1047', name: 'Windows Management Instrumentation', tactic: 'execution', desc: 'Execute commands over WMI.', detectability: 0.6 },
  // -- Persistence --
  { id: 'T1547', name: 'Boot/Logon Autostart', tactic: 'persistence', desc: 'Install persistence on a host.', detectability: 0.5 },
  { id: 'T1136', name: 'Create Account', tactic: 'persistence', desc: 'Add a rogue local or domain account.', detectability: 0.55 },
  { id: 'T1505', name: 'Server Software Component', tactic: 'persistence', desc: 'Plant a web shell or malicious module.', detectability: 0.45 },
  { id: 'T1098', name: 'Account Manipulation', tactic: 'persistence', desc: 'Add keys or roles to keep account access.', detectability: 0.45 },
  { id: 'T1543', name: 'Create/Modify System Process', tactic: 'persistence', desc: 'Register a malicious service or daemon.', detectability: 0.5 },
  // -- Privilege Escalation --
  { id: 'T1068', name: 'Exploit for Priv Esc', tactic: 'privilege-escalation', desc: 'Escalate to elevated privileges.', detectability: 0.5 },
  { id: 'T1055', name: 'Process Injection', tactic: 'privilege-escalation', desc: 'Inject code into a privileged process.', detectability: 0.55 },
  { id: 'T1484', name: 'Domain Policy Modification', tactic: 'privilege-escalation', desc: 'Abuse Group Policy for elevated control.', detectability: 0.45 },
  { id: 'T1548', name: 'Abuse Elevation Control', tactic: 'privilege-escalation', desc: 'Bypass UAC / sudo to elevate.', detectability: 0.5 },
  // -- Defense Evasion --
  { id: 'T1070', name: 'Indicator Removal', tactic: 'defense-evasion', desc: 'Clear logs and artifacts.', detectability: 0.35 },
  { id: 'T1027', name: 'Obfuscated Files or Info', tactic: 'defense-evasion', desc: 'Pack, encode or encrypt payloads.', detectability: 0.4 },
  { id: 'T1562', name: 'Impair Defenses', tactic: 'defense-evasion', desc: 'Disable EDR, logging or firewall rules.', detectability: 0.5 },
  { id: 'T1112', name: 'Modify Registry', tactic: 'defense-evasion', desc: 'Tamper with registry to hide activity.', detectability: 0.4 },
  { id: 'T1218', name: 'System Binary Proxy Exec', tactic: 'defense-evasion', desc: 'Live-off-the-land via signed binaries.', detectability: 0.45 },
  // -- Credential Access --
  { id: 'T1003', name: 'OS Credential Dumping', tactic: 'credential-access', desc: 'Dump credentials from memory/stores.', detectability: 0.55 },
  { id: 'T1110', name: 'Brute Force', tactic: 'credential-access', desc: 'Password spray or guess credentials.', detectability: 0.6 },
  { id: 'T1558', name: 'Steal/Forge Kerberos Tickets', tactic: 'credential-access', desc: 'Kerberoasting or golden-ticket forging.', detectability: 0.45 },
  { id: 'T1552', name: 'Unsecured Credentials', tactic: 'credential-access', desc: 'Find secrets in files, configs or history.', detectability: 0.4 },
  { id: 'T1555', name: 'Credentials from Password Stores', tactic: 'credential-access', desc: 'Extract secrets from vaults or browsers.', detectability: 0.5 },
  // -- Discovery --
  { id: 'T1046', name: 'Network Service Discovery', tactic: 'discovery', desc: 'Enumerate internal services.', detectability: 0.6 },
  { id: 'T1087', name: 'Account Discovery', tactic: 'discovery', desc: 'Enumerate local and domain accounts.', detectability: 0.5 },
  { id: 'T1018', name: 'Remote System Discovery', tactic: 'discovery', desc: 'Enumerate reachable hosts on the network.', detectability: 0.55 },
  { id: 'T1082', name: 'System Information Discovery', tactic: 'discovery', desc: 'Query host details for targeting.', detectability: 0.4 },
  { id: 'T1069', name: 'Permission Groups Discovery', tactic: 'discovery', desc: 'Enumerate privileged groups and roles.', detectability: 0.45 },
  // -- Lateral Movement --
  { id: 'T1021', name: 'Remote Services', tactic: 'lateral-movement', desc: 'Pivot to another host over RDP/SSH/SMB.', detectability: 0.55 },
  { id: 'T1550', name: 'Use Alternate Auth Material', tactic: 'lateral-movement', desc: 'Pass-the-hash / pass-the-ticket pivot.', detectability: 0.45 },
  { id: 'T1210', name: 'Exploit Remote Services', tactic: 'lateral-movement', desc: 'Exploit an internal service to move.', detectability: 0.55 },
  { id: 'T1534', name: 'Internal Spearphishing', tactic: 'lateral-movement', desc: 'Phish internally from a trusted mailbox.', detectability: 0.4 },
  { id: 'T1570', name: 'Lateral Tool Transfer', tactic: 'lateral-movement', desc: 'Copy tooling between internal hosts.', detectability: 0.5 },
  // -- Collection --
  { id: 'T1005', name: 'Data from Local System', tactic: 'collection', desc: 'Stage sensitive data for theft.', detectability: 0.4 },
  { id: 'T1039', name: 'Data from Network Shared Drive', tactic: 'collection', desc: 'Harvest data from file shares.', detectability: 0.45 },
  { id: 'T1114', name: 'Email Collection', tactic: 'collection', desc: 'Collect mailbox contents for intel.', detectability: 0.4 },
  { id: 'T1560', name: 'Archive Collected Data', tactic: 'collection', desc: 'Compress and encrypt staged data.', detectability: 0.45 },
  { id: 'T1119', name: 'Automated Collection', tactic: 'collection', desc: 'Script bulk harvesting of files.', detectability: 0.5 },
  // -- Command & Control --
  { id: 'T1071', name: 'App Layer Protocol C2', tactic: 'command-and-control', desc: 'Beacon to C2 over HTTPS/DNS.', detectability: 0.5 },
  { id: 'T1105', name: 'Ingress Tool Transfer', tactic: 'command-and-control', desc: 'Download additional tooling to a host.', detectability: 0.5 },
  { id: 'T1572', name: 'Protocol Tunneling', tactic: 'command-and-control', desc: 'Tunnel traffic to evade inspection.', detectability: 0.45 },
  { id: 'T1090', name: 'Proxy', tactic: 'command-and-control', desc: 'Relay C2 through intermediary hosts.', detectability: 0.4 },
  { id: 'T1568', name: 'Dynamic Resolution', tactic: 'command-and-control', desc: 'Use DGA / fast-flux to reach C2.', detectability: 0.45 },
  // -- Exfiltration --
  { id: 'T1041', name: 'Exfil Over C2 Channel', tactic: 'exfiltration', desc: 'Exfiltrate staged data.', detectability: 0.45 },
  { id: 'T1567', name: 'Exfil Over Web Service', tactic: 'exfiltration', desc: 'Push data to a cloud storage service.', detectability: 0.4 },
  { id: 'T1048', name: 'Exfil Over Alt Protocol', tactic: 'exfiltration', desc: 'Exfiltrate over DNS or ICMP.', detectability: 0.45 },
  { id: 'T1030', name: 'Data Transfer Size Limits', tactic: 'exfiltration', desc: 'Chunk exfil to evade thresholds.', detectability: 0.35 },
  { id: 'T1029', name: 'Scheduled Transfer', tactic: 'exfiltration', desc: 'Exfiltrate on a timed schedule to blend in.', detectability: 0.35 },
  // -- Impact --
  { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'impact', desc: 'Deploy ransomware / destroy data.', detectability: 0.7 },
  { id: 'T1490', name: 'Inhibit System Recovery', tactic: 'impact', desc: 'Delete shadow copies and backups.', detectability: 0.6 },
  { id: 'T1489', name: 'Service Stop', tactic: 'impact', desc: 'Stop critical services to disrupt ops.', detectability: 0.55 },
  { id: 'T1485', name: 'Data Destruction', tactic: 'impact', desc: 'Wipe data to cause irreversible loss.', detectability: 0.65 },
  { id: 'T1498', name: 'Network Denial of Service', tactic: 'impact', desc: 'Flood services to deny availability.', detectability: 0.7 },
];
export const TECH = TECHNIQUES.reduce((m, t) => (m[t.id] = t, m), {});

// ------------------------------ the estate ---------------------------------
export const ESTATE = {
  zones: [
    { id: 'dmz', name: 'DMZ / Perimeter', trust: 1 },
    { id: 'corp', name: 'Corporate LAN', trust: 2 },
    { id: 'cloud', name: 'Cloud / SaaS', trust: 2 },
    { id: 'ops', name: 'Operations / OT', trust: 3 },
    { id: 'crown', name: 'Restricted / Crown Jewels', trust: 4 },
  ],
  assets: [
    { id: 'a-web', name: 'edge-web-01', type: 'server', ip: '10.0.1.5', zone: 'dmz', os: 'Linux', crit: 3, services: ['https', 'ssh'] },
    { id: 'a-vpn', name: 'vpn-gateway', type: 'gateway', ip: '10.0.1.9', zone: 'dmz', os: 'Linux', crit: 4, services: ['ike', 'https'] },
    { id: 'a-mail', name: 'mail-relay', type: 'server', ip: '10.0.1.20', zone: 'dmz', os: 'Linux', crit: 3, services: ['smtp'] },
    { id: 'a-cdn', name: 'ext-cdn-edge', type: 'gateway', ip: '10.0.1.30', zone: 'dmz', os: 'Linux', crit: 2, services: ['https'] },
    { id: 'a-ws', name: 'hr-workstation-14', type: 'endpoint', ip: '10.0.2.14', zone: 'corp', os: 'Windows', crit: 2, services: ['smb'] },
    { id: 'a-ws2', name: 'fin-workstation-07', type: 'endpoint', ip: '10.0.2.17', zone: 'corp', os: 'Windows', crit: 3, services: ['smb'] },
    { id: 'a-ad', name: 'dc-primary', type: 'server', ip: '10.0.2.10', zone: 'corp', os: 'Windows', crit: 5, services: ['ldap', 'kerberos', 'smb'] },
    { id: 'a-file', name: 'file-cluster-01', type: 'server', ip: '10.0.2.30', zone: 'corp', os: 'Windows', crit: 4, services: ['smb'] },
    { id: 'a-jump', name: 'admin-jumpbox', type: 'server', ip: '10.0.2.5', zone: 'corp', os: 'Linux', crit: 4, services: ['ssh', 'rdp'] },
    { id: 'a-build', name: 'ci-build-01', type: 'server', ip: '10.0.2.60', zone: 'corp', os: 'Linux', crit: 4, services: ['https', 'ssh'] },
    { id: 'a-saas', name: 'm365-tenant', type: 'saas', ip: 'cloud', zone: 'cloud', os: 'SaaS', crit: 4, services: ['https', 'graph'] },
    { id: 'a-cloud', name: 'aws-prod-account', type: 'cloud', ip: 'cloud', zone: 'cloud', os: 'Cloud', crit: 5, services: ['https', 'api'] },
    { id: 'a-scada', name: 'scada-hist-01', type: 'ics', ip: '10.0.3.40', zone: 'ops', os: 'Windows', crit: 5, services: ['modbus', 'https'] },
    { id: 'a-plc', name: 'plc-controller-3', type: 'ics', ip: '10.0.3.55', zone: 'ops', os: 'RTOS', crit: 5, services: ['modbus'] },
    { id: 'a-db', name: 'db-classified', type: 'server', ip: '10.0.4.50', zone: 'crown', os: 'Linux', crit: 5, services: ['postgres'] },
    { id: 'a-vault', name: 'secrets-vault', type: 'server', ip: '10.0.4.60', zone: 'crown', os: 'Linux', crit: 5, services: ['https'] },
    { id: 'a-backup', name: 'backup-vault-01', type: 'server', ip: '10.0.4.70', zone: 'crown', os: 'Linux', crit: 5, services: ['https', 'nfs'] },
  ],
  users: [
    { id: 'u-hr', name: 'j.okafor', role: 'HR Analyst', priv: 'user', asset: 'a-ws' },
    { id: 'u-fin', name: 'l.marchetti', role: 'Finance Controller', priv: 'user', asset: 'a-ws2' },
    { id: 'u-adm', name: 'svc-backup', role: 'Service Account', priv: 'admin', asset: 'a-ad' },
    { id: 'u-dom', name: 'a.kessler', role: 'Domain Admin', priv: 'admin', asset: 'a-jump' },
    { id: 'u-dev', name: 'svc-ci', role: 'CI Service Account', priv: 'admin', asset: 'a-build' },
    { id: 'u-eng', name: 'p.reyes', role: 'OT Engineer', priv: 'user', asset: 'a-scada' },
    { id: 'u-cloud', name: 'svc-terraform', role: 'Cloud Automation', priv: 'admin', asset: 'a-cloud' },
  ],
  crownJewels: ['a-db', 'a-vault', 'a-scada', 'a-ad', 'a-backup', 'a-cloud', 'a-plc'],
};
export const ASSET = ESTATE.assets.reduce((m, a) => (m[a.id] = a, m), {});
export const ZONE = ESTATE.zones.reduce((m, z) => (m[z.id] = z, m), {});

// ------------------------------ adversaries --------------------------------
// Agent A may add more campaigns; keep the shape and reference real asset ids.
export const CAMPAIGNS = [
  {
    id: 'c-apt', name: 'SILENT HERON', actor: 'Nation-state APT', sophistication: 4,
    objective: 'Exfiltrate classified records from db-classified.',
    steps: [
      { techniqueId: 'T1595', targetAssetId: 'a-web', dwellMin: 20, noise: 0.4 },
      { techniqueId: 'T1566', targetAssetId: 'a-ws', dwellMin: 45, noise: 0.3 },
      { techniqueId: 'T1059', targetAssetId: 'a-ws', dwellMin: 15, noise: 0.5 },
      { techniqueId: 'T1547', targetAssetId: 'a-ws', dwellMin: 30, noise: 0.3 },
      { techniqueId: 'T1003', targetAssetId: 'a-ws', dwellMin: 25, noise: 0.5 },
      { techniqueId: 'T1021', targetAssetId: 'a-ad', dwellMin: 40, noise: 0.4 },
      { techniqueId: 'T1046', targetAssetId: 'a-ad', dwellMin: 20, noise: 0.6 },
      { techniqueId: 'T1021', targetAssetId: 'a-db', dwellMin: 50, noise: 0.4 },
      { techniqueId: 'T1005', targetAssetId: 'a-db', dwellMin: 30, noise: 0.3 },
      { techniqueId: 'T1071', targetAssetId: 'a-db', dwellMin: 20, noise: 0.4 },
      { techniqueId: 'T1041', targetAssetId: 'a-db', dwellMin: 25, noise: 0.5 },
    ],
  },
  {
    id: 'c-ransom', name: 'BLACK TIDE', actor: 'Ransomware crew', sophistication: 3,
    objective: 'Encrypt the file cluster and domain for impact.',
    steps: [
      { techniqueId: 'T1190', targetAssetId: 'a-web', dwellMin: 15, noise: 0.7 },
      { techniqueId: 'T1059', targetAssetId: 'a-web', dwellMin: 10, noise: 0.7 },
      { techniqueId: 'T1068', targetAssetId: 'a-web', dwellMin: 15, noise: 0.6 },
      { techniqueId: 'T1021', targetAssetId: 'a-file', dwellMin: 25, noise: 0.6 },
      { techniqueId: 'T1003', targetAssetId: 'a-ad', dwellMin: 20, noise: 0.7 },
      { techniqueId: 'T1486', targetAssetId: 'a-file', dwellMin: 15, noise: 0.9 },
    ],
  },
  {
    id: 'c-ics', name: 'GRID GHOST', actor: 'OT-focused threat', sophistication: 5,
    objective: 'Reach and manipulate the SCADA historian.',
    steps: [
      { techniqueId: 'T1566', targetAssetId: 'a-ws', dwellMin: 60, noise: 0.2 },
      { techniqueId: 'T1059', targetAssetId: 'a-ws', dwellMin: 20, noise: 0.3 },
      { techniqueId: 'T1070', targetAssetId: 'a-ws', dwellMin: 30, noise: 0.2 },
      { techniqueId: 'T1021', targetAssetId: 'a-ad', dwellMin: 45, noise: 0.3 },
      { techniqueId: 'T1046', targetAssetId: 'a-scada', dwellMin: 30, noise: 0.5 },
      { techniqueId: 'T1021', targetAssetId: 'a-scada', dwellMin: 40, noise: 0.4 },
      { techniqueId: 'T1489', targetAssetId: 'a-plc', dwellMin: 25, noise: 0.7 },
      { techniqueId: 'T1486', targetAssetId: 'a-scada', dwellMin: 20, noise: 0.8 },
    ],
  },
  {
    id: 'c-insider', name: 'IRON MOLE', actor: 'Malicious insider', sophistication: 2,
    objective: 'Quietly exfiltrate finance records using legitimate access.',
    steps: [
      { techniqueId: 'T1078', targetAssetId: 'a-ws2', dwellMin: 5, noise: 0.1 },
      { techniqueId: 'T1087', targetAssetId: 'a-ad', dwellMin: 30, noise: 0.15 },
      { techniqueId: 'T1552', targetAssetId: 'a-ws2', dwellMin: 40, noise: 0.1 },
      { techniqueId: 'T1039', targetAssetId: 'a-file', dwellMin: 60, noise: 0.15 },
      { techniqueId: 'T1114', targetAssetId: 'a-saas', dwellMin: 45, noise: 0.2 },
      { techniqueId: 'T1560', targetAssetId: 'a-ws2', dwellMin: 20, noise: 0.2 },
      { techniqueId: 'T1567', targetAssetId: 'a-saas', dwellMin: 30, noise: 0.25 },
    ],
  },
  {
    id: 'c-hacktivist', name: 'CRIMSON SIGNAL', actor: 'Hacktivist collective', sophistication: 3,
    objective: 'Use a DDoS smokescreen to pivot into a data breach and leak.',
    steps: [
      { techniqueId: 'T1590', targetAssetId: 'a-cdn', dwellMin: 25, noise: 0.4 },
      { techniqueId: 'T1595', targetAssetId: 'a-web', dwellMin: 20, noise: 0.5 },
      { techniqueId: 'T1498', targetAssetId: 'a-cdn', dwellMin: 30, noise: 0.95 },
      { techniqueId: 'T1190', targetAssetId: 'a-web', dwellMin: 20, noise: 0.6 },
      { techniqueId: 'T1505', targetAssetId: 'a-web', dwellMin: 15, noise: 0.4 },
      { techniqueId: 'T1046', targetAssetId: 'a-web', dwellMin: 25, noise: 0.6 },
      { techniqueId: 'T1021', targetAssetId: 'a-file', dwellMin: 35, noise: 0.5 },
      { techniqueId: 'T1119', targetAssetId: 'a-file', dwellMin: 25, noise: 0.4 },
      { techniqueId: 'T1567', targetAssetId: 'a-file', dwellMin: 30, noise: 0.5 },
    ],
  },
  {
    id: 'c-supply', name: 'HOLLOW VESSEL', actor: 'Supply-chain APT', sophistication: 5,
    objective: 'Poison the build pipeline to reach cloud production and secrets.',
    steps: [
      { techniqueId: 'T1195', targetAssetId: 'a-build', dwellMin: 30, noise: 0.15 },
      { techniqueId: 'T1059', targetAssetId: 'a-build', dwellMin: 15, noise: 0.3 },
      { techniqueId: 'T1552', targetAssetId: 'a-build', dwellMin: 25, noise: 0.2 },
      { techniqueId: 'T1027', targetAssetId: 'a-build', dwellMin: 20, noise: 0.15 },
      { techniqueId: 'T1078', targetAssetId: 'a-cloud', dwellMin: 20, noise: 0.2 },
      { techniqueId: 'T1098', targetAssetId: 'a-cloud', dwellMin: 30, noise: 0.25 },
      { techniqueId: 'T1555', targetAssetId: 'a-vault', dwellMin: 40, noise: 0.3 },
      { techniqueId: 'T1567', targetAssetId: 'a-cloud', dwellMin: 25, noise: 0.35 },
    ],
  },
];
export const CAMPAIGN = CAMPAIGNS.reduce((m, c) => (m[c.id] = c, m), {});

// ------------------------------ detections ---------------------------------
export const DETECTIONS = [
  // -- Recon --
  { id: 'd-ids', name: 'Perimeter IDS', techniqueId: 'T1595', sensor: 'Suricata', fidelity: 0.6, coverage: ['recon'] },
  { id: 'd-osint', name: 'Attack Surface Monitor', techniqueId: 'T1590', sensor: 'ASM', fidelity: 0.4, coverage: ['recon'] },
  // -- Initial Access --
  { id: 'd-mail', name: 'Mail Sandbox', techniqueId: 'T1566', sensor: 'SEG', fidelity: 0.55, coverage: ['initial-access'] },
  { id: 'd-waf', name: 'Web WAF', techniqueId: 'T1190', sensor: 'ModSecurity', fidelity: 0.6, coverage: ['initial-access'] },
  { id: 'd-imp', name: 'Impossible Travel', techniqueId: 'T1078', sensor: 'Identity', fidelity: 0.55, coverage: ['initial-access', 'defense-evasion'] },
  { id: 'd-vpn', name: 'Remote Access Analytics', techniqueId: 'T1133', sensor: 'ZTNA', fidelity: 0.5, coverage: ['initial-access'] },
  { id: 'd-scm', name: 'Pipeline Integrity Monitor', techniqueId: 'T1195', sensor: 'SCA', fidelity: 0.45, coverage: ['initial-access'] },
  // -- Execution --
  { id: 'd-edr1', name: 'EDR Behavioral', techniqueId: 'T1059', sensor: 'EDR', fidelity: 0.7, coverage: ['execution', 'defense-evasion'] },
  { id: 'd-sched', name: 'Scheduled Task Monitor', techniqueId: 'T1053', sensor: 'EDR', fidelity: 0.55, coverage: ['execution', 'persistence'] },
  // -- Persistence --
  { id: 'd-shell', name: 'Web Shell Detection', techniqueId: 'T1505', sensor: 'EDR', fidelity: 0.6, coverage: ['persistence'] },
  { id: 'd-acct', name: 'New Account Alert', techniqueId: 'T1136', sensor: 'Identity', fidelity: 0.6, coverage: ['persistence'] },
  { id: 'd-acctmod', name: 'Account Manipulation Monitor', techniqueId: 'T1098', sensor: 'Identity', fidelity: 0.55, coverage: ['persistence'] },
  // -- Privilege Escalation --
  { id: 'd-inject', name: 'Process Injection Detection', techniqueId: 'T1055', sensor: 'EDR', fidelity: 0.65, coverage: ['privilege-escalation', 'defense-evasion'] },
  { id: 'd-exploit', name: 'Kernel Exploit Guard', techniqueId: 'T1068', sensor: 'EDR', fidelity: 0.55, coverage: ['privilege-escalation'] },
  // -- Defense Evasion --
  { id: 'd-tamper', name: 'Security Tooling Tamper Alert', techniqueId: 'T1562', sensor: 'EDR', fidelity: 0.6, coverage: ['defense-evasion'] },
  { id: 'd-obf', name: 'Obfuscation Heuristics', techniqueId: 'T1027', sensor: 'EDR', fidelity: 0.45, coverage: ['defense-evasion'] },
  // -- Credential Access --
  { id: 'd-edr2', name: 'EDR Credential Guard', techniqueId: 'T1003', sensor: 'EDR', fidelity: 0.65, coverage: ['credential-access'] },
  { id: 'd-brute', name: 'Auth Brute-Force Analytics', techniqueId: 'T1110', sensor: 'Identity', fidelity: 0.65, coverage: ['credential-access'] },
  { id: 'd-secret', name: 'Secret Scanner', techniqueId: 'T1552', sensor: 'CSPM', fidelity: 0.45, coverage: ['credential-access'] },
  { id: 'd-vault', name: 'Vault Access Anomaly', techniqueId: 'T1555', sensor: 'PAM', fidelity: 0.6, coverage: ['credential-access'] },
  { id: 'd-krb', name: 'Kerberoast Detection', techniqueId: 'T1558', sensor: 'Identity', fidelity: 0.55, coverage: ['credential-access'] },
  // -- Discovery --
  { id: 'd-net', name: 'East-West NDR', techniqueId: 'T1046', sensor: 'NDR', fidelity: 0.55, coverage: ['discovery', 'lateral-movement'] },
  { id: 'd-acctdisc', name: 'Directory Enumeration Alert', techniqueId: 'T1087', sensor: 'Identity', fidelity: 0.5, coverage: ['discovery'] },
  // -- Lateral Movement --
  { id: 'd-ad', name: 'AD Auth Analytics', techniqueId: 'T1021', sensor: 'Identity', fidelity: 0.6, coverage: ['lateral-movement'] },
  { id: 'd-pth', name: 'Pass-the-Hash Detection', techniqueId: 'T1550', sensor: 'Identity', fidelity: 0.55, coverage: ['lateral-movement'] },
  // -- Collection --
  { id: 'd-share', name: 'File Share Access Analytics', techniqueId: 'T1039', sensor: 'DLP', fidelity: 0.45, coverage: ['collection'] },
  { id: 'd-mailcol', name: 'Mailbox Exfil Rules Alert', techniqueId: 'T1114', sensor: 'CASB', fidelity: 0.5, coverage: ['collection'] },
  { id: 'd-arch', name: 'Bulk Archive Heuristics', techniqueId: 'T1560', sensor: 'EDR', fidelity: 0.45, coverage: ['collection'] },
  // -- Command & Control --
  { id: 'd-c2', name: 'C2 Beacon Detection', techniqueId: 'T1071', sensor: 'NDR', fidelity: 0.6, coverage: ['command-and-control'] },
  { id: 'd-tun', name: 'Tunnel / DNS Anomaly', techniqueId: 'T1572', sensor: 'NDR', fidelity: 0.5, coverage: ['command-and-control'] },
  // -- Exfiltration --
  { id: 'd-dlp', name: 'DLP Egress', techniqueId: 'T1041', sensor: 'DLP', fidelity: 0.5, coverage: ['exfiltration'] },
  { id: 'd-casb', name: 'Cloud Egress Monitor', techniqueId: 'T1567', sensor: 'CASB', fidelity: 0.5, coverage: ['exfiltration'] },
  { id: 'd-dns', name: 'DNS Exfil Detection', techniqueId: 'T1048', sensor: 'NDR', fidelity: 0.45, coverage: ['exfiltration'] },
  // -- Impact --
  { id: 'd-ransom', name: 'Ransomware Canary', techniqueId: 'T1486', sensor: 'EDR', fidelity: 0.8, coverage: ['impact'] },
  { id: 'd-backup', name: 'Backup Deletion Alert', techniqueId: 'T1490', sensor: 'EDR', fidelity: 0.65, coverage: ['impact'] },
  { id: 'd-ddos', name: 'Volumetric DDoS Detection', techniqueId: 'T1498', sensor: 'Scrubbing', fidelity: 0.75, coverage: ['impact'] },
  { id: 'd-svc', name: 'Critical Service Stop Alert', techniqueId: 'T1489', sensor: 'SIEM', fidelity: 0.6, coverage: ['impact'] },
];
export const DET_BY_TECH = DETECTIONS.reduce((m, d) => ((m[d.techniqueId] || (m[d.techniqueId] = [])).push(d), m), {});

// ------------------------------ postures -----------------------------------
export const POSTURES = [
  { id: 'baseline', name: 'Baseline', mult: 1.0 },
  { id: 'elevated', name: 'Elevated', mult: 1.2 },
  { id: 'defcon', name: 'Maximum Readiness', mult: 1.4 },
];
export const POSTURE = POSTURES.reduce((m, p) => (m[p.id] = p, m), {});

// ------------------------------ containment actions ------------------------
export const ACTIONS = [
  { id: 'isolate', name: 'Isolate Host', kind: 'contain', cost: 2, blocks: ['lateral-movement', 'collection', 'exfiltration', 'impact'] },
  { id: 'block-c2', name: 'Block C2 Egress', kind: 'contain', cost: 1, blocks: ['command-and-control', 'exfiltration'] },
  { id: 'disable-acct', name: 'Disable Account', kind: 'contain', cost: 1, blocks: ['lateral-movement', 'privilege-escalation'] },
  { id: 'reset-creds', name: 'Force Credential Reset', kind: 'contain', cost: 2, blocks: ['credential-access', 'lateral-movement'] },
  { id: 'quarantine', name: 'Quarantine File', kind: 'contain', cost: 1, blocks: ['execution', 'impact'] },
];
export const ACTION = ACTIONS.reduce((m, a) => (m[a.id] = a, m), {});

// ================================ ENGINE ===================================
// A run is a single wargame execution. Pillars drive it with stepRun().
export function newRun(campaignId, opts = {}) {
  const camp = CAMPAIGN[campaignId] || CAMPAIGNS[0];
  const posture = POSTURE[opts.postureId] || POSTURES[0];
  return {
    id: uid('run'), campaignId: camp.id, campaign: camp,
    postureId: posture.id, autopilot: opts.autopilot !== false,
    cursor: 0, clockMin: 0, done: false, startedAt: Date.now(),
    events: [], alerts: [], actions: [], blockedTactics: {},
    isolatedAssets: {}, reached: [], contained: false, containedAt: null,
  };
}

// Advance the campaign by one step; resolve detection; emit events/alerts.
export function stepRun(run) {
  if (run.done) return { done: true, step: null, phase: null, events: [], alerts: [] };
  if (run.contained || run.cursor >= run.campaign.steps.length) {
    run.done = true;
    return { done: true, step: null, phase: null, events: [], alerts: [] };
  }
  const step = run.campaign.steps[run.cursor];
  const tech = TECH[step.techniqueId] || { id: step.techniqueId, name: step.techniqueId, tactic: 'execution', detectability: 0.5 };
  const asset = ASSET[step.targetAssetId] || { id: step.targetAssetId, name: step.targetAssetId, zone: 'corp' };
  run.clockMin += step.dwellMin;
  run.cursor += 1;

  const events = [];
  const alerts = [];

  // Was this step blocked by a prior containment action targeting its tactic,
  // or is its target host already isolated from the network?
  const blocked = !!run.blockedTactics[tech.tactic] || !!(run.isolatedAssets || {})[asset.id];
  const ev = {
    id: uid('ev'), t: run.clockMin, techniqueId: tech.id, techniqueName: tech.name,
    tactic: tech.tactic, assetId: asset.id, assetName: asset.name, zone: asset.zone,
    blocked, sophistication: run.campaign.sophistication,
  };
  run.events.push(ev); events.push(ev);
  if (!blocked) run.reached.push(asset.id);

  // Detection roll: technique detectability * sensor fidelity * posture mult * noise,
  // modulated by how heavily the target is instrumented (zone trust + asset criticality).
  // Higher-trust zones and higher-criticality assets carry deeper sensor coverage.
  const posture = POSTURE[run.postureId] || POSTURES[0];
  const dets = DET_BY_TECH[tech.id] || [];
  const monitoring = instrumentation(asset);
  let best = null;
  dets.forEach((d) => {
    const p = Math.min(0.98, (tech.detectability) * d.fidelity * posture.mult * monitoring * (0.5 + step.noise));
    if (Math.random() < p) { if (!best || d.fidelity > best.fidelity) best = d; }
  });
  if (best) {
    const al = {
      id: uid('al'), t: run.clockMin, techniqueId: tech.id, techniqueName: tech.name,
      tactic: tech.tactic, assetId: asset.id, assetName: asset.name,
      sensor: best.sensor, detection: best.name, severity: sevFor(asset, tech),
      status: 'new', suggested: suggestActions(tech.tactic),
    };
    run.alerts.push(al); alerts.push(al);
    emit('alert', al);
  }
  emit('event', ev);
  if (run.cursor >= run.campaign.steps.length) run.done = true;
  return { done: run.done, step, phase: tech.tactic, events, alerts };
}

function sevFor(asset, tech) {
  const c = (asset && asset.crit) || 3;
  if (tech.tactic === 'impact' || c >= 5) return 'critical';
  if (c >= 4) return 'high';
  if (c >= 3) return 'medium';
  return 'low';
}

// How heavily a target is instrumented (0.75..~1.3). Sensitive zones and
// critical assets get deeper telemetry, so activity there is easier to catch.
function instrumentation(asset) {
  const zone = ZONE[(asset && asset.zone)] || { trust: 2 };
  const crit = (asset && asset.crit) || 3;
  const m = 0.85 + (zone.trust - 1) * 0.07 + (crit - 3) * 0.05;
  return Math.max(0.75, Math.min(1.3, m));
}

export function suggestActions(tactic) {
  return ACTIONS.filter((a) => a.blocks.includes(tactic)).map((a) => a.id);
}

// Apply a containment action. If it targets the attacker's current path,
// it blocks those tactics for the remainder of the run.
export function applyAction(run, actionId, alertId) {
  const act = ACTION[actionId];
  if (!act) return { ok: false, note: 'Unknown action' };
  act.blocks.forEach((tac) => { run.blockedTactics[tac] = true; });
  run.isolatedAssets = run.isolatedAssets || {};
  // Host-level actions cut a specific asset off the attacker's path.
  let isolated = null;
  const alert = alertId ? run.alerts.find((x) => x.id === alertId) : null;
  if ((actionId === 'isolate' || actionId === 'quarantine') && alert && alert.assetId) {
    run.isolatedAssets[alert.assetId] = true;
    isolated = alert.assetName || alert.assetId;
  }
  run.actions.push({ id: uid('act'), actionId, alertId: alertId || null, t: run.clockMin, name: act.name, assetId: alert ? alert.assetId : null });
  if (alert) alert.status = 'contained';
  // Containment succeeds if every remaining step is now stopped -- either its
  // tactic is blocked or its target host has been isolated.
  const remaining = run.campaign.steps.slice(run.cursor);
  const allBlocked = remaining.length > 0 && remaining.every((s) => {
    const t = (TECH[s.techniqueId] || {}).tactic;
    return run.blockedTactics[t] || run.isolatedAssets[s.targetAssetId];
  });
  if (allBlocked) { run.contained = true; run.containedAt = run.clockMin; run.done = true; emit('contained', run); }
  emit('action', { run, actionId, alertId });
  return { ok: true, note: act.name + ' applied' + (isolated ? ' to ' + isolated : '') + (run.contained ? ' -- threat contained' : '') };
}

export function resetRun(run) {
  const fresh = newRun(run.campaignId, { postureId: run.postureId, autopilot: run.autopilot });
  Object.assign(run, fresh);
  return run;
}

// ----------------------------- scoring -------------------------------------
export function scoreRun(run) {
  const steps = run.campaign.steps;
  const totalTechniques = steps.length;
  const detectedSteps = run.alerts.length;
  const detectionRate = totalTechniques ? Math.round((detectedSteps / totalTechniques) * 100) : 0;
  const firstAlert = run.alerts[0];
  const mttdMin = firstAlert ? firstAlert.t : null;

  // MITRE coverage per tactic that the campaign exercised.
  const mitre = {};
  steps.forEach((s) => {
    const tac = (TECH[s.techniqueId] || {}).tactic;
    if (!tac) return;
    mitre[tac] = mitre[tac] || { total: 0, detected: 0 };
    mitre[tac].total += 1;
  });
  run.alerts.forEach((a) => { if (mitre[a.tactic]) mitre[a.tactic].detected += 1; });
  const mitrePct = {};
  Object.keys(mitre).forEach((k) => { mitrePct[k] = Math.round((mitre[k].detected / mitre[k].total) * 100); });

  const reachedSet = Array.from(new Set(run.reached));
  const crownHit = reachedSet.filter((id) => ESTATE.crownJewels.includes(id));
  const missed = steps
    .filter((s) => !run.alerts.some((a) => a.techniqueId === s.techniqueId && a.assetId === s.targetAssetId))
    .map((s) => ({ techniqueId: s.techniqueId, techniqueName: (TECH[s.techniqueId] || {}).name, assetId: s.targetAssetId }));

  // Grade blends detection, speed, containment and crown-jewel protection.
  let g = detectionRate * 0.5;
  g += run.contained ? 25 : 0;
  g += mttdMin != null && mttdMin < 60 ? 15 : (mttdMin != null ? 5 : 0);
  g -= crownHit.length * 8;
  g = Math.max(0, Math.min(100, Math.round(g)));
  const grade = g >= 90 ? 'A' : g >= 80 ? 'B' : g >= 70 ? 'C' : g >= 55 ? 'D' : 'F';

  return {
    detectionRate, mttdMin, contained: run.contained, containedAt: run.containedAt,
    missed, reached: reachedSet, crownHit, mitre: mitrePct, score: g, grade,
    totalTechniques, detectedSteps,
  };
}

// Run the whole campaign, invoking onStep for each step (for animated UIs).
export function runToCompletion(run, onStep) {
  let guard = 0;
  while (!run.done && guard++ < 200) {
    const r = stepRun(run);
    if (onStep) onStep(r, run);
  }
  return scoreRun(run);
}

// ----------------------------- lookup helpers ------------------------------
// All pure, read-only conveniences over the static libraries above.
export const techniquesByTactic = (tacticId) => TECHNIQUES.filter((t) => t.tactic === tacticId);
export const detectionsByTactic = (tacticId) => DETECTIONS.filter((d) => (d.coverage || []).includes(tacticId));
export const tacticName = (id) => (TACTICS.find((t) => t.id === id) || {}).name || id;
export const assetsByZone = (zoneId) => ESTATE.assets.filter((a) => a.zone === zoneId);
export const isCrownJewel = (assetId) => ESTATE.crownJewels.includes(assetId);
// Tactics with no detection at all -- the defender's true blind spots.
export const coverageGaps = () => TACTICS
  .filter((t) => !DETECTIONS.some((d) => (d.coverage || []).includes(t.id)))
  .map((t) => t.id);
