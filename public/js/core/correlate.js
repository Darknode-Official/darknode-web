// Cross-tool correlation (Deck D3). PURE — no DOM, no network, no graph writes.
//
// One tool sees "no MFA", another sees "impossible travel" — on the SAME person that
// is an account-takeover risk no single tool reports. This engine reads the graph's
// findings, uses core/resolve.js to tell when findings from different tools touch the
// same resolved host or identity, and returns correlation hits. It does NOT write to
// the graph (turning hits into INCIDENT entities is a separate, idempotent step), so
// it can never corrupt the graph.
import { resolveAssets, resolveIdentities, hostParts, canonIp, identityKeys } from "./resolve.js";

const str = (v) => String(v == null ? "" : v).trim();
const lc = (v) => str(v).toLowerCase();
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const DAY = 86400000;

const toMs = (v) => (typeof v === "number" ? v : (typeof v === "string" && v ? Date.parse(v) : NaN));

// ---- leg predicate helpers (compose into a finding predicate) -------------
const src = (...tools) => (f) => tools.includes(f.source);
const cat = (...cats) => (f) => cats.includes(f.category);
const sevAtLeast = (level) => (f) => (SEV_RANK[f.severity] || 0) >= (SEV_RANK[level] || 0);
const kw = (re) => (f) => re.test(f.title);
const all = (...preds) => (f) => preds.every((p) => p(f));
const any = (...preds) => (f) => preds.some((p) => p(f));

// ---- the rule set. Each leg names tools + a predicate; a hit needs every leg
// matched by some finding on the same subject, within `window` if set. ----------
export const RULES = [
  {
    id: "account-takeover", subject: "identity", severity: "high",
    attack: ["T1078"], window: 30 * DAY,
    title: "Account-takeover risk",
    explain: "A sign-in anomaly on an account whose MFA or legacy-auth posture is weak — the classic account-takeover setup.",
    legs: [
      { id: "weak-auth", label: "Weak sign-in control (no/weak MFA or legacy auth)", when: any(all(src("caaudit"), cat("mfa", "legacy-auth")), all(src("vpnaudit"), cat("no_mfa", "legacy_client"))) },
      { id: "anomaly", label: "Sign-in anomaly (impossible travel, new country, brute force)", when: any(all(src("vpnaudit"), cat("impossible_travel", "new_country", "new_source", "brute_force", "spraying")), all(src("signins"), sevAtLeast("medium"))) },
    ],
  },
  {
    id: "leaver-active", subject: "identity", severity: "high",
    attack: ["T1078.004"], window: 90 * DAY,
    title: "Leaver still has access",
    explain: "HR marks this person a leaver, yet a sign-in or remote-access session is still happening on their account.",
    legs: [
      { id: "terminated", label: "Terminated in HR (offboarding verifier)", when: all(src("jml"), cat("leaver")) },
      { id: "still-active", label: "Sign-in or VPN activity after termination", when: any(src("vpnaudit"), src("signins")) },
    ],
  },
  {
    id: "priv-no-mfa", subject: "identity", severity: "high",
    attack: ["T1078"], window: 60 * DAY,
    title: "Privileged account without strong MFA",
    explain: "A standing-privileged account that also shows a weak MFA posture — a high-value target with a soft door.",
    legs: [
      { id: "privileged", label: "Standing or over-broad privilege", when: all(src("privaudit"), cat("standing-privilege", "privileged-use", "over-broad-policy", "role-sprawl")) },
      { id: "weak-mfa", label: "Weak MFA / legacy auth", when: any(all(src("caaudit"), cat("mfa", "legacy-auth")), all(src("vpnaudit"), cat("no_mfa"))) },
    ],
  },
  {
    id: "exploit-exposed-host", subject: "asset", severity: "critical",
    attack: ["T1190"], window: 60 * DAY,
    title: "Exploitable vulnerability on an internet-exposed host",
    explain: "A high/known-exploited vulnerability on a host that is also internet-exposed (RDP/SMB/SSH or a takeover-prone record).",
    legs: [
      { id: "vuln", label: "High / known-exploited vulnerability", when: any(all(src("vulnimport"), sevAtLeast("high")), (f) => f.kev) },
      { id: "exposed", label: "Internet-exposed service or record", when: any(all(src("netexposure"), cat("rdp", "smb", "ssh", "segmentation")), all(src("domainguard"), cat("takeover"))) },
    ],
  },
  {
    id: "exposed-no-backup", subject: "asset", severity: "high",
    attack: ["T1486"], window: 90 * DAY,
    title: "Exposed host with no sound backup",
    explain: "An internet-exposed host that also has a backup gap — if it is hit, recovery is not assured.",
    legs: [
      { id: "exposed", label: "Internet-exposed service", when: all(src("netexposure"), cat("rdp", "smb", "ssh", "segmentation")) },
      { id: "backup-gap", label: "Backup gap (unprotected, failing jobs, no restore test)", when: all(src("backupready"), cat("unprotected", "job-failures", "restore-testing", "immutability")) },
    ],
  },
  {
    id: "live-secret", subject: "asset", severity: "critical",
    attack: ["T1552"], window: 30 * DAY,
    title: "Leaked secret with a matching live credential",
    explain: "A secret was found in code/data and a matching machine credential is still active and unrotated.",
    legs: [
      { id: "leaked", label: "Secret found in code or data", when: any(all(src("codescan", "leakprobe", "dlp"), kw(/secret|key|token|credential|password/i)), all(src("codescan", "leakprobe"), cat("secrets"))) },
      { id: "active-key", label: "Active, unrotated machine credential", when: all(src("nhi"), cat("rotation", "expiry", "usage")) },
    ],
  },
];

// ---- subject indexing: map a finding's referenced asset/identity names to the
// resolved cluster they belong to. ------------------------------------------------
function buildIndex(entities) {
  const assetClusters = resolveAssets(entities);
  const idRes = resolveIdentities(entities);
  const idClusters = idRes.clusters;

  const assetIdToKey = new Map();
  assetClusters.forEach((c) => c.members.forEach((id) => assetIdToKey.set(id, c.key)));
  const idIdToKey = new Map();
  idClusters.forEach((c) => c.members.forEach((id) => idIdToKey.set(id, c.key)));

  const assetNameKey = new Map(); // lookup string -> cluster key
  const idNameKey = new Map();
  for (const e of entities) {
    if (assetIdToKey.has(e.id)) {
      const ck = assetIdToKey.get(e.id), p = hostParts(e.name);
      assetNameKey.set(p.key, ck);
      if (p.kind === "ip") assetNameKey.set(canonIp(e.name), ck);
    }
    if (idIdToKey.has(e.id)) {
      const ck = idIdToKey.get(e.id), k = identityKeys(e.name, e.data || {});
      for (const v of [k.emailKey, k.upnKey, k.samKey]) if (v) idNameKey.set(v, ck);
      idNameKey.set(lc(e.name), ck);
    }
  }
  const nameMap = new Map();
  assetClusters.forEach((c) => nameMap.set("a:" + c.key, c.name));
  idClusters.forEach((c) => nameMap.set("i:" + c.key, c.name));
  return { assetNameKey, idNameKey, nameMap };
}

// Which cluster keys (per type) does a finding concern?
function subjectsOf(f, idx) {
  const assets = new Set(), identities = new Set();
  for (const raw of f.assetNames) {
    const name = str(raw); if (!name) continue;
    const hk = hostParts(name).key;
    if (idx.assetNameKey.has(hk)) assets.add(idx.assetNameKey.get(hk));
    const ik = identityKeys(name, {});
    for (const v of [ik.emailKey, ik.upnKey, ik.samKey, lc(name)]) if (v && idx.idNameKey.has(v)) identities.add(idx.idNameKey.get(v));
  }
  return { assets: [...assets], identities: [...identities] };
}

// ---- main ------------------------------------------------------------------------
// correlate(entities, { now }) -> hits[], each:
//   { ruleId, title, severity, attack, subjectType, subjectKey, subjectName,
//     explanation, legs:[{ id, label, findingId, findingTitle }], window, span }
export function correlate(entities, opts = {}) {
  const ents = entities || [];
  const idx = buildIndex(ents);

  // finding views + their subjects
  const views = [];
  for (const e of ents) {
    if (e.type !== "FINDING" && e.type !== "VULNERABILITY") continue;
    const d = e.data || {};
    const tags = e.tags || [];
    const title = str(e.name).replace(/\s*\([a-z0-9_-]+:[^)]*\)\s*$/i, ""); // strip "(tool:key)"
    const f = {
      id: e.id, title, source: str(e.source || d.tool), category: lc(d.category), severity: lc(e.severity),
      tags, ts: toMs(e.updatedAt) || toMs(e.createdAt) || 0, assetNames: Array.isArray(d.assets) ? d.assets : [],
      kev: tags.includes("kev") || /\bkev\b|known[- ]exploited/i.test(title) || !!d.kev,
    };
    f.subjects = subjectsOf(f, idx);
    views.push(f);
  }

  // group finding views by subject, per type
  const byAsset = new Map(), byId = new Map();
  const push = (map, key, f) => { if (!map.has(key)) map.set(key, []); map.get(key).push(f); };
  for (const f of views) { for (const k of f.subjects.assets) push(byAsset, k, f); for (const k of f.subjects.identities) push(byId, k, f); }

  const hits = [];
  for (const rule of RULES) {
    const groups = rule.subject === "asset" ? byAsset : byId;
    const prefix = rule.subject === "asset" ? "a:" : "i:";
    for (const [subjectKey, findings] of groups) {
      const matched = [];
      let ok = true;
      for (const leg of rule.legs) {
        const hit = findings.find((f) => leg.when(f));
        if (!hit) { ok = false; break; }
        matched.push({ leg, f: hit });
      }
      if (!ok) continue;
      // time window across the matched legs
      const times = matched.map((m) => m.f.ts).filter((t) => t > 0);
      const span = times.length >= 2 ? Math.max(...times) - Math.min(...times) : 0;
      if (rule.window && times.length >= 2 && span > rule.window) continue;
      hits.push({
        ruleId: rule.id, title: rule.title, severity: rule.severity, attack: rule.attack.slice(),
        subjectType: rule.subject, subjectKey, subjectName: idx.nameMap.get(prefix + subjectKey) || subjectKey,
        explanation: rule.explain, window: rule.window || null, span,
        legs: matched.map((m) => ({ id: m.leg.id, label: m.leg.label, findingId: m.f.id, findingTitle: m.f.title })),
      });
    }
  }
  hits.sort((a, b) => (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0) || a.ruleId.localeCompare(b.ruleId) || String(a.subjectKey).localeCompare(String(b.subjectKey)));
  return hits;
}
