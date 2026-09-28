// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Learn & Do — the data spine. Pure, dependency-free, and unit-tested (test/core/learndo.test.mjs)
// so the catalog can't rot: every activity points at a REAL section `sec` (validated against the
// nav at render time), and the filter/progress helpers are exercised without a DOM.
//
// An activity is one concrete thing a user can DO right now: { id, title, desc, sec, cat, level, mins }.
//   - sec  : the data-sec the card navigates to (must exist in the app's nav)
//   - cat  : one of CATEGORIES[].id  (the collection it belongs to)
//   - level: "intro" | "core" | "advanced"
//   - mins : rough minutes, for the "quick win vs. deep dive" filter

export const LEVELS = [
  { id: "intro", name: "Intro", desc: "No experience needed" },
  { id: "core", name: "Core", desc: "The everyday skills" },
  { id: "advanced", name: "Advanced", desc: "Go deep" },
];

export const CATEGORIES = [
  { id: "start", name: "Start Here", color: "emerald", blurb: "New? Do these first." },
  { id: "web", name: "Web & App Security", color: "red", blurb: "Break and defend web apps." },
  { id: "recon", name: "Recon & OSINT", color: "cyan", blurb: "Map a target from the outside." },
  { id: "offense", name: "Offense & Exploitation", color: "red", blurb: "Attacker tradecraft, safely." },
  { id: "blue", name: "Blue Team & Detection", color: "green", blurb: "Hunt, detect, respond." },
  { id: "intel", name: "Threat Intelligence", color: "orange", blurb: "Know the adversary." },
  { id: "forensics", name: "Forensics & Malware", color: "purple", blurb: "Investigate what happened." },
  { id: "crypto", name: "Crypto & Encoding", color: "indigo", blurb: "Encode, hash, decode." },
  { id: "network", name: "Network Analysis", color: "teal", blurb: "Read the wire." },
  { id: "grc", name: "Compliance & GRC", color: "yellow", blurb: "Risk, frameworks, posture." },
  { id: "ranges", name: "Ranges & Challenges", color: "violet", blurb: "Prove it under pressure." },
  { id: "ai", name: "AI & Automation", color: "violet", blurb: "Let the agents help." },
];

// verb-first, concrete "do this now" items. Every `sec` below exists in console-nav.js NAV.
export const ACTIVITIES = [
  // --- Start Here ---
  { id: "d-learnhub", title: "Open the Learn Hub and start a path", desc: "Pick a guided track and earn XP as you complete topics.", sec: "learn", cat: "start", level: "intro", mins: 10 },
  { id: "d-quiz1", title: "Take the security fundamentals quiz", desc: "Find out what you already know and where the gaps are.", sec: "securityquiz", cat: "start", level: "intro", mins: 10 },
  { id: "d-cheats", title: "Skim the cheat sheets", desc: "Bookmark the commands and payloads you'll reach for again.", sec: "cheats", cat: "start", level: "intro", mins: 5 },
  { id: "d-range1", title: "Run your first Cyber Range scenario", desc: "A guided, hands-on scenario end to end.", sec: "cyberrange", cat: "start", level: "intro", mins: 20 },
  { id: "d-targets", title: "Explore the practice targets", desc: "Legal, intentionally-vulnerable apps to try things on.", sec: "targets", cat: "start", level: "intro", mins: 8 },
  { id: "d-education", title: "Read the field guide", desc: "The big picture: how the disciplines fit together.", sec: "education", cat: "start", level: "intro", mins: 6 },

  // --- Web & App Security ---
  { id: "d-xss", title: "Exploit and fix a reflected XSS", desc: "In the Web Security Lab, land a payload then patch it.", sec: "xsslab", cat: "web", level: "core", mins: 20 },
  { id: "d-headers", title: "Grade a site's security headers", desc: "Analyze HSTS, CSP, X-Frame-Options and more.", sec: "headeranalyzer", cat: "web", level: "core", mins: 8 },
  { id: "d-csp", title: "Evaluate a Content-Security-Policy", desc: "Spot the bypasses in a real CSP string.", sec: "cspevaluator", cat: "web", level: "core", mins: 10 },
  { id: "d-jwt", title: "Decode and probe a JWT", desc: "Inspect claims, alg, and common signature mistakes.", sec: "jwtanalyzer", cat: "web", level: "core", mins: 8 },
  { id: "d-cors", title: "Test a CORS configuration", desc: "Find over-permissive origins that leak data.", sec: "corstester", cat: "web", level: "core", mins: 8 },
  { id: "d-apitest", title: "Send and inspect an API request", desc: "Craft requests, read responses, chain calls.", sec: "apitester", cat: "web", level: "core", mins: 10 },
  { id: "d-apifuzz", title: "Fuzz an API endpoint", desc: "Throw malformed input and watch what breaks.", sec: "apifuzzer", cat: "web", level: "advanced", mins: 15 },
  { id: "d-apiscan", title: "Scan an API for security issues", desc: "Automated checks against a target API.", sec: "apiscan", cat: "web", level: "advanced", mins: 15 },
  { id: "d-regex", title: "Build and test a regex safely", desc: "Match patterns and avoid catastrophic backtracking.", sec: "regexlab", cat: "web", level: "core", mins: 8 },

  // --- Recon & OSINT ---
  { id: "d-dns", title: "Map a domain's DNS records", desc: "A, MX, TXT, NS — the whole picture in the DNS Toolkit.", sec: "dns", cat: "recon", level: "intro", mins: 8 },
  { id: "d-subs", title: "Enumerate subdomains of a target", desc: "Expand the attack surface from one root domain.", sec: "subdomains", cat: "recon", level: "core", mins: 12 },
  { id: "d-whois", title: "Run a WHOIS + registration lookup", desc: "Ownership, dates, and pivot points.", sec: "whoisrecon", cat: "recon", level: "intro", mins: 6 },
  { id: "d-osint", title: "Build an OSINT profile", desc: "Pull threads together in the OSINT dashboard.", sec: "osint", cat: "recon", level: "core", mins: 20 },
  { id: "d-ghdb", title: "Find exposures with Google dorks", desc: "Search operators that surface what shouldn't be public.", sec: "ghdb", cat: "recon", level: "core", mins: 10 },
  { id: "d-wayback", title: "Dig through the Wayback Machine", desc: "Recover old endpoints, keys, and pages.", sec: "wayback", cat: "recon", level: "core", mins: 10 },
  { id: "d-tech", title: "Fingerprint a site's tech stack", desc: "Identify frameworks, servers, and versions.", sec: "techfingerprint", cat: "recon", level: "intro", mins: 6 },
  { id: "d-asn", title: "Explore an ASN's IP space", desc: "Understand who owns what on the internet.", sec: "asnexplorer", cat: "recon", level: "advanced", mins: 12 },
  { id: "d-attacksurf", title: "Map an organization's attack surface", desc: "Turn recon into a prioritized exposure map.", sec: "attacksurf", cat: "recon", level: "advanced", mins: 20 },

  // --- Offense & Exploitation ---
  { id: "d-attacksim", title: "Run a threat simulation", desc: "Play out an attack chain step by step.", sec: "attacksim", cat: "offense", level: "core", mins: 20 },
  { id: "d-payloadgen", title: "Generate a test payload", desc: "Build safe test scripts for a chosen scenario.", sec: "payloadgen", cat: "offense", level: "core", mins: 10 },
  { id: "d-pentest", title: "Work a security assessment console", desc: "Structure an engagement from scoping to findings.", sec: "pentestconsole", cat: "offense", level: "advanced", mins: 25 },
  { id: "d-crack", title: "Test password strength in the lab", desc: "See how fast weak credentials fall.", sec: "cracklab", cat: "offense", level: "core", mins: 12 },
  { id: "d-privesc", title: "Analyze a privilege-escalation path", desc: "Spot the misconfig that hands over root.", sec: "privesc", cat: "offense", level: "advanced", mins: 15 },
  { id: "d-exploitdb", title: "Search the vulnerability database", desc: "Find known exploits for a product and version.", sec: "exploitdb", cat: "offense", level: "core", mins: 8 },
  { id: "d-packet", title: "Craft a custom packet", desc: "Hand-build traffic and understand every field.", sec: "packetcraft", cat: "offense", level: "advanced", mins: 15 },

  // --- Blue Team & Detection ---
  { id: "d-hunt", title: "Run a threat hunt", desc: "Form a hypothesis and chase it through the data.", sec: "huntlab", cat: "blue", level: "advanced", mins: 25 },
  { id: "d-siem", title: "Triage alerts in the SIEM dashboard", desc: "Separate signal from noise under time pressure.", sec: "siemdash", cat: "blue", level: "core", mins: 15 },
  { id: "d-ir", title: "Work an incident-response playbook", desc: "Contain, eradicate, recover — in order.", sec: "incidentresponse", cat: "blue", level: "core", mins: 20 },
  { id: "d-deception", title: "Design a deception / honeypot", desc: "Lay a trap that catches an intruder early.", sec: "deception", cat: "blue", level: "advanced", mins: 15 },
  { id: "d-threatmodel", title: "Threat-model a system", desc: "Enumerate what can go wrong before it does.", sec: "threatmodel", cat: "blue", level: "core", mins: 20 },
  { id: "d-breachsim", title: "Simulate a breach and measure blast radius", desc: "See how far an attacker gets from one foothold.", sec: "breachsim", cat: "blue", level: "advanced", mins: 20 },
  { id: "d-purple", title: "Run a purple-team exercise", desc: "Attack and defend in the same loop.", sec: "purpleteam", cat: "blue", level: "advanced", mins: 25 },

  // --- Threat Intelligence ---
  { id: "d-cve", title: "Research a CVE end to end", desc: "Understand a vuln, its impact, and its fix.", sec: "cvesearch", cat: "intel", level: "intro", mins: 10 },
  { id: "d-cvetl", title: "Trace a CVE's timeline", desc: "From disclosure to patch to exploitation.", sec: "cvetimeline", cat: "intel", level: "core", mins: 8 },
  { id: "d-threatfeed", title: "Read today's threat feed", desc: "Stay current on active campaigns.", sec: "threat", cat: "intel", level: "intro", mins: 6 },
  { id: "d-breach", title: "Check an account against breaches", desc: "See where a credential has leaked.", sec: "breachlookup", cat: "intel", level: "intro", mins: 5 },
  { id: "d-ioc", title: "Extract IOCs from a report", desc: "Pull hashes, IPs, and domains into a usable list.", sec: "iocextractor", cat: "intel", level: "core", mins: 10 },
  { id: "d-iprep", title: "Score an IP's reputation", desc: "Decide whether to block, watch, or allow.", sec: "ipreputation", cat: "intel", level: "core", mins: 6 },

  // --- Forensics & Malware ---
  { id: "d-stego", title: "Hide and extract data with steganography", desc: "Then learn how defenders find it.", sec: "stego", cat: "forensics", level: "core", mins: 12 },
  { id: "d-mem", title: "Analyze a memory image", desc: "Find the process an attacker tried to hide.", sec: "memforensics", cat: "forensics", level: "advanced", mins: 25 },
  { id: "d-bin", title: "Inspect a binary", desc: "Strings, headers, and what a file really is.", sec: "binanalyze", cat: "forensics", level: "core", mins: 12 },
  { id: "d-reveng", title: "Reverse-engineer a sample", desc: "Work out behavior without running it.", sec: "reveng", cat: "forensics", level: "advanced", mins: 25 },
  { id: "d-sandbox", title: "Detonate a sample in the analysis lab", desc: "Watch what malware does, safely.", sec: "sandbox", cat: "forensics", level: "advanced", mins: 20 },
  { id: "d-phish", title: "Analyze a phishing email", desc: "Headers, links, and the tell-tale signs.", sec: "phishing", cat: "forensics", level: "intro", mins: 8 },
  { id: "d-timeline", title: "Build a forensic timeline", desc: "Order the events of an intrusion.", sec: "ftimeline", cat: "forensics", level: "core", mins: 15 },

  // --- Crypto & Encoding ---
  { id: "d-encode", title: "Encode and decode across formats", desc: "Base64, hex, URL, and more in one suite.", sec: "encoding", cat: "crypto", level: "intro", mins: 5 },
  { id: "d-hash", title: "Hash and identify digests", desc: "MD5 through SHA-512, plus HMAC.", sec: "hashsuite", cat: "crypto", level: "intro", mins: 6 },
  { id: "d-crypto", title: "Play with classic and modern ciphers", desc: "See how encryption succeeds and fails.", sec: "cryptotools", cat: "crypto", level: "core", mins: 12 },
  { id: "d-cred", title: "Audit a set of credentials", desc: "Find reuse, weakness, and exposure.", sec: "credaudit", cat: "crypto", level: "core", mins: 10 },

  // --- Network Analysis ---
  { id: "d-netscan", title: "Scan a network for live hosts and ports", desc: "Build a map of what's reachable.", sec: "networkscanner", cat: "network", level: "core", mins: 12 },
  { id: "d-pcap", title: "Analyze captured packets", desc: "Follow a stream and reconstruct a session.", sec: "packetanalyzer", cat: "network", level: "advanced", mins: 20 },
  { id: "d-ssl", title: "Inspect a TLS/SSL configuration", desc: "Protocols, ciphers, and cert problems.", sec: "sslinspector", cat: "network", level: "core", mins: 8 },
  { id: "d-subnet", title: "Visualize a subnet", desc: "CIDR math made obvious.", sec: "subnetvisualizer", cat: "network", level: "intro", mins: 6 },

  // --- Compliance & GRC ---
  { id: "d-compliance", title: "Run a compliance check", desc: "Measure a posture against a framework.", sec: "compliance", cat: "grc", level: "core", mins: 15 },
  { id: "d-zerotrust", title: "Plan a zero-trust rollout", desc: "Turn the buzzword into concrete steps.", sec: "zerotrust", cat: "grc", level: "advanced", mins: 20 },
  { id: "d-risk", title: "Calculate risk for a scenario", desc: "Likelihood x impact, made defensible.", sec: "riskcalculator", cat: "grc", level: "core", mins: 10 },
  { id: "d-brief", title: "Generate a cyber briefing", desc: "Turn activity into an executive-ready summary.", sec: "cyberbriefing", cat: "grc", level: "core", mins: 10 },

  // --- Ranges & Challenges ---
  { id: "d-crucible", title: "Enter CRUCIBLE and run a wargame", desc: "Full attack/defend simulation with after-action review.", sec: "crucible", cat: "ranges", level: "advanced", mins: 30 },
  { id: "d-secquiz", title: "Take a skill assessment", desc: "Benchmark yourself on a specific domain.", sec: "secquiz", cat: "ranges", level: "core", mins: 15 },
  { id: "d-checklist", title: "Work through a security checklist", desc: "Harden a system item by item.", sec: "secchecklist", cat: "ranges", level: "core", mins: 15 },
  { id: "d-training", title: "Pick an external training lab", desc: "Curated HTB / TryHackMe / PortSwigger jump-offs.", sec: "training", cat: "ranges", level: "intro", mins: 5 },

  // --- AI & Automation ---
  { id: "d-ai", title: "Ask Darknode AI a security question", desc: "Get an explanation, a plan, or a payload idea.", sec: "ai", cat: "ai", level: "intro", mins: 5 },
  { id: "d-coder", title: "Have the Nexus agent do a task", desc: "An agent that reads, edits, and runs on your side.", sec: "coder", cat: "ai", level: "core", mins: 10 },
  { id: "d-report", title: "Generate a report", desc: "Turn findings into a shareable document.", sec: "report", cat: "ai", level: "core", mins: 10 },
  { id: "d-dataviz", title: "Visualize a dataset", desc: "Make patterns in security data pop.", sec: "dataviz", cat: "ai", level: "core", mins: 10 },
];

// ---- pure helpers (tested) ----
const norm = (s) => String(s == null ? "" : s).toLowerCase();

// Filter by category id ("all" = any), level ("all" = any), and a free-text query over title/desc.
export function filterActivities(list, opts) {
  opts = opts || {};
  const cat = opts.cat && opts.cat !== "all" ? opts.cat : null;
  const level = opts.level && opts.level !== "all" ? opts.level : null;
  const q = norm(opts.q).trim();
  return (list || []).filter((a) => {
    if (cat && a.cat !== cat) return false;
    if (level && a.level !== level) return false;
    if (q && !(norm(a.title).includes(q) || norm(a.desc).includes(q) || norm(a.cat).includes(q))) return false;
    return true;
  });
}

// Progress rollup given the set of completed activity ids.
export function progressStats(list, doneIds) {
  const done = new Set((doneIds || []).filter(Boolean));
  const byCat = {};
  for (const c of CATEGORIES) byCat[c.id] = { total: 0, done: 0 };
  let total = 0, completed = 0;
  for (const a of list || []) {
    if (!byCat[a.cat]) byCat[a.cat] = { total: 0, done: 0 };
    byCat[a.cat].total++; total++;
    if (done.has(a.id)) { byCat[a.cat].done++; completed++; }
  }
  return { total, done: completed, pct: total ? Math.round((completed / total) * 100) : 0, byCat };
}

// Keep only activities whose `sec` exists in the live nav (guards against a renamed/removed
// section leaving a dead card). `knownSecs` is a Set; when null, nothing is filtered.
export function validActivities(list, knownSecs) {
  if (!knownSecs) return (list || []).slice();
  return (list || []).filter((a) => knownSecs.has(a.sec));
}
