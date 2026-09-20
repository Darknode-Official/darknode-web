// Darknode Threat Engine — IOC extraction, YARA-like matching, Sigma parsing,
// MITRE ATT&CK mapping, DGA detection, beaconing detection, threat scoring.
// Pure browser JS, no dependencies. All functions are ES module exports.

// ─── IOC Extraction ─────────────────────────────────────────────────────────
// Extract Indicators of Compromise from unstructured text

const RE_IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const RE_IPV6 = /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g;
const RE_DOMAIN = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ai|edu|gov|mil|int|info|biz|name|pro|aero|coop|museum|xyz|top|site|online|club|tech|dev|app|cloud|security|hack|cyber|onion|bit|cc|ws|tk|ml|ga|cf|gq|ru|cn|br|in|de|uk|fr|jp|au|ca|it|nl|se|no|fi|dk|pl|cz|ch|at|be|es|pt|ie|nz|sg|hk|tw|kr|za|mx|ar|co|cl|pe|ve|ec|uy|py|bo)\b/gi;
const RE_URL = /https?:\/\/[^\s"'<>\])}]+/gi;
const RE_EMAIL = /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g;
const RE_MD5 = /\b[a-fA-F0-9]{32}\b/g;
const RE_SHA1 = /\b[a-fA-F0-9]{40}\b/g;
const RE_SHA256 = /\b[a-fA-F0-9]{64}\b/g;
const RE_SHA512 = /\b[a-fA-F0-9]{128}\b/g;
const RE_CVE = /CVE-\d{4}-\d{4,}/gi;
const RE_BTC = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g;
const RE_MAC = /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g;
const RE_REGISTRY = /\b(?:HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s"']+/g;
const RE_FILEPATH_WIN = /\b[A-Z]:\\(?:[^\s"'\\]+\\)*[^\s"'\\]+/g;
const RE_FILEPATH_UNIX = /(?:^|\s)(\/(?:etc|var|tmp|usr|opt|home|root|proc|sys|dev|bin|sbin)\/[^\s"']+)/gm;
const RE_USERAGENT = /(?:Mozilla|Opera|curl|wget|python-requests|Go-http-client|Java)\/.+/g;
const RE_MITRE = /T\d{4}(?:\.\d{3})?/g;
const RE_YARA_RULE_NAME = /rule\s+(\w+)/g;

export function extractIOCs(text) {
  const dedup = (arr) => [...new Set(arr)];
  const ipv4 = dedup((text.match(RE_IPV4) || []).filter(ip => {
    const parts = ip.split(".").map(Number);
    if (parts[0] === 0 || parts[0] === 127 || parts[0] === 255) return false;
    if (parts[0] === 10) return true; // private but still IOC-worthy
    return true;
  }));
  const ipv6 = dedup(text.match(RE_IPV6) || []);
  const domains = dedup((text.match(RE_DOMAIN) || []).filter(d => {
    const lower = d.toLowerCase();
    if (["example.com","localhost.localdomain","test.com"].includes(lower)) return false;
    return true;
  }));
  const urls = dedup(text.match(RE_URL) || []);
  const emails = dedup(text.match(RE_EMAIL) || []);
  const hashes = {
    md5: dedup(text.match(RE_MD5) || []),
    sha1: dedup(text.match(RE_SHA1) || []),
    sha256: dedup(text.match(RE_SHA256) || []),
    sha512: dedup(text.match(RE_SHA512) || []),
  };
  // Remove sha256 from sha512 matches, sha1 from sha256, md5 from sha1
  hashes.sha512 = hashes.sha512.filter(h => !hashes.sha256.includes(h.substring(0, 64)));
  hashes.sha256 = hashes.sha256.filter(h => !hashes.sha1.includes(h.substring(0, 40)));
  hashes.sha1 = hashes.sha1.filter(h => !hashes.md5.includes(h.substring(0, 32)));

  const cves = dedup((text.match(RE_CVE) || []).map(c => c.toUpperCase()));
  const bitcoin = dedup(text.match(RE_BTC) || []);
  const macs = dedup(text.match(RE_MAC) || []);
  const registry = dedup(text.match(RE_REGISTRY) || []);
  const filepaths = dedup([...(text.match(RE_FILEPATH_WIN) || []), ...(text.match(RE_FILEPATH_UNIX) || []).map(s => s.trim())]);
  const mitre = dedup((text.match(RE_MITRE) || []).map(t => t.toUpperCase()));

  const total = ipv4.length + ipv6.length + domains.length + urls.length + emails.length +
    hashes.md5.length + hashes.sha1.length + hashes.sha256.length + hashes.sha512.length +
    cves.length + bitcoin.length + macs.length + registry.length + filepaths.length + mitre.length;

  return { ipv4, ipv6, domains, urls, emails, hashes, cves, bitcoin, macs, registry, filepaths, mitre, total };
}

// ─── IOC Defanging / Refanging ──────────────────────────────────────────────
export function defang(text) {
  return text
    .replace(/https?:\/\//g, m => m.replace("http", "hxxp"))
    .replace(/\./g, "[.]")
    .replace(/@/g, "[@]");
}

export function refang(text) {
  return text
    .replace(/hxxps?:\/\//gi, m => m.replace("hxxp", "http"))
    .replace(/\[\.\]/g, ".")
    .replace(/\[@\]/g, "@")
    .replace(/\[:\]/g, ":");
}

// ─── Shannon Entropy ────────────────────────────────────────────────────────
export function shannonEntropy(data) {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  if (!bytes.length) return 0;
  const freq = new Uint32Array(256);
  for (const b of bytes) freq[b]++;
  let entropy = 0;
  const len = bytes.length;
  for (let i = 0; i < 256; i++) {
    if (freq[i] === 0) continue;
    const p = freq[i] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// ─── DGA Detection ──────────────────────────────────────────────────────────
// Domain Generation Algorithm detection via entropy + character analysis
export function detectDGA(domain) {
  const name = domain.split(".")[0].toLowerCase();
  if (name.length < 4) return { isDGA: false, score: 0, reasons: ["too short"] };

  const entropy = shannonEntropy(name);
  const consonantRatio = (name.match(/[bcdfghjklmnpqrstvwxyz]/g) || []).length / name.length;
  const vowelRatio = (name.match(/[aeiou]/g) || []).length / name.length;
  const digitRatio = (name.match(/[0-9]/g) || []).length / name.length;
  const maxConsecutiveConsonants = Math.max(...(name.match(/[bcdfghjklmnpqrstvwxyz]+/g) || [""]).map(s => s.length));
  const hasCommonBigrams = /th|he|in|er|an|re|on|at|en|nd|ti|es|or|te|of|ed|is|it|al|ar|st|to|nt|ng|se|ha|as|ou|io|le|ve|co|me|de|hi|ri|ro|ic|ne|ea|ra|ce/.test(name);
  const len = name.length;

  const reasons = [];
  let score = 0;

  if (entropy > 3.5) { score += 25; reasons.push(`high entropy (${entropy.toFixed(2)})`); }
  if (entropy > 4.0) { score += 15; }
  if (consonantRatio > 0.75) { score += 20; reasons.push("excessive consonants"); }
  if (vowelRatio < 0.15) { score += 15; reasons.push("very few vowels"); }
  if (digitRatio > 0.3) { score += 20; reasons.push("many digits"); }
  if (maxConsecutiveConsonants > 4) { score += 15; reasons.push(`${maxConsecutiveConsonants} consecutive consonants`); }
  if (!hasCommonBigrams && len > 6) { score += 10; reasons.push("no common English bigrams"); }
  if (len > 15) { score += 10; reasons.push("unusually long"); }
  if (len > 25) { score += 10; }

  // Known benign patterns
  if (/^(www|mail|ftp|cdn|api|app|dev|test|staging|prod|admin|ns\d?)$/.test(name)) {
    score = 0; reasons.length = 0; reasons.push("common subdomain name");
  }

  return {
    isDGA: score >= 50,
    score: Math.min(100, score),
    entropy: Math.round(entropy * 100) / 100,
    consonantRatio: Math.round(consonantRatio * 100) / 100,
    vowelRatio: Math.round(vowelRatio * 100) / 100,
    digitRatio: Math.round(digitRatio * 100) / 100,
    reasons,
    domain
  };
}

// ─── Beaconing Detection ────────────────────────────────────────────────────
// Detect periodic callback patterns from timestamps
export function detectBeaconing(timestamps, tolerancePct = 15) {
  if (timestamps.length < 5) return { isBeaconing: false, reason: "insufficient data points" };
  const sorted = [...timestamps].sort((a, b) => a - b);
  const intervals = [];
  for (let i = 1; i < sorted.length; i++) intervals.push(sorted[i] - sorted[i - 1]);

  const mean = intervals.reduce((s, v) => s + v, 0) / intervals.length;
  const variance = intervals.reduce((s, v) => s + (v - mean) ** 2, 0) / intervals.length;
  const stddev = Math.sqrt(variance);
  const cv = stddev / mean; // coefficient of variation

  const tolerance = mean * (tolerancePct / 100);
  const withinTolerance = intervals.filter(i => Math.abs(i - mean) <= tolerance).length;
  const regularityPct = (withinTolerance / intervals.length) * 100;

  // Detect jitter — beacons often add random jitter
  const jitterEstimate = stddev / mean * 100;

  // Check for common beacon intervals (seconds)
  const commonIntervals = [1, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600];
  const nearestCommon = commonIntervals.reduce((best, ci) =>
    Math.abs(mean - ci) < Math.abs(mean - best) ? ci : best, commonIntervals[0]);
  const matchesCommon = Math.abs(mean - nearestCommon) / nearestCommon < 0.2;

  const isBeaconing = cv < 0.3 && regularityPct > 60;
  const confidence = isBeaconing ? Math.min(100, Math.round((1 - cv) * regularityPct)) : Math.round(regularityPct * (1 - cv));

  return {
    isBeaconing,
    confidence,
    intervalMean: Math.round(mean * 100) / 100,
    intervalStddev: Math.round(stddev * 100) / 100,
    coefficientOfVariation: Math.round(cv * 1000) / 1000,
    regularity: Math.round(regularityPct),
    jitterPct: Math.round(jitterEstimate * 10) / 10,
    dataPoints: timestamps.length,
    matchesCommonInterval: matchesCommon ? nearestCommon : null,
    intervals: intervals.slice(0, 20), // first 20 for inspection
  };
}

// ─── MITRE ATT&CK Mapping ──────────────────────────────────────────────────
const MITRE_TECHNIQUES = {
  "T1059": { name: "Command and Scripting Interpreter", tactic: "Execution" },
  "T1059.001": { name: "PowerShell", tactic: "Execution" },
  "T1059.003": { name: "Windows Command Shell", tactic: "Execution" },
  "T1059.004": { name: "Unix Shell", tactic: "Execution" },
  "T1059.006": { name: "Python", tactic: "Execution" },
  "T1053": { name: "Scheduled Task/Job", tactic: "Execution, Persistence" },
  "T1053.005": { name: "Scheduled Task", tactic: "Execution, Persistence" },
  "T1547": { name: "Boot or Logon Autostart Execution", tactic: "Persistence" },
  "T1547.001": { name: "Registry Run Keys", tactic: "Persistence" },
  "T1543": { name: "Create or Modify System Process", tactic: "Persistence" },
  "T1543.003": { name: "Windows Service", tactic: "Persistence" },
  "T1078": { name: "Valid Accounts", tactic: "Defense Evasion, Persistence, Privilege Escalation, Initial Access" },
  "T1027": { name: "Obfuscated Files or Information", tactic: "Defense Evasion" },
  "T1027.001": { name: "Binary Padding", tactic: "Defense Evasion" },
  "T1055": { name: "Process Injection", tactic: "Defense Evasion, Privilege Escalation" },
  "T1055.001": { name: "DLL Injection", tactic: "Defense Evasion, Privilege Escalation" },
  "T1055.012": { name: "Process Hollowing", tactic: "Defense Evasion" },
  "T1036": { name: "Masquerading", tactic: "Defense Evasion" },
  "T1070": { name: "Indicator Removal", tactic: "Defense Evasion" },
  "T1070.001": { name: "Clear Windows Event Logs", tactic: "Defense Evasion" },
  "T1070.004": { name: "File Deletion", tactic: "Defense Evasion" },
  "T1003": { name: "OS Credential Dumping", tactic: "Credential Access" },
  "T1003.001": { name: "LSASS Memory", tactic: "Credential Access" },
  "T1003.003": { name: "NTDS", tactic: "Credential Access" },
  "T1110": { name: "Brute Force", tactic: "Credential Access" },
  "T1110.001": { name: "Password Guessing", tactic: "Credential Access" },
  "T1110.003": { name: "Password Spraying", tactic: "Credential Access" },
  "T1558": { name: "Steal or Forge Kerberos Tickets", tactic: "Credential Access" },
  "T1558.003": { name: "Kerberoasting", tactic: "Credential Access" },
  "T1046": { name: "Network Service Discovery", tactic: "Discovery" },
  "T1082": { name: "System Information Discovery", tactic: "Discovery" },
  "T1083": { name: "File and Directory Discovery", tactic: "Discovery" },
  "T1087": { name: "Account Discovery", tactic: "Discovery" },
  "T1018": { name: "Remote System Discovery", tactic: "Discovery" },
  "T1021": { name: "Remote Services", tactic: "Lateral Movement" },
  "T1021.001": { name: "Remote Desktop Protocol", tactic: "Lateral Movement" },
  "T1021.002": { name: "SMB/Windows Admin Shares", tactic: "Lateral Movement" },
  "T1021.004": { name: "SSH", tactic: "Lateral Movement" },
  "T1570": { name: "Lateral Tool Transfer", tactic: "Lateral Movement" },
  "T1560": { name: "Archive Collected Data", tactic: "Collection" },
  "T1005": { name: "Data from Local System", tactic: "Collection" },
  "T1039": { name: "Data from Network Shared Drive", tactic: "Collection" },
  "T1041": { name: "Exfiltration Over C2 Channel", tactic: "Exfiltration" },
  "T1048": { name: "Exfiltration Over Alternative Protocol", tactic: "Exfiltration" },
  "T1071": { name: "Application Layer Protocol", tactic: "Command and Control" },
  "T1071.001": { name: "Web Protocols", tactic: "Command and Control" },
  "T1071.004": { name: "DNS", tactic: "Command and Control" },
  "T1105": { name: "Ingress Tool Transfer", tactic: "Command and Control" },
  "T1572": { name: "Protocol Tunneling", tactic: "Command and Control" },
  "T1573": { name: "Encrypted Channel", tactic: "Command and Control" },
  "T1486": { name: "Data Encrypted for Impact", tactic: "Impact" },
  "T1489": { name: "Service Stop", tactic: "Impact" },
  "T1490": { name: "Inhibit System Recovery", tactic: "Impact" },
  "T1491": { name: "Defacement", tactic: "Impact" },
  "T1566": { name: "Phishing", tactic: "Initial Access" },
  "T1566.001": { name: "Spearphishing Attachment", tactic: "Initial Access" },
  "T1566.002": { name: "Spearphishing Link", tactic: "Initial Access" },
  "T1190": { name: "Exploit Public-Facing Application", tactic: "Initial Access" },
  "T1133": { name: "External Remote Services", tactic: "Initial Access" },
  "T1195": { name: "Supply Chain Compromise", tactic: "Initial Access" },
  "T1568": { name: "Dynamic Resolution", tactic: "Command and Control" },
  "T1568.002": { name: "Domain Generation Algorithms", tactic: "Command and Control" },
};

export function mapToMITRE(techniqueIds) {
  return techniqueIds.map(id => {
    const upper = id.toUpperCase();
    const entry = MITRE_TECHNIQUES[upper];
    return entry ? { id: upper, ...entry } : { id: upper, name: "Unknown", tactic: "Unknown" };
  });
}

export function mapIndicatorsToMITRE(indicators) {
  const mapped = [];
  if (indicators.ipv4?.length || indicators.domains?.length) {
    mapped.push("T1071.001", "T1105");
  }
  if (indicators.hashes?.sha256?.length || indicators.hashes?.md5?.length) {
    mapped.push("T1027");
  }
  if (indicators.registry?.length) {
    mapped.push("T1547.001", "T1112");
  }
  if (indicators.cves?.length) {
    mapped.push("T1190");
  }
  if (indicators.filepaths?.some(p => /powershell|cmd\.exe|bash/i.test(p))) {
    mapped.push("T1059.001", "T1059.003");
  }
  if (indicators.emails?.length) {
    mapped.push("T1566");
  }
  return mapToMITRE([...new Set(mapped)]);
}

// ─── Threat Scoring ─────────────────────────────────────────────────────────
export function threatScore(indicators) {
  let score = 0;
  const factors = [];

  if (indicators.ipv4?.length > 0) { score += indicators.ipv4.length * 5; factors.push(`${indicators.ipv4.length} IP addresses`); }
  if (indicators.domains?.length > 0) { score += indicators.domains.length * 3; factors.push(`${indicators.domains.length} domains`); }
  if (indicators.urls?.length > 0) { score += indicators.urls.length * 4; factors.push(`${indicators.urls.length} URLs`); }
  if (indicators.hashes?.md5?.length > 0) { score += indicators.hashes.md5.length * 8; factors.push(`${indicators.hashes.md5.length} MD5 hashes`); }
  if (indicators.hashes?.sha256?.length > 0) { score += indicators.hashes.sha256.length * 10; factors.push(`${indicators.hashes.sha256.length} SHA-256 hashes`); }
  if (indicators.cves?.length > 0) { score += indicators.cves.length * 15; factors.push(`${indicators.cves.length} CVEs`); }
  if (indicators.registry?.length > 0) { score += indicators.registry.length * 12; factors.push(`${indicators.registry.length} registry keys`); }
  if (indicators.bitcoin?.length > 0) { score += indicators.bitcoin.length * 20; factors.push(`${indicators.bitcoin.length} Bitcoin addresses (ransomware indicator)`); }
  if (indicators.mitre?.length > 0) { score += indicators.mitre.length * 7; factors.push(`${indicators.mitre.length} MITRE techniques`); }

  // Check for known malicious patterns
  const maliciousPatterns = [
    { re: /cobalt\s*strike|beacon/i, score: 30, name: "Cobalt Strike reference" },
    { re: /mimikatz|sekurlsa/i, score: 25, name: "Mimikatz reference" },
    { re: /metasploit|meterpreter/i, score: 20, name: "Metasploit reference" },
    { re: /ransomware|encrypt.*files|bitcoin.*ransom/i, score: 35, name: "Ransomware indicators" },
    { re: /c2\s*server|command.and.control|callback/i, score: 25, name: "C2 infrastructure" },
    { re: /lateral\s*movement|pivot/i, score: 15, name: "Lateral movement" },
    { re: /privilege\s*escalation|priv\s*esc/i, score: 15, name: "Privilege escalation" },
    { re: /exfiltrat/i, score: 20, name: "Data exfiltration" },
    { re: /persistence|autorun|startup/i, score: 12, name: "Persistence mechanism" },
    { re: /phishing|spearphish/i, score: 15, name: "Phishing" },
  ];

  const allText = JSON.stringify(indicators);
  for (const pat of maliciousPatterns) {
    if (pat.re.test(allText)) { score += pat.score; factors.push(pat.name); }
  }

  let severity;
  if (score >= 100) severity = "critical";
  else if (score >= 60) severity = "high";
  else if (score >= 30) severity = "medium";
  else if (score >= 10) severity = "low";
  else severity = "informational";

  return { score: Math.min(100, score), severity, factors, indicatorCount: indicators.total || 0 };
}

// ─── Malware Family Heuristics ──────────────────────────────────────────────
const MALWARE_SIGNATURES = [
  { family: "Emotet", indicators: [/emotet/i, /epoch\d/i, /\.dll.*regsvr32/i, /C:\\Users\\.*\\AppData\\Local\\.*\.dll/i], score: 0 },
  { family: "TrickBot", indicators: [/trickbot/i, /trickloader/i, /moduleconfig/i, /tabDll/i], score: 0 },
  { family: "Cobalt Strike", indicators: [/cobalt\s*strike/i, /beacon\.dll/i, /sleeptime/i, /watermark/i, /\.cobaltstrike/i], score: 0 },
  { family: "Mimikatz", indicators: [/mimikatz/i, /sekurlsa/i, /kerberos::list/i, /lsadump/i, /privilege::debug/i], score: 0 },
  { family: "Ryuk", indicators: [/ryuk/i, /RyukReadMe/i, /\.ryk$/i, /hermes/i], score: 0 },
  { family: "REvil/Sodinokibi", indicators: [/revil/i, /sodinokibi/i, /\{EXT\}-readme\.txt/i], score: 0 },
  { family: "WannaCry", indicators: [/wannacry/i, /wcry/i, /\.wncry/i, /mssecsvc/i, /tasksche\.exe/i], score: 0 },
  { family: "AgentTesla", indicators: [/agent\s*tesla/i, /smtp.*exfil/i, /keylog.*ftp/i, /\.net.*obfuscat/i], score: 0 },
  { family: "Remcos RAT", indicators: [/remcos/i, /breaking-security/i, /remcos\.exe/i], score: 0 },
  { family: "Qakbot", indicators: [/qakbot/i, /qbot/i, /pinkslipbot/i], score: 0 },
  { family: "IcedID", indicators: [/icedid/i, /bokbot/i, /license\.dat/i], score: 0 },
  { family: "AsyncRAT", indicators: [/asyncrat/i, /async.*client/i, /venomrat/i], score: 0 },
  { family: "Conti", indicators: [/conti/i, /conti_locker/i, /\.CONTI$/i], score: 0 },
  { family: "LockBit", indicators: [/lockbit/i, /\.lockbit$/i, /restore-my-files\.txt/i], score: 0 },
  { family: "APT29/Cozy Bear", indicators: [/cozy\s*bear/i, /apt29/i, /sunburst/i, /nobelium/i], score: 0 },
  { family: "APT28/Fancy Bear", indicators: [/fancy\s*bear/i, /apt28/i, /sofacy/i, /sednit/i], score: 0 },
  { family: "Lazarus Group", indicators: [/lazarus/i, /hidden\s*cobra/i, /apt38/i], score: 0 },
];

export function classifyMalware(text) {
  const matches = [];
  for (const sig of MALWARE_SIGNATURES) {
    let matchCount = 0;
    const matchedPatterns = [];
    for (const re of sig.indicators) {
      if (re.test(text)) { matchCount++; matchedPatterns.push(re.source); }
    }
    if (matchCount > 0) {
      matches.push({
        family: sig.family,
        confidence: Math.min(100, Math.round((matchCount / sig.indicators.length) * 100)),
        matchedPatterns: matchedPatterns.length,
        totalPatterns: sig.indicators.length,
      });
    }
  }
  matches.sort((a, b) => b.confidence - a.confidence);
  return { matches, topMatch: matches[0] || null };
}

// ─── YARA-like Rule Engine ──────────────────────────────────────────────────
// Simplified YARA rule matching: supports string matches and conditions

export function parseYaraRule(ruleText) {
  const nameMatch = ruleText.match(/rule\s+(\w+)/);
  if (!nameMatch) return null;
  const name = nameMatch[1];

  // Extract meta
  const metaBlock = ruleText.match(/meta\s*:\s*([\s\S]*?)(?=strings\s*:|condition\s*:|$)/);
  const meta = {};
  if (metaBlock) {
    for (const line of metaBlock[1].split("\n")) {
      const m = line.match(/(\w+)\s*=\s*"([^"]*)"/);
      if (m) meta[m[1]] = m[2];
    }
  }

  // Extract strings
  const stringsBlock = ruleText.match(/strings\s*:\s*([\s\S]*?)(?=condition\s*:|$)/);
  const strings = {};
  if (stringsBlock) {
    for (const line of stringsBlock[1].split("\n")) {
      const textMatch = line.match(/(\$\w+)\s*=\s*"([^"]*)"/);
      const hexMatch = line.match(/(\$\w+)\s*=\s*\{([^}]*)\}/);
      if (textMatch) strings[textMatch[1]] = { type: "text", value: textMatch[2] };
      else if (hexMatch) strings[hexMatch[1]] = { type: "hex", value: hexMatch[2].replace(/\s/g, "") };
    }
  }

  // Extract condition
  const condBlock = ruleText.match(/condition\s*:\s*([\s\S]*?)$/);
  const condition = condBlock ? condBlock[1].trim() : "any of them";

  return { name, meta, strings, condition };
}

export function matchYaraRule(rule, data) {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  const text = typeof data === "string" ? data : new TextDecoder().decode(data);

  const stringMatches = {};
  let totalMatches = 0;

  for (const [varName, def] of Object.entries(rule.strings)) {
    const matches = [];
    if (def.type === "text") {
      let idx = 0;
      while ((idx = text.indexOf(def.value, idx)) !== -1) {
        matches.push({ offset: idx, length: def.value.length });
        idx++;
      }
    } else if (def.type === "hex") {
      const hexBytes = [];
      for (let i = 0; i < def.value.length; i += 2) {
        if (def.value[i] === "?") { hexBytes.push(-1); i += (def.value[i+1] === "?" ? 0 : -1); }
        else hexBytes.push(parseInt(def.value.substr(i, 2), 16));
      }
      for (let i = 0; i <= bytes.length - hexBytes.length; i++) {
        let match = true;
        for (let j = 0; j < hexBytes.length; j++) {
          if (hexBytes[j] !== -1 && bytes[i + j] !== hexBytes[j]) { match = false; break; }
        }
        if (match) matches.push({ offset: i, length: hexBytes.length });
      }
    }
    stringMatches[varName] = matches;
    totalMatches += matches.length;
  }

  // Evaluate condition
  let matched = false;
  const cond = rule.condition.trim();
  if (cond === "any of them") {
    matched = totalMatches > 0;
  } else if (cond === "all of them") {
    matched = Object.values(stringMatches).every(m => m.length > 0);
  } else if (/^\d+ of them$/.test(cond)) {
    const n = parseInt(cond);
    matched = Object.values(stringMatches).filter(m => m.length > 0).length >= n;
  } else {
    // Try to evaluate simple $var references
    for (const [v, m] of Object.entries(stringMatches)) {
      if (cond.includes(v) && m.length > 0) matched = true;
    }
  }

  return { ruleName: rule.name, matched, stringMatches, totalMatches, meta: rule.meta };
}

// ─── Sigma Rule Parser ──────────────────────────────────────────────────────
// Parse Sigma rules (YAML-like format) and match against log entries

export function parseSigmaRule(yamlText) {
  const lines = yamlText.split("\n");
  const rule = { title: "", status: "", level: "", description: "", detection: {}, logsource: {} };
  let currentSection = "";
  let currentKey = "";
  let indent = 0;

  for (const rawLine of lines) {
    const line = rawLine.trimEnd();
    if (!line || line.startsWith("#")) continue;
    const lineIndent = line.length - line.trimStart().length;
    const trimmed = line.trim();

    if (trimmed.startsWith("title:")) rule.title = trimmed.slice(6).trim();
    else if (trimmed.startsWith("status:")) rule.status = trimmed.slice(7).trim();
    else if (trimmed.startsWith("level:")) rule.level = trimmed.slice(6).trim();
    else if (trimmed.startsWith("description:")) rule.description = trimmed.slice(12).trim();
    else if (trimmed === "detection:") currentSection = "detection";
    else if (trimmed === "logsource:") currentSection = "logsource";
    else if (currentSection === "logsource" && trimmed.includes(":")) {
      const [k, v] = trimmed.split(":").map(s => s.trim());
      rule.logsource[k] = v;
    }
    else if (currentSection === "detection") {
      if (trimmed.startsWith("condition:")) {
        rule.detection.condition = trimmed.slice(10).trim();
      } else if (lineIndent === 4 && trimmed.endsWith(":")) {
        currentKey = trimmed.slice(0, -1);
        rule.detection[currentKey] = {};
      } else if (lineIndent >= 8 && currentKey) {
        if (trimmed.startsWith("- ")) {
          const val = trimmed.slice(2);
          if (!Array.isArray(rule.detection[currentKey])) {
            const existing = rule.detection[currentKey];
            rule.detection[currentKey] = typeof existing === "object" && !Array.isArray(existing) ? existing : [];
          }
          if (Array.isArray(rule.detection[currentKey])) rule.detection[currentKey].push(val);
        } else if (trimmed.includes(":")) {
          const [k, v] = trimmed.split(":").map(s => s.trim());
          if (typeof rule.detection[currentKey] === "object" && !Array.isArray(rule.detection[currentKey])) {
            rule.detection[currentKey][k] = v;
          }
        }
      }
    }
  }
  return rule;
}

export function matchSigmaRule(rule, logEntry) {
  const cond = rule.detection.condition || "";
  const selectionKeys = Object.keys(rule.detection).filter(k => k !== "condition");

  const selectionResults = {};
  for (const selKey of selectionKeys) {
    const sel = rule.detection[selKey];
    let matched = false;

    if (typeof sel === "object" && !Array.isArray(sel)) {
      matched = Object.entries(sel).every(([field, pattern]) => {
        const value = logEntry[field] || logEntry[field.toLowerCase()] || "";
        const strVal = String(value).toLowerCase();
        const strPat = String(pattern).toLowerCase();
        if (strPat.startsWith("*") && strPat.endsWith("*")) return strVal.includes(strPat.slice(1, -1));
        if (strPat.startsWith("*")) return strVal.endsWith(strPat.slice(1));
        if (strPat.endsWith("*")) return strVal.startsWith(strPat.slice(0, -1));
        return strVal === strPat || strVal.includes(strPat);
      });
    } else if (Array.isArray(sel)) {
      const logStr = JSON.stringify(logEntry).toLowerCase();
      matched = sel.some(v => logStr.includes(String(v).toLowerCase()));
    }
    selectionResults[selKey] = matched;
  }

  let finalMatch = false;
  if (cond.includes(" and ")) {
    finalMatch = cond.split(" and ").every(part => {
      const key = part.trim().replace(/^not\s+/, "");
      const negated = part.trim().startsWith("not ");
      const result = selectionResults[key] ?? false;
      return negated ? !result : result;
    });
  } else if (cond.includes(" or ")) {
    finalMatch = cond.split(" or ").some(part => selectionResults[part.trim()] ?? false);
  } else {
    finalMatch = selectionResults[cond.trim()] ?? false;
  }

  return {
    matched: finalMatch,
    ruleName: rule.title,
    level: rule.level,
    selectionResults,
  };
}

// ─── Network Traffic Anomaly Detection ──────────────────────────────────────
export function detectNetworkAnomalies(connections) {
  // connections: array of { src, dst, port, bytes, timestamp, protocol }
  const anomalies = [];

  // 1. Port scan detection — single source hitting many ports on same dest
  const portScans = {};
  for (const c of connections) {
    const key = `${c.src}->${c.dst}`;
    if (!portScans[key]) portScans[key] = new Set();
    portScans[key].add(c.port);
  }
  for (const [key, ports] of Object.entries(portScans)) {
    if (ports.size > 20) {
      anomalies.push({ type: "port_scan", severity: "high", source: key.split("->")[0], target: key.split("->")[1], portCount: ports.size, description: `${key} touched ${ports.size} unique ports` });
    }
  }

  // 2. Data exfiltration — large outbound transfers
  const outboundBytes = {};
  for (const c of connections) {
    outboundBytes[c.src] = (outboundBytes[c.src] || 0) + (c.bytes || 0);
  }
  for (const [src, bytes] of Object.entries(outboundBytes)) {
    if (bytes > 100_000_000) {
      anomalies.push({ type: "data_exfiltration", severity: "high", source: src, bytes, description: `${src} sent ${(bytes/1e6).toFixed(1)} MB — possible exfiltration` });
    }
  }

  // 3. Unusual ports — connections to non-standard ports
  const unusualPorts = [4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 12345, 54321, 4443, 8443, 1234, 9001, 9030];
  for (const c of connections) {
    if (unusualPorts.includes(c.port)) {
      anomalies.push({ type: "unusual_port", severity: "medium", source: c.src, target: c.dst, port: c.port, description: `Connection to suspicious port ${c.port}` });
    }
  }

  // 4. DNS tunneling indicators — many DNS queries to same domain
  const dnsQueries = {};
  for (const c of connections) {
    if (c.protocol === "DNS" || c.port === 53) {
      dnsQueries[c.dst] = (dnsQueries[c.dst] || 0) + 1;
    }
  }
  for (const [dst, count] of Object.entries(dnsQueries)) {
    if (count > 100) {
      anomalies.push({ type: "dns_tunneling", severity: "high", target: dst, queryCount: count, description: `${count} DNS queries to ${dst} — possible DNS tunneling` });
    }
  }

  // 5. Beaconing — regular interval connections
  const connByPair = {};
  for (const c of connections) {
    if (!c.timestamp) continue;
    const key = `${c.src}->${c.dst}:${c.port}`;
    if (!connByPair[key]) connByPair[key] = [];
    connByPair[key].push(c.timestamp);
  }
  for (const [key, times] of Object.entries(connByPair)) {
    if (times.length >= 10) {
      const beacon = detectBeaconing(times);
      if (beacon.isBeaconing) {
        anomalies.push({ type: "beaconing", severity: "high", connection: key, interval: beacon.intervalMean, confidence: beacon.confidence, description: `Periodic beaconing detected: ${key} every ${beacon.intervalMean.toFixed(1)}s` });
      }
    }
  }

  anomalies.sort((a, b) => {
    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return (sevOrder[a.severity] || 4) - (sevOrder[b.severity] || 4);
  });

  return { anomalies, totalConnections: connections.length, uniqueSources: new Set(connections.map(c => c.src)).size, uniqueDestinations: new Set(connections.map(c => c.dst)).size };
}
