// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
// Blue Team & Detection mini-tools: detection-engineering scaffolds, log-format
// parsers, severity/scoring helpers and accurate defender reference tables.
// Pure client-side, deterministic. See _schema.md.

const S = (v) => (v == null ? "" : String(v));
const lines = (s) => S(s).split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
// searchable reference table: rows = array of string arrays, q = filter text
const ref = (rows, q) => {
  const s = S(q).toLowerCase().trim();
  const f = s ? rows.filter((r) => r.join(" ").toLowerCase().includes(s)) : rows;
  return f.length ? f.map((r) => r.join("\t")).join("\n") : "No matches.";
};
const num = (v) => { const n = Number(S(v).replace(/[, _]/g, "")); return isFinite(n) ? n : NaN; };
const humanTime = (mins) => {
  if (!isFinite(mins)) return "effectively infeasible";
  if (mins < 1 / 60) return `${(mins * 60).toFixed(2)} seconds`;
  if (mins < 60) return `${mins.toFixed(2)} minutes`;
  const hrs = mins / 60; if (hrs < 24) return `${hrs.toFixed(2)} hours`;
  const days = hrs / 24; if (days < 365) return `${days.toFixed(2)} days`;
  const yrs = days / 365; if (yrs < 1e6) return `${yrs.toFixed(2)} years`;
  return `${yrs.toExponential(2)} years`;
};
const humanBytes = (b) => {
  if (!isFinite(b)) return "?"; const u = ["B", "KB", "MB", "GB", "TB", "PB"]; let i = 0, n = b;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; } return `${n.toFixed(2)} ${u[i]}`;
};

// ---- grok base patterns (curated subset of logstash-patterns-core) ----
const GROK = {
  WORD: "\\b\\w+\\b", NOTSPACE: "\\S+", SPACE: "\\s*", DATA: ".*?", GREEDYDATA: ".*",
  INT: "(?:[+-]?(?:[0-9]+))", POSINT: "\\b(?:[1-9][0-9]*)\\b", NONNEGINT: "\\b(?:[0-9]+)\\b",
  NUMBER: "(?:[+-]?(?:[0-9]+(?:\\.[0-9]+)?))",
  USERNAME: "[a-zA-Z0-9._-]+", USER: "%{USERNAME}",
  IPV4: "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",
  IP: "%{IPV4}",
  HOSTNAME: "\\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*\\b",
  IPORHOST: "(?:%{IPV4}|%{HOSTNAME})",
  MONTHNUM: "(?:0?[1-9]|1[0-2])", MONTHDAY: "(?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9])",
  YEAR: "(?:\\d\\d){1,2}", HOUR: "(?:2[0123]|[01]?[0-9])", MINUTE: "(?:[0-5][0-9])",
  SECOND: "(?:(?:[0-5]?[0-9]|60)(?:[.,][0-9]+)?)", TIME: "%{HOUR}:%{MINUTE}:%{SECOND}",
  TIMESTAMP_ISO8601: "%{YEAR}-%{MONTHNUM}-%{MONTHDAY}[T ]%{HOUR}:%{MINUTE}:%{SECOND}(?:Z|[+-]%{HOUR}(?::?%{MINUTE})?)?",
  LOGLEVEL: "(?:[Tt]race|TRACE|[Dd]ebug|DEBUG|[Nn]otice|NOTICE|[Ii]nfo(?:rmation)?|INFO|[Ww]arn(?:ing)?|WARN(?:ING)?|[Ee]rr(?:or)?|ERR(?:OR)?|[Cc]rit(?:ical)?|CRIT(?:ICAL)?|[Ff]atal|FATAL|[Aa]lert|ALERT|[Ee]merg(?:ency)?|EMERG(?:ENCY)?)",
  QUOTEDSTRING: "(?:\"(?:\\\\.|[^\\\\\"]*)*\"|'(?:\\\\.|[^\\\\']*)*')",
  UUID: "[A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}",
  MAC: "(?:[A-Fa-f0-9]{2}[:-]){5}[A-Fa-f0-9]{2}",
};
function resolveGrok(name, stack) {
  stack = stack || [];
  if (!(name in GROK)) return null;
  if (stack.includes(name)) return "";
  let bad = false;
  const res = GROK[name].replace(/%\{(\w+)\}/g, (m, p) => { const r = resolveGrok(p, stack.concat(name)); if (r == null) { bad = true; return m; } return r; });
  return bad ? null : res;
}
function grokToRegex(grok) {
  const missing = [];
  const out = S(grok).replace(/%\{(\w+)(?::([\w.\[\]]+))?\}/g, (m, pat, field) => {
    const r = resolveGrok(pat);
    if (r == null) { missing.push(pat); return m; }
    if (field) { let g = field.replace(/[^\w]/g, "_"); if (/^\d/.test(g)) g = "f_" + g; return `(?<${g}>${r})`; }
    return `(?:${r})`;
  });
  return { out, missing };
}

// ---- IP protocol numbers (IANA, common) ----
const IP_PROTO = { 1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6 (encap)", 47: "GRE", 50: "ESP", 51: "AH", 58: "IPv6-ICMP", 89: "OSPF", 103: "PIM", 112: "VRRP", 132: "SCTP" };

export const TOOLS = [
  // ======================= DETECTION-AS-CODE BUILDERS =======================
  { id: "bt-sigma-scaffold", name: "Sigma Rule Scaffold", cat: "blueteam", desc: "Generate a valid Sigma detection rule YAML skeleton from title, logsource and selection fields.", tags: ["sigma", "detection", "yaml"],
    inputs: [
      { k: "title", label: "Title", type: "text", value: "Suspicious cmd.exe spawned by Office" },
      { k: "category", label: "logsource category", type: "text", value: "process_creation" },
      { k: "product", label: "logsource product", type: "text", value: "windows" },
      { k: "selection", label: "Selection (one 'Field: value' per line)", type: "textarea", rows: 4, value: "ParentImage|endswith: \\\\winword.exe\nImage|endswith: \\\\cmd.exe" },
      { k: "condition", label: "condition", type: "text", value: "selection" },
      { k: "level", label: "level", type: "select", opts: ["informational", "low", "medium", "high", "critical"], value: "high" },
    ],
    run(v, H) {
      if (!v.title) return { error: "Set a title." };
      const sel = lines(v.selection).map((l) => "        " + l).join("\n") || "        Image|endswith: \\cmd.exe";
      return [
        `title: ${v.title}`,
        `id: ${H.uuid()}`,
        `status: experimental`,
        `description: Describe what this rule detects and why it matters.`,
        `references:`,
        `    - https://example.com/reference`,
        `author: analyst`,
        `date: ${new Date().toISOString().slice(0, 10)}`,
        `logsource:`,
        v.category ? `    category: ${v.category}` : null,
        v.product ? `    product: ${v.product}` : null,
        `detection:`,
        `    selection:`,
        sel,
        `    condition: ${v.condition || "selection"}`,
        `falsepositives:`,
        `    - Unknown`,
        `level: ${v.level}`,
        `tags:`,
        `    - attack.execution`,
      ].filter((x) => x != null).join("\n");
    } },

  { id: "bt-sigma-modifiers", name: "Sigma Field-Modifier Reference", cat: "blueteam", desc: "Reference of Sigma detection field value-modifiers (contains, startswith, re, base64, cidr, ...).", tags: ["sigma", "reference", "modifier"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "base64, cidr, re..." }],
    run(v) {
      return ref([
        ["contains", "value appears anywhere in the field"],
        ["startswith", "field begins with the value"],
        ["endswith", "field ends with the value"],
        ["all", "list values must ALL match (default for a list is OR)"],
        ["re", "value is a regular expression"],
        ["cidr", "field (an IP) falls inside the given CIDR range"],
        ["base64", "encode the value as base64 before matching"],
        ["base64offset", "match base64 at any of the 3 byte offsets"],
        ["utf16 / utf16le / utf16be / wide", "encode value as UTF-16 before matching"],
        ["windash", "match both - and / command-line dash variants"],
        ["lt / lte / gt / gte", "numeric comparison less/greater than"],
        ["exists", "field is present (true) or absent (false)"],
        ["fieldref", "compare the field against another field's value"],
        ["cased", "case-sensitive match (default is case-insensitive)"],
      ], v.q);
    } },

  { id: "bt-sigma-logsource", name: "Sigma Logsource Reference", cat: "blueteam", desc: "Common Sigma logsource category / product / service values for the logsource block.", tags: ["sigma", "logsource", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "process, dns, firewall..." }],
    run(v) {
      return ref([
        ["category: process_creation", "product: windows (Sysmon EID 1 / Security 4688)"],
        ["category: image_load", "product: windows (Sysmon EID 7)"],
        ["category: network_connection", "product: windows (Sysmon EID 3)"],
        ["category: dns_query", "product: windows (Sysmon EID 22)"],
        ["category: file_event", "product: windows (Sysmon EID 11)"],
        ["category: registry_event / registry_set / registry_add", "product: windows (Sysmon EID 12-14)"],
        ["category: ps_script", "product: windows, service: powershell (EID 4104)"],
        ["category: ps_module", "product: windows, service: powershell (EID 4103)"],
        ["service: security", "product: windows (Security event log)"],
        ["service: system", "product: windows (System event log)"],
        ["service: sysmon", "product: windows"],
        ["service: powershell-classic", "product: windows (Windows PowerShell log, EID 400/800)"],
        ["service: wmi", "product: windows"],
        ["category: firewall", "product: (vendor)"],
        ["category: proxy", "product: (vendor)"],
        ["category: webserver", "product: (apache/nginx/iis)"],
        ["product: linux, service: auditd", ""],
        ["product: linux, service: syslog / sshd / cron / sudo", ""],
        ["product: aws, service: cloudtrail", ""],
        ["product: azure / gcp", ""],
      ], v.q);
    } },

  { id: "bt-spl-builder", name: "Splunk SPL Query Builder", cat: "blueteam", desc: "Build a Splunk search from index/sourcetype, field filters, time range and a stats-by clause.", tags: ["splunk", "spl", "siem"],
    inputs: [
      { k: "index", label: "index", type: "text", value: "wineventlog" },
      { k: "sourcetype", label: "sourcetype", type: "text", value: "WinEventLog:Security" },
      { k: "earliest", label: "earliest", type: "text", value: "-24h" },
      { k: "filters", label: "Field filters (one 'field=value' per line)", type: "textarea", rows: 3, value: "EventCode=4625\nAccount_Name=*" },
      { k: "statsBy", label: "stats count by (field, optional)", type: "text", value: "Account_Name, src_ip" },
    ],
    run(v) {
      const parts = [];
      if (v.index) parts.push(`index=${v.index}`);
      if (v.sourcetype) parts.push(`sourcetype="${v.sourcetype}"`);
      if (v.earliest) parts.push(`earliest=${v.earliest}`);
      for (const f of lines(v.filters)) parts.push(f);
      let q = parts.join(" ");
      if (v.statsBy && v.statsBy.trim()) q += `\n| stats count by ${v.statsBy.trim()}\n| sort - count`;
      return q || { error: "Set at least an index or a filter." };
    } },

  { id: "bt-spl-rex-build", name: "Splunk rex Extraction Builder", cat: "blueteam", desc: "Turn a regex with named groups into a Splunk `| rex` field-extraction command.", tags: ["splunk", "rex", "extract"],
    inputs: [
      { k: "field", label: "Source field", type: "text", value: "_raw" },
      { k: "regex", label: "Regex with (?<name>...) groups", type: "textarea", rows: 2, value: "user=(?<user>\\w+)\\s+src=(?<src_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)" },
    ],
    run(v) {
      if (!v.regex) return "";
      const names = Array.from(S(v.regex).matchAll(/\(\?<([A-Za-z_][\w]*)>/g)).map((m) => m[1]);
      const esc = S(v.regex).replace(/"/g, '\\"');
      return `| rex field=${v.field || "_raw"} "${esc}"` + (names.length ? `\n\nExtracted fields: ${names.join(", ")}` : `\n\n(no named groups found — Splunk rex needs (?<name>...) syntax)`);
    } },

  { id: "bt-spl-cheatsheet", name: "Splunk SPL Command Reference", cat: "blueteam", desc: "Quick reference of common Splunk SPL search commands used in detection and hunting.", tags: ["splunk", "spl", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "stats, rex, tstats..." }],
    run(v) {
      return ref([
        ["search", "filter events by terms/field comparisons"],
        ["where", "filter with eval expressions (e.g. where count>5)"],
        ["eval", "create/modify a field with an expression"],
        ["rex", "extract fields with a PCRE named-group regex"],
        ["stats", "aggregate: count, dc(), values(), sum() by field"],
        ["tstats", "fast aggregation over indexed/accelerated fields"],
        ["timechart", "aggregate over time for charting"],
        ["bin / bucket", "group a numeric/time field into ranges"],
        ["dedup", "keep first event per field combination"],
        ["sort", "order results (sort - count = descending)"],
        ["top / rare", "most / least common values of a field"],
        ["table / fields", "select which fields to show/keep"],
        ["transaction", "group related events into one transaction"],
        ["lookup / inputlookup", "enrich from a CSV/KV lookup table"],
        ["eventstats / streamstats", "add aggregate values back to each event"],
        ["makeresults", "generate a synthetic result row (testing)"],
      ], v.q);
    } },

  { id: "bt-kql-builder", name: "KQL Query Builder (Sentinel/Defender)", cat: "blueteam", desc: "Build a Microsoft Sentinel / Defender KQL query from a table, filters, time window and summarize.", tags: ["kql", "sentinel", "defender", "kusto"],
    inputs: [
      { k: "table", label: "Table", type: "text", value: "DeviceProcessEvents" },
      { k: "timespan", label: "Time window (ago)", type: "text", value: "24h" },
      { k: "where", label: "where conditions (one per line)", type: "textarea", rows: 3, value: 'FileName =~ "cmd.exe"\nProcessCommandLine has "whoami"' },
      { k: "summarize", label: "summarize ... by (optional)", type: "text", value: "count() by DeviceName, AccountName" },
      { k: "project", label: "project fields (optional)", type: "text" },
    ],
    run(v) {
      if (!v.table) return { error: "Set a table name." };
      const out = [v.table];
      if (v.timespan) out.push(`| where TimeGenerated > ago(${v.timespan})`);
      for (const w of lines(v.where)) out.push(`| where ${w}`);
      if (v.summarize && v.summarize.trim()) out.push(`| summarize ${v.summarize.trim()}`);
      if (v.project && v.project.trim()) out.push(`| project ${v.project.trim()}`);
      return out.join("\n");
    } },

  { id: "bt-kql-parse-build", name: "KQL parse Statement Builder", cat: "blueteam", desc: "Build a KQL `parse` operator from a sample line with {field} placeholders.", tags: ["kql", "parse", "extract"],
    inputs: [
      { k: "column", label: "Source column", type: "text", value: "RawData" },
      { k: "template", label: "Template with {field} placeholders", type: "text", value: "user={user} ip={src_ip} action={action}" },
    ],
    run(v) {
      if (!v.template) return "";
      const re = /\{([A-Za-z_]\w*)\}/g;
      let last = 0, m, segs = [], fields = [];
      const t = S(v.template);
      while ((m = re.exec(t))) {
        const lit = t.slice(last, m.index);
        if (lit) segs.push(`"${lit.replace(/"/g, '\\"')}"`);
        segs.push(m[1]); fields.push(m[1]); last = re.lastIndex;
      }
      const tail = t.slice(last);
      if (tail) segs.push(`"${tail.replace(/"/g, '\\"')}"`);
      if (!fields.length) return { error: "Add at least one {field} placeholder." };
      return `| parse ${v.column || "RawData"} with ${segs.join(" ")}\n\nExtracted: ${fields.join(", ")}`;
    } },

  { id: "bt-kql-cheatsheet", name: "KQL Operator Reference", cat: "blueteam", desc: "Reference of common Kusto (KQL) operators and functions for Sentinel/Defender hunting.", tags: ["kql", "kusto", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "summarize, join, ago..." }],
    run(v) {
      return ref([
        ["where", "filter rows by a predicate"],
        ["project / project-away", "select / drop columns"],
        ["extend", "add a calculated column"],
        ["summarize", "aggregate: count(), dcount(), make_list() by key"],
        ["join kind=inner|leftouter|...", "join two tables on a key"],
        ["union", "combine rows from multiple tables"],
        ["parse / parse-where", "extract substrings into columns"],
        ["has / contains / startswith / endswith", "string match operators"],
        ["=~ / !~", "case-insensitive equals / not-equals"],
        ["ago(timespan)", "a time relative to now, e.g. ago(1h)"],
        ["bin(col, span)", "round a value/time into buckets"],
        ["make_list() / make_set()", "collect values into an array"],
        ["mv-expand", "expand an array column into rows"],
        ["top N by col", "take the N highest rows"],
        ["render timechart", "chart aggregated results over time"],
        ["materialize()", "cache a subquery result for reuse"],
      ], v.q);
    } },

  { id: "bt-defender-tables", name: "Defender Hunting Table Reference", cat: "blueteam", desc: "Reference of common Microsoft Defender / Sentinel advanced-hunting table names and what they hold.", tags: ["defender", "sentinel", "kql", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "process, logon, network..." }],
    run(v) {
      return ref([
        ["DeviceProcessEvents", "process creations (command lines, parents)"],
        ["DeviceNetworkEvents", "network connections from endpoints"],
        ["DeviceFileEvents", "file create/modify/delete on endpoints"],
        ["DeviceRegistryEvents", "registry create/modify/delete"],
        ["DeviceLogonEvents", "logons observed on endpoints"],
        ["DeviceImageLoadEvents", "DLL / image loads"],
        ["DeviceEvents", "miscellaneous security events (misc EDR)"],
        ["DeviceInfo / DeviceNetworkInfo", "device inventory / network config"],
        ["IdentityLogonEvents", "logons from AD / Azure AD (identity)"],
        ["IdentityQueryEvents", "LDAP/directory queries"],
        ["EmailEvents / EmailUrlInfo / EmailAttachmentInfo", "Defender for Office 365 mail"],
        ["SigninLogs", "Azure AD interactive sign-ins (Sentinel)"],
        ["AADNonInteractiveUserSignInLogs", "non-interactive Azure AD sign-ins"],
        ["AuditLogs", "Azure AD directory audit events"],
        ["SecurityEvent", "Windows Security log via agent (Sentinel)"],
        ["SecurityAlert", "alerts from connected products"],
        ["Syslog / CommonSecurityLog", "syslog / CEF data (Sentinel)"],
      ], v.q);
    } },

  { id: "bt-osquery-pack", name: "osquery Pack Snippet Builder", cat: "blueteam", desc: "Build an osquery query-pack JSON entry from a name, SQL, interval and platform.", tags: ["osquery", "pack", "json"],
    inputs: [
      { k: "name", label: "Query name", type: "text", value: "listening_ports" },
      { k: "query", label: "SQL query", type: "textarea", rows: 2, value: "SELECT pid, address, port, protocol FROM listening_ports;" },
      { k: "interval", label: "Interval (seconds)", type: "text", value: "300" },
      { k: "platform", label: "Platform", type: "select", opts: ["all", "linux", "darwin", "windows", "posix"], value: "all" },
      { k: "snapshot", label: "Snapshot (vs differential)", type: "checkbox", value: false },
      { k: "desc", label: "Description", type: "text", value: "Current listening network ports" },
    ],
    run(v) {
      if (!v.name || !v.query) return { error: "Set a name and query." };
      const q = {};
      q[v.name] = { query: S(v.query).replace(/\s+/g, " ").trim(), interval: Number(v.interval) || 300, platform: v.platform === "all" ? undefined : v.platform, snapshot: v.snapshot || undefined, description: v.desc || undefined };
      Object.keys(q[v.name]).forEach((k) => q[v.name][k] === undefined && delete q[v.name][k]);
      return JSON.stringify({ queries: q }, null, 2);
    } },

  { id: "bt-osquery-tables", name: "osquery Table Reference", cat: "blueteam", desc: "Reference of commonly used osquery tables for endpoint detection and inventory.", tags: ["osquery", "reference", "endpoint"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "process, startup, user..." }],
    run(v) {
      return ref([
        ["processes", "running processes (pid, name, path, cmdline)"],
        ["process_open_sockets", "sockets opened by processes"],
        ["listening_ports", "ports in a listening state"],
        ["users", "local user accounts"],
        ["logged_in_users", "current interactive/remote sessions"],
        ["crontab", "cron jobs (Linux/macOS)"],
        ["startup_items", "auto-start programs"],
        ["scheduled_tasks", "Windows scheduled tasks"],
        ["services", "Windows services"],
        ["kernel_modules / kernel_extensions", "loaded kernel modules"],
        ["file", "file metadata by path"],
        ["hash", "md5/sha1/sha256 of a file"],
        ["authorized_keys", "SSH authorized_keys entries"],
        ["shell_history", "command history per user"],
        ["etc_hosts", "entries in the hosts file"],
        ["dns_resolvers", "configured DNS resolvers"],
        ["certificates", "installed certificates"],
        ["registry", "Windows registry keys/values"],
      ], v.q);
    } },

  { id: "bt-ids-rule", name: "Suricata / Snort Rule Builder", cat: "blueteam", desc: "Scaffold a Suricata or Snort IDS/IPS rule with action, header and common detection keywords.", tags: ["suricata", "snort", "ids", "rule"],
    inputs: [
      { k: "action", label: "Action", type: "select", opts: ["alert", "drop", "reject", "pass"], value: "alert" },
      { k: "proto", label: "Protocol", type: "select", opts: ["tcp", "udp", "icmp", "ip", "http", "dns", "tls"], value: "http" },
      { k: "src", label: "Source", type: "text", value: "$EXTERNAL_NET" },
      { k: "srcport", label: "Src port", type: "text", value: "any" },
      { k: "dir", label: "Direction", type: "select", opts: ["->", "<>"], value: "->" },
      { k: "dst", label: "Dest", type: "text", value: "$HOME_NET" },
      { k: "dstport", label: "Dst port", type: "text", value: "any" },
      { k: "msg", label: "msg", type: "text", value: "ET POLICY Suspicious whoami in URI" },
      { k: "content", label: "content (optional)", type: "text", value: "whoami" },
      { k: "sid", label: "sid", type: "text", value: "1000001" },
    ],
    run(v) {
      const opts = [];
      if (v.msg) opts.push(`msg:"${v.msg}"`);
      if (v.content) opts.push(`content:"${v.content}"`, `nocase`);
      opts.push(`classtype:policy-violation`);
      opts.push(`sid:${v.sid || 1000001}`, `rev:1`);
      return `${v.action} ${v.proto} ${v.src} ${v.srcport} ${v.dir} ${v.dst} ${v.dstport} (${opts.join("; ")};)`;
    } },

  { id: "bt-suricata-keywords", name: "Suricata/Snort Rule Keyword Reference", cat: "blueteam", desc: "Reference of common Suricata/Snort rule-option keywords used in the rule body.", tags: ["suricata", "snort", "reference", "keyword"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "content, flow, pcre..." }],
    run(v) {
      return ref([
        ["msg", "human-readable alert message"],
        ["sid", "unique rule signature ID (>=1000000 for local)"],
        ["rev", "rule revision number"],
        ["content", "match a byte/string in the payload"],
        ["nocase", "make the preceding content case-insensitive"],
        ["depth / offset", "limit where content is searched from start"],
        ["distance / within", "position relative to the previous content"],
        ["pcre", "match a Perl-compatible regular expression"],
        ["flow", "connection direction/state (to_server, established)"],
        ["classtype", "rule category from classification.config"],
        ["reference", "external reference (cve, url, ...)"],
        ["priority", "override the classtype priority (1=highest)"],
        ["http.uri / http.method / http.host", "Suricata HTTP sticky buffers"],
        ["dns.query", "match on the DNS query name"],
        ["tls.sni / tls.cert_subject", "match TLS SNI / certificate fields"],
        ["flowbits", "set/check stateful flags across rules"],
        ["threshold / detection_filter", "rate-limit alerting on a rule"],
      ], v.q);
    } },

  { id: "bt-grok-build", name: "Grok Pattern Builder", cat: "blueteam", desc: "Assemble a Logstash grok pattern from PATTERN:field tokens and literal text.", tags: ["grok", "logstash", "parse"],
    inputs: [{ k: "tokens", label: "Tokens (one 'PATTERN field' or 'lit:text' per line)", type: "textarea", rows: 5, value: "IPORHOST client\nlit: - \nUSER user\nlit:  [\nTIMESTAMP_ISO8601 ts\nlit:] \nWORD method" }],
    run(v) {
      const out = [];
      for (const l of lines(v.tokens)) {
        if (/^lit:/i.test(l)) { out.push(l.slice(4)); continue; }
        const [pat, field] = l.split(/\s+/);
        if (!(pat in GROK)) return { error: `Unknown grok pattern: ${pat} (see Grok Pattern Reference).` };
        out.push(field ? `%{${pat}:${field}}` : `%{${pat}}`);
      }
      if (!out.length) return "";
      return out.join("");
    } },

  { id: "bt-grok-test", name: "Grok Pattern Tester", cat: "blueteam", desc: "Test a grok pattern against a sample log line and show the captured fields as JSON.", tags: ["grok", "test", "logstash"],
    inputs: [
      { k: "pattern", label: "Grok pattern", type: "textarea", rows: 2, value: "%{IPV4:client} - %{USER:user} \\[%{TIMESTAMP_ISO8601:ts}\\] %{WORD:method}" },
      { k: "sample", label: "Sample line", type: "text", value: "192.0.2.10 - alice [2026-10-03T12:30:00Z] GET" },
    ],
    run(v) {
      if (!v.pattern || !v.sample) return "";
      const { out, missing } = grokToRegex(v.pattern);
      if (missing.length) return { error: `Unknown grok pattern(s): ${[...new Set(missing)].join(", ")}` };
      let re;
      try { re = new RegExp(out); } catch (e) { return { error: "Resolved regex is invalid: " + e.message }; }
      const m = re.exec(v.sample);
      if (!m) return "NO MATCH — the pattern did not match the sample line.";
      if (m.groups && Object.keys(m.groups).length) return "MATCH\n\n" + JSON.stringify(m.groups, null, 2);
      return "MATCH (no named fields captured).";
    } },

  { id: "bt-grok-ref", name: "Grok Pattern Reference", cat: "blueteam", desc: "The built-in grok base patterns available in the builder/tester, with their regex.", tags: ["grok", "reference", "regex"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "IP, TIME, NUMBER..." }],
    run(v) {
      const rows = Object.keys(GROK).map((k) => [k, GROK[k]]);
      return ref(rows, v.q) + "\n\n(Curated subset; references like %{IPV4} resolve recursively.)";
    } },

  { id: "bt-logstash-filter", name: "Logstash Filter Block Builder", cat: "blueteam", desc: "Build a Logstash filter{} block with grok, date and mutate stages.", tags: ["logstash", "grok", "pipeline"],
    inputs: [
      { k: "match", label: "grok match pattern", type: "textarea", rows: 2, value: "%{IPV4:client} %{WORD:method} %{NOTSPACE:request}" },
      { k: "field", label: "Source field", type: "text", value: "message" },
      { k: "dateField", label: "Date field to parse (optional)", type: "text", value: "ts" },
      { k: "remove", label: "mutate remove_field (comma-sep, optional)", type: "text", value: "message" },
    ],
    run(v) {
      if (!v.match) return "";
      const out = ["filter {", "  grok {", `    match => { "${v.field || "message"}" => "${S(v.match).replace(/"/g, '\\"')}" }`, "  }"];
      if (v.dateField && v.dateField.trim()) out.push("  date {", `    match => [ "${v.dateField.trim()}", "ISO8601" ]`, "  }");
      const rm = (v.remove || "").split(",").map((x) => x.trim()).filter(Boolean);
      if (rm.length) out.push("  mutate {", `    remove_field => [ ${rm.map((x) => `"${x}"`).join(", ")} ]`, "  }");
      out.push("}");
      return out.join("\n");
    } },

  { id: "bt-log-field-extract", name: "Log Field Extractor", cat: "blueteam", desc: "Apply a regex with named groups to each log line and output the captured fields as JSON.", tags: ["regex", "extract", "log", "parse"],
    inputs: [
      { k: "regex", label: "Regex with (?<name>...) groups", type: "textarea", rows: 2, value: "^(?<ip>\\S+) \\S+ (?<user>\\S+) \\[(?<ts>[^\\]]+)\\]" },
      { k: "text", label: "Log lines", type: "textarea", rows: 5, value: '198.51.100.7 - bob [03/Oct/2026:10:00:00 +0000]\n198.51.100.9 - eve [03/Oct/2026:10:00:05 +0000]' },
    ],
    run(v) {
      if (!v.regex || !v.text) return "";
      let re;
      try { re = new RegExp(v.regex); } catch (e) { return { error: "Invalid regex: " + e.message }; }
      const rows = [];
      for (const line of S(v.text).split(/\r?\n/)) {
        if (!line.trim()) continue;
        const m = re.exec(line);
        if (!m) { rows.push({ _nomatch: line }); continue; }
        if (m.groups && Object.keys(m.groups).length) rows.push({ ...m.groups });
        else rows.push(Object.fromEntries(m.slice(1).map((g, i) => [`g${i + 1}`, g])));
      }
      return JSON.stringify(rows, null, 2);
    } },

  { id: "bt-yara-rule", name: "YARA Rule Scaffold", cat: "blueteam", desc: "Generate a YARA rule skeleton with meta, string definitions and a condition.", tags: ["yara", "detection", "malware"],
    inputs: [
      { k: "name", label: "Rule name", type: "text", value: "Suspicious_Dropper" },
      { k: "author", label: "Author", type: "text", value: "analyst" },
      { k: "desc", label: "Description", type: "text", value: "Detects marker strings in a dropper sample" },
      { k: "type", label: "String type", type: "select", opts: ["text", "hex", "regex"], value: "text" },
      { k: "strings", label: "Strings (one per line)", type: "textarea", rows: 3, value: "cmd.exe /c\npowershell -enc" },
      { k: "condition", label: "Condition", type: "text", value: "any of them" },
    ],
    run(v) {
      if (!v.name) return { error: "Set a rule name." };
      const nm = S(v.name).replace(/[^A-Za-z0-9_]/g, "_");
      const defs = lines(v.strings).map((s, i) => {
        if (v.type === "hex") return `        $s${i + 1} = { ${s} }`;
        if (v.type === "regex") return `        $s${i + 1} = /${s}/`;
        return `        $s${i + 1} = "${s.replace(/"/g, '\\"')}"`;
      });
      return [
        `rule ${nm}`,
        `{`,
        `    meta:`,
        `        author = "${v.author || "analyst"}"`,
        `        description = "${(v.desc || "").replace(/"/g, '\\"')}"`,
        `        date = "${new Date().toISOString().slice(0, 10)}"`,
        `    strings:`,
        defs.join("\n") || `        $s1 = "example"`,
        `    condition:`,
        `        ${v.condition || "any of them"}`,
        `}`,
      ].join("\n");
    } },

  { id: "bt-wazuh-rule", name: "Wazuh / OSSEC Rule Scaffold", cat: "blueteam", desc: "Generate a Wazuh/OSSEC decoder-matching rule XML block.", tags: ["wazuh", "ossec", "rule", "xml"],
    inputs: [
      { k: "group", label: "Group name", type: "text", value: "local,authentication" },
      { k: "id", label: "Rule id (>=100000 for custom)", type: "text", value: "100100" },
      { k: "level", label: "Level (0-16)", type: "text", value: "10" },
      { k: "ifSid", label: "if_sid (parent rule, optional)", type: "text", value: "5716" },
      { k: "match", label: "match / field value", type: "text", value: "authentication failure" },
      { k: "desc", label: "Description", type: "text", value: "Repeated SSH authentication failure" },
    ],
    run(v) {
      const lvl = Math.max(0, Math.min(16, parseInt(v.level, 10) || 0));
      const inner = [v.ifSid ? `    <if_sid>${v.ifSid}</if_sid>` : null, v.match ? `    <match>${v.match}</match>` : null, `    <description>${v.desc || "Custom rule"}</description>`].filter(Boolean).join("\n");
      return [`<group name="${v.group || "local"}">`, `  <rule id="${v.id || 100100}" level="${lvl}">`, inner, `  </rule>`, `</group>`].join("\n");
    } },

  { id: "bt-eql-build", name: "Elastic EQL Query Builder", cat: "blueteam", desc: "Build an Elastic EQL event query (optionally a sequence) from category and conditions.", tags: ["eql", "elastic", "detection"],
    inputs: [
      { k: "category", label: "Event category", type: "select", opts: ["process", "network", "file", "registry", "authentication", "any"], value: "process" },
      { k: "conds", label: "Conditions (one per line)", type: "textarea", rows: 3, value: 'process.name == "cmd.exe"\nprocess.args : "*whoami*"' },
      { k: "sequence", label: "Wrap as a 2-event sequence", type: "checkbox", value: false },
    ],
    run(v) {
      const cat = v.category || "process";
      const conds = lines(v.conds);
      const where = conds.length ? conds.join(" and ") : "true";
      if (v.sequence) {
        return `sequence by host.id with maxspan=5m\n  [ ${cat} where ${where} ]\n  [ process where event.type == "start" ]`;
      }
      return `${cat} where ${where}`;
    } },

  { id: "bt-es-dsl-build", name: "Elasticsearch Query DSL Builder", cat: "blueteam", desc: "Build an Elasticsearch bool query (must/filter/should) plus an optional range filter.", tags: ["elasticsearch", "dsl", "query"],
    inputs: [
      { k: "must", label: "must match (one 'field:value' per line)", type: "textarea", rows: 2, value: "event.action:logon-failed" },
      { k: "should", label: "should match (optional)", type: "textarea", rows: 2, value: "" },
      { k: "rangeField", label: "range field (optional)", type: "text", value: "@timestamp" },
      { k: "gte", label: "range gte", type: "text", value: "now-24h" },
    ],
    run(v) {
      const term = (l) => { const i = l.indexOf(":"); const f = l.slice(0, i), val = l.slice(i + 1); return { match: { [f]: val } }; };
      const bool = {};
      const must = lines(v.must).filter((l) => l.includes(":")).map(term);
      const should = lines(v.should).filter((l) => l.includes(":")).map(term);
      const filter = [];
      if (v.rangeField && v.gte) filter.push({ range: { [v.rangeField]: { gte: v.gte } } });
      if (must.length) bool.must = must;
      if (should.length) { bool.should = should; bool.minimum_should_match = 1; }
      if (filter.length) bool.filter = filter;
      if (!Object.keys(bool).length) return { error: "Add at least one must/should/range clause." };
      return JSON.stringify({ query: { bool } }, null, 2);
    } },

  // ======================= LOG FORMAT PARSERS / DECODERS =======================
  { id: "bt-cef-parse", name: "CEF Log Parser", cat: "blueteam", desc: "Parse an ArcSight CEF log line into its header fields and extension key=value pairs.", tags: ["cef", "arcsight", "parse"],
    inputs: [{ k: "line", label: "CEF line", type: "textarea", rows: 3, value: "CEF:0|Security|threatmanager|1.0|100|worm detected|10|src=192.0.2.1 dst=198.51.100.2 spt=1232" }],
    run(v) {
      const raw = S(v.line).trim();
      if (!raw) return "";
      const i = raw.indexOf("CEF:");
      if (i < 0) return { error: "Not a CEF line (missing 'CEF:' prefix)." };
      const body = raw.slice(i + 4);
      // split header on unescaped pipes, max 8 fields (last = extension)
      const parts = []; let cur = "";
      for (let j = 0; j < body.length; j++) {
        const c = body[j];
        if (c === "\\" && j + 1 < body.length) { cur += body[j + 1]; j++; continue; }
        if (c === "|" && parts.length < 7) { parts.push(cur); cur = ""; continue; }
        cur += c;
      }
      parts.push(cur);
      if (parts.length < 8) return { error: "Malformed CEF header (expected 7 pipe-separated header fields + extension)." };
      const names = ["CEF Version", "Device Vendor", "Device Product", "Device Version", "Signature ID", "Name", "Severity"];
      const head = names.map((n, k) => `${n}: ${parts[k]}`);
      const ext = {};
      const ere = /([^\s=]+)=((?:\\.|[^\\])*?)(?=\s+[^\s=]+=|$)/g;
      let m; const extStr = parts[7] || "";
      while ((m = ere.exec(extStr))) ext[m[1]] = m[2].replace(/\\(.)/g, "$1");
      const extLines = Object.keys(ext).map((k) => `  ${k} = ${ext[k]}`);
      return head.join("\n") + "\n\nExtension:\n" + (extLines.join("\n") || "  (none)");
    } },

  { id: "bt-cef-build", name: "CEF Log Builder", cat: "blueteam", desc: "Build a well-formed ArcSight CEF log line from header fields and extension pairs.", tags: ["cef", "arcsight", "build"],
    inputs: [
      { k: "vendor", label: "Device Vendor", type: "text", value: "Darknode" },
      { k: "product", label: "Device Product", type: "text", value: "Sensor" },
      { k: "version", label: "Device Version", type: "text", value: "1.0" },
      { k: "sig", label: "Signature ID", type: "text", value: "100" },
      { k: "name", label: "Name", type: "text", value: "Port scan detected" },
      { k: "severity", label: "Severity (0-10)", type: "text", value: "6" },
      { k: "ext", label: "Extension (one 'key=value' per line)", type: "textarea", rows: 3, value: "src=192.0.2.5\ndst=198.51.100.8\nspt=44321" },
    ],
    run(v) {
      const esc = (s) => S(s).replace(/\\/g, "\\\\").replace(/\|/g, "\\|");
      const header = ["CEF:0", esc(v.vendor), esc(v.product), esc(v.version), esc(v.sig), esc(v.name), esc(v.severity)].join("|");
      const ext = lines(v.ext).map((l) => { const i = l.indexOf("="); return i < 0 ? l : `${l.slice(0, i)}=${l.slice(i + 1).replace(/\\/g, "\\\\").replace(/=/g, "\\=")}`; }).join(" ");
      return header + "|" + ext;
    } },

  { id: "bt-leef-parse", name: "LEEF Log Parser", cat: "blueteam", desc: "Parse an IBM QRadar LEEF (1.0/2.0) log line into header fields and attributes.", tags: ["leef", "qradar", "parse"],
    inputs: [{ k: "line", label: "LEEF line", type: "textarea", rows: 3, value: "LEEF:2.0|Lancope|StealthWatch|1.0|41|^|src=192.0.2.1^dst=198.51.100.2^spt=1232" }],
    run(v) {
      const raw = S(v.line).trim();
      if (!raw) return "";
      if (!raw.startsWith("LEEF:")) return { error: "Not a LEEF line (missing 'LEEF:' prefix)." };
      const parts = raw.split("|");
      const ver = parts[0].slice(5);
      const names = ["Vendor", "Product", "Version", "Event ID"];
      let attrStart = 5, delim = "\t";
      // LEEF 2.0 may carry an explicit attribute-delimiter field before the attributes
      if (/^2/.test(ver) && parts.length > 6 && parts[5] !== undefined && !parts[5].includes("=") && parts[5].length <= 4) {
        attrStart = 6;
        const d = parts[5];
        if (/^x09$/i.test(d) || /^0x09$/i.test(d) || d === "\\t" || d === "\t") delim = "\t";
        else if (/^x[0-9a-f]{2}$/i.test(d)) delim = String.fromCharCode(parseInt(d.slice(1), 16));
        else if (/^0x[0-9a-f]{2}$/i.test(d)) delim = String.fromCharCode(parseInt(d.slice(2), 16));
        else delim = d;
      }
      const head = [`LEEF Version: ${ver}`, ...names.map((n, k) => `${n}: ${parts[k + 1] !== undefined ? parts[k + 1] : ""}`)];
      const attrStr = parts.slice(attrStart).join("|");
      // if the chosen delimiter is absent, fall back to tab then space
      let useDelim = delim;
      if (!attrStr.includes(useDelim)) { if (attrStr.includes("\t")) useDelim = "\t"; else if (attrStr.includes(" ")) useDelim = " "; }
      const attrs = attrStr.split(useDelim).filter((x) => x.includes("=")).map((kv) => { const i = kv.indexOf("="); return `  ${kv.slice(0, i)} = ${kv.slice(i + 1)}`; });
      return head.join("\n") + `\n(attribute delimiter: ${JSON.stringify(useDelim)})\n\nAttributes:\n` + (attrs.join("\n") || "  (none)");
    } },

  { id: "bt-syslog-parse", name: "RFC 5424 Syslog Parser", cat: "blueteam", desc: "Parse an RFC 5424 syslog message into PRI (facility/severity), header fields and message.", tags: ["syslog", "rfc5424", "parse"],
    inputs: [{ k: "line", label: "Syslog line", type: "textarea", rows: 3, value: '<34>1 2026-10-03T22:14:15.003Z host1 su 1234 ID47 - BOM\'su root\' failed for user on /dev/pts/8' }],
    run(v) {
      const raw = S(v.line).trim();
      if (!raw) return "";
      const m = raw.match(/^<(\d{1,3})>(\d)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:(-)|(\[.*?\](?:\s*\[.*?\])*))\s?([\s\S]*)$/);
      if (!m) return { error: "Does not match RFC 5424 format (<PRI>VERSION TIMESTAMP HOST APP PROCID MSGID SD MSG)." };
      const pri = parseInt(m[1], 10);
      const FAC = ["kernel", "user-level", "mail", "system daemons", "security/authorization", "syslogd", "line printer", "network news", "UUCP", "clock daemon", "security/authorization (private)", "FTP", "NTP", "log audit", "log alert", "clock daemon (note 2)", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"];
      const SEV = ["Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug"];
      const fac = pri >> 3, sev = pri & 7;
      return [
        `PRI: ${pri}  ->  facility ${fac} (${FAC[fac] || "?"}), severity ${sev} (${SEV[sev] || "?"})`,
        `Version: ${m[2]}`,
        `Timestamp: ${m[3]}`,
        `Hostname: ${m[4]}`,
        `App-Name: ${m[5]}`,
        `ProcID: ${m[6]}`,
        `MsgID: ${m[7]}`,
        `Structured-Data: ${m[8] || m[9] || "-"}`,
        `Message: ${m[10] || ""}`,
      ].join("\n");
    } },

  { id: "bt-syslog-pri", name: "Syslog PRI Decoder", cat: "blueteam", desc: "Decode a syslog PRI value into its facility and severity, or compute PRI from them.", tags: ["syslog", "pri", "facility", "severity"],
    inputs: [
      { k: "mode", label: "Mode", type: "select", opts: ["PRI -> facility/severity", "facility+severity -> PRI"], value: "PRI -> facility/severity" },
      { k: "pri", label: "PRI value", type: "text", value: "34" },
      { k: "facility", label: "Facility (0-23)", type: "text", value: "4" },
      { k: "severity", label: "Severity (0-7)", type: "text", value: "2" },
    ],
    run(v) {
      const FAC = ["kernel", "user-level", "mail", "system daemons", "security/authorization", "syslogd", "line printer", "network news", "UUCP", "clock daemon", "security/authorization (private)", "FTP", "NTP", "log audit", "log alert", "clock daemon", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"];
      const SEV = ["Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug"];
      if (v.mode === "facility+severity -> PRI") {
        const f = parseInt(v.facility, 10), s = parseInt(v.severity, 10);
        if (!(f >= 0 && f <= 23) || !(s >= 0 && s <= 7)) return { error: "Facility must be 0-23 and severity 0-7." };
        return `PRI = facility*8 + severity = ${f}*8 + ${s} = ${f * 8 + s}\nfacility ${f} (${FAC[f]}), severity ${s} (${SEV[s]})`;
      }
      const pri = parseInt(v.pri, 10);
      if (!(pri >= 0 && pri <= 191)) return { error: "PRI must be 0-191." };
      const f = pri >> 3, s = pri & 7;
      return `PRI ${pri}\nfacility = ${f} (${FAC[f]})\nseverity = ${s} (${SEV[s]})`;
    } },

  { id: "bt-syslog-ref", name: "Syslog Facility / Severity Reference", cat: "blueteam", desc: "RFC 5424 syslog facility (0-23) and severity (0-7) code tables.", tags: ["syslog", "reference", "rfc5424"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "auth, error, local..." }],
    run(v) {
      const FAC = ["kernel messages", "user-level messages", "mail system", "system daemons", "security/authorization messages", "messages generated internally by syslogd", "line printer subsystem", "network news subsystem", "UUCP subsystem", "clock daemon", "security/authorization messages (private)", "FTP daemon", "NTP subsystem", "log audit", "log alert", "clock daemon (note 2)", "local use 0", "local use 1", "local use 2", "local use 3", "local use 4", "local use 5", "local use 6", "local use 7"];
      const SEV = ["Emergency - system is unusable", "Alert - action must be taken immediately", "Critical - critical conditions", "Error - error conditions", "Warning - warning conditions", "Notice - normal but significant", "Informational - informational messages", "Debug - debug-level messages"];
      const rows = [["FACILITY", "", ""], ...FAC.map((d, i) => [String(i), "facility", d]), ["SEVERITY", "", ""], ...SEV.map((d, i) => [String(i), "severity", d])];
      return ref(rows, v.q);
    } },

  { id: "bt-logfmt-parse", name: "logfmt Parser", cat: "blueteam", desc: "Parse a logfmt line (key=value, quoted values supported) into JSON.", tags: ["logfmt", "parse", "json"],
    inputs: [{ k: "line", label: "logfmt line", type: "textarea", rows: 2, value: 'level=error msg="connection refused" src=192.0.2.9 attempt=3 ok=false' }],
    run(v) {
      const raw = S(v.line).trim();
      if (!raw) return "";
      const out = {};
      const re = /([^\s=]+)=(?:"((?:\\.|[^"\\])*)"|(\S*))/g;
      let m, any = false;
      while ((m = re.exec(raw))) { any = true; out[m[1]] = m[2] !== undefined ? m[2].replace(/\\(.)/g, "$1") : m[3]; }
      if (!any) return { error: "No key=value pairs found." };
      return JSON.stringify(out, null, 2);
    } },

  { id: "bt-accesslog-parse", name: "Apache/Nginx Access Log Parser", cat: "blueteam", desc: "Parse a Common or Combined Log Format access-log line into named fields.", tags: ["apache", "nginx", "clf", "parse"],
    inputs: [{ k: "line", label: "Access log line", type: "textarea", rows: 3, value: '198.51.100.7 - frank [03/Oct/2026:13:55:36 +0000] "GET /admin HTTP/1.1" 403 512 "http://example.com/" "Mozilla/5.0"' }],
    run(v) {
      const raw = S(v.line).trim();
      if (!raw) return "";
      const m = raw.match(/^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?/);
      if (!m) return { error: "Does not match Common/Combined Log Format." };
      const req = m[5].split(/\s+/);
      const out = [
        `Remote host: ${m[1]}`, `Identd: ${m[2]}`, `User: ${m[3]}`, `Time: ${m[4]}`,
        `Request: ${m[5]}`, `  Method: ${req[0] || ""}`, `  Path:   ${req[1] || ""}`, `  Proto:  ${req[2] || ""}`,
        `Status: ${m[6]}`, `Bytes: ${m[7]}`,
      ];
      if (m[8] !== undefined) out.push(`Referer: ${m[8]}`, `User-Agent: ${m[9]}`);
      return out.join("\n");
    } },

  { id: "bt-iis-log-parse", name: "IIS W3C Log Parser", cat: "blueteam", desc: "Map an IIS W3C extended log line to its fields using the #Fields header.", tags: ["iis", "w3c", "parse"],
    inputs: [
      { k: "fields", label: "#Fields line", type: "text", value: "date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status time-taken" },
      { k: "line", label: "Log line", type: "text", value: "2026-10-03 13:55:36 192.0.2.5 GET /login - 443 - 198.51.100.7 Mozilla/5.0 401 0 0 15" },
    ],
    run(v) {
      let fields = S(v.fields).replace(/^#Fields:\s*/i, "").trim().split(/\s+/).filter(Boolean);
      if (!fields.length) return { error: "Provide the #Fields header." };
      const vals = S(v.line).trim().split(/\s+/);
      if (!vals.length || !vals[0]) return "";
      return fields.map((f, i) => `${f}: ${vals[i] !== undefined ? vals[i] : ""}`).join("\n") + (vals.length !== fields.length ? `\n\n(warning: ${vals.length} values vs ${fields.length} fields)` : "");
    } },

  { id: "bt-vpcflow-parse", name: "AWS VPC Flow Log Parser", cat: "blueteam", desc: "Parse an AWS VPC Flow Log v2 (default-format) record into named fields.", tags: ["aws", "vpcflow", "parse", "network"],
    inputs: [{ k: "line", label: "Flow log record", type: "text", value: "2 123456789012 eni-0abc12 192.0.2.5 198.51.100.8 44321 443 6 20 4000 1696339200 1696339260 ACCEPT OK" }],
    run(v) {
      const names = ["version", "account-id", "interface-id", "srcaddr", "dstaddr", "srcport", "dstport", "protocol", "packets", "bytes", "start", "end", "action", "log-status"];
      const vals = S(v.line).trim().split(/\s+/);
      if (vals.length < 2) return "";
      const out = names.map((n, i) => {
        let val = vals[i] !== undefined ? vals[i] : "";
        if (n === "protocol" && IP_PROTO[val]) val += ` (${IP_PROTO[val]})`;
        if ((n === "start" || n === "end") && /^\d{10}$/.test(val)) val += ` (${new Date(parseInt(val, 10) * 1000).toISOString()})`;
        return `${n}: ${val}`;
      });
      return out.join("\n") + (vals.length !== 14 ? `\n\n(default v2 format expects 14 fields; got ${vals.length})` : "");
    } },

  { id: "bt-ps-decode", name: "PowerShell EncodedCommand Decoder", cat: "blueteam", desc: "Decode a PowerShell -EncodedCommand base64 value (UTF-16LE) back to the original script.", tags: ["powershell", "base64", "decode", "utf16"],
    inputs: [{ k: "b64", label: "Base64 (-enc) value", type: "textarea", rows: 3, value: "dwBoAG8AYQBtAGkA" }],
    run(v) {
      const s = S(v.b64).trim().replace(/\s+/g, "");
      if (!s) return "";
      let bin;
      try { bin = atob(s.replace(/-/g, "+").replace(/_/g, "/")); } catch (e) { return { error: "Not valid base64." }; }
      const u = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
      try { return new TextDecoder("utf-16le").decode(u); } catch (e) { return { error: "Could not decode as UTF-16LE." }; }
    } },

  { id: "bt-defang", name: "URL / IP Defanger", cat: "blueteam", desc: "Defang or refang URLs, domains and IPs (http->hxxp, . -> [.]) for safe sharing in reports.", tags: ["defang", "refang", "ioc", "report"],
    inputs: [
      { k: "text", label: "Text", type: "textarea", rows: 3, value: "http://evil.example.com/path and 192.0.2.5 contacted mail@evil.example.com" },
      { k: "mode", label: "Mode", type: "select", opts: ["Defang", "Refang"], value: "Defang" },
    ],
    run(v) {
      if (!v.text) return "";
      let t = v.text;
      if (v.mode === "Defang") {
        t = t.replace(/http(s?)/gi, "hxxp$1");
        t = t.replace(/\./g, "[.]");
        t = t.replace(/@/g, "[@]");
      } else {
        t = t.replace(/\[\.\]/g, ".").replace(/\[:\/\/\]/g, "://").replace(/\[@\]/g, "@").replace(/\[at\]/gi, "@");
        t = t.replace(/hxxp(s?)/gi, "http$1");
      }
      return t;
    } },

  // ======================= SCORING / SEVERITY =======================
  { id: "bt-cvss4-parse", name: "CVSS v4.0 Vector Parser", cat: "blueteam", desc: "Parse and validate a CVSS v4.0 vector, expand each metric, and give its nomenclature (does not compute the numeric score).", tags: ["cvss", "cvss4", "vector", "parse"],
    inputs: [{ k: "vector", label: "CVSS v4.0 vector", type: "textarea", rows: 2, value: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" }],
    run(v) {
      const raw = S(v.vector).trim();
      if (!raw) return "";
      if (!/^CVSS:4\.0\//.test(raw)) return { error: "Vector must start with CVSS:4.0/." };
      const M = {
        AV: ["Attack Vector", { N: "Network", A: "Adjacent", L: "Local", P: "Physical" }],
        AC: ["Attack Complexity", { L: "Low", H: "High" }],
        AT: ["Attack Requirements", { N: "None", P: "Present" }],
        PR: ["Privileges Required", { N: "None", L: "Low", H: "High" }],
        UI: ["User Interaction", { N: "None", P: "Passive", A: "Active" }],
        VC: ["Vuln Confidentiality", { H: "High", L: "Low", N: "None" }],
        VI: ["Vuln Integrity", { H: "High", L: "Low", N: "None" }],
        VA: ["Vuln Availability", { H: "High", L: "Low", N: "None" }],
        SC: ["Subsequent Confidentiality", { H: "High", L: "Low", N: "None" }],
        SI: ["Subsequent Integrity", { H: "High", L: "Low", N: "None" }],
        SA: ["Subsequent Availability", { H: "High", L: "Low", N: "None" }],
        E: ["Exploit Maturity", { X: "Not Defined", A: "Attacked", P: "PoC", U: "Unreported" }],
        CR: ["Confidentiality Req.", { X: "Not Defined", H: "High", M: "Medium", L: "Low" }],
        IR: ["Integrity Req.", { X: "Not Defined", H: "High", M: "Medium", L: "Low" }],
        AR: ["Availability Req.", { X: "Not Defined", H: "High", M: "Medium", L: "Low" }],
        MAV: ["Modified AV", { X: "Not Defined", N: "Network", A: "Adjacent", L: "Local", P: "Physical" }],
        MAC: ["Modified AC", { X: "Not Defined", L: "Low", H: "High" }],
        MAT: ["Modified AT", { X: "Not Defined", N: "None", P: "Present" }],
        MPR: ["Modified PR", { X: "Not Defined", N: "None", L: "Low", H: "High" }],
        MUI: ["Modified UI", { X: "Not Defined", N: "None", P: "Passive", A: "Active" }],
        MVC: ["Modified VC", { X: "Not Defined", H: "High", L: "Low", N: "None" }],
        MVI: ["Modified VI", { X: "Not Defined", H: "High", L: "Low", N: "None" }],
        MVA: ["Modified VA", { X: "Not Defined", H: "High", L: "Low", N: "None" }],
        MSC: ["Modified SC", { X: "Not Defined", H: "High", L: "Low", N: "None" }],
        MSI: ["Modified SI", { X: "Not Defined", S: "Safety", H: "High", L: "Low", N: "None" }],
        MSA: ["Modified SA", { X: "Not Defined", S: "Safety", H: "High", L: "Low", N: "None" }],
        S: ["Safety", { X: "Not Defined", N: "Negligible", P: "Present" }],
        AU: ["Automatable", { X: "Not Defined", N: "No", Y: "Yes" }],
        R: ["Recovery", { X: "Not Defined", A: "Automatic", U: "User", I: "Irrecoverable" }],
        V: ["Value Density", { X: "Not Defined", D: "Diffuse", C: "Concentrated" }],
        RE: ["Response Effort", { X: "Not Defined", L: "Low", M: "Moderate", H: "High" }],
        U: ["Provider Urgency", { X: "Not Defined", Clear: "Clear", Green: "Green", Amber: "Amber", Red: "Red" }],
      };
      const pairs = raw.split("/").slice(1);
      const seen = {}; const outRows = []; const errs = [];
      for (const p of pairs) {
        const [k, val] = p.split(":");
        if (!M[k]) { errs.push(`unknown metric ${k}`); continue; }
        if (!(val in M[k][1])) { errs.push(`invalid value ${val} for ${k}`); continue; }
        seen[k] = val; outRows.push(`${k} (${M[k][0]}): ${M[k][1][val]}`);
      }
      const baseReq = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"];
      const missing = baseReq.filter((k) => !(k in seen));
      if (missing.length) errs.push(`missing required base metric(s): ${missing.join(", ")}`);
      if (errs.length) return { error: errs.join("; ") };
      const hasT = seen.E && seen.E !== "X";
      const envKeys = ["CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA"];
      const hasE = envKeys.some((k) => seen[k] && seen[k] !== "X");
      const nom = "CVSS-B" + (hasT ? "T" : "") + (hasE ? "E" : "");
      return `Nomenclature: ${nom}\n\n` + outRows.join("\n") + `\n\nNote: this validates/expands the vector. The official v4.0 numeric score requires the FIRST CVSS-B lookup table and is not computed here.`;
    } },

  { id: "bt-cvss-severity-ref", name: "CVSS Severity Rating Reference", cat: "blueteam", desc: "Qualitative severity rating bands for CVSS v2, v3.x and v4.0 base scores.", tags: ["cvss", "severity", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "critical, v2, medium..." }],
    run(v) {
      return ref([
        ["v3.x / v4.0", "None", "0.0"],
        ["v3.x / v4.0", "Low", "0.1 - 3.9"],
        ["v3.x / v4.0", "Medium", "4.0 - 6.9"],
        ["v3.x / v4.0", "High", "7.0 - 8.9"],
        ["v3.x / v4.0", "Critical", "9.0 - 10.0"],
        ["v2.0", "Low", "0.0 - 3.9"],
        ["v2.0", "Medium", "4.0 - 6.9"],
        ["v2.0", "High", "7.0 - 10.0"],
      ], v.q);
    } },

  { id: "bt-severity-normalize", name: "Severity Normalizer", cat: "blueteam", desc: "Normalize a CVSS score, qualitative label or syslog severity onto a single 0-4 (Informational-Critical) scale.", tags: ["severity", "normalize", "triage"],
    inputs: [
      { k: "scale", label: "Input scale", type: "select", opts: ["CVSS (0-10)", "Qualitative (none/low/medium/high/critical)", "Syslog severity (0-7)"], value: "CVSS (0-10)" },
      { k: "value", label: "Value", type: "text", value: "8.1" },
    ],
    run(v) {
      const LVL = ["Informational", "Low", "Medium", "High", "Critical"];
      let lvl;
      if (v.scale === "CVSS (0-10)") {
        const n = num(v.value);
        if (isNaN(n) || n < 0 || n > 10) return { error: "Enter a CVSS score 0.0-10.0." };
        lvl = n >= 9 ? 4 : n >= 7 ? 3 : n >= 4 ? 2 : n >= 0.1 ? 1 : 0;
      } else if (v.scale.startsWith("Qualitative")) {
        const map = { none: 0, informational: 0, info: 0, low: 1, medium: 2, moderate: 2, high: 3, critical: 4, severe: 4 };
        lvl = map[S(v.value).toLowerCase().trim()];
        if (lvl === undefined) return { error: "Use none/low/medium/high/critical." };
      } else {
        const n = parseInt(v.value, 10);
        if (!(n >= 0 && n <= 7)) return { error: "Syslog severity is 0-7." };
        lvl = n <= 2 ? 4 : n === 3 ? 3 : n === 4 ? 2 : n === 5 ? 1 : 0; // emerg/alert/crit->Crit, err->High, warn->Med, notice->Low, info/debug->Info
      }
      return `Normalized level: ${lvl}/4 = ${LVL[lvl]}\n(Scheme: Critical=4, High=3, Medium=2, Low=1, Informational=0.)`;
    } },

  { id: "bt-epss-explain", name: "EPSS Score Explainer", cat: "blueteam", desc: "Interpret an EPSS probability and percentile and explain how they differ from CVSS severity.", tags: ["epss", "exploit", "prioritization"],
    inputs: [
      { k: "score", label: "EPSS score (0-1)", type: "text", value: "0.42" },
      { k: "percentile", label: "EPSS percentile (0-100, optional)", type: "text", value: "96" },
    ],
    run(v) {
      const s = num(v.score);
      if (isNaN(s) || s < 0 || s > 1) return { error: "EPSS score is a probability between 0 and 1." };
      const out = [`EPSS score ${s} = ~${(s * 100).toFixed(1)}% estimated probability that this vulnerability will be exploited in the wild in the next 30 days.`];
      if (v.percentile && v.percentile.trim()) {
        const p = num(v.percentile);
        if (!isNaN(p)) out.push(`Percentile ${p}: this CVE's score is higher than about ${p}% of all scored CVEs (relative ranking).`);
      }
      out.push("", "EPSS measures LIKELIHOOD of exploitation, not impact. CVSS measures severity/impact. Use them together: a high-CVSS, low-EPSS bug may be less urgent than a medium-CVSS, high-EPSS one that is actively exploited.");
      out.push("", "Example prioritization policy (tune to your org): EPSS >= 0.1 (10%) warrants prompt review; combine with CVSS and asset exposure for final ranking.");
      return out.join("\n");
    } },

  { id: "bt-incident-priority", name: "Incident Priority Matrix", cat: "blueteam", desc: "Derive an ITIL-style incident priority (P1-P5) from impact and urgency.", tags: ["incident", "priority", "itil", "triage"],
    inputs: [
      { k: "impact", label: "Impact", type: "select", opts: ["High", "Medium", "Low"], value: "High" },
      { k: "urgency", label: "Urgency", type: "select", opts: ["High", "Medium", "Low"], value: "High" },
    ],
    run(v) {
      const idx = { High: 0, Medium: 1, Low: 2 };
      // rows = urgency, cols = impact
      const table = [[1, 2, 3], [2, 3, 4], [3, 4, 5]];
      const labels = { 1: "P1 - Critical", 2: "P2 - High", 3: "P3 - Medium", 4: "P4 - Low", 5: "P5 - Planning" };
      const u = idx[v.urgency], i = idx[v.impact];
      if (u === undefined || i === undefined) return { error: "Pick impact and urgency." };
      const p = table[u][i];
      const resp = { 1: "immediate, all-hands", 2: "within hours", 3: "within 1 business day", 4: "within a few days", 5: "scheduled / backlog" };
      return `Impact: ${v.impact}, Urgency: ${v.urgency}\nPriority: ${labels[p]}\nTypical response target: ${resp[p]}\n\n(ITIL impact x urgency matrix; tune the response targets to your SLA.)`;
    } },

  // ======================= WINDOWS DEFENDER REFERENCES =======================
  { id: "bt-win-audit-policy", name: "Windows Audit Policy Reference", cat: "blueteam", desc: "Windows advanced audit policy categories and their subcategories (auditpol).", tags: ["windows", "auditpol", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "logon, process, policy..." }],
    run(v) {
      const data = {
        "Account Logon": ["Credential Validation", "Kerberos Authentication Service", "Kerberos Service Ticket Operations", "Other Account Logon Events"],
        "Account Management": ["User Account Management", "Computer Account Management", "Security Group Management", "Distribution Group Management", "Application Group Management", "Other Account Management Events"],
        "Detailed Tracking": ["Process Creation", "Process Termination", "DPAPI Activity", "RPC Events", "Plug and Play Events", "Token Right Adjusted Events"],
        "DS Access": ["Directory Service Access", "Directory Service Changes", "Directory Service Replication", "Detailed Directory Service Replication"],
        "Logon/Logoff": ["Logon", "Logoff", "Account Lockout", "Special Logon", "Other Logon/Logoff Events", "Network Policy Server", "User / Device Claims", "Group Membership", "IPsec Main Mode", "IPsec Quick Mode", "IPsec Extended Mode"],
        "Object Access": ["File System", "Registry", "Kernel Object", "SAM", "Certification Services", "Application Generated", "Handle Manipulation", "File Share", "Detailed File Share", "Filtering Platform Packet Drop", "Filtering Platform Connection", "Removable Storage", "Central Policy Staging", "Other Object Access Events"],
        "Policy Change": ["Audit Policy Change", "Authentication Policy Change", "Authorization Policy Change", "MPSSVC Rule-Level Policy Change", "Filtering Platform Policy Change", "Other Policy Change Events"],
        "Privilege Use": ["Sensitive Privilege Use", "Non Sensitive Privilege Use", "Other Privilege Use Events"],
        "System": ["Security State Change", "Security System Extension", "System Integrity", "IPsec Driver", "Other System Events"],
      };
      const rows = [];
      for (const cat of Object.keys(data)) for (const sub of data[cat]) rows.push([cat, sub]);
      return ref(rows, v.q);
    } },

  { id: "bt-win-event-ids", name: "Windows Security Event ID Reference", cat: "blueteam", desc: "Security-relevant Windows Security-log event IDs used in detections.", tags: ["windows", "event id", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "logon, 4688, kerberos..." }],
    run(v) {
      return ref([
        ["4624", "An account was successfully logged on"],
        ["4625", "An account failed to log on"],
        ["4634", "An account was logged off"],
        ["4647", "User initiated logoff"],
        ["4648", "Logon attempted using explicit credentials"],
        ["4672", "Special privileges assigned to new logon"],
        ["4673", "A privileged service was called"],
        ["4688", "A new process has been created"],
        ["4689", "A process has exited"],
        ["4697", "A service was installed in the system"],
        ["4698", "A scheduled task was created"],
        ["4699", "A scheduled task was deleted"],
        ["4700", "A scheduled task was enabled"],
        ["4702", "A scheduled task was updated"],
        ["4719", "System audit policy was changed"],
        ["4720", "A user account was created"],
        ["4722", "A user account was enabled"],
        ["4723", "An attempt was made to change an account's password"],
        ["4724", "An attempt was made to reset an account's password"],
        ["4725", "A user account was disabled"],
        ["4726", "A user account was deleted"],
        ["4728", "A member was added to a security-enabled global group"],
        ["4732", "A member was added to a security-enabled local group"],
        ["4740", "A user account was locked out"],
        ["4756", "A member was added to a security-enabled universal group"],
        ["4768", "A Kerberos authentication ticket (TGT) was requested"],
        ["4769", "A Kerberos service ticket was requested"],
        ["4771", "Kerberos pre-authentication failed"],
        ["4776", "The domain controller attempted to validate credentials (NTLM)"],
        ["4798", "A user's local group membership was enumerated"],
        ["4799", "A security-enabled local group membership was enumerated"],
        ["4964", "Special groups have been assigned to a new logon"],
        ["5140", "A network share object was accessed"],
        ["5145", "A network share object was checked for access (detailed)"],
        ["1102", "The audit log was cleared"],
      ], v.q);
    } },

  { id: "bt-sysmon-ids", name: "Sysmon Event ID Reference", cat: "blueteam", desc: "Sysmon operational-log event IDs and what each one records.", tags: ["sysmon", "event id", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "process, network, dns..." }],
    run(v) {
      return ref([
        ["1", "Process creation"],
        ["2", "A process changed a file creation time"],
        ["3", "Network connection"],
        ["4", "Sysmon service state changed"],
        ["5", "Process terminated"],
        ["6", "Driver loaded"],
        ["7", "Image (DLL) loaded"],
        ["8", "CreateRemoteThread"],
        ["9", "RawAccessRead"],
        ["10", "ProcessAccess"],
        ["11", "FileCreate"],
        ["12", "Registry object added or deleted"],
        ["13", "Registry value set"],
        ["14", "Registry object renamed"],
        ["15", "FileCreateStreamHash (alternate data stream)"],
        ["16", "Sysmon config changed"],
        ["17", "Pipe created"],
        ["18", "Pipe connected"],
        ["19", "WmiEventFilter activity"],
        ["20", "WmiEventConsumer activity"],
        ["21", "WmiEventConsumerToFilter activity"],
        ["22", "DNS query"],
        ["23", "FileDelete (archived)"],
        ["24", "Clipboard change"],
        ["25", "Process tampering (image hollowing/herpaderping)"],
        ["26", "FileDeleteDetected (not archived)"],
        ["255", "Sysmon error"],
      ], v.q);
    } },

  { id: "bt-win-logon-types", name: "Windows Logon Type Reference", cat: "blueteam", desc: "Windows logon type codes (the LogonType field in 4624/4625) and their meaning.", tags: ["windows", "logon", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "network, rdp, service..." }],
    run(v) {
      return ref([
        ["2", "Interactive", "logon at the console (keyboard)"],
        ["3", "Network", "access to shares/printers over the network"],
        ["4", "Batch", "scheduled task / batch job"],
        ["5", "Service", "a service started by the Service Control Manager"],
        ["7", "Unlock", "workstation unlocked"],
        ["8", "NetworkCleartext", "network logon sending cleartext credentials (e.g. IIS basic auth)"],
        ["9", "NewCredentials", "RunAs /netonly - new credentials for network connections"],
        ["10", "RemoteInteractive", "Remote Desktop (RDP)"],
        ["11", "CachedInteractive", "logon with cached domain credentials (DC unreachable)"],
        ["12", "CachedRemoteInteractive", "cached RemoteInteractive"],
        ["13", "CachedUnlock", "cached unlock"],
      ], v.q);
    } },

  { id: "bt-logon-status", name: "Windows Logon Failure Status Codes", cat: "blueteam", desc: "Decode the Status / Sub Status codes in Windows 4625 failed-logon events.", tags: ["windows", "4625", "status", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "password, locked, disabled..." }],
    run(v) {
      return ref([
        ["0xC0000064", "user name does not exist"],
        ["0xC000006A", "user name correct but password wrong"],
        ["0xC000006D", "bad user name or authentication information (generic)"],
        ["0xC000006E", "account restriction prevents logon"],
        ["0xC000006F", "logon outside authorized hours"],
        ["0xC0000070", "logon from an unauthorized workstation"],
        ["0xC0000071", "password has expired"],
        ["0xC0000072", "account is currently disabled"],
        ["0xC0000133", "clock skew between the DC and the client too great"],
        ["0xC0000193", "account has expired"],
        ["0xC0000224", "user must change password at next logon"],
        ["0xC0000234", "account is currently locked out"],
      ], v.q);
    } },

  { id: "bt-kerberos-ref", name: "Kerberos Codes Reference", cat: "blueteam", desc: "Kerberos ticket encryption types and common failure codes seen in 4768/4769/4771.", tags: ["kerberos", "4769", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "rc4, aes, preauth..." }],
    run(v) {
      return ref([
        ["etype 0x1", "DES-CBC-CRC (legacy, weak)"],
        ["etype 0x3", "DES-CBC-MD5 (legacy, weak)"],
        ["etype 0x11", "AES128-CTS-HMAC-SHA1-96"],
        ["etype 0x12", "AES256-CTS-HMAC-SHA1-96"],
        ["etype 0x17", "RC4-HMAC (used by Kerberoasting; flag if unexpected)"],
        ["etype 0x18", "RC4-HMAC-EXP (export, weak)"],
        ["fail 0x6", "KDC_ERR_C_PRINCIPAL_UNKNOWN - client not found"],
        ["fail 0x7", "KDC_ERR_S_PRINCIPAL_UNKNOWN - server not found"],
        ["fail 0x12", "KDC_ERR_CLIENT_REVOKED - account disabled/locked/expired"],
        ["fail 0x17", "KDC_ERR_KEY_EXPIRED - password expired"],
        ["fail 0x18", "KDC_ERR_PREAUTH_FAILED - wrong password"],
        ["fail 0x19", "KDC_ERR_PREAUTH_REQUIRED - pre-auth needed (AS-REP roasting flag if absent)"],
        ["fail 0x20", "KRB_AP_ERR_TKT_EXPIRED - ticket expired"],
        ["fail 0x25", "KRB_AP_ERR_SKEW - clock skew too great"],
      ], v.q);
    } },

  { id: "bt-win-eventlog-channels", name: "Windows Event Log Channel Reference", cat: "blueteam", desc: "Common Windows event log channel names useful when writing detections and forwarding.", tags: ["windows", "channel", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "powershell, sysmon, rdp..." }],
    run(v) {
      return ref([
        ["Security", "logons, privilege use, audit events"],
        ["System", "service control, driver, system events"],
        ["Application", "application-level events"],
        ["Setup", "OS/feature setup events"],
        ["Microsoft-Windows-Sysmon/Operational", "Sysmon events"],
        ["Microsoft-Windows-PowerShell/Operational", "PowerShell 5+ (4103 module, 4104 script block)"],
        ["Windows PowerShell", "classic PowerShell engine events (400/800)"],
        ["Microsoft-Windows-TaskScheduler/Operational", "scheduled task activity"],
        ["Microsoft-Windows-WinRM/Operational", "WinRM / remoting"],
        ["Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", "RDP local session events"],
        ["Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", "RDP connection events"],
        ["Microsoft-Windows-Windows Defender/Operational", "Defender AV detections"],
        ["Microsoft-Windows-WMI-Activity/Operational", "WMI activity"],
        ["Microsoft-Windows-DNS-Client/Operational", "DNS client queries"],
        ["Microsoft-Windows-AppLocker/EXE and DLL", "AppLocker exe/dll events"],
        ["Microsoft-Windows-CodeIntegrity/Operational", "code integrity (WDAC) events"],
        ["Microsoft-Windows-SmbClient/Security", "SMB client security events"],
      ], v.q);
    } },

  { id: "bt-sysmon-config", name: "Sysmon Config Snippet Builder", cat: "blueteam", desc: "Build a Sysmon configuration RuleGroup filtering a chosen event type on a field condition.", tags: ["sysmon", "config", "xml"],
    inputs: [
      { k: "event", label: "Event type", type: "select", opts: ["ProcessCreate", "NetworkConnect", "FileCreate", "RegistryEvent", "ImageLoad", "DnsQuery"], value: "ProcessCreate" },
      { k: "onmatch", label: "onmatch", type: "select", opts: ["include", "exclude"], value: "include" },
      { k: "field", label: "Field", type: "text", value: "Image" },
      { k: "condition", label: "Condition", type: "select", opts: ["is", "is not", "contains", "contains any", "begin with", "end with", "image", "excludes"], value: "end with" },
      { k: "value", label: "Value", type: "text", value: "\\powershell.exe" },
    ],
    run(v) {
      return [
        `<Sysmon schemaversion="4.90">`,
        `  <EventFiltering>`,
        `    <RuleGroup name="" groupRelation="or">`,
        `      <${v.event} onmatch="${v.onmatch}">`,
        `        <${v.field} condition="${v.condition}">${v.value}</${v.field}>`,
        `      </${v.event}>`,
        `    </RuleGroup>`,
        `  </EventFiltering>`,
        `</Sysmon>`,
      ].join("\n");
    } },

  // ======================= HOST / NETWORK DETECTION =======================
  { id: "bt-auditd-rule", name: "Linux auditd Rule Builder", cat: "blueteam", desc: "Build a Linux auditd rule: a file watch or a syscall audit rule with a key.", tags: ["auditd", "linux", "rule"],
    inputs: [
      { k: "mode", label: "Mode", type: "select", opts: ["File watch", "Syscall"], value: "File watch" },
      { k: "path", label: "Path (watch)", type: "text", value: "/etc/passwd" },
      { k: "perms", label: "Permissions (watch: r/w/x/a)", type: "text", value: "wa" },
      { k: "syscall", label: "Syscall (syscall mode)", type: "text", value: "execve" },
      { k: "arch", label: "Arch (syscall mode)", type: "select", opts: ["b64", "b32"], value: "b64" },
      { k: "key", label: "Key", type: "text", value: "identity" },
    ],
    run(v) {
      if (v.mode === "File watch") {
        if (!v.path) return { error: "Set a path to watch." };
        return `-w ${v.path} -p ${(v.perms || "wa").replace(/[^rwxa]/g, "") || "wa"} -k ${v.key || "watch"}`;
      }
      if (!v.syscall) return { error: "Set a syscall." };
      return `-a always,exit -F arch=${v.arch} -S ${v.syscall} -k ${v.key || "syscall"}`;
    } },

  { id: "bt-falco-rule", name: "Falco Rule Scaffold", cat: "blueteam", desc: "Generate a Falco runtime-security rule YAML with condition, output and priority.", tags: ["falco", "runtime", "rule", "yaml"],
    inputs: [
      { k: "rule", label: "Rule name", type: "text", value: "Shell in container" },
      { k: "desc", label: "Description", type: "text", value: "A shell was spawned inside a container" },
      { k: "condition", label: "Condition", type: "textarea", rows: 2, value: "spawned_process and container and shell_procs" },
      { k: "output", label: "Output", type: "text", value: "Shell in container (user=%user.name container=%container.name cmd=%proc.cmdline)" },
      { k: "priority", label: "Priority", type: "select", opts: ["EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFORMATIONAL", "DEBUG"], value: "WARNING" },
      { k: "tags", label: "Tags (comma-sep)", type: "text", value: "container, shell, mitre_execution" },
    ],
    run(v) {
      if (!v.rule) return { error: "Set a rule name." };
      const tags = (v.tags || "").split(",").map((x) => x.trim()).filter(Boolean);
      return [
        `- rule: ${v.rule}`,
        `  desc: ${v.desc || ""}`,
        `  condition: ${v.condition || "evt.type=execve"}`,
        `  output: "${(v.output || "").replace(/"/g, '\\"')}"`,
        `  priority: ${v.priority}`,
        tags.length ? `  tags: [${tags.join(", ")}]` : null,
      ].filter((x) => x != null).join("\n");
    } },

  { id: "bt-zeek-conn", name: "Zeek conn.log Field Reference", cat: "blueteam", desc: "Zeek (Bro) conn.log core fields and conn_state values for network log analysis.", tags: ["zeek", "bro", "reference", "network"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "bytes, state, duration..." }],
    run(v) {
      return ref([
        ["ts", "timestamp of the first packet"],
        ["uid", "unique connection ID"],
        ["id.orig_h", "originator (source) IP"],
        ["id.orig_p", "originator (source) port"],
        ["id.resp_h", "responder (destination) IP"],
        ["id.resp_p", "responder (destination) port"],
        ["proto", "transport protocol (tcp/udp/icmp)"],
        ["service", "application protocol detected (http, dns, ssl...)"],
        ["duration", "connection duration"],
        ["orig_bytes", "payload bytes sent by originator"],
        ["resp_bytes", "payload bytes sent by responder"],
        ["conn_state", "connection state summary (see values below)"],
        ["history", "per-packet connection history flags"],
        ["orig_pkts / resp_pkts", "packet counts each direction"],
        ["conn_state S0", "connection attempt, no reply"],
        ["conn_state S1", "established, not terminated"],
        ["conn_state SF", "normal establishment and termination"],
        ["conn_state REJ", "connection attempt rejected"],
        ["conn_state RSTO", "established, originator aborted (RST)"],
        ["conn_state RSTR", "responder aborted (RST)"],
        ["conn_state SH", "originator SYN then FIN, no responder SYN-ACK"],
        ["conn_state OTH", "no SYN seen, midstream traffic"],
      ], v.q);
    } },

  { id: "bt-jq-build", name: "jq Filter Builder", cat: "blueteam", desc: "Build a jq filter for JSON log analysis (select, pick fields, count).", tags: ["jq", "json", "log"],
    inputs: [
      { k: "op", label: "Operation", type: "select", opts: ["select by field", "pick fields", "count by field", "flatten array"], value: "select by field" },
      { k: "field", label: "Field", type: "text", value: "level" },
      { k: "value", label: "Value (for select)", type: "text", value: "error" },
      { k: "fields", label: "Fields (for pick, comma-sep)", type: "text", value: "ts, msg, src" },
    ],
    run(v) {
      const f = v.field || "field";
      if (v.op === "select by field") return `jq 'select(.${f} == "${v.value}")'`;
      if (v.op === "pick fields") { const fs = (v.fields || "").split(",").map((x) => x.trim()).filter(Boolean); return `jq '{${fs.map((x) => `${x}: .${x}`).join(", ")}}'`; }
      if (v.op === "count by field") return `jq -s 'group_by(.${f}) | map({key: .[0].${f}, count: length}) | sort_by(-.count)'`;
      return `jq '.${f}[]'`;
    } },

  // ======================= FIREWALL REFERENCES =======================
  { id: "bt-iptables-ref", name: "iptables Syntax Reference", cat: "blueteam", desc: "Reference of common iptables options, chains and targets.", tags: ["iptables", "firewall", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "append, dport, drop..." }],
    run(v) {
      return ref([
        ["-A chain", "append a rule to a chain (INPUT/OUTPUT/FORWARD)"],
        ["-I chain [n]", "insert a rule at position n (default top)"],
        ["-D chain", "delete a matching rule"],
        ["-L -n -v --line-numbers", "list rules (numeric, verbose)"],
        ["-F [chain]", "flush (delete all) rules"],
        ["-P chain target", "set default policy for a chain"],
        ["-p tcp|udp|icmp", "match protocol"],
        ["--dport / --sport", "destination / source port (with -p)"],
        ["-s / -d CIDR", "source / destination address"],
        ["-i / -o iface", "input / output interface"],
        ["-m state --state NEW,ESTABLISHED", "stateful connection match (conntrack)"],
        ["-m multiport --dports 80,443", "multiple ports"],
        ["-m limit --limit 5/min", "rate-limit matches"],
        ["-j ACCEPT|DROP|REJECT|LOG", "jump to a target/verdict"],
        ["-j DNAT --to-destination", "destination NAT (nat table)"],
        ["-t nat|filter|mangle", "select the table"],
      ], v.q);
    } },

  { id: "bt-iptables-build", name: "iptables Rule Builder", cat: "blueteam", desc: "Build an iptables command from chain, protocol, ports, addresses and target.", tags: ["iptables", "firewall", "build"],
    inputs: [
      { k: "chain", label: "Chain", type: "select", opts: ["INPUT", "OUTPUT", "FORWARD"], value: "INPUT" },
      { k: "proto", label: "Protocol", type: "select", opts: ["tcp", "udp", "icmp", "all"], value: "tcp" },
      { k: "src", label: "Source (CIDR, optional)", type: "text", value: "203.0.113.0/24" },
      { k: "dport", label: "Dest port (optional)", type: "text", value: "22" },
      { k: "state", label: "Stateful match", type: "checkbox", value: true },
      { k: "target", label: "Target", type: "select", opts: ["ACCEPT", "DROP", "REJECT", "LOG"], value: "DROP" },
    ],
    run(v) {
      const p = [`iptables -A ${v.chain}`];
      if (v.proto && v.proto !== "all") p.push(`-p ${v.proto}`);
      if (v.src) p.push(`-s ${v.src}`);
      if (v.dport && v.proto !== "icmp" && v.proto !== "all") p.push(`--dport ${v.dport}`);
      if (v.state) p.push(`-m state --state NEW,ESTABLISHED`);
      p.push(`-j ${v.target}`);
      return p.join(" ");
    } },

  { id: "bt-nftables-ref", name: "nftables Syntax Reference", cat: "blueteam", desc: "Reference of common nftables syntax for tables, chains and rules.", tags: ["nftables", "nft", "firewall", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "table, chain, accept..." }],
    run(v) {
      return ref([
        ["nft add table inet filter", "create an inet (v4+v6) table"],
        ["nft add chain inet filter input { type filter hook input priority 0 ; policy drop ; }", "create a base chain with a hook"],
        ["nft add rule inet filter input ct state established,related accept", "accept established connections"],
        ["nft add rule inet filter input tcp dport 22 accept", "allow SSH"],
        ["nft add rule inet filter input ip saddr 203.0.113.0/24 drop", "drop a source range"],
        ["nft add rule inet filter input tcp dport { 80, 443 } accept", "set/anonymous-set of ports"],
        ["nft add rule inet filter input limit rate 5/minute accept", "rate-limit"],
        ["nft list ruleset", "show the full ruleset"],
        ["nft flush ruleset", "clear everything"],
        ["nft -f /etc/nftables.conf", "load a ruleset file"],
        ["counter / log prefix \"drop: \"", "statement keywords (count, log)"],
        ["hooks: prerouting/input/forward/output/postrouting", "netfilter hooks for base chains"],
      ], v.q);
    } },

  // ======================= THRESHOLD / RATE CALCULATORS =======================
  { id: "bt-bruteforce-threshold", name: "Brute-Force / Lockout Calculator", cat: "blueteam", desc: "Estimate online password-guessing time given a keyspace and an account-lockout policy.", tags: ["bruteforce", "lockout", "calculator"],
    inputs: [
      { k: "charset", label: "Charset size", type: "select", opts: [["10", "digits (10)"], ["26", "lowercase (26)"], ["62", "alphanumeric (62)"], ["95", "all printable ASCII (95)"]], value: "62" },
      { k: "length", label: "Password length", type: "range", min: 1, max: 16, step: 1, value: 8 },
      { k: "attempts", label: "Attempts before lockout", type: "text", value: "5" },
      { k: "lockoutMin", label: "Lockout window (minutes)", type: "text", value: "30" },
    ],
    run(v, H) {
      const cs = parseInt(v.charset, 10), len = H.clampInt(v.length, 1, 16, 8);
      const attempts = Math.max(1, num(v.attempts) || 5), win = Math.max(0.0001, num(v.lockoutMin) || 30);
      const keyspace = Math.pow(cs, len);
      const perMin = attempts / win;
      const expectedMin = (keyspace / 2) / perMin;
      const worstMin = keyspace / perMin;
      return [
        `Keyspace: ${cs}^${len} = ${keyspace.toExponential(3)} combinations`,
        `Allowed guess rate: ${attempts} per ${win} min = ${(perMin * 60).toFixed(3)} per hour`,
        `Expected time to guess (50% of keyspace): ${humanTime(expectedMin)}`,
        `Worst case (100%): ${humanTime(worstMin)}`,
        ``,
        `Lockout policy throttles online guessing massively. This does NOT model offline cracking of a stolen hash (which has no lockout).`,
      ].join("\n");
    } },

  { id: "bt-ratelimit-calc", name: "Rate-Limit / Token-Bucket Calculator", cat: "blueteam", desc: "Convert a request allowance into sustained RPS and token-bucket parameters, with an nginx example.", tags: ["ratelimit", "token bucket", "calculator"],
    inputs: [
      { k: "limit", label: "Requests allowed", type: "text", value: "100" },
      { k: "window", label: "Per window (seconds)", type: "text", value: "60" },
      { k: "burst", label: "Burst capacity (optional)", type: "text", value: "20" },
    ],
    run(v) {
      const limit = num(v.limit), win = num(v.window);
      if (isNaN(limit) || isNaN(win) || limit <= 0 || win <= 0) return { error: "Enter a positive request count and window." };
      const rps = limit / win;
      const burst = num(v.burst) || limit;
      return [
        `Sustained rate: ${rps.toFixed(4)} req/s`,
        `  = ${(rps * 60).toFixed(2)} req/min = ${(rps * 3600).toFixed(0)} req/hour`,
        `Token bucket: capacity ${burst}, refill ${rps.toFixed(4)} tokens/s`,
        `Time to refill a full bucket from empty: ${(burst / rps).toFixed(2)} s`,
        ``,
        `nginx example:`,
        `  limit_req_zone $binary_remote_addr zone=api:10m rate=${rps >= 1 ? Math.round(rps) + "r/s" : Math.round(rps * 60) + "r/m"};`,
        `  limit_req zone=api burst=${burst} nodelay;`,
      ].join("\n");
    } },

  { id: "bt-log-volume", name: "Log Volume / SIEM Sizing Calculator", cat: "blueteam", desc: "Estimate EPS, daily ingest and retained storage from event volume and average event size.", tags: ["siem", "eps", "sizing", "calculator"],
    inputs: [
      { k: "perDay", label: "Events per day", type: "text", value: "50000000" },
      { k: "avgBytes", label: "Avg event size (bytes)", type: "text", value: "500" },
      { k: "retention", label: "Retention (days)", type: "text", value: "90" },
      { k: "compress", label: "Compression (%)", type: "text", value: "70" },
    ],
    run(v) {
      const perDay = num(v.perDay), avg = num(v.avgBytes), ret = num(v.retention), comp = Math.min(99, Math.max(0, num(v.compress) || 0));
      if (isNaN(perDay) || isNaN(avg) || perDay < 0 || avg < 0) return { error: "Enter events/day and average size." };
      const eps = perDay / 86400;
      const rawDay = perDay * avg;
      const storedDay = rawDay * (1 - comp / 100);
      const total = storedDay * (ret || 0);
      return [
        `Average EPS: ${eps.toFixed(1)} events/sec`,
        `Raw ingest/day: ${humanBytes(rawDay)}`,
        `Stored/day (after ${comp}% compression): ${humanBytes(storedDay)}`,
        `Retained total over ${ret || 0} days: ${humanBytes(total)}`,
      ].join("\n");
    } },

  { id: "bt-base-rate", name: "Alert Base-Rate Calculator", cat: "blueteam", desc: "Show how prevalence, detection rate and false-positive rate drive alert precision (the base-rate fallacy).", tags: ["base rate", "precision", "fp", "calculator"],
    inputs: [
      { k: "perDay", label: "Events per day", type: "text", value: "1000000" },
      { k: "prevalence", label: "Malicious fraction (0-1)", type: "text", value: "0.0001" },
      { k: "sens", label: "Detection rate / recall (%)", type: "text", value: "95" },
      { k: "fpr", label: "False-positive rate (%)", type: "text", value: "1" },
    ],
    run(v) {
      const n = num(v.perDay), prev = num(v.prevalence), sens = num(v.sens) / 100, fpr = num(v.fpr) / 100;
      if ([n, prev, sens, fpr].some((x) => isNaN(x)) || prev < 0 || prev > 1) return { error: "Check inputs (prevalence 0-1, rates in %)." };
      const mal = n * prev, ben = n - mal;
      const tp = mal * sens, fp = ben * fpr, fn = mal - tp;
      const alerts = tp + fp;
      const precision = alerts > 0 ? tp / alerts : 0;
      return [
        `Per day: ${Math.round(mal)} malicious, ${Math.round(ben)} benign`,
        `True positives (alerts that are real): ${Math.round(tp)}`,
        `False positives: ${Math.round(fp)}`,
        `Missed (false negatives): ${Math.round(fn)}`,
        `Total alerts: ${Math.round(alerts)}`,
        ``,
        `Precision = TP/(TP+FP) = ${(precision * 100).toFixed(2)}%`,
        `=> only about ${(precision * 100).toFixed(1)}% of alerts are true threats. Even a 1% FP rate on a huge benign volume buries rare real events.`,
      ].join("\n");
    } },

  { id: "bt-detection-metrics", name: "Detection Metrics Calculator", cat: "blueteam", desc: "Compute precision, recall, specificity, FPR, accuracy and F1 from a confusion matrix.", tags: ["metrics", "precision", "recall", "f1"],
    inputs: [
      { k: "tp", label: "True positives", type: "text", value: "80" },
      { k: "fp", label: "False positives", type: "text", value: "20" },
      { k: "fn", label: "False negatives", type: "text", value: "10" },
      { k: "tn", label: "True negatives", type: "text", value: "890" },
    ],
    run(v) {
      const tp = num(v.tp), fp = num(v.fp), fn = num(v.fn), tn = num(v.tn);
      if ([tp, fp, fn, tn].some((x) => isNaN(x) || x < 0)) return { error: "Enter non-negative counts." };
      const pct = (x) => isFinite(x) ? (x * 100).toFixed(2) + "%" : "n/a";
      const precision = tp + fp ? tp / (tp + fp) : NaN;
      const recall = tp + fn ? tp / (tp + fn) : NaN;
      const spec = tn + fp ? tn / (tn + fp) : NaN;
      const fpr = fp + tn ? fp / (fp + tn) : NaN;
      const acc = (tp + fp + fn + tn) ? (tp + tn) / (tp + fp + fn + tn) : NaN;
      const f1 = (precision + recall) ? 2 * precision * recall / (precision + recall) : NaN;
      return [
        `Precision (PPV):     ${pct(precision)}`,
        `Recall (TPR):        ${pct(recall)}`,
        `Specificity (TNR):   ${pct(spec)}`,
        `False positive rate: ${pct(fpr)}`,
        `Accuracy:            ${pct(acc)}`,
        `F1 score:            ${isFinite(f1) ? f1.toFixed(4) : "n/a"}`,
      ].join("\n");
    } },

  // ======================= ALERTING / COVERAGE / TRIAGE =======================
  { id: "bt-alert-dedup-key", name: "Alert Dedup / Grouping Key Builder", cat: "blueteam", desc: "Build a stable dedup/correlation key by joining selected fields, with an optional hash.", tags: ["alert", "dedup", "correlation"],
    inputs: [
      { k: "fields", label: "Key fields (one 'name=value' or value per line)", type: "textarea", rows: 4, value: "rule=ssh-bruteforce\nsrc=198.51.100.7\ndst=192.0.2.5" },
      { k: "sep", label: "Separator", type: "text", value: "|" },
      { k: "hash", label: "Also show SHA-1 of the key", type: "checkbox", value: true },
    ],
    async run(v, H) {
      const parts = lines(v.fields);
      if (!parts.length) return { error: "Add at least one key field." };
      const sep = v.sep || "|";
      const key = parts.join(sep);
      let out = `dedup_key: ${key}`;
      if (v.hash) out += `\nsha1:      ${await H.sha1(key)}`;
      return out;
    } },

  { id: "bt-coverage-matrix", name: "ATT&CK Coverage Matrix Helper", cat: "blueteam", desc: "Tally your detections per MITRE ATT&CK tactic and highlight tactics with no coverage.", tags: ["attack", "coverage", "detection"],
    inputs: [{ k: "entries", label: "Entries (one 'Tactic | rule name' per line)", type: "textarea", rows: 6, value: "Initial Access | phishing-attachment\nExecution | suspicious-powershell\nExecution | wmic-exec\nPersistence | new-service\nExfiltration | large-dns-txt" }],
    run(v) {
      const TACTICS = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"];
      const counts = Object.fromEntries(TACTICS.map((t) => [t, 0]));
      const unknown = [];
      for (const l of lines(v.entries)) {
        const tac = l.split("|")[0].trim();
        const match = TACTICS.find((t) => t.toLowerCase() === tac.toLowerCase());
        if (match) counts[match]++; else unknown.push(tac);
      }
      const rows = TACTICS.map((t) => `${counts[t] ? "COVERED" : "  GAP  "}  ${t}: ${counts[t]} rule(s)`);
      const gaps = TACTICS.filter((t) => !counts[t]);
      let out = rows.join("\n") + `\n\nGaps (${gaps.length}): ${gaps.join(", ") || "none"}`;
      if (unknown.length) out += `\nUnrecognized tactic names: ${[...new Set(unknown)].join(", ")}`;
      return out;
    } },

  { id: "bt-attack-tactics", name: "MITRE ATT&CK Tactics Reference", cat: "blueteam", desc: "The 14 MITRE ATT&CK Enterprise tactics with their IDs and goals.", tags: ["attack", "mitre", "tactics", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "persistence, TA0001..." }],
    run(v) {
      return ref([
        ["TA0043", "Reconnaissance", "gather information to plan operations"],
        ["TA0042", "Resource Development", "establish resources (infrastructure, accounts)"],
        ["TA0001", "Initial Access", "get into the network"],
        ["TA0002", "Execution", "run malicious code"],
        ["TA0003", "Persistence", "maintain a foothold"],
        ["TA0004", "Privilege Escalation", "gain higher-level permissions"],
        ["TA0005", "Defense Evasion", "avoid detection"],
        ["TA0006", "Credential Access", "steal account names and passwords"],
        ["TA0007", "Discovery", "figure out the environment"],
        ["TA0008", "Lateral Movement", "move through the environment"],
        ["TA0009", "Collection", "gather data of interest"],
        ["TA0011", "Command and Control", "communicate with compromised systems"],
        ["TA0010", "Exfiltration", "steal data"],
        ["TA0040", "Impact", "manipulate, interrupt or destroy systems/data"],
      ], v.q);
    } },

  { id: "bt-fp-triage", name: "False-Positive Triage Checklist", cat: "blueteam", desc: "Generate a tailored false-positive triage checklist for a given alert type.", tags: ["triage", "false positive", "checklist", "soc"],
    inputs: [{ k: "type", label: "Alert type", type: "select", opts: ["Failed logons / brute force", "Port scan", "Malware / AV detection", "DNS anomaly", "Data exfiltration", "Phishing report", "Generic"], value: "Failed logons / brute force" }],
    run(v) {
      const common = ["Confirm the alert details: timestamp, source/dest, user, asset.", "Check whether the source/user/asset is known or expected.", "Correlate with other alerts and recent events on the same entity.", "Determine if a change/maintenance window or known app explains it.", "Decide: true positive -> escalate; false positive -> tune rule and document."];
      const spec = {
        "Failed logons / brute force": ["Count failures per source and per account over the window.", "Check for a matching SUCCESS (4624) after the failures.", "Identify service accounts / expired passwords causing noise.", "Check source geo/ASN vs expected locations."],
        "Port scan": ["Is the source a known vuln scanner or monitoring host?", "Distinguish vertical (many ports/one host) vs horizontal (one port/many hosts).", "Check whether any connection actually completed (SYN-ACK)."],
        "Malware / AV detection": ["Was the file quarantined/blocked or did it execute?", "Check the file hash reputation (offline) and path (temp/downloads?).", "Look for parent process and follow-on activity (network, new files)."],
        "DNS anomaly": ["Inspect the queried domain: NXDOMAIN rate, entropy, length.", "Is it a known CDN/telemetry domain (benign noise)?", "Check query type (TXT/NULL) and volume for tunneling signs."],
        "Data exfiltration": ["Quantify bytes out vs normal baseline for the host.", "Identify the destination (known SaaS/backup vs unknown).", "Check protocol/port and whether it is business-approved."],
        "Phishing report": ["Review headers: SPF/DKIM/DMARC alignment and sender.", "Defang and check URLs/attachments in a safe manner.", "Determine who received it and whether anyone clicked/replied."],
        "Generic": [],
      };
      const steps = [...(spec[v.type] || []), ...common];
      return `Triage checklist - ${v.type}\n\n` + steps.map((s, i) => `${i + 1}. ${s}`).join("\n");
    } },

  { id: "bt-detection-doc", name: "Detection Rule Documentation Template", cat: "blueteam", desc: "Produce a structured markdown documentation/runbook block for a detection rule.", tags: ["detection", "documentation", "runbook"],
    inputs: [
      { k: "name", label: "Detection name", type: "text", value: "Encoded PowerShell execution" },
      { k: "source", label: "Data source", type: "text", value: "Sysmon EID 1 / Security 4688" },
      { k: "logic", label: "Logic summary", type: "textarea", rows: 2, value: "Process powershell.exe with -EncodedCommand / -enc in the command line." },
      { k: "severity", label: "Severity", type: "select", opts: ["Low", "Medium", "High", "Critical"], value: "High" },
      { k: "mitre", label: "ATT&CK technique(s)", type: "text", value: "T1059.001 (PowerShell)" },
      { k: "fp", label: "Known false positives", type: "text", value: "Some admin tooling uses -enc legitimately." },
      { k: "response", label: "Response steps", type: "text", value: "Decode the command, inspect, isolate host if malicious." },
    ],
    run(v) {
      if (!v.name) return { error: "Set a detection name." };
      return [
        `# Detection: ${v.name}`,
        ``, `**Severity:** ${v.severity}`,
        `**Data source:** ${v.source || "-"}`,
        `**ATT&CK:** ${v.mitre || "-"}`,
        ``, `## Logic`, v.logic || "-",
        ``, `## Known false positives`, v.fp || "-",
        ``, `## Response`, v.response || "-",
        ``, `## Validation`, `- Trigger the behavior in a lab and confirm the rule fires.`, `- Review a week of hits to measure the false-positive rate.`,
      ].join("\n");
    } },

  // ======================= PROTOCOL / NETWORK REFERENCES =======================
  { id: "bt-ip-proto", name: "IP Protocol Number Reference", cat: "blueteam", desc: "IANA IP protocol numbers for decoding the protocol field in flow logs and firewall logs.", tags: ["protocol", "reference", "network"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "tcp, 17, gre..." }],
    run(v) {
      const rows = Object.keys(IP_PROTO).map((k) => [k, IP_PROTO[k]]);
      return ref(rows, v.q);
    } },

  { id: "bt-icmp-ref", name: "ICMP Type / Code Reference", cat: "blueteam", desc: "ICMPv4 message types and the codes for Destination Unreachable and Time Exceeded.", tags: ["icmp", "reference", "network"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "unreachable, echo, redirect..." }],
    run(v) {
      return ref([
        ["0", "Echo Reply"],
        ["3", "Destination Unreachable (code 0=net, 1=host, 2=protocol, 3=port, 4=frag needed+DF, 13=comm admin prohibited)"],
        ["4", "Source Quench (deprecated)"],
        ["5", "Redirect"],
        ["8", "Echo Request (ping)"],
        ["9", "Router Advertisement"],
        ["10", "Router Solicitation"],
        ["11", "Time Exceeded (code 0=TTL exceeded, 1=frag reassembly time exceeded)"],
        ["12", "Parameter Problem"],
        ["13", "Timestamp Request"],
        ["14", "Timestamp Reply"],
      ], v.q);
    } },

  { id: "bt-dns-rcode", name: "DNS Response Code Reference", cat: "blueteam", desc: "DNS RCODE values for analyzing DNS logs (NXDOMAIN, SERVFAIL, REFUSED, ...).", tags: ["dns", "rcode", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "nxdomain, servfail..." }],
    run(v) {
      return ref([
        ["0", "NOERROR", "no error"],
        ["1", "FORMERR", "format error (malformed query)"],
        ["2", "SERVFAIL", "server failure (e.g. DNSSEC validation failed)"],
        ["3", "NXDOMAIN", "non-existent domain"],
        ["4", "NOTIMP", "query type not implemented"],
        ["5", "REFUSED", "server refused (policy)"],
        ["6", "YXDOMAIN", "name exists when it should not"],
        ["7", "YXRRSET", "RR set exists when it should not"],
        ["8", "NXRRSET", "RR set that should exist does not"],
        ["9", "NOTAUTH", "server not authoritative / not authorized"],
        ["10", "NOTZONE", "name not in zone"],
      ], v.q);
    } },

  // ======================= IR / DETECTION CONCEPTS =======================
  { id: "bt-ir-lifecycle", name: "Incident Response Lifecycle Reference", cat: "blueteam", desc: "NIST SP 800-61 and SANS PICERL incident-response phases side by side.", tags: ["incident", "nist", "sans", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "containment, lessons..." }],
    run(v) {
      return ref([
        ["NIST 1", "Preparation", "build tooling, playbooks, training before an incident"],
        ["NIST 2", "Detection & Analysis", "identify and scope the incident"],
        ["NIST 3", "Containment, Eradication & Recovery", "stop spread, remove threat, restore"],
        ["NIST 4", "Post-Incident Activity", "lessons learned and improvements"],
        ["SANS 1", "Preparation", ""],
        ["SANS 2", "Identification", ""],
        ["SANS 3", "Containment", ""],
        ["SANS 4", "Eradication", ""],
        ["SANS 5", "Recovery", ""],
        ["SANS 6", "Lessons Learned", ""],
      ], v.q);
    } },

  { id: "bt-pyramid-of-pain", name: "Pyramid of Pain Reference", cat: "blueteam", desc: "David Bianco's Pyramid of Pain: how much disruption blocking each indicator type causes an adversary.", tags: ["pyramid of pain", "ioc", "detection", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "hash, ttp, tools..." }],
    run(v) {
      return ref([
        ["1 (bottom)", "Hash values", "Trivial - a single byte change defeats the block"],
        ["2", "IP addresses", "Easy - attackers rotate IPs readily"],
        ["3", "Domain names", "Simple - can re-register / use new domains"],
        ["4", "Network/Host artifacts", "Annoying - forces attacker to change tooling behavior"],
        ["5", "Tools", "Challenging - attacker must find/build new tools"],
        ["6 (top)", "TTPs", "Tough - detecting behavior forces them to relearn how they operate"],
      ], v.q);
    } },
];
