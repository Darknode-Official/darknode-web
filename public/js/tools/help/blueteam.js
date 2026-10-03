// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
// Plain-English help for the blueteam.js mini-tools. See help/README.md for the contract.
export const HELP = {
  "bt-sigma-scaffold": {
    what: "Builds a ready-to-edit Sigma detection rule in YAML. Sigma is a vendor-neutral format for writing detections that can be converted to Splunk, Elastic and others. You fill in a title, log source and match fields and it produces the full rule skeleton.",
    when: "You are writing a new detection and want a correct Sigma rule structure to start from instead of remembering the YAML layout.",
    example: { title: "Suspicious cmd.exe spawned by Office", category: "process_creation", product: "windows", selection: "ParentImage|endswith: \\\\winword.exe\nImage|endswith: \\\\cmd.exe", condition: "selection", level: "high" },
  },
  "bt-sigma-modifiers": {
    what: "A searchable list of Sigma value-modifiers (like contains, startswith, re, base64, cidr) and what each one does to a match. Type a keyword to filter.",
    when: "You are writing a Sigma rule and need to remember how to match a substring, a regex, an IP range or an encoded value.",
    example: { q: "base64" },
  },
  "bt-sigma-logsource": {
    what: "A reference of common values for the Sigma logsource block (category, product and service) and which data each maps to. Type to filter.",
    when: "You are writing a Sigma rule and need the right logsource category/product/service for the data you are detecting on.",
    example: { q: "process" },
  },
  "bt-spl-builder": {
    what: "Assembles a Splunk search (SPL) from an index, sourcetype, field filters, a time range and an optional stats-by clause. SPL is Splunk's search query language. You get a pasteable query.",
    when: "You want a starting Splunk query for a hunt or detection without hand-writing the whole search.",
    example: { index: "wineventlog", sourcetype: "WinEventLog:Security", earliest: "-24h", filters: "EventCode=4625", statsBy: "Account_Name, src_ip" },
  },
  "bt-spl-rex-build": {
    what: "Turns a regular expression that has named groups into a Splunk `| rex` command that extracts those groups as fields. It also lists the field names it found.",
    when: "You have a regex that captures fields from a log line and want the Splunk command to extract them at search time.",
    example: { field: "_raw", regex: "user=(?<user>\\w+)\\s+src=(?<src_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)" },
  },
  "bt-spl-cheatsheet": {
    what: "A searchable list of common Splunk SPL commands (stats, rex, eval, timechart and more) with a one-line description of each.",
    when: "You are building a Splunk search and need a quick reminder of which command does what.",
    example: { q: "stats" },
  },
  "bt-kql-builder": {
    what: "Builds a Microsoft Sentinel / Defender KQL query from a table, where-conditions, a time window and an optional summarize. KQL (Kusto Query Language) is what Microsoft hunting uses. You get a pasteable query.",
    when: "You are hunting in Sentinel or Defender advanced hunting and want a correct KQL query scaffold to adapt.",
    example: { table: "DeviceProcessEvents", timespan: "24h", where: 'FileName =~ "cmd.exe"\nProcessCommandLine has "whoami"', summarize: "count() by DeviceName, AccountName", project: "" },
  },
  "bt-kql-parse-build": {
    what: "Turns a sample line with {field} placeholders into a KQL `parse` statement that pulls those fields out of a column. It also lists the fields it will extract.",
    when: "You have an unstructured column in Sentinel/Defender and want to extract fields from it with the parse operator.",
    example: { column: "RawData", template: "user={user} ip={src_ip} action={action}" },
  },
  "bt-kql-cheatsheet": {
    what: "A searchable list of common KQL operators and functions (where, summarize, join, ago and more) with short descriptions.",
    when: "You are writing a KQL query and need a quick reminder of an operator's name or purpose.",
    example: { q: "summarize" },
  },
  "bt-defender-tables": {
    what: "A searchable reference of common Microsoft Defender / Sentinel advanced-hunting table names and what data each table holds.",
    when: "You are writing a KQL hunting query and need the right table for process, network, logon or email events.",
    example: { q: "process" },
  },
  "bt-osquery-pack": {
    what: "Builds an osquery query-pack JSON entry from a query name, SQL, run interval and platform. osquery exposes an operating system as SQL tables you can query for monitoring.",
    when: "You are adding a scheduled osquery check to a pack and want correctly formatted JSON.",
    example: { name: "listening_ports", query: "SELECT pid, address, port, protocol FROM listening_ports;", interval: "300", platform: "all", snapshot: false, desc: "Current listening network ports" },
  },
  "bt-osquery-tables": {
    what: "A searchable reference of commonly used osquery tables (processes, listening_ports, users and so on) and what each returns.",
    when: "You are writing an osquery query and need to recall which table holds the data you want.",
    example: { q: "process" },
  },
  "bt-ids-rule": {
    what: "Scaffolds a Suricata or Snort intrusion-detection rule from the action, protocol, addresses/ports and a content match. These rules tell an IDS/IPS what traffic to alert on or block.",
    when: "You are writing a network detection signature and want a correctly structured rule to edit.",
    example: { action: "alert", proto: "http", src: "$EXTERNAL_NET", srcport: "any", dir: "->", dst: "$HOME_NET", dstport: "any", msg: "ET POLICY Suspicious whoami in URI", content: "whoami", sid: "1000001" },
  },
  "bt-suricata-keywords": {
    what: "A searchable list of common Suricata/Snort rule-option keywords (content, flow, pcre, classtype and more) and what each does inside a rule.",
    when: "You are writing or reading an IDS rule and need to remember what a keyword in the rule body means.",
    example: { q: "content" },
  },
  "bt-grok-build": {
    what: "Assembles a Logstash grok pattern from a list of PATTERN:field tokens and literal text. Grok parses unstructured log lines into named fields. You get the grok string to paste into a filter.",
    when: "You are writing a Logstash grok filter and want to build the pattern piece by piece from known base patterns.",
    example: { tokens: "IPORHOST client\nlit: - \nUSER user" },
  },
  "bt-grok-test": {
    what: "Tests a grok pattern against one sample log line and shows the captured fields as JSON, or tells you it did not match. It resolves the built-in base patterns for you.",
    when: "You wrote a grok pattern and want to confirm it matches a real line and extracts the right fields before deploying it.",
    example: { pattern: "%{IPV4:client} - %{USER:user} \\[%{TIMESTAMP_ISO8601:ts}\\] %{WORD:method}", sample: "192.0.2.10 - alice [2026-10-03T12:30:00Z] GET" },
  },
  "bt-grok-ref": {
    what: "Lists the built-in grok base patterns (like IPV4, NUMBER, TIMESTAMP_ISO8601) and the regex each expands to. Type to filter.",
    when: "You are writing a grok pattern and need to know which named patterns are available and what they match.",
    example: { q: "IP" },
  },
  "bt-logstash-filter": {
    what: "Builds a complete Logstash filter{} block with a grok stage, an optional date-parse stage and an optional mutate to drop fields. Logstash filters transform logs as they are ingested.",
    when: "You are configuring a Logstash pipeline and want a correct filter block around your grok pattern.",
    example: { match: "%{IPV4:client} %{WORD:method} %{NOTSPACE:request}", field: "message", dateField: "ts", remove: "message" },
  },
  "bt-log-field-extract": {
    what: "Runs a regex with named groups over each log line you paste and returns the captured fields as JSON, one object per line. Lines that do not match are flagged.",
    when: "You have a batch of similar log lines and want to pull structured fields out of them to inspect or feed elsewhere.",
    example: { regex: "^(?<ip>\\S+) \\S+ (?<user>\\S+) \\[(?<ts>[^\\]]+)\\]", text: "198.51.100.7 - bob [03/Oct/2026:10:00:00 +0000]\n198.51.100.9 - eve [03/Oct/2026:10:00:05 +0000]" },
  },
  "bt-yara-rule": {
    what: "Builds a YARA rule skeleton with a meta block, string definitions and a condition. YARA matches files/memory against text, hex or regex patterns to identify malware.",
    when: "You are writing a YARA rule to detect a sample and want the structure filled in from your strings.",
    example: { name: "Suspicious_Dropper", author: "analyst", desc: "Detects marker strings in a dropper sample", type: "text", strings: "cmd.exe /c\npowershell -enc", condition: "any of them" },
  },
  "bt-wazuh-rule": {
    what: "Builds a Wazuh/OSSEC rule XML block from a group, rule id, level and a match string. Wazuh is an open-source host IDS/SIEM; rules raise alerts from decoded log fields.",
    when: "You are adding a custom detection to Wazuh and want a correctly structured rule element.",
    example: { group: "local,authentication", id: "100100", level: "10", ifSid: "5716", match: "authentication failure", desc: "Repeated SSH authentication failure" },
  },
  "bt-eql-build": {
    what: "Builds an Elastic EQL query from an event category and conditions, optionally as a two-event sequence. EQL (Event Query Language) is Elastic's language for event-based detections.",
    when: "You are writing an Elastic detection and want an EQL event or sequence query scaffold.",
    example: { category: "process", conds: 'process.name == "cmd.exe"\nprocess.args : "*whoami*"', sequence: false },
  },
  "bt-es-dsl-build": {
    what: "Builds an Elasticsearch query DSL bool query (must / should / filter) with an optional time range, as JSON. Query DSL is the JSON query format Elasticsearch APIs accept.",
    when: "You are querying Elasticsearch directly and want a correctly shaped bool query to paste into a search or alert.",
    example: { must: "event.action:logon-failed", should: "", rangeField: "@timestamp", gte: "now-24h" },
  },
  "bt-cef-parse": {
    what: "Reads an ArcSight CEF log line and splits it into its seven header fields and the key=value extension pairs. CEF (Common Event Format) is a standard log format many security products emit.",
    when: "You have a CEF line from a log and want to read its vendor, event name, severity and extension fields clearly.",
    example: { line: "CEF:0|Security|threatmanager|1.0|100|worm detected|10|src=192.0.2.1 dst=198.51.100.2 spt=1232" },
  },
  "bt-cef-build": {
    what: "Builds a correctly escaped ArcSight CEF log line from the vendor, product, signature, name, severity and extension key=value pairs you provide.",
    when: "You are generating CEF output (for a connector, test or integration) and want a valid line with the pipes and equals signs escaped properly.",
    example: { vendor: "Darknode", product: "Sensor", version: "1.0", sig: "100", name: "Port scan detected", severity: "6", ext: "src=192.0.2.5\ndst=198.51.100.8\nspt=44321" },
  },
  "bt-leef-parse": {
    what: "Reads an IBM QRadar LEEF log line (version 1.0 or 2.0) and splits it into its header fields and attribute key=value pairs, handling the attribute delimiter. LEEF is QRadar's log event format.",
    when: "You have a LEEF line and want to read its vendor, event id and attributes clearly.",
    example: { line: "LEEF:2.0|Lancope|StealthWatch|1.0|41|^|src=192.0.2.1^dst=198.51.100.2^spt=1232" },
  },
  "bt-syslog-parse": {
    what: "Parses an RFC 5424 syslog message into its PRI (decoded to facility and severity), version, timestamp, host, app, process id, message id, structured data and message text.",
    when: "You have a modern (RFC 5424) syslog line and want to read every field, including what its priority number means.",
    example: { line: "<34>1 2026-10-03T22:14:15.003Z host1 su 1234 ID47 - BOM'su root' failed for user on /dev/pts/8" },
  },
  "bt-syslog-pri": {
    what: "Converts a syslog PRI number into its facility and severity, or the other way around. PRI encodes both values as facility times 8 plus severity.",
    when: "You see a syslog PRI value and want to know which facility and severity it represents (or need to compute a PRI).",
    example: { mode: "PRI -> facility/severity", pri: "34", facility: "4", severity: "2" },
  },
  "bt-syslog-ref": {
    what: "A searchable reference of the RFC 5424 syslog facility codes (0-23) and severity codes (0-7) with their meanings.",
    when: "You are reading or configuring syslog and need to look up what a facility or severity number means.",
    example: { q: "auth" },
  },
  "bt-logfmt-parse": {
    what: "Parses a logfmt line (space-separated key=value pairs, with quoted values supported) into JSON. logfmt is a common structured-logging style.",
    when: "You have a logfmt-style log line and want it as clean JSON to read or process.",
    example: { line: 'level=error msg="connection refused" src=192.0.2.9 attempt=3 ok=false' },
  },
  "bt-accesslog-parse": {
    what: "Parses an Apache or Nginx access-log line in Common or Combined Log Format into named fields (host, user, time, request method/path, status, bytes, referer, user-agent).",
    when: "You are reviewing web server access logs and want a single line broken into readable fields.",
    example: { line: '198.51.100.7 - frank [03/Oct/2026:13:55:36 +0000] "GET /admin HTTP/1.1" 403 512 "http://example.com/" "Mozilla/5.0"' },
  },
  "bt-iis-log-parse": {
    what: "Maps an IIS W3C extended log line to field names using the #Fields header line, so each space-separated value gets its correct label.",
    when: "You are reading IIS web server logs and want each value matched to its field name.",
    example: { fields: "date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status time-taken", line: "2026-10-03 13:55:36 192.0.2.5 GET /login - 443 - 198.51.100.7 Mozilla/5.0 401 0 0 15" },
  },
  "bt-vpcflow-parse": {
    what: "Parses an AWS VPC Flow Log record in the default version-2 format into named fields, and decodes the protocol number and the start/end epoch times.",
    when: "You are analyzing AWS VPC flow logs and want a record broken into readable fields like source, destination, action and ports.",
    example: { line: "2 123456789012 eni-0abc12 192.0.2.5 198.51.100.8 44321 443 6 20 4000 1696339200 1696339260 ACCEPT OK" },
  },
  "bt-ps-decode": {
    what: "Decodes a PowerShell -EncodedCommand value back to the original script. These are base64 of UTF-16LE text, so a plain base64 decode gives garbage; this tool decodes them correctly.",
    when: "You found an encoded PowerShell command in a log or process list and want to read what it actually runs.",
    example: { b64: "dwBoAG8AYQBtAGkA" },
  },
  "bt-defang": {
    what: "Defangs or refangs text: defanging turns http into hxxp and . into [.] so URLs and IPs are not clickable; refanging reverses it. This makes indicators safe to paste into reports and tickets.",
    when: "You are writing up findings and want to share a malicious URL or IP without it being a live, clickable link (or you received a defanged one and want it back).",
    example: { text: "http://evil.example.com/path and 192.0.2.5 contacted mail@evil.example.com", mode: "Defang" },
  },
  "bt-cvss4-parse": {
    what: "Reads a CVSS v4.0 vector string, checks every metric is valid, expands each to its full name, and tells you the nomenclature (CVSS-B / BT / BE / BTE). It does not compute the number, because the official v4.0 score needs a large lookup table.",
    when: "You have a CVSS v4.0 vector and want to validate it and read what each metric means.",
    example: { vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" },
  },
  "bt-cvss-severity-ref": {
    what: "Shows the qualitative severity rating bands (None/Low/Medium/High/Critical) for CVSS v2, v3.x and v4.0 base scores. Type to filter.",
    when: "You have a CVSS number and want to know which severity label it falls into, for the right CVSS version.",
    example: { q: "critical" },
  },
  "bt-severity-normalize": {
    what: "Maps a severity expressed as a CVSS score, a qualitative word, or a syslog severity number onto one simple 0-4 scale (Informational to Critical), so different sources can be compared.",
    when: "You are combining alerts from tools that rate severity differently and want them on one common scale.",
    example: { scale: "CVSS (0-10)", value: "8.1" },
  },
  "bt-epss-explain": {
    what: "Explains an EPSS score and percentile in plain language. EPSS estimates the probability a vulnerability will be exploited in the wild in the next 30 days; the percentile ranks it against all CVEs. It also contrasts EPSS with CVSS.",
    when: "You have an EPSS value from a scanner or feed and want to understand what it means for prioritization.",
    example: { score: "0.42", percentile: "96" },
  },
  "bt-incident-priority": {
    what: "Works out an incident priority (P1 to P5) from its impact and urgency, using the standard ITIL matrix, and suggests a response timeframe.",
    when: "You are triaging an incident and want a consistent priority from how bad it is and how fast it must be handled.",
    example: { impact: "High", urgency: "High" },
  },
  "bt-win-audit-policy": {
    what: "A searchable reference of the Windows advanced audit policy categories and their subcategories (what auditpol configures). These control which security events Windows logs.",
    when: "You are tuning Windows audit policy and need the exact category and subcategory names.",
    example: { q: "logon" },
  },
  "bt-win-event-ids": {
    what: "A searchable reference of security-relevant Windows Security-log event IDs (like 4624 logon, 4688 process creation, 4769 Kerberos ticket) and what each records.",
    when: "You are writing or reading a Windows detection and need to know what an event ID means.",
    example: { q: "logon" },
  },
  "bt-sysmon-ids": {
    what: "A searchable reference of Sysmon event IDs (process creation, network connection, DNS query and so on). Sysmon is a Windows tool that logs rich endpoint telemetry.",
    when: "You are building detections on Sysmon data and need to recall which event ID is which.",
    example: { q: "network" },
  },
  "bt-win-logon-types": {
    what: "A searchable reference of Windows logon type codes (the LogonType field in 4624/4625 events), such as 3 Network, 10 RemoteInteractive (RDP), and what each means.",
    when: "You are analyzing Windows logon events and want to know whether a logon was console, network, RDP, service and so on.",
    example: { q: "rdp" },
  },
  "bt-logon-status": {
    what: "A searchable reference that decodes the Status / Sub Status hex codes in Windows 4625 failed-logon events (e.g. 0xC000006A = wrong password, 0xC0000234 = account locked).",
    when: "You are investigating failed logons and want to know exactly why each one failed.",
    example: { q: "password" },
  },
  "bt-kerberos-ref": {
    what: "A searchable reference of Kerberos ticket encryption types and common failure codes seen in Windows 4768/4769/4771 events (useful for spotting Kerberoasting and AS-REP roasting).",
    when: "You are analyzing Kerberos events and want to decode an encryption type or failure code.",
    example: { q: "rc4" },
  },
  "bt-win-eventlog-channels": {
    what: "A searchable reference of Windows event log channel names (Security, Sysmon/Operational, PowerShell/Operational and more) and the activity each holds.",
    when: "You are configuring log forwarding or writing a query and need the exact event log channel name.",
    example: { q: "powershell" },
  },
  "bt-sysmon-config": {
    what: "Builds a Sysmon configuration snippet that filters one event type on a field condition, with onmatch include or exclude. Sysmon configs decide which events get logged.",
    when: "You are tuning a Sysmon configuration and want a correctly structured RuleGroup element to add.",
    example: { event: "ProcessCreate", onmatch: "include", field: "Image", condition: "end with", value: "\\powershell.exe" },
  },
  "bt-auditd-rule": {
    what: "Builds a Linux auditd rule: either a file watch (alert when a path is written/read) or a syscall rule (alert on a system call like execve), tagged with a key for searching.",
    when: "You are configuring Linux audit logging and want a correct auditd rule line for a file or syscall.",
    example: { mode: "File watch", path: "/etc/passwd", perms: "wa", syscall: "execve", arch: "b64", key: "identity" },
  },
  "bt-falco-rule": {
    what: "Builds a Falco runtime-security rule in YAML with a condition, output message and priority. Falco watches system/container activity and alerts on suspicious behavior.",
    when: "You are writing a Falco rule for container or host runtime detection and want the YAML structure filled in.",
    example: { rule: "Shell in container", desc: "A shell was spawned inside a container", condition: "spawned_process and container and shell_procs", output: "Shell in container (user=%user.name container=%container.name cmd=%proc.cmdline)", priority: "WARNING", tags: "container, shell, mitre_execution" },
  },
  "bt-zeek-conn": {
    what: "A searchable reference of Zeek (Bro) conn.log fields and the connection-state (conn_state) values. Zeek is a network monitor whose conn.log summarizes every connection.",
    when: "You are analyzing Zeek network logs and need to know what a field or a conn_state like S0 or SF means.",
    example: { q: "state" },
  },
  "bt-jq-build": {
    what: "Builds a jq filter for working with JSON logs, for common operations like selecting by a field, picking fields, counting by a field, or flattening an array. jq is a command-line JSON processor.",
    when: "You are slicing JSON logs on the command line with jq and want the right filter without memorizing jq syntax.",
    example: { op: "select by field", field: "level", value: "error", fields: "ts, msg, src" },
  },
  "bt-iptables-ref": {
    what: "A searchable reference of common iptables options, chains and targets (the Linux netfilter firewall command).",
    when: "You are reading or writing iptables rules and need a reminder of a flag like --dport or a target like REJECT.",
    example: { q: "dport" },
  },
  "bt-iptables-build": {
    what: "Builds an iptables command from a chain, protocol, source, destination port, stateful match and target. iptables is the classic Linux firewall tool.",
    when: "You want a correct iptables rule to allow or block specific traffic without hand-writing the flags.",
    example: { chain: "INPUT", proto: "tcp", src: "203.0.113.0/24", dport: "22", state: true, target: "DROP" },
  },
  "bt-nftables-ref": {
    what: "A searchable reference of common nftables syntax for tables, chains and rules. nftables is the modern replacement for iptables on Linux.",
    when: "You are moving to or reading nftables and need the syntax for a table, base chain or rule.",
    example: { q: "chain" },
  },
  "bt-bruteforce-threshold": {
    what: "Estimates how long online password guessing would take against an account-lockout policy, given the password keyspace (charset and length) and how many attempts are allowed per lockout window.",
    when: "You are setting or reviewing a lockout policy and want to see how much it slows down online password guessing. It does not model offline cracking of a stolen hash.",
    example: { charset: "62", length: "8", attempts: "5", lockoutMin: "30" },
  },
  "bt-ratelimit-calc": {
    what: "Converts a request allowance (so many requests per window) into a sustained requests-per-second rate and token-bucket settings, and prints an nginx limit_req example.",
    when: "You are configuring a rate limit and want the equivalent per-second rate, burst and a sample config.",
    example: { limit: "100", window: "60", burst: "20" },
  },
  "bt-log-volume": {
    what: "Estimates events per second, daily ingest volume and total retained storage for a SIEM, from events per day, average event size, retention days and a compression percentage.",
    when: "You are sizing or budgeting a SIEM/log pipeline and want rough EPS and storage figures.",
    example: { perDay: "50000000", avgBytes: "500", retention: "90", compress: "70" },
  },
  "bt-base-rate": {
    what: "Shows how many of your alerts are actually true threats, given the daily event volume, how rare real threats are, your detection rate and your false-positive rate. It demonstrates why a tiny false-positive rate still buries real events (the base-rate fallacy).",
    when: "You are evaluating a detection and want to understand its real-world alert precision, not just its lab accuracy.",
    example: { perDay: "1000000", prevalence: "0.0001", sens: "95", fpr: "1" },
  },
  "bt-detection-metrics": {
    what: "Computes precision, recall, specificity, false-positive rate, accuracy and F1 from the four confusion-matrix counts (true/false positives and negatives).",
    when: "You tested a detection against labelled data and want the standard quality metrics from the counts.",
    example: { tp: "80", fp: "20", fn: "10", tn: "890" },
  },
  "bt-alert-dedup-key": {
    what: "Joins the fields you choose into one stable key for de-duplicating or grouping alerts, and can also give its SHA-1 hash. A consistent key lets a SIEM collapse repeats of the same alert.",
    when: "You want a reliable grouping/correlation key for an alert rule so identical alerts are merged instead of flooding.",
    example: { fields: "rule=ssh-bruteforce\nsrc=198.51.100.7\ndst=192.0.2.5", sep: "|", hash: true },
  },
  "bt-coverage-matrix": {
    what: "Counts how many of your detection rules map to each of the 14 MITRE ATT&CK tactics and highlights tactics with no coverage. You paste a list of 'Tactic | rule name' lines.",
    when: "You want a quick view of where your detections cover the ATT&CK tactics and where the gaps are.",
    example: { entries: "Initial Access | phishing-attachment\nExecution | suspicious-powershell\nExecution | wmic-exec\nPersistence | new-service\nExfiltration | large-dns-txt" },
  },
  "bt-attack-tactics": {
    what: "A searchable reference of the 14 MITRE ATT&CK Enterprise tactics with their IDs (like TA0001 Initial Access) and the goal each represents.",
    when: "You are mapping detections or reading a report and need the ATT&CK tactic names and IDs.",
    example: { q: "persistence" },
  },
  "bt-fp-triage": {
    what: "Generates a numbered false-positive triage checklist tailored to the alert type you pick (failed logons, port scan, malware, DNS, exfiltration, phishing, or generic).",
    when: "You caught an alert and want a consistent set of steps to decide whether it is a real threat or noise.",
    example: { type: "Failed logons / brute force" },
  },
  "bt-detection-doc": {
    what: "Produces a structured markdown documentation block for a detection rule: severity, data source, ATT&CK mapping, logic, known false positives, response steps and validation.",
    when: "You wrote a detection and need to document it consistently for your team or a rule repository.",
    example: { name: "Encoded PowerShell execution", source: "Sysmon EID 1 / Security 4688", logic: "Process powershell.exe with -EncodedCommand / -enc in the command line.", severity: "High", mitre: "T1059.001 (PowerShell)", fp: "Some admin tooling uses -enc legitimately.", response: "Decode the command, inspect, isolate host if malicious." },
  },
  "bt-ip-proto": {
    what: "A searchable reference of IANA IP protocol numbers (1 ICMP, 6 TCP, 17 UDP, and more) used in the protocol field of flow and firewall logs.",
    when: "You see a protocol number in a flow log or firewall log and want to know which protocol it is.",
    example: { q: "tcp" },
  },
  "bt-icmp-ref": {
    what: "A searchable reference of ICMPv4 message types and the codes for Destination Unreachable and Time Exceeded.",
    when: "You are analyzing ICMP traffic or firewall logs and want to decode an ICMP type or code.",
    example: { q: "unreachable" },
  },
  "bt-dns-rcode": {
    what: "A searchable reference of DNS response codes (0 NOERROR, 3 NXDOMAIN, 2 SERVFAIL, 5 REFUSED and more) for analyzing DNS logs.",
    when: "You are looking at DNS logs and want to know what a response code means.",
    example: { q: "nxdomain" },
  },
  "bt-ir-lifecycle": {
    what: "A searchable reference putting the NIST SP 800-61 incident-response phases next to the SANS PICERL phases so you can see how they line up.",
    when: "You are following or documenting an incident-response process and want the standard phase names.",
    example: { q: "containment" },
  },
  "bt-pyramid-of-pain": {
    what: "A searchable reference of David Bianco's Pyramid of Pain, showing indicator types from hashes up to TTPs and how much it hurts an adversary when you detect/block each level.",
    when: "You are prioritizing detection work and want to focus on indicators that cost attackers the most to change.",
    example: { q: "ttp" },
  },
};
