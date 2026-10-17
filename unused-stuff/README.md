# Unused stuff

Archived code that the live site no longer uses. Nothing in this folder is deployed:
Firebase Hosting serves only `public/`. The code scanner, tests, lint and line counts
also skip this folder.

## removed-duplicates/

These are tools removed in the duplicate-tool cleanup of 2026-10-17. Each one did the same job
as another tool. Its useful features were merged into the tool that stayed, and old links
redirect there through the `ALIAS` map in `public/js/auth.js`. Files are restored from commit
`c705d792`, the last commit before the cleanup, at their original paths under `public/`.

| File | Route -> where it went |
|---|---|
| `data/firewall-rules.js` | no route (nothing used it) |
| `js/api-security-scanner.js` | `apiscan` -> `apifuzzer` |
| `js/attack-surface-mapper.js` | `attacksurf` -> `posture` |
| `js/breach-simulator.js` | `breachsim` -> `incidentcost` |
| `js/case-manager.js` | `casemgmt` -> `investigation` |
| `js/cert-analyzer.js` | no route (nothing used it) |
| `js/chess.js` | no route (nothing used it) |
| `js/cloud-security.js` | no route (nothing used it) |
| `js/container-security.js` | `containers` -> `iacscan` |
| `js/cred-auditor.js` | no route (nothing used it) |
| `js/crypto-engine.js` | no route (nothing used it) |
| `js/crypto-playground.js` | no route (nothing used it) |
| `js/crypto-toolkit.js` | no route (nothing used it) |
| `js/darkweb-osint.js` | `darkwebosint` -> `darknetradar` |
| `js/dns-recon.js` | `dnsrecon` -> `dns` |
| `js/dns-toolkit.js` | `dns` |
| `js/downloads.js` | no route (nothing used it) |
| `js/email-intel.js` | `emailintel` -> `emailheader` |
| `js/encoding-toolkit.js` | no route (nothing used it) |
| `js/exploit-db-browser.js` | no route (nothing used it) |
| `js/firewall-rules.js` | no route (nothing used it) |
| `js/forensics-tools.js` | no route (nothing used it) |
| `js/hash-lookup.js` | no route (nothing used it) |
| `js/hash-toolkit.js` | no route (nothing used it) |
| `js/http-inspector.js` | `httpinspector` -> `headeranalyzer` |
| `js/http-probe.js` | `httpprobe` -> `headeranalyzer` |
| `js/incident-response.js` | `incidentresponse` -> `incidents` |
| `js/ioc-extractor.js` | `iocextractor` -> `iocenrich` |
| `js/ip-geolocation.js` | `ipgeolocation` -> `addressintel` |
| `js/ip-reputation.js` | `ipreputation` -> `addressintel` |
| `js/ip-tools.js` | `iptools` -> `networktools` |
| `js/jwt-analyzer.js` | `jwtanalyzer` -> `tool-w-jwt-analyzer` |
| `js/log-forensics.js` | no route (nothing used it) |
| `js/log-parser.js` | no route (nothing used it) |
| `js/malware-sandbox.js` | `sandbox` -> `malclass` |
| `js/network-traffic.js` | `networktraffic` -> `phantom` |
| `js/osint-email.js` | `osintemail` -> `osint/email` |
| `js/packet-inspector.js` | `packetinspector` -> `packetanalyzer` |
| `js/password-analyzer.js` | no route (nothing used it) |
| `js/password-tools.js` | `passwordtools` -> `credaudit` |
| `js/phishing-analyzer.js` | `phishing` -> `phishtriage` |
| `js/purple-team-ops.js` | `purpleteam` -> `adversaryplaybook` |
| `js/report-builder.js` | no route (nothing used it) |
| `js/reverse-engineering.js` | `reveng` -> `binanalyze` |
| `js/risk-calculator.js` | `riskcalculator` -> `riskreg` |
| `js/sec-checklist.js` | `secchecklist` -> `compliance` |
| `js/security-scanner.js` | `securityscanner` -> `headeranalyzer` |
| `js/siem-dash.js` | `siemdash` -> `loghunt` |
| `js/ssl-cert-analyzer.js` | no route (nothing used it) |
| `js/subdomain-enum.js` | no route (nothing used it) |
| `js/subdomain-scanner.js` | no route (nothing used it) |
| `js/subnet-visualizer.js` | `subnetvisualizer` -> `networktools` |
| `js/threat-dashboard.js` | `threatdashboard` -> `cyberbriefing` |
| `js/threat-feed-aggregator.js` | no route (nothing used it) |
| `js/threat-feed.js` | `threatfeed` -> `cvesearch` |
| `js/threat-hunt.js` | no route (nothing used it) |
| `js/timeline-viz.js` | `timelineviz` -> `ftimeline` |
| `js/traffic-analyzer.js` | `trafficanalyzer` -> `phantom` |
| `js/utils.js` | `utils` -> `toolbox` |
| `js/vms.js` | `vms` -> `targets` |
| `js/vulnerability-prioritizer.js` | `vulnprio` -> `vulnimport` |
| `js/vuln-triage.js` | `vulntriage` -> `vulnimport` |
| `js/webshell.js` | `webshell` -> `pentestconsole` |
| `js/whois-recon.js` | `whoisrecon` -> `dossier` |

## mini-tools-before-merge/

These are the Toolbox mini-tool files as they were before 110 duplicate mini-tools were
removed (902 -> 792). The removed tool ids still open their replacements through
`TOOL_ALIAS` / `ROUTE_ALIAS` in `public/js/mini-tools.js`.

## Restoring something

These are plain copies, so to bring a tool back, copy it into `public/` and re-register its
route. The git history also has every version, e.g. `git show c705d792:public/js/<file>`.
