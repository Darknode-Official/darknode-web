// Web Gateway Hunt engine tests (public/js/ops/proxyhunt-engine.js): one parser test per vendor
// layout (verbatim lines), app catalogue matching, every detection positive and negative,
// robust z maths, business hours / time zone, Squid CONNECT limitation, determinism, exports.

import { test, assert, group } from "../harness.mjs";
import {
  selfTest, analyze, parseInput, exampleDataset, detectFile, findingsToCsv, shadowSaasCsv, blocklistText, userReportText, summaryText,
  matchHost, matchAppName, classify, robustZ, parseTime, hostOf, scriptedFamily, DEFAULTS, TOOL_ID,
} from "../../public/js/ops/proxyhunt-engine.js";

const MB = 1048576;
const T = "\t";

// Zscaler NSS QRadar LEEF (feed output layout; tab-delimited attributes).
const LEEF_LINE = "Oct 16 22:55:48 zscaler-nss: LEEF:1.0|Zscaler|NSSWeblog|5.0|Allowed|cat=Online Storage" + T + "devTime=Oct 16 2026 22:55:48 UTC" + T +
  "devTimeFormat=MMM dd yyyy HH:mm:ss z" + T + "src=10.20.0.12" + T + "dst=203.0.113.20" + T + "srcPostNAT=198.51.100.10" + T + "realm=HQ" + T +
  "usrName=bob@test.darknode.ai" + T + "srcBytes=157286400" + T + "dstBytes=812" + T + "role=Engineering" + T + "policy=Allowed" + T +
  "url=content.dropboxapi.com/2/files/upload" + T + "recordid=1" + T + "bwthrottle=NO" + T + "useragent=Mozilla/5.0 (Windows NT 10.0; Win64; x64)" + T + "referer=None" + T +
  "hostname=content.dropboxapi.com" + T + "appproto=HTTPS" + T + "urlcategory=Online Storage" + T + "urlsupercategory=Internet Communication" + T + "urlclass=Business Use" + T +
  "appclass=File Sharing" + T + "appname=Dropbox" + T + "malwaretype=None" + T + "malwareclass=None" + T + "threatname=None" + T + "riskscore=0" + T + "dlpdict=None" + T +
  "dlpengine=None" + T + "fileclass=None" + T + "filetype=None" + T + "reqmethod=POST" + T + "respcode=200";
const LEEF_ALIAS = "LEEF:1.0|Zscaler|NSSWeblog|5.0|Blocked|usrName=alice@test.darknode.ai" + T + "src=10.20.0.11" + T + "dst=203.0.113.5" + T + "url=pastebin.com/api/api_post.php" + T +
  "reqmethod=POST" + T + "respcode=403" + T + "reqsize=2048" + T + "respsize=512" + T + "urlcategory=Web Search" + T + "appname=Pastebin" + T + "appclass=General Browsing" + T +
  "action=Blocked" + T + "ua=curl/8.4.0" + T + "devTime=Oct 16 2026 10:00:00 GMT" + T + "filetype=None" + T + "dlpengine=None";
// Zscaler NSS ArcSight CEF.
const CEF_LINE = "CEF:0|Zscaler|NSSWeblog|5.0|Allowed|Allowed|3|act=Allowed reason=Allowed app=HTTPS dhost=pastebin.com dst=203.0.113.9 src=10.20.0.11 sourceTranslatedAddress=198.51.100.10 in=2048 out=5242880 request=https://pastebin.com/api/api_post.php requestContext=None outcome=200 requestClientApplication=Mozilla/5.0 requestMethod=POST suser=alice@test.darknode.ai spriv=Engineering externalId=7 fileType=None destinationServiceName=Pastebin cat=Web Search rt=Oct 16 2026 10:00:00";
// Squid native access.log (verbatim layout).
const SQUID_LINE = "1697447643.123    250 10.0.0.25 TCP_TUNNEL/200 12345 CONNECT drive.google.com:443 alice HIER_DIRECT/142.250.0.1 -";
const SQUID_DENIED = "1697447650.001      0 10.0.0.26 TCP_DENIED/403 3925 GET http://www.kproxy.com/ carol HIER_NONE/- text/html";
// Palo Alto Networks URL Filtering log export (Monitor > Logs > URL Filtering > Export to CSV).
const PAN_URL_HDR = "Domain,Receive Time,Serial #,Type,Threat/Content Type,Config Version,Generate Time,Source address,Destination address,NAT Source IP,NAT Destination IP,Rule,Source User,Destination User,Application,Virtual System,Source Zone,Destination Zone,Inbound Interface,Outbound Interface,Log Action,Time Logged,Session ID,Repeat Count,Source Port,Destination Port,NAT Source Port,NAT Destination Port,Flags,IP Protocol,Action,URL/Filename,Threat/Content Name,Category,Severity,Direction,Sequence Number,Action Flags,Source Country,Destination Country,Content Type,User Agent,HTTP Method";
const PAN_URL_ROW = "1,2026/10/16 10:00:00,013201001234,THREAT,url,2049,2026/10/16 10:00:00,10.20.0.13,203.0.113.44,198.51.100.10,0.0.0.0,allow-web,test\\carol,,dropbox-base,vsys1,trust,untrust,ethernet1/2,ethernet1/1,fwd,2026/10/16 10:00:00,40001,1,52311,443,40311,0,0x8000,tcp,alert,www.dropbox.com/upload,(9999),online-storage-and-backup,informational,client-to-server,7000001,0x0,10.0.0.0-10.255.255.255,US,,Mozilla/5.0,post";
const PAN_TRAFFIC_HDR = "Domain,Receive Time,Serial #,Type,Threat/Content Type,Config Version,Generate Time,Source address,Destination address,NAT Source IP,NAT Destination IP,Rule,Source User,Destination User,Application,Virtual System,Source Zone,Destination Zone,Inbound Interface,Outbound Interface,Log Action,Time Logged,Session ID,Repeat Count,Source Port,Destination Port,NAT Source Port,NAT Destination Port,Flags,IP Protocol,Action,Bytes,Bytes Sent,Bytes Received,Packets,Start Time,Elapsed Time (sec),Category";
const PAN_TRAFFIC_ROW = "1,2026/10/16 11:00:00,013201001234,TRAFFIC,end,2049,2026/10/16 11:00:00,10.20.0.14,203.0.113.45,198.51.100.10,0.0.0.0,allow-web,test\\dave,,mega,vsys1,trust,untrust,ethernet1/2,ethernet1/1,fwd,2026/10/16 11:00:00,40002,1,52312,443,40312,0,0x1c,tcp,allow,210000000,209715200,284800,140000,2026/10/16 10:40:00,1200,online-storage-and-backup";
// Netskope web transactions / page events CSV.
const NETSKOPE_HDR = "timestamp,user,srcip,dstip,url,domain,app,appcategory,ccl,activity,object,object_type,client_bytes,server_bytes,action,policy,instance_id";
const NETSKOPE_ROW = "1792152000,erin@test.darknode.ai,10.20.0.15,203.0.113.60,https://drive.google.com/upload/drive/v3/files,drive.google.com,Google Drive,Cloud Storage,high,Upload,q3-forecast.xlsx,File,157286400,4096,allow,Monitor-Uploads,personal";
// Cloudflare Gateway HTTP Logpush (NDJSON).
const CF_LINE = JSON.stringify({ Datetime: "2026-10-16T12:00:00Z", AccountID: "a1", Action: "allow", DestinationIP: "203.0.113.70", DestinationPort: 443, DeviceName: "WS-07", DownloadedFileNames: [], Email: "frank@test.darknode.ai", HTTPHost: "wetransfer.com", HTTPMethod: "POST", HTTPStatusCode: 200, HTTPVersion: "HTTP/2", PolicyName: "Allow all", Referer: "", RequestID: "r1", SourceIP: "198.51.100.10", SourceInternalIP: "10.20.0.16", SourcePort: 52000, URL: "https://wetransfer.com/api/v4/transfers", UploadedFileNames: ["design.zip"], UserAgent: "Mozilla/5.0", UserID: "u1" });
// Cisco Umbrella proxy log (S3 export, headerless), documented 37-field order (timestamp .. producer).
const UMB_LINE = '"2026-10-16 13:00:00","Grace Hall (grace@test.darknode.ai)","10.20.0.17","198.51.100.10","203.0.113.80","text/html","ALLOWED","https://pastebin.com/raw/abc","","Mozilla/5.0","200","8388608","1200","1200","","Paste Sites","","","","","","AD Users","","Grace Hall (grace@test.darknode.ai),WS-17","AD Users,Roaming Computer","POST","","","","","","","","","","",""';
// Umbrella optional V12 proxy header row (51 columns), as documented.
const UMB_V12_HDR = '"Timestamp","Policy Identity Label","Internal Client IP","External Client IP","Destination IP","Content Type","Action","URL","Referer","User Agent","Status Code","Request Size","Response Size","Response Body Size","SHA256 Hash","Categories","AV Detections","PUAs","AMP Disposition","AMP Malware Name","AMP Score","Policy Identity Type","Blocked Categories","Identities","Identity Types","Request Method","DLP Status","Certificate Errors","File Name","Ruleset ID","Rule ID","Destination List IDs","Isolate Action","File Action","Warn Status","Forwarding Method","Producer","MSP Organization ID","Geo Location Of Blocked Destination Countries","Application IDs","Host Name","Data Center","Egress","Server Name","Time Based Rule","Security Overridden","Detected Response File Type","Warn Categories","Organization ID","Application Entity Name","Application Entity Category"';
const UMB_V12_ROW = UMB_LINE + ',"","","","","","","","","","","","","",""';
// PAN-OS URL Filtering syslog (headerless), positions per the documented Format line, behind a syslog header.
const PAN_URL_SYSLOG = '<14>Oct 16 10:00:00 PA-test 1,2026/10/16 10:00:00,013201001234,THREAT,url,2049,2026/10/16 10:00:00,10.20.0.13,203.0.113.44,198.51.100.10,0.0.0.0,allow-web,test\\carol,,dropbox-base,vsys1,trust,untrust,ethernet1/2,ethernet1/1,fwd,,40001,1,52311,443,40311,0,0x8000,tcp,alert,"www.dropbox.com/upload",(9999),online-storage-and-backup,informational,client-to-server,7000001,0x0,10.0.0.0-10.255.255.255,US,,text/html,0,,,,"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",,,"https://www.dropbox.com/home",,,,,,,,,,PA-test,,,,post,,,,,,';
// Zscaler NSS Splunk key=value.
const ZKV_LINE = 'sourcetype="zscalernss-web"' + T + "datetime=Mon Oct 16 22:55:48 2026" + T + "reason=Allowed" + T + "event_id=1" + T + "protocol=HTTPS" + T + "action=Allowed" + T + "transactionsize=1000" + T + "responsesize=900" + T + "requestsize=100" + T + "urlcategory=Generative AI" + T + "serverip=203.0.113.90" + T + "requestmethod=POST" + T + "useragent=Mozilla/5.0" + T + "ClientIP=10.20.0.11" + T + "status=200" + T + "user=alice@test.darknode.ai" + T + "url=claude.ai/api/chat" + T + "vendor=Zscaler" + T + "hostname=claude.ai" + T + "appname=Claude" + T + "filetype=None";

const GEN_HDR = "ts,user,src_ip,dst_host,url,method,status,bytes_out,bytes_in,category,app,action,user_agent";
function gen(rows) {
  const q = (v) => (/[",\n]/.test(String(v)) ? '"' + String(v).replace(/"/g, '""') + '"' : String(v));
  return GEN_HDR + "\n" + rows.map((r) => [r.ts, r.user ?? "alice@test.darknode.ai", r.src ?? "10.20.0.11", r.host, r.url ?? "https://" + r.host + "/", r.method ?? "GET", r.status ?? 200, r.out ?? 1000, r.in ?? 5000, r.cat ?? "Business", r.app ?? "", r.action ?? "allowed", r.ua ?? "Mozilla/5.0"].map(q).join(",")).join("\n") + "\n";
}
const at = (d, h, m = 0) => new Date(Date.UTC(2026, 9, d, h, m, 0)).toISOString();
const run = (rows, opts) => analyze([{ name: "gen.csv", text: gen(rows) }], opts);
const rule = (r, id) => r.findings.filter((f) => f.rule === id);
// 10 weekday-ish baseline days of light activity for a user.
function baseline(user, days = 10, host = "intranet.test.darknode.ai", out = 1000) {
  const rows = [];
  for (let d = 1; d <= days; d++) rows.push({ ts: at(d, 10), user, host, out });
  return rows;
}

group("proxyhunt: parsers (one per vendor layout)", () => {
  test("Zscaler LEEF: detect, user, upload bytes, host, method, time", () => {
    const p = parseInput([{ name: "z.log", text: LEEF_LINE + "\n" }]);
    assert.equal(p.formats[0].format, "zscaler-leef");
    const e = p.rows[0];
    assert.equal(e.user, "bob@test.darknode.ai"); assert.equal(e.bytesOut, 157286400); assert.equal(e.bytesIn, 812);
    assert.equal(e.host, "content.dropboxapi.com"); assert.equal(e.method, "POST"); assert.equal(e.ts, Date.UTC(2026, 9, 16, 22, 55, 48));
    assert.equal(e.category, "Online Storage"); assert.equal(e.app, "Dropbox");
  });
  test("Zscaler LEEF with reqsize / respsize / ua keys", () => {
    const e = parseInput(LEEF_ALIAS).rows[0];
    assert.equal(e.bytesOut, 2048); assert.equal(e.bytesIn, 512); assert.equal(e.ua, "curl/8.4.0"); assert.equal(e.action, "Blocked"); assert.equal(e.host, "pastebin.com");
  });
  test("Zscaler CEF: out = upload, in = download, suser, request", () => {
    const p = parseInput(CEF_LINE);
    assert.equal(p.formats[0].format, "zscaler-cef");
    const e = p.rows[0];
    assert.equal(e.user, "alice@test.darknode.ai"); assert.equal(e.bytesOut, 5242880); assert.equal(e.bytesIn, 2048); assert.equal(e.host, "pastebin.com");
    assert.equal(e.method, "POST"); assert.equal(e.ts, Date.UTC(2026, 9, 16, 10, 0, 0));
  });
  test("Squid native: CONNECT gives host and total bytes only", () => {
    const p = parseInput(SQUID_LINE);
    assert.equal(p.formats[0].format, "squid");
    const e = p.rows[0];
    assert.equal(e.host, "drive.google.com"); assert.ok(e.connect); assert.equal(e.bytesTotal, 12345); assert.equal(e.bytesOut, null);
    assert.equal(e.elapsedMs, 250); assert.equal(e.src, "10.0.0.25"); assert.equal(e.user, "alice"); assert.equal(e.dst, "142.250.0.1"); assert.equal(e.ts, 1697447643123);
  });
  test("Squid native: TCP_DENIED is a block, reply bytes are download", () => {
    const e = parseInput(SQUID_DENIED).rows[0];
    assert.ok(/blocked/.test(e.action)); assert.equal(e.bytesIn, 3925); assert.equal(e.host, "www.kproxy.com"); assert.equal(e.user, "carol");
  });
  test("Palo Alto URL Filtering CSV export", () => {
    const p = parseInput([{ name: "url.csv", text: PAN_URL_HDR + "\n" + PAN_URL_ROW + "\n" }]);
    assert.equal(p.formats[0].format, "pan-url");
    const e = p.rows[0];
    assert.equal(e.host, "www.dropbox.com"); assert.equal(e.user, "test\\carol"); assert.equal(e.src, "10.20.0.13"); assert.equal(e.method, "POST");
    assert.equal(e.category, "online-storage-and-backup"); assert.equal(e.ts, Date.UTC(2026, 9, 16, 10, 0, 0));
  });
  test("Palo Alto Traffic CSV: Bytes Sent / Received, App-ID matched", () => {
    const p = parseInput([{ name: "traffic.csv", text: PAN_TRAFFIC_HDR + "\n" + PAN_TRAFFIC_ROW + "\n" }]);
    assert.equal(p.formats[0].format, "pan-traffic");
    const e = p.rows[0];
    assert.equal(e.bytesOut, 209715200); assert.equal(e.bytesIn, 284800); assert.equal(e.bytesTotal, null); assert.equal(e.app, "mega");
    const r = analyze([{ name: "traffic.csv", text: PAN_TRAFFIC_HDR + "\n" + PAN_TRAFFIC_ROW + "\n" }]);
    assert.equal(rule(r, "upload_exfil").length, 1);
  });
  test("Netskope CSV: client_bytes upload, personal instance", () => {
    const text = NETSKOPE_HDR + "\n" + NETSKOPE_ROW + "\n";
    const p = parseInput([{ name: "ns.csv", text }]);
    assert.equal(p.formats[0].format, "netskope");
    const e = p.rows[0];
    assert.equal(e.bytesOut, 157286400); assert.equal(e.instance, "personal"); assert.equal(e.ts, 1792152000000); assert.equal(e.host, "drive.google.com");
    const r = analyze([{ name: "ns.csv", text }]);
    const f = rule(r, "upload_exfil")[0];
    assert.ok(f && f.description.includes("Google Drive (personal)"));
  });
  test("Cloudflare Gateway HTTP Logpush NDJSON and JSON array", () => {
    const p = parseInput([{ name: "cf.json", text: CF_LINE + "\n" + CF_LINE + "\n" }]);
    assert.equal(p.formats[0].format, "cloudflare");
    assert.equal(p.rows.length, 2);
    const e = p.rows[0];
    assert.equal(e.user, "frank@test.darknode.ai"); assert.equal(e.host, "wetransfer.com"); assert.equal(e.method, "POST"); assert.equal(e.uploaded, "design.zip"); assert.equal(e.bytesOut, null);
    assert.equal(parseInput([{ name: "cf.json", text: "[" + CF_LINE + "]" }]).rows.length, 1);
  });
  test("Cisco Umbrella headerless proxy CSV", () => {
    const p = parseInput([{ name: "umb.csv", text: UMB_LINE + "\n" }]);
    assert.equal(p.formats[0].format, "umbrella-nohdr");
    const e = p.rows[0];
    assert.equal(e.user, "grace@test.darknode.ai"); assert.equal(e.bytesOut, 8388608); assert.equal(e.host, "pastebin.com"); assert.equal(e.action, "ALLOWED");
  });
  test("Cisco Umbrella headerless proxy CSV reads documented positions incl. request method", () => {
    const e = parseInput([{ name: "umb.csv", text: UMB_LINE + "\n" }]).rows[0];
    assert.equal(e.method, "POST"); assert.equal(e.ua, "Mozilla/5.0"); assert.equal(e.status, "200"); assert.equal(e.category, "Paste Sites"); assert.equal(e.src, "10.20.0.17"); assert.equal(e.dst, "203.0.113.80");
  });
  test("Cisco Umbrella proxy CSV with the optional V12 header", () => {
    const p = parseInput([{ name: "umb12.csv", text: UMB_V12_HDR + "\n" + UMB_V12_ROW + "\n" }]);
    assert.equal(p.formats[0].format, "umbrella");
    const e = p.rows[0];
    assert.equal(e.user, "grace@test.darknode.ai"); assert.equal(e.src, "10.20.0.17"); assert.equal(e.host, "pastebin.com"); assert.equal(e.method, "POST"); assert.equal(e.bytesOut, 8388608); assert.equal(e.action, "ALLOWED");
  });
  test("PAN-OS URL Filtering syslog (headerless CSV) by documented positions", () => {
    const p = parseInput([{ name: "pan-url.log", text: PAN_URL_SYSLOG + "\n" }]);
    assert.equal(p.formats[0].format, "pan-url-syslog");
    const e = p.rows[0];
    assert.equal(e.src, "10.20.0.13"); assert.equal(e.dst, "203.0.113.44"); assert.equal(e.host, "www.dropbox.com"); assert.equal(e.app, "dropbox-base");
    assert.equal(e.category, "online-storage-and-backup"); assert.equal(e.ua, "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"); assert.equal(e.method, "POST");
    assert.ok(/carol$/.test(e.user)); assert.equal(e.ts, Date.UTC(2026, 9, 16, 10, 0, 0));
  });
  test("Zscaler Splunk key=value", () => {
    const p = parseInput([{ name: "zkv.log", text: ZKV_LINE + "\n" }]);
    assert.equal(p.formats[0].format, "zscaler-kv");
    const e = p.rows[0];
    assert.equal(e.user, "alice@test.darknode.ai"); assert.equal(e.host, "claude.ai"); assert.equal(e.bytesOut, 100); assert.equal(e.ts, Date.UTC(2026, 9, 16, 22, 55, 48));
  });
  test("generic CSV: high confidence when ts, user and host resolve", () => {
    const d = detectFile("g.csv", gen([{ ts: at(1, 10), host: "a.test" }]));
    assert.equal(d.format, "generic-csv"); assert.ok(d.confidence >= 0.8);
  });
  test("generic CSV with odd headers: low confidence, mapping overrides read it", () => {
    const text = "when,who,dest,up\n2026-10-01T10:00:00Z,alice@test.darknode.ai,mega.nz,209715200\n";
    const d = detectFile("odd.csv", text);
    assert.ok(d.confidence < 0.8);
    const r = analyze([{ name: "odd.csv", text }], { columns: { ts: "when", user: "who", host: "dest", bytesOut: "up" } });
    assert.equal(rule(r, "upload_exfil").length, 1);
  });
  test("unrecognised text is reported in skipped, not guessed", () => {
    const r = analyze([{ name: "x.bin", text: "hello" }]);
    assert.ok(r.skipped.some((s) => s.check === "parse"));
    assert.equal(r.findings.length, 0);
  });
});

group("proxyhunt: app catalogue", () => {
  test("longest suffix wins", () => {
    assert.equal(matchHost("content.dropboxapi.com").app, "Dropbox");
    assert.equal(matchHost("mail.google.com").app, "Gmail");
    assert.equal(matchHost("www.google.com"), null);
    assert.equal(matchHost("gemini.google.com").category, "genai");
    assert.equal(matchHost("gemini.com").category, "crypto");
    assert.equal(matchHost("abc.ngrok-free.app").category, "tunnel");
    assert.equal(matchHost("notdropbox.com"), null);
    assert.equal(matchHost("203.0.113.5"), null);
  });
  test("gateway application names map to the catalogue", () => {
    assert.equal(matchAppName("dropbox-base").app, "Dropbox");
    assert.equal(matchAppName("ChatGPT").category, "genai");
    assert.equal(matchAppName("teamviewer-base").category, "remote");
  });
  test("SharePoint tenant: own tenant is corporate, others are named", () => {
    const o = { tenants: new Set(["darknode"]), ownDomains: ["darknode.ai"], sanctioned: [] };
    const own = classify({ host: "darknode-my.sharepoint.com", app: "", instance: "" }, o);
    assert.equal(own.sanctioned, "yes"); assert.equal(own.instance, "corporate");
    const other = classify({ host: "rival.sharepoint.com", app: "", instance: "" }, o);
    assert.equal(other.sanctioned, "no"); assert.ok(other.app.includes("tenant rival"));
  });
  test("mixed services are 'unknown' until listed as sanctioned", () => {
    const o0 = { tenants: new Set(), ownDomains: [], sanctioned: [] };
    assert.equal(classify({ host: "drive.google.com", app: "", instance: "" }, o0).sanctioned, "unknown");
    assert.equal(classify({ host: "box.com", app: "", instance: "" }, o0).sanctioned, "unknown");
    assert.equal(classify({ host: "drive.google.com", app: "", instance: "" }, { ...o0, sanctioned: ["drive.google.com"] }).sanctioned, "yes");
    assert.equal(classify({ host: "www.dropbox.com", app: "", instance: "" }, { ...o0, sanctioned: ["dropbox"] }).sanctioned, "yes");
    assert.equal(classify({ host: "www.dropbox.com", app: "", instance: "" }, o0).sanctioned, "no");
  });
});

group("proxyhunt: detections", () => {
  test("upload exfil fires at exactly the absolute threshold", () => {
    const r = run([{ ts: at(5, 10), host: "mega.nz", method: "POST", out: 100 * MB }]);
    const f = rule(r, "upload_exfil");
    assert.equal(f.length, 1); assert.equal(f[0].severity, "high"); assert.equal(f[0].confidence, "likely");
    assert.ok(f[0].controls.some((c) => c.id === "T1567.002"));
  });
  test("upload exfil stays silent one byte below the threshold", () => {
    const r = run([{ ts: at(5, 10), host: "mega.nz", method: "POST", out: 100 * MB - 1 }]);
    assert.equal(rule(r, "upload_exfil").length, 0);
  });
  test("robust z rule fires against the user's own baseline", () => {
    const rows = [];
    for (let d = 1; d <= 9; d++) rows.push({ ts: at(d, 10), host: "mega.nz", method: "POST", out: 100000 + d * 1000 });
    rows.push({ ts: at(12, 10), host: "mega.nz", method: "POST", out: 30 * MB });
    const f = rule(run(rows), "upload_exfil");
    assert.equal(f.length, 1); assert.equal(f[0].confidence, "review"); assert.ok(/robust z/.test(f[0].description));
  });
  test("z rule refuses with fewer than the minimum baseline days", () => {
    const rows = [];
    for (let d = 1; d <= 3; d++) rows.push({ ts: at(d, 10), host: "mega.nz", method: "POST", out: 100000 });
    rows.push({ ts: at(12, 10), host: "mega.nz", method: "POST", out: 30 * MB });
    assert.equal(rule(run(rows), "upload_exfil").length, 0);
  });
  test("sanctioned apps are excluded from exfiltration", () => {
    const r = run([{ ts: at(5, 10), host: "mega.nz", method: "POST", out: 500 * MB }], { sanctioned: "MEGA" });
    assert.equal(rule(r, "upload_exfil").length, 0);
  });
  test("POST counts stand in when bytes are not logged (Cloudflare)", () => {
    const lines = [];
    for (let i = 0; i < 25; i++) lines.push(CF_LINE.replace("12:00:00", "12:" + String(i).padStart(2, "0") + ":00"));
    const r = analyze([{ name: "cf.json", text: lines.join("\n") }]);
    const f = rule(r, "upload_writes");
    assert.equal(f.length, 1); assert.equal(f[0].severity, "medium"); assert.ok(/does not record upload bytes/.test(f[0].description));
    assert.ok(r.skipped.some((s) => s.check === "upload_volume"));
    const r2 = analyze([{ name: "cf.json", text: lines.slice(0, 5).join("\n") }]);
    assert.equal(rule(r2, "upload_writes").length, 0);
  });
  test("generative AI: inventory plus medium finding on a large upload", () => {
    const rows = [{ ts: at(3, 10), host: "claude.ai", method: "POST", out: 12 * MB }, { ts: at(3, 11), user: "bob@test.darknode.ai", host: "chatgpt.com", method: "POST", out: 20000 }];
    const r = run(rows);
    assert.equal(rule(r, "genai_inventory").length, 1); assert.equal(rule(r, "genai_inventory")[0].severity, "info");
    const g = rule(r, "genai_upload");
    assert.equal(g.length, 1); assert.equal(g[0].severity, "medium"); assert.equal(g[0].userKey, "alice@test.darknode.ai");
    assert.equal(r.summary.aiServices, 2); assert.equal(r.summary.aiUsers, 2);
  });
  test("tunnel from a server range is high; from a user is medium", () => {
    const rows = [{ ts: at(3, 2), src: "10.50.0.12", user: "", host: "abc.ngrok-free.app" }, { ts: at(3, 10), host: "xyz.trycloudflare.com" }];
    const r = run(rows, { serverCidrs: "10.50.0.0/24" });
    const srv = rule(r, "tunnel_server"), usr = rule(r, "tunnel_user");
    assert.equal(srv.length, 1); assert.equal(srv[0].severity, "high");
    assert.equal(usr.length, 1); assert.equal(usr[0].severity, "medium");
  });
  test("remote access: medium for users, lowered when every request was blocked", () => {
    const r = run([{ ts: at(3, 10), host: "router7.teamviewer.com" }, { ts: at(3, 10), user: "bob@test.darknode.ai", src: "10.20.0.12", host: "net.anydesk.com", action: "blocked" }]);
    const f = rule(r, "remote_user");
    assert.equal(f.length, 2);
    assert.equal(f.find((x) => x.title.includes("TeamViewer")).severity, "medium");
    assert.equal(f.find((x) => x.title.includes("AnyDesk")).severity, "low");
  });
  test("malicious destination IP: high when listed, skipped without a list", () => {
    const rows = [{ ts: at(3, 10), host: "update-k2.test", url: "http://update-k2.test/a" }];
    const text = "ts,user,src_ip,dst_ip,dst_host,url\n" + at(3, 10) + ",alice@test.darknode.ai,10.20.0.11,203.0.113.66,update-k2.test,http://update-k2.test/a\n";
    const r = analyze([{ name: "m.csv", text }], { maliciousIps: [{ ip: "203.0.113.66", source: "ipsum", score: 9 }] });
    assert.equal(rule(r, "malicious_ip").length, 1); assert.equal(rule(r, "malicious_ip")[0].severity, "high");
    const r2 = run(rows);
    assert.ok(r2.skipped.some((s) => s.check === "malicious_destination"));
    const r3 = analyze([{ name: "m.csv", text }], { maliciousIps: ["198.51.100.1"] });
    assert.equal(rule(r3, "malicious_ip").length, 0);
  });
  test("uncategorized destination with high upload fires; categorized one does not", () => {
    const r = run([{ ts: at(3, 10), host: "q7vxk2lm-cdn.test", method: "POST", out: 60 * MB, cat: "Miscellaneous or Unknown" }]);
    assert.equal(rule(r, "uncat_upload").length, 1);
    const r2 = run([{ ts: at(3, 10), host: "partner.test.darknode.ai", method: "POST", out: 60 * MB, cat: "Business and Economy" }]);
    assert.equal(rule(r2, "uncat_upload").length, 0);
    const r3 = run([{ ts: at(3, 10), host: "q7vxk2lm-cdn.test", method: "POST", out: 40 * MB, cat: "Miscellaneous or Unknown" }]);
    assert.equal(rule(r3, "uncat_upload").length, 0);
  });
  test("executable from a public IP fires; from an internal IP does not", () => {
    const r = run([{ ts: at(3, 10), host: "203.0.113.77", url: "http://203.0.113.77/update/agent.exe" }]);
    assert.equal(rule(r, "ip_executable").length, 1); assert.equal(rule(r, "ip_executable")[0].severity, "high");
    const r2 = run([{ ts: at(3, 10), host: "10.1.1.5", url: "http://10.1.1.5/tools/agent.exe" }]);
    assert.equal(rule(r2, "ip_executable").length, 0);
    const r3 = run([{ ts: at(3, 10), host: "203.0.113.77", url: "http://203.0.113.77/index.html" }]);
    assert.equal(rule(r3, "ip_executable").length, 0);
  });
  test("blocked-attempt spike per user per hour", () => {
    const rows = [];
    for (let i = 0; i < 35; i++) rows.push({ ts: at(4, 13, i), host: "site" + (i % 7) + ".test", action: "blocked" });
    assert.equal(rule(run(rows), "blocked_spike").length, 1);
    assert.equal(rule(run(rows.slice(0, 20)), "blocked_spike").length, 0);
    const sameHost = rows.map((r) => ({ ...r, host: "one.test" }));
    assert.equal(rule(run(sameHost), "blocked_spike").length, 0);
  });
  test("scripted user agents: workstation fires, dev hosts and servers do not", () => {
    const mk = (host, src, user) => [0, 1, 2, 3].map((i) => ({ ts: at(3, 10, i), host, ua: "python-requests/2.31.0", src, user }));
    assert.equal(rule(run(mk("q7vxk2lm-cdn.test")), "scripted_ua").length, 1);
    assert.equal(rule(run(mk("pypi.org")), "scripted_ua").length, 0);
    assert.equal(rule(run(mk("q7vxk2lm-cdn.test", "10.50.0.12", "")), "scripted_ua").length, 0);
    assert.equal(rule(run(mk("q7vxk2lm-cdn.test"), { allowHosts: "q7vxk2lm-cdn.test" }), "scripted_ua").length, 0);
    assert.equal(scriptedFamily("Mozilla/5.0 (Windows NT 10.0; Microsoft Windows 10.0.19045; en-US) WindowsPowerShell/5.1.19041.3031"), "PowerShell");
    assert.equal(scriptedFamily("Go-http-client/1.1"), "Go-http-client");
    assert.equal(scriptedFamily("Mozilla/5.0 Chrome/129.0"), null);
  });
  test("empty user agent from a client is listed above the minimum", () => {
    const rows = [];
    for (let i = 0; i < 25; i++) rows.push({ ts: at(3, 10, i), host: "beacon-z.test", ua: "" });
    assert.equal(rule(run(rows), "empty_ua").length, 1);
    assert.equal(rule(run(rows.slice(0, 10)), "empty_ua").length, 0);
  });
  test("off-hours upload: fires at 02:00 UTC, silent when the time zone makes it business hours", () => {
    const rows = [{ ts: at(7, 2), host: "partner.test.darknode.ai", method: "POST", out: 150 * MB, cat: "Business" }];
    assert.equal(rule(run(rows), "offhours_upload").length, 1);
    // 02:00 UTC is 10:00 at UTC+8 (Wednesday) -> business hours
    assert.equal(rule(run(rows, { utcOffset: 8 }), "offhours_upload").length, 0);
  });
  test("weekend counts as off-hours unless disabled", () => {
    const rows = [{ ts: at(10, 11), host: "partner.test.darknode.ai", method: "POST", out: 150 * MB, cat: "Business" }]; // Saturday 2026-10-10
    assert.equal(rule(run(rows), "offhours_upload").length, 1);
    assert.equal(rule(run(rows, { weekendOffHours: false }), "offhours_upload").length, 0);
  });
  test("long CONNECT tunnel to a rare host (Squid)", () => {
    const line = (host, user) => "1792152000.000 3600000 10.20.0.30 TCP_TUNNEL/200 188743680 CONNECT " + host + ":443 " + user + " HIER_DIRECT/203.0.113.150 -";
    const r = analyze([{ name: "s.log", text: line("odd-k9.test", "zed") + "\n" }]);
    assert.equal(rule(r, "long_tunnel").length, 1);
    const many = ["u1", "u2", "u3"].map((u) => line("busy.test", u)).join("\n");
    assert.equal(rule(analyze([{ name: "s.log", text: many }]), "long_tunnel").length, 0);
    const short = "1792152000.000 60000 10.20.0.30 TCP_TUNNEL/200 188743680 CONNECT odd-k9.test:443 zed HIER_DIRECT/203.0.113.150 -";
    assert.equal(rule(analyze([{ name: "s.log", text: short }]), "long_tunnel").length, 0);
  });
  test("Squid CONNECT byte limitation is reported in skipped", () => {
    const r = analyze([{ name: "s.log", text: SQUID_LINE + "\n" + SQUID_DENIED + "\n" }]);
    const s = r.skipped.find((x) => x.check === "upload_volume (Squid native)");
    assert.ok(s && /both directions/.test(s.reason) && /%>st/.test(s.reason));
  });
  test("new app inside the recent window; skipped on a short log", () => {
    const rows = baseline("alice@test.darknode.ai", 20);
    rows.push({ ts: at(19, 10), host: "wetransfer.com", method: "POST", out: 1000 });
    assert.equal(rule(run(rows), "new_app").length, 1);
    const r2 = run([{ ts: at(1, 10), host: "wetransfer.com" }, { ts: at(3, 10), host: "intranet.test.darknode.ai" }]);
    assert.ok(r2.skipped.some((s) => s.check === "new_app"));
  });
  test("shadow SaaS inventory counts users per app", () => {
    const r = run([{ ts: at(3, 10), host: "mega.nz" }, { ts: at(3, 11), user: "bob@test.darknode.ai", host: "mega.nz" }, { ts: at(3, 12), host: "pastebin.com" }]);
    const mega = r.tables.apps.find((a) => a.app === "MEGA");
    assert.equal(mega.users, 2); assert.equal(mega.sanctioned, "no");
    assert.equal(r.summary.unsanctionedApps, 2);
    assert.equal(rule(r, "shadow_saas").length, 1);
  });
});

group("proxyhunt: maths, time and helpers", () => {
  test("robust z: MAD, MeanAD fallback and constant baseline", () => {
    const a = robustZ(10, [1, 2, 3, 4, 5]);
    assert.equal(a.method, "MAD"); assert.ok(Math.abs(a.z - 0.6745 * 7) < 1e-9);
    const b = robustZ(10, [0, 0, 0, 0, 0, 0, 5]);
    assert.equal(b.method, "MeanAD"); assert.ok(Math.abs(b.z - 10 / (1.253314 * (5 / 7))) < 1e-9);
    const c = robustZ(10, [0, 0, 0]);
    assert.equal(c.z, null); assert.equal(c.method, "constant");
  });
  test("timestamp formats", () => {
    assert.equal(parseTime("1697447643.123"), 1697447643123);
    assert.equal(parseTime("1792152000"), 1792152000000);
    assert.equal(parseTime("1792152000000000000"), 1792152000000);
    assert.equal(parseTime("2026/10/16 10:00:00"), Date.UTC(2026, 9, 16, 10));
    assert.equal(parseTime("Oct 16 2026 22:55:48 UTC"), Date.UTC(2026, 9, 16, 22, 55, 48));
    assert.equal(parseTime("2026-10-16T10:00:00+02:00"), Date.UTC(2026, 9, 16, 8));
    assert.equal(parseTime("16/Oct/2026:10:00:00 +0000"), Date.UTC(2026, 9, 16, 10));
    assert.equal(parseTime("garbage"), null);
  });
  test("host extraction", () => {
    assert.equal(hostOf("https://User@Drive.Google.com:443/x?y"), "drive.google.com");
    assert.equal(hostOf("drive.google.com:443"), "drive.google.com");
    assert.equal(hostOf("www.dropbox.com/upload"), "www.dropbox.com");
    assert.equal(hostOf("http://[2001:db8::1]/a.exe"), "2001:db8::1");
  });
  test("business day buckets follow the configured time zone", () => {
    const rows = [{ ts: "2026-10-05T23:30:00Z", host: "mega.nz", method: "POST", out: 60 * MB }, { ts: "2026-10-06T00:30:00Z", host: "mega.nz", method: "POST", out: 60 * MB }];
    assert.equal(rule(run(rows), "upload_exfil").length, 0); // two UTC days of 60 MB
    assert.equal(rule(run(rows, { utcOffset: 2 }), "upload_exfil").length, 1); // one local day of 120 MB
  });
});

group("proxyhunt: contract", () => {
  test("in-engine self-test passes", () => {
    const r = selfTest();
    assert.ok(r.pass, "failed: " + r.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
  });
  test("analyze is deterministic (byte-identical JSON)", () => {
    const ex = exampleDataset();
    assert.equal(JSON.stringify(analyze(ex.files)), JSON.stringify(analyze(exampleDataset().files)));
  });
  test("example dataset is synthetic, format-faithful and uses safe addresses", () => {
    const ex = exampleDataset();
    assert.ok(/synthetic/.test(ex.label));
    assert.equal(detectFile(ex.files[0].name, ex.files[0].text).format, "zscaler-leef");
    assert.equal(detectFile(ex.files[1].name, ex.files[1].text).format, "squid");
    const ips = (ex.files[0].text + ex.files[1].text).match(/(?<![\/\w.])\d+\.\d+\.\d+\.\d+\b/g);
    assert.ok(ips.every((ip) => /^(10\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)/.test(ip)), "non-documentation IP present");
    const r = analyze(ex.files);
    assert.ok(r.findings.every((f) => f.controls.length >= 1 && f.evidence.length <= 50 && ["confirmed", "likely", "review"].includes(f.confidence)));
  });
  test("empty input yields zero findings and does not throw", () => {
    const parsed = parseInput("");
    assert.equal(parsed.rows.length, 0);
    const r = analyze(parsed.rows);
    assert.equal(r.findings.length, 0); assert.equal(r.meta.rows, 0);
  });
  test("rows input (already parsed) gives the same findings as text input", () => {
    const files = [{ name: "z.log", text: LEEF_LINE + "\n" }];
    const a = analyze(files), b = analyze(parseInput(files).rows);
    assert.deepEqual(a.findings.map((f) => f.id), b.findings.map((f) => f.id));
  });
  test("missing columns are skipped with reasons", () => {
    const r = analyze([{ name: "h.csv", text: "ts,user,host\n" + at(1, 10) + ",alice@test.darknode.ai,mega.nz\n" }]);
    const checks = r.skipped.map((s) => s.check);
    for (const c of ["upload_volume", "blocked_spike", "scripted_user_agent", "malicious_destination", "long_connect_tunnel"]) assert.ok(checks.includes(c), c);
  });
  test("evidence is capped at 50 with the full count kept", () => {
    const rows = [];
    for (let i = 0; i < 80; i++) rows.push({ ts: at(5, 10, i % 60), host: "mega.nz", method: "POST", out: 2 * MB });
    const f = rule(run(rows), "upload_exfil")[0];
    assert.equal(f.evidence.length, 50); assert.equal(f.evidenceCount, 80);
  });
  test("progress is reported and optional", () => {
    const calls = [];
    analyze(exampleDataset().files, {}, { progress: (i, n, l) => calls.push([i, n, l]) });
    assert.ok(calls.length >= 2); assert.equal(calls[calls.length - 1][0], calls[calls.length - 1][1]);
  });
  test("findingsToCsv header row and escaping", () => {
    const csv = findingsToCsv([{ id: "x", severity: "high", confidence: "likely", category: "c", title: 'a "quoted", title', controls: [{ framework: "MITRE", id: "T1567" }], evidence: [], evidenceCount: 3 }]);
    const lines = csv.trim().split("\n");
    assert.equal(lines[0], "id,severity,confidence,category,title,entity,description,recommendation,controls,evidenceCount,firstSeen,lastSeen");
    assert.ok(lines[1].includes('"a ""quoted"", title"') && lines[1].includes('"MITRE T1567"') && lines[1].includes('"3"'));
  });
  test("shadow-SaaS CSV, blocklist, per-user report and summary", () => {
    const r = analyze(exampleDataset().files);
    assert.ok(shadowSaasCsv(r.tables.apps).startsWith("app,category,sanctioned,instance,domains,users"));
    const bl = blocklistText(r.findings);
    assert.ok(bl.includes("k7q2vx.ngrok-free.app")); assert.ok(!bl.includes("dropbox")); assert.ok(bl.includes("203.0.113.77"));
    const rep = userReportText(r);
    assert.ok(rep.includes("== user02@test.darknode.ai") && rep.includes("Large upload"));
    assert.ok(summaryText(r).includes("Web Gateway Hunt summary"));
  });
  test("defaults and tool id", () => {
    assert.equal(TOOL_ID, "proxyhunt"); assert.equal(DEFAULTS.uploadMb, 100); assert.equal(DEFAULTS.uploadZ, 4); assert.equal(DEFAULTS.newAppDays, 7);
  });
});
