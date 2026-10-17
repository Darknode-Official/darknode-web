// Remote Access Audit engine tests (public/js/identity/vpnaudit-engine.js): one parser
// fixture per vendor format (lines / headers in the vendor layout), session
// reconstruction, every detection on a positive and a negative, threshold edges,
// time zones, roster matching, service-account exclusion, skipped-check reporting,
// determinism, exports and the self-test. Pure logic only.

import { test, assert, group } from "../harness.mjs";
import {
  TOOL_ID, DEFAULTS, COLUMNS, parseInput, classifyText, analyze, findingsToCsv, revocationCsv, blocklistText, userReportText, summaryText,
  exampleDataset, selfTest, parseTime, makeZone, cmpVersion, parseDuration, normUser, robustZ, mfaFromMethod,
} from "../../public/js/identity/vpnaudit-engine.js";
import { haversineKm } from "../../public/js/identity/signin-forensics-engine.js";

const MIN = 60000, HOUR = 3600000, DAY = 86400000;
const D = "test.darknode.ai";
const T0 = Date.UTC(2026, 9, 1, 0, 0, 0); // Thu 2026-10-01
const isoT = (t) => new Date(t).toISOString();
const evs = (files, opts) => parseInput(files, { opts }).rows;
const find = (r, pred) => r.findings.find(pred);
const byId = (r, id) => r.findings.find((f) => f.id === id);
const skippedChecks = (r) => r.skipped.map((s) => s.check);

// Generic CSV builder: rows of { ts, user, src_ip, country, lat, lon, event, mfa, client, client_version, device_id, duration_s, bytes_in, bytes_out }
const GH = ["ts", "user", "src_ip", "country", "lat", "lon", "event", "mfa", "client", "client_version", "device_id", "duration_s", "bytes_in", "bytes_out"];
const gcsv = (rows) => GH.join(",") + "\n" + rows.map((r) => GH.map((k) => (r[k] == null ? "" : k === "ts" && typeof r[k] === "number" ? isoT(r[k]) : String(r[k]))).join(",")).join("\n") + "\n";
const gfile = (rows, name = "remote.csv") => ({ name, text: gcsv(rows) });
const ROSTER_HEAD = "employee_id,name,email,username,department,manager_email,status,hire_date,termination_date";
const roster = (lines) => ({ name: "roster.csv", text: ROSTER_HEAD + "\n" + lines.join("\n") + "\n" });
const run = (files, opts = {}) => analyze({ files }, opts);
// one successful session per weekday for n days at 09:00 UTC
const routine = (user, ip, days, extra = {}) => {
  const out = [];
  for (let d = 0; d < days; d++) {
    const t = T0 + d * DAY + 9 * HOUR;
    out.push({ ts: t, user, src_ip: ip, event: "connect", device_id: "dev-" + user, duration_s: 3600, ...extra });
  }
  return out;
};

// ------------------------------------------------------------------ fixtures (vendor layouts)
const FORTI = [
  'date=2026-10-16 time=09:14:03 devname="FGT-HQ" devid="FG100FTK19000001" tz="+0000" logid="0101039947" type="event" subtype="vpn" level="information" vd="root" logdesc="SSL VPN tunnel up" action="tunnel-up" tunneltype="ssl-tunnel" tunnelid=1424 remip=203.0.113.5 tunnelip=10.212.134.200 user="alice" group="vpn-users" dst_host="N/A" reason="N/A" msg="SSL tunnel established"',
  'date=2026-10-16 time=10:14:03 devname="FGT-HQ" devid="FG100FTK19000001" tz="+0000" logid="0101039948" type="event" subtype="vpn" level="information" vd="root" logdesc="SSL VPN tunnel down" action="tunnel-down" tunneltype="ssl-tunnel" tunnelid=1424 remip=203.0.113.5 tunnelip=N/A user="alice" group="vpn-users" dst_host="N/A" reason="N/A" duration=3600 sentbyte=1048576 rcvdbyte=2048 msg="SSL tunnel shutdown"',
  'date=2026-10-16 time=09:20:00 devname="FGT-HQ" devid="FG100FTK19000001" tz="+0000" logid="0101039426" type="event" subtype="vpn" level="alert" vd="root" logdesc="SSL VPN login fail" action="ssl-login-fail" tunneltype="ssl-web" tunnelid=0 remip=198.51.100.9 tunnelip=N/A user="bob" group="N/A" dst_host="N/A" reason="sslvpn_login_permission_denied" msg="SSL user failed to logged in"',
  'date=2026-10-16 time=09:21:00 devname=FGT-HQ logid=0100022948 type=event subtype=system level=information vd=root logdesc="Admin login successful" user=admin action=login',
].join("\n");

const GP_HEAD = "Domain,Receive Time,Serial #,Sequence Number,Action Flags,Type,Threat/Content Type,Config Version,Generate Time,Virtual System,Event ID,Stage,Authentication Method,Tunnel Type,Source User,Source Region,Machine Name,Public IP,Public IPv6,Private IP,Private IPv6,Host ID,Serial Number,Client Version,Client OS,Client OS Version,Repeat Count,Reason,Error,Description,Status,Location,Login Duration,Connect Method,Error Code,Portal,Selection Type,Response Time,Priority,Attempted Gateways,Gateway";
const GP_CSV = [GP_HEAD,
  '1,2026/10/16 09:14:03,012801000001,7001,0x0,GLOBALPROTECT,gateway,2561,2026/10/16 09:14:03,vsys1,gateway-auth,login,LDAP,SSL,alice@test.darknode.ai,US,LT-ALICE,203.0.113.5,,,,host-a,,6.2.4-24,Windows,"Microsoft Windows 11 Enterprise , 64-bit",1,,,,success,,,user-logon,0,GP-Portal,auto,,0,,GW-East',
  '1,2026/10/16 09:14:23,012801000001,7002,0x0,GLOBALPROTECT,gateway,2561,2026/10/16 09:14:23,vsys1,gateway-connected,connected,LDAP,SSL,alice@test.darknode.ai,US,LT-ALICE,203.0.113.5,,10.20.0.5,,host-a,,6.2.4-24,Windows,"Microsoft Windows 11 Enterprise , 64-bit",1,,,,success,,,user-logon,0,GP-Portal,auto,,0,,GW-East',
  '1,2026/10/16 12:14:23,012801000001,7003,0x0,GLOBALPROTECT,gateway,2561,2026/10/16 12:14:23,vsys1,gateway-logout,logout,LDAP,SSL,alice@test.darknode.ai,US,LT-ALICE,203.0.113.5,,10.20.0.5,,host-a,,6.2.4-24,Windows,"Microsoft Windows 11 Enterprise , 64-bit",1,client logout,,,success,,10800,user-logon,0,GP-Portal,auto,,0,,GW-East',
  '1,2026/10/16 09:30:00,012801000001,7004,0x0,GLOBALPROTECT,portal,2561,2026/10/16 09:30:00,vsys1,portal-auth,login,LDAP,,bob@test.darknode.ai,NL,,198.51.100.77,,,,,,,,,1,,Authentication failed: Invalid username or password,,failure,,,,1,GP-Portal,,,0,,',
].join("\n") + "\n";

// Field order per PAN-OS "GlobalProtect Log Fields" (High Res Timestamp after Action Flags; DG hierarchy etc. after Gateway).
const GP_SYSLOG = [
  "<14>Oct 16 09:14:03 PA-VM 1,2026/10/16 09:14:03,012801000001,GLOBALPROTECT,0,2561,2026/10/16 09:14:03,vsys1,gateway-connected,connected,SAML,ipsec,carol@test.darknode.ai,GB,LT-CAROL,198.51.100.40,0.0.0.0,10.20.0.9,0.0.0.0,host-c,SN123,6.1.0-30,Windows,\"Microsoft Windows 10 Pro , 64-bit\",1,,,\"\",success,,0,user-logon,0,GP-Portal,8100,0x0,2026-10-16T09:14:03.412+00:00,auto,38,1,\"GW-West,38,1;GW-East,-1,2\",GW-West,0,0,0,0,,PA-VM,0,",
  "<14>Oct 16 09:20:03 PA-VM 1,2026/10/16 09:20:03,012801000001,GLOBALPROTECT,0,2561,2026/10/16 09:20:03,vsys1,gateway-auth,login,LDAP,,dan@test.darknode.ai,US,,203.0.113.66,0.0.0.0,0.0.0.0,0.0.0.0,,,,,,1,,Invalid credentials,\"\",failure,,0,,1,GP-Portal,8101,0x0,2026-10-16T09:20:03.007+00:00,,,0,,GW-West,0,0,0,0,,PA-VM,0,",
].join("\n");

const ASA = [
  "Oct 16 2026 09:14:01: %ASA-6-113004: AAA user authentication Successful : server = 10.0.0.5 : user = alice",
  "Oct 16 2026 09:14:03: %ASA-6-113039: Group <GP-Staff> User <alice> IP <203.0.113.5> AnyConnect parent session started.",
  "Oct 16 2026 09:14:04: %ASA-6-722022: Group <GP-Staff> User <alice> IP <203.0.113.5> TCP SVC connection established without compression",
  "Oct 16 2026 09:14:04: %ASA-6-722051: Group <GP-Staff> User <alice> IP <203.0.113.5> IPv4 Address <10.50.0.7> IPv6 address <::> assigned to session",
  "Oct 16 2026 09:14:05: %ASA-6-722055: Group <GP-Staff> User <alice> IP <203.0.113.5> Client Type: Cisco AnyConnect VPN Agent for Windows 4.10.05095",
  "Oct 16 2026 10:16:06: %ASA-4-113019: Group = GP-Staff, Username = alice, IP = 203.0.113.5, Session disconnected. Session Type: AnyConnect-Parent, Duration: 1h:02m:03s, Bytes xmt: 5242880, Bytes rcv: 40960, Reason: User Requested",
  "Oct 16 2026 09:30:00: %ASA-6-113005: AAA user authentication Rejected : reason = AAA failure : server = 10.0.0.5 : user = bob : user IP = 198.51.100.9",
  "Oct 16 2026 09:31:00: %ASA-6-113005: AAA user authentication Rejected : reason = AAA failure : server = 10.0.0.5 : user = ***** : user IP = 198.51.100.9",
].join("\n");

const OVPN_LOG = [
  "2026-10-16 09:14:01 203.0.113.5:51234 peer info: IV_VER=2.6.8",
  "2026-10-16 09:14:02 203.0.113.5:51234 TLS: Username/Password authentication succeeded for username 'alice'",
  "2026-10-16 09:14:03 203.0.113.5:51234 [alice] Peer Connection Initiated with [AF_INET]203.0.113.5:51234",
  "2026-10-16 09:14:03 alice/203.0.113.5:51234 MULTI_sva: pool returned IPv4=10.8.0.6, IPv6=(Not enabled)",
  "2026-10-16 09:20:00 198.51.100.9:40000 TLS: Username/Password authentication failed for username 'bob'",
  "2026-10-16 09:20:00 198.51.100.9:40000 TLS Auth Error: Auth Username/Password verification failed for peer",
  "2026-10-16 11:14:03 alice/203.0.113.5:51234 SIGTERM[soft,remote-exit] received, client-instance exiting",
].join("\n");

const OVPN_STATUS2 = [
  "TITLE,OpenVPN 2.6.8 x86_64-pc-linux-gnu",
  "TIME,2026-10-17 12:00:00,1792238400",
  "HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,Client ID,Peer ID,Data Channel Cipher",
  "CLIENT_LIST,alice,203.0.113.5:51234,10.8.0.6,,123456,654321,2026-10-16 09:14:03,1792142043,UNDEF,4,0,AES-256-GCM",
  "HEADER,ROUTING_TABLE,Virtual Address,Common Name,Real Address,Last Ref,Last Ref (time_t)",
  "ROUTING_TABLE,10.8.0.6,alice,203.0.113.5:51234,2026-10-17 11:59:00,1792238340",
  "GLOBAL_STATS,Max bcast/mcast queue length,0",
  "END",
].join("\n");

const OVPN_STATUS1 = [
  "OpenVPN CLIENT LIST",
  "Updated,2026-10-16 12:00:00",
  "Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since",
  "bob,198.51.100.20:1194,1000,2000,2026-10-16 10:00:00",
  "ROUTING TABLE",
  "Virtual Address,Common Name,Real Address,Last Ref",
  "10.8.0.10,bob,198.51.100.20:1194,2026-10-16 11:59:00",
  "GLOBAL STATS",
  "Max bcast/mcast queue length,0",
  "END",
].join("\n");

const CF = [
  JSON.stringify({ Action: "login", Allowed: true, AppDomain: "wiki.test.darknode.ai", AppUUID: "2b7c2c0e-0000-4000-8000-000000000001", Connection: "azureAD", Country: "us", CreatedAt: "2026-10-16T09:14:03Z", Email: "alice@" + D, IPAddress: "203.0.113.5", PurposeJustificationPrompt: "", PurposeJustificationResponse: "", RayID: "8c1b2f3a4d5e6f70", TemporaryAccessApprovers: [], UserUID: "u-1" }),
  JSON.stringify({ Action: "login", Allowed: false, AppDomain: "wiki.test.darknode.ai", AppUUID: "2b7c2c0e-0000-4000-8000-000000000001", Connection: "onetimepin", Country: "nl", CreatedAt: "2026-10-16T09:20:00Z", Email: "bob@" + D, IPAddress: "198.51.100.9", PurposeJustificationPrompt: "", PurposeJustificationResponse: "", RayID: "8c1b2f3a4d5e6f71", TemporaryAccessApprovers: [], UserUID: "u-2" }),
].join("\n");

const ZPA_JSON = JSON.stringify([
  { LogTimestamp: "Fri Oct 16 09:14:03 2026", Customer: "Darknode Test", Username: "carol@" + D, SessionID: "s-1", SessionStatus: "ZPN_STATUS_AUTHENTICATED", Version: "4.3.0.188", ZEN: "US-NY-8179", CertificateCN: "cn-carol", PrivateIP: "10.30.0.5", PublicIP: "203.0.113.12", Latitude: 40.7128, Longitude: -74.006, CountryCode: "US", TimestampAuthentication: "2026-10-16T09:14:03.000Z", TimestampUnAuthentication: "", TotalBytesRx: 0, TotalBytesTx: 0, Idp: "Okta", Hostname: "LT-CAROL", Platform: "windows", ClientType: "zpn_client_type_zapp" },
  { LogTimestamp: "Fri Oct 16 11:14:03 2026", Customer: "Darknode Test", Username: "carol@" + D, SessionID: "s-1", SessionStatus: "ZPN_STATUS_DISCONNECTED", Version: "4.3.0.188", ZEN: "US-NY-8179", CertificateCN: "cn-carol", PrivateIP: "10.30.0.5", PublicIP: "203.0.113.12", Latitude: 40.7128, Longitude: -74.006, CountryCode: "US", TimestampAuthentication: "2026-10-16T09:14:03.000Z", TimestampUnAuthentication: "2026-10-16T11:14:03.000Z", TotalBytesRx: 50000000, TotalBytesTx: 2000000, Idp: "Okta", Hostname: "LT-CAROL", Platform: "windows", ClientType: "zpn_client_type_zapp" },
]);

const AZURE = JSON.stringify({ records: [
  { time: "2026-10-16T09:14:03.0000000Z", resourceId: "/SUBSCRIPTIONS/00000000-0000-0000-0000-000000000000/RESOURCEGROUPS/RG-NET/PROVIDERS/MICROSOFT.NETWORK/VIRTUALNETWORKGATEWAYS/VGW-HQ", category: "P2SDiagnosticLog", operationName: "P2SLogEvent", properties: { Level: 4, message: "Connection successful for user alice@test.darknode.ai from 203.0.113.5:4500", instance: "GatewayTenantWorker_IN_0" } },
  { time: "2026-10-16T09:20:03.0000000Z", resourceId: "/SUBSCRIPTIONS/00000000-0000-0000-0000-000000000000/RESOURCEGROUPS/RG-NET/PROVIDERS/MICROSOFT.NETWORK/VIRTUALNETWORKGATEWAYS/VGW-HQ", category: "P2SDiagnosticLog", operationName: "P2SLogEvent", properties: { Level: 2, message: "Authentication failed for user bob@test.darknode.ai from 198.51.100.9:4500", instance: "GatewayTenantWorker_IN_0" } },
  { time: "2026-10-16T10:14:03.0000000Z", resourceId: "/SUBSCRIPTIONS/00000000-0000-0000-0000-000000000000/RESOURCEGROUPS/RG-NET/PROVIDERS/MICROSOFT.NETWORK/VIRTUALNETWORKGATEWAYS/VGW-HQ", category: "P2SDiagnosticLog", operationName: "P2SLogEvent", properties: { Level: 4, message: "User alice@test.darknode.ai from 203.0.113.5:4500 disconnected", instance: "GatewayTenantWorker_IN_0" } },
] });

// ------------------------------------------------------------------ engine basics
group("vpnaudit: engine", () => {
  test("in-engine self-test passes", () => {
    const r = selfTest();
    assert.ok(r.pass, "failed: " + r.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
  });
  test("analyze is byte-identical across runs and file order", () => {
    const ex = exampleDataset();
    const a = JSON.stringify(analyze(ex));
    assert.equal(a, JSON.stringify(analyze(ex)));
    assert.equal(a, JSON.stringify(analyze({ files: ex.files.slice().reverse() })));
  });
  test("empty input yields zero findings and does not throw", () => {
    const r = analyze({ files: [] });
    assert.equal(r.findings.length, 0);
    assert.equal(r.meta.rows, 0);
    assert.ok(skippedChecks(r).includes("all"));
  });
  test("example: every scripted scenario fires", () => {
    const r = analyze(exampleDataset());
    assert.ok(byId(r, "leaver:mallory@" + D));
    assert.ok(byId(r, "spraysucc:198.51.100.77"));
    assert.ok(byId(r, "travel:carol@" + D));
    assert.ok(byId(r, "long:dave@" + D));
    assert.ok(byId(r, "shared:erin@" + D));
    assert.ok(byId(r, "bf:bob@" + D));
    assert.ok(byId(r, "leaver:mallory@" + D).description.includes("9 day(s)"));
  });
  test("exports TOOL_ID and documented defaults", () => {
    assert.equal(TOOL_ID, "vpnaudit");
    assert.equal(DEFAULTS.failThreshold, 10);
    assert.equal(DEFAULTS.maxKmh, 900);
    assert.ok(COLUMNS.roster.termination_date.length);
  });
  test("progress is reported and optional", () => {
    const calls = [];
    analyze(exampleDataset(), {}, { progress: (d, n) => calls.push([d, n]) });
    assert.ok(calls.length >= 2);
    assert.equal(calls[calls.length - 1][0], calls[calls.length - 1][1]);
  });
});

// ------------------------------------------------------------------ parsers
group("vpnaudit: parsers", () => {
  test("FortiGate: tunnel-up / tunnel-down / ssl-login-fail, quoted and unquoted values, non-VPN lines ignored", () => {
    const f = { name: "fgt.log", text: FORTI };
    assert.equal(classifyText(f.name, f.text).format, "fortigate");
    const e = evs([f]);
    assert.equal(e.length, 3);
    const up = e.find((x) => x.k === "connect"), down = e.find((x) => x.k === "disconnect"), fail = e.find((x) => x.k === "auth");
    assert.equal(up.u, "alice"); assert.equal(up.ip, "203.0.113.5");
    assert.equal(up.t, Date.UTC(2026, 9, 16, 9, 14, 3));
    assert.equal(down.dur, 3600); assert.equal(down.bout, 1048576); assert.equal(down.bin, 2048);
    assert.equal(fail.ok, false); assert.equal(fail.u, "bob"); assert.equal(fail.why, "sslvpn_login_permission_denied");
  });
  test("FortiGate: tz field and eventtime (ns) are honoured", () => {
    const line = 'date=2026-10-16 time=11:14:03 devname="FGT" tz="+0200" logid="0101039947" type="event" subtype="vpn" action="tunnel-up" tunnelid=1 remip=203.0.113.5 user="alice"';
    assert.equal(evs([{ name: "a.log", text: line }])[0].t, Date.UTC(2026, 9, 16, 9, 14, 3));
    const ns = String(Date.UTC(2026, 9, 16, 9, 0, 0)) + "000000";
    const line2 = 'date=2026-10-16 time=23:59:59 devname="FGT" eventtime=' + ns + ' tz="-0700" logid="0101039947" type="event" subtype="vpn" action="tunnel-up" tunnelid=2 remip=203.0.113.5 user="alice"';
    assert.equal(evs([{ name: "b.log", text: line2 }])[0].t, Date.UTC(2026, 9, 16, 9, 0, 0));
  });
  test("GlobalProtect CSV export: auth, connected, logout, failure, region and host id", () => {
    const f = { name: "gp.csv", text: GP_CSV };
    const c = classifyText(f.name, f.text);
    assert.equal(c.format, "gp-csv"); assert.equal(c.confidence, "high");
    const e = evs([f]);
    assert.equal(e.length, 4);
    const fail = e.find((x) => x.k === "auth" && x.ok === false);
    assert.equal(fail.u, "bob@" + D); assert.equal(fail.cc, "NL"); assert.equal(fail.ip, "198.51.100.77");
    const conn = e.find((x) => x.k === "connect");
    assert.equal(conn.dev, "host-a"); assert.equal(conn.ver, "6.2.4-24"); assert.equal(conn.mfa, false);
    assert.equal(e.find((x) => x.k === "disconnect").dur, 10800);
    assert.equal(conn.t, Date.UTC(2026, 9, 16, 9, 14, 23));
  });
  test("GlobalProtect syslog (PAN-OS CSV payload behind a syslog header)", () => {
    const f = { name: "gp-syslog.log", text: GP_SYSLOG };
    assert.equal(classifyText(f.name, f.text).format, "gp-syslog");
    const e = evs([f]);
    assert.equal(e.length, 2);
    assert.equal(e[0].u, "carol@" + D); assert.equal(e[0].k, "connect"); assert.equal(e[0].cc, "GB"); assert.equal(e[0].dev, "host-c"); assert.equal(e[0].ver, "6.1.0-30");
    assert.equal(e[1].ok, false); assert.equal(e[1].ip, "203.0.113.66");
    // Gateway is read from its documented position, not from Attempted Gateways.
    assert.equal(e[0].gw, "GW-West"); assert.equal(e[1].gw, "GW-West"); assert.equal(e[0].pip, "10.20.0.9");
  });
  test("Cisco ASA: 113004/113039/722051/722055/113019/113005 with message-specific regexes", () => {
    const f = { name: "asa.log", text: ASA };
    assert.equal(classifyText(f.name, f.text).format, "asa");
    const e = evs([f]);
    assert.ok(e.some((x) => x.k === "auth" && x.ok === true && x.u === "alice"));
    const conn = e.find((x) => x.k === "connect");
    assert.equal(conn.ip, "203.0.113.5"); assert.equal(conn.t, Date.UTC(2026, 9, 16, 9, 14, 3));
    assert.equal(e.find((x) => x.why === "client").ver, "4.10.05095");
    const d = e.find((x) => x.k === "disconnect");
    assert.equal(d.dur, 3723); assert.equal(d.bout, 5242880); assert.equal(d.bin, 40960); assert.equal(d.why, "User Requested");
    assert.equal(e.filter((x) => x.k === "auth" && x.ok === false).length, 2);
  });
  test("Cisco ASA: 722051 takes the IPv4 address, not the IPv6 one that follows it", () => {
    const a = evs([{ name: "asa.log", text: ASA }]).find((x) => x.why === "assign");
    assert.equal(a.pip, "10.50.0.7");
  });
  test("Cisco ASA: Group/User/IP without angle brackets (Cisco syslog guide layout) parse the same", () => {
    const text = [
      "Oct 16 2026 09:14:03: %ASA-6-113039: Group GP-Staff User alice IP 203.0.113.5 AnyConnect parent session started.",
      "Oct 16 2026 09:14:04: %ASA-6-722051: Group GP-Staff User alice IP 203.0.113.5 IPv4 Address 10.50.0.7 IPv6 address :: assigned to session",
      "Oct 16 2026 09:14:05: %ASA-6-722055: Group GP-Staff User alice IP 203.0.113.5 Client Type: Cisco AnyConnect VPN Agent for Windows 4.10.05095",
      "Oct 16 2026 09:20:00: %ASA-6-716039: Group GP-Staff User bob IP 198.51.100.9 Authentication: rejected, Session Type: WebVPN.",
    ].join("\n");
    const e = evs([{ name: "asa.log", text }]);
    const c = e.find((x) => x.k === "connect");
    assert.equal(c.u, "alice"); assert.equal(c.ip, "203.0.113.5"); assert.equal(c.gw, "GP-Staff");
    assert.equal(e.find((x) => x.why === "assign").pip, "10.50.0.7");
    assert.equal(e.find((x) => x.why === "client").ver, "4.10.05095");
    const rej = e.find((x) => x.k === "auth" && x.ok === false);
    assert.equal(rej.u, "bob"); assert.equal(rej.ip, "198.51.100.9");
  });
  test("Cisco ASA: masked usernames of any asterisk length are never one shared user", () => {
    const text = [
      "Oct 16 2026 09:31:00: %ASA-6-113005: AAA user authentication Rejected : reason = AAA failure : server = 10.0.0.5 : user = ***** : user IP = 198.51.100.9",
      "Oct 16 2026 09:31:05: %ASA-6-113015: AAA user authentication Rejected : reason = Invalid password : local database : user = ******** : user IP = 198.51.100.10",
    ].join("\n");
    assert.equal(normUser("********"), null);
    const r = run([{ name: "asa.log", text }]);
    assert.ok(r.skipped.some((x) => /2 failed authentication\(s\) carry no username/.test(x.reason)));
  });
  test("Cisco ASA: one session from parent + SVC lines, client version attached, masked usernames reported", () => {
    const r = run([{ name: "asa.log", text: ASA }]);
    assert.equal(r.summary.sessions, 1);
    const s = r.tables.sessions[0];
    assert.equal(s.version, "4.10.05095"); assert.equal(s.hours, 1.03);
    assert.ok(r.skipped.some((x) => /masks/.test(x.reason)));
  });
  test("syslog without a year uses the setting, and without any year the line is reported, not guessed", () => {
    const line = "Oct 16 09:14:03 asa01 : %ASA-6-113039: Group <G> User <alice> IP <203.0.113.5> AnyConnect parent session started.";
    assert.equal(evs([{ name: "a.log", text: line }], { syslogYear: 2026 })[0].t, Date.UTC(2026, 9, 16, 9, 14, 3));
    const p = parseInput([{ name: "a.log", text: line }]);
    assert.equal(p.rows.length, 0);
    assert.ok(p.skipped.some((s) => /without a readable timestamp/.test(s.reason)));
  });
  test("OpenVPN server log: auth success/failure by username, peer connection, disconnect, IV_VER", () => {
    const f = { name: "openvpn.log", text: OVPN_LOG };
    assert.equal(classifyText(f.name, f.text).format, "openvpn-log");
    const e = evs([f]);
    const conn = e.find((x) => x.k === "connect");
    assert.equal(conn.u, "alice"); assert.equal(conn.ver, "2.6.8");
    assert.equal(e.filter((x) => x.k === "auth" && x.ok === false && x.u === "bob").length, 2);
    const r = run([f]);
    assert.equal(r.tables.sessions[0].hours, 2);
    assert.equal(r.tables.sessions[0].version, "2.6.8");
  });
  test("OpenVPN status file v2: CLIENT_LIST measured to the snapshot TIME", () => {
    const f = { name: "openvpn-status.log", text: OVPN_STATUS2 };
    assert.equal(classifyText(f.name, f.text).format, "openvpn-status");
    const r = run([f]);
    const s = r.tables.sessions[0];
    assert.equal(s.user, "alice"); assert.equal(s.ip, "203.0.113.5"); assert.equal(s.bytesOut, 654321);
    assert.equal(s.start, "2026-10-16T09:14:03Z");
    assert.ok(Math.abs(s.hours - 26.77) < 0.01);
    assert.ok(byId(r, "long:alice"));
  });
  test("OpenVPN status file v1", () => {
    const r = run([{ name: "status.log", text: OVPN_STATUS1 }]);
    assert.equal(r.tables.sessions.length, 1);
    assert.equal(r.tables.sessions[0].user, "bob"); assert.equal(r.tables.sessions[0].bytesOut, 2000); assert.equal(r.tables.sessions[0].hours, 2);
  });
  test("Cloudflare Access Logpush NDJSON: login allowed / policy denial kept out of brute force", () => {
    const f = { name: "access_requests.json", text: CF };
    assert.equal(classifyText(f.name, f.text).format, "cloudflare");
    const e = evs([f]);
    assert.equal(e.length, 2);
    assert.equal(e[0].ok, true); assert.equal(e[0].cc, "US"); assert.equal(e[0].u, "alice@" + D);
    assert.equal(e[1].ok, false); assert.equal(e[1].deny, "policy");
  });
  test("Zscaler ZPA user status JSON: coordinates, session from authenticated to disconnected, bytes", () => {
    const f = { name: "zpa.json", text: ZPA_JSON };
    assert.equal(classifyText(f.name, f.text).format, "zpa");
    const r = run([f]);
    assert.equal(r.tables.sessions.length, 1);
    const s = r.tables.sessions[0];
    assert.equal(s.lat, 40.7128); assert.equal(s.country, "US"); assert.equal(s.hours, 2); assert.equal(s.bytesOut, 50000000); assert.equal(s.device, "LT-CAROL");
  });
  test("Zscaler ZPA user activity + AUTH_FAILED status, documented LSS field names", () => {
    // Field names from help.zscaler.com "Understanding User Activity Log Fields" / "User Status Log Fields".
    const act = [
      { LogTimestamp: "Fri Oct 16 09:20:00 2026", Customer: "Darknode Test", SessionID: "s-9", ConnectionID: "c-1", ConnectionStatus: "Open", Username: "dave@" + D, ClientPublicIP: "203.0.113.44", ClientLatitude: 51.5074, ClientLongitude: -0.1278, ClientCountryCode: "GB", ClientCity: "London", Hostname: "LT-DAVE", Platform: "windows", Idp: "Okta", Application: "wiki", Host: "wiki.test.darknode.ai", ServerPort: 443 },
    ].map((o) => JSON.stringify(o)).join("\n");
    const e = evs([{ name: "zpa-activity.json", text: act }]);
    assert.equal(classifyText("zpa-activity.json", act).format, "zpa");
    assert.equal(e.length, 1); assert.equal(e[0].k, "touch"); assert.equal(e[0].ip, "203.0.113.44"); assert.equal(e[0].cc, "GB"); assert.equal(e[0].lat, 51.5074); assert.equal(e[0].dev, "LT-DAVE");
    const fail = JSON.stringify([{ LogTimestamp: "Fri Oct 16 09:25:00 2026", Username: "erin@" + D, SessionID: "s-10", SessionStatus: "ZPN_STATUS_AUTH_FAILED", PublicIP: "198.51.100.61", TimestampAuthentication: "", TimestampUnAuthentication: "" }]);
    const f = evs([{ name: "zpa-status.json", text: fail }]);
    assert.equal(f.length, 1); assert.equal(f[0].k, "auth"); assert.equal(f[0].ok, false); assert.equal(f[0].t, Date.UTC(2026, 9, 16, 9, 25, 0));
  });
  test("Azure VPN Gateway P2SDiagnosticLog JSON records", () => {
    const f = { name: "p2s.json", text: AZURE };
    assert.equal(classifyText(f.name, f.text).format, "azure-p2s");
    const e = evs([f]);
    assert.equal(e.length, 3);
    assert.equal(e[0].k, "connect"); assert.equal(e[0].u, "alice@" + D); assert.equal(e[0].ip, "203.0.113.5");
    assert.equal(e[1].ok, false);
    assert.equal(run([f]).tables.sessions[0].hours, 1);
  });
  test("generic CSV: all documented columns", () => {
    const f = gfile([{ ts: "2026-10-16T09:00:00Z", user: "alice", src_ip: "203.0.113.5", country: "US", lat: 40.7, lon: -74, event: "auth_success", mfa: "yes", client: "FortiClient", client_version: "7.0.12", device_id: "dev-1" },
      { ts: "2026-10-16T09:00:05Z", user: "alice", src_ip: "203.0.113.5", event: "connect", device_id: "dev-1" },
      { ts: "2026-10-16T10:00:05Z", user: "alice", src_ip: "203.0.113.5", event: "disconnect", device_id: "dev-1", duration_s: 3600, bytes_in: 10, bytes_out: 20 }]);
    assert.equal(classifyText(f.name, f.text).format, "generic");
    const e = evs([f]);
    assert.equal(e[0].mfa, true); assert.equal(e[0].prod, "forticlient"); assert.equal(e[0].lat, 40.7);
    const r = run([f]);
    assert.equal(r.tables.sessions.length, 1); assert.equal(r.tables.sessions[0].bytesOut, 20);
  });
  test("generic CSV without a user column is reported as skipped, never guessed", () => {
    const p = parseInput([{ name: "x.csv", text: "ts,src_ip,event\n2026-10-16T09:00:00Z,203.0.113.5,connect\n" }]);
    const r = analyze({ files: [{ name: "x.csv", text: "ts,src_ip,event\n2026-10-16T09:00:00Z,203.0.113.5,connect\n", format: "generic" }] });
    assert.equal(p.files[0].format, "unknown");
    assert.ok(r.skipped.some((s) => s.check === "parse" && /no user column/.test(s.reason)));
  });
  test("column-mapping overrides are applied", () => {
    const text = "when,who,addr,what\n2026-10-16T09:00:00Z,alice,203.0.113.5,connect\n";
    const r = analyze({ files: [{ name: "m.csv", text, format: "generic", kind: "log", container: "csv", columns: { ts: "when", user: "who", src_ip: "addr", event: "what" } }] });
    assert.equal(r.summary.events, 1);
    assert.equal(r.tables.sessions[0].ip, "203.0.113.5");
  });
});

// ------------------------------------------------------------------ sessions & helpers
group("vpnaudit: sessions and helpers", () => {
  test("up/down pairing by tunnel id; missing down stays open", () => {
    const up2 = 'date=2026-10-16 time=12:00:00 devname="FGT-HQ" tz="+0000" logid="0101039947" type="event" subtype="vpn" action="tunnel-up" tunnelid=1500 remip=203.0.113.6 user="carol"';
    const r = run([{ name: "fgt.log", text: FORTI + "\n" + up2 }]);
    const open = r.tables.sessions.find((s) => s.user === "carol");
    assert.ok(open.open); assert.equal(open.end, undefined);
    assert.equal(r.tables.sessions.find((s) => s.user === "alice").hours, 1);
  });
  test("disconnect without connect but with a duration infers the start", () => {
    const down = 'date=2026-10-16 time=12:00:00 devname="FGT-HQ" tz="+0000" logid="0101039948" type="event" subtype="vpn" action="tunnel-down" tunnelid=77 remip=203.0.113.6 user="carol" duration=7200 sentbyte=1 rcvdbyte=1';
    const s = run([{ name: "fgt.log", text: down }]).tables.sessions[0];
    assert.equal(s.start, "2026-10-16T10:00:00Z"); assert.ok(s.inferredStart);
  });
  test("an open session followed by a later session of the same user is not measured as long", () => {
    const rows = [{ ts: T0, user: "u1", src_ip: "203.0.113.5", event: "connect", device_id: "d" }, { ts: T0 + 3 * DAY, user: "u1", src_ip: "203.0.113.5", event: "connect", device_id: "d2", duration_s: 60 }];
    assert.ok(!run([gfile(rows)]).findings.some((f) => f.category === "long_session"));
  });
  test("parseTime: zones, ISO offsets, PAN-OS, OpenVPN and epoch forms", () => {
    const want = Date.UTC(2026, 9, 16, 9, 14, 3);
    assert.equal(parseTime("2026-10-16T11:14:03+02:00"), want);
    assert.equal(parseTime("2026/10/16 09:14:03"), want);
    assert.equal(parseTime("Fri Oct 16 09:14:03 2026"), want);
    assert.equal(parseTime("1792142043"), Date.UTC(2026, 9, 16, 9, 14, 3));
    assert.equal(parseTime("2026-10-16 11:14:03", { zone: makeZone("Europe/Berlin") }), want); // CEST +2
    assert.equal(parseTime("2026-12-16 10:14:03", { zone: makeZone("Europe/Berlin") }), Date.UTC(2026, 11, 16, 9, 14, 3)); // CET +1
    assert.equal(parseTime("2026-10-16 14:44:03", { zone: makeZone("UTC+05:30") }), want);
    assert.equal(parseTime("16 Oct 09:14"), null);
  });
  test("log time zone setting shifts zone-less timestamps", () => {
    const f = gfile([{ ts: "2026-10-16 09:00:00", user: "alice", src_ip: "203.0.113.5", event: "auth_success" }]);
    assert.equal(evs([f], { logTimeZone: "America/New_York" })[0].t, Date.UTC(2026, 9, 16, 13, 0, 0));
  });
  test("haversine edges: same point, antipodes, NYC-London", () => {
    assert.equal(haversineKm(10, 10, 10, 10), 0);
    assert.ok(Math.abs(haversineKm(0, 0, 0, 180) - 20015) < 5);
    assert.ok(Math.abs(haversineKm(40.7128, -74.006, 51.5074, -0.1278) - 5570) < 15);
  });
  test("version compare, ASA duration, user normalisation, MFA from method, robust z", () => {
    assert.equal(cmpVersion("4.10.05095", "4.10.08025"), -1);
    assert.equal(cmpVersion("6.2.4-24", "6.2.4"), 1);
    assert.equal(cmpVersion("5.1", "5.1.0"), 0);
    assert.equal(parseDuration("1d 2h:03m:04s"), 93784);
    assert.equal(parseDuration("31h:00m:00s"), 111600);
    assert.equal(normUser("CORP\\Alice"), "alice");
    assert.equal(normUser("N/A"), null);
    assert.equal(mfaFromMethod("LDAP"), false);
    assert.equal(mfaFromMethod("SAML"), null);
    assert.equal(mfaFromMethod("RADIUS + Duo push"), true);
    assert.equal(robustZ(5, [5, 5, 5]), null);
    assert.ok(robustZ(100, [1, 2, 3, 4, 100]) > 4);
  });
});

// ------------------------------------------------------------------ roster
group("vpnaudit: roster and leavers", () => {
  const R = roster([
    "E1,Alice Example,alice@" + D + ",alice,Eng,boss@" + D + ",active,2023-01-01,",
    "E2,Mallory Example,mallory@" + D + ",mal,Fin,boss@" + D + ",terminated,2022-01-01,2026-10-03",
    "E3,Ivan Example,ivan@" + D + ",ivan,Fin,boss@" + D + ",inactive,2022-01-01,",
  ]);
  test("leaver connecting after termination is critical with days since termination", () => {
    const r = run([R, gfile([{ ts: Date.UTC(2026, 9, 12, 22, 0), user: "mal", src_ip: "198.51.100.23", event: "auth_success" }])]);
    const f = byId(r, "leaver:mallory@" + D);
    assert.ok(f); assert.equal(f.severity, "critical"); assert.equal(f.confidence, "confirmed");
    assert.ok(f.description.includes("9 day(s)"));
    assert.equal(r.summary.leaversConnecting, 1);
    assert.ok(revocationCsv(r).includes("mallory@" + D));
  });
  test("access on the termination day itself is not a leaver finding", () => {
    const r = run([R, gfile([{ ts: Date.UTC(2026, 9, 3, 16, 0), user: "mal", src_ip: "198.51.100.23", event: "auth_success" }])]);
    assert.ok(!byId(r, "leaver:mallory@" + D));
  });
  test("termination day is read in the business time zone", () => {
    // 2026-10-04 02:00 UTC is still 2026-10-03 in New York
    const files = [R, gfile([{ ts: Date.UTC(2026, 9, 4, 2, 0), user: "mal", src_ip: "198.51.100.23", event: "auth_success" }])];
    assert.ok(byId(run(files), "leaver:mallory@" + D));
    assert.ok(!byId(run(files, { timeZone: "America/New_York" }), "leaver:mallory@" + D));
  });
  test("roster matching by email, username, email local part and mapping file", () => {
    const map = { name: "map.csv", text: "username,email\nm.x,mallory@" + D + "\n" };
    const after = Date.UTC(2026, 9, 10, 9, 0);
    const r = run([R, map, gfile([
      { ts: after, user: "alice@" + D, src_ip: "203.0.113.5", event: "auth_success" },
      { ts: after, user: "CORP\\ivan", src_ip: "203.0.113.6", event: "auth_success" },
      { ts: after, user: "alice@corp.invalid", src_ip: "203.0.113.5", event: "auth_success" },
      { ts: after, user: "m.x", src_ip: "203.0.113.7", event: "auth_success" },
    ])]);
    const u = (k) => r.tables.users.find((x) => x.user === k);
    assert.equal(u("alice@" + D).matchBasis, "email");
    assert.equal(u("ivan@" + D).matchBasis, "username");
    assert.ok(byId(r, "leaver:mallory@" + D), "mapped username resolves to the leaver");
    assert.ok(!r.tables.users.some((x) => x.user === "alice@corp.invalid"), "local part folds into the roster identity");
  });
  test("inactive HR status without a termination date is high / likely", () => {
    const r = run([R, gfile([{ ts: T0, user: "ivan", src_ip: "203.0.113.6", event: "auth_success" }])]);
    const f = byId(r, "inactive:ivan@" + D);
    assert.equal(f.severity, "high"); assert.equal(f.confidence, "likely");
  });
  test("accounts not on the roster are listed; service accounts (setting, glob, list file) are excluded", () => {
    const files = [R, gfile([
      { ts: T0, user: "contractor7", src_ip: "203.0.113.8", event: "auth_success" },
      { ts: T0, user: "svc-backup", src_ip: "203.0.113.9", event: "auth_success" },
      { ts: T0, user: "scanner01", src_ip: "203.0.113.9", event: "auth_success" },
    ]), { name: "service-accounts.txt", text: "service_account\nscanner01\n" }];
    const f = byId(run(files, { serviceAccounts: ["svc-*"] }), "notroster");
    assert.ok(f); assert.equal(f.evidenceCount, 1); assert.ok(f.description.includes("contractor7"));
    assert.equal(byId(run(files), "notroster").evidenceCount, 2);
  });
  test("no roster: leaver checks are skipped with a reason", () => {
    const r = run([gfile([{ ts: T0, user: "alice", src_ip: "203.0.113.5", event: "auth_success" }])]);
    assert.ok(skippedChecks(r).includes("leaver_connecting"));
  });
});

// ------------------------------------------------------------------ detections
group("vpnaudit: detections", () => {
  const fails = (user, ip, n, start, stepMs = MIN) => Array.from({ length: n }, (_, i) => ({ ts: start + i * stepMs, user, src_ip: ip, event: "auth_fail" }));
  test("brute force -> success fires at exactly the threshold and stays silent one below", () => {
    const t = T0 + 9 * HOUR;
    const hit = run([gfile([...fails("bob", "203.0.113.200", 10, t), { ts: t + 15 * MIN, user: "bob", src_ip: "203.0.113.200", event: "auth_success" }])]);
    const f = byId(hit, "bf:bob");
    assert.ok(f); assert.equal(f.severity, "high"); assert.equal(f.evidenceCount, 11);
    const miss = run([gfile([...fails("bob", "203.0.113.200", 9, t), { ts: t + 15 * MIN, user: "bob", src_ip: "203.0.113.200", event: "auth_success" }])]);
    assert.ok(!byId(miss, "bf:bob"));
  });
  test("brute force window: failures older than the window do not count", () => {
    const t = T0 + 9 * HOUR;
    const r = run([gfile([...fails("bob", "203.0.113.200", 10, t), { ts: t + 2 * HOUR, user: "bob", src_ip: "203.0.113.200", event: "auth_success" }])]);
    assert.ok(!byId(r, "bf:bob"));
    assert.ok(byId(run([gfile([...fails("bob", "203.0.113.200", 10, t), { ts: t + 2 * HOUR, user: "bob", src_ip: "203.0.113.200", event: "auth_success" }])], { bfWindowMin: 180 }), "bf:bob"));
  });
  test("password spraying: 10 users from one IP is high; 9 is silent; success from that IP is critical", () => {
    const t = T0 + 2 * HOUR;
    const sprayRows = (n) => Array.from({ length: n }, (_, i) => ({ ts: t + i * MIN, user: "user" + i, src_ip: "198.51.100.77", event: "auth_fail" }));
    const r = run([gfile([...sprayRows(10), { ts: t + 30 * MIN, user: "user3", src_ip: "198.51.100.77", event: "auth_success" }])]);
    assert.equal(byId(r, "spray:198.51.100.77").severity, "high");
    const s = byId(r, "spraysucc:198.51.100.77");
    assert.equal(s.severity, "critical"); assert.equal(s.confidence, "confirmed");
    assert.ok(blocklistText(r).includes("198.51.100.77"));
    assert.ok(byId(r, "spray:198.51.100.77").controls.some((c) => c.id === "T1110.003"));
    assert.ok(!byId(run([gfile(sprayRows(9))]), "spray:198.51.100.77"));
  });
  test("allow-listed sources are not reported as spraying", () => {
    const rows = Array.from({ length: 12 }, (_, i) => ({ ts: T0 + i * MIN, user: "user" + i, src_ip: "198.51.100.77", event: "auth_fail" }));
    assert.ok(!byId(run([gfile(rows)], { allowIps: ["198.51.100.0/24"] }), "spray:198.51.100.77"));
  });
  test("impossible travel from log coordinates; slow travel and short hops are silent; simultaneous counts", () => {
    const ny = { lat: 40.7128, lon: -74.006, country: "US" }, ldn = { lat: 51.5074, lon: -0.1278, country: "GB" };
    const fast = run([gfile([{ ts: T0, user: "carol", src_ip: "203.0.113.12", event: "auth_success", ...ny }, { ts: T0 + 2 * HOUR, user: "carol", src_ip: "198.51.100.40", event: "auth_success", ...ldn }])]);
    assert.ok(byId(fast, "travel:carol")); assert.equal(fast.summary.impossibleTravel, 1);
    const slow = run([gfile([{ ts: T0, user: "carol", src_ip: "203.0.113.12", event: "auth_success", ...ny }, { ts: T0 + 8 * HOUR, user: "carol", src_ip: "198.51.100.40", event: "auth_success", ...ldn }])]);
    assert.ok(!byId(slow, "travel:carol"));
    const jitter = run([gfile([{ ts: T0, user: "carol", src_ip: "203.0.113.12", event: "auth_success", lat: 40.71, lon: -74.0 }, { ts: T0 + MIN, user: "carol", src_ip: "203.0.113.13", event: "auth_success", lat: 40.2, lon: -74.5 }])]);
    assert.ok(!byId(jitter, "travel:carol"), "hops under minTravelKm are geolocation noise");
    const same = run([gfile([{ ts: T0, user: "carol", src_ip: "203.0.113.12", event: "auth_success", ...ny }, { ts: T0, user: "carol", src_ip: "198.51.100.40", event: "auth_success", ...ldn }])]);
    assert.ok(byId(same, "travel:carol").description.includes("simultaneous"));
  });
  test("country-only logs: travel skipped with reason, new-country check used instead", () => {
    const rows = [];
    for (let d = 0; d < 7; d++) rows.push({ ts: T0 + d * DAY + 10 * HOUR, user: "dave", src_ip: "203.0.113.20", country: "US", event: "auth_success" });
    rows.push({ ts: T0 + 9 * DAY + 10 * HOUR, user: "dave", src_ip: "198.51.100.50", country: "BR", event: "auth_success" });
    const r = run([gfile(rows)]);
    const sk = r.skipped.find((s) => s.check === "impossible_travel");
    assert.ok(/new-country/.test(sk.reason));
    const f = byId(r, "newcountry:dave");
    assert.equal(f.confidence, "review"); assert.ok(f.title.includes("BR"));
    rows[rows.length - 1].country = "US";
    assert.ok(!byId(run([gfile(rows)]), "newcountry:dave"));
  });
  test("concurrent sessions far apart", () => {
    const r = run([gfile([
      { ts: T0, user: "erin", src_ip: "203.0.113.30", lat: 40.7, lon: -74, event: "connect", device_id: "a", duration_s: 7200 },
      { ts: T0 + 30 * MIN, user: "erin", src_ip: "198.51.100.31", lat: 34.05, lon: -118.24, event: "connect", device_id: "b", duration_s: 7200 },
    ])]);
    assert.ok(byId(r, "concurrent:erin"));
    const near = run([gfile([
      { ts: T0, user: "erin", src_ip: "203.0.113.30", lat: 40.7, lon: -74, event: "connect", device_id: "a", duration_s: 7200 },
      { ts: T0 + 30 * MIN, user: "erin", src_ip: "198.51.100.31", lat: 40.0, lon: -75.1, event: "connect", device_id: "b", duration_s: 7200 },
    ])]);
    assert.ok(!byId(near, "concurrent:erin"));
  });
  test("threat feed: success is high, failures only medium, missing feed skipped", () => {
    const rows = [{ ts: T0, user: "a", src_ip: "198.51.100.66", event: "auth_success" }, { ts: T0, user: "b", src_ip: "198.51.100.67", event: "auth_fail" }];
    const r = run([gfile(rows)], { feedIps: ["198.51.100.66", "198.51.100.67"], feedUpdated: "2026-10-16" });
    assert.equal(byId(r, "feed:198.51.100.66").severity, "high");
    assert.equal(byId(r, "feed:198.51.100.67").severity, "medium");
    assert.ok(byId(r, "feed:198.51.100.66").description.includes("2026-10-16"));
    assert.ok(skippedChecks(run([gfile(rows)])).includes("threat_feed"));
  });
  test("no MFA: explicit flag fires per user; MFA yes is silent; logs without MFA info skip the check", () => {
    const r = run([gfile([{ ts: T0, user: "frank", src_ip: "203.0.113.15", event: "auth_success", mfa: "no" }, { ts: T0, user: "gina", src_ip: "203.0.113.16", event: "auth_success", mfa: "yes" }])]);
    assert.equal(byId(r, "nomfa:frank").confidence, "confirmed");
    assert.ok(!byId(r, "nomfa:gina"));
    assert.equal(r.summary.noMfaUsers, 1);
    assert.ok(skippedChecks(run([{ name: "fgt.log", text: FORTI }])).includes("no_mfa"));
  });
  test("outdated clients: below the entered minimum fires; newer is silent; blank minimum skipped with reason", () => {
    const f = { name: "asa.log", text: ASA };
    assert.ok(byId(run([f], { minClientVersions: { anyconnect: "4.10.08025" } }), "legacy:alice"));
    assert.ok(!byId(run([f], { minClientVersions: { anyconnect: "4.9" } }), "legacy:alice"));
    assert.ok(run([f]).skipped.some((s) => s.check === "legacy_client" && /no minimum/.test(s.reason)));
  });
  test("shared account: 3 devices at once fires, 2 devices does not; many IPs in a window fires", () => {
    const dev = (n) => Array.from({ length: n }, (_, i) => ({ ts: T0 + i * 5 * MIN, user: "erin", src_ip: "203.0.113.14", event: "connect", device_id: "dev" + i, duration_s: 3 * 3600 }));
    assert.ok(byId(run([gfile(dev(3))]), "shared:erin"));
    assert.ok(!byId(run([gfile(dev(2))]), "shared:erin"));
    const ips = Array.from({ length: 4 }, (_, i) => ({ ts: T0 + i * 10 * MIN, user: "sam", src_ip: "203.0.113." + (50 + i), event: "auth_success" }));
    const r = run([gfile(ips)]);
    assert.equal(byId(r, "shared:sam").confidence, "review");
    assert.ok(revocationCsv(r).includes("possible shared account"));
    assert.ok(!byId(run([gfile(ips)], { sharedWindowMin: 20 }), "shared:sam"));
  });
  test("long sessions: 31 hours fires, 23 hours is silent", () => {
    const s = (h) => gfile([{ ts: T0, user: "dave", src_ip: "203.0.113.20", event: "connect", device_id: "d", duration_s: h * 3600 }]);
    const f = byId(run([s(31)]), "long:dave");
    assert.equal(f.severity, "medium"); assert.ok(f.description.includes("31"));
    assert.ok(!byId(run([s(23)]), "long:dave"));
  });
  test("off-hours after an in-hours baseline, judged in the business time zone", () => {
    const rows = routine("heidi", "203.0.113.40", 7); // 09:00 UTC daily
    rows.push({ ts: T0 + 8 * DAY + 23 * HOUR, user: "heidi", src_ip: "203.0.113.40", event: "connect", device_id: "dev-heidi", duration_s: 600 }); // Fri 23:00 UTC
    const opts = { weekendOffHours: false };
    assert.ok(byId(run([gfile(rows)], opts), "offhours:heidi"));
    // In Asia/Tokyo the baseline (18:00 JST) is already off-hours, so the user has off-hours history: silent.
    assert.ok(!byId(run([gfile(rows)], { ...opts, timeZone: "Asia/Tokyo" }), "offhours:heidi"));
  });
  test("dormant account reactivated after more than 90 days; short logs skip the check", () => {
    const r = run([gfile([{ ts: T0, user: "ken", src_ip: "203.0.113.41", event: "auth_success" }, { ts: T0 + 100 * DAY, user: "ken", src_ip: "203.0.113.41", event: "auth_success" }])]);
    assert.ok(byId(r, "dormant:ken"));
    const short = run([gfile([{ ts: T0, user: "ken", src_ip: "203.0.113.41", event: "auth_success" }, { ts: T0 + 10 * DAY, user: "ken", src_ip: "203.0.113.41", event: "auth_success" }])]);
    assert.ok(skippedChecks(short).includes("dormant_reactivated"));
  });
  test("large transfers: absolute threshold, robust z with enough samples, small samples noted", () => {
    const base = (n, big) => Array.from({ length: n }, (_, i) => ({ ts: T0 + i * DAY + 9 * HOUR, user: "lena", src_ip: "203.0.113.42", event: "connect", device_id: "d", duration_s: 3600, bytes_out: i === n - 1 ? big : 100e6 + i * 1e6 }));
    const abs = run([gfile(base(3, 6 * 1024 ** 3))]);
    assert.ok(byId(abs, "bytes:lena"));
    assert.ok(skippedChecks(abs).includes("large_transfer_z"));
    const z = run([gfile(base(10, 3 * 1024 ** 3))]);
    const f = byId(z, "bytes:lena");
    assert.ok(f && /robust z/.test(f.description));
    assert.ok(!byId(run([gfile(base(10, 110e6))]), "bytes:lena"));
  });
  test("checks without the needed columns are skipped, never guessed", () => {
    const r = run([{ name: "fgt.log", text: FORTI }]);
    const s = skippedChecks(r);
    for (const c of ["impossible_travel", "concurrent_distant_sessions", "no_mfa", "threat_feed", "leaver_connecting"]) assert.ok(s.includes(c), c);
  });
});

// ------------------------------------------------------------------ exports
group("vpnaudit: exports", () => {
  const r = analyze(exampleDataset());
  test("findingsToCsv header row and one line per finding", () => {
    const csv = findingsToCsv(r.findings);
    const lines = csv.trim().split("\n");
    assert.equal(lines[0], "severity,confidence,category,title,description,recommendation,controls,assets,evidenceCount");
    assert.ok(lines.length >= r.findings.length + 1);
    assert.equal(findingsToCsv([]).trim(), lines[0]);
  });
  test("revocation CSV, blocklist, user report and summary text", () => {
    assert.ok(revocationCsv(r).startsWith("user,name,email,reason,termination_date,last_seen,last_ip,accesses_after"));
    assert.ok(revocationCsv(r).includes("erin@" + D));
    assert.ok(blocklistText(r).includes("198.51.100.77  # password spraying"));
    assert.ok(userReportText(r).includes("mallory@" + D));
    assert.ok(summaryText(r).includes("Leavers connecting: 1"));
  });
  test("every finding has controls, a confidence class, capped evidence and assets", () => {
    for (const f of r.findings) {
      assert.ok(f.controls.length >= 1, f.title);
      assert.ok(["confirmed", "likely", "review"].includes(f.confidence), f.title);
      assert.ok(f.evidence.length <= 50 && f.evidenceCount >= f.evidence.length, f.title);
      assert.ok(f.assets.length >= 1 && f.assets.every((a) => ["IDENTITY", "IP"].includes(a.type)), f.title);
    }
  });
  test("tables: users, sources, sessions, countries", () => {
    assert.ok(r.tables.users.length > 10);
    assert.ok(r.tables.sources.find((s) => s.ip === "198.51.100.77").spraying);
    assert.ok(r.tables.sessions.length > 100);
    assert.ok(r.tables.countries.some((c) => c.country === "US"));
  });
});
