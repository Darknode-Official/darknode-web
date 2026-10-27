// Sign-in Forensics engine tests (public/js/identity/signin-forensics-engine.js):
// CSV tokenizer edge cases, source autodetection, normalisation of Entra / Google /
// Okta exports, haversine, each detection positive + negative, threshold boundaries,
// skip-when-column-missing behaviour, scoring and export text. Pure logic only.

import { test, assert, group } from "../harness.mjs";
import {
  parseCsv, iterCsvRows, sniffDelimiter, detectSourceFromHeaders, detectSourceFromObject, parseTs, parseOutcome, parseMfa,
  isLegacyClient, adminHint, hostingHint, subnet24, haversineKm, resolvePlace, createParser, parseAll, analyze, isAfterHours,
  userTimeline, findingsToCsv, evidenceToCsv, summaryText, correlateOktaMfa, DEFAULTS, DETECTIONS, toSinkFindings,
} from "../../public/js/identity/signin-forensics-engine.js";
import { checkSinkFindings } from "./sink-check.mjs";

// ---------------------------------------------------------------------------
// Fixture builders (format-faithful column names and value vocabularies)
// ---------------------------------------------------------------------------
const T0 = Date.UTC(2026, 9, 1, 10, 0, 0); // Thu 2026-10-01 10:00Z
const min = (n) => n * 60000;
const day = (n) => n * 86400000;
const isoZ = (t) => new Date(t).toISOString();
const q = (s) => `"${String(s == null ? "" : s).replace(/"/g, '""')}"`;

const ENTRA_HEADERS = ["Date (UTC)", "Request ID", "User", "Username", "User ID", "Application", "Status", "IP address", "Location", "City", "State/province",
  "Country/Region", "Client app", "Authentication requirement", "Multifactor authentication result", "Conditional Access", "Failure reason", "Browser", "Operating System", "Device ID", "Risk state", "Latitude", "Longitude"];

function entraCsv(rows, headers = ENTRA_HEADERS) {
  const lines = [headers.map(q).join(",")];
  let n = 0;
  for (const r of rows) {
    const rec = {
      "Date (UTC)": isoZ(r.ts), "Request ID": `req-${++n}`, "User": r.user.split("@")[0], "Username": r.user, "User ID": `uid-${r.user}`,
      "Application": r.app || "Office 365 Exchange Online", "Status": r.success ? "Success" : "Failure", "IP address": r.ip || "",
      "Location": [r.city, r.country].filter(Boolean).join(", "), "City": r.city || "", "State/province": r.state || "", "Country/Region": r.country || "",
      "Client app": r.clientApp || "Browser", "Authentication requirement": r.mfa === true ? "multiFactorAuthentication" : r.mfa === false ? "singleFactorAuthentication" : "",
      "Multifactor authentication result": r.mfa === true ? "MFA requirement satisfied by claim in the token" : "", "Conditional Access": "notApplied",
      "Failure reason": r.success ? "" : (r.reason || "Error validating credentials due to invalid username or password."), "Browser": "Edge 130.0.0", "Operating System": "Windows 11",
      "Device ID": "", "Risk state": r.risk || "none", "Latitude": r.lat == null ? "" : r.lat, "Longitude": r.lon == null ? "" : r.lon,
    };
    lines.push(headers.map((h) => q(rec[h] == null ? "" : rec[h])).join(","));
  }
  return lines.join("\r\n") + "\r\n";
}

const GOOGLE_HEADERS = ["Date", "Event Name", "Event Description", "User", "IP Address", "Login Type", "Is Suspicious", "Login Challenge Method", "Is Second Factor", "Login Failure Type"];
function googleCsv(rows) {
  const lines = [GOOGLE_HEADERS.join(",")];
  for (const r of rows) {
    const ev = r.event || (r.success ? "login_success" : "login_failure");
    lines.push([isoZ(r.ts), ev, q(r.success ? `${r.user} logged in` : `${r.user} failed to log in`), r.user, r.ip, r.loginType || "google_password",
      r.suspicious ? "TRUE" : "FALSE", "", r.mfa ? "TRUE" : "FALSE", r.success ? "" : (r.reason || "login_failure_invalid_password")].join(","));
  }
  return lines.join("\n") + "\n";
}

function oktaEvent(r) {
  return {
    uuid: `u-${Math.random().toString(36).slice(2)}`, published: isoZ(r.ts), eventType: r.type || "user.session.start", // darknode-ignore: test fixture event id, not a security value
    version: "0", severity: "INFO", legacyEventType: "core.user_auth.login_success", displayMessage: r.type === "user.authentication.auth_via_mfa" ? "Authentication of user via MFA" : "User login to Okta",
    actor: { id: `00u${r.user}`, type: "User", alternateId: r.user, displayName: r.user.split("@")[0] },
    client: { userAgent: { rawUserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0", os: "Windows 10", browser: "CHROME" }, zone: "null", device: "Computer", ipAddress: r.ip,
      geographicalContext: { city: r.city || "Dublin", state: null, country: r.country || "Ireland", postalCode: null, geolocation: { lat: r.lat == null ? 53.33 : r.lat, lon: r.lon == null ? -6.25 : r.lon } } },
    outcome: { result: r.success ? "SUCCESS" : "FAILURE", reason: r.success ? null : (r.reason || "INVALID_CREDENTIALS") },
    target: r.app ? [{ id: "0oa1", type: "AppInstance", alternateId: r.app, displayName: r.app }] : null,
    authenticationContext: { credentialType: r.type === "user.authentication.auth_via_mfa" ? "OTP" : "PASSWORD", authenticationStep: 0, externalSessionId: `sess-${r.user}` },
    securityContext: { asNumber: r.asn == null ? 5466 : r.asn, asOrg: r.isp || "eircom limited", isp: r.isp || "eircom limited", domain: "eircom.net", isProxy: !!r.proxy },
    debugContext: { debugData: { threatSuspected: "false" } },
  };
}
const oktaJson = (rows) => JSON.stringify(rows.map(oktaEvent));

// A quiet baseline: 6 users signing in once a day for 10 days from Dublin, MFA on.
function baseline(days = 10, users = ["ana@corp.example", "bo@corp.example", "cy@corp.example", "di@corp.example", "ed@corp.example", "fay@corp.example"]) {
  const out = [];
  for (let d = 0; d < days; d++) for (const u of users) out.push({ ts: T0 + day(d) + min(5), user: u, success: true, ip: "86.43.10.20", country: "IE", city: "Dublin", mfa: true, lat: 53.35, lon: -6.26 });
  return out;
}
const run = (rows, opts, csv = entraCsv) => { const p = parseAll(csv(rows)); return { p, r: analyze(p.records, opts, { columns: p.columns, source: p.source }) }; };
const byId = (r, id) => r.findings.filter((f) => f.id === id);
const cov = (r, id) => r.coverage.find((c) => c.id === id);

// ---------------------------------------------------------------------------
group("sif: csv tokenizer", () => {
  test("quoted commas stay inside a field", () => {
    const { headers, rows } = parseCsv('a,b\n"x, y",2\n');
    assert.deepEqual(headers, ["a", "b"]); assert.deepEqual(rows, [["x, y", "2"]]);
  });
  test("embedded newline inside quotes does not split the row", () => {
    const { rows } = parseCsv('a,b\n"line1\nline2",2\n');
    assert.equal(rows.length, 1); assert.equal(rows[0][0], "line1\nline2");
  });
  test("CRLF line endings and trailing newline", () => {
    const { rows } = parseCsv("a,b\r\n1,2\r\n3,4\r\n");
    assert.deepEqual(rows, [["1", "2"], ["3", "4"]]);
  });
  test("UTF-8 BOM is stripped from the first header", () => {
    const { headers } = parseCsv("﻿Date (UTC),User\n2026-10-01T10:00:00Z,a@b.c\n");
    assert.equal(headers[0], "Date (UTC)");
  });
  test("doubled quotes decode to one quote", () => {
    const { rows } = parseCsv('a\n"say ""hi"""\n');
    assert.equal(rows[0][0], 'say "hi"');
  });
  test("semicolon delimiter is sniffed", () => {
    assert.equal(sniffDelimiter("a;b;c\n1;2;3"), ";");
    const { rows } = parseCsv("a;b\n1;2\n");
    assert.deepEqual(rows, [["1", "2"]]);
  });
  test("blank lines are skipped and the generator yields row by row", () => {
    const rows = [...iterCsvRows("a,b\n\n1,2\n\n")];
    assert.equal(rows.length, 2);
  });
});

group("sif: source detection and value parsing", () => {
  test("Entra headers detected", () => assert.equal(detectSourceFromHeaders(ENTRA_HEADERS), "entra"));
  test("Google Login audit headers detected", () => assert.equal(detectSourceFromHeaders(GOOGLE_HEADERS), "google"));
  test("Okta event object detected", () => assert.equal(detectSourceFromObject(oktaEvent({ ts: T0, user: "a@b.c", ip: "1.2.3.4", success: true })), "okta"));
  test("generic CSV with user/ip/status recognised; unrelated CSV is unknown", () => {
    assert.equal(detectSourceFromHeaders(["time", "email", "source_ip", "result"]), "generic");
    assert.equal(detectSourceFromHeaders(["sku", "price", "qty"]), "unknown");
  });
  test("timestamps: ISO, epoch seconds, epoch ms, Google 'at' format, space-separated", () => {
    assert.equal(parseTs("2026-10-01T10:00:00Z"), T0);
    assert.equal(parseTs("1790848800"), T0);
    assert.equal(parseTs(1790848800000), T0);
    assert.equal(parseTs("October 1, 2026 at 10:00:00 AM UTC"), T0);
    assert.equal(parseTs("2026-10-01 10:00:00"), T0);
    assert.ok(Number.isNaN(parseTs("not a date")));
  });
  test("outcomes: Entra, Google and Okta vocabularies", () => {
    assert.equal(parseOutcome("Success"), true); assert.equal(parseOutcome("Failure"), false); assert.equal(parseOutcome("Interrupted"), null);
    assert.equal(parseOutcome("login_success"), true); assert.equal(parseOutcome("login_failure"), false); assert.equal(parseOutcome("logout"), null);
    assert.equal(parseOutcome("0"), true); assert.equal(parseOutcome("50126"), false);
  });
  test("MFA: Entra requirement wins over result text; Google boolean", () => {
    assert.equal(parseMfa("", "multiFactorAuthentication"), true);
    assert.equal(parseMfa("MFA requirement satisfied by claim in the token", ""), true);
    assert.equal(parseMfa("", "singleFactorAuthentication"), false);
    assert.equal(parseMfa("TRUE", undefined), true);
    assert.equal(parseMfa("", ""), null);
  });
  test("legacy client vocabulary", () => {
    for (const c of ["Exchange ActiveSync", "IMAP4", "POP3", "SMTP", "Authenticated SMTP", "Other clients", "MAPI Over HTTP", "exchange"]) assert.ok(isLegacyClient(c), c);
    for (const c of ["Browser", "Mobile Apps and Desktop clients", "google_password", "saml"]) assert.notOk(isLegacyClient(c), c);
  });
  test("admin hints: role column, admin app, username pattern; plain user is null", () => {
    assert.deepEqual(adminHint("x@c.e", null, "Global Administrator"), { isAdmin: true, basis: "role" });
    assert.deepEqual(adminHint("x@c.e", null, "Member"), { isAdmin: false, basis: "role" });
    assert.equal(adminHint("x@c.e", "Azure Portal", undefined).basis, "admin application");
    assert.equal(adminHint("it-admin@c.e", "Office 365", undefined).basis, "username pattern");
    assert.equal(adminHint("administrative-assistant@c.e", "Office 365", undefined).isAdmin, null);
    assert.equal(adminHint("ana@c.e", "Office 365", undefined).isAdmin, null);
  });
  test("hosting/VPN hint and /24 grouping", () => {
    assert.ok(hostingHint("DigitalOcean, LLC", "14061"));
    assert.equal(hostingHint("eircom limited", "5466"), null);
    assert.equal(subnet24("203.0.113.77"), "203.0.113.0/24");
    // IPv6: "::" expanded, zeros normalised, so one /64 written two ways groups together
    assert.equal(subnet24("2001:db8::1"), "2001:db8:0:0::/64");
    assert.equal(subnet24("2001:0DB8:0000:0000:abcd::1"), "2001:db8:0:0::/64");
    assert.equal(subnet24("::ffff:203.0.113.9"), "203.0.113.0/24");
  });
});

group("sif: geography", () => {
  test("haversine London to New York is about 5,570 km", () => {
    const km = haversineKm(51.5074, -0.1278, 40.7128, -74.006);
    assert.ok(Math.abs(km - 5570) < 30, `got ${km}`);
  });
  test("haversine zero distance and antipodes", () => {
    assert.equal(haversineKm(10, 10, 10, 10), 0);
    assert.ok(Math.abs(haversineKm(0, 0, 0, 180) - 20015) < 20);
  });
  test("resolvePlace prefers coordinates, then city, then country centroid", () => {
    assert.equal(resolvePlace({ lat: 1, lon: 2, city: "London", country: "GB" }).basis, "coordinates");
    assert.equal(resolvePlace({ lat: null, lon: null, city: "London", country: "GB" }).basis, "city");
    assert.equal(resolvePlace({ lat: null, lon: null, city: "Nowhereville", country: "Germany" }).basis, "country");
    assert.equal(resolvePlace({ lat: null, lon: null, city: null, country: "Atlantis" }), null);
  });
});

group("sif: normalisation per source", () => {
  test("Entra CSV: UPN, outcome, MFA, legacy client, location, coordinates", () => {
    const p = parseAll(entraCsv([{ ts: T0, user: "Ana@Corp.Example", success: true, ip: "86.43.10.20", country: "IE", city: "Dublin", mfa: false, clientApp: "IMAP4", lat: 53.35, lon: -6.26 }]));
    assert.equal(p.source, "entra"); assert.equal(p.records.length, 1);
    const r = p.records[0];
    assert.equal(r.user, "ana@corp.example"); assert.equal(r.success, true); assert.equal(r.mfa, false); assert.equal(r.clientApp, "IMAP4");
    assert.equal(r.country, "IE"); assert.equal(r.lat, 53.35); assert.equal(r.ts, T0);
    assert.ok(p.columns.mfa && p.columns.country && p.columns.latlon && p.columns.clientApp && !p.columns.role);
  });
  test("Google CSV: event names map to outcomes, logout dropped as non-auth, no location columns", () => {
    const p = parseAll(googleCsv([
      { ts: T0, user: "bo@corp.example", success: true, ip: "1.1.1.1", mfa: true },
      { ts: T0 + min(1), user: "bo@corp.example", success: false, ip: "1.1.1.1" },
      { ts: T0 + min(2), user: "bo@corp.example", event: "logout", ip: "1.1.1.1" },
    ]));
    assert.equal(p.source, "google"); assert.equal(p.records.length, 2); assert.equal(p.stats.nonAuth, 1);
    assert.equal(p.records[0].mfa, true); assert.equal(p.records[1].success, false); assert.equal(p.records[1].failureReason, "login_failure_invalid_password");
    assert.notOk(p.columns.country); assert.notOk(p.columns.latlon);
  });
  test("Okta JSON: actor, geo, ISP, and MFA correlated from auth_via_mfa events", () => {
    const p = parseAll(oktaJson([
      { ts: T0, user: "cy@corp.example", success: true, ip: "2.2.2.2" },
      { ts: T0 + min(1), user: "cy@corp.example", success: true, ip: "2.2.2.2", type: "user.authentication.auth_via_mfa" },
      { ts: T0 + min(30), user: "di@corp.example", success: true, ip: "3.3.3.3" },
    ]));
    assert.equal(p.source, "okta"); assert.equal(p.records.length, 3);
    const cy = p.records.find((r) => r.user === "cy@corp.example" && r.raw.eventType === "user.session.start");
    const di = p.records.find((r) => r.user === "di@corp.example");
    assert.equal(cy.mfa, true, "session start followed by MFA event is MFA'd");
    assert.equal(di.mfa, false, "session start with no MFA event is single-factor");
    assert.equal(cy.city, "Dublin"); assert.equal(cy.lat, 53.33); assert.equal(cy.isp, "eircom limited"); assert.equal(cy.isProxy, false);
  });
  test("Okta: an MFA factor deactivate is a settings change, not a sign-in (no fabricated travel)", () => {
    const p = parseAll(oktaJson([
      { ts: T0, user: "ok@corp.example", success: true, ip: "86.43.10.20", country: "IE", city: "Dublin", lat: 53.35, lon: -6.26 },
      { ts: T0 + min(10), user: "ok@corp.example", success: true, ip: "118.189.5.5", country: "SG", city: "Singapore", lat: 1.35, lon: 103.82, type: "user.mfa.factor.deactivate" },
    ]));
    const r = analyze(p.records, {}, { columns: p.columns, source: p.source });
    assert.equal(byId(r, "impossible_travel").length, 0, "an MFA settings change must not be compared as a login");
  });
  test("Okta NDJSON accepted; rows without timestamp or user are dropped and counted", () => {
    const nd = [oktaEvent({ ts: T0, user: "cy@corp.example", success: true, ip: "2.2.2.2" }), { eventType: "user.session.start", published: "garbage" }].map((e) => JSON.stringify(e)).join("\n");
    const p = parseAll(nd);
    assert.equal(p.records.length, 1); assert.equal(p.stats.badTs, 1);
  });
  test("pretty-printed wrapper object { value: [...] } parses (not mis-read as NDJSON)", () => {
    const events = [
      oktaEvent({ ts: T0, user: "cy@corp.example", success: true, ip: "2.2.2.2" }),
      oktaEvent({ ts: T0 + min(5), user: "di@corp.example", success: true, ip: "3.3.3.3" }),
    ];
    const p = parseAll(JSON.stringify({ value: events }, null, 2));
    assert.equal(p.records.length, 2); assert.equal(p.source, "okta");
  });
  test("pretty-printed single event object parses as one record", () => {
    const p = parseAll(JSON.stringify(oktaEvent({ ts: T0, user: "cy@corp.example", success: true, ip: "2.2.2.2" }), null, 2));
    assert.equal(p.records.length, 1);
  });
  test("createParser chunks until done and totals match", () => {
    const rows = baseline(3);
    const p = createParser(entraCsv(rows));
    let n = 0, calls = 0;
    while (!p.done()) { n += p.next(7).length; calls++; }
    assert.equal(n, rows.length); assert.ok(calls >= 3);
  });
});

group("sif: password spraying (T1110.003)", () => {
  const spray = (n) => Array.from({ length: n }, (_, i) => ({ ts: T0 + min(i * 2), user: `user${i}@corp.example`, success: false, ip: "203.0.113.9", country: "NL", city: "Amsterdam" }));
  test("positive: 10 users from one IP in 60 min at default threshold", () => {
    const { r } = run(baseline().concat(spray(10)));
    const f = byId(r, "password_spray");
    assert.equal(f.length, 1); assert.equal(f[0].ip, "203.0.113.9"); assert.equal(f[0].counts.distinctUsers, 10); assert.equal(f[0].technique, "T1110.003");
  });
  test("boundary: 9 users does not fire; threshold 9 does", () => {
    assert.equal(byId(run(baseline().concat(spray(9))).r, "password_spray").length, 0);
    assert.equal(byId(run(baseline().concat(spray(9)), { sprayUsers: 9 }).r, "password_spray").length, 1);
  });
  test("negative: the same failures spread over 10 hours do not fire", () => {
    const slow = spray(10).map((x, i) => Object.assign({}, x, { ts: T0 + min(i * 65) }));
    assert.equal(byId(run(baseline().concat(slow)).r, "password_spray").length, 0);
  });
  test("/24 rotation: 10 users across 10 addresses in one range fires once for the range", () => {
    const rot = spray(10).map((x, i) => Object.assign({}, x, { ip: `203.0.113.${10 + i}` }));
    const f = byId(run(baseline().concat(rot)).r, "password_spray");
    assert.equal(f.length, 1); assert.equal(f[0].ip, "203.0.113.0/24");
  });
});

group("sif: brute force (T1110.001)", () => {
  // starts 60 min after the baseline success so a quiet account is tested
  const brute = (n, gapMin = 1) => Array.from({ length: n }, (_, i) => ({ ts: T0 + min(60 + i * gapMin), user: "ana@corp.example", success: false, ip: "198.51.100.7", country: "RO", city: "Bucharest" }));
  test("positive: 20 failures on one account in 30 min", () => {
    const f = byId(run(baseline().concat(brute(20))).r, "brute_force");
    assert.equal(f.length, 1); assert.equal(f[0].user, "ana@corp.example"); assert.equal(f[0].severity, "medium");
  });
  test("boundary: 19 failures does not fire", () => assert.equal(byId(run(baseline().concat(brute(19))).r, "brute_force").length, 0));
  test("negative: 20 failures spread over 10 hours does not fire", () => assert.equal(byId(run(baseline().concat(brute(20, 30))).r, "brute_force").length, 0));
  test("severity rises to high when a success follows inside the window", () => {
    const rows = baseline().concat(brute(20)).concat([{ ts: T0 + min(81), user: "ana@corp.example", success: true, ip: "198.51.100.7", country: "RO", city: "Bucharest", mfa: false }]);
    const f = byId(run(rows).r, "brute_force");
    assert.equal(f[0].severity, "high");
  });
});

group("sif: failures then success (T1110.004 / T1078.004)", () => {
  const fails = (n, ip = "198.51.100.7") => Array.from({ length: n }, (_, i) => ({ ts: T0 + min(i), user: "bo@corp.example", success: false, ip, country: "RO", city: "Bucharest" }));
  test("positive: 5 failures then success from the same IP is critical", () => {
    const rows = baseline().concat(fails(5)).concat([{ ts: T0 + min(6), user: "bo@corp.example", success: true, ip: "198.51.100.7", country: "RO", city: "Bucharest", mfa: false }]);
    const f = byId(run(rows).r, "cred_stuffing_success");
    assert.equal(f.length, 1); assert.equal(f[0].severity, "critical"); assert.equal(f[0].counts.priorFailures, 5);
    assert.equal(f[0].evidence[f[0].evidence.length - 1].success, true);
  });
  test("same /24 but different address still correlates", () => {
    const rows = baseline().concat(fails(6, "198.51.100.7")).concat([{ ts: T0 + min(7), user: "bo@corp.example", success: true, ip: "198.51.100.200", country: "RO", mfa: true }]);
    assert.equal(byId(run(rows).r, "cred_stuffing_success").length, 1);
  });
  test("negative: success from an unrelated network after failures does not fire; 4 failures does not fire", () => {
    const other = baseline().concat(fails(6)).concat([{ ts: T0 + min(7), user: "bo@corp.example", success: true, ip: "86.43.10.20", country: "IE", mfa: true }]);
    assert.equal(byId(run(other).r, "cred_stuffing_success").length, 0);
    const few = baseline().concat(fails(4)).concat([{ ts: T0 + min(5), user: "bo@corp.example", success: true, ip: "198.51.100.7", country: "RO", mfa: true }]);
    assert.equal(byId(run(few).r, "cred_stuffing_success").length, 0);
  });
});

group("sif: impossible travel (T1078.004)", () => {
  test("positive with coordinates: Dublin then Singapore 40 minutes later", () => {
    const rows = baseline().concat([{ ts: T0 + min(40), user: "ana@corp.example", success: true, ip: "118.189.5.5", country: "SG", city: "Singapore", lat: 1.35, lon: 103.82, mfa: true }]);
    const f = byId(run(rows).r, "impossible_travel");
    assert.equal(f.length, 1); assert.equal(f[0].confidence, "high"); assert.ok(f[0].counts.km > 10000); assert.equal(f[0].counts.basis, "coordinates");
  });
  test("city lookup when the export has no coordinates: medium confidence", () => {
    const H = ENTRA_HEADERS.filter((h) => h !== "Latitude" && h !== "Longitude");
    const rows = baseline().concat([{ ts: T0 + min(40), user: "ana@corp.example", success: true, ip: "118.189.5.5", country: "SG", city: "Singapore", mfa: true }]);
    const p = parseAll(entraCsv(rows, H)); const r = analyze(p.records, {}, { columns: p.columns, source: p.source });
    const f = byId(r, "impossible_travel");
    assert.equal(f.length, 1); assert.equal(f[0].confidence, "medium"); assert.equal(f[0].counts.basis, "city");
  });
  test("negative: same distance 14 hours later is a plausible flight (about 800 km/h)", () => {
    const rows = baseline().concat([
      { ts: T0, user: "zed@corp.example", success: true, ip: "86.43.10.20", country: "IE", city: "Dublin", lat: 53.35, lon: -6.26, mfa: true },
      { ts: T0 + min(14 * 60), user: "zed@corp.example", success: true, ip: "118.189.5.5", country: "SG", city: "Singapore", lat: 1.35, lon: 103.82, mfa: true },
    ]);
    assert.equal(byId(run(rows).r, "impossible_travel").length, 0);
  });
  test("the return leg fires: a user back in Dublin 10 hours after Singapore (about 1,100 km/h)", () => {
    const rows = baseline().concat([{ ts: T0 + min(14 * 60), user: "ana@corp.example", success: true, ip: "118.189.5.5", country: "SG", city: "Singapore", lat: 1.35, lon: 103.82, mfa: true }]);
    const f = byId(run(rows).r, "impossible_travel");
    assert.equal(f.length, 1); assert.ok(f[0].counts.kmh > 900 && f[0].counts.kmh < 1300, String(f[0].counts.kmh));
  });
  test("negative: two sign-ins from the same IP with jittery geodata are ignored", () => {
    const rows = baseline().concat([{ ts: T0 + min(10), user: "ana@corp.example", success: true, ip: "86.43.10.20", country: "SG", city: "Singapore", lat: 1.35, lon: 103.82, mfa: true }]);
    assert.equal(byId(run(rows).r, "impossible_travel").length, 0);
  });
});

group("sif: new country (T1078)", () => {
  test("positive: first sign-in from a new country after 9 days of history is medium", () => {
    const rows = baseline().concat([{ ts: T0 + day(9) + min(60), user: "cy@corp.example", success: true, ip: "41.203.0.1", country: "NG", city: "Lagos", lat: 6.52, lon: 3.38, mfa: true }]);
    const f = byId(run(rows).r, "new_country");
    assert.equal(f.length, 1); assert.equal(f[0].severity, "medium"); assert.equal(f[0].counts.newCountry, "NG");
  });
  test("negative: a new country on day 2 (no baseline for that user yet) does not fire", () => {
    const rows = baseline().concat([{ ts: T0 + day(2), user: "cy@corp.example", success: true, ip: "41.203.0.1", country: "NG", city: "Lagos", mfa: true }]);
    assert.equal(byId(run(rows).r, "new_country").length, 0);
  });
  test("negative: a user's first-ever geolocated country is not a 'new' country", () => {
    // zz has a countryless success at T0 (establishes history) then their first country on day 9.
    const rows = baseline().concat([
      { ts: T0, user: "zz@corp.example", success: true, ip: "10.0.0.1", mfa: true },
      { ts: T0 + day(9) + min(60), user: "zz@corp.example", success: true, ip: "41.203.0.1", country: "NG", city: "Lagos", lat: 6.52, lon: 3.38, mfa: true },
    ]);
    assert.equal(byId(run(rows).r, "new_country").filter((f) => f.user === "zz@corp.example").length, 0);
  });
  test("skipped with reason when the dataset spans under 7 days", () => {
    const { r } = run(baseline(3));
    const c = cov(r, "new_country");
    assert.notOk(c.ran); assert.ok(/spans 2\.0 days/.test(c.reason), c.reason);
  });
});

group("sif: legacy auth (T1078)", () => {
  test("positive: IMAP4 success is medium, high for an administrator", () => {
    const rows = baseline().concat([
      { ts: T0 + min(5), user: "di@corp.example", success: true, ip: "86.43.10.20", country: "IE", clientApp: "IMAP4", mfa: false },
      { ts: T0 + min(6), user: "it-admin@corp.example", success: true, ip: "86.43.10.20", country: "IE", clientApp: "Exchange ActiveSync", mfa: false },
    ]);
    const f = byId(run(rows).r, "legacy_auth");
    assert.equal(f.length, 2);
    assert.equal(f.find((x) => x.user === "di@corp.example").severity, "medium");
    assert.equal(f.find((x) => x.user === "it-admin@corp.example").severity, "high");
  });
  test("negative: legacy failures and modern clients do not fire", () => {
    const rows = baseline().concat([{ ts: T0 + min(5), user: "di@corp.example", success: false, ip: "9.9.9.9", clientApp: "POP3" }]);
    assert.equal(byId(run(rows).r, "legacy_auth").length, 0);
  });
  test("skipped when the export has no client application column", () => {
    const H = ENTRA_HEADERS.filter((h) => h !== "Client app");
    const p = parseAll(entraCsv(baseline(), H)); const r = analyze(p.records, {}, { columns: p.columns, source: p.source });
    const c = cov(r, "legacy_auth");
    assert.notOk(c.ran); assert.ok(/client application/.test(c.reason), c.reason);
  });
});

group("sif: admin without MFA (T1556.006)", () => {
  test("positive via username pattern: high, medium confidence, basis named", () => {
    const rows = baseline().concat([{ ts: T0 + min(5), user: "it-admin@corp.example", success: true, ip: "86.43.10.20", country: "IE", app: "Office 365 Exchange Online", mfa: false }]);
    const f = byId(run(rows).r, "admin_no_mfa");
    assert.equal(f.length, 1); assert.equal(f[0].severity, "high"); assert.equal(f[0].confidence, "medium"); assert.equal(f[0].counts.basis, "username pattern");
  });
  test("positive via admin application (Azure Portal) for a plain username", () => {
    const rows = baseline().concat([{ ts: T0 + min(5), user: "ed@corp.example", success: true, ip: "86.43.10.20", country: "IE", app: "Azure Portal", mfa: false }]);
    assert.equal(byId(run(rows).r, "admin_no_mfa").length, 1);
  });
  test("negative: admin with MFA, and non-admin without MFA, do not fire", () => {
    const rows = baseline().concat([
      { ts: T0 + min(5), user: "it-admin@corp.example", success: true, ip: "86.43.10.20", country: "IE", mfa: true },
      { ts: T0 + min(6), user: "ed@corp.example", success: true, ip: "86.43.10.20", country: "IE", mfa: false },
    ]);
    assert.equal(byId(run(rows).r, "admin_no_mfa").length, 0);
  });
  test("skipped when no account is identified as an administrator", () => {
    const c = cov(run(baseline()).r, "admin_no_mfa");
    assert.notOk(c.ran); assert.ok(/administrator/.test(c.reason));
  });
});

group("sif: after-hours admin", () => {
  test("isAfterHours respects UTC offset and weekends", () => {
    const o = Object.assign({}, DEFAULTS);
    assert.notOk(isAfterHours(T0, o), "10:00Z Thursday at UTC+0 is in hours");
    assert.ok(isAfterHours(T0, Object.assign({}, o, { utcOffsetMin: 600 })), "20:00 local at UTC+10 is after hours");
    assert.ok(isAfterHours(T0 + day(2), o), "Saturday is after hours by default");
    assert.notOk(isAfterHours(T0 + day(2), Object.assign({}, o, { weekendIsAfterHours: false })));
  });
  test("positive: admin success at 03:00 local fires medium; same event inside hours does not", () => {
    const night = baseline().concat([{ ts: T0 + day(4) + min(-7 * 60), user: "it-admin@corp.example", success: true, ip: "86.43.10.20", country: "IE", mfa: true }]); // Mon 03:00Z
    const f = byId(run(night).r, "after_hours_admin");
    assert.equal(f.length, 1); assert.equal(f[0].severity, "medium"); assert.equal(f[0].counts.afterHours, 1);
    const dayt = baseline().concat([{ ts: T0 + day(4) + min(60), user: "it-admin@corp.example", success: true, ip: "86.43.10.20", country: "IE", mfa: true }]); // Mon 11:00Z
    assert.equal(byId(run(dayt).r, "after_hours_admin").length, 0);
  });
});

group("sif: concurrent distant sessions", () => {
  test("positive: two countries within 30 min from different IPs, no coordinates (country basis)", () => {
    const H = ENTRA_HEADERS.filter((h) => h !== "Latitude" && h !== "Longitude" && h !== "City");
    const rows = baseline().concat([{ ts: T0 + min(10), user: "fay@corp.example", success: true, ip: "200.1.1.1", country: "BR", mfa: true }]);
    const p = parseAll(entraCsv(rows, H)); const r = analyze(p.records, { travelSpeedKmh: 1e9 }, { columns: p.columns, source: p.source });
    const f = byId(r, "concurrent_distant");
    assert.equal(f.length, 1); assert.equal(f[0].user, "fay@corp.example");
  });
  test("a pair already reported as impossible travel is not double-counted", () => {
    const rows = baseline().concat([{ ts: T0 + min(10), user: "fay@corp.example", success: true, ip: "200.1.1.1", country: "BR", city: "Sao Paulo", lat: -23.55, lon: -46.63, mfa: true }]);
    const { r } = run(rows);
    assert.equal(byId(r, "impossible_travel").length, 1); assert.equal(byId(r, "concurrent_distant").length, 0);
  });
  test("negative: two sign-ins from the same country do not fire", () => {
    const rows = baseline().concat([{ ts: T0 + min(10), user: "fay@corp.example", success: true, ip: "86.43.99.99", country: "IE", city: "Cork", mfa: true }]);
    assert.equal(byId(run(rows).r, "concurrent_distant").length, 0);
  });
});

group("sif: anonymiser/hosting ASN and provider flags", () => {
  test("Okta: success from a hosting ASN fires; provider isProxy raises severity", () => {
    const p = parseAll(oktaJson([
      { ts: T0, user: "ana@corp.example", success: true, ip: "86.43.10.20" },
      { ts: T0 + min(5), user: "bo@corp.example", success: true, ip: "165.22.1.1", isp: "DigitalOcean, LLC", asn: 14061 },
      { ts: T0 + min(6), user: "cy@corp.example", success: true, ip: "185.220.101.1", isp: "Zwiebelfreunde e.V.", asn: 60729, proxy: true },
    ]));
    const r = analyze(p.records, {}, { columns: p.columns, source: p.source });
    const f = byId(r, "anonymizer_asn");
    assert.equal(f.length, 2);
    assert.equal(f.find((x) => x.user === "bo@corp.example").severity, "medium");
    assert.equal(f.find((x) => x.user === "cy@corp.example").severity, "high");
  });
  test("skipped (not guessed) when the export has no ASN/ISP column", () => {
    const c = cov(run(baseline()).r, "anonymizer_asn");
    assert.notOk(c.ran); assert.ok(/no network lookups/.test(c.reason));
  });
  test("Entra 'Risk state' atRisk and Google suspicious_login surface as provider flags", () => {
    const e = run(baseline().concat([{ ts: T0 + min(5), user: "ed@corp.example", success: true, ip: "86.43.10.20", country: "IE", mfa: true, risk: "atRisk" }])).r;
    assert.equal(byId(e, "provider_risk_flag").length, 1);
    const g = parseAll(googleCsv([{ ts: T0, user: "bo@corp.example", success: true, ip: "1.1.1.1", mfa: true }, { ts: T0 + min(2), user: "bo@corp.example", event: "suspicious_login", success: true, ip: "5.5.5.5", suspicious: true }]));
    const gr = analyze(g.records, {}, { columns: g.columns, source: g.source });
    assert.equal(byId(gr, "provider_risk_flag").length, 1);
    assert.notOk(cov(run(baseline()).r, "provider_risk_flag").ran);
  });
});

group("sif: coverage honesty for a Google export", () => {
  test("location detections are skipped and the reason names the missing columns", () => {
    const p = parseAll(googleCsv([{ ts: T0, user: "bo@corp.example", success: true, ip: "1.1.1.1", mfa: true }, { ts: T0 + day(8), user: "bo@corp.example", success: true, ip: "1.1.1.1", mfa: true }]));
    const r = analyze(p.records, {}, { columns: p.columns, source: p.source });
    assert.notOk(cov(r, "impossible_travel").ran); assert.ok(/position/.test(cov(r, "impossible_travel").reason));
    assert.notOk(cov(r, "new_country").ran); assert.ok(/Google Login audit/.test(cov(r, "new_country").reason));
    assert.ok(cov(r, "password_spray").ran); assert.ok(cov(r, "brute_force").ran);
  });
  test("every detection has an ATT&CK technique and appears in coverage", () => {
    const { r } = run(baseline());
    assert.equal(r.coverage.length, DETECTIONS.length);
    for (const d of DETECTIONS) assert.ok(/T1\d{3}/.test(d.technique), d.id);
  });
});

group("sif: scoring, timeline and exports", () => {
  const scenario = () => baseline().concat(
    Array.from({ length: 6 }, (_, i) => ({ ts: T0 + min(i), user: "bo@corp.example", success: false, ip: "198.51.100.7", country: "RO", city: "Bucharest" })),
    [{ ts: T0 + min(7), user: "bo@corp.example", success: true, ip: "198.51.100.7", country: "RO", city: "Bucharest", lat: 44.43, lon: 26.1, mfa: false }],
  );
  test("the compromised user ranks first with a score; quiet users score 0", () => {
    const { r } = run(scenario());
    assert.equal(r.users[0].user, "bo@corp.example"); assert.ok(r.users[0].score >= 40);
    assert.equal(r.users[r.users.length - 1].score, 0);
    assert.ok(r.score.overall >= 40); assert.ok(/Per-user scores/.test(r.score.explanation));
  });
  test("an all-quiet dataset scores 0 with an explicit no-findings explanation", () => {
    const { r } = run(baseline());
    assert.equal(r.findings.length, 0); assert.equal(r.score.overall, 0); assert.equal(r.score.label, "No findings");
  });
  test("userTimeline marks the rows a finding cites", () => {
    const { p, r } = run(scenario());
    const tl = userTimeline(r, p.records, "bo@corp.example");
    assert.ok(tl.length >= 17);
    assert.ok(tl.some((row) => row.flags.length > 0 && row.success === true));
    assert.ok(tl.every((row, i) => i === 0 || row.ts >= tl[i - 1].ts), "sorted by time");
  });
  test("CSV exports have headers, one line per finding / evidence row, and quote commas", () => {
    const { r } = run(scenario());
    const csv = findingsToCsv(r.findings);
    assert.equal(csv.split("\n").length - 2, r.findings.length);
    assert.ok(csv.startsWith("severity,confidence,detection,technique,"));
    const ev = evidenceToCsv(r.findings);
    assert.equal(ev.split("\n").length - 2, r.findings.reduce((n, f) => n + f.evidence.length, 0));
  });
  test("summary text states source, counts and skipped detections", () => {
    const { r } = run(scenario());
    const s = summaryText(r);
    assert.ok(/Microsoft Entra ID/.test(s)); assert.ok(/Detections run: \d+\/\d+/.test(s)); assert.ok(/CRITICAL/.test(s));
  });
  test("correlateOktaMfa leaves explicit MFA values alone", () => {
    const recs = [{ ts: T0, user: "a", success: true, mfa: true }, { ts: T0 + 1000, user: "a", success: true, mfa: null }, { ts: T0 + day(1), user: "a", success: true, mfa: null }];
    correlateOktaMfa(recs);
    assert.equal(recs[1].mfa, true); assert.equal(recs[2].mfa, false);
  });
});

group("sif: Security Graph sink mapping", () => {
  const spray = (n) => Array.from({ length: n }, (_, i) => ({ ts: T0 + min(i * 2), user: `user${i}@corp.example`, success: false, ip: "203.0.113.9", country: "NL", city: "Amsterdam" }));
  const stuffing = () => baseline().concat(
    Array.from({ length: 6 }, (_, i) => ({ ts: T0 + min(i), user: "bo@corp.example", success: false, ip: "198.51.100.7", country: "RO", city: "Bucharest" })),
    [{ ts: T0 + min(7), user: "bo@corp.example", success: true, ip: "198.51.100.7", country: "RO", city: "Bucharest", lat: 44.43, lon: 26.1, mfa: false }],
    spray(10),
  );
  test("required fields, normalised severity, stable ids/titles across runs, sample tagging", () => {
    const a = toSinkFindings(run(stuffing()).r), b = toSinkFindings(run(stuffing()).r);
    const { items } = checkSinkFindings("signins", a, b, { minFindings: 2 });
    assert.ok(items.some((i) => i.type === "IDENTITY" && i.name === "bo@corp.example"));
    assert.ok(items.some((i) => i.type === "IP" && i.name === "203.0.113.9"));
    assert.ok(items.some((i) => i.type === "CONTROL" && i.name === "MITRE T1110.003"));
  });
  test("spray graph title ignores the target count; the counted title moves to the description", () => {
    const f10 = toSinkFindings(run(baseline().concat(spray(10))).r).find((f) => f.category === "password_spray");
    const f14 = toSinkFindings(run(baseline().concat(spray(14))).r).find((f) => f.category === "password_spray");
    assert.equal(f10.title, "Password spraying: 203.0.113.9"); assert.equal(f10.id, f14.id); assert.equal(f10.title, f14.title);
    assert.ok(/10 accounts/.test(f10.description) && /14 accounts/.test(f14.description));
    assert.equal(f10.assets.filter((x) => x.type === "IDENTITY").length, 10);
  });
});

group("signin-forensics: impossible travel with country-level locations", () => {
  const mk = (t, ip, o) => Object.assign({ ts: Date.UTC(2026, 9, 1, 10, t), user: "u@x", ip, success: true, app: "a", clientApp: "Browser", mfa: true, country: null, city: null, lat: null, lon: null, raw: {} }, o);
  const travel = (recs) => analyze(recs.map((x, i) => Object.assign(x, { _i: i })), {}, {}).findings.filter((f) => f.id === "impossible_travel");
  test("a city/coordinate fix and a same-country centroid are not impossible travel", () => {
    assert.equal(travel([mk(0, "1.1.1.1", { lat: 40.71, lon: -74.01, country: "US" }), mk(30, "2.2.2.2", { country: "United States" })]).length, 0);
    assert.equal(travel([mk(0, "1.1.1.1", { city: "Moscow", country: "RU" }), mk(20, "2.2.2.2", { country: "RU" })]).length, 0);
  });
  test("different countries are still compared", () => {
    assert.equal(travel([mk(0, "1.1.1.1", { city: "London", country: "GB" }), mk(60, "2.2.2.2", { country: "JP" })]).length, 1);
  });
});
