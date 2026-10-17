// Endpoint Fleet Compliance engine tests (public/js/exposure/fleetcomply-engine.js).
// One fixture per vendor export in its exact header layout, device matching precedence,
// Windows build / macOS version comparison, EOL mapping (unknown -> skipped), every check on a
// crafted positive and a silent negative, coverage gaps, score maths, blocklist regex,
// determinism, the in-engine self-test and the CSV serialisers.

import { test, assert, group } from "../harness.mjs";
import {
  TOOL_ID, FORMATS, WEIGHTS, DETECTIONS, DEVICE_COLS,
  parseTs, parseBool, normSerial, normHost, normMac, verTuple, cmpVer, parseWinBuild, osFamily,
  eolIndex, cycleStatus, mapOsCycle, mapAppProduct, classifyHeaders, classifyJson, detectFile,
  parseInput, matchDevices, parseMatchList, analyze,
  findingsToCsv, devicesToCsv, softwareToCsv, worklistToCsv, coverageToCsv, summaryText, exampleDataset, selfTest,
} from "../../public/js/exposure/fleetcomply-engine.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------
const NOW = "2026-10-16T12:00:00Z";
// EOL fixture: cycle values copied from the endoflife.date cycles they name.
const EOL = { updated: "fixture", data: [
  { product: "windows", cycles: [
    { cycle: "11-25h2-e", eol: "2028-10-10", latest: "10.0.26200" }, { cycle: "11-25h2-w", eol: "2027-10-12", latest: "10.0.26200" },
    { cycle: "11-24h2-e", eol: "2027-10-12", latest: "10.0.26100" }, { cycle: "11-24h2-w", eol: "2026-10-13", latest: "10.0.26100" },
    { cycle: "11-24h2-e-lts", eol: "2029-10-09", latest: "10.0.26100" },
    { cycle: "11-23h2-e", eol: "2026-11-10", latest: "10.0.22631" }, { cycle: "11-23h2-w", eol: "2025-11-11", latest: "10.0.22631" },
    { cycle: "10-22h2", eol: "2025-10-14", latest: "10.0.19045" }] },
  { product: "windows-server", cycles: [{ cycle: "2019", eol: "2029-01-09", latest: "10.0.17763", lts: true }, { cycle: "2016", eol: "2027-01-12", latest: "10.0.14393", lts: true }] },
  { product: "macos", cycles: [{ cycle: "26", eol: false, latest: "26.0.1" }, { cycle: "15", eol: false, latest: "15.7.1" }, { cycle: "14", eol: "2026-09-14", latest: "14.8.1" }, { cycle: "10.15", eol: "2022-09-12", latest: "10.15.7" }] },
  { product: "ubuntu", cycles: [{ cycle: "22.04", eol: "2027-04-01" }] },
  { product: "ios", cycles: [{ cycle: "17", eol: true }] },
  { product: "chrome", cycles: [{ cycle: "155", eol: "2026-10-20" }, { cycle: "138", eol: "2025-08-05" }] },
  { product: "office", cycles: [{ cycle: "2016", eol: "2025-10-14" }] },
  { product: "python", cycles: [{ cycle: "3.9", eol: "2025-10-31" }, { cycle: "3.13", eol: "2029-10-31" }] },
] };
const IDX = eolIndex(EOL);

const q = (v) => (/[",\n]/.test(String(v)) ? '"' + String(v).replace(/"/g, '""') + '"' : String(v));
/** CSV in a vendor's exact header layout; rows are objects keyed by header name. */
const csvOf = (format, rows) => [FORMATS[format].headers.map(q).join(","), ...rows.map((r) => FORMATS[format].headers.map((h) => q(r[h] == null ? "" : r[h])).join(","))].join("\n");
const file = (name, format, rows) => ({ name, text: csvOf(format, rows) });

const intune = (o) => ({ "Device name": "WIN-01", "Managed by": "Intune", Ownership: "Corporate", Compliance: "Compliant", OS: "Windows", "OS version": "10.0.26200.6899",
  "Primary user UPN": "ana@test.darknode.ai", "Last check-in": "2026-10-15 10:00:00", "Serial number": "SN0001", Manufacturer: "Dell Inc.", Model: "OptiPlex 7010", Encrypted: "Yes", ...o });
const falcon = (o) => ({ Hostname: "WIN-01", "Host ID": "a".repeat(32), "Last Seen": "2026-10-15T10:00:00Z", OS: "Windows", "OS Version": "Windows 11", Platform: "Windows",
  "Sensor Version": "7.29.20004.0", "Agent Status": "Normal", "RFM (Reduced Functionality Mode)": "No", "Serial Number": "SN0001", ...o });
const entra = (o) => ({ Name: "WIN-01", Enabled: "True", "Operating system": "Windows", Version: "10.0.26200.6899", "Join type": "Microsoft Entra joined", Owner: "ana@test.darknode.ai",
  MDM: "Microsoft Intune", Compliant: "Yes", "Activity (last sign-in)": "10/15/2026, 9:00:00 AM", ...o });
const jamf = (o) => ({ "Computer Name": "MBP-01", "Serial Number": "C02XJ1AAQ6L", "Last Check-in": "2026-10-15 09:00:00", "Operating System Version": "15.7.1", Model: "MacBook Pro (14-inch, 2023)",
  Username: "lee", "FileVault 2 Status": "All Partitions Encrypted", Gatekeeper: "App Store and identified developers", "System Integrity Protection": "Enabled", "Firewall Enabled": "Yes",
  Managed: "Yes", "Recovery Lock Enabled": "Yes", "Activation Lock": "Enabled", ...o });

const run = (files, o) => analyze(files, { now: NOW, eol: EOL, ...o });
const hit = (r, check) => r.findings.find((f) => f.check === check);
const names = (r, check) => (hit(r, check) ? hit(r, check).evidence.map((e) => e.device).sort() : []);
const skipped = (r, check) => r.skipped.filter((s) => s.check === check);

// ---------------------------------------------------------------------------
group("fleetcomply: format detection", () => {
  for (const [key, f] of Object.entries(FORMATS)) {
    if (!f.headers) continue;
    test("detects " + key + " from its exact header row", () => {
      const d = detectFile({ name: key + ".csv", text: f.headers.map(q).join(",") + "\n" + f.headers.map(() => "x").join(",") });
      assert.equal(d.format, key);
      assert.equal(d.confidence, "high");
    });
  }

  test("partial header set is medium confidence; unrelated headers fall back to generic", () => {
    const h = FORMATS.crowdstrike.headers.slice(0, 13);
    assert.equal(classifyHeaders(h).format, "crowdstrike");
    assert.equal(classifyHeaders(h).confidence, "medium");
    assert.equal(classifyHeaders(["hostname", "serial", "owner"]).format, "generic");
  });

  test("Workstation Audit fleet record (real darknode-app toFleetRecord shape)", () => {
    const rec = { host: "WIN-LT-002", os: "Windows 10.0.26200", generated: "2026-10-15T14:02:11.000Z", appVersion: "1.9.0", score: { percent: 78, grade: "C" },
      results: [{ id: "disk-encryption", status: "pass", severity: "high", cisRef: "x" }, { id: "firewall", status: "fail", severity: "high", cisRef: "y" }] };
    assert.equal(classifyJson(rec).format, "dn-audit");
    assert.equal(detectFile({ name: "a.json", text: JSON.stringify([rec, rec]) }).format, "dn-audit");
    const p = parseInput([{ name: "a.json", text: JSON.stringify(rec) }]);
    const d = p.sources[0].devices[0];
    assert.equal(d.host, "win-lt-002");
    assert.equal(d.encrypted, true);
    assert.equal(d.firewall, false);
  });

  test("Workstation Audit fallback shape with host object and checks[]", () => {
    const rec = { tool: "darknode-app", kind: "workstation-audit", host: { hostname: "MBP-9", os: "macOS", osVersion: "15.7.1", serial: "C02ZZ9ZZQ6L", user: "kim" }, collectedAt: "2026-10-15T10:00:00Z",
      checks: [{ id: "disk-encryption", status: "fail" }, { id: "firewall", status: "pass" }] };
    const p = parseInput([{ name: "audit.json", text: JSON.stringify(rec) }]);
    assert.equal(p.sources[0].format, "dn-audit");
    const d = p.sources[0].devices[0];
    assert.equal(d.serial, "C02ZZ9ZZQ6L");
    assert.equal(d.encrypted, false);
    assert.equal(d.firewall, true);
  });

  test("Graph managedDevices and Jamf Pro API JSON are recognised", () => {
    const graph = { value: [{ deviceName: "WIN-02", serialNumber: "SN0002", operatingSystem: "Windows", osVersion: "10.0.26100.4652", complianceState: "noncompliant", isEncrypted: false, lastSyncDateTime: "2026-10-15T08:00:00Z", userPrincipalName: "bo@test.darknode.ai", model: "Latitude 7450" }] };
    const p = parseInput([{ name: "managedDevices.json", text: JSON.stringify(graph) }]);
    assert.equal(p.sources[0].format, "graph-managed");
    assert.equal(p.sources[0].devices[0].encrypted, false);
    assert.equal(p.sources[0].devices[0].compliance, "noncompliant");
    const jamfApi = { totalCount: 1, results: [{ id: "1", general: { name: "MBP-02", lastContactTime: "2026-10-15T09:00:00Z" }, hardware: { serialNumber: "C02AAAAAQ6L", model: "MacBook Air" }, operatingSystem: { version: "14.8.1", fileVault2Status: "NOT_ENCRYPTED" }, security: { firewallEnabled: false } }] };
    const j = parseInput([{ name: "inventory.json", text: JSON.stringify(jamfApi) }]);
    assert.equal(j.sources[0].format, "jamf-api");
    assert.equal(j.sources[0].devices[0].encrypted, false);
    assert.equal(j.sources[0].devices[0].firewall, false);
  });

  test("garbage and empty files are reported, not parsed", () => {
    const p = parseInput([{ name: "x.json", text: "{not json" }, { name: "e.csv", text: "" }]);
    assert.equal(p.sources.reduce((s, x) => s + x.devices.length, 0), 0);
    assert.ok(p.skipped.length >= 1);
  });
});

group("fleetcomply: parsing", () => {
  test("Intune devices export: encryption, compliance, laptop and user", () => {
    const p = parseInput([file("IntuneDevices.csv", "intune-devices", [intune({ Model: "Latitude 7450", Encrypted: "No", Compliance: "Noncompliant" })])]);
    const d = p.sources[0].devices[0];
    assert.equal(p.sources[0].format, "intune-devices");
    assert.equal(d.encrypted, false);
    assert.equal(d.compliance, "noncompliant");
    assert.equal(d.user, "ana@test.darknode.ai");
    assert.equal(d.serial, "SN0001");
  });

  test("CrowdStrike host export: RFM becomes an EDR health issue", () => {
    const p = parseInput([file("hosts.csv", "crowdstrike", [falcon({ "RFM (Reduced Functionality Mode)": "Yes" })])]);
    const d = p.sources[0].devices[0];
    assert.equal(p.sources[0].kind, "edr");
    assert.ok(d.edrIssues.some((x) => /rfm|reduced/i.test(x)));
    assert.equal(d.sensorVersion, "7.29.20004.0");
  });

  test("Jamf computers export: FileVault, Gatekeeper, SIP, firewall", () => {
    const p = parseInput([file("jamf.csv", "jamf-computers", [jamf({ "FileVault 2 Status": "Not Encrypted", Gatekeeper: "Off", "Firewall Enabled": "No" })])]);
    const d = p.sources[0].devices[0];
    assert.equal(d.encrypted, false);
    assert.equal(d.gatekeeper, false);
    assert.equal(d.sip, true);
    assert.equal(d.firewall, false);
    assert.equal(d.family, "macos");
  });

  test("Entra devices export: enabled flag, unmanaged when MDM is empty", () => {
    const p = parseInput([file("entra.csv", "entra-devices", [entra({ Name: "DESKTOP-ABC", MDM: "" })])]);
    const d = p.sources[0].devices[0];
    assert.equal(d.enabled, true);
    assert.equal(d.managed, false);
    assert.equal(parseTs("10/15/2026, 9:00:00 AM"), Date.parse("2026-10-15T09:00:00Z"));
  });

  test("ChromeOS export: Auto-update Expiration drives EOL (not in the feed)", () => {
    const p = parseInput([file("chrome.csv", "chromeos", [{ "Serial Number": "5CD1234ABC", Status: "ACTIVE", "Last Sync": "2026-10-15", User: "kim@test.darknode.ai", "OS Version": "128.0.6613.0", Model: "HP Chromebook", "Auto-update Expiration": "2026-06" }])]);
    const d = p.sources[0].devices[0];
    assert.equal(d.family, "chromeos");
    const m = mapOsCycle(d, IDX);
    assert.equal(m.product, "chromeos-aue");
    assert.equal(cycleStatus(m.cycle, Date.parse(NOW)).status, "eol");
  });

  test("software exports: Intune discovered apps, SCCM and Lansweeper rows", () => {
    const p = parseInput([
      file("apps.csv", "intune-apps", [{ "Device name": "WIN-01", "App name": "Google Chrome", "App version": "155.0.1", Platform: "Windows", Publisher: "Google LLC" }]),
      file("sccm.csv", "sccm-software", [{ "Computer Name": "WIN-02", "Product Name": "7-Zip", "Product Version": "24.08", Publisher: "Igor Pavlov" }]),
      file("ls.csv", "lansweeper", [{ AssetName: "WIN-03", Software: "AnyDesk", Version: "9.0.4", Publisher: "AnyDesk Software GmbH" }]),
    ]);
    assert.deepEqual(p.sources.map((s) => s.kind), ["software", "software", "software"]);
    assert.deepEqual(p.sources.map((s) => s.software[0].name), ["Google Chrome", "7-Zip", "AnyDesk"]);
  });

  test("duplicate rows in one source collapse to the newest", () => {
    const p = parseInput([file("i.csv", "intune-devices", [intune({ "Last check-in": "2026-09-01 10:00:00", Encrypted: "No" }), intune({ "Last check-in": "2026-10-15 10:00:00", Encrypted: "Yes" })])]);
    assert.equal(p.sources[0].devices.length, 1);
    assert.equal(p.sources[0].devices[0].encrypted, true);
  });

  test("generic CSV with a column mapping override", () => {
    const text = "Machine,SN,Bitlocker\nPC-77,SN7777,No\n";
    const p = parseInput([{ name: "custom.csv", text }], { columns: { "custom.csv": { name: "Machine", serial: "SN", encrypted: "Bitlocker" } } });
    const d = p.sources[0].devices[0];
    assert.equal(p.sources[0].format, "generic");
    assert.equal(d.serial, "SN7777");
    assert.equal(d.encrypted, false);
  });
});

group("fleetcomply: matching", () => {
  test("hostname normalisation strips domains and DOMAIN\\ prefixes; IPs are ignored", () => {
    assert.equal(normHost("WIN-01.corp.example.com"), "win-01");
    assert.equal(normHost("CORP\\WIN-01"), "win-01");
    assert.equal(normHost("10.1.2.3"), "");
    assert.equal(normSerial(" sn0001 "), "SN0001");
    assert.equal(normSerial("To Be Filled By O.E.M."), "");
    assert.equal(normMac("AA-BB-CC-00-11-22"), "aabbcc001122");
  });

  test("FQDN in EDR joins the short MDM name into one device", () => {
    const r = run([file("i.csv", "intune-devices", [intune({ "Serial number": "" })]), file("c.csv", "crowdstrike", [falcon({ Hostname: "WIN-01.corp.example.com", "Serial Number": "" })])]);
    assert.equal(r.summary.devices, 1);
    assert.deepEqual(r.tables.devices[0].sources.length, 2);
  });

  test("serial wins over hostname: same name with different serials stays two devices", () => {
    const r = run([file("i.csv", "intune-devices", [intune({ "Serial number": "SN0001" })]), file("c.csv", "crowdstrike", [falcon({ "Serial Number": "SN0999" })])]);
    assert.equal(r.summary.devices, 2);
  });

  test("serial match joins records with different hostnames", () => {
    const r = run([file("i.csv", "intune-devices", [intune({ "Device name": "LAPTOP-OLD" })]), file("c.csv", "crowdstrike", [falcon({ Hostname: "WIN-NEW" })])]);
    assert.equal(r.summary.devices, 1);
  });

  test("matchDevices records hostname conflicts between different serials", () => {
    const recs = [
      { kind: "mdm", src: 0, row: 0, serial: "SN1", host: "pc", ids: [], mac: "" },
      { kind: "edr", src: 1, row: 0, serial: "SN2", host: "pc", ids: [], mac: "" },
      { kind: "directory", src: 2, row: 0, serial: "", host: "", ids: [], mac: "001122334455" },
      { kind: "edr", src: 1, row: 1, serial: "", host: "other", ids: [], mac: "001122334455" },
    ];
    const m = matchDevices(recs);
    assert.equal(m.groups.length, 3);
    assert.equal(m.conflicts.length, 1);
    assert.equal(m.conflicts[0].key, "hostname");
    assert.deepEqual(m.conflicts[0].serials, ["SN1", "SN2"]);
    assert.equal(m.groupOf.get(recs[2]), m.groupOf.get(recs[3]));
  });
});

group("fleetcomply: versions and EOL", () => {
  test("Windows build parsing and comparison", () => {
    assert.deepEqual(parseWinBuild("10.0.19045.4651"), { major: 10, build: 19045, rev: 4651 });
    assert.deepEqual(parseWinBuild("19045"), { major: 10, build: 19045, rev: null });
    assert.equal(parseWinBuild("Windows"), null);
    assert.equal(cmpVer("10.0.26100.4652", "10.0.26100.6899"), -1);
    assert.equal(cmpVer("10.0.26200", "10.0.26100.9999"), 1);
  });

  test("macOS version comparison is numeric, not lexical", () => {
    assert.equal(cmpVer("15.10", "15.9"), 1);
    assert.equal(cmpVer("14.8.1", "14.8.1"), 0);
    assert.equal(cmpVer("10.15.7", "11.0"), -1);
    assert.deepEqual(verTuple("Sequoia 15.7.1 (24G231)"), [15, 7, 1]);
  });

  test("Windows build maps to the edition cycle", () => {
    const m = (os, v, o) => { const c = mapOsCycle({ family: osFamily(os, v), os, osVersion: v }, IDX, o).cycle; return c && c.cycle; };
    assert.equal(m("Windows", "10.0.26100.4652"), "11-24h2-w");
    assert.equal(m("Windows", "10.0.26100.4652", { windowsEdition: "e" }), "11-24h2-e");
    assert.equal(m("Windows 11 Enterprise", "10.0.22631"), "11-23h2-e");
    assert.equal(m("Windows 11 Enterprise LTSC", "10.0.26100"), "11-24h2-e-lts");
    assert.equal(m("Windows10", "22H2"), "10-22h2");
    assert.equal(m("Windows Server 2019 Datacenter", "10.0.17763"), "2019");
  });

  test("macOS, Darwin (audit), Ubuntu and iOS mapping", () => {
    assert.equal(mapOsCycle({ family: "macos", os: "macOS", osVersion: "14.8.1" }, IDX).cycle.cycle, "14");
    assert.equal(mapOsCycle({ family: "macos", os: "macOS 23.4.0", osVersion: "", darwin: true }, IDX).cycle.cycle, "14");
    assert.equal(mapOsCycle({ family: "macos", os: "macOS", osVersion: "10.15.7" }, IDX).cycle.cycle, "10.15");
    assert.equal(mapOsCycle({ family: "ubuntu", os: "Ubuntu 22.04.5 LTS", osVersion: "" }, IDX).cycle.cycle, "22.04");
    assert.equal(mapOsCycle({ family: "ios", os: "iOS", osVersion: "17.6.1" }, IDX).cycle.cycle, "17");
  });

  test("unknown OS is not guessed: it is reported in skipped", () => {
    const u = mapOsCycle({ family: "linux", os: "Linux 6.8.0", osVersion: "" }, IDX);
    assert.equal(u.cycle, null);
    assert.ok(u.reason);
    const r = run([file("i.csv", "intune-devices", [intune({ OS: "Linux", "OS version": "6.8.0" })])]);
    assert.equal(r.tables.devices[0].eolStatus, "unknown");
    assert.ok(skipped(r, "os_eol").some((s) => /not mapped/.test(s.reason)));
  });

  test("cycle status: eol, soon, supported, eol:true/false", () => {
    const now = Date.parse(NOW);
    assert.equal(cycleStatus({ eol: "2025-10-14" }, now).status, "eol");
    assert.equal(cycleStatus({ eol: "2026-11-10" }, now).status, "soon");
    assert.equal(cycleStatus({ eol: "2026-11-10" }, now, 10).status, "supported");
    assert.equal(cycleStatus({ eol: false }, now).status, "supported");
    assert.equal(cycleStatus({ eol: true }, now).status, "eol");
    assert.equal(cycleStatus(null, now).status, "unknown");
  });

  test("software titles map to EOL products; unmapped titles return null", () => {
    assert.deepEqual(mapAppProduct("Google Chrome", "138.0.7204.101"), { product: "chrome", key: "138" });
    assert.deepEqual(mapAppProduct("Python 3.9.13 (64-bit)", "3.9.13150.0"), { product: "python", key: "3.9" });
    assert.deepEqual(mapAppProduct("Microsoft Office Professional Plus 2016", "16.0.4266"), { product: "office", key: "2016" });
    assert.equal(mapAppProduct("Chrome Remote Desktop Host", "130"), null);
    assert.equal(mapAppProduct("Zoom Workplace", "6.6.2"), null);
  });

  test("missing EOL feed skips the EOL checks rather than passing them", () => {
    const r = analyze([file("i.csv", "intune-devices", [intune({ "OS version": "10.0.19045.4651" })])], { now: NOW });
    assert.notOk(hit(r, "os_eol"));
    assert.ok(skipped(r, "os_eol").length);
  });
});

group("fleetcomply: checks", () => {
  test("encryption: laptop critical, desktop high, encrypted silent", () => {
    const r = run([file("i.csv", "intune-devices", [
      intune({ "Device name": "LT-1", "Serial number": "SNL1", Model: "Latitude 7450", Encrypted: "No" }),
      intune({ "Device name": "DT-1", "Serial number": "SND1", Model: "OptiPlex 7010", Encrypted: "No" }),
      intune({ "Device name": "OK-1", "Serial number": "SNO1", Model: "Latitude 7450", Encrypted: "Yes" })])]);
    assert.deepEqual(names(r, "encryption_laptop"), ["LT-1"]);
    assert.equal(hit(r, "encryption_laptop").severity, "critical");
    assert.deepEqual(names(r, "encryption"), ["DT-1"]);
  });

  test("EDR missing: in MDM but absent from the EDR export; present device silent", () => {
    const r = run([file("i.csv", "intune-devices", [intune(), intune({ "Device name": "WIN-02", "Serial number": "SN0002" })]), file("c.csv", "crowdstrike", [falcon()])]);
    assert.deepEqual(names(r, "edr_missing"), ["WIN-02"]);
  });

  test("EDR missing needs both inventories, otherwise skipped", () => {
    const r = run([file("i.csv", "intune-devices", [intune()])]);
    assert.notOk(hit(r, "edr_missing"));
    assert.ok(skipped(r, "edr_missing").length);
  });

  test("mobile devices are excluded from EDR missing and reported", () => {
    const r = run([file("i.csv", "intune-devices", [intune({ "Device name": "IPHONE-1", "Serial number": "SNIP1", OS: "iOS", "OS version": "17.6.1", Model: "iPhone 15" })]), file("c.csv", "crowdstrike", [falcon()])]);
    assert.notOk(names(r, "edr_missing").includes("IPHONE-1"));
    assert.ok(skipped(r, "edr_missing").some((s) => /mobile/.test(s.reason)));
  });

  test("EDR unhealthy (RFM) and EDR stale vs MDM check-in", () => {
    const r = run([file("i.csv", "intune-devices", [intune(), intune({ "Device name": "WIN-02", "Serial number": "SN0002" })]),
      file("c.csv", "crowdstrike", [falcon({ "RFM (Reduced Functionality Mode)": "Yes" }), falcon({ Hostname: "WIN-02", "Serial Number": "SN0002", "Last Seen": "2026-10-01T00:00:00Z" })])]);
    assert.deepEqual(names(r, "edr_unhealthy"), ["WIN-01"]);
    assert.deepEqual(names(r, "edr_stale"), ["WIN-02"]);
  });

  test("sensor behind the fleet mode by more than the lag", () => {
    const rows = ["7.29.1", "7.29.2", "7.29.3", "7.24.0", "7.28.0"].map((v, i) => falcon({ Hostname: "H" + i, "Serial Number": "SNH000" + i, "Sensor Version": v }));
    const r = run([file("c.csv", "crowdstrike", rows)]);
    assert.deepEqual(names(r, "sensor_behind"), ["H3"]);
  });

  test("OS EOL: Windows 10 22H2 critical; supported Windows 11 25H2 silent", () => {
    const r = run([file("i.csv", "intune-devices", [intune({ "Device name": "W10", "Serial number": "SN10", "OS version": "10.0.19045.6456" }), intune()])]);
    assert.deepEqual(names(r, "os_eol"), ["W10"]);
    assert.equal(hit(r, "os_eol").severity, "critical");
  });

  test("OS EOL soon: Windows 11 23H2 Enterprise inside the 90-day window", () => {
    const r = run([file("i.csv", "intune-devices", [intune({ OS: "Windows 11 Enterprise", "OS version": "10.0.22631.5909" })])]);
    assert.deepEqual(names(r, "os_eol_soon"), ["WIN-01"]);
    assert.notOk(run([file("i.csv", "intune-devices", [intune({ OS: "Windows 11 Enterprise", "OS version": "10.0.22631.5909" })])], { eolSoonDays: 10 }).findings.some((f) => f.check === "os_eol_soon"));
  });

  test("app EOL: Chrome 138 flagged, Chrome 155 silent", () => {
    const r = run([file("i.csv", "intune-devices", [intune(), intune({ "Device name": "WIN-02", "Serial number": "SN0002" })]),
      file("a.csv", "intune-apps", [{ "Device name": "WIN-01", "App name": "Google Chrome", "App version": "138.0.7204.101" }, { "Device name": "WIN-02", "App name": "Google Chrome", "App version": "155.0.7712.81" }])]);
    assert.deepEqual(names(r, "app_eol"), ["WIN-01"]);
  });

  test("patch behind: revisions more than one release behind the newest in the build line", () => {
    const vers = ["10.0.26200.6899", "10.0.26200.6899", "10.0.26200.6584", "10.0.26200.6000"];
    const r = run([file("i.csv", "intune-devices", vers.map((v, i) => intune({ "Device name": "P" + i, "Serial number": "SNP00" + i, "OS version": v })))]);
    assert.deepEqual(names(r, "patch_behind"), ["P3"]);
  });

  test("stale (>30 days) and stale with an enabled directory object (>90 days)", () => {
    const r = run([file("e.csv", "entra-devices", [entra(), entra({ Name: "OLD-1", "Activity (last sign-in)": "8/1/2026, 9:00:00 AM" }), entra({ Name: "OLD-2", "Activity (last sign-in)": "5/1/2026, 9:00:00 AM" }), entra({ Name: "OLD-3", Enabled: "False", "Activity (last sign-in)": "5/1/2026, 9:00:00 AM" })])]);
    assert.deepEqual(names(r, "stale"), ["OLD-1", "OLD-3"]);
    assert.deepEqual(names(r, "stale_enabled"), ["OLD-2"]);
  });

  test("local admin from the Jamf API local accounts; many admins over the baseline", () => {
    const rec = (n, user, admins) => ({ id: n, general: { name: "MBP-" + n, lastContactTime: "2026-10-15T09:00:00Z" }, hardware: { serialNumber: "C02AAAA" + n + "Q6L", model: "MacBook Pro" },
      operatingSystem: { version: "15.7.1", fileVault2Status: "ALL_ENCRYPTED" }, userAndLocation: { username: user }, localUserAccounts: admins });
    const jamfApi = { results: [rec("1", "raj", [{ username: "raj", admin: true }, { username: "itadmin", admin: true }]), rec("2", "ana", [{ username: "ana", admin: false }, { username: "itadmin", admin: true }]),
      rec("3", "kim", [{ username: "kim", admin: false }, { username: "a1", admin: true }, { username: "a2", admin: true }, { username: "a3", admin: true }])] };
    const r = run([{ name: "jamf.json", text: JSON.stringify(jamfApi) }]);
    assert.deepEqual(names(r, "local_admin"), ["MBP-1"]);
    assert.deepEqual(names(r, "many_admins"), ["MBP-3"]);
  });

  test("Mac configuration: firewall, Gatekeeper/SIP, Recovery Lock; healthy Mac silent", () => {
    const r = run([file("j.csv", "jamf-computers", [jamf(), jamf({ "Computer Name": "MBP-02", "Serial Number": "C02XJ2AAQ6L", "Firewall Enabled": "No", "System Integrity Protection": "Disabled", "Recovery Lock Enabled": "No" })])]);
    assert.deepEqual(names(r, "firewall"), ["MBP-02"]);
    assert.deepEqual(names(r, "gatekeeper_sip"), ["MBP-02"]);
    assert.deepEqual(names(r, "recovery_lock"), ["MBP-02"]);
    assert.notOk(r.findings.some((f) => f.evidence.some((e) => e.device === "MBP-01")));
  });

  test("jailbroken device is critical", () => {
    const r = run([file("i.csv", "intune-devices", [intune({ "Device name": "IPHONE-1", OS: "iOS", "OS version": "17.6.1", Model: "iPhone 15", Jailbroken: "True" }), intune({ "Device name": "IPHONE-2", "Serial number": "SN0002", OS: "iOS", "OS version": "17.6.1", Model: "iPhone 15", Jailbroken: "False" })])]);
    assert.deepEqual(names(r, "jailbroken"), ["IPHONE-1"]);
    assert.equal(hit(r, "jailbroken").severity, "critical");
  });

  test("Workstation Audit fails become guest account, screen lock and firewall findings", () => {
    const rec = { host: "WIN-01", os: "Windows 10.0.26200", generated: "2026-10-15T14:02:11.000Z", results: [
      { id: "guest-account", status: "fail" }, { id: "screen-lock", status: "warn" }, { id: "firewall", status: "fail" }, { id: "disk-encryption", status: "pass" }] };
    const r = run([file("i.csv", "intune-devices", [intune()]), { name: "audit.json", text: JSON.stringify(rec) }]);
    assert.equal(r.summary.devices, 1);
    assert.deepEqual(names(r, "guest_account"), ["WIN-01"]);
    assert.deepEqual(names(r, "screen_lock"), ["WIN-01"]);
    assert.deepEqual(names(r, "firewall"), ["WIN-01"]);
  });

  test("noncompliant and unmanaged; compliant managed device silent", () => {
    const r = run([file("i.csv", "intune-devices", [intune(), intune({ "Device name": "WIN-02", "Serial number": "SN0002", Compliance: "Noncompliant" })]),
      file("e.csv", "entra-devices", [entra(), entra({ Name: "DESKTOP-X", MDM: "", "Join type": "Microsoft Entra registered" })])]);
    assert.deepEqual(names(r, "noncompliant"), ["WIN-02"]);
    assert.deepEqual(names(r, "unmanaged"), ["DESKTOP-X"]);
  });

  test("blocklist: plain names and /regex/; allowlist suppresses the remote-access review", () => {
    const files = [file("i.csv", "intune-devices", [intune(), intune({ "Device name": "WIN-02", "Serial number": "SN0002" })]),
      file("a.csv", "intune-apps", [{ "Device name": "WIN-01", "App name": "uTorrent", "App version": "3.6" }, { "Device name": "WIN-02", "App name": "AnyDesk", "App version": "9.0.4" }, { "Device name": "WIN-02", "App name": "Notepad++", "App version": "8.8" }])];
    const r = run(files, { blocklist: "# comment\n/^u?torrent$/i\nnotepad++" });
    assert.deepEqual(names(r, "blocklist"), ["WIN-01", "WIN-02"]);
    assert.deepEqual(names(r, "remote_access"), ["WIN-01", "WIN-02"]);
    const r2 = run(files, { allowlist: "AnyDesk" });
    assert.deepEqual(names(r2, "remote_access"), ["WIN-01"]);
    assert.ok(skipped(r2, "blocklist").some((s) => /empty/.test(s.reason)));
  });

  test("parseMatchList escapes plain names and reports invalid regexes", () => {
    const { list, errors } = parseMatchList("a.b\n/[unclosed/\n\n#x\n/teamviewer/i");
    assert.equal(list.length, 2);
    assert.ok(list[0].re.test("A.B"));
    assert.notOk(list[0].re.test("axb"));
    assert.ok(list[1].re.test("TeamViewer 15"));
    assert.equal(errors.length, 1);
  });

  test("every finding carries the required fields and capped evidence", () => {
    const ex = exampleDataset();
    const r = run(ex.files, { now: ex.now });
    assert.ok(r.findings.length > 10);
    for (const f of r.findings) {
      for (const k of ["title", "severity", "confidence", "category", "description", "recommendation"]) assert.ok(f[k], f.check + " missing " + k);
      assert.ok(f.controls.length >= 1, f.check + " has no controls");
      assert.ok(f.evidence.length <= 50 && f.evidenceCount >= f.evidence.length);
      assert.ok(f.assets.some((a) => a.type === "ASSET"));
    }
    assert.ok(DETECTIONS.every((d) => d.controls.length && d.needs));
  });

  test("evidence is capped at 50 with the true count kept", () => {
    const rows = Array.from({ length: 60 }, (_, i) => intune({ "Device name": "D" + i, "Serial number": "SN" + String(1000 + i), Encrypted: "No" }));
    const f = hit(run([file("i.csv", "intune-devices", rows)]), "encryption");
    assert.equal(f.evidence.length, 50);
    assert.equal(f.evidenceCount, 60);
  });
});

group("fleetcomply: coverage and score", () => {
  test("coverage gaps across three inventories", () => {
    const r = run([file("i.csv", "intune-devices", [intune(), intune({ "Device name": "WIN-02", "Serial number": "SN0002" })]),
      file("c.csv", "crowdstrike", [falcon()]), file("e.csv", "entra-devices", [entra(), entra({ Name: "WIN-03" })])]);
    const cov = (a, b) => r.tables.coverage.find((c) => c.from === a && c.to === b);
    assert.deepEqual(cov("MDM", "EDR").devices, ["WIN-02"]);
    assert.deepEqual(cov("Directory", "MDM").devices, ["WIN-03"]);
    assert.equal(cov("MDM", "Directory").missing, 1);
    assert.ok(r.findings.some((f) => f.check === "coverage"));
  });

  test("score = 100 minus the weights of failed checks; fleet score is the mean", () => {
    const r = run([file("i.csv", "intune-devices", [intune({ Model: "Latitude 7450", Encrypted: "No", Compliance: "Noncompliant" }), intune({ "Device name": "WIN-02", "Serial number": "SN0002" })])]);
    const d = r.tables.devices.find((x) => x.name === "WIN-01");
    assert.deepEqual(d.flags, ["encryption", "noncompliant"]);
    assert.equal(d.score, 100 - WEIGHTS.encryption - WEIGHTS.noncompliant);
    assert.equal(r.summary.fleetScore, (d.score + 100) / 2);
    assert.equal(r.summary.distribution["90-100"], 1);
  });

  test("custom weights change the score and the floor is zero", () => {
    const f = [file("i.csv", "intune-devices", [intune({ Encrypted: "No" })])];
    assert.equal(run(f, { weights: { encryption: 40 } }).tables.devices[0].score, 60);
    assert.equal(run(f, { weights: { encryption: 400 } }).tables.devices[0].score, 0);
  });
});

group("fleetcomply: determinism, exports, self-test", () => {
  test("in-engine self-test passes", () => {
    const r = selfTest();
    assert.ok(r.pass, "failed: " + r.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
  });

  test("analyze is deterministic and input order of files does not change the register", () => {
    const ex = exampleDataset();
    const a = run(ex.files, { now: ex.now });
    assert.equal(JSON.stringify(a), JSON.stringify(run(ex.files, { now: ex.now })));
    const b = run(ex.files.slice().reverse(), { now: ex.now });
    assert.deepEqual(a.tables.devices.map((d) => d.name + d.score).sort(), b.tables.devices.map((d) => d.name + d.score).sort());
  });

  test("now defaults to the newest timestamp in the data, not the wall clock", () => {
    const f = [file("i.csv", "intune-devices", [intune({ "Last check-in": "2020-01-01 10:00:00" }), intune({ "Device name": "WIN-02", "Serial number": "SN0002", "Last check-in": "2020-03-01 10:00:00" })])];
    const r = analyze(f, { eol: EOL });
    assert.equal(r.summary.now.slice(0, 10), "2020-03-01");
    assert.deepEqual(names(r, "stale"), ["WIN-01"]);
  });

  test("empty input yields zero findings and does not throw", () => {
    const r = analyze([]);
    assert.equal(r.findings.length, 0);
    assert.equal(r.summary.devices, 0);
    assert.equal(analyze("").findings.length, 0);
  });

  test("example: 18 devices, 7 sources, synthetic label", () => {
    const ex = exampleDataset();
    assert.ok(/synthetic/.test(ex.label));
    const r = run(ex.files, { now: ex.now });
    assert.equal(r.summary.devices, 18);
    assert.equal(r.tables.sources.length, 7);
  });

  test("CSV exports have stable headers and one row per record", () => {
    const ex = exampleDataset();
    const r = run(ex.files, { now: ex.now });
    const lines = (s) => s.split("\n").filter(Boolean);
    assert.equal(lines(devicesToCsv(r.tables.devices))[0], DEVICE_COLS.join(","));
    assert.equal(lines(devicesToCsv(r.tables.devices)).length, r.tables.devices.length + 1);
    assert.ok(/^severity,confidence,category,check,title/.test(findingsToCsv(r.findings).split("\n")[0]));
    assert.equal(lines(softwareToCsv(r.tables.software))[0], "name,version,publisher,devices,eol,eolDate,blocklisted,remoteAccess");
    assert.equal(lines(worklistToCsv(r.tables.worklist))[0], "device,serial,owner,severity,check,action,detail");
    assert.equal(lines(coverageToCsv(r.tables.coverage)).length, r.tables.coverage.length + 1);
    assert.ok(summaryText(r).includes("Fleet score"));
    assert.equal(TOOL_ID, "fleetcomply");
  });

  test("CSV cells are quoted and formula-leading values are neutralised", () => {
    const csv = findingsToCsv([{ severity: "low", confidence: "review", category: "x", check: "c", title: '=HYPERLINK("a")', description: "a,b", recommendation: "r", controls: [], assets: [], evidence: [] }]);
    const row = csv.split("\n")[1];
    assert.notOk(/(^|,)"?=HYPERLINK/.test(row));
    assert.ok(row.includes('"a,b"'));
  });

  test("parseBool understands vendor spellings", () => {
    for (const v of ["Yes", "TRUE", "enabled", "On", "1"]) assert.equal(parseBool(v), true, v);
    for (const v of ["No", "false", "Disabled", "Off", "0"]) assert.equal(parseBool(v), false, v);
    assert.equal(parseBool(""), null);
  });
});
