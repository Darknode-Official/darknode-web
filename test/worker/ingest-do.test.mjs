// Unit tests for worker/ingest.js — IngestDO (API keys + ingest queue), in-memory shim.
import { test, group, assert } from "../harness.mjs";
import { IngestDO } from "../../worker/ingest.js";

function memState() {
  const map = new Map();
  return { storage: { async get(k) { return map.has(k) ? map.get(k) : undefined; }, async put(k, v) { map.set(k, v); }, async delete(k) { map.delete(k); } }, blockConcurrencyWhile: async (fn) => fn(), _map: map };
}
const mgmt = (op, extra = {}, role = "owner") => new Request("https://ingest/", { method: "POST", headers: { "content-type": "application/json", "x-ing-uid": "u1", "x-ing-role": role }, body: JSON.stringify({ op, ...extra }) });
const ingest = (key, body) => new Request("https://ingest/", { method: "POST", headers: { "x-ing-key": key, "content-type": "application/json" }, body });
const readback = (key) => new Request("https://ingest/findings", { method: "GET", headers: { "x-ing-key": key } });
const jsonOf = async (res) => ({ status: res.status, json: await res.json() });

async function newKey(doInst, scopes) {
  const r = await jsonOf(await doInst.fetch(mgmt("create", { label: "ci", scopes })));
  return r.json;
}

group("ingest DO/keys", () => {
  test("create returns the full key once; list redacts it", async () => {
    const d = new IngestDO(memState());
    const k = await newKey(d, ["ingest:write", "findings:read"]);
    assert.ok(/^dk_[0-9a-f]{10}_/.test(k.key));
    assert.deepEqual(k.scopes, ["ingest:write", "findings:read"]);
    const list = (await jsonOf(await d.fetch(mgmt("list")))).json;
    assert.equal(list.keys.length, 1);
    assert.equal(list.keys[0].key, undefined, "no secret in list");
    assert.ok(list.keys[0].prefix.endsWith("…"));
  });

  test("a viewer cannot create or revoke keys but can list", async () => {
    const d = new IngestDO(memState());
    assert.equal((await d.fetch(mgmt("create", {}, "viewer"))).status, 403);
    assert.equal((await d.fetch(mgmt("list", {}, "viewer"))).status, 200);
  });
});

group("ingest DO/data plane", () => {
  test("a valid key ingests a Finding-contract batch and it queues", async () => {
    const d = new IngestDO(memState());
    const k = await newKey(d, ["ingest:write", "findings:read"]);
    const r = await jsonOf(await d.fetch(ingest(k.key, JSON.stringify([{ title: "SQLi", severity: "high" }, { title: "XSS", severity: "medium" }]))));
    assert.equal(r.status, 200);
    assert.equal(r.json.format, "findings");
    assert.equal(r.json.accepted, 2);
    assert.equal(r.json.queued, 2);
  });

  test("ingest accepts SARIF and maps it", async () => {
    const d = new IngestDO(memState());
    const k = await newKey(d);
    const sarif = JSON.stringify({ version: "2.1.0", runs: [{ tool: { driver: { name: "T", rules: [] } }, results: [{ ruleId: "r1", level: "error", message: { text: "boom" } }] }] });
    const r = await jsonOf(await d.fetch(ingest(k.key, sarif)));
    assert.equal(r.json.format, "sarif");
    assert.equal(r.json.accepted, 1);
  });

  test("an unknown or revoked key is rejected", async () => {
    const d = new IngestDO(memState());
    const k = await newKey(d);
    assert.equal((await d.fetch(ingest("dk_0000000000_xxxxxxxxxxxxxxxxxxxx", "[]"))).status, 401);
    await d.fetch(mgmt("revoke", { keyId: k.keyId }));
    assert.equal((await d.fetch(ingest(k.key, JSON.stringify([{ title: "x", severity: "low" }])))).status, 401);
  });

  test("a read-only key cannot ingest; an ingest-only key cannot read back", async () => {
    const d = new IngestDO(memState());
    const ro = await newKey(d, ["findings:read"]);
    assert.equal((await d.fetch(ingest(ro.key, JSON.stringify([{ title: "x", severity: "low" }])))).status, 403);
    const wo = await newKey(d, ["ingest:write"]);
    assert.equal((await d.fetch(readback(wo.key))).status, 403);
  });

  test("read-back lists pending findings for a read-scoped key", async () => {
    const d = new IngestDO(memState());
    const k = await newKey(d, ["ingest:write", "findings:read"]);
    await d.fetch(ingest(k.key, JSON.stringify([{ title: "SQLi", severity: "high" }])));
    const r = await jsonOf(await d.fetch(readback(k.key)));
    assert.equal(r.json.pending, 1);
    assert.equal(r.json.findings[0].title, "SQLi");
  });

  test("drain returns the queued batches and clears the queue", async () => {
    const d = new IngestDO(memState());
    const k = await newKey(d);
    await d.fetch(ingest(k.key, JSON.stringify([{ title: "a", severity: "low" }, { title: "b", severity: "low" }])));
    const drained = (await jsonOf(await d.fetch(mgmt("drain")))).json;
    assert.equal(drained.batches.length, 1);
    assert.equal(drained.batches[0].findings.length, 2);
    const after = (await jsonOf(await d.fetch(mgmt("peek")))).json;
    assert.equal(after.pending, 0);
  });

  test("malformed JSON ingest is a 422 with errors, not a crash", async () => {
    const d = new IngestDO(memState());
    const k = await newKey(d);
    const r = await jsonOf(await d.fetch(ingest(k.key, "{not json")));
    assert.equal(r.status, 422);
    assert.ok(r.json.errors[0].includes("invalid JSON"));
  });
});
