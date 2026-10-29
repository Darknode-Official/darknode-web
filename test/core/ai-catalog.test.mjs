import { test, group, assert } from "../harness.mjs";
import { readFileSync, existsSync } from "fs";
import { TOOLS, toolById, run } from "../../public/js/api/catalog.js";
import { PLAN_GROUP, PLAN_ITEM, tierFor, TIERS } from "../../public/js/core/entitlements.js";

const deckSrc = readFileSync(new URL("../../public/js/deck-ui.js", import.meta.url), "utf8");
// sidebar tool id -> group id, read from the Deck's NAV_DEF
const sidebar = {};
for (const line of deckSrc.split("\n")) {
  const g = /\{ id: "(\w+)", g: "/.exec(line); if (!g) continue;
  for (const m of line.matchAll(/\["tool", "([\w-]+)", "([^"]+)"/g)) sidebar[m[1]] = { group: g[1], name: m[2] };
}

group("api/catalog (tools for AI clients)", () => {
  test("the Deck reads its plan table from entitlements, not a copy of its own", () => {
    assert.ok(/PLAN_GROUP, PLAN_ITEM \} from "\/js\/core\/entitlements\.js/.test(deckSrc));
    assert.ok(!/const PLAN_GROUP\s*=/.test(deckSrc) && !/const PLAN_ITEM\s*=/.test(deckSrc));
    assert.ok(Object.values(PLAN_GROUP).concat(Object.values(PLAN_ITEM)).every((t) => TIERS.includes(t)));
  });
  test("every catalog tool is a Deck sidebar tool, in the same group, under the same name", () => {
    for (const t of TOOLS) {
      assert.ok(sidebar[t.id], t.id + " is not in the Deck sidebar");
      assert.equal(t.group, sidebar[t.id].group, t.id + " group");
      assert.equal(t.name, sidebar[t.id].name, t.id + " name");
    }
  });
  test("a tool needs the same plan through an AI as in the Deck", () => {
    for (const t of TOOLS) assert.equal(t.tier, tierFor(t.id, sidebar[t.id].group), t.id);
    assert.equal(toolById("dlp").tier, "pro");          // item override beats the compliance group
    assert.equal(toolById("breachclock").tier, "enterprise");
  });
  test("ids are unique and every engine file exists", () => {
    assert.equal(new Set(TOOLS.map((t) => t.id)).size, TOOLS.length);
    for (const t of TOOLS) assert.ok(existsSync(new URL("../../public/js/" + t.engine, import.meta.url)), t.engine);
  });
  test("every tool runs its Deck engine in node on real input and returns findings", async () => {
    const inline = {
      fwaudit: "iptables -A INPUT -p tcp --dport 22 -j ACCEPT\n",
      loghunt: Array.from({ length: 30 }, (_, i) => "Jan 1 00:00:" + String(i).padStart(2, "0") + " h sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2").join("\n"),
      dlp: "card 4111 1111 1111 1111",
      phishtriage: "http://paypa1-login.example-verify.xyz/account/verify\nhttps://example.com",
      signins: "UserPrincipalName,CreatedDateTime,IPAddress,Status\ntest@darknode.ai,2026-01-01T00:00:00Z,203.0.113.9,Success\n",
    };
    let ran = 0;
    for (const t of TOOLS) {
      const E = await import("../../public/js/" + t.engine);
      const ex = E.exampleDataset ? E.exampleDataset() : null;
      const files = ex && Array.isArray(ex.files) ? ex.files : inline[t.id] ? [{ name: t.id + ".txt", text: inline[t.id] }] : null;
      if (!files) continue;                                       // record-only examples: covered by the tool's own tests
      const r = await run(t, E, files);
      assert.ok(r && typeof r === "object", t.id);
      assert.ok(Array.isArray(r.findings) || Array.isArray(r.urls), t.id + " returns findings");
      ran++;
    }
    assert.ok(ran >= 25, "ran " + ran);
  });
  test("the catalog and entitlements stay DOM-free so the MCP server can load them", () => {
    for (const f of ["api/catalog.js", "core/entitlements.js"]) {
      const s = readFileSync(new URL("../../public/js/" + f, import.meta.url), "utf8");
      assert.ok(!/\b(document|window|localStorage)\./.test(s), f);
    }
  });
});
