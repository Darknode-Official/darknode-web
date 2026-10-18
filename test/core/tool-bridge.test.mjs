// Unit tests for public/js/core/tool-bridge.js — the Deck tool-bridge message protocol.
import { test, group, assert } from "../harness.mjs";
import { makeMessage, parseMessage, MSG, BRIDGE, BRIDGE_VERSION, isBridgeType } from "../../public/js/core/tool-bridge.js";

group("tool-bridge/makeMessage", () => {
  test("builds a tagged, versioned message for a known type", () => {
    const m = makeMessage(MSG.RESULT, { tool: "codescan", created: 2 });
    assert.equal(m.__b, BRIDGE);
    assert.equal(m.v, BRIDGE_VERSION);
    assert.equal(m.type, "result");
    assert.equal(m.payload.tool, "codescan");
  });

  test("rejects an unknown type", () => {
    assert.equal(makeMessage("evil", { x: 1 }), null);
  });

  test("coerces a missing or non-object payload to {}", () => {
    assert.deepEqual(makeMessage(MSG.READY).payload, {});
    assert.deepEqual(makeMessage(MSG.READY, "nope").payload, {});
  });
});

group("tool-bridge/parseMessage", () => {
  test("round-trips a valid message", () => {
    const m = makeMessage(MSG.OPEN_ENTITY, { id: "e1" });
    const p = parseMessage(m);
    assert.equal(p.type, "open-entity");
    assert.equal(p.payload.id, "e1");
  });

  test("returns null for non-objects and foreign messages", () => {
    assert.equal(parseMessage(null), null);
    assert.equal(parseMessage("x"), null);
    assert.equal(parseMessage({ hello: 1 }), null); // no bridge marker
    assert.equal(parseMessage({ __b: BRIDGE, v: 999, type: "result" }), null); // wrong version
    assert.equal(parseMessage({ __b: "other", v: BRIDGE_VERSION, type: "result" }), null);
  });

  test("returns null for an unknown type even when tagged", () => {
    assert.equal(parseMessage({ __b: BRIDGE, v: BRIDGE_VERSION, type: "drop-table" }), null);
  });

  test("defaults a missing payload to {}", () => {
    const p = parseMessage({ __b: BRIDGE, v: BRIDGE_VERSION, type: MSG.FOCUS });
    assert.deepEqual(p.payload, {});
  });

  test("isBridgeType knows the protocol types", () => {
    assert.equal(isBridgeType(MSG.FOCUS), true);
    assert.equal(isBridgeType("nope"), false);
  });
});
