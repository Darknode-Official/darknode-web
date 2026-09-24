// Unit tests for public/js/core/bus.js
import { test, group, assert } from "../harness.mjs";
import { EventBus, EVENTS } from "../../public/js/core/bus.js";

group("bus", () => {
  test("delivers emitted payloads to subscribers", () => {
    const bus = new EventBus();
    let got;
    bus.on("x", (p) => { got = p; });
    const n = bus.emit("x", 42);
    assert.equal(n, 1);
    assert.equal(got, 42);
  });

  test("off() and the returned unsubscribe both stop delivery", () => {
    const bus = new EventBus();
    let count = 0;
    const off = bus.on("x", () => count++);
    bus.emit("x");
    off();
    bus.emit("x");
    assert.equal(count, 1);
    const h = () => count++;
    bus.on("x", h); bus.off("x", h); bus.emit("x");
    assert.equal(count, 1);
  });

  test("once() fires exactly once", () => {
    const bus = new EventBus();
    let count = 0;
    bus.once("x", () => count++);
    bus.emit("x"); bus.emit("x"); bus.emit("x");
    assert.equal(count, 1);
  });

  test("a throwing handler is isolated from the others and the emitter", () => {
    const errs = [];
    const bus = new EventBus({ onError: (e) => errs.push(e) });
    let reached = false;
    bus.on("x", () => { throw new Error("boom"); });
    bus.on("x", () => { reached = true; });
    const n = bus.emit("x"); // must not throw
    assert.ok(reached, "second handler still ran");
    assert.equal(n, 1, "only the successful handler is counted");
    assert.equal(errs.length, 1, "the error was reported");
  });

  test("sticky events replay the last payload to late subscribers", () => {
    const bus = new EventBus();
    bus.emit(EVENTS.CONTEXT_CHANGED, { id: "a1" });
    let got;
    bus.on(EVENTS.CONTEXT_CHANGED, (p) => { got = p; });
    assert.deepEqual(got, { id: "a1" });
  });

  test("replayLast:false suppresses sticky replay", () => {
    const bus = new EventBus();
    bus.emit(EVENTS.CONTEXT_CHANGED, { id: "a1" });
    let got = "untouched";
    bus.on(EVENTS.CONTEXT_CHANGED, (p) => { got = p; }, { replayLast: false });
    assert.equal(got, "untouched");
  });

  test("non-sticky events do not replay", () => {
    const bus = new EventBus();
    bus.emit("transient", 1);
    let got = "untouched";
    bus.on("transient", (p) => { got = p; });
    assert.equal(got, "untouched");
  });

  test("listenerCount and clear behave correctly", () => {
    const bus = new EventBus();
    bus.on("a", () => {}); bus.on("a", () => {}); bus.on("b", () => {});
    assert.equal(bus.listenerCount("a"), 2);
    assert.equal(bus.listenerCount(), 3);
    bus.clear("a");
    assert.equal(bus.listenerCount("a"), 0);
    bus.clear();
    assert.equal(bus.listenerCount(), 0);
  });

  test("emitting with no subscribers returns 0", () => {
    const bus = new EventBus();
    assert.equal(bus.emit("nobody", 1), 0);
  });

  test("subscribing during dispatch does not affect the current emit", () => {
    const bus = new EventBus();
    let extra = 0;
    bus.on("x", () => { bus.on("x", () => extra++); });
    bus.emit("x"); // the newly-added handler must not run this round
    assert.equal(extra, 0);
    bus.emit("x");
    assert.equal(extra, 1);
  });

  test("EVENTS catalog is frozen", () => {
    assert.throws(() => { EVENTS.SECTION_CHANGED = "x"; });
  });
});
