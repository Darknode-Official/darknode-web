// Test fixture engine for worker.test.mjs — follows the engine convention:
// trailing optional ctx = { progress }.
export function echo(a, b, ctx) {
  if (ctx && ctx.progress) ctx.progress(1, 2, "half");
  return { a, b };
}
export function boom() { throw new Error("boom failed"); }
export function noCtx(x, ctx) { return { x, hasCtx: !!(ctx && typeof ctx.progress === "function") }; }
