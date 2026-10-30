// Read a request body as text, but stop at `max` bytes. request.text() buffers the whole
// body first (up to the platform's 100 MB) and only then could a route check its length,
// so one oversized POST could exhaust the isolate's 128 MB for every request sharing it.
// Returns the text, or null when the body is over the cap.
export async function readCapped(request, max) {
  const len = Number(request.headers.get("content-length"));
  if (len > max) return null;
  if (!request.body) return "";
  const reader = request.body.getReader(), chunks = [];
  let n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    n += value.byteLength;
    if (n > max) { try { await reader.cancel(); } catch (_) {} return null; }
    chunks.push(value);
  }
  const all = new Uint8Array(n);
  let o = 0;
  for (const c of chunks) { all.set(c, o); o += c.byteLength; }
  return new TextDecoder().decode(all);
}
