# Mini-tool definition contract

Each category file (e.g. `js/tools/hashing.js`) is an ES module that exports one
array: `export const TOOLS = [ ...defs ];`. Every def is a plain object:

```js
{
  id: "base64",              // unique across ALL files, kebab-case, stable (used in URLs)
  name: "Base64 Encoder / Decoder",
  cat: "encoding",           // must be a key in TOOL_CATS (see tools-registry.js)
  desc: "Encode or decode Base64, with URL-safe and MIME variants.",
  tags: ["b64", "encode", "decode"],   // optional, improves search
  button: "Convert",          // optional label; omit for default "Run". button:false = no button (live only)
  live: true,                 // optional (default true): recompute as the user types
  inputs: [
    { k: "text", label: "Input", type: "textarea", rows: 6, placeholder: "..." },
    { k: "mode", label: "Mode", type: "select", opts: ["Encode", "Decode"], value: "Encode" },
    { k: "urlsafe", label: "URL-safe", type: "checkbox", value: false },
    { k: "shift", label: "Shift", type: "range", min: 1, max: 25, step: 1, value: 13 },
    { k: "key", label: "Key", type: "text", placeholder: "secret" }
  ],
  run(v, H) {
    // v = { text, mode, urlsafe, shift, key } -> values from the inputs (checkbox => boolean).
    // H = shared helpers (see _helpers.js). run may be sync OR async (return a Promise).
    // Return: a string (the output), OR { out: string }, OR { error: "message" } to show an error.
    if (!v.text) return "";
    return v.mode === "Encode" ? H.b64encode(v.text, { url: v.urlsafe }) : H.b64decode(v.text, { url: v.urlsafe });
  }
}
```

## Rules
- **Pure client-side.** No `fetch`, no network, no external libraries, no DOM access. Deterministic given inputs (crypto random is fine for generators).
- **Never throw for ordinary bad input** — return `{ error: "..." }` with a clear message. Throwing is caught and shown, but a returned error reads better.
- **Real and unique.** Each tool must do something genuinely useful and distinct from the others. No duplicates, no stubs, no "coming soon".
- **Security framing:** offensive tools (payload/command builders, cheatsheets) are for authorized testing — fine to include; do not add anything that only makes sense for unauthorized harm.
- `input.type`: `text` (default), `textarea`, `select` (`opts` = array of strings or `[value,label]`), `checkbox` (value boolean), `range` (min/max/step), plus `inputType` on text for `number`/`password`.
- Keep each `run` self-contained (inline any small table/data it needs). Files must be valid ES modules and pass `node --check`.
- Prefer the helpers in `H` for base64/base32/base58/hex/sha*/hmac/md5/crc32/uuid/randBytes. Everything else, implement inline.
