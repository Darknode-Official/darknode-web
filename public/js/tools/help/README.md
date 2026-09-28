# Mini-tool help contract

Every mini-tool gets a plain-English help entry in `help/<same file name>.js`:

```js
export const HELP = {
  "h-djb2": {
    what: "Turns any text into a short number that is always the same for the same text.",
    when: "You need a quick fingerprint of a string, for example to spot duplicate lines or to bucket items. Not for passwords or security.",
    example: { text: "hello" },   // keys are the tool's input `k` names; omitted inputs keep their defaults
  },
};
```

Rules:
- `what`: one or two short sentences a beginner understands. Say what goes in and what comes out.
  No unexplained jargon; if a technical term is unavoidable, explain it in a few words.
- `when`: one sentence starting with a real situation ("You are ...", "You need ...", "You want ...").
  Mention an important limitation if there is one (for example "not for passwords").
- `example`: realistic input values that produce a useful, non-empty, non-error output when the
  tool runs. Values must be strings (checkbox: true/false). Use harmless example data only
  (example.com, 192.0.2.x / 198.51.100.x, fake names).
- No emojis. Keep the tool code itself unchanged.
- Check with: `node tools/check-tool-help.mjs [file]` (every tool has help, example keys exist,
  the example runs without error and gives output).
