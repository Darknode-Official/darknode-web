// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Central registry for the mini-tools. TOOL_CATS defines the categories (name +
// accent colour, matching the console colour system). Each category's tools live
// in js/tools/<file>.js and are aggregated here. console-nav.js reads this to add
// the tool categories to the Services menu; mini-tools.js reads it to render.
import { TOOLS as encoding } from "/js/tools/encoding.js?v=20260925p";
import { TOOLS as hashing } from "/js/tools/hashing.js?v=20260925p";
import { TOOLS as generators } from "/js/tools/generators.js?v=20260925p";
import { TOOLS as converters } from "/js/tools/converters.js?v=20260925p";
import { TOOLS as network } from "/js/tools/network.js?v=20260925p";
import { TOOLS as websec } from "/js/tools/websec.js?v=20260925p";
import { TOOLS as text } from "/js/tools/text.js?v=20260925p";
import { TOOLS as dev } from "/js/tools/dev.js?v=20260925p";
import { TOOLS as color } from "/js/tools/color.js?v=20260925p";
import { TOOLS as datetime } from "/js/tools/datetime.js?v=20260925p";
import { TOOLS as mathx } from "/js/tools/mathx.js?v=20260925p";
import { TOOLS as datafmt } from "/js/tools/datafmt.js?v=20260925p";
import { TOOLS as webhttp } from "/js/tools/webhttp.js?v=20260925p";
import { TOOLS as appsec } from "/js/tools/appsec.js?v=20260925p";
import { TOOLS as textx } from "/js/tools/textx.js?v=20260925p";
import { TOOLS as devx } from "/js/tools/devx.js?v=20260925p";

export const TOOL_CATS = {
  encoding: { name: "Encoding & Ciphers", color: "indigo" },
  hashing: { name: "Hashing & Checksums", color: "violet" },
  generators: { name: "Generators", color: "emerald" },
  converters: { name: "Converters & Formats", color: "cyan" },
  network: { name: "Network Utilities", color: "teal" },
  websec: { name: "Web & AppSec Utilities", color: "red" },
  text: { name: "Text Utilities", color: "orange" },
  dev: { name: "Developer Utilities", color: "blue" },
  color: { name: "Color & Design", color: "rose" },
  datetime: { name: "Date & Time", color: "yellow" },
  math: { name: "Math & Numbers", color: "green" },
  data: { name: "Data & Formats", color: "purple" },
  web: { name: "Web & HTTP", color: "slate" },
  appsec: { name: "Security & AppSec", color: "red" },
  textx: { name: "Text & Format", color: "orange" },
  devx: { name: "Dev Toolbox", color: "blue" },
};

const _all = [].concat(
  encoding,
  hashing,
  generators,
  converters,
  network,
  websec,
  text,
  dev,
  color,
  datetime,
  mathx,
  datafmt,
  webhttp,
  appsec,
  textx,
  devx,
);

// Dev guard: a duplicate id would make one tool unreachable. Keep the first.
const _seen = new Set();
export const TOOLS = _all.filter((t) => {
  if (!t || !t.id || _seen.has(t.id)) return false;
  _seen.add(t.id);
  return true;
});
