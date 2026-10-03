// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
// Central registry for the mini-tools. TOOL_CATS defines the categories (name +
// accent colour, matching the console colour system). Each category's tools live
// in js/tools/<file>.js and are aggregated here. mini-tools.js reads this to render.
// The console shell (auth.js, console-nav.js) reads js/tools-manifest.js instead, a
// generated id/name/cat list, so the tool code loads only when the Toolbox opens.
// After changing TOOL_CATS or any tool id/name: node tools/tools-manifest-build.mjs
//
// Scope: the Toolbox holds only security- and coding-relevant utilities. General
// consumer utilities (color/design, date & time, math, generic text, generators,
// unit/format converters) were removed on 2026-10-02 to keep the platform coherent.
import { TOOLS as encoding } from "/js/tools/encoding.js?v=20261003a";
import { TOOLS as hashing } from "/js/tools/hashing.js?v=20261003a";
import { TOOLS as network } from "/js/tools/network.js?v=20261003a";
import { TOOLS as websec } from "/js/tools/websec.js?v=20261003a";
import { TOOLS as dev } from "/js/tools/dev.js?v=20261003a";
import { TOOLS as webhttp } from "/js/tools/webhttp.js?v=20261003a";
import { TOOLS as appsec } from "/js/tools/appsec.js?v=20261003a";
import { TOOLS as devx } from "/js/tools/devx.js?v=20261003a";
import { TOOLS as crypto } from "/js/tools/crypto.js?v=20261003a";
import { TOOLS as forensics } from "/js/tools/forensics.js?v=20261003a";
import { TOOLS as bininspect } from "/js/tools/bininspect.js?v=20261003a";
import { TOOLS as blueteam } from "/js/tools/blueteam.js?v=20261003a";
import { TOOLS as cloud } from "/js/tools/cloud.js?v=20261003a";
import { TOOLS as identity } from "/js/tools/identity.js?v=20261003a";
import { TOOLS as coding } from "/js/tools/coding.js?v=20261003a";
import { TOOLS as netproto } from "/js/tools/netproto.js?v=20261003a";

export const TOOL_CATS = {
  encoding: { name: "Encoding & Ciphers", color: "indigo" },
  hashing: { name: "Hashing & Checksums", color: "violet" },
  crypto: { name: "Cryptography & PKI", color: "emerald" },
  network: { name: "Network Utilities", color: "teal" },
  netproto: { name: "Network Protocols", color: "cyan" },
  websec: { name: "Web Security", color: "red" },
  web: { name: "HTTP & Web", color: "slate" },
  appsec: { name: "Application Security", color: "red" },
  identity: { name: "Identity & Access", color: "yellow" },
  cloud: { name: "Cloud & Container Security", color: "purple" },
  blueteam: { name: "Blue Team & Detection", color: "cyan" },
  forensics: { name: "Forensics & DFIR", color: "orange" },
  bininspect: { name: "Binary & Threat Triage", color: "rose" },
  dev: { name: "Developer Utilities", color: "blue" },
  devx: { name: "Developer Toolbox", color: "blue" },
  coding: { name: "Coding & Data Formats", color: "green" },
};

const _all = [].concat(
  encoding,
  hashing,
  crypto,
  network,
  netproto,
  websec,
  dev,
  webhttp,
  appsec,
  identity,
  cloud,
  blueteam,
  forensics,
  bininspect,
  devx,
  coding,
);

// Dev guard: a duplicate id would make one tool unreachable. Keep the first.
const _seen = new Set();
export const TOOLS = _all.filter((t) => {
  if (!t || !t.id || _seen.has(t.id)) return false;
  _seen.add(t.id);
  return true;
});
