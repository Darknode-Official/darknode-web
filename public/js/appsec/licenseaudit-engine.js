// License Compliance engine (licenseaudit). Builds a license inventory from lockfiles
// (npm, yarn, pnpm, pip, Pipfile, Poetry, Go, Cargo, Bundler, Composer, Maven), license
// tool reports (license-checker, pip-licenses, CSV inventories) and incoming SBOMs
// (CycloneDX 1.4-1.6 JSON/XML, SPDX 2.3 JSON and tag-value), parses every SPDX license
// expression, classifies it, and checks it against a user policy and a distribution
// context. Pure: no DOM, no network, deterministic. Safe inside a Worker and in node.
// Live license lookups happen in the UI only; their results arrive as opts.resolved.

import { parseCsv, findColumn, xmlLite } from "../ingest/parse.js";
import {
  parsePackageLock, parseYarnLock, parsePoetryLock, parseGoSum, parseGoMod, parsePomXml,
  parseRequirementsTxt, parseGemfileLock,
} from "../supply-chain-engine.js";

export const TOOL_ID = "licenseaudit";
export const VERSION = "1.0.0";

/** Column aliases for CSV / JSON license inventories (license-checker, pip-licenses, spreadsheets). */
export const COLUMNS = {
  name: ["name", "module name", "package", "package name", "component", "component name", "library", "artifact", "module", "dependency"],
  version: ["version", "package version", "installed version", "component version", "versioninfo"],
  license: ["license", "licenses", "license expression", "license_expression", "spdx", "spdx license", "license id", "license name", "license type", "declared license"],
  ecosystem: ["ecosystem", "package manager", "package type", "language"],
  purl: ["purl", "package url", "package-url"],
};

/** Distribution contexts and their labels (the UI renders these). */
export const CONTEXTS = {
  saas: "SaaS only (served over a network, not distributed)",
  binary: "Shipped binary or on-premise distribution",
  mobile: "Mobile app (app-store distribution)",
  internal: "Internal use only (never leaves the organisation)",
};

/** Policy and context settings; the UI renders these as the settings panel. */
export const DEFAULTS = {
  context: "binary",        // one of CONTEXTS
  projectLicense: "",       // outbound license of your product (SPDX expression); blank = use the one in the input
  includeDev: false,        // development-only packages are not distributed; include them in obligation checks?
  allow: [],                // SPDX ids, globs (GPL-*) or categories (permissive, weak-copyleft, ...)
  review: [],
  deny: [],
  maxEvidence: 50,
};

export const CATEGORIES = ["public-domain", "permissive", "weak-copyleft", "strong-copyleft", "network-copyleft", "proprietary", "unknown"];
export const CATEGORY_LABEL = {
  "public-domain": "Public domain", permissive: "Permissive", "weak-copyleft": "Weak copyleft", "strong-copyleft": "Strong copyleft",
  "network-copyleft": "Network copyleft", proprietary: "Proprietary or restricted", unknown: "Unknown",
};
const CAT_RANK = { "public-domain": 0, permissive: 0, "weak-copyleft": 1, "strong-copyleft": 2, "network-copyleft": 3, proprietary: 4, unknown: 5 };
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
export const SEVERITIES = ["critical", "high", "medium", "low", "info"];

// ---------------------------------------------------------------------------
// License table. c = category, osi = on the OSI approved list.
// ---------------------------------------------------------------------------
const L = (c, osi, extra) => Object.assign({ c, osi: !!osi }, extra || {});
const LICENSES = {
  // public domain dedications
  "CC0-1.0": L("public-domain", 0), "Unlicense": L("public-domain", 1), "PDDL-1.0": L("public-domain", 0),
  "LicenseRef-Public-Domain": L("public-domain", 0),
  // permissive
  "MIT": L("permissive", 1), "MIT-0": L("permissive", 1), "ISC": L("permissive", 1), "0BSD": L("permissive", 1),
  "BSD-1-Clause": L("permissive", 1), "BSD-2-Clause": L("permissive", 1), "BSD-2-Clause-Patent": L("permissive", 1),
  "BSD-3-Clause": L("permissive", 1), "BSD-3-Clause-Clear": L("permissive", 0), "BSD-4-Clause": L("permissive", 0),
  "Apache-1.0": L("permissive", 0), "Apache-1.1": L("permissive", 1), "Apache-2.0": L("permissive", 1),
  "Zlib": L("permissive", 1), "BSL-1.0": L("permissive", 1), "PostgreSQL": L("permissive", 1), "X11": L("permissive", 0),
  "Python-2.0": L("permissive", 1), "PSF-2.0": L("permissive", 0), "Artistic-1.0": L("permissive", 1), "Artistic-2.0": L("permissive", 1),
  "Unicode-DFS-2016": L("permissive", 1), "Unicode-3.0": L("permissive", 1), "BlueOak-1.0.0": L("permissive", 1),
  "UPL-1.0": L("permissive", 1), "NCSA": L("permissive", 1), "AFL-3.0": L("permissive", 1), "AFL-2.1": L("permissive", 1),
  "CC-BY-3.0": L("permissive", 0), "CC-BY-4.0": L("permissive", 0), "WTFPL": L("permissive", 0), "Ruby": L("permissive", 0),
  "OpenSSL": L("permissive", 0), "Libpng": L("permissive", 0), "libpng-2.0": L("permissive", 0), "curl": L("permissive", 0),
  "HPND": L("permissive", 1), "ICU": L("permissive", 0), "ZPL-2.1": L("permissive", 1), "W3C": L("permissive", 1),
  "MirOS": L("permissive", 1), "Beerware": L("permissive", 0), "PHP-3.01": L("permissive", 1), "PHP-3.0": L("permissive", 1),
  "Xnet": L("permissive", 1), "MulanPSL-2.0": L("permissive", 1), "ECL-2.0": L("permissive", 1), "Info-ZIP": L("permissive", 0),
  "BSD-Source-Code": L("permissive", 0), "bzip2-1.0.6": L("permissive", 0), "Python-2.0.1": L("permissive", 0),
  // weak copyleft (file- or library-level reciprocity)
  "LGPL-2.0-only": L("weak-copyleft", 1, { gpl: [2, 3], lgpl: true }), "LGPL-2.0-or-later": L("weak-copyleft", 1, { gpl: [2, 3], lgpl: true }),
  "LGPL-2.1-only": L("weak-copyleft", 1, { gpl: [2, 3], lgpl: true }), "LGPL-2.1-or-later": L("weak-copyleft", 1, { gpl: [2, 3], lgpl: true }),
  "LGPL-3.0-only": L("weak-copyleft", 1, { gpl: [3], lgpl: true }), "LGPL-3.0-or-later": L("weak-copyleft", 1, { gpl: [3], lgpl: true }),
  "MPL-1.0": L("weak-copyleft", 1), "MPL-1.1": L("weak-copyleft", 1), "MPL-2.0": L("weak-copyleft", 1),
  "MPL-2.0-no-copyleft-exception": L("weak-copyleft", 1), "EPL-1.0": L("weak-copyleft", 1), "EPL-2.0": L("weak-copyleft", 1),
  "CDDL-1.0": L("weak-copyleft", 1), "CDDL-1.1": L("weak-copyleft", 0), "CPL-1.0": L("weak-copyleft", 1),
  "EUPL-1.1": L("weak-copyleft", 1), "EUPL-1.2": L("weak-copyleft", 1), "MS-PL": L("weak-copyleft", 1), "MS-RL": L("weak-copyleft", 1),
  "CC-BY-SA-3.0": L("weak-copyleft", 0), "CC-BY-SA-4.0": L("weak-copyleft", 0), "OFL-1.1": L("weak-copyleft", 1),
  "APSL-2.0": L("weak-copyleft", 1), "CECILL-C": L("weak-copyleft", 0), "ODbL-1.0": L("weak-copyleft", 0), "LGPLLR": L("weak-copyleft", 0),
  // strong copyleft
  "GPL-1.0-only": L("strong-copyleft", 0, { gpl: [1] }), "GPL-1.0-or-later": L("strong-copyleft", 0, { gpl: [1, 2, 3] }),
  "GPL-2.0-only": L("strong-copyleft", 1, { gpl: [2] }), "GPL-2.0-or-later": L("strong-copyleft", 1, { gpl: [2, 3] }),
  "GPL-3.0-only": L("strong-copyleft", 1, { gpl: [3] }), "GPL-3.0-or-later": L("strong-copyleft", 1, { gpl: [3] }),
  "CECILL-2.1": L("strong-copyleft", 1), "Sleepycat": L("strong-copyleft", 1), "QPL-1.0": L("strong-copyleft", 1),
  // network copyleft (source must be offered to users who interact over a network)
  "AGPL-1.0-only": L("network-copyleft", 0), "AGPL-1.0-or-later": L("network-copyleft", 0),
  "AGPL-3.0-only": L("network-copyleft", 1, { gpl: [3] }), "AGPL-3.0-or-later": L("network-copyleft", 1, { gpl: [3] }),
  "SSPL-1.0": L("network-copyleft", 0, { note: "SSPL-1.0 is not OSI-approved; section 13 requires releasing the source of the whole service stack when the software is offered as a service." }),
  "OSL-2.1": L("network-copyleft", 1), "OSL-3.0": L("network-copyleft", 1), "RPL-1.5": L("network-copyleft", 1), "CPAL-1.0": L("network-copyleft", 1),
  // proprietary, source-available or use-restricted
  "BUSL-1.1": L("proprietary", 0, { note: "Business Source License: production use is restricted until the change date." }),
  "Elastic-2.0": L("proprietary", 0, { note: "Elastic License 2.0 forbids offering the software as a managed service." }),
  "PolyForm-Noncommercial-1.0.0": L("proprietary", 0), "PolyForm-Small-Business-1.0.0": L("proprietary", 0),
  "CC-BY-NC-4.0": L("proprietary", 0), "CC-BY-NC-3.0": L("proprietary", 0), "CC-BY-NC-SA-4.0": L("proprietary", 0),
  "CC-BY-NC-SA-3.0": L("proprietary", 0), "CC-BY-NC-ND-4.0": L("proprietary", 0), "CC-BY-ND-4.0": L("proprietary", 0),
  "JSON": L("proprietary", 0, { note: "The JSON license adds a field-of-use restriction (\"Good, not Evil\"); the FSF lists it as non-free." }),
  "LicenseRef-Proprietary": L("proprietary", 0),
};

// Deprecated SPDX ids -> current ids (SPDX License List deprecations).
const DEPRECATED = {
  "GPL-1.0": "GPL-1.0-only", "GPL-1.0+": "GPL-1.0-or-later", "GPL-2.0": "GPL-2.0-only", "GPL-2.0+": "GPL-2.0-or-later",
  "GPL-3.0": "GPL-3.0-only", "GPL-3.0+": "GPL-3.0-or-later", "LGPL-2.0": "LGPL-2.0-only", "LGPL-2.0+": "LGPL-2.0-or-later",
  "LGPL-2.1": "LGPL-2.1-only", "LGPL-2.1+": "LGPL-2.1-or-later", "LGPL-3.0": "LGPL-3.0-only", "LGPL-3.0+": "LGPL-3.0-or-later",
  "AGPL-1.0": "AGPL-1.0-only", "AGPL-3.0": "AGPL-3.0-only", "BSD-2-Clause-FreeBSD": "BSD-2-Clause", "BSD-2-Clause-NetBSD": "BSD-2-Clause",
  "GPL-2.0-with-classpath-exception": "GPL-2.0-only WITH Classpath-exception-2.0",
  "GPL-2.0-with-GCC-exception": "GPL-2.0-only WITH GCC-exception-2.0",
  "GPL-3.0-with-GCC-exception": "GPL-3.0-only WITH GCC-exception-3.1",
  "GPL-2.0-with-autoconf-exception": "GPL-2.0-only WITH Autoconf-exception-2.0",
  "GPL-2.0-with-bison-exception": "GPL-2.0-only WITH Bison-exception-2.2",
};

// "+" suffix on an -only/-or-later-less id: "GPL-2.0-only+" is invalid, "LGPL-2.1+" handled above, "MPL-1.1+" = this version or later.
// SPDX exceptions. link = linking/runtime exception that keeps the library's copyleft from reaching your code.
const EXCEPTIONS = {
  "Classpath-exception-2.0": { link: true }, "GCC-exception-2.0": { link: true }, "GCC-exception-3.1": { link: true },
  "LLVM-exception": { link: true }, "Linux-syscall-note": { link: true }, "Autoconf-exception-2.0": { link: true },
  "Autoconf-exception-3.0": { link: true }, "Bison-exception-2.2": { link: true }, "Libtool-exception": { link: true },
  "GPL-3.0-linking-exception": { link: true }, "GPL-3.0-linking-source-exception": { link: true },
  "OCaml-LGPL-linking-exception": { link: true }, "WxWindows-exception-3.1": { link: true }, "eCos-exception-2.0": { link: true },
  "freertos-exception-2.0": { link: true }, "mif-exception": { link: true }, "Font-exception-2.0": { link: true },
  "Qt-LGPL-exception-1.1": { link: true }, "Bootloader-exception": { link: true }, "Swift-exception": { link: true },
  "LZMA-exception": { link: true }, "u-boot-exception-2.0": { link: true }, "openvpn-openssl-exception": { link: false },
  "Universal-FOSS-exception-1.0": { link: false, foss: true }, "OpenJDK-assembly-exception-1.0": { link: true },
  "389-exception": { link: true }, "i2p-gpl-java-exception": { link: true }, "GPL-CC-1.0": { link: false },
};

const LIC_BY_LOWER = new Map(Object.keys(LICENSES).map((k) => [k.toLowerCase(), k]));
const DEP_BY_LOWER = new Map(Object.keys(DEPRECATED).map((k) => [k.toLowerCase(), k]));
const EXC_BY_LOWER = new Map(Object.keys(EXCEPTIONS).map((k) => [k.toLowerCase(), k]));

// Free-text license names seen in package metadata and PyPI classifiers -> SPDX.
// Only unambiguous names are mapped; "BSD", "GPL" or "LGPL" without a version stay unknown.
const ALIASES = (() => {
  const m = {};
  const add = (target, ...names) => { for (const n of names) m[aliasKey(n)] = target; };
  add("MIT", "mit", "mit license", "the mit license", "mit licence", "expat", "expat license", "mit/x11");
  add("MIT-0", "mit no attribution", "mit no attribution license", "mit-0 license");
  add("Apache-2.0", "apache 2.0", "apache-2", "apache 2", "apache2", "apache license 2.0", "apache license, version 2.0", "apache license version 2.0",
    "apache software license", "apache software license 2.0", "asl 2.0", "asl2", "apache license (2.0)", "the apache software license, version 2.0",
    "the apache license, version 2.0", "apache public license 2.0", "apache-2.0 license", "apache v2", "apache license v2.0");
  add("BSD-2-Clause", "bsd-2", "bsd 2-clause", "bsd 2 clause", "2-clause bsd", "simplified bsd", "simplified bsd license", "freebsd", "bsd-2-clause license");
  add("BSD-3-Clause", "bsd-3", "bsd 3-clause", "bsd 3 clause", "3-clause bsd", "new bsd", "new bsd license", "modified bsd", "modified bsd license",
    "revised bsd", "bsd 3-clause license", "the 3-clause bsd license", "bsd-3-clause license", "the new bsd license");
  add("ISC", "isc license", "iscl", "isc license (iscl)");
  add("0BSD", "zero-clause bsd", "bsd zero clause license");
  add("MPL-2.0", "mpl 2.0", "mpl-2", "mpl2", "mozilla public license 2.0", "mozilla public license 2.0 (mpl 2.0)", "mozilla public license, version 2.0");
  add("MPL-1.1", "mpl 1.1", "mozilla public license 1.1", "mozilla public license 1.1 (mpl 1.1)");
  add("LGPL-2.1-only", "lgplv2.1", "lgpl-2.1", "lgpl 2.1", "lgpl v2.1", "gnu lesser general public license v2.1", "gnu lesser general public license v2 (lgplv2)", "lgplv2");
  add("LGPL-2.1-or-later", "lgplv2.1+", "lgpl-2.1+", "lgpl 2.1 or later");
  add("LGPL-2.0-or-later", "lgplv2+", "gnu lesser general public license v2 or later (lgplv2+)", "gnu library or lesser general public license (lgpl)");
  add("LGPL-3.0-only", "lgplv3", "lgpl-3", "lgpl 3", "lgpl v3", "lgpl-3.0", "gnu lesser general public license v3", "gnu lesser general public license v3 (lgplv3)");
  add("LGPL-3.0-or-later", "lgplv3+", "lgpl-3+", "gnu lesser general public license v3 or later (lgplv3+)");
  add("GPL-2.0-only", "gplv2", "gpl-2", "gpl 2", "gpl v2", "gpl2", "gnu gpl v2", "gnu general public license v2", "gnu general public license v2 (gplv2)",
    "gnu general public license, version 2", "gnu general public license version 2");
  add("GPL-2.0-or-later", "gplv2+", "gpl-2+", "gpl 2 or later", "gnu general public license v2 or later (gplv2+)");
  add("GPL-3.0-only", "gplv3", "gpl-3", "gpl 3", "gpl v3", "gpl3", "gnu gpl v3", "gnu general public license v3", "gnu general public license v3 (gplv3)",
    "gnu general public license, version 3", "gnu general public license version 3");
  add("GPL-3.0-or-later", "gplv3+", "gpl-3+", "gpl 3 or later", "gnu general public license v3 or later (gplv3+)");
  add("AGPL-3.0-only", "agplv3", "agpl-3", "agpl 3", "agpl v3", "agpl-3.0", "gnu affero general public license v3", "gnu affero general public license v3 (agplv3)", "gnu agpl v3");
  add("AGPL-3.0-or-later", "agplv3+", "gnu affero general public license v3 or later (agplv3+)");
  add("Unlicense", "the unlicense", "unlicense", "the unlicense (unlicense)");
  add("CC0-1.0", "cc0", "cc0 1.0", "cc0 1.0 universal", "cc0-1.0 universal", "creative commons zero", "cc0 1.0 universal (cc0 1.0) public domain dedication");
  add("PSF-2.0", "python software foundation license", "psf", "psf license", "psfl", "python software foundation");
  add("Zlib", "zlib", "zlib license", "zlib/libpng license", "zlib/libpng");
  add("WTFPL", "wtfpl", "do what the f*ck you want to public license");
  add("BSL-1.0", "boost", "boost software license", "boost software license 1.0", "boost software license 1.0 (bsl-1.0)");
  add("EPL-2.0", "epl 2.0", "epl-2", "eclipse public license 2.0", "eclipse public license - v 2.0", "eclipse public license 2.0 (epl-2.0)", "eclipse public license v2.0");
  add("EPL-1.0", "epl 1.0", "epl-1", "eclipse public license 1.0", "eclipse public license - v 1.0", "eclipse public license v1.0");
  add("CDDL-1.0", "cddl", "cddl 1.0", "cddl-1", "common development and distribution license 1.0", "common development and distribution license (cddl)");
  add("CDDL-1.1", "cddl 1.1", "common development and distribution license 1.1", "cddl+gpl license");
  add("Artistic-2.0", "artistic 2.0", "artistic license 2.0", "the artistic license 2.0");
  add("HPND", "historical permission notice and disclaimer (hpnd)", "historical permission notice and disclaimer");
  add("UPL-1.0", "universal permissive license (upl)", "universal permissive license 1.0", "upl");
  add("CC-BY-4.0", "cc by 4.0", "cc-by 4.0", "creative commons attribution 4.0", "creative commons attribution 4.0 international");
  add("CC-BY-SA-4.0", "cc by-sa 4.0", "creative commons attribution share alike 4.0", "creative commons attribution-sharealike 4.0 international");
  add("EUPL-1.2", "eupl 1.2", "european union public licence 1.2", "european union public licence 1.2 (eupl 1.2)");
  add("Python-2.0", "python-2", "python license", "python license 2.0");
  add("LicenseRef-Public-Domain", "public domain", "public-domain", "publicdomain");
  add("LicenseRef-Proprietary", "unlicensed", "proprietary", "commercial", "other/proprietary license", "proprietary license", "closed source", "all rights reserved");
  return m;
})();
function aliasKey(s) { return String(s || "").toLowerCase().replace(/[‘’"']/g, "").replace(/\s+/g, " ").replace(/^\s+|\s+$/g, "").replace(/\s*[.;]$/, ""); }

// ---------------------------------------------------------------------------
// SPDX license expression parser (SPDX 2.3 Annex D).
//   expression := or ; or := and ("OR" and)* ; and := with ("AND" with)* ;
//   with := simple ("WITH" exception)? | "(" expression ")" ; simple := id ["+"] | LicenseRef
// Precedence: WITH > AND > OR. Operators are case-sensitive per the spec; lower-case
// operators are accepted and reported as a note.
// ---------------------------------------------------------------------------
function tokenize(s) {
  const toks = [];
  const re = /\s*(\(|\)|[A-Za-z0-9.\-:+]+)/y;
  let i = 0;
  const str = String(s);
  while (i < str.length) {
    if (/\s/.test(str[i])) { i++; continue; }
    re.lastIndex = i;
    const m = re.exec(str);
    if (!m) return { error: "unexpected character '" + str[i] + "' at position " + i };
    toks.push(m[1]);
    i = re.lastIndex;
  }
  return { toks };
}

/**
 * Parse an SPDX license expression.
 * Returns { ok, ast?, error?, notes[] }. ast nodes:
 *   { type: "license", id, plus, exception?, ref? } | { type: "and"|"or", args } | { type: "none" } | { type: "noassertion" }
 * ids are canonicalised (case, deprecated forms) where the id is on the SPDX list.
 */
export function parseExpression(input) {
  const notes = [];
  const src = String(input == null ? "" : input).trim();
  if (!src) return { ok: false, error: "empty expression", notes };
  if (src === "NONE" || src === "NOASSERTION") return { ok: true, ast: { type: src === "NONE" ? "none" : "noassertion" }, notes };
  if (/^(none|noassertion)$/i.test(src)) { notes.push("special value should be upper case"); return { ok: true, ast: { type: /^none$/i.test(src) ? "none" : "noassertion" }, notes }; }
  const tk = tokenize(src);
  if (tk.error) return { ok: false, error: tk.error, notes };
  const toks = tk.toks;
  let p = 0;
  const peek = () => toks[p];
  const isOp = (t, op) => {
    if (t === op) return true;
    if (t && t.toLowerCase() === op.toLowerCase()) { if (!notes.includes("lower-case operator '" + t + "'")) notes.push("lower-case operator '" + t + "'"); return true; }
    return false;
  };
  function parseOr() {
    const args = [parseAnd()];
    while (p < toks.length && isOp(peek(), "OR")) { p++; args.push(parseAnd()); }
    return args.length === 1 ? args[0] : { type: "or", args };
  }
  function parseAnd() {
    const args = [parseWith()];
    while (p < toks.length && isOp(peek(), "AND")) { p++; args.push(parseWith()); }
    return args.length === 1 ? args[0] : { type: "and", args };
  }
  function parseWith() {
    const t = peek();
    if (t === undefined) throw new Error("expression ends early");
    if (t === "(") {
      p++;
      const inner = parseOr();
      if (peek() !== ")") throw new Error("missing closing parenthesis");
      p++;
      return inner;
    }
    if (t === ")") throw new Error("unexpected ')'");
    if (isOp(t, "AND") || isOp(t, "OR") || isOp(t, "WITH")) throw new Error("operator '" + t + "' where a license was expected");
    if (t === "NONE" || t === "NOASSERTION") throw new Error(t + " cannot be combined with other licenses");
    p++;
    const leaf = makeLeaf(t, notes);
    if (p < toks.length && isOp(peek(), "WITH")) {
      p++;
      const ex = peek();
      if (ex === undefined || ex === "(" || ex === ")") throw new Error("WITH must be followed by an exception id");
      p++;
      const canon = EXC_BY_LOWER.get(ex.toLowerCase());
      if (!canon && !/^(DocumentRef-[A-Za-z0-9.\-]+:)?AdditionRef-[A-Za-z0-9.\-]+$/.test(ex)) notes.push("unrecognised exception '" + ex + "'");
      leaf.exception = canon || ex;
    }
    return leaf;
  }
  try {
    const ast = parseOr();
    if (p < toks.length) throw new Error("unexpected '" + toks[p] + "'");
    return { ok: true, ast: expandDeprecated(ast), notes };
  } catch (e) {
    return { ok: false, error: e.message, notes };
  }
}

function makeLeaf(tok, notes) {
  let t = tok;
  const ref = /^(DocumentRef-[A-Za-z0-9.\-]+:)?LicenseRef-[A-Za-z0-9.\-]+$/.test(t);
  if (ref) return { type: "license", id: t, plus: false, ref: true };
  // Deprecated ids that end in "+" ("GPL-2.0+") are mapped whole.
  const depWhole = DEP_BY_LOWER.get(t.toLowerCase());
  if (depWhole) { notes.push("deprecated id '" + t + "' read as '" + DEPRECATED[depWhole] + "'"); return { type: "license", id: DEPRECATED[depWhole], plus: false, deprecated: t }; }
  let plus = false;
  if (t.endsWith("+")) { plus = true; t = t.slice(0, -1); }
  const dep = DEP_BY_LOWER.get(t.toLowerCase());
  if (dep) {
    let to = DEPRECATED[dep];
    if (plus && /-only$/.test(to)) { to = to.replace(/-only$/, "-or-later"); plus = false; }
    notes.push("deprecated id '" + tok + "' read as '" + to + "'");
    return { type: "license", id: to, plus, deprecated: tok };
  }
  const canon = LIC_BY_LOWER.get(t.toLowerCase());
  if (canon) {
    if (canon !== t) notes.push("id case corrected '" + t + "' to '" + canon + "'");
    if (plus && /-only$/.test(canon)) return { type: "license", id: canon.replace(/-only$/, "-or-later"), plus: false };
    return { type: "license", id: canon, plus };
  }
  if (!/^[A-Za-z0-9.\-]+$/.test(t)) throw new Error("invalid license id '" + tok + "'");
  notes.push("unrecognised license id '" + t + "'");
  return { type: "license", id: t, plus, unknown: true };
}

// A deprecated id such as GPL-2.0-with-classpath-exception expands to "GPL-2.0-only WITH ...".
function expandDeprecated(ast) {
  if (ast.type === "license" && / WITH /.test(ast.id)) {
    const [id, ex] = ast.id.split(" WITH ");
    return { type: "license", id, plus: false, exception: ex, deprecated: ast.deprecated };
  }
  if (ast.type === "and" || ast.type === "or") return { type: ast.type, args: ast.args.map(expandDeprecated) };
  return ast;
}

/** Serialise an AST back to a canonical SPDX expression string. */
export function exprToString(ast, parent) {
  if (!ast) return "";
  if (ast.type === "none") return "NONE";
  if (ast.type === "noassertion") return "NOASSERTION";
  if (ast.type === "license") return ast.id + (ast.plus ? "+" : "") + (ast.exception ? " WITH " + ast.exception : "");
  const op = ast.type === "and" ? " AND " : " OR ";
  const s = ast.args.map((a) => exprToString(a, ast.type)).join(op);
  return parent && parent !== ast.type ? "(" + s + ")" : s;
}

/** All license leaves of an AST. */
export function leaves(ast) {
  if (!ast) return [];
  if (ast.type === "license") return [ast];
  if (ast.type === "and" || ast.type === "or") return ast.args.flatMap(leaves);
  return [];
}

/**
 * Normalise a raw license value (SPDX expression, deprecated id, free-text name, PyPI
 * classifier, Cargo "MIT/Apache-2.0" form) into an SPDX AST.
 * Returns { raw, status: "spdx"|"normalized"|"invalid"|"none"|"noassertion"|"missing", expr, ast, notes }.
 */
export function normalizeLicense(raw) {
  const r = raw == null ? "" : String(raw).trim();
  if (!r) return { raw: r, status: "missing", expr: "", ast: null, notes: [] };
  // npm "SEE LICENSE IN <file>" points at a custom license file.
  const see = r.match(/^SEE LICEN[CS]E IN (.+)$/i);
  if (see) return { raw: r, status: "normalized", expr: "LicenseRef-See-File", ast: { type: "license", id: "LicenseRef-See-File", plus: false, ref: true, file: see[1].trim() }, notes: ["custom license file " + see[1].trim()] };
  const classifier = r.match(/^License\s*::\s*(?:OSI Approved\s*::\s*)?(.+)$/i);
  const text = classifier ? classifier[1].trim() : r;
  const viaAlias = (s) => {
    const k = aliasKey(s);
    if (ALIASES[k]) return ALIASES[k];
    const paren = s.match(/\(([^()]+)\)\s*$/);
    if (paren && ALIASES[aliasKey(paren[1])]) return ALIASES[aliasKey(paren[1])];
    if (paren && LIC_BY_LOWER.get(paren[1].trim().toLowerCase())) return LIC_BY_LOWER.get(paren[1].trim().toLowerCase());
    return null;
  };
  const direct = parseExpression(text);
  if (direct.ok && !leaves(direct.ast).some((l) => l.unknown)) {
    const changed = direct.notes.length > 0 || classifier;
    return { raw: r, status: changed ? "normalized" : "spdx", expr: exprToString(direct.ast), ast: direct.ast, notes: direct.notes.concat(classifier ? ["PyPI classifier"] : []) };
  }
  const a = viaAlias(text);
  if (a) {
    const pa = parseExpression(a);
    return { raw: r, status: "normalized", expr: exprToString(pa.ast), ast: pa.ast, notes: ["license name '" + text + "' read as " + a] };
  }
  // Cargo's legacy "MIT/Apache-2.0" means MIT OR Apache-2.0; "MIT, Apache-2.0" and "MIT or Apache-2.0" are common free-text forms.
  if (/[/,]| or | and /i.test(text)) {
    const parts = text.split(/\s*\/\s*|\s*,\s*|\s+or\s+/i).filter(Boolean);
    const andParts = parts.length === 1 ? text.split(/\s+and\s+/i) : null;
    const list = andParts && andParts.length > 1 ? andParts : parts;
    const op = andParts && andParts.length > 1 ? "AND" : "OR";
    const mapped = list.map((p) => { const pe = parseExpression(p); if (pe.ok && !leaves(pe.ast).some((l) => l.unknown)) return exprToString(pe.ast, "x"); const al = viaAlias(p); return al; });
    if (mapped.length > 1 && mapped.every(Boolean)) {
      const pe = parseExpression(mapped.map((m) => (/ (AND|OR) /.test(m) ? "(" + m + ")" : m)).join(" " + op + " "));
      if (pe.ok) return { raw: r, status: "normalized", expr: exprToString(pe.ast), ast: pe.ast, notes: ["free-text list '" + text + "' read as " + op] };
    }
  }
  if (direct.ok) return { raw: r, status: "normalized", expr: exprToString(direct.ast), ast: direct.ast, notes: direct.notes };
  return { raw: r, status: "invalid", expr: "", ast: null, notes: [direct.error] };
}

// ---------------------------------------------------------------------------
// Classification and policy evaluation.
// ---------------------------------------------------------------------------

/** Category and facts for one license leaf. */
export function classifyLeaf(leaf) {
  if (!leaf) return { category: "unknown", osi: false };
  const base = LICENSES[leaf.id];
  let category = base ? base.c : leaf.ref ? (/proprietary|commercial|eula/i.test(leaf.id) ? "proprietary" : "unknown") : "unknown";
  const out = { id: leaf.id, category, osi: !!(base && base.osi), known: !!base, gpl: base && base.gpl ? base.gpl.slice() : null, lgpl: !!(base && base.lgpl), note: base && base.note || "" };
  if (leaf.plus && out.gpl) out.gpl = [...new Set(out.gpl.concat([3]))].sort();
  if (leaf.exception) {
    const ex = EXCEPTIONS[leaf.exception];
    out.exception = leaf.exception;
    if (ex && ex.link && (category === "strong-copyleft" || category === "network-copyleft")) { out.category = "weak-copyleft"; out.linkException = true; }
    if (ex && ex.link && category === "weak-copyleft") out.linkException = true;
    if (ex && ex.foss) out.fossException = true;
  }
  return out;
}

function globToRe(g) { return new RegExp("^" + g.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$", "i"); }
function compilePolicy(o) {
  const mk = (list) => (Array.isArray(list) ? list : String(list || "").split(/[\n,]+/)).map((s) => String(s).trim()).filter(Boolean).map((s) => {
    const cat = s.toLowerCase().replace(/^category:\s*/, "");
    if (CATEGORIES.includes(cat)) return { kind: "category", value: cat, label: s };
    return { kind: "id", re: globToRe(s), label: s };
  });
  return { compiled: true, allow: mk(o.allow), review: mk(o.review), deny: mk(o.deny) };
}
function matchList(list, leaf, info) {
  const full = leaf.id + (leaf.plus ? "+" : "") + (leaf.exception ? " WITH " + leaf.exception : "");
  for (const r of list) {
    if (r.kind === "category" ? r.value === info.category : (r.re.test(leaf.id) || r.re.test(full))) return r.label;
  }
  return null;
}
const POLICY_RANK = { allow: 0, unlisted: 1, review: 2, deny: 3 };
function leafPolicy(leaf, info, pol) {
  const d = matchList(pol.deny, leaf, info); if (d) return { state: "deny", rule: d };
  const r = matchList(pol.review, leaf, info); if (r) return { state: "review", rule: r };
  if (pol.allow.length) { const a = matchList(pol.allow, leaf, info); return a ? { state: "allow", rule: a } : { state: "unlisted", rule: "" }; }
  return { state: "allow", rule: "" };
}

/**
 * Evaluate an AST under a policy: OR picks the most permissive option the policy allows,
 * AND requires every operand. Returns { chosen: leaf[], infos, category, policy, alternatives }.
 */
export function evaluate(ast, policy) {
  const pol = policy && policy.compiled ? policy : compilePolicy(policy || {});
  function ev(n) {
    if (!n || n.type === "none" || n.type === "noassertion") return { chosen: [], infos: [], category: "unknown", policy: "allow", rules: [], alternatives: [] };
    if (n.type === "license") {
      const info = classifyLeaf(n);
      const pl = leafPolicy(n, info, pol);
      return { chosen: [n], infos: [info], category: info.category, policy: pl.state, rules: pl.rule ? [pl.rule] : [], alternatives: [] };
    }
    const parts = n.args.map(ev);
    if (n.type === "and") {
      return {
        chosen: parts.flatMap((p) => p.chosen), infos: parts.flatMap((p) => p.infos),
        category: parts.map((p) => p.category).sort((a, b) => CAT_RANK[b] - CAT_RANK[a])[0],
        policy: parts.map((p) => p.policy).sort((a, b) => POLICY_RANK[b] - POLICY_RANK[a])[0],
        rules: [...new Set(parts.flatMap((p) => p.rules))].sort(), alternatives: parts.flatMap((p) => p.alternatives),
      };
    }
    const ranked = parts.map((p, i) => ({ p, i, s: exprToString(n.args[i]) })).sort((a, b) =>
      POLICY_RANK[a.p.policy] - POLICY_RANK[b.p.policy] || CAT_RANK[a.p.category] - CAT_RANK[b.p.category] || (a.s < b.s ? -1 : a.s > b.s ? 1 : 0));
    const best = ranked[0];
    return { ...best.p, alternatives: best.p.alternatives.concat(ranked.slice(1).map((x) => x.s)) };
  }
  return ev(ast);
}

// ---------------------------------------------------------------------------
// Known incompatibilities (FSF "Various Licenses and Comments about Them",
// https://www.gnu.org/licenses/license-list.html, and the Apache Software
// Foundation's https://www.apache.org/licenses/GPL-compatibility.html).
// ---------------------------------------------------------------------------
const GPL_INCOMPATIBLE = {
  "EPL-1.0": "The FSF lists EPL-1.0 as incompatible with the GPL (weak copyleft plus a choice-of-law clause).",
  "MPL-1.1": "The FSF lists MPL-1.1 as incompatible with the GPL.",
  "MPL-1.0": "The FSF lists MPL-1.0 as incompatible with the GPL.",
  "MPL-2.0-no-copyleft-exception": "MPL-2.0 marked Incompatible With Secondary Licenses cannot be combined into a GPL work (MPL-2.0 section 3.3 does not apply).",
  "CDDL-1.0": "The FSF lists CDDL-1.0 as incompatible with the GPL.",
  "CDDL-1.1": "CDDL-1.1 keeps the CDDL-1.0 terms the FSF lists as GPL-incompatible.",
  "BSD-4-Clause": "The FSF lists the original 4-clause BSD license as GPL-incompatible because of its advertising clause.",
  "OpenSSL": "The FSF lists the OpenSSL license as GPL-incompatible (advertising requirements).",
  "Apache-1.1": "The FSF lists Apache-1.1 as GPL-incompatible.",
  "Apache-1.0": "The FSF lists Apache-1.0 as GPL-incompatible.",
  "PHP-3.01": "The FSF lists the PHP License 3.01 as GPL-incompatible.",
  "MS-PL": "The FSF lists the Microsoft Public License as GPL-incompatible.",
  "MS-RL": "The FSF lists the Microsoft Reciprocal License as GPL-incompatible.",
  "CPL-1.0": "The FSF lists the Common Public License 1.0 as GPL-incompatible.",
  "OSL-3.0": "The FSF lists the Open Software License as GPL-incompatible.",
  "EUPL-1.1": "The FSF lists EUPL-1.1 as GPL-incompatible (EUPL-1.2 is compatible through its compatibility list).",
};
const FSF_SRC = "FSF license list (gnu.org/licenses/license-list.html)";

/**
 * Is `other` incompatible with the copyleft `host` when both end up in one GPL-governed work?
 * Both are classifyLeaf() outputs. Returns { reason, source } or null.
 */
export function incompatibility(host, other) {
  if (!host || !other || !host.gpl || host.linkException) return null;
  if (host.category !== "strong-copyleft" && host.category !== "network-copyleft") return null;
  // The Universal FOSS Exception permits combining with code under any OSI-approved license.
  if ((host.fossException && other.osi) || (other.fossException && host.osi)) return null;
  const hs = new Set(host.gpl);
  if (other.id === "Apache-2.0" && !hs.has(3)) return { reason: "Apache-2.0 is incompatible with GPL version 2 (its patent termination and indemnification terms are additional restrictions); it is compatible with GPL version 3 only.", source: "FSF license list; apache.org/licenses/GPL-compatibility.html" };
  if (other.gpl && !other.linkException) {
    const overlap = other.gpl.some((v) => hs.has(v));
    if (!overlap) return { reason: host.id + " and " + other.id + " share no common GPL version, so the combination cannot satisfy both (for example GPLv2-only code cannot be relicensed under GPLv3).", source: FSF_SRC };
  }
  if (GPL_INCOMPATIBLE[other.id]) return { reason: GPL_INCOMPATIBLE[other.id], source: FSF_SRC };
  if (other.category === "proprietary") return { reason: "A GPL-family work must be distributed under GPL terms as a whole; " + other.id + " does not grant those permissions.", source: FSF_SRC };
  return null;
}

// ---------------------------------------------------------------------------
// Input parsing
// ---------------------------------------------------------------------------
const FORMAT_LABEL = {
  "cyclonedx-json": "CycloneDX JSON SBOM", "cyclonedx-xml": "CycloneDX XML SBOM", "spdx-json": "SPDX JSON SBOM", "spdx-tv": "SPDX tag-value SBOM",
  "package-lock": "npm package-lock.json", "npm-manifest": "npm package.json (project metadata)", "yarn-lock": "yarn.lock", "pnpm-lock": "pnpm-lock.yaml",
  "requirements": "pip requirements.txt", "pipfile-lock": "Pipfile.lock", "poetry-lock": "poetry.lock", "go-sum": "go.sum", "go-mod": "go.mod",
  "cargo-lock": "Cargo.lock", "gemfile-lock": "Gemfile.lock", "composer-lock": "composer.lock", "pom": "Maven pom.xml",
  "license-checker-json": "license-checker JSON report", "license-csv": "License inventory CSV", "license-json": "License inventory JSON",
  unknown: "Unrecognised", empty: "Empty",
};
export { FORMAT_LABEL };

const PURL_ECO = { npm: "npm", pypi: "pypi", maven: "maven", cargo: "cargo", gem: "gem", golang: "go", composer: "composer", nuget: "nuget", github: "github", deb: "deb", rpm: "rpm", apk: "apk", generic: "generic", swift: "swift", cocoapods: "cocoapods", hex: "hex", pub: "pub" };

/** Parse a package URL (purl) into { type, namespace, name, version, ecosystem, fullName }. */
export function parsePurl(purl) {
  const m = String(purl || "").trim().match(/^pkg:([A-Za-z0-9.+-]+)\/([^@?#]+)(?:@([^?#]+))?/);
  if (!m) return null;
  const dec = (s) => { try { return decodeURIComponent(s); } catch (_) { return s; } };
  const type = m[1].toLowerCase();
  const segs = m[2].split("/").map(dec);
  const name = segs.pop();
  const namespace = segs.join("/");
  const version = m[3] ? dec(m[3]) : "";
  const fullName = type === "maven" ? (namespace ? namespace + ":" + name : name) : namespace ? namespace + "/" + name : name;
  return { type, namespace, name, version, ecosystem: PURL_ECO[type] || type, fullName };
}

function comp(base) {
  return Object.assign({ name: "", version: "", ecosystem: "", purl: "", declared: "", concluded: "", license: "", licenseSource: "none", copyright: "", direct: undefined, dev: false, path: null, ref: "", file: "" }, base);
}

function sniffFile(name, text) {
  const n = String(name || "").toLowerCase().replace(/^.*[\\/]/, "");
  const t = String(text || "").replace(/^﻿/, "");
  const s = t.trimStart();
  if (!s) return { format: "empty", confidence: "high" };
  if (s[0] === "{" || s[0] === "[") {
    let j; try { j = JSON.parse(s); } catch (_) { j = undefined; }
    if (j && !Array.isArray(j)) {
      if (j.bomFormat === "CycloneDX" || (j.specVersion && Array.isArray(j.components))) return { format: "cyclonedx-json", confidence: j.bomFormat === "CycloneDX" ? "high" : "medium", json: j };
      if (typeof j.spdxVersion === "string" || (j.SPDXID && Array.isArray(j.packages))) return { format: "spdx-json", confidence: /^SPDX-2\./.test(j.spdxVersion || "") ? "high" : "medium", json: j };
      if (j.lockfileVersion !== undefined && (j.packages || j.dependencies)) return { format: "package-lock", confidence: "high", json: j };
      if (j._meta && (j.default || j.develop)) return { format: "pipfile-lock", confidence: "high", json: j };
      if (Array.isArray(j.packages) && (j["content-hash"] || j["packages-dev"] !== undefined || n === "composer.lock")) return { format: "composer-lock", confidence: "high", json: j };
      if ((j.name || j.version) && (j.dependencies || j.devDependencies || j.license) && !j.packages && n !== "composer.json") return { format: "npm-manifest", confidence: n === "package.json" ? "high" : "medium", json: j };
      const vals = Object.entries(j);
      if (vals.length && vals.every(([k, v]) => /.@[^@]+$/.test(k) && v && typeof v === "object" && ("licenses" in v || "licence" in v))) return { format: "license-checker-json", confidence: "high", json: j };
    }
    if (Array.isArray(j) && j.length && j.every((r) => r && typeof r === "object")) {
      const headers = Object.keys(j[0]);
      const ok = findColumn(headers, COLUMNS.name) && findColumn(headers, COLUMNS.license);
      return { format: "license-json", confidence: ok ? "high" : "low", json: j };
    }
    if (j === undefined) return { format: "unknown", confidence: "low", reason: "JSON did not parse" };
    return { format: "unknown", confidence: "low", reason: "JSON shape not recognised" };
  }
  if (/^<\?xml|^<bom[\s>]/.test(s) || (s[0] === "<" && /<bom[\s>][\s\S]*cyclonedx/i.test(s.slice(0, 4000)))) {
    if (/<bom[\s>]/.test(s.slice(0, 4000)) && /cyclonedx/i.test(s.slice(0, 4000))) return { format: "cyclonedx-xml", confidence: "high" };
    if (/<project[\s>]/.test(s) && /<dependency>/.test(s)) return { format: "pom", confidence: "high" };
    if (/<bom[\s>]/.test(s)) return { format: "cyclonedx-xml", confidence: "medium" };
    return { format: "unknown", confidence: "low", reason: "XML that is neither CycloneDX nor a Maven POM" };
  }
  if (/^SPDXVersion:\s*SPDX-/m.test(s)) return { format: "spdx-tv", confidence: "high" };
  if (/^lockfileVersion:/m.test(s) && /^packages:/m.test(s)) return { format: "pnpm-lock", confidence: "high" };
  if (/\[\[package\]\]/.test(s)) {
    if (n === "cargo.lock" || /@generated by Cargo/.test(s) || /source = "registry\+https:\/\/github\.com\/rust-lang\/crates\.io-index"/.test(s) || /\nchecksum = "[0-9a-f]{64}"/.test(s)) return { format: "cargo-lock", confidence: "high" };
    return { format: "poetry-lock", confidence: n === "poetry.lock" || /content-hash/.test(s) ? "high" : "medium" };
  }
  if (/^#\s*yarn lockfile/m.test(s) || /^__metadata:/m.test(s) || n === "yarn.lock") return { format: "yarn-lock", confidence: "high" };
  if (/^GEM$/m.test(s) && /^\s{2}specs:/m.test(s)) return { format: "gemfile-lock", confidence: "high" };
  if (/\s+h1:/.test(s) && /\/go\.mod\s+h1:/.test(s)) return { format: "go-sum", confidence: "high" };
  if (/^module\s+\S+/m.test(s) && /\brequire\b/.test(s)) return { format: "go-mod", confidence: "high" };
  if (/<dependency>/.test(s)) return { format: "pom", confidence: "medium" };
  // CSV inventories (license-checker --csv, pip-licenses --format=csv, spreadsheets)
  const first = s.split(/\r?\n/, 1)[0];
  if (/[,;\t]/.test(first)) {
    const { headers } = parseCsv(s.split(/\r?\n/).slice(0, 2).join("\n"));
    const nameH = findColumn(headers, COLUMNS.name), licH = findColumn(headers, COLUMNS.license);
    if (nameH && licH) return { format: "license-csv", confidence: "high" };
    if (headers.length >= 2) return { format: "license-csv", confidence: "low" };
  }
  if (/^requirements.*\.txt$|\.req$/.test(n) || s.split(/\r?\n/).filter((l) => l.trim() && !/^\s*#/.test(l)).slice(0, 20).every((l) => /^\s*-|^[A-Za-z0-9_.\-[\],]+\s*(==|>=|<=|~=|!=|>|<|===)?\s*[^\s]*\s*(;.*)?(#.*)?$/.test(l.trim()))) {
    return { format: "requirements", confidence: /^requirements/.test(n) ? "high" : "medium" };
  }
  return { format: "unknown", confidence: "low", reason: "not a recognised lockfile, SBOM or license report" };
}

// ---- CycloneDX JSON -------------------------------------------------------
function cdxLicenses(list) {
  const declared = [], concluded = [], plain = [];
  for (const e of Array.isArray(list) ? list : []) {
    if (!e || typeof e !== "object") continue;
    let v = "";
    let ack = "";
    if (typeof e.expression === "string") { v = e.expression; ack = e.acknowledgement || ""; }
    else if (e.license) { v = e.license.id || e.license.name || ""; ack = e.license.acknowledgement || ""; }
    if (!v) continue;
    (ack === "concluded" ? concluded : ack === "declared" ? declared : plain).push(v);
  }
  const join = (arr) => (arr.length <= 1 ? arr[0] || "" : arr.map((x) => (/\s(AND|OR)\s/i.test(x) ? "(" + x + ")" : x)).join(" AND "));
  return { declared: join(declared.concat(plain)), concluded: join(concluded), multi: plain.length + declared.length > 1 };
}
function walkCdxComponents(list, out, parentRef) {
  for (const c of Array.isArray(list) ? list : []) {
    if (!c || typeof c !== "object") continue;
    out.push({ c, parentRef });
    if (Array.isArray(c.components)) walkCdxComponents(c.components, out, c["bom-ref"] || "");
  }
}
function parseCycloneDxJson(j, file) {
  const issues = [];
  const all = [];
  walkCdxComponents(j.components, all, "");
  const meta = j.metadata && j.metadata.component;
  const project = meta ? { name: meta.name || "", version: meta.version || "", license: cdxLicenses(meta.licenses).declared || cdxLicenses(meta.licenses).concluded, ref: meta["bom-ref"] || "" } : null;
  const comps = [];
  let multi = 0;
  for (const { c } of all) {
    if (c.type && /^(file|data|device|firmware-config)$/.test(c.type) && !c.purl) continue;
    const lic = cdxLicenses(c.licenses);
    if (lic.multi) multi++;
    const pu = parsePurl(c.purl);
    comps.push(comp({
      name: pu ? pu.fullName : (c.group ? c.group + ":" : "") + (c.name || ""), version: c.version || (pu && pu.version) || "", ecosystem: pu ? pu.ecosystem : "",
      purl: c.purl || "", declared: lic.declared, concluded: lic.concluded, copyright: c.copyright || "", ref: c["bom-ref"] || "",
      dev: c.scope === "excluded", licenseSource: lic.declared || lic.concluded ? "sbom" : "none", file,
    }));
  }
  if (multi) issues.push(multi + " component(s) list several licenses without an expression; read as AND (CycloneDX defines no OR for a list)");
  const edges = new Map();
  for (const d of Array.isArray(j.dependencies) ? j.dependencies : []) {
    if (!d || !d.ref) continue;
    edges.set(d.ref, (Array.isArray(d.dependsOn) ? d.dependsOn : []).map(String));
  }
  if (edges.size) applyGraph(comps, edges, project ? [project.ref] : [], project ? project.name : "", (c) => c.ref);
  const spec = String(j.specVersion || "");
  if (spec && !/^1\.[4-6]$/.test(spec)) issues.push("specVersion " + spec + " is outside the tested 1.4-1.6 range");
  return { components: comps, project, issues, version: spec, hasGraph: edges.size > 0, hasAck: comps.some((c) => c.concluded) };
}

// ---- CycloneDX XML --------------------------------------------------------
const local = (t) => String(t || "").replace(/^.*:/, "");
const kids = (n, tag) => (n && n.children ? n.children.filter((c) => local(c.tag) === tag) : []);
const kid = (n, tag) => kids(n, tag)[0] || null;
const ktext = (n, tag) => { const k = kid(n, tag); return k ? String(k.text || "").trim() : ""; };
function cdxXmlLicenses(node) {
  const list = [];
  const lic = kid(node, "licenses");
  if (!lic) return cdxLicenses([]);
  for (const ch of lic.children || []) {
    const t = local(ch.tag);
    if (t === "expression") list.push({ expression: String(ch.text || "").trim(), acknowledgement: ch.attrs && ch.attrs.acknowledgement });
    else if (t === "license") list.push({ license: { id: ktext(ch, "id"), name: ktext(ch, "name"), acknowledgement: ch.attrs && ch.attrs.acknowledgement } });
  }
  return cdxLicenses(list);
}
function parseCycloneDxXml(text, file) {
  let root = xmlLite(text);
  if (local(root.tag) !== "bom") root = (root.children || []).find((c) => local(c.tag) === "bom") || root;
  const issues = [];
  const ns = (root.attrs && root.attrs.xmlns) || "";
  const spec = (ns.match(/cyclonedx\.org\/schema\/bom\/(\d+\.\d+)/) || [])[1] || "";
  if (spec && !/^1\.[4-6]$/.test(spec)) issues.push("schema " + spec + " is outside the tested 1.4-1.6 range");
  const metaC = kid(kid(root, "metadata"), "component");
  const project = metaC ? { name: ktext(metaC, "name"), version: ktext(metaC, "version"), license: cdxXmlLicenses(metaC).declared || cdxXmlLicenses(metaC).concluded, ref: (metaC.attrs && metaC.attrs["bom-ref"]) || "" } : null;
  const comps = [];
  let multi = 0;
  const walk = (container) => {
    for (const c of kids(container, "component")) {
      const lic = cdxXmlLicenses(c);
      if (lic.multi) multi++;
      const purl = ktext(c, "purl");
      const pu = parsePurl(purl);
      const group = ktext(c, "group");
      comps.push(comp({
        name: pu ? pu.fullName : (group ? group + ":" : "") + ktext(c, "name"), version: ktext(c, "version") || (pu && pu.version) || "", ecosystem: pu ? pu.ecosystem : "",
        purl, declared: lic.declared, concluded: lic.concluded, copyright: ktext(c, "copyright"), ref: (c.attrs && c.attrs["bom-ref"]) || "",
        dev: ktext(c, "scope") === "excluded", licenseSource: lic.declared || lic.concluded ? "sbom" : "none", file,
      }));
      const nested = kid(c, "components");
      if (nested) walk(nested);
    }
  };
  walk(kid(root, "components"));
  if (multi) issues.push(multi + " component(s) list several licenses without an expression; read as AND");
  const edges = new Map();
  for (const d of kids(kid(root, "dependencies"), "dependency")) {
    const ref = d.attrs && d.attrs.ref;
    if (ref) edges.set(ref, kids(d, "dependency").map((x) => x.attrs && x.attrs.ref).filter(Boolean));
  }
  if (edges.size) applyGraph(comps, edges, project ? [project.ref] : [], project ? project.name : "", (c) => c.ref);
  return { components: comps, project, issues, version: spec, hasGraph: edges.size > 0, hasAck: comps.some((c) => c.concluded) };
}

// ---- SPDX JSON and tag-value ---------------------------------------------
function spdxPkgToComp(p, file) {
  let purl = "";
  for (const r of p.externalRefs || []) {
    if (r && /package[-_]manager/i.test(r.referenceCategory || "") && r.referenceType === "purl") { purl = r.referenceLocator; break; }
  }
  const pu = parsePurl(purl);
  const decl = p.licenseDeclared || "", conc = p.licenseConcluded || "";
  return comp({
    name: pu ? pu.fullName : p.name || "", version: p.versionInfo || (pu && pu.version) || "", ecosystem: pu ? pu.ecosystem : "", purl,
    declared: decl, concluded: conc, copyright: p.copyrightText && p.copyrightText !== "NOASSERTION" ? p.copyrightText : "",
    ref: p.SPDXID || "", licenseSource: decl || conc ? "sbom" : "none", file,
  });
}
function spdxRelationsToEdges(rels) {
  const edges = new Map(); const describes = [];
  const add = (a, b) => { if (!edges.has(a)) edges.set(a, []); edges.get(a).push(b); };
  for (const r of rels) {
    const t = String(r.type || "").toUpperCase();
    if (t === "DESCRIBES") describes.push(r.b);
    else if (t === "DESCRIBED_BY") describes.push(r.a);
    else if (t === "DEPENDS_ON" || t === "CONTAINS" || t === "STATIC_LINK" || t === "DYNAMIC_LINK") add(r.a, r.b);
    else if (/_DEPENDENCY_OF$|^DEPENDENCY_OF$|^CONTAINED_BY$/.test(t)) add(r.b, r.a);
  }
  return { edges, describes };
}
function finishSpdx(pkgs, rels, describesDoc, extracted, file, spec) {
  const issues = [];
  const { edges, describes } = spdxRelationsToEdges(rels);
  const rootIds = [...new Set(describesDoc.concat(describes))];
  let project = null;
  const comps = [];
  for (const p of pkgs) {
    const c = spdxPkgToComp(p, file);
    if (rootIds.length === 1 && p.SPDXID === rootIds[0]) { project = { name: c.name, version: c.version, license: c.concluded && c.concluded !== "NOASSERTION" ? c.concluded : c.declared, ref: c.ref }; continue; }
    comps.push(c);
  }
  if (edges.size && rootIds.length) applyGraph(comps, edges, rootIds, project ? project.name : "", (c) => c.ref);
  if (spec && !/^SPDX-2\.[23]$/.test(spec)) issues.push(spec + " is not SPDX 2.3; parsed with the 2.3 field names");
  return { components: comps, project, issues, version: spec, hasGraph: edges.size > 0, hasAck: true, extracted };
}
function parseSpdxJson(j, file) {
  const rels = (Array.isArray(j.relationships) ? j.relationships : []).map((r) => ({ a: r.spdxElementId, type: r.relationshipType, b: r.relatedSpdxElement }));
  const extracted = {};
  for (const x of Array.isArray(j.hasExtractedLicensingInfos) ? j.hasExtractedLicensingInfos : []) if (x && x.licenseId) extracted[x.licenseId] = { name: x.name || "", text: String(x.extractedText || "").slice(0, 2000) };
  return finishSpdx(Array.isArray(j.packages) ? j.packages : [], rels, Array.isArray(j.documentDescribes) ? j.documentDescribes : [], extracted, file, j.spdxVersion || "");
}
function parseSpdxTv(text, file) {
  const lines = String(text).split(/\r?\n/);
  const pkgs = []; const rels = []; const extracted = {};
  let cur = null, curLic = null, spec = "";
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^([A-Za-z]+):\s?(.*)$/);
    if (!m) continue;
    const tag = m[1];
    let val = m[2];
    if (/^<text>/.test(val)) {
      val = val.replace(/^<text>/, "");
      while (!/<\/text>\s*$/.test(val) && i + 1 < lines.length) { i++; val += "\n" + lines[i]; }
      val = val.replace(/<\/text>\s*$/, "");
    }
    val = val.trim();
    if (tag === "SPDXVersion") spec = val;
    else if (tag === "PackageName") { cur = { name: val, externalRefs: [] }; curLic = null; pkgs.push(cur); }
    else if (tag === "LicenseID") { curLic = { id: val }; extracted[val] = { name: "", text: "" }; cur = null; }
    else if (tag === "ExtractedText" && curLic) extracted[curLic.id].text = val.slice(0, 2000);
    else if (tag === "LicenseName" && curLic) extracted[curLic.id].name = val;
    else if (tag === "Relationship") { const r = val.split(/\s+/); if (r.length >= 3) rels.push({ a: r[0], type: r[1], b: r[2] }); }
    else if (tag === "FileName" || tag === "SnippetSPDXID") cur = null;
    else if (cur) {
      if (tag === "SPDXID") cur.SPDXID = val;
      else if (tag === "PackageVersion") cur.versionInfo = val;
      else if (tag === "PackageLicenseConcluded") cur.licenseConcluded = val;
      else if (tag === "PackageLicenseDeclared") cur.licenseDeclared = val;
      else if (tag === "PackageCopyrightText") cur.copyrightText = val;
      else if (tag === "ExternalRef") { const r = val.split(/\s+/); if (r.length >= 3) cur.externalRefs.push({ referenceCategory: r[0], referenceType: r[1], referenceLocator: r[2] }); }
    }
  }
  return finishSpdx(pkgs, rels, [], extracted, file, spec);
}

// Breadth-first shortest path from the root(s) over a dependency graph; sets comp.path (names, root first) and comp.direct.
function applyGraph(comps, edges, roots, rootName, keyOf) {
  const byKey = new Map();
  for (const c of comps) { const k = keyOf(c); if (k) byKey.set(k, c); }
  const prev = new Map();
  const start = roots.filter((r) => r && edges.has(r));
  if (!start.length) return;
  const q = [];
  for (const r of start) { prev.set(r, null); q.push(r); }
  while (q.length) {
    const cur = q.shift();
    for (const nx of (edges.get(cur) || []).slice().sort()) {
      if (prev.has(nx)) continue;
      prev.set(nx, cur); q.push(nx);
    }
  }
  const nameOf = (k) => (byKey.get(k) ? byKey.get(k).name : k === start[0] && rootName ? rootName : k);
  for (const [k, c] of byKey) {
    if (!prev.has(k)) continue;
    const chain = [];
    let at = k;
    while (at != null) { chain.unshift(nameOf(at)); at = prev.get(at); }
    c.path = chain;
    c.direct = chain.length === 2;
  }
}

// ---- npm package-lock.json ------------------------------------------------
function lockLicense(v) {
  if (!v) return "";
  if (typeof v === "string") return v;
  if (typeof v === "object" && v.type) return String(v.type);
  if (Array.isArray(v)) return v.map((x) => (typeof x === "string" ? x : x && x.type) || "").filter(Boolean).join(" OR ");
  return "";
}
function parseLock(j, text, file) {
  const deps = parsePackageLock(text) || [];
  const issues = [];
  const rootPkg = (j.packages && j.packages[""]) || {};
  const project = { name: j.name || rootPkg.name || "", version: j.version || rootPkg.version || "", license: lockLicense(rootPkg.license), ref: "" };
  const info = new Map(); // name@version -> { license, dev, path }
  let hasGraph = false;
  if (j.packages) {
    const P = j.packages;
    const nameAt = (p) => p.replace(/^.*node_modules\//, "");
    for (const [p, v] of Object.entries(P)) {
      if (!p || !v || !v.version) continue;
      const key = nameAt(p) + "@" + v.version;
      if (!info.has(key)) info.set(key, { license: lockLicense(v.license), dev: !!v.dev, path: null, lp: p });
    }
    // Resolve each declared dependency the way node does: nearest node_modules walking up.
    const resolve = (from, dep) => {
      let base = from;
      for (;;) {
        const cand = (base ? base + "/" : "") + "node_modules/" + dep;
        if (P[cand]) return cand;
        if (!base) return null;
        const i = base.lastIndexOf("/node_modules/");
        base = i >= 0 ? base.slice(0, i) : "";
      }
    };
    const depNames = (v, root) => Object.keys(Object.assign({}, v.dependencies || {}, v.optionalDependencies || {}, v.peerDependencies || {}, root ? v.devDependencies || {} : {})).sort();
    const prev = new Map([["", null]]);
    const q = [""];
    while (q.length) {
      const cur = q.shift();
      const v = P[cur] || {};
      for (const d of depNames(v, cur === "")) {
        const at = resolve(cur, d);
        if (!at || prev.has(at)) continue;
        prev.set(at, cur); q.push(at);
      }
    }
    hasGraph = prev.size > 1;
    for (const [p, v] of Object.entries(P)) {
      if (!p || !v || !v.version || !prev.has(p)) continue;
      const key = nameAt(p) + "@" + v.version;
      const rec = info.get(key);
      if (!rec || rec.path) continue;
      const chain = [];
      let at = p;
      while (at) { chain.unshift(nameAt(at)); at = prev.get(at); }
      chain.unshift(project.name || "(project)");
      rec.path = chain;
    }
  } else issues.push("lockfileVersion 1 does not record license fields or the root's declared dependencies; licenses and paths need an SBOM or a v2/v3 lockfile");
  const comps = deps.map((d) => {
    const rec = info.get(d.name + "@" + d.version) || {};
    return comp({ name: d.name, version: d.version, ecosystem: "npm", purl: npmPurl(d.name, d.version), declared: rec.license || "", licenseSource: rec.license ? "lockfile" : "none", dev: d.type === "development", direct: d.direct, path: rec.path || null, file });
  });
  return { components: comps, project, issues, version: "v" + (j.lockfileVersion || 1), hasGraph };
}
function npmPurl(name, version) {
  const n = String(name);
  return "pkg:npm/" + (n.startsWith("@") ? "%40" + n.slice(1).split("/").map(encodeURIComponent).join("/") : encodeURIComponent(n)) + "@" + encodeURIComponent(version);
}

// ---- pnpm-lock.yaml (v5.x, v6, v9) ---------------------------------------
function parsePnpm(text, file) {
  const lines = String(text).split(/\r?\n/);
  const ver = ((text.match(/^lockfileVersion:\s*'?([\d.]+)'?/m) || [])[1]) || "";
  const pkgs = new Map(); // key name@version -> { name, version, dev, deps: [name@version] }
  const direct = new Map(); // name -> { version, dev }
  let section = "", sub = "", cur = null, inDeps = false, importer = "", impSec = "", impDep = "";
  const keyOf = (raw) => {
    let k = raw.trim().replace(/^['"]|['"]:?$/g, "").replace(/:$/, "").replace(/^['"]|['"]$/g, "").replace(/^\//, "");
    k = k.replace(/\(.*$/, "").replace(/_[^/@]*$/, (m) => (/^_\d/.test(m) ? m : ""));
    if (/^\d/.test(ver) && parseFloat(ver) < 6 && !/@[^@/]+$/.test(k.replace(/^@/, ""))) {
      const i = k.lastIndexOf("/");
      return i > 0 ? { name: k.slice(0, i), version: k.slice(i + 1).replace(/_.*$/, "") } : null;
    }
    const at = k.lastIndexOf("@");
    return at > 0 ? { name: k.slice(0, at), version: k.slice(at + 1) } : null;
  };
  const cleanVer = (v) => String(v || "").trim().replace(/^['"]|['"]$/g, "").replace(/\(.*$/, "").replace(/_.*$/, "");
  for (const raw of lines) {
    if (!raw.trim() || /^\s*#/.test(raw)) continue;
    const ind = raw.match(/^ */)[0].length;
    const line = raw.trim();
    if (ind === 0) { section = line.replace(/:.*$/, ""); sub = ""; cur = null; importer = ""; continue; }
    if (section === "packages" || section === "snapshots") {
      if (ind === 2) { const k = keyOf(line); cur = k ? k.name + "@" + k.version : null; if (cur && !pkgs.has(cur)) pkgs.set(cur, { name: k.name, version: k.version, dev: false, deps: [] }); inDeps = false; continue; }
      if (!cur) continue;
      if (ind === 4) { inDeps = /^(dependencies|optionalDependencies):/.test(line); if (/^dev:\s*true/.test(line)) pkgs.get(cur).dev = true; continue; }
      if (ind === 6 && inDeps) { const m = line.match(/^['"]?([^'":]+(?:\/[^'":]+)?)['"]?:\s*['"]?([^'"\s]+)/); if (m) pkgs.get(cur).deps.push(m[1] + "@" + cleanVer(m[2])); }
      continue;
    }
    // root dependencies: v5/v6 top-level dependencies:, v9 importers: '.': dependencies:
    if (section === "dependencies" || section === "devDependencies" || section === "optionalDependencies") {
      if (ind === 2) { const m = line.match(/^['"]?([^'":]+(?:\/[^'":]+)?)['"]?:\s*(.*)$/); if (m) { sub = m[1]; if (m[2]) direct.set(sub, { version: cleanVer(m[2]), dev: section === "devDependencies" }); else direct.set(sub, { version: "", dev: section === "devDependencies" }); } }
      else if (ind === 4 && /^version:/.test(line) && sub) direct.get(sub).version = cleanVer(line.replace(/^version:\s*/, ""));
      continue;
    }
    if (section === "importers") {
      if (ind === 2) { importer = line.replace(/:$/, "").replace(/^['"]|['"]$/g, ""); continue; }
      if (importer !== ".") continue;
      if (ind === 4) { impSec = line.replace(/:.*$/, ""); continue; }
      if (ind === 6 && /ependencies$/.test(impSec)) { impDep = line.replace(/:.*$/, "").replace(/^['"]|['"]$/g, ""); direct.set(impDep, { version: "", dev: impSec === "devDependencies" }); continue; }
      if (ind === 8 && /^version:/.test(line) && impDep) direct.get(impDep).version = cleanVer(line.replace(/^version:\s*/, ""));
    }
  }
  const edges = new Map();
  edges.set("(root)", [...direct].map(([n, d]) => n + "@" + d.version));
  for (const [k, p] of pkgs) edges.set(k, p.deps);
  const comps = [...pkgs.values()].map((p) => comp({ name: p.name, version: p.version, ecosystem: "npm", purl: npmPurl(p.name, p.version), dev: p.dev || !!(direct.get(p.name) && direct.get(p.name).dev && direct.get(p.name).version === p.version), ref: p.name + "@" + p.version, file }));
  if (direct.size) applyGraph(comps, edges, ["(root)"], "(project)", (c) => c.ref);
  return { components: comps, project: null, issues: ["pnpm-lock.yaml does not record licenses; use Resolve or an SBOM"], version: ver, hasGraph: direct.size > 0 };
}

// ---- Cargo.lock ------------------------------------------------------------
function parseCargo(text, file) {
  const blocks = String(text).split(/\[\[package\]\]/).slice(1);
  const pkgs = [];
  for (const b of blocks) {
    const name = (b.match(/\n\s*name\s*=\s*"([^"]+)"/) || [])[1];
    const version = (b.match(/\n\s*version\s*=\s*"([^"]+)"/) || [])[1];
    if (!name || !version) continue;
    const source = (b.match(/\n\s*source\s*=\s*"([^"]+)"/) || [])[1] || "";
    const depBlock = (b.match(/\n\s*dependencies\s*=\s*\[([\s\S]*?)\]/) || [])[1] || "";
    const deps = [...depBlock.matchAll(/"([^"]+)"/g)].map((m) => m[1].split(" "));
    pkgs.push({ name, version, source, deps });
  }
  const byName = new Map();
  for (const p of pkgs) { if (!byName.has(p.name)) byName.set(p.name, []); byName.get(p.name).push(p); }
  const edges = new Map();
  for (const p of pkgs) {
    edges.set(p.name + "@" + p.version, p.deps.map(([n, v]) => { const cands = byName.get(n) || []; const hit = v ? cands.find((c) => c.version === v) : cands[0]; return hit ? hit.name + "@" + hit.version : n; }));
  }
  const roots = pkgs.filter((p) => !p.source);
  const comps = pkgs.filter((p) => p.source).map((p) => comp({ name: p.name, version: p.version, ecosystem: "cargo", purl: "pkg:cargo/" + p.name + "@" + p.version, ref: p.name + "@" + p.version, file, licenseSource: "none" }));
  const project = roots.length === 1 ? { name: roots[0].name, version: roots[0].version, license: "", ref: roots[0].name + "@" + roots[0].version } : null;
  if (roots.length) applyGraph(comps, edges, roots.map((r) => r.name + "@" + r.version), roots.length === 1 ? roots[0].name : "", (c) => c.ref);
  return { components: comps, project, issues: ["Cargo.lock does not record licenses; use Resolve (crates.io) or an SBOM"], version: (text.match(/^version\s*=\s*(\d+)/m) || [])[1] || "", hasGraph: roots.length > 0 };
}

// ---- Pipfile.lock / composer.lock ----------------------------------------
function parsePipfileLock(j, file) {
  const comps = [];
  for (const [sec, dev] of [["default", false], ["develop", true]]) {
    for (const [name, v] of Object.entries(j[sec] || {}).sort()) {
      const version = String((v && v.version) || "").replace(/^==/, "");
      if (!version) continue;
      comps.push(comp({ name: name.toLowerCase(), version, ecosystem: "pypi", purl: "pkg:pypi/" + name.toLowerCase() + "@" + version, dev, file }));
    }
  }
  return { components: comps, project: null, issues: ["Pipfile.lock does not record licenses; use Resolve (PyPI) or an SBOM"], version: String((j._meta && j._meta["pipfile-spec"]) || ""), hasGraph: false };
}
function parseComposerLock(j, file) {
  const comps = [];
  for (const [sec, dev] of [["packages", false], ["packages-dev", true]]) {
    for (const p of Array.isArray(j[sec]) ? j[sec] : []) {
      if (!p || !p.name) continue;
      const version = String(p.version || "").replace(/^v(?=\d)/, "");
      const lic = Array.isArray(p.license) ? p.license.filter(Boolean) : p.license ? [String(p.license)] : [];
      // composer.json: an array of licenses is a disjunction (the user may choose).
      const expr = lic.length > 1 ? lic.map((x) => (/\s/.test(x) ? "(" + x + ")" : x)).join(" OR ") : lic[0] || "";
      comps.push(comp({ name: p.name, version, ecosystem: "composer", purl: "pkg:composer/" + p.name + "@" + version, declared: expr, licenseSource: expr ? "lockfile" : "none", dev, file }));
    }
  }
  return { components: comps, project: null, issues: [], version: "", hasGraph: false };
}

// ---- simple lockfiles via supply-chain-engine parsers ---------------------
const ECO_PURL = { npm: "npm", pypi: "pypi", gem: "gem", go: "golang", maven: "maven", cargo: "cargo", composer: "composer" };
function fromDeps(deps, file, note) {
  const comps = (deps || []).filter((d) => d.version).map((d) => {
    const p = ECO_PURL[d.ecosystem] || d.ecosystem;
    const nm = d.ecosystem === "maven" ? d.name.replace(":", "/") : d.ecosystem === "npm" ? null : d.name;
    return comp({ name: d.name, version: d.version, ecosystem: d.ecosystem, purl: d.ecosystem === "npm" ? npmPurl(d.name, d.version) : "pkg:" + p + "/" + nm + "@" + d.version, dev: d.type === "development", direct: d.direct, file });
  });
  return { components: comps, project: null, issues: note ? [note] : [], version: "", hasGraph: false };
}

// ---- license reports / CSV inventories -----------------------------------
function parseLicenseChecker(j, file) {
  const comps = [];
  const issues = [];
  let guessed = 0;
  for (const [k, v] of Object.entries(j).sort()) {
    const at = k.lastIndexOf("@");
    const name = k.slice(0, at), version = k.slice(at + 1);
    let lic = Array.isArray(v.licenses) ? v.licenses.join(" OR ") : String(v.licenses || v.licence || "");
    if (/\*$/.test(lic)) { guessed++; lic = lic.replace(/\*$/, ""); }
    comps.push(comp({ name, version, ecosystem: "npm", purl: npmPurl(name, version), declared: lic, licenseSource: lic ? "report" : "none", copyright: v.copyright || "", file }));
  }
  if (guessed) issues.push(guessed + " license(s) marked with * were guessed by license-checker from README or LICENSE text");
  return { components: comps, project: null, issues, version: "", hasGraph: false };
}
function parseInventoryRows(rows, headers, mapping, file) {
  const issues = [];
  const m = mapping || {};
  const col = (key) => (m[key] && headers.includes(m[key]) ? m[key] : findColumn(headers, COLUMNS[key]));
  const cols = { name: col("name"), version: col("version"), license: col("license"), ecosystem: col("ecosystem"), purl: col("purl") };
  const comps = [];
  if (!cols.name && !cols.purl) return { components: [], project: null, issues: ["no package name or purl column"], version: "", hasGraph: false, cols, needsMapping: true };
  for (const r of rows) {
    const pu = cols.purl ? parsePurl(r[cols.purl]) : null;
    let name = String((cols.name && r[cols.name]) || (pu && pu.fullName) || "").trim();
    let version = String((cols.version && r[cols.version]) || (pu && pu.version) || "").trim();
    if (!version && /.@[^@/]+$/.test(name)) { const at = name.lastIndexOf("@"); version = name.slice(at + 1); name = name.slice(0, at); }
    if (!name) continue;
    let lic = String((cols.license && r[cols.license]) || "").trim();
    let guessed = false;
    if (/\*$/.test(lic)) { lic = lic.replace(/\*$/, ""); guessed = true; }
    const eco = String((cols.ecosystem && r[cols.ecosystem]) || (pu && pu.ecosystem) || "").trim().toLowerCase();
    comps.push(comp({ name, version, ecosystem: eco, purl: (cols.purl && r[cols.purl]) || "", declared: lic, licenseSource: lic ? "report" : "none", file, guessed }));
  }
  if (!cols.license) issues.push("no license column; every row is treated as missing license data");
  return { components: comps, project: null, issues, version: "", hasGraph: false, cols, needsMapping: !cols.license };
}

function parseOne(name, text, mapping) {
  const s = sniffFile(name, text);
  const t = String(text || "").replace(/^﻿/, "");
  const base = { name, format: s.format, label: FORMAT_LABEL[s.format] || s.format, confidence: s.confidence, components: [], project: null, issues: s.reason ? [s.reason] : [], headers: [], hasGraph: false };
  try {
    let r = null;
    switch (s.format) {
      case "cyclonedx-json": r = parseCycloneDxJson(s.json, name); break;
      case "cyclonedx-xml": r = parseCycloneDxXml(t, name); break;
      case "spdx-json": r = parseSpdxJson(s.json, name); break;
      case "spdx-tv": r = parseSpdxTv(t, name); break;
      case "package-lock": r = parseLock(s.json, t, name); break;
      case "npm-manifest": r = { components: [], project: { name: s.json.name || "", version: s.json.version || "", license: lockLicense(s.json.license) || lockLicense(s.json.licenses), ref: "" }, issues: ["package.json gives the project license and direct dependency ranges only; add the lockfile for the resolved tree"], version: "" }; break;
      case "yarn-lock": r = fromDeps(parseYarnLock(t), name, "yarn.lock does not record licenses or which packages are direct; use Resolve or an SBOM"); break;
      case "pnpm-lock": r = parsePnpm(t, name); break;
      case "requirements": r = fromDeps((parseRequirementsTxt(t) || []).filter((d) => d.exact), name, "requirements.txt does not record licenses; only == pinned lines are inventoried"); break;
      case "pipfile-lock": r = parsePipfileLock(s.json, name); break;
      case "poetry-lock": r = fromDeps(parsePoetryLock(t), name, "poetry.lock does not record licenses; use Resolve (PyPI) or an SBOM"); break;
      case "go-sum": r = fromDeps(parseGoSum(t), name, "go.sum does not record licenses; use Resolve (ClearlyDefined) or an SBOM"); break;
      case "go-mod": r = fromDeps(parseGoMod(t), name, "go.mod does not record licenses"); break;
      case "cargo-lock": r = parseCargo(t, name); break;
      case "gemfile-lock": r = fromDeps(parseGemfileLock(t), name, "Gemfile.lock does not record licenses; use Resolve (ClearlyDefined) or an SBOM"); break;
      case "composer-lock": r = parseComposerLock(s.json, name); break;
      case "pom": r = fromDeps(parsePomXml(t), name, "pom.xml declares direct dependencies only (property-managed versions are skipped); licenses need an SBOM or Resolve"); break;
      case "license-checker-json": r = parseLicenseChecker(s.json, name); break;
      case "license-json": { const headers = Object.keys(s.json[0] || {}); r = parseInventoryRows(s.json, headers, mapping, name); base.headers = headers; break; }
      case "license-csv": { const p = parseCsv(t); r = parseInventoryRows(p.rows, p.headers, mapping, name); base.headers = p.headers; break; }
      default: r = null;
    }
    if (r) {
      base.components = r.components; base.project = r.project; base.issues = base.issues.concat(r.issues || []);
      base.specVersion = r.version || ""; base.hasGraph = !!r.hasGraph; base.hasAck = !!r.hasAck; base.extracted = r.extracted || null;
      if (r.cols) base.columns = r.cols;
      if (r.needsMapping) base.confidence = "low";
      else if ((s.format === "license-csv" || s.format === "license-json") && mapping && Object.keys(mapping).length) base.confidence = "high";
    }
  } catch (e) {
    base.issues.push("could not parse: " + ((e && e.message) || e));
    base.confidence = "low";
  }
  return base;
}

/**
 * Parse one or more inputs. input: text | {name,text} | {name,text}[]. opts.mapping:
 * { [fileName]: { name, version, license, ecosystem, purl } } for CSV/JSON inventories.
 * Returns { format, headers, rows, skipped, files }. rows = components across files.
 */
export function parseInput(input, opts = {}) {
  const list = Array.isArray(input) ? input : input && typeof input === "object" && "text" in input ? [input] : [{ name: "input", text: String(input || "") }];
  const files = [];
  const skipped = [];
  for (const f of list) {
    if (!f) continue;
    const name = String(f.name || "input");
    const text = String(f.text == null ? "" : f.text);
    if (!text.trim()) { skipped.push({ check: "parse:" + name, reason: "empty file" }); continue; }
    const mapping = opts.mapping && (opts.mapping[name] || opts.mapping["*"]);
    const pf = parseOne(name, text, mapping);
    if (pf.format === "unknown") skipped.push({ check: "parse:" + name, reason: pf.issues[0] || "unrecognised format" });
    files.push(pf);
  }
  const rows = files.flatMap((f) => f.components);
  const headers = [...new Set(files.flatMap((f) => f.headers || []))];
  const format = files.length === 0 ? "empty" : files.length === 1 ? files[0].format : "multi";
  return { format, headers, rows, skipped, files };
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------
const C = {
  oc331: { framework: "OpenChain ISO/IEC 5230:2020", id: "3.3.1 Bill of materials" },
  oc332: { framework: "OpenChain ISO/IEC 5230:2020", id: "3.3.2 License compliance" },
  oc341: { framework: "OpenChain ISO/IEC 5230:2020", id: "3.4.1 Compliance artifacts" },
  spdxD: { framework: "SPDX 2.3", id: "Annex D license expressions" },
  spdx713: { framework: "SPDX 2.3", id: "7.13 Concluded license" },
  spdx715: { framework: "SPDX 2.3", id: "7.15 Declared license" },
  spdx10: { framework: "SPDX 2.3", id: "10 Other licensing information" },
  ssdfPw44: { framework: "NIST SP 800-218 (SSDF)", id: "PW.4.4" },
  ssdfPs32: { framework: "NIST SP 800-218 (SSDF)", id: "PS.3.2" },
  iso532: { framework: "ISO27001", id: "A.5.32" },
};

const CTX_SEV = {
  "network-copyleft": { saas: "high", binary: "high", mobile: "high", internal: "medium" },
  "strong-copyleft": { saas: "medium", binary: "high", mobile: "high", internal: "info" },
  "weak-copyleft": { saas: "info", binary: "low", mobile: "low", internal: null },
  proprietary: { saas: "high", binary: "high", mobile: "high", internal: "medium" },
};

function evRow(c, extra) {
  return Object.assign({
    package: c.name, version: c.version, ecosystem: c.ecosystem || "", license: c.expr || c.rawLicense || "", chosen: c.chosen || "",
    category: c.category, source: c.files.join("; "), path: c.path ? c.path.join(" > ") : "",
  }, extra || {});
}
const assetOf = (c) => ({ type: "ASSET", name: c.name + (c.version ? "@" + c.version : ""), data: { license: c.chosen || c.expr || "", category: c.category, ecosystem: c.ecosystem || "" } });
const keyOf = (c) => (c.ecosystem || "?") + ":" + c.name.toLowerCase() + "@" + c.version;
const resolvedKey = (c) => (c.ecosystem || "") + ":" + c.name + "@" + c.version;

/**
 * Analyze a parsed dataset (parseInput output, or raw input which is parsed first).
 * opts: DEFAULTS plus resolved: { "eco:name@version": { license, host, at } } from live lookups.
 */
export function analyze(dataset, opts = {}, ctx) {
  const o = { ...DEFAULTS, ...(opts || {}) };
  if (!CONTEXTS[o.context]) o.context = DEFAULTS.context;
  const ds = dataset && Array.isArray(dataset.files) && dataset.files.every((f) => f && Array.isArray(f.components)) ? dataset : parseInput(dataset || [], { mapping: o.mapping });
  const skipped = (ds.skipped || []).slice();
  const policy = compilePolicy(o);
  const maxEv = Math.max(1, Math.min(50, Number(o.maxEvidence) || 50));
  const resolved = o.resolved && typeof o.resolved === "object" ? o.resolved : {};

  // 1. merge components across files (ecosystem + name + version), SBOM data first
  const SRC_RANK = { sbom: 0, lockfile: 1, report: 2, resolved: 3, none: 4 };
  const merged = new Map();
  const conflicts = [];
  const files = ds.files || [];
  const total = files.reduce((a, f) => a + f.components.length, 0);
  let done = 0;
  for (const f of files) {
    for (const c of f.components) {
      if (++done % 1000 === 0) ctx?.progress?.(done, total, "merge");
      const k = keyOf(c);
      const cur = merged.get(k);
      if (!cur) { merged.set(k, { ...c, files: [f.name], formats: [f.format], path: c.path || null }); continue; }
      if (!cur.files.includes(f.name)) { cur.files.push(f.name); cur.formats.push(f.format); }
      const a = cur.concluded || cur.declared, b = c.concluded || c.declared;
      if (a && b && normalizeLicense(a).expr !== normalizeLicense(b).expr) conflicts.push({ k, a, b, fa: cur.files[0], fb: f.name });
      if (SRC_RANK[c.licenseSource] < SRC_RANK[cur.licenseSource]) { cur.declared = c.declared; cur.concluded = c.concluded; cur.licenseSource = c.licenseSource; }
      if (!cur.path && c.path) cur.path = c.path;
      if (cur.direct === undefined && c.direct !== undefined) cur.direct = c.direct;
      if (!cur.purl && c.purl) cur.purl = c.purl;
      if (!cur.copyright && c.copyright) cur.copyright = c.copyright;
      cur.dev = cur.dev && c.dev;
    }
  }
  const comps = [...merged.values()].sort((a, b) => (keyOf(a) < keyOf(b) ? -1 : keyOf(a) > keyOf(b) ? 1 : 0));

  // 2. project (outbound) license
  const projFile = files.find((f) => f.project && f.project.license) || files.find((f) => f.project && f.project.name);
  const project = { name: (projFile && projFile.project.name) || "", license: String(o.projectLicense || "").trim() || (projFile && projFile.project.license) || "", source: String(o.projectLicense || "").trim() ? "settings" : projFile && projFile.project.license ? projFile.name : "" };
  const extracted = Object.assign({}, ...files.map((f) => f.extracted || {}));

  // 3. per-component license evaluation
  const inventory = [];
  for (let i = 0; i < comps.length; i++) {
    if (i % 1000 === 0) ctx?.progress?.(i, comps.length, "licenses");
    const c = comps[i];
    let raw = c.concluded && c.concluded !== "NOASSERTION" ? c.concluded : c.declared || c.concluded;
    let source = c.licenseSource;
    if (c.concluded === "NOASSERTION" && c.declared && c.declared !== "NOASSERTION") raw = c.declared;
    const res = resolved[resolvedKey(c)] || resolved[keyOf(c)];
    if ((!raw || raw === "NOASSERTION") && res && res.license) { raw = res.license; source = "resolved"; c.resolvedHost = res.host || ""; c.resolvedAt = res.at || ""; }
    const norm = normalizeLicense(raw);
    c.rawLicense = raw || "";
    c.licenseSource = norm.status === "missing" ? "none" : source;
    c.status = norm.status; c.notes = norm.notes; c.expr = norm.expr;
    if (norm.ast && norm.ast.type !== "none" && norm.ast.type !== "noassertion") {
      const e = evaluate(norm.ast, policy);
      c.eval = e; c.chosen = exprToString(e.chosen.length > 1 ? { type: "and", args: e.chosen } : e.chosen[0]); c.category = e.category; c.policy = e.policy;
      c.alternatives = e.alternatives; c.policyRules = e.rules;
    } else {
      c.eval = null; c.chosen = ""; c.category = "unknown"; c.policy = "allow"; c.alternatives = []; c.policyRules = [];
      if (norm.ast && norm.ast.type === "none") c.status = "none";
      if (norm.ast && norm.ast.type === "noassertion") c.status = "noassertion";
    }
    if (c.declared && c.concluded && c.declared !== "NOASSERTION" && c.concluded !== "NOASSERTION") {
      const d = normalizeLicense(c.declared), k = normalizeLicense(c.concluded);
      c.mismatch = d.expr && k.expr && d.expr !== k.expr ? { declared: d.expr, concluded: k.expr } : null;
    }
    c.inScope = o.includeDev || !c.dev;
    inventory.push(c);
  }

  // 4. findings
  const groups = new Map();
  const add = (gk, base, c, extra) => {
    let g = groups.get(gk);
    if (!g) { g = { ...base, rows: [], assets: new Map() }; groups.set(gk, g); }
    g.rows.push(evRow(c, extra));
    if (c.name) g.assets.set(c.name + "@" + c.version, assetOf(c));
  };
  const ctxName = o.context;
  const ctxLabel = CONTEXTS[ctxName];
  const inScope = inventory.filter((c) => c.inScope);

  for (const c of inScope) {
    const leavesInfo = c.eval ? c.eval.infos : [];
    // policy
    if (c.policy === "deny") add("deny:" + c.policyRules.join(","), { rule: "LIC-POLICY-DENY", title: "License denied by policy: " + c.policyRules.join(", "), severity: "high", confidence: "confirmed", category: "policy",
      description: "These packages resolve to a license your policy denies (" + c.policyRules.join(", ") + "), and no OR alternative avoids it.",
      recommendation: "Replace the package, obtain a commercial license, or record an approved exception with legal sign-off.", controls: [C.oc332, C.ssdfPw44, C.iso532] }, c);
    else if (c.policy === "review") add("review:" + c.policyRules.join(","), { rule: "LIC-POLICY-REVIEW", title: "License needs review under policy: " + c.policyRules.join(", "), severity: "medium", confidence: "confirmed", category: "policy",
      description: "These packages resolve to a license your policy marks for review (" + c.policyRules.join(", ") + ").",
      recommendation: "Route each package through your open-source review process and record the decision with the inventory.", controls: [C.oc332, C.ssdfPw44] }, c);
    else if (c.policy === "unlisted" && c.eval) add("unlisted", { rule: "LIC-POLICY-UNLISTED", title: "License not on the allow list", severity: "low", confidence: "review", category: "policy",
      description: "Your policy has an allow list and these licenses are on none of the allow, review or deny lists.",
      recommendation: "Classify each license in the policy so future scans decide automatically.", controls: [C.oc332] }, c);

    // distribution context by category of the chosen licenses
    for (const info of dedupeInfos(leavesInfo)) {
      const sevMap = CTX_SEV[info.category];
      if (!sevMap) continue;
      let sev = sevMap[ctxName];
      if (info.category === "weak-copyleft" && info.lgpl && ctxName === "mobile" && !info.linkException) {
        add("lgpl-mobile:" + info.id, { rule: "LIC-LGPL-MOBILE", title: info.id + " in a mobile app: relinking obligation", severity: "medium", confidence: "likely", category: "obligation",
          description: "LGPL lets you ship the library with closed code only if users can replace or relink it (LGPL-2.1 section 6, LGPL-3.0 section 4(d)). App-store distribution, static linking and code signing usually make that impractical.",
          recommendation: "Link the library dynamically and document how to replace it, ship the object files needed to relink, or replace the package.", controls: [C.oc332, C.iso532] }, c, { obligation: "relink" });
        continue;
      }
      if (!sev) continue;
      if (info.fossException && sev === "high") sev = "medium";
      const text = contextText(info, ctxName);
      add("ctx:" + info.category + ":" + info.id + (info.exception ? "+" + info.exception : ""), { rule: "LIC-CTX-" + info.category.toUpperCase(), title: text.title, severity: sev, confidence: info.category === "proprietary" ? "review" : "likely", category: "obligation",
        description: text.description + (info.note ? " " + info.note : "") + (info.fossException ? " The " + info.exception + " permits combination with code under other FOSS licenses; confirm your product qualifies." : ""),
        recommendation: text.recommendation, controls: info.category === "proprietary" ? [C.oc332, C.iso532, C.ssdfPw44] : [C.oc332, C.iso532] }, c);
    }

    // missing / special license values
    if (c.status === "none") add("none", { rule: "LIC-NONE", title: "Package declares no license (NONE)", severity: ctxName === "internal" ? "medium" : "high", confidence: "confirmed", category: "coverage",
      description: "NONE means the author granted no license: copyright law reserves all rights, so you have no permission to copy, modify or distribute it.",
      recommendation: "Ask the author for a license, buy one, or remove the package.", controls: [C.spdx713, C.oc332, C.iso532] }, c);
    else if (c.status === "noassertion") add("noassert", { rule: "LIC-NOASSERTION", title: "No license asserted in the SBOM", severity: ctxName === "internal" ? "low" : "medium", confidence: "review", category: "coverage",
      description: "The SBOM says NOASSERTION (or gives no license) for these components, so their terms are unknown.",
      recommendation: "Resolve the license from the package source or registry, then record it as the concluded license.", controls: [C.oc331, C.spdx713, C.ssdfPs32] }, c);
    else if (c.status === "invalid") add("invalid", { rule: "LIC-INVALID-EXPR", title: "License value is not a valid SPDX expression", severity: "low", confidence: "review", category: "coverage",
      description: "The license string could not be parsed or matched to an SPDX id.", recommendation: "Correct the license in the SBOM or manifest to a valid SPDX expression.", controls: [C.spdxD, C.oc331] }, c, { problem: c.notes.join("; ") });
    else if (c.status === "missing") {
      const fromSbom = c.formats.some((f) => /cyclonedx|spdx/.test(f));
      if (fromSbom) add("noassert", { rule: "LIC-NOASSERTION", title: "No license asserted in the SBOM", severity: ctxName === "internal" ? "low" : "medium", confidence: "review", category: "coverage",
        description: "The SBOM says NOASSERTION (or gives no license) for these components, so their terms are unknown.",
        recommendation: "Resolve the license from the package source or registry, then record it as the concluded license.", controls: [C.oc331, C.spdx713, C.ssdfPs32] }, c);
      else add("nodata", { rule: "LIC-NO-DATA", title: "No license data in the input", severity: "low", confidence: "review", category: "coverage",
        description: "These inputs (for example yarn.lock, go.sum, Cargo.lock) do not carry license fields, so these packages could not be classified.",
        recommendation: "Use Resolve unknown licenses, or generate an SBOM with licenses (CycloneDX or SPDX) and load it with the lockfile.", controls: [C.oc331, C.ssdfPs32] }, c);
    }
    if (c.eval) {
      for (const info of c.eval.infos) {
        if (/^(DocumentRef-[^:]+:)?LicenseRef-/.test(info.id) && !LICENSES[info.id]) {
          const ex = extracted[info.id];
          add("ref:" + info.id, { rule: "LIC-CUSTOM-REF", title: "Custom license " + info.id + " needs manual review", severity: "medium", confidence: "review", category: "coverage",
            description: "A LicenseRef is a license outside the SPDX list" + (ex && ex.name ? " (" + ex.name + ")" : "") + ". Its terms are only in the text the SBOM carries" + (ex && ex.text ? "" : ", which this input does not include") + ".",
            recommendation: "Read the license text, classify it in your policy (allow, review or deny) and keep the text with your compliance artifacts.", controls: [C.spdx10, C.oc332] }, c, { licenseText: ex && ex.text ? ex.text.slice(0, 300) : "" });
        } else if (!info.known && !/LicenseRef-/.test(info.id)) {
          add("unk:" + info.id, { rule: "LIC-UNKNOWN-ID", title: "Unrecognised license id " + info.id, severity: "low", confidence: "review", category: "coverage",
            description: "This id is not on the SPDX license list as known to this tool, so its category could not be determined.",
            recommendation: "Check the id against spdx.org/licenses, correct the metadata, or classify it in your policy.", controls: [C.spdxD, C.oc332] }, c);
        }
      }
    }
    if (c.status === "normalized" && c.notes.length) add("nonspdx", { rule: "LIC-NON-SPDX", title: "Non-canonical license strings normalised", severity: "info", confidence: "confirmed", category: "hygiene",
      description: "These license values were deprecated SPDX ids, free-text names or classifiers and were read as the SPDX expression shown.",
      recommendation: "Record the canonical SPDX expression in your SBOM so other tools read it the same way.", controls: [C.spdxD] }, c, { raw: c.rawLicense, read: c.expr, note: c.notes.join("; ") });
    if (c.alternatives && c.alternatives.length && c.eval) add("dual", { rule: "LIC-OR-ELECTION", title: "Dual-licensed packages: license elected", severity: "info", confidence: "confirmed", category: "hygiene",
      description: "These packages offer a choice (OR). The most permissive option your policy allows was selected; the alternatives are listed.",
      recommendation: "Record the elected license in your attribution notices and SBOM concluded license.", controls: [C.spdxD, C.oc341] }, c, { elected: c.chosen, alternatives: c.alternatives.join(" | ") });
    if (c.mismatch) add("mismatch", { rule: "LIC-DECLARED-CONCLUDED", title: "Declared and concluded licenses differ", severity: "medium", confidence: "review", category: "coverage",
      description: "The package author's declared license differs from the license the SBOM producer concluded. The concluded license was used for this analysis.",
      recommendation: "Check the package source: a mismatch often means extra license files (bundled code) or a relicensed version.", controls: [C.spdx713, C.spdx715, C.oc332] }, c, { declared: c.mismatch.declared, concluded: c.mismatch.concluded });
    if (c.licenseSource === "resolved") add("resolved", { rule: "LIC-RESOLVED-LIVE", title: "License taken from a live registry lookup", severity: "info", confidence: "likely", category: "coverage",
      description: "These packages had no license in your input; the license shown came from a registry or ClearlyDefined lookup you ran, not from your SBOM.",
      recommendation: "Confirm the registry value against the package source and record it in your SBOM.", controls: [C.oc331, C.ssdfPs32] }, c, { resolvedFrom: c.resolvedHost, resolvedAt: c.resolvedAt });
  }
  for (const cf of conflicts) {
    const c = merged.get(cf.k);
    if (!c || !c.inScope) continue;
    add("conflict", { rule: "LIC-SOURCE-CONFLICT", title: "Inputs disagree on a package's license", severity: "medium", confidence: "review", category: "coverage",
      description: "Two of your inputs give different licenses for the same package version. The SBOM value was preferred.",
      recommendation: "Check which source is right and regenerate the other.", controls: [C.oc331, C.spdx713] }, c, { first: cf.a + " (" + cf.fa + ")", second: cf.b + " (" + cf.fb + ")" });
  }

  // transitive copyleft
  const withPaths = inScope.filter((c) => c.path && c.path.length);
  if (!withPaths.length) skipped.push({ check: "transitive_copyleft", reason: "no input records dependency paths (needs package-lock v2/v3, pnpm-lock, Cargo.lock, or an SBOM with a dependency graph)" });
  for (const c of withPaths) {
    if (c.path.length < 3) continue;
    const worst = c.category;
    if (worst !== "strong-copyleft" && worst !== "network-copyleft" && worst !== "weak-copyleft") continue;
    const strong = worst !== "weak-copyleft";
    add("trans:" + (strong ? "strong" : "weak"), { rule: "LIC-TRANSITIVE-COPYLEFT", title: (strong ? "Strong or network" : "Weak") + " copyleft pulled in transitively", severity: strong ? "medium" : "low", confidence: "likely", category: "obligation",
      description: "These copyleft packages are not declared by your project; a direct dependency brings them in. They are easy to miss in review.",
      recommendation: "Decide whether the direct dependency shown first in the path is worth the obligation; look for an alternative or an option that drops the transitive package.", controls: [C.oc331, C.oc332, C.ssdfPw44] }, c, { via: c.path[1] || "" });
  }

  // incompatibilities with the project license
  if (!project.license) skipped.push({ check: "project_incompatibility", reason: "no project license: none in the input (SBOM metadata component, package.json, package-lock root) and none set in the policy" });
  else {
    const pn = normalizeLicense(project.license);
    project.expr = pn.expr;
    const pe = pn.ast && pn.ast.type !== "none" && pn.ast.type !== "noassertion" ? evaluate(pn.ast, compilePolicy({})) : null;
    project.chosen = pe ? exprToString(pe.chosen.length > 1 ? { type: "and", args: pe.chosen } : pe.chosen[0]) : "";
    project.category = pe ? pe.category : "unknown";
    if (!pe) skipped.push({ check: "project_incompatibility", reason: "project license '" + project.license + "' is not a usable SPDX expression" });
    else if (ctxName !== "internal") {
      const hosts = pe.infos.filter((i) => i.gpl && !i.linkException && (i.category === "strong-copyleft" || i.category === "network-copyleft"));
      for (const c of inScope) {
        if (!c.eval) continue;
        for (const info of dedupeInfos(c.eval.infos)) {
          for (const h of hosts) {
            const bad = incompatibility(h, info);
            if (!bad) continue;
            add("proj:" + h.id + ":" + info.id, { rule: "LIC-INCOMPAT-PROJECT", title: info.id + " is incompatible with your project license " + h.id, severity: "high", confidence: info.category === "proprietary" ? "review" : "likely", category: "incompatibility",
              description: bad.reason + " Source: " + bad.source + ".", recommendation: "Replace the package, choose a different license option if one exists, or change the project's outbound license with legal advice.", controls: [C.oc332, C.iso532, C.ssdfPw44] }, c, { projectLicense: h.id });
          }
        }
      }
    }
  }

  // incompatible combinations among dependencies (distributed contexts)
  if (ctxName === "internal") skipped.push({ check: "dependency_incompatibility", reason: "internal-only use: license compatibility matters when the combined work is distributed or offered to users" });
  else {
    const byLeaf = new Map();
    for (const c of inScope) if (c.eval) for (const info of dedupeInfos(c.eval.infos)) { const k = info.id + (info.exception ? " WITH " + info.exception : ""); if (!byLeaf.has(k)) byLeaf.set(k, { info, comps: [] }); byLeaf.get(k).comps.push(c); }
    const keys = [...byLeaf.keys()].sort();
    const donePairs = new Set();
    for (const hk of keys) {
      const H = byLeaf.get(hk);
      if (!H.info.gpl || H.info.linkException) continue;
      if (H.info.category !== "strong-copyleft" && H.info.category !== "network-copyleft") continue;
      if (ctxName === "saas" && H.info.category !== "network-copyleft") continue;
      for (const ok of keys) {
        if (ok === hk) continue;
        const O = byLeaf.get(ok);
        const pk = [hk, ok].sort().join("\u0000");
        if (donePairs.has(pk)) continue;
        const bad = incompatibility(H.info, O.info);
        if (!bad) continue;
        donePairs.add(pk);
        const base = { rule: "LIC-INCOMPAT-PAIR", title: hk + " combined with " + ok, severity: "medium", confidence: "review", category: "incompatibility",
          description: bad.reason + " This only matters if the packages are combined into one distributed work (for example linked into one binary or bundle). Source: " + bad.source + ".",
          recommendation: "Check whether these packages end up in the same distributed artifact; if they do, replace one of them.", controls: [C.oc332, C.iso532] };
        for (const h of H.comps) add("pair:" + pk, base, h, { role: "copyleft side (" + hk + ")" });
        for (const x of O.comps) add("pair:" + pk, base, x, { role: "conflicting side (" + ok + ")" });
      }
    }
  }

  if (!files.some((f) => f.hasAck || /spdx/.test(f.format))) skipped.push({ check: "declared_vs_concluded", reason: "no SPDX document or CycloneDX 1.6 acknowledgement data in the input" });
  const devCount = inventory.filter((c) => !c.inScope).length;

  // 5. assemble findings
  const findings = [...groups.entries()].map(([gk, g]) => {
    const rows = g.rows.slice().sort((a, b) => (a.package < b.package ? -1 : a.package > b.package ? 1 : a.version < b.version ? -1 : a.version > b.version ? 1 : 0));
    const n = rows.length;
    const assets = [...g.assets.values()].sort((a, b) => (a.name < b.name ? -1 : 1)).slice(0, 50);
    return {
      id: "lic:" + g.rule + ":" + gk.replace(/[^A-Za-z0-9.+:-]+/g, "_"), ruleId: g.rule,
      title: g.title, severity: g.severity, confidence: g.confidence, category: g.category,
      description: g.description + " " + n + " package" + (n === 1 ? "" : "s") + " (" + ctxLabel + ").",
      recommendation: g.recommendation, controls: g.controls, evidence: rows.slice(0, maxEv), evidenceCount: n, assets,
      tags: ["license", g.category, ctxName],
    };
  }).sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || (a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

  // 6. tables
  const invRows = inventory.map((c) => ({
    package: c.name, version: c.version, ecosystem: c.ecosystem || "", purl: c.purl || "", license: c.expr || c.rawLicense || "", chosen: c.chosen || "",
    category: c.category, status: c.status, declared: c.declared || "", concluded: c.concluded || "", licenseSource: c.licenseSource, resolvedFrom: c.resolvedHost || "",
    policy: c.eval ? c.policy : "", direct: c.direct === undefined ? "" : c.direct ? "yes" : "no", dev: c.dev ? "yes" : "no", path: c.path ? c.path.join(" > ") : "",
    copyright: c.copyright || "", files: c.files.join("; "),
  }));
  const licMap = new Map();
  for (const c of inventory) {
    const ids = c.eval ? dedupeInfos(c.eval.infos).map((i) => ({ id: i.id + (i.exception ? " WITH " + i.exception : ""), info: i })) : [{ id: c.status === "none" ? "NONE" : c.status === "invalid" ? "(invalid)" : "NOASSERTION", info: { category: "unknown", osi: false } }];
    for (const { id, info } of ids) {
      if (!licMap.has(id)) licMap.set(id, { license: id, category: info.category, osi: info.osi ? "yes" : "no", packages: 0, inScope: 0, names: [] });
      const r = licMap.get(id); r.packages++; if (c.inScope) r.inScope++; if (r.names.length < 200) r.names.push(c.name + (c.version ? "@" + c.version : ""));
    }
  }
  const licenses = [...licMap.values()].sort((a, b) => CAT_RANK[b.category] - CAT_RANK[a.category] || b.packages - a.packages || (a.license < b.license ? -1 : 1));
  const unresolved = inventory.filter((c) => (c.status === "missing" || c.status === "noassertion") && c.name && c.version && c.ecosystem)
    .map((c) => ({ key: resolvedKey(c), ecosystem: c.ecosystem, name: c.name, version: c.version, purl: c.purl || "" }));
  const fileRows = files.map((f) => ({ name: f.name, format: f.format, label: f.label, confidence: f.confidence, components: f.components.length, specVersion: f.specVersion || "", project: f.project ? (f.project.name || "") + (f.project.license ? " (" + f.project.license + ")" : "") : "", hasGraph: !!f.hasGraph, issues: f.issues.slice(), headers: f.headers || [], columns: f.columns || null }));

  const byCategory = {};
  for (const k of CATEGORIES) byCategory[k] = 0;
  for (const c of inventory) byCategory[c.category] = (byCategory[c.category] || 0) + 1;
  const bySeverity = {};
  for (const s of SEVERITIES) bySeverity[s] = 0;
  for (const f of findings) bySeverity[f.severity]++;
  ctx?.progress?.(comps.length, comps.length, "done");
  const summary = {
    files: files.length, components: inventory.length, inScope: inScope.length, devExcluded: devCount, licenses: licenses.length,
    byCategory, copyleft: byCategory["weak-copyleft"] + byCategory["strong-copyleft"] + byCategory["network-copyleft"],
    unknown: inventory.filter((c) => c.status === "missing" || c.status === "noassertion" || c.status === "invalid").length,
    policyHits: inScope.filter((c) => c.policy === "deny" || c.policy === "review").length,
    resolvedLive: inventory.filter((c) => c.licenseSource === "resolved").length,
    findings: findings.length, bySeverity, context: ctxName, contextLabel: ctxLabel,
    project: { name: project.name, license: project.license, source: project.source, chosen: project.chosen || "", category: project.category || "" },
  };
  return {
    summary, findings, skipped,
    tables: { inventory: invRows, licenses, files: fileRows, unresolved, extracted },
    meta: { tool: TOOL_ID, version: VERSION, rows: inventory.length, context: ctxName, policy: { allow: policy.allow.map((x) => x.label), review: policy.review.map((x) => x.label), deny: policy.deny.map((x) => x.label) }, includeDev: !!o.includeDev },
  };
}

function dedupeInfos(infos) {
  const seen = new Set(); const out = [];
  for (const i of infos || []) { const k = i.id + "|" + (i.exception || ""); if (seen.has(k)) continue; seen.add(k); out.push(i); }
  return out;
}

function contextText(info, ctx) {
  const id = info.id + (info.exception ? " WITH " + info.exception : "");
  if (info.category === "network-copyleft") {
    return {
      title: id + ": network copyleft" + (ctx === "saas" ? " applies even to SaaS" : ctx === "internal" ? " in internal use" : " in distributed software"),
      description: ctx === "internal"
        ? "Network copyleft is triggered by users interacting with modified software over a network; employees using an internal service can count as users (AGPL-3.0 section 13)."
        : "Network copyleft licenses require offering the complete corresponding source to everyone who interacts with a modified version over a network (AGPL-3.0 section 13), in addition to normal distribution obligations.",
      recommendation: "Keep the package unmodified and isolated as a separate program, publish your modifications, or replace it / buy a commercial license.",
    };
  }
  if (info.category === "strong-copyleft") {
    return {
      title: id + ": strong copyleft " + (ctx === "saas" ? "in a SaaS product" : ctx === "internal" ? "in internal use" : "in distributed software"),
      description: ctx === "saas"
        ? "GPL obligations are triggered by distribution; running software on your servers is not distribution, but any part shipped to users (client-side JavaScript bundles, desktop agents, containers given to customers) is."
        : ctx === "internal" ? "Internal use without distribution does not trigger GPL source obligations; transferring the software to another legal entity does."
        : "Distributing a work that includes GPL code requires licensing the combined work under the GPL and providing complete corresponding source.",
      recommendation: ctx === "saas" ? "Confirm the package never ships to users (check frontend bundles and customer-installed components)." : ctx === "internal" ? "Record that the package must not be distributed outside the organisation." : "Remove or replace the package, isolate it as a separate program, or license your product under compatible terms.",
    };
  }
  if (info.category === "weak-copyleft") {
    return {
      title: id + ": weak copyleft obligations",
      description: "Weak copyleft (" + id + ") requires sharing source for changes to the licensed files or library itself and keeping its notices; your own code linked to it stays under your terms" + (info.linkException ? " (a linking exception applies)" : "") + ".",
      recommendation: "Do not modify the files, or publish your modifications to them; keep the license text and notices with the distribution.",
    };
  }
  return {
    title: id + ": proprietary or restricted terms",
    description: "This license is not an open-source license" + (info.osi ? "" : " (not OSI-approved)") + " and may restrict commercial use, hosting or redistribution.",
    recommendation: "Have legal review the terms for your use case, or confirm you hold a commercial license.",
  };
}

// ---------------------------------------------------------------------------
// Live resolution helpers (pure). The UI fetches; these build URLs and read responses.
// ---------------------------------------------------------------------------
const CD_TYPE = { npm: ["npm", "npmjs"], pypi: ["pypi", "pypi"], cargo: ["crate", "cratesio"], gem: ["gem", "rubygems"], go: ["go", "golang"], maven: ["maven", "mavencentral"], composer: ["composer", "packagist"], nuget: ["nuget", "nuget"] };

/** Lookup plan for unresolved packages: [{ key, name, version, ecosystem, urls: [{ host, kind, url }] }]. */
export function resolutionPlan(unresolved, { limit = 200 } = {}) {
  const out = [];
  for (const u of (unresolved || []).slice(0, limit)) {
    const urls = [];
    const n = u.name, v = u.version;
    if (u.ecosystem === "npm") urls.push({ host: "registry.npmjs.org", kind: "npm", url: "https://registry.npmjs.org/" + (n.startsWith("@") ? "@" + encodeURIComponent(n.slice(1)) : encodeURIComponent(n)) + "/" + encodeURIComponent(v) });
    if (u.ecosystem === "pypi") urls.push({ host: "pypi.org", kind: "pypi", url: "https://pypi.org/pypi/" + encodeURIComponent(n) + "/" + encodeURIComponent(v) + "/json" });
    if (u.ecosystem === "cargo") urls.push({ host: "crates.io", kind: "crates", url: "https://crates.io/api/v1/crates/" + encodeURIComponent(n) + "/" + encodeURIComponent(v) });
    const cd = CD_TYPE[u.ecosystem];
    if (cd) {
      let ns = "-", nm = n;
      if (u.ecosystem === "npm" && n.startsWith("@")) { [ns, nm] = n.split("/"); }
      else if (u.ecosystem === "maven") { [ns, nm] = n.split(":"); }
      else if (u.ecosystem === "composer") { [ns, nm] = n.split("/"); }
      else if (u.ecosystem === "go") { const i = n.lastIndexOf("/"); ns = i > 0 ? n.slice(0, i) : "-"; nm = i > 0 ? n.slice(i + 1) : n; }
      const ver = u.ecosystem === "go" ? "v" + v.replace(/^v/, "") : v;
      if (ns && nm) urls.push({ host: "api.clearlydefined.io", kind: "clearlydefined", url: "https://api.clearlydefined.io/definitions/" + cd[0] + "/" + cd[1] + "/" + encodeURIComponent(ns) + "/" + encodeURIComponent(nm) + "/" + encodeURIComponent(ver) });
    }
    if (urls.length) out.push({ key: u.key, name: n, version: v, ecosystem: u.ecosystem, urls });
  }
  return out;
}

/** Extract a license string from a registry response. Returns { license, detail } or null. */
export function extractResolvedLicense(kind, json) {
  if (!json || typeof json !== "object") return null;
  if (kind === "npm") {
    const l = json.license;
    if (typeof l === "string" && l) return { license: l, detail: "package.json license" };
    if (l && typeof l === "object" && l.type) return { license: String(l.type), detail: "package.json license object" };
    if (Array.isArray(json.licenses) && json.licenses.length) return { license: json.licenses.map((x) => (typeof x === "string" ? x : x && x.type) || "").filter(Boolean).join(" OR "), detail: "legacy licenses array" };
    return null;
  }
  if (kind === "pypi") {
    const info = json.info || {};
    if (info.license_expression) return { license: String(info.license_expression), detail: "license_expression (PEP 639)" };
    const lic = String(info.license || "").trim();
    if (lic && lic.length <= 80 && !/\n/.test(lic) && normalizeLicense(lic).status !== "invalid") return { license: lic, detail: "license field" };
    const cls = (info.classifiers || []).filter((c) => /^License ::/.test(c) && !/^License :: OSI Approved$/.test(c.trim()));
    if (cls.length) {
      const mapped = cls.map((c) => normalizeLicense(c)).filter((n) => n.expr);
      if (mapped.length) return { license: [...new Set(mapped.map((n) => n.expr))].map((e) => (/ (AND|OR) /.test(e) ? "(" + e + ")" : e)).join(" OR "), detail: "trove classifiers (" + cls.length + ")" };
    }
    if (lic) return { license: lic.split(/\n/)[0].slice(0, 120), detail: "license field (free text, first line)" };
    return null;
  }
  if (kind === "crates") {
    const v = json.version || {};
    return v.license ? { license: String(v.license), detail: "crate version license" } : null;
  }
  if (kind === "clearlydefined") {
    const d = json.licensed && json.licensed.declared;
    return d && d !== "NOASSERTION" ? { license: String(d), detail: "ClearlyDefined licensed.declared" } : null;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------
const csvCell = (v) => { const s = String(v == null ? "" : v); const guard = /^[=+\-@\t]/.test(s) ? "'" : ""; return /[",\n\r]/.test(s) || guard ? '"' + guard + s.replace(/"/g, '""') + '"' : s; };
const FINDING_COLS = ["severity", "confidence", "rule", "category", "title", "description", "recommendation", "controls", "evidenceCount", "packages"];

/** Findings as CSV with fixed columns. */
export function findingsToCsv(findings) {
  const body = (findings || []).map((f) => [f.severity, f.confidence, f.ruleId || "", f.category, f.title, f.description, f.recommendation,
    (f.controls || []).map((c) => c.framework + " " + c.id).join("; "), f.evidenceCount != null ? f.evidenceCount : (f.evidence || []).length,
    (f.evidence || []).map((e) => e.package + (e.version ? "@" + e.version : "")).join(" ")].map(csvCell).join(","));
  return [FINDING_COLS.join(","), ...body].join("\n") + "\n";
}

const INV_COLS = ["package", "version", "ecosystem", "purl", "license", "chosen", "category", "status", "declared", "concluded", "licenseSource", "resolvedFrom", "policy", "direct", "dev", "path", "copyright", "files"];
/** License inventory as CSV. */
export function inventoryToCsv(result) {
  const rows = (result && result.tables && result.tables.inventory) || [];
  return [INV_COLS.join(","), ...rows.map((r) => INV_COLS.map((k) => csvCell(r[k])).join(","))].join("\n") + "\n";
}

/** Plain-text summary. */
export function toTxt(result) {
  const s = result.summary;
  const lines = [
    "License Compliance summary", "Context: " + s.contextLabel,
    "Project: " + (s.project.name || "(unnamed)") + " - license " + (s.project.license || "not set") + (s.project.source ? " (from " + s.project.source + ")" : ""),
    "Files: " + s.files + "  Packages: " + s.components + " (" + s.inScope + " in scope, " + s.devExcluded + " development-only excluded)",
    "Licenses: " + s.licenses + "  Copyleft packages: " + s.copyleft + "  Unknown: " + s.unknown + "  Policy hits: " + s.policyHits + "  Resolved live: " + s.resolvedLive,
    "By category: " + CATEGORIES.map((k) => CATEGORY_LABEL[k] + " " + s.byCategory[k]).join(", "),
    "Findings: " + s.findings + " (" + SEVERITIES.map((k) => k + " " + s.bySeverity[k]).join(", ") + ")", "",
  ];
  for (const f of result.findings) lines.push("[" + f.severity.toUpperCase() + "] " + f.title + " (" + f.evidenceCount + ")", "  " + f.recommendation, "  " + f.controls.map((c) => c.framework + " " + c.id).join("; "));
  if (result.skipped.length) { lines.push("", "Not evaluated:"); for (const k of result.skipped) lines.push("- " + k.check + ": " + k.reason); }
  return lines.join("\n") + "\n";
}

/** Third-party attribution notice grouped by license (in-scope packages). */
export function toNotice(result, { productName } = {}) {
  const inv = (result && result.tables && result.tables.inventory) || [];
  const scoped = inv.filter((r) => result.meta.includeDev || r.dev !== "yes");
  const groups = new Map();
  for (const r of scoped) {
    const k = r.chosen || r.license || "NOASSERTION";
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(r);
  }
  const name = productName || result.summary.project.name || "this product";
  const out = [
    "THIRD-PARTY SOFTWARE NOTICES", "", name + " includes the third-party packages listed below, grouped by the license under which each is used.",
    "Where a package offered a choice of licenses, the elected license is shown. The full text of each license is published at the SPDX URL given",
    "and must accompany any distribution together with the copyright notices shipped inside each package.", "",
  ];
  for (const k of [...groups.keys()].sort()) {
    const rows = groups.get(k).sort((a, b) => (a.package < b.package ? -1 : a.package > b.package ? 1 : 0));
    out.push("=".repeat(72), k + "  (" + rows.length + " package" + (rows.length === 1 ? "" : "s") + ")");
    const ids = leaves((parseExpression(k).ast) || null).map((l) => l.id).filter((id) => !/LicenseRef-|NOASSERTION|NONE/.test(id));
    for (const id of [...new Set(ids)]) out.push("License text: https://spdx.org/licenses/" + id + ".html");
    if (/LicenseRef-/.test(k)) out.push("License text: custom license; include the text supplied with the package.");
    if (k === "NOASSERTION" || k === "NONE" || !k) out.push("License not determined; resolve before distribution.");
    out.push("-".repeat(72));
    for (const r of rows) out.push("  " + r.package + (r.version ? " " + r.version : "") + (r.copyright ? "  -  " + r.copyright : ""));
    out.push("");
  }
  return out.join("\n");
}

function spdxIdSafe(s) { return String(s).replace(/[^A-Za-z0-9.-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80) || "pkg"; }
function hash32(s) { let h = 0x811c9dc5; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193); } return (h >>> 0).toString(16).padStart(8, "0"); }

/** SPDX 2.3 JSON document of the inventory (resolved licenses go in licenseDeclared, concluded stays as given). */
export function toSpdx(result, { now, name } = {}) {
  const inv = (result && result.tables && result.tables.inventory) || [];
  const created = String(now || "1970-01-01T00:00:00Z").replace(/\.\d+Z$/, "Z");
  const docName = name || (result.summary.project.name ? result.summary.project.name + "-license-inventory" : "license-inventory");
  const used = new Map();
  const ids = new Set();
  const usableExpr = (e) => {
    if (!e) return "NOASSERTION";
    const p = parseExpression(e);
    if (!p.ok || leaves(p.ast).some((l) => l.unknown)) return "NOASSERTION";
    for (const l of leaves(p.ast)) if (/LicenseRef-/.test(l.id)) used.set(l.id, true);
    return exprToString(p.ast);
  };
  const packages = inv.map((r, i) => {
    let id = "SPDXRef-Package-" + spdxIdSafe(r.package + "-" + r.version);
    if (ids.has(id)) id += "-" + (i + 1);
    ids.add(id);
    const decl = usableExpr(r.declared && r.declared !== "NOASSERTION" ? normalizeLicense(r.declared).expr : /^(resolved|report|lockfile)$/.test(r.licenseSource) ? r.license : r.declared);
    const conc = r.concluded ? usableExpr(normalizeLicense(r.concluded).expr || r.concluded) : "NOASSERTION";
    const p = { SPDXID: id, name: r.package, versionInfo: r.version || undefined, downloadLocation: "NOASSERTION", filesAnalyzed: false, licenseConcluded: conc, licenseDeclared: decl, copyrightText: r.copyright || "NOASSERTION" };
    if (r.licenseSource === "resolved") p.comment = "licenseDeclared resolved from " + (r.resolvedFrom || "a registry") + "; not stated in the source SBOM or lockfile.";
    if (r.purl) p.externalRefs = [{ referenceCategory: "PACKAGE-MANAGER", referenceType: "purl", referenceLocator: r.purl }];
    return p;
  });
  const extracted = (result.tables && result.tables.extracted) || {};
  const doc = {
    spdxVersion: "SPDX-2.3", dataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", name: docName,
    documentNamespace: "https://darknode.ai/spdx/licenseaudit/" + spdxIdSafe(docName) + "-" + hash32(JSON.stringify(inv)),
    creationInfo: { created, creators: ["Tool: darknode-licenseaudit-" + VERSION] },
    packages,
    relationships: packages.map((p) => ({ spdxElementId: "SPDXRef-DOCUMENT", relationshipType: "DESCRIBES", relatedSpdxElement: p.SPDXID })),
  };
  if (used.size) doc.hasExtractedLicensingInfos = [...used.keys()].sort().map((id) => ({ licenseId: id, extractedText: (extracted[id] && extracted[id].text) || "License text not present in the analysed input; see the package for its terms.", name: (extracted[id] && extracted[id].name) || id.replace(/^LicenseRef-/, "") }));
  return JSON.parse(JSON.stringify(doc));
}

// ---------------------------------------------------------------------------
// Synthetic example: a fictional ledger app. Package names and licenses are
// the real ones for those versions; the app, its vendored components and their
// licenses are invented.
// ---------------------------------------------------------------------------
export function exampleDataset() {
  const cdx = {
    bomFormat: "CycloneDX", specVersion: "1.6", serialNumber: "urn:uuid:3f1c2a8e-5b7d-4e2a-9c41-7a0d2e6b9f13", version: 1,
    metadata: {
      timestamp: "2026-10-01T09:00:00Z",
      tools: { components: [{ type: "application", name: "cyclonedx-maven-plugin", version: "2.8.1" }] },
      component: { type: "application", "bom-ref": "pdf-service", name: "pdf-service", version: "3.2.0", licenses: [{ license: { id: "LicenseRef-TestOrg-Proprietary" } }] },
    },
    components: [
      { type: "library", "bom-ref": "pkg:maven/com.itextpdf/kernel@8.0.4", group: "com.itextpdf", name: "kernel", version: "8.0.4", purl: "pkg:maven/com.itextpdf/kernel@8.0.4", licenses: [{ license: { id: "AGPL-3.0-only" } }] },
      { type: "library", "bom-ref": "pkg:maven/com.itextpdf/io@8.0.4", group: "com.itextpdf", name: "io", version: "8.0.4", purl: "pkg:maven/com.itextpdf/io@8.0.4", licenses: [{ license: { id: "AGPL-3.0-only" } }] },
      { type: "library", "bom-ref": "pkg:maven/com.mysql/mysql-connector-j@8.4.0", group: "com.mysql", name: "mysql-connector-j", version: "8.4.0", purl: "pkg:maven/com.mysql/mysql-connector-j@8.4.0", licenses: [{ expression: "GPL-2.0-only WITH Universal-FOSS-exception-1.0" }] },
      { type: "library", "bom-ref": "pkg:maven/org.apache.commons/commons-lang3@3.14.0", group: "org.apache.commons", name: "commons-lang3", version: "3.14.0", purl: "pkg:maven/org.apache.commons/commons-lang3@3.14.0", licenses: [{ license: { id: "Apache-2.0" } }] },
      { type: "library", "bom-ref": "pkg:maven/org.slf4j/slf4j-api@2.0.13", group: "org.slf4j", name: "slf4j-api", version: "2.0.13", purl: "pkg:maven/org.slf4j/slf4j-api@2.0.13", licenses: [{ license: { id: "MIT" } }] },
      { type: "library", "bom-ref": "pkg:maven/ch.qos.logback/logback-classic@1.5.6", group: "ch.qos.logback", name: "logback-classic", version: "1.5.6", purl: "pkg:maven/ch.qos.logback/logback-classic@1.5.6", licenses: [{ expression: "EPL-1.0 OR LGPL-2.1-only" }] },
      { type: "library", "bom-ref": "pkg:maven/com.testorg.vendor/chartsuite-pro@5.1.0", group: "com.testorg.vendor", name: "chartsuite-pro", version: "5.1.0", purl: "pkg:maven/com.testorg.vendor/chartsuite-pro@5.1.0", licenses: [{ license: { id: "LicenseRef-Chartsuite-EULA" } }] },
      { type: "library", "bom-ref": "pkg:maven/com.testorg.vendor/ledger-fx-rates@0.9.2", group: "com.testorg.vendor", name: "ledger-fx-rates", version: "0.9.2", purl: "pkg:maven/com.testorg.vendor/ledger-fx-rates@0.9.2" },
      { type: "library", "bom-ref": "pkg:maven/com.testorg.vendor/fiscal-calendar@2.3.1", group: "com.testorg.vendor", name: "fiscal-calendar", version: "2.3.1", purl: "pkg:maven/com.testorg.vendor/fiscal-calendar@2.3.1",
        licenses: [{ license: { id: "MIT", acknowledgement: "declared" } }, { expression: "MIT AND GPL-3.0-or-later", acknowledgement: "concluded" }] },
    ],
    dependencies: [
      { ref: "pdf-service", dependsOn: ["pkg:maven/com.itextpdf/kernel@8.0.4", "pkg:maven/com.mysql/mysql-connector-j@8.4.0", "pkg:maven/org.apache.commons/commons-lang3@3.14.0", "pkg:maven/ch.qos.logback/logback-classic@1.5.6", "pkg:maven/com.testorg.vendor/chartsuite-pro@5.1.0", "pkg:maven/com.testorg.vendor/ledger-fx-rates@0.9.2", "pkg:maven/com.testorg.vendor/fiscal-calendar@2.3.1"] },
      { ref: "pkg:maven/com.itextpdf/kernel@8.0.4", dependsOn: ["pkg:maven/com.itextpdf/io@8.0.4", "pkg:maven/org.slf4j/slf4j-api@2.0.13"] },
      { ref: "pkg:maven/ch.qos.logback/logback-classic@1.5.6", dependsOn: ["pkg:maven/org.slf4j/slf4j-api@2.0.13"] },
    ],
  };
  const P = (version, license, extra) => Object.assign({ version, resolved: "https://registry.npmjs.org/-/x-" + version + ".tgz", integrity: "sha512-synthetic" }, license ? { license } : {}, extra || {});
  const lock = {
    name: "testorg-ledger", version: "4.7.0", lockfileVersion: 3, requires: true,
    packages: {
      "": { name: "testorg-ledger", version: "4.7.0", license: "UNLICENSED", dependencies: { express: "^4.19.2", jszip: "^3.10.1", "node-forge": "^1.3.1", sharp: "^0.33.4", "ledger-csv-utils": "^0.3.1" }, devDependencies: { typescript: "^5.4.5" } },
      "node_modules/express": P("4.19.2", "MIT", { dependencies: { "body-parser": "1.20.2", "mime-types": "~2.1.34" } }),
      "node_modules/body-parser": P("1.20.2", "MIT"),
      "node_modules/mime-types": P("2.1.35", "MIT", { dependencies: { "mime-db": "1.52.0" } }),
      "node_modules/mime-db": P("1.52.0", "MIT"),
      "node_modules/jszip": P("3.10.1", "(MIT OR GPL-3.0-or-later)", { dependencies: { lie: "~3.3.0", pako: "~1.0.2", "readable-stream": "~2.3.6", setimmediate: "^1.0.5" } }),
      "node_modules/lie": P("3.3.0", "MIT", { dependencies: { immediate: "~3.0.5" } }),
      "node_modules/immediate": P("3.0.6", "MIT"),
      "node_modules/pako": P("1.0.11", "(MIT AND Zlib)"),
      "node_modules/readable-stream": P("2.3.8", "MIT"),
      "node_modules/setimmediate": P("1.0.5", "MIT"),
      "node_modules/node-forge": P("1.3.1", "(BSD-3-Clause OR GPL-2.0)"),
      "node_modules/sharp": P("0.33.4", "Apache-2.0", { optionalDependencies: { "@img/sharp-linux-x64": "0.33.4" } }),
      "node_modules/@img/sharp-linux-x64": P("0.33.4", "Apache-2.0", { optional: true, optionalDependencies: { "@img/sharp-libvips-linux-x64": "1.0.2" } }),
      "node_modules/@img/sharp-libvips-linux-x64": P("1.0.2", "LGPL-3.0-or-later", { optional: true }),
      "node_modules/ledger-csv-utils": P("0.3.1", null),
      "node_modules/typescript": P("5.4.5", "Apache-2.0", { dev: true }),
    },
  };
  return {
    label: "synthetic example: ledger app (fictional, not real data)",
    files: [
      { name: "pdf-service.cdx.json", text: JSON.stringify(cdx, null, 2) },
      { name: "package-lock.json", text: JSON.stringify(lock, null, 2) },
    ],
  };
}

/** Deterministic engine self-test. */
export function selfTest() {
  const tests = [];
  const t = (name, fn) => { let pass = false; try { pass = !!fn(); } catch (_) { pass = false; } tests.push({ name, pass }); };
  t("OR picks the permissive option", () => evaluate(parseExpression("MIT OR GPL-3.0-or-later").ast, {}).chosen[0].id === "MIT");
  t("WITH binds tighter than AND", () => { const a = parseExpression("GPL-2.0-only WITH Classpath-exception-2.0 AND MIT").ast; return a.type === "and" && a.args[0].exception === "Classpath-exception-2.0"; });
  t("deprecated GPL-2.0+ reads as GPL-2.0-or-later", () => parseExpression("GPL-2.0+").ast.id === "GPL-2.0-or-later");
  t("Apache-2.0 into GPL-2.0-only is incompatible", () => !!incompatibility(classifyLeaf({ id: "GPL-2.0-only" }), classifyLeaf({ id: "Apache-2.0" })));
  t("Apache-2.0 into GPL-3.0-or-later is compatible", () => !incompatibility(classifyLeaf({ id: "GPL-3.0-or-later" }), classifyLeaf({ id: "Apache-2.0" })));
  const ex = exampleDataset();
  const r = analyze(parseInput(ex.files), { context: "saas" });
  t("example flags AGPL in SaaS", () => r.findings.some((f) => f.ruleId === "LIC-CTX-NETWORK-COPYLEFT" && f.severity === "high"));
  t("example is deterministic", () => JSON.stringify(r) === JSON.stringify(analyze(parseInput(ex.files), { context: "saas" })));
  t("empty input yields no findings", () => analyze(parseInput("")).findings.length === 0);
  return { pass: tests.every((x) => x.pass), tests };
}
