// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Generator mini-tools. See _schema.md for the contract.
// Pure client-side. No fetch/network/DOM/imports. run(v, H) may be sync or async.

// ---- local helpers (self-contained; no imports) ----
function randInt(min, max) { // inclusive, uniform via crypto
  const range = max - min + 1;
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return min + (buf[0] % range);
}
function pick(arr) { return arr[randInt(0, arr.length - 1)]; }

const B32C = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function b32FromBytes(u8) {
  let bits = 0, val = 0, out = "";
  for (let i = 0; i < u8.length; i++) {
    val = (val << 8) | u8[i];
    bits += 8;
    while (bits >= 5) { out += B32C[(val >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32C[(val << (5 - bits)) & 31];
  return out;
}
function b64FromBytes(u8) {
  let bin = "";
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  return btoa(bin);
}
function hslToHex(h, s, l) {
  s /= 100; l /= 100;
  const k = (n) => (n + h / 30) % 12;
  const a = s * Math.min(l, 1 - l);
  const f = (n) => l - a * Math.max(-1, Math.min(k(n) - 3, Math.min(9 - k(n), 1)));
  const toHex = (x) => Math.round(255 * x).toString(16).padStart(2, "0");
  return `#${toHex(f(0))}${toHex(f(8))}${toHex(f(4))}`;
}
function compressIPv6(groups) {
  let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] === "0") { if (curStart === -1) curStart = i; curLen++; }
    else { if (curLen > bestLen) { bestStart = curStart; bestLen = curLen; } curStart = -1; curLen = 0; }
  }
  if (curLen > bestLen) { bestStart = curStart; bestLen = curLen; }
  if (bestLen < 2) return groups.join(":");
  const before = groups.slice(0, bestStart).join(":");
  const after = groups.slice(bestStart + bestLen).join(":");
  return `${before}::${after}`;
}
function luhnCheckDigit(numStr) {
  let sum = 0, alt = true;
  for (let i = numStr.length - 1; i >= 0; i--) {
    let d = parseInt(numStr[i], 10);
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d; alt = !alt;
  }
  return (10 - (sum % 10)) % 10;
}
function slugify(text, sep) {
  return String(text)
    .normalize("NFD").replace(/[̀-ͯ]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, sep)
    .replace(new RegExp(`^\\${sep}+|\\${sep}+$`, "g"), "")
    .replace(new RegExp(`\\${sep}{2,}`, "g"), sep);
}

// ---- word / data lists ----
const PASSPHRASE_WORDS = ["able","acid","aged","also","area","army","away","baby","back","ball","band","bank","base","bath","bead","beam","bean","bear","beat","been","beer","bell","belt","bend","bent","best","bike","bird","bite","blue","boat","body","bold","bolt","bone","book","boot","born","boss","both","bowl","bulk","burn","bush","busy","cake","calm","camp","card","care","case","cash","cast","cave","chef","chip","city","clay","club","coal","coat","code","coin","cold","come","cook","cool","core","cost","crew","crop","dark","data","dawn","deal","dear","debt","deep","deny","desk","dial","dice","diet","dish","dock","door","dose","down","draw","drop","drum","dust","duty","each","earn","east","easy","edge","exit","face","fact","fade","fair","fall","farm","fast","fate","fear","feed","feel","file","fill","film","find","fine","fire","fish","five","flag","flat","flow","folk","food","foot","ford","form","fort","free","from","fuel","full","fund","gain","game","gate","gear","gene","gift","girl","glow","goal","goat","gold","golf","good","grid","grow","half","hall","hand","hard","harm","hawk","head","heap","heat","hero","hill","hold","hole","holy","home","hope","horn","host","hour","huge","hull","hunt","hurt","idea","iron","item","jack","join","joke","jump","june","junk","just","keen","keep","kick","kind","king","kite","knee","lace","lack","lake","lamp","land","lane","last","late","lead","leaf","lean","left","lens","lift","like","limb","lime","line","link","lion","list","live","load","loan","lock","logo","long","look","loop","lord","lose","loss","loud","love"];
const LOREM_WORDS = ["lorem","ipsum","dolor","sit","amet","consectetur","adipiscing","elit","sed","do","eiusmod","tempor","incididunt","ut","labore","et","dolore","magna","aliqua","enim","ad","minim","veniam","quis","nostrud","exercitation","ullamco","laboris","nisi","aliquip","ex","ea","commodo","consequat","duis","aute","irure","in","reprehenderit","voluptate","velit","esse","cillum","eu","fugiat","nulla","pariatur","excepteur","sint","occaecat","cupidatat","non","proident","sunt","culpa","qui","officia","deserunt","mollit","anim","id","est","laborum"];
const FIRST_NAMES = ["James","Mary","Robert","Patricia","John","Jennifer","Michael","Linda","David","Elizabeth","William","Barbara","Priya","Wei","Fatima","Santiago","Amara","Liam","Olivia","Noah","Emma","Ava","Ethan","Sofia","Mateo","Yuki","Chen","Aisha","Lucas","Mia"];
const LAST_NAMES = ["Smith","Johnson","Williams","Brown","Jones","Garcia","Miller","Davis","Rodriguez","Martinez","Kumar","Patel","Nguyen","Kim","Chen","Silva","Muller","Kowalski","Andersson","Ivanov","Okafor","Diaz","Wilson","Moore","Taylor","Clark","Lewis","Walker","Hall","Young"];
const STREET_NAMES = ["Maple","Oak","Cedar","Pine","Elm","Washington","Lincoln","Main","Highland","Sunset","River","Lake","Park","Church","Spring","Ridge","Hill","Forest","Meadow","Willow"];
const STREET_TYPES = ["St","Ave","Blvd","Dr","Ln","Rd","Ct","Way"];
const US_CITIES = [["Springfield","IL"],["Franklin","TN"],["Greenville","SC"],["Georgetown","TX"],["Madison","WI"],["Salem","OR"],["Auburn","AL"],["Arlington","VA"],["Bristol","CT"],["Clinton","IA"],["Fairview","NJ"],["Riverside","CA"],["Manchester","NH"],["Kingston","NY"],["Oakland","CA"]];
const COMPANY_PREFIX = ["Nex","Vertex","Quantum","Orbit","Summit","Nova","Helix","Cobalt","Zenith","Pioneer","Lattice","Beacon","Ironclad","Stratus","Catalyst"];
const COMPANY_SUFFIX = ["Dynamics","Systems","Solutions","Labs","Works","Networks","Technologies","Partners","Holdings","Industries","Ventures","Group"];
const COMPANY_LEGAL = ["Inc.","LLC","Ltd.","Corp.","Co."];
const ADJECTIVES = ["Silent","Crimson","Rapid","Hidden","Quiet","Bold","Shadow","Bright","Steel","Frozen","Golden","Wild","Lone","Swift","Iron","Dark","Rogue","Sharp","Cosmic","Arctic"];
const NOUNS = ["Falcon","Wolf","Raven","Tiger","Cipher","Comet","Phantom","Hawk","Otter","Fox","Panther","Viper","Ember","Nomad","Drifter","Ranger","Wraith","Beacon","Sentinel","Nebula"];
const UA_BROWSERS = [
  (v1, v2) => `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${v1}.0.0.0 Safari/537.36`,
  (v1, v2) => `Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${v1}.0 Safari/605.1.15`,
  (v1, v2) => `Mozilla/5.0 (X11; Linux x86_64; rv:${v1}.0) Gecko/20100101 Firefox/${v1}.0`,
  (v1, v2) => `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${v1}.0.0.0 Safari/537.36 Edg/${v1}.0.0.0`,
];
const GITIGNORE = {
  Node: "node_modules/\nnpm-debug.log*\nyarn-debug.log*\nyarn-error.log*\ndist/\nbuild/\n.env\n.env.local\ncoverage/\n*.tsbuildinfo\n.DS_Store",
  Python: "__pycache__/\n*.py[cod]\n*.egg-info/\n.venv/\nvenv/\n.env\nbuild/\ndist/\n*.log\n.pytest_cache/\n.mypy_cache/\n.DS_Store",
  Java: "target/\n*.class\n*.jar\n*.war\n.gradle/\nbuild/\n.settings/\n.classpath\n.project\n*.iml\n.idea/\n.DS_Store",
  Go: "bin/\n*.exe\n*.test\n*.out\nvendor/\ngo.sum.bak\n.env\ncoverage.out\n.DS_Store",
};

const S = (v) => (v == null ? "" : String(v));
const MIN_OPTS = ["*", ...Array.from({ length: 60 }, (_, i) => String(i))];
const HOUR_OPTS = ["*", ...Array.from({ length: 24 }, (_, i) => String(i))];
const DOM_OPTS = ["*", ...Array.from({ length: 31 }, (_, i) => String(i + 1))];
const MONTH_OPTS = ["*", ...Array.from({ length: 12 }, (_, i) => String(i + 1))];
const DOW_OPTS = ["*", "0", "1", "2", "3", "4", "5", "6"];

export const TOOLS = [
  { id: "g-uuid-v4", name: "UUID v4 Generator", cat: "generators", desc: "Generate a random RFC 4122 version-4 UUID.", tags: ["uuid", "guid"], button: "Generate",
    inputs: [],
    run(v, H) { return H.uuid(); } },

  { id: "g-uuid-guid", name: "GUID Generator (uppercase, braces)", cat: "generators", desc: "Generate a UUID v4 formatted as a Windows-style GUID: {UPPERCASE}.", tags: ["guid", "uuid", "windows"], button: "Generate",
    inputs: [],
    run(v, H) { return `{${H.uuid().toUpperCase()}}`; } },

  { id: "g-uuid-nil", name: "Nil UUID", cat: "generators", desc: "The reserved all-zero UUID, useful as a placeholder/sentinel value.", tags: ["uuid", "nil", "zero"],
    inputs: [],
    run() { return "00000000-0000-0000-0000-000000000000"; } },

  { id: "g-ulid", name: "ULID Generator", cat: "generators", desc: "Generate a Universally Unique Lexicographically sortable ID (Crockford Base32, 48-bit time + 80-bit random).", tags: ["ulid", "sortable id"], button: "Generate",
    inputs: [],
    run(v, H) {
      const ENC = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
      let time = Date.now(), timeChars = "";
      for (let i = 0; i < 10; i++) { const mod = time % 32; timeChars = ENC[mod] + timeChars; time = (time - mod) / 32; }
      const rb = H.randBytes(10);
      let bits = 0, val = 0, randChars = "";
      for (let i = 0; i < rb.length; i++) { val = (val << 8) | rb[i]; bits += 8; while (bits >= 5) { randChars += ENC[(val >>> (bits - 5)) & 31]; bits -= 5; } }
      return timeChars + randChars.slice(0, 16);
    } },

  { id: "g-nanoid", name: "NanoID Generator", cat: "generators", desc: "Generate a compact URL-safe unique ID with a custom alphabet and length.", tags: ["nanoid", "id"], button: "Generate",
    inputs: [
      { k: "alphabet", label: "Alphabet", type: "text", placeholder: "leave blank for default", value: "" },
      { k: "length", label: "Length", type: "range", min: 4, max: 64, step: 1, value: 21 },
    ],
    run(v, H) {
      const alphabet = v.alphabet && v.alphabet.length >= 2 ? v.alphabet : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
      const len = H.clampInt(v.length, 4, 64, 21);
      const b = H.randBytes(len);
      let out = "";
      for (let i = 0; i < len; i++) out += alphabet[b[i] % alphabet.length];
      return out;
    } },

  { id: "g-password", name: "Strong Password Generator", cat: "generators", desc: "Generate a cryptographically random password with configurable length and character sets.", tags: ["password", "secret"], button: "Generate",
    inputs: [
      { k: "length", label: "Length", type: "range", min: 4, max: 128, step: 1, value: 16 },
      { k: "upper", label: "Uppercase (A-Z)", type: "checkbox", value: true },
      { k: "lower", label: "Lowercase (a-z)", type: "checkbox", value: true },
      { k: "digits", label: "Digits (0-9)", type: "checkbox", value: true },
      { k: "symbols", label: "Symbols (!@#$...)", type: "checkbox", value: true },
      { k: "noAmbiguous", label: "Exclude ambiguous (0 O 1 l I)", type: "checkbox", value: false },
    ],
    run(v, H) {
      let set = "";
      if (v.upper) set += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
      if (v.lower) set += "abcdefghijklmnopqrstuvwxyz";
      if (v.digits) set += "0123456789";
      if (v.symbols) set += "!@#$%^&*()-_=+[]{}?";
      if (!set) return { error: "Select at least one character set." };
      if (v.noAmbiguous) set = set.replace(/[0O1lI]/g, "");
      if (!set) return { error: "No characters left after excluding ambiguous ones." };
      const len = H.clampInt(v.length, 4, 128, 16);
      const b = H.randBytes(len);
      let out = "";
      for (let i = 0; i < len; i++) out += set[b[i] % set.length];
      return out;
    } },

  { id: "g-passphrase", name: "Passphrase Generator", cat: "generators", desc: "Generate a memorable multi-word passphrase (Diceware-style) from a wordlist.", tags: ["passphrase", "diceware"], button: "Generate",
    inputs: [
      { k: "count", label: "Word count", type: "range", min: 3, max: 10, step: 1, value: 4 },
      { k: "sep", label: "Separator", type: "select", opts: ["-", "_", ".", " "], value: "-" },
      { k: "capitalize", label: "Capitalize words", type: "checkbox", value: true },
      { k: "number", label: "Append random number", type: "checkbox", value: true },
    ],
    run(v) {
      const n = Math.max(3, Math.min(10, parseInt(v.count, 10) || 4));
      const words = [];
      for (let i = 0; i < n; i++) {
        let w = pick(PASSPHRASE_WORDS);
        if (v.capitalize) w = w[0].toUpperCase() + w.slice(1);
        words.push(w);
      }
      let out = words.join(v.sep || "-");
      if (v.number) out += (v.sep || "-") + String(randInt(10, 99));
      return out;
    } },

  { id: "g-api-key", name: "API Key Generator", cat: "generators", desc: "Generate a prefixed API key/token (e.g. sk_live_...) for testing SDKs and auth flows.", tags: ["api key", "token", "secret"], button: "Generate",
    inputs: [
      { k: "prefix", label: "Prefix", type: "text", value: "sk_live" },
      { k: "length", label: "Random part length", type: "range", min: 16, max: 64, step: 1, value: 32 },
    ],
    run(v, H) {
      const len = H.clampInt(v.length, 16, 64, 32);
      const set = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
      const b = H.randBytes(len);
      let rand = "";
      for (let i = 0; i < len; i++) rand += set[b[i] % set.length];
      const prefix = (v.prefix || "key").replace(/[^a-zA-Z0-9_]/g, "");
      return `${prefix}_${rand}`;
    } },

  { id: "g-hex-string", name: "Random Hex String", cat: "generators", desc: "Generate N random bytes rendered as a hex string.", tags: ["hex", "random"], button: "Generate",
    inputs: [
      { k: "length", label: "Byte length", type: "range", min: 1, max: 128, step: 1, value: 16 },
      { k: "upper", label: "Uppercase", type: "checkbox", value: false },
    ],
    run(v, H) {
      const len = H.clampInt(v.length, 1, 128, 16);
      const hex = H.toHex(H.randBytes(len));
      return v.upper ? hex.toUpperCase() : hex;
    } },

  { id: "g-random-bytes-b64", name: "Random Bytes (Base64)", cat: "generators", desc: "Generate N cryptographically random bytes, output as Base64 (or Base64url).", tags: ["random", "base64", "token"], button: "Generate",
    inputs: [
      { k: "length", label: "Byte length", type: "range", min: 1, max: 256, step: 1, value: 32 },
      { k: "urlsafe", label: "URL-safe (base64url, no padding)", type: "checkbox", value: false },
    ],
    run(v, H) {
      const len = H.clampInt(v.length, 1, 256, 32);
      const b64 = b64FromBytes(H.randBytes(len));
      return v.urlsafe ? b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "") : b64;
    } },

  { id: "g-mac-address", name: "Random MAC Address", cat: "generators", desc: "Generate a random MAC-48 address, optionally locally-administered.", tags: ["mac", "network"], button: "Generate",
    inputs: [
      { k: "sep", label: "Separator", type: "select", opts: [":", "-", ""], value: ":" },
      { k: "local", label: "Locally administered (set U/L bit)", type: "checkbox", value: true },
    ],
    run(v, H) {
      const b = H.randBytes(6);
      if (v.local) b[0] = (b[0] & 0xfc) | 0x02; else b[0] = b[0] & 0xfe;
      const hex = Array.from(b, (x) => x.toString(16).padStart(2, "0"));
      return hex.join(v.sep);
    } },

  { id: "g-ipv4", name: "Random IPv4 Address", cat: "generators", desc: "Generate a random IPv4 address for test data.", tags: ["ip", "network", "ipv4"], button: "Generate",
    inputs: [{ k: "private", label: "Use private range (10.x/172.16.x/192.168.x)", type: "checkbox", value: false }],
    run(v) {
      if (v.private) {
        const kind = pick(["10", "172", "192"]);
        if (kind === "10") return `10.${randInt(0, 255)}.${randInt(0, 255)}.${randInt(1, 254)}`;
        if (kind === "172") return `172.${randInt(16, 31)}.${randInt(0, 255)}.${randInt(1, 254)}`;
        return `192.168.${randInt(0, 255)}.${randInt(1, 254)}`;
      }
      return `${randInt(1, 223)}.${randInt(0, 255)}.${randInt(0, 255)}.${randInt(1, 254)}`;
    } },

  { id: "g-ipv6", name: "Random IPv6 Address", cat: "generators", desc: "Generate a random IPv6 address, optionally in the documentation range (2001:db8::/32) with zero-group compression.", tags: ["ip", "network", "ipv6"], button: "Generate",
    inputs: [
      { k: "docRange", label: "Documentation range (2001:db8::/32)", type: "checkbox", value: true },
      { k: "compress", label: "Compress zero groups (::)", type: "checkbox", value: true },
    ],
    run(v) {
      const groups = [];
      if (v.docRange) { groups.push("2001", "db8"); for (let i = 0; i < 6; i++) groups.push(randInt(0, 65535).toString(16)); }
      else { for (let i = 0; i < 8; i++) groups.push(randInt(0, 65535).toString(16)); }
      return v.compress ? compressIPv6(groups) : groups.join(":");
    } },

  { id: "g-lorem-ipsum", name: "Lorem Ipsum Generator", cat: "generators", desc: "Generate placeholder Lorem Ipsum text as paragraphs of sentences.", tags: ["lorem", "placeholder", "text"], button: "Generate",
    inputs: [
      { k: "paragraphs", label: "Paragraphs", type: "range", min: 1, max: 10, step: 1, value: 3 },
      { k: "sentences", label: "Sentences per paragraph", type: "range", min: 1, max: 12, step: 1, value: 5 },
      { k: "startLorem", label: "Start with 'Lorem ipsum dolor sit amet'", type: "checkbox", value: true },
    ],
    run(v) {
      const pc = Math.max(1, Math.min(10, parseInt(v.paragraphs, 10) || 3));
      const sc = Math.max(1, Math.min(12, parseInt(v.sentences, 10) || 5));
      const sentence = () => {
        const len = randInt(6, 14);
        const words = Array.from({ length: len }, () => pick(LOREM_WORDS));
        let s = words.join(" ");
        return s[0].toUpperCase() + s.slice(1) + ".";
      };
      const paras = [];
      for (let p = 0; p < pc; p++) {
        const sentences = [];
        for (let s = 0; s < sc; s++) sentences.push(sentence());
        if (p === 0 && v.startLorem) sentences[0] = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        paras.push(sentences.join(" "));
      }
      return paras.join("\n\n");
    } },

  { id: "g-fake-name", name: "Fake Full Name Generator", cat: "generators", desc: "Generate a random realistic-looking full name for test data.", tags: ["fake data", "name", "pii"], button: "Generate",
    inputs: [{ k: "middle", label: "Include middle initial", type: "checkbox", value: false }],
    run(v) {
      const first = pick(FIRST_NAMES), last = pick(LAST_NAMES);
      if (v.middle) return `${first} ${String.fromCharCode(65 + randInt(0, 25))}. ${last}`;
      return `${first} ${last}`;
    } },

  { id: "g-fake-email", name: "Fake Email Address Generator", cat: "generators", desc: "Generate a random fake email address for test fixtures.", tags: ["fake data", "email", "pii"], button: "Generate",
    inputs: [{ k: "domain", label: "Domain", type: "select", opts: ["example.com", "test.local", "mailinator.com", "fakemail.dev", "acme-corp.io"], value: "example.com" }],
    run(v) {
      const first = pick(FIRST_NAMES).toLowerCase(), last = pick(LAST_NAMES).toLowerCase();
      const sep = pick([".", "_", ""]);
      const n = randInt(0, 99);
      return `${first}${sep}${last}${n > 9 ? n : ""}@${v.domain || "example.com"}`;
    } },

  { id: "g-fake-address", name: "Fake US Address Generator", cat: "generators", desc: "Generate a random fake US street address, city, state and ZIP for test data.", tags: ["fake data", "address", "pii"], button: "Generate",
    inputs: [],
    run() {
      const num = randInt(100, 9999);
      const [city, state] = pick(US_CITIES);
      const zip = String(randInt(10000, 99999));
      return `${num} ${pick(STREET_NAMES)} ${pick(STREET_TYPES)}\n${city}, ${state} ${zip}`;
    } },

  { id: "g-fake-phone", name: "Fake Phone Number Generator", cat: "generators", desc: "Generate a random fake North American phone number.", tags: ["fake data", "phone", "pii"], button: "Generate",
    inputs: [{ k: "format", label: "Format", type: "select", opts: ["(555) 555-5555", "555-555-5555", "+1 555 555 5555"], value: "(555) 555-5555" }],
    run(v) {
      const area = randInt(200, 999), mid = randInt(200, 999), last = randInt(1000, 9999);
      if (v.format === "555-555-5555") return `${area}-${mid}-${last}`;
      if (v.format === "+1 555 555 5555") return `+1 ${area} ${mid} ${last}`;
      return `(${area}) ${mid}-${last}`;
    } },

  { id: "g-fake-company", name: "Fake Company Name Generator", cat: "generators", desc: "Generate a random plausible-sounding company name.", tags: ["fake data", "company"], button: "Generate",
    inputs: [],
    run() { return `${pick(COMPANY_PREFIX)}${pick(COMPANY_SUFFIX)} ${pick(COMPANY_LEGAL)}`; } },

  { id: "g-credit-card", name: "Test Credit Card Number Generator", cat: "generators", desc: "Generate a Luhn-valid but non-issued test credit card number for a chosen brand.", tags: ["credit card", "luhn", "test data"], button: "Generate",
    inputs: [{ k: "brand", label: "Brand", type: "select", opts: ["Visa", "Mastercard", "Amex", "Discover"], value: "Visa" }],
    run(v) {
      let prefix, length;
      if (v.brand === "Mastercard") { prefix = "5" + String(randInt(1, 5)); length = 16; }
      else if (v.brand === "Amex") { prefix = pick(["34", "37"]); length = 15; }
      else if (v.brand === "Discover") { prefix = "6011"; length = 16; }
      else { prefix = "4"; length = 16; }
      let digits = prefix;
      while (digits.length < length - 1) digits += String(randInt(0, 9));
      const full = digits + luhnCheckDigit(digits);
      return full.match(/.{1,4}/g).join(" ") + "  (test number, Luhn-valid — not a real card)";
    } },

  { id: "g-totp-secret", name: "TOTP Secret Generator", cat: "generators", desc: "Generate a random Base32 secret suitable for TOTP (RFC 6238) enrollment, e.g. with Google Authenticator.", tags: ["totp", "2fa", "mfa", "base32"], button: "Generate",
    inputs: [{ k: "length", label: "Secret length (chars)", type: "select", opts: ["16", "26", "32"], value: "32" }],
    run(v) {
      const len = [16, 26, 32].includes(parseInt(v.length, 10)) ? parseInt(v.length, 10) : 32;
      const bytes = new Uint8Array(Math.ceil((len * 5) / 8));
      crypto.getRandomValues(bytes);
      return b32FromBytes(bytes).slice(0, len);
    } },

  { id: "g-hex-color", name: "Random Hex Color", cat: "generators", desc: "Generate a random hex color code.", tags: ["color", "css", "hex"], button: "Generate",
    inputs: [],
    run(v, H) { return "#" + H.toHex(H.randBytes(3)); } },

  { id: "g-color-palette", name: "Color Palette Generator", cat: "generators", desc: "Generate 5 harmonious hex colors around a random base hue (analogous + accents).", tags: ["color", "palette", "css", "design"], button: "Generate",
    inputs: [{ k: "scheme", label: "Scheme", type: "select", opts: ["Analogous", "Complementary", "Triadic"], value: "Analogous" }],
    run(v) {
      const h = randInt(0, 359);
      let hues;
      if (v.scheme === "Complementary") hues = [h, (h + 180) % 360, (h + 30) % 360, (h + 210) % 360, (h + 60) % 360];
      else if (v.scheme === "Triadic") hues = [h, (h + 120) % 360, (h + 240) % 360, (h + 60) % 360, (h + 300) % 360];
      else hues = [h, (h + 20) % 360, (h + 40) % 360, (h - 20 + 360) % 360, (h - 40 + 360) % 360];
      return hues.map((hue, i) => hslToHex(hue, 65 - i * 5, i === 0 ? 50 : 45 + (i % 2) * 10)).join(", ");
    } },

  { id: "g-css-gradient", name: "CSS linear-gradient Generator", cat: "generators", desc: "Generate a random CSS linear-gradient() declaration.", tags: ["css", "gradient", "color"], button: "Generate",
    inputs: [
      { k: "angle", label: "Angle (deg)", type: "range", min: 0, max: 360, step: 5, value: 135 },
      { k: "stops", label: "Color stops", type: "select", opts: ["2", "3"], value: "2" },
    ],
    run(v) {
      const n = parseInt(v.stops, 10) === 3 ? 3 : 2;
      const h = randInt(0, 359);
      const colors = Array.from({ length: n }, (_, i) => hslToHex((h + i * (360 / (n + 1))) % 360, 70, 55));
      const angle = H_clampAngle(v.angle);
      return `background: linear-gradient(${angle}deg, ${colors.join(", ")});`;
    } },

  { id: "g-css-box-shadow", name: "CSS box-shadow Generator", cat: "generators", desc: "Generate a random CSS box-shadow declaration (offsets, blur, spread, color, inset).", tags: ["css", "shadow"], button: "Generate",
    inputs: [{ k: "inset", label: "Inset shadow", type: "checkbox", value: false }],
    run(v) {
      const x = randInt(-20, 20), y = randInt(-20, 20), blur = randInt(0, 40), spread = randInt(-10, 10);
      const color = `rgba(0,0,0,${(randInt(10, 45) / 100).toFixed(2)})`;
      return `box-shadow: ${v.inset ? "inset " : ""}${x}px ${y}px ${blur}px ${spread}px ${color};`;
    } },

  { id: "g-cron", name: "Cron Expression Builder", cat: "generators", desc: "Build a 5-field cron expression from minute/hour/day-of-month/month/day-of-week selects.", tags: ["cron", "schedule"],
    inputs: [
      { k: "minute", label: "Minute", type: "select", opts: MIN_OPTS, value: "0" },
      { k: "hour", label: "Hour", type: "select", opts: HOUR_OPTS, value: "*" },
      { k: "dom", label: "Day of month", type: "select", opts: DOM_OPTS, value: "*" },
      { k: "month", label: "Month", type: "select", opts: MONTH_OPTS, value: "*" },
      { k: "dow", label: "Day of week (0=Sun)", type: "select", opts: DOW_OPTS, value: "*" },
    ],
    run(v) { return `${v.minute || "*"} ${v.hour || "*"} ${v.dom || "*"} ${v.month || "*"} ${v.dow || "*"}`; } },

  { id: "g-gitignore", name: ".gitignore Generator", cat: "generators", desc: "Generate a starter .gitignore for a chosen language/stack.", tags: ["git", "gitignore"],
    inputs: [{ k: "lang", label: "Language / stack", type: "select", opts: ["Node", "Python", "Java", "Go"], value: "Node" }],
    run(v) { return GITIGNORE[v.lang] || GITIGNORE.Node; } },

  { id: "g-robots-txt", name: "robots.txt Generator", cat: "generators", desc: "Build a robots.txt from allow/disallow paths, user-agent and sitemap URL.", tags: ["robots.txt", "seo"],
    inputs: [
      { k: "ua", label: "User-agent", type: "text", value: "*" },
      { k: "disallow", label: "Disallow paths (one per line)", type: "textarea", placeholder: "/admin\n/private", rows: 4 },
      { k: "allow", label: "Allow paths (one per line)", type: "textarea", placeholder: "/public", rows: 3 },
      { k: "sitemap", label: "Sitemap URL", type: "text", placeholder: "https://example.com/sitemap.xml" },
    ],
    run(v) {
      const lines = [`User-agent: ${v.ua || "*"}`];
      (v.disallow || "").split("\n").map((s) => s.trim()).filter(Boolean).forEach((p) => lines.push(`Disallow: ${p}`));
      (v.allow || "").split("\n").map((s) => s.trim()).filter(Boolean).forEach((p) => lines.push(`Allow: ${p}`));
      if (!v.disallow && !v.allow) lines.push("Disallow:");
      if (v.sitemap) lines.push("", `Sitemap: ${v.sitemap.trim()}`);
      return lines.join("\n");
    } },

  { id: "g-meta-tags", name: "HTML Meta / OG Tags Generator", cat: "generators", desc: "Generate standard meta, Open Graph and Twitter Card tags from a title/description/URL.", tags: ["html", "meta", "og", "seo"],
    inputs: [
      { k: "title", label: "Title", type: "text", placeholder: "My Page" },
      { k: "desc", label: "Description", type: "textarea", rows: 3, placeholder: "Short page description" },
      { k: "url", label: "URL", type: "text", placeholder: "https://example.com/" },
    ],
    run(v, H) {
      if (!v.title) return { error: "Enter a title." };
      const title = H.escapeHtml(v.title), desc = H.escapeHtml(v.desc || ""), url = H.escapeHtml(v.url || "");
      return [
        `<title>${title}</title>`,
        `<meta name="description" content="${desc}">`,
        `<meta property="og:title" content="${title}">`,
        `<meta property="og:description" content="${desc}">`,
        url ? `<meta property="og:url" content="${url}">` : "",
        `<meta property="og:type" content="website">`,
        `<meta name="twitter:card" content="summary_large_image">`,
        `<meta name="twitter:title" content="${title}">`,
        `<meta name="twitter:description" content="${desc}">`,
      ].filter(Boolean).join("\n");
    } },

  { id: "g-dockerfile", name: "Dockerfile Generator", cat: "generators", desc: "Generate a minimal starter Dockerfile for a chosen language.", tags: ["docker", "dockerfile"],
    inputs: [{ k: "lang", label: "Language", type: "select", opts: ["Node", "Python", "Go", "Java"], value: "Node" }],
    run(v) {
      const T = {
        Node: "FROM node:20-alpine\nWORKDIR /app\nCOPY package*.json ./\nRUN npm ci --omit=dev\nCOPY . .\nEXPOSE 3000\nCMD [\"node\", \"index.js\"]",
        Python: "FROM python:3.12-slim\nWORKDIR /app\nCOPY requirements.txt .\nRUN pip install --no-cache-dir -r requirements.txt\nCOPY . .\nEXPOSE 8000\nCMD [\"python\", \"app.py\"]",
        Go: "FROM golang:1.22-alpine AS build\nWORKDIR /app\nCOPY . .\nRUN go build -o server .\n\nFROM alpine:latest\nWORKDIR /app\nCOPY --from=build /app/server .\nEXPOSE 8080\nCMD [\"./server\"]",
        Java: "FROM eclipse-temurin:21-jdk-alpine AS build\nWORKDIR /app\nCOPY . .\nRUN ./mvnw package -DskipTests\n\nFROM eclipse-temurin:21-jre-alpine\nWORKDIR /app\nCOPY --from=build /app/target/*.jar app.jar\nEXPOSE 8080\nCMD [\"java\", \"-jar\", \"app.jar\"]",
      };
      return T[v.lang] || T.Node;
    } },

  { id: "g-docker-compose", name: "docker-compose Snippet Generator", cat: "generators", desc: "Generate a docker-compose.yml service block from name/image/port.", tags: ["docker", "docker-compose", "yaml"],
    inputs: [
      { k: "service", label: "Service name", type: "text", value: "web" },
      { k: "image", label: "Image", type: "text", value: "nginx:latest" },
      { k: "port", label: "Host:Container port", type: "text", value: "8080:80" },
    ],
    run(v) {
      const svc = (v.service || "web").replace(/[^a-zA-Z0-9_-]/g, "");
      if (!svc) return { error: "Enter a valid service name." };
      return `version: "3.9"\nservices:\n  ${svc}:\n    image: ${v.image || "nginx:latest"}\n    ports:\n      - "${v.port || "8080:80"}"\n    restart: unless-stopped\n`;
    } },

  { id: "g-nginx-conf", name: "Nginx Server Block Generator", cat: "generators", desc: "Generate a basic Nginx server block (vhost) for a domain, docroot and port.", tags: ["nginx", "config", "vhost"],
    inputs: [
      { k: "domain", label: "Domain", type: "text", value: "example.com" },
      { k: "root", label: "Document root", type: "text", value: "/var/www/example" },
      { k: "port", label: "Listen port", type: "text", value: "80" },
    ],
    run(v) {
      const port = parseInt(v.port, 10) || 80;
      return `server {\n    listen ${port};\n    server_name ${v.domain || "example.com"};\n    root ${v.root || "/var/www/html"};\n    index index.html;\n\n    location / {\n        try_files $uri $uri/ =404;\n    }\n}`;
    } },

  { id: "g-systemd-unit", name: "systemd Service Unit Generator", cat: "generators", desc: "Generate a basic systemd .service unit file from a name and exec command.", tags: ["systemd", "service", "linux"],
    inputs: [
      { k: "name", label: "Description", type: "text", value: "My App" },
      { k: "exec", label: "ExecStart command", type: "text", value: "/usr/bin/node /app/index.js" },
      { k: "user", label: "Run as user", type: "text", value: "appuser" },
    ],
    run(v) {
      return `[Unit]\nDescription=${v.name || "My App"}\nAfter=network.target\n\n[Service]\nType=simple\nUser=${v.user || "appuser"}\nExecStart=${v.exec || "/usr/bin/app"}\nRestart=on-failure\n\n[Install]\nWantedBy=multi-user.target`;
    } },

  { id: "g-ssh-keygen", name: "SSH Keygen Command Builder", cat: "generators", desc: "Build an ssh-keygen command line for a chosen key type.", tags: ["ssh", "keygen", "command"],
    inputs: [
      { k: "type", label: "Key type", type: "select", opts: ["ed25519", "rsa", "ecdsa"], value: "ed25519" },
      { k: "comment", label: "Comment (email/label)", type: "text", placeholder: "you@example.com" },
      { k: "file", label: "Output file", type: "text", value: "~/.ssh/id_ed25519" },
    ],
    run(v) {
      const bits = v.type === "rsa" ? " -b 4096" : v.type === "ecdsa" ? " -b 521" : "";
      const comment = v.comment ? ` -C "${v.comment.replace(/"/g, "")}"` : "";
      return `ssh-keygen -t ${v.type || "ed25519"}${bits} -f ${v.file || "~/.ssh/id_ed25519"}${comment}`;
    } },

  { id: "g-openssl-cert", name: "OpenSSL Self-Signed Cert Command Builder", cat: "generators", desc: "Build an openssl command to generate a self-signed TLS certificate for a CN and validity period.", tags: ["openssl", "tls", "certificate"],
    inputs: [
      { k: "cn", label: "Common Name (CN)", type: "text", value: "localhost" },
      { k: "days", label: "Valid days", type: "range", min: 1, max: 3650, step: 1, value: 365 },
    ],
    run(v, H) {
      const days = H.clampInt(v.days, 1, 3650, 365);
      const cn = (v.cn || "localhost").replace(/"/g, "");
      return `openssl req -x509 -newkey rsa:4096 -sha256 -days ${days} -nodes \\\n  -keyout key.pem -out cert.pem -subj "/CN=${cn}"`;
    } },

  { id: "g-htpasswd", name: "htpasswd Line Generator (SHA)", cat: "generators", desc: "Generate an Apache htpasswd-style line using the legacy {SHA} scheme: username:{SHA}base64(sha1(password)).", tags: ["htpasswd", "apache", "sha1"],
    inputs: [
      { k: "username", label: "Username", type: "text" },
      { k: "password", label: "Password", type: "text", inputType: "password" },
    ],
    async run(v, H) {
      if (!v.username) return { error: "Enter a username." };
      if (!v.password) return { error: "Enter a password." };
      const digest = await crypto.subtle.digest("SHA-1", H.bytes(v.password));
      return `${v.username}:{SHA}${b64FromBytes(new Uint8Array(digest))}`;
    } },

  

  { id: "g-pin", name: "Random PIN Generator", cat: "generators", desc: "Generate a random numeric PIN of a given length.", tags: ["pin", "numeric", "random"], button: "Generate",
    inputs: [{ k: "length", label: "Digits", type: "range", min: 4, max: 12, step: 1, value: 6 }],
    run(v, H) {
      const len = H.clampInt(v.length, 4, 12, 6);
      let out = "";
      for (let i = 0; i < len; i++) out += String(randInt(0, 9));
      return out;
    } },

  { id: "g-dice-roll", name: "Dice Roller (NdM)", cat: "generators", desc: "Roll N dice with M sides each and show individual rolls plus total.", tags: ["dice", "rng", "random"], button: "Roll",
    inputs: [
      { k: "n", label: "Number of dice (N)", type: "range", min: 1, max: 20, step: 1, value: 2 },
      { k: "m", label: "Sides per die (M)", type: "select", opts: ["4", "6", "8", "10", "12", "20", "100"], value: "6" },
    ],
    run(v, H) {
      const n = H.clampInt(v.n, 1, 20, 2);
      const m = parseInt(v.m, 10) || 6;
      const rolls = Array.from({ length: n }, () => randInt(1, m));
      const total = rolls.reduce((a, b) => a + b, 0);
      return `${n}d${m}: [${rolls.join(", ")}]  total = ${total}`;
    } },

  { id: "g-random-int", name: "Random Integer Generator", cat: "generators", desc: "Generate a uniformly random integer between min and max (inclusive).", tags: ["random", "integer", "rng"], button: "Generate",
    inputs: [
      { k: "min", label: "Min", type: "text", inputType: "number", value: "1" },
      { k: "max", label: "Max", type: "text", inputType: "number", value: "100" },
    ],
    run(v) {
      let min = parseInt(v.min, 10), max = parseInt(v.max, 10);
      if (isNaN(min) || isNaN(max)) return { error: "Enter valid integers for min and max." };
      if (min > max) [min, max] = [max, min];
      return String(randInt(min, max));
    } },

  { id: "g-uuid-batch", name: "UUID Batch Generator", cat: "generators", desc: "Generate a batch of random UUID v4 values, one per line.", tags: ["uuid", "batch", "bulk"], button: "Generate",
    inputs: [{ k: "count", label: "Count", type: "range", min: 1, max: 200, step: 1, value: 10 }],
    run(v, H) {
      const n = H.clampInt(v.count, 1, 200, 10);
      return Array.from({ length: n }, () => H.uuid()).join("\n");
    } },

  { id: "g-placeholder-image", name: "Placeholder Image URL Builder", cat: "generators", desc: "Build a picsum.photos-style placeholder image URL string (width/height/seed/grayscale). Produces text only — no request is made.", tags: ["placeholder", "image", "url"],
    inputs: [
      { k: "width", label: "Width", type: "range", min: 32, max: 2000, step: 1, value: 600 },
      { k: "height", label: "Height", type: "range", min: 32, max: 2000, step: 1, value: 400 },
      { k: "seed", label: "Seed (blank = random)", type: "text", placeholder: "my-seed" },
      { k: "grayscale", label: "Grayscale", type: "checkbox", value: false },
      { k: "blur", label: "Blur", type: "checkbox", value: false },
    ],
    run(v, H) {
      const w = H.clampInt(v.width, 32, 2000, 600);
      const hgt = H.clampInt(v.height, 32, 2000, 400);
      const seed = (v.seed && v.seed.trim()) || H.toHex(H.randBytes(4));
      let url = `https://picsum.photos/seed/${encodeURIComponent(seed)}/${w}/${hgt}`;
      const q = [];
      if (v.grayscale) q.push("grayscale");
      if (v.blur) q.push("blur=2");
      if (q.length) url += "?" + q.join("&");
      return url;
    } },

  { id: "g-random-string", name: "Random String Generator", cat: "generators", desc: "Generate a random string from a preset or custom character set.", tags: ["random", "string"], button: "Generate",
    inputs: [
      { k: "preset", label: "Character set", type: "select", opts: ["Alphanumeric", "Letters only", "Digits only", "Hex", "Custom"], value: "Alphanumeric" },
      { k: "custom", label: "Custom charset (if Custom)", type: "text", placeholder: "ABC123!?" },
      { k: "length", label: "Length", type: "range", min: 1, max: 256, step: 1, value: 24 },
    ],
    run(v, H) {
      const sets = {
        "Alphanumeric": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "Letters only": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "Digits only": "0123456789",
        "Hex": "0123456789abcdef",
      };
      let set = v.preset === "Custom" ? (v.custom || "") : (sets[v.preset] || sets["Alphanumeric"]);
      if (!set || set.length < 2) return { error: "Provide at least 2 distinct characters." };
      const len = H.clampInt(v.length, 1, 256, 24);
      const b = H.randBytes(len);
      let out = "";
      for (let i = 0; i < len; i++) out += set[b[i] % set.length];
      return out;
    } },

  

  { id: "g-user-agent", name: "Random User-Agent Generator", cat: "generators", desc: "Generate a random plausible browser User-Agent string for test requests.", tags: ["user-agent", "http", "browser"], button: "Generate",
    inputs: [{ k: "browser", label: "Browser", type: "select", opts: ["Chrome", "Safari", "Firefox", "Edge"], value: "Chrome" }],
    run(v) {
      const idx = { Chrome: 0, Safari: 1, Firefox: 2, Edge: 3 }[v.browser] ?? 0;
      const v1 = randInt(100, 128);
      return UA_BROWSERS[idx](v1);
    } },

  { id: "g-username", name: "Fake Username Generator", cat: "generators", desc: "Generate a random adjective+noun+number style username for test accounts and wordlists.", tags: ["username", "fake data", "wordlist"], button: "Generate",
    inputs: [{ k: "digits", label: "Trailing digits", type: "range", min: 0, max: 4, step: 1, value: 2 }],
    run(v, H) {
      const nd = H.clampInt(v.digits, 0, 4, 2);
      let suffix = "";
      for (let i = 0; i < nd; i++) suffix += String(randInt(0, 9));
      return `${pick(ADJECTIVES)}${pick(NOUNS)}${suffix}`;
    } },
];

function H_clampAngle(a) { const n = parseInt(a, 10); if (isNaN(n)) return 135; return ((n % 360) + 360) % 360; }
