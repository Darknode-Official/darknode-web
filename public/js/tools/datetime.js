// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Date & time mini-tools.

// ---- shared pure helpers (no imports, no network, no DOM) ----
const pad = (n, w = 2) => String(Math.trunc(Math.abs(n))).padStart(w, "0");
const DATE_ERR = { error: "Enter a valid date/time, e.g. 2026-09-25 14:30 or a unix timestamp." };
const WEEKDAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
const MONTHS = ["January", "February", "March", "April", "May", "June",
  "July", "August", "September", "October", "November", "December"];

function isLeap(y) { return (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0; }
function daysInMonth(y, m0) { return new Date(Date.UTC(y, m0 + 1, 0)).getUTCDate(); }

function parseDate(s) {
  if (s == null) return null;
  s = String(s).trim();
  if (!s) return null;
  if (/^-?\d+$/.test(s)) {
    const num = Number(s);
    const ms = Math.abs(num) < 1e11 ? num * 1000 : num;
    const d = new Date(ms);
    return isNaN(d.getTime()) ? null : d;
  }
  // A bare calendar date (YYYY-MM-DD) is parsed by `new Date` as UTC midnight,
  // which disagrees with the local-time parsing this function gives date+time
  // strings and with the local getters most consumers use. Parse it as LOCAL
  // midnight so a typed calendar date means that same calendar day everywhere.
  const iso = /^(\d{4})-(\d{1,2})-(\d{1,2})$/.exec(s);
  if (iso) { const d = new Date(+iso[1], +iso[2] - 1, +iso[3]); return isNaN(d.getTime()) ? null : d; }
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d;
}

function parseAsUTC(s) {
  s = String(s == null ? "" : s).trim();
  const m = /^(\d{4})-(\d{1,2})-(\d{1,2})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2}))?)?/.exec(s);
  if (!m) return null;
  const dt = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0)));
  return isNaN(dt.getTime()) ? null : dt;
}

function parseOffset(s) {
  s = String(s == null ? "" : s).trim().toUpperCase().replace(/^UTC|^GMT/, "");
  if (s === "" || s === "Z") return 0;
  const m = /^([+-])?(\d{1,2}):?(\d{2})?$/.exec(s);
  if (!m) return null;
  const sign = m[1] === "-" ? -1 : 1;
  const h = parseInt(m[2], 10);
  const mi = m[3] ? parseInt(m[3], 10) : 0;
  if (h > 14 || mi > 59) return null;
  return sign * (h * 60 + mi);
}
function offsetLabel(off) {
  const sign = off < 0 ? "-" : "+";
  return sign + pad(Math.floor(Math.abs(off) / 60)) + ":" + pad(Math.abs(off) % 60);
}

function isoUTC(d) {
  return d.getUTCFullYear() + "-" + pad(d.getUTCMonth() + 1) + "-" + pad(d.getUTCDate()) +
    " " + pad(d.getUTCHours()) + ":" + pad(d.getUTCMinutes()) + ":" + pad(d.getUTCSeconds());
}

function formatPattern(d, pat) {
  const h12 = ((d.getHours() + 11) % 12) + 1;
  const map = {
    YYYY: d.getFullYear(), YY: pad(d.getFullYear() % 100),
    MMMM: MONTHS[d.getMonth()], MMM: MONTHS[d.getMonth()].slice(0, 3),
    MM: pad(d.getMonth() + 1), M: d.getMonth() + 1,
    DD: pad(d.getDate()), D: d.getDate(),
    dddd: WEEKDAYS[d.getDay()], ddd: WEEKDAYS[d.getDay()].slice(0, 3),
    HH: pad(d.getHours()), H: d.getHours(),
    hh: pad(h12), h: h12,
    mm: pad(d.getMinutes()), m: d.getMinutes(),
    ss: pad(d.getSeconds()), s: d.getSeconds(),
    A: d.getHours() < 12 ? "AM" : "PM", a: d.getHours() < 12 ? "am" : "pm"
  };
  return pat.replace(/YYYY|YY|MMMM|MMM|MM|M|DD|D|dddd|ddd|HH|H|hh|h|mm|m|ss|s|A|a/g, t => String(map[t]));
}

function humanizeDuration(totalSec) {
  totalSec = Math.floor(totalSec);
  const neg = totalSec < 0; totalSec = Math.abs(totalSec);
  const d = Math.floor(totalSec / 86400); totalSec %= 86400;
  const h = Math.floor(totalSec / 3600); totalSec %= 3600;
  const m = Math.floor(totalSec / 60); const s = totalSec % 60;
  const parts = [];
  if (d) parts.push(d + "d");
  if (h) parts.push(h + "h");
  if (m) parts.push(m + "m");
  if (s || !parts.length) parts.push(s + "s");
  return (neg ? "-" : "") + parts.join(" ");
}

function parseDuration(str) {
  const re = /(-?\d+(?:\.\d+)?)\s*(w|d|h|m|s)/gi;
  let total = 0, mtch, found = false;
  const mult = { w: 604800, d: 86400, h: 3600, m: 60, s: 1 };
  while ((mtch = re.exec(str))) { found = true; total += parseFloat(mtch[1]) * mult[mtch[2].toLowerCase()]; }
  return found ? total : null;
}

function isoWeek(d) {
  const date = new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()));
  const dayNum = (date.getUTCDay() + 6) % 7;
  date.setUTCDate(date.getUTCDate() - dayNum + 3);
  const firstThursday = new Date(Date.UTC(date.getUTCFullYear(), 0, 4));
  const fdn = (firstThursday.getUTCDay() + 6) % 7;
  firstThursday.setUTCDate(firstThursday.getUTCDate() - fdn + 3);
  const week = 1 + Math.round((date - firstThursday) / (7 * 86400000));
  return { week: week, year: date.getUTCFullYear() };
}

function toJDN(y, m, d) {
  const a = Math.floor((14 - m) / 12);
  const yy = y + 4800 - a;
  const mm = m + 12 * a - 3;
  return d + Math.floor((153 * mm + 2) / 5) + 365 * yy + Math.floor(yy / 4) - Math.floor(yy / 100) + Math.floor(yy / 400) - 32045;
}
function fromJDN(jdn) {
  const a = jdn + 32044;
  const b = Math.floor((4 * a + 3) / 146097);
  const c = a - Math.floor(146097 * b / 4);
  const dd = Math.floor((4 * c + 3) / 1461);
  const e = c - Math.floor(1461 * dd / 4);
  const mm = Math.floor((5 * e + 2) / 153);
  const day = e - Math.floor((153 * mm + 2) / 5) + 1;
  const month = mm + 3 - 12 * Math.floor(mm / 10);
  const year = 100 * b + dd - 4800 + Math.floor(mm / 10);
  return { year: year, month: month, day: day };
}

function cronField(expr, lo, hi) {
  const out = new Set();
  for (const part of String(expr).split(",")) {
    let step = 1, range = part;
    const slash = part.split("/");
    if (slash.length === 2) { range = slash[0]; step = parseInt(slash[1], 10); if (!(step > 0)) return null; }
    else if (slash.length > 2) return null;
    let a, b;
    if (range === "*") { a = lo; b = hi; }
    else if (range.includes("-")) { const [x, y] = range.split("-"); a = parseInt(x, 10); b = parseInt(y, 10); }
    else { a = parseInt(range, 10); b = a; }
    if (isNaN(a) || isNaN(b) || a < lo || b > hi || a > b) return null;
    for (let i = a; i <= b; i += step) out.add(i);
  }
  return out.size ? out : null;
}

function ordinalSuffix(n) {
  const v = Math.abs(n) % 100;
  if (v >= 11 && v <= 13) return "th";
  switch (Math.abs(n) % 10) { case 1: return "st"; case 2: return "nd"; case 3: return "rd"; default: return "th"; }
}

function seasonName(m, day) {
  if ((m === 12 && day >= 21) || m === 1 || m === 2 || (m === 3 && day < 20)) return "Winter";
  if (m === 3 || m === 4 || m === 5 || (m === 6 && day < 21)) return "Spring";
  if (m === 6 || m === 7 || m === 8 || (m === 9 && day < 22)) return "Summer";
  return "Autumn";
}

function weeksInYear(y) {
  const p = (yy) => (((yy + Math.floor(yy / 4) - Math.floor(yy / 100) + Math.floor(yy / 400)) % 7) + 7) % 7;
  return (p(y) === 4 || p(y - 1) === 3) ? 53 : 52;
}

function isoWeekToDate(y, w) {
  const simple = new Date(Date.UTC(y, 0, 1 + (w - 1) * 7));
  const dow = simple.getUTCDay();
  const start = new Date(simple);
  if (dow <= 4) start.setUTCDate(simple.getUTCDate() - dow + 1);
  else start.setUTCDate(simple.getUTCDate() + 8 - dow);
  return start;
}

// ---- tool definitions ----
const defs = [
  {
    id: "dt-unix-to-human", name: "Unix Seconds to Human Date", cat: "datetime",
    desc: "Convert a Unix timestamp (seconds) to UTC, ISO and local date strings.",
    tags: ["unix", "epoch", "convert", "utc"],
    inputs: [{ k: "x", label: "Unix seconds", type: "text", inputType: "number", placeholder: "1700000000" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      if (!/^-?\d+(\.\d+)?$/.test(s)) return { error: "Enter a numeric unix timestamp in seconds." };
      const d = new Date(parseFloat(s) * 1000);
      if (isNaN(d.getTime())) return DATE_ERR;
      return "UTC:   " + d.toUTCString() + "\nISO:   " + d.toISOString() + "\nLocal: " + d.toString();
    }
  },
  {
    id: "dt-human-to-unix", name: "Human Date to Unix Seconds", cat: "datetime",
    desc: "Parse a date/time string and return the Unix timestamp in seconds and millis.",
    tags: ["unix", "epoch", "parse"],
    inputs: [{ k: "x", label: "Date/time", type: "text", placeholder: "2026-09-25 14:30" }],
    run(v) {
      if (v.x == null || !String(v.x).trim()) return "";
      const d = parseDate(v.x);
      if (!d) return DATE_ERR;
      return "Unix seconds: " + Math.floor(d.getTime() / 1000) + "\nUnix millis:  " + d.getTime();
    }
  },
  {
    id: "dt-unix-millis-to-date", name: "Unix Millis to Date", cat: "datetime",
    desc: "Convert a Unix timestamp in milliseconds to UTC and local date strings.",
    tags: ["unix", "millis", "convert"],
    inputs: [{ k: "x", label: "Unix millis", type: "text", inputType: "number", placeholder: "1700000000000" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      if (!/^-?\d+(\.\d+)?$/.test(s)) return { error: "Enter a numeric unix timestamp in milliseconds." };
      const d = new Date(parseFloat(s));
      if (isNaN(d.getTime())) return DATE_ERR;
      return "UTC:   " + d.toUTCString() + "\nISO:   " + d.toISOString() + "\nLocal: " + d.toString();
    }
  },
  {
    id: "dt-date-to-unix-millis", name: "Date to Unix Millis", cat: "datetime",
    desc: "Parse a date/time string and return the Unix timestamp in milliseconds.",
    tags: ["unix", "millis", "parse"],
    inputs: [{ k: "x", label: "Date/time", type: "text", placeholder: "2026-09-25 14:30" }],
    run(v) {
      if (v.x == null || !String(v.x).trim()) return "";
      const d = parseDate(v.x);
      if (!d) return DATE_ERR;
      return String(d.getTime());
    }
  },
  {
    id: "dt-now", name: "Current Unix Timestamp", cat: "datetime",
    desc: "Return the current Unix timestamp in the selected unit.",
    tags: ["now", "unix", "epoch"],
    inputs: [{ k: "unit", type: "select", opts: [["s", "seconds"], ["ms", "milliseconds"], ["us", "microseconds"]], value: "s" }],
    run(v) {
      const u = v.unit || "s";
      const now = Date.now();
      if (u === "ms") return "Unix millis: " + now;
      if (u === "us") return "Unix micros: " + (now * 1000);
      return "Unix seconds: " + Math.floor(now / 1000);
    }
  },
  {
    id: "dt-iso-parse", name: "ISO-8601 Parser", cat: "datetime",
    desc: "Parse an ISO-8601 date/time and list its UTC components.",
    tags: ["iso", "parse", "components"],
    inputs: [{ k: "x", label: "ISO-8601 string", type: "text", placeholder: "2026-09-25T14:30:00Z" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const d = new Date(s);
      if (isNaN(d.getTime())) return DATE_ERR;
      return [
        "Year:    " + d.getUTCFullYear(), "Month:   " + (d.getUTCMonth() + 1),
        "Day:     " + d.getUTCDate(), "Hour:    " + d.getUTCHours(),
        "Minute:  " + d.getUTCMinutes(), "Second:  " + d.getUTCSeconds(),
        "Millis:  " + d.getUTCMilliseconds(), "Weekday: " + WEEKDAYS[d.getUTCDay()],
        "ISO:     " + d.toISOString()
      ].join("\n");
    }
  },
  {
    id: "dt-format-pattern", name: "Format Date with Pattern", cat: "datetime",
    desc: "Format a date using tokens: YYYY YY MMMM MMM MM M DD D dddd ddd HH H hh h mm m ss s A a.",
    tags: ["format", "pattern", "tokenizer"],
    inputs: [
      { k: "x", label: "Date/time", type: "text", placeholder: "2026-09-25 14:30" },
      { k: "p", label: "Pattern", type: "text", placeholder: "YYYY-MM-DD HH:mm:ss" }
    ],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const d = parseDate(s);
      if (!d) return DATE_ERR;
      const pat = (v.p && v.p.trim()) || "YYYY-MM-DD HH:mm:ss";
      return formatPattern(d, pat);
    }
  },
  {
    id: "dt-tz-offset-convert", name: "Timezone Offset Converter", cat: "datetime",
    desc: "Convert a UTC date/time to a local time given an offset like +05:30 or -08:00.",
    tags: ["timezone", "offset", "convert", "utc"],
    inputs: [
      { k: "x", label: "UTC date/time", type: "text", placeholder: "2026-09-25 14:30" },
      { k: "off", label: "Offset", type: "text", placeholder: "+05:30" }
    ],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const d = parseAsUTC(s);
      if (!d) return DATE_ERR;
      const mins = parseOffset(v.off || "");
      if ((v.off || "").trim() && mins === null) return { error: "Enter an offset like +05:30 or -08:00." };
      const off = mins || 0;
      const local = new Date(d.getTime() + off * 60000);
      return "UTC:    " + isoUTC(d) + "\nOffset: " + offsetLabel(off) + "\nLocal:  " + isoUTC(local);
    }
  },
  {
    id: "dt-tz-offset-list", name: "Common Timezone Offsets", cat: "datetime",
    desc: "A reference list of common UTC offsets and example regions.",
    tags: ["timezone", "offset", "reference"],
    inputs: [],
    run() {
      const rows = [
        ["-08:00", "PST — Los Angeles"], ["-07:00", "MST — Denver"], ["-06:00", "CST — Chicago"],
        ["-05:00", "EST — New York"], ["-03:00", "Sao Paulo"], ["+00:00", "UTC — London"],
        ["+01:00", "CET — Paris"], ["+02:00", "EET — Cairo"], ["+03:00", "Moscow"],
        ["+03:30", "Tehran"], ["+04:00", "Dubai"], ["+05:00", "Karachi"],
        ["+05:30", "IST — India"], ["+05:45", "Kathmandu"], ["+06:00", "Dhaka"],
        ["+07:00", "Bangkok"], ["+08:00", "Beijing / Singapore"], ["+09:00", "JST — Tokyo"],
        ["+09:30", "Adelaide"], ["+10:00", "Sydney"], ["+12:00", "Auckland"]
      ];
      return rows.map(r => r[0] + "  " + r[1]).join("\n");
    }
  },
  {
    id: "dt-duration-humanize", name: "Seconds to Duration", cat: "datetime",
    desc: "Convert a number of seconds to a human duration like 1d 2h 3m 4s.",
    tags: ["duration", "seconds", "humanize"],
    inputs: [{ k: "x", label: "Seconds", type: "text", inputType: "number", placeholder: "93784" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      if (!/^-?\d+(\.\d+)?$/.test(s)) return { error: "Enter a number of seconds." };
      return humanizeDuration(parseFloat(s));
    }
  },
  {
    id: "dt-duration-parse", name: "Duration String to Seconds", cat: "datetime",
    desc: "Parse a duration string like 1h30m or 2d 4h into seconds.",
    tags: ["duration", "parse", "seconds"],
    inputs: [{ k: "x", label: "Duration", type: "text", placeholder: "1h30m" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const sec = parseDuration(s);
      if (sec === null) return { error: "Enter a duration like 1h30m, 2d, or 90s." };
      return "Seconds: " + sec + "\nMinutes: " + (sec / 60) + "\nHuman:   " + humanizeDuration(sec);
    }
  },
  {
    id: "dt-between-dates", name: "Time Between Two Dates", cat: "datetime",
    desc: "Compute the difference between two dates in ms, seconds, minutes, hours and days.",
    tags: ["difference", "between", "dates"],
    inputs: [
      { k: "a", label: "First date", type: "text", placeholder: "2026-01-01" },
      { k: "b", label: "Second date", type: "text", placeholder: "2026-09-25" }
    ],
    run(v) {
      const A = (v.a || "").trim(), B = (v.b || "").trim();
      if (!A || !B) return "";
      const da = parseDate(A), db = parseDate(B);
      if (!da || !db) return DATE_ERR;
      const ms = Math.abs(db - da);
      const sec = Math.floor(ms / 1000);
      return "Milliseconds: " + ms + "\nSeconds: " + sec + "\nMinutes: " + (ms / 60000).toFixed(4) +
        "\nHours:   " + (ms / 3600000).toFixed(4) + "\nDays:    " + (ms / 86400000).toFixed(4) +
        "\nHuman:   " + humanizeDuration(sec);
    }
  },
  {
    id: "dt-add-duration", name: "Add Duration to a Date", cat: "datetime",
    desc: "Add a duration like 1h30m or 2d to a date and return the result.",
    tags: ["add", "duration", "date"],
    inputs: [
      { k: "x", label: "Date/time", type: "text", placeholder: "2026-09-25 14:30" },
      { k: "dur", label: "Duration", type: "text", placeholder: "1h30m" }
    ],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const d = parseDate(s);
      if (!d) return DATE_ERR;
      const sec = parseDuration(v.dur || "");
      if ((v.dur || "").trim() && sec === null) return { error: "Enter a duration like 1h30m, 2d, or 90s." };
      const res = new Date(d.getTime() + (sec || 0) * 1000);
      return "ISO:   " + res.toISOString() + "\nLocal: " + res.toString();
    }
  },
  {
    id: "dt-subtract-duration", name: "Subtract Duration from a Date", cat: "datetime",
    desc: "Subtract a duration like 1h30m or 2d from a date and return the result.",
    tags: ["subtract", "duration", "date"],
    inputs: [
      { k: "x", label: "Date/time", type: "text", placeholder: "2026-09-25 14:30" },
      { k: "dur", label: "Duration", type: "text", placeholder: "1h30m" }
    ],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const d = parseDate(s);
      if (!d) return DATE_ERR;
      const sec = parseDuration(v.dur || "");
      if ((v.dur || "").trim() && sec === null) return { error: "Enter a duration like 1h30m, 2d, or 90s." };
      const res = new Date(d.getTime() - (sec || 0) * 1000);
      return "ISO:   " + res.toISOString() + "\nLocal: " + res.toString();
    }
  },
  {
    id: "dt-day-of-week", name: "Day of Week", cat: "datetime",
    desc: "Return the weekday name and number for a date.",
    tags: ["weekday", "day", "date"],
    inputs: [{ k: "x", label: "Date", type: "text", placeholder: "2026-09-25" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const d = parseDate(s);
      if (!d) return DATE_ERR;
      return WEEKDAYS[d.getDay()] + " (ISO " + (((d.getDay() + 6) % 7) + 1) + ", Sunday-based " + d.getDay() + ")";
    }
  },
  {
    id: "dt-day-of-year", name: "Day of Year", cat: "datetime",
    desc: "Return the ordinal day of the year (1-366) for a date.",
    tags: ["day-of-year", "ordinal", "date"],
    inputs: [{ k: "x", label: "Date", type: "text", placeholder: "2026-09-25" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const d = parseDate(s);
      if (!d) return DATE_ERR;
      const diff = Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()) - Date.UTC(d.getFullYear(), 0, 1);
      const doy = Math.floor(diff / 86400000) + 1;
      return "Day " + doy + " of " + d.getFullYear();
    }
  },
  {
    id: "dt-iso-week", name: "ISO Week Number", cat: "datetime",
    desc: "Return the ISO-8601 week number and week-year for a date.",
    tags: ["iso", "week", "number"],
    inputs: [{ k: "x", label: "Date", type: "text", placeholder: "2026-09-25" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const d = parseDate(s);
      if (!d) return DATE_ERR;
      const w = isoWeek(new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate())));
      return "ISO week " + w.week + " of " + w.year;
    }
  },
  {
    id: "dt-week-of-month", name: "Week of Month", cat: "datetime",
    desc: "Return which week of the month a date falls in.",
    tags: ["week", "month", "date"],
    inputs: [{ k: "x", label: "Date", type: "text", placeholder: "2026-09-25" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const d = parseDate(s);
      if (!d) return DATE_ERR;
      const dom = d.getDate();
      const first = new Date(d.getFullYear(), d.getMonth(), 1).getDay();
      const wom = Math.ceil((dom + first) / 7);
      return "Week " + wom + " of " + MONTHS[d.getMonth()] + " " + d.getFullYear();
    }
  },
  {
    id: "dt-days-in-month", name: "Days in Month", cat: "datetime",
    desc: "Return the number of days in the month of a given date.",
    tags: ["days", "month", "calendar"],
    inputs: [{ k: "x", label: "Date", type: "text", placeholder: "2026-02-10" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const d = parseDate(s);
      if (!d) return DATE_ERR;
      return daysInMonth(d.getFullYear(), d.getMonth()) + " days in " + MONTHS[d.getMonth()] + " " + d.getFullYear();
    }
  },
  {
    id: "dt-is-leap-year", name: "Is Leap Year", cat: "datetime",
    desc: "Determine whether a given year is a leap year.",
    tags: ["leap", "year", "calendar"],
    inputs: [{ k: "x", label: "Year", type: "text", inputType: "number", placeholder: "2028" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const y = parseInt(s, 10);
      if (isNaN(y)) return { error: "Enter a year, e.g. 2028." };
      return isLeap(y) ? y + " is a leap year (366 days)." : y + " is not a leap year (365 days).";
    }
  },
  {
    id: "dt-age", name: "Age Calculator", cat: "datetime",
    desc: "Compute age in years, months and days from a birthdate.",
    tags: ["age", "birthday", "calculator"],
    inputs: [{ k: "x", label: "Birthdate", type: "text", placeholder: "1990-05-15" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const b = parseDate(s);
      if (!b) return DATE_ERR;
      const now = new Date();
      if (b > now) return { error: "Birthdate is in the future." };
      let y = now.getFullYear() - b.getFullYear();
      let m = now.getMonth() - b.getMonth();
      let d2 = now.getDate() - b.getDate();
      if (d2 < 0) { m--; d2 += daysInMonth(now.getFullYear(), now.getMonth() - 1); }
      if (m < 0) { y--; m += 12; }
      const totalDays = Math.floor((now - b) / 86400000);
      return y + " years, " + m + " months, " + d2 + " days\nTotal days: " + totalDays;
    }
  },
  {
    id: "dt-countdown", name: "Countdown to a Date", cat: "datetime",
    desc: "Show the time remaining until a future date/time.",
    tags: ["countdown", "remaining", "future"],
    inputs: [{ k: "x", label: "Target date/time", type: "text", placeholder: "2027-01-01 00:00" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const t = parseDate(s);
      if (!t) return DATE_ERR;
      const diff = t - Date.now();
      if (diff <= 0) return "That moment has passed (" + humanizeDuration(-Math.floor(diff / 1000)) + " ago).";
      return "Time remaining: " + humanizeDuration(Math.floor(diff / 1000));
    }
  },
  {
    id: "dt-cron-describe", name: "Cron Expression Describer", cat: "datetime",
    desc: "Describe a standard 5-field cron expression in plain terms.",
    tags: ["cron", "schedule", "describe"],
    inputs: [{ k: "x", label: "Cron (5 fields)", type: "text", placeholder: "*/15 9-17 * * 1-5" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const f = s.split(/\s+/);
      if (f.length !== 5) return { error: "Enter a standard 5-field cron: minute hour day-of-month month day-of-week." };
      const mins = cronField(f[0], 0, 59), hrs = cronField(f[1], 0, 23), dom = cronField(f[2], 1, 31),
        mon = cronField(f[3], 1, 12), dow = cronField(f[4], 0, 6);
      if (!mins || !hrs || !dom || !mon || !dow) return { error: "Invalid cron field. Use *, ranges (1-5), lists (1,3), or steps (*/5)." };
      const list = (set, full) => set.size === full ? "every" : [...set].sort((a, b) => a - b).join(",");
      return "cron: " + s + "\nAt minute " + list(mins, 60) + ", hour " + list(hrs, 24) +
        ", day-of-month " + list(dom, 31) + ", month " + list(mon, 12) +
        ", day-of-week " + list(dow, 7) + "\n(day-of-week: 0=Sun ... 6=Sat)";
    }
  },
  {
    id: "dt-cron-next", name: "Next Cron Runs", cat: "datetime",
    desc: "List the next N run times for a standard 5-field cron expression.",
    tags: ["cron", "schedule", "next"],
    inputs: [
      { k: "x", label: "Cron (5 fields)", type: "text", placeholder: "0 9 * * 1-5" },
      { k: "n", label: "How many", type: "text", inputType: "number", placeholder: "5" }
    ],
    run(v, H) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const f = s.split(/\s+/);
      if (f.length !== 5) return { error: "Enter a standard 5-field cron." };
      const mins = cronField(f[0], 0, 59), hrs = cronField(f[1], 0, 23), dom = cronField(f[2], 1, 31),
        mon = cronField(f[3], 1, 12), dow = cronField(f[4], 0, 6);
      if (!mins || !hrs || !dom || !mon || !dow) return { error: "Invalid cron field." };
      const n = (H && H.clampInt) ? H.clampInt(v.n, 1, 20, 5) : Math.min(20, Math.max(1, parseInt(v.n || "5", 10) || 5));
      const out = [];
      let t = new Date(); t.setSeconds(0, 0); t.setMinutes(t.getMinutes() + 1);
      let guard = 0;
      const domR = dom.size !== 31, dowR = dow.size !== 7;
      while (out.length < n && guard < 600000) {
        let match = mins.has(t.getMinutes()) && hrs.has(t.getHours()) && mon.has(t.getMonth() + 1);
        if (match) {
          const dm = dom.has(t.getDate()), dw = dow.has(t.getDay());
          match = (domR && dowR) ? (dm || dw) : domR ? dm : dowR ? dw : true;
        }
        if (match) out.push(formatPattern(t, "YYYY-MM-DD HH:mm") + " " + WEEKDAYS[t.getDay()].slice(0, 3));
        t = new Date(t.getTime() + 60000); guard++;
      }
      if (!out.length) return "No runs found within the search window.";
      return out.join("\n");
    }
  },
  {
    id: "dt-business-days", name: "Business Days Between Dates", cat: "datetime",
    desc: "Count business days (Mon-Fri) between two dates, inclusive of both ends.",
    tags: ["business", "weekdays", "between"],
    inputs: [
      { k: "a", label: "First date", type: "text", placeholder: "2026-09-01" },
      { k: "b", label: "Second date", type: "text", placeholder: "2026-09-30" }
    ],
    run(v) {
      const A = (v.a || "").trim(), B = (v.b || "").trim();
      if (!A || !B) return "";
      const da = parseDate(A), db = parseDate(B);
      if (!da || !db) return DATE_ERR;
      let start = new Date(Date.UTC(da.getFullYear(), da.getMonth(), da.getDate()));
      let end = new Date(Date.UTC(db.getFullYear(), db.getMonth(), db.getDate()));
      if (start > end) { const t = start; start = end; end = t; }
      let count = 0, cur = new Date(start), guard = 0;
      while (cur <= end && guard < 400000) {
        const wd = cur.getUTCDay();
        if (wd !== 0 && wd !== 6) count++;
        cur = new Date(cur.getTime() + 86400000); guard++;
      }
      return count + " business days (inclusive, Sat/Sun excluded).";
    }
  },
  {
    id: "dt-quarter", name: "Quarter of the Year", cat: "datetime",
    desc: "Return the calendar quarter (Q1-Q4) for a date.",
    tags: ["quarter", "fiscal", "date"],
    inputs: [{ k: "x", label: "Date", type: "text", placeholder: "2026-09-25" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const d = parseDate(s);
      if (!d) return DATE_ERR;
      const q = Math.floor(d.getMonth() / 3) + 1;
      return "Q" + q + " " + d.getFullYear();
    }
  },
  {
    id: "dt-relative-time", name: "Relative Time", cat: "datetime",
    desc: "Express how long ago (or ahead) a timestamp is, like '2 hours ago'.",
    tags: ["relative", "ago", "humanize"],
    inputs: [{ k: "x", label: "Date/time or unix", type: "text", placeholder: "2026-09-25 12:00" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const d = parseDate(s);
      if (!d) return DATE_ERR;
      const diff = Date.now() - d.getTime();
      const sec = Math.floor(Math.abs(diff) / 1000);
      let unit, val;
      if (sec < 60) { val = sec; unit = "second"; }
      else if (sec < 3600) { val = Math.floor(sec / 60); unit = "minute"; }
      else if (sec < 86400) { val = Math.floor(sec / 3600); unit = "hour"; }
      else if (sec < 2592000) { val = Math.floor(sec / 86400); unit = "day"; }
      else if (sec < 31536000) { val = Math.floor(sec / 2592000); unit = "month"; }
      else { val = Math.floor(sec / 31536000); unit = "year"; }
      const p = val === 1 ? "" : "s";
      return diff >= 0 ? val + " " + unit + p + " ago" : "in " + val + " " + unit + p;
    }
  },
  {
    id: "dt-weekday-name", name: "Weekday Name from Number", cat: "datetime",
    desc: "Return the weekday name for a number (0=Sunday ... 6=Saturday).",
    tags: ["weekday", "name", "number"],
    inputs: [{ k: "x", label: "Number 0-6", type: "text", inputType: "number", placeholder: "1" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const n = parseInt(s, 10);
      if (isNaN(n) || n < 0 || n > 6) return { error: "Enter 0-6 (0=Sunday ... 6=Saturday)." };
      return WEEKDAYS[n];
    }
  },
  {
    id: "dt-month-name", name: "Month Name from Number", cat: "datetime",
    desc: "Return the month name for a number (1=January ... 12=December).",
    tags: ["month", "name", "number"],
    inputs: [{ k: "x", label: "Number 1-12", type: "text", inputType: "number", placeholder: "9" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const n = parseInt(s, 10);
      if (isNaN(n) || n < 1 || n > 12) return { error: "Enter 1-12." };
      return MONTHS[n - 1];
    }
  },
  {
    id: "dt-seconds-to-hms", name: "Seconds to HH:MM:SS", cat: "datetime",
    desc: "Convert a number of seconds to an HH:MM:SS clock string.",
    tags: ["seconds", "clock", "hms"],
    inputs: [{ k: "x", label: "Seconds", type: "text", inputType: "number", placeholder: "3725" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      if (!/^-?\d+(\.\d+)?$/.test(s)) return { error: "Enter a number of seconds." };
      let sec = Math.floor(Math.abs(parseFloat(s)));
      const neg = parseFloat(s) < 0;
      const h = Math.floor(sec / 3600); sec %= 3600;
      const m = Math.floor(sec / 60); const s2 = sec % 60;
      return (neg ? "-" : "") + pad(h) + ":" + pad(m) + ":" + pad(s2);
    }
  },
  {
    id: "dt-hms-to-seconds", name: "HH:MM:SS to Seconds", cat: "datetime",
    desc: "Convert an HH:MM:SS or MM:SS clock string to total seconds.",
    tags: ["clock", "seconds", "hms"],
    inputs: [{ k: "x", label: "Clock time", type: "text", placeholder: "01:02:05" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const parts = s.split(":").map(x => x.trim());
      if (parts.length < 2 || parts.length > 3 || parts.some(p => !/^\d+$/.test(p)))
        return { error: "Enter time as HH:MM:SS or MM:SS." };
      let h = 0, m = 0, sec = 0;
      if (parts.length === 3) { h = +parts[0]; m = +parts[1]; sec = +parts[2]; }
      else { m = +parts[0]; sec = +parts[1]; }
      return (h * 3600 + m * 60 + sec) + " seconds";
    }
  },
  {
    id: "dt-12h-to-24h", name: "12-Hour to 24-Hour Time", cat: "datetime",
    desc: "Convert a 12-hour time with AM/PM to 24-hour format.",
    tags: ["12h", "24h", "time", "convert"],
    inputs: [{ k: "x", label: "12-hour time", type: "text", placeholder: "02:30 PM" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const m = /^(\d{1,2}):(\d{2})(?::(\d{2}))?\s*([APap][Mm])$/.exec(s);
      if (!m) return { error: "Enter time like 02:30 PM." };
      let h = +m[1]; const mi = +m[2]; const se = m[3] ? +m[3] : 0;
      if (h < 1 || h > 12 || mi > 59 || se > 59) return { error: "Invalid 12-hour time." };
      const pm = /p/i.test(m[4]);
      if (h === 12) h = 0;
      if (pm) h += 12;
      return pad(h) + ":" + pad(mi) + (m[3] ? ":" + pad(se) : "");
    }
  },
  {
    id: "dt-24h-to-12h", name: "24-Hour to 12-Hour Time", cat: "datetime",
    desc: "Convert a 24-hour time to 12-hour format with AM/PM.",
    tags: ["24h", "12h", "time", "convert"],
    inputs: [{ k: "x", label: "24-hour time", type: "text", placeholder: "14:30" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const m = /^(\d{1,2}):(\d{2})(?::(\d{2}))?$/.exec(s);
      if (!m) return { error: "Enter time like 14:30." };
      const h = +m[1]; const mi = +m[2]; const se = m[3] ? +m[3] : 0;
      if (h > 23 || mi > 59 || se > 59) return { error: "Invalid 24-hour time." };
      const ap = h < 12 ? "AM" : "PM";
      let h12 = h % 12; if (h12 === 0) h12 = 12;
      return h12 + ":" + pad(mi) + (m[3] ? ":" + pad(se) : "") + " " + ap;
    }
  },
  {
    id: "dt-epoch-units", name: "Epoch in Multiple Units", cat: "datetime",
    desc: "Show a date/time as Unix seconds, milliseconds, microseconds and nanoseconds.",
    tags: ["epoch", "units", "convert"],
    inputs: [{ k: "x", label: "Date/time or unix", type: "text", placeholder: "2026-09-25 14:30" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const d = parseDate(s);
      if (!d) return DATE_ERR;
      const ms = d.getTime();
      return "Seconds:      " + Math.floor(ms / 1000) + "\nMilliseconds: " + ms +
        "\nMicroseconds: " + (ms * 1000) + "\nNanoseconds:  " + (ms * 1000000);
    }
  },
  {
    id: "dt-julian-day", name: "Julian Day Number", cat: "datetime",
    desc: "Compute the Julian Day Number and Julian Date for a calendar date.",
    tags: ["julian", "jdn", "astronomy"],
    inputs: [{ k: "x", label: "Date/time", type: "text", placeholder: "2026-09-25 12:00" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const d = parseAsUTC(s) || parseDate(s);
      if (!d) return DATE_ERR;
      const jdn = toJDN(d.getUTCFullYear(), d.getUTCMonth() + 1, d.getUTCDate());
      const jd = jdn + (d.getUTCHours() - 12) / 24 + d.getUTCMinutes() / 1440 + d.getUTCSeconds() / 86400;
      return "Julian Day Number: " + jdn + "\nJulian Date: " + jd.toFixed(5);
    }
  },
  {
    id: "dt-from-julian", name: "Date from Julian Day", cat: "datetime",
    desc: "Convert a Julian Day Number back to a Gregorian calendar date.",
    tags: ["julian", "jdn", "convert"],
    inputs: [{ k: "x", label: "Julian Day Number", type: "text", inputType: "number", placeholder: "2461309" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const n = parseInt(s, 10);
      if (isNaN(n)) return { error: "Enter a Julian Day Number, e.g. 2461309." };
      const r = fromJDN(n);
      return r.year + "-" + pad(r.month) + "-" + pad(r.day);
    }
  },
  {
    id: "dt-days-until-weekday", name: "Days Until Next Weekday", cat: "datetime",
    desc: "Days from today until the next occurrence of a given weekday.",
    tags: ["weekday", "until", "next"],
    inputs: [{ k: "x", label: "Weekday 0-6", type: "text", inputType: "number", placeholder: "5" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const n = parseInt(s, 10);
      if (isNaN(n) || n < 0 || n > 6) return { error: "Enter 0-6 (0=Sunday ... 6=Saturday)." };
      const cur = new Date().getDay();
      let diff = (n - cur + 7) % 7;
      if (diff === 0) diff = 7;
      return diff + " day(s) until the next " + WEEKDAYS[n] + ".";
    }
  },
  {
    id: "dt-days-until-date", name: "Days Until a Date", cat: "datetime",
    desc: "Number of whole days from today until a target date.",
    tags: ["until", "days", "countdown"],
    inputs: [{ k: "x", label: "Target date", type: "text", placeholder: "2027-01-01" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const t = parseDate(s);
      if (!t) return DATE_ERR;
      const today = new Date();
      const a = Date.UTC(today.getFullYear(), today.getMonth(), today.getDate());
      const b = Date.UTC(t.getFullYear(), t.getMonth(), t.getDate());
      const days = Math.round((b - a) / 86400000);
      if (days < 0) return Math.abs(days) + " day(s) ago.";
      if (days === 0) return "That date is today.";
      return days + " day(s) until " + formatPattern(t, "YYYY-MM-DD") + ".";
    }
  },
  {
    id: "dt-add-business-days", name: "Add Business Days", cat: "datetime",
    desc: "Add (or subtract) a number of business days to a date, skipping weekends.",
    tags: ["business", "add", "weekdays"],
    inputs: [
      { k: "x", label: "Start date", type: "text", placeholder: "2026-09-25" },
      { k: "n", label: "Business days", type: "text", inputType: "number", placeholder: "10" }
    ],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const d = parseDate(s);
      if (!d) return DATE_ERR;
      const nRaw = (v.n || "").trim();
      const n = parseInt(nRaw, 10);
      if (nRaw && isNaN(n)) return { error: "Enter a whole number of business days." };
      let count = Math.abs(n || 0);
      const dir = (n || 0) < 0 ? -1 : 1;
      let cur = new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()));
      let guard = 0;
      while (count > 0 && guard < 200000) {
        cur = new Date(cur.getTime() + dir * 86400000);
        const wd = cur.getUTCDay();
        if (wd !== 0 && wd !== 6) count--;
        guard++;
      }
      return cur.getUTCFullYear() + "-" + pad(cur.getUTCMonth() + 1) + "-" + pad(cur.getUTCDate()) +
        " (" + WEEKDAYS[cur.getUTCDay()] + ")";
    }
  },
  {
    id: "dt-rfc2822", name: "Unix to RFC 2822 Date", cat: "datetime",
    desc: "Format a date/time as an RFC 2822 date string (UTC).",
    tags: ["rfc2822", "format", "utc"],
    inputs: [{ k: "x", label: "Date/time or unix", type: "text", placeholder: "1700000000" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const d = parseDate(s);
      if (!d) return DATE_ERR;
      const dn = WEEKDAYS[d.getUTCDay()].slice(0, 3);
      const mn = MONTHS[d.getUTCMonth()].slice(0, 3);
      return dn + ", " + pad(d.getUTCDate()) + " " + mn + " " + d.getUTCFullYear() + " " +
        pad(d.getUTCHours()) + ":" + pad(d.getUTCMinutes()) + ":" + pad(d.getUTCSeconds()) + " +0000";
    }
  },
  {
    id: "dt-to-iso8601", name: "Unix to ISO 8601", cat: "datetime",
    desc: "Format a date/time or Unix timestamp as an ISO 8601 UTC string.",
    tags: ["iso", "format", "utc"],
    inputs: [{ k: "x", label: "Date/time or unix", type: "text", placeholder: "1700000000" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const d = parseDate(s);
      if (!d) return DATE_ERR;
      return d.toISOString();
    }
  },
  {
    id: "dt-week-bounds", name: "Week Start and End", cat: "datetime",
    desc: "Return the start and end of the week containing a date.",
    tags: ["week", "bounds", "start", "end"],
    inputs: [
      { k: "x", label: "Date", type: "text", placeholder: "2026-09-25" },
      { k: "start", type: "select", opts: ["monday", "sunday"], value: "monday" }
    ],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const d = parseDate(s);
      if (!d) return DATE_ERR;
      const startMon = (v.start || "monday") === "monday";
      const day = d.getDay();
      const diffToStart = startMon ? ((day + 6) % 7) : day;
      const s0 = new Date(d); s0.setDate(d.getDate() - diffToStart); s0.setHours(0, 0, 0, 0);
      const e0 = new Date(s0); e0.setDate(s0.getDate() + 6); e0.setHours(23, 59, 59, 999);
      return "Week start: " + formatPattern(s0, "YYYY-MM-DD dddd") +
        "\nWeek end:   " + formatPattern(e0, "YYYY-MM-DD dddd");
    }
  },
  {
    id: "dt-month-bounds", name: "Start and End of Month", cat: "datetime",
    desc: "Return the first and last moments of the month containing a date.",
    tags: ["month", "bounds", "start", "end"],
    inputs: [{ k: "x", label: "Date", type: "text", placeholder: "2026-09-25" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const d = parseDate(s);
      if (!d) return DATE_ERR;
      const s0 = new Date(d.getFullYear(), d.getMonth(), 1, 0, 0, 0, 0);
      const e0 = new Date(d.getFullYear(), d.getMonth() + 1, 0, 23, 59, 59, 999);
      return "Month start: " + formatPattern(s0, "YYYY-MM-DD HH:mm:ss") +
        "\nMonth end:   " + formatPattern(e0, "YYYY-MM-DD HH:mm:ss");
    }
  },
  {
    id: "dt-day-bounds", name: "Start and End of Day", cat: "datetime",
    desc: "Return the start (00:00:00) and end (23:59:59.999) of a date's day.",
    tags: ["day", "bounds", "start", "end"],
    inputs: [{ k: "x", label: "Date", type: "text", placeholder: "2026-09-25" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const d = parseDate(s);
      if (!d) return DATE_ERR;
      const s0 = new Date(d); s0.setHours(0, 0, 0, 0);
      const e0 = new Date(d); e0.setHours(23, 59, 59, 999);
      return "Day start: " + s0.toString() + "\nDay end:   " + e0.toString();
    }
  },
  {
    id: "dt-minutes-since-midnight", name: "Minutes Since Midnight", cat: "datetime",
    desc: "Compute how many minutes have elapsed since midnight for a time.",
    tags: ["minutes", "midnight", "time"],
    inputs: [{ k: "x", label: "Time or date/time", type: "text", placeholder: "14:30" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const tm = /^(\d{1,2}):(\d{2})(?::(\d{2}))?$/.exec(s);
      let h, mi;
      if (tm) {
        h = +tm[1]; mi = +tm[2];
        if (h > 23 || mi > 59) return { error: "Enter a valid time like 14:30." };
      } else {
        const d = parseDate(s);
        if (!d) return DATE_ERR;
        h = d.getHours(); mi = d.getMinutes();
      }
      return (h * 60 + mi) + " minutes since midnight";
    }
  },
  {
    id: "dt-decimal-hours", name: "Decimal Hours and HH:MM", cat: "datetime",
    desc: "Convert between decimal hours and HH:MM clock time.",
    tags: ["decimal", "hours", "convert"],
    inputs: [
      { k: "x", label: "Value", type: "text", placeholder: "2.5 or 02:30" },
      { k: "mode", type: "select", opts: [["to-hms", "decimal to HH:MM"], ["to-decimal", "HH:MM to decimal"]], value: "to-hms" }
    ],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const mode = v.mode || "to-hms";
      if (mode === "to-hms") {
        if (!/^-?\d+(\.\d+)?$/.test(s)) return { error: "Enter decimal hours, e.g. 2.5." };
        const dec = parseFloat(s);
        const neg = dec < 0; const abs = Math.abs(dec);
        let h = Math.floor(abs); let m = Math.round((abs - h) * 60);
        if (m === 60) { h++; m = 0; }
        return (neg ? "-" : "") + pad(h) + ":" + pad(m);
      }
      const m = /^(\d{1,2}):(\d{2})$/.exec(s);
      if (!m) return { error: "Enter time like 02:30." };
      const hh = +m[1], mm = +m[2];
      if (mm > 59) return { error: "Minutes must be 0-59." };
      return (hh + mm / 60).toFixed(4) + " hours";
    }
  },
  {
    id: "dt-diff-humanized", name: "Timestamp Difference Humanized", cat: "datetime",
    desc: "Show the difference between two dates as a human duration.",
    tags: ["difference", "humanize", "duration"],
    inputs: [
      { k: "a", label: "First date", type: "text", placeholder: "2026-01-01 08:00" },
      { k: "b", label: "Second date", type: "text", placeholder: "2026-01-02 10:30" }
    ],
    run(v) {
      const A = (v.a || "").trim(), B = (v.b || "").trim();
      if (!A || !B) return "";
      const da = parseDate(A), db = parseDate(B);
      if (!da || !db) return DATE_ERR;
      const sec = Math.floor(Math.abs(db - da) / 1000);
      return humanizeDuration(sec) + " (" + (da <= db ? "second is later" : "first is later") + ")";
    }
  },
  {
    id: "dt-is-weekend", name: "Is Weekend", cat: "datetime",
    desc: "Determine whether a date falls on a weekend.",
    tags: ["weekend", "weekday", "date"],
    inputs: [{ k: "x", label: "Date", type: "text", placeholder: "2026-09-26" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const d = parseDate(s);
      if (!d) return DATE_ERR;
      const wd = d.getDay();
      return (wd === 0 || wd === 6)
        ? WEEKDAYS[wd] + " — yes, it's a weekend."
        : WEEKDAYS[wd] + " — no, it's a weekday.";
    }
  },
  {
    id: "dt-next-weekday", name: "Next Occurrence of a Weekday", cat: "datetime",
    desc: "Return the date of the next occurrence of a weekday, optionally from a start date.",
    tags: ["weekday", "next", "occurrence"],
    inputs: [
      { k: "x", label: "Weekday 0-6", type: "text", inputType: "number", placeholder: "1" },
      { k: "from", label: "From date (optional)", type: "text", placeholder: "2026-09-25" }
    ],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const n = parseInt(s, 10);
      if (isNaN(n) || n < 0 || n > 6) return { error: "Enter 0-6 (0=Sunday ... 6=Saturday)." };
      let base;
      if ((v.from || "").trim()) {
        base = parseDate(v.from);
        if (!base) return DATE_ERR;
      } else base = new Date();
      let diff = (n - base.getDay() + 7) % 7;
      if (diff === 0) diff = 7;
      const res = new Date(base); res.setDate(base.getDate() + diff);
      return "Next " + WEEKDAYS[n] + ": " + formatPattern(res, "YYYY-MM-DD");
    }
  },
  {
    id: "dt-ordinal-date", name: "Ordinal Date", cat: "datetime",
    desc: "Return the day of month with an ordinal suffix (1st, 2nd, 3rd...).",
    tags: ["ordinal", "day", "suffix"],
    inputs: [{ k: "x", label: "Date or day number", type: "text", placeholder: "2026-09-01 or 1" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      if (/^\d{1,2}$/.test(s)) {
        const n = parseInt(s, 10);
        if (n < 1 || n > 31) return { error: "Enter a day 1-31 or a full date." };
        return n + ordinalSuffix(n);
      }
      const d = parseDate(s);
      if (!d) return DATE_ERR;
      const day = d.getDate();
      return day + ordinalSuffix(day) + " of " + MONTHS[d.getMonth()] + " " + d.getFullYear();
    }
  },
  {
    id: "dt-season", name: "Season for a Date", cat: "datetime",
    desc: "Return the astronomical season (Northern Hemisphere) for a date.",
    tags: ["season", "hemisphere", "date"],
    inputs: [{ k: "x", label: "Date", type: "text", placeholder: "2026-09-25" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const d = parseDate(s);
      if (!d) return DATE_ERR;
      return seasonName(d.getMonth() + 1, d.getDate()) + " (Northern Hemisphere)";
    }
  },
  {
    id: "dt-moon-phase", name: "Moon Phase Approximation", cat: "datetime",
    desc: "Approximate the lunar phase and illumination for a date.",
    tags: ["moon", "phase", "astronomy"],
    inputs: [{ k: "x", label: "Date", type: "text", placeholder: "2026-09-25" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const d = parseAsUTC(s) || parseDate(s);
      if (!d) return DATE_ERR;
      const jd = toJDN(d.getUTCFullYear(), d.getUTCMonth() + 1, d.getUTCDate()) + (d.getUTCHours() - 12) / 24;
      const synodic = 29.530588853;
      let phase = ((jd - 2451550.1) / synodic) % 1;
      if (phase < 0) phase += 1;
      const names = ["New Moon", "Waxing Crescent", "First Quarter", "Waxing Gibbous",
        "Full Moon", "Waning Gibbous", "Last Quarter", "Waning Crescent"];
      const idx = Math.floor(phase * 8 + 0.5) % 8;
      const illum = (1 - Math.cos(2 * Math.PI * phase)) / 2 * 100;
      return names[idx] + "\nAge: " + (phase * synodic).toFixed(1) + " days\nIllumination: ~" + illum.toFixed(0) + "%";
    }
  },
  {
    id: "dt-tz-abbrev-table", name: "Timezone Abbreviation Table", cat: "datetime",
    desc: "A reference table of timezone abbreviations and their UTC offsets.",
    tags: ["timezone", "abbreviation", "reference"],
    inputs: [],
    run() {
      const rows = [
        ["UTC", "+00:00", "Coordinated Universal Time"], ["GMT", "+00:00", "Greenwich Mean Time"],
        ["EST", "-05:00", "Eastern Standard"], ["EDT", "-04:00", "Eastern Daylight"],
        ["CST", "-06:00", "Central Standard"], ["CDT", "-05:00", "Central Daylight"],
        ["MST", "-07:00", "Mountain Standard"], ["PST", "-08:00", "Pacific Standard"],
        ["PDT", "-07:00", "Pacific Daylight"], ["CET", "+01:00", "Central European"],
        ["EET", "+02:00", "Eastern European"], ["IST", "+05:30", "India Standard"],
        ["JST", "+09:00", "Japan Standard"], ["AEST", "+10:00", "Australian Eastern"],
        ["NZST", "+12:00", "New Zealand Standard"]
      ];
      return rows.map(r => r[0].padEnd(5) + " " + r[1] + "  " + r[2]).join("\n");
    }
  },
  {
    id: "dt-now-hex", name: "Unix Time Now in Hex", cat: "datetime",
    desc: "Show the current Unix time in decimal and hexadecimal.",
    tags: ["now", "hex", "unix"],
    inputs: [],
    run() {
      const secs = Math.floor(Date.now() / 1000);
      const ms = Date.now();
      return "Unix seconds: " + secs + "\nHex (seconds): 0x" + secs.toString(16) +
        "\nUnix millis: " + ms + "\nHex (millis): 0x" + ms.toString(16);
    }
  },
  {
    id: "dt-seconds-breakdown", name: "Seconds to Weeks/Days Breakdown", cat: "datetime",
    desc: "Break a number of seconds into weeks, days, hours, minutes and seconds.",
    tags: ["seconds", "breakdown", "weeks"],
    inputs: [{ k: "x", label: "Seconds", type: "text", inputType: "number", placeholder: "1000000" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      if (!/^-?\d+(\.\d+)?$/.test(s)) return { error: "Enter a number of seconds." };
      let sec = Math.floor(Math.abs(parseFloat(s)));
      const w = Math.floor(sec / 604800); sec %= 604800;
      const d = Math.floor(sec / 86400); sec %= 86400;
      const h = Math.floor(sec / 3600); sec %= 3600;
      const m = Math.floor(sec / 60); const s2 = sec % 60;
      return w + " weeks, " + d + " days, " + h + " hours, " + m + " minutes, " + s2 + " seconds";
    }
  },
  {
    id: "dt-millis-humanize", name: "Milliseconds to Human", cat: "datetime",
    desc: "Convert a number of milliseconds to a human-readable duration.",
    tags: ["millis", "humanize", "duration"],
    inputs: [{ k: "x", label: "Milliseconds", type: "text", inputType: "number", placeholder: "93784000" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      if (!/^-?\d+(\.\d+)?$/.test(s)) return { error: "Enter a number of milliseconds." };
      const ms = Math.floor(parseFloat(s));
      const sec = Math.floor(ms / 1000);
      const rem = Math.abs(ms % 1000);
      return humanizeDuration(sec) + (rem ? " " + rem + "ms" : "");
    }
  },
  {
    id: "dt-nanos-to-seconds", name: "Nanoseconds to Seconds", cat: "datetime",
    desc: "Convert nanoseconds to seconds and milliseconds.",
    tags: ["nanoseconds", "seconds", "convert"],
    inputs: [{ k: "x", label: "Nanoseconds", type: "text", inputType: "number", placeholder: "1500000000" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      if (!/^-?\d+(\.\d+)?$/.test(s)) return { error: "Enter a number of nanoseconds." };
      const ns = parseFloat(s);
      return "Seconds:      " + (ns / 1e9) + "\nMilliseconds: " + (ns / 1e6) + "\nMicroseconds: " + (ns / 1e3);
    }
  },
  {
    id: "dt-stopwatch-splits", name: "Stopwatch Split Calculator", cat: "datetime",
    desc: "Given lap times in seconds (one per line or comma-separated), compute cumulative totals.",
    tags: ["stopwatch", "splits", "laps"],
    inputs: [{ k: "text", type: "textarea", rows: 6, placeholder: "12.4\n11.9\n13.1" }],
    run(v) {
      const s = (v.text || "").trim();
      if (!s) return "";
      const laps = s.split(/[\s,]+/).filter(Boolean);
      const nums = [];
      for (const l of laps) {
        if (!/^-?\d+(\.\d+)?$/.test(l)) return { error: "Each lap must be a number of seconds, e.g. 12.4." };
        nums.push(parseFloat(l));
      }
      let cum = 0;
      const out = nums.map((n, i) => {
        cum += n;
        return "Lap " + (i + 1) + ": " + n + "s   cumulative " + cum.toFixed(3) + "s";
      });
      const avg = cum / nums.length;
      out.push("---");
      out.push("Total: " + cum.toFixed(3) + "s  (" + humanizeDuration(cum) + ")");
      out.push("Average lap: " + avg.toFixed(3) + "s");
      out.push("Fastest: " + Math.min(...nums) + "s   Slowest: " + Math.max(...nums) + "s");
      return out.join("\n");
    }
  },
  {
    id: "dt-meeting-times", name: "Meeting Time Across Offsets", cat: "datetime",
    desc: "Given a time in a source offset, show the local time in a list of target offsets.",
    tags: ["meeting", "timezone", "offset"],
    inputs: [
      { k: "x", label: "Time (source zone)", type: "text", placeholder: "2026-09-25 09:00" },
      { k: "from", label: "Source offset", type: "text", placeholder: "-05:00" },
      { k: "to", label: "Target offsets (comma)", type: "text", placeholder: "+00:00, +05:30, +09:00" }
    ],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const base = parseAsUTC(s);
      if (!base) return DATE_ERR;
      const fromOff = parseOffset(v.from || "");
      if ((v.from || "").trim() && fromOff === null) return { error: "Enter a source offset like -05:00." };
      const utc = new Date(base.getTime() - (fromOff || 0) * 60000);
      const targets = (v.to || "").split(",").map(x => x.trim()).filter(Boolean);
      if (!targets.length) return "UTC: " + isoUTC(utc);
      const out = ["Source " + offsetLabel(fromOff || 0) + ": " + isoUTC(base), "UTC: " + isoUTC(utc), "---"];
      for (const t of targets) {
        const off = parseOffset(t);
        if (off === null) return { error: "Invalid target offset: " + t };
        const local = new Date(utc.getTime() + off * 60000);
        out.push(offsetLabel(off) + ": " + isoUTC(local) + " " + WEEKDAYS[local.getUTCDay()].slice(0, 3));
      }
      return out.join("\n");
    }
  },
  {
    id: "dt-days-since", name: "Days Since Counter", cat: "datetime",
    desc: "Count whole days elapsed since a past date.",
    tags: ["since", "days", "elapsed"],
    inputs: [{ k: "x", label: "Past date", type: "text", placeholder: "2020-01-01" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const d = parseDate(s);
      if (!d) return DATE_ERR;
      const today = new Date();
      const a = Date.UTC(d.getFullYear(), d.getMonth(), d.getDate());
      const b = Date.UTC(today.getFullYear(), today.getMonth(), today.getDate());
      const days = Math.round((b - a) / 86400000);
      if (days < 0) return "That date is " + Math.abs(days) + " day(s) in the future.";
      return days + " day(s) since " + formatPattern(d, "YYYY-MM-DD") + ".";
    }
  },
  {
    id: "dt-date-validator", name: "Date Validator", cat: "datetime",
    desc: "Check whether a YYYY-MM-DD string is a real calendar date.",
    tags: ["validate", "date", "calendar"],
    inputs: [{ k: "x", label: "Date (YYYY-MM-DD)", type: "text", placeholder: "2026-02-29" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const m = /^(\d{4})-(\d{1,2})-(\d{1,2})$/.exec(s);
      if (!m) return { error: "Enter a date as YYYY-MM-DD." };
      const y = +m[1], mo = +m[2], da = +m[3];
      if (mo < 1 || mo > 12) return "Not a real date - month " + mo + " is out of range (1-12).";
      const dim = daysInMonth(y, mo - 1);
      if (da < 1 || da > dim) return "Not a real date - " + MONTHS[mo - 1] + " " + y + " has " + dim + " days, got day " + da + ".";
      return "Real date - " + formatPattern(new Date(y, mo - 1, da), "YYYY-MM-DD dddd") + ".";
    }
  },
  {
    id: "dt-days-in-year", name: "Days in Year", cat: "datetime",
    desc: "Return the number of days in a given year (365 or 366).",
    tags: ["days", "year", "leap"],
    inputs: [{ k: "x", label: "Year", type: "text", inputType: "number", placeholder: "2028" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const y = parseInt(s, 10);
      if (isNaN(y)) return { error: "Enter a year, e.g. 2028." };
      return (isLeap(y) ? 366 : 365) + " days in " + y;
    }
  },
  {
    id: "dt-weeks-in-year", name: "ISO Weeks in Year", cat: "datetime",
    desc: "Return the number of ISO-8601 weeks (52 or 53) in a given year.",
    tags: ["iso", "weeks", "year"],
    inputs: [{ k: "x", label: "Year", type: "text", inputType: "number", placeholder: "2026" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const y = parseInt(s, 10);
      if (isNaN(y)) return { error: "Enter a year, e.g. 2026." };
      return weeksInYear(y) + " ISO weeks in " + y;
    }
  },
  {
    id: "dt-percent-of-day", name: "Percent of Day Elapsed", cat: "datetime",
    desc: "Return what percentage of the day has elapsed at a given time.",
    tags: ["percent", "day", "elapsed"],
    inputs: [{ k: "x", label: "Time or date/time", type: "text", placeholder: "14:30" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const tm = /^(\d{1,2}):(\d{2})(?::(\d{2}))?$/.exec(s);
      let secOfDay;
      if (tm) {
        const h = +tm[1], mi = +tm[2], se = tm[3] ? +tm[3] : 0;
        if (h > 23 || mi > 59 || se > 59) return { error: "Enter a valid time like 14:30." };
        secOfDay = h * 3600 + mi * 60 + se;
      } else {
        const d = parseDate(s);
        if (!d) return DATE_ERR;
        secOfDay = d.getHours() * 3600 + d.getMinutes() * 60 + d.getSeconds();
      }
      return (secOfDay / 86400 * 100).toFixed(2) + "% of the day elapsed (" + secOfDay + "s of 86400s)";
    }
  },
  {
    id: "dt-percent-of-year", name: "Percent of Year Elapsed", cat: "datetime",
    desc: "Return what percentage of the year has elapsed on a given date.",
    tags: ["percent", "year", "elapsed"],
    inputs: [{ k: "x", label: "Date/time", type: "text", placeholder: "2026-09-25" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      const d = parseDate(s);
      if (!d) return DATE_ERR;
      const y = d.getFullYear();
      const start = new Date(y, 0, 1).getTime();
      const end = new Date(y + 1, 0, 1).getTime();
      const pct = (d.getTime() - start) / (end - start) * 100;
      return pct.toFixed(2) + "% of " + y + " elapsed";
    }
  },
  {
    id: "dt-next-leap-year", name: "Next Leap Year", cat: "datetime",
    desc: "Find the next leap year on or after a given year.",
    tags: ["leap", "year", "next"],
    inputs: [{ k: "x", label: "From year", type: "text", inputType: "number", placeholder: "2026" }],
    run(v) {
      const s = (v.x || "").trim();
      if (!s) return "";
      let y = parseInt(s, 10);
      if (isNaN(y)) return { error: "Enter a year, e.g. 2026." };
      let guard = 0;
      while (!isLeap(y) && guard < 10) { y++; guard++; }
      return "Next leap year: " + y + (parseInt(s, 10) === y ? " (this year is a leap year)" : "");
    }
  },
  {
    id: "dt-time-until-midnight", name: "Time Until Midnight", cat: "datetime",
    desc: "Return the duration remaining until the next midnight from a time.",
    tags: ["midnight", "remaining", "duration"],
    inputs: [{ k: "x", label: "Time or date/time (blank = now)", type: "text", placeholder: "14:30" }],
    run(v) {
      const s = (v.x || "").trim();
      let secOfDay;
      if (!s) {
        const now = new Date();
        secOfDay = now.getHours() * 3600 + now.getMinutes() * 60 + now.getSeconds();
      } else {
        const tm = /^(\d{1,2}):(\d{2})(?::(\d{2}))?$/.exec(s);
        if (tm) {
          const h = +tm[1], mi = +tm[2], se = tm[3] ? +tm[3] : 0;
          if (h > 23 || mi > 59 || se > 59) return { error: "Enter a valid time like 14:30." };
          secOfDay = h * 3600 + mi * 60 + se;
        } else {
          const d = parseDate(s);
          if (!d) return DATE_ERR;
          secOfDay = d.getHours() * 3600 + d.getMinutes() * 60 + d.getSeconds();
        }
      }
      const rem = 86400 - secOfDay;
      return humanizeDuration(rem) + " until midnight";
    }
  },
  {
    id: "dt-week-to-dates", name: "ISO Week to Date Range", cat: "datetime",
    desc: "Convert an ISO year and week number to its Monday-Sunday date range.",
    tags: ["iso", "week", "range"],
    inputs: [
      { k: "y", label: "ISO year", type: "text", inputType: "number", placeholder: "2026" },
      { k: "w", label: "Week number", type: "text", inputType: "number", placeholder: "39" }
    ],
    run(v) {
      const ys = (v.y || "").trim(), ws = (v.w || "").trim();
      if (!ys || !ws) return "";
      const y = parseInt(ys, 10), w = parseInt(ws, 10);
      if (isNaN(y)) return { error: "Enter an ISO year, e.g. 2026." };
      if (isNaN(w) || w < 1 || w > 53) return { error: "Enter a week number 1-53." };
      const max = weeksInYear(y);
      if (w > max) return { error: y + " has only " + max + " ISO weeks." };
      const start = isoWeekToDate(y, w);
      const end = new Date(start.getTime() + 6 * 86400000);
      const f = (d) => d.getUTCFullYear() + "-" + pad(d.getUTCMonth() + 1) + "-" + pad(d.getUTCDate());
      return "Week " + w + " of " + y + "\nMonday: " + f(start) + "\nSunday: " + f(end);
    }
  }
];

export const TOOLS = [ ...defs ];
