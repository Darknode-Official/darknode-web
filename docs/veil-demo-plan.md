# Veil — a next-generation privacy overlay (demo-area plan)

Codename **VEIL** · *Verifiable Encrypted Isolation Layer*
Status: PROPOSAL / not built · Placement: gated **Labs** demo area, never the main page.

---

## 0. Reality check (read this first)

You asked for something "more powerful, faster, safer and more secure than Tor."
Being honest, because this is a security product and overclaiming here is
genuinely harmful:

- **A website cannot replace Tor.** Tor's anonymity comes from ~8,000 volunteer
  relays, a huge concurrent user set, a decade of academic attack/defence, and a
  hardened fork of Firefox. No page we host can manufacture that anonymity set,
  and a browser tab can't provide network-layer anonymity to its own visitors.
- **What we *can* do, and do impressively:** design a next-gen privacy overlay
  that is genuinely better than Tor on *specific, defensible axes*, and build a
  **real, working browser demo** of it — real modern crypto, real onion
  wrapping, real peer-to-peer relaying over WebRTC — presented as a research
  prototype with honest "real vs simulated" labels and a frank comparison that
  also says where Tor is still stronger.
- The deliverable is therefore **"Veil: a research prototype + interactive
  demo"**, not "the Tor killer." That framing is what makes it credible to the
  security audience, and keeps us legally and ethically clean.

Everything below is designed so each "better than Tor" claim is backed by a real,
measurable, in-browser artefact the user and visitors can poke at.

---

## 1. Positioning & the four claims

| Claim | How Veil actually earns it | Honest tradeoff |
|---|---|---|
| **Safer / more secure** | Post-quantum **hybrid** handshake (X25519 + ML-KEM/Kyber), AEAD everywhere (ChaCha20-Poly1305 / AES-256-GCM), Sphinx-format packets with replay protection, forward secrecy per hop. Tor only recently started PQ work. | More crypto = heavier handshake; mitigated by session reuse. |
| **Stronger anonymity vs traffic analysis** | Optional **mixnet mode**: batched/delayed mixes + constant-rate **cover traffic** + fixed-size cells. Defeats the end-to-end timing correlation that *does* deanonymise low-latency Tor. | Added latency. We expose a live **latency ↔ anonymity slider** so the tradeoff is explicit, not hidden. |
| **Faster** | **QUIC/UDP** transport (no TCP-over-TCP head-of-line blocking, which is Tor's classic slowdown), **multipath** option, 0-RTT session resume, ChaCha on mobile. Demo proves it with real in-browser crypto benchmarks. | "Faster" only in low-latency mode; mixnet mode is deliberately slower. |
| **More powerful / censorship-resistant** | Decentralised **gossip + DHT directory** (no fixed directory authorities to block), **pluggable transports** (domain fronting, WebSocket, WebRTC/Snowflake-style), in-browser relays so any visitor can *be* a bridge. | Decentralised directory is harder to secure against Sybil; we document the defence (stake/vouch + rate limits). |

**Where Tor is still better (we say so, prominently):** anonymity-set size,
relay diversity, years of audits, exit-node ecosystem, mature browser
fingerprinting defences. Veil's demo is a prototype; Tor is production.

---

## 2. Threat model (explicit)

**Defends against:** local network eavesdropper, malicious/observing single
relay, directory-server blocking/censorship, *passive* global timing correlation
(mixnet mode), future quantum "harvest-now-decrypt-later" on captured traffic.

**Does NOT defend against (stated plainly in the UI):** a global *active*
adversary with huge Sybil capacity, browser-level fingerprinting if the user
doesn't use a hardened browser, endpoint compromise, or the fundamental fact
that a small demo network has a tiny anonymity set. The demo is for learning and
evaluating the design — **not** for real-world threat-to-life anonymity. That
warning is non-dismissible on entry.

---

## 3. Architecture (the design we're demoing)

```
 client ──Sphinx packet (fixed cell)──► Mix/Relay 1 ──► Mix 2 ──► Mix 3 ──► gateway
   │  layered AEAD (peel one per hop)        │           │          │
   │  PQ-hybrid session keys per hop         └── cover traffic + batch/delay (mixnet mode)
   └── directory via gossip/DHT, PIR lookup so you don't reveal who you asked about
```

Core components:

1. **Sphinx packet format** — every packet is the same size, carries a layered
   header + payload, each hop learns only prev/next, includes a replay tag.
   This is the single biggest cryptographic upgrade over Tor cells.
2. **PQ-hybrid noise handshake** — `Noise_XK`-style pattern with X25519 **and**
   ML-KEM-768; session key = KDF(both). Breaks only if *both* primitives break.
3. **Transport layer** — pluggable: QUIC (native target), WebRTC DataChannels
   (browser relays), WebSocket (censorship fallback). Fixed-rate padding on top.
4. **Routing modes** — *Express* (low-latency onion, Tor-like, fast) vs *Mix*
   (batched + cover traffic, slow, timing-resistant). User chooses per circuit.
5. **Directory** — decentralised gossip + Kademlia DHT; relay descriptors signed;
   Sybil resistance via vouching + proof-of-resource + rate limiting; lookups via
   simple PIR so the directory can't log who you're routing to.
6. **Relay incentives / health** — bandwidth self-measurement, reputation,
   optional "be a bridge in your browser tab" (WebRTC) to grow the set.

---

## 4. The DEMO (what actually ships in the browser)

A gated **Labs → Veil** area. Five modules, each clearly tagged **[REAL]**
(actually runs) or **[SIM]** (visualised model):

1. **Onion Playground [REAL].** Type a message, pick a 3-hop path. We do real
   WebCrypto: generate per-hop X25519 keys, derive AEAD keys, wrap the payload in
   3 real ChaCha20-Poly1305 / AES-GCM layers, pad to a fixed cell, add replay
   tags. Step through each relay "peeling" exactly one layer. Shows that no single
   hop sees both origin and content. Byte-level inspector included.

2. **PQ Handshake Lab [REAL].** Run the X25519+Kyber hybrid handshake live
   (Kyber via a small audited WASM, e.g. from liboqs/noble). Show both shared
   secrets combining into the session key, and a "harvest-now-decrypt-later"
   explainer. Benchmarks keygen/encaps/decaps in ms right in the page.

3. **Mixnet Simulator [SIM].** Animated network: packets as uniform cells flowing
   through layered mixes, with the **latency ↔ anonymity slider**, cover-traffic
   toggle, and a live **traffic-analysis attack view** — run a timing-correlation
   adversary and watch it succeed in Express mode and fail in Mix mode. This is
   the "why batching+cover beats low-latency onion routing" teaching moment.

4. **WebRTC Relay Mesh [REAL, limited].** Browsers (or local simulated peers)
   form a small onion-routing mesh over real WebRTC DataChannels; route a real
   message through N real hops, each knowing only neighbours. Honest banner: tiny
   set, not real anonymity — it proves the *mechanism*, not the *anonymity-set*.

5. **Veil vs Tor vs VPN [REAL data].** Interactive comparison matrix across
   latency, traffic-analysis resistance, PQ, censorship resistance, metadata
   leakage, trust assumptions, maturity — including the rows where Tor wins, with
   the live crypto benchmarks from modules 1–2 backing the "faster/safer" cells.

All five are self-contained, client-side, dependency-light (WebCrypto + one WASM
for Kyber), and run with no backend beyond static hosting.

---

## 5. Placement, gating & UX

- New route **`/labs`** (a "Darknode Labs" demo hub) — **not linked from the
  landing page**; reachable by direct URL and from an admin/console entry.
  Veil lives at **`/labs/veil`**.
- **Entry gate:** a non-dismissible "research demo, not for real anonymity +
  authorized/educational use" interstitial before first use (stored ack).
- Audience: you (admin) always; "users can see it" → either (a) signed-in users
  via a Labs opt-in flag, or (b) a public but clearly-labelled demo. **Decision
  needed — see §10.**
- Honors existing rules: no emojis, no native dialogs (dnModal/dnToast), dark
  theme, SPA route served by the service worker, `?v=` cache-busting on importers.

---

## 6. How it fits the existing stack

- **Frontend:** SPA module(s) under `public/js/labs/veil/*`, routed like other
  SPA sections; service worker already serves app shell for unknown routes.
- **Crypto:** WebCrypto (X25519, AES-GCM, HKDF) + a vetted WASM/JS Kyber and
  ChaCha20-Poly1305 lib pulled from a permissive, audited source (noble-* /
  liboqs-wasm). No home-rolled primitives — that's a hard rule for a crypto demo.
- **WebRTC mesh:** peer signalling can reuse a tiny Cloudflare Worker endpoint
  (we already run `darknode-proxy`) purely as a signalling relay; no traffic
  content passes through it. Fully optional; local simulated peers work offline.
- **No secrets, no PII**, nothing leaves the browser except WebRTC signalling.

---

## 7. Security, abuse & legal

- **Dual-use:** privacy/PET research and education are legitimate and defensible.
  We frame Veil as an educational research prototype, keep the "authorized/
  educational use" gate, and do **not** build it into a turnkey "evade detection"
  product or ship real exit-proxying from our infrastructure.
- **No open proxy:** the demo never relays arbitrary user traffic through our
  servers (that would create an abuse/liability surface). Mesh relaying is
  peer-to-peer and scoped to demo messages.
- **No home-rolled crypto**; cite every primitive's source; mark the prototype
  as **not audited** wherever keys are shown.
- Clear "this is a prototype, not Tor" language everywhere so no user mistakes it
  for real-world-safe anonymity.

---

## 8. Phased roadmap

- **M0 — Labs shell + gate (small).** `/labs` hub, `/labs/veil` route, entry
  interstitial, honest framing, comparison matrix (static first).
- **M1 — Onion Playground [REAL].** Real layered AEAD + fixed cells + replay tags
  + byte inspector. *This alone is a compelling, shippable demo.*
- **M2 — PQ Handshake Lab [REAL]** + live crypto benchmarks feeding §4.5 matrix.
- **M3 — Mixnet Simulator [SIM]** with the latency/anonymity slider + timing-
  attack visualiser (the "why it beats Tor on traffic analysis" centrepiece).
- **M4 — WebRTC Relay Mesh [REAL, limited]** over real DataChannels.
- **M5 — Polish:** guided tour, export/share a demo run, deep-dive explainers.

Recommended first ship: **M0 + M1** (gate + real onion playground) — smallest
honest slice that already demonstrates the core idea end-to-end.

---

## 9. Risks & open questions

- Kyber-in-WASM size/perf budget (keep the Labs bundle lazy-loaded).
- WebRTC signalling needs the Worker; fine, but adds one moving part — mesh is
  optional so M1–M3 don't depend on it.
- Sybil resistance for the decentralised directory is genuinely hard; in the demo
  it's modelled/explained, not production-solved (stated clearly).
- "Public vs signed-in-only" for the Labs area (§5) — your call.

---

## 10. Decisions I need from you

1. **Audience:** public demo, or signed-in users only (Labs opt-in)?
2. **Scope to build now:** just M0+M1 (gate + real onion playground), or push
   straight through M3 (add PQ lab + mixnet simulator)?
3. **Name:** keep **Veil**, or pick another (Nyx / Umbra / Obsidian Relay)?
4. Route naming: `/labs` + `/labs/veil` ok, or a different hub name?
```
