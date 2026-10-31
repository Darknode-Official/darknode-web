# Darknode Ecosystem — Convergence Decision Record

*Canonical cross-repo record of the "which spine wins" decisions. Owned across all repos
(`darknode-web`, `darknode-app`, `darknode-os-distro`, and the Obsidian research kernel).
The full roadmap lives in `~/.claude/plans/darknode-trident-master-plan.md`.*

Established 2026-10-18 (Phase 0 of the Trident Master Plan).

---

## Thesis

Darknode is **one product expressed at three power levels**, backed by **one honest research line**:

1. **The Deck** (`darknode-web`) — the cloud B2B control plane (team workspace, security graph,
   findings work queue, correlation, server-side monitoring, reporting).
2. **The Desktop App** (`darknode-app`) — the *same Deck UI* packaged to run locally and offline,
   made strictly more capable through a native superset (raw TCP/DNS/TLS, filesystem, PTY, QEMU,
   local Ollama). Never a thin wrapper around the live website.
3. **Darknode OS** (`darknode-os-distro`) — the Deck as a bootable security workstation; the app is
   the native shell.
4. **Obsidian kernel** — a from-scratch 32-bit research kernel, **bounded and boot-verified**, that
   is **never** the shipping OS.

The engines are already pure and server-reusable, so convergence is **incremental, not a rewrite**.
Hard rule everywhere: **no simulations, no fakes, no filler** — anything that can't run for real is
cut, never stubbed.

---

## Spine decisions (binding)

| Concern | THE spine | Demoted / alternate |
|---|---|---|
| **UI** | The **Deck** (`darknode-web/public`) is the one UI, reused in the App and shipped in the OS | The AWS-style console stays live but archived to its own folder (easy to discontinue). The App's classic `renderer/app.js` → compatibility shim, retired only once parity is proven. |
| **OS** | The from-source **`core/`** (Linux 6.12 + BusyBox + Darknode init) is THE OS product | `cloud-init` Debian provisioner → a *documented alternate install target*, not the identity. |
| **Kernel** | The **hardened mainline `core/` kernel** (KSPP + LSM profile, Phase 6) is THE kernel | The from-scratch **Obsidian** kernel → a bounded **research artifact**; add `SCOPE.md` + QEMU boot-smoke CI, then stop. Never described as the shipping OS. |
| **Identity/data** | One **Firebase project + Cloudflare worker** backend for web, App, and OS | — |
| **Engine library** | **Nexus** (`darknode-cli`, clean-room, zero-dep) behind every collector + the CLI | Shipped builds bundle a *versioned, pinned* Nexus (single source of truth), not a stale vendored fork. |

---

## Brand & version

- **Product name:** **Darknode** / **Darknode OS**. `os-release`: `NAME="Darknode OS"`,
  `ID=darknode`, `BUILD_ID=darknode-core` (was `obsidian-core` — fixed; Obsidian ≠ the shipping core).
- **Shipping kernel identity:** `CONFIG_LOCALVERSION="-darknode"` so `uname -r` carries the brand.
- **Research kernel:** **"Obsidian"** — reserved exclusively for the from-scratch kernel.
- **Boot chrome:** GRUB + Plymouth both read `>_ DARKNODE OS` (Plymouth's `SENTINEL OS` residue fixed).
- **Version scheme:** OS `VERSION=1.0`; App semver (`v2.x`, electron-builder `v*` tags); Deck ships
  continuously (SW `vNNN` + `?v=YYYYMMDD<letter>` cache-busters). All release tags are `v*`.
- The `sentinel-*` naming is fully retired (88 toolkit symlinks + cloud-init identity fixed).

---

## Owner decision gates (pending — do not assume a "yes")

1. **Money gate** — recurring paid services that half the roadmap depends on:
   Firebase **Blaze** (Cloud Functions for invites/deletion/retention + Identity Platform for
   SSO/MFA — Spark can't deploy functions at all) and **Cloudflare paid** (DO volume + cron cadence at
   real usage). Gates Phases 2 & 7. *Stripe, EV/Apple signing: deferred until needed.*
2. **App audience** — does the Deck open to non-admin app users, or does the App ship a desktop-only
   capability set? **This gates the entire App line** — until decided, a shipped App is empty for
   everyone but the owner, so the `feat/web-shell` → `main` merge must wait on it.
3. **Signing identities** — Apple Developer ($99/yr) + Windows EV/Azure Trusted Signing; long
   procurement lead time (Phase 8) — start early.

---

## Current divergence / duplicate inventory (what must converge)

- **App:** the whole "app = packaged Deck" direction lives on `feat/web-shell` (D0 shell + auto-update
  + typed toasts); `main` is still v2.54.0 with the old renderer. The ~90–102-handler native moat
  (TCP/DNS/TLS/port-scan, PTY, QEMU, forensics, Ollama) is dark to the Deck UI. **Merge is gated on
  decision #2.**
- **OS:** three historical tracks (from-source `core/`, cloud-init Debian provisioner, Obsidian
  kernel). The shipping image still uses a **stock vendor kernel** — the "custom kernel" claim is
  unbacked until Phase 6 ships the hardened mainline kernel.
- **Deck:** false enterprise plan cards (SSO/SCIM) **already relabelled** (Phase 0); still
  localStorage-bounded with no live connectors — addressed in Phases 1–2.
- **Release:** three overlapping pipelines (`build.yml` `v*`, `build-mac.yml`/`publish-release.sh`
  "latest", `app-update.yml` GitHub-latest) → collapse to one `v*`-tag contract in Phase 8.

---

## Phase 0 status (this record's phase)

Done: honest Deck plan cards + monitor pause/delete bug fixes (deployed, SW v166); 88 OS toolkit
symlinks repointed; brand unified (os-release/Plymouth/cloud-init + kernel LOCALVERSION); App README
OS-build overclaim corrected; this decision record. `gen_data.py` was already absent (stale recon
premise). **Pending:** the three owner decisions above.
