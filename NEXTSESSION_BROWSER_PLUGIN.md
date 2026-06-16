# NEXTSESSION_BROWSER_PLUGIN.md — start here for D.4 (browser autofill)

> **Standalone handoff for the browser-plugin track.** This file is deliberately **not** the
> `NEXT_SESSION.md` symlink (that points at the latest `docs/handoffs/` entry for the main
> line of work). The browser-plugin track runs **parallel** to other Secretary sessions; keep
> its handoff here so the two don't collide. Do a worktree (`.worktrees/`) per CLAUDE.md
> "Working directory discipline" so a parallel window can't switch branches under you.

## TL;DR

**D.4.1 (channel skeleton) and D.4.2 (per-fill open) are shipped** — see
`docs/handoffs/2026-06-16-d41-shipped.md` and `docs/handoffs/2026-06-16-d42-shipped.md`. The
next session **implements D.4.3 — the origin-matching engine, the security-critical slice.** It
replaces the current trivial "all live blocks" count with a real `(top_origin, frame_origin,
stored_origin, binding) → {fill | refuse}` decision, gated by a **pinned KAT corpus**. Still
returns only a *count* — injection is D.4.4.

## What already exists (D.4.1 + D.4.2, on branch `claude/intelligent-davinci-hriple`)

- `browser/secretary-browser-host/` — Rust workspace member, now `secretary-core`-linked:
  - `frame.rs` (1 MiB-capped never-panic codec), `protocol.rs` (`query`/`available`/`error`).
  - `config.rs` (helper-local `HostConfig`: vault path, device_uuid, secret source).
  - `secret_source.rs` (`DeviceSecretSource` **port** + dev-only `DevFileSecretSource`).
  - `vault.rs::per_fill_count` — opens the casual vault via `open_vault(Unlocker::DeviceSecret)`
    (the **exact** B.2 verify-before-decrypt) and returns `manifest.blocks.len()`.
  - `lib.rs::Context` + `run()` — `query → available{count}`; not-enrolled → `count:0`.
  - `enroll.rs` + `src/bin/enroll.rs` (`secretary-browser-enroll`, **dev-only**).
- `browser/extension/` — Chromium MV3; `browser/host-manifest/` — dev manifest + install +
  enrollment notes; `browser/README.md` — architecture + dev-run + enrollment.

The host opens **only** the casual vault, holds **no key material between fills**, and **no
secrets cross the channel** (the reply is an integer count).

## Read these first

1. `docs/handoffs/2026-06-16-d42-shipped.md` — what D.4.2 shipped + exactly what D.4.3 picks up.
2. `docs/superpowers/specs/2026-06-15-d4-browser-autofill-design.md` **§5 "Origin-matching
   engine (security core)"** — the D.4.3 contract: `registrable_domain` (PSL/eTLD+1) vs
   `exact_origin`; top-frame-governs; cross-origin-iframe refusal; HTTPS-only; IDN
   de-confusion; no credential-list leak. **§6** — where `origin_binding` lives (the record
   `unknown` map under `d4_origin_binding`; **no on-disk format change**) and the helper-local
   global default. **§12** — the invariants (esp. 5: matching runs only in the helper, passes
   the pinned KAT, never fills a cross-origin iframe, HTTPS-only; 8: PSL exact-pinned).
3. `docs/threat-model.md` **§6** — the adversary model the matcher defends against.
4. CLAUDE.md "Spec is normative" + the `*_kat.json` discipline — D.4.3 adds
   `origin_match_kat.json`, pinned and (ideally) cross-checked clean-room, mirroring the
   existing KAT pattern.

## What D.4.3 ships (design §5/§6, the security-critical slice)

- An **origin-matching engine** in the host (never in a content script): given a query's
  `top_origin`/`frame_origin`/`https` and a credential's stored origin + binding, decide
  fill-vs-refuse under **both** bindings:
  - `registrable_domain` — eTLD+1 via the **Public Suffix List** (mandatory, not a string
    suffix; `foo.github.io` is its own registrable domain).
  - `exact_origin` — scheme + host + port.
  - Rules (each a KAT vector): top-frame-origin governs (refuse cross-origin iframes),
    HTTPS-only (refuse `http`/`file`/`data`/`blob`/`about`/extension pages), IDN de-confusion,
    no credential-list leak.
- `per_fill_count` becomes **origin-aware**: count only records whose stored origin matches the
  query under the active binding (read the credential's URL field + the per-record
  `d4_origin_binding` from the record `unknown` map, falling back to the helper-local default).
- A **pinned `origin_match_kat.json`** corpus replayed in Rust (and ideally clean-room), plus
  the **PSL as a versioned, exact-pinned data dependency** with a deliberate-bump review
  (mirror the `tempfile =3.27.0` discipline; a stale PSL silently moves match boundaries).

The two other D.4.2 follow-ups also live around here: the **real OS-keystore
`DeviceSecretSource` adapters** (behind the existing port, replacing `DevFileSecretSource`) and
the **desktop enrollment UI** (replacing `secretary-browser-enroll`). They can be a sub-slice or
folded in — but the origin-matching engine is the heart of D.4.3 and earns the most review.

### Explicit non-goals (later slices — do not pull forward)

| Deferred | Slice |
|---|---|
| Click-to-fill, native confirmation dialog, credential injection | D.4.4 |
| Writing `d4_origin_binding` (read is D.4.3) + tiering guard-rails | D.4.5 |
| Firefox + Safari + Windows registry + signing/packaging | D.4.6 |
| Any write/capture path | D.4.7 |

## Guardrails (must hold — these become the D.4.3 DoD)

- **Matching runs only in the helper**, never in a content script (design §12 invariant 5).
- **Pinned KAT.** `origin_match_kat.json` is the contract; every rule is a vector. Don't relax a
  vector to make code pass — a disagreement is a code or spec bug, resolved explicitly.
- **PSL exact-pinned** with a rationale comment + deliberate-bump review (invariant 8).
- **No on-disk format change.** `origin_binding` lives in the record `unknown` map under
  `d4_origin_binding` (design §6) — `golden_vault_001` stays byte-identical.
- **Still no secrets cross the channel** — the reply is a count; injection is D.4.4.
- **Reuse, don't weaken.** The per-fill open stays `open_vault(Unlocker::DeviceSecret)`; the
  host still holds no key material between fills. `#![forbid(unsafe_code)]` + clippy
  `-D warnings` + never-panic 1 MiB framing stay clean.

## How to start

```bash
# from a clean main (D.4.1+D.4.2 live on claude/intelligent-davinci-hriple; rebase/merge as needed):
cd /path/to/secretary && git fetch --prune origin && git checkout main && git pull --ff-only origin main
pwd && git branch --show-current && git worktree list        # CLAUDE.md discipline check
git worktree add .worktrees/d43-origin-matching -b feature/d43-origin-matching main
# bring in the D.4.1+D.4.2 browser/ tree, then implement design §5: PSL + binding rules +
# the pinned origin_match_kat.json + origin-aware per_fill_count.
```

## What this slice hands D.4.4

A host that returns a **page-accurate** candidate count (origin-matched). D.4.4 adds the genuine
user gesture → the **native** confirmation/picker dialog (outside web content) → a **single**
credential injected into the page DOM — the first slice where any secret crosses the channel,
and only after native approval (design §7, §3 steps 3–6).
