# NEXTSESSION_BROWSER_PLUGIN.md — start here for D.4 (browser autofill)

> **Standalone handoff for the browser-plugin track.** This file is deliberately **not** the
> `NEXT_SESSION.md` symlink (that points at the latest `docs/handoffs/` entry for the main
> line of work). The browser-plugin track runs **parallel** to other Secretary sessions; keep
> its handoff here so the two don't collide. Do a worktree (`.worktrees/`) per CLAUDE.md
> "Working directory discipline" so a parallel window can't switch branches under you.

## TL;DR

**D.4.1 is shipped** (the native-messaging walking skeleton — see
`docs/handoffs/2026-06-16-d41-shipped.md`). The next session **implements D.4.2** — attach the
**first crypto** to the proven channel: add the `secretary-core` dependency to the host, open a
**casual vault per fill** via `open_with_device_secret`, enroll a native-app device slot, and
replace the `count:0` no-op with a **real candidate count**. **Still no secrets cross the
channel** — credential injection waits for D.4.4's native-confirmation gate.

## What already exists (D.4.1, on branch `claude/intelligent-davinci-hriple`)

- `browser/secretary-browser-host/` — Rust workspace member, **pure transport**. `frame.rs`
  (1 MiB-capped, never-panic length-prefix codec), `protocol.rs` (`query`/`available`/`error`),
  `lib.rs::run()` (read→dispatch→write loop), `tests/echo.rs`. **No `secretary-core` dep yet.**
- `browser/extension/` — Chromium MV3: `connectNative` → send `query` → log `available`.
- `browser/host-manifest/` — dev manifest binding host ↔ extension ID + macOS/Linux install
  notes + the manual-smoke runbook.
- `browser/README.md` — architecture pointer + dev-run steps.

The host **always** replies `available{count:0}` today, mints a fresh `request_id` per query,
and answers unknown message types with a typed `error` frame.

## Read these first (all on `main` unless noted)

1. `docs/handoffs/2026-06-16-d41-shipped.md` — **what D.4.1 shipped** and exactly what D.4.2
   picks up (§2).
2. `docs/adr/0010-browser-autofill-native-messaging.md` — **the decision** (thin-courier +
   native messaging + **per-fill open** + cryptographic vault tiering).
3. `docs/superpowers/specs/2026-06-15-d4-browser-autofill-design.md` — **§4 "Per-fill open &
   device-slot enrollment"** is the D.4.2 core; §10 records every resolved decision.
4. `docs/threat-model.md` **§6** — the browser-extension adversary model + the structural
   invariants. D.4.2 starts proving the **crypto** invariants (§6 invariant 1: host holds no
   long-lived key material; opens go through verify-before-decrypt), not just the structural
   ones D.4.1 locked in.
5. CLAUDE.md "device unlock (ADR 0009)" + `core/src/vault/orchestrators.rs::open_vault`
   (`Unlocker::DeviceSecret` arm) + `ffi/secretary-ffi-bridge/src/device.rs` — the **existing**
   device-slot + `open_with_device_secret` surface D.4.2 must reuse, **not** reimplement.

## What D.4.2 ships (design §4 / §9)

- Add `secretary-core` (and the FFI bridge surface as needed) as a dependency of
  `secretary-browser-host`. It stops being pure transport.
- **Per-fill open:** on a `query`, open the casual vault via `open_with_device_secret` — the
  **same** B.2 manifest verify-before-decrypt path as password/recovery/device unlock. The
  browser path must **never** be a weaker open. Close/zeroize immediately after the query; no
  long-lived unlocked identity in the host.
- **Native-app device-slot enrollment:** create/manage `devices/<uuid>.wrap` (`file_kind
  0x0004`) so the host can release the IBK under a device secret. Reuse
  `core/src/vault/device_slot.rs` + `core/src/unlock/device.rs`; do not fork the crypto.
- **Real candidate count:** replace the hard-coded `count: 0` with the number of records that
  match the query's origins. **No secrets cross the channel** — the reply is still just a count.
  Origin-matching is intentionally trivial here (exact-origin only); the real PSL/binding/iframe
  engine is D.4.3.

### Explicit non-goals (later slices — do not pull forward)

| Deferred | Slice |
|---|---|
| Real origin matching (PSL, bindings, iframe rules) | D.4.3 |
| Click-to-fill, native confirmation dialog, credential injection | D.4.4 |
| `origin_binding` record metadata, guard-rails | D.4.5 |
| Firefox + Safari + Windows registry + signing/packaging | D.4.6 |
| Any write/capture path | D.4.7 |

## Guardrails (must hold — these become the D.4.2 DoD)

- **Reuse the existing open path.** The per-fill open MUST funnel through
  `open_with_device_secret` / the `Unlocker::DeviceSecret` arm — the same verify-before-decrypt
  as every other unlock. Adding a parallel or weaker open is the one thing review will reject.
- **No long-lived key material in the host** (threat-model §6 invariant 1). Open per fill,
  zeroize on drop, hold nothing between queries.
- **No secrets cross the channel in D.4.2.** The `available` reply gains a real `count`, nothing
  more. Credentials wait for D.4.4's native-confirmation gate.
- **No listening socket; manifest-bound extension ID** — the structural invariants D.4.1 locked
  in stay locked in.
- **Framing codec still never panics and caps at 1 MiB**; `#![forbid(unsafe_code)]` + clippy
  `-D warnings` stay clean across the (now `secretary-core`-linked) host crate.
- **Additive under `browser/` + `docs/`.** A `core/` change is only acceptable if D.4.2
  genuinely needs a new *public* API on the existing device-slot/open surface — and that is a
  deliberate, reviewed core edit, not a silent one. Default expectation: no `core/src` change.

## How to start

```bash
# from a clean main (D.4.1 lives on claude/intelligent-davinci-hriple; rebase/merge as needed):
cd /path/to/secretary && git fetch --prune origin && git checkout main && git pull --ff-only origin main
pwd && git branch --show-current && git worktree list        # CLAUDE.md discipline check
git worktree add .worktrees/d42-per-fill-open -b feature/d42-per-fill-open main
# bring in the D.4.1 browser/ tree, then implement design §4: secretary-core dep →
# open_with_device_secret per-fill open → device-slot enrollment → real candidate count.
```

## What this slice hands D.4.3

A host that, given a query, opens the casual vault per fill and returns a **real** candidate
count for exact-origin matches. D.4.3 replaces the trivial matcher with the real origin-matching
engine (PSL, explicit bindings, iframe rules) — design §5, the security core — still returning
only a count, with injection deferred to D.4.4.
