# NEXTSESSION_BROWSER_PLUGIN.md — start here for D.4 (browser autofill)

> **Standalone handoff for the browser-plugin track.** This file is deliberately **not** the
> `NEXT_SESSION.md` symlink (that points at the latest `docs/handoffs/` entry for the main
> line of work). The browser-plugin track runs **parallel** to other Secretary sessions; keep
> its handoff here so the two don't collide. Do a worktree (`.worktrees/`) per CLAUDE.md
> "Working directory discipline" so a parallel window can't switch branches under you.

## TL;DR

Planning is done and merged. The next session **implements D.4.1** — a native-messaging
*walking skeleton*: a browser extension + a small Rust host that complete one
`query → available{count:0}` **no-op** round trip. **No crypto, no vault, no `secretary-core`
dependency, no fill.** It exists only to prove the channel before any feature work.

## Read these first (all on `main`)

1. `docs/adr/0010-browser-autofill-native-messaging.md` — **the decision** (why thin-courier +
   native messaging + per-fill open + cryptographic vault tiering).
2. `docs/threat-model.md` **§6** — the browser-extension adversary model + the structural
   invariants D.4.1 must preserve.
3. `docs/superpowers/specs/2026-06-15-d4-browser-autofill-design.md` — **the build plan** for the
   whole sub-project. §10 records every resolved decision (fill-only for v1, helper-local
   binding default, Safari = App-Extension, TOTP in v1, etc.).
4. `docs/superpowers/specs/2026-06-16-d41-native-messaging-skeleton-plan.md` — **the slice you
   are building.** Layout, framing codec, host manifest, the 6-task breakdown, and the DoD.

## What D.4.1 ships (from the plan §1)

- `browser/secretary-browser-host/` — a **new Rust crate, a workspace member** (so it inherits
  `#![forbid(unsafe_code)]` + clippy `-D warnings`). stdin/stdout framed read→handle→write loop.
  **No `secretary-core` dep yet** (D.4.2 adds it).
- `browser/extension/` — Chromium MV3 extension that `connectNative`s, sends `query`, logs
  `available`.
- `browser/host-manifest/` — dev manifest binding host ↔ extension ID + per-OS install notes.

## Task order (plan §6) — start with 1–2, the load-bearing core

1. **Host crate + `frame.rs` framing codec** — 4-byte native-endian length prefix, **1 MiB
   cap**, **no panic on malformed input** (return `Result`, mirroring the fuzz "assert Result,
   not panic" contract). Unit-test every branch: round-trip, oversize→`TooLarge`, truncated
   length, non-JSON body, EOF→clean shutdown.
2. **`protocol.rs` + `main.rs` loop** — serde `query`/`available`/`error`; no-op handler returns
   `available{count:0}` + a fresh `request_id` UUID. `tests/echo.rs`: pipe a `query` frame in,
   assert an `available` frame out; unknown type → `error`.
3. Chromium MV3 extension scaffold (reuse `desktop/` pnpm/tsconfig conventions).
4. `host-manifest/` dev manifest + macOS/Linux install README.
5. Wire the host crate into `cargo test --release --workspace`; clippy `-D warnings` clean.
6. `browser/README.md` + a `docs/handoffs/2026-..-d41-shipped.md` handoff, then update **this
   file** to point at D.4.2.

Tasks 1, 2, 5 are fully CI-gated in Rust. Tasks 3–4 carry a **documented manual browser smoke**
(load-unpacked + installed manifest → console shows the round trip) — same posture as the iOS
on-device proof; automated browser-driver e2e is a later optional add, not D.4.1.

## Guardrails (must hold — these are the DoD, plan §8)

- **No `core/`, `ffi/`, `ios/`, `android/`, or on-disk-format change.** D.4.1 is purely additive
  under `browser/` + `docs/`. Guardrail grep before you push:
  `git diff main...HEAD --name-only | grep -vE '^(browser/|docs/|Cargo\.(toml|lock)|README\.md|ROADMAP\.md|NEXTSESSION_BROWSER_PLUGIN\.md)'` → expect empty.
  (The only root touch allowed is adding the new crate to the workspace members in `Cargo.toml`.)
- **No listening socket** — the host speaks only over the browser-provided stdio. This is the
  whole point of the slice (threat-model §6 invariant 3).
- **No key material, no vault open** — trivially true (no `secretary-core` dep). Don't add one;
  that's D.4.2's job, and it must go through the same `open_with_device_secret`
  verify-before-decrypt path.
- **Framing codec never panics** and caps at 1 MiB.
- `#![forbid(unsafe_code)]` holds in the new crate; `cargo clippy --release --workspace --tests
  -- -D warnings` clean.

## How to start

```bash
# from a clean main (these docs are merged):
cd /path/to/secretary && git fetch --prune origin && git checkout main && git pull --ff-only origin main
pwd && git branch --show-current && git worktree list        # CLAUDE.md discipline check
git worktree add .worktrees/d41-native-messaging -b feature/d41-native-messaging main
# then implement plan §6 task 1 (browser/secretary-browser-host + frame.rs) first.
```

## What this slice hands D.4.2

A working channel to attach crypto to: add the `secretary-core` dep, the casual-vault
per-fill `open_with_device_secret`, native-app device-slot enrollment, and replace the
`count:0` no-op with a real candidate count (still **no secrets crossing** — that waits for
D.4.4's native-confirmation gate). See design §9 / plan §9.
