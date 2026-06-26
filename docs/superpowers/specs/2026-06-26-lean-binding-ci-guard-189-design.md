# Lean mobile-binding CI guard (#189)

**Date:** 2026-06-26
**Issue:** #189 — CI: assert lean mobile-binding feature boundary (no `notify`/`clap` in `secretary-ffi-uniffi`)
**Status:** approved, ready for implementation

## Problem

`secretary-cli`'s `daemon` feature gates the headless-sync deps (`notify`, `clap`,
`tracing-subscriber`, `rpassword`, `serde_json`). `secretary-ffi-bridge` depends on
`secretary-cli` with `default-features = false`, so the daemon deps are kept out of the
bridge and the two mobile bindings beneath it (`secretary-ffi-uniffi`, `secretary-ffi-py`).

This "lean binding" property is **build-context-dependent**. Under `cargo test --workspace`,
Cargo unifies `daemon` ON for the bridge too (the `secretary-sync` bin in the same package
requires it). The guarantee only holds for a `-p`-scoped resolution that excludes the bin
target — which is exactly the context in which the shipping cdylib/`.so` is built. Nothing
in-repo currently prevents a future dependency edit from silently re-enabling `daemon` (or
otherwise pulling `notify`/`clap`) into the binding tree.

When the issue was filed there were no CI workflows. There now are
(`.github/workflows/rust-lint.yml`, `test.yml`, `ios-tsan.yml`), so the guard is actionable.

The property holds today — verified for all three crates with
`cargo tree -p <crate> --no-default-features -e normal` (no `notify`/`clap`). This change is
**regression insurance**, not a fix.

## Design

### Component 1 — `ffi/scripts/check-lean-binding.sh`

A runnable shell script (mirrors the existing `ffi/secretary-ffi-uniffi/tests/*/run_conformance.sh`
pattern: locally runnable, CI-invoked, self-documenting).

- `set -euo pipefail`.
- **One forbidden-deps matcher**, not scattered literals: `FORBIDDEN_RE='^(clap|notify) '`.
- **One guarded-crate list**: `secretary-ffi-uniffi secretary-ffi-py secretary-ffi-bridge`.
- For each crate:
  `cargo tree -p <crate> --no-default-features -e normal --prefix none`
  → grep for `FORBIDDEN_RE` → if it matches, print the offending lines and record a failure.
  - `--prefix none` strips cargo-tree's box-drawing characters so the line-anchored regex is
    robust (the issue's proposed `^\S*(notify|clap) ` anchor does not survive the `├──` prefix).
  - `-e normal` scopes to normal (linked/runtime) edges — the deps that actually land in the
    shipped artifact — excluding build- and dev-dependencies.
  - `--no-default-features` matches the real shipping context (the cdylib is built with
    `secretary-ffi-uniffi`'s empty default feature set) and additionally guards against a
    future move of the opt-in `cli` feature into `default`.
- Exit non-zero if **any** guarded crate trips; exit 0 when all are clean.
- **`--self-test` mode** (positive control): assert the matcher *does* flag `clap` and `notify`
  in `secretary-cli` built with default features (daemon ON). If the positive control fails to
  trip, the script exits non-zero. This proves the guard is not vacuous — the exact failure
  mode #231 surfaced (a "zero warnings" bar that checked nothing). The self-test is a
  pure matcher check; it does not assert anything about the bindings.
- Header comment states **why** `notify`/`clap` are forbidden (the `daemon` feature boundary)
  and points at this spec + `cli/Cargo.toml`'s `daemon` feature.

### Component 2 — CI wiring

A new lightweight `lean-binding` job in `.github/workflows/rust-lint.yml` (the guard is a
static dependency-boundary lint, thematically a lint alongside fmt/clippy). `cargo tree` only
resolves the graph — it never compiles the crates — so the job needs no GTK/WebKit/Tauri
system deps and runs ubuntu-only and fast.

Steps:
1. `actions/checkout@v4`
2. `bash ffi/scripts/check-lean-binding.sh --self-test` (prove the matcher fires)
3. `bash ffi/scripts/check-lean-binding.sh` (the real guard)

The toolchain comes from `rust-toolchain.toml` (same as the other jobs).

### Component 3 — docs

Add the local command to CLAUDE.md's "Commands" section so the documented-commands surface
stays in sync (the same discipline rust-lint.yml's header cites).

## Out of scope / non-goals

- No `core` / FFI / on-disk-format / `conformance.py` change. No observable bytes or merge
  semantics touched, so no spec/`conformance.py` lockstep update is required.
- No change to the `daemon` feature or any Cargo manifest. The boundary already exists; this
  only adds a regression tripwire.

## Verification (red→green)

- **Green:** `check-lean-binding.sh` exits 0 against the three crates today.
- **Red (built-in):** `--self-test` proves the matcher flags `clap`+`notify` in the
  `secretary-cli` positive control.
- **Red (manual, during dev):** point the matcher at `secretary-cli` (daemon on) and confirm
  it reports a violation, demonstrating the guard would catch a real regression.
