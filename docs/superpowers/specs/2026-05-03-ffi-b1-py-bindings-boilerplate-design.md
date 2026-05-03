# Sub-project B.1 — FFI Python Bindings Boilerplate

**Date:** 2026-05-03
**Author:** Horst Herb (with Claude)
**Status:** Approved — ready for implementation
**Touches:** `ffi/secretary-ffi-py/Cargo.toml`, `ffi/secretary-ffi-py/src/lib.rs`, `ffi/secretary-ffi-py/pyproject.toml` (new), `ffi/secretary-ffi-py/tests/test_smoke.py` (new), `ffi/secretary-ffi-py/README.md` (new)

> **Note (post-PR-#20-review).** The body of this spec has been rewritten to describe the as-shipped state. Three review-driven refinements landed in commit `eace3e2`:
>
> - **`sum` → `add`** (avoid shadowing Python's builtin `sum()` once imported). Step 2's commit subject `e98f684` ("expose sum and version via #[pymodule]") is preserved verbatim in the commit-cluster table for git-history accuracy; everywhere else describes the as-shipped `add` surface.
> - **`a + b` → `a.wrapping_add(b)`** + regression test `add_wraps_on_overflow` pinning `add(u32::MAX, 1) == 0`.
> - **`version() as u32` → `u32::from(version())`** (lossless u16 → u32 widening via the infallible `From` impl).
>
> Test counts in this spec reflect the post-rename state (448 + 6 cargo / 3 pytest).

## Background

Sub-project A (the Rust cryptographic core) is feature-complete for v1; Phase A.7's three internal hardening passes have closed. The next bounded unit of work per [secretary_next_session.md](../../../secretary_next_session.md) is **Sub-project B.1**: FFI binding boilerplate that proves the Python binding pipeline works end-to-end. This unblocks Sub-project C (sync orchestration) and Sub-project D (platform UIs), and runs in parallel with the gated external paid review track.

The two FFI crates exist as stubs today: [ffi/secretary-ffi-py/](../../../ffi/secretary-ffi-py/) for PyO3 (Python desktop / web) and [ffi/secretary-ffi-uniffi/](../../../ffi/secretary-ffi-uniffi/) for uniffi (Swift/Kotlin via one UDL). This spec covers the **PyO3 crate only** — uniffi is deferred to B.1.1.

## Goals

- A single `import secretary_ffi_py` from Python returns the value of two trivial Rust functions: `add(a, b) -> u32` and `version() -> u32`. (`add`, not `sum`, so the Python-side surface doesn't shadow the builtin once imported at module level.)
- The build pipeline is documented end-to-end in the FFI crate's README so the next contributor doesn't have to reverse-engineer it.
- The existing `cargo test --release --workspace` baseline (445 + 6 ignored) gains the FFI Rust unit tests cleanly (→ 448 + 6).
- The existing `clippy --release --workspace -- -D warnings` invariant continues to hold.
- The workspace `unsafe_code = "forbid"` invariant stays intact for `core/` and `secretary-ffi-uniffi/`. Only the PyO3 crate gets a localized relaxation, with the rationale committed.

## Non-goals (YAGNI)

- **No vault crypto exposed.** No `unlock`, no `open_vault`, no `Record` types. The PyO3 surface is just `add` + `version`. Vault crypto exposure is B.2+ and warrants its own design pass (lifetime-of-secret across the FFI boundary, zeroize discipline through Python's GC, error-type marshalling).
- **No Swift / Kotlin smoke runners.** `secretary-ffi-uniffi` stays as the existing stub. UDL design + uniffi-bindgen wiring is B.1.1.
- **No CI integration for the Python pytest layer.** Repo has no `.github/workflows/` yet (matches the deferred-CI pattern from `spec_test_name_freshness.py`); the FFI README documents the manual invocation.
- **No top-level `pyproject.toml`.** Each FFI crate self-describes its Python build under its own directory.
- **No `PyResult` / exception marshalling.** `add` uses `wrapping_add` (matches default release-build `+` semantics, which silently wrap on overflow); a regression test `add_wraps_on_overflow` pins `add(u32::MAX, 1) == 0` so saturation / `PyResult<u32>` overflow plumbing in B.2 will be a deliberate contract change. Fallible surface (and `PyResult` ergonomics) comes with B.2.
- **No multi-version Python matrix.** Whatever `uv` resolves; pinned via `requires-python` in `pyproject.toml`.
- **No abi3 / stable ABI.** Build for whatever Python version `uv` resolves; abi3 is a release-engineering decision for a future B.x.

## Architecture

### Files

| File | Status | Purpose |
|---|---|---|
| `ffi/secretary-ffi-py/Cargo.toml` | edit | Add `pyo3 = { version = "0.28" }` (no Cargo features — see note below on `extension-module` deprecation). Replace `[lints] workspace = true` with crate-local lint table (see *Lints & invariants*). |
| `ffi/secretary-ffi-py/src/lib.rs` | edit | Add `#[pymodule] fn secretary_ffi_py(...)` exposing `add(a: u32, b: u32) -> u32` (using `wrapping_add` for explicit-overflow semantics) and `version() -> u32`. Keep the existing free function `version()` for Rust callers and Rust unit tests. Add `#[cfg(test)] mod tests` with three unit tests (`version_returns_format_version`, `add_returns_arithmetic_sum`, `add_wraps_on_overflow`). |
| `ffi/secretary-ffi-py/pyproject.toml` | **new** | Build-system: `maturin>=1.9.4,<2.0` (≥1.9.4 required because PyO3 0.28 deprecated the `extension-module` Cargo feature in favour of the `PYO3_BUILD_EXTENSION_MODULE` env var that maturin ≥ 1.9.4 sets automatically). Dev deps: `pytest`, `maturin` (so `uv run --directory ... maturin develop` finds it in the project venv). Module name: `secretary_ffi_py`. `requires-python = ">=3.11"`. |
| `ffi/secretary-ffi-py/tests/test_smoke.py` | **new** | Pytest: `import secretary_ffi_py`, assert `add(2, 3) == 5`, `add(u32::MAX, 1) == 0` (wrapping contract), and `version() == 1` (matches `secretary_core::version::FORMAT_VERSION`). |
| `ffi/secretary-ffi-py/README.md` | **new** | Documents the build / test flow per acceptance criterion 5 of NEXT_SESSION.md (the "where does the Python build product live" answer). Cites this design doc. |

No files outside the FFI crate change. Root `Cargo.toml` workspace lints stay untouched. No top-level `pyproject.toml`. `secretary-ffi-uniffi` stub untouched.

### Test layers

Two independent layers, each runnable on its own:

| Layer | Where | Runs via | Proves |
|---|---|---|---|
| **Rust unit tests** | `ffi/secretary-ffi-py/src/lib.rs` `#[cfg(test)] mod tests` | `cargo test --release --workspace` | The Rust functions return the expected values when called directly. Adds 3 tests to the existing 445+6 baseline → 448+6. No Python interpreter involved. |
| **Python smoke tests** | `ffi/secretary-ffi-py/tests/test_smoke.py` | `uv run --directory ffi/secretary-ffi-py pytest` (after `uv sync` / `maturin develop`) | The maturin-built wheel installs cleanly into a `uv` venv, `import secretary_ffi_py` works, and the same two functions return the same values when called from Python — including the wrapping-overflow boundary. Proves the binding pipeline end-to-end. |

The split is load-bearing: the Rust layer keeps `cargo test --release --workspace` self-contained — no `uv` / Python / maturin required. The Python layer is gated on `maturin develop` having run first, but is independent of the Rust suite. They cross-validate each other: a logic bug in `add` fails both layers; an FFI marshalling bug fails only the Python layer; a build/install bug stops the Python layer from running at all (clear failure signal).

### Build flow

The single answer to NEXT_SESSION.md's hardest sub-question (criterion 5):

```bash
# One-time setup (after first checkout): uv sync invokes the maturin
# build-backend automatically and installs the editable wheel into
# ffi/secretary-ffi-py/.venv/. The .so lives in the venv's site-packages,
# NOT in the source tree (no rogue .so files to .gitignore).
uv sync --directory ffi/secretary-ffi-py

# Run the smoke tests:
uv run --directory ffi/secretary-ffi-py pytest

# Iterate on Rust source:
#   1. Edit src/lib.rs
#   2. uv run --directory ffi/secretary-ffi-py maturin develop --release
#   3. uv run --directory ffi/secretary-ffi-py pytest
# (Step 2 is incremental; ~2-3s after the first cold build. `--release`
# matches the project's "always --release" posture for the slow crypto deps.
# `maturin` is in the [dependency-groups] dev table so `uv run` finds it.)

# Rust-only flow stays identical:
cargo test --release --workspace        # 448+6 (was 445+6)
cargo clippy --release --workspace -- -D warnings
```

The build artifact lives in `ffi/secretary-ffi-py/.venv/site-packages/`. The repo's existing [.gitignore](../../../.gitignore) already covers `.venv` (line 73), `*.so` (line 7), and `.pytest_cache/` (line 51) — no `.gitignore` change needed.

### `extension-module` deprecation (PyO3 0.28)

PyO3 0.28 deprecated the `extension-module` Cargo feature in favour of the `PYO3_BUILD_EXTENSION_MODULE` environment variable, which `maturin >= 1.9.4` sets automatically when building wheels. The deprecated feature suppresses linking against `libpython`, which is correct for the produced extension `.so` (the host Python interpreter already provides those symbols) but breaks `cargo test` because the test binary is a standalone executable that DOES need libpython at link time. Removing the feature makes both `cargo test` and `maturin develop` work simultaneously, and is the path now recommended by upstream PyO3 ([FAQ entry](https://pyo3.rs/main/faq.html)). Consequence for B.1: the PyO3 dep declaration is `pyo3 = { version = "0.28" }` with no `features` array, and `pyproject.toml` declares `requires = ["maturin>=1.9.4,<2.0"]` (not `>=1.7`) so the env-var auto-set is guaranteed.

### Lints & invariants

The workspace currently sets `unsafe_code = "forbid"` ([root Cargo.toml](../../../Cargo.toml)) and the FFI crate inherits via `[lints] workspace = true`. PyO3's `#[pymodule]` / `#[pyfunction]` macros expand to user-crate code containing `unsafe` blocks (the bridge to the CPython C-API is inherently unsafe). `forbid` is non-overridable by inner `#[allow]`, so PyO3 will fail to compile in `secretary-ffi-py` unless the inheritance is relaxed.

**Decision (B.1):** the FFI crate replaces `[lints] workspace = true` with its own lint table that uses `unsafe_code = "deny"` (locally overridable per-call-site), and `lib.rs` carries a crate-level `#![allow(unsafe_code)]`. The placement is **crate-level** rather than item-level because the function-style `#[pymodule]` macro generates code at crate scope (an `extern "C"` PyInit symbol alongside the entry-point function), which an item-level `#[allow]` doesn't cover. The workspace only defines `[workspace.lints.rust] unsafe_code = "forbid"` today (no clippy or rustdoc lint tables), so the crate-local replacement is a single line: `[lints.rust] unsafe_code = "deny"`.

**Why this scope:** matches CLAUDE.md's existing principle: *"If a primitive truly needs FFI, isolate it in its own crate behind a reviewed boundary."* Workspace `forbid` stays intact for `core/` and `secretary-ffi-uniffi`. Any new `unsafe` block elsewhere in the FFI crate would still trigger a `deny` error and require an explicit `#[allow]` with justification.

**The macro site:**

```rust
//! Python bindings for secretary-core via PyO3.
//!
//! The crate-level `#![allow(unsafe_code)]` is the minimal escape hatch
//! for PyO3's #[pymodule] / #[pyfunction] macros, which expand to unsafe
//! blocks (the CPython C-API bridge is inherently unsafe). The crate-local
//! lint relaxation (workspace `forbid` → crate-local `deny`) is required
//! because `forbid` is non-overridable by inner #[allow]; see Cargo.toml.
//!
//! The `#[allow]` is **crate-level** rather than item-level because the
//! function-style `#[pymodule]` macro generates code at crate scope (an
//! `extern "C"` PyInit symbol alongside the entry-point function); a
//! narrower item-level `#[allow]` doesn't cover that expansion.

#![allow(unsafe_code)]

use pyo3::prelude::*;

#[pyfunction]
fn add(a: u32, b: u32) -> u32 {
    a.wrapping_add(b)
}

#[pyfunction]
#[pyo3(name = "version")]
fn version_py() -> u32 {
    u32::from(version())
}

#[pymodule]
fn secretary_ffi_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(add, m)?)?;
    m.add_function(wrap_pyfunction!(version_py, m)?)?;
    Ok(())
}

/// Smoke test: returns the vault format version exposed by the core crate.
/// Kept as a free function so Rust callers (and Rust unit tests) can use
/// it without going through PyO3 / a Python interpreter.
pub fn version() -> u16 {
    secretary_core::version::FORMAT_VERSION
}
```

`add`'s overflow handling: explicit `wrapping_add` (matches default release-build `+` semantics, which silently wrap on overflow). The named choice puts the contract in the code rather than a comment, and a regression test `add_wraps_on_overflow` pins `add(u32::MAX, 1) == 0` so a future switch to `checked_add` / `saturating_add` is a deliberate test failure rather than a silent contract change. Saturation / `PyResult<u32>` overflow plumbing is deferred to B.2 when fallible crypto operations make `PyResult` a first-class citizen.

## Implementation plan

Five planned commits on `feat/ffi-b1-py-bindings-boilerplate` (worktree at `.worktrees/feat-ffi-b1-py-bindings-boilerplate/`), each leaving the workspace green (`cargo test --release --workspace` + `cargo clippy --release --workspace -- -D warnings`). A sixth row records the post-PR-#20-review refinement:

| # | Title | Diff scope | Verification |
|---|---|---|---|
| **0** | `docs(spec): B.1 FFI Python bindings boilerplate design` | This file. | None functional. |
| **1** | `chore(ffi-py): relax workspace unsafe_code lint and add pyo3 dep` | `ffi/secretary-ffi-py/Cargo.toml` only: replace `[lints] workspace = true` with `[lints.rust] unsafe_code = "deny"` (the only workspace lint set today); add `pyo3 = { version = "0.28" }` (no Cargo features). | Workspace builds + tests + clippy stay clean. Test count still 445+6. |
| **2** | `feat(ffi-py): expose sum and version via #[pymodule]` | `ffi/secretary-ffi-py/src/lib.rs`: add `#[pymodule] fn secretary_ffi_py` with `#[pyfunction] sum` + `#[pyfunction] version`; add `#[cfg(test)] mod tests` with 2 Rust unit tests. (Subject preserved verbatim from git; the function was renamed to `add` in Step 5 below.) | Test count moves to 447+6; clippy clean. Python side not yet exercised. |
| **3** | `feat(ffi-py): add maturin pyproject and pytest smoke test` | New `ffi/secretary-ffi-py/pyproject.toml` and `ffi/secretary-ffi-py/tests/test_smoke.py`. | `uv run --directory ffi/secretary-ffi-py maturin develop --release` then `uv run --directory ffi/secretary-ffi-py pytest` passes (2 tests). Cargo flow unchanged from commit 2. |
| **4** | `docs(ffi-py): document build flow and B.1 scope` | New `ffi/secretary-ffi-py/README.md`: build/test commands, where the `.so` lives, what's in scope vs deferred. Cites this design doc. | None functional. |
| **5** | `refactor(ffi-py): PR #20 review fixes — rename sum→add, pin wrapping, document uv-cache trap` (`eace3e2`) | Three review-driven refinements bundled: rename the exposed `sum` to `add` (avoid shadowing Python's builtin); switch `a + b` → `a.wrapping_add(b)` and add `add_wraps_on_overflow` (Rust) + `test_add_wraps_on_overflow` (Python) pinning the wrapping contract; switch `version() as u32` → `u32::from(version())`. Plus a docs note in the FFI README documenting the uv editable-install cache-stickiness trap surfaced while validating the rename. | Test count moves to 448+6 cargo / 3 pytest; clippy clean; conformance + spec-freshness unaffected. |

**TDD ordering inside each commit:**
- Commit 2: write the 2 Rust unit tests first, watch them fail (function not yet exposed), implement.
- Commit 3: write `test_smoke.py` first, watch `import secretary_ffi_py` fail, run `maturin develop`, watch tests pass.
- Commit 5: write the wrapping regression tests first (Rust + Python), watch them fail (function not yet using `wrapping_add`), implement the rename + body change together.

## Open questions

None. All four session-start clarifying questions resolved:

1. **Lint relaxation scope** — crate-local in `secretary-ffi-py` only.
2. **Function surface** — `add` + `version`. (`version` already exists as a free function in the stub. The exposed addition was named `sum` at design time and renamed to `add` in Step 5 to avoid shadowing Python's builtin once imported at module level.)
3. **Python tests location** — `ffi/secretary-ffi-py/tests/` (FFI crate's own subdir; preserves the `core/tests/python/` "stdlib only" clean-room invariant).
4. **`pyproject.toml` location** — `ffi/secretary-ffi-py/pyproject.toml`, standalone (no top-level `pyproject.toml`).

## Risks

- **PyO3 0.28 macro expansion details could surprise.** Mitigated by the `#[cfg(test)] mod tests` Rust layer at commit 2, which exercises the macro-generated code under `cargo test --release --workspace` before the Python layer is wired up. Any macro-expansion failure surfaces at the workspace-build / test boundary, not at `maturin develop` time.
- **First `maturin develop --release` is slow** (cold cargo build of `pyo3` + transitive deps; ~30–60s on M-class hardware). Subsequent rebuilds are incremental (~2–3s). Documented in the FFI README so the user isn't surprised.
- **`requires-python = ">=3.11"` may be tighter or looser than the user's actual setup.** Verified at commit 3 by running `uv run --directory ffi/secretary-ffi-py pytest`; if `uv` errors on Python version resolution, the constraint is adjusted in the same commit.

## What this enables next

- **B.1.1:** uniffi UDL + Swift/Kotlin smoke runners on `ffi/secretary-ffi-uniffi/`. Same pattern as B.1, different binding mechanism.
- **B.2:** expose `core/`'s vault unlock + record read surface through PyO3, with `PyResult` exception marshalling for the fallible operations and a deliberate design pass on secret-lifetime across the FFI boundary.
- **External paid review:** continues to proceed in parallel — FFI work touches no `core/src/` code, so any spec clarification the external reviewer surfaces lands without conflict.
