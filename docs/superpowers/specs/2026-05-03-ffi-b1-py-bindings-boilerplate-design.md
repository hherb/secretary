# Sub-project B.1 — FFI Python Bindings Boilerplate

**Date:** 2026-05-03
**Author:** Horst Herb (with Claude)
**Status:** Approved — ready for implementation
**Touches:** `ffi/secretary-ffi-py/Cargo.toml`, `ffi/secretary-ffi-py/src/lib.rs`, `ffi/secretary-ffi-py/pyproject.toml` (new), `ffi/secretary-ffi-py/tests/test_smoke.py` (new), `ffi/secretary-ffi-py/README.md` (new)

## Background

Sub-project A (the Rust cryptographic core) is feature-complete for v1; Phase A.7's three internal hardening passes have closed. The next bounded unit of work per [secretary_next_session.md](../../../secretary_next_session.md) is **Sub-project B.1**: FFI binding boilerplate that proves the Python binding pipeline works end-to-end. This unblocks Sub-project C (sync orchestration) and Sub-project D (platform UIs), and runs in parallel with the gated external paid review track.

The two FFI crates exist as stubs today: [ffi/secretary-ffi-py/](../../../ffi/secretary-ffi-py/) for PyO3 (Python desktop / web) and [ffi/secretary-ffi-uniffi/](../../../ffi/secretary-ffi-uniffi/) for uniffi (Swift/Kotlin via one UDL). This spec covers the **PyO3 crate only** — uniffi is deferred to B.1.1.

## Goals

- A single `import secretary_ffi_py` from Python returns the value of two trivial Rust functions: `sum(a, b) -> u32` and `version() -> u32`.
- The build pipeline is documented end-to-end in the FFI crate's README so the next contributor doesn't have to reverse-engineer it.
- The existing `cargo test --release --workspace` baseline (445 + 6 ignored) gains the FFI Rust unit tests cleanly (→ 447 + 6).
- The existing `clippy --release --workspace -- -D warnings` invariant continues to hold.
- The workspace `unsafe_code = "forbid"` invariant stays intact for `core/` and `secretary-ffi-uniffi/`. Only the PyO3 crate gets a localized relaxation, with the rationale committed.

## Non-goals (YAGNI)

- **No vault crypto exposed.** No `unlock`, no `open_vault`, no `Record` types. The PyO3 surface is just `sum` + `version`. Vault crypto exposure is B.2+ and warrants its own design pass (lifetime-of-secret across the FFI boundary, zeroize discipline through Python's GC, error-type marshalling).
- **No Swift / Kotlin smoke runners.** `secretary-ffi-uniffi` stays as the existing stub. UDL design + uniffi-bindgen wiring is B.1.1.
- **No CI integration for the Python pytest layer.** Repo has no `.github/workflows/` yet (matches the deferred-CI pattern from `spec_test_name_freshness.py`); the FFI README documents the manual invocation.
- **No top-level `pyproject.toml`.** Each FFI crate self-describes its Python build under its own directory.
- **No `PyResult` / exception marshalling.** `sum` uses default `+` (debug-panics on overflow, release-wraps). Fallible surface comes with B.2.
- **No multi-version Python matrix.** Whatever `uv` resolves; pinned via `requires-python` in `pyproject.toml`.
- **No abi3 / stable ABI.** Build for whatever Python version `uv` resolves; abi3 is a release-engineering decision for a future B.x.

## Architecture

### Files

| File | Status | Purpose |
|---|---|---|
| `ffi/secretary-ffi-py/Cargo.toml` | edit | Add `pyo3 = { version = "0.28", features = ["extension-module"] }`. Replace `[lints] workspace = true` with crate-local lint table (see *Lints & invariants*). |
| `ffi/secretary-ffi-py/src/lib.rs` | edit | Add `#[pymodule] mod secretary_ffi_py { ... }` exposing `sum(a: u32, b: u32) -> u32` and `version() -> u32`. Keep the existing free function `version()` for Rust callers and Rust unit tests. Add `#[cfg(test)] mod tests` with two unit tests. |
| `ffi/secretary-ffi-py/pyproject.toml` | **new** | Build-system: `maturin>=1.7,<2.0`. Dev deps: `pytest`. Module name: `secretary_ffi_py`. `requires-python = ">=3.11"`. |
| `ffi/secretary-ffi-py/tests/test_smoke.py` | **new** | Pytest: `import secretary_ffi_py`, assert `sum(2, 3) == 5` and `version() == 1` (matches `secretary_core::version::FORMAT_VERSION`). |
| `ffi/secretary-ffi-py/README.md` | **new** | Documents the build / test flow per acceptance criterion 5 of NEXT_SESSION.md (the "where does the Python build product live" answer). Cites this design doc. |

No files outside the FFI crate change. Root `Cargo.toml` workspace lints stay untouched. No top-level `pyproject.toml`. `secretary-ffi-uniffi` stub untouched.

### Test layers

Two independent layers, each runnable on its own:

| Layer | Where | Runs via | Proves |
|---|---|---|---|
| **Rust unit tests** | `ffi/secretary-ffi-py/src/lib.rs` `#[cfg(test)] mod tests` | `cargo test --release --workspace` | The Rust functions return the expected values when called directly. Adds 2 tests to the existing 445+6 baseline → 447+6. No Python interpreter involved. |
| **Python smoke tests** | `ffi/secretary-ffi-py/tests/test_smoke.py` | `uv run --directory ffi/secretary-ffi-py pytest` (after `maturin develop`) | The maturin-built wheel installs cleanly into a `uv` venv, `import secretary_ffi_py` works, and the same two functions return the same values when called from Python. Proves the binding pipeline end-to-end. |

The split is load-bearing: the Rust layer keeps `cargo test --release --workspace` self-contained — no `uv` / Python / maturin required. The Python layer is gated on `maturin develop` having run first, but is independent of the Rust suite. They cross-validate each other: a logic bug in `sum` fails both layers; an FFI marshalling bug fails only the Python layer; a build/install bug stops the Python layer from running at all (clear failure signal).

### Build flow

The single answer to NEXT_SESSION.md's hardest sub-question (criterion 5):

```bash
# One-time setup (after first checkout, or after Cargo.toml deps change):
uv run --directory ffi/secretary-ffi-py maturin develop --release

# Builds the cdylib, packages as a Python wheel, installs into the
# uv-managed venv at ffi/secretary-ffi-py/.venv/. After this:
#   - The compiled .so/.dylib lives inside the venv's site-packages,
#     NOT in the source tree (no rogue .so files to .gitignore).
#   - `import secretary_ffi_py` works from anything `uv run`-ed in
#     that directory.
#   - `--release` matches the project's "always --release" posture.

# Run the smoke tests:
uv run --directory ffi/secretary-ffi-py pytest

# Iterate on Rust source:
#   1. Edit src/lib.rs
#   2. uv run --directory ffi/secretary-ffi-py maturin develop --release
#   3. uv run --directory ffi/secretary-ffi-py pytest
# (Step 2 is incremental; ~2-3s after the first cold build.)

# Rust-only flow stays identical:
cargo test --release --workspace        # 447+6 (was 445+6)
cargo clippy --release --workspace -- -D warnings
```

The build artifact lives in `ffi/secretary-ffi-py/.venv/site-packages/`. The repo's existing [.gitignore](../../../.gitignore) already covers `.venv` (line 73), `*.so` (line 7), and `.pytest_cache/` (line 51) — no `.gitignore` change needed.

### Lints & invariants

The workspace currently sets `unsafe_code = "forbid"` ([root Cargo.toml](../../../Cargo.toml)) and the FFI crate inherits via `[lints] workspace = true`. PyO3's `#[pymodule]` / `#[pyfunction]` macros expand to user-crate code containing `unsafe` blocks (the bridge to the CPython C-API is inherently unsafe). `forbid` is non-overridable by inner `#[allow]`, so PyO3 will fail to compile in `secretary-ffi-py` unless the inheritance is relaxed.

**Decision (B.1):** the FFI crate replaces `[lints] workspace = true` with its own lint table that uses `unsafe_code = "deny"` (locally overridable per-call-site), and the `#[pymodule]` block in `lib.rs` carries `#[allow(unsafe_code)]`. The workspace only defines `[workspace.lints.rust] unsafe_code = "forbid"` today (no clippy or rustdoc lint tables), so the crate-local replacement is a single line: `[lints.rust] unsafe_code = "deny"`.

**Why this scope:** matches CLAUDE.md's existing principle: *"If a primitive truly needs FFI, isolate it in its own crate behind a reviewed boundary."* Workspace `forbid` stays intact for `core/` and `secretary-ffi-uniffi`. Any new `unsafe` block elsewhere in the FFI crate would still trigger a `deny` error and require an explicit `#[allow]` with justification.

**The macro site:**

```rust
use pyo3::prelude::*;

/// Python-callable surface for secretary-core.
///
/// The crate-local lint relaxation (`unsafe_code = "deny"` instead of
/// the workspace `forbid`) and the `#[allow(unsafe_code)]` here are
/// the minimal escape hatch needed for PyO3's #[pymodule] / #[pyfunction]
/// macros to compile. Rationale: see
/// docs/superpowers/specs/2026-05-03-ffi-b1-py-bindings-boilerplate-design.md
#[allow(unsafe_code)]
#[pymodule]
mod secretary_ffi_py {
    use pyo3::prelude::*;

    #[pyfunction]
    fn sum(a: u32, b: u32) -> u32 {
        a + b
    }

    #[pyfunction]
    fn version() -> u32 {
        super::version() as u32
    }
}

/// Smoke test: returns the vault format version exposed by the core crate.
/// Kept as a free function so Rust callers (and Rust unit tests) can use
/// it without going through PyO3 / a Python interpreter.
pub fn version() -> u16 {
    secretary_core::version::FORMAT_VERSION
}
```

`sum`'s overflow handling: default `a + b` (debug-panics, release-wraps). Saturation / `PyResult<u32>` overflow plumbing is deferred to B.2 when fallible crypto operations make `PyResult` a first-class citizen.

## Implementation plan

Five commits on `feat/ffi-b1-py-bindings-boilerplate` (worktree at `.worktrees/feat-ffi-b1-py-bindings-boilerplate/`), each leaving the workspace green (`cargo test --release --workspace` + `cargo clippy --release --workspace -- -D warnings`):

| # | Title | Diff scope | Verification |
|---|---|---|---|
| **0** | `docs(spec): B.1 FFI Python bindings boilerplate design` | This file. | None functional. |
| **1** | `chore(ffi-py): relax workspace unsafe_code lint and add pyo3 dep` | `ffi/secretary-ffi-py/Cargo.toml` only: replace `[lints] workspace = true` with `[lints.rust] unsafe_code = "deny"` (the only workspace lint set today); add `pyo3 = { version = "0.28", features = ["extension-module"] }`. | Workspace builds + tests + clippy stay clean. Test count still 445+6. |
| **2** | `feat(ffi-py): expose sum and version via #[pymodule]` | `ffi/secretary-ffi-py/src/lib.rs`: add `#[pymodule] mod secretary_ffi_py` with `#[pyfunction] sum` + `#[pyfunction] version`; add `#[cfg(test)] mod tests` with 2 Rust unit tests. | Test count moves to 447+6; clippy clean. Python side not yet exercised. |
| **3** | `feat(ffi-py): add maturin pyproject and pytest smoke test` | New `ffi/secretary-ffi-py/pyproject.toml` and `ffi/secretary-ffi-py/tests/test_smoke.py`. | `uv run --directory ffi/secretary-ffi-py maturin develop --release` then `uv run --directory ffi/secretary-ffi-py pytest` passes. Cargo flow unchanged from commit 2. |
| **4** | `docs(ffi-py): document build flow and B.1 scope` | New `ffi/secretary-ffi-py/README.md`: build/test commands, where the `.so` lives, what's in scope vs deferred. Cites this design doc. | None functional. |

**TDD ordering inside each commit:**
- Commit 2: write the 2 Rust unit tests first, watch them fail (function not yet exposed), implement.
- Commit 3: write `test_smoke.py` first, watch `import secretary_ffi_py` fail, run `maturin develop`, watch tests pass.

## Open questions

None. All four session-start clarifying questions resolved:

1. **Lint relaxation scope** — crate-local in `secretary-ffi-py` only.
2. **Function surface** — `sum` + `version` (both, since `version` already exists as a free function in the stub).
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
