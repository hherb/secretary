# B.1 — FFI Python Bindings Boilerplate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Post-PR-#20-review addendum (2026-05-03):** Three review-driven fixes landed after the four-task plan below executed and are not back-ported into the per-task content — read them as overrides:
> 1. The exposed function `sum` was renamed to `add` (avoid shadowing Python's builtin `sum()` once imported). Below references to `sum` should be read as `add`. The historical commit subject `e98f684` ("expose sum and version via #[pymodule]") preserves the original name in git history.
> 2. The body switched from `a + b` to `a.wrapping_add(b)` and added `add_wraps_on_overflow` (Rust) plus `test_add_wraps_on_overflow` (Python) pinning `add(u32::MAX, 1) == 0`.
> 3. `version() as u32` switched to `u32::from(version())` (lossless widening via `From`).
>
> **Final test counts:** `cargo test --release --workspace` → 448 + 6 ignored (was 447 + 6 in the body); pytest → 3 (was 2 in the body).

**Goal:** Wire PyO3 + maturin into [ffi/secretary-ffi-py](../../../ffi/secretary-ffi-py/) so that `import secretary_ffi_py; sum(2, 3) == 5` and `version() == 1` work end-to-end from Python — proving the binding pipeline before exposing any vault crypto in B.2.

**Architecture:** Function-style `#[pymodule]` entrypoint plus two top-level `#[pyfunction]` items in a single `src/lib.rs`. Crate-local lint relaxation (`unsafe_code = "deny"` replacing inherited workspace `forbid`) and `#![allow(unsafe_code)]` at the lib.rs top — the minimal escape hatch for PyO3's macros, which expand to `unsafe` blocks (the CPython C-API bridge is inherently unsafe). Maturin builds the wheel into a `uv`-managed venv at `ffi/secretary-ffi-py/.venv/`; the compiled `.so` lives in the venv's `site-packages/`, not in the source tree. Two test layers: Rust unit tests via `cargo test --release --workspace`, Python pytest via `uv run --directory ffi/secretary-ffi-py pytest` after `maturin develop`.

**Tech Stack:** Rust 1.87 stable, PyO3 0.28, maturin 1.9.4+ (required for `PYO3_BUILD_EXTENSION_MODULE` env-var auto-set), uv 0.6+, pytest, Python 3.11+

**Spec:** [docs/superpowers/specs/2026-05-03-ffi-b1-py-bindings-boilerplate-design.md](../specs/2026-05-03-ffi-b1-py-bindings-boilerplate-design.md)

**Worktree:** `.worktrees/feat-ffi-b1-py-bindings-boilerplate/` on branch `feat/ffi-b1-py-bindings-boilerplate`. Spec doc commit `3bc0cea` is already in place; tasks below produce commits 1–4 of the cluster.

**Note on deviation from spec:** The spec doc's code sample showed the declarative `#[pymodule] mod secretary_ffi_py { ... }` style. This plan uses the function-style `#[pymodule] fn secretary_ffi_py(...)` style instead — same Python-side behaviour, but avoids the awkward inner-module-named-the-same-as-the-crate, keeps `#[pyfunction]` items at crate root for direct testability without `pub(super)` visibility games, and is the time-tested PyO3 idiom. Both styles work in PyO3 0.28; the declarative style's value (nested modules, `#[pymodule_export]`) isn't needed at B.1 scope.

---

## File structure

After all four tasks complete, [ffi/secretary-ffi-py/](../../../ffi/secretary-ffi-py/) contains:

| File | Status | Responsibility |
|---|---|---|
| `Cargo.toml` | modified | PyO3 dep, crate-local `[lints.rust]` table replacing workspace inheritance |
| `src/lib.rs` | modified | `#[pymodule]` entrypoint, two `#[pyfunction]`s, the underlying `pub fn version()` for Rust callers, two `#[cfg(test)]` unit tests |
| `pyproject.toml` | **new** | Maturin build backend, pytest dev dep, Python version constraint |
| `tests/test_smoke.py` | **new** | Pytest mirroring the Rust unit tests against the maturin-built wheel |
| `README.md` | **new** | Build/test commands, "where does the .so live", in-scope vs deferred |

No files outside `ffi/secretary-ffi-py/` change.

---

## Task 1: Workspace integration — relax lint inheritance and add PyO3 dep

**Files:**
- Modify: `ffi/secretary-ffi-py/Cargo.toml`

This commit is Cargo.toml-only. No source change yet, so the source-level `#![forbid(unsafe_code)]` at `src/lib.rs:1` keeps the FFI crate effectively `forbid` until Task 2 lifts it. Workspace tests + clippy must stay green.

- [ ] **Step 1: Verify the current `Cargo.toml` baseline**

Run from worktree root:

```bash
cat ffi/secretary-ffi-py/Cargo.toml
```

Expected: shows `[lints] workspace = true` at the bottom and no `pyo3` dependency. If anything else differs from the file's current state, stop and reconcile.

- [ ] **Step 2: Edit `ffi/secretary-ffi-py/Cargo.toml`**

Replace the existing file with:

```toml
[package]
name = "secretary-ffi-py"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true
description = "PyO3 binding stub for secretary-core. Smoke-test only; full bindings live in the desktop sub-project."

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
secretary-core = { path = "../../core" }
pyo3 = { version = "0.28", features = ["extension-module"] }

# Crate-local lint table replacing the inherited workspace `unsafe_code = "forbid"`.
# PyO3's #[pymodule] / #[pyfunction] macros expand to user-crate code containing
# unsafe blocks (the CPython C-API bridge is inherently unsafe). `forbid` is
# non-overridable by inner #[allow], so this crate downgrades to `deny` and the
# lib.rs `#![allow(unsafe_code)]` covers the macro expansions. The workspace
# only sets `unsafe_code = "forbid"` today (no clippy / rustdoc lint tables),
# so this single line is the entire crate-local table.
# Decision: docs/superpowers/specs/2026-05-03-ffi-b1-py-bindings-boilerplate-design.md
[lints.rust]
unsafe_code = "deny"
```

- [ ] **Step 3: Verify the workspace still builds, tests pass, clippy is clean**

Run from worktree root:

```bash
cargo build --release --workspace
```

Expected: completes successfully (PyO3 + transitive deps will compile for the first time; expect ~30–60s on M-class hardware).

```bash
cargo test --release --workspace 2>&1 | grep -E "test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "passed:", passed, "failed:", failed, "ignored:", ignored}'
```

Expected output: `passed: 445 failed: 0 ignored: 6` (no source change, baseline unchanged).

```bash
cargo clippy --release --workspace -- -D warnings 2>&1 | tail -5
```

Expected: completes with no warnings, exit code 0.

- [ ] **Step 4: Commit**

```bash
git add ffi/secretary-ffi-py/Cargo.toml
git commit -m "$(cat <<'EOF'
chore(ffi-py): relax workspace unsafe_code lint and add pyo3 dep

PyO3's #[pymodule] / #[pyfunction] macros expand to unsafe blocks
(the CPython C-API bridge is inherently unsafe). The workspace
sets `unsafe_code = "forbid"` which is non-overridable, so this
crate replaces `[lints] workspace = true` with crate-local
`[lints.rust] unsafe_code = "deny"`. The workspace forbid stays
intact for core/ and secretary-ffi-uniffi.

No source change in this commit; the source-level
#![forbid(unsafe_code)] in src/lib.rs keeps the crate effectively
forbid until commit 2 wires the pymodule in.

Adds pyo3 = { version = "0.28", features = ["extension-module"] }.

Spec: docs/superpowers/specs/2026-05-03-ffi-b1-py-bindings-boilerplate-design.md

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: PyO3 wiring + Rust unit tests

**Files:**
- Modify: `ffi/secretary-ffi-py/src/lib.rs`

TDD ordering: write the two failing Rust unit tests first; watch them fail (compile error — `sum` doesn't exist; `version` returns `u16` so the test against the new `u32`-returning surface fails). Then implement.

- [ ] **Step 1: Write the failing tests first**

Replace `ffi/secretary-ffi-py/src/lib.rs` entirely with the test-only scaffold below. (We're inverting the usual "add tests next to existing code" because TDD says tests come first; the production code lands in Step 3.)

```rust
//! Python bindings for secretary-core via PyO3.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_format_version() {
        assert_eq!(version(), secretary_core::version::FORMAT_VERSION);
    }

    #[test]
    fn sum_returns_arithmetic_sum() {
        assert_eq!(sum(2, 3), 5);
    }
}
```

Note: the file-level `#![forbid(unsafe_code)]` from the previous version is removed — it would block PyO3's macros in Step 3. The `pub fn version()` helper from the previous version is also removed and will come back in Step 3 alongside the `#[pyfunction]` items.

- [ ] **Step 2: Run the tests; confirm they fail**

```bash
cargo test --release --workspace --package secretary-ffi-py 2>&1 | tail -20
```

Expected: compile error — `cannot find function 'sum' in this scope`, `cannot find function 'version' in this scope`. This proves the tests are exercising the to-be-added surface.

- [ ] **Step 3: Implement the production code**

Replace `ffi/secretary-ffi-py/src/lib.rs` with:

```rust
//! Python bindings for secretary-core via PyO3.
//!
//! The crate-level `#![allow(unsafe_code)]` is the minimal escape hatch
//! for PyO3's #[pymodule] / #[pyfunction] macros, which expand to unsafe
//! blocks (the CPython C-API bridge is inherently unsafe). The crate-local
//! lint relaxation (workspace `forbid` → crate-local `deny`) is required
//! because `forbid` is non-overridable by inner #[allow]; see Cargo.toml.
//! Rationale: docs/superpowers/specs/2026-05-03-ffi-b1-py-bindings-boilerplate-design.md

#![allow(unsafe_code)]

use pyo3::prelude::*;

/// Returns the vault format version exposed by the core crate.
///
/// Kept as a free function so Rust callers (and the Rust unit tests below)
/// can use it without going through PyO3 / a Python interpreter.
pub fn version() -> u16 {
    secretary_core::version::FORMAT_VERSION
}

/// Python-exposed addition. B.1 round-trip target. Wraps on overflow in
/// release builds (matches default Rust `+`); B.2 will reconsider when
/// fallible crypto operations make `PyResult` first-class.
#[pyfunction]
fn sum(a: u32, b: u32) -> u32 {
    a + b
}

/// Python-exposed wrapper around `version()`. Renamed at the PyO3 layer
/// from the Rust ident `version_py` to the Python name `version` so the
/// Python-side surface stays clean.
#[pyfunction]
#[pyo3(name = "version")]
fn version_py() -> u32 {
    version() as u32
}

/// `#[pymodule]` entrypoint. The function name (`secretary_ffi_py`) is the
/// Python module name that `import` looks up; it must match the wheel name
/// declared in `pyproject.toml` (`[tool.maturin] module-name`).
#[pymodule]
fn secretary_ffi_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sum, m)?)?;
    m.add_function(wrap_pyfunction!(version_py, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_format_version() {
        assert_eq!(version(), secretary_core::version::FORMAT_VERSION);
    }

    #[test]
    fn sum_returns_arithmetic_sum() {
        assert_eq!(sum(2, 3), 5);
    }
}
```

- [ ] **Step 4: Run the tests; confirm they pass**

```bash
cargo test --release --workspace --package secretary-ffi-py 2>&1 | tail -10
```

Expected: 2 passed (`version_returns_format_version`, `sum_returns_arithmetic_sum`).

```bash
cargo test --release --workspace 2>&1 | grep -E "test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "passed:", passed, "failed:", failed, "ignored:", ignored}'
```

Expected output: `passed: 447 failed: 0 ignored: 6` (was 445; +2 from the new tests).

- [ ] **Step 5: Verify clippy is still clean**

```bash
cargo clippy --release --workspace -- -D warnings 2>&1 | tail -5
```

Expected: completes with no warnings, exit code 0.

- [ ] **Step 6: Commit**

```bash
git add ffi/secretary-ffi-py/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(ffi-py): expose sum and version via #[pymodule]

Wires the PyO3 entry point: a single `secretary_ffi_py` Python
module exposing `sum(a, b) -> u32` and `version() -> u32` (the
latter wraps the existing Rust `version()` helper, which still
returns u16 for Rust callers).

TDD: two #[cfg(test)] unit tests pin both surfaces. Test count
moves from 445 to 447 (+2). Python side wires up in commit 3.

Removes the file-level #![forbid(unsafe_code)] (the workspace
relaxation in Cargo.toml from the previous commit only takes
effect once the file-level forbid is also lifted) and adds
crate-level #![allow(unsafe_code)] for the PyO3 macros.

Spec: docs/superpowers/specs/2026-05-03-ffi-b1-py-bindings-boilerplate-design.md

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Maturin pyproject + pytest smoke

**Files:**
- Create: `ffi/secretary-ffi-py/pyproject.toml`
- Create: `ffi/secretary-ffi-py/tests/test_smoke.py`

TDD ordering: write the failing pytest first; watch `import secretary_ffi_py` fail (the wheel isn't built yet); run `maturin develop`; watch tests pass.

- [ ] **Step 1: Write the failing Python test first**

Create `ffi/secretary-ffi-py/tests/test_smoke.py`:

```python
"""B.1 round-trip smoke tests for the secretary_ffi_py PyO3 extension.

These tests assert the same surface as the Rust #[cfg(test)] unit tests in
src/lib.rs, exercised through the maturin-built wheel and Python's import
machinery. They prove the binding pipeline (PyO3 + maturin + uv venv +
import) works end-to-end.
"""

import secretary_ffi_py


def test_sum_returns_arithmetic_sum() -> None:
    assert secretary_ffi_py.sum(2, 3) == 5


def test_version_matches_format_version() -> None:
    # FORMAT_VERSION is pinned at 1 in core/src/version.rs; if the Rust
    # core bumps the format version this test will fail and demand an
    # explicit update — that's intentional, the wire-format constant is
    # security-critical and shouldn't drift silently.
    assert secretary_ffi_py.version() == 1
```

- [ ] **Step 2: Create the maturin `pyproject.toml`**

Create `ffi/secretary-ffi-py/pyproject.toml`:

```toml
[build-system]
requires = ["maturin>=1.9.4,<2.0"]
build-backend = "maturin"

[project]
name = "secretary_ffi_py"
description = "PyO3 bindings for secretary-core (B.1 boilerplate)."
requires-python = ">=3.11"
license = { text = "AGPL-3.0-or-later" }
dynamic = ["version"]
classifiers = [
    "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)",
    "Programming Language :: Rust",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3 :: Only",
]

[dependency-groups]
# maturin is also declared in [build-system] requires (it's the build
# backend that uv invokes during `uv sync` to build the cdylib wheel).
# Listing it again here puts it in the project venv so `uv run --directory
# ffi/secretary-ffi-py maturin develop --release` works for the iteration
# loop without needing `uvx maturin` (which uses an unpinned tool cache).
dev = ["pytest>=8.0", "maturin>=1.9.4,<2.0"]

[tool.maturin]
# Module name as it appears to Python (`import secretary_ffi_py`). Must
# match the function name on `#[pymodule]` in src/lib.rs.
module-name = "secretary_ffi_py"
# No Cargo features declared here: PyO3 0.28 deprecated the
# `extension-module` feature in favor of the `PYO3_BUILD_EXTENSION_MODULE`
# environment variable, which `maturin >= 1.9.4` sets automatically when
# building wheels. Keeping the deprecated feature would break `cargo test`
# (libpython linking is suppressed). `--release` is passed on the maturin
# command line (`uv run ... maturin develop --release`), matching the
# project's "always --release" posture for the slow crypto deps.
```

- [ ] **Step 3: Run pytest BEFORE `uv sync` to observe the failing import**

Run from worktree root:

```bash
# Without uv sync first — the venv either doesn't exist yet or doesn't
# have secretary_ffi_py installed. This is the TDD "watch it fail" step.
uv run --directory ffi/secretary-ffi-py --no-sync pytest 2>&1 | tail -10
```

Expected: pytest collection error — `ModuleNotFoundError: No module named 'secretary_ffi_py'` (or `error: project requires sync`, depending on uv version — either is the expected failure mode that proves the wheel isn't yet built/installed).

**If you forget `--no-sync` and uv runs `sync` automatically:** the wheel will be built as part of dependency resolution (uv treats the maturin `[build-system]` as a build-backend and invokes it during sync), and pytest will go straight to PASS. That's not a bug — it's an artifact of uv's PEP 517 integration. The TDD intent (verifying the test exercises the right surface) is satisfied as long as Step 5 below shows 2 passing tests.

- [ ] **Step 4: Build and install the wheel via `uv sync` (which invokes maturin) OR explicit `maturin develop`**

```bash
# Option A (canonical for first-time setup): let uv sync do the build
uv sync --directory ffi/secretary-ffi-py 2>&1 | tail -10

# Option B (canonical for iteration after editing src/lib.rs): explicit
# maturin develop. Requires maturin in dev deps (see Step 2's pyproject.toml).
uv run --directory ffi/secretary-ffi-py maturin develop --release 2>&1 | tail -10
```

Expected: maturin builds the cdylib, packages as a wheel, and installs it editable into the project's `.venv/`. You'll see `📦 Built wheel for CPython 3.12 to .../secretary_ffi_py-...-cp312-cp312-...whl` and `🛠 Installed secretary_ffi_py-0.1.0`. Cold build is ~30–60s (compiles `pyo3` + transitive deps); warm rebuilds are ~2–3s.

- [ ] **Step 5: Run pytest; confirm it now passes**

```bash
uv run --directory ffi/secretary-ffi-py pytest 2>&1 | tail -10
```

Expected: 2 passed (`test_sum_returns_arithmetic_sum`, `test_version_matches_format_version`). 0 failed.

- [ ] **Step 6: Verify cargo test + clippy are still clean**

```bash
cargo test --release --workspace 2>&1 | grep -E "test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "passed:", passed, "failed:", failed, "ignored:", ignored}'
cargo clippy --release --workspace -- -D warnings 2>&1 | tail -3
```

Expected: `passed: 447 failed: 0 ignored: 6` and clippy clean.

- [ ] **Step 7: Verify nothing accidentally got staged**

```bash
git status
```

Expected: only `ffi/secretary-ffi-py/pyproject.toml` and `ffi/secretary-ffi-py/tests/test_smoke.py` show as untracked. The `ffi/secretary-ffi-py/.venv/`, `ffi/secretary-ffi-py/target/`, `ffi/secretary-ffi-py/uv.lock` should all be gitignored or otherwise filtered. If `uv.lock` shows as untracked, it should be committed (it pins the test runner's Python deps for reproducibility); add it in the commit below.

- [ ] **Step 8: Commit**

```bash
git add ffi/secretary-ffi-py/pyproject.toml ffi/secretary-ffi-py/tests/test_smoke.py
# Add uv.lock if Step 7 surfaced it as untracked:
git add ffi/secretary-ffi-py/uv.lock 2>/dev/null || true
git commit -m "$(cat <<'EOF'
feat(ffi-py): add maturin pyproject and pytest smoke test

Closes the B.1 round-trip end-to-end. After running
`uv run --directory ffi/secretary-ffi-py maturin develop --release`
the maturin-built wheel installs into ffi/secretary-ffi-py/.venv/
and `uv run --directory ffi/secretary-ffi-py pytest` asserts the
same surface as the Rust unit tests (sum(2,3)==5, version()==1).

pyproject.toml uses maturin>=1.9.4,<2.0 as the build backend
requires-python = ">=3.11" matches the project's available
Python (uv resolves 3.12.3 today). Module name is set to
`secretary_ffi_py` to match the #[pymodule] entry-point name.

Spec: docs/superpowers/specs/2026-05-03-ffi-b1-py-bindings-boilerplate-design.md

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: README documenting build flow

**Files:**
- Create: `ffi/secretary-ffi-py/README.md`

This task is documentation only — no functional change. The README is the answer to NEXT_SESSION.md acceptance criterion 5 ("where does the Python build product live so that `uv run` can import it").

- [ ] **Step 1: Create `ffi/secretary-ffi-py/README.md`**

```markdown
# secretary-ffi-py

PyO3 + maturin bindings for [secretary-core](../../core/). Sub-project B.1 boilerplate — proves the binding pipeline works end-to-end with two trivial round-trip functions (`sum`, `version`). Vault crypto exposure comes in B.2.

## Build & test

This crate ships **two** test layers: a Rust unit-test layer that runs as part of the workspace `cargo test`, and a Python pytest layer that exercises the maturin-built wheel through Python's import machinery. They cross-validate each other.

### Rust layer

Runs as part of the normal workspace sweep — no Python / maturin / uv required:

```bash
cargo test --release --workspace
cargo clippy --release --workspace -- -D warnings
```

The two FFI unit tests appear in the workspace total (447 passed + 6 ignored after this crate is fully wired up).

### Python layer

```bash
# One-time setup (after first checkout): uv sync invokes the maturin
# build-backend automatically and installs the editable wheel into
# ffi/secretary-ffi-py/.venv/.
uv sync --directory ffi/secretary-ffi-py

# Run the smoke tests:
uv run --directory ffi/secretary-ffi-py pytest
```

`uv sync` resolves the `[build-system] requires` table (which lists `maturin>=1.9.4,<2.0`), spins up an isolated PEP 517 build env, runs `maturin build`, and installs the resulting wheel as an editable package into the project venv at `ffi/secretary-ffi-py/.venv/`. The compiled `.so` (or `.dylib` on macOS) lives in the venv's `site-packages/` — **not** in the source tree, so there are no rogue binaries to gitignore.

**Cold build** is ~30–60s on M-class hardware (compiles `pyo3` + transitive deps for the first time). **Warm rebuilds** after a `src/lib.rs` edit are ~2–3s.

### Iteration loop

After editing `src/lib.rs`, you need an explicit rebuild — `uv sync` won't notice Rust source changes. Use `maturin develop` (it's in the `[dependency-groups] dev` table so `uv run` finds it):

```bash
# Edit src/lib.rs, then:
uv run --directory ffi/secretary-ffi-py maturin develop --release
uv run --directory ffi/secretary-ffi-py pytest
```

`--release` matches the project's "always --release" posture (the underlying crypto crates are slow in debug; PyO3 + transitive deps benefit from the same posture).

## Scope (B.1)

Exposed Python surface:

| Function | Signature | Notes |
|---|---|---|
| `sum(a, b)` | `(int, int) -> int` | Rust `u32 + u32`; release-wraps on overflow (B.2 will reconsider when `PyResult` becomes first-class). |
| `version()` | `() -> int` | Returns `secretary_core::version::FORMAT_VERSION` (currently 1). |

## What B.1 deliberately does NOT do

- **No vault crypto.** No `unlock`, no `open_vault`, no `Record` types. Comes in B.2.
- **No exception marshalling.** All B.1 functions are infallible. Fallible operations (and `PyResult` ergonomics) come with the first crypto-bearing function in B.2.
- **No CI integration for the Python pytest layer.** Repo has no `.github/workflows/` yet (matches the deferred-CI pattern from `core/tests/python/spec_test_name_freshness.py`); the manual invocation above is the source of truth until CI infrastructure lands.
- **No multi-version Python matrix.** Whatever `uv` resolves under `requires-python = ">=3.11"`.
- **No abi3 / stable ABI.** Build for whatever Python version `uv` resolves; abi3 is a release-engineering decision for a future B.x.
- **No Swift / Kotlin bindings.** Lives in `secretary-ffi-uniffi`; B.1.1+.

## Lint discipline

This crate replaces the inherited workspace `unsafe_code = "forbid"` with crate-local `unsafe_code = "deny"` (PyO3 macros expand to `unsafe` blocks; `forbid` is non-overridable). The lib.rs carries a single crate-level `#![allow(unsafe_code)]` with a comment pointing at the design doc. Workspace `forbid` stays intact for `core/` and `secretary-ffi-uniffi`.

Any new `unsafe` block elsewhere in this crate would still trigger `deny` and require an explicit `#[allow]` with justification at that site.

## References

- Design: [docs/superpowers/specs/2026-05-03-ffi-b1-py-bindings-boilerplate-design.md](../../docs/superpowers/specs/2026-05-03-ffi-b1-py-bindings-boilerplate-design.md)
- Plan: [docs/superpowers/plans/2026-05-03-ffi-b1-py-bindings-boilerplate.md](../../docs/superpowers/plans/2026-05-03-ffi-b1-py-bindings-boilerplate.md)
- Project convention: [CLAUDE.md](../../CLAUDE.md) (FFI as isolated reviewed boundary; "always --release" posture; uv exclusive)
```

- [ ] **Step 2: Verify the README renders cleanly (links resolve, no broken markdown)**

```bash
cat ffi/secretary-ffi-py/README.md | head -20
```

Expected: shows the title and the first ~20 lines as written. (No GitHub-flavored markdown linter is in the repo today; visual inspection is sufficient at B.1 scope.)

- [ ] **Step 3: Commit**

```bash
git add ffi/secretary-ffi-py/README.md
git commit -m "$(cat <<'EOF'
docs(ffi-py): document build flow and B.1 scope

Answers the "where does the Python build product live so that
uv run can import it" question raised in NEXT_SESSION.md
acceptance criterion 5: maturin develop installs the wheel into
ffi/secretary-ffi-py/.venv/site-packages/, no rogue .so in the
source tree.

Documents the two-layer test discipline (Rust unit tests via
cargo, Python pytest via uv after maturin develop), the
iteration loop, the explicit YAGNI list, and the lint
relaxation rationale.

Spec: docs/superpowers/specs/2026-05-03-ffi-b1-py-bindings-boilerplate-design.md

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Final verification (after Task 4)

- [ ] **Step 1: Workspace sweep**

```bash
cargo test --release --workspace 2>&1 | grep -E "test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "passed:", passed, "failed:", failed, "ignored:", ignored}'
cargo clippy --release --workspace -- -D warnings 2>&1 | tail -3
```

Expected: `passed: 447 failed: 0 ignored: 6` and clippy clean.

- [ ] **Step 2: Python smoke sweep**

```bash
uv run --directory ffi/secretary-ffi-py pytest 2>&1 | tail -10
```

Expected: 2 passed, 0 failed.

- [ ] **Step 3: Conformance & spec-freshness baselines unchanged**

```bash
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
```

Expected: conformance reports all 5 sections PASS; spec-freshness shows `96 resolved + 0 unresolved + 2 allowlisted` (or `97 + 0 + 2` if the new design / plan / README docs introduced new test-name citations the freshness script picks up — both are acceptable as long as `unresolved == 0`).

- [ ] **Step 4: Branch state check**

```bash
git log --oneline main..HEAD
```

Expected: 13 commits, all on `feat/ffi-b1-py-bindings-boilerplate`. The original 5-commit estimate (spec doc + 4 task commits) grew to 13 because mid-stream code review surfaced four corrections — the PyO3 0.28 `extension-module` deprecation, the maturin dev-deps requirement, the pytest `testpaths` declaration, and a broken `CLAUDE.md` link in the README — each fixed in its own commit per the project's "step by step, one issue per commit" preference, with matching spec/plan amendments.

- [ ] **Step 5: Worktree cleanup posture**

The implementation work is complete. Per the project's `superpowers:finishing-a-development-branch` flow, the next step is to push the branch and open a PR for review. **Do not** auto-push or auto-PR — those are user-driven decisions per CLAUDE.md (any action visible to others is gated on explicit user authorization).

---

## Self-review (writing-plans skill checklist)

**Spec coverage:** Each spec section has at least one task implementing it.
- "Files" table → Tasks 1 (Cargo.toml) + 2 (lib.rs) + 3 (pyproject.toml + tests) + 4 (README). ✓
- "Test layers" → Task 2 (Rust) + Task 3 (Python). ✓
- "Build flow" → Task 3 (executes the flow); Task 4 (documents it). ✓
- "Lints & invariants" → Task 1 (Cargo.toml) + Task 2 (lib.rs `#![allow]`). ✓
- "Implementation plan" 5-commit table → Task 1, 2, 3, 4 are commits 1-4 of the cluster (commit 0 is the already-landed spec doc commit `3bc0cea`). ✓
- "Risks" → first `maturin develop` slowness called out in Task 3 Step 4 expected output; `requires-python` constraint is exercised by Task 3 Step 3 `uv sync`. ✓

**Placeholder scan:** No "TBD", "TODO", "implement later" anywhere in the plan. Every code block is concrete; every command has expected output. ✓

**Type consistency:** `sum(a: u32, b: u32) -> u32` consistent across spec, Task 2, Task 3, Task 4 README. `version() -> u16` (Rust free fn) and `version() -> u32` (Python-exposed wrapper via `version_py` Rust ident with `#[pyo3(name = "version")]` rename) consistent across Task 2 and Task 3. The `secretary_ffi_py` module name is consistent across `#[pymodule]` fn name (Task 2), `[tool.maturin] module-name` (Task 3), and `import secretary_ffi_py` (Task 3 + Task 4). ✓

No issues to fix.
