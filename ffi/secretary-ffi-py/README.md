# secretary-ffi-py

PyO3 + maturin bindings for [secretary-core](../../core/). Sub-project B.1 boilerplate — proves the binding pipeline works end-to-end with two trivial round-trip functions (`add`, `version`). Vault crypto exposure comes in B.2.

## Build & test

This crate ships **two** test layers: a Rust unit-test layer that runs as part of the workspace `cargo test`, and a Python pytest layer that exercises the maturin-built wheel through Python's import machinery. They cross-validate each other.

### Rust layer

Runs as part of the normal workspace sweep — no Python / maturin / uv required:

```bash
cargo test --release --workspace
cargo clippy --release --workspace -- -D warnings
```

The three FFI unit tests appear in the workspace total (448 passed + 6 ignored after this crate is fully wired up).

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

### Cache-stickiness gotcha when iterating on the Python surface

If you rename or add a `#[pyfunction]` and pytest reports `module 'secretary_ffi_py' has no attribute '<new_name>'` — but `cargo test --release --workspace` passes the renamed Rust unit tests — the build is fine; the install is stale.

Cause: uv's editable-install cache (`~/.cache/uv/sdists-v9/editable/*` and `~/.cache/uv/archive-v0/*`) keys on `<package>-<version>`, and `pyproject.toml` declares a static `version = "0.1.0"` (via `dynamic = ["version"]` falling through to `Cargo.toml`'s workspace version). Every rebuild produces wheels with the same name+version, so uv treats them as equivalent and on the next `uv run` / `uv sync` it auto-restores the *first* wheel's `.so` into the venv — silently undoing the freshly-built one.

Quick diagnostic:

```bash
shasum target/maturin/libsecretary_ffi_py.dylib \
       ffi/secretary-ffi-py/.venv/lib/python3.12/site-packages/secretary_ffi_py/*.so
# Hashes should match. If they don't, the install is stale.
```

Nuclear fix that always works (≈ 8s rebuild from clean state):

```bash
rm -rf ffi/secretary-ffi-py/.venv
find ~/.cache/uv -name "*secretary*" -exec rm -rf {} +
uv sync --directory ffi/secretary-ffi-py
```

`uv sync` invokes the maturin build-backend automatically and installs the editable wheel fresh, so a separate `maturin develop` is not needed after this. The trap is **specific to maturin + uv editable installs** — the sibling [secretary-ffi-uniffi](../secretary-ffi-uniffi/) crate has no equivalent (cargo + swiftc only, no Python-style sticky-install layer).

## Scope (B.1)

Exposed Python surface:

| Function | Signature | Notes |
|---|---|---|
| `add(a, b)` | `(int, int) -> int` | Rust `u32::wrapping_add`; matches default release-build `+` semantics, which silently wrap on overflow (B.2 will reconsider when `PyResult` becomes first-class). Named `add` rather than `sum` to avoid shadowing Python's builtin. |
| `version()` | `() -> int` | Returns `secretary_core::version::FORMAT_VERSION` (currently 1). |

## What B.1 deliberately does NOT do

- **No vault crypto.** No `unlock`, no `open_vault`, no `Record` types. Comes in B.2.
- **No exception marshalling.** All B.1 functions are infallible. Fallible operations (and `PyResult` ergonomics) come with the first crypto-bearing function in B.2.
- **No CI integration for the Python pytest layer.** Repo has no `.github/workflows/` yet (matches the deferred-CI pattern from `core/tests/python/spec_test_name_freshness.py`); the manual invocation above is the source of truth until CI infrastructure lands.
- **No multi-version Python matrix.** Whatever `uv` resolves under `requires-python = ">=3.11"`.
- **No abi3 / stable ABI.** Build for whatever Python version `uv` resolves; abi3 is a release-engineering decision for a future B.x.
- **No Swift / Kotlin bindings.** Lives in [secretary-ffi-uniffi](../secretary-ffi-uniffi/) (Swift landed in B.1.1; Kotlin smoke runner deferred to B.1.1.1).

## Lint discipline

This crate replaces the inherited workspace `unsafe_code = "forbid"` with crate-local `unsafe_code = "deny"` (PyO3 macros expand to `unsafe` blocks; `forbid` is non-overridable). The lib.rs carries a single crate-level `#![allow(unsafe_code)]` with a comment pointing at the design doc. Workspace `forbid` stays intact for `core/`. The sibling [secretary-ffi-uniffi](../secretary-ffi-uniffi/) crate adopted the same `forbid → deny` carve-out in B.1.1 for its uniffi macro expansions.

Any new `unsafe` block elsewhere in this crate would still trigger `deny` and require an explicit `#[allow]` with justification at that site.

## References

- Design: [docs/superpowers/specs/2026-05-03-ffi-b1-py-bindings-boilerplate-design.md](../../docs/superpowers/specs/2026-05-03-ffi-b1-py-bindings-boilerplate-design.md)
- Plan: [docs/superpowers/plans/2026-05-03-ffi-b1-py-bindings-boilerplate.md](../../docs/superpowers/plans/2026-05-03-ffi-b1-py-bindings-boilerplate.md)
- Project conventions inherited from the wider codebase: FFI crates are the isolated reviewed boundary for `unsafe_code` relaxation; all cargo invocations use `--release` (the underlying crypto crates are slow in debug); Python tooling is `uv` exclusively (never `pip`).
