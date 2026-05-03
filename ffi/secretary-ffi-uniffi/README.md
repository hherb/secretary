# secretary-ffi-uniffi

uniffi 0.31 bindings for [secretary-core](../../core/). Sub-project B.1.1 boilerplate — proves the UDL → cdylib → Swift binding pipeline works end-to-end with two trivial round-trip functions (`add`, `version`). Vault crypto exposure comes in B.2. Sibling of [secretary-ffi-py](../secretary-ffi-py/) which provides the same surface for Python via PyO3.

## Build & test

This crate ships **two** test layers: a Rust unit-test layer that runs as part of the workspace `cargo test`, and a macOS-host Swift smoke runner that exercises the uniffi-generated bindings through the C ABI bridge. They cross-validate each other.

### Rust layer

Runs as part of the normal workspace sweep — no swiftc / Xcode required:

```bash
cargo test --release --workspace
cargo clippy --release --workspace -- -D warnings
```

The three FFI unit tests appear in the workspace total (451 passed + 6 ignored after this crate is fully wired up).

### Swift layer (macOS host)

```bash
ffi/secretary-ffi-uniffi/tests/swift/run.sh
```

The script is self-contained — it resolves paths relative to itself, so it works from any CWD. The pipeline is:

1. `cargo build --release -p secretary-ffi-uniffi` — produces `target/release/libsecretary_ffi_uniffi.dylib` (the cdylib that Swift links against).
2. `cargo run --bin uniffi-bindgen -- generate --library ... --language swift --out-dir bindings/swift` — emits three files into `ffi/secretary-ffi-uniffi/bindings/swift/`:
   - `secretary.swift` — user-facing Swift API (calls `add` and `version`).
   - `secretaryFFI.h` — C header for the FFI bridge symbols.
   - `secretaryFFI.modulemap` — Clang module map so `import secretaryFFI` resolves.
3. `swiftc` — compiles `bindings/swift/secretary.swift` + `tests/swift/main.swift` into a single executable, linking against the cdylib via `-fmodule-map-file` (registers the C bridge as a Clang module) and `-lsecretary_ffi_uniffi` (links the cdylib symbols).
4. Execute the binary with `DYLD_LIBRARY_PATH=target/release` so the dynamic linker finds `libsecretary_ffi_uniffi.dylib` at run time.

**Cold build** is ~2–3 minutes on M-class hardware (compiles `uniffi` + transitive deps for the first time). **Warm rebuilds** after a `src/lib.rs` or UDL edit are ~5–10s.

### Iteration loop

After editing `src/lib.rs` or `src/secretary.udl`, just re-run the script:

```bash
ffi/secretary-ffi-uniffi/tests/swift/run.sh
```

Cargo picks up source changes (build.rs reads the UDL via `uniffi::generate_scaffolding`); the bindgen step regenerates the Swift files; swiftc recompiles. No equivalent of the editable-install cache trap from secretary-ffi-py — uniffi has no Python-style sticky-install layer.

### Where the build products live

- **cdylib** (committed to `target/`, gitignored): `target/release/libsecretary_ffi_uniffi.dylib`
- **Swift bindings** (gitignored, regenerated each run): `ffi/secretary-ffi-uniffi/bindings/swift/`
- **Compiled smoke runner** (gitignored): `ffi/secretary-ffi-uniffi/tests/swift/secretary_smoke`

Bindings are deliberately not committed: regenerating them on every run keeps the contract honest (any UDL drift is caught at swiftc time, not silently inherited from a stale checked-in copy).

## In-crate `uniffi-bindgen` binary

The crate ships its own `[[bin]] uniffi-bindgen` target rather than relying on a globally-installed CLI. This is Mozilla's recommended pattern for uniffi 0.30+: shipping the bindgen alongside the crate locks its version to the crate's `uniffi` dep, which prevents the version-skew bugs you hit when contributors `cargo install uniffi-bindgen-cli` at different points in time. Trade-off: each contributor runs a one-time `cargo build` of the bindgen binary; net win in determinism.

## Scope (B.1.1)

Exposed Swift surface:

| Function | Signature | Notes |
|---|---|---|
| `add(a:b:)` | `(UInt32, UInt32) -> UInt32` | Rust `u32::wrapping_add`; matches default release-build `+` semantics, which silently wrap on overflow (B.2 will reconsider when uniffi's error marshalling becomes first-class). |
| `version()` | `() -> UInt16` | Returns `secretary_core::version::FORMAT_VERSION` (currently 1). |

## What B.1.1 deliberately does NOT do

- **No Kotlin smoke runner.** Deferred to B.1.1.1 — Swift is essentially free on macOS hosts (`swiftc` ships with Xcode), Kotlin needs an additional JVM/JNI loader harness or an Android emulator. uniffi-bindgen can already emit Kotlin bindings (`--language kotlin`); only the runner is missing.
- **No vault crypto.** No `unlock`, no `open_vault`, no `Record` types. Comes in B.2.
- **No error marshalling.** All B.1.1 functions are infallible. Fallible operations (and uniffi's `[Throws]` UDL syntax) come with the first crypto-bearing function in B.2.
- **No iOS simulator integration.** macOS-host smoke runner only. iOS-target builds (which need `staticlib` in `[lib] crate-type` and an Xcode project shell) come with the iOS sub-project.
- **No CI integration for the Swift smoke runner.** Repo has no `.github/workflows/` yet (matches the deferred-CI pattern from `core/tests/python/spec_test_name_freshness.py` and the Python pytest layer); manual `tests/swift/run.sh` invocation is the source of truth until CI infrastructure lands.
- **No `uniffi.toml` per-language config.** Defaults are fine for the B.1.1 surface; per-binding renames / package names get set when B.2+ exposes a real API.

## Lint discipline

This crate replaces the inherited workspace `unsafe_code = "forbid"` with crate-local `unsafe_code = "deny"` (`uniffi::include_scaffolding!()` macro expands to FFI bridge code containing `unsafe extern "C"` blocks; `forbid` is non-overridable). The lib.rs carries a single crate-level `#![allow(unsafe_code)]` with a comment pointing at the rationale.

Any new `unsafe` block elsewhere in this crate would still trigger `deny` and require an explicit `#[allow]` with justification at that site. Same pattern as [secretary-ffi-py](../secretary-ffi-py/) for PyO3.

## References

- Decisions and plan-of-attack: [secretary_next_session.md](../../secretary_next_session.md) § "Begin Sub-project B.1.1".
- Sibling Python crate: [../secretary-ffi-py/README.md](../secretary-ffi-py/README.md).
- Project conventions inherited from the wider codebase: FFI crates are the isolated reviewed boundary for `unsafe_code` relaxation; all cargo invocations use `--release` (the underlying crypto crates are slow in debug); foreign-language bindings ship their bindgen in-crate, not as a global tool.
