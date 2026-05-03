# secretary-ffi-uniffi

uniffi 0.31 bindings for [secretary-core](../../core/). Sub-project B.1.1 / B.1.1.1 boilerplate — proves the UDL → cdylib → Swift / Kotlin binding pipeline works end-to-end with two trivial round-trip functions (`add`, `version`). Vault crypto exposure comes in B.2. Sibling of [secretary-ffi-py](../secretary-ffi-py/) which provides the same surface for Python via PyO3.

## Build & test

This crate ships **three** test layers: a Rust unit-test layer that runs as part of the workspace `cargo test`, a macOS-host Swift smoke runner, and a JVM-host Kotlin smoke runner. The two foreign-language layers each exercise the uniffi-generated bindings through the C ABI bridge — Swift via direct `swiftc` linking, Kotlin via JNA. All three layers assert the same three pinned values, so a contract change in any one fails in all three places.

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
2. `cargo run --release --features cli -p secretary-ffi-uniffi --bin uniffi-bindgen -- generate --library ... --language swift --out-dir bindings/swift` — emits three files into `ffi/secretary-ffi-uniffi/bindings/swift/` (`--features cli` enables the gated bindgen binary; `--release` matches step 1's profile so cargo reuses the compiled uniffi + transitive deps):
   - `secretary.swift` — user-facing Swift API (calls `add` and `version`).
   - `secretaryFFI.h` — C header for the FFI bridge symbols.
   - `secretaryFFI.modulemap` — Clang module map so `import secretaryFFI` resolves.
3. `swiftc` — compiles `bindings/swift/secretary.swift` + `tests/swift/main.swift` into a single executable, linking against the cdylib via `-fmodule-map-file` (registers the C bridge as a Clang module) and `-lsecretary_ffi_uniffi` (links the cdylib symbols).
4. Execute the binary with `DYLD_LIBRARY_PATH=target/release` so the dynamic linker finds `libsecretary_ffi_uniffi.dylib` at run time.

**Cold build** is ~2–3 minutes on M-class hardware (compiles `uniffi` + transitive deps for the first time). **Warm rebuilds** after a `src/lib.rs` or UDL edit are ~5–10s.

### Kotlin layer (JVM host)

```bash
ffi/secretary-ffi-uniffi/tests/kotlin/run.sh
```

Self-contained like the Swift runner. Pipeline:

1. `cargo build --release -p secretary-ffi-uniffi` — same cdylib, reused if already built.
2. `cargo run --release --features cli -p secretary-ffi-uniffi --bin uniffi-bindgen -- generate --library ... --language kotlin --out-dir bindings/kotlin` — emits `bindings/kotlin/uniffi/secretary/secretary.kt` (single file; package `uniffi.secretary`).
3. **JNA fetch.** uniffi 0.31's Kotlin bindings depend on [JNA](https://github.com/java-native-access/jna) for the `Native.register` bridge. The script fetches `jna-5.14.0.jar` from Maven Central into `tests/kotlin/lib/` (gitignored) on first run, with **SHA-256 verification** on every invocation (cached or not). Version pin + checksum live as `JNA_VERSION` / `JNA_SHA256` constants near the top of `run.sh`.
4. `kotlinc -include-runtime -d secretary_smoke.jar` — compiles the generated bindings + `Main.kt` into a single fat jar (Kotlin stdlib bundled in).
5. Execute with `java -Djna.library.path=$TARGET_DIR -cp secretary_smoke.jar:jna.jar MainKt` so JNA finds `libsecretary_ffi_uniffi.dylib` at runtime. Top-level `main()` in `Main.kt` compiles to the implicit `MainKt` class.

**Prerequisites** (one-time): `kotlinc` (e.g. `brew install kotlin` on macOS, `sdk install kotlin` via SDKMAN on Linux) and a JDK 17+. The runner sanity-checks both and emits an actionable error if either is missing.

**Cold build** mirrors the Swift runner (~2–3 min cdylib compile shared between layers); the Kotlin-specific steps add ~10–15s for kotlinc + the first-run JNA fetch. **Warm rebuilds** are ~5–10s.

### Iteration loop

After editing `src/lib.rs` or `src/secretary.udl`, just re-run either runner:

```bash
ffi/secretary-ffi-uniffi/tests/swift/run.sh    # macOS host
ffi/secretary-ffi-uniffi/tests/kotlin/run.sh   # JVM host (any platform)
```

Cargo picks up source changes (build.rs reads the UDL via `uniffi::generate_scaffolding`); the bindgen step regenerates the foreign-language files; the foreign compiler recompiles. No equivalent of the editable-install cache trap from secretary-ffi-py — uniffi has no Python-style sticky-install layer.

### Where the build products live

- **cdylib** (under `target/`, gitignored): `target/release/libsecretary_ffi_uniffi.dylib`
- **Swift bindings** (gitignored, regenerated each run): `ffi/secretary-ffi-uniffi/bindings/swift/`
- **Kotlin bindings** (gitignored, regenerated each run): `ffi/secretary-ffi-uniffi/bindings/kotlin/uniffi/secretary/secretary.kt`
- **Compiled Swift smoke runner** (gitignored): `ffi/secretary-ffi-uniffi/tests/swift/secretary_smoke`
- **Compiled Kotlin smoke jar** (gitignored): `ffi/secretary-ffi-uniffi/tests/kotlin/secretary_smoke.jar`
- **Cached JNA jar** (gitignored, integrity-pinned): `ffi/secretary-ffi-uniffi/tests/kotlin/lib/jna-5.14.0.jar`

Bindings are deliberately not committed: regenerating them on every run keeps the contract honest (any UDL drift is caught at compile time in the foreign language, not silently inherited from a stale checked-in copy).

## In-crate `uniffi-bindgen` binary

The crate ships its own `[[bin]] uniffi-bindgen` target rather than relying on a globally-installed CLI. This is Mozilla's recommended pattern for uniffi 0.30+: shipping the bindgen alongside the crate locks its version to the crate's `uniffi` dep, which prevents the version-skew bugs you hit when contributors `cargo install uniffi-bindgen-cli` at different points in time. Trade-off: each contributor runs a one-time `cargo build` of the bindgen binary; net win in determinism.

The bindgen target is gated behind a crate-local `cli` feature (`required-features = ["cli"]` in `Cargo.toml`) so its clap + askama transitives don't land in the cdylib's default dependency tree. `cargo build --workspace` and downstream consumers see the cdylib without those deps; the bindgen binary is built only when the smoke-runner script (or any explicit invocation) passes `--features cli`.

## Scope (B.1.1 + B.1.1.1)

Exposed surface, identical across both bindings:

| Function | Swift signature | Kotlin signature | Notes |
|---|---|---|---|
| `add` | `(UInt32, UInt32) -> UInt32` | `(UInt, UInt) -> UInt` | Rust `u32::wrapping_add`; matches default release-build `+` semantics, which silently wrap on overflow (B.2 will reconsider when uniffi's error marshalling becomes first-class). |
| `version` | `() -> UInt16` | `() -> UShort` | Returns `secretary_core::version::FORMAT_VERSION` (currently 1). |

## What B.1.1 / B.1.1.1 deliberately do NOT do

- **No vault crypto.** No `unlock`, no `open_vault`, no `Record` types. Comes in B.2.
- **No error marshalling.** All B.1.1 functions are infallible. Fallible operations (and uniffi's `[Throws]` UDL syntax) come with the first crypto-bearing function in B.2.
- **No iOS simulator integration.** macOS-host Swift runner only. iOS-target builds (which need `staticlib` in `[lib] crate-type` and an Xcode project shell) come with the iOS sub-project.
- **No Android emulator integration.** JVM-host Kotlin runner only. Android-target builds (which need cross-compilation to `aarch64-linux-android` / `armv7-linux-androideabi` / `x86_64-linux-android`, a Gradle module, and the Android Gradle Plugin) come with the Android sub-project.
- **No CI integration for the foreign-language smoke runners.** Repo has no `.github/workflows/` yet (matches the deferred-CI pattern from `core/tests/python/spec_test_name_freshness.py` and the Python pytest layer); manual `tests/swift/run.sh` / `tests/kotlin/run.sh` invocation is the source of truth until CI infrastructure lands.
- **No `uniffi.toml` per-language config.** Defaults are fine for the B.1.1 surface; per-binding renames / package names get set when B.2+ exposes a real API.

## Lint discipline

This crate replaces the inherited workspace `unsafe_code = "forbid"` with crate-local `unsafe_code = "deny"` (`uniffi::include_scaffolding!()` macro expands to FFI bridge code containing `unsafe extern "C"` blocks; `forbid` is non-overridable). The lib.rs carries a single crate-level `#![allow(unsafe_code)]` with a comment pointing at the rationale.

Any new `unsafe` block elsewhere in this crate would still trigger `deny` and require an explicit `#[allow]` with justification at that site. Same pattern as [secretary-ffi-py](../secretary-ffi-py/) for PyO3.

## References

- Decisions and plan-of-attack: [secretary_next_session.md](../../secretary_next_session.md) § "Begin Sub-project B.1.1" and § "Begin Sub-project B.1.1.1 — Kotlin smoke runner".
- Sibling Python crate: [../secretary-ffi-py/README.md](../secretary-ffi-py/README.md).
- Project conventions inherited from the wider codebase: FFI crates are the isolated reviewed boundary for `unsafe_code` relaxation; all cargo invocations use `--release` (the underlying crypto crates are slow in debug); foreign-language bindings ship their bindgen in-crate, not as a global tool.
