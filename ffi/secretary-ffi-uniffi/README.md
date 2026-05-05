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

> **B.3a (this version) adds the recovery-phrase unlock path on top of B.2's password-path surface; see [Vault unlock — recovery path (B.3a)](#vault-unlock--recovery-path-b3a) at the bottom of this README. B.2 (`open_with_password`) is still current; see [Vault unlock (B.2)](#vault-unlock-b2). The sections below are kept as historical context.**


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

## Vault unlock (B.2)

UDL adds: `interface UnlockedIdentity` (opaque handle), `[Error]
interface UnlockError`, and namespace function
`[Throws=UnlockError] open_with_password(bytes, bytes, bytes) ->
UnlockedIdentity`. (As of B.3a the same `[Error] interface UnlockError`
spans five variants — see the [B.3a section](#vault-unlock--recovery-path-b3a)
below.)

The Rust-side `UnlockedIdentity::close()` is renamed to `wipe()` on
the uniffi projection because uniffi 0.31's Kotlin codegen
auto-generates `AutoCloseable.close()` on every interface handle, and
a UDL-declared `close()` would collide. The bridge crate's API is
unchanged; only the uniffi projection renames it.

`CorruptVault.message` was likewise renamed to `detail` in B.2 to
avoid a Kotlin `Throwable.message` collision. In B.3a the bridge
crate field itself was renamed to `detail` for naming uniformity with
the new `InvalidMnemonic { detail }` variant; the uniffi codegen
still produces `detail` on the foreign side, just now without a
Kotlin-only rename in between.

### Swift idiom (`defer { wipe() }`)

```swift
import secretary

let toml = try Data(contentsOf: vaultTomlURL)
let bundle = try Data(contentsOf: identityBundleURL)
let password = "my password".data(using: .utf8)!

let identity = try openWithPassword(
    vaultTomlBytes: toml,
    identityBundleBytes: bundle,
    password: password
)
defer { identity.wipe() }    // pin explicit zeroize at scope exit

print(identity.displayName())
print(identity.userUuid())

// Error path:
do {
    let _ = try openWithPassword(...)
} catch UnlockError.WrongPasswordOrCorrupt {
    // ...
} catch let UnlockError.CorruptVault(detail) {
    print("Vault corrupt: \(detail)")
}
```

### Kotlin idiom (`.use { }`)

uniffi 0.31's Kotlin codegen auto-implements `AutoCloseable` on
`UnlockedIdentity`, so Kotlin's stdlib `.use { }` works directly — no
hand-rolled extension function needed.

```kotlin
import uniffi.secretary.*

val toml = Files.readAllBytes(vaultTomlPath)
val bundle = Files.readAllBytes(identityBundlePath)
val password = "my password".toByteArray(Charsets.UTF_8)

openWithPassword(
    vaultTomlBytes = toml,
    identityBundleBytes = bundle,
    password = password,
).use { identity ->
    println(identity.displayName())
    println(identity.userUuid().contentToString())
}
// .use exit → AutoCloseable.close() → Rust refcount → 0 → Drop → zeroize.
// To zeroize earlier inside the block, call identity.wipe() explicitly.

// Error path:
try {
    openWithPassword(...)
} catch (e: UnlockException.WrongPasswordOrCorrupt) {
    // ...
} catch (e: UnlockException.CorruptVault) {
    println("Vault corrupt: ${e.detail}")
}
```

### Password-input discipline (caller-zeroize)

Same as the Python crate: passwords accepted as **bytes** (`Data` in
Swift, `ByteArray` in Kotlin), not `String`. The Rust-side projection
zeroizes its transient `Vec<u8>` after the bridge returns; first-party
clients should additionally zero their mutable buffer after the call.

### Test fixtures via env var

The Swift / Kotlin smoke runners read `SECRETARY_GOLDEN_VAULT_DIR`
(set by `run.sh`) for the `core/tests/data/` parent directory; runners
append `golden_vault_001` or `golden_vault_002` as needed. Standalone
runs (without `run.sh`) fail loudly with an actionable error message.

### Test coverage

12 Swift asserts + 12 Kotlin asserts (3 B.1.1 smoke + 5 B.2 unlock +
4 B.3a unlock each): B.2 covers the success path, wrong password,
cross-vault mismatch (vault_001 toml + vault_002 bundle), truncated
TOML, and explicit-`wipe()` use-after-close behaviour. B.3a adds the
parallel four for the recovery path (see the [B.3a section](#vault-unlock--recovery-path-b3a)
below). Both runners share the `SECRETARY_GOLDEN_VAULT_DIR` fixture
path with the bridge-crate Rust tests and the Python pytest suite —
KAT drift cannot land silently.

## Vault unlock — recovery path (B.3a)

UDL adds: 2 new variants on `[Error] interface UnlockError`
(`WrongMnemonicOrCorrupt`, `InvalidMnemonic(string detail)`) and
1 new namespace function
`[Throws=UnlockError] open_with_recovery(bytes, bytes, bytes) ->
UnlockedIdentity`. Mnemonic input is `bytes` (UTF-8 encoded BIP-39
phrase), parallel to B.2's password input shape. The bridge does
`std::str::from_utf8` and surfaces malformed-UTF-8 input as
`InvalidMnemonic(detail: "phrase contained invalid UTF-8")`.

### Swift idiom (`defer { wipe() }`)

```swift
import secretary

let toml = try Data(contentsOf: vaultTomlURL)
let bundle = try Data(contentsOf: identityBundleURL)
let phrase: [UInt8] = Array("abandon abandon ... 24 words".utf8)

do {
    let identity = try openWithRecovery(
        vaultTomlBytes: toml,
        identityBundleBytes: bundle,
        mnemonic: phrase
    )
    defer { identity.wipe() }    // pin explicit zeroize at scope exit
    print(identity.displayName())
} catch UnlockError.WrongMnemonicOrCorrupt {
    // Phrase is wrong, OR vault tampered with — §13 anti-oracle
    // conflation, parallel to WrongPasswordOrCorrupt for the
    // password path.
} catch let UnlockError.InvalidMnemonic(detail) {
    // Pre-decryption validation failure: wrong word count, unknown
    // word, bad checksum, or invalid UTF-8. NOT an oracle.
    print("Invalid phrase: \(detail)")
} catch UnlockError.VaultMismatch {
    // ...
} catch let UnlockError.CorruptVault(detail) {
    print("Vault corrupt: \(detail)")
}
```

### Kotlin idiom (`.use { }`)

```kotlin
import uniffi.secretary.*

val toml = Files.readAllBytes(vaultTomlPath)
val bundle = Files.readAllBytes(identityBundlePath)
val phrase = "abandon abandon ... 24 words".toByteArray(Charsets.UTF_8)

try {
    openWithRecovery(
        vaultTomlBytes = toml,
        identityBundleBytes = bundle,
        mnemonic = phrase,
    ).use { identity ->
        println(identity.displayName())
    }
} catch (e: UnlockException.WrongMnemonicOrCorrupt) {
    // ...
} catch (e: UnlockException.InvalidMnemonic) {
    println("Invalid phrase: ${e.detail}")
} catch (e: UnlockException.VaultMismatch) {
    // ...
} catch (e: UnlockException.CorruptVault) {
    println("Vault corrupt: ${e.detail}")
} finally {
    phrase.fill(0)   // caller-side zeroize discipline
}
```

The single `UnlockError` (Swift) / `UnlockException` (Kotlin) enum
spans both unlock entry points; foreign callers do not maintain two
error types. The variants they need to handle differ by which entry
point they called: `WrongPasswordOrCorrupt` vs `WrongMnemonicOrCorrupt`
are mutually exclusive by call site. `VaultMismatch` and
`CorruptVault` apply to both.

### Mnemonic-input discipline (caller-zeroize)

Same shape as the password input: `Data` in Swift, `ByteArray` in
Kotlin (not `String`). The mnemonic is *more secret* than the
password (it derives the recovery KEK; compromising it permanently
unlocks the vault), so first-party clients MUST pass a mutable buffer
and zero it after the call — strings are immutable in both languages
and cannot be zeroized.

The Rust-side projection wraps the input as an owned `Vec<u8>` and
zeroizes it after the bridge call returns; first-party clients
should additionally zero their foreign-side buffer.

### Test fixtures via env var

The Swift / Kotlin smoke runners read `recovery_mnemonic_phrase` from
`golden_vault_{001,002}_inputs.json` at runtime — no hardcoded
24-word strings in the smoke runners. The phrase is mathematically
determined by the already-pinned recovery entropy in those JSON
files; a `bip39::Mnemonic::from_entropy(entropy).to_string() ==
pinned_phrase` drift-detection assertion in `core/tests/common/fixture_builder.rs`
keeps the JSON pin honest.

