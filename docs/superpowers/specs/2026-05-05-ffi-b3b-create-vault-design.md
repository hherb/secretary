# Sub-project B.3b — FFI Vault Creation

**Date:** 2026-05-05
**Author:** Horst Herb (with Claude)
**Status:** Approved — ready for implementation plan
**Touches:** edits in `ffi/secretary-ffi-bridge/`, `ffi/secretary-ffi-py/`, `ffi/secretary-ffi-uniffi/`; no `core/` changes; no on-disk fixture changes.

## Background

Sub-project B.3a ([design](2026-05-04-ffi-b3a-recovery-unlock-design.md), [PR #26](https://github.com/hherb/secretary/pull/26)) shipped `open_with_recovery` — the second of the two unlock paths — through both PyO3 and uniffi via the existing shared `secretary-ffi-bridge` crate. With both unlock entry points exposed and the 5-variant `FfiUnlockError` settled, the FFI surface has consumed every input-direction secret-bearing operation in `secretary_core::unlock`.

B.3b closes the remaining v1 surface gap: `create_vault`, the operation that produces a fresh vault. The architectural delta from B.3a is that it is the first **output-direction** secret-bearing operation — the freshly-generated 24-word BIP-39 mnemonic must reach the foreign caller exactly once so the user can write it down, then disappear from the system. This re-opens the deferred-from-B.2 question: **how does `Sensitive<T>` materialize on the foreign side?** This spec answers that question with a one-shot opaque handle pattern that mirrors the explicit-close discipline already chosen for `UnlockedIdentity`.

The core API being exposed is [`secretary_core::unlock::create_vault`](../../../core/src/unlock/mod.rs#L127):

```rust
pub fn create_vault(
    password: &SecretBytes,
    display_name: &str,
    created_at_ms: u64,
    kdf_params: Argon2idParams,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<CreatedVault, UnlockError>;

pub struct CreatedVault {
    pub vault_toml_bytes: Vec<u8>,
    pub identity_bundle_bytes: Vec<u8>,
    pub recovery_mnemonic: Mnemonic,         // <-- the new design problem
    pub identity_block_key: Sensitive<[u8; 32]>,
    pub identity: bundle::IdentityBundle,
}
```

This spec defines the FFI projection of that single fallible operation through both PyO3 and uniffi, with the design discipline established by B.2 and B.3a: **architectural soundness and long-term maintainability over short-term ship velocity**.

## Goals

- Expose `create_vault` through both FFI flavors (PyO3 → Python; uniffi → Swift/Kotlin) using the same shared `secretary-ffi-bridge` crate as B.2 and B.3a.
- Bridge instantiates **`OsRng` and `Argon2idParams::V1_DEFAULT` internally**; foreign callers get neither knob. Production-safe-only.
- The freshly-generated 24-word mnemonic reaches the foreign caller via a **separate one-shot opaque `MnemonicOutput` handle** with `take_phrase() -> Option<Vec<u8>>` and explicit `wipe()`. Returns `None` on the second call (one-shot semantics, not an error). The returned `Vec<u8>` exits the `Sensitive<T>` boundary as plain heap-allocated bytes; the caller is responsible for zeroizing it after use, parallel to the input-side caller-zeroize discipline from B.2/B.3a.
- The successfully-created vault's `UnlockedIdentity` is returned alongside — **immediately live, no second `open_with_password` call needed**. The `CreateVaultOutput` is a 4-field struct: `(vault_toml_bytes, identity_bundle_bytes, identity, mnemonic)`.
- The 5-variant `FfiUnlockError` shape from B.3a is **structurally unchanged**. Hardcoding `V1_DEFAULT` makes `WeakKdfParams` unreachable through B.3b's surface (it stays defensively folded into `CorruptVault` for forward-compat). The only error-side edit is a Display-text tweak: `CorruptVault` becomes `"vault data integrity failure: {detail}"` (path-neutral), replacing the read-path-only `"vault is corrupt or unreadable: {detail}"`.
- All B.2 + B.3a gates remain green and counts grow predictably: cargo workspace +~5, pytest +~6, Swift smoke +~3, Kotlin smoke +~3, bridge unit tests +~5.

## Non-goals (YAGNI)

- **No `create_vault_unchecked` exposure.** The unsafe-for-production sub-floor entry point exists in core for test speed only; the FFI must not expose it.
- **No foreign-side `Argon2idParams` knob.** Bridge always passes `V1_DEFAULT`. First-party clients want the conservative default; tuning is a v2 design conversation, not an FFI runtime parameter.
- **No foreign-side RNG control.** Bridge always uses `OsRng`. Reproducibility tests use core's `create_vault_unchecked` directly with seeded RNG — that's `cargo test`'s job, not the FFI smoke runners'.
- **No public-key accessors** on `UnlockedIdentity` — same as B.2 / B.3a; deferred until contact-card / sharing operations need them.
- **No secret-key accessors** — same as B.2 / B.3a.
- **No mnemonic re-derivation accessor** on the post-create `UnlockedIdentity`. The mnemonic crosses the FFI exactly once via `MnemonicOutput.take_phrase()`. After that, it does not exist anywhere in the system that the foreign caller can reach.
- **No promotion of `WeakKdfParams` to its own variant.** With `V1_DEFAULT` hardcoded the variant is unreachable; the existing `From<core::UnlockError>` defensive arm folds it into `CorruptVault { detail }` for forward-compat. If a future B.3c re-introduces foreign-side params, that's the right time to revisit.
- **No new variant `CreateFailed`.** `create_vault`'s reachable failure paths under V1_DEFAULT are extremely rare (Argon2id system-OOM, CBOR serialization of a well-formed Rust struct) and fold cleanly into the existing `CorruptVault { detail }`. The Display tweak (`"vault data integrity failure"`) makes that reuse correct on both directions.
- **No on-disk fixture changes.** No new `golden_vault_NNN/` directories. `create_vault` produces fresh randomness; round-trip assertions (create-then-open) become the contract pin instead.
- **No conformance.py extension.** Same rationale as B.3a — the create-path is documented in `docs/crypto-design.md` §3/§4 well enough for a clean-room reader; adding a stdlib-only Argon2id implementation to `conformance.py` would be enormous effort with no spec-contract benefit.
- **No CI integration.** Still no `.github/workflows/`.

## Architecture

### Crate layout after B.3b

Strictly additive on top of B.3a; one new file in the bridge crate, no removed files.

```
ffi/
├── secretary-ffi-bridge/        ← single source of code truth
│   └── src/
│       ├── lib.rs               ← edit: re-export create_vault, CreateVaultOutput, MnemonicOutput
│       ├── error.rs             ← edit: Display string tweak only ("vault data integrity failure: ...")
│       ├── identity.rs          ← UNCHANGED
│       ├── unlock.rs            ← UNCHANGED
│       └── create.rs            ← NEW: pub fn create_vault, CreateVaultOutput, MnemonicOutput, +5 tests
│
├── secretary-ffi-py/             ← +1 #[pyfunction], +2 #[pyclass], +6 pytest
└── secretary-ffi-uniffi/         ← +1 namespace fn, +1 dictionary, +1 interface, +3 Swift, +3 Kotlin
```

The bridge crate stays pure-safe Rust; the workspace's `#![forbid(unsafe_code)]` invariant applies. The two binding-flavor crates retain their existing crate-local `unsafe_code = "deny"` carve-outs (B.1 / B.1.1 era) for the FFI macros.

`create.rs` is a new file — distinct from `unlock.rs` because creation is a different verb, and `unlock.rs` is already at ~150 lines. Keeping the file-per-concern split preserves the 500-line ceiling comfortably.

### What lives where

| Concern | Bridge crate | secretary-ffi-py | secretary-ffi-uniffi |
|---|---|---|---|
| `create_vault(&[u8], &str, u64) -> Result<CreateVaultOutput, FfiUnlockError>` | ✓ — calls core::create_vault, builds CreateVaultOutput | thin `#[pyfunction]` forwarder | thin `pub fn` forwarder |
| `CreateVaultOutput { vault_toml_bytes, identity_bundle_bytes, identity, mnemonic }` | ✓ — struct definition | `#[pyclass]` newtype | `pub struct` newtype |
| `MnemonicOutput` (one-shot opaque handle) | ✓ — `Mutex<Option<Mnemonic>>` newtype | `#[pyclass]` newtype with `__enter__`/`__exit__` | `pub struct` newtype, AutoCloseable via uniffi 0.31 codegen |
| `OsRng` instantiation | ✓ — bridge owns it | ✗ | ✗ |
| `Argon2idParams::V1_DEFAULT` selection | ✓ — bridge owns it | ✗ | ✗ |
| Wrapper-side `Vec<u8>` zeroize for password input | ✗ | `#[pyfunction]` body zeroizes the owned `Vec<u8>` after the bridge call | `pub fn` body zeroizes the owned `Vec<u8>` after the bridge call |
| `FfiUnlockError` variants + `From<core::UnlockError>` | ✓ (unchanged from B.3a; only Display string tweak) | unchanged | unchanged |
| `UnlockedIdentity` wrapper + accessors + `wipe()` | ✓ (unchanged from B.2) | `#[pyclass]` newtype unchanged | `pub struct` newtype unchanged |

### API surface — bridge crate signatures

```rust
// ffi/secretary-ffi-bridge/src/create.rs

use std::sync::Mutex;
use rand_core::OsRng;
use secretary_core::crypto::kdf::Argon2idParams;
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::unlock::{self, mnemonic::Mnemonic};
use crate::error::FfiUnlockError;
use crate::identity::UnlockedIdentity;

/// Output of [`create_vault`]. Holds the on-disk byte artifacts plus two
/// opaque handles for the live identity and the one-shot recovery mnemonic.
///
/// **Drop discipline:** fields drop in source order. Non-secret byte vectors
/// drop first; the two secret-bearing handles last (each zeroizing their own
/// inner state on drop). The order is observable but not load-bearing —
/// neither secret depends on the other for cleanup.
pub struct CreateVaultOutput {
    pub vault_toml_bytes: Vec<u8>,
    pub identity_bundle_bytes: Vec<u8>,
    pub identity: UnlockedIdentity,
    pub mnemonic: MnemonicOutput,
}

/// One-shot opaque handle wrapping a freshly-generated [`Mnemonic`].
///
/// The recovery phrase is `Sensitive<String>`-equivalent on the Rust side;
/// it cannot be projected directly through the FFI without copying out of
/// the `Sensitive<T>` boundary (no foreign language has a generic
/// `Sensitive<T>` analog). [`take_phrase`] does that copy explicitly,
/// once, then drops the inner Mnemonic so its `Drop` impl zeroizes both
/// the `String` phrase and the `Sensitive<[u8; 32]>` entropy.
///
/// The returned `Vec<u8>` is fresh caller-owned heap. Callers MUST zeroize
/// it after use (e.g. Python `for i in range(len(buf)): buf[i] = 0`,
/// Swift `phrase.withUnsafeMutableBytes { buf in buf.initializeMemory(... 0) }`,
/// Kotlin `phrase.fill(0)`). The bridge cannot enforce this from across the
/// FFI; the documentation contract mirrors the input-side caller-zeroize
/// discipline from B.2/B.3a, but inverted in direction.
pub struct MnemonicOutput {
    inner: Mutex<Option<Mnemonic>>,
}

impl MnemonicOutput {
    pub(crate) fn new(m: Mnemonic) -> Self {
        Self {
            inner: Mutex::new(Some(m)),
        }
    }

    /// Take the recovery phrase as freshly-allocated UTF-8 bytes. ONE-SHOT —
    /// subsequent calls return `None`.
    ///
    /// The inner `Mnemonic` is consumed and dropped here; its `Drop` impl
    /// zeroizes the `String` phrase and the `Sensitive<[u8; 32]>` entropy.
    /// The returned `Vec<u8>` was copied OUT of the about-to-be-zeroized
    /// `String` BEFORE the drop, so it survives intact for the caller to
    /// display, copy, and explicitly zeroize.
    ///
    /// `None` is the documented signal for "already consumed", not an
    /// error. The foreign call sites use `if let Some(phrase) = ...`
    /// (Swift), `phrase?.let { ... }` (Kotlin), or `phrase = ...; if phrase
    /// is None: ...` (Python).
    pub fn take_phrase(&self) -> Option<Vec<u8>> {
        let mut guard = self
            .inner
            .lock()
            .expect("MnemonicOutput mutex poisoned; this should be impossible");
        let m = guard.take()?;
        let bytes = m.phrase().as_bytes().to_vec();
        // m drops at end-of-scope; Mnemonic's Drop zeroizes phrase + entropy
        Some(bytes)
    }

    /// Idempotent explicit close. Drops the inner [`Mnemonic`] if still
    /// present, zeroizing its secret state. Safe to call multiple times;
    /// safe to call after [`take_phrase`] returned `Some`.
    pub fn wipe(&self) {
        let mut guard = self
            .inner
            .lock()
            .expect("MnemonicOutput mutex poisoned; this should be impossible");
        let _ = guard.take();
    }
}

/// Create a fresh v1 vault using `OsRng` and `Argon2idParams::V1_DEFAULT`.
/// See module docs for the rationale on why neither knob is exposed.
///
/// On success, returns:
/// - `vault_toml_bytes` and `identity_bundle_bytes` — non-secret byte
///   artifacts the caller MUST persist atomically before considering the
///   vault created.
/// - `identity` — a live `UnlockedIdentity` ready for vault operations
///   without a second `open_with_password` call.
/// - `mnemonic` — a one-shot `MnemonicOutput`. The caller is expected to
///   `take_phrase()` once, display the phrase to the user as a
///   recovery affordance, then zeroize their copy and `wipe()` the handle.
///
/// # Errors
///
/// Returns [`FfiUnlockError`]; under the hardcoded `V1_DEFAULT` design,
/// the only reachable variant is [`FfiUnlockError::CorruptVault`], which
/// fires on extremely rare paths: Argon2id derivation failure (system OOM
/// / threading) or CBOR serialization failure of the in-memory identity
/// bundle. The `detail` string carries the original `core::UnlockError`'s
/// `Display` text.
pub fn create_vault(
    password: &[u8],
    display_name: &str,
    created_at_ms: u64,
) -> Result<CreateVaultOutput, FfiUnlockError> {
    let pw = SecretBytes::from(password);
    let mut rng = OsRng;
    let core_out = unlock::create_vault(
        &pw,
        display_name,
        created_at_ms,
        Argon2idParams::V1_DEFAULT,
        &mut rng,
    )?;

    let unlock::CreatedVault {
        vault_toml_bytes,
        identity_bundle_bytes,
        recovery_mnemonic,
        identity_block_key,
        identity,
    } = core_out;

    let unlocked = unlock::UnlockedIdentity {
        identity_block_key,
        identity,
    };

    Ok(CreateVaultOutput {
        vault_toml_bytes,
        identity_bundle_bytes,
        identity: UnlockedIdentity::new(unlocked),
        mnemonic: MnemonicOutput::new(recovery_mnemonic),
    })
}
```

### Mnemonic output shape — the one-shot opaque handle rationale

The mnemonic is the first genuinely-secret material that crosses the FFI as a *return value*. The defaulted approach for `Sensitive<T>`-on-the-foreign-side is structurally hard:

- **Python** — `bytes` is immutable and unzeroizable. `bytearray` is mutable but offers no destructor hook. There is no `SecretBytes` equivalent in stdlib.
- **Swift** — `Data` is value-typed and can be mutated, but has no automatic zeroize. `[UInt8]` similarly.
- **Kotlin** — `ByteArray` is reference-typed and mutable but unzeroized. `kotlin.io.path.Path` patterns don't apply.

None of the three foreign languages can hold a `Sensitive<T>`-equivalent. So the bridge has two structural choices:

1. **Keep the secret Rust-side, expose a one-shot accessor** — the foreign caller "borrows" the bytes once across the FFI by copying them out; the Rust side then drops/zeroizes the original. This is the chosen approach.
2. **Expose `Vec<u8>` directly with caller-zeroize discipline** — symmetric with the *input* side from B.2/B.3a. Simpler API, but no type-level "this came from a Sensitive<T>" affordance on the output side.

Approach (1) wins because:

- **Type-level mark on the output side.** Foreign code that reads from a `MnemonicOutput` handle is visibly different from code that reads a plain bytes return. The handle's `take_phrase()` name + `wipe()` discipline reads as "this is a one-time-use secret"; a tuple member named `phrase: bytes` does not.
- **Decouples temporary lifecycle from long-lived.** The recovery mnemonic is needed exactly once at create time; `UnlockedIdentity` persists for the session. Coupling them ("`identity.recovery_phrase()` returns Option") reads worse — a long-lived handle with a dribble of secret state.
- **One-shot semantics.** A second call to `take_phrase()` returns `None`. This is documented and tested as the contract; it isn't a misuse-resistance accident.
- **Symmetry with `UnlockedIdentity.wipe()`.** Both handles use the same Rust-side `Mutex<Option<T>>` pattern, the same explicit-close discipline, the same RAII safety net at drop, and the same auto-AutoCloseable codegen in Kotlin (uniffi 0.31).

The cost of (1) is **two** opaque handles in the foreign code instead of one. Foreign idioms (Python `with`, Swift `defer`, Kotlin `.use { }`) handle this cleanly; the verbosity is small.

### RNG and KDF params — bridge owns both

The bridge calls `OsRng` and `Argon2idParams::V1_DEFAULT` directly. Foreign callers cannot supply alternatives.

This is structurally simpler than the alternatives (which would have added one or two foreign-visible parameters) and more secure-by-default. First-party clients always want the OS CSPRNG and the conservative KDF default. Tests through the FFI are smoke runners, not byte-determinism checks; reproducibility tests live in `core/tests/` using Rust-side seeded RNG and `create_vault_unchecked`.

The cost is real Argon2id runtime (~1s per create on M-class hardware) in tests that go through the bridge's `create_vault`. Mitigations: pytest tests share a module-scoped fixture where possible; bridge integration tests run real Argon2id sparingly (2 round-trip tests).

### Error variant cardinality — 5 variants, unchanged structurally

The 5-variant `FfiUnlockError` shape from B.3a is preserved. Under B.3b's design:

| Variant | Reachable from `create_vault`? |
|---|---|
| `WrongPasswordOrCorrupt` | No — no decryption happens during create. |
| `WrongMnemonicOrCorrupt` | No — same. |
| `InvalidMnemonic { detail }` | No — no mnemonic input on the create path. |
| `VaultMismatch` | No — no two-file comparison on the create path. |
| `CorruptVault { detail }` | **Yes** — folds `KdfFailure(_)` (Argon2id OOM) and `MalformedBundle(_)` (CBOR serialization failure) from `core::UnlockError`. |

The 5-variant cardinality is path-independent and stays exactly intact. The §13 anti-oracle conflation property is unchanged (no decryption on the create path means the property is vacuous here, but its preservation across the unlock paths is unaffected).

The only error-side edit is a Display-text tweak on `CorruptVault`:

- **Before:** `"vault is corrupt or unreadable: {detail}"`
- **After:** `"vault data integrity failure: {detail}"`

The new wording reads correctly on both the create path ("a vault couldn't be created — see detail for cause") and the open path ("a vault couldn't be read — see detail for cause"). The variant name `CorruptVault` stays; the path-neutral Display text replaces the read-path-only one. One existing bridge unit test asserts on the Display string and is updated in the same commit.

### Lifecycle / handle drop chain

```
foreign-side wrapper drops MnemonicOutput
  → bridge::MnemonicOutput drops
    → Mutex<Option<core::Mnemonic>> drops
      → core::Mnemonic drops
        → phrase: String — explicit Drop impl zeroizes the String buffer
        → entropy: Sensitive<[u8; 32]> — ZeroizeOnDrop wipes the 32 bytes
```

The `MnemonicOutput` Drop chain mirrors `UnlockedIdentity`'s exactly. After `take_phrase()` returns Some, the inner Mnemonic has already dropped (and zeroized) — subsequent `wipe()` is a no-op on the now-empty `Mutex<Option>`.

### Foreign-language idioms

**Python (PyO3):**

```python
import secretary_ffi_py as sec

output = sec.create_vault(
    password=b"my-strong-password",
    display_name="Owner",
    created_at_ms=int(time.time() * 1000),
)

# One-shot: read the phrase, display to the user, zero the buffer.
with output.mnemonic as mn:
    phrase = bytearray(mn.take_phrase())
    show_recovery_phrase_to_user(phrase)
    for i in range(len(phrase)):
        phrase[i] = 0
# mnemonic auto-closed here; subsequent take_phrase() returns None

# Persist the byte artifacts. Caller's responsibility (matches B.2/B.3a).
write_atomic(vault_dir / "vault.toml", output.vault_toml_bytes)
write_atomic(vault_dir / "identity.bundle.enc", output.identity_bundle_bytes)

# Use the live identity directly; no second open_with_password needed.
with output.identity as identity:
    print(identity.display_name())
```

**Swift (uniffi):**

```swift
let output = try createVault(
    password: passwordBytes,
    displayName: "Owner",
    createdAtMs: Int64(Date().timeIntervalSince1970 * 1000)
)
defer { output.identity.wipe() }
defer { output.mnemonic.wipe() }

if let phrase = output.mnemonic.takePhrase() {
    showRecoveryPhraseToUser(phrase)
    // caller-side zeroize discipline applies (Swift idiom omitted here for brevity)
}

try Data(output.vaultTomlBytes).write(to: tomlURL, options: .atomic)
try Data(output.identityBundleBytes).write(to: bundleURL, options: .atomic)

print(output.identity.displayName())
```

**Kotlin (uniffi):**

```kotlin
val output = createVault(
    password = passwordBytes,
    displayName = "Owner",
    createdAtMs = System.currentTimeMillis(),
)
output.mnemonic.use { mn ->
    mn.takePhrase()?.let { phrase ->
        showRecoveryPhraseToUser(phrase)
        phrase.fill(0)
    }
}
Files.write(tomlPath, output.vaultTomlBytes, ...)
Files.write(bundlePath, output.identityBundleBytes, ...)
output.identity.use { id ->
    println(id.displayName())
}
```

The two-handle pattern is visible but small. Both languages' idioms (`with`/`defer`/`use`) handle the explicit-close ergonomics cleanly. The PyO3 binding implements `__enter__`/`__exit__` on `MnemonicOutput`; uniffi 0.31 auto-generates Kotlin `AutoCloseable` for free.

### UDL surface delta

```idl
// existing:
[Error] interface UnlockError { ... };  // 5 variants, unchanged
interface UnlockedIdentity { ... };     // unchanged

// NEW:
interface MnemonicOutput {
    sequence<u8>? take_phrase();  // None => already consumed
    void wipe();
};

dictionary CreateVaultOutput {
    bytes vault_toml_bytes;
    bytes identity_bundle_bytes;
    UnlockedIdentity identity;
    MnemonicOutput mnemonic;
};

namespace secretary_ffi_uniffi {
    [Throws=UnlockError]
    UnlockedIdentity open_with_password(bytes vault_toml_bytes, bytes identity_bundle_bytes, bytes password);

    [Throws=UnlockError]
    UnlockedIdentity open_with_recovery(bytes vault_toml_bytes, bytes identity_bundle_bytes, bytes mnemonic);

    [Throws=UnlockError]
    CreateVaultOutput create_vault(bytes password, string display_name, u64 created_at_ms);
};
```

The `dictionary` (struct-by-value) vs `interface` (opaque-handle) distinction matters for uniffi codegen: `CreateVaultOutput` is a value-type record because all four fields are themselves either values (`bytes`) or interfaces (which marshal as opaque handles). `MnemonicOutput` is an `interface` because uniffi requires opaque-handle types for anything that has methods.

Foreign-language naming: the Rust function is `take_phrase` (no `_bytes` suffix; consistent with `UnlockedIdentity::display_name()` / `user_uuid()` on the same crate, which also drop the type-suffix because the return type is unambiguous on a single-purpose handle). uniffi codegen converts to camelCase: Swift and Kotlin see `takePhrase()`. PyO3 keeps the snake_case `take_phrase()` directly.

### Files

| File | Status | Purpose |
|---|---|---|
| `ffi/secretary-ffi-bridge/src/create.rs` | **new** | `pub fn create_vault`, `CreateVaultOutput`, `MnemonicOutput`; +5 unit tests |
| `ffi/secretary-ffi-bridge/src/error.rs` | edit | Display string tweak on `CorruptVault` ("vault data integrity failure: ..."); update the one existing test asserting on the Display text |
| `ffi/secretary-ffi-bridge/src/lib.rs` | edit | Re-export `create_vault`, `CreateVaultOutput`, `MnemonicOutput`; crate-doc updated |
| `ffi/secretary-ffi-bridge/src/identity.rs` | unchanged | — |
| `ffi/secretary-ffi-bridge/src/unlock.rs` | unchanged | — |
| `ffi/secretary-ffi-py/src/lib.rs` | edit | New `#[pyfunction] create_vault`; 2 new `#[pyclass]` (`CreateVaultOutput`, `MnemonicOutput`); context-manager protocol on `MnemonicOutput`; wrapper-side `Vec<u8>` zeroize for password input |
| `ffi/secretary-ffi-py/tests/test_smoke.py` | edit | +6 tests; module-scoped `created_vault` fixture for amortized Argon2id cost |
| `ffi/secretary-ffi-uniffi/src/secretary.udl` | edit | +1 namespace function, +1 `dictionary`, +1 `interface` |
| `ffi/secretary-ffi-uniffi/src/lib.rs` | edit | +1 `pub fn`, +2 wrapper structs, password input zeroize |
| `ffi/secretary-ffi-uniffi/tests/swift/main.swift` | edit | +3 asserts (shape, round-trip-with-password, round-trip-with-recovery) |
| `ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt` | edit | +3 asserts (same shape) |
| `ffi/secretary-ffi-bridge/README.md` | edit | "B.3b — Vault creation" section |
| `ffi/secretary-ffi-py/README.md` | edit | "Vault creation (B.3b)" section parallel to B.2/B.3a |
| `ffi/secretary-ffi-uniffi/README.md` | edit | Same |
| `README.md` (top-level) | edit | Progress bar advance; "Where we are" date; test counts |
| `ROADMAP.md` | edit | B.3b entry flipped ⏳ → ✅ |
| `NEXT_SESSION.md` | edit | Replaced with B.3b retrospective + B.4-or-equivalent forward-looking content |
| `docs/handoffs/2026-MM-DD-b3b-create-vault.md` | **new** | Timestamped handoff archive |

No new crates. No `Cargo.toml` workspace edits. No new dependencies.

## Test plan

### Bridge crate (`secretary-ffi-bridge`) — `create.rs::tests`

**5 new unit/integration tests** atop B.3a's 30:

Fast tests (no Argon2id, ~ms each):

| Test | Inputs | Expected |
|---|---|---|
| `mnemonic_output_take_phrase_returns_24_words` | `MnemonicOutput::new(mnemonic::generate(&mut seeded_rng))` | `Some(bytes)` where `bytes.split(b' ').count() == 24` |
| `mnemonic_output_take_phrase_is_one_shot` | construct, call twice | first → `Some`, second → `None` |
| `mnemonic_output_wipe_is_idempotent` | construct, wipe, wipe, take | both wipes succeed; take → `None` |

Slow tests (real `Argon2idParams::V1_DEFAULT`, ~1s + ~1s = ~2s each):

| Test | Inputs | Expected |
|---|---|---|
| `create_vault_round_trip_with_password` | `create_vault(b"pw", "Bob", 42)`, then `open_with_password(toml, bundle, b"pw")` | identity.display_name() == "Bob" on both sides |
| `create_vault_round_trip_with_recovery` | `create_vault(...)`, take phrase, then `open_with_recovery(toml, bundle, phrase)` | display_name preserved |

`error.rs::tests` — **1 test updated** to assert the new Display text (`"vault data integrity failure"` instead of `"vault is corrupt or unreadable"`).

### pytest (`ffi/secretary-ffi-py/tests/test_smoke.py`) — +6 tests atop B.3a's 16

Module-scoped fixture amortizes one Argon2id cost across the read-only assertions:

```python
@pytest.fixture(scope="module")
def created_vault():
    """Single create_vault invocation reused across read-only tests in this module.
    Cost: ~1s for V1_DEFAULT Argon2id."""
    return secretary_ffi_py.create_vault(
        password=b"test-password",
        display_name="Owner",
        created_at_ms=42,
    )
```

| Test | Probe | Argon2id cost |
|---|---|---|
| `test_create_vault_returns_artifacts_with_expected_shape` | uses fixture; asserts each of the 4 fields exists and has the expected type | shared (~0) |
| `test_create_vault_identity_is_immediately_live` | uses fixture; `output.identity.display_name() == "Owner"` | shared (~0) |
| `test_create_vault_mnemonic_take_returns_24_words` | fresh create; phrase = take_phrase; assert `len(phrase.split(b" ")) == 24` | ~1s |
| `test_create_vault_mnemonic_take_is_one_shot` | fresh create; first take → bytes, second take → None | ~1s |
| `test_create_vault_round_trip_with_password` | fresh create; reopen with same password; display_name preserved | ~2s |
| `test_create_vault_round_trip_with_recovery` | fresh create; take phrase; reopen with phrase; display_name preserved | ~2s |

Total added Argon2id cost: ~7s. pytest goes from 0.5s → ~7.5s.

### Swift smoke + Kotlin smoke — +3 asserts each atop B.3a's 12

Identical shape across both languages:

1. **Shape** — `output.vaultTomlBytes`/`vault_toml_bytes` non-empty, `output.identity` is the expected handle type, `output.mnemonic` is the expected handle type.
2. **Round-trip with password** — create, then `open_with_password` against the produced bytes with the same password; assert display_name preserved.
3. **Round-trip with recovery** — create, take phrase, then `open_with_recovery` against the produced bytes; assert display_name preserved.

Each smoke runner pays ~3-6s extra (real Argon2id × 2 creates × 2 opens). Baselines are ~10s; new totals ~15s. Acceptable.

### Conformance script (`core/tests/python/conformance.py`)

**No change.** Same rationale as B.3a — the create-path crypto is well-documented in `docs/crypto-design.md` §3 and §4; adding a stdlib-only Argon2id implementation to the Python clean-room verifier would be enormous effort with no spec-contract benefit. Round-trip assertions in the bridge / pytest / smoke layers cover the integration; `cargo test --release --workspace` covers the cryptographic determinism via `core::create_vault_unchecked` with seeded RNG.

### Expected gate counts at session close

| Gate | Before B.3b | After B.3b |
|---|---|---|
| `cargo test --release --workspace` | 489 + 9 ignored | **~494 + 9 ignored** (+5 bridge tests) |
| `uv run --directory ffi/secretary-ffi-py pytest` | 16 | **22** |
| Swift smoke | 12/12 | **15/15** |
| Kotlin smoke | 12/12 | **15/15** |
| Bridge crate unit tests | 30 | **~35** |
| `cargo clippy -- -D warnings` | clean | clean |
| `cargo fmt --all -- --check` | clean | clean |
| `uv run core/tests/python/conformance.py` | PASS | PASS |
| `uv run core/tests/python/spec_test_name_freshness.py` | PASS | PASS |
| `FfiUnlockError` variant count | 5 | **5** (unchanged) |
| `CorruptVault` Display text | `"vault is corrupt or unreadable: ..."` | `"vault data integrity failure: ..."` |

## B.3a vs B.3b boundary

B.3b closes the v1 unlock-and-create FFI surface as a clean **output-direction-only** unit:

| | B.3a (shipped) | B.3b (this spec) |
|---|---|---|
| `open_with_recovery` (mnemonic in) | ✅ | — |
| `create_vault` (mnemonic out) | — | ✅ |
| RNG seam | not applicable (no RNG used in unlock) | OS CSPRNG hardcoded |
| KDF params ergonomics | reads from vault.toml | `V1_DEFAULT` hardcoded |
| Output-direction `Sensitive<T>` marshalling | not applicable | one-shot opaque handle |
| Re-uses existing fixtures | ✅ (vault_001, vault_002) | no new fixtures (round-trip pinned) |
| `WeakKdfParams` reachability | unreachable (defensive map) | unreachable (params hardcoded) |

After B.3b, the FFI surface contains every `secretary_core::unlock` v1 entry point. Subsequent FFI work (B.4 or later) addresses different concerns — vault operations on records, sharing primitives, public-key accessors — none of which are in scope here.

## Rollout

Same shape as B.3a:

1. Branch `feat/ffi-b3b-create-vault` cut from `main`.
2. This spec is committed to `main` first as a stand-alone "PR-pending" doc (matches the B.3a pattern: spec on main, then plan on main, then feature branch).
3. Implementation plan written via `superpowers:writing-plans` (next step after this spec is approved by the user).
4. Subagent-driven-development workflow: bridge first, then PyO3 forwarders, then uniffi UDL + glue, then foreign smoke runners, then docs + handoff.
5. Two-stage review per task: spec compliance → code quality. Fix every flagged issue before moving on (no technical debt deferred).
6. Final commit ships updated `NEXT_SESSION.md` + `docs/handoffs/2026-MM-DD-b3b-create-vault.md` on the feature branch BEFORE pushing the PR.
7. PR opened against `main`; squash-merged on approval; SHA recorded in `NEXT_SESSION.md` post-merge per the recurring pattern.
