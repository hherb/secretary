# Sub-project B.3a — FFI Recovery-Phrase Unlock

**Date:** 2026-05-04
**Author:** Horst Herb (with Claude)
**Status:** Approved — ready for implementation plan
**Touches:** edits in `ffi/secretary-ffi-bridge/`, `ffi/secretary-ffi-py/`, `ffi/secretary-ffi-uniffi/`, `core/tests/common/fixture_builder.rs`, `core/tests/data/golden_vault_{001,002}_inputs.json`

## Background

Sub-project B.2 ([design](2026-05-04-ffi-b2-vault-unlock-design.md), [PR #24](https://github.com/hherb/secretary/pull/24)) shipped the first fallible, secret-bearing FFI operation: `open_with_password`, exposed through both PyO3 (Python) and uniffi (Swift, Kotlin) via the new shared `secretary-ffi-bridge` crate. That work resolved three architectural questions: a thinned 3-variant error type with `From<core::UnlockError>`, an opaque `UnlockedIdentity` handle with explicit `close`/`wipe` plus RAII safety net, and a bytes-not-string discipline for secret inputs at the boundary.

B.3 was originally scoped to bundle `open_with_recovery` (the recovery-phrase unlock path) **and** `create_vault` (vault creation, which produces a fresh 24-word phrase as output). The two operations were split into B.3a and B.3b because they are orthogonal design exercises:

- **B.3a (this spec)** is *input-direction only*: a 24-word BIP-39 mnemonic flows in across the FFI; nothing genuinely secret flows back. It is structurally a sister of B.2's `open_with_password` — the same bridge-crate pattern, the same opaque-handle output, the same caller-side zeroize discipline. The architectural delta is small.
- **B.3b (deferred)** is *output-direction*: `create_vault` returns a freshly-generated mnemonic that must cross the FFI back to the caller. That re-opens the deferred "how does `Sensitive<T>` materialize on the foreign side?" question from B.2's non-goals — a meaningfully different design exercise.

The core API being exposed is [`secretary_core::unlock::open_with_recovery`](../../../core/src/unlock/mod.rs#L396-L457):

```rust
pub fn open_with_recovery(
    vault_toml_bytes: &[u8],
    identity_bundle_bytes: &[u8],
    mnemonic_words: &str,
) -> Result<UnlockedIdentity, UnlockError>;
```

This spec defines the FFI projection of that single fallible operation through both PyO3 and uniffi, with the design decisions chosen for **architectural soundness and long-term maintainability over short-term ship velocity** — same discipline as B.2.

## Goals

- Expose `open_with_recovery` through both FFI flavors (PyO3 → Python; uniffi → Swift/Kotlin) using the same shared `secretary-ffi-bridge` crate as B.2.
- Mnemonic input crosses the boundary as **bytes (`Vec<u8>` UTF-8)**, parallel to B.2's password input. The bridge converts `&[u8]` → `&str` via `std::str::from_utf8`; failure surfaces as a typed `InvalidMnemonic` error variant (caller-actionable).
- Error type grows from B.2's 3 variants to 5 — `WrongMnemonicOrCorrupt` (parallel to `WrongPasswordOrCorrupt`) and `InvalidMnemonic { detail }` (pre-decryption BIP-39 validation failures, flattened into a single Display string). The §13 anti-oracle conflation property is preserved.
- Two new exception classes registered in PyO3 (`WrongMnemonicOrCorrupt`, `InvalidMnemonic`); two new variants added to the existing `[Error] interface UnlockError` in uniffi UDL. The single shared `UnlockError`/`UnlockException` enum spans both unlock entry points.
- Existing `golden_vault_001` and `golden_vault_002` fixtures are re-used unchanged on disk — the corresponding 24-word phrase is mathematically determined by the already-pinned recovery entropy, and is added as a string field in each fixture's `*_inputs.json`. A drift-detection assertion at fixture-build time keeps the JSON pin honest.
- All B.2 gates remain green and counts grow predictably: cargo workspace +~10, pytest +6, Swift smoke +4, Kotlin smoke +4, bridge unit tests +~10.
- Wrapper-side caller-zeroize discipline (mutable `bytearray` / `Data` / `ByteArray` zeroized after the bridge call returns) follows the B.2 pattern — same caveats, same documented contract.

## Non-goals (YAGNI)

- **No `create_vault` exposure.** Deferred to B.3b. Pulls in output-direction mnemonic marshalling (the deferred `Sensitive<T>`-on-the-foreign-side question), RNG seam decisions, and KDF-params-ergonomics — meaningfully different from B.3a's input-direction-only scope.
- **No `recovery_phrase()` accessor on `UnlockedIdentity`.** `open_with_recovery` consumes the phrase the caller typed; the bridge does not surface it back. The output-direction mnemonic case is `create_vault`'s problem.
- **No public-key accessors.** Same as B.2 — `x25519_pk()` / `ml_kem_768_pk()` / `ed25519_pk()` / `ml_dsa_65_pk()` not added; deferred until contact-card / sharing operations need them.
- **No genuinely-secret bytes crossing back to the foreign side.** Same as B.2 — no `x25519_sk()` / `ml_kem_768_sk()` / `ed25519_sk()` / `ml_dsa_65_sk()` accessors.
- **No `WeakKdfParams` reachability through the FFI.** Per current Rust core, this variant is only returned by `create_vault`, which `open_with_recovery` does not call. With `create_vault` deferred to B.3b, `WeakKdfParams` remains unreachable through B.3a's surface. The `From<UnlockError>` impl maps it defensively into `CorruptVault { detail }` for forward-compat — surfacing follows when `create_vault` enters scope.
- **No new on-disk fixtures.** `golden_vault_001/` and `golden_vault_002/` byte contents are unchanged; only their inputs JSONs gain a single new field. No `golden_vault_003/` is created.
- **No conformance.py extension to verify the recovery path.** Skipped deliberately. Adding a clean-room Python BIP-39 wordlist + checksum implementation is significant effort with no spec-contract benefit (the §4 recovery-KEK derivation is already documented in `docs/crypto-design.md`; a future clean-room reader can implement it from the spec when needed). The fixture-builder drift-detection assertion provides the integrity guarantee between pinned phrase and pinned entropy without requiring a Python re-implementation.
- **No structural exposure of `MnemonicError` sub-variants.** Core's `MnemonicError` has `WrongLength { got }` / `UnknownWord(String)` / `BadChecksum`. The FFI surface flattens these into a single `InvalidMnemonic { detail: String }` carrying Display text. Decouples the foreign API from any future BIP-39 sub-variant additions.
- **No CI integration.** Same as B.2 — repo has no `.github/workflows/` yet. Manual invocation documented in READMEs.

## Architecture

### Crate layout after B.3a

Strictly additive on top of B.2; no structural change.

```
ffi/
├── secretary-ffi-bridge/      ← single source of code truth (B.2)
│   └── src/
│       ├── lib.rs             ← re-exports `open_with_recovery`
│       ├── error.rs           ← FfiUnlockError grows from 3 → 5 variants
│       ├── identity.rs        ← UNCHANGED
│       └── unlock.rs          ← gains `pub fn open_with_recovery`
│
├── secretary-ffi-py/          ← +1 #[pyfunction] + 2 create_exception! macros
└── secretary-ffi-uniffi/      ← +1 UDL function, +2 UDL [Error] enum variants
```

The bridge crate stays pure-safe Rust; the workspace's `#![forbid(unsafe_code)]` invariant applies. The two binding-flavor crates retain their existing crate-local `unsafe_code = "deny"` carve-outs (B.1 / B.1.1 era) for the FFI macros.

### What lives where

| Concern | Bridge crate | secretary-ffi-py | secretary-ffi-uniffi |
|---|---|---|---|
| `FfiUnlockError` 5 variants + `From<core::UnlockError>` mapping | ✓ — single impl | re-projected via 5 `create_exception!` macros (3 existing + 2 new) + `From<FfiUnlockError> for PyErr` | re-projected via UDL `[Error]` interface (3 existing + 2 new) + uniffi auto-marshalling |
| `UnlockedIdentity` wrapper + accessors + `wipe()` | ✓ (unchanged from B.2) | `#[pyclass]` newtype unchanged | `pub struct` newtype unchanged |
| `open_with_recovery` body (UTF-8 validation + core call) | ✓ — calls core, wraps Result | thin `#[pyfunction]` forwarder | thin function declared in UDL; Rust impl forwards |
| Wrapper-side `Vec<u8>` zeroize for mnemonic input | ✗ | `#[pyfunction]` body zeroizes the owned `Vec<u8>` after the bridge call | `pub fn open_with_recovery` body zeroizes the owned `Vec<u8>` after the bridge call |
| Existing B.1 / B.1.1 / B.1.1.1 / B.2 surface | ✗ | unchanged | unchanged |

### API surface details

**Bridge-crate Rust signatures** (the contract):

```rust
// ffi/secretary-ffi-bridge/src/error.rs

#[derive(Debug, thiserror::Error)]
pub enum FfiUnlockError {
    // Existing (B.2):
    #[error("wrong password or vault corruption")]
    WrongPasswordOrCorrupt,
    #[error("vault.toml and identity.bundle.enc reference different vaults")]
    VaultMismatch,
    #[error("vault is corrupt or unreadable: {detail}")]
    CorruptVault { detail: String },

    // New (B.3a):
    #[error("wrong recovery phrase or vault corruption")]
    WrongMnemonicOrCorrupt,
    #[error("invalid recovery phrase: {detail}")]
    InvalidMnemonic { detail: String },
}

impl From<secretary_core::unlock::UnlockError> for FfiUnlockError {
    fn from(e: secretary_core::unlock::UnlockError) -> Self {
        use secretary_core::unlock::UnlockError as U;
        match e {
            U::WrongPasswordOrCorrupt        => Self::WrongPasswordOrCorrupt,
            U::WrongMnemonicOrCorrupt        => Self::WrongMnemonicOrCorrupt,
            U::InvalidMnemonic(inner)        => Self::InvalidMnemonic { detail: inner.to_string() },
            U::VaultMismatch                 => Self::VaultMismatch,
            U::CorruptVault                  => Self::CorruptVault { detail: "vault data integrity failure".into() },
            U::MalformedVaultToml(inner)     => Self::CorruptVault { detail: format!("malformed vault.toml: {inner}") },
            U::MalformedBundleFile(inner)    => Self::CorruptVault { detail: format!("malformed identity.bundle.enc: {inner}") },
            U::MalformedBundle(inner)        => Self::CorruptVault { detail: format!("malformed identity bundle plaintext: {inner}") },
            U::KdfFailure(inner)             => Self::CorruptVault { detail: format!("KDF failure: {inner}") },
            U::WeakKdfParams { .. }          => Self::CorruptVault { detail: e.to_string() },
        }
    }
}

// ffi/secretary-ffi-bridge/src/unlock.rs

pub fn open_with_recovery(
    vault_toml_bytes: &[u8],
    identity_bundle_bytes: &[u8],
    mnemonic_bytes: &[u8],
) -> Result<UnlockedIdentity, FfiUnlockError> {
    let mnemonic_str = std::str::from_utf8(mnemonic_bytes).map_err(|_| {
        FfiUnlockError::InvalidMnemonic {
            detail: "phrase contained invalid UTF-8".into(),
        }
    })?;
    let inner = secretary_core::unlock::open_with_recovery(
        vault_toml_bytes,
        identity_bundle_bytes,
        mnemonic_str,
    )?;
    Ok(UnlockedIdentity::from_core(inner))
}
```

**Field rename: `CorruptVault.message → CorruptVault.detail`.** B.2 introduced `CorruptVault { message: String }` on the bridge side. The Kotlin codegen renamed it to `detail` because Kotlin's `Throwable.message` is a built-in property that uniffi's auto-generated subclass collides with. Carrying that rename back into the bridge crate field name eliminates a Kotlin-only divergence and matches the `InvalidMnemonic { detail }` introduced in this work. The rename is a single-call-site change in `secretary-ffi-py/src/lib.rs` (the PyO3 forwarder) plus the bridge tests; no foreign-language API change (Python's `CorruptVault` already exposed `str(e)`, not a named field; Kotlin's was already `detail` via codegen).

**Match exhaustiveness.** No wildcard arm in the `From` impl; adding a new core `UnlockError` variant in the future is a compile error in the bridge, forcing a deliberate decision.

### Mnemonic input shape — bytes-in design rationale

The mnemonic input is `Vec<u8>` (UTF-8 bytes), not `String`/`Vec<String>`/`List<String>`. Three reasons:

1. **Consistency with B.2 password input.** B.2 chose `Vec<u8>` for password specifically so callers could zeroize a mutable buffer (`bytearray` in Python; `[UInt8]` in Swift; `ByteArray` in Kotlin). Strings are immutable in Python and don't support overwrite. The mnemonic is *more* secret than the password and the same discipline applies — the "bytes-not-string at the FFI boundary for secret inputs" decision recorded in B.2's NEXT_SESSION.md is load-bearing here.

2. **Caller-zeroize works in all three foreign languages.** Wrapper-side, the binding crates wrap the input as an owned `Vec<u8>` and call `.zeroize()` after the bridge returns — same pattern as B.2's password. The bridge takes a borrowed slice and never retains it, so the wrapper-side zeroize is the durable wipe.

3. **Bridge becomes the single normalization seam.** The bridge calls `std::str::from_utf8(mnemonic_bytes)` and surfaces `InvalidMnemonic { detail: "phrase contained invalid UTF-8" }` on failure. That UTF-8 check is the only pre-core validation the bridge does — past it, core's `unlock::mnemonic::parse` does NFKD normalization, lowercase, whitespace-collapse, BIP-39 wordlist lookup, and checksum validation. The bridge does not duplicate any of that.

The rejected alternatives:

- **`Vec<String>` (List[str]).** Pros: foreign-side UI naturally has 24 input fields per word; word-list autocomplete possible. Cons: Python's `str` is immutable per element, so 24 separate phrase-leaks instead of one; uniffi's per-element marshalling overhead; bridge has to rejoin into a string before calling core. The autocomplete benefit is a foreign-side concern that can be solved without changing the FFI shape (the foreign UI joins its 24 fields with `" "` before calling). Net: the per-element zeroize gap is the deal-breaker.
- **`String` (single space-separated).** Pros: matches core's input type directly. Cons: Python's `str` is immutable and unzeroizable; the FFI's most-secret input becomes the one shape that callers cannot zeroize. Net: violates B.2's caller-zeroize discipline.

### Error variant cardinality — 5 variants

Five distinct user-actionable failure categories on the unlock surface. Each is mapped from a specific core `UnlockError` variant (or set thereof):

| # | Variant | Path | Triggered by | User remedy | Anti-oracle? |
|---|---|---|---|---|---|
| 1 | `WrongPasswordOrCorrupt` | password only | AEAD tag fail under `master_kek` | retype password | ✓ (kept) |
| 2 | `WrongMnemonicOrCorrupt` | recovery only | AEAD tag fail under `recovery_kek` | retype phrase | ✓ (new) |
| 3 | `InvalidMnemonic { detail }` | recovery only | wrong word count / unknown word / bad checksum / invalid UTF-8 — **pre-decryption** | fix typo | not applicable (pre-crypto) |
| 4 | `VaultMismatch` | both | UUID/timestamp mismatch between vault.toml and bundle | use matching files | not applicable |
| 5 | `CorruptVault { detail }` | both | malformed TOML/CBOR/bundle, post-decryption failure | restore from backup | not applicable |

The §13 anti-oracle conflation property (AEAD tag failure ≡ wrong key OR corruption) is preserved on variants 1 and 2. They are deliberately *not* unified into a single `WrongCredentialOrCorrupt` because:

- The caller already knows which entry point they invoked, so the variant name carries useful UI affordance ("wrong password — try again" vs "wrong recovery phrase — try again") at zero security cost.
- Renaming the already-shipped `WrongPasswordOrCorrupt` Python exception class would break the B.2 contract for no security gain.
- The "single anti-oracle variant" framing isn't a real security improvement; both paths' AEAD failures are independently conflated with corruption and that property stays intact under parallel variants.

`InvalidMnemonic` is **not** a security oracle. The BIP-39 wordlist + checksum validation runs on the input *before* any vault byte is touched. An attacker who can submit phrases learns "valid BIP-39 vs not" trivially via the BIP-39 spec itself. Surfacing the specific failure mode ("expected 24 words, got 3") is a UI win with zero security cost.

The `MnemonicError` sub-enum (`WrongLength`/`UnknownWord`/`BadChecksum`) is flattened into a single `detail: String` field carrying the Display text — the FFI surface stays decoupled from any future BIP-39 sub-variant additions.

**Timing-side-channel note (variant 3 vs variant 2):** an `InvalidMnemonic` reply returns immediately after the BIP-39 parse step, while a `WrongMnemonicOrCorrupt` reply pays the full Argon2id + AEAD-decrypt cost first. The wall-clock difference therefore reveals only the **shape** of the input phrase (well-formed BIP-39 vs not), which the attacker already controls — they submitted it. It does not reveal anything about the credential-vs-corruption distinction the §13 conflation is designed to hide. The two anti-oracle variants (1 and 2) remain time-indistinguishable from each other and from `CorruptVault` arising from post-AEAD decode failures, which is the property §13 actually requires.

**Display-string coupling note (test fragility):** the bridge / pytest / Swift / Kotlin tests assert substrings like `"got 3"`, `"checksum"`, and `"xyzzy"` against the `detail` field. Those substrings come from the upstream `bip39` crate's `MnemonicError::Display` impl. If `bip39` ever rewords its messages (e.g. "got N" → "received N words"), all such assertions fail in lockstep across the four sites. That is a loud, easy-to-fix regression rather than a silent coupling, but the spec records it explicitly so a future bip39 upgrade lands deliberately. The flatten-to-string design is still the right v1 trade — the alternative (mirror the `MnemonicError` sub-enum across the FFI) couples the foreign API to BIP-39's variant set, which is a worse coupling than to its Display strings.

### Lifecycle / handle drop

Identical to B.2 — `open_with_recovery` returns the same `UnlockedIdentity` opaque handle, with the same drop chain:

```
binding-flavor wrapper drops (PyO3 #[pyclass] / uniffi::Object)
  → bridge::UnlockedIdentity drops
    → Mutex<Option<core::UnlockedIdentity>> drops
      → core::UnlockedIdentity drops
        → identity_block_key: Sensitive<[u8; 32]> ZeroizeOnDrop
        → identity: IdentityBundle drops
          → x25519_sk: Sensitive<[u8; 32]> ZeroizeOnDrop
          → ml_kem_768_sk: Sensitive<Vec<u8>> ZeroizeOnDrop  (~2400 bytes)
          → ed25519_sk: Sensitive<[u8; 32]> ZeroizeOnDrop
          → ml_dsa_65_sk: Sensitive<[u8; 32]> ZeroizeOnDrop
```

Successful unlock via either path produces byte-identical secret state — that is the whole point of the §3/§4 dual-KEK design. `wipe()` (Python `close`) is idempotent and works the same way regardless of which entry point produced the handle.

### Foreign-language idioms

**Python (PyO3):**

```python
import secretary_ffi_py as sec

phrase = bytearray(b"abandon abandon abandon ... 24 words")  # mutable, caller-zeroizable
try:
    with sec.open_with_recovery(toml_bytes, bundle_bytes, phrase) as identity:
        assert identity.display_name() == "Owner"
        assert identity.user_uuid() == bytes.fromhex("bf08a3300cd994b877e1a15baa28df35")
finally:
    for i in range(len(phrase)):
        phrase[i] = 0  # caller-side zeroize discipline (matches B.2)

try:
    sec.open_with_recovery(toml, bundle, b"only three words")
except sec.InvalidMnemonic as e:
    print(f"invalid: {e}")           # → "invalid: invalid recovery phrase: expected 24 words, got 3"
except sec.WrongMnemonicOrCorrupt:
    print("wrong phrase or vault tampered")
```

**Swift (uniffi):**

```swift
let phrase: [UInt8] = Array("abandon abandon ... 24 words".utf8)
do {
    let identity = try openWithRecovery(
        vaultTomlBytes: tomlBytes,
        identityBundleBytes: bundleBytes,
        mnemonic: phrase
    )
    defer { identity.wipe() }
    assert(identity.displayName() == "Owner")
} catch UnlockError.InvalidMnemonic(let detail) {
    print("invalid: \(detail)")
} catch UnlockError.WrongMnemonicOrCorrupt {
    print("wrong phrase or vault tampered")
}
```

**Kotlin (uniffi):**

```kotlin
val phrase = "abandon abandon ... 24 words".toByteArray(Charsets.UTF_8)
try {
    openWithRecovery(
        vaultTomlBytes = tomlBytes,
        identityBundleBytes = bundleBytes,
        mnemonic = phrase,
    ).use { identity ->
        assert(identity.displayName() == "Owner")
    }
} catch (e: UnlockException.InvalidMnemonic) {   // uniffi codegen: `Exception` not `Error`
    println("invalid: ${e.detail}")
} catch (e: UnlockException.WrongMnemonicOrCorrupt) {
    println("wrong phrase or vault tampered")
} finally {
    phrase.fill(0)
}
```

The single shared `UnlockError`/`UnlockException` enum spans both unlock entry points; foreign callers do not maintain two error types. The variants they need to handle differ by which entry point they called — `WrongPasswordOrCorrupt` vs `WrongMnemonicOrCorrupt` are mutually exclusive by call site. `VaultMismatch` and `CorruptVault` apply to both.

### UDL surface delta

```idl
[Error]
interface UnlockError {
    WrongPasswordOrCorrupt();
    WrongMnemonicOrCorrupt();          // NEW
    InvalidMnemonic(string detail);    // NEW
    VaultMismatch();
    CorruptVault(string detail);
};

namespace secretary_ffi_uniffi {
    [Throws=UnlockError]
    UnlockedIdentity open_with_password(bytes vault_toml_bytes, bytes identity_bundle_bytes, bytes password);

    [Throws=UnlockError]
    UnlockedIdentity open_with_recovery(bytes vault_toml_bytes, bytes identity_bundle_bytes, bytes mnemonic);
};
```

### Files

| File | Status | Purpose |
|---|---|---|
| `ffi/secretary-ffi-bridge/src/error.rs` | edit | 5-variant `FfiUnlockError`; field rename `message → detail` on `CorruptVault`; expanded `From<UnlockError>` arms; +5 unit tests for new variants and field rename |
| `ffi/secretary-ffi-bridge/src/unlock.rs` | edit | New `pub fn open_with_recovery(&[u8], &[u8], &[u8])`; UTF-8-validation seam; +5 integration tests |
| `ffi/secretary-ffi-bridge/src/identity.rs` | unchanged | `UnlockedIdentity` already supports both unlock paths |
| `ffi/secretary-ffi-bridge/src/lib.rs` | edit | Re-export `open_with_recovery`; crate-doc updated to mention 5-variant error and the bytes-in mnemonic contract |
| `ffi/secretary-ffi-py/src/lib.rs` | edit | New `#[pyfunction] open_with_recovery`; 2 new `create_exception!` macros (`WrongMnemonicOrCorrupt`, `InvalidMnemonic`); `From<FfiUnlockError> for PyErr` extended; wrapper-side `Vec<u8>` zeroize for mnemonic input |
| `ffi/secretary-ffi-py/tests/test_smoke.py` | edit | +6 tests; `_golden_vault_phrase(n)` helper reading `recovery_mnemonic_phrase` from inputs JSON |
| `ffi/secretary-ffi-uniffi/src/secretary.udl` | edit | 2 new UDL `[Error]` variants; 1 new namespace function |
| `ffi/secretary-ffi-uniffi/src/lib.rs` | edit | New `pub fn open_with_recovery(...)`; wrapper-side `Vec<u8>` zeroize |
| `ffi/secretary-ffi-uniffi/tests/swift/main.swift` | edit | +4 asserts; phrase loading via `SECRETARY_GOLDEN_VAULT_DIR` |
| `ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt` | edit | +4 asserts; phrase loading parallel to Swift |
| `ffi/secretary-ffi-uniffi/tests/swift/run.sh` | unchanged | Same env-var orchestration as B.2 |
| `ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` | unchanged | Same env-var orchestration as B.2 |
| `core/tests/common/fixture_builder.rs` | edit | Read `recovery_mnemonic_phrase` from inputs struct; assert it matches `bip39::Mnemonic::from_entropy(pinned_entropy).to_string()` |
| `core/tests/data/golden_vault_001_inputs.json` | edit | Add `recovery_mnemonic_phrase` field (24-word string) |
| `core/tests/data/golden_vault_002_inputs.json` | edit | Same as above with vault_002's distinct phrase |
| `core/tests/data/golden_vault_001/` | unchanged | Pinned vault bytes UNCHANGED — only the inputs JSON gains a field |
| `core/tests/data/golden_vault_002/` | unchanged | Same |
| `ffi/secretary-ffi-bridge/README.md` | edit | "B.3a — Recovery unlock" section; document UTF-8-validation seam, 5-variant error, the `message → detail` field rename |
| `ffi/secretary-ffi-py/README.md` | edit | "Vault unlock — recovery path (B.3a)" section parallel to B.2's password-path section |
| `ffi/secretary-ffi-uniffi/README.md` | edit | Same as above |
| `README.md` (top-level) | edit | ASCII progress bar advances; "Where we are" date updated; test counts updated |
| `ROADMAP.md` | edit | B.3a entry flipped ⏳ → ✅ |
| `NEXT_SESSION.md` | edit | Replaced with B.3b forward-looking content + B.3a retrospective |
| `docs/handoffs/2026-MM-DD-b3a-recovery-unlock.md` | **new** | Timestamped handoff archive for the session(s) that ship B.3a |

No new crates. No new top-level dependencies. No changes to `Cargo.toml` workspace members.

## Test plan

### Bridge crate (`secretary-ffi-bridge`)

`error.rs` — **+5 unit tests** atop B.2's 11:

- `wrong_mnemonic_or_corrupt_maps_through`
- `invalid_mnemonic_wrong_length_carries_detail`
- `invalid_mnemonic_unknown_word_carries_detail`
- `invalid_mnemonic_bad_checksum_carries_detail`
- `corrupt_vault_field_renamed_to_detail` (regression-pin for the field rename)

`unlock.rs` — **+5 integration tests** atop B.2's 4:

| Test | Inputs | Expected |
|---|---|---|
| `open_with_recovery_success_against_vault_001` | vault_001 toml + bundle + vault_001 phrase | `Ok(identity)` matches B.2's KAT |
| `open_with_recovery_wrong_mnemonic_returns_error` | vault_001 toml + bundle + vault_002 phrase | `Err(WrongMnemonicOrCorrupt)` |
| `open_with_recovery_invalid_length_returns_error` | vault_001 toml + bundle + `b"only three words"` | `Err(InvalidMnemonic { detail: "expected 24 words, got 3" })` |
| `open_with_recovery_invalid_utf8_returns_error` | vault_001 toml + bundle + `&[0xFFu8; 32]` | `Err(InvalidMnemonic { detail: "phrase contained invalid UTF-8" })` |
| `open_with_recovery_vault_mismatch_returns_error` | vault_001 toml + vault_002 bundle + vault_001 phrase | `Err(VaultMismatch)` |

Helper `_golden_vault_phrase(n: usize) -> Vec<u8>` reads `recovery_mnemonic_phrase` from `core/tests/data/golden_vault_{n:03}_inputs.json` and returns its UTF-8 bytes. One accessor used by all bridge integration tests + the foreign smoke runners' fixture loaders.

### pytest (`ffi/secretary-ffi-py/tests/test_smoke.py`) — +6 tests atop B.2's 10

| Test | Probe |
|---|---|
| `test_open_with_recovery_success_returns_pinned_identity` | success path KAT — display_name + user_uuid match pinned values |
| `test_open_with_recovery_wrong_mnemonic_raises` | vault_002 phrase against vault_001 → `sec.WrongMnemonicOrCorrupt` |
| `test_open_with_recovery_invalid_length_raises` | 3-word phrase → `sec.InvalidMnemonic`; assert `str(e)` contains `"got 3"` |
| `test_open_with_recovery_invalid_utf8_raises` | `bytes([0xFF]*32)` → `sec.InvalidMnemonic`; assert `str(e)` contains `"UTF-8"` |
| `test_open_with_recovery_vault_mismatch_raises` | swapped pair → `sec.VaultMismatch` |
| `test_open_with_recovery_bytearray_caller_zeroize` | mutable `bytearray` zeroized after call returns; matches B.2's `test_open_with_password_bytearray_caller_zeroize` shape |

### Swift smoke + Kotlin smoke — +4 asserts each atop B.2's 7

Identical shape across both languages:

1. success → `displayName == "Owner"`, `userUuid` matches pinned KAT
2. wrong mnemonic → `UnlockError.WrongMnemonicOrCorrupt` (Swift) / `UnlockException.WrongMnemonicOrCorrupt` (Kotlin)
3. invalid length (`"three words only"`) → `InvalidMnemonic`, assert `detail` contains `"got 3"`
4. vault mismatch → `VaultMismatch`

Phrase source: read `recovery_mnemonic_phrase` field from `golden_vault_{001,002}_inputs.json` at smoke-runner startup (Swift uses `JSONSerialization`; Kotlin uses `org.json.JSONObject` via the existing bundle loader). **No hardcoded 24-word strings in test files** — single source of truth is the JSON.

### Fixture builder (`core/tests/common/fixture_builder.rs`) — additive

```rust
// Inside the inputs struct (additive field):
pub recovery_mnemonic_phrase: String,  // 24 space-separated lowercase words

// Inside the existing build function, immediately after recovery_entropy is finalized:
let derived = bip39::Mnemonic::from_entropy(&recovery_entropy)
    .expect("32 bytes is a valid BIP-39 entropy length")
    .to_string();
assert_eq!(
    derived, inputs.recovery_mnemonic_phrase,
    "pinned recovery_mnemonic_phrase drifted from RNG-derived entropy"
);
```

This assertion is the **drift-detection invariant**: if the pinned entropy ever changes (it won't — vault bytes are pinned and `conformance.py` reads them as-is), the assertion fires loudly. The `bip39` crate is already in core's deps.

The phrase is added by:

1. Running each fixture's existing materialize-and-pin test once with a `println!` of the derived phrase.
2. Pasting that phrase into `golden_vault_001_inputs.json` and `golden_vault_002_inputs.json` as a new `recovery_mnemonic_phrase` field.
3. Re-running the test — the assertion proves the JSON matches the bytes.

This is a **one-time pin**; subsequent runs are deterministic. The 24-word phrase is **not a secret** in the test-fixture context (the test inputs JSON already pins password bytes, recovery entropy bytes, and identity-key bytes — the phrase is derivable from data already in the JSON; pinning it as text only makes the derivation explicit so foreign smoke runners can read it directly).

### Conformance script (`core/tests/python/conformance.py`)

**No change.** Conformance proves "the spec doc alone is sufficient to clean-room implement a vault reader". Adding stdlib-only BIP-39 wordlist + checksum + recovery-KEK derivation would require porting ~2K lines of well-defined but non-trivial logic to stdlib Python with no spec-contract benefit. The fixture-builder drift-detection assertion provides the integrity guarantee between pinned phrase and pinned entropy.

### Expected gate counts at session close

| Gate | Before B.3a | After B.3a |
|---|---|---|
| `cargo test --release --workspace` | 479 + 9 ignored | **~489 + 9 ignored** (+10 bridge tests; the fixture-builder assertion is inline-not-separate) |
| `uv run --directory ffi/secretary-ffi-py pytest` | 10 | **16** |
| Swift smoke | 7 | **11** |
| Kotlin smoke | 7 | **11** |
| Bridge crate unit tests | 22 | **~32** |
| `cargo clippy -- -D warnings` | clean | clean |
| `cargo fmt --all -- --check` | clean | clean |
| `uv run core/tests/python/conformance.py` | PASS | PASS |
| `uv run core/tests/python/spec_test_name_freshness.py` | PASS | PASS |

## B.3a vs B.3b boundary

The split lets B.3a ship as a clean **input-direction-only** unit:

| | B.3a (this spec) | B.3b (future) |
|---|---|---|
| `open_with_recovery` (mnemonic in) | ✅ | — |
| `create_vault` (mnemonic out) | — | ✅ |
| RNG seam decision | not needed | required |
| KDF params ergonomics | not needed | required |
| Output-direction `Sensitive<T>` marshalling | not needed | required (the deferred B.2 question) |
| Re-uses existing fixtures | ✅ (vault_001, vault_002) | likely needs RNG-seeded build path |
| `WeakKdfParams` reachability | unreachable (defensive map) | reachable (FFI surface decision required) |

B.3b's design pass will need to re-open the deferred "how does `Sensitive<T>` materialize on the foreign side?" question — the freshly-generated 24-word phrase from `create_vault` is genuinely-secret material that must cross the FFI boundary as a return value. That's a meaningfully different design exercise; bundling it into B.3a would have entangled two orthogonal concerns.

## Rollout

Same shape as B.2:

1. Branch `feat/ffi-b3a-recovery-unlock` cut from `main`.
2. Implementation plan written via `superpowers:writing-plans` (next step after this spec is approved).
3. Subagent-driven-development workflow: bridge first, then PyO3 forwarders, then uniffi UDL + glue, then foreign smoke runners, then docs + handoff.
4. Two-stage review per task: spec compliance → code quality. Fix every flagged issue before moving on (no technical debt deferred).
5. Final commit ships updated `NEXT_SESSION.md` + `docs/handoffs/2026-MM-DD-b3a-recovery-unlock.md` on the feature branch BEFORE pushing the PR (so post-merge `main` carries the correct baton, not a stale one).
6. PR opened against `main`; squash-merged on approval; SHA recorded in NEXT_SESSION.md.
