# Sub-project B.2 — FFI Vault Unlock

**Date:** 2026-05-04
**Author:** Horst Herb (with Claude)
**Status:** Approved — ready for implementation plan
**Touches:** new `ffi/secretary-ffi-bridge/` crate; edits in `ffi/secretary-ffi-py/`, `ffi/secretary-ffi-uniffi/`; refactor of `core/tests/golden_vault_001.rs` extracting shared `core/tests/common/fixture_builder.rs`; new `core/tests/golden_vault_002.rs` + `core/tests/data/golden_vault_002_inputs.json` + on-disk fixture under `core/tests/data/golden_vault_002/`

## Background

Sub-project B's binding-pipeline triad is complete: B.1 (PyO3 → Python, [PR #20](https://github.com/hherb/secretary/pull/20)), B.1.1 (uniffi UDL + Swift smoke runner, [PR #21](https://github.com/hherb/secretary/pull/21)), and B.1.1.1 (uniffi + Kotlin smoke runner, [PR #22](https://github.com/hherb/secretary/pull/22)). All three currently expose only infallible `add(u32, u32) -> u32` and `version() -> u16` round-trips. The next bounded unit of work is **B.2: the first fallible, secret-bearing operation** — vault unlock.

B.2 introduces three previously-deferred design surfaces in a controlled, minimum-viable form:

1. **Fallible operations crossing the FFI** — error marshalling design becomes load-bearing. PyO3's `PyResult<T>`-to-exception-class projection, uniffi's `[Throws]` annotation, and the discipline that errors decouple from internal Rust enum churn.
2. **Secret-bearing material at the boundary** — though deliberately scoped to *input direction only* in B.2 (password as bytes flowing in; the unlocked identity stays Rust-side as an opaque handle). Output-direction secret marshalling (`Sensitive<T>` materializing on the foreign side) is explicitly deferred to a later B.x.
3. **Lifecycle of foreign-held secret state** — handles must be drop-pinnable (`with` / `.use { }` / `defer`), not solely RAII-dependent.

The core API being exposed is [`secretary_core::unlock::open_with_password`](../../../core/src/unlock/mod.rs#L302-L376):

```rust
pub fn open_with_password(
    vault_toml_bytes: &[u8],
    identity_bundle_bytes: &[u8],
    password: &SecretBytes,
) -> Result<UnlockedIdentity, UnlockError>;
```

This spec defines an FFI projection that exposes this single fallible operation through both PyO3 (Python) and uniffi (Swift/Kotlin), with the design decisions chosen for **architectural soundness and long-term maintainability over short-term ship velocity**.

## Goals

- Expose `open_with_password` through both FFI flavors (PyO3 → Python; uniffi → Swift/Kotlin) with foreign-language-idiomatic ergonomics.
- The opaque `UnlockedIdentity` handle owns the unlocked secret state on the Rust side; foreign callers hold a refcount and read non-secret fields via accessor methods. Genuinely-secret material does not cross the boundary in B.2.
- Two non-secret accessors prove cross-language data marshalling for two foundational shapes: `display_name() -> String` (UTF-8 string) and `user_uuid() -> Vec<u8>` (16-byte fixed array).
- A thinned 3-variant error type — `WrongPasswordOrCorrupt`, `VaultMismatch`, `CorruptVault { message }` — projects cleanly to each language's idiomatic exception/error surface and decouples from internal `core::UnlockError`'s 7-variant structure (which carries inner-error-wrapped variants that would balloon the foreign API surface).
- Explicit close + RAII lifecycle: foreign callers can pin secret-state drop time via `with` / `.use { }` / `defer`; RAII is the safety net for naive callers, not the only mechanism.
- A new shared `secretary-ffi-bridge` crate is the **single source of code truth** for the FFI-friendly facade of `secretary-core`. Both binding-flavor crates (`secretary-ffi-py`, `secretary-ffi-uniffi`) project that facade through binding-specific macros; drift between the two flavors is impossible at compile time.
- Two pinned KAT fixtures (`golden_vault_001/` already exists; `golden_vault_002/` is created in this work) enable real-vault-pair tests of the `VaultMismatch` error path on both the Rust bridge layer and through the foreign-language smoke runners.
- Existing test gates remain green: `cargo test --release --workspace`, `cargo clippy --release --workspace -- -D warnings`, `uv run --directory ffi/secretary-ffi-py pytest`, `uv run core/tests/python/conformance.py`, `uv run core/tests/python/spec_test_name_freshness.py`, `tests/swift/run.sh`, `tests/kotlin/run.sh`.

## Non-goals (YAGNI)

- **No `create_vault` exposure.** Pulls in mnemonic-string-crossing-boundary design (the BIP-39 24-word phrase is THE most-secret material in the system; making it usable from foreign code forces a `Sensitive<String>`-marshalling decision) plus RNG-seam, KDF-params-ergonomics, and fixture-speed concerns. Deferred to B.3+ with its own design pass.
- **No `open_with_recovery` exposure.** Adds a sister code path with a mnemonic-input parameter and one extra error variant (`WrongMnemonicOrCorrupt`); orthogonal to B.2's "first fallible operation" scope. Deferred to B.3+.
- **No `WeakKdfParams` reachability through the FFI.** Per current Rust core, this variant is only returned by `create_vault` (which enforces the §1.2 v1 floor at write time); `open_with_password` does not enforce the floor at read time (the spec does not require it). With `create_vault` deferred, `WeakKdfParams` is unreachable through the B.2 FFI surface. Defensive forward-compat mapping is in place in the bridge crate; surfacing follows when `create_vault` enters scope.
- **No genuinely-secret bytes crossing back to the foreign side.** No `x25519_sk()` / `ml_kem_768_sk()` / `ed25519_sk()` / `ml_dsa_65_sk()` accessors, no `recovery_phrase()` (the mnemonic stays a deferred concern with `create_vault`). The "how does `Sensitive<T>` materialize on the foreign side?" question (Python `bytes` copy, `bytearray` mutable, custom managed type; Swift `Data`; Kotlin `ByteArray`) deserves its own brainstorm and is deferred to a future B.x.
- **No public-key accessors.** `x25519_pk()` / `ml_kem_768_pk()` / `ed25519_pk()` / `ml_dsa_65_pk()` are non-secret but each carries a different size and algorithmic identity; the "which key do you mean" question makes the accessor surface verbose. Deferred until contact-card / sharing operations need them.
- **No multi-step vault-object abstraction.** No `Vault.from_bytes(...).open_with_password(...)` two-step API. The FFI is a thin pass-through over the Rust core's procedural API; if multi-step orchestration ever becomes useful, the convenience function lives on the Rust side, not as foreign-side abstraction.
- **No conformance.py extension to verify the FFI surface.** [`core/tests/python/conformance.py`](../../../core/tests/python/conformance.py) intentionally proves that the spec docs alone are sufficient to implement a clean-room reader; the FFI is not part of the spec contract. The cross-reference invariant (foreign smoke runners assert the same KAT values that golden-vault verification depends on) provides FFI ↔ spec agreement without entangling conformance with FFI concerns.
- **No CI integration.** Repo has no `.github/workflows/` yet. The FFI READMEs document manual invocation; CI follows when the repo gains workflow infrastructure.

## Architecture

### Crate layout after B.2

```
ffi/
├── secretary-ffi-bridge/        ← NEW. The single source of code truth.
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs               ← re-exports + crate-doc on the boundary contract
│       ├── error.rs             ← FfiUnlockError + From<core::UnlockError>
│       ├── identity.rs          ← UnlockedIdentity wrapper (opaque) + accessors + close
│       └── unlock.rs            ← open_with_password free function
│
├── secretary-ffi-py/            ← EXISTING. Stays small.
│   └── src/lib.rs
│       - depends on secretary-ffi-bridge
│       - PyO3-specific glue: #[pyclass] newtype, exception classes, #[pyfunction]
│       - existing add() / version() unchanged
│
└── secretary-ffi-uniffi/        ← EXISTING. Stays small.
    ├── Cargo.toml
    │   - depends on secretary-ffi-bridge
    └── src/
        ├── lib.rs               ← uniffi scaffolding + UDL Rust impls calling into bridge
        └── secretary.udl        ← UDL gains UnlockedIdentity interface, UnlockError [Error] interface, open_with_password namespace function
```

The bridge crate is **pure-safe Rust**: no PyO3, no uniffi, no `unsafe_code` carve-out. The workspace's `#![forbid(unsafe_code)]` invariant applies. The two binding-flavor crates retain their existing crate-local `unsafe_code = "deny"` carve-outs (B.1 / B.1.1 era) for the FFI macros.

### What lives where

| Concern | Bridge crate | secretary-ffi-py | secretary-ffi-uniffi |
|---|---|---|---|
| `FfiUnlockError` enum + `From<core::UnlockError>` mapping | ✓ — single impl | re-projected via `create_exception!` + `From<FfiUnlockError> for PyErr` | re-projected via UDL `[Error]` complex-error form + uniffi auto-marshalling |
| `UnlockedIdentity` wrapper + accessors + `close()` | ✓ — methods written once | `#[pyclass]` newtype with method forwarders + `__enter__` / `__exit__` | `pub struct` newtype with method forwarders; UDL declares `interface` |
| `open_with_password` body | ✓ — calls core, wraps Result | thin `#[pyfunction]` forwarder | thin function declared in UDL; Rust impl forwards |
| Language-specific annotations | ✗ | `#[pyclass]`, `#[pymethods]`, `#[pyfunction]`, `create_exception!` | UDL declarations + `uniffi::Object` |
| Existing B.1 / B.1.1 / B.1.1.1 surface (`add`, `version`) | ✗ — stays per-crate | unchanged | unchanged |

### Files

| File | Status | Purpose |
|---|---|---|
| `ffi/secretary-ffi-bridge/Cargo.toml` | **new** | Workspace member. Deps: `secretary-core`, `thiserror`, `zeroize`. No PyO3, no uniffi. Inherits workspace `forbid(unsafe_code)`. |
| `ffi/secretary-ffi-bridge/src/lib.rs` | **new** | Re-exports `FfiUnlockError`, `UnlockedIdentity`, `open_with_password`. Crate-doc explains the bridge's role: "FFI-friendly facade of `secretary-core`; binding-flavor crates project this through their respective macros." |
| `ffi/secretary-ffi-bridge/src/error.rs` | **new** | `FfiUnlockError` 3-variant enum (`WrongPasswordOrCorrupt`, `VaultMismatch`, `CorruptVault { message: String }`) with thiserror Display impls. `From<core::unlock::UnlockError>` impl with explicit match arms (no wildcard) so future core variants force a compile error. ~8 unit tests pin the variant mappings, including defensive forward-compat mappings of currently-unreachable variants (`WrongMnemonicOrCorrupt`, `InvalidMnemonic(_)`, `WeakKdfParams { .. }`). |
| `ffi/secretary-ffi-bridge/src/identity.rs` | **new** | Opaque `UnlockedIdentity` wrapping `Mutex<Option<core::unlock::UnlockedIdentity>>`. Methods: `display_name() -> String` (returns "" if closed), `user_uuid() -> Vec<u8>` (returns `vec![0u8; 16]` if closed), `close()` (idempotent; takes inner Option). ~4 unit tests. Mutex-poisoning policy documented inline. |
| `ffi/secretary-ffi-bridge/src/unlock.rs` | **new** | `pub fn open_with_password(&[u8], &[u8], &[u8]) -> Result<UnlockedIdentity, FfiUnlockError>` wrapping the core call. Wraps the input password slice in `SecretBytes`, lets it zeroize-on-drop. ~3 integration tests (success vs golden_vault_001, wrong password, vault_mismatch via real golden_vault_001/golden_vault_002 file pair). |
| `ffi/secretary-ffi-py/Cargo.toml` | edit | Add `secretary-ffi-bridge = { path = "../secretary-ffi-bridge" }` dependency. |
| `ffi/secretary-ffi-py/src/lib.rs` | edit | Add `#[pyclass] UnlockedIdentity(secretary_ffi_bridge::UnlockedIdentity)` newtype with `#[pymethods]` forwarders for `display_name`, `user_uuid`, `close`, plus `__enter__` / `__exit__`. Three `create_exception!` macros (`WrongPasswordOrCorrupt`, `VaultMismatch`, `CorruptVault`) registered under the module. `From<FfiUnlockError> for PyErr` raises the correct class per variant. New `#[pyfunction] open_with_password`. Existing `add` / `version` unchanged. |
| `ffi/secretary-ffi-py/tests/test_smoke.py` | edit | Existing 3 tests stay (`add`, `version`, module-level). Add: `test_open_with_password_success_returns_pinned_identity`, `test_open_with_password_wrong_password_raises`, `test_open_with_password_swapped_files_raises_vault_mismatch` (uses both golden_vault_001 + golden_vault_002 by swapping vault.toml ↔ identity.bundle.enc), `test_close_is_idempotent`, `test_use_after_close_returns_empty_values`. Helper: `_golden_vault_dir(n: int) -> Path` resolving via `Path(__file__).resolve().parents[3] / f"core/tests/data/golden_vault_{n:03d}"`. |
| `ffi/secretary-ffi-uniffi/Cargo.toml` | edit | Add `secretary-ffi-bridge = { path = "../secretary-ffi-bridge" }` dependency. |
| `ffi/secretary-ffi-uniffi/src/secretary.udl` | edit | Add `interface UnlockedIdentity { string display_name(); bytes user_uuid(); void close(); };`. Add `[Error] interface UnlockError { WrongPasswordOrCorrupt(); VaultMismatch(); CorruptVault(string message); };`. Add inside namespace block: `[Throws=UnlockError] UnlockedIdentity open_with_password(bytes vault_toml_bytes, bytes identity_bundle_bytes, bytes password);`. |
| `ffi/secretary-ffi-uniffi/src/lib.rs` | edit | Add `pub struct UnlockedIdentity(secretary_ffi_bridge::UnlockedIdentity)` with method forwarders. Add `pub fn open_with_password(...)` calling bridge. Existing `add` / `version` unchanged. |
| `ffi/secretary-ffi-uniffi/tests/swift/main.swift` | edit | Existing 3 asserts stay. Add 4-5 unlock asserts mirroring Python tests. Read fixture paths via `ProcessInfo.processInfo.environment["SECRETARY_GOLDEN_VAULT_DIR"]` (a parent dir; sub-name `golden_vault_001` / `golden_vault_002` appended). Fail loudly if env var unset. |
| `ffi/secretary-ffi-uniffi/tests/swift/run.sh` | edit | Add `export SECRETARY_GOLDEN_VAULT_DIR="$REPO_ROOT/core/tests/data"` (the parent dir; runner appends sub-name). |
| `ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt` | edit | Same shape as Swift's main.swift. Reads `System.getenv("SECRETARY_GOLDEN_VAULT_DIR")`. |
| `ffi/secretary-ffi-uniffi/tests/kotlin/UnlockedIdentityExt.kt` | **new** | 5-line `inline fun <T> UnlockedIdentity.use(block: ...)` extension function so the Kotlin smoke runner uses idiomatic `.use { }`. The weekly `uniffi Closeable-trait watch` routine (`trig_018gYtGpiycgLXqUsDpV2NZD`) tracks upstream uniffi for native Closeable support; when that lands, this file deletes. |
| `ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` | edit | Add `export SECRETARY_GOLDEN_VAULT_DIR="$REPO_ROOT/core/tests/data"`. |
| `core/tests/common/mod.rs` | **new** | Module declaration for `core/tests/common/`. |
| `core/tests/common/fixture_builder.rs` | **new** | Shared fixture-build infrastructure extracted from `golden_vault_001.rs`. Helpers (`parse_hex`, `parse_uuid`, `identity_from_inputs`, `build_block_plaintext`, `build_identity_envelope`, `build_golden_vault`, `compose_aad`, hex helpers) parameterized over `(inputs_path: &Path, fixture_root: &Path)`. ~900 lines moved from `golden_vault_001.rs`. |
| `core/tests/golden_vault_001.rs` | edit (refactor) | Becomes a thin caller of `common::fixture_builder`. Hardcodes `golden_vault_001_inputs.json` / `golden_vault_001/` paths. Tests (`generate_golden_inputs`, `materialize_golden_vault_001`, `golden_vault_001_pinned`, `golden_vault_001_bootstrap_dump`, `golden_vault_001_opens_with_password`) stay in this file but call into the shared builder. **Pinned bytes must remain unchanged after refactor.** |
| `core/tests/golden_vault_002.rs` | **new** | Thin caller of `common::fixture_builder` for golden_vault_002. Mirrors golden_vault_001's four named tests pattern. |
| `core/tests/data/golden_vault_002_inputs.json` | **new** | Distinct vault_uuid (`aabbccdd-eeff-0011-2233-445566778899`), distinct password (`"correct horse battery staple two"`), regenerated identities (different RNG seed than 001's), KDF params identical to 001's (memory_kib=8192 sub-floor for test speed; same justification). |
| `core/tests/data/golden_vault_002/{vault.toml, identity.bundle.enc, manifest.cbor.enc, blocks/<uuid>.cbor.enc, contacts/...}` | **new** (committed bytes) | The on-disk fixture — generated via `cargo test --release --test golden_vault_002 -- --ignored materialize_golden_vault_002 --nocapture`, then committed. ~5 KB. |
| `core/tests/python/conformance.py` | edit (1-line comment) | Add a comment explaining why conformance.py stays at golden_vault_001 only (one canonical fixture is sufficient for the spec-clean-room contract; golden_vault_002 exists for FFI tests). No test changes. |
| `ffi/secretary-ffi-bridge/README.md` | **new** | Describes the bridge crate's role, the thinning-discipline principle (express intent not implementation), the security-property note (do not split `WrongPasswordOrCorrupt`), the Mutex overhead choice. |
| `ffi/secretary-ffi-py/README.md` | edit | Add "Vault unlock (B.2)" section. Documents call signature, exception classes, context-manager idiom, the third-party-library-consumer caveat (password buffers should be mutable + zeroed by the caller; first-party clients enforce this discipline; `bytes` literals are convenient but immutable). |
| `ffi/secretary-ffi-uniffi/README.md` | edit | Add "Vault unlock (B.2)" section parallel to the Python crate's. Documents Swift `defer` + Kotlin `.use { }` patterns, the third-party-library-consumer caveat, the env-var orchestration. Notes the B.1.1.1-era ktlint cosmetic warning is unchanged. |
| `Cargo.toml` (root) | edit | Add `"ffi/secretary-ffi-bridge"` to `[workspace] members`. |
| `README.md` (top-level) | edit | Status table flips uniffi entry to ✅ B.2; ASCII progress bar advanced. |
| `ROADMAP.md` | edit | § "Sub-project B" header updated; B.2 entry flipped ⏳ → ✅ with description. |
| `NEXT_SESSION.md` | edit | Replaced with B.3 forward-looking content (B.2 retrospective + B.3 brainstorm prompt). |
| `docs/handoffs/2026-MM-DD-b2-vault-unlock.md` | **new** | Timestamped handoff archive for the session(s) that ship B.2. |

### API surface details

**Bridge-crate Rust signatures** (the contract):

```rust
// ffi/secretary-ffi-bridge/src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum FfiUnlockError {
    #[error("wrong password or vault corruption")]
    WrongPasswordOrCorrupt,
    #[error("vault.toml and identity.bundle.enc reference different vaults")]
    VaultMismatch,
    #[error("vault is corrupt or unreadable: {message}")]
    CorruptVault { message: String },
}

impl From<secretary_core::unlock::UnlockError> for FfiUnlockError { /* explicit match arms; no wildcards */ }

// ffi/secretary-ffi-bridge/src/identity.rs
pub struct UnlockedIdentity { /* Mutex<Option<core::unlock::UnlockedIdentity>> */ }
impl UnlockedIdentity {
    pub fn display_name(&self) -> String;     // returns "" if closed
    pub fn user_uuid(&self) -> Vec<u8>;       // returns vec![0u8; 16] if closed
    pub fn close(&self);                       // idempotent
}

// ffi/secretary-ffi-bridge/src/unlock.rs
pub fn open_with_password(
    vault_toml_bytes: &[u8],
    identity_bundle_bytes: &[u8],
    password: &[u8],
) -> Result<UnlockedIdentity, FfiUnlockError>;
```

**Python (PyO3) idiom:**

```python
import secretary_ffi_py as sec

with sec.open_with_password(toml_bytes, bundle_bytes, password_bytes) as identity:
    assert identity.display_name() == "Owner"
    assert identity.user_uuid() == bytes.fromhex("bf08a3300cd994b877e1a15baa28df35")

try:
    sec.open_with_password(toml, bundle, b"wrong")
except sec.WrongPasswordOrCorrupt:
    ...
except sec.CorruptVault as e:
    print(str(e))  # carries the inner Display text
```

**Swift (uniffi) idiom:**

```swift
let identity = try openWithPassword(
    vaultTomlBytes: tomlBytes,
    identityBundleBytes: bundleBytes,
    password: passwordBytes
)
defer { identity.close() }
assert(identity.displayName() == "Owner")

// Error path:
do {
    let _ = try openWithPassword(...)
} catch UnlockError.wrongPasswordOrCorrupt {
    ...
} catch UnlockError.corruptVault(let message) {
    print("Vault corrupt: \(message)")
}
```

**Kotlin (uniffi) idiom:**

```kotlin
openWithPassword(
    vaultTomlBytes = tomlBytes,
    identityBundleBytes = bundleBytes,
    password = passwordBytes,
).use { identity ->
    assert(identity.displayName() == "Owner")
}

try {
    openWithPassword(...)
} catch (e: UnlockError) {
    when (e) {
        is UnlockError.WrongPasswordOrCorrupt -> ...
        is UnlockError.CorruptVault -> println("Vault corrupt: ${e.message}")
        is UnlockError.VaultMismatch -> ...
    }
}
```

### Lifecycle / handle drop

The chain executed when the foreign-side reference releases (or `close()` is called explicitly):

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

The `Mutex<Option<...>>` shape gives:
- **Idempotent close** — `take()` on `None` is no-op
- **Thread-safe accessors** — short lock (clone a String / copy 16 bytes)
- **Use-after-close non-throwing** — `as_ref()` on `None` yields default values, matches B.1's non-throwing accessor pattern
- **Prompt zeroize** — `take()` consumes the inner Option, drops cascade through all `ZeroizeOnDrop` impls

**What close() does NOT promise:**
- It does not zeroize the foreign-side caller's password buffer (that is the caller's responsibility per the Q5 (ii) discipline; documented in the READMEs).
- It does not zeroize bytes in transit through the FFI ABI marshalling layer (PyO3 / uniffi internally copy the input bytes; those copies live in binding-internal allocations the bridge cannot reach).

### Error projection

**Why the thinned 3-variant shape:** core's `UnlockError` has 7 reachable-from-`open_with_password` variants, three of which (`MalformedVaultToml(_)`, `MalformedBundleFile(_)`, `MalformedBundle(_)`) wrap inner enums with their own variant counts. Mirroring exactly to the foreign side either re-exposes ~15 inner types per language (huge surface, churns on every `core/` internal refactor) or collapses inners to strings (anti-pattern; foreign callers parse strings to understand failure causes).

The thinned 3-variant shape **expresses user-actionable intent rather than internal Rust enum structure**:
- `WrongPasswordOrCorrupt` — "your password is wrong, try again". Deliberately conflates wrong-password and corruption per [docs/threat-model.md](../../../docs/threat-model.md) §13's anti-oracle property; this **must not** be split into separate variants on the foreign side, and the bridge crate's docs make this explicit so a future maintainer doesn't try to "improve" the error shape.
- `VaultMismatch` — "vault.toml and identity.bundle.enc reference different vaults". User-actionable: re-pair from backups.
- `CorruptVault { message }` — collapses {core::CorruptVault, all MalformedX, KdfFailure}. The `message` field carries the inner `Display` text for diagnostics; structured pattern-matching on the inner cause is intentionally not supported (corruption recovery is "restore from backup", not "branch on which file was malformed").

**Long-term decoupling:** internal core refactors (adding a new sub-variant inside `VaultTomlError`, etc.) automatically fold into `CorruptVault { message: <new Display> }` without rippling foreign-API changes. The thinned set is a stable contract.

**Defensive forward-compat:** the `From<core::UnlockError>` impl explicitly handles currently-unreachable variants (`WrongMnemonicOrCorrupt`, `InvalidMnemonic(_)`, `WeakKdfParams { .. }`) by mapping them to `CorruptVault { message }` rather than `unreachable!()`. Rationale: an FFI boundary should be defensive against future core changes that might (legitimately) make these reachable through `open_with_password`.

### Password-input discipline

Per Q5: passwords cross as bytes, not as strings. This:
- Matches Argon2id's cryptographic abstraction (opaque bytes, not Unicode codepoints).
- Allows disciplined callers using mutable buffers (`bytearray` / `Data` / `ByteArray`) to zero their copy after the call. First-party clients enforce this discipline; third-party documentation makes it explicit (the crate READMEs flag this as a security-relevant convention).
- Avoids the per-language UTF-8 encoding decision (`String` immutability prevents caller-side zeroize anyway, so the convenience of `String` would come at the cost of architectural correctness).

The Rust-side wrapper builds a `SecretBytes` from the input slice; that wrapper zeroizes on drop. The caller's foreign-side buffer is the caller's concern.

### Code-organization principle

Per Q8 + the user's explicit principle "single source of code truth wherever practicable": the bridge crate is **one place** where:
- `FfiUnlockError`'s shape and mapping live
- `UnlockedIdentity`'s accessor logic lives
- `open_with_password`'s wrapping behavior lives

Both binding-flavor crates project from this single source. Drift between the PyO3 and uniffi versions of the FFI surface is impossible at compile time — they share underlying signatures and methods.

When future B.x operations land (`open_with_recovery`, `create_vault`, `share_as_fork`, etc.), each lives once in the bridge crate and projects through both binding-flavor crates with mechanical forwarder code (one line per accessor / one method per pyclass / one UDL declaration).

### API namespace shape

Per Q7: free functions parallel to Rust core's procedural shape. No `Vault.from_bytes(...).open_with_password(...)` two-step abstraction. **If multi-step orchestration ever becomes useful, the convenience function lives on the Rust side, not as foreign-side abstraction.** This keeps the FFI thin, mirrors Rust core, and avoids speculative re-abstraction of a system that doesn't yet need it.

## Lints & invariants

- `#![forbid(unsafe_code)]` applies to `secretary-ffi-bridge` (no carve-out — pure-safe Rust). The two binding-flavor crates retain their crate-local `unsafe_code = "deny"` carve-outs for FFI macros (B.1 / B.1.1 era; unchanged).
- `cargo clippy --release --workspace -- -D warnings` stays clean.
- `cargo fmt --all` applied before each commit.
- `cargo test --release --workspace` baseline grows from 451 + 6 ignored to ~469 + 6 ignored (15 new bridge-crate tests, 3 new golden_vault_002 tests, all golden_vault_001 tests unchanged).

## Testing strategy

Three test layers, each with a specific job:

### Layer 1 — Bridge-crate Rust unit + integration tests

Lives in `ffi/secretary-ffi-bridge/src/{error,identity,unlock}.rs` `#[cfg(test)]` modules. Validates the FFI-friendly facade in isolation — no PyO3, no uniffi, just Rust calling Rust. Uses `include_bytes!` for golden_vault_001 and golden_vault_002 fixture inclusion (~10 KB embedded into test binary; trivial).

| Test | What it pins |
|---|---|
| `wrong_password_maps_to_wrong_password_or_corrupt` | 1:1 variant mapping |
| `vault_mismatch_maps_to_vault_mismatch` | 1:1 variant mapping |
| `malformed_vault_toml_collapses_to_corrupt_vault_with_message` | Inner Display preserved |
| `malformed_bundle_file_collapses_to_corrupt_vault` | Same shape, different inner type |
| `malformed_bundle_collapses_to_corrupt_vault` | Same |
| `kdf_failure_collapses_to_corrupt_vault` | Same |
| `wrong_mnemonic_or_corrupt_maps_defensively` | Forward-compat mapping |
| `weak_kdf_params_maps_defensively` | Forward-compat mapping |
| `unlocked_identity_display_name_returns_owner` | Accessor passthrough |
| `unlocked_identity_user_uuid_returns_pinned_16_bytes` | Accessor passthrough; pins hex `bf08a3300cd994b877e1a15baa28df35` |
| `unlocked_identity_close_then_accessors_return_empty` | Use-after-close non-throwing |
| `unlocked_identity_close_idempotent` | Multiple `close()` calls don't panic |
| `open_with_password_success_returns_unlocked_handle` | End-to-end against golden_vault_001 |
| `open_with_password_wrong_password_returns_thinned_error` | End-to-end error path |
| `open_with_password_swapped_files_returns_vault_mismatch` | golden_vault_001's vault.toml + golden_vault_002's identity.bundle.enc |

Estimate: ~15 tests. Workspace baseline grows from ~454 (after 7.2) → ~469.

### Layer 2 — Per-binding-flavor projection tests

**Python pytest** at `ffi/secretary-ffi-py/tests/test_smoke.py`: existing 3 tests stay; add 4-5 unlock tests asserting:
- success path opens golden_vault_001 with password `b"correct horse battery staple"`, asserts `display_name() == "Owner"` and `user_uuid() == bytes.fromhex("bf08a3300cd994b877e1a15baa28df35")`
- wrong password raises `WrongPasswordOrCorrupt`
- file-swap (golden_vault_001's vault.toml + golden_vault_002's identity.bundle.enc) raises `VaultMismatch`. The reverse swap (002's vault.toml + 001's bundle) would behave identically by code symmetry; tests pin one direction for KAT discipline rather than asserting both.
- `close()` idempotent
- use-after-close returns empty values

Path resolution: `Path(__file__).resolve().parents[3] / "core/tests/data/golden_vault_NNN"`.

**Swift smoke runner** at `ffi/secretary-ffi-uniffi/tests/swift/main.swift`: existing 3 asserts stay; add 4-5 unlock asserts mirroring Python. Reads fixture parent dir from `SECRETARY_GOLDEN_VAULT_DIR` env var (set by run.sh).

**Kotlin smoke runner** at `ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt`: same as Swift.

### Layer 3 — Conformance integration

[`conformance.py`](../../../core/tests/python/conformance.py) is **not extended** in B.2 — it stays focused on the spec-docs↔Rust clean-room contract. The cross-reference invariant (foreign smoke runners assert the same KAT values that golden-vault verification depends on) provides FFI ↔ spec agreement: if `display_name == "Owner"` or `user_uuid` ever change in golden_vault_001, all four tests (Rust integration, conformance.py, foreign-side smoke runners) break together — KAT drift cannot land silently.

### Test-runner orchestration

Per Q9 (2): env var via run.sh for shell-orchestrated runners, script-relative for pytest. The env var carries the **parent directory** (`core/tests/data/`); each runner appends `golden_vault_001` or `golden_vault_002` as needed.

```bash
# tests/swift/run.sh and tests/kotlin/run.sh:
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
export SECRETARY_GOLDEN_VAULT_DIR="$REPO_ROOT/core/tests/data"
```

```swift
guard let dir = ProcessInfo.processInfo.environment["SECRETARY_GOLDEN_VAULT_DIR"] else {
    fputs("error: SECRETARY_GOLDEN_VAULT_DIR not set; run via tests/swift/run.sh\n", stderr); exit(1)
}
let golden001 = URL(fileURLWithPath: dir).appendingPathComponent("golden_vault_001")
```

### Final test-count rollup

| Suite | Before B.2 | After B.2 | Delta |
|---|---|---|---|
| `cargo test --release --workspace` | 451 + 6 ignored | ~469 + 6 ignored | +18 (3 vault_002 + 15 bridge) |
| `uv run --directory ffi/secretary-ffi-py pytest` | 3 | ~7-8 | +4-5 |
| `tests/swift/run.sh` asserts | 3 | ~7-8 | +4-5 |
| `tests/kotlin/run.sh` asserts | 3 | ~7-8 | +4-5 |
| `conformance.py` sections | 5 PASS | 5 PASS | 0 |
| `spec_test_name_freshness.py` | 96 / 0 / 2 | 96 / 0 / 2 (or +N if new test names referenced) | 0 or small |

## Build sequence (commit phases)

Five independently-verifiable phases on the feature branch. Each is its own commit (or small commit cluster) ordered so an early phase can be reverted without unwinding later ones. The squash-merge bundles them.

### Phase 7.1 — Generator refactor

**What:** extract `core/tests/common/fixture_builder.rs` from `golden_vault_001.rs`.

**Acceptance:** `cargo test --release --workspace` stays green at 451 + 6 ignored. `git diff core/tests/data/golden_vault_001/` empty (refactor is purely structural). `cargo clippy --release --workspace -- -D warnings` clean.

### Phase 7.2 — Create golden_vault_002

**What:** author `golden_vault_002_inputs.json`, add `core/tests/golden_vault_002.rs` (thin caller of fixture_builder), run `materialize_golden_vault_002` to write fixture bytes, commit. Update conformance.py with the explanatory comment.

**Acceptance:** `cargo test --release --workspace` grows from 451 → ~454 (+3 named tests for vault_002). `conformance.py` PASS unchanged.

### Phase 7.3 — secretary-ffi-bridge crate

**What:** new workspace member with `error.rs` + `identity.rs` + `unlock.rs` + tests. Pure-safe Rust.

**Acceptance:** `cargo test --release --workspace` grows from ~454 → ~469. `cargo clippy --release --workspace -- -D warnings` clean. Bridge crate has no `unsafe_code` carve-out.

### Phase 7.4 — secretary-ffi-py projection

**What:** add bridge dependency; PyO3 newtype + exception classes + `__enter__` / `__exit__` + `#[pyfunction]`; pytest tests.

**Acceptance:** `uv run --directory ffi/secretary-ffi-py pytest` grows from 3 → ~7-8 passed.

### Phase 7.5 — secretary-ffi-uniffi projection

**What:** add bridge dependency; UDL additions; Rust impl forwarders; Swift+Kotlin smoke runners; env-var orchestration in run.sh; READMEs updated; ROADMAP / top-level README flipped; NEXT_SESSION + handoff archive.

**Acceptance:** `tests/swift/run.sh` and `tests/kotlin/run.sh` all asserts PASS. All gates green at session close.

## Risk register

| Risk | Mitigation |
|---|---|
| Generator refactor (7.1) breaks pinned bytes | Refactor is purely structural — no semantic changes. Verify `git diff core/tests/data/golden_vault_001/` empty before committing. |
| `golden_vault_002` regeneration is non-deterministic | Pinned RNG seed in `_inputs.json`; `*_pinned` tests detect drift on subsequent regenerations. |
| uniffi `[Error] interface` complex-error form requires uniffi version bump | Verify current uniffi version (B.1.1.1's resolved version) supports the syntax before committing 7.5. If unsupported, fall back to flat `[Error] enum` + lose the `message` field on Swift/Kotlin (mitigated: bake the inner Display into `Display::fmt` for `FfiUnlockError` so `Error.localizedDescription` / `Throwable.message` carry it). |
| PyO3 maturin develop + uv editable-install cache trap | Documented in user memory; nuke venv + uv cache before re-testing after Rust changes. |
| Bridge-crate `Mutex` overhead surfaces in profiling | Currently sub-microsecond; `RwLock` is a drop-in upgrade if benchmarking ever shows this as a hot path. Documented in bridge crate README. |
| Three foreign-side smoke runners drift in their assertions | All assertions pin the same KAT values from golden_vault_001's `_inputs.json`. Cross-reference in the bridge crate test ensures the bridge layer agrees with foreign-side agreements. |
| Kotlin's hand-written `.use { }` extension diverges from future uniffi `[Trait=Closeable]` | Weekly `uniffi Closeable-trait watch` routine `trig_018gYtGpiycgLXqUsDpV2NZD` flags when this changes; pinned for review. |

## Estimated scope

- Phase 7.1: ~half day
- Phase 7.2: ~2-3 hours
- Phase 7.3: ~half day
- Phase 7.4: ~2-3 hours
- Phase 7.5: ~half day

**Total: ~2 focused sessions** for complete B.2 with golden_vault_002.

Recommended split: session 1 = phases 7.1-7.3 (fixture infra + bridge crate); session 2 = phases 7.4-7.5 (PyO3 + uniffi projections + docs + handoff).

## What this enables long-term

- **Sub-project B.3 (open_with_recovery + create_vault):** bridge crate gains two new functions; both binding-flavor crates each gain mechanical forwarders. The mnemonic-string-crossing-boundary design conversation runs in B.3's brainstorm with the right context.
- **Sub-project C (sync orchestration):** uses `golden_vault_002` as a real second-vault fixture for cross-vault tests; the parameterized `fixture_builder` handles any future fixture additions.
- **Sub-project D (platform UIs):** consumes the Python / Swift / Kotlin bindings shipped here; the thinned error type and explicit-close lifecycle are the contract UI code is written against.
- **External paid review:** the bridge crate is reviewable in isolation as the FFI-friendly facade; the binding-flavor projections are mechanical and don't need security review beyond the macro hygiene already covered in B.1 / B.1.1 / B.1.1.1.

## References

- [secretary_next_session.md](../../../secretary_next_session.md) — multi-session entry point; Sub-project B status table
- [NEXT_SESSION.md](../../../NEXT_SESSION.md) — B.1.1.1 retrospective + B.2 brainstorm prompt
- [docs/crypto-design.md](../../../docs/crypto-design.md) §3 (Master KEK), §13 (anti-oracle property)
- [docs/threat-model.md](../../../docs/threat-model.md) — wrong-password-vs-corruption indistinguishability rationale
- [core/src/unlock/mod.rs](../../../core/src/unlock/mod.rs) — `open_with_password` reference impl + `UnlockError` enum
- [core/src/crypto/secret.rs](../../../core/src/crypto/secret.rs) — `SecretBytes`, `Sensitive<T>` zeroize-on-drop wrappers
- [core/tests/golden_vault_001.rs](../../../core/tests/golden_vault_001.rs) — fixture generator; refactored in Phase 7.1
- [docs/superpowers/specs/2026-05-03-ffi-b1-py-bindings-boilerplate-design.md](2026-05-03-ffi-b1-py-bindings-boilerplate-design.md) — B.1 design (the boilerplate this builds on)
- [PR #20](https://github.com/hherb/secretary/pull/20), [PR #21](https://github.com/hherb/secretary/pull/21), [PR #22](https://github.com/hherb/secretary/pull/22) — B.1, B.1.1, B.1.1.1 shipped
- Routine `trig_018gYtGpiycgLXqUsDpV2NZD` — weekly uniffi Closeable-trait watch
