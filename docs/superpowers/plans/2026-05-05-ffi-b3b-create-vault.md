# B.3b — FFI Vault Creation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire `secretary_core::unlock::create_vault` through both FFI flavors (PyO3 → Python; uniffi → Swift / Kotlin) via the existing shared `secretary-ffi-bridge` crate. The bridge instantiates `OsRng` and `Argon2idParams::V1_DEFAULT` internally; foreign callers get neither knob. The freshly-generated 24-word recovery mnemonic crosses the FFI back to the caller via a separate one-shot opaque `MnemonicOutput` handle with `take_phrase() -> Option<Vec<u8>>` and idempotent `wipe()`. The successfully-created `UnlockedIdentity` is returned alongside, immediately live for vault operations without a second `open_with_password` call. The 5-variant `FfiUnlockError` shape stays structurally unchanged; the only error-side edit is a Display-text tweak on `CorruptVault` from `"vault is corrupt or unreadable: {detail}"` to `"vault data integrity failure: {detail}"` so the variant reads correctly on both create and open paths.

**Architecture:** Strictly additive on B.3a's three-crate FFI layout. Bridge crate gains: a new `create.rs` module with `pub fn create_vault`, `CreateVaultOutput`, and `MnemonicOutput`; one Display string tweak in `error.rs`; one re-export line in `lib.rs`. PyO3 + uniffi projection layers add 1 new entry point + 2 new opaque-handle types each, mirroring the patterns established in B.2 / B.3a. `MnemonicOutput` uses the same `Mutex<Option<T>>` newtype pattern + `lock_or_recover` poisoning-safety helper as `UnlockedIdentity`. Test count grows: cargo workspace +5, pytest +6, Swift smoke +3, Kotlin smoke +3, bridge unit tests +5.

**Tech Stack:** Rust 1.87 stable, PyO3 0.28, uniffi 0.31, maturin 1.9.4+, uv 0.6+, pytest, kotlinc 2.x, swiftc, JNA 5.14.0, thiserror, zeroize, rand_core's `OsRng`. No new top-level dependencies.

**Spec:** [docs/superpowers/specs/2026-05-05-ffi-b3b-create-vault-design.md](../specs/2026-05-05-ffi-b3b-create-vault-design.md) (commit `ca20b9b`)

**Worktree:** `.worktrees/feat-ffi-b3b-create-vault/` on branch `feat/ffi-b3b-create-vault`. Created as Pre-flight Task 0 below; the spec doc commit `ca20b9b` is already in place on `main` and inherits into the worktree.

---

## File structure

After all tasks complete, the FFI tree contains:

```
ffi/
├── secretary-ffi-bridge/
│   ├── README.md                                            ← edit (Task 8; +B.3b section)
│   └── src/
│       ├── lib.rs                                           ← edit (Task 3; re-export create_vault, CreateVaultOutput, MnemonicOutput, B.3b crate-doc)
│       ├── error.rs                                         ← edit (Task 1; Display string tweak only)
│       ├── identity.rs                                      ← unchanged
│       ├── unlock.rs                                        ← unchanged
│       └── create.rs                                        ← NEW (Task 2; create_vault, CreateVaultOutput, MnemonicOutput, +5 tests)
│
├── secretary-ffi-py/
│   ├── README.md                                            ← edit (Task 8; +B.3b section)
│   ├── src/lib.rs                                           ← edit (Task 4; +2 #[pyclass], +1 #[pyfunction])
│   └── tests/test_smoke.py                                  ← edit (Task 5; +6 tests, +1 module-scoped fixture)
│
└── secretary-ffi-uniffi/
    ├── README.md                                            ← edit (Task 8; +B.3b section)
    ├── src/
    │   ├── lib.rs                                           ← edit (Task 6; +2 wrapper structs, +1 pub fn, +tests)
    │   └── secretary.udl                                    ← edit (Task 6; +1 dictionary, +1 interface, +1 namespace fn)
    └── tests/
        ├── swift/main.swift                                 ← edit (Task 7; +3 asserts)
        └── kotlin/Main.kt                                   ← edit (Task 7; +3 asserts)

README.md (root)                                             ← edit (Task 8)
ROADMAP.md                                                   ← edit (Task 8)
NEXT_SESSION.md                                              ← edit (Task 9)
docs/handoffs/2026-MM-DD-b3b-create-vault.md                 ← NEW (Task 9)
```

**Decomposition rationale:**
- Task 1 (Display string tweak) lands first as a tiny, self-contained edit. It's a wire-level change to one Display string + one test assertion; isolating it means the larger create.rs work in Task 2 doesn't entangle with what is conceptually a separate concern (path-neutral error text on the existing variant).
- Task 2 is the largest single piece — new file, new types, new function, 5 tests including 2 slow round-trip tests.
- Task 3 (lib.rs re-export) is mechanically tiny but must come after Task 2 since it re-exports the new symbols.
- Phase 2 (Tasks 4–5) is the PyO3 layer: wrapper first, then tests.
- Phase 3 (Tasks 6–7) is the uniffi layer: UDL + Rust glue, then foreign smoke runners.
- Phase 4 (Tasks 8–9) is the doc + handoff cluster — last commits before push + PR.

---

## Pre-flight

### Task 0: Create the worktree

**Files:** none in repo; creates `.worktrees/feat-ffi-b3b-create-vault/` and branch `feat/ffi-b3b-create-vault`.

- [ ] **Step 1: Verify clean state on main**

```bash
cd /Users/hherb/src/secretary
git status
git log --oneline -3
```

Expected: clean working tree (the three untracked `.claude/` items are local Claude tooling, not project code; ignore them); `main` HEAD is `ca20b9b docs(spec): add B.3b FFI vault creation design (PR-pending)` or newer.

- [ ] **Step 2: Verify all gates green before forking**

```bash
cargo test --release --workspace 2>&1 | grep -E "^test result:" > /tmp/cargo_baseline.txt
python3 -c "
import re
p=f=i=0
for line in open('/tmp/cargo_baseline.txt'):
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'TOTAL: {p} passed; {f} failed; {i} ignored')"
cargo clippy --release --workspace -- -D warnings && echo "clippy OK"
cargo fmt --all -- --check && echo "fmt OK"
```

Expected: `TOTAL: 489 passed; 0 failed; 9 ignored`; clippy OK; fmt OK. If anything diverges, STOP and triage before forking.

- [ ] **Step 3: Create worktree + branch**

```bash
git worktree add -b feat/ffi-b3b-create-vault .worktrees/feat-ffi-b3b-create-vault main
cd .worktrees/feat-ffi-b3b-create-vault
git status
```

Expected: new branch on the same commit as main; clean status.

- [ ] **Step 4: Verify worktree is project-local (per user preference)**

```bash
git worktree list
```

Expected: the new worktree is at `.worktrees/feat-ffi-b3b-create-vault` (relative to repo root), NOT in a global location.

All subsequent tasks run from inside the worktree at `.worktrees/feat-ffi-b3b-create-vault/`.

---

## Phase 1 — Bridge crate

### Task 1: error.rs — Display string tweak on CorruptVault

The `CorruptVault` Display text is currently `"vault is corrupt or unreadable: {detail}"`, which reads correctly on the open path but reads wrong on the create path (where the variant fires when `create_vault` cannot even produce vault bytes). B.3b changes the text to the path-neutral `"vault data integrity failure: {detail}"`.

The variant name (`CorruptVault`), the field shape (`{ detail: String }`), and the placement in the enum are all unchanged. This is a one-line wire edit plus one updated test assertion.

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/error.rs`

- [ ] **Step 1: Update the Display string on the `CorruptVault` variant**

Open `ffi/secretary-ffi-bridge/src/error.rs`. Find the `#[error(...)]` attribute on `CorruptVault` (around line 71):

Current:
```rust
    #[error("vault is corrupt or unreadable: {detail}")]
    CorruptVault {
```

Change to:
```rust
    #[error("vault data integrity failure: {detail}")]
    CorruptVault {
```

Update the inline doc comment immediately above the variant to match (around line 69-70):

Current:
```rust
    /// Vault is corrupt or unreadable. Carries a diagnostic `detail` string
    /// for debugging; not pattern-matchable on the inner cause.
```

Change to:
```rust
    /// Vault data integrity failure — covers BOTH directions: open-path
    /// failure (vault file is malformed / unreadable) AND create-path
    /// failure (couldn't even produce the vault bytes; rare, e.g. Argon2id
    /// system-OOM or CBOR serialization failure of the in-memory bundle).
    /// Carries a diagnostic `detail` string for debugging; not
    /// pattern-matchable on the inner cause.
```

- [ ] **Step 2: Update the existing test that asserts on the Display text**

Locate the `mod tests` block at the bottom of `error.rs`. Find the test `corrupt_vault_collapses_to_corrupt_vault` (or similar — search for `vault is corrupt or unreadable` to find the existing assertion). The test asserts the Display text contains `"vault data integrity failure"` AFTER the rename — but the prior B.3a-era test was checking either the variant shape or some text detail. Check the actual content with grep:

```bash
grep -nE "vault is corrupt|vault data integrity|vault is malformed" ffi/secretary-ffi-bridge/src/error.rs | head -5
```

If any test asserts on `"vault is corrupt or unreadable"`, change the asserted text to `"vault data integrity failure"`. If the existing tests only assert on the structural variant + the `detail` content (NOT on the Display text directly), no test edit is needed.

Add one NEW test that pins the new Display text as a tripwire:

```rust
#[test]
fn corrupt_vault_display_uses_path_neutral_text() {
    // B.3b changed the Display text from "vault is corrupt or unreadable"
    // (read-path-only) to "vault data integrity failure" (path-neutral)
    // so the variant reads correctly on the create path too. This test
    // is a tripwire: a future refactor that reverts to read-path-only
    // text would fail here, forcing a deliberate decision rather than
    // a silent regression.
    let ffi = FfiUnlockError::CorruptVault {
        detail: "fnord".to_string(),
    };
    let rendered = format!("{ffi}");
    assert!(
        rendered.contains("vault data integrity failure"),
        "Display did not contain the path-neutral text: {rendered}",
    );
    assert!(rendered.contains("fnord"), "Display did not include detail");
    // Negative: must NOT contain the old read-path-only phrasing.
    assert!(
        !rendered.contains("corrupt or unreadable"),
        "Display still contains the old read-path-only text: {rendered}",
    );
}
```

(Place it inside `mod tests` after the existing tests; the import scope already has `FfiUnlockError` available.)

- [ ] **Step 3: Update the module-level docstring**

The error.rs module-level doc comment (around line 26) currently says:

```rust
//! - [`FfiUnlockError::CorruptVault`] — collapses
//!   `{core::CorruptVault, all MalformedX, KdfFailure, WeakKdfParams}`.
//!   Carries a diagnostic `detail: String` for debugging; structured
//!   pattern-matching on the inner cause is intentionally not supported.
```

Append a sentence explaining the path-neutral wording:

```rust
//! - [`FfiUnlockError::CorruptVault`] — collapses
//!   `{core::CorruptVault, all MalformedX, KdfFailure, WeakKdfParams}`.
//!   Carries a diagnostic `detail: String` for debugging; structured
//!   pattern-matching on the inner cause is intentionally not supported.
//!   Display text is path-neutral (`"vault data integrity failure"`)
//!   so the variant reads correctly on BOTH the open path (where it
//!   fires when a vault file is malformed) AND the create path (where
//!   it fires on rare system-level failures during vault production).
```

- [ ] **Step 4: Run bridge unit tests in isolation**

```bash
cargo test --release --package secretary-ffi-bridge --lib 2>&1 | grep -E "^test result:|FAIL|panicked"
```

Expected: `test result: ok. 31 passed; 0 failed` (was 30 in error.rs+identity.rs+unlock.rs; +1 new tripwire test). No FAIL or panicked. If any pre-existing test FAILS because it asserted on the old Display text, edit that test to assert on the new text in this same commit.

- [ ] **Step 5: Run the full workspace build to surface any downstream caller that asserted on the old text**

```bash
cargo test --release --workspace 2>&1 | grep -E "^test result:" > /tmp/cargo_t1.txt
python3 -c "
import re
p=f=i=0
for line in open('/tmp/cargo_t1.txt'):
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'TOTAL: {p} passed; {f} failed; {i} ignored')"
```

Expected: `TOTAL: 490 passed; 0 failed; 9 ignored` (was 489; +1 from the new tripwire). If any other test fails, search for the old text in the failing crate and update.

- [ ] **Step 6: Verify clippy + fmt clean**

```bash
cargo clippy --release --package secretary-ffi-bridge -- -D warnings && echo "bridge clippy OK"
cargo fmt --all -- --check && echo "fmt OK"
```

- [ ] **Step 7: Commit**

```bash
git add ffi/secretary-ffi-bridge/src/error.rs
git commit -m "$(cat <<'EOF'
feat(ffi-b3b): tweak CorruptVault Display to path-neutral wording

Changes the Display string on FfiUnlockError::CorruptVault from
"vault is corrupt or unreadable: {detail}" (read-path-only framing)
to "vault data integrity failure: {detail}" (path-neutral) so the
variant reads correctly on both the open path (where the existing
mappings collapse malformed-X / KdfFailure / etc. into it) and the
new create path landed in subsequent commits.

The variant name, struct shape, and placement are unchanged. One new
unit test pins the new text as a tripwire so a future revert is a
deliberate decision rather than a silent regression. Module-level
docstring annotated with the path-neutral rationale.

No structural error change. No new variant. The 5-variant cardinality
that B.3a settled stays exactly intact.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: create.rs — new module with create_vault, CreateVaultOutput, MnemonicOutput, and 5 tests

The bridge crate gains a new file `ffi/secretary-ffi-bridge/src/create.rs` containing the third `pub fn` entry point (after `open_with_password` and `open_with_recovery`), two new opaque-handle types, and 5 unit tests.

The module is conceptually distinct from `unlock.rs` (creation is a different verb; the spec separates them under "B.3a vs B.3b boundary") and structurally distinct from `identity.rs` (which holds the `UnlockedIdentity` opaque handle that both unlock and create paths return). Following B.3a's file-per-concern split keeps each file single-purpose and well under 500 lines.

**Files:**
- Create: `ffi/secretary-ffi-bridge/src/create.rs`

- [ ] **Step 1: Create the new file with module-level documentation**

Create `ffi/secretary-ffi-bridge/src/create.rs` with this initial header content:

```rust
//! Vault creation: the third `pub fn` entry point on the bridge surface
//! (after `open_with_password` and `open_with_recovery`), and the first
//! **output-direction** secret-bearing operation. Defines two new opaque-
//! handle types ([`CreateVaultOutput`] and [`MnemonicOutput`]) for the
//! return-side `Sensitive<T>` materialization.
//!
//! # Why a separate handle for the mnemonic
//!
//! `secretary_core::unlock::create_vault` returns a [`CreatedVault`]
//! containing — among other artifacts — a freshly-generated 24-word BIP-39
//! mnemonic wrapped as `Sensitive<...>` on the Rust side. That phrase MUST
//! reach the foreign caller exactly once so the user can write it down,
//! then disappear from the system.
//!
//! The three foreign languages all lack a `Sensitive<T>` analog:
//! - **Python** — `bytes` is immutable; `bytearray` is mutable but offers
//!   no destructor hook.
//! - **Swift** — `Data` is value-typed but unzeroized.
//! - **Kotlin** — `ByteArray` is reference-typed but unzeroized.
//!
//! So the bridge keeps the `Sensitive<...>` Rust-side, exposes a one-shot
//! [`MnemonicOutput::take_phrase`] accessor that copies the bytes out into
//! caller-owned heap (a fresh `Vec<u8>`), and drops the inner
//! [`Mnemonic`](secretary_core::unlock::mnemonic::Mnemonic) immediately —
//! which zeroizes the `String` phrase + `Sensitive<[u8; 32]>` entropy. The
//! caller is responsible for zeroizing their copy after use, mirroring the
//! input-side caller-zeroize discipline from B.2 / B.3a but inverted in
//! direction.
//!
//! # Why a separate handle from `UnlockedIdentity`
//!
//! The mnemonic is a one-time-use secret consumed at vault-creation time;
//! the unlocked identity persists for the session. Coupling them
//! (`identity.recovery_phrase()` returning `Option<...>`) reads worse — a
//! long-lived handle with a dribble of secret state. Keeping them as
//! sister handles produced from the same `create_vault` call lets each
//! match its natural lifecycle: `MnemonicOutput` is one-shot then wiped,
//! `UnlockedIdentity` is used for vault operations until session end.
//!
//! # Why no foreign-side RNG / KDF-params knobs
//!
//! The bridge instantiates `OsRng` and `Argon2idParams::V1_DEFAULT`
//! directly. First-party clients always want the OS CSPRNG and the
//! conservative KDF default; tuning is a v2 design conversation, not an
//! FFI runtime parameter. With `V1_DEFAULT` hardcoded,
//! `core::UnlockError::WeakKdfParams` is structurally unreachable through
//! this surface — the existing defensive fold-into-`CorruptVault`
//! mapping in [`crate::error`] stays in place for forward-compat.
//!
//! Rationale: docs/superpowers/specs/2026-05-05-ffi-b3b-create-vault-design.md

use std::sync::{Mutex, MutexGuard, PoisonError};

use rand_core::OsRng;
use secretary_core::crypto::kdf::Argon2idParams;
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::unlock::{self, mnemonic::Mnemonic};

use crate::error::FfiUnlockError;
use crate::identity::UnlockedIdentity;
```

(The imports are exactly what the rest of the file needs; they all resolve from existing dependencies.)

- [ ] **Step 2: Add the `lock_or_recover` helper**

Mirroring the same helper used by [`crate::identity`] (poisoning-safety for non-throwing accessors), define:

```rust
/// Acquire the inner lock, falling through poisoning to preserve the
/// non-throwing API contract. See [`crate::identity::lock_or_recover`]
/// for the same pattern; copied here verbatim because Rust's privacy
/// rules prevent re-using the identity-module-private helper across
/// modules without exposing a wider surface than warranted.
fn lock_or_recover<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}
```

(`crate::identity::lock_or_recover` is currently a private function in `identity.rs`. Re-exporting it would widen the bridge's internal API. Duplicating the 1-line helper here is the correct trade-off — it's tiny, keeps each module self-contained, and a future refactor that promotes it to `crate::shared` is trivial.)

- [ ] **Step 3: Define the `MnemonicOutput` opaque handle**

Append this struct + impl block to `create.rs`:

```rust
/// One-shot opaque handle wrapping a freshly-generated [`Mnemonic`].
///
/// The recovery phrase is `Sensitive<String>`-equivalent on the Rust side;
/// it cannot be projected directly through the FFI without copying out of
/// the `Sensitive<T>` boundary (no foreign language has a generic
/// `Sensitive<T>` analog). [`MnemonicOutput::take_phrase`] does that copy
/// explicitly, ONCE, then drops the inner `Mnemonic` so its `Drop` impl
/// zeroizes both the `String` phrase and the `Sensitive<[u8; 32]>` entropy.
///
/// The returned `Vec<u8>` is fresh caller-owned heap. Callers MUST
/// zeroize it after use; the bridge cannot enforce this from across the
/// FFI. The contract is documented at the foreign-language API level
/// (Python: `for i in range(len(buf)): buf[i] = 0`; Swift / Kotlin: see
/// language idioms in the spec).
///
/// # Lifecycle
///
/// - [`MnemonicOutput::take_phrase`] returns `Some(bytes)` once, then
///   `None` on every subsequent call (one-shot semantics, NOT an error).
///   The inner Mnemonic is consumed and zeroized after the first
///   successful call.
/// - [`MnemonicOutput::wipe`] is idempotent. It drops the inner Mnemonic
///   if still present, zeroizing its secret state.
/// - The Drop impl runs `wipe`-equivalent automatically via
///   `Mutex<Option<Mnemonic>>`'s standard drop chain.
pub struct MnemonicOutput {
    /// Wrapped behind a `Mutex<Option<...>>` to provide:
    /// - **one-shot take** via `Option::take()` (returns the inner
    ///   Mnemonic exactly once)
    /// - **idempotent wipe** via the same `Option::take()` (a second
    ///   wipe finds `None` and is a no-op)
    /// - **thread-safe access** (the Mutex serializes the take/wipe
    ///   calls; the lock is short — at most copying the phrase bytes)
    /// - **post-take non-throwing** semantics (subsequent take returns
    ///   `None` rather than panicking)
    inner: Mutex<Option<Mnemonic>>,
}

impl MnemonicOutput {
    /// Wrap a freshly-generated `Mnemonic`. Crate-private: only
    /// [`create_vault`] constructs this.
    pub(crate) fn new(m: Mnemonic) -> Self {
        Self {
            inner: Mutex::new(Some(m)),
        }
    }

    /// Take the recovery phrase as freshly-allocated UTF-8 bytes. ONE-SHOT —
    /// subsequent calls return `None`.
    ///
    /// On the first successful call, the inner `Mnemonic` is consumed and
    /// dropped here; its `Drop` impl zeroizes the `String` phrase and the
    /// `Sensitive<[u8; 32]>` entropy. The returned `Vec<u8>` was copied
    /// OUT of the about-to-be-zeroized `String` BEFORE the drop, so it
    /// survives intact for the caller to display, copy, and explicitly
    /// zeroize.
    ///
    /// `None` is the documented signal for "already consumed", not an
    /// error. The foreign call sites use `if let Some(phrase) = ...`
    /// (Swift), `phrase?.let { ... }` (Kotlin), or `phrase = ...; if
    /// phrase is None: ...` (Python).
    pub fn take_phrase(&self) -> Option<Vec<u8>> {
        let mut guard = lock_or_recover(&self.inner);
        let m = guard.take()?;
        // Copy bytes out BEFORE m drops; the Drop impl on Mnemonic will
        // zeroize the String buffer when m goes out of scope at the end
        // of this fn. The returned Vec<u8> is a fresh allocation, NOT
        // a slice into the zeroized buffer.
        let bytes = m.phrase().as_bytes().to_vec();
        // m drops here; Mnemonic's explicit Drop wipes phrase + entropy
        Some(bytes)
    }

    /// Idempotent explicit close. Drops the inner [`Mnemonic`] if still
    /// present, zeroizing its secret state. Safe to call multiple times;
    /// safe to call after [`MnemonicOutput::take_phrase`] returned
    /// `Some`.
    pub fn wipe(&self) {
        let _drop = lock_or_recover(&self.inner).take();
        // _drop goes out of scope here → Mnemonic drops → phrase + entropy
        // zeroized.
    }
}
```

- [ ] **Step 4: Add a redacted `Debug` impl for `MnemonicOutput`**

Append immediately after the impl block:

```rust
impl std::fmt::Debug for MnemonicOutput {
    /// Redacted Debug: never leak the phrase through fmt. Mirrors the
    /// pattern in `crate::identity::UnlockedIdentity` and core's
    /// `Mnemonic`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let consumed = lock_or_recover(&self.inner).is_none();
        f.debug_struct("MnemonicOutput")
            .field("consumed_or_wiped", &consumed)
            .finish()
    }
}
```

- [ ] **Step 5: Define the `CreateVaultOutput` struct**

Append:

```rust
/// Output of [`create_vault`]. Holds the on-disk byte artifacts plus two
/// opaque handles for the live identity and the one-shot recovery
/// mnemonic.
///
/// # Drop discipline
///
/// Fields drop in source order. Non-secret byte vectors drop first; the
/// two secret-bearing handles last (each zeroizing their own inner
/// state on drop). The order is observable but not load-bearing — neither
/// secret depends on the other for cleanup.
///
/// # Persistence
///
/// `vault_toml_bytes` and `identity_bundle_bytes` are non-secret byte
/// artifacts the foreign caller MUST persist atomically before
/// considering the vault created. The bridge does not perform file I/O;
/// matches the bytes-not-paths discipline of B.2 / B.3a's
/// `open_with_*`.
pub struct CreateVaultOutput {
    /// Vault metadata file contents, non-secret. Caller writes this to
    /// `<vault-dir>/vault.toml` atomically.
    pub vault_toml_bytes: Vec<u8>,
    /// Encrypted identity bundle file contents, non-secret. Caller writes
    /// this to `<vault-dir>/identity.bundle.enc` atomically.
    pub identity_bundle_bytes: Vec<u8>,
    /// Live opaque handle to the just-created `UnlockedIdentity`. Ready
    /// for vault operations immediately; no second `open_with_password`
    /// call is needed.
    pub identity: UnlockedIdentity,
    /// One-shot opaque handle wrapping the freshly-generated 24-word
    /// recovery mnemonic. Caller calls
    /// [`MnemonicOutput::take_phrase`] once, displays the phrase to
    /// the user, then zeroizes their copy and calls
    /// [`MnemonicOutput::wipe`].
    pub mnemonic: MnemonicOutput,
}
```

- [ ] **Step 6: Define the `create_vault` free function**

Append:

```rust
/// Create a fresh v1 vault using `OsRng` and `Argon2idParams::V1_DEFAULT`.
///
/// See [module docs](self) for why neither the RNG nor the KDF params
/// are foreign-callable knobs.
///
/// # Inputs
///
/// - `password` — UTF-8-encoded master password as raw bytes. The bridge
///   wraps this into `SecretBytes` (which zeroizes on drop). The caller
///   should still zeroize their input buffer after the call returns
///   (matches the B.2 password-input pattern).
/// - `display_name` — user-facing identity name (UTF-8 string). Stored
///   in the IdentityBundle as plaintext metadata.
/// - `created_at_ms` — wall-clock millisecond timestamp at vault
///   creation. Caller's responsibility to use a sane value (e.g.
///   `int(time.time() * 1000)` in Python).
///
/// # Returns
///
/// On success, a [`CreateVaultOutput`] with four fields:
/// - `vault_toml_bytes` and `identity_bundle_bytes` to persist atomically
/// - `identity` (live [`UnlockedIdentity`] handle, ready for vault ops)
/// - `mnemonic` ([`MnemonicOutput`] one-shot handle for the 24-word
///   recovery phrase)
///
/// # Errors
///
/// Returns [`FfiUnlockError`]; under the hardcoded `V1_DEFAULT` design,
/// the only reachable variant is [`FfiUnlockError::CorruptVault`], which
/// fires on extremely rare paths: Argon2id derivation failure (system OOM
/// / threading) or CBOR serialization failure of the in-memory identity
/// bundle. The `detail` string carries the original
/// `core::UnlockError`'s `Display` text.
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

- [ ] **Step 7: Add the `mod tests` block with 5 tests**

Append at the bottom of `create.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    use secretary_core::unlock::mnemonic;

    /// Helper: build a `MnemonicOutput` from a deterministically-seeded
    /// `mnemonic::generate` call. Avoids the ~1s Argon2id cost of
    /// invoking `create_vault` itself; the three fast tests below
    /// exercise `MnemonicOutput`'s contract in isolation.
    fn fresh_mnemonic_output() -> MnemonicOutput {
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let m = mnemonic::generate(&mut rng);
        MnemonicOutput::new(m)
    }

    #[test]
    fn mnemonic_output_take_phrase_returns_24_words() {
        let mo = fresh_mnemonic_output();
        let phrase = mo.take_phrase().expect("first call must return Some");
        // BIP-39 24-word phrase is 24 lowercase ASCII words separated by
        // single spaces. Counting whitespace-separated tokens is the
        // contract pin.
        let word_count = phrase.split(|&b| b == b' ').count();
        assert_eq!(
            word_count, 24,
            "expected 24 words, got {word_count}: {:?}",
            std::str::from_utf8(&phrase).unwrap_or("<not utf-8>"),
        );
    }

    #[test]
    fn mnemonic_output_take_phrase_is_one_shot() {
        let mo = fresh_mnemonic_output();
        let first = mo.take_phrase();
        let second = mo.take_phrase();
        assert!(first.is_some(), "first call must return Some");
        assert!(second.is_none(), "second call must return None (one-shot)");
    }

    #[test]
    fn mnemonic_output_wipe_is_idempotent() {
        let mo = fresh_mnemonic_output();
        mo.wipe();
        mo.wipe(); // second call must not panic
        mo.wipe(); // third call must not panic
        assert!(
            mo.take_phrase().is_none(),
            "take_phrase after wipe must return None",
        );
    }

    #[test]
    fn create_vault_round_trip_with_password() {
        // Slow test: real Argon2idParams::V1_DEFAULT. ~1s for create
        // + ~1s for open. Justified because this is the only place that
        // exercises the bridge's create_vault end-to-end against a real
        // produced byte artifact.
        let out = create_vault(b"hunter2", "Round-Trip-Bob", 1_700_000_000_000)
            .expect("create_vault should succeed");
        assert_eq!(out.identity.display_name(), "Round-Trip-Bob");

        let opened = crate::open_with_password(
            &out.vault_toml_bytes,
            &out.identity_bundle_bytes,
            b"hunter2",
        )
        .expect("re-open with the same password must succeed");
        assert_eq!(opened.display_name(), "Round-Trip-Bob");
        assert_eq!(opened.user_uuid(), out.identity.user_uuid());
    }

    #[test]
    fn create_vault_round_trip_with_recovery() {
        // Slow test: same shape as the password round-trip but
        // exercises the recovery path end-to-end.
        let out = create_vault(b"unused-pw", "Round-Trip-Carol", 1_700_000_000_000)
            .expect("create_vault should succeed");
        let phrase = out.mnemonic.take_phrase().expect("phrase must be available");

        let opened = crate::open_with_recovery(
            &out.vault_toml_bytes,
            &out.identity_bundle_bytes,
            &phrase,
        )
        .expect("re-open with the just-taken phrase must succeed");
        assert_eq!(opened.display_name(), "Round-Trip-Carol");
    }
}
```

- [ ] **Step 8: Wire the new module into `lib.rs` (declaration only; re-exports come in Task 3)**

The file is created but not yet visible to the rest of the crate. Open `ffi/secretary-ffi-bridge/src/lib.rs` and add a single line in the `mod` declarations block (around line 44-46):

Current:
```rust
pub mod error;
pub mod identity;
pub mod unlock;
```

Change to:
```rust
pub mod create;
pub mod error;
pub mod identity;
pub mod unlock;
```

(Alphabetical order. Don't touch the `pub use ...` re-exports yet — those are Task 3.)

- [ ] **Step 9: Run bridge unit tests in isolation**

```bash
cargo test --release --package secretary-ffi-bridge --lib 2>&1 | grep -E "^test result:|FAIL|panicked"
```

Expected: `test result: ok. 36 passed; 0 failed` (was 31 after Task 1; +5 new tests in `create.rs::mod tests`). No FAIL or panicked. The 2 slow tests (`create_vault_round_trip_with_*`) each run real Argon2id at V1_DEFAULT (~1s + ~1s for open per test) → cargo test wall-clock for the whole package goes from ~3s to ~7s. Expected.

- [ ] **Step 10: Verify clippy + fmt clean**

```bash
cargo clippy --release --package secretary-ffi-bridge -- -D warnings && echo "bridge clippy OK"
cargo fmt --all -- --check && echo "fmt OK"
```

If clippy flags anything in `create.rs`, fix it inline before committing.

- [ ] **Step 11: Commit**

```bash
git add ffi/secretary-ffi-bridge/src/create.rs ffi/secretary-ffi-bridge/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(ffi-b3b): add create_vault, CreateVaultOutput, MnemonicOutput to bridge crate

New file ffi/secretary-ffi-bridge/src/create.rs holds the third
pub fn entry point on the bridge surface (after open_with_password
and open_with_recovery), the first that produces secret material
in the output direction. Two new opaque-handle types:

- CreateVaultOutput: non-secret bytes (vault.toml + identity.bundle.enc)
  + live UnlockedIdentity + one-shot MnemonicOutput.
- MnemonicOutput: Mutex<Option<core::Mnemonic>> newtype with one-shot
  take_phrase() -> Option<Vec<u8>> and idempotent wipe(), mirroring
  UnlockedIdentity's pattern. Returned Vec<u8> exits Sensitive<T> as
  caller-zeroize-discipline bytes (documented contract; bridge cannot
  enforce from across the FFI).

The bridge instantiates OsRng and Argon2idParams::V1_DEFAULT
internally; foreign callers cannot tune either. With V1_DEFAULT
hardcoded, core::UnlockError::WeakKdfParams stays unreachable through
this surface; the existing defensive fold-into-CorruptVault mapping
remains forward-compat.

Five new tests:
- 3 fast tests on MnemonicOutput contract (24-word phrase shape,
  one-shot take, idempotent wipe)
- 2 slow round-trip tests through real V1_DEFAULT Argon2id
  (create-then-open-with-password, create-then-open-with-recovery)
  pin display_name + user_uuid preservation across the dual-KEK
  convergence point.

Module declaration added to lib.rs; re-exports come in Task 3.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: lib.rs — re-export create_vault, CreateVaultOutput, MnemonicOutput; update crate-doc

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs`

- [ ] **Step 1: Add the new re-exports**

Open `ffi/secretary-ffi-bridge/src/lib.rs`. Find the `pub use ...` block (around line 48-50):

Current:
```rust
pub use error::FfiUnlockError;
pub use identity::UnlockedIdentity;
pub use unlock::{open_with_password, open_with_recovery};
```

Add a new line:

```rust
pub use create::{create_vault, CreateVaultOutput, MnemonicOutput};
pub use error::FfiUnlockError;
pub use identity::UnlockedIdentity;
pub use unlock::{open_with_password, open_with_recovery};
```

(Alphabetical by module name.)

- [ ] **Step 2: Update the crate-level `# Surface` doc comment**

Find the `# Surface` block (around line 10-30) and replace with:

```rust
//! # Surface
//!
//! - [`FfiUnlockError`] — thinned 5-variant error type expressing
//!   user-actionable intent rather than mirroring `core::UnlockError`'s
//!   internal enum structure. Two variants per unlock path
//!   (`WrongPasswordOrCorrupt` / `WrongMnemonicOrCorrupt`) plus a
//!   pre-decryption `InvalidMnemonic { detail }` for BIP-39 validation
//!   failures, plus the cross-path `VaultMismatch` and `CorruptVault { detail }`.
//!   `CorruptVault`'s Display text is path-neutral
//!   (`"vault data integrity failure"`) and reads correctly on both
//!   the open and create paths. See [`error`] module docs.
//! - [`UnlockedIdentity`] — opaque handle wrapping a successfully-unlocked
//!   `core::UnlockedIdentity`. Foreign callers hold a refcount and read
//!   non-secret fields via accessor methods; the secret keys stay Rust-
//!   side and zeroize on drop. Both unlock entry points return this same
//!   shape (the §3/§4 dual-KEK design produces byte-identical secret state).
//!   `create_vault` also returns this shape — immediately live, no second
//!   `open_with_password` call needed. See [`identity`] module docs.
//! - [`open_with_password`] — fallible, secret-bearing operation: vault
//!   unlock by master password. See [`unlock`] module docs.
//! - [`open_with_recovery`] — fallible, secret-bearing operation: vault
//!   unlock by 24-word BIP-39 recovery phrase. Mnemonic input is UTF-8
//!   bytes (`&[u8]`), parallel to the password input shape. See [`unlock`]
//!   module docs.
//! - [`create_vault`] — fallible, secret-bearing operation: produce a
//!   fresh v1 vault using OS CSPRNG and `Argon2idParams::V1_DEFAULT`.
//!   Returns [`CreateVaultOutput`] (non-secret byte artifacts +
//!   live [`UnlockedIdentity`] + one-shot [`MnemonicOutput`]). See
//!   [`create`] module docs.
//! - [`CreateVaultOutput`] — return type from `create_vault`. Four fields:
//!   `vault_toml_bytes`, `identity_bundle_bytes` (non-secret bytes the
//!   caller persists atomically), `identity` (live unlocked-identity
//!   handle), and `mnemonic` (one-shot recovery-phrase handle).
//! - [`MnemonicOutput`] — one-shot opaque handle for the freshly-generated
//!   24-word BIP-39 recovery mnemonic. The phrase exits the
//!   `Sensitive<T>` boundary via [`MnemonicOutput::take_phrase`] as
//!   caller-owned `Vec<u8>` with documented caller-zeroize discipline;
//!   second `take_phrase` call returns `None` (one-shot semantics, NOT
//!   an error). [`MnemonicOutput::wipe`] is idempotent. See [`create`]
//!   module docs.
```

- [ ] **Step 3: Verify bridge crate still builds cleanly**

```bash
cargo build --release --package secretary-ffi-bridge 2>&1 | tail -3
cargo test --release --package secretary-ffi-bridge 2>&1 | grep -E "^test result:"
```

Expected: `Finished` and `test result: ok. 36 passed; 0 failed`.

- [ ] **Step 4: Verify rustdoc is clean (no broken intra-doc links)**

```bash
cargo doc --package secretary-ffi-bridge --no-deps 2>&1 | grep -E "warning|error" | head -10
```

Expected: zero warnings, zero errors. The crate-doc references `[crate::create]` etc.; intra-doc links must resolve.

- [ ] **Step 5: Commit**

```bash
git add ffi/secretary-ffi-bridge/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(ffi-b3b): re-export create_vault + CreateVaultOutput + MnemonicOutput

Crate-doc updated to describe the new B.3b surface:
- create_vault as the third pub fn entry point
- CreateVaultOutput as the four-field return type
- MnemonicOutput as the one-shot recovery-phrase handle

The crate's "single source of FFI code truth" property is preserved:
both binding-flavor crates (secretary-ffi-py, secretary-ffi-uniffi)
now have access to the new types from this re-export and can project
them through their respective binding macros.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Phase 2 — secretary-ffi-py projection

### Task 4: PyO3 wrapper — 2 new #[pyclass] + 1 new #[pyfunction]

**Files:**
- Modify: `ffi/secretary-ffi-py/src/lib.rs`

The PyO3 layer adds two newtype wrappers (`CreateVaultOutput`, `MnemonicOutput`) and one new `#[pyfunction] create_vault`. Both wrappers project the bridge's types directly; `MnemonicOutput` implements the context-manager protocol matching `UnlockedIdentity`'s B.2 pattern.

- [ ] **Step 1: Add the `MnemonicOutput` `#[pyclass]` newtype**

Open `ffi/secretary-ffi-py/src/lib.rs`. Below the existing `UnlockedIdentity` `#[pyclass]` (around line 144, after the closing `}` of its `#[pymethods]` block), add:

```rust
/// Opaque Python-side handle to a one-shot recovery mnemonic. Newtype
/// around `secretary_ffi_bridge::MnemonicOutput`; methods are thin
/// forwarders. Implements the context-manager protocol so the idiomatic
/// usage is `with output.mnemonic as mn: phrase = mn.take_phrase()`.
///
/// `take_phrase()` returns `bytes` once; subsequent calls return `None`.
/// `close()` (and the equivalent context-manager `__exit__`) is
/// idempotent and wipes any still-resident phrase from Rust-side memory.
#[pyclass]
pub struct MnemonicOutput(secretary_ffi_bridge::MnemonicOutput);

#[pymethods]
impl MnemonicOutput {
    /// Take the recovery phrase as `bytes`. ONE-SHOT — second call
    /// returns `None`. The returned `bytes` is fresh caller-owned heap;
    /// the caller is responsible for zeroizing it after use (e.g. by
    /// converting to `bytearray` and overwriting in place; PyO3 cannot
    /// hand back a mutable buffer typed as a foreign Sensitive analog).
    fn take_phrase<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.0.take_phrase().map(|v| PyBytes::new(py, &v))
    }

    /// Drop any still-resident inner mnemonic now, zeroizing its
    /// `Sensitive<...>` fields. Idempotent.
    fn close(&self) {
        self.0.wipe();
    }

    /// Context-manager `__enter__`. Returns `self` so
    /// `with output.mnemonic as mn` binds the handle.
    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    /// Context-manager `__exit__`. Calls `close()` and returns `False`
    /// so any exception raised inside the `with`-block propagates after
    /// close runs. Mirrors the exit pattern on `UnlockedIdentity`.
    fn __exit__(
        &self,
        _exc_type: Option<&Bound<'_, PyType>>,
        _exc_value: Option<&Bound<'_, PyAny>>,
        _traceback: Option<&Bound<'_, PyAny>>,
    ) -> bool {
        self.0.wipe();
        false
    }
}
```

- [ ] **Step 2: Add the `CreateVaultOutput` `#[pyclass]`**

Append immediately after the `MnemonicOutput` block:

```rust
/// Output of `create_vault`. Holds the on-disk byte artifacts plus two
/// opaque handles for the live identity and the one-shot recovery
/// mnemonic. The fields are accessed through getter methods because
/// `#[pyclass]` types cannot expose non-trivial fields directly.
#[pyclass]
pub struct CreateVaultOutput {
    /// Vault metadata bytes — non-secret. Caller writes these to
    /// `<vault-dir>/vault.toml` atomically.
    vault_toml_bytes: Vec<u8>,
    /// Encrypted identity bundle bytes — non-secret. Caller writes these
    /// to `<vault-dir>/identity.bundle.enc` atomically.
    identity_bundle_bytes: Vec<u8>,
    /// Live opaque handle to the just-created identity. Wrapped in
    /// `Option` so the getter can move it out exactly once (see
    /// `take_identity`); after that the field becomes `None` and
    /// subsequent calls raise.
    identity: Option<UnlockedIdentity>,
    /// One-shot opaque handle for the recovery mnemonic. Same Option
    /// take-once pattern as `identity`.
    mnemonic: Option<MnemonicOutput>,
}

#[pymethods]
impl CreateVaultOutput {
    /// Vault metadata bytes — non-secret. Returns a fresh `bytes` object
    /// each call (PyO3 copies from the underlying `Vec<u8>`).
    #[getter]
    fn vault_toml_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.vault_toml_bytes)
    }

    /// Encrypted identity bundle bytes — non-secret.
    #[getter]
    fn identity_bundle_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.identity_bundle_bytes)
    }

    /// Take ownership of the live `UnlockedIdentity` handle. ONE-SHOT —
    /// subsequent calls raise `RuntimeError`. The Python idiom is to
    /// bind the result and use it directly, e.g.
    /// `with output.identity as id: ...`.
    ///
    /// Implemented via interior take rather than a borrowed reference
    /// because Python `with` semantics need to OWN the context manager;
    /// returning a reference into a `#[pyclass]` field would couple the
    /// `with`-block's lifetime to the parent `output` value in ways that
    /// are awkward at the FFI boundary.
    #[getter]
    fn identity(&mut self) -> PyResult<UnlockedIdentity> {
        self.identity.take().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(
                "CreateVaultOutput.identity already taken (one-shot)",
            )
        })
    }

    /// Take ownership of the one-shot `MnemonicOutput` handle. Same
    /// take-once semantics as `identity`.
    #[getter]
    fn mnemonic(&mut self) -> PyResult<MnemonicOutput> {
        self.mnemonic.take().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(
                "CreateVaultOutput.mnemonic already taken (one-shot)",
            )
        })
    }
}
```

(The take-once pattern is necessary because Python's `with` statement and PyO3's `#[pyclass]` ownership semantics interact poorly: a borrowed reference into a parent `#[pyclass]` field would couple the lifetime of the `with`-block to the parent value, which Python's GC handles awkwardly. Taking ownership at first access mirrors the same pattern Rust's `Option::take()` provides.)

- [ ] **Step 3: Add the `create_vault` `#[pyfunction]`**

After the existing `open_with_recovery` `#[pyfunction]` (at the bottom of the function block, before the `#[pymodule]` declaration around line 197), add:

```rust
/// Create a fresh v1 vault. Bridge instantiates `OsRng` and
/// `Argon2idParams::V1_DEFAULT` internally; foreign callers get
/// neither knob.
///
/// Returns a `CreateVaultOutput` containing:
/// - `vault_toml_bytes`, `identity_bundle_bytes` — non-secret bytes the
///   caller persists atomically.
/// - `identity` — live `UnlockedIdentity`, ready for vault operations.
/// - `mnemonic` — one-shot `MnemonicOutput` for the 24-word recovery
///   phrase.
///
/// See module-level docs for the exception classes raised on failure.
#[pyfunction]
fn create_vault(
    mut password: Vec<u8>,
    display_name: &str,
    created_at_ms: u64,
) -> PyResult<CreateVaultOutput> {
    // Mirrors the open_with_password / open_with_recovery wrapper-side
    // zeroize discipline: the bridge's create_vault wraps password into
    // SecretBytes (which zeroizes on drop). This Vec is a transient
    // cleartext residue on the wrapper's heap; zero it explicitly so we
    // don't leave the password lingering after the call returns.
    let result = secretary_ffi_bridge::create_vault(&password, display_name, created_at_ms);
    password.zeroize();
    let bridge_out = result.map_err(ffi_unlock_error_to_pyerr)?;

    let secretary_ffi_bridge::CreateVaultOutput {
        vault_toml_bytes,
        identity_bundle_bytes,
        identity,
        mnemonic,
    } = bridge_out;

    Ok(CreateVaultOutput {
        vault_toml_bytes,
        identity_bundle_bytes,
        identity: Some(UnlockedIdentity(identity)),
        mnemonic: Some(MnemonicOutput(mnemonic)),
    })
}
```

- [ ] **Step 4: Register the new types and function in the `#[pymodule]`**

Locate the `#[pymodule]` `secretary_ffi_py` function. Append to its body, after the existing B.3a registrations:

```rust
    // B.3b surface:
    m.add_class::<CreateVaultOutput>()?;
    m.add_class::<MnemonicOutput>()?;
    m.add_function(wrap_pyfunction!(create_vault, m)?)?;
```

- [ ] **Step 5: Update the crate-level doc comment**

The existing comment ends with the B.3a rationale line. Append below it:

```rust
//!
//! B.3b adds the `create_vault` entry-point and 2 new opaque-handle
//! types (`CreateVaultOutput`, `MnemonicOutput`). Bridge instantiates
//! `OsRng` and `Argon2idParams::V1_DEFAULT` internally; foreign callers
//! get neither knob. The freshly-generated 24-word recovery mnemonic
//! crosses the FFI back via `MnemonicOutput.take_phrase()` as `bytes`,
//! one-shot — second call returns `None`. Caller-zeroize discipline on
//! the returned `bytes` parallels the input-side discipline from B.2
//! / B.3a, inverted in direction.
//!
//! Rationale (B.3b): docs/superpowers/specs/2026-05-05-ffi-b3b-create-vault-design.md
```

- [ ] **Step 6: Build the maturin wheel**

```bash
cd ffi/secretary-ffi-py
uv run maturin develop --release --uv 2>&1 | tail -10
cd ../..
```

Expected: `Finished` then `Built wheel ...` then `Installed secretary_ffi_py-0.1.0`. If the build fails with a compile error, the most likely culprits are:
- Missing import (`use pyo3::types::PyType` or similar — already imported in B.2)
- Field-access syntax on `#[pyclass]` (must use getter methods, not direct field access)
- Lifetime parameter on `&self, py: Python<'py>`

If pytest cache stickiness symptoms appear later (B.3a-era trap, see [ffi/secretary-ffi-py/README.md](../../ffi/secretary-ffi-py/README.md)), use the documented nuclear fix:

```bash
rm -rf ffi/secretary-ffi-py/.venv
find ~/.cache/uv -name "*secretary*" -exec rm -rf {} +
uv sync --directory ffi/secretary-ffi-py
```

- [ ] **Step 7: Smoke-test the new module attributes from the Python side**

```bash
uv run --directory ffi/secretary-ffi-py python -c "
import secretary_ffi_py as sec
print('create_vault:', hasattr(sec, 'create_vault'))
print('CreateVaultOutput:', hasattr(sec, 'CreateVaultOutput'))
print('MnemonicOutput:', hasattr(sec, 'MnemonicOutput'))
"
```

Expected: three lines all printing `True`.

- [ ] **Step 8: Run the existing pytest suite to make sure B.3a tests still pass**

```bash
uv run --directory ffi/secretary-ffi-py pytest 2>&1 | tail -3
```

Expected: `16 passed` (no count change yet — Task 5 adds the B.3b tests).

- [ ] **Step 9: Run cargo test on the secretary-ffi-py crate**

```bash
cargo test --release --package secretary-ffi-py 2>&1 | grep -E "^test result:|FAIL"
```

Expected: existing 3 unit tests pass.

- [ ] **Step 10: Verify clippy clean**

```bash
cargo clippy --release --package secretary-ffi-py -- -D warnings && echo "py clippy OK"
```

- [ ] **Step 11: Commit**

```bash
git add ffi/secretary-ffi-py/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(ffi-b3b): add PyO3 create_vault + 2 new opaque-handle types

Projects the bridge crate's create_vault free function through PyO3
as a Python-facing #[pyfunction]. Adds two new #[pyclass] newtypes:

- MnemonicOutput: one-shot opaque handle wrapping
  secretary_ffi_bridge::MnemonicOutput. take_phrase() returns bytes
  once, then None. close() (and __exit__) wipes idempotently.
  Implements __enter__/__exit__ for `with output.mnemonic as mn` idiom.

- CreateVaultOutput: four-field result type. Non-secret bytes via
  getters; identity and mnemonic via take-once getters that move
  ownership out of the parent #[pyclass]. The take-once pattern
  sidesteps PyO3's awkward parent-field-borrow lifetime issue with
  Python `with` semantics.

Wrapper-side Vec<u8> zeroize for the password input mirrors the B.2
password-input pattern. Updates ffi_unlock_error_to_pyerr is
unchanged from B.3a (the 5-variant error shape stays).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: pytest tests — 6 new B.3b tests

**Files:**
- Modify: `ffi/secretary-ffi-py/tests/test_smoke.py`

The tests share a module-scoped `created_vault` fixture for the read-only assertions; the take-phrase-consuming tests need their own fresh `create_vault` invocation since the fixture's mnemonic is one-shot.

- [ ] **Step 1: Add the module-scoped fixture**

Open `ffi/secretary-ffi-py/tests/test_smoke.py`. Near the top (after imports + existing `_read_fixture` helper), add:

```python
import time


@pytest.fixture(scope="module")
def created_vault():
    """Single create_vault invocation reused across read-only B.3b tests
    in this module. Cost: ~1s for V1_DEFAULT Argon2id.

    Tests that consume the one-shot mnemonic use their own fresh
    invocation; the fixture's mnemonic stays untouched so multiple
    read-only tests can share the same identity handle.
    """
    return secretary_ffi_py.create_vault(
        password=b"test-fixture-password",
        display_name="Owner",
        created_at_ms=42_000,
    )
```

(The `import time` is at top-level near other stdlib imports; the fixture goes below `_read_fixture` for proximity to other test scaffolding.)

- [ ] **Step 2: Add the 6 new pytest tests**

Append to the bottom of `test_smoke.py` after the existing B.3a tests:

```python
# ---------------------------------------------------------------------------
# B.3b: create_vault tests against an in-process freshly-built vault.
# Bridge hardcodes OsRng + Argon2idParams::V1_DEFAULT, so each invocation
# costs ~1s (real Argon2id at 256 MiB / 3 iterations / 1 thread).
# ---------------------------------------------------------------------------


def test_create_vault_returns_artifacts_with_expected_shape(created_vault) -> None:
    """The four CreateVaultOutput fields exist and carry the expected
    types: bytes for the on-disk artifacts; opaque handles for the
    identity and mnemonic. Uses the module-scoped fixture (no extra
    Argon2id cost)."""
    assert isinstance(created_vault.vault_toml_bytes, bytes)
    assert len(created_vault.vault_toml_bytes) > 0
    assert isinstance(created_vault.identity_bundle_bytes, bytes)
    assert len(created_vault.identity_bundle_bytes) > 0
    # The identity and mnemonic getters take ownership; assert their types
    # without consuming both — split into separate tests below (which use
    # fresh invocations to avoid clobbering the fixture).


def test_create_vault_identity_is_immediately_live() -> None:
    """The identity returned from create_vault is ready for vault
    operations without a second open_with_password call. Uses a fresh
    invocation since `identity` is take-once."""
    out = secretary_ffi_py.create_vault(
        password=b"x",
        display_name="ImmediateLive",
        created_at_ms=0,
    )
    with out.identity as identity:
        assert identity.display_name() == "ImmediateLive"
    out.mnemonic.close()


def test_create_vault_mnemonic_take_returns_24_words() -> None:
    """The recovery mnemonic exits the FFI as 24 space-separated UTF-8
    words. Pin the contract on the byte shape; the BIP-39 wordlist
    membership is core's responsibility (already covered by core tests)."""
    out = secretary_ffi_py.create_vault(
        password=b"x",
        display_name="X",
        created_at_ms=0,
    )
    with out.mnemonic as mn:
        phrase = mn.take_phrase()
        assert phrase is not None, "first call must return bytes"
        assert isinstance(phrase, bytes)
        assert len(phrase.split(b" ")) == 24, f"expected 24 words, got: {phrase!r}"
    out.identity.close()


def test_create_vault_mnemonic_take_is_one_shot() -> None:
    """Second take_phrase call returns None — documented one-shot
    semantics."""
    out = secretary_ffi_py.create_vault(
        password=b"x",
        display_name="X",
        created_at_ms=0,
    )
    with out.mnemonic as mn:
        first = mn.take_phrase()
        second = mn.take_phrase()
        assert first is not None
        assert second is None, "second take_phrase must return None"
    out.identity.close()


def test_create_vault_round_trip_with_password() -> None:
    """The vault bytes produced by create_vault re-open with the same
    password and yield the same display_name. Pins the dual-KEK
    convergence point: the bridge's create_vault and open_with_password
    agree on identity bytes."""
    pw = b"my-round-trip-password"
    out = secretary_ffi_py.create_vault(
        password=pw,
        display_name="RoundTripBob",
        created_at_ms=42_000,
    )
    out.mnemonic.close()  # not exercising the recovery path here
    with secretary_ffi_py.open_with_password(
        out.vault_toml_bytes,
        out.identity_bundle_bytes,
        pw,
    ) as id2:
        assert id2.display_name() == "RoundTripBob"
    out.identity.close()


def test_create_vault_round_trip_with_recovery() -> None:
    """The vault bytes produced by create_vault re-open via the recovery
    path using the just-taken mnemonic. Pins the create→take→open
    pipeline end-to-end."""
    out = secretary_ffi_py.create_vault(
        password=b"unused",
        display_name="RoundTripCarol",
        created_at_ms=42_000,
    )
    with out.mnemonic as mn:
        phrase = mn.take_phrase()
        assert phrase is not None
        with secretary_ffi_py.open_with_recovery(
            out.vault_toml_bytes,
            out.identity_bundle_bytes,
            phrase,
        ) as id2:
            assert id2.display_name() == "RoundTripCarol"
    out.identity.close()
```

- [ ] **Step 3: Run pytest**

```bash
uv run --directory ffi/secretary-ffi-py pytest 2>&1 | tail -10
```

Expected: `22 passed` (was 16; +6). The new tests' total wall-clock cost is ~7s (one shared fixture create + 5 fresh creates + 2 round-trip opens). pytest goes from ~0.5s to ~7-8s. If any test fails, the most likely causes are:
- The `with output.mnemonic as mn` pattern — verify the `__enter__`/`__exit__` methods got registered on `MnemonicOutput`'s `#[pymethods]` block.
- The take-once `identity` / `mnemonic` getters — verify the getter implementation moves the field out of the parent.
- Cache stickiness from Task 4 — apply the documented nuclear fix (see Task 4 Step 6 note).

- [ ] **Step 4: Commit**

```bash
git add ffi/secretary-ffi-py/tests/test_smoke.py
git commit -m "$(cat <<'EOF'
test(ffi-b3b): add 6 pytest tests for create_vault

Six new tests pin the foreign-language surface for the create path:
shape assertion (4 expected fields with expected types), immediately-
live identity (no second open_with_password call), 24-word mnemonic
shape, one-shot take_phrase semantics, round-trip with password,
round-trip with recovery.

Module-scoped `created_vault` fixture amortizes one Argon2id cost
across the read-only tests; the take-phrase-consuming tests use fresh
invocations because the mnemonic is one-shot per CreateVaultOutput
instance.

Total added wall-clock: ~7s (one shared fixture + 5 fresh creates
+ 2 round-trip opens at V1_DEFAULT Argon2id). Pytest goes from
0.5s to ~8s. Acceptable cost; documented in the spec rationale.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Phase 3 — secretary-ffi-uniffi projection

### Task 6: UDL + Rust glue — 1 dictionary, 1 interface, 1 namespace fn

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/src/secretary.udl`
- Modify: `ffi/secretary-ffi-uniffi/src/lib.rs`

- [ ] **Step 1: Update the UDL surface**

Open `ffi/secretary-ffi-uniffi/src/secretary.udl`. After the existing `interface UnlockedIdentity { ... }` block, add the new `MnemonicOutput` interface and `CreateVaultOutput` dictionary:

```idl
/// One-shot opaque handle for the freshly-generated 24-word BIP-39
/// recovery mnemonic. Exits the Sensitive<...> boundary as caller-owned
/// bytes via take_phrase(); second call returns null (one-shot
/// semantics). wipe() is idempotent.
///
/// Same close → wipe rename rationale as UnlockedIdentity (uniffi 0.31's
/// auto-generated AutoCloseable.close() collides with a UDL-declared
/// close()).
interface MnemonicOutput {
    /// Take the recovery phrase as UTF-8 bytes. ONE-SHOT — second call
    /// returns null. The returned bytes are caller-owned heap; the
    /// caller is responsible for zeroizing them after use.
    sequence<u8>? take_phrase();

    /// Drop any still-resident inner mnemonic now, zeroizing its
    /// Sensitive<...> fields. Idempotent.
    void wipe();
};

/// Output of create_vault. Holds the on-disk byte artifacts plus two
/// opaque handles for the live identity and the one-shot recovery
/// mnemonic. Dictionary (struct-by-value) because all four fields are
/// either values (bytes) or interface-typed (opaque handles).
dictionary CreateVaultOutput {
    /// Vault metadata bytes — non-secret. Persist atomically.
    bytes vault_toml_bytes;
    /// Encrypted identity bundle bytes — non-secret. Persist atomically.
    bytes identity_bundle_bytes;
    /// Live opaque handle to the just-created identity. Ready for vault
    /// operations immediately; no second open_with_password call needed.
    UnlockedIdentity identity;
    /// One-shot opaque handle for the recovery phrase.
    MnemonicOutput mnemonic;
};
```

Inside the `namespace secretary { ... }` block, after the existing `open_with_recovery` declaration, add:

```idl
    /// Create a fresh v1 vault using the OS CSPRNG and
    /// Argon2idParams::V1_DEFAULT (no foreign-side knobs). (B.3b)
    [Throws=UnlockError]
    CreateVaultOutput create_vault(
        bytes password,
        string display_name,
        u64 created_at_ms
    );
```

- [ ] **Step 2: Add the uniffi-side `MnemonicOutput` wrapper struct**

Open `ffi/secretary-ffi-uniffi/src/lib.rs`. After the existing `UnlockedIdentity` wrapper struct + impl block, add:

```rust
/// uniffi-side opaque-handle wrapper around
/// `secretary_ffi_bridge::MnemonicOutput`. Newtype; methods are thin
/// forwarders.
pub struct MnemonicOutput(secretary_ffi_bridge::MnemonicOutput);

impl MnemonicOutput {
    pub fn take_phrase(&self) -> Option<Vec<u8>> {
        self.0.take_phrase()
    }

    pub fn wipe(&self) {
        self.0.wipe();
    }
}
```

(uniffi 0.31's UDL-driven scaffolding wires the trait impls automatically; no `#[uniffi::export]` macros required because the UDL declaration drives everything via `build.rs`'s scaffolding generation.)

- [ ] **Step 3: Add the uniffi-side `CreateVaultOutput` dictionary**

Append to the same file after the `MnemonicOutput` block:

```rust
/// uniffi-side dictionary (struct-by-value) for create_vault's return
/// shape. Two `Vec<u8>` (non-secret) plus two `Arc<Interface>` (uniffi
/// marshals interface-typed dictionary fields as Arc handles).
pub struct CreateVaultOutput {
    pub vault_toml_bytes: Vec<u8>,
    pub identity_bundle_bytes: Vec<u8>,
    pub identity: std::sync::Arc<UnlockedIdentity>,
    pub mnemonic: std::sync::Arc<MnemonicOutput>,
}
```

(uniffi marshals `interface`-typed fields inside dictionaries as `Arc<T>` because the Foreign-side caller holds a refcount via the interface handle; the dictionary is value-type at the marshalling layer.)

- [ ] **Step 4: Add the `create_vault` `pub fn`**

After the existing `open_with_recovery` `pub fn` (around line 195), add:

```rust
/// Create a fresh v1 vault. uniffi-projected. (B.3b)
///
/// The bridge crate instantiates `OsRng` and
/// `Argon2idParams::V1_DEFAULT` internally; foreign callers cannot tune
/// either.
///
/// Returns a [`CreateVaultOutput`] containing on-disk byte artifacts and
/// two opaque handles ([`UnlockedIdentity`] and [`MnemonicOutput`]).
///
/// # Errors
///
/// Returns [`UnlockError`] on failure. See the bridge crate's
/// [`FfiUnlockError`](secretary_ffi_bridge::FfiUnlockError) docs for the
/// thinned 5-variant rationale.
pub fn create_vault(
    mut password: Vec<u8>,
    display_name: String,
    created_at_ms: u64,
) -> Result<CreateVaultOutput, UnlockError> {
    use zeroize::Zeroize;
    // Mirrors the open_with_password / open_with_recovery wrapper-side
    // stack-residue discipline: zero the password Vec after the bridge
    // returns. The bridge takes &[u8] and never retains; this Vec is the
    // projection-side transient.
    let result = secretary_ffi_bridge::create_vault(&password, &display_name, created_at_ms);
    password.zeroize();

    let bridge_out = result.map_err(UnlockError::from)?;

    let secretary_ffi_bridge::CreateVaultOutput {
        vault_toml_bytes,
        identity_bundle_bytes,
        identity,
        mnemonic,
    } = bridge_out;

    Ok(CreateVaultOutput {
        vault_toml_bytes,
        identity_bundle_bytes,
        identity: std::sync::Arc::new(UnlockedIdentity(identity)),
        mnemonic: std::sync::Arc::new(MnemonicOutput(mnemonic)),
    })
}
```

- [ ] **Step 5: Update the crate-level doc comment**

The existing doc ends with the B.3a rationale line. Append:

```rust
//!
//! B.3b adds the `create_vault` namespace function and 2 new opaque-
//! handle types (`CreateVaultOutput` dictionary, `MnemonicOutput`
//! interface). Bridge instantiates `OsRng` and
//! `Argon2idParams::V1_DEFAULT` internally; foreign callers get
//! neither knob. Recovery mnemonic crosses back via
//! `MnemonicOutput.take_phrase()` as `sequence<u8>?` (one-shot;
//! second call returns null).
//!
//! Rationale (B.3b): docs/superpowers/specs/2026-05-05-ffi-b3b-create-vault-design.md
```

- [ ] **Step 6: Add 2 new mapping-or-shape tests in the existing `mod tests`**

The existing `mod tests` block in `lib.rs` has tests like `from_bridge_corrupt_vault_preserves_detail`. Add:

```rust
#[test]
fn create_vault_returns_live_identity_and_mnemonic() {
    // Slow test: real Argon2id. ~1s. Sole uniffi-layer integration test
    // for create_vault; the bridge crate already covers MnemonicOutput
    // contract semantics in isolation.
    let out = create_vault(
        b"hunter2".to_vec(),
        "UniffiTest".to_string(),
        1_700_000_000_000,
    )
    .expect("create_vault should succeed");
    assert_eq!(out.identity.display_name(), "UniffiTest");
    assert_eq!(out.identity.user_uuid().len(), 16);
    assert!(!out.vault_toml_bytes.is_empty());
    assert!(!out.identity_bundle_bytes.is_empty());

    let phrase = out.mnemonic.take_phrase().expect("phrase available");
    assert_eq!(
        phrase.split(|&b| b == b' ').count(),
        24,
        "expected 24-word phrase",
    );

    let second = out.mnemonic.take_phrase();
    assert!(second.is_none(), "second take_phrase must return None");
}

#[test]
fn mnemonic_output_wipe_is_idempotent_through_uniffi_wrapper() {
    // Fast test: synthesize a MnemonicOutput from a seeded mnemonic
    // generation. No Argon2id; checks the wrapper plumbing only.
    use secretary_core::unlock::mnemonic;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let m = mnemonic::generate(&mut rng);
    let bridge_mo = secretary_ffi_bridge::MnemonicOutput::new_for_test(m);
    let mo = MnemonicOutput(bridge_mo);
    mo.wipe();
    mo.wipe(); // must not panic
    assert!(mo.take_phrase().is_none());
}
```

(The second test calls `MnemonicOutput::new_for_test` — a small `pub(crate)` constructor we need to add. See Step 7.)

- [ ] **Step 7: Add a `pub(crate) fn new_for_test` on the bridge's `MnemonicOutput`**

The bridge's `MnemonicOutput::new` is `pub(crate)`, which works for in-crate construction inside `create.rs`'s `mod tests`. But the uniffi crate needs to construct one for its own tests. Open `ffi/secretary-ffi-bridge/src/create.rs` and find the `pub(crate) fn new` on `MnemonicOutput`. Promote a sibling `#[cfg(any(test, feature = "test-utils"))]`-gated constructor to test-only `pub`:

Wait — the simpler answer is to add a `#[doc(hidden)] pub fn new_for_test` that's marked as test-only. Add this method to the existing `impl MnemonicOutput`:

```rust
    /// Test-only constructor. Crate-public so the sibling
    /// secretary-ffi-uniffi crate's mod tests can build a wrapper without
    /// invoking the slow create_vault path. Hidden from rustdoc; not part
    /// of the supported public API.
    #[doc(hidden)]
    pub fn new_for_test(m: Mnemonic) -> Self {
        Self::new(m)
    }
```

(Place it inside `impl MnemonicOutput { ... }` after the existing `pub(crate) fn new`.)

This adds one line + signature to the bridge crate's API surface, marked `#[doc(hidden)]` so it doesn't appear in user-facing rustdoc. The alternative — a Cargo feature flag — would be heavier infrastructure for one helper.

After adding, re-run bridge tests to confirm nothing broke:

```bash
cargo test --release --package secretary-ffi-bridge --lib 2>&1 | grep -E "^test result:"
```

Expected: still `36 passed; 0 failed` (no test count change; just one new helper method that doesn't have its own test).

Update the same commit boundary: amend the bridge crate change into the uniffi-side commit OR include both files in the Task 6 commit. Cleaner to land them together since they're logically one change ("uniffi-side projection of B.3b"); include both in Task 6's commit.

- [ ] **Step 8: Build the secretary-ffi-uniffi crate to surface compile errors**

```bash
cargo build --release --package secretary-ffi-uniffi 2>&1 | tail -10
```

Expected: `Finished` (no errors). uniffi's UDL-driven scaffolding regenerates from the new `secretary.udl`. If it errors, the most likely culprit is a UDL-Rust mismatch — verify field names match exactly between the UDL `dictionary CreateVaultOutput` and the Rust `pub struct CreateVaultOutput`.

- [ ] **Step 9: Run unit tests for the secretary-ffi-uniffi crate**

```bash
cargo test --release --package secretary-ffi-uniffi 2>&1 | grep -E "^test result:"
```

Expected: `test result: ok. 10 passed; 0 failed` (was 8 in B.3a; +2 new tests). One of the new tests runs real Argon2id (~1s); total wall-clock for the package goes from ~2s to ~3s.

- [ ] **Step 10: Verify clippy + fmt clean**

```bash
cargo clippy --release --package secretary-ffi-uniffi -- -D warnings && echo "uniffi clippy OK"
cargo clippy --release --package secretary-ffi-bridge -- -D warnings && echo "bridge clippy OK"
cargo fmt --all -- --check && echo "fmt OK"
```

- [ ] **Step 11: Commit**

```bash
git add ffi/secretary-ffi-uniffi/src/secretary.udl ffi/secretary-ffi-uniffi/src/lib.rs ffi/secretary-ffi-bridge/src/create.rs
git commit -m "$(cat <<'EOF'
feat(ffi-b3b): add uniffi create_vault + 2 new opaque-handle types

UDL gains:
- 1 new namespace function: create_vault(bytes, string, u64) -> CreateVaultOutput
- 1 new dictionary: CreateVaultOutput (4 fields)
- 1 new interface: MnemonicOutput (take_phrase() -> sequence<u8>?, wipe())

uniffi-side Rust glue mirrors the bridge's shape exactly:
- MnemonicOutput newtype around secretary_ffi_bridge::MnemonicOutput
- CreateVaultOutput struct with Arc<Interface>-typed identity + mnemonic
  fields (uniffi marshals interface-typed dictionary fields as Arc)

Wrapper-side Vec<u8> zeroize for the password input mirrors B.2 / B.3a.
The bridge's MnemonicOutput grows a #[doc(hidden)] pub fn new_for_test
so the uniffi crate's mod tests can synthesize a handle without paying
the create_vault Argon2id cost.

Two new uniffi-side tests:
- create_vault_returns_live_identity_and_mnemonic (slow; real Argon2id)
- mnemonic_output_wipe_is_idempotent_through_uniffi_wrapper (fast)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: Swift + Kotlin smoke runners — 3 new asserts each

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/tests/swift/main.swift`
- Modify: `ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt`

- [ ] **Step 1: Add 3 Swift asserts after the existing assertion 12**

Open `ffi/secretary-ffi-uniffi/tests/swift/main.swift`. Append after the closing `}` of assertion 12 (around line 230, before the `if !failures.isEmpty` block):

```swift
// --- B.3b: create_vault assertions ---

// Assertion 13: create_vault produces a CreateVaultOutput with the
// expected shape — non-empty bytes for both on-disk artifacts, the
// identity is immediately live with the display_name we passed.
do {
    let out = try createVault(
        password: Array("smoke-runner-password".utf8),
        displayName: "Owner",
        createdAtMs: 1_700_000_000_000
    )
    defer { out.identity.wipe() }
    defer { out.mnemonic.wipe() }
    let displayName = out.identity.displayName()
    let tomlNonEmpty = !out.vaultTomlBytes.isEmpty
    let bundleNonEmpty = !out.identityBundleBytes.isEmpty
    check(
        displayName == "Owner" && tomlNonEmpty && bundleNonEmpty,
        "create_vault shape: displayName=\"\(displayName)\" tomlBytes=\(out.vaultTomlBytes.count) bundleBytes=\(out.identityBundleBytes.count)"
    )
} catch {
    check(false, "create_vault threw \(error), expected to succeed")
}

// Assertion 14: round-trip with password — the vault bytes produced by
// create_vault re-open with the same password and yield the same
// display_name. Pins the create→open agreement.
do {
    let pw: [UInt8] = Array("round-trip-password".utf8)
    let out = try createVault(
        password: pw,
        displayName: "RoundTripBob",
        createdAtMs: 1_700_000_000_000
    )
    defer { out.identity.wipe() }
    out.mnemonic.wipe()  // not used in this path
    let reopened = try openWithPassword(
        vaultTomlBytes: out.vaultTomlBytes,
        identityBundleBytes: out.identityBundleBytes,
        password: pw
    )
    defer { reopened.wipe() }
    check(
        reopened.displayName() == "RoundTripBob",
        "create→open_with_password round-trip: got displayName=\"\(reopened.displayName())\""
    )
} catch {
    check(false, "round-trip with password threw \(error), expected to succeed")
}

// Assertion 15: round-trip with recovery — take the phrase, re-open via
// the recovery path. Pins create→take→open end-to-end.
do {
    let out = try createVault(
        password: Array("unused".utf8),
        displayName: "RoundTripCarol",
        createdAtMs: 1_700_000_000_000
    )
    defer { out.identity.wipe() }
    if let phrase = out.mnemonic.takePhrase() {
        let reopened = try openWithRecovery(
            vaultTomlBytes: out.vaultTomlBytes,
            identityBundleBytes: out.identityBundleBytes,
            mnemonic: phrase
        )
        defer { reopened.wipe() }
        check(
            reopened.displayName() == "RoundTripCarol",
            "create→take_phrase→open_with_recovery: got displayName=\"\(reopened.displayName())\""
        )
    } else {
        check(false, "take_phrase returned nil on first call")
    }
    out.mnemonic.wipe()
} catch {
    check(false, "round-trip with recovery threw \(error), expected to succeed")
}
```

- [ ] **Step 2: Update the Swift assertion-count constant**

Locate the failure-summary line (search for `of 12 assertion`):

```swift
if !failures.isEmpty {
    FileHandle.standardError.write(
        Data("FAIL: \(failures.count) of 12 assertion(s) failed\n".utf8)
    )
    exit(1)
}
```

Change `12` to `15`.

- [ ] **Step 3: Run the Swift smoke runner**

```bash
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh 2>&1 | tail -10
```

Expected: 15 PASS lines, then `OK: secretary uniffi Swift smoke runner — all assertions passed.` Wall-clock cost increases by ~3-5s due to real Argon2id × 3 creates × ~1s + ~1s for two opens.

- [ ] **Step 4: Add 3 Kotlin asserts after the existing assertion 12**

Open `ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt`. Append inside `fun main()` after the existing assertion 12 block (before the `if (failures.isNotEmpty())` block):

```kotlin
    // --- B.3b: create_vault assertions ---

    // Assertion 13: create_vault produces a CreateVaultOutput with the
    // expected shape.
    try {
        val out = createVault(
            password = "smoke-runner-password".toByteArray(Charsets.UTF_8),
            displayName = "Owner",
            createdAtMs = 1_700_000_000_000UL.toLong(),
        )
        out.mnemonic.use { /* immediately wipe */ }
        out.identity.use { id ->
            val displayName = id.displayName()
            val tomlNonEmpty = out.vaultTomlBytes.isNotEmpty()
            val bundleNonEmpty = out.identityBundleBytes.isNotEmpty()
            check(
                displayName == "Owner" && tomlNonEmpty && bundleNonEmpty,
                "create_vault shape: displayName=\"$displayName\" tomlBytes=${out.vaultTomlBytes.size} bundleBytes=${out.identityBundleBytes.size}",
            )
        }
    } catch (e: Throwable) {
        check(false, "create_vault threw $e, expected to succeed")
    }

    // Assertion 14: round-trip with password.
    try {
        val pw = "round-trip-password".toByteArray(Charsets.UTF_8)
        val out = createVault(
            password = pw,
            displayName = "RoundTripBob",
            createdAtMs = 1_700_000_000_000L,
        )
        out.mnemonic.use { /* not used in this path */ }
        out.identity.use { _ ->
            openWithPassword(
                vaultTomlBytes = out.vaultTomlBytes,
                identityBundleBytes = out.identityBundleBytes,
                password = pw,
            ).use { reopened ->
                check(
                    reopened.displayName() == "RoundTripBob",
                    "create→open_with_password round-trip: got displayName=\"${reopened.displayName()}\"",
                )
            }
        }
    } catch (e: Throwable) {
        check(false, "round-trip with password threw $e, expected to succeed")
    }

    // Assertion 15: round-trip with recovery.
    try {
        val out = createVault(
            password = "unused".toByteArray(Charsets.UTF_8),
            displayName = "RoundTripCarol",
            createdAtMs = 1_700_000_000_000L,
        )
        out.identity.use { _ ->
            out.mnemonic.use { mn ->
                val phrase = mn.takePhrase()
                check(phrase != null, "take_phrase returned null on first call")
                if (phrase != null) {
                    openWithRecovery(
                        vaultTomlBytes = out.vaultTomlBytes,
                        identityBundleBytes = out.identityBundleBytes,
                        mnemonic = phrase,
                    ).use { reopened ->
                        check(
                            reopened.displayName() == "RoundTripCarol",
                            "create→take_phrase→open_with_recovery: got displayName=\"${reopened.displayName()}\"",
                        )
                    }
                }
            }
        }
    } catch (e: Throwable) {
        check(false, "round-trip with recovery threw $e, expected to succeed")
    }
```

(Note: the Kotlin idiom for the dictionary's interface-typed fields differs slightly from Swift because uniffi 0.31's Kotlin codegen produces the dictionary's interface fields as already-Arc-wrapped, AutoCloseable instances; `out.identity.use { ... }` works directly. The Swift codegen produces the same shape but without the AutoCloseable trait, so `defer { out.identity.wipe() }` is the equivalent.)

- [ ] **Step 5: Update the Kotlin assertion-count constant**

Locate (search for `of 12 assertion`):

```kotlin
    if (failures.isNotEmpty()) {
        System.err.println("FAIL: ${failures.size} of 12 assertion(s) failed")
        exitProcess(1)
    }
```

Change `12` to `15`.

- [ ] **Step 6: Add the createVault import to the Kotlin import block**

Top of file, alongside `import uniffi.secretary.openWithRecovery`:

```kotlin
import uniffi.secretary.createVault
```

- [ ] **Step 7: Run the Kotlin smoke runner**

```bash
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh 2>&1 | tail -10
```

Expected: 15 PASS lines, then `OK: secretary uniffi Kotlin smoke runner — all assertions passed.` Wall-clock increases by ~3-5s from the real Argon2id costs.

- [ ] **Step 8: Commit**

```bash
git add ffi/secretary-ffi-uniffi/tests/swift/main.swift ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt
git commit -m "$(cat <<'EOF'
test(ffi-b3b): Swift + Kotlin smoke runners exercise create_vault

Three new asserts each pin the foreign-language surface for the create
path:
- shape (displayName preserved + non-empty byte artifacts)
- round-trip with password (create→open_with_password agree)
- round-trip with recovery (create→take_phrase→open_with_recovery)

Both runners use the same real-Argon2id-cost discipline as the bridge
+ pytest tests; total wall-clock per runner increases by ~3-5s.
Failure-summary assertion counts updated 12 → 15 in both runners.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Phase 4 — Docs + finalize

### Task 8: READMEs (bridge, py, uniffi) + top-level README + ROADMAP

**Files:**
- Modify: `ffi/secretary-ffi-bridge/README.md`
- Modify: `ffi/secretary-ffi-py/README.md`
- Modify: `ffi/secretary-ffi-uniffi/README.md`
- Modify: `README.md` (root)
- Modify: `ROADMAP.md`

- [ ] **Step 1: Append a B.3b section to `ffi/secretary-ffi-bridge/README.md`**

Open the file and find the existing "B.3a" section. Append a parallel B.3b section after it:

```markdown
## B.3b — Vault creation

Adds `create_vault` to the bridge surface — the third `pub fn` entry
point and the first that produces secret material in the **output**
direction.

```rust
pub fn create_vault(
    password: &[u8],
    display_name: &str,
    created_at_ms: u64,
) -> Result<CreateVaultOutput, FfiUnlockError>;
```

Bridge instantiates `OsRng` and `Argon2idParams::V1_DEFAULT` internally;
foreign callers cannot tune either knob. With `V1_DEFAULT` hardcoded,
`core::UnlockError::WeakKdfParams` is structurally unreachable through
this surface — the existing defensive fold-into-`CorruptVault` mapping
remains for forward-compat.

The return shape is a 4-field `CreateVaultOutput`:

| Field | Type | Direction |
|---|---|---|
| `vault_toml_bytes` | `Vec<u8>` | non-secret bytes; caller persists atomically |
| `identity_bundle_bytes` | `Vec<u8>` | non-secret bytes; caller persists atomically |
| `identity` | `UnlockedIdentity` | live opaque handle, ready for vault ops |
| `mnemonic` | `MnemonicOutput` | one-shot opaque handle for recovery phrase |

`MnemonicOutput` is a new opaque-handle type with one-shot
`take_phrase() -> Option<Vec<u8>>` and idempotent `wipe()`. The phrase
exits the `Sensitive<T>` boundary as caller-owned heap-allocated bytes;
callers MUST zeroize their copy after use (matches the input-side
caller-zeroize discipline of B.2 / B.3a, inverted in direction). Second
`take_phrase()` call returns `None` (one-shot semantics, NOT an error).

`CorruptVault`'s Display text was tweaked from `"vault is corrupt or
unreadable: {detail}"` to the path-neutral `"vault data integrity
failure: {detail}"` so the variant reads correctly on both the open
path and the new create path. Variant name and shape unchanged; the
5-variant cardinality from B.3a is structurally intact.
```

- [ ] **Step 2: Append a B.3b section to `ffi/secretary-ffi-py/README.md`**

Find the existing "Vault unlock — recovery path (B.3a)" section. Append after it:

```markdown
### Vault creation (B.3b)

```python
import secretary_ffi_py as sec
import time

output = sec.create_vault(
    password=b"my-strong-password",
    display_name="Owner",
    created_at_ms=int(time.time() * 1000),
)

# Read the recovery phrase ONCE. Display to user, then zeroize the buffer.
with output.mnemonic as mn:
    phrase = bytearray(mn.take_phrase())  # one-shot; second call returns None
    show_recovery_phrase_to_user(phrase)
    for i in range(len(phrase)):
        phrase[i] = 0   # caller-side zeroize discipline

# Persist the byte artifacts atomically. Caller's responsibility.
write_atomic(vault_dir / "vault.toml", output.vault_toml_bytes)
write_atomic(vault_dir / "identity.bundle.enc", output.identity_bundle_bytes)

# Use the live identity directly — no second open_with_password call needed.
with output.identity as identity:
    print(identity.display_name())
```

Two new `#[pyclass]` types:

- `secretary_ffi_py.CreateVaultOutput` — the four-field result struct.
  `vault_toml_bytes` / `identity_bundle_bytes` are `bytes` (non-secret).
  `identity` and `mnemonic` are take-once getters that move ownership
  out of the parent struct.
- `secretary_ffi_py.MnemonicOutput` — one-shot opaque handle.
  `take_phrase()` returns `bytes` once, then `None`. `close()` (or
  `__exit__` via `with`) wipes idempotently.

The bridge instantiates `OsRng` and `Argon2idParams::V1_DEFAULT`
internally; foreign callers cannot tune either. Cost: ~1s per
`create_vault` call for real Argon2id at V1_DEFAULT (256 MiB / 3 iter).
```

- [ ] **Step 3: Append a B.3b section to `ffi/secretary-ffi-uniffi/README.md`**

Find the existing "Vault unlock — recovery path (B.3a)" section. Append after it:

```markdown
### Vault creation (B.3b)

**Swift:**

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
    // caller-side zeroize discipline — see spec for the language idiom
}

try Data(output.vaultTomlBytes).write(to: tomlURL, options: .atomic)
try Data(output.identityBundleBytes).write(to: bundleURL, options: .atomic)

print(output.identity.displayName())
```

**Kotlin:**

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

The bridge instantiates `OsRng` and `Argon2idParams::V1_DEFAULT`
internally; foreign callers cannot tune either knob. The recovery
mnemonic crosses the FFI as `sequence<u8>?` (one-shot via
`takePhrase()` — second call returns null). Caller is responsible for
zeroizing the returned bytes after use.
```

- [ ] **Step 4: Update top-level `README.md`**

Find the "Where we are" / status table block. Locate the line referencing the current sub-project status and update:

(a) Update the date marker to `2026-05-05` (or whatever date the implementation completes).
(b) Update the test-counts line — currently shows `489 + 9 ignored`; update to `~494 + 9 ignored` (use the actual final count from Task 9's verification).
(c) Advance the ASCII progress bar one segment toward "complete".

If the README has a "Sub-project B" entry-status table, advance B.3b from ⏳ → ✅:

```
| B.3b — `create_vault` through bridge / PyO3 / uniffi          | ✅ |
```

(d) Pytest count appears as `16` in the status block — update to `22`.
(e) Swift smoke `12` → `15`; Kotlin smoke `12` → `15`.

- [ ] **Step 5: Update `ROADMAP.md`**

Open `ROADMAP.md`, find the Sub-project B section, and flip B.3b's checkbox from ⏳ → ✅. Match B.3a's flip pattern. Add a one-line summary of what B.3b delivers.

- [ ] **Step 6: Verify all gates green after the doc edits**

Doc edits don't affect compilation, but run the gates anyway as a smoke test:

```bash
cargo test --release --workspace 2>&1 | grep -E "^test result:" > /tmp/cargo_t8.txt
python3 -c "
import re
p=f=i=0
for line in open('/tmp/cargo_t8.txt'):
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'TOTAL: {p} passed; {f} failed; {i} ignored')"
cargo clippy --release --workspace -- -D warnings && echo "clippy OK"
cargo fmt --all -- --check && echo "fmt OK"
uv run --directory ffi/secretary-ffi-py pytest 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh 2>&1 | tail -3
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3
```

Expected:
- `TOTAL: ~494 passed; 0 failed; 9 ignored` (the actual count is whatever it is — record for Task 9's NEXT_SESSION update).
- clippy + fmt OK.
- `22 passed` in pytest.
- `15 PASS` in Swift + Kotlin smoke runners (with `OK:` summary).
- conformance + freshness PASS.

If anything fails, STOP and triage before proceeding to Task 9.

- [ ] **Step 7: Commit**

```bash
git add ffi/secretary-ffi-bridge/README.md ffi/secretary-ffi-py/README.md ffi/secretary-ffi-uniffi/README.md README.md ROADMAP.md
git commit -m "$(cat <<'EOF'
docs(ffi-b3b): READMEs + top-level docs document vault creation path

Bridge crate README documents the new create_vault entry point,
CreateVaultOutput's four-field shape, MnemonicOutput's one-shot
take_phrase() semantics, and the path-neutral CorruptVault Display
text rationale.

PyO3 + uniffi crate READMEs document the new entry point with code
samples mirroring the B.2 / B.3a section structure: Python
with-statement + bytearray zeroize discipline; Swift defer-wipe pattern;
Kotlin .use { } via auto-AutoCloseable.

Top-level README progress bar advances; ROADMAP B.3b entry flipped
⏳ → ✅. Test-count baselines updated for the new gate counts (cargo
489 → ~494; pytest 16 → 22; Swift+Kotlin 12 → 15).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: NEXT_SESSION + handoff archive + final verification + push + open PR

**Files:**
- Modify: `NEXT_SESSION.md`
- Create: `docs/handoffs/2026-MM-DD-b3b-create-vault.md`

- [ ] **Step 1: Determine the handoff date**

```bash
date +"%Y-%m-%d"
```

Use that date in the `docs/handoffs/` filename.

- [ ] **Step 2: Capture the final test counts**

```bash
cargo test --release --workspace 2>&1 | grep -E "^test result:" > /tmp/cargo_final.txt
python3 -c "
import re
p=f=i=0
for line in open('/tmp/cargo_final.txt'):
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'cargo: {p} passed; {f} failed; {i} ignored')"

cargo test --release --package secretary-ffi-bridge 2>&1 | grep -E "^test result:" | head -3
echo "---"
uv run --directory ffi/secretary-ffi-py pytest 2>&1 | tail -3
echo "---"
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh 2>&1 | grep -E "^OK|FAIL" | tail -1
echo "---"
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh 2>&1 | grep -E "^OK|FAIL" | tail -1
```

Record these numbers — they go into the NEXT_SESSION.md verification table.

- [ ] **Step 3: Replace `NEXT_SESSION.md` with B.3b retrospective**

Use the structure below as a template; replace placeholders with actual values:

```markdown
# NEXT_SESSION.md

**Session date:** YYYY-MM-DD (Sub-project B.3b — vault creation through FFI)
**Status:** Sub-project B.3b complete; PR pending merge. The vault creation path is now exposed across PyO3 (Python) and uniffi (Swift / Kotlin) via the existing shared `secretary-ffi-bridge` crate. With B.3b done, the FFI surface contains every `secretary_core::unlock` v1 entry point: `open_with_password`, `open_with_recovery`, and `create_vault`. Subsequent FFI work addresses different concerns (vault operations on records, sharing primitives, public-key accessors).

## (1) What we shipped this session

| Task | Commit(s) | What landed |
|---|---|---|
| 1 — bridge error.rs Display tweak | `<sha>` | CorruptVault Display text path-neutral; +1 tripwire test; module-doc updated. |
| 2 — bridge create.rs | `<sha>` | New file with create_vault, CreateVaultOutput, MnemonicOutput; +5 tests (3 fast on MnemonicOutput contract, 2 slow round-trip through real V1_DEFAULT Argon2id). |
| 3 — bridge lib.rs | `<sha>` | Re-exports + crate-doc updated. |
| 4 — PyO3 wrapper | `<sha>` | #[pyfunction] create_vault; 2 new #[pyclass] (CreateVaultOutput with take-once getters, MnemonicOutput with __enter__/__exit__); wrapper-side Vec<u8> password zeroize. |
| 5 — pytest | `<sha>` | +6 tests (shape, immediately-live identity, 24-word mnemonic, one-shot take, round-trip × 2); module-scoped fixture amortizes one Argon2id cost. |
| 6 — UDL + uniffi glue | `<sha>` | UDL gains 1 dictionary + 1 interface + 1 namespace fn; uniffi-side wrapper structs; +2 mapping tests; bridge gains #[doc(hidden)] new_for_test helper. |
| 7 — Swift + Kotlin smoke | `<sha>` | +3 asserts each; failure-summary count updated 12 → 15 in both runners. |
| 8 — READMEs + ROADMAP | `<sha>` | Per-crate B.3b sections + top-level progress bar advance + ROADMAP B.3b flip. |
| 9 — NEXT_SESSION + handoff | `<this commit>` | This file + docs/handoffs/YYYY-MM-DD-b3b-create-vault.md. |

### Verification at session close

| Check | Result |
|---|---|
| `cargo test --release --workspace` | **<N> passed + 9 ignored** (was 489 at branch start; +<delta> from B.3b) |
| `cargo clippy --release --workspace -- -D warnings` | clean |
| `cargo fmt --all -- --check` | OK |
| `uv run --directory ffi/secretary-ffi-py pytest` | **22 passed** (was 16) |
| `uv run core/tests/python/conformance.py` | PASS |
| `uv run core/tests/python/spec_test_name_freshness.py` | PASS |
| `bash ffi/secretary-ffi-uniffi/tests/swift/run.sh` | **15/15 PASS** (was 12/12) |
| `bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` | **15/15 PASS** (was 12/12) |

## (2) What's next

With B.3b done, the v1 unlock-and-create FFI surface is complete. The
next logical work depends on user direction. Candidate sub-projects:

- **B.4: Record operations.** Expose vault read/write of `Record` types
  through the FFI. Brings in CRDT merge semantics, record-level
  encryption, and the user's actual secret-storage workflows.
- **B.5: Sharing primitives.** Public-key accessors + cross-vault
  encryption operations. Re-opens the deferred public-key-accessors
  non-goal from B.2 / B.3a / B.3b.
- **C: Sync orchestration.** Beyond client-only operations; involves
  the as-yet-undesigned sync layer.
- **D: Platform UIs.** Swift/Kotlin/Python desktop apps consuming the
  now-stable FFI.

Brainstorm needed for whichever sub-project is selected next.

## (3) Open decisions and risks

### Decisions made and load-bearing for future sub-projects

These are the B.3b decisions that constrain subsequent FFI work:

1. **Bridge crate stays the single source of FFI code truth.** Any new entry point lives there first.
2. **5-variant thinned error preserves §13 anti-oracle conflation.** B.3b kept the cardinality unchanged structurally; only the Display text on `CorruptVault` was tweaked to be path-neutral.
3. **Bytes-not-string at the FFI boundary for secret inputs and outputs.** B.3b extended this to outputs via `MnemonicOutput.take_phrase() -> Option<Vec<u8>>`. The caller-zeroize discipline is documented.
4. **Explicit close + RAII safety net stays in place.** Python `with`, Swift `defer`, Kotlin `.use {}`. Both `UnlockedIdentity` and `MnemonicOutput` follow this pattern.
5. **OsRng + V1_DEFAULT hardcoded for create paths.** No foreign-side knobs. Future entry points that need RNG or KDF tuning may revisit.

### Pre-existing technical debt

None outstanding from B.3b.

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git checkout main
git pull --ff-only

# Verify the post-merge state on main:
cargo test --release --workspace 2>&1 | grep -E "^test result:" | python3 -c "
import sys, re
p=f=i=0
for line in sys.stdin:
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'TOTAL: {p} passed; {f} failed; {i} ignored')"
cargo clippy --release --workspace -- -D warnings && echo "clippy OK"
cargo fmt --all -- --check && echo "fmt OK"

# Re-build the maturin dylib BEFORE pytest (the post-merge cache-stickiness
# trap is documented in ffi/secretary-ffi-py/README.md; the harsher remedy
# may be needed if simple maturin develop doesn't pick up new symbols).
( cd ffi/secretary-ffi-py && uv run maturin develop --release --uv )

uv run --directory ffi/secretary-ffi-py pytest
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh
```

---

## Closing inventory

- **Branch:** `feat/ffi-b3b-create-vault` (PR-pending; squash-merge target is `main`)
- **Total commits since branching from `main@ca20b9b`:** ~9 (1 Display tweak + 1 create.rs + 1 lib.rs + 2 PyO3 + 2 uniffi + 1 docs + 1 handoff). Will squash to 1 in the PR.
- **Workspace tests:** <N> + 9 ignored
- **Pytest:** 22 (16 from B.1 + B.2 + B.3a + 6 B.3b)
- **Swift smoke:** 15/15 (12 from prior + 3 B.3b)
- **Kotlin smoke:** 15/15 (12 from prior + 3 B.3b)
- **Bridge crate:** ~36 unit tests (was 30; +5 in create.rs, +1 in error.rs)
- **PR:** [#NN](https://github.com/hherb/secretary/pull/NN)
```

(Replace `<sha>`, `<N>`, `<delta>`, `<NN>`, and the dates with actual values when filling in.)

- [ ] **Step 4: Create the timestamped handoff archive**

```bash
cp NEXT_SESSION.md docs/handoffs/$(date +"%Y-%m-%d")-b3b-create-vault.md
```

- [ ] **Step 5: Run all gates one final time**

```bash
cargo test --release --workspace 2>&1 | grep -E "^test result:" > /tmp/cargo_final2.txt
python3 -c "
import re
p=f=i=0
for line in open('/tmp/cargo_final2.txt'):
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'TOTAL: {p} passed; {f} failed; {i} ignored')"
cargo clippy --release --workspace -- -D warnings && echo "clippy OK"
cargo fmt --all -- --check && echo "fmt OK"
( cd ffi/secretary-ffi-py && uv run maturin develop --release --uv 2>&1 | tail -3 )
uv run --directory ffi/secretary-ffi-py pytest 2>&1 | tail -3
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh 2>&1 | tail -3
```

Expected: all green. If any fail, STOP and triage before pushing.

- [ ] **Step 6: Commit the NEXT_SESSION + handoff archive**

```bash
git add NEXT_SESSION.md docs/handoffs/$(date +"%Y-%m-%d")-b3b-create-vault.md
git commit -m "$(cat <<'EOF'
docs(handoff): B.3b complete — record verification + completed v1 FFI surface

NEXT_SESSION.md updated with B.3b retrospective + forward-looking
content: with B.3b done, the v1 unlock-and-create FFI surface is
complete; next sub-project is user-selectable (record operations,
sharing primitives, sync orchestration, or platform UIs).
Timestamped handoff archive committed alongside on the feature branch
so post-merge main carries the correct baton.

All gates green at session close (cargo, clippy, fmt, pytest,
conformance, freshness, both smoke runners).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 7: Push the branch + open PR**

```bash
git push -u origin feat/ffi-b3b-create-vault
```

Then open a PR:

```bash
gh pr create --title "feat(ffi-b3b): expose create_vault through PyO3 + uniffi via shared bridge crate" --body "$(cat <<'EOF'
## Summary
- Adds `create_vault` to the bridge crate; bridge instantiates `OsRng` + `Argon2idParams::V1_DEFAULT` internally (no foreign-side knobs)
- Two new opaque-handle types: `CreateVaultOutput` (4-field result) and `MnemonicOutput` (one-shot recovery-phrase handle with `take_phrase() -> Option<Vec<u8>>` and idempotent `wipe()`); the freshly-generated 24-word mnemonic exits the `Sensitive<T>` boundary as caller-zeroize-discipline bytes
- `FfiUnlockError` 5-variant cardinality structurally unchanged; `CorruptVault` Display text tweaked to path-neutral `"vault data integrity failure: {detail}"`

## Test plan
- [x] `cargo test --release --workspace` green (was 489 + 9 ignored; +5)
- [x] `cargo clippy --release --workspace -- -D warnings` clean
- [x] `cargo fmt --all -- --check` OK
- [x] `uv run --directory ffi/secretary-ffi-py pytest` 22/22 (was 16)
- [x] `uv run core/tests/python/conformance.py` PASS
- [x] `uv run core/tests/python/spec_test_name_freshness.py` PASS
- [x] `bash ffi/secretary-ffi-uniffi/tests/swift/run.sh` 15/15 (was 12)
- [x] `bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` 15/15 (was 12)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 8: Record the PR URL in NEXT_SESSION + handoff archive**

```bash
# After capturing the PR URL from gh pr create's output, edit
# NEXT_SESSION.md and docs/handoffs/<date>-b3b-create-vault.md
# replacing the [#NN] placeholder with the actual PR number.

git add NEXT_SESSION.md docs/handoffs/*-b3b-create-vault.md
git commit -m "$(cat <<'EOF'
docs(handoff): record PR #<NN> URL in NEXT_SESSION + handoff archive

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"

git push
```

The PR is now ready for review. Subagent-driven-development workflow ends here; controller hands back to user for review/merge.

---

## Self-review checklist

After completing all 10 tasks (0 + 1-9), verify:

- [ ] All 10 commits on the feature branch (one per task, plus the optional PR-URL fix-up).
- [ ] No commits to `main` directly.
- [ ] Spec coverage: every section of the spec doc has a corresponding task.
- [ ] No placeholders (`TBD`, `TODO`, `FIXME`, `<paste here>`) remain in committed code.
- [ ] All gates green at the final commit before push.
- [ ] PR description references the spec doc.
- [ ] NEXT_SESSION.md and docs/handoffs/* live on the feature branch (NOT cherry-picked to main post-merge).
- [ ] `MnemonicOutput::new_for_test` is `#[doc(hidden)]` and gates only the uniffi crate's test usage.
