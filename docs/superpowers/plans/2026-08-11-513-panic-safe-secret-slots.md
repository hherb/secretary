# Panic- and error-safe secret slots — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every secret stack slot that is live across a fallible call wipe on *every* exit path — normal return, `?`, explicit `return Err`, and unwinding panic — by wrapping it in a `Drop`-wiping type instead of relying on a trailing `.zeroize()` statement that control flow can skip.

**Architecture:** Wrap first, don't fill-then-wipe. Two new constructors on the existing `Sensitive<T>` (`build`, `try_build`) let a slot be wrapped *before* it is filled, so the wrapper is live for the whole fill. Everywhere else the existing `SecretBytes` / `SecretString` wrappers already fit and simply were not being used. No new wrapper type, no `zeroize::Zeroizing`, no CI guard.

**Tech Stack:** Rust (stable, pinned 1.97.0), `zeroize =1.8.2`, `pyo3 0.29`, `uniffi 0.32`, `uv` for Python.

**Spec:** [`docs/superpowers/specs/2026-08-11-513-panic-safe-secret-slots-design.md`](../specs/2026-08-11-513-panic-safe-secret-slots-design.md). Read §1.2 (the three exit classes E1/E2/E3), §2.2 (why not `expose_mut`), and §3.3 (the confirmed census) before starting.

**Issues:** `#513` (panic path), `#518` (error paths — the two live leaks), `#503` (ffi-py's by-value `[u8; 32]` producer, still open; `#503` only ever fixed uniffi).

---

## Global Constraints

- **Working directory is the worktree**, not the main repo: `/Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots`. Shell state does not persist between tool calls — chain with `&&` or use absolute paths. Editing tools must be given the full worktree path; a bare `core/src/...` path targets the MAIN repo.
- `#![forbid(unsafe_code)]` is a workspace lint. Do not introduce `unsafe`.
- Clippy must stay clean: `cargo clippy --release --workspace --tests -- -D warnings` **and** without `--tests`.
- Rustdoc must stay clean: `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace`.
- Always build/test `--release`; the crypto crates are unusably slow in debug.
- **No on-disk format change, no FFI surface change.** `git diff main... -- ffi/secretary-ffi-uniffi/src/secretary.udl` must be **empty** at the end. No `FfiVaultError` variant or field changes. No KAT regeneration.
- **No behaviour change.** Every conversion is refactor-only: the same error variants, in the same precedence order, for the same inputs. Existing tests must pass unmodified. Where a test *must* change, that is a signal the conversion changed behaviour — stop and re-read.
- Tests use runtime-random crypto values (`OsRng` / `rand`), never hardcoded literal byte arrays — those trip CodeQL. KATs come from JSON fixtures only.
- Every commit ends with the trailer `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`.
- Reference issues as `(#513)` in commit subjects, never `Closes #513` — this repo's convention keeps issues open until manually closed.

---

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `core/src/crypto/secret.rs` | `Sensitive::build` / `try_build` — the only new API | 1 |
| `core/tests/secret_panic_safety.rs` *(new)* | The unwind-safety mechanism test | 1 |
| `core/src/crypto/kdf.rs` | 3 windowed KEK derivations | 3 |
| `core/src/crypto/kem.rs` | 1 windowed slot (`ikm`) | 3 |
| `core/src/unlock/mnemonic.rs` | `parse`'s #518 leak, `generate`'s window + the §3.4 missed wipe | 4 |
| `core/src/unlock/bundle.rs` | `from_canonical_cbor`'s #518 leak | 5 |
| `core/src/unlock/mod.rs` | `create_vault_unchecked`'s `bundle_plaintext` + `ibk` | 6 |
| `ffi/secretary-ffi-py/src/errors.rs` | `array32_or_value_error` → write-through (#503) | 7 |
| `ffi/secretary-ffi-py/src/{unlock,vault,device,repair,repair_preview,record}.rs` | 37 windowed sites | 8 |
| `ffi/secretary-ffi-uniffi/src/namespace/{mod,repair}.rs` | the 3 sites #513 names | 9 |
| `docs/manual/contributors/memory-hygiene-audit-internal.md` | census table + the corrected §3.4 claim | 10 |

---

## Task 1: `Sensitive::build` / `try_build`, and the unwind-safety proof

The whole slice rests on one premise: `Drop` runs when the stack unwinds. **Nothing in the tree demonstrates that today.** This task pins it before anything depends on it.

**Files:**
- Modify: `core/src/crypto/secret.rs` (add two constructors to the existing `impl<T: Zeroize> Sensitive<T>` block at lines 170-182)
- Create: `core/tests/secret_panic_safety.rs`

**Interfaces:**
- Produces:
  - `Sensitive::<T>::build(init: T, f: impl FnOnce(&mut T)) -> Sensitive<T>`
  - `Sensitive::<T>::try_build<E>(init: T, f: impl FnOnce(&mut T) -> Result<(), E>) -> Result<Sensitive<T>, E>`
  - Both are `pub`, both on `impl<T: Zeroize> Sensitive<T>`.

- [ ] **Step 1: Write the failing mechanism test**

Create `core/tests/secret_panic_safety.rs`. The test needs a witness that observes its own `Drop` during an unwind — a plain assertion after `catch_unwind` cannot see a dead stack frame, which is exactly the limit spec §5.4 records.

```rust
//! Proves the premise the #513 conversion rests on: a `Drop`-wiping wrapper
//! runs its destructor when the stack UNWINDS, not merely when a function
//! returns normally. Without this, every conversion in the slice is unfounded.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroize;

use secretary_core::crypto::secret::Sensitive;

static WITNESS_DROPPED: AtomicBool = AtomicBool::new(false);

/// A `Zeroize` payload that records whether it was zeroized. `Sensitive<T>`
/// is `ZeroizeOnDrop`, so its drop glue calls `zeroize()` on the inner value —
/// observing that call is how we prove the wipe happened during the unwind.
#[derive(Default)]
struct Witness {
    wiped: bool,
}

impl Zeroize for Witness {
    fn zeroize(&mut self) {
        self.wiped = true;
        WITNESS_DROPPED.store(true, Ordering::SeqCst);
    }
}

#[test]
fn sensitive_wipes_the_inner_value_when_the_stack_unwinds() {
    WITNESS_DROPPED.store(false, Ordering::SeqCst);

    let unwound = catch_unwind(AssertUnwindSafe(|| {
        let _secret = Sensitive::new(Witness::default());
        panic!("simulated panic inside a bridge call");
    }));

    assert!(unwound.is_err(), "the closure must actually have panicked");
    assert!(
        WITNESS_DROPPED.load(Ordering::SeqCst),
        "Sensitive's Drop must zeroize the inner value while the stack unwinds; \
         if this fails, the entire #513 conversion rests on a false premise"
    );
}

#[test]
fn try_build_wipes_when_the_fill_closure_panics() {
    WITNESS_DROPPED.store(false, Ordering::SeqCst);

    let unwound = catch_unwind(AssertUnwindSafe(|| {
        let _r: Result<Sensitive<Witness>, ()> =
            Sensitive::try_build(Witness::default(), |_slot| {
                panic!("simulated panic partway through filling the slot");
            });
    }));

    assert!(unwound.is_err(), "the fill closure must actually have panicked");
    assert!(
        WITNESS_DROPPED.load(Ordering::SeqCst),
        "try_build must wrap BEFORE filling, so a panic inside the fill still wipes"
    );
}

#[test]
fn try_build_wipes_when_the_fill_closure_returns_err() {
    WITNESS_DROPPED.store(false, Ordering::SeqCst);

    let r: Result<Sensitive<Witness>, &'static str> =
        Sensitive::try_build(Witness::default(), |_slot| Err("fill failed"));

    assert_eq!(r.err(), Some("fill failed"));
    assert!(
        WITNESS_DROPPED.load(Ordering::SeqCst),
        "the partially-filled slot must be wiped on the error path too"
    );
}

#[test]
fn build_runs_the_fill_and_the_writes_land() {
    let mut rng_bytes = [0u8; 32];
    getrandom_fill(&mut rng_bytes);

    let secret = Sensitive::build([0u8; 32], |slot| slot.copy_from_slice(&rng_bytes));

    assert_eq!(secret.expose(), &rng_bytes, "build's closure writes must reach the wrapped value");
}

#[test]
fn try_build_ok_path_returns_the_filled_value() {
    let mut rng_bytes = [0u8; 32];
    getrandom_fill(&mut rng_bytes);

    let secret: Sensitive<[u8; 32]> =
        Sensitive::try_build([0u8; 32], |slot| -> Result<(), ()> {
            slot.copy_from_slice(&rng_bytes);
            Ok(())
        })
        .expect("an Ok fill yields a Sensitive");

    assert_eq!(secret.expose(), &rng_bytes);
}

/// Runtime-random test bytes. Hardcoded literal key material trips CodeQL,
/// so tests in this repo always draw at runtime.
fn getrandom_fill(buf: &mut [u8; 32]) {
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(buf);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
  cargo test --release -p secretary-core --test secret_panic_safety 2>&1 | tail -30
```

Expected: compile FAILURE — `no function or associated item named 'build' found` and `... 'try_build' ...`.

If instead it fails on `use secretary_core::crypto::secret::Sensitive;` being private, check the module's re-export path with `grep -rn "pub mod secret\|pub use.*Sensitive" core/src/crypto/mod.rs core/src/lib.rs` and use whatever path the crate actually exposes. Do **not** widen visibility to make the test compile.

If `rand` is not a dev-dependency of `secretary-core`, add it to `[dev-dependencies]` in `core/Cargo.toml` (it is already in the dependency tree via the crypto crates; match the version already resolved in `Cargo.lock` rather than introducing a new one).

- [ ] **Step 3: Implement the two constructors**

In `core/src/crypto/secret.rs`, inside the existing `impl<T: Zeroize> Sensitive<T>` block, after `expose`:

```rust
    /// Build a secret by filling a zeroed slot **in place**.
    ///
    /// The wrapper is constructed *before* `f` runs, so the value is live —
    /// and therefore `ZeroizeOnDrop`-covered — for the whole fill. An
    /// unwinding panic inside `f` drops it and wipes.
    ///
    /// Prefer this over `let mut buf = …; fill(&mut buf); let s =
    /// Sensitive::new(buf); buf.zeroize();`, where the trailing wipe is a
    /// separate statement that a panic can skip (#513).
    ///
    /// # Security
    ///
    /// `f` receives `&mut T`. A closure that moves the secret out — e.g. via
    /// `std::mem::swap` or `std::mem::replace` — defeats the wipe, because
    /// the wrapper would then zeroize whatever was swapped in. This borrow is
    /// deliberately scoped to one expression at the call site rather than
    /// exposed as a method on the type; every closure written here is a
    /// review point. See the design spec §2.2.
    #[must_use]
    pub fn build(init: T, f: impl FnOnce(&mut T)) -> Self {
        let mut s = Self { inner: init };
        f(&mut s.inner);
        s
    }

    /// Fallible sibling of [`Sensitive::build`], for fills that can fail.
    ///
    /// On `Err`, the partially-filled wrapper is dropped — and wiped — before
    /// the error propagates, so an early `?` leaves no residue. Carries the
    /// same `&mut` caveat as [`Sensitive::build`].
    pub fn try_build<E>(init: T, f: impl FnOnce(&mut T) -> Result<(), E>) -> Result<Self, E> {
        let mut s = Self { inner: init };
        f(&mut s.inner)?;
        Ok(s)
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
  cargo test --release -p secretary-core --test secret_panic_safety 2>&1 | tail -20
```

Expected: `test result: ok. 5 passed`.

- [ ] **Step 5: Verify the new public API is rustdoc- and clippy-clean**

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
  cargo clippy --release --workspace --tests -- -D warnings && \
  RUSTDOCFLAGS="-D warnings" cargo doc --no-deps -p secretary-core
```

Both must be silent. `Sensitive` is public, so the doc comments above are subject to the `#92` intra-doc-link gate.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
git add core/src/crypto/secret.rs core/tests/secret_panic_safety.rs core/Cargo.toml && \
git commit -F - <<'MSG'
feat(core): Sensitive::build / try_build — wrap before filling (#513)

The trailing-`.zeroize()` idiom is correct only if control reaches the
wipe statement. `build`/`try_build` construct the wrapper FIRST and hand
the closure `&mut self.inner`, so the value is ZeroizeOnDrop-covered for
the whole fill: `?` and an unwinding panic both drop it and wipe.

Rejected `expose_mut(&mut self) -> &mut T`, which would expose the same
borrow permanently on every live Sensitive and thereby permit
`mem::swap(secret.expose_mut(), &mut plain)` to move a secret out in safe
code. A constructor confines the borrow to one reviewable expression per
call site. See the design spec §2.2.

The unwind test is the point of this commit as much as the constructors:
nothing in the tree demonstrated that Drop runs during an unwind, and
every conversion in this slice rests on it.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

## Task 2: Confirm the census tail

Spec §3.3 classifies most of `core/src` and flags a tail as *expected* adjacent without having read each one. Confirm, don't assume — this is the task that turns a prediction into a record.

**Files:**
- Create: `docs/superpowers/plans/2026-08-11-513-census.md` (working artifact; folded into the audit memo in Task 10)

**Interfaces:**
- Consumes: spec §3.3's confirmed table.
- Produces: a complete per-slot table with a one-line reason each, consumed by Task 10.

- [ ] **Step 1: Read every unconfirmed site**

The tail is: `crypto/kem.rs::decap` (slots `sk_x_bytes`, `ss_x_bytes`, `dk_arr`, `ss_pq_bytes`, `ss_pq_arr`, `k`), `crypto/sig.rs` (`sk_bytes`, `seed_bytes`, `seed`, `seed_arr`, `seed`), `sync/prepare.rs::derive_block_reader_keys` (`x_sk_bytes`), `sync/commit/write.rs` (`ed_sk_bytes`), `vault/repair/orchestration.rs` (`x_sk_bytes` ×2), `vault/device_slot.rs::add_device_slot` (`secret_arr`).

For each, apply the §1.2 test and record the verdict:

> Between the slot's **last write** and its `.zeroize()`, is there an operation that can `?`-return, `return`, or panic?
> - `Sensitive::new` / `SecretBytes::new` / struct construction — **cannot**; not a window.
> - `copy_from_slice` — *can* panic on length mismatch, but is not a window if the length was already checked or is statically fixed. Say which.
> - Anything with `?`, `.expect()`, `.unwrap()`, or a call into another module — **is** a window.

Watch for the false positive spec §3.3 names: `let mut x: [u8; 32] = v.try_into().map_err(..)?;` is a *fill* whose `?` fires before the slot is bound. That is adjacent, not windowed.

- [ ] **Step 2: Write the census table**

Create `docs/superpowers/plans/2026-08-11-513-census.md` with one row per slot across all four roots — the §3.3 rows verbatim plus the tail confirmed in Step 1:

```markdown
# #513 census — every secret stack slot with a trailing `.zeroize()`

Method: spec §1.2's window test, applied per slot. A script can shortlist
but cannot decide (spec §3.1); every row here is a read judgement.

| file | slot | window? | reason | action |
|---|---|---|---|---|
| `core/src/crypto/kdf.rs::derive_master_kek` | `out` | **E2** | `?` on the Argon2 fill; `out` may be partially written | `try_build` |
| … one row per slot … |
```

- [ ] **Step 3: Reconcile the counts**

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
  grep -rn "\.zeroize()" core/src ffi --include="*.rs" | grep -v "^\s*//" | wc -l
```

Every non-comment call site must appear as a row. If the count and the row count disagree, find the missing slot — a slot silently absent from the census is the one failure mode this task exists to prevent.

- [ ] **Step 4: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
git add docs/superpowers/plans/2026-08-11-513-census.md && \
git commit -F - <<'MSG'
docs: complete per-slot census of the trailing-zeroize idiom (#513)

Confirms spec §3.3's predicted-adjacent tail by reading each site rather
than assuming it. One row per slot across all four roots, each with the
window verdict and the reason for it, reconciled against the raw
`.zeroize()` call-site count so no slot is silently absent.

Folded into memory-hygiene-audit-internal.md in the final task.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

## Task 3: `crypto/kdf.rs` + `crypto/kem.rs`

Four windowed slots. `derive_master_kek` is the only E2 (`?`) among them.

**Files:**
- Modify: `core/src/crypto/kdf.rs` (`derive_master_kek`, `derive_recovery_kek`, `derive_device_kek`)
- Modify: `core/src/crypto/kem.rs` (`derive_wrap_key`, slot `ikm` only)

**Interfaces:**
- Consumes: `Sensitive::build`, `Sensitive::try_build` from Task 1.
- Produces: no signature changes. All four functions keep their exact current signatures and error types.

- [ ] **Step 1: Confirm the existing tests cover these functions, and run them green first**

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
  cargo test --release -p secretary-core kdf 2>&1 | tail -15 && \
  cargo test --release -p secretary-core kem 2>&1 | tail -15
```

Expected: PASS. These are refactor-only conversions — record the pass counts, they must be identical after Step 3. If a KAT test exists for these derivations (RFC 5869 / RFC 9106 vectors), note its name; it is the strongest evidence the conversion preserved behaviour.

- [ ] **Step 2: Convert `derive_master_kek` (E2 — the `?` case)**

In `core/src/crypto/kdf.rs`, replace:

```rust
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(password.expose(), salt, &mut out)
        .map_err(|_| KdfError::Argon2ParamsRejected)?;
    let kek = Sensitive::new(out);
    // `Sensitive::new` copied `out` (which is `[u8; 32]: Copy`); zeroize the
    // stack copy so the secret only lives inside `kek`. Mirrors the pattern
    // in `derive_recovery_kek` and `crypto::kem::derive_wrap_key`.
    out.zeroize();
    Ok(kek)
```

with:

```rust
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    // Wrapped BEFORE the fill: `hash_password_into` writes into `out` and may
    // then fail, so the pre-#513 form's trailing `out.zeroize()` was skipped by
    // its own `?` — leaving a partially-derived KEK on the stack. `try_build`
    // wipes on the error path and on an unwinding panic alike.
    let kek = Sensitive::try_build([0u8; 32], |out| {
        argon
            .hash_password_into(password.expose(), salt, out)
            .map_err(|_| KdfError::Argon2ParamsRejected)
    })?;
    Ok(kek)
```

- [ ] **Step 3: Convert the two HKDF derivations (E1 — infallible fill)**

Both `derive_recovery_kek` and `derive_device_kek` have the identical shape. For `derive_recovery_kek`, replace:

```rust
    let salt = [0u8; 32];
    let mut out = [0u8; 32];
    {
        // `Hkdf<Sha256>` has no `Drop` impl in upstream `hkdf` 0.12, so this
        // scope only bounds the lexical lifetime of `hk` — there is no
        // zeroization callback. See SECURITY note above.
        let hk = Hkdf::<Sha256>::new(Some(&salt), entropy.expose());
        hk.expand(TAG_RECOVERY_KEK, &mut out)
            .expect("32 bytes is well within HKDF-SHA-256 output limits");
    }
    let kek = Sensitive::new(out);
    out.zeroize();
    kek
```

with:

```rust
    let salt = [0u8; 32];
    // `Hkdf<Sha256>` has no `Drop` impl in upstream `hkdf` 0.12, so the inner
    // scope only bounds the lexical lifetime of `hk` — there is no zeroization
    // callback. See SECURITY note above. The `.expect()` can panic in
    // principle, which the pre-#513 trailing wipe did not cover; `build` does.
    Sensitive::build([0u8; 32], |out| {
        let hk = Hkdf::<Sha256>::new(Some(&salt), entropy.expose());
        hk.expand(TAG_RECOVERY_KEK, out)
            .expect("32 bytes is well within HKDF-SHA-256 output limits");
    })
```

Apply the same transformation to `derive_device_kek`, substituting `TAG_DEVICE_KEK` and `secret.expose()`. Both functions return `Sensitive<[u8; 32]>` directly, so there is no `Ok(...)` wrapper.

- [ ] **Step 4: Convert `kem::derive_wrap_key`'s `ikm`**

`ikm` is a `Vec<u8>` holding **both** KEM shared secrets in cleartext, live across the HKDF call. It needs `SecretBytes`, not `Sensitive` — no new API. In `core/src/crypto/kem.rs`, change the `ikm` construction so the `Vec` is moved into a `SecretBytes` before `hkdf_sha256_extract_and_expand` runs, and pass `ikm.expose()` to it. Delete the now-dead `ikm.zeroize();`.

Leave `okm` and `key` exactly as they are — spec §3.3 classifies both as adjacent, and converting them is churn on frozen-adjacent crypto.

- [ ] **Step 5: Run the crypto tests and the KATs**

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
  cargo test --release -p secretary-core kdf 2>&1 | tail -8 && \
  cargo test --release -p secretary-core kem 2>&1 | tail -8 && \
  cargo test --release --workspace 2>&1 | tail -8
```

Expected: identical pass counts to Step 1, zero failures. **Any changed count means behaviour changed** — these are refactor-only. Stop and diagnose rather than adjusting a test.

- [ ] **Step 6: Prove the byte-level output is unchanged**

The KDF and KEM outputs are pinned against published vectors. Run the clean-room verifier, which decrypts the golden vault using only `docs/`:

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
  uv run core/tests/python/conformance.py
```

Expected: PASS. A failure here means the conversion changed a derived key.

- [ ] **Step 7: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
git add core/src/crypto/kdf.rs core/src/crypto/kem.rs && \
git commit -F - <<'MSG'
fix(core): wrap KEK and wrap-key material before filling it (#513)

Four windowed slots, per the census:

- derive_master_kek's `out` is the E2 case and the worst of them: the
  `?` on `hash_password_into` fires AFTER Argon2 has written into the
  slot, so the trailing `out.zeroize()` was skipped on exactly the path
  that leaves a partially-derived master KEK on the stack.
- derive_recovery_kek / derive_device_kek are E1 only — their fill ends
  in `.expect()`, which the trailing wipe never covered.
- kem::derive_wrap_key's `ikm` holds BOTH KEM shared secrets in
  cleartext across the HKDF call; it becomes SecretBytes, needing no new
  API.

`okm` and `key` in the same function are deliberately untouched: the
census classifies both as adjacent, and rewriting them would be churn on
frozen-adjacent crypto for no gain.

Refactor-only: same signatures, same error variants, same derived bytes
— conformance.py re-verifies the golden vault against docs/ alone.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

## Task 4: `unlock/mnemonic.rs` — #518's recovery-phrase leak, and the §3.4 missed wipe

The highest-value fix in the slice. `parse` leaks the user's full 24-word recovery phrase on both its error paths, including `UnknownWord` — one mistyped word, the most common failure.

**Files:**
- Modify: `core/src/unlock/mnemonic.rs` (`generate`, `parse`)
- Modify: `core/tests/` — whichever file already holds the mnemonic tests (find it: `grep -rln "MnemonicError::WrongLength\|UnknownWord" core/tests/`)

**Interfaces:**
- Consumes: `Sensitive::build` from Task 1; existing `SecretString`.
- Produces: no signature changes. `generate` and `parse` keep their exact signatures and `MnemonicError` variants.

- [ ] **Step 1: Write failing regression tests for the leaking paths**

These pin that the paths *are reached and behave correctly*. Per spec §5.4, a wipe of freed heap is not observable from safe Rust — these tests document and exercise the paths, they do not assert the wipe. Say so in a comment so a later reader does not over-read them.

Add to the mnemonic test file:

```rust
/// #518: `parse` returned on these paths WITHOUT wiping `normalized`, the
/// String holding the user's full recovery phrase.
///
/// A wipe of a freed heap buffer is not observable from safe Rust (spec
/// §5.4), so these tests do NOT assert the wipe. They pin that both leaking
/// paths are reached and keep their exact error variants, so the converted
/// code is covered by execution rather than by inspection.
#[test]
fn parse_rejects_a_short_phrase_with_wrong_length() {
    let err = Mnemonic::parse("abandon abandon abandon").unwrap_err();
    assert!(
        matches!(err, MnemonicError::WrongLength { got: 3 }),
        "expected WrongLength {{ got: 3 }}, got {err:?}"
    );
}

#[test]
fn parse_rejects_an_unknown_word_by_index_only() {
    // Take a valid 24-word phrase and corrupt exactly one word, which is the
    // realistic failure: a typo during vault recovery.
    let good = Mnemonic::generate(&mut rand::rngs::OsRng);
    let mut words: Vec<&str> = good.phrase().split_whitespace().collect();
    words[7] = "notaword";
    let err = Mnemonic::parse(&words.join(" ")).unwrap_err();

    assert!(
        matches!(err, MnemonicError::UnknownWord { index: 7 }),
        "expected UnknownWord {{ index: 7 }}, got {err:?}"
    );
}
```

Check the real accessor names first (`grep -n "pub fn phrase\|pub fn parse\|pub fn generate" core/src/unlock/mnemonic.rs`) and adjust — do not invent an API.

- [ ] **Step 2: Run them**

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
  cargo test --release -p secretary-core mnemonic 2>&1 | tail -20
```

These may already PASS — the error variants are correct today; only the wipe is missing. That is expected and fine: their job is path coverage for the conversion that follows. If either FAILS, the API names are wrong; fix them before proceeding.

- [ ] **Step 3: Fix `parse`'s leak by wrapping `normalized`**

Replace the `let mut normalized = parts.join(" ");` binding with a `SecretString`, read it via `.expose()` at the three use sites (`split_whitespace`, `parse_in_normalized`, and nothing else), and **delete the trailing `normalized.zeroize();`** — `SecretString` is `ZeroizeOnDrop`, so the wipe now happens on all four exits (both early returns, the happy path, and an unwind).

Keep `nfkd` and `parts` exactly as they are; both are already wiped before the branches.

Update the comment above the deleted wipe, which currently reads "`normalized` is wiped after parsing below (it must live until `parse_in_normalized` and `tokens` are done with it)" — that statement was the bug's cover.

- [ ] **Step 4: Fix `generate` — the window AND the never-wiped slot**

Two distinct defects in one function:

1. `entropy_buf` is live across `Bip39Mnemonic::from_entropy(...).expect(...)`, `bip.to_string()` and `to_entropy_array()` — an E1 window. Convert it to `Sensitive::build([0u8; 32], |buf| rng.fill_bytes(buf))` and read via `.expose()`; delete the trailing `entropy_buf.zeroize()`.
2. **`entropy` is never wiped at all** (spec §3.4). It is moved into `Sensitive::new(entropy)` inside the returned struct literal, and `[u8; 32]` is `Copy`, so the source slot stays dirty. Build it through the wrapper instead:

```rust
    let entropy = Sensitive::build([0u8; 32], |slot| slot.copy_from_slice(&full[..32]));
    full.zeroize();

    Mnemonic { phrase, entropy }
```

Also correct the function's doc comment, which claims "The local 32-byte entropy buffer is zeroized after the BIP-39 mnemonic has been constructed" — true of `entropy_buf`, false of `entropy`. State what is actually true now.

- [ ] **Step 5: Run the full mnemonic suite plus the workspace**

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
  cargo test --release -p secretary-core mnemonic 2>&1 | tail -10 && \
  cargo test --release --workspace 2>&1 | tail -8
```

Expected: all PASS. The BIP-39 KATs (Trezor canonical vectors) are the ones that matter — `generate` and `parse` must still round-trip identical phrases and entropy.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
git add core/src/unlock/mnemonic.rs core/tests/ && \
git commit -F - <<'MSG'
fix(core): recovery phrase no longer survives parse's error paths (#518, #513)

`parse` held the user's full 24-word recovery phrase in `normalized:
String` and wiped it only on the happy path. Both error paths returned
with the heap buffer live, and it is then freed unwiped:

- WrongLength, an explicit `return Err` (E3);
- the `?` after `parse_in_normalized` (E2) — which is UnknownWord, i.e. a
  single mistyped word. That is the most common way this function fails,
  and someone recovering a vault typically hits it several times in a
  row, leaving a fresh copy of a nearly-correct phrase each time.

`normalized` becomes a SecretString, so Drop wipes on all four exits.

`generate` carried two separate defects. `entropy_buf` was live across
from_entropy/to_string/to_entropy_array (E1). And `entropy` was NEVER
wiped: it is moved into Sensitive::new inside the return literal, and
`[u8; 32]` is Copy, so the move copied and left the source dirty. Its
sibling parse() does wipe it; the 2026-05-02 audit's twelve-gap table
lists this function's `full` buffer but not this slot; and the fn's own
doc comment claimed a wipe covering only `entropy_buf`. Comment
corrected.

The two new tests pin path coverage, not the wipe — a freed heap buffer
is not observable from safe Rust (spec §5.4), and the comment above them
says so, so a later reader does not over-read them.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

## Task 5: `unlock/bundle.rs` — #518's second leak

**Files:**
- Modify: `core/src/unlock/bundle.rs` (`from_canonical_cbor`)
- Modify: the bundle test file (`grep -rln "BundleError::MissingField" core/tests/ core/src/unlock/bundle.rs`)

**Interfaces:**
- Consumes: nothing from earlier tasks — this is a wrapper-adoption fix.
- Produces: no signature change. `from_canonical_cbor` keeps its `BundleError` variants and their precedence.

- [ ] **Step 1: Write a failing regression test for the leaking path**

```rust
/// #518: the `.ok_or(MissingField)?` chain in the struct construction returns
/// BEFORE the explicit wipe block below it, leaving whichever secret keys were
/// already decoded on the stack.
///
/// As in mnemonic.rs, this pins the path and its error variant, not the wipe
/// itself — a dead stack frame is not observable from safe Rust (spec §5.4).
#[test]
fn from_canonical_cbor_reports_the_missing_field_and_takes_the_early_return() {
    // Build a valid bundle, re-encode it minus one required key, and confirm
    // the MissingField path is the one taken.
    // (Construct the truncated CBOR from a generated bundle — never from a
    // hardcoded literal byte array, which trips CodeQL.)
}
```

Fill this in against the real helpers in the file — find how existing tests build a bundle (`grep -n "fn.*test\|to_canonical_cbor" core/src/unlock/bundle.rs | head -40`) and remove one key from the encoded map.

- [ ] **Step 2: Run it**

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
  cargo test --release -p secretary-core bundle 2>&1 | tail -15
```

Expected: PASS on the error variant (the variant is already correct). If it fails, the test's CBOR surgery is wrong — fix it before proceeding.

- [ ] **Step 3: Fix the leak**

The two `Copy`-typed slots `x25519_sk_bytes` / `ed25519_sk_bytes` are `Option<[u8; N]>` and are wiped only after the struct construction. Two viable shapes — pick the one that reads cleanest against the surrounding decode loop:

- **(a)** Wrap at decode time: make the decode-loop bindings `Option<Sensitive<[u8; N]>>` so each is `ZeroizeOnDrop` from the moment it is populated, and drop the explicit wipe block for those two slots.
- **(b)** Hoist the `.ok_or(...)?` extractions above the struct literal, so every fallible step completes before any secret is copied into an unprotected slot.

(a) is preferred: it makes the property structural rather than order-dependent. Keep the `canonical` buffer's existing wipe either way — that one is correct.

Update the comment block, which currently explains the wipe as covering "the two Copy-typed sk stack copies" — it must no longer imply the `?` paths above are covered by it.

- [ ] **Step 4: Run the tests**

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
  cargo test --release -p secretary-core bundle 2>&1 | tail -10 && \
  cargo test --release --workspace 2>&1 | tail -8 && \
  uv run core/tests/python/conformance.py
```

Expected: all PASS. `conformance.py` is load-bearing here — it decodes the golden vault's identity bundle from `docs/` alone, so it proves the CBOR decode is byte-identical.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
git add core/src/unlock/bundle.rs core/tests/ && \
git commit -F - <<'MSG'
fix(core): identity-bundle secret keys no longer survive the MissingField path (#518, #513)

`from_canonical_cbor` wipes `x25519_sk_bytes` / `ed25519_sk_bytes` in an
explicit block before the NonCanonicalCbor return — correctly, and the
comment there says so. But the `.ok_or(BundleError::MissingField(_))?`
chain in the struct construction ABOVE it returns first on malformed
input, leaving whichever secret keys were already decoded on the stack.
`Option<[u8; N]>` is Copy, so the struct construction copied rather than
moved them out.

Wrapping the decode-loop bindings makes the property structural rather
than dependent on statement order. Lower severity than #518's first half
— reaching this code means the bundle already decrypted, so an attacker
holding the ciphertext already had the KEK — but it is residue the
surrounding code was written to avoid.

conformance.py re-verifies the decode against docs/ alone.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

## Task 6: `unlock/mod.rs` — the four-secret-key cleartext buffer

**Files:**
- Modify: `core/src/unlock/mod.rs` (`create_vault_unchecked`)

**Interfaces:**
- Consumes: `Sensitive::build` from Task 1; existing `SecretBytes`.
- Produces: no signature change.

- [ ] **Step 1: Run the vault-creation tests green first**

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
  cargo test --release -p secretary-core create_vault 2>&1 | tail -15
```

Record the pass count.

- [ ] **Step 2: Convert `bundle_plaintext` (E1, highest value in this file)**

`bundle_plaintext` is a `Vec<u8>` holding cleartext CBOR of **all four secret keys**, live across three `random_nonce` draws, `compose_aad`, and an `encrypt(...).expect(...)`. Change:

```rust
    let mut bundle_plaintext = identity.to_canonical_cbor()?;
```

to bind a `SecretBytes` instead, pass `bundle_plaintext.expose()` to `encrypt`, and **delete** the trailing `bundle_plaintext.zeroize();`. Update the comment above it — it currently says the buffer "is AEAD-encrypted under the IBK below, then zeroized so the cleartext key material does not linger in freed heap", which describes the happy path only.

- [ ] **Step 3: Convert `ibk` opportunistically**

The census classifies `ibk` as adjacent, so this is not required — but `Sensitive::build` reads better than the current four-line comment-plus-wipe, and the conversion is free:

```rust
    let identity_block_key = Sensitive::build([0u8; 32], |slot| rng.fill_bytes(slot));
```

This lets the five-line SECURITY comment above it (which explains why the post-move zeroize is the best available discipline) be replaced by a one-line statement that the slot is wrapped before it is filled. **If this conversion causes any borrow-checker friction with `rng`, skip it** — it is optional, and `ibk` is not a windowed slot.

- [ ] **Step 4: Run the tests**

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
  cargo test --release --workspace 2>&1 | tail -8 && \
  uv run core/tests/python/conformance.py
```

Expected: identical pass count to Step 1; conformance PASS. `create_vault` writes the golden-vault-shaped artifacts, so a behaviour change here would surface as a conformance failure.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
git add core/src/unlock/mod.rs && \
git commit -F - <<'MSG'
fix(core): wrap the cleartext four-key bundle buffer at creation (#513)

create_vault_unchecked's `bundle_plaintext` is a Vec<u8> holding
cleartext CBOR of ALL FOUR secret keys, live across three nonce draws,
compose_aad, and an `encrypt(..).expect(..)`. The trailing zeroize
covered the happy path only. It becomes SecretBytes, needing no new API.

`ibk` is converted opportunistically — the census calls it adjacent, so
this is not a fix; Sensitive::build simply states the invariant in one
line where five lines of SECURITY comment previously explained why the
post-move wipe was the best available discipline. It no longer is.

conformance.py re-verifies the created artifacts against docs/ alone.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

## Task 7: `ffi-py` — remove the by-value `[u8; 32]` producer (#503)

Structural half of the enforcement story (spec §4 item 4): remove the shape rather than merely stop using it.

**Files:**
- Modify: `ffi/secretary-ffi-py/src/errors.rs` (`array32_or_value_error`, line ~263)
- Modify: every caller of it (`grep -rn "array32_or_value_error" ffi/secretary-ffi-py/src/`)

**Interfaces:**
- Produces: `array32_into_or_value_error(bytes: &[u8], out: &mut [u8; 32], field: &'static str) -> PyResult<()>` — write-through, mirroring `array32_from_vec_into` in `ffi/secretary-ffi-uniffi/src/namespace/mod.rs:686`. The by-value `array32_or_value_error` is **deleted**, not deprecated.

- [ ] **Step 1: Write the failing unit test**

Mirror the uniffi sibling's test (`array32_from_vec_into_writes_through_and_rejects_wrong_length` at `ffi/secretary-ffi-uniffi/src/namespace/mod.rs:1027`). In `ffi/secretary-ffi-py/src/errors.rs`'s `#[cfg(test)]` module:

```rust
    #[test]
    fn array32_into_writes_through_and_rejects_wrong_length() {
        let mut out = [0u8; 32];
        let src: Vec<u8> = (0u8..32).collect();
        array32_into_or_value_error(&src, &mut out, "device_secret")
            .expect("32 bytes is valid");
        assert_eq!(out.to_vec(), src);

        let mut out2 = [0u8; 32];
        let short: Vec<u8> = (0u8..31).collect();
        let err = array32_into_or_value_error(&short, &mut out2, "device_secret")
            .expect_err("31 bytes must be rejected");
        // The message must report the ACTUAL wrong length, not 0 — the bug
        // #501 describes was exactly this, read after a zeroize() cleared it.
        assert!(format!("{err}").contains("31"), "got: {err}");
        assert_eq!(out2, [0u8; 32], "a rejected input must not partially fill");
    }
```

- [ ] **Step 2: Run it**

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
  cargo test --release -p secretary-ffi-py array32 2>&1 | tail -20
```

Expected: FAIL — `cannot find function 'array32_into_or_value_error'`.

- [ ] **Step 3: Implement it and delete the by-value version**

Add the write-through function next to the existing one, then delete `array32_or_value_error` and migrate its callers (`repair.rs:93`, `repair.rs:95`, plus any others the grep in Step 0 found). Note those two callers pass **fingerprints, not secrets** — they are non-secret and the migration is purely to remove the by-value shape from the crate, not because those sites leak.

```rust
/// Write-through 32-byte extractor. Mirrors `array32_from_vec_into` in the
/// uniffi crate: the caller owns the destination slot, so no second `[u8; 32]`
/// is minted on this function's frame for the caller to forget about (#503).
pub(crate) fn array32_into_or_value_error(
    bytes: &[u8],
    out: &mut [u8; 32],
    field: &'static str,
) -> PyResult<()> {
    if bytes.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            crate::detail::arg_len(field, 32, bytes.len()),
        ));
    }
    out.copy_from_slice(bytes);
    Ok(())
}
```

- [ ] **Step 4: Verify no by-value producer remains**

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
  grep -rn "array32_or_value_error\|-> PyResult<\[u8; 32\]>" ffi/secretary-ffi-py/src/
```

Expected: **no output**. Any hit is a surviving by-value producer.

- [ ] **Step 5: Run the tests**

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
  cargo test --release --workspace 2>&1 | tail -8 && \
  cargo clippy --release --workspace --tests -- -D warnings
```

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
git add ffi/secretary-ffi-py/src/ && \
git commit -F - <<'MSG'
refactor(ffi-py): write-through 32-byte extractor, by-value form deleted (#503, #513)

#503 replaced the by-value `array32_from_vec` with a write-through
sibling on the UNIFFI side only; ffi-py kept its own by-value producer,
`array32_or_value_error(..) -> PyResult<[u8; 32]>`, so #503's ffi-py half
stayed open. A by-value 32-byte return mints a second stack copy the
caller must remember to wipe, which is the shape this whole slice exists
to remove.

Deleted rather than deprecated: leaving it callable leaves the hazard
callable. Its two existing callers pass fingerprints, not secrets, so
this migration removes the shape from the crate rather than fixing a leak
at those sites.

The wrong-length assertion checks the message reports the ACTUAL length,
pinning the #501-documented bug class where a length was read after a
zeroize() had already cleared it to 0.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

## Task 8: `ffi-py` — the 37 windowed sites

33 are a marshalled parameter or scratch slot live across a full bridge call (Argon2id, file I/O, CBOR, hybrid verify) — this is where the manual choreography is thickest. The remaining 4 are the secret accessors Step 3 covers.

**Files:**
- Modify: `ffi/secretary-ffi-py/src/unlock.rs`, `vault.rs`, `device.rs`, `repair.rs`, `repair_preview.rs`, `record.rs`
- **Take the authoritative per-file site list from the census's conversion action list** (`docs/superpowers/plans/2026-08-11-513-census.md`), not from this file. The counts here drifted once already when the Task 2 review moved four accessor sites into scope; the census is the single source of truth and includes `record.rs`, which an earlier version of this list omitted entirely.

**Interfaces:**
- Consumes: `array32_into_or_value_error` from Task 7; existing `SecretBytes`.
- Produces: no signature changes visible to Python. The `#[pyfunction]` parameter lists stay byte-identical — `mut password: Vec<u8>` may lose its `mut`, which is not part of the ABI.

- [ ] **Step 1: Convert the simple owned-`Vec` parameters first**

`unlock.rs` and `vault.rs` hold the simplest shape — one bridge call, one trailing wipe:

```rust
// before
pub(crate) fn open_with_password(
    vault_toml_bytes: &[u8],
    identity_bundle_bytes: &[u8],
    mut password: Vec<u8>,
) -> PyResult<UnlockedIdentity> {
    let result = secretary_ffi_bridge::open_with_password(
        vault_toml_bytes, identity_bundle_bytes, &password,
    ).map(UnlockedIdentity).map_err(ffi_unlock_error_to_pyerr);
    password.zeroize();
    result
}

// after — Drop covers the panic path the deferred-result dance never did
pub(crate) fn open_with_password(
    vault_toml_bytes: &[u8],
    identity_bundle_bytes: &[u8],
    password: Vec<u8>,
) -> PyResult<UnlockedIdentity> {
    let password = SecretBytes::new(password);
    secretary_ffi_bridge::open_with_password(
        vault_toml_bytes, identity_bundle_bytes, password.expose(),
    ).map(UnlockedIdentity).map_err(ffi_unlock_error_to_pyerr)
}
```

Note the deferred-`let result = …; wipe; result` dance disappears entirely — it existed only to cover the error path, which `Drop` now covers along with the panic path.

Keep `#[allow(clippy::needless_pass_by_value)]` where it is present: the owned `Vec` is still required so the wrapper can take ownership. Its comment should now say so.

- [ ] **Step 2: Convert the multi-early-return functions**

`device.rs::open_with_device_secret` is the worst case — **six** `.zeroize()` calls, one inside a `map_err` closure. After conversion it should have **zero**. Wrap the parameter once at the top, use `array32_into_or_value_error` with a `Sensitive`-wrapped destination for the `[u8; 32]`, and delete every manual wipe:

```rust
    let device_secret = SecretBytes::new(device_secret);
    if device_uuid.len() != 16 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            crate::detail::arg_len("device_uuid", 16, device_uuid.len()),
        ));
    }
    // ... remaining validation, no wipes needed on any path ...
    let secret = Sensitive::try_build([0u8; 32], |slot| {
        array32_into_or_value_error(device_secret.expose(), slot, "device_secret")
    })?;
```

The `len()`-before-`zeroize()` comment in that function documents a bug that **cannot recur** once the manual wipes are gone — `SecretBytes` does not clear until drop. Replace the comment rather than deleting it silently; it records real history.

- [ ] **Step 3: Convert the four accessor helpers too — AMENDED**

> **This step originally said to leave these four alone.** That instruction was wrong and was withdrawn after the Task 2 review, on the human partner's ruling. Recorded rather than silently rewritten, because the plan being wrong here is the interesting part.
>
> `take_secret` (`device.rs:57-64`, a device secret), `take_phrase` (`unlock.rs:33-41`, a full 24-word recovery mnemonic), `expose_text` (`record.rs:51-59`) and `expose_bytes` (`record.rs:66-74`, decrypted record fields) all have the window shape:
>
> ```rust
> self.0.take_secret().map(|mut v| {
>     let b = PyBytes::new(py, &v);   // ← call into another module, between fill and wipe
>     v.zeroize();
>     b
> })
> ```
>
> `PyBytes::new` / `PyString::new` genuinely panic — pyo3 0.29 `src/types/bytes.rs:76` documents "Panics if out of memory", and `assume_owned` → `Bound::from_owned_ptr` → `panic_on_null` (`instance.rs:2429`) unwinds. The receivers are plain `Vec<u8>` / `String` from the bridge (`device.rs:97`, `create.rs:130`, `record/field.rs:125`/`:152`) with no `ZeroizeOnDrop`.

Convert each to wrap before handing out, so `Drop` covers the panic:

```rust
self.0.take_secret().map(|v| {
    let v = SecretBytes::new(v);
    PyBytes::new(py, v.expose())
})
```

`expose_text` / `take_phrase` use `SecretString` and `PyString::new` correspondingly. Take the exact list of sites — including any further ones the Task 2 re-audit surfaced — from the census's conversion action list, not from this paragraph.

- [ ] **Step 4: Verify no manual wipes remain in the two wrapper crates**

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
  grep -rn "\.zeroize()" ffi/secretary-ffi-py/src/ ffi/secretary-ffi-uniffi/src/
```

Expected after Tasks 8 and 9: **no output at all** outside `#[cfg(test)]`. Every secret local in both wrapper crates should now be wrapper-typed, with `Drop` doing the wiping. Any hit is an unconverted site — check it against the census's action list.

- [ ] **Step 5: Run the Rust and Python test suites**

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
  cargo test --release --workspace 2>&1 | tail -8 && \
  cargo clippy --release --workspace --tests -- -D warnings
```

Then the ffi-py pytest suite, which **CI never runs** (#501) — so it must be run here:

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots/ffi/secretary-ffi-py && \
  uv run --with maturin maturin develop --release 2>&1 | tail -5 && \
  uv run --with pytest pytest tests/ -v 2>&1 | tail -25
```

If pytest sees a stale `.so` after the rebuild, nuke the venv and the `uv` cache — that is a known `maturin develop` + `uv` editable-cache interaction, not a code failure.

`tests/test_device_slot.py:117` is the one to watch: it asserts on message *content* and is exactly the regression the wrong-length path must keep passing.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
git add ffi/secretary-ffi-py/src/ && \
git commit -F - <<'MSG'
fix(ffi-py): wrapper-typed secrets across every bridge call (#513)

37 slots. 33 are a marshalled parameter or scratch slot live across a full
bridge invocation — Argon2id, file I/O, CBOR decode, hybrid verify. The
other 4 are the secret accessors, added after the Task 2 review (see below).
pyo3 0.29 catches an unwinding panic at the boundary
(impl_/trampoline.rs:301) and converts it to PanicException, so the
process SURVIVES with the residue on a frame later calls reuse. #513's
"the process is typically about to die" does not hold here.

open_with_device_secret went from six hand-placed `.zeroize()` calls
across its early returns — one inside a map_err closure — to zero. The
`let result = ..; wipe; result` dance disappears with them: it existed
only to cover the error path, which Drop now covers alongside the panic
path.

The len()-before-zeroize() comment is replaced rather than dropped. It
records a real shipped bug (every wrong-length secret reported "got 0"),
and the class cannot recur now that no manual wipe precedes the read.

Verified against ffi-py's pytest suite, which CI does not run (#501).

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

## Task 9: `ffi-uniffi` — the three sites #513 names

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/src/namespace/mod.rs` (`open_with_device_secret`, ~line 624), `namespace/repair.rs` (`repair_with_device_secret` ~254, `preview_repair_with_device_secret` ~382)

**Interfaces:**
- Consumes: `Sensitive::try_build` from Task 1; the existing `array32_from_vec_into` at `namespace/mod.rs:686` (unchanged — it is already write-through).
- Produces: no signature changes. **`secretary.udl` must not be touched.**

- [ ] **Step 1: Convert all three**

Each has the identical shape. Replace:

```rust
    let mut secret_arr = [0u8; 32];
    array32_from_vec_into(device_secret, &mut secret_arr, "device_secret")?;
    let result: Result<…> = match std::str::from_utf8(&folder_path) { … };
    secret_arr.zeroize();
    let bridge_out = result?;
```

with:

```rust
    let secret = Sensitive::try_build([0u8; 32], |slot| {
        array32_from_vec_into(device_secret, slot, "device_secret")
    })?;
    let bridge_out = match std::str::from_utf8(&folder_path) { … }?;
```

passing `secret.expose()` where `&secret_arr` was passed. The deferred-`result` dance goes away for the same reason as in Task 8.

The existing comment block explaining why `secret_arr` is bound `mut` ("binding it immutably and later doing `let mut secret_arr = secret_arr;` would COPY the array…") describes a hazard that no longer exists — replace it with a one-line note that the slot is wrapped before it is filled.

- [ ] **Step 2: Prove the FFI surface did not move**

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
  git diff main... -- ffi/secretary-ffi-uniffi/src/secretary.udl
```

Expected: **empty output**. Any diff means the conversion changed the projected API, which is out of scope.

- [ ] **Step 3: Run the tests and both binding-side checks**

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
  cargo test --release --workspace 2>&1 | tail -8 && \
  cargo clippy --release --workspace --tests -- -D warnings && \
  bash ffi/scripts/check-lean-binding.sh --self-test && \
  bash ffi/scripts/check-lean-binding.sh
```

- [ ] **Step 4: Build the downstream Gradle modules**

A uniffi-side change can pass conformance yet break `:kit`, which `cargo` cannot see:

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots/android && \
  ./gradlew :vault-access:test :kit:compileDebugKotlin 2>&1 | tail -15
```

Expected: BUILD SUCCESSFUL.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
git add ffi/secretary-ffi-uniffi/src/ && \
git commit -F - <<'MSG'
fix(ffi-uniffi): wrap the device-secret slot before filling it (#513)

The three sites #513 names. uniffi 0.32 catches an unwinding panic at the
boundary (uniffi_core/src/ffi/rustcalls.rs:207), so a panic inside the
bridge call left 32 plaintext bytes on a live process's stack frame — not
a dying one.

array32_from_vec_into is unchanged; it is already write-through (#503).
Only the destination moves inside a Sensitive, via try_build, so the
`?` on a wrong-length secret and an unwinding panic both wipe.

The comment explaining why `secret_arr` had to be bound `mut` describes a
hazard that no longer exists once the slot is never a bare local.

.udl diff verified empty; :kit compiled, since a uniffi return-shape
change can pass conformance yet break the Gradle module.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

## Task 10: Documentation, and the full gate run

**Files:**
- Modify: `docs/manual/contributors/memory-hygiene-audit-internal.md`
- Delete: `docs/superpowers/plans/2026-08-11-513-census.md` (folded into the memo)
- Check: `README.md`, `ROADMAP.md`, `CLAUDE.md`

**Interfaces:**
- Consumes: the census from Task 2.

- [ ] **Step 1: Fold the census into the audit memo**

Add a new section after "Stack-residue gaps fixed in this pass", following that table's established shape but adding the window verdict. It must state:

- The three exit classes E1/E2/E3, and that the pre-existing idiom covered only the happy path.
- That both FFI boundaries `catch_unwind`, with the two file:line citations, so the "process is about to die" reasoning is on record as false.
- The full per-slot table.
- The §3.4 thirteenth gap, correcting the memo's own "twelve stack-residue gaps" claim — that number is now wrong and the memo must say why rather than silently renumber.
- Spec §5.4's limit verbatim: the per-site argument is type-level, not assertion-based.

Also fix the memo's header, which declares cross-FFI hygiene out of scope while its later "Cross-sub-project discipline" section already covers the bridge (spec §4 item 5).

- [ ] **Step 2: Check whether README / ROADMAP need updating**

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
  grep -n "zeroize\|memory hygiene\|Memory hygiene" README.md ROADMAP.md | head -20
```

Precedent from the previous eight slices in this track (#467, #472, #474, #479, #480, #486, #489, #496, #500) is that neither file gets an entry: this adds no user-facing feature and no FFI surface. **Follow the grep, not the precedent** — if either file makes a claim the census contradicts, fix it.

- [ ] **Step 3: Update CLAUDE.md's zeroize-discipline section**

The "Memory hygiene: zeroize discipline" section currently teaches the old idiom:

> Any time you `Sensitive::new(stack_var)` where `stack_var: [u8; N]`, follow with `stack_var.zeroize()` to overwrite the source slot

That is now the *fallback*, correct only where there is no window. Rewrite it to lead with `Sensitive::build` / `try_build` for any slot live across a fallible call, keep the trailing-wipe form for adjacent sites, and name the E1/E2/E3 distinction so a contributor can tell which they have.

- [ ] **Step 4: Run every gate**

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
  cargo fmt --all --check && \
  cargo build --release --workspace && \
  cargo test --release --workspace 2>&1 | tail -8 && \
  cargo clippy --release --workspace --tests -- -D warnings && \
  cargo clippy --release --workspace -- -D warnings && \
  RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace && \
  uv run core/tests/python/conformance.py && \
  uv run scripts/check-error-payload-hygiene.py --self-test && \
  uv run scripts/check-error-payload-hygiene.py && \
  uv run scripts/check-test-support-placement.py --self-test && \
  uv run scripts/check-test-support-placement.py && \
  bash ios/scripts/check-public-log-hygiene.sh --self-test && \
  bash ios/scripts/check-public-log-hygiene.sh && \
  bash android/scripts/check-log-hygiene.sh --self-test && \
  bash android/scripts/check-log-hygiene.sh && \
  bash ffi/scripts/check-lean-binding.sh --self-test && \
  bash ffi/scripts/check-lean-binding.sh
```

Then the front-end and Gradle gates:

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots/desktop && \
  pnpm test && pnpm run svelte-check
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots/android && \
  ./gradlew :vault-access:test :kit:compileDebugKotlin
```

And the scope assertions:

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
  git diff main... -- ffi/secretary-ffi-uniffi/src/secretary.udl && \
  echo "^^^ must be EMPTY" && \
  git diff main... --stat -- core/tests/data/
```

`core/tests/data/` must show **no** KAT regeneration.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots && \
git rm docs/superpowers/plans/2026-08-11-513-census.md && \
git add docs/manual/contributors/memory-hygiene-audit-internal.md CLAUDE.md README.md ROADMAP.md && \
git commit -F - <<'MSG'
docs: record the window census and correct the memo's twelve-gap claim (#513, #518)

The audit memo gains the per-slot census, the E1/E2/E3 exit classes, and
the two catch_unwind citations that put #513's "the process is typically
about to die" reasoning on record as false.

Its "twelve stack-residue gaps" figure is corrected rather than silently
renumbered: mnemonic::generate's `entropy` slot is a thirteenth, missed
in 2026-05-02, and the memo should show that its own census was
incomplete rather than quietly absorb the correction.

CLAUDE.md's zeroize-discipline section led with the trailing-wipe idiom
as though it were universally correct. It is correct only where there is
no window, so it is demoted to the adjacent-site fallback and
build/try_build leads.

Spec §5.4's limit is carried over verbatim: a wipe of freed heap or a
dead stack frame is not observable from safe Rust, so the per-site
argument is type-level, not assertion-based. Overstating that would
repeat the defect this track has caught in five consecutive reviews.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

## Self-Review

**Spec coverage:**

| Spec section | Task |
|---|---|
| §2.2 `build` / `try_build` | 1 |
| §3.1 census method + limits | 2 |
| §3.3 confirmed core classification | 3, 4, 5, 6 |
| §3.4 the thirteenth gap | 4 |
| §4 item 1 (new API) | 1 |
| §4 item 2 (convert windowed sites) | 3, 4, 5, 6, 8, 9 |
| §4 item 3 (the two #518 leaks) | 4, 5 |
| §4 item 4 (`array32_or_value_error` → write-through, #503) | 7 |
| §4 item 5 (census into the memo) | 2 → 10 |
| §5.1 mechanism test | 1 |
| §5.2 `try_build` API tests | 1 |
| §5.3 path-coverage regressions | 4, 5 |
| §5.4 stated limit | 4, 5, 10 |
| §6 scope assertions (`.udl` empty, no KAT regen) | 9, 10 |

**Type consistency:** `Sensitive::build(init, f)` / `Sensitive::try_build(init, f)` are used with those exact names and argument orders in Tasks 1, 3, 4, 6, 8, 9. `array32_into_or_value_error(bytes, out, field)` is defined in Task 7 and consumed in Task 8 with that signature. `array32_from_vec_into(bytes, out, field)` is pre-existing and unchanged, consumed in Task 9.

**Ordering:** Task 1 must be first (everything consumes it). Task 7 must precede Task 8. Tasks 3-6 are independent of each other and of 7-9. Task 2 can run any time before Task 10; running it early informs 3-6. Task 10 must be last.

**Known plan risk:** Task 5 Step 1's test body is specified as intent plus explicit constraints (build from a generated bundle, never a hardcoded byte array) rather than finished code, because the CBOR surgery depends on helpers in `bundle.rs` that must be read first. That is the one place in this plan a step does not hand over runnable code, and it is called out rather than disguised.
