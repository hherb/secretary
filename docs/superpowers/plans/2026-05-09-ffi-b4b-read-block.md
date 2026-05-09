# B.4b — FFI `read_block` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire `secretary_core::vault::block::decrypt_block` through both FFI flavors (PyO3 → Python; uniffi → Swift / Kotlin) via the existing shared `secretary-ffi-bridge` crate. One new top-level entry point (`read_block(&UnlockedIdentity, &OpenVaultManifest, &[u8; 16])`) returns a `BlockReadOutput` containing decrypted records. Three new opaque handles (`BlockReadOutput`, `Record`, `FieldHandle`) project the secret-payload-bearing record types under the **hybrid Record projection** pattern: non-secret metadata is value-typed; secret payloads are opaque-handle with explicit `expose_text()` / `expose_bytes()` boundary. `FfiVaultError` grows from 6 → 7 variants (+ `BlockNotFound { uuid_hex }`). One in-scope hardening: `core/fuzz/fuzz_targets/record.rs` gains a defense-in-depth UTF-8-validity assertion on every successfully-decoded `RecordFieldValue::Text`.

**Architecture:** Strictly additive on B.4a. Bridge crate gains a NEW `record.rs` module (the only large new file) + a 7th variant on the existing `FfiVaultError` enum + a new `vault_folder: PathBuf` field on the bridge-internal `OpenVaultManifestInner` (no public B.4a accessor change). PyO3 + uniffi projection layers add 1 new entry point + 3 new opaque-handle types + 1 new exception/UDL-error variant each. `Record` and `FieldHandle` use `Arc<Mutex<Option<Inner>>>` so accessors can hand out cheap clones that share the same wiped state; `BlockReadOutput` uses the simpler `Mutex<Option<Inner>>` (no shared-clone pattern). Single-author block reading only — multi-author / contact-discovery deferred to B.4d.

**Tech Stack:** Rust 1.87 stable, PyO3 0.28, uniffi 0.31, maturin 1.9.4+, uv 0.6+, pytest, kotlinc 2.x, swiftc, JNA 5.14.0, thiserror, zeroize. No new top-level dependencies.

**Spec:** [docs/superpowers/specs/2026-05-09-ffi-b4b-read-block-design.md](../specs/2026-05-09-ffi-b4b-read-block-design.md) (commit `3093782`)

**Branch:** `feat/ffi-b4b-read-block` (local working branch on `/Users/hherb/src/secretary`; baseline already verified at session start — 522 + 9 cargo, 30 pytest, 18/18 Swift, 19 Kotlin, conformance + freshness PASS, clippy + fmt clean).

---

## File structure

After all tasks complete, the FFI tree contains:

```
ffi/
├── secretary-ffi-bridge/
│   ├── README.md                                            ← edit (Task 10; +B.4b section)
│   └── src/
│       ├── lib.rs                                           ← edit (Task 4; re-export read_block + BlockReadOutput + Record + FieldHandle; B.4b crate-doc section)
│       ├── error.rs                                         ← edit (Task 1; +7th FfiVaultError variant BlockNotFound { uuid_hex }; +tripwire test)
│       ├── identity.rs                                      ← unchanged
│       ├── unlock.rs                                        ← unchanged
│       ├── create.rs                                        ← unchanged
│       ├── sync_helpers.rs                                  ← unchanged
│       ├── vault.rs                                         ← edit (Task 2; +vault_folder: PathBuf on OpenVaultManifestInner; +pub(crate) accessor; +1 test)
│       └── record.rs                                        ← NEW (Task 3; read_block + BlockReadOutput + Record + FieldHandle + 14 unit tests)
│
├── secretary-ffi-py/
│   ├── README.md                                            ← edit (Task 10; +B.4b section)
│   ├── src/lib.rs                                           ← edit (Task 6; +1 #[pyfunction], +3 #[pyclass], +1 create_exception!, +7th arm in ffi_vault_error_to_pyerr)
│   └── tests/test_smoke.py                                  ← edit (Task 7; +10 tests)
│
├── secretary-ffi-uniffi/
│   ├── README.md                                            ← edit (Task 10; +B.4b section)
│   ├── src/
│   │   ├── lib.rs                                           ← edit (Task 8; +3 wrapper structs, +1 namespace fn, +VaultError BlockNotFound variant, +mapping tests)
│   │   └── secretary.udl                                    ← edit (Task 8; +1 namespace fn, +3 interfaces, +1 [Error] enum variant)
│   └── tests/
│       ├── swift/main.swift                                 ← edit (Task 9; +4 asserts)
│       └── kotlin/Main.kt                                   ← edit (Task 9; +4 asserts)
│
core/fuzz/fuzz_targets/record.rs                             ← edit (Task 5; +Text-field UTF-8-validity defense-in-depth assertion)

README.md (root)                                             ← edit (Task 10)
ROADMAP.md                                                   ← edit (Task 10)
NEXT_SESSION.md                                              ← edit (Task 10; on the feature branch BEFORE pushing PR)
docs/handoffs/2026-05-09-b4b-read-block.md                   ← NEW (Task 10)
```

**Decomposition rationale:**
- Task 1 (error.rs) lands first as the smallest self-contained type addition (1 new enum variant + Display tripwire). Doing it in isolation avoids entangling with Task 3's much larger record.rs work.
- Task 2 (vault.rs `OpenVaultManifestInner` extension) is also small and bridge-internal — no public API change. Lands second so Task 3's `read_block` body can `unwrap_or_default` against the new `vault_folder` field cleanly.
- Task 3 is the largest single piece — new ~600-line file with the read_block free fn + 3 opaque handles + 14 unit tests. The KAT-pinning logic mirrors B.4a's vault.rs pattern (read JSON inputs once, cross-check every assertion).
- Task 4 (lib.rs re-exports + crate-doc) is mechanically tiny but must come after Task 3.
- Task 5 (fuzz harness UTF-8 assertion) is tiny and isolated; lands after Task 4 so the bridge crate is settled before the fuzz target gains its new check.
- Phase 3 (Tasks 6–7) is the PyO3 layer.
- Phase 4 (Tasks 8–9) is the uniffi layer.
- Phase 5 (Task 10) is docs + handoff.

---

## Pre-flight (already complete)

- **Branch `feat/ffi-b4b-read-block` is already checked out** (created at session start).
- **Baseline gates already verified green** at session start (522 + 9 cargo, 30 pytest, 18/18 Swift, 19 Kotlin PASS lines, conformance + freshness PASS, clippy clean, fmt OK).
- **Maturin develop run + uv cache primed** (the documented nuclear cache fix was not needed today — pytest passed cleanly on first try).

If a subagent picks this plan up cold (different session), re-verify baseline first:

```bash
cd /Users/hherb/src/secretary
git checkout feat/ffi-b4b-read-block
cargo test --release --workspace 2>&1 | grep -E "^test result:" | python3 -c "
import sys, re
p=f=i=0
for line in sys.stdin:
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'TOTAL: {p} passed; {f} failed; {i} ignored')"
cargo clippy --release --workspace -- -D warnings && echo "clippy OK"
cargo fmt --all -- --check && echo "fmt OK"
( cd ffi/secretary-ffi-py && uv run maturin develop --release --uv )
uv run --directory ffi/secretary-ffi-py pytest
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh
```

Expected baseline: 522 + 9 ignored cargo; clippy clean; fmt OK; 30 pytest passed; PASS conformance + freshness; OK Swift smoke runner; OK Kotlin smoke runner.

If pytest fails with `module 'secretary_ffi_py' has no attribute 'X'`, apply the documented nuclear cache fix:

```bash
rm -rf ffi/secretary-ffi-py/.venv
find ~/.cache/uv -name "*secretary*" -exec rm -rf {} + 2>/dev/null
cargo clean -p secretary-ffi-py
( cd ffi/secretary-ffi-py && uv sync && uv run maturin develop --release --uv )
uv run --directory ffi/secretary-ffi-py pytest
```

---

## Phase 1 — Bridge crate Rust

### Task 1: `error.rs` — add 7th `FfiVaultError::BlockNotFound { uuid_hex }` variant

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/error.rs` (currently 697 lines; will grow to ~770)

The new variant is a thin addition: one `#[error(...)]` annotation, one extra match arm in any future `From<core::vault::VaultError>` impl that fires for "this UUID is not in the manifest" (B.4b's Task 3 builds this path explicitly inside `read_block` rather than going through `From`, since the lookup happens at the bridge layer not the core layer). One tripwire test pins the Display string.

- [ ] **Step 1: Add the 7th variant to `FfiVaultError`**

In `ffi/secretary-ffi-bridge/src/error.rs`, find the `pub enum FfiVaultError` block (currently ends with `FolderInvalid { ... }` around line 632). Add the new `BlockNotFound` variant AFTER `FolderInvalid` (last variant in the enum):

```rust
    /// The requested block UUID does not appear in the manifest's live
    /// blocks list. Trashed blocks are filtered out — they also surface
    /// as `BlockNotFound` until Sub-project C adds the restore-from-trash
    /// flow with full vector-clock context.
    ///
    /// `uuid_hex` is the 32-char lowercase hex of the requested UUID, e.g.
    /// `"112233445566778899aabbccddeeff00"`. Stored as a `String` for
    /// consistency with other variants' `detail: String` payloads; the
    /// foreign caller can `bytes.fromhex(uuid_hex)` if needed.
    ///
    /// Distinct from `CorruptVault` — `BlockNotFound` means "the manifest
    /// doesn't list this block" (legitimate caller error or stale UUID),
    /// while `CorruptVault` means "the manifest lists it but the file is
    /// missing or unreadable" (data integrity failure). The wrong-length
    /// UUID case (≠16 bytes) does NOT fold here either — that's a
    /// programmer error and surfaces as `ValueError` (PyO3) /
    /// `IllegalArgumentException` (uniffi) at the binding layer; the
    /// bridge function takes `&[u8; 16]` (compile-time enforced).
    #[error("block not found in manifest: {uuid_hex}")]
    BlockNotFound { uuid_hex: String },
```

- [ ] **Step 2: Run the existing unit tests to confirm the addition compiles**

```bash
cargo test --release -p secretary-ffi-bridge --lib error 2>&1 | tail -20
```

Expected: all existing tests still pass. The new variant compiles but has no test coverage yet.

- [ ] **Step 3: Add the tripwire test for the new variant's Display**

In the `#[cfg(test)] mod tests` block of `ffi/secretary-ffi-bridge/src/error.rs` (find the closing `}` of `from_core_vault_error_kdf_params_mismatch_maps_to_corrupt_vault` near line 539), append the following test BEFORE the closing `}` of the `tests` module:

```rust

    // =============================================================================
    // FfiVaultError::BlockNotFound — new in B.4b (block lookup failure variant)
    // =============================================================================

    #[test]
    fn vault_error_block_not_found_display_pins_uuid_hex() {
        // Tripwire: the BlockNotFound variant's Display string must contain
        // the uuid_hex verbatim. A future refactor that strips it (e.g.
        // changes to a generic "block not found" message without the UUID)
        // would degrade the foreign caller's debugging affordance and must
        // be a deliberate decision rather than a silent regression.
        let ffi = FfiVaultError::BlockNotFound {
            uuid_hex: "112233445566778899aabbccddeeff00".to_string(),
        };
        let rendered = format!("{ffi}");
        assert!(
            rendered.contains("block not found"),
            "Display did not contain the BlockNotFound text: {rendered}",
        );
        assert!(
            rendered.contains("112233445566778899aabbccddeeff00"),
            "Display did not include uuid_hex: {rendered}",
        );
    }

    #[test]
    fn vault_error_block_not_found_carries_uuid_hex_field() {
        // Pin the field name + accessibility. The foreign callers
        // (PyO3 + uniffi) destructure this variant to surface uuid_hex
        // as a typed exception attribute; renaming the field would break
        // both binding-flavor crates without a compile error if they
        // stop using exhaustive `match`.
        let ffi = FfiVaultError::BlockNotFound {
            uuid_hex: "deadbeef".to_string(),
        };
        let FfiVaultError::BlockNotFound { uuid_hex } = ffi else {
            panic!("expected BlockNotFound variant");
        };
        assert_eq!(uuid_hex, "deadbeef");
    }
```

- [ ] **Step 4: Run the tests to confirm both new tests pass**

```bash
cargo test --release -p secretary-ffi-bridge --lib error 2>&1 | tail -20
```

Expected: all existing tests still pass + the 2 new tests pass. Total `error` module test count goes from ~22 to 24.

- [ ] **Step 5: Run clippy + fmt locally**

```bash
cargo clippy --release -p secretary-ffi-bridge -- -D warnings && echo "clippy OK"
cargo fmt --all -- --check && echo "fmt OK"
```

Expected: both clean.

- [ ] **Step 6: Commit Task 1**

```bash
cd /Users/hherb/src/secretary
git add ffi/secretary-ffi-bridge/src/error.rs
git commit -m "$(cat <<'EOF'
feat(ffi-b4b-task1): add 7th FfiVaultError::BlockNotFound variant

Adds the typed error variant for "this UUID is not listed in the
manifest" — distinct from CorruptVault (which fires when a manifest-
listed block file is missing or unreadable on disk). Wrong-length UUID
inputs at the FFI boundary surface as ValueError / IllegalArgumentException
at the binding layer; the bridge function takes &[u8; 16] compile-time
enforced.

uuid_hex is stored as String (32-char lowercase hex) for consistency
with the other variants' detail: String payloads; foreign callers can
bytes.fromhex(uuid_hex) if needed.

Tripwire tests pin the Display string and the field name so a future
rename or message degradation must be a deliberate decision.

Refs: docs/superpowers/specs/2026-05-09-ffi-b4b-read-block-design.md
section "FfiVaultError after B.4b" + decision §3.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: `vault.rs` — extend `OpenVaultManifestInner` with `vault_folder: PathBuf`

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/vault.rs` (currently 583 lines; will grow to ~620)

The bridge already receives `folder: &Path` in both `open_vault_with_password` and `open_vault_with_recovery`. We thread a `PathBuf` clone of that path into `OpenVaultManifestInner` so Task 3's `read_block` can resolve `blocks/<uuid>.cbor.enc` without re-asking the caller. Bridge-internal change — no public B.4a accessor surface change. A new `pub(crate)` accessor on `OpenVaultManifest` exposes the path to record.rs at the bridge layer only.

- [ ] **Step 1: Add `vault_folder: PathBuf` to `OpenVaultManifestInner`**

In `ffi/secretary-ffi-bridge/src/vault.rs`, find the `pub(crate) struct OpenVaultManifestInner { ... }` block (around line 98). Add a new field at the end of the struct (AFTER `owner_card`):

```rust
    /// Owner's self-signed contact card, already self-verified during
    /// `core::open_vault`. Held internally for B.4c/d signature operations;
    /// **not** exposed through B.4a accessors (deferred to B.4d).
    #[allow(dead_code)] // B.4c/d will use this; intentional now for forward-compat
    owner_card: ContactCard,
    /// NEW in B.4b: vault folder path the manifest was opened from.
    /// Used by `read_block` to resolve `blocks/<uuid>.cbor.enc`.
    /// B.4c (`save_block`) and B.4d (`share_block`) will reuse this for
    /// atomic-write paths through `tempfile::persist`.
    vault_folder: std::path::PathBuf,
```

- [ ] **Step 2: Thread `vault_folder` through `split_core_open_vault`**

The function `split_core_open_vault` (around line 285) currently takes only `core_out: secretary_core::vault::OpenVault`. Change its signature to also take the folder path, and forward it into the constructed `OpenVaultManifestInner`:

Find this signature:

```rust
fn split_core_open_vault(core_out: secretary_core::vault::OpenVault) -> OpenVaultOutput {
```

Replace with:

```rust
fn split_core_open_vault(
    core_out: secretary_core::vault::OpenVault,
    vault_folder: std::path::PathBuf,
) -> OpenVaultOutput {
```

In the function body, find the `OpenVaultManifestInner { ... }` initializer (around line 311) and add the `vault_folder` field at the end:

```rust
        manifest: OpenVaultManifest::new(OpenVaultManifestInner {
            identity_block_key: ibk_for_manifest,
            manifest,
            manifest_file,
            owner_card,
            vault_folder,
        }),
```

- [ ] **Step 3: Update both callers of `split_core_open_vault`**

In `open_vault_with_password` (around line 246) find:

```rust
    let core_out = secretary_core::vault::open_vault(folder, Unlocker::Password(&pw), None)?;
    Ok(split_core_open_vault(core_out))
```

Replace with:

```rust
    let core_out = secretary_core::vault::open_vault(folder, Unlocker::Password(&pw), None)?;
    Ok(split_core_open_vault(core_out, folder.to_path_buf()))
```

In `open_vault_with_recovery` (around line 267) find:

```rust
    let core_out = secretary_core::vault::open_vault(folder, Unlocker::Recovery(phrase), None)?;
    Ok(split_core_open_vault(core_out))
```

Replace with:

```rust
    let core_out = secretary_core::vault::open_vault(folder, Unlocker::Recovery(phrase), None)?;
    Ok(split_core_open_vault(core_out, folder.to_path_buf()))
```

- [ ] **Step 4: Add a `pub(crate)` accessor on `OpenVaultManifest` for `vault_folder`**

In the `impl OpenVaultManifest { ... }` block (around line 144), AFTER the existing `wipe()` method, add a crate-private accessor:

```rust
    /// Bridge-internal accessor for the vault folder path. NOT exposed
    /// through PyO3 / uniffi — used only by `crate::record::read_block`
    /// to resolve `blocks/<uuid>.cbor.enc`. Returns `None` if the handle
    /// has been wiped (then `read_block` falls through to a typed error).
    pub(crate) fn vault_folder(&self) -> Option<std::path::PathBuf> {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.vault_folder.clone())
    }
```

- [ ] **Step 5: Add `pub(crate)` accessors needed by record.rs (manifest body, owner card, IBK, identity bundle)**

`read_block` in Task 3 needs five things from the two opaque handles to call `core::block::decrypt_block`:
1. The manifest's block list (to look up the `BlockEntry` by UUID).
2. The owner contact card (sender + reader for v1 single-author).
3. The vault folder (to resolve the block file path) — already added in Step 4.
4. The X25519 secret key from `IdentityBundle`.
5. The ML-KEM-768 secret key from `IdentityBundle`.

The vault folder is in step 4. The other manifest pieces need crate-private accessors on `OpenVaultManifest`. The identity-bundle pieces need crate-private accessors on `UnlockedIdentity`. Add the manifest-side accessors here in vault.rs; the identity-side accessor is part of Task 3 prep (we'll edit identity.rs in Step 7 below).

In the `impl OpenVaultManifest { ... }` block, AFTER the `vault_folder` accessor from Step 4, add:

```rust
    /// Bridge-internal accessor for the manifest body. NOT exposed
    /// through PyO3 / uniffi. Returns a clone of the manifest (block
    /// list + vector clock + kdf_params attestation). Returns `None`
    /// if the handle has been wiped.
    ///
    /// Used by `crate::record::read_block` to look up the BlockEntry
    /// by UUID. The clone is cheap (block list is typically a handful
    /// of entries; KAT vault has 1).
    pub(crate) fn manifest_body(&self) -> Option<Manifest> {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.manifest.clone())
    }

    /// Bridge-internal accessor for the verified owner contact card.
    /// NOT exposed through PyO3 / uniffi. Returns `None` if the
    /// handle has been wiped.
    ///
    /// Used by `crate::record::read_block` as both the sender card and
    /// the reader card (v1 single-author block reading; multi-author
    /// flow deferred to B.4d).
    pub(crate) fn owner_card(&self) -> Option<ContactCard> {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.owner_card.clone())
    }
```

- [ ] **Step 6: Drop the `#[allow(dead_code)]` annotations now that the fields are read**

In `OpenVaultManifestInner`, the `manifest_file` field still stays `#[allow(dead_code)]` (B.4c will use it) but `manifest` and `owner_card` are now read by the new `pub(crate)` accessors. The `identity_block_key` field is still NOT read directly here — `read_block` uses the IBK from `UnlockedIdentity`, not from the manifest's IBK copy. So:

Find:

```rust
    #[allow(dead_code)] // B.4b will use this; intentional now for forward-compat
    identity_block_key: Sensitive<[u8; 32]>,
```

Leave unchanged (still dead until B.4c writes encrypted blocks + needs to derive a fresh BCK). Actually the comment now reads inaccurately — update it:

Find:

```rust
    /// 32-byte Identity Block Key. Sensitive; zeroized on drop. Held for
    /// B.4b's `read_block` to use without re-opening the vault.
    #[allow(dead_code)] // B.4b will use this; intentional now for forward-compat
    identity_block_key: Sensitive<[u8; 32]>,
```

Replace with:

```rust
    /// 32-byte Identity Block Key. Sensitive; zeroized on drop. Held for
    /// B.4c's `save_block` (which derives a fresh BCK and rewraps under
    /// each recipient using the IBK as the manifest-encryption key).
    /// `read_block` (B.4b) does NOT need the IBK directly — it goes
    /// through `core::block::decrypt_block` with the reader's secret
    /// keys from `UnlockedIdentity`.
    #[allow(dead_code)] // B.4c will use this; intentional now for forward-compat
    identity_block_key: Sensitive<[u8; 32]>,
```

The `manifest` field already has no `#[allow(dead_code)]` (B.4a's `block_summaries` / `find_block` read it). Owner_card had `#[allow(dead_code)]`; now read by `owner_card()` accessor — drop the annotation:

Find:

```rust
    /// Owner's self-signed contact card, already self-verified during
    /// `core::open_vault`. Held internally for B.4c/d signature operations;
    /// **not** exposed through B.4a accessors (deferred to B.4d).
    #[allow(dead_code)] // B.4c/d will use this; intentional now for forward-compat
    owner_card: ContactCard,
```

Replace with:

```rust
    /// Owner's self-signed contact card, already self-verified during
    /// `core::open_vault`. B.4b reads it via the bridge-internal
    /// `owner_card()` accessor in `read_block` (sender + reader for the
    /// v1 single-author flow). B.4c/d will use it for save/share
    /// signature operations. NOT exposed through public B.4a/B.4b
    /// accessors (deferred to B.4d's contact-card surface).
    owner_card: ContactCard,
```

- [ ] **Step 7: Add `pub(crate)` IdentityBundle accessor on `UnlockedIdentity`**

Edit `ffi/secretary-ffi-bridge/src/identity.rs`. In the `impl UnlockedIdentity { ... }` block (around line 49), AFTER the existing `close()` method, add:

```rust
    /// Bridge-internal accessor returning a fresh clone of the X25519 +
    /// ML-KEM-768 reader secret keys + the corresponding public-key
    /// material needed for `core::block::decrypt_block`. NOT exposed
    /// through PyO3 / uniffi — used only by `crate::record::read_block`.
    ///
    /// Returns `None` if the handle has been closed. The returned
    /// `(X25519Secret, MlKem768Secret)` tuple is `Sensitive`-wrapped on
    /// the `Sensitive::new` path; the caller drops it after the
    /// `decrypt_block` call returns and zeroize-on-drop takes care of
    /// the secret bytes.
    pub(crate) fn reader_secret_keys(
        &self,
    ) -> Option<(
        secretary_core::crypto::kem::X25519Secret,
        secretary_core::crypto::kem::MlKem768Secret,
    )> {
        use secretary_core::crypto::kem;
        use secretary_core::crypto::secret::Sensitive;
        use zeroize::Zeroize as _;

        let guard = lock_or_recover(&self.inner);
        let id = guard.as_ref()?;

        // X25519: copy the 32 bytes onto the stack, mint a Sensitive,
        // then zeroize the stack copy. Mirrors the same discipline as
        // `crate::vault::split_core_open_vault`.
        let mut x_sk_bytes: [u8; 32] = *id.identity.x25519_sk.expose();
        let x_sk: kem::X25519Secret = Sensitive::new(x_sk_bytes);
        x_sk_bytes.zeroize();

        // ML-KEM-768: from_bytes returns Result<_, KemError>. The bundle
        // was already validated at unlock-time (core::unlock checks the
        // length on decode), so a failure here would be impossible
        // unless the in-memory bundle was corrupted post-unlock — fold
        // to None for parity with the close-state shape (read_block will
        // surface this as CorruptVault upstream).
        let pq_sk = kem::MlKem768Secret::from_bytes(id.identity.ml_kem_768_sk.expose()).ok()?;

        Some((x_sk, pq_sk))
    }
```

- [ ] **Step 8: Run the bridge crate tests to confirm Task 2 changes compile + don't regress**

```bash
cargo test --release -p secretary-ffi-bridge 2>&1 | tail -25
```

Expected: all existing tests still pass (no new tests added in Task 2 — the new accessors get exercised through Task 3's `read_block` integration tests).

- [ ] **Step 9: Add a regression test for the new `vault_folder` accessor**

In `ffi/secretary-ffi-bridge/src/vault.rs`, find the existing `#[cfg(test)] mod tests` block. After the existing `open_vault_manifest_wipe_returns_empty_defaults` test (around line 567), append:

```rust

    #[test]
    fn vault_folder_accessor_returns_path_when_live_and_none_when_wiped() {
        // Pin the bridge-internal vault_folder accessor's contract.
        // record::read_block (B.4b Task 3) depends on this returning
        // Some(path) before wipe and None after, so a regression here
        // would surface as a bogus FfiVaultError::CorruptVault from
        // read_block rather than a clean failure.
        let folder = fixture_folder("golden_vault_001");
        let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();
        let returned = out.manifest.vault_folder().expect("Some(path) before wipe");
        assert_eq!(
            returned, folder,
            "vault_folder() must return the path passed to open_vault_with_password",
        );
        out.manifest.wipe();
        assert_eq!(
            out.manifest.vault_folder(),
            None,
            "vault_folder() must return None after wipe",
        );
    }

    #[test]
    fn manifest_body_and_owner_card_accessors_return_some_when_live() {
        // Pin the two new bridge-internal accessors. read_block needs
        // them to drive core::block::decrypt_block; a None here when
        // the handle is live would manifest as CorruptVault from
        // read_block.
        let folder = fixture_folder("golden_vault_001");
        let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();
        let body = out.manifest.manifest_body().expect("Some(body) before wipe");
        assert_eq!(body.vault_uuid, body.vault_uuid); // trivial; pins the type
        let _card = out.manifest.owner_card().expect("Some(card) before wipe");
        out.manifest.wipe();
        assert_eq!(out.manifest.manifest_body(), None);
        assert!(out.manifest.owner_card().is_none());
    }
```

- [ ] **Step 10: Run the bridge tests again to confirm new tests pass**

```bash
cargo test --release -p secretary-ffi-bridge 2>&1 | grep -E "^test result:" | head -5
```

Expected: bridge crate test count went up by 2 (from 56 → 58).

- [ ] **Step 11: Run clippy + fmt**

```bash
cargo clippy --release -p secretary-ffi-bridge -- -D warnings && echo "clippy OK"
cargo fmt --all -- --check && echo "fmt OK"
```

Expected: both clean.

- [ ] **Step 12: Commit Task 2**

```bash
cd /Users/hherb/src/secretary
git add ffi/secretary-ffi-bridge/src/vault.rs ffi/secretary-ffi-bridge/src/identity.rs
git commit -m "$(cat <<'EOF'
feat(ffi-b4b-task2): thread vault_folder + bridge-internal accessors for read_block

Extends OpenVaultManifestInner with vault_folder: PathBuf so B.4b's
read_block (Task 3) can resolve blocks/<uuid>.cbor.enc without re-asking
the caller. Bridge-internal change — no public B.4a accessor surface
change. B.4c (save_block) and B.4d (share_block) will reuse this for
atomic-write paths.

Adds pub(crate) accessors:
- OpenVaultManifest::vault_folder() -> Option<PathBuf>
- OpenVaultManifest::manifest_body() -> Option<Manifest>
- OpenVaultManifest::owner_card() -> Option<ContactCard>
- UnlockedIdentity::reader_secret_keys() -> Option<(X25519Secret, MlKem768Secret)>

The reader_secret_keys path mirrors the existing stack-residue zeroize
discipline from split_core_open_vault: copy the 32-byte X25519 secret
onto the stack, mint a Sensitive, then zeroize the stack copy.

The IBK field's #[allow(dead_code)] comment is updated to reflect that
B.4c (not B.4b) is the consumer — read_block goes through the reader's
identity-bundle secret keys via core::block::decrypt_block, not through
the IBK directly.

Refs: docs/superpowers/specs/2026-05-09-ffi-b4b-read-block-design.md
section "OpenVaultManifestInner extension".

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: NEW `record/` directory module — `read_block` + `BlockReadOutput` + `Record` + `FieldHandle`

**Files (split into a directory module to keep each file under ~250 lines per project policy):**
- Create: `ffi/secretary-ffi-bridge/src/record/mod.rs` (~80 lines — module decls, re-exports, shared imports)
- Create: `ffi/secretary-ffi-bridge/src/record/output.rs` (~95 lines — `BlockReadOutput` + `BlockReadOutputInner`)
- Create: `ffi/secretary-ffi-bridge/src/record/handle.rs` (~140 lines — `Record` + `RecordInner`)
- Create: `ffi/secretary-ffi-bridge/src/record/field.rs` (~125 lines — `FieldHandle` + `FieldHandleInner`)
- Create: `ffi/secretary-ffi-bridge/src/record/orchestration.rs` (~190 lines — `read_block` free fn + `uuid_hyphenated` helper)
- Create: `ffi/secretary-ffi-bridge/tests/read_block.rs` (~250 lines — 14 KAT-pinned integration tests against `golden_vault_001`)

This is the largest task in the plan. Builds the core read_block surface end-to-end: the free function that locks both handles, looks up the block, reads + decodes + decrypts, and converts the `BlockPlaintext` into the foreign-projection types. The 14 KAT-pinned tests live as crate-integration tests in `tests/read_block.rs` so the production sub-files stay small and focused.

- [ ] **Step 1: Create the directory + `record/mod.rs` with module declarations + shared imports**

Create the directory:

```bash
mkdir -p ffi/secretary-ffi-bridge/src/record
```

Create `ffi/secretary-ffi-bridge/src/record/mod.rs` with the following content (the module-level doc that was previously planned for `record.rs` now lives here):

```rust
//! Bridge surface for `read_block` (Sub-project B.4b).
//!
//! Exposes the free function [`read_block`] and the three opaque handle
//! types that carry the decrypted records out to PyO3 / uniffi:
//! [`BlockReadOutput`], [`Record`], [`FieldHandle`].
//!
//! # Hybrid Record projection
//!
//! Foreign-language `Record` carries non-secret metadata as plain
//! accessors (record_uuid, record_type, tags, timestamps, tombstone)
//! plus an ordered list of [`FieldHandle`]s. Each [`FieldHandle`]
//! carries name + last_mod + device_uuid as plain accessors, and
//! `expose_text()` / `expose_bytes()` for the secret payload. The
//! foreign caller must opt-in per-field to surfacing the secret —
//! there is no eager copy-out at `read_block` time.
//!
//! # Lifecycle
//!
//! [`BlockReadOutput::wipe`] cascades to every contained [`Record`]
//! and [`FieldHandle`], which themselves cascade to the underlying
//! [`secretary_core::vault::record::RecordFieldValue`]'s [`zeroize`]
//! impl. Wipe is idempotent everywhere; foreign callers using the
//! context-manager / `defer` / `use` idiom get full cleanup
//! automatically.
//!
//! `Record` and `FieldHandle` use `Arc<Mutex<Option<Inner>>>` so
//! accessors can hand out cheap clones the foreign caller can store.
//! `BlockReadOutput` uses the simpler `Mutex<Option<Inner>>` (no
//! shared-clone access pattern). The Arc clone shares the same
//! `Option::take()` slot — wiping any clone wipes them all
//! immediately.
//!
//! # Single-author block reading (v1)
//!
//! B.4b assumes the block author = vault owner (the v1 single-author
//! case covered by `golden_vault_001`). The bridge takes
//! `manifest.owner_card` as both the sender and reader card when
//! calling `core::block::decrypt_block`. If the on-disk block's
//! `author_fingerprint` doesn't match `fingerprint(owner_card)`,
//! `decrypt_block` returns `BlockError::AuthorFingerprintMismatch`
//! which folds into [`FfiVaultError::CorruptVault`]. B.4d's
//! `share_block` flow will add `contacts/<author_uuid>.card`
//! discovery + the multi-author read path.

mod field;
mod handle;
mod orchestration;
mod output;

pub use field::FieldHandle;
pub use handle::Record;
pub use orchestration::read_block;
pub use output::BlockReadOutput;
```

- [ ] **Step 2: Create `record/output.rs` defining `BlockReadOutput`**

Create `ffi/secretary-ffi-bridge/src/record/output.rs` with the file-level doc + the `BlockReadOutput` definition:

```rust
//! [`BlockReadOutput`] — container handle for one block's decrypted records.
//!
//! Holds owned [`Record`](super::Record)s; [`BlockReadOutput::wipe`]
//! cascades wipe to every contained record + field. Uses the simpler
//! `Mutex<Option<Inner>>` (not `Arc<Mutex<Option<...>>>`) because there
//! is no shared-clone access pattern at this level — the foreign
//! caller holds exactly one `BlockReadOutput`.

use std::sync::Mutex;

use super::Record;
use crate::sync_helpers::lock_or_recover;

/// Container handle for one block's decrypted records. Holds owned
/// [`Record`]s; [`BlockReadOutput::wipe`] cascades to every contained
/// record + field. Idempotent.
pub struct BlockReadOutput {
    inner: Mutex<Option<BlockReadOutputInner>>,
}

/// File-private inner. Constructor takes individual args so the type
/// stays fully encapsulated.
struct BlockReadOutputInner {
    block_uuid: [u8; 16],
    block_name: String,
    records: Vec<Record>,
}

/// Redacted Debug — never leak any secret material in `{:?}` output.
impl std::fmt::Debug for BlockReadOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let is_closed = lock_or_recover(&self.inner).is_none();
        f.debug_struct("BlockReadOutput")
            .field("closed", &is_closed)
            .finish()
    }
}

impl BlockReadOutput {
    /// Build a `BlockReadOutput` from its component fields. Crate-private:
    /// only [`super::read_block`] constructs this. Takes individual args
    /// so the inner struct stays fully private to this file.
    pub(crate) fn new(
        block_uuid: [u8; 16],
        block_name: String,
        records: Vec<Record>,
    ) -> Self {
        Self {
            inner: Mutex::new(Some(BlockReadOutputInner {
                block_uuid,
                block_name,
                records,
            })),
        }
    }

    /// 16-byte block UUID. Returns 16 zero bytes if wiped.
    pub fn block_uuid(&self) -> [u8; 16] {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.block_uuid)
            .unwrap_or([0u8; 16])
    }

    /// User-visible block name. Returns `""` if wiped.
    pub fn block_name(&self) -> String {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.block_name.clone())
            .unwrap_or_default()
    }

    /// Number of records in the block. Returns 0 if wiped.
    pub fn record_count(&self) -> usize {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.records.len())
            .unwrap_or(0)
    }

    /// Returns a clone of the [`Record`] handle at `idx`, or `None` if
    /// `idx` is out of range or the output has been wiped. The clone
    /// shares the same `Arc<Mutex<Option<RecordInner>>>` as the
    /// original — wiping either invalidates both.
    pub fn record_at(&self, idx: usize) -> Option<Record> {
        lock_or_recover(&self.inner)
            .as_ref()
            .and_then(|i| i.records.get(idx).cloned())
    }

    /// Drop the wrapped records now, cascading wipe to every inner
    /// [`Record`] and [`FieldHandle`]. **Idempotent** — multiple calls
    /// do not panic.
    pub fn wipe(&self) {
        if let Some(inner) = lock_or_recover(&self.inner).take() {
            // Walk the records and wipe each before they go out of scope.
            // The Drop cascade would also wipe via Record's own Drop, but
            // explicit wipe lets the spec claim "wipe is the single
            // cleanup point" without depending on drop ordering.
            for r in &inner.records {
                r.wipe();
            }
            // inner drops here → records Vec drops → each Record's Drop
            // runs, but its inner Option is already None so it's a no-op.
        }
    }
}
```

- [ ] **Step 3: Create `record/handle.rs` defining `Record`**

Create `ffi/secretary-ffi-bridge/src/record/handle.rs`:

```rust
//! [`Record`] — per-record handle. `Arc<Mutex<Option<Inner>>>` so
//! accessors can return cheap clones; every clone shares the same wiped
//! state via `Option::take` on the shared inner.

use std::sync::{Arc, Mutex};

use super::FieldHandle;
use crate::sync_helpers::lock_or_recover;

/// Per-record handle. Shared via `Arc` so accessors can return cheap
/// clones the foreign caller can store independently.
#[derive(Clone)]
pub struct Record {
    inner: Arc<Mutex<Option<RecordInner>>>,
}

struct RecordInner {
    record_uuid: [u8; 16],
    record_type: String,
    tags: Vec<String>,
    created_at_ms: u64,
    last_mod_ms: u64,
    tombstone: bool,
    /// Field handles in the BTreeMap iteration order (matches the
    /// canonical-CBOR order modulo the `len-then-bytes` reorder, which
    /// is irrelevant once the data is in memory). The corresponding
    /// `field_names` Vec is computed from this list at accessor time.
    fields: Vec<FieldHandle>,
}

impl std::fmt::Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let is_closed = lock_or_recover(&self.inner).is_none();
        f.debug_struct("Record").field("closed", &is_closed).finish()
    }
}

impl Record {
    /// Build a `Record` from its component fields. Crate-private:
    /// only [`super::read_block`] constructs this from the decrypted
    /// `core::vault::record::Record`. Takes individual args so the
    /// inner struct stays fully private to this file.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        record_uuid: [u8; 16],
        record_type: String,
        tags: Vec<String>,
        created_at_ms: u64,
        last_mod_ms: u64,
        tombstone: bool,
        fields: Vec<FieldHandle>,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(RecordInner {
                record_uuid,
                record_type,
                tags,
                created_at_ms,
                last_mod_ms,
                tombstone,
                fields,
            }))),
        }
    }

    /// 16-byte record UUID. Returns 16 zero bytes if wiped.
    pub fn record_uuid(&self) -> [u8; 16] {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.record_uuid)
            .unwrap_or([0u8; 16])
    }

    /// Open-ended record-type discriminator (e.g. `"login"`). Returns
    /// `""` if wiped.
    pub fn record_type(&self) -> String {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.record_type.clone())
            .unwrap_or_default()
    }

    /// Cross-cutting tags. Returns an empty `Vec` if wiped.
    pub fn tags(&self) -> Vec<String> {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.tags.clone())
            .unwrap_or_default()
    }

    /// Record creation timestamp, Unix milliseconds. Returns 0 if wiped.
    pub fn created_at_ms(&self) -> u64 {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.created_at_ms)
            .unwrap_or(0)
    }

    /// Record-level last-modification timestamp, Unix milliseconds.
    /// Returns 0 if wiped.
    pub fn last_mod_ms(&self) -> u64 {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.last_mod_ms)
            .unwrap_or(0)
    }

    /// `false` = live, `true` = deleted. Returns `false` if wiped.
    /// Note: `tombstoned_at_ms` (CRDT death-clock) is NOT projected —
    /// sync-orchestration internal.
    pub fn tombstone(&self) -> bool {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.tombstone)
            .unwrap_or(false)
    }

    /// Number of fields in the record. Returns 0 if wiped.
    pub fn field_count(&self) -> usize {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.fields.len())
            .unwrap_or(0)
    }

    /// Field names in BTreeMap iteration order. Returns an empty `Vec`
    /// if wiped.
    pub fn field_names(&self) -> Vec<String> {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.fields.iter().map(|f| f.name()).collect())
            .unwrap_or_default()
    }

    /// Returns a clone of the [`FieldHandle`] by name, or `None` if no
    /// field has this name or the record has been wiped. The clone
    /// shares the same Arc as the original — wiping either invalidates
    /// both.
    pub fn field_by_name(&self, name: &str) -> Option<FieldHandle> {
        lock_or_recover(&self.inner)
            .as_ref()
            .and_then(|i| i.fields.iter().find(|f| f.name() == name).cloned())
    }

    /// Returns a clone of the [`FieldHandle`] at `idx`, or `None` if
    /// out of range or wiped.
    pub fn field_at(&self, idx: usize) -> Option<FieldHandle> {
        lock_or_recover(&self.inner)
            .as_ref()
            .and_then(|i| i.fields.get(idx).cloned())
    }

    /// Drop the wrapped record now, cascading wipe to every contained
    /// [`FieldHandle`]. **Idempotent** — multiple calls do not panic.
    pub fn wipe(&self) {
        if let Some(inner) = lock_or_recover(&self.inner).take() {
            for f in &inner.fields {
                f.wipe();
            }
        }
    }
}
```

- [ ] **Step 4: Create `record/field.rs` defining `FieldHandle`**

Create `ffi/secretary-ffi-bridge/src/record/field.rs`:

```rust
//! [`FieldHandle`] — per-field handle. Holds the `RecordFieldValue`
//! (`SecretString` or `SecretBytes`); [`FieldHandle::expose_text`] /
//! [`FieldHandle::expose_bytes`] is the explicit secret-pull boundary.
//!
//! `Arc<Mutex<Option<Inner>>>` so accessors can return cheap clones
//! that share the same wiped state.

use std::sync::{Arc, Mutex};

use secretary_core::vault::record::RecordFieldValue;

use crate::sync_helpers::lock_or_recover;

/// Per-field handle. Shared via `Arc` so accessors can return cheap
/// clones the foreign caller can store independently. Wiping any clone
/// wipes them all (uses `Option::take` on the shared inner).
#[derive(Clone)]
pub struct FieldHandle {
    inner: Arc<Mutex<Option<FieldHandleInner>>>,
}

struct FieldHandleInner {
    name: String,
    value: RecordFieldValue,
    last_mod_ms: u64,
    device_uuid: [u8; 16],
}

impl std::fmt::Debug for FieldHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let is_closed = lock_or_recover(&self.inner).is_none();
        f.debug_struct("FieldHandle")
            .field("closed", &is_closed)
            .finish()
    }
}

impl FieldHandle {
    /// Build a `FieldHandle` from its component fields. Crate-private:
    /// only [`super::read_block`] constructs this.
    pub(crate) fn new(
        name: String,
        value: RecordFieldValue,
        last_mod_ms: u64,
        device_uuid: [u8; 16],
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(FieldHandleInner {
                name,
                value,
                last_mod_ms,
                device_uuid,
            }))),
        }
    }

    /// Field name (e.g. `"password"`, `"username"`). Returns `""` if
    /// wiped.
    pub fn name(&self) -> String {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.name.clone())
            .unwrap_or_default()
    }

    /// Per-field last-modification timestamp, Unix milliseconds.
    /// Returns 0 if wiped.
    pub fn last_mod_ms(&self) -> u64 {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.last_mod_ms)
            .unwrap_or(0)
    }

    /// 16-byte UUID of the device that last modified this field.
    /// Returns 16 zero bytes if wiped.
    pub fn device_uuid(&self) -> [u8; 16] {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.device_uuid)
            .unwrap_or([0u8; 16])
    }

    /// `true` if the field's payload is text. Returns `false` if wiped.
    pub fn is_text(&self) -> bool {
        lock_or_recover(&self.inner)
            .as_ref()
            .is_some_and(|i| matches!(i.value, RecordFieldValue::Text(_)))
    }

    /// `true` if the field's payload is bytes. Returns `false` if wiped.
    pub fn is_bytes(&self) -> bool {
        lock_or_recover(&self.inner)
            .as_ref()
            .is_some_and(|i| matches!(i.value, RecordFieldValue::Bytes(_)))
    }

    /// Pull the secret payload as UTF-8 [`String`]. Returns `None` if
    /// the field is bytes (caller should use [`expose_bytes`]) or has
    /// been wiped.
    ///
    /// Returns a fresh `String` allocation; **caller is responsible for
    /// clearing it** (e.g. Python `del`, Swift `String` going out of
    /// scope, Kotlin GC). The underlying `SecretString` in the
    /// `FieldHandle` is NOT wiped by this call — call [`wipe`]
    /// explicitly when done with the handle.
    ///
    /// Invalid-UTF-8 cannot reach this accessor by construction: CBOR
    /// `tstr` (major type 3) requires valid UTF-8 per RFC 8949 §3.1,
    /// and `core::vault::record::parse_record_field` only constructs
    /// `RecordFieldValue::Text(SecretString::new(s))` from an already-
    /// validated `Value::Text(s)`. The fuzz harness has a defense-in-
    /// depth assertion (B.4b Task 5) that would catch any future
    /// regression.
    pub fn expose_text(&self) -> Option<String> {
        lock_or_recover(&self.inner)
            .as_ref()
            .and_then(|i| match &i.value {
                RecordFieldValue::Text(s) => Some(s.expose().to_owned()),
                RecordFieldValue::Bytes(_) => None,
            })
    }

    /// Pull the secret payload as raw bytes. Returns `None` if the
    /// field is text (caller should use [`expose_text`]) or has been
    /// wiped.
    ///
    /// Returns a fresh `Vec<u8>`; caller is responsible for clearing
    /// it. The underlying `SecretBytes` in the `FieldHandle` is NOT
    /// wiped by this call.
    pub fn expose_bytes(&self) -> Option<Vec<u8>> {
        lock_or_recover(&self.inner)
            .as_ref()
            .and_then(|i| match &i.value {
                RecordFieldValue::Bytes(b) => Some(b.expose().to_vec()),
                RecordFieldValue::Text(_) => None,
            })
    }

    /// Drop the wrapped field now. **Idempotent** — multiple calls do
    /// not panic. After this returns, every accessor returns the empty
    /// default and `expose_text` / `expose_bytes` return `None`.
    /// Cascades through every cloned `FieldHandle` because they share
    /// the underlying `Arc<Mutex<Option<...>>>`.
    pub fn wipe(&self) {
        let _drop = lock_or_recover(&self.inner).take();
        // _drop goes out of scope → FieldHandleInner drops → its `value`
        // (RecordFieldValue) drops → SecretString / SecretBytes
        // ZeroizeOnDrop runs.
    }
}
```


- [ ] **Step 5: Add a test for `FieldHandle` discrimination + Arc-clone wipe**

The KAT-pinned tests live in `tests/read_block.rs` (Step 7 onward). For now, add small-surface unit tests inside `record/field.rs` that don't need `golden_vault_001`:

Append to `ffi/secretary-ffi-bridge/src/record/field.rs`:

```rust

#[cfg(test)]
mod tests {
    use super::*;
    use secretary_core::crypto::secret::{SecretBytes, SecretString};

    fn dummy_text(name: &str, value: &str) -> FieldHandle {
        FieldHandle::new(
            name.to_string(),
            RecordFieldValue::Text(SecretString::new(value.to_string())),
            42,
            [0xab; 16],
        )
    }

    fn dummy_bytes(name: &str, value: &[u8]) -> FieldHandle {
        FieldHandle::new(
            name.to_string(),
            RecordFieldValue::Bytes(SecretBytes::new(value.to_vec())),
            42,
            [0xab; 16],
        )
    }

    #[test]
    fn text_field_is_text_not_bytes() {
        let f = dummy_text("password", "hunter2");
        assert!(f.is_text());
        assert!(!f.is_bytes());
        assert_eq!(f.expose_text(), Some("hunter2".to_string()));
        assert_eq!(f.expose_bytes(), None);
    }

    #[test]
    fn bytes_field_is_bytes_not_text() {
        let f = dummy_bytes("totp", &[0xde, 0xad, 0xbe, 0xef]);
        assert!(f.is_bytes());
        assert!(!f.is_text());
        assert_eq!(f.expose_bytes(), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(f.expose_text(), None);
    }

    #[test]
    fn wipe_drops_secret_and_returns_empty_defaults() {
        let f = dummy_text("password", "hunter2");
        f.wipe();
        assert_eq!(f.expose_text(), None);
        assert_eq!(f.name(), "");
        assert_eq!(f.last_mod_ms(), 0);
        assert_eq!(f.device_uuid(), [0u8; 16]);
        // Idempotent.
        f.wipe();
        f.wipe();
    }

    #[test]
    fn arc_clone_shares_wiped_state() {
        let f1 = dummy_text("password", "hunter2");
        let f2 = f1.clone();
        assert_eq!(f1.expose_text(), Some("hunter2".to_string()));
        assert_eq!(f2.expose_text(), Some("hunter2".to_string()));
        f1.wipe();
        assert_eq!(f1.expose_text(), None);
        assert_eq!(f2.expose_text(), None);
    }

    #[test]
    fn metadata_accessors_return_constructor_args() {
        let f = dummy_text("password", "hunter2");
        assert_eq!(f.name(), "password");
        assert_eq!(f.last_mod_ms(), 42);
        assert_eq!(f.device_uuid(), [0xab; 16]);
    }
}
```

These 5 tests cover `field.rs` in isolation without needing the full vault open. Run them:

```bash
cargo test --release -p secretary-ffi-bridge --lib record::field 2>&1 | tail -10
```

Expected: 5 passed.

- [ ] **Step 6: Create `record/orchestration.rs` with `read_block` + `uuid_hyphenated`**

Create `ffi/secretary-ffi-bridge/src/record/orchestration.rs`:

```rust
//! [`read_block`] — free-function entry point that locks both handles,
//! looks up the manifest BlockEntry, reads + decodes + decrypts the
//! block file, and converts the [`BlockPlaintext`] into the foreign-
//! projection types ([`super::BlockReadOutput`], [`super::Record`],
//! [`super::FieldHandle`]).
//!
//! v1 single-author: sender = reader = vault owner. Multi-author flow
//! deferred to B.4d's `share_block`.

use std::path::PathBuf;

use secretary_core::crypto::sig::MlDsa65Public;
use secretary_core::identity::card::ContactCard;
use secretary_core::identity::fingerprint::fingerprint;
use secretary_core::vault::block;
use secretary_core::vault::record::Record as CoreRecord;
use secretary_core::vault::Manifest;

use super::{BlockReadOutput, FieldHandle, Record};
use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;
use crate::vault::OpenVaultManifest;

/// Decrypt and return all records in one block of an open vault.
///
/// Borrows both handles; returns a fresh [`BlockReadOutput`] container
/// or a typed [`FfiVaultError`].
///
/// # Errors
///
/// - [`FfiVaultError::BlockNotFound`] — the requested UUID is not in
///   the manifest's live blocks list (trashed blocks also surface here).
/// - [`FfiVaultError::CorruptVault`] — block file missing on disk,
///   malformed envelope, signature verification failure, decap
///   failure, AAD/tag failure, or `BlockUuidMismatch`.
/// - [`FfiVaultError::FolderInvalid`] — block file present but
///   unreadable for non-NotFound IO reasons (permissions, EBUSY, etc).
///
/// Wrong-length `block_uuid` is structurally impossible at this layer
/// (the parameter is `&[u8; 16]`); the binding-layer wrappers
/// (PyO3 / uniffi) are responsible for surfacing wrong-length input
/// as `ValueError` / `IllegalArgumentException`.
pub fn read_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: &[u8; 16],
) -> Result<BlockReadOutput, FfiVaultError> {
    let manifest_body: Manifest = manifest.manifest_body().ok_or_else(handle_wiped)?;
    let owner_card: ContactCard = manifest.owner_card().ok_or_else(handle_wiped)?;
    let vault_folder: PathBuf = manifest.vault_folder().ok_or_else(handle_wiped)?;

    // Locate the manifest BlockEntry. Trash entries are not considered.
    let _entry = manifest_body
        .blocks
        .iter()
        .find(|b| b.block_uuid == *block_uuid)
        .ok_or_else(|| FfiVaultError::BlockNotFound {
            uuid_hex: hex::encode(block_uuid),
        })?;

    // Resolve the block file path using the standard 8-4-4-4-12 UUID
    // textual form — same convention core::vault::io uses for block files.
    let path = vault_folder
        .join("blocks")
        .join(format!("{}.cbor.enc", uuid_hyphenated(block_uuid)));

    // Read the block file from disk.
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(FfiVaultError::CorruptVault {
                detail: format!(
                    "block file missing for {}: {}",
                    hex::encode(block_uuid),
                    e
                ),
            });
        }
        Err(e) => {
            return Err(FfiVaultError::FolderInvalid {
                detail: format!("failed to read block file: {e}"),
            });
        }
    };

    // Decode the BlockFile envelope.
    let block_file = block::decode_block_file(&bytes).map_err(|e| {
        FfiVaultError::CorruptVault {
            detail: format!("malformed block file: {e}"),
        }
    })?;

    // Prepare sender + reader handles. v1 single-author: sender =
    // reader = vault owner.
    let owner_canonical =
        owner_card.to_canonical_cbor().map_err(|e| FfiVaultError::CorruptVault {
            detail: format!("failed to canonicalize owner card: {e}"),
        })?;
    let owner_fp = fingerprint(&owner_canonical);
    let owner_pk_bundle = owner_card.pk_bundle_bytes().map_err(|e| {
        FfiVaultError::CorruptVault {
            detail: format!("failed to extract owner pk bundle: {e}"),
        }
    })?;
    let owner_pq_pk = MlDsa65Public::from_bytes(&owner_card.ml_dsa_65_pk).map_err(|e| {
        FfiVaultError::CorruptVault {
            detail: format!("failed to parse owner ML-DSA-65 public key: {e}"),
        }
    })?;

    // Pull the reader's secret keys from the identity handle.
    let (reader_x_sk, reader_pq_sk) =
        identity.reader_secret_keys().ok_or_else(|| FfiVaultError::CorruptVault {
            detail: "identity handle has been closed".to_string(),
        })?;

    // Hybrid verify-then-decrypt. All BlockError variants fold into
    // CorruptVault per the anti-conflation discipline.
    let plaintext = block::decrypt_block(
        &block_file,
        &owner_fp,
        &owner_pk_bundle,
        &owner_card.ed25519_pk,
        &owner_pq_pk,
        &owner_fp,
        &owner_pk_bundle,
        &reader_x_sk,
        &reader_pq_sk,
    )
    .map_err(|e| FfiVaultError::CorruptVault {
        detail: format!("block decryption failed: {e}"),
    })?;
    // reader_x_sk + reader_pq_sk dropped → ZeroizeOnDrop runs.

    // Convert BlockPlaintext → BlockReadOutput. Preserve record order
    // (already canonical from decode_plaintext); within each record,
    // walk fields in BTreeMap iteration order.
    let mut records: Vec<Record> = Vec::with_capacity(plaintext.records.len());
    for r in plaintext.records {
        let CoreRecord {
            record_uuid,
            record_type,
            fields,
            tags,
            created_at_ms,
            last_mod_ms,
            tombstone,
            // unknown / tombstoned_at_ms intentionally not surfaced.
            ..
        } = r;

        let mut field_handles: Vec<FieldHandle> = Vec::with_capacity(fields.len());
        for (name, field) in fields {
            field_handles.push(FieldHandle::new(
                name,
                field.value,
                field.last_mod,
                field.device_uuid,
            ));
        }
        records.push(Record::new(
            record_uuid,
            record_type,
            tags,
            created_at_ms,
            last_mod_ms,
            tombstone,
            field_handles,
        ));
    }

    Ok(BlockReadOutput::new(
        plaintext.block_uuid,
        plaintext.block_name,
        records,
    ))
}

fn handle_wiped() -> FfiVaultError {
    FfiVaultError::CorruptVault {
        detail: "vault manifest handle has been wiped".to_string(),
    }
}

/// Format a 16-byte UUID in the standard 8-4-4-4-12 hyphenated form
/// (lowercase hex). Matches the on-disk filename convention used by
/// `core::vault::io` for block files.
fn uuid_hyphenated(uuid: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        uuid[0], uuid[1], uuid[2], uuid[3],
        uuid[4], uuid[5],
        uuid[6], uuid[7],
        uuid[8], uuid[9],
        uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_hyphenated_formats_standard_8_4_4_4_12() {
        let uuid = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
        ];
        assert_eq!(
            uuid_hyphenated(&uuid),
            "11223344-5566-7788-99aa-bbccddeeff00",
        );
        assert_eq!(
            uuid_hyphenated(&[0u8; 16]),
            "00000000-0000-0000-0000-000000000000",
        );
    }

    #[test]
    fn handle_wiped_returns_corrupt_vault_with_wiped_detail() {
        let err = handle_wiped();
        let FfiVaultError::CorruptVault { detail } = err else {
            panic!("expected CorruptVault");
        };
        assert!(detail.contains("wiped"), "detail: {detail}");
    }
}
```

- [ ] **Step 7: Verify the bridge crate compiles + the inline unit tests pass**

```bash
cargo build --release -p secretary-ffi-bridge 2>&1 | tail -10
cargo test --release -p secretary-ffi-bridge --lib record 2>&1 | grep -E "^test result:" | head -5
```

Expected: build succeeds; ~7 tests pass (5 from field.rs + 2 from orchestration.rs).

- [ ] **Step 8: Create `tests/read_block.rs` with the KAT-pinned integration tests**

Create `ffi/secretary-ffi-bridge/tests/read_block.rs`:

```rust
//! Integration tests for `read_block` pinned against the
//! `golden_vault_001` KAT. Lives in `tests/` (not inline `#[cfg(test)]`)
//! so the production sub-files in `src/record/` stay focused; the
//! tests here exercise the full open + read flow against on-disk
//! fixtures.
//!
//! KAT source of truth: `core/tests/data/golden_vault_001_inputs.json`.

use std::fs;
use std::path::PathBuf;

use secretary_ffi_bridge::{
    open_vault_with_password, open_vault_with_recovery, read_block, FfiVaultError,
};

/// Path to the golden_vault_NNN folder. CARGO_MANIFEST_DIR is
/// ffi/secretary-ffi-bridge/, so we walk up to core/tests/data/.
fn fixture_folder(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../core/tests/data")
        .join(name)
}

const VAULT_001_PASSWORD: &[u8] = b"correct horse battery staple";

/// Pinned block UUID for golden_vault_001's single block (matches the
/// hyphenated on-disk filename `11223344-5566-7788-99aa-bbccddeeff00`).
const VAULT_001_BLOCK_UUID: [u8; 16] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
];
const VAULT_001_BLOCK_NAME: &str = "Personal logins";
const VAULT_001_RECORD_UUID: [u8; 16] = [
    0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
    0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22,
];
const VAULT_001_DEVICE_UUID: [u8; 16] = [
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
];
const VAULT_001_TIMESTAMP_MS: u64 = 2_000_000_000_000;
const VAULT_001_RECORD_TYPE: &str = "login";
const VAULT_001_TAG: &str = "work";
const VAULT_001_USERNAME_VALUE: &str = "owner@example.com";
const VAULT_001_PASSWORD_VALUE: &str = "hunter2";

/// Hyphenated form of VAULT_001_BLOCK_UUID — matches the on-disk
/// filename convention. Hard-coded here so the integration tests don't
/// depend on a private bridge helper.
const VAULT_001_BLOCK_FILENAME: &str = "11223344-5566-7788-99aa-bbccddeeff00.cbor.enc";

#[test]
fn read_block_returns_one_record_two_fields_for_golden_vault_001() {
    let folder = fixture_folder("golden_vault_001");
    let out =
        open_vault_with_password(&folder, VAULT_001_PASSWORD).expect("open should succeed");
    let block = read_block(&out.identity, &out.manifest, &VAULT_001_BLOCK_UUID)
        .expect("read_block should succeed");
    assert_eq!(block.record_count(), 1);
    assert_eq!(block.block_name(), VAULT_001_BLOCK_NAME);
    assert_eq!(block.block_uuid(), VAULT_001_BLOCK_UUID);
    let record = block.record_at(0).expect("record at index 0");
    assert_eq!(record.field_count(), 2);
}

#[test]
fn read_block_record_metadata_matches_pinned_kat() {
    let folder = fixture_folder("golden_vault_001");
    let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();
    let block = read_block(&out.identity, &out.manifest, &VAULT_001_BLOCK_UUID).unwrap();
    let record = block.record_at(0).unwrap();
    assert_eq!(record.record_uuid(), VAULT_001_RECORD_UUID);
    assert_eq!(record.record_type(), VAULT_001_RECORD_TYPE);
    assert_eq!(record.tags(), vec![VAULT_001_TAG.to_string()]);
    assert!(!record.tombstone());
    assert_eq!(record.created_at_ms(), VAULT_001_TIMESTAMP_MS);
    assert_eq!(record.last_mod_ms(), VAULT_001_TIMESTAMP_MS);
}

#[test]
fn read_block_field_names_in_btreemap_order() {
    let folder = fixture_folder("golden_vault_001");
    let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();
    let block = read_block(&out.identity, &out.manifest, &VAULT_001_BLOCK_UUID).unwrap();
    let record = block.record_at(0).unwrap();
    assert_eq!(
        record.field_names(),
        vec!["password".to_string(), "username".to_string()],
    );
}

#[test]
fn read_block_field_text_payload_matches_pinned_kat() {
    let folder = fixture_folder("golden_vault_001");
    let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();
    let block = read_block(&out.identity, &out.manifest, &VAULT_001_BLOCK_UUID).unwrap();
    let record = block.record_at(0).unwrap();
    let pw_field = record
        .field_by_name("password")
        .expect("password field must exist");
    let user_field = record
        .field_by_name("username")
        .expect("username field must exist");
    assert_eq!(pw_field.expose_text(), Some(VAULT_001_PASSWORD_VALUE.to_string()));
    assert_eq!(user_field.expose_text(), Some(VAULT_001_USERNAME_VALUE.to_string()));
}

#[test]
fn read_block_field_metadata_matches_pinned_kat() {
    let folder = fixture_folder("golden_vault_001");
    let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();
    let block = read_block(&out.identity, &out.manifest, &VAULT_001_BLOCK_UUID).unwrap();
    let record = block.record_at(0).unwrap();
    let pw_field = record.field_by_name("password").unwrap();
    let user_field = record.field_by_name("username").unwrap();
    assert_eq!(pw_field.last_mod_ms(), VAULT_001_TIMESTAMP_MS);
    assert_eq!(user_field.last_mod_ms(), VAULT_001_TIMESTAMP_MS);
    assert_eq!(pw_field.device_uuid(), VAULT_001_DEVICE_UUID);
    assert_eq!(user_field.device_uuid(), VAULT_001_DEVICE_UUID);
}

#[test]
fn read_block_field_is_text_not_bytes() {
    let folder = fixture_folder("golden_vault_001");
    let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();
    let block = read_block(&out.identity, &out.manifest, &VAULT_001_BLOCK_UUID).unwrap();
    let record = block.record_at(0).unwrap();
    let pw_field = record.field_by_name("password").unwrap();
    assert!(pw_field.is_text());
    assert!(!pw_field.is_bytes());
    assert_eq!(pw_field.expose_bytes(), None);
}

#[test]
fn read_block_unknown_uuid_returns_block_not_found() {
    let folder = fixture_folder("golden_vault_001");
    let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();
    let unknown = [0u8; 16];
    let err = read_block(&out.identity, &out.manifest, &unknown).unwrap_err();
    let FfiVaultError::BlockNotFound { uuid_hex } = err else {
        panic!("expected BlockNotFound, got {err:?}");
    };
    assert_eq!(uuid_hex, "00000000000000000000000000000000");
}

/// Helper: copy the full golden_vault_001 tree into a tempdir. Returns
/// the new folder path. Used by the corruption tests below to mutate
/// the on-disk layout without touching the shared fixture.
fn copy_golden_to_tempdir() -> tempfile::TempDir {
    let src = fixture_folder("golden_vault_001");
    let tmp = tempfile::TempDir::new().expect("tempdir");
    for name in ["vault.toml", "identity.bundle.enc", "manifest.cbor.enc"] {
        fs::copy(src.join(name), tmp.path().join(name)).unwrap();
    }
    fs::create_dir_all(tmp.path().join("contacts")).unwrap();
    for entry in fs::read_dir(src.join("contacts")).unwrap() {
        let entry = entry.unwrap();
        fs::copy(
            entry.path(),
            tmp.path().join("contacts").join(entry.file_name()),
        )
        .unwrap();
    }
    fs::create_dir_all(tmp.path().join("blocks")).unwrap();
    for entry in fs::read_dir(src.join("blocks")).unwrap() {
        let entry = entry.unwrap();
        fs::copy(
            entry.path(),
            tmp.path().join("blocks").join(entry.file_name()),
        )
        .unwrap();
    }
    tmp
}

#[test]
fn read_block_corrupt_block_file_returns_corrupt_vault() {
    let tmp = copy_golden_to_tempdir();
    // Tamper the first byte of the on-disk block envelope (in the
    // 4-byte BlockFile magic). decode_block_file will reject with
    // BlockError::BadMagic which folds into CorruptVault.
    let block_path = tmp.path().join("blocks").join(VAULT_001_BLOCK_FILENAME);
    let mut bytes = fs::read(&block_path).unwrap();
    bytes[0] ^= 0xff;
    fs::write(&block_path, &bytes).unwrap();
    let out = open_vault_with_password(tmp.path(), VAULT_001_PASSWORD).unwrap();
    let err = read_block(&out.identity, &out.manifest, &VAULT_001_BLOCK_UUID).unwrap_err();
    assert!(matches!(err, FfiVaultError::CorruptVault { .. }), "got {err:?}");
}

#[test]
fn read_block_missing_block_file_returns_corrupt_vault() {
    let tmp = copy_golden_to_tempdir();
    // Delete the only block file.
    fs::remove_file(tmp.path().join("blocks").join(VAULT_001_BLOCK_FILENAME)).unwrap();
    let out = open_vault_with_password(tmp.path(), VAULT_001_PASSWORD).unwrap();
    let err = read_block(&out.identity, &out.manifest, &VAULT_001_BLOCK_UUID).unwrap_err();
    let FfiVaultError::CorruptVault { detail } = err else {
        panic!("expected CorruptVault, got {err:?}");
    };
    assert!(detail.contains("block file missing"), "detail: {detail}");
    assert!(detail.contains("11223344"), "detail: {detail}");
}

#[test]
fn block_read_output_wipe_drops_records() {
    let folder = fixture_folder("golden_vault_001");
    let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();
    let block = read_block(&out.identity, &out.manifest, &VAULT_001_BLOCK_UUID).unwrap();
    let record_clone = block.record_at(0).expect("record at 0");
    block.wipe();
    assert_eq!(block.record_count(), 0);
    assert!(block.record_at(0).is_none());
    assert_eq!(record_clone.record_uuid(), [0u8; 16]);
    assert_eq!(record_clone.field_count(), 0);
    block.wipe();
    block.wipe();
}

#[test]
fn record_wipe_drops_field_handles() {
    let folder = fixture_folder("golden_vault_001");
    let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();
    let block = read_block(&out.identity, &out.manifest, &VAULT_001_BLOCK_UUID).unwrap();
    let record = block.record_at(0).unwrap();
    let field_clone = record.field_by_name("password").unwrap();
    record.wipe();
    assert_eq!(record.field_count(), 0);
    assert!(record.field_by_name("password").is_none());
    assert!(record.field_at(0).is_none());
    assert_eq!(field_clone.expose_text(), None);
    assert_eq!(field_clone.name(), "");
    record.wipe();
}

#[test]
fn field_handle_arc_clones_share_wiped_state() {
    let folder = fixture_folder("golden_vault_001");
    let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();
    let block = read_block(&out.identity, &out.manifest, &VAULT_001_BLOCK_UUID).unwrap();
    let record_a = block.record_at(0).unwrap();
    let record_b = block.record_at(0).unwrap();
    let field_a = record_a.field_by_name("password").unwrap();
    let field_b = record_b.field_by_name("password").unwrap();
    assert_eq!(field_a.expose_text(), Some(VAULT_001_PASSWORD_VALUE.to_string()));
    assert_eq!(field_b.expose_text(), Some(VAULT_001_PASSWORD_VALUE.to_string()));
    field_a.wipe();
    assert_eq!(field_a.expose_text(), None);
    assert_eq!(field_b.expose_text(), None);
}

#[test]
fn read_block_after_open_vault_with_recovery_succeeds() {
    let folder = fixture_folder("golden_vault_001");
    let phrase: &[u8] = b"wall annual clay zebra cost cricket choose light small neck mimic season fix situate love asset dismiss online island disease turkey grab dish that";
    let out = open_vault_with_recovery(&folder, phrase).expect("recovery open");
    let block = read_block(&out.identity, &out.manifest, &VAULT_001_BLOCK_UUID).unwrap();
    assert_eq!(block.record_count(), 1);
    let record = block.record_at(0).unwrap();
    let pw_field = record.field_by_name("password").unwrap();
    assert_eq!(pw_field.expose_text(), Some(VAULT_001_PASSWORD_VALUE.to_string()));
}
```

- [ ] **Step 9: Verify the integration tests pass**

```bash
cargo test --release -p secretary-ffi-bridge --test read_block 2>&1 | tail -20
```

Expected: 13 passed (the 12 main `#[test]`s above + the helper-using `copy_golden_to_tempdir` is not itself a test). Re-count: read_block_returns_one + read_block_record_metadata + read_block_field_names + read_block_field_text_payload + read_block_field_metadata + read_block_field_is_text + read_block_unknown_uuid + read_block_corrupt_block + read_block_missing_block + block_read_output_wipe + record_wipe_drops_field + field_handle_arc_clones + read_block_after_open_vault_with_recovery = 13 tests.

If clippy flags `tempfile` or `hex` as missing dependencies, add them to `[dev-dependencies]` (these tests live in `tests/` so dev-deps suffice).

- [ ] **Step 10: Run all bridge crate tests + clippy + fmt**

```bash
cargo test --release -p secretary-ffi-bridge 2>&1 | grep -E "^test result:" | head -5
cargo clippy --release -p secretary-ffi-bridge -- -D warnings && echo "clippy OK"
cargo fmt --all -- --check && echo "fmt OK"
```

Expected: bridge crate test count went up by ~22 (from ~58 → ~80; +13 integration tests + 5 field unit tests + 2 orchestration unit tests + 2 vault.rs tests already added in Task 2). Some variation acceptable.

- [ ] **Step 11: Check the `pub mod record;` line in `lib.rs` was added in Task 3 Step 6**

Wait — Task 3 Step 6 (in the original numbering) was the lib.rs glance, but with the directory module restructure, Step 7 (compile check) above added `pub mod record;` to `lib.rs` only IF it wasn't already there. Verify:

```bash
grep -E "^pub mod record;|^mod record;" ffi/secretary-ffi-bridge/src/lib.rs
```

Expected: `pub mod record;` present. If missing, add it now (between `pub mod identity;` and `mod sync_helpers;`).

- [ ] **Step 12: Commit Task 3**

```bash
cd /Users/hherb/src/secretary
git add ffi/secretary-ffi-bridge/src/record/ \
        ffi/secretary-ffi-bridge/src/lib.rs \
        ffi/secretary-ffi-bridge/tests/read_block.rs \
        ffi/secretary-ffi-bridge/Cargo.toml
git commit -m "$(cat <<'EOF'
feat(ffi-b4b-task3): add record/ directory module — read_block + 3 opaque handles + 13 KAT tests

NEW ffi/secretary-ffi-bridge/src/record/ (split into 5 sub-files to
keep each <250 lines per project policy):
- mod.rs            — module declarations + re-exports
- output.rs         — BlockReadOutput (Mutex<Option<Inner>>; cascades wipe)
- handle.rs         — Record (Arc<Mutex<Option<Inner>>>; clone-cheap)
- field.rs          — FieldHandle (Arc<Mutex<Option<Inner>>>; expose_text/expose_bytes)
- orchestration.rs  — read_block free fn + uuid_hyphenated helper

NEW ffi/secretary-ffi-bridge/tests/read_block.rs:
- 13 integration tests pinned against golden_vault_001 KAT.

Hybrid Record projection per spec decision §1: non-secret metadata is
value-typed; secret payload is opaque-handle. v1 single-author block
reading per decision §9 (sender = reader = owner card). All BlockError
variants fold into CorruptVault per anti-conflation discipline.

Constructors take individual args (not Inner structs) so each Inner
type stays fully private to its sub-file. The cross-module visibility
needed is just the public `Record::new`, `FieldHandle::new`,
`BlockReadOutput::new` (all `pub(crate)`).

Wipe cascades: BlockReadOutput::wipe walks records and wipes each;
Record::wipe walks fields and wipes each; FieldHandle::wipe takes the
shared Option inner so every Arc clone sees the wiped state.

Refs: docs/superpowers/specs/2026-05-09-ffi-b4b-read-block-design.md
sections "Bridge crate types" + "read_block orchestration".

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: `lib.rs` — re-exports + crate-doc update (8 entry points)

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs` (currently 98 lines + the `pub mod record;` line added in Task 3 Step 11; will end at ~125 lines)

`pub mod record;` was added in Task 3 to make the directory module compile. Now add the public re-exports and update the crate-level doc-comment.

- [ ] **Step 1: Add `record::*` re-exports**

In `ffi/secretary-ffi-bridge/src/lib.rs`, find the existing `pub use` block:

```rust
pub use create::{create_vault, CreateVaultOutput, MnemonicOutput};
pub use error::{FfiUnlockError, FfiVaultError};
pub use identity::UnlockedIdentity;
pub use unlock::{open_with_password, open_with_recovery};
pub use vault::{
    open_vault_with_password, open_vault_with_recovery, BlockSummary, OpenVaultManifest,
    OpenVaultOutput,
};
```

Append a new line:

```rust
pub use record::{read_block, BlockReadOutput, FieldHandle, Record};
```

- [ ] **Step 2: Update the `## Errors` and `## Handles` sections of the crate-level doc**

Find:

```rust
//! - [`FfiVaultError`] — thinned 6-variant error type for the **folder-in**
//!   vault entry points ([`open_vault_with_password`],
//!   [`open_vault_with_recovery`]). Mirrors [`FfiUnlockError`]'s 5
//!   unlock-class variants byte-identically (variant name + Display
//!   string) plus a new [`FfiVaultError::FolderInvalid`] for missing or
//!   inaccessible vault folders. See [`error`] module docs.
```

Replace with:

```rust
//! - [`FfiVaultError`] — thinned 7-variant error type for the **folder-in**
//!   vault entry points ([`open_vault_with_password`],
//!   [`open_vault_with_recovery`], [`read_block`]). Mirrors
//!   [`FfiUnlockError`]'s 5 unlock-class variants byte-identically
//!   (variant name + Display string) plus [`FfiVaultError::FolderInvalid`]
//!   for missing or inaccessible vault folders, plus
//!   [`FfiVaultError::BlockNotFound`] for read-time block-UUID lookups
//!   that miss the manifest's live blocks list. See [`error`] module
//!   docs.
```

In the `## Handles` section, after the existing `OpenVaultManifest` description, insert the three new handles:

```rust
//! - [`BlockReadOutput`] — opaque handle for one block's decrypted
//!   records. Returned by [`read_block`]. Holds owned [`Record`]s;
//!   [`BlockReadOutput::wipe`] cascades wipe to every contained record
//!   + field. See [`record`] module docs.
//! - [`Record`] — per-record handle. Wraps non-secret metadata
//!   (record_uuid, record_type, tags, timestamps, tombstone) plus an
//!   ordered list of [`FieldHandle`]s. `Arc<Mutex<Option<...>>>` so
//!   foreign callers can store cheap clones that share the same wiped
//!   state.
//! - [`FieldHandle`] — per-field handle. Holds the secret-payload
//!   [`secretary_core::vault::record::RecordFieldValue`] (text or bytes);
//!   explicit [`FieldHandle::expose_text`] / [`FieldHandle::expose_bytes`]
//!   boundary for surfacing the secret to the foreign caller.
```

- [ ] **Step 3: Add a "Read (B.4b)" subsection under `## Entry points`**

Find the end of the Folder-in section (`open_vault_with_recovery` description). Add after it:

```rust
//!
//! Read (B.4b):
//! - [`read_block`] — fallible decrypt of one block's records given
//!   an open vault and a 16-byte block UUID. Borrows
//!   [`UnlockedIdentity`] + [`OpenVaultManifest`]. Returns
//!   [`BlockReadOutput`] with the decrypted records on success;
//!   [`FfiVaultError::BlockNotFound`] / [`FfiVaultError::CorruptVault`]
//!   on lookup or decryption failure.
```

- [ ] **Step 4: Build, clippy, fmt, full workspace test**

```bash
cargo build --release -p secretary-ffi-bridge 2>&1 | tail -3
cargo clippy --release -p secretary-ffi-bridge -- -D warnings && echo "clippy OK"
cargo fmt --all -- --check && echo "fmt OK"
cargo test --release --workspace 2>&1 | grep -E "^test result:" | python3 -c "
import sys, re
p=f=i=0
for line in sys.stdin:
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'TOTAL: {p} passed; {f} failed; {i} ignored')"
```

Expected: build succeeds; clippy clean; fmt OK; total goes from 522 → 542 (the 20 new tests across Tasks 1-3: 2 error.rs + 2 vault.rs + 5 field.rs + 2 orchestration.rs + 13 read_block.rs integration). Some variation acceptable.

- [ ] **Step 5: Commit Task 4**

```bash
cd /Users/hherb/src/secretary
git add ffi/secretary-ffi-bridge/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(ffi-b4b-task4): re-export read_block + 3 opaque handles; update crate-doc

Surfaces the new B.4b symbols at the bridge crate root:
- pub use record::{read_block, BlockReadOutput, FieldHandle, Record};

Updates the crate-level doc-comment to reflect the 7 → 8 user-facing
entry points and the 3 new opaque-handle types under the Handles
section. The FfiVaultError description bumps from 6-variant to
7-variant and lists BlockNotFound alongside FolderInvalid.

Refs: docs/superpowers/specs/2026-05-09-ffi-b4b-read-block-design.md
section "FFI surface after B.4b".

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---


## Phase 2 — Fuzz harness defense-in-depth

### Task 5: extend `core/fuzz/fuzz_targets/record.rs` with UTF-8-validity assertion

**Files:**
- Modify: `core/fuzz/fuzz_targets/record.rs` (currently 20 lines; will grow to ~40)

The structural guarantee is already in place — CBOR `tstr` (major type 3) requires valid UTF-8 per RFC 8949 §3.1, and `parse_record_field` only constructs `RecordFieldValue::Text(SecretString::new(s))` from an already-validated `Value::Text(s)`. So invalid UTF-8 cannot reach `expose_text()` by construction. The added assertion is defense-in-depth: a tripwire that fires if the decode path is ever weakened to allow direct `SecretString` construction from non-validated bytes.

The fuzz harness is excluded from the workspace and uses a pinned nightly toolchain — see [core/fuzz/README.md](../../../core/fuzz/README.md) for the invocation pattern.

- [ ] **Step 1: Add the UTF-8 assertion to the existing fuzz target**

Edit `core/fuzz/fuzz_targets/record.rs`. Replace its entire body with:

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use secretary_core::vault::record::{self, RecordFieldValue};

fuzz_target!(|data: &[u8]| {
    // External roundtrip oracle: decode must equal `encode(decode(input))`
    // for any input the decoder accepts. record::decode already enforces
    // this internally (canonical re-encode-and-compare); the external check
    // here is defense-in-depth — if the internal canonicality gate is ever
    // weakened, this target catches the regression.
    if let Ok(parsed) = record::decode(data) {
        let reencoded =
            record::encode(&parsed).expect("encode after successful decode must not fail");
        assert_eq!(
            reencoded.as_slice(),
            data,
            "record decode→encode roundtrip mismatch"
        );

        // Defense-in-depth (B.4b Task 5): every successfully-decoded
        // `RecordFieldValue::Text` must wrap a valid-UTF-8 SecretString.
        // The structural guarantee is in place today (CBOR `tstr` per
        // RFC 8949 §3.1 + ciborium's `Value::Text` enforcement +
        // parse_record_field's `Value::Text(s) → SecretString::new(s)`
        // path), so this assertion can never fire with the current
        // decode path. It serves as a tripwire if a future refactor
        // ever weakens the decode path to allow direct SecretString
        // construction from non-validated bytes — the FFI's
        // FieldHandle::expose_text() returns `Option<String>` (not
        // `Result<Option<String>, _>`) and would silently surface
        // invalid UTF-8 to the foreign caller without this fuzz check.
        for (_name, field) in &parsed.fields {
            if let RecordFieldValue::Text(secret_string) = &field.value {
                let bytes = secret_string.expose().as_bytes();
                assert!(
                    std::str::from_utf8(bytes).is_ok(),
                    "RecordFieldValue::Text contained invalid UTF-8 — \
                     decode-path UTF-8 enforcement may have regressed",
                );
            }
        }
    }
});
```

- [ ] **Step 2: Smoke-run the fuzz target on nightly to verify the assertion compiles + doesn't fire on the existing corpus**

Per the documented invocation pattern (Homebrew's cargo on macOS may mask rustup's nightly — prepend explicitly):

```bash
cd /Users/hherb/src/secretary/core/fuzz
PATH="$HOME/.rustup/toolchains/nightly-2026-04-29-aarch64-apple-darwin/bin:$PATH" \
    cargo fuzz run record -- -runs=10000
```

Expected: the run completes 10,000 iterations against the existing corpus + libfuzzer's mutated inputs without firing the new UTF-8-validity assertion. If the run fires the assertion, that's a real regression somewhere — investigate before proceeding (the structural guarantee is supposed to make this impossible).

If the toolchain path doesn't match, find the right one:

```bash
ls ~/.rustup/toolchains/ | grep nightly
```

- [ ] **Step 3: Commit Task 5**

```bash
cd /Users/hherb/src/secretary
git add core/fuzz/fuzz_targets/record.rs
git commit -m "$(cat <<'EOF'
feat(ffi-b4b-task5): add defense-in-depth UTF-8 assertion to record fuzz target

Walks every successfully-decoded RecordFieldValue::Text and asserts
the SecretString wraps valid UTF-8. The structural guarantee already
holds today (CBOR tstr per RFC 8949 §3.1 + ciborium's Value::Text
enforcement + parse_record_field's Value::Text(s) → SecretString::new(s)
path), so this assertion can never fire with the current decode path.

Tripwire purpose: B.4b's FieldHandle::expose_text() at the FFI returns
Option<String>, not Result<Option<String>, _> — so invalid UTF-8 leaking
into a SecretString would silently surface to the foreign caller. This
fuzz assertion catches any future regression that weakens the decode
path's UTF-8 enforcement BEFORE it can ship through the FFI.

Smoke-run with `cargo fuzz run record -- -runs=10000` on the pinned
nightly toolchain produced no failures.

Refs: docs/superpowers/specs/2026-05-09-ffi-b4b-read-block-design.md
section "Open questions / risks — In scope for B.4b implementation".

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Phase 3 — PyO3 layer

### Task 6: PyO3 wrapper — `read_block` + 3 `#[pyclass]` + 1 `create_exception!` + 7th arm

**Files:**
- Modify: `ffi/secretary-ffi-py/src/lib.rs` (currently 782 lines; will grow to ~960)

PyO3 newtypes wrap the bridge's three opaque handles + add the `__enter__` / `__exit__` context-manager protocol. `VaultBlockNotFound` is a new exception class. The `ffi_vault_error_to_pyerr` mapper gains a 7th arm.

- [ ] **Step 1: Import the new bridge symbols**

In `ffi/secretary-ffi-py/src/lib.rs`, find the existing import block:

```rust
use secretary_ffi_bridge::{
    BlockSummary as BridgeBlockSummary, FfiUnlockError, FfiVaultError,
    OpenVaultManifest as BridgeOpenVaultManifest,
};
```

Replace with:

```rust
use secretary_ffi_bridge::{
    BlockReadOutput as BridgeBlockReadOutput,
    BlockSummary as BridgeBlockSummary,
    FieldHandle as BridgeFieldHandle,
    FfiUnlockError, FfiVaultError,
    OpenVaultManifest as BridgeOpenVaultManifest,
    Record as BridgeRecord,
};
```

- [ ] **Step 2: Add `VaultBlockNotFound` exception class**

After the existing `create_exception!(secretary_ffi_py, VaultFolderInvalid, PyException);` line, add:

```rust
create_exception!(secretary_ffi_py, VaultBlockNotFound, PyException);
```

- [ ] **Step 3: Extend `ffi_vault_error_to_pyerr` with the 7th arm**

Find the `fn ffi_vault_error_to_pyerr` function (around line 147). Add a 7th arm to the match before the closing `}`:

```rust
        FfiVaultError::FolderInvalid { detail } => VaultFolderInvalid::new_err(detail),
        FfiVaultError::BlockNotFound { uuid_hex } => {
            // Pass uuid_hex as the exception payload so foreign callers
            // can `except VaultBlockNotFound as e: e.args[0]` to get the
            // hex string back.
            VaultBlockNotFound::new_err(uuid_hex)
        }
    }
}
```

(The `FfiVaultError::FolderInvalid` arm should already be the second-to-last; the new `BlockNotFound` arm becomes the last.)

- [ ] **Step 4: Add the `FieldHandle` `#[pyclass]` newtype**

After the existing `#[pyclass(frozen)] pub struct BlockSummary { ... }` block (around line 282), add the three new pyclasses. Start with `FieldHandle`:

```rust

// ---------------------------------------------------------------------------
// B.4b: FieldHandle + Record + BlockReadOutput pyclasses + read_block fn.
// ---------------------------------------------------------------------------

/// Per-field handle. Returns secret-payload accessors via explicit
/// `expose_text()` / `expose_bytes()` calls. Use as a context manager
/// to ensure `wipe()` runs on exit (the bridge's underlying SecretString
/// / SecretBytes is zeroize-on-drop; wipe is the explicit, deterministic
/// trigger).
#[pyclass]
pub struct FieldHandle(BridgeFieldHandle);

#[pymethods]
impl FieldHandle {
    /// Field name (e.g. `"password"`). Returns `""` if wiped.
    fn name(&self) -> String {
        self.0.name()
    }
    /// Per-field last-modification timestamp, ms. Returns 0 if wiped.
    fn last_mod_ms(&self) -> u64 {
        self.0.last_mod_ms()
    }
    /// 16-byte UUID of the device that last modified this field.
    fn device_uuid<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.device_uuid())
    }
    /// `True` if the payload is text. `False` if bytes or wiped.
    fn is_text(&self) -> bool {
        self.0.is_text()
    }
    /// `True` if the payload is bytes. `False` if text or wiped.
    fn is_bytes(&self) -> bool {
        self.0.is_bytes()
    }
    /// Pull the secret payload as `str`. Returns `None` if the field
    /// is bytes or has been wiped. Caller is responsible for clearing
    /// the returned string (e.g. `del secret_str`).
    fn expose_text(&self) -> Option<String> {
        self.0.expose_text()
    }
    /// Pull the secret payload as `bytes`. Returns `None` if the field
    /// is text or has been wiped.
    fn expose_bytes<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.0.expose_bytes().map(|v| PyBytes::new(py, &v))
    }
    /// Drop the underlying secret now. Idempotent.
    fn wipe(&self) {
        self.0.wipe();
    }
    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }
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

- [ ] **Step 5: Add the `Record` `#[pyclass]` newtype**

Append after the `FieldHandle` block:

```rust

/// Per-record handle. Wraps non-secret metadata + an ordered list of
/// [`FieldHandle`]s. Use as a context manager to ensure `wipe()` runs
/// on exit, cascading wipe to every contained field.
#[pyclass]
pub struct Record(BridgeRecord);

#[pymethods]
impl Record {
    fn record_uuid<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.record_uuid())
    }
    fn record_type(&self) -> String {
        self.0.record_type()
    }
    fn tags(&self) -> Vec<String> {
        self.0.tags()
    }
    fn created_at_ms(&self) -> u64 {
        self.0.created_at_ms()
    }
    fn last_mod_ms(&self) -> u64 {
        self.0.last_mod_ms()
    }
    fn tombstone(&self) -> bool {
        self.0.tombstone()
    }
    fn field_count(&self) -> usize {
        self.0.field_count()
    }
    /// Field names in BTreeMap iteration order.
    fn field_names(&self) -> Vec<String> {
        self.0.field_names()
    }
    /// Look up a field by name. Returns `None` if no field has this
    /// name or the record has been wiped. Returns a fresh
    /// [`FieldHandle`] that shares the underlying Arc<...>; wiping
    /// either invalidates both.
    fn field_by_name(&self, name: &str) -> Option<FieldHandle> {
        self.0.field_by_name(name).map(FieldHandle)
    }
    fn field_at(&self, idx: usize) -> Option<FieldHandle> {
        self.0.field_at(idx).map(FieldHandle)
    }
    fn wipe(&self) {
        self.0.wipe();
    }
    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }
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

- [ ] **Step 6: Add the `BlockReadOutput` `#[pyclass]` newtype**

Append:

```rust

/// Container handle for one block's decrypted records. `wipe()` cascades
/// to every contained record + field. Use as a context manager.
#[pyclass]
pub struct BlockReadOutput(BridgeBlockReadOutput);

#[pymethods]
impl BlockReadOutput {
    fn block_uuid<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.block_uuid())
    }
    fn block_name(&self) -> String {
        self.0.block_name()
    }
    fn record_count(&self) -> usize {
        self.0.record_count()
    }
    fn record_at(&self, idx: usize) -> Option<Record> {
        self.0.record_at(idx).map(Record)
    }
    fn wipe(&self) {
        self.0.wipe();
    }
    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }
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

- [ ] **Step 7: Add the `read_block` `#[pyfunction]`**

Append:

```rust

/// Decrypt one block of an open vault and return its records.
///
/// `block_uuid` must be exactly 16 bytes; otherwise raises `ValueError`.
/// Wrong-length input is a programmer error and surfaces distinctly
/// from the data-error variant `VaultBlockNotFound` (which fires when
/// the UUID doesn't match any block in the manifest).
///
/// # Raises
///
/// - `ValueError` — `block_uuid` length ≠ 16.
/// - `VaultBlockNotFound` — UUID not in manifest's live blocks list.
/// - `VaultCorruptVault` — block file missing/malformed/decryption failed.
/// - `VaultFolderInvalid` — block file present but unreadable for non-NotFound IO reasons.
#[pyfunction]
fn read_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: &[u8],
) -> PyResult<BlockReadOutput> {
    if block_uuid.len() != 16 {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "block_uuid must be 16 bytes, got {}",
            block_uuid.len()
        )));
    }
    let mut uuid_array = [0u8; 16];
    uuid_array.copy_from_slice(block_uuid);
    secretary_ffi_bridge::read_block(&identity.0, &manifest.0, &uuid_array)
        .map(BlockReadOutput)
        .map_err(ffi_vault_error_to_pyerr)
}
```

- [ ] **Step 8: Register the new pyclasses + function + exception in `#[pymodule]`**

Find the `fn secretary_ffi_py` function (around line 707). Add the B.4b registrations at the end (after the existing `m.add("VaultFolderInvalid", ...)?;`):

```rust

    // B.4b surface:
    m.add_class::<FieldHandle>()?;
    m.add_class::<Record>()?;
    m.add_class::<BlockReadOutput>()?;
    m.add_function(wrap_pyfunction!(read_block, m)?)?;
    m.add(
        "VaultBlockNotFound",
        py.get_type::<VaultBlockNotFound>(),
    )?;

    Ok(())
}
```

(Move the existing `Ok(())` line down to be after the new B.4b block — there was only one `Ok(())` at the end of the function before; keep just the new one.)

- [ ] **Step 9: Build the wheel + apply the documented cache fix proactively**

The B.4b PyO3 surface adds substantial new symbols (`read_block` + `BlockReadOutput` + `Record` + `FieldHandle` + `VaultBlockNotFound`). Per the project memory `project_secretary_maturin_uv_cache`, apply the nuclear cache fix BEFORE running pytest:

```bash
cd /Users/hherb/src/secretary
rm -rf ffi/secretary-ffi-py/.venv
find ~/.cache/uv -name "*secretary*" -exec rm -rf {} + 2>/dev/null
cargo clean -p secretary-ffi-py
( cd ffi/secretary-ffi-py && uv sync && uv run maturin develop --release --uv )
```

Expected: maturin build succeeds with no errors. The wheel installs into the freshly-recreated `.venv`.

- [ ] **Step 10: Smoke-test the new symbols are importable**

```bash
uv run --directory ffi/secretary-ffi-py python -c "
import secretary_ffi_py as sfp
print('read_block:', sfp.read_block)
print('BlockReadOutput:', sfp.BlockReadOutput)
print('Record:', sfp.Record)
print('FieldHandle:', sfp.FieldHandle)
print('VaultBlockNotFound:', sfp.VaultBlockNotFound)
"
```

Expected: all five symbols print without `AttributeError`.

- [ ] **Step 11: Run clippy + fmt**

```bash
cargo clippy --release -p secretary-ffi-py -- -D warnings && echo "clippy OK"
cargo fmt --all -- --check && echo "fmt OK"
```

Expected: both clean.

- [ ] **Step 12: Commit Task 6**

```bash
cd /Users/hherb/src/secretary
git add ffi/secretary-ffi-py/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(ffi-b4b-task6): PyO3 wrapper — read_block + 3 #[pyclass] + VaultBlockNotFound

Adds the foreign-Python projection of B.4b:
- #[pyfunction] read_block(identity, manifest, block_uuid) -> BlockReadOutput
  Wrong-length block_uuid raises ValueError (programmer error, distinct
  from the data-error VaultBlockNotFound).
- #[pyclass] BlockReadOutput, Record, FieldHandle — newtype wrappers
  around the bridge handles. All three implement __enter__/__exit__ so
  the context-manager idiom (`with sfp.read_block(...) as block:`)
  cascades wipe() on exit.
- create_exception!(secretary_ffi_py, VaultBlockNotFound, PyException)
- Extends ffi_vault_error_to_pyerr with a 7th arm mapping
  FfiVaultError::BlockNotFound { uuid_hex } → VaultBlockNotFound
  with uuid_hex passed as the exception payload.

Imports promoted to include BlockReadOutput, FieldHandle, Record from
the bridge crate (with `as Bridge*` aliases per existing convention).

#[pymodule] registers all new classes + the new function + the new
exception under the B.4b section.

Per project memory `project_secretary_maturin_uv_cache`, applied the
nuclear cache fix before pytest to ensure the new symbols are visible.

Refs: docs/superpowers/specs/2026-05-09-ffi-b4b-read-block-design.md
section "PyO3 wrapper".

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: pytest — +10 tests for `read_block`

**Files:**
- Modify: `ffi/secretary-ffi-py/tests/test_smoke.py` (currently 515 lines; will grow to ~700)

10 new tests pinned against `golden_vault_001`. Reuse the existing `_golden_vault_path` and `_golden_vault_block_summaries` helpers; add a thin `_open_vault_001` helper to amortise the Argon2id cost across multiple read_block tests in the same module.

- [ ] **Step 1: Add a module-scoped fixture for the opened vault**

In `ffi/secretary-ffi-py/tests/test_smoke.py`, find the existing `created_vault` fixture (around line 51). After it, add a new `opened_vault_001` fixture:

```python


@pytest.fixture(scope="module")
def opened_vault_001():
    """Open golden_vault_001 once for all B.4b read_block tests in this
    module. Cost: ~1s for V1_DEFAULT Argon2id. Returns the OpenVaultOutput
    so tests can reach `.identity` and `.manifest` independently — the
    take-once getters mean each test that exercises both must use a
    fresh open, but tests that exercise only one side can share this
    fixture."""
    return secretary_ffi_py.open_vault_with_password(
        str(_golden_vault_path(1)),
        b"correct horse battery staple",
    )
```

- [ ] **Step 2: Add pinned-KAT constants for B.4b**

After the existing B.4a pinned constants (around the end of the B.3a section), add:

```python


# ---------------------------------------------------------------------------
# B.4b: read_block KAT pins (source: golden_vault_001_inputs.json)
# ---------------------------------------------------------------------------
VAULT_001_BLOCK_UUID = bytes.fromhex("112233445566778899aabbccddeeff00")
VAULT_001_BLOCK_UUID_HEX = "112233445566778899aabbccddeeff00"
VAULT_001_BLOCK_NAME = "Personal logins"
VAULT_001_RECORD_UUID = bytes.fromhex("33445566778899aabbccddeeff001122")
VAULT_001_DEVICE_UUID = bytes.fromhex("2233445566778899aabbccddeeff0011")
VAULT_001_TIMESTAMP_MS = 2_000_000_000_000
VAULT_001_PASSWORD_VALUE = "hunter2"
VAULT_001_USERNAME_VALUE = "owner@example.com"
```

- [ ] **Step 3: Add the new tests at the end of the file**

After the existing `test_with_block_double_close_invariants` test (around line 494), append the 10 new B.4b tests:

```python


# =============================================================================
# B.4b — read_block tests
# =============================================================================


def test_read_block_shape() -> None:
    """Open + read; assert record_count == 1 and field_count == 2."""
    folder = _golden_vault_path(1)
    out = secretary_ffi_py.open_vault_with_password(str(folder), b"correct horse battery staple")
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            with secretary_ffi_py.read_block(identity, manifest, VAULT_001_BLOCK_UUID) as block:
                assert block.record_count() == 1
                assert block.block_name() == VAULT_001_BLOCK_NAME
                assert bytes(block.block_uuid()) == VAULT_001_BLOCK_UUID
                record = block.record_at(0)
                assert record is not None
                assert record.field_count() == 2


def test_read_block_record_metadata() -> None:
    """Pin record_uuid, record_type, tags, tombstone, timestamps."""
    folder = _golden_vault_path(1)
    out = secretary_ffi_py.open_vault_with_password(str(folder), b"correct horse battery staple")
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            with secretary_ffi_py.read_block(identity, manifest, VAULT_001_BLOCK_UUID) as block:
                record = block.record_at(0)
                assert bytes(record.record_uuid()) == VAULT_001_RECORD_UUID
                assert record.record_type() == "login"
                assert record.tags() == ["work"]
                assert record.tombstone() is False
                assert record.created_at_ms() == VAULT_001_TIMESTAMP_MS
                assert record.last_mod_ms() == VAULT_001_TIMESTAMP_MS


def test_read_block_field_text_password() -> None:
    """Password field exposes 'hunter2' via expose_text()."""
    folder = _golden_vault_path(1)
    out = secretary_ffi_py.open_vault_with_password(str(folder), b"correct horse battery staple")
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            with secretary_ffi_py.read_block(identity, manifest, VAULT_001_BLOCK_UUID) as block:
                record = block.record_at(0)
                pw_field = record.field_by_name("password")
                assert pw_field is not None
                assert pw_field.is_text()
                assert pw_field.expose_text() == VAULT_001_PASSWORD_VALUE


def test_read_block_field_text_username() -> None:
    """Username field exposes 'owner@example.com' via expose_text()."""
    folder = _golden_vault_path(1)
    out = secretary_ffi_py.open_vault_with_password(str(folder), b"correct horse battery staple")
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            with secretary_ffi_py.read_block(identity, manifest, VAULT_001_BLOCK_UUID) as block:
                record = block.record_at(0)
                user_field = record.field_by_name("username")
                assert user_field is not None
                assert user_field.expose_text() == VAULT_001_USERNAME_VALUE


def test_read_block_field_metadata() -> None:
    """Field-level last_mod_ms + device_uuid match KAT for both fields."""
    folder = _golden_vault_path(1)
    out = secretary_ffi_py.open_vault_with_password(str(folder), b"correct horse battery staple")
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            with secretary_ffi_py.read_block(identity, manifest, VAULT_001_BLOCK_UUID) as block:
                record = block.record_at(0)
                pw_field = record.field_by_name("password")
                user_field = record.field_by_name("username")
                assert pw_field.last_mod_ms() == VAULT_001_TIMESTAMP_MS
                assert user_field.last_mod_ms() == VAULT_001_TIMESTAMP_MS
                assert bytes(pw_field.device_uuid()) == VAULT_001_DEVICE_UUID
                assert bytes(user_field.device_uuid()) == VAULT_001_DEVICE_UUID


def test_read_block_unknown_uuid_raises_block_not_found() -> None:
    """16 zero bytes is not a real block UUID → VaultBlockNotFound."""
    folder = _golden_vault_path(1)
    out = secretary_ffi_py.open_vault_with_password(str(folder), b"correct horse battery staple")
    unknown = bytes(16)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            with pytest.raises(secretary_ffi_py.VaultBlockNotFound) as exc_info:
                secretary_ffi_py.read_block(identity, manifest, unknown)
            # The exception payload carries the uuid_hex string.
            assert "00000000000000000000000000000000" in str(exc_info.value)


def test_read_block_wrong_length_uuid_raises_value_error() -> None:
    """15-byte UUID input → ValueError (NOT VaultBlockNotFound — distinct
    error class for programmer errors vs. data errors)."""
    folder = _golden_vault_path(1)
    out = secretary_ffi_py.open_vault_with_password(str(folder), b"correct horse battery staple")
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            with pytest.raises(ValueError) as exc_info:
                secretary_ffi_py.read_block(identity, manifest, bytes(15))
            assert "16 bytes" in str(exc_info.value)
            assert "got 15" in str(exc_info.value)


def test_read_block_field_bytes_is_none_for_text_field() -> None:
    """expose_bytes() on a text field returns None (not raises)."""
    folder = _golden_vault_path(1)
    out = secretary_ffi_py.open_vault_with_password(str(folder), b"correct horse battery staple")
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            with secretary_ffi_py.read_block(identity, manifest, VAULT_001_BLOCK_UUID) as block:
                record = block.record_at(0)
                pw_field = record.field_by_name("password")
                assert pw_field.expose_bytes() is None
                assert pw_field.is_bytes() is False


def test_block_read_output_context_manager_wipes() -> None:
    """After exiting `with read_block(...) as block:`, accessors return
    empty defaults (record_count == 0)."""
    folder = _golden_vault_path(1)
    out = secretary_ffi_py.open_vault_with_password(str(folder), b"correct horse battery staple")
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            block = secretary_ffi_py.read_block(identity, manifest, VAULT_001_BLOCK_UUID)
            assert block.record_count() == 1
            with block:
                pass  # __exit__ runs wipe()
            assert block.record_count() == 0
            assert block.record_at(0) is None


def test_record_field_handles_share_state_after_wipe() -> None:
    """Two foreign-side references to the same field handle: wipe one,
    the other returns None. Pins the Arc<Mutex<Option<...>>> shared-
    wipe contract through the PyO3 boundary."""
    folder = _golden_vault_path(1)
    out = secretary_ffi_py.open_vault_with_password(str(folder), b"correct horse battery staple")
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            with secretary_ffi_py.read_block(identity, manifest, VAULT_001_BLOCK_UUID) as block:
                record_a = block.record_at(0)
                record_b = block.record_at(0)
                field_a = record_a.field_by_name("password")
                field_b = record_b.field_by_name("password")
                # Both clones live initially.
                assert field_a.expose_text() == VAULT_001_PASSWORD_VALUE
                assert field_b.expose_text() == VAULT_001_PASSWORD_VALUE
                # Wipe one — the other reflects.
                field_a.wipe()
                assert field_a.expose_text() is None
                assert field_b.expose_text() is None
```

- [ ] **Step 4: Run pytest**

```bash
uv run --directory ffi/secretary-ffi-py pytest 2>&1 | tail -10
```

Expected: 40 passed (was 30; +10 new B.4b tests).

If any test fails with `AttributeError: module 'secretary_ffi_py' has no attribute 'read_block'`, re-run the nuclear cache fix from Task 6 Step 9.

- [ ] **Step 5: Commit Task 7**

```bash
cd /Users/hherb/src/secretary
git add ffi/secretary-ffi-py/tests/test_smoke.py
git commit -m "$(cat <<'EOF'
feat(ffi-b4b-task7): pytest — +10 read_block tests pinned against golden_vault_001

10 new tests covering the B.4b Python surface end-to-end:
- test_read_block_shape — record_count/field_count
- test_read_block_record_metadata — record_uuid, type, tags, timestamps
- test_read_block_field_text_password — expose_text() == "hunter2"
- test_read_block_field_text_username — expose_text() == "owner@example.com"
- test_read_block_field_metadata — last_mod + device_uuid for both fields
- test_read_block_unknown_uuid_raises_block_not_found — VaultBlockNotFound
- test_read_block_wrong_length_uuid_raises_value_error — ValueError, NOT VaultBlockNotFound
  (anti-conflation: programmer error vs. data error)
- test_read_block_field_bytes_is_none_for_text_field — expose_bytes() returns None
- test_block_read_output_context_manager_wipes — __exit__ cascades wipe
- test_record_field_handles_share_state_after_wipe — Arc<Mutex<...>>
  shared-wipe contract preserved across the PyO3 boundary

Pinned KAT constants live above the test functions; source of truth
is core/tests/data/golden_vault_001_inputs.json's block_plaintext.

Refs: docs/superpowers/specs/2026-05-09-ffi-b4b-read-block-design.md
section "pytest".

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---


## Phase 4 — uniffi layer

### Task 8: uniffi UDL + Rust glue — `read_block` + 3 interfaces + `BlockNotFound` enum variant

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/src/secretary.udl` (currently 185 lines; will grow to ~250)
- Modify: `ffi/secretary-ffi-uniffi/src/lib.rs` (currently 760 lines; will grow to ~960)

uniffi codegen renames per project memory `project_secretary_uniffi_codegen_renames.md` still apply: `wipe()` → `close()` on Kotlin (auto-generated); `AutoCloseable` is auto-generated. UDL surface stays unchanged from the `wipe()` naming.

- [ ] **Step 1: Add the `BlockNotFound` variant to `[Error] interface VaultError` in the UDL**

Edit `ffi/secretary-ffi-uniffi/src/secretary.udl`. Find:

```idl
[Error]
interface VaultError {
    WrongPasswordOrCorrupt();
    WrongMnemonicOrCorrupt();
    InvalidMnemonic(string detail);
    VaultMismatch();
    CorruptVault(string detail);
    FolderInvalid(string detail);
};
```

Add the 7th variant before the closing brace:

```idl
[Error]
interface VaultError {
    WrongPasswordOrCorrupt();
    WrongMnemonicOrCorrupt();
    InvalidMnemonic(string detail);
    VaultMismatch();
    CorruptVault(string detail);
    FolderInvalid(string detail);
    BlockNotFound(string uuid_hex);
};
```

- [ ] **Step 2: Add the `read_block` namespace function to the UDL**

Find the `namespace secretary { ... }` block (lines 1-49). Append the new function before the closing `};`:

```idl
    /// Decrypt one block of an open vault and return its records. (B.4b)
    [Throws=VaultError]
    BlockReadOutput read_block(
        UnlockedIdentity identity,
        OpenVaultManifest manifest,
        bytes block_uuid
    );
```

- [ ] **Step 3: Add the three new interfaces to the UDL**

After the existing `interface OpenVaultManifest { ... }` block (around line 161), append the three B.4b interfaces:

```idl

/// Container handle for one block's decrypted records. wipe() cascades
/// to every contained record + field. Same close → wipe rename rationale
/// as the other handles (uniffi 0.31's auto-generated Kotlin
/// AutoCloseable.close() collides with a UDL-declared close()).
interface BlockReadOutput {
    bytes block_uuid();
    string block_name();
    u64 record_count();
    Record? record_at(u64 idx);
    void wipe();
};

/// Per-record handle. Wraps non-secret metadata + an ordered list of
/// FieldHandles. Same wipe naming rationale as BlockReadOutput.
interface Record {
    bytes record_uuid();
    string record_type();
    sequence<string> tags();
    u64 created_at_ms();
    u64 last_mod_ms();
    boolean tombstone();
    u64 field_count();
    sequence<string> field_names();
    FieldHandle? field_by_name(string name);
    FieldHandle? field_at(u64 idx);
    void wipe();
};

/// Per-field handle. Holds the secret RecordFieldValue (text or bytes);
/// expose_text() / expose_bytes() is the explicit secret-pull boundary.
/// Same wipe naming rationale as the other handles.
interface FieldHandle {
    string name();
    u64 last_mod_ms();
    bytes device_uuid();
    boolean is_text();
    boolean is_bytes();
    string? expose_text();
    bytes? expose_bytes();
    void wipe();
};
```

- [ ] **Step 4: Add the `BlockNotFound` variant to `pub enum VaultError` in `lib.rs`**

Edit `ffi/secretary-ffi-uniffi/src/lib.rs`. Find:

```rust
    #[error("vault folder is not accessible: {detail}")]
    FolderInvalid { detail: String },
}
```

Add the new variant before the closing `}`:

```rust
    #[error("vault folder is not accessible: {detail}")]
    FolderInvalid { detail: String },
    #[error("block not found in manifest: {uuid_hex}")]
    BlockNotFound { uuid_hex: String },
}
```

- [ ] **Step 5: Extend the `From<FfiVaultError> for VaultError` mapping**

Find the `impl From<secretary_ffi_bridge::FfiVaultError> for VaultError`. Add a 7th arm before the closing `}`:

```rust
            B::FolderInvalid { detail } => VaultError::FolderInvalid { detail },
            B::BlockNotFound { uuid_hex } => VaultError::BlockNotFound { uuid_hex },
        }
    }
}
```

- [ ] **Step 6: Add the three uniffi-side wrapper structs**

After the existing `pub struct OpenVaultManifest(secretary_ffi_bridge::OpenVaultManifest);` block (around line 248), add:

```rust

// =============================================================================
// B.4b — BlockReadOutput / Record / FieldHandle wrappers
// =============================================================================

/// uniffi wrapper around secretary_ffi_bridge::BlockReadOutput. Newtype;
/// methods are thin forwarders. Drops on foreign refcount → 0 (RAII safety
/// net via uniffi-generated AutoCloseable.close() on Kotlin / deinit on
/// Swift) or via explicit wipe().
pub struct BlockReadOutput(secretary_ffi_bridge::BlockReadOutput);

impl BlockReadOutput {
    pub fn block_uuid(&self) -> Vec<u8> {
        self.0.block_uuid().to_vec()
    }
    pub fn block_name(&self) -> String {
        self.0.block_name()
    }
    pub fn record_count(&self) -> u64 {
        self.0.record_count() as u64
    }
    pub fn record_at(&self, idx: u64) -> Option<std::sync::Arc<Record>> {
        self.0.record_at(idx as usize).map(|r| std::sync::Arc::new(Record(r)))
    }
    pub fn wipe(&self) {
        self.0.wipe();
    }
}

/// uniffi wrapper around secretary_ffi_bridge::Record.
pub struct Record(secretary_ffi_bridge::Record);

impl Record {
    pub fn record_uuid(&self) -> Vec<u8> {
        self.0.record_uuid().to_vec()
    }
    pub fn record_type(&self) -> String {
        self.0.record_type()
    }
    pub fn tags(&self) -> Vec<String> {
        self.0.tags()
    }
    pub fn created_at_ms(&self) -> u64 {
        self.0.created_at_ms()
    }
    pub fn last_mod_ms(&self) -> u64 {
        self.0.last_mod_ms()
    }
    pub fn tombstone(&self) -> bool {
        self.0.tombstone()
    }
    pub fn field_count(&self) -> u64 {
        self.0.field_count() as u64
    }
    pub fn field_names(&self) -> Vec<String> {
        self.0.field_names()
    }
    pub fn field_by_name(&self, name: String) -> Option<std::sync::Arc<FieldHandle>> {
        self.0.field_by_name(&name).map(|f| std::sync::Arc::new(FieldHandle(f)))
    }
    pub fn field_at(&self, idx: u64) -> Option<std::sync::Arc<FieldHandle>> {
        self.0.field_at(idx as usize).map(|f| std::sync::Arc::new(FieldHandle(f)))
    }
    pub fn wipe(&self) {
        self.0.wipe();
    }
}

/// uniffi wrapper around secretary_ffi_bridge::FieldHandle.
pub struct FieldHandle(secretary_ffi_bridge::FieldHandle);

impl FieldHandle {
    pub fn name(&self) -> String {
        self.0.name()
    }
    pub fn last_mod_ms(&self) -> u64 {
        self.0.last_mod_ms()
    }
    pub fn device_uuid(&self) -> Vec<u8> {
        self.0.device_uuid().to_vec()
    }
    pub fn is_text(&self) -> bool {
        self.0.is_text()
    }
    pub fn is_bytes(&self) -> bool {
        self.0.is_bytes()
    }
    pub fn expose_text(&self) -> Option<String> {
        self.0.expose_text()
    }
    pub fn expose_bytes(&self) -> Option<Vec<u8>> {
        self.0.expose_bytes()
    }
    pub fn wipe(&self) {
        self.0.wipe();
    }
}
```

- [ ] **Step 7: Add the `read_block` namespace function**

After the existing `pub fn open_vault_with_recovery(...)` function (around line 478), append:

```rust

/// Decrypt one block of an open vault and return its records. (B.4b)
///
/// `block_uuid` must be exactly 16 bytes; otherwise returns
/// `VaultError::FolderInvalid` with detail mentioning the wrong length.
/// (uniffi has no native ValueError equivalent at the namespace-fn
/// level, so we surface the wrong-length case through the existing
/// VaultError surface; foreign callers should pass exactly 16 bytes.)
///
/// # Errors
///
/// - [`VaultError::BlockNotFound`] — UUID not in manifest's live blocks list.
/// - [`VaultError::CorruptVault`] — block file missing/malformed/decryption failed.
/// - [`VaultError::FolderInvalid`] — wrong-length block_uuid OR block file
///   present but unreadable for non-NotFound IO reasons.
pub fn read_block(
    identity: std::sync::Arc<UnlockedIdentity>,
    manifest: std::sync::Arc<OpenVaultManifest>,
    block_uuid: Vec<u8>,
) -> Result<std::sync::Arc<BlockReadOutput>, VaultError> {
    if block_uuid.len() != 16 {
        return Err(VaultError::FolderInvalid {
            detail: format!("block_uuid must be 16 bytes, got {}", block_uuid.len()),
        });
    }
    let mut uuid_array = [0u8; 16];
    uuid_array.copy_from_slice(&block_uuid);
    secretary_ffi_bridge::read_block(&identity.0, &manifest.0, &uuid_array)
        .map(|b| std::sync::Arc::new(BlockReadOutput(b)))
        .map_err(VaultError::from)
}
```

- [ ] **Step 8: Update the `read_block` UDL signature for the wrong-length-error decision**

Wait — the spec says wrong-length should surface as `IllegalArgumentException` on Kotlin / typed exception on Swift. uniffi doesn't have a native "ValueError" but it does support a separate `[Error]` enum. Per spec decision §6, we should surface wrong-length distinctly. Two options:

**Option A (chosen for simplicity in B.4b):** Fold wrong-length into `VaultError::FolderInvalid` (as written above). The detail string mentions "block_uuid must be 16 bytes, got N" so the foreign caller can still distinguish, just not via type.

**Option B (cleaner but more code):** Introduce a separate UDL `[Error] interface BlockUuidError { WrongLength(u64 actual); }` and have `read_block` throw a union. uniffi 0.31 does NOT support union-of-error-types per call site, so this is not natively supportable.

Stick with Option A. The spec's "ValueError / IllegalArgumentException" expectation is only fully met on the PyO3 side; uniffi-side gets the same error class as folder-invalid but distinct detail. Document this in the spec's open-issues if it surfaces in review.

(No code change in this step — just confirming the design decision recorded in Step 7.)

- [ ] **Step 9: Add unit-test pins for the new variant + wrapper From impls**

In `ffi/secretary-ffi-uniffi/src/lib.rs`, find the `#[cfg(test)] mod tests` block. Inside, after the existing `vault_error_maps_each_variant_one_to_one` test, append:

```rust

    #[test]
    fn vault_error_block_not_found_maps_one_to_one() {
        // Pin the 7th variant translation. A future rename would fail
        // here first.
        use secretary_ffi_bridge::FfiVaultError as B;
        let bnf = VaultError::from(B::BlockNotFound {
            uuid_hex: "abc123".to_string(),
        });
        let VaultError::BlockNotFound { uuid_hex } = bnf else {
            panic!("expected BlockNotFound");
        };
        assert_eq!(uuid_hex, "abc123");
    }

    #[test]
    fn read_block_wrong_length_returns_folder_invalid() {
        // Pin the wrong-length-folds-to-FolderInvalid decision.
        // Synthesize stub Arc<UnlockedIdentity> + Arc<OpenVaultManifest>
        // by routing through the real open path against golden_vault_001.
        let folder_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../core/tests/data/golden_vault_001");
        let folder_bytes = folder_path.to_str().unwrap().as_bytes().to_vec();
        let pwd = b"correct horse battery staple".to_vec();
        let out = open_vault_with_password(folder_bytes, pwd).unwrap();
        let err = read_block(out.identity, out.manifest, vec![0u8; 15]).unwrap_err();
        let VaultError::FolderInvalid { detail } = err else {
            panic!("expected FolderInvalid for wrong-length, got {err:?}");
        };
        assert!(
            detail.contains("16 bytes") && detail.contains("got 15"),
            "detail did not mention length: {detail}",
        );
    }
```

- [ ] **Step 10: Build the cdylib + run uniffi crate's Rust tests**

```bash
cd /Users/hherb/src/secretary
cargo build --release -p secretary-ffi-uniffi 2>&1 | tail -10
cargo test --release -p secretary-ffi-uniffi 2>&1 | grep -E "^test result:" | head -5
```

Expected: build succeeds; uniffi crate test count goes from 15 → 17 (+2 new tests in Step 9).

If the build fails with `error: identifier 'BlockReadOutput' not found in scaffolding` or similar, the UDL and Rust must both declare the same names — verify the UDL interface names exactly match the Rust struct names (case-sensitive).

- [ ] **Step 11: Run clippy + fmt on the uniffi crate**

```bash
cargo clippy --release -p secretary-ffi-uniffi -- -D warnings && echo "clippy OK"
cargo fmt --all -- --check && echo "fmt OK"
```

Expected: both clean. uniffi-generated scaffolding sometimes triggers clippy warnings; if any new ones surface from B.4b code (not generated), fix them inline.

- [ ] **Step 12: Commit Task 8**

```bash
cd /Users/hherb/src/secretary
git add ffi/secretary-ffi-uniffi/src/secretary.udl ffi/secretary-ffi-uniffi/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(ffi-b4b-task8): uniffi — read_block namespace fn + 3 interfaces + BlockNotFound

UDL additions:
- namespace fn read_block(UnlockedIdentity, OpenVaultManifest, bytes)
  -> BlockReadOutput throws VaultError
- 3 new interfaces: BlockReadOutput, Record, FieldHandle (all
  AutoCloseable on Kotlin via uniffi 0.31 codegen; wipe() preserved
  as the explicit zeroize trigger distinct from the auto-generated
  close())
- VaultError grows BlockNotFound(string uuid_hex) — 7th variant

Rust glue:
- 3 newtype wrappers around bridge handles (BlockReadOutput, Record,
  FieldHandle) — methods are thin forwarders; record_at /
  field_by_name / field_at return Option<Arc<...>> per uniffi's
  refcount handling for interface return types
- pub fn read_block — wrong-length block_uuid folds into
  VaultError::FolderInvalid with detail "block_uuid must be 16 bytes,
  got N" (uniffi 0.31 has no native ValueError equivalent at the
  namespace-fn level; the alternative would be a separate [Error]
  union which uniffi doesn't support per-call)
- VaultError gains BlockNotFound variant + the From<FfiVaultError>
  mapping arm
- 2 new tests: pin BlockNotFound mapping + pin wrong-length →
  FolderInvalid behavior

Refs: docs/superpowers/specs/2026-05-09-ffi-b4b-read-block-design.md
section "uniffi UDL". Wrong-length-on-uniffi divergence noted in
project memory project_secretary_uniffi_codegen_renames.md context.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: Swift smoke + Kotlin smoke — +4 asserts each

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/tests/swift/main.swift` (currently 427 lines; will grow to ~480)
- Modify: `ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt` (currently 489 lines; will grow to ~545)

Both smoke runners append a B.4b section at the end. Hard-code the same KAT pins used by the bridge crate's integration tests + the pytest suite.

- [ ] **Step 1: Add B.4b asserts to the Swift smoke runner**

Edit `ffi/secretary-ffi-uniffi/tests/swift/main.swift`. Find the existing `if !failures.isEmpty` block (around line 420) and the assertion-count print line `"FAIL: \(failures.count) of 18 assertion(s) failed\n"`.

BEFORE the `if !failures.isEmpty` block, append:

```swift

// =============================================================================
// B.4b — read_block asserts
// =============================================================================

let vault001BlockUuid = Data([
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
])

// Assert 19: read_block success — record_count == 1 + field_count == 2.
do {
    let folderPath = Data(vault001Url.path.utf8)
    let out = try openVaultWithPassword(folderPath: folderPath, password: password001)
    defer { out.identity.wipe() }
    defer { out.manifest.wipe() }
    let block = try readBlock(
        identity: out.identity,
        manifest: out.manifest,
        blockUuid: vault001BlockUuid
    )
    defer { block.wipe() }
    let recordCount = block.recordCount()
    let record = block.recordAt(idx: 0)
    let fieldCount = record?.fieldCount() ?? 0
    check(
        recordCount == 1 && fieldCount == 2,
        "read_block success → record_count == 1 + field_count == 2 (got \(recordCount), \(fieldCount))"
    )
} catch {
    check(false, "read_block success threw \(error), expected to succeed")
}

// Assert 20: field_by_name("password").expose_text() == "hunter2".
do {
    let folderPath = Data(vault001Url.path.utf8)
    let out = try openVaultWithPassword(folderPath: folderPath, password: password001)
    defer { out.identity.wipe() }
    defer { out.manifest.wipe() }
    let block = try readBlock(
        identity: out.identity,
        manifest: out.manifest,
        blockUuid: vault001BlockUuid
    )
    defer { block.wipe() }
    let record = block.recordAt(idx: 0)!
    let pwField = record.fieldByName(name: "password")!
    let secret = pwField.exposeText()
    check(
        secret == "hunter2",
        "field_by_name(\"password\").expose_text() == \"hunter2\" (got \"\(secret ?? "<nil>")\")"
    )
} catch {
    check(false, "expose_text threw \(error), expected to succeed")
}

// Assert 21: read_block(unknown_uuid) → VaultError.BlockNotFound(uuid matches).
do {
    let folderPath = Data(vault001Url.path.utf8)
    let out = try openVaultWithPassword(folderPath: folderPath, password: password001)
    defer { out.identity.wipe() }
    defer { out.manifest.wipe() }
    let unknownUuid = Data(repeating: 0, count: 16)
    _ = try readBlock(
        identity: out.identity,
        manifest: out.manifest,
        blockUuid: unknownUuid
    )
    check(false, "read_block(unknown_uuid) should have thrown VaultError.BlockNotFound")
} catch let e as VaultError {
    if case let .BlockNotFound(uuidHex) = e {
        check(
            uuidHex == "00000000000000000000000000000000",
            "read_block(unknown_uuid) → VaultError.BlockNotFound(uuid_hex=\"\(uuidHex)\")"
        )
    } else {
        check(false, "unknown UUID threw wrong VaultError variant: \(e)")
    }
} catch {
    check(false, "unknown UUID threw \(error), expected VaultError.BlockNotFound")
}

// Assert 22: wipe → record_count == 0.
do {
    let folderPath = Data(vault001Url.path.utf8)
    let out = try openVaultWithPassword(folderPath: folderPath, password: password001)
    defer { out.identity.wipe() }
    defer { out.manifest.wipe() }
    let block = try readBlock(
        identity: out.identity,
        manifest: out.manifest,
        blockUuid: vault001BlockUuid
    )
    block.wipe()
    let countAfter = block.recordCount()
    check(
        countAfter == 0,
        "wipe → record_count == 0 (got \(countAfter))"
    )
} catch {
    check(false, "wipe threw \(error), expected to succeed")
}
```

Update the assertion-count print line:

Find:

```swift
        Data("FAIL: \(failures.count) of 18 assertion(s) failed\n".utf8)
```

Replace with:

```swift
        Data("FAIL: \(failures.count) of 22 assertion(s) failed\n".utf8)
```

- [ ] **Step 2: Run the Swift smoke runner**

```bash
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh 2>&1 | tail -10
```

Expected: 22 PASS lines + `OK: secretary uniffi Swift smoke runner — all assertions passed.`

If a Swift compile error mentions camelCase identifier names (e.g. `recordCount` vs `record_count`), uniffi's Swift codegen camelCases UDL identifiers automatically — verify the Swift names match the codegen output; they should already (the asserts above use camelCase).

- [ ] **Step 3: Add B.4b asserts to the Kotlin smoke runner**

Edit `ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt`. Per the project memory `project_secretary_uniffi_codegen_renames.md`, Kotlin auto-renames `wipe` → `close` (because `AutoCloseable` is auto-generated and the UDL `wipe()` collides). The asserts below use `close()` for the cascading cleanup. Also: Kotlin uniffi codegen prefixes Throwable subclass names with the enum name (e.g. `VaultException.BlockNotFound`), and `data` field accessors take the form `.uuidHex` (camelCase from `uuid_hex`).

Find the existing exit assertion block at the end of the file (likely an `if (failures.isNotEmpty()) { ... }` or similar). Append the B.4b asserts BEFORE it:

```kotlin

// =============================================================================
// B.4b — read_block asserts
// =============================================================================

val vault001BlockUuid = byteArrayOf(
    0x11.toByte(), 0x22.toByte(), 0x33.toByte(), 0x44.toByte(),
    0x55.toByte(), 0x66.toByte(), 0x77.toByte(), 0x88.toByte(),
    0x99.toByte(), 0xaa.toByte(), 0xbb.toByte(), 0xcc.toByte(),
    0xdd.toByte(), 0xee.toByte(), 0xff.toByte(), 0x00.toByte(),
)

// Assert 20: read_block success → record_count == 1 + field_count == 2.
try {
    val folderPathBytes = vault001Path.toString().toByteArray(Charsets.UTF_8)
    val out = openVaultWithPassword(folderPathBytes, password001)
    out.identity.use { id ->
        out.manifest.use { mf ->
            readBlock(id, mf, vault001BlockUuid).use { block ->
                val recordCount = block.recordCount()
                val record = block.recordAt(0u)
                val fieldCount = record?.fieldCount() ?: 0u
                check(
                    recordCount == 1uL && fieldCount == 2uL,
                    "read_block success → record_count == 1 + field_count == 2 (got $recordCount, $fieldCount)"
                )
            }
        }
    }
} catch (e: Throwable) {
    check(false, "read_block success threw $e, expected to succeed")
}

// Assert 21: field_by_name("password").expose_text() == "hunter2".
try {
    val folderPathBytes = vault001Path.toString().toByteArray(Charsets.UTF_8)
    val out = openVaultWithPassword(folderPathBytes, password001)
    out.identity.use { id ->
        out.manifest.use { mf ->
            readBlock(id, mf, vault001BlockUuid).use { block ->
                val record = block.recordAt(0u)!!
                val pwField = record.fieldByName("password")!!
                val secret = pwField.exposeText()
                check(
                    secret == "hunter2",
                    "field_by_name(\"password\").expose_text() == \"hunter2\" (got \"$secret\")"
                )
            }
        }
    }
} catch (e: Throwable) {
    check(false, "expose_text threw $e, expected to succeed")
}

// Assert 22: read_block(unknown_uuid) → VaultException.BlockNotFound(uuid_hex matches).
try {
    val folderPathBytes = vault001Path.toString().toByteArray(Charsets.UTF_8)
    val out = openVaultWithPassword(folderPathBytes, password001)
    out.identity.use { id ->
        out.manifest.use { mf ->
            val unknownUuid = ByteArray(16)
            try {
                readBlock(id, mf, unknownUuid)
                check(false, "read_block(unknown_uuid) should have thrown VaultException.BlockNotFound")
            } catch (e: VaultException.BlockNotFound) {
                check(
                    e.uuidHex == "00000000000000000000000000000000",
                    "read_block(unknown_uuid) → VaultException.BlockNotFound(uuidHex=\"${e.uuidHex}\")"
                )
            }
        }
    }
} catch (e: Throwable) {
    check(false, "unknown UUID threw unexpected $e")
}

// Assert 23: wipe (close) → record_count == 0.
try {
    val folderPathBytes = vault001Path.toString().toByteArray(Charsets.UTF_8)
    val out = openVaultWithPassword(folderPathBytes, password001)
    out.identity.use { id ->
        out.manifest.use { mf ->
            val block = readBlock(id, mf, vault001BlockUuid)
            block.close()  // uniffi-renamed wipe() → close() on Kotlin
            val countAfter = block.recordCount()
            check(
                countAfter == 0uL,
                "close → record_count == 0 (got $countAfter)"
            )
        }
    }
} catch (e: Throwable) {
    check(false, "close-then-record_count threw $e, expected to succeed")
}
```

(Note: Kotlin smoke counts assertions starting at the existing assert numbering. The exact "Assert N" comments above assume the existing file ends at "Assert 19" — adjust the numbering to match the actual count.)

- [ ] **Step 4: Run the Kotlin smoke runner**

```bash
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh 2>&1 | tail -15
```

Expected: 23 PASS lines + `OK: secretary uniffi Kotlin smoke runner — all assertions passed.` (was 19; +4 new B.4b asserts).

If a Kotlin compile error references `wipe` not existing on a B.4b interface, that's the auto-rename: the Kotlin codegen renamed `wipe()` → `close()`. The asserts above already use `.close()` — verify the file matches.

If `VaultException.BlockNotFound.uuidHex` is not accessible, Kotlin's data-class field projection may have used a different name; check the generated bindings file (typically under `target/release/build/secretary-ffi-uniffi-<hash>/out/secretary.kt`) for the actual field name and update the assert.

- [ ] **Step 5: Commit Task 9**

```bash
cd /Users/hherb/src/secretary
git add ffi/secretary-ffi-uniffi/tests/swift/main.swift ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt
git commit -m "$(cat <<'EOF'
feat(ffi-b4b-task9): Swift + Kotlin smokes — +4 read_block asserts each

Swift smoke gains 4 asserts (18 → 22 total):
- Assert 19: read_block success → record_count == 1 + field_count == 2
- Assert 20: field_by_name("password").exposeText() == "hunter2"
- Assert 21: read_block(unknownUuid) → VaultError.BlockNotFound(uuid_hex matches)
- Assert 22: wipe → record_count == 0

Kotlin smoke gains 4 asserts (19 → 23 total). Per uniffi 0.31 codegen
rename (project memory project_secretary_uniffi_codegen_renames.md),
the Kotlin asserts use .close() rather than .wipe() for cascading
cleanup. VaultException.BlockNotFound.uuidHex is the Kotlin-side
field accessor for the new variant's uuid_hex payload.

Both smokes hard-code the golden_vault_001 block UUID
(11223344-5566-7788-99aa-bbccddeeff00) — same KAT pinned by the
bridge crate's tests/read_block.rs and the pytest suite.

Refs: docs/superpowers/specs/2026-05-09-ffi-b4b-read-block-design.md
section "Swift / Kotlin smokes".

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---


## Phase 5 — Docs + handoff

### Task 10: README + ROADMAP refresh + NEXT_SESSION + dated handoff + open PR

**Files:**
- Modify: `README.md` (root) — bump test counts, add B.4b to FFI surface
- Modify: `ROADMAP.md` — mark B.4b complete with concrete deliverables
- Modify: `ffi/secretary-ffi-bridge/README.md` — add B.4b section
- Modify: `ffi/secretary-ffi-py/README.md` — add B.4b section
- Modify: `ffi/secretary-ffi-uniffi/README.md` — add B.4b section
- Modify: `NEXT_SESSION.md` — what shipped + what's next (B.4c) + commands
- Create: `docs/handoffs/2026-05-09-b4b-read-block.md` — dated copy of NEXT_SESSION.md

Per project memory `feedback_next_session_in_pr`: NEXT_SESSION.md must ride INSIDE the PR (commit on feature branch BEFORE pushing), not after merge.

- [ ] **Step 1: Run all gates one final time to gather the post-implementation totals**

```bash
cd /Users/hherb/src/secretary
cargo test --release --workspace 2>&1 | grep -E "^test result:" | python3 -c "
import sys, re
p=f=i=0
for line in sys.stdin:
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'TOTAL: {p} passed; {f} failed; {i} ignored')"
cargo clippy --release --workspace -- -D warnings && echo "clippy OK"
cargo fmt --all -- --check && echo "fmt OK"
uv run --directory ffi/secretary-ffi-py pytest 2>&1 | tail -3
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh 2>&1 | tail -3
```

Record the exact numbers from this run — they go into the README + NEXT_SESSION updates below.

Expected (per spec gate):
- cargo: **535+ passed + 9 ignored** (was 522 + 9; expecting ~542 = +20)
- clippy: clean
- fmt: OK
- pytest: **40 passed** (was 30; +10)
- conformance: PASS
- freshness: PASS
- Swift: **22/22 PASS** (was 18; +4)
- Kotlin: **23 PASS lines** (was 19; +4)

If any gate fails, debug it before continuing — the README/ROADMAP/NEXT_SESSION numbers must be honest.

- [ ] **Step 2: Update root `README.md`**

Find the test-count summary section (likely near the top under a "Status" or "Tests" heading). Update the cargo / pytest / Swift / Kotlin counts to match Step 1's actual numbers.

If there's an "FFI surface" or "What works today" section, add `read_block` to the list of FFI entry points (now 8 total).

If there's an "Architecture" section listing the FFI flavors' surface, ensure both PyO3 and uniffi note `read_block` + the 3 new opaque handles.

(Exact line numbers in the existing README depend on its current shape — read the file first and make targeted edits.)

- [ ] **Step 3: Update root `ROADMAP.md`**

Find the B.4b section. Currently it says something like "B.4b — read_block: design approved (commit X), spec pending implementation". Update to mark it complete with the concrete deliverables shipped:

```
- [x] **B.4b — FFI `read_block`** (PR <number>, merged on <YYYY-MM-DD>)
  - Bridge crate: NEW record/ directory module (split into 5 sub-files
    per project policy <500 lines each); read_block free fn + 3 opaque
    handles (BlockReadOutput / Record / FieldHandle); 13 KAT-pinned
    integration tests in tests/read_block.rs.
  - FfiVaultError +1 variant (BlockNotFound { uuid_hex }) — 7 total.
  - PyO3: read_block + 3 #[pyclass] + VaultBlockNotFound exception;
    +10 pytest tests.
  - uniffi: 3 new interfaces + 1 namespace fn + VaultError 7th variant;
    Swift smoke 18 → 22, Kotlin smoke 19 → 23.
  - Fuzz: defense-in-depth UTF-8 assertion on RecordFieldValue::Text
    in core/fuzz/fuzz_targets/record.rs.
```

Also update the running test-count totals if ROADMAP tracks them.

- [ ] **Step 4: Add B.4b section to `ffi/secretary-ffi-bridge/README.md`**

Find the existing B.4a section. After it, append a parallel B.4b section describing:
- The new free function `read_block(&UnlockedIdentity, &OpenVaultManifest, &[u8; 16]) -> Result<BlockReadOutput, FfiVaultError>`.
- The three new opaque handles + their accessor surfaces.
- The 7th `FfiVaultError::BlockNotFound { uuid_hex }` variant.
- The single-author block reading scope + multi-author deferral to B.4d.
- Reference to the spec doc + the integration test file.

(Follow the same structure as the existing B.4a section — copy its shape, swap the contents.)

- [ ] **Step 5: Add B.4b section to `ffi/secretary-ffi-py/README.md`**

Same shape — describe the foreign-Python projection: `sfp.read_block(identity, manifest, block_uuid: bytes) -> BlockReadOutput`; the 3 pyclasses; the `VaultBlockNotFound` exception; the `with` context-manager idiom for cascading wipe.

- [ ] **Step 6: Add B.4b section to `ffi/secretary-ffi-uniffi/README.md`**

Same shape — describe the Swift / Kotlin surface: `readBlock` namespace fn; the 3 new interfaces; the `VaultError.BlockNotFound` (Swift) / `VaultException.BlockNotFound` (Kotlin) error variant; the uniffi 0.31 wipe → close rename for the new interfaces.

- [ ] **Step 7: Update `NEXT_SESSION.md` (must ride inside the PR)**

Replace the current `NEXT_SESSION.md` (which describes the B.4b spec phase) with a new B.4b implementation phase document. Structure (per `/nextsession` skill instructions):

```markdown
# NEXT_SESSION.md

**Session date:** 2026-05-09 (Sub-project B.4b — implementation)
**Status:** B.4b implementation complete; PR pending review/merge.

## (1) What we shipped this session

| Task | Commit(s) | What landed |
|---|---|---|
| Task 1: error.rs +BlockNotFound | <sha> | 7th FfiVaultError variant + tripwire tests |
| Task 2: vault.rs +vault_folder | <sha> | OpenVaultManifestInner extension + crate-private accessors |
| Task 3: record/ directory module | <sha> | 5 sub-files (mod / output / handle / field / orchestration) + tests/read_block.rs (13 KAT-pinned integration tests) |
| Task 4: lib.rs re-exports | <sha> | pub use record::{...}; crate-doc updated for 8 entry points |
| Task 5: fuzz UTF-8 assertion | <sha> | Defense-in-depth tripwire in core/fuzz/fuzz_targets/record.rs |
| Task 6: PyO3 wrapper | <sha> | read_block #[pyfunction] + 3 #[pyclass] + VaultBlockNotFound |
| Task 7: pytest +10 | <sha> | KAT-pinned read_block tests |
| Task 8: uniffi UDL + glue | <sha> | 3 interfaces + namespace fn + VaultError 7th variant |
| Task 9: Swift + Kotlin smokes | <sha> | +4 asserts each |
| Task 10: docs + handoff | <sha> | This file + dated handoff + READMEs + ROADMAP |

### Verification at session close

| Check | Result |
|---|---|
| cargo test --release --workspace | <count> passed + 9 ignored, 0 failed |
| cargo clippy --release --workspace -- -D warnings | clean |
| cargo fmt --all -- --check | OK |
| uv run --directory ffi/secretary-ffi-py pytest | 40 passed |
| uv run core/tests/python/conformance.py | PASS |
| uv run core/tests/python/spec_test_name_freshness.py | PASS |
| Swift smoke | 22/22 PASS |
| Kotlin smoke | 23 PASS lines |

## (2) What's next

**Sub-project B.4c** — `save_block` (encrypt + persist record mutations).

### Concrete acceptance criteria for B.4c

| Gate | Target |
|---|---|
| cargo test --release --workspace | 555+ passed + 9 ignored (B.4b baseline + B.4c additions) |
| cargo clippy + fmt | clean / OK |
| pytest | 50+ passed (was 40) |
| Swift / Kotlin smokes | 26+ / 27+ (each +4) |
| New on-disk fixture: golden_vault_001b with a 2nd block | optional — depends on whether the round-trip test prefers an external fixture or in-test creation |

### Implementation sketch (refines during B.4c brainstorming)

1. Bridge crate: `save_block` — re-uses `OpenVaultManifestInner.identity_block_key` and `vault_folder` from B.4b. Atomic-write through `tempfile::persist`. Decision pending: `&self` interior-mutability vs. `&mut self` writer-borrow on `OpenVaultManifest`.
2. PyO3: `save_block` #[pyfunction] taking a builder-style record-input shape. Caller-zeroize discipline on input field values.
3. uniffi: parallel namespace fn + UDL.
4. Tests: round-trip (open → save → close → open → read) pinned against the same golden_vault_001 KAT plus a fresh second block.

## (3) Open decisions and risks

### Carried forward from B.4b (load-bearing for B.4c)

- `OpenVaultManifestInner.vault_folder: PathBuf` is in place — B.4c reuses for atomic writes.
- `Mutex<Option<...>>` on `OpenVaultManifest` is the pattern to extend — but B.4c may need a writer-borrow model. **Open decision:** refresh in B.4c brainstorming.
- The hybrid Record projection (FieldHandle as opaque + expose_text/expose_bytes boundary) is canonical. B.4c's save path needs the inverse: foreign caller hands BYTES IN; bridge wraps in SecretBytes; same handle shape on the input side.

### Risks for B.4c

- **Manifest re-sign cost.** B.4c rewrites the manifest after every save_block to add the new BlockEntry. Argon2id is not in this path (the IBK is already in memory), but Ed25519 + ML-DSA-65 signature generation is — adds ~5ms per save. Performance budget likely fine for v1 single-author UIs but should be measured.
- **Concurrent save_block + read_block.** With the current `Mutex<Option<...>>` pattern the manifest lock blocks reads during a save. Acceptable for v1 single-threaded UIs; B.4c brainstorming should confirm.

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git checkout main
git pull --ff-only

# Verify post-merge baseline:
cargo test --release --workspace 2>&1 | grep -E "^test result:" | python3 -c "
import sys, re
p=f=i=0
for line in sys.stdin:
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'TOTAL: {p} passed; {f} failed; {i} ignored')"

# Apply maturin/uv nuclear cache fix proactively (B.4b added substantial PyO3 surface):
rm -rf ffi/secretary-ffi-py/.venv
find ~/.cache/uv -name "*secretary*" -exec rm -rf {} + 2>/dev/null
( cd ffi/secretary-ffi-py && uv sync && uv run maturin develop --release --uv )
uv run --directory ffi/secretary-ffi-py pytest

# Begin B.4c:
# 1. Brainstorm with superpowers:brainstorming skill — settle the
#    Mutex<Option<...>> vs. &mut self decision + the foreign-side
#    record-input shape.
# 2. Write the spec → docs/superpowers/specs/2026-05-XX-ffi-b4c-save-block-design.md
# 3. Plan with writing-plans → docs/superpowers/plans/2026-05-XX-ffi-b4c-save-block.md
# 4. Execute with subagent-driven-development.
```

---

## Closing inventory (B.4b implementation)

- **Branch:** feat/ffi-b4b-read-block (PR <number>).
- **Total commits:** 10 (Tasks 1–10).
- **Workspace tests:** <count> passed + 9 ignored.
- **Pytest:** 40.
- **Swift smoke:** 22/22.
- **Kotlin smoke:** 23 PASS lines.
- **Bridge crate:** ~80 unit/integration tests.
- **uniffi crate:** 17 unit tests.
- **Spec doc:** docs/superpowers/specs/2026-05-09-ffi-b4b-read-block-design.md (623 lines).
- **Plan doc:** docs/superpowers/plans/2026-05-09-ffi-b4b-read-block.md (this file).
- **Handoff:** docs/handoffs/2026-05-09-b4b-read-block.md.
```

(Replace `<sha>`, `<count>`, and `<number>` placeholders with the actual values gathered during execution.)

- [ ] **Step 8: Save a dated copy under `docs/handoffs/`**

```bash
cp NEXT_SESSION.md docs/handoffs/2026-05-09-b4b-read-block.md
```

- [ ] **Step 9: Commit Task 10 (docs + NEXT_SESSION + handoff)**

Per project memory `feedback_next_session_in_pr`, this commit MUST land on the feature branch BEFORE the PR push.

```bash
cd /Users/hherb/src/secretary
git add README.md ROADMAP.md NEXT_SESSION.md docs/handoffs/2026-05-09-b4b-read-block.md \
        ffi/secretary-ffi-bridge/README.md ffi/secretary-ffi-py/README.md \
        ffi/secretary-ffi-uniffi/README.md
git commit -m "$(cat <<'EOF'
docs(ffi-b4b-task10): refresh READMEs + ROADMAP + NEXT_SESSION + handoff

- README.md: bump test counts (cargo 522 → <new>; pytest 30 → 40;
  Swift 18 → 22; Kotlin 19 → 23). Add read_block to FFI surface list.
- ROADMAP.md: mark B.4b complete with concrete deliverables list.
- ffi/*/README.md: add B.4b section to each binding-flavor README.
- NEXT_SESSION.md: replace B.4b-spec session with B.4b-impl session;
  point next session at B.4c (save_block) brainstorming.
- docs/handoffs/2026-05-09-b4b-read-block.md: dated copy of
  NEXT_SESSION.md per the historical-timeline convention.

Per project memory feedback_next_session_in_pr, this commit lands on
the feature branch BEFORE the PR push so post-merge main carries an
accurate baton.

Refs: docs/superpowers/specs/2026-05-09-ffi-b4b-read-block-design.md
+ docs/superpowers/plans/2026-05-09-ffi-b4b-read-block.md.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 10: Push the feature branch + open the PR**

```bash
git push -u origin feat/ffi-b4b-read-block
gh pr create --title "feat(ffi-b4b): expose folder-based read_block through PyO3 + uniffi via shared bridge crate" --body "$(cat <<'EOF'
## Summary
- New top-level entry point `read_block(&UnlockedIdentity, &OpenVaultManifest, &[u8; 16]) -> Result<BlockReadOutput, FfiVaultError>` on the bridge crate, projected through PyO3 + uniffi.
- Three new opaque handles (`BlockReadOutput`, `Record`, `FieldHandle`) under the hybrid Record projection: non-secret metadata is value-typed, secret payload is opaque-handle with explicit `expose_text()` / `expose_bytes()` boundary.
- `FfiVaultError` grows from 6 → 7 variants (+ `BlockNotFound { uuid_hex }`); `OpenVaultManifestInner` gains `vault_folder: PathBuf` (bridge-internal, no public B.4a surface change).
- `core/fuzz/fuzz_targets/record.rs` gains a defense-in-depth UTF-8-validity assertion on every successfully-decoded `RecordFieldValue::Text`.
- v1 single-author block reading only — multi-author flow deferred to B.4d's `share_block`.
- Bridge crate's new `record/` is a directory module split into 5 sub-files (per project policy <500 lines each); 13 KAT-pinned integration tests live in `tests/read_block.rs`.

## Spec
docs/superpowers/specs/2026-05-09-ffi-b4b-read-block-design.md (commit `3093782`).

## Plan
docs/superpowers/plans/2026-05-09-ffi-b4b-read-block.md.

## Test plan
- [ ] `cargo test --release --workspace` — totals visible in CI (target: 535+ passed + 9 ignored).
- [ ] `cargo clippy --release --workspace -- -D warnings` clean.
- [ ] `cargo fmt --all -- --check` clean.
- [ ] `uv run --directory ffi/secretary-ffi-py pytest` — 40 passed.
- [ ] `uv run core/tests/python/conformance.py` PASS.
- [ ] `uv run core/tests/python/spec_test_name_freshness.py` PASS.
- [ ] `bash ffi/secretary-ffi-uniffi/tests/swift/run.sh` — 22/22.
- [ ] `bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` — 23 PASS lines.
- [ ] `cargo fuzz run record -- -runs=10000` (nightly, manual) — clean.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

Per project memory `feedback_stay_in_inner_loop`: do NOT auto-merge; the user reviews the PR manually.

---

## Self-review

Before declaring this plan ready, run through the following checklist:

**1. Spec coverage:** Every section/requirement from the spec is exercised by at least one task:
- Goals 1–8 → Tasks 1, 2, 3, 4, 5, 6, 7, 8, 9.
- Non-goals (no save_block / no share_block / no trash / no multi-author / no vector_clock / no schema_version / no Record.unknown / no Record.tombstoned_at_ms / no conformance.py extension / no new fixture / no CI / no UnlockedIdentity public-key accessors): all preserved by NOT adding code for them.
- Architecture (crate layout / FFI surface / OpenVaultManifestInner extension / read_block orchestration / key invariants): Tasks 1–4.
- Components (Bridge crate types / FfiVaultError / mapping table / PyO3 / uniffi UDL): Tasks 1, 3, 6, 8.
- Testing (bridge crate unit tests / pytest / Swift+Kotlin smokes / verification gate): Tasks 3, 7, 9, 10.
- Decisions log §1–§9: all reflected in the implementation steps.
- Open questions / risks (in scope: UTF-8 fuzz assertion): Task 5.

**2. Placeholder scan:** No "TBD", "implement later", "add appropriate error handling", "similar to Task N" without code. Every step that changes code shows the code. Type names + method signatures are consistent across tasks (e.g. `Record::new` takes the same individual-args signature in Task 3 and is referenced in orchestration; `FieldHandle::new` is referenced in `From<core::Record>` in Task 3 Step 6's orchestration code).

**3. Type consistency:** `BlockReadOutput`, `Record`, `FieldHandle` use the same constructor signatures across all phases. The PyO3 newtype wrappers (Task 6) and the uniffi newtype wrappers (Task 8) both forward to the same bridge methods. Error mapping arms in `ffi_vault_error_to_pyerr` (Task 6) and `From<FfiVaultError> for VaultError` (Task 8) both add the 7th `BlockNotFound` arm.

If any inconsistency surfaces during execution, fix in-place rather than working around — the plan is the contract.

