# B.4d `share_block` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose `core::vault::share_block` end-to-end through the bridge crate, PyO3, and uniffi flavors so foreign callers can append one new recipient to an existing block via canonical-CBOR `ContactCard` bytes-in.

**Architecture:** Mirrors B.4c (`save_block`) 1-for-1: shared `secretary-ffi-bridge` crate exposes a `share/` module containing `orchestration::share_block`; `secretary-ffi-py` and `secretary-ffi-uniffi` project that single function through their respective binding macros. Reuses the B.4c `snapshot_for_save_block` / `replace_manifest_and_file` helpers verbatim. New input shape: bytes-in `ContactCard` (canonical CBOR), validated inside the bridge. New error surface: 4 typed `FfiVaultError` variants atomically added across all three crates (cross-flavor exhaustive `match`es require simultaneous growth).

**Tech Stack:** stable Rust (workspace), `proptest`, PyO3 0.28 + maturin, uniffi 0.31, `cargo-fuzz` excluded, `uv` for Python.

**Spec:** [`docs/superpowers/specs/2026-05-10-ffi-b4d-share-block-design.md`](../specs/2026-05-10-ffi-b4d-share-block-design.md)

---

## File Structure

| File | Action | Purpose |
|---|---|---|
| `ffi/secretary-ffi-bridge/src/error.rs` | Modify | +4 variants on `FfiVaultError` (NotAuthor / RecipientAlreadyPresent / MissingRecipientCard / CardDecodeFailure); +3 arms in `From<core::VaultError>` (CardDecodeFailure is bridge-internal) |
| `ffi/secretary-ffi-bridge/src/vault.rs` | Modify | +1 accessor `owner_card_bytes()` + 2 unit tests |
| `ffi/secretary-ffi-bridge/src/share/mod.rs` | Create | Module docs + re-exports |
| `ffi/secretary-ffi-bridge/src/share/orchestration.rs` | Create | `pub fn share_block(...) -> Result<(), FfiVaultError>` + private `map_core_vault_error` helper |
| `ffi/secretary-ffi-bridge/src/lib.rs` | Modify | +1 line `pub use share::share_block;` and module declaration |
| `ffi/secretary-ffi-bridge/tests/share_block.rs` | Create | 7 integration tests (happy path + 6 failure modes) |
| `ffi/secretary-ffi-bridge/tests/share_block_proptest.rs` | Create | 1 round-trip proptest (16 cases) |
| `ffi/secretary-ffi-uniffi/src/secretary.udl` | Modify | +4 `VaultError` variants; +1 namespace fn `share_block`; +1 `OpenVaultManifest` method `owner_card_bytes` |
| `ffi/secretary-ffi-uniffi/src/errors.rs` | Modify | +4 variants on uniffi-side `VaultError` enum + `From<FfiVaultError>` arms + 8 pin tests |
| `ffi/secretary-ffi-uniffi/src/namespace.rs` | Modify | +1 namespace fn `share_block` (UUID validation + forward to bridge) |
| `ffi/secretary-ffi-uniffi/src/wrappers/vault.rs` | Modify | +1 `owner_card_bytes()` impl on the `OpenVaultManifest` wrapper |
| `ffi/secretary-ffi-py/src/lib.rs` | Modify | +1 `#[pyfunction] share_block`; +4 `#[pyclass(extends=PyVaultError)]` exception classes; +1 `owner_card_bytes` method on `OpenVaultManifest` pyclass |
| `ffi/secretary-ffi-py/tests/test_smoke.py` | Modify | +8 pytest tests |
| `ffi/secretary-ffi-uniffi/tests/swift/main.swift` | Modify | +4 Swift smoke assertions |
| `ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt` | Modify | +4 Kotlin smoke assertions |
| `README.md` | Modify | B.4d shipped row |
| `ROADMAP.md` | Modify | B.4d → DONE; B.5 surfaces as next |
| `NEXT_SESSION.md` | Modify | Reset for B.5 baton |
| `docs/handoffs/2026-05-10-b4d-share-block.md` | Create | Frozen NEXT_SESSION snapshot |

---

## Task 1: Atomic addition of 4 FfiVaultError variants across all 3 crates

**Why atomic:** every `match e { ... }` against `core::VaultError` or `FfiVaultError` is exhaustive; if a variant is added in one crate but not its consumers, compilation breaks. Mirrors PR #34 commit `bbbf2da`.

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/error.rs:631` (add 4 variants), `:746` (add 3 `From` arms)
- Modify: `ffi/secretary-ffi-uniffi/src/errors.rs` (mirror 4 variants + `From<FfiVaultError>`)
- Modify: `ffi/secretary-ffi-uniffi/src/secretary.udl` (mirror 4 enum variants)
- Modify: `ffi/secretary-ffi-py/src/lib.rs` (4 new exception classes + From<FfiVaultError> arms)

- [ ] **Step 1: Write failing bridge unit test for `NotAuthor` Display + From mapping**

In `ffi/secretary-ffi-bridge/src/error.rs` (append to existing test module near end of file):

```rust
#[test]
fn ffi_vault_error_not_author_display_pins_string() {
    let e = FfiVaultError::NotAuthor {
        expected_fingerprint_hex: "aa".repeat(16),
        got_fingerprint_hex: "bb".repeat(16),
    };
    assert_eq!(e.to_string(), "only the block author can share this block");
}

#[test]
fn from_core_vault_error_not_author_maps_to_ffi_not_author() {
    use secretary_core::vault::VaultError as VE;
    let core_err = VE::NotAuthor {
        expected: [0xaa; 16],
        got: [0xbb; 16],
    };
    let ffi: FfiVaultError = core_err.into();
    match ffi {
        FfiVaultError::NotAuthor {
            expected_fingerprint_hex,
            got_fingerprint_hex,
        } => {
            assert_eq!(expected_fingerprint_hex, "aa".repeat(16));
            assert_eq!(got_fingerprint_hex, "bb".repeat(16));
        }
        other => panic!("expected NotAuthor, got {other:?}"),
    }
}
```

- [ ] **Step 2: Run test to verify it fails (variant doesn't exist yet)**

Run: `cargo test --release -p secretary-ffi-bridge ffi_vault_error_not_author_display_pins_string -- --nocapture`
Expected: FAIL — `error[E0599]: no variant or associated item named NotAuthor`.

- [ ] **Step 3: Add the 4 new `FfiVaultError` variants**

In `ffi/secretary-ffi-bridge/src/error.rs`, inside `pub enum FfiVaultError { ... }` (after `SaveCryptoFailure { detail: String }`):

```rust
    /// Block-share authorization failure: the calling identity's
    /// `user_uuid` does not match the block's recorded `author_fingerprint`,
    /// OR the supplied `author_card`'s contact_uuid does not match the
    /// vault owner's `user_uuid`. v1 single-author: only the vault owner
    /// can share blocks they authored. The future "share-as-fork" path
    /// will lift this restriction; B.4d cements the v1 semantics.
    ///
    /// `expected_fingerprint_hex` is the 32-char lowercase hex of the
    /// fingerprint stored on disk in the block file's `author_fingerprint`
    /// field. `got_fingerprint_hex` is the 32-char lowercase hex of
    /// `fingerprint(author_card.to_canonical_cbor())`. Foreign callers
    /// can `bytes.fromhex(...)` either if needed.
    #[error("only the block author can share this block")]
    NotAuthor {
        /// 32-char lowercase hex of the on-disk author fingerprint.
        expected_fingerprint_hex: String,
        /// 32-char lowercase hex of the supplied author-card fingerprint.
        got_fingerprint_hex: String,
    },

    /// The supplied `new_recipient` is already in the block's wire-level
    /// recipient table (deduplication check performed by core, key on
    /// fingerprint). Foreign UX: idempotent — the recipient already has
    /// access; no further action needed.
    #[error("recipient is already present in the block's recipient set")]
    RecipientAlreadyPresent,

    /// The caller's `existing_recipient_cards` did not cover every
    /// recipient currently in the block's wire-level recipient table.
    /// `recipient_fingerprint_hex` is the 32-char lowercase hex of the
    /// missing recipient's fingerprint; foreign callers can use it to
    /// look up the contact card in their address book / contacts dir.
    #[error("missing contact card for recipient: {recipient_fingerprint_hex}")]
    MissingRecipientCard {
        /// 32-char lowercase hex of the missing recipient's fingerprint.
        recipient_fingerprint_hex: String,
    },

    /// One of the canonical-CBOR ContactCard byte slices passed to
    /// `share_block` failed to decode via
    /// `ContactCard::from_canonical_cbor`. Constructed directly inside
    /// the bridge — never reachable through `From<core::VaultError>`
    /// (mirrors `SaveCryptoFailure`'s bridge-internal pattern).
    #[error("failed to decode contact card: {detail}")]
    CardDecodeFailure {
        /// Diagnostic text from the inner `CardError` variant's `Display`
        /// impl. Free-form; not part of the API contract.
        detail: String,
    },
```

In the same file, inside `impl From<secretary_core::vault::VaultError> for FfiVaultError { fn from(e: VE) -> Self { match e { ... } } }`, add three new arms (BEFORE the existing catch-all that folds to `CorruptVault`):

```rust
            VE::NotAuthor { expected, got } => FfiVaultError::NotAuthor {
                expected_fingerprint_hex: hex::encode(expected),
                got_fingerprint_hex: hex::encode(got),
            },
            VE::RecipientAlreadyPresent => FfiVaultError::RecipientAlreadyPresent,
            VE::MissingRecipientCard {
                recipient_fingerprint,
            } => FfiVaultError::MissingRecipientCard {
                recipient_fingerprint_hex: hex::encode(recipient_fingerprint),
            },
```

If `hex` crate is not already in `ffi/secretary-ffi-bridge/Cargo.toml`, add it (or use `format!("{:02x}", ...)` over the bytes — check existing pattern in the same file by grepping for `BlockNotFound { uuid_hex }`'s mapping, which already encodes 16-byte UUID as hex).

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --release -p secretary-ffi-bridge ffi_vault_error_not_author -- --nocapture`
Expected: PASS for both tests.

- [ ] **Step 5: Repeat steps 1-4 for `RecipientAlreadyPresent`, `MissingRecipientCard`, `CardDecodeFailure`**

Tests to add (same structure):

```rust
#[test]
fn ffi_vault_error_recipient_already_present_display_pins_string() {
    let e = FfiVaultError::RecipientAlreadyPresent;
    assert_eq!(
        e.to_string(),
        "recipient is already present in the block's recipient set"
    );
}

#[test]
fn from_core_vault_error_recipient_already_present_maps_to_ffi() {
    use secretary_core::vault::VaultError as VE;
    let ffi: FfiVaultError = VE::RecipientAlreadyPresent.into();
    assert!(matches!(ffi, FfiVaultError::RecipientAlreadyPresent));
}

#[test]
fn ffi_vault_error_missing_recipient_card_display_pins_string() {
    let e = FfiVaultError::MissingRecipientCard {
        recipient_fingerprint_hex: "cc".repeat(16),
    };
    assert_eq!(
        e.to_string(),
        format!("missing contact card for recipient: {}", "cc".repeat(16))
    );
}

#[test]
fn from_core_vault_error_missing_recipient_card_maps_to_ffi() {
    use secretary_core::vault::VaultError as VE;
    let ffi: FfiVaultError = VE::MissingRecipientCard {
        recipient_fingerprint: [0xcc; 16],
    }
    .into();
    match ffi {
        FfiVaultError::MissingRecipientCard {
            recipient_fingerprint_hex,
        } => assert_eq!(recipient_fingerprint_hex, "cc".repeat(16)),
        other => panic!("expected MissingRecipientCard, got {other:?}"),
    }
}

#[test]
fn ffi_vault_error_card_decode_failure_display_pins_string() {
    let e = FfiVaultError::CardDecodeFailure {
        detail: "malformed CBOR".into(),
    };
    assert_eq!(e.to_string(), "failed to decode contact card: malformed CBOR");
}
```

(`CardDecodeFailure` has only one test — there is no `From<core::VaultError>` arm for it.)

- [ ] **Step 6: Add the 4 mirror variants to uniffi-side `VaultError` enum**

In `ffi/secretary-ffi-uniffi/src/secretary.udl`, inside the `[Error] enum VaultError { ... }` block, append the 4 string identifiers in the order matching the bridge:

```idl
[Error]
enum VaultError {
    // ... 9 existing ...
    "NotAuthor",
    "RecipientAlreadyPresent",
    "MissingRecipientCard",
    "CardDecodeFailure",
};
```

In `ffi/secretary-ffi-uniffi/src/errors.rs`, mirror the 4 variants on the local enum (with the same field shapes — uniffi enums-with-fields use Rust-side struct variants):

```rust
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    // ... 9 existing ...

    #[error("only the block author can share this block")]
    NotAuthor {
        expected_fingerprint_hex: String,
        got_fingerprint_hex: String,
    },

    #[error("recipient is already present in the block's recipient set")]
    RecipientAlreadyPresent,

    #[error("missing contact card for recipient: {recipient_fingerprint_hex}")]
    MissingRecipientCard {
        recipient_fingerprint_hex: String,
    },

    #[error("failed to decode contact card: {detail}")]
    CardDecodeFailure {
        detail: String,
    },
}
```

Add 4 arms in `impl From<FfiVaultError> for VaultError`:

```rust
            FfiVaultError::NotAuthor {
                expected_fingerprint_hex,
                got_fingerprint_hex,
            } => VaultError::NotAuthor {
                expected_fingerprint_hex,
                got_fingerprint_hex,
            },
            FfiVaultError::RecipientAlreadyPresent => VaultError::RecipientAlreadyPresent,
            FfiVaultError::MissingRecipientCard {
                recipient_fingerprint_hex,
            } => VaultError::MissingRecipientCard {
                recipient_fingerprint_hex,
            },
            FfiVaultError::CardDecodeFailure { detail } => {
                VaultError::CardDecodeFailure { detail }
            }
```

- [ ] **Step 7: Add 8 uniffi pin tests (mirroring B.4c's `a31e6e6` shape)**

In `ffi/secretary-ffi-uniffi/src/errors.rs`, inside the existing `mod tests`:

```rust
#[test]
fn vault_error_not_author_display_matches_bridge() {
    let e = VaultError::NotAuthor {
        expected_fingerprint_hex: "aa".repeat(16),
        got_fingerprint_hex: "bb".repeat(16),
    };
    assert_eq!(e.to_string(), "only the block author can share this block");
}

#[test]
fn vault_error_not_author_translation_from_bridge_preserves_fields() {
    let bridge_err = secretary_ffi_bridge::FfiVaultError::NotAuthor {
        expected_fingerprint_hex: "aa".repeat(16),
        got_fingerprint_hex: "bb".repeat(16),
    };
    match VaultError::from(bridge_err) {
        VaultError::NotAuthor {
            expected_fingerprint_hex,
            got_fingerprint_hex,
        } => {
            assert_eq!(expected_fingerprint_hex, "aa".repeat(16));
            assert_eq!(got_fingerprint_hex, "bb".repeat(16));
        }
        other => panic!("expected NotAuthor, got {other:?}"),
    }
}

#[test]
fn vault_error_recipient_already_present_display_matches_bridge() {
    let e = VaultError::RecipientAlreadyPresent;
    assert_eq!(e.to_string(), "recipient is already present in the block's recipient set");
}

#[test]
fn vault_error_recipient_already_present_translation_from_bridge() {
    let bridge_err = secretary_ffi_bridge::FfiVaultError::RecipientAlreadyPresent;
    assert!(matches!(
        VaultError::from(bridge_err),
        VaultError::RecipientAlreadyPresent
    ));
}

#[test]
fn vault_error_missing_recipient_card_display_matches_bridge() {
    let e = VaultError::MissingRecipientCard {
        recipient_fingerprint_hex: "cc".repeat(16),
    };
    assert_eq!(
        e.to_string(),
        format!("missing contact card for recipient: {}", "cc".repeat(16))
    );
}

#[test]
fn vault_error_missing_recipient_card_translation_preserves_fp() {
    let bridge_err = secretary_ffi_bridge::FfiVaultError::MissingRecipientCard {
        recipient_fingerprint_hex: "cc".repeat(16),
    };
    match VaultError::from(bridge_err) {
        VaultError::MissingRecipientCard {
            recipient_fingerprint_hex,
        } => assert_eq!(recipient_fingerprint_hex, "cc".repeat(16)),
        other => panic!("expected MissingRecipientCard, got {other:?}"),
    }
}

#[test]
fn vault_error_card_decode_failure_display_matches_bridge() {
    let e = VaultError::CardDecodeFailure {
        detail: "bad CBOR".into(),
    };
    assert_eq!(e.to_string(), "failed to decode contact card: bad CBOR");
}

#[test]
fn vault_error_card_decode_failure_translation_preserves_detail() {
    let bridge_err = secretary_ffi_bridge::FfiVaultError::CardDecodeFailure {
        detail: "bad CBOR".into(),
    };
    match VaultError::from(bridge_err) {
        VaultError::CardDecodeFailure { detail } => assert_eq!(detail, "bad CBOR"),
        other => panic!("expected CardDecodeFailure, got {other:?}"),
    }
}
```

- [ ] **Step 8: Add 4 PyO3 exception classes**

In `ffi/secretary-ffi-py/src/lib.rs`, near the existing exception class declarations (search for `create_exception!(... PyVaultBlockNotFound, ...)`):

```rust
create_exception!(secretary_ffi_py, PyVaultNotAuthor, PyVaultError);
create_exception!(secretary_ffi_py, PyVaultRecipientAlreadyPresent, PyVaultError);
create_exception!(secretary_ffi_py, PyVaultMissingRecipientCard, PyVaultError);
create_exception!(secretary_ffi_py, PyVaultCardDecodeFailure, PyVaultError);
```

In the same file, register them on the module (search for `m.add("VaultBlockNotFound", py.get_type::<PyVaultBlockNotFound>())?;` and add 4 lines below it with their respective Python-facing names: `VaultNotAuthor`, `VaultRecipientAlreadyPresent`, `VaultMissingRecipientCard`, `VaultCardDecodeFailure`).

In the `From<FfiVaultError> for PyErr` impl (search for the existing `match e { FfiVaultError::BlockNotFound { ... } => ...`), add 4 arms:

```rust
            FfiVaultError::NotAuthor {
                expected_fingerprint_hex,
                got_fingerprint_hex,
            } => {
                let msg = format!(
                    "{}: expected={}, got={}",
                    e, expected_fingerprint_hex, got_fingerprint_hex
                );
                PyVaultNotAuthor::new_err(msg)
            }
            FfiVaultError::RecipientAlreadyPresent => {
                PyVaultRecipientAlreadyPresent::new_err(format!("{e}"))
            }
            FfiVaultError::MissingRecipientCard {
                recipient_fingerprint_hex,
            } => {
                let msg = format!("{}: {}", e, recipient_fingerprint_hex);
                PyVaultMissingRecipientCard::new_err(msg)
            }
            FfiVaultError::CardDecodeFailure { detail } => {
                PyVaultCardDecodeFailure::new_err(format!("{}: {}", e, detail))
            }
```

(Match the format exactly to whatever B.4c's `SaveCryptoFailure` arm does — search for that for the pattern reference.)

- [ ] **Step 9: Run full workspace tests + lint**

Run: `cargo test --release --workspace 2>&1 | grep "test result:" | head -5`
Expected: ok lines for every crate, no failures.

Run: `cargo clippy --release --workspace -- -D warnings`
Expected: no output (clean).

Run: `cargo fmt --all -- --check`
Expected: no output (clean).

- [ ] **Step 10: Commit**

```bash
git add ffi/secretary-ffi-bridge/src/error.rs \
        ffi/secretary-ffi-uniffi/src/errors.rs \
        ffi/secretary-ffi-uniffi/src/secretary.udl \
        ffi/secretary-ffi-py/src/lib.rs
git commit -m "feat(ffi-b4d): add 4 share_block error variants atomically across crates

NotAuthor, RecipientAlreadyPresent, MissingRecipientCard, and
CardDecodeFailure variants added simultaneously to FfiVaultError, the
uniffi-side VaultError mirror, and the PyO3 exception class set.
Atomic because exhaustive match ergonomics on the From<core::VaultError>
impl require all flavors to grow at once.

7 bridge unit tests pin Display strings + From<core::VaultError>
mappings (CardDecodeFailure has no From arm — bridge-internal only,
mirroring B.4c's SaveCryptoFailure pattern).

8 uniffi pin tests mirror Display strings + From<FfiVaultError>
translation, matching B.4c commit a31e6e6's shape.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Add `owner_card_bytes()` accessor on `OpenVaultManifest`

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/vault.rs:282` (after existing `owner_card()` accessor)
- Modify: `ffi/secretary-ffi-uniffi/src/secretary.udl` (`interface OpenVaultManifest` section)
- Modify: `ffi/secretary-ffi-uniffi/src/wrappers/vault.rs` (mirror impl)
- Modify: `ffi/secretary-ffi-py/src/lib.rs` (`#[pymethods]` for the OpenVaultManifest pyclass)

- [ ] **Step 1: Write failing bridge unit tests**

In `ffi/secretary-ffi-bridge/src/vault.rs` test module (search for `mod tests` near bottom, append):

```rust
#[test]
fn owner_card_bytes_returns_canonical_cbor_matching_on_disk_card_file() {
    use secretary_core::identity::ContactCard;
    use std::fs;
    let (out, vault_folder, _td) = open_vault_with_password_test_helper();
    let on_disk_path = vault_folder
        .join("contacts")
        .join(format!("{}.card", hex::encode(out.identity.user_uuid())));
    let on_disk_bytes = fs::read(&on_disk_path).expect("owner card on disk");
    let accessor_bytes = out.manifest.owner_card_bytes().expect("Some(bytes) live");
    // Both byte sequences must round-trip to the same ContactCard struct.
    let on_disk_card = ContactCard::from_canonical_cbor(&on_disk_bytes).unwrap();
    let accessor_card = ContactCard::from_canonical_cbor(&accessor_bytes).unwrap();
    assert_eq!(on_disk_card, accessor_card);
    // And the canonical re-encoding of either is byte-equal to accessor_bytes.
    assert_eq!(on_disk_card.to_canonical_cbor().unwrap(), accessor_bytes);
}

#[test]
fn owner_card_bytes_returns_none_after_wipe() {
    let (out, _vault_folder, _td) = open_vault_with_password_test_helper();
    out.manifest.wipe();
    assert!(out.manifest.owner_card_bytes().is_none());
}
```

(`open_vault_with_password_test_helper` — find the existing helper used by `manifest_body_and_owner_card_accessors_return_some_when_live_and_none_when_wiped` at vault.rs:801 and reuse it directly. If it returns a different shape, adapt.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --release -p secretary-ffi-bridge owner_card_bytes -- --nocapture`
Expected: FAIL — `error[E0599]: no method named owner_card_bytes`.

- [ ] **Step 3: Add the accessor**

In `ffi/secretary-ffi-bridge/src/vault.rs`, after the existing `owner_card()` method (around line 282):

```rust
    /// Canonical-CBOR bytes of the vault's `owner_card`. Returns the same
    /// byte sequence as the on-disk `<vault>/contacts/<owner_uuid>.card`
    /// content. Use as the `existing_recipient_cards` element when calling
    /// [`crate::share::share_block`] on a v1 owner-only block.
    ///
    /// `None` iff the manifest handle has been wiped.
    ///
    /// Encodes on demand via `ContactCard::to_canonical_cbor`. The
    /// `.expect()` is justified by the open-vault invariant: the card was
    /// decoded + verified during `open_vault` and lives behind an
    /// immutable handle, so re-encoding a previously-validated card cannot
    /// fail (no IO; deterministic encoder over fixed inputs).
    pub fn owner_card_bytes(&self) -> Option<Vec<u8>> {
        let g = self.inner.lock().expect("OpenVaultManifest inner poisoned");
        g.as_ref().map(|i| {
            i.owner_card
                .to_canonical_cbor()
                .expect("re-encoding a verified card cannot fail")
        })
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --release -p secretary-ffi-bridge owner_card_bytes -- --nocapture`
Expected: PASS for both tests.

- [ ] **Step 5: Add UDL declaration + uniffi wrapper impl**

In `ffi/secretary-ffi-uniffi/src/secretary.udl`, inside `interface OpenVaultManifest { ... }`, add:

```idl
    /// Canonical-CBOR bytes of the vault's owner contact card, suitable
    /// for passing as `existing_recipient_cards[0]` to share_block on a
    /// v1 owner-only block. Returns null after wipe.
    bytes? owner_card_bytes();
```

In `ffi/secretary-ffi-uniffi/src/wrappers/vault.rs` (or wherever the existing OpenVaultManifest wrapper methods live), mirror:

```rust
    pub fn owner_card_bytes(&self) -> Option<Vec<u8>> {
        self.inner.owner_card_bytes()
    }
```

- [ ] **Step 6: Add PyO3 method**

In `ffi/secretary-ffi-py/src/lib.rs`, inside the `#[pymethods] impl OpenVaultManifest { ... }` block, append:

```rust
    /// Canonical-CBOR bytes of the vault's owner contact card. Returns
    /// `None` after wipe. Suitable as the only element of
    /// `existing_recipient_cards` when calling `share_block` on a v1
    /// owner-only block.
    fn owner_card_bytes(&self) -> Option<Vec<u8>> {
        self.inner.owner_card_bytes()
    }
```

- [ ] **Step 7: Run full workspace tests + lint**

Run: `cargo test --release --workspace`
Expected: all green; bridge crate has +2 tests.

Run: `cargo clippy --release --workspace -- -D warnings && cargo fmt --all -- --check`
Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add ffi/secretary-ffi-bridge/src/vault.rs \
        ffi/secretary-ffi-uniffi/src/secretary.udl \
        ffi/secretary-ffi-uniffi/src/wrappers/vault.rs \
        ffi/secretary-ffi-py/src/lib.rs
git commit -m "feat(ffi-b4d): add owner_card_bytes accessor on OpenVaultManifest

Encodes on demand via ContactCard::to_canonical_cbor; .expect() justified
by the immutable-handle-over-validated-card invariant. Returns None
after wipe. Mirrored on uniffi (interface method) + PyO3 (pymethod) so
foreign callers have a one-liner for the v1 share_block happy path
where existing_recipient_cards = [owner_card_bytes].

2 bridge unit tests: round-trip equals on-disk <owner_uuid>.card content;
returns None post-wipe.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Stub `share_block` in `share/orchestration.rs`

The stub returns a placeholder `CardDecodeFailure` so the cross-flavor wiring compiles before real logic lands. Mirrors B.4c commit `d12567b`.

**Files:**
- Create: `ffi/secretary-ffi-bridge/src/share/mod.rs`
- Create: `ffi/secretary-ffi-bridge/src/share/orchestration.rs`
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs` (add `pub mod share;` + `pub use share::share_block;`)

- [ ] **Step 1: Create `share/mod.rs`**

```rust
//! `share_block` — append one new recipient to an existing block.
//!
//! Mirrors [`crate::save`]'s module layout. v1 single-author: only the
//! vault owner can share blocks they authored; the future "share-as-fork"
//! path will lift this restriction.
//!
//! Rationale: docs/superpowers/specs/2026-05-10-ffi-b4d-share-block-design.md.

mod orchestration;

pub use orchestration::share_block;
```

- [ ] **Step 2: Create `share/orchestration.rs` with stub**

```rust
//! `share_block` orchestration: decode caller-supplied ContactCard bytes,
//! snapshot the bridge handles, build a temporary `core::vault::OpenVault`,
//! call `core::vault::share_block`, write back the mutated manifest +
//! manifest_file on Ok, map errors per the spec §6 table.
//!
//! Failure invariant: bridge in-memory state is byte-identical to pre-call
//! on Err. On-disk state may have a partial write (block file rewritten
//! but manifest re-sign failed) — harmless because `open_vault` reads
//! only entries listed in the manifest.

use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;
use crate::vault::OpenVaultManifest;

/// Append one new recipient to an existing block. v1 single-author: only
/// the vault's owner can share blocks they authored.
///
/// See spec §4 for the full argument contract; §6 for error mapping;
/// §9 for the behavioral invariants this function pins.
#[allow(clippy::too_many_arguments)]
pub fn share_block(
    _identity: &UnlockedIdentity,
    _manifest: &OpenVaultManifest,
    _block_uuid: [u8; 16],
    _existing_recipient_cards: &[Vec<u8>],
    _new_recipient: &[u8],
    _device_uuid: [u8; 16],
    _now_ms: u64,
) -> Result<(), FfiVaultError> {
    Err(FfiVaultError::CardDecodeFailure {
        detail: "share_block stub — not yet implemented (Task 4)".into(),
    })
}
```

- [ ] **Step 3: Wire `share` module into `lib.rs`**

In `ffi/secretary-ffi-bridge/src/lib.rs`, near the existing `pub mod save;`:

```rust
pub mod share;

// Re-exports near the existing `pub use save::{...};` line:
pub use share::share_block;
```

- [ ] **Step 4: Run full workspace tests**

Run: `cargo test --release --workspace`
Expected: all existing tests still pass; the stub compiles.

- [ ] **Step 5: Commit**

```bash
git add ffi/secretary-ffi-bridge/src/share/ \
        ffi/secretary-ffi-bridge/src/lib.rs
git commit -m "feat(ffi-b4d): stub share_block returning CardDecodeFailure

New share/ module mirrors save/ layout. Stub allows the cross-flavor
wiring (uniffi namespace fn + PyO3 pyfunction in subsequent tasks) to
compile against the real signature before the orchestration logic
lands in Task 4.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Real `share_block` implementation + happy-path integration test

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/share/orchestration.rs`
- Create: `ffi/secretary-ffi-bridge/tests/share_block.rs`

- [ ] **Step 1: Write failing happy-path integration test**

Create `ffi/secretary-ffi-bridge/tests/share_block.rs`:

```rust
//! Integration tests for `secretary_ffi_bridge::share_block`.
//!
//! Mirrors `tests/save_block.rs` shape: each test opens a vault in a
//! tempdir, performs the share, and re-opens (or stages a fresh open as
//! the recipient) to verify the round-trip.

mod common;

use common::{create_test_vault, open_test_vault, MANIFEST_DEVICE_UUID};
use secretary_core::identity::ContactCard;
use secretary_ffi_bridge::{read_block, save_block, share_block, BlockInput};
use std::fs;

const NOW_MS_BASE: u64 = 1_700_000_000_000;

/// Happy path: owner saves a block; owner shares it with a freshly-minted
/// Alice; Alice's vault directory gets the block file + an Alice-shaped
/// manifest (test-staging — actual sync is Sub-project C); Alice can
/// read_block and recover the original plaintext.
#[test]
fn share_block_happy_path_owner_to_alice_round_trip() {
    let (owner_out, owner_folder, _owner_td) = create_test_vault();
    // Alice mints her own vault to source her ContactCard.
    let (alice_out, _alice_folder, _alice_td) = create_test_vault();

    // 1. Owner saves a block with one record.
    let block_uuid = [0xab; 16];
    let record_uuid = [0xcd; 16];
    let plaintext = "hunter2";
    let input = single_field_block_input(block_uuid, record_uuid, "password", plaintext);
    save_block(
        &owner_out.identity,
        &owner_out.manifest,
        input,
        MANIFEST_DEVICE_UUID,
        NOW_MS_BASE,
    )
    .expect("owner save_block should succeed");

    // 2. Owner shares with Alice.
    let owner_card_bytes = owner_out
        .manifest
        .owner_card_bytes()
        .expect("owner card present");
    let alice_card_bytes = alice_out
        .manifest
        .owner_card_bytes()
        .expect("alice card present");
    share_block(
        &owner_out.identity,
        &owner_out.manifest,
        block_uuid,
        &[owner_card_bytes.clone()],
        &alice_card_bytes,
        MANIFEST_DEVICE_UUID,
        NOW_MS_BASE + 1,
    )
    .expect("share_block should succeed");

    // 3. Stage Alice's vault: copy the shared block file + manifest into
    //    Alice's vault folder. (Sub-project C will replace this with real
    //    sync; the test does the equivalent file-level copy.)
    let block_uuid_hex: String = block_uuid.iter().map(|b| format!("{b:02x}")).collect();
    let block_filename = format!("{block_uuid_hex}.cbor.enc");
    let owner_block = owner_folder.join("blocks").join(&block_filename);
    // Alice's manifest must reference the new block; in lieu of a real
    // sync layer, we patch Alice's vault by copying the owner's manifest
    // into Alice's folder and the block file alongside.
    let alice_blocks_dir = _alice_folder.join("blocks");
    fs::create_dir_all(&alice_blocks_dir).unwrap();
    fs::copy(&owner_block, alice_blocks_dir.join(&block_filename)).unwrap();
    fs::copy(
        owner_folder.join("manifest.cbor.enc"),
        _alice_folder.join("manifest.cbor.enc"),
    )
    .unwrap();
    // Alice also needs the owner's card in her contacts dir (so her
    // open_vault can verify the shared block's author_fingerprint chain).
    let owner_card = ContactCard::from_canonical_cbor(&owner_card_bytes).unwrap();
    let owner_card_filename = format!(
        "{}.card",
        owner_card
            .contact_uuid
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    fs::create_dir_all(_alice_folder.join("contacts")).unwrap();
    fs::write(
        _alice_folder.join("contacts").join(&owner_card_filename),
        &owner_card_bytes,
    )
    .unwrap();

    // 4. Reopen as Alice and read_block.
    let alice_reopen = open_test_vault(&_alice_folder);
    let block = read_block(&alice_reopen.identity, &alice_reopen.manifest, block_uuid)
        .expect("alice read_block should succeed");
    assert_eq!(block.record_count(), 1);
    let rec = block.record_at(0).expect("one record");
    let pw = rec
        .field_by_name("password")
        .expect("password field")
        .expose_text()
        .expect("text payload");
    assert_eq!(pw, plaintext);
}
```

The `mod common;` line refers to `tests/common/mod.rs`. If it doesn't exist, copy the helper functions from `tests/save_block.rs`'s setup — find `create_test_vault`, `open_test_vault`, `single_field_block_input`, `MANIFEST_DEVICE_UUID` there. Lift them into a new `tests/common/mod.rs` so this test file and the existing save_block.rs can share.

- [ ] **Step 2: Run test to verify it fails (stub returns CardDecodeFailure)**

Run: `cargo test --release -p secretary-ffi-bridge --test share_block share_block_happy_path -- --nocapture`
Expected: FAIL — share_block returns CardDecodeFailure with the stub message.

- [ ] **Step 3: Replace stub with real implementation**

In `ffi/secretary-ffi-bridge/src/share/orchestration.rs`, replace the stub body with the full implementation. The full code follows spec §5 step-by-step:

```rust
use rand_core::OsRng;
use secretary_core::identity::ContactCard;
use secretary_core::vault::{OpenVault, VaultError};

use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;
use crate::vault::OpenVaultManifest;

#[allow(clippy::too_many_arguments)]
pub fn share_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: [u8; 16],
    existing_recipient_cards: &[Vec<u8>],
    new_recipient: &[u8],
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError> {
    // Step 0: decode every input card into core::ContactCard. Bytes-in
    // is the canonical wire shape (per spec §2 design decision). Any
    // decode failure surfaces as CardDecodeFailure — bridge-internal,
    // not reachable through From<core::VaultError>.
    let existing_decoded: Vec<ContactCard> = existing_recipient_cards
        .iter()
        .map(|b| ContactCard::from_canonical_cbor(b))
        .collect::<Result<_, _>>()
        .map_err(|e| FfiVaultError::CardDecodeFailure {
            detail: e.to_string(),
        })?;
    let new_decoded = ContactCard::from_canonical_cbor(new_recipient).map_err(|e| {
        FfiVaultError::CardDecodeFailure {
            detail: e.to_string(),
        }
    })?;

    // Step 1: snapshot manifest. Re-uses save's snapshot fn unchanged —
    // share_block needs the same 5-tuple.
    let (manifest_body, manifest_file, owner_card, ibk, vault_folder) = manifest
        .snapshot_for_save_block()
        .ok_or_else(|| FfiVaultError::CorruptVault {
            detail: "vault manifest handle has been closed".into(),
        })?;

    // Step 2: snapshot identity. Need both the IdentityBundle clone (for
    // OpenVault construction) AND the signer keys directly (core's
    // share_block takes them as separate &Ed25519Secret + &MlDsa65Secret
    // arguments, unlike save_block which derives them from
    // open_vault.identity).
    let identity_clone = identity
        .clone_inner_bundle()
        .ok_or_else(|| FfiVaultError::CorruptVault {
            detail: "identity handle has been closed".into(),
        })?;
    let signer_keys = identity
        .signer_secret_keys()
        .map_err(|e| FfiVaultError::CorruptVault {
            detail: format!("signer keys: {e}"),
        })?;

    // Step 3: build temporary OpenVault. owner_card serves as both the
    // OpenVault.owner_card field AND (cloned) the author_card argument
    // to core::share_block — for v1 single-author, owner == author.
    let author_card = owner_card.clone();
    let mut open_vault = OpenVault {
        identity_block_key: ibk,
        identity: identity_clone,
        owner_card,
        manifest: manifest_body,
        manifest_file,
    };

    // Step 4: call core. Single-recipient-append.
    let result = secretary_core::vault::share_block(
        &vault_folder,
        &mut open_vault,
        block_uuid,
        &author_card,
        &signer_keys.ed25519_sk,
        &signer_keys.ml_dsa_65_sk,
        &existing_decoded,
        &new_decoded,
        device_uuid,
        now_ms,
        &mut OsRng,
    );

    // Step 5: on Ok, write back. Failure-invariant matches B.4c verbatim.
    match result {
        Ok(()) => manifest
            .replace_manifest_and_file(open_vault.manifest, open_vault.manifest_file)
            .map_err(|e| FfiVaultError::CorruptVault {
                detail: e.to_string(),
            }),
        Err(e) => Err(map_core_vault_error_share(e)),
    }
}

/// Map [`secretary_core::vault::VaultError`] to [`FfiVaultError`] per the
/// spec §6 error table for share_block. NotAuthor / RecipientAlreadyPresent /
/// MissingRecipientCard fold into the matching new typed variants (via
/// the existing `From<VE>` impl). IO failures fold to FolderInvalid.
/// Block-decode failures during Step 2 of core::share_block (reading the
/// on-disk block file) fold to CorruptVault. Crypto/encoding failures
/// post-validation fold to SaveCryptoFailure.
fn map_core_vault_error_share(e: VaultError) -> FfiVaultError {
    match &e {
        VaultError::Io { context, source } => FfiVaultError::FolderInvalid {
            detail: format!("{context}: {source}"),
        },
        VaultError::Block { .. } => FfiVaultError::CorruptVault {
            detail: format!("{e}"),
        },
        // NotAuthor / RecipientAlreadyPresent / MissingRecipientCard are
        // handled by the existing `From<core::VaultError> for FfiVaultError`
        // impl — fall through to it for the typed mapping.
        VaultError::NotAuthor { .. }
        | VaultError::RecipientAlreadyPresent
        | VaultError::MissingRecipientCard { .. } => e.into(),
        _ => FfiVaultError::SaveCryptoFailure {
            detail: format!("{e}"),
        },
    }
}
```

NOTE: verify the exact field name of `signer_secret_keys()` return — check `ffi/secretary-ffi-bridge/src/identity.rs` for the struct shape (the spec calls them `ed25519_sk` and `ml_dsa_65_sk`; if the actual field names differ, adjust). Also verify `signer_secret_keys()` returns `Result<_, _>`; if it returns `Option<_>` instead, replace the `.map_err(...)` with `.ok_or_else(|| ...)`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --release -p secretary-ffi-bridge --test share_block share_block_happy_path -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Run full workspace + lint**

Run: `cargo test --release --workspace && cargo clippy --release --workspace -- -D warnings && cargo fmt --all -- --check`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add ffi/secretary-ffi-bridge/src/share/orchestration.rs \
        ffi/secretary-ffi-bridge/tests/share_block.rs \
        ffi/secretary-ffi-bridge/tests/common/
git commit -m "feat(ffi-b4d): implement share_block + first integration test

Real share_block implementation in src/share/orchestration.rs replaces
the Task-3 stub. Decodes caller-supplied canonical-CBOR ContactCard
bytes (bytes-in wire shape per spec §2), snapshots manifest + identity
via the existing B.4c helpers, builds a temporary core::OpenVault, calls
core::vault::share_block, and writes back the mutated manifest +
envelope on Ok via the existing replace_manifest_and_file helper.

map_core_vault_error_share handles share-specific error mapping:
NotAuthor / RecipientAlreadyPresent / MissingRecipientCard fold to
the typed variants via From<core::VaultError>; Block-decode failures
(on-disk block file) fold to CorruptVault; crypto/encoding failures
fold to SaveCryptoFailure.

Happy-path integration test: owner saves a block, shares to a freshly-
minted Alice, stages Alice's vault layout (manual file copy in lieu of
Sub-project C sync), re-opens as Alice, reads the block, asserts the
original plaintext recovers.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: NotAuthor failure mode test

**Files:**
- Modify: `ffi/secretary-ffi-bridge/tests/share_block.rs`

- [ ] **Step 1: Write failing test for NotAuthor**

Append to `tests/share_block.rs`:

```rust
/// Calling share_block with an identity whose user_uuid does not match
/// the block's author_fingerprint surfaces FfiVaultError::NotAuthor with
/// the two fingerprint hex strings populated.
#[test]
fn share_block_called_by_non_author_returns_not_author() {
    let (owner_out, owner_folder, _owner_td) = create_test_vault();
    // Bob is the impostor.
    let (bob_out, _bob_folder, _bob_td) = create_test_vault();
    let (alice_out, _alice_folder, _alice_td) = create_test_vault();

    // Owner saves the block.
    let block_uuid = [0xab; 16];
    let input = single_field_block_input(block_uuid, [0xcd; 16], "k", "v");
    save_block(
        &owner_out.identity,
        &owner_out.manifest,
        input,
        MANIFEST_DEVICE_UUID,
        NOW_MS_BASE,
    )
    .unwrap();

    // Stage Bob's vault by copying owner's manifest + block file + owner's
    // card. Bob then attempts to share. Bob's identity is NOT the author,
    // so the NotAuthor check fires.
    stage_recipient_vault(&owner_folder, &_bob_folder, &owner_out, block_uuid);
    let bob_reopen = open_test_vault(&_bob_folder);
    let owner_bytes = owner_out.manifest.owner_card_bytes().unwrap();
    let alice_bytes = alice_out.manifest.owner_card_bytes().unwrap();

    let err = share_block(
        &bob_reopen.identity,
        &bob_reopen.manifest,
        block_uuid,
        &[owner_bytes],
        &alice_bytes,
        MANIFEST_DEVICE_UUID,
        NOW_MS_BASE + 1,
    )
    .unwrap_err();
    match err {
        FfiVaultError::NotAuthor {
            expected_fingerprint_hex,
            got_fingerprint_hex,
        } => {
            assert_eq!(expected_fingerprint_hex.len(), 32);
            assert_eq!(got_fingerprint_hex.len(), 32);
            assert_ne!(expected_fingerprint_hex, got_fingerprint_hex);
        }
        other => panic!("expected NotAuthor, got {other:?}"),
    }
}
```

`stage_recipient_vault` is a helper to lift into `tests/common/mod.rs`: copies the owner's manifest + block files + owner's card into a recipient's vault folder. Lift the relevant chunk from Task 4's happy-path test into a function to share between tests.

- [ ] **Step 2: Run test → expect FAIL (compile or runtime, depending on helper status)**

Run: `cargo test --release -p secretary-ffi-bridge --test share_block share_block_called_by_non_author -- --nocapture`
Expected: FAIL — likely needs `stage_recipient_vault` helper.

- [ ] **Step 3: Add helper + run again**

Add `stage_recipient_vault` to `tests/common/mod.rs`. Implement to factor out the file-copying done inline in Task 4's happy-path test.

Run: `cargo test --release -p secretary-ffi-bridge --test share_block share_block_called_by_non_author -- --nocapture`
Expected: PASS — the From<core::VaultError::NotAuthor> mapping from Task 1 is what makes this work end-to-end.

- [ ] **Step 4: Commit**

```bash
git add ffi/secretary-ffi-bridge/tests/share_block.rs \
        ffi/secretary-ffi-bridge/tests/common/mod.rs
git commit -m "test(ffi-b4d): integration test for NotAuthor on non-author share attempt

Bob (a different vault's owner) opens the staged copy of the owner's
vault and attempts share_block. Bob's user_uuid does not match the
block's author_fingerprint, so core::share_block returns NotAuthor;
the bridge maps it to FfiVaultError::NotAuthor with both fingerprint
hex fields populated.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: RecipientAlreadyPresent failure mode test

- [ ] **Step 1: Append test**

```rust
/// Calling share_block twice with the same new_recipient surfaces
/// FfiVaultError::RecipientAlreadyPresent on the second call.
#[test]
fn share_block_with_duplicate_recipient_returns_already_present() {
    let (owner_out, _owner_folder, _owner_td) = create_test_vault();
    let (alice_out, _alice_folder, _alice_td) = create_test_vault();

    let block_uuid = [0xab; 16];
    let input = single_field_block_input(block_uuid, [0xcd; 16], "k", "v");
    save_block(
        &owner_out.identity,
        &owner_out.manifest,
        input,
        MANIFEST_DEVICE_UUID,
        NOW_MS_BASE,
    )
    .unwrap();

    let owner_bytes = owner_out.manifest.owner_card_bytes().unwrap();
    let alice_bytes = alice_out.manifest.owner_card_bytes().unwrap();

    // First share: ok.
    share_block(
        &owner_out.identity,
        &owner_out.manifest,
        block_uuid,
        &[owner_bytes.clone()],
        &alice_bytes,
        MANIFEST_DEVICE_UUID,
        NOW_MS_BASE + 1,
    )
    .unwrap();

    // Second share with the same Alice: RecipientAlreadyPresent.
    let err = share_block(
        &owner_out.identity,
        &owner_out.manifest,
        block_uuid,
        &[owner_bytes, alice_bytes.clone()],
        &alice_bytes,
        MANIFEST_DEVICE_UUID,
        NOW_MS_BASE + 2,
    )
    .unwrap_err();
    assert!(matches!(err, FfiVaultError::RecipientAlreadyPresent));
}
```

- [ ] **Step 2: Run + commit**

Run: `cargo test --release -p secretary-ffi-bridge --test share_block share_block_with_duplicate_recipient -- --nocapture`
Expected: PASS.

```bash
git add ffi/secretary-ffi-bridge/tests/share_block.rs
git commit -m "test(ffi-b4d): RecipientAlreadyPresent on duplicate recipient

Owner shares with Alice once (succeeds), then attempts the same share
again. The second call surfaces RecipientAlreadyPresent — idempotent
foreign-side UX hint.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: MissingRecipientCard failure mode test

- [ ] **Step 1: Append test**

```rust
/// Calling share_block with an existing_recipient_cards list that is
/// missing the author's card (a recipient currently in the wire-level
/// recipient table) surfaces FfiVaultError::MissingRecipientCard with
/// the unmatched fingerprint hex populated.
#[test]
fn share_block_with_missing_existing_recipient_card_returns_missing() {
    let (owner_out, _owner_folder, _owner_td) = create_test_vault();
    let (alice_out, _alice_folder, _alice_td) = create_test_vault();

    let block_uuid = [0xab; 16];
    let input = single_field_block_input(block_uuid, [0xcd; 16], "k", "v");
    save_block(
        &owner_out.identity,
        &owner_out.manifest,
        input,
        MANIFEST_DEVICE_UUID,
        NOW_MS_BASE,
    )
    .unwrap();

    // The block's wire-level recipient table currently contains the
    // owner. Pass an EMPTY existing_recipient_cards list; core's
    // MissingRecipientCard check fires for the owner's fingerprint.
    let alice_bytes = alice_out.manifest.owner_card_bytes().unwrap();
    let err = share_block(
        &owner_out.identity,
        &owner_out.manifest,
        block_uuid,
        &[],
        &alice_bytes,
        MANIFEST_DEVICE_UUID,
        NOW_MS_BASE + 1,
    )
    .unwrap_err();
    match err {
        FfiVaultError::MissingRecipientCard {
            recipient_fingerprint_hex,
        } => assert_eq!(recipient_fingerprint_hex.len(), 32),
        other => panic!("expected MissingRecipientCard, got {other:?}"),
    }
}
```

- [ ] **Step 2: Run + commit**

Run: `cargo test --release -p secretary-ffi-bridge --test share_block share_block_with_missing_existing_recipient_card -- --nocapture`
Expected: PASS.

```bash
git add ffi/secretary-ffi-bridge/tests/share_block.rs
git commit -m "test(ffi-b4d): MissingRecipientCard when caller omits a recipient

share_block called with an empty existing_recipient_cards list against
a block whose wire-level recipient table contains the owner surfaces
MissingRecipientCard with the owner's fingerprint hex.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: CardDecodeFailure failure mode test

- [ ] **Step 1: Append test**

```rust
/// Passing arbitrary bytes (not canonical CBOR ContactCard) to
/// share_block surfaces CardDecodeFailure with a non-empty detail
/// string.
#[test]
fn share_block_with_malformed_existing_card_returns_card_decode_failure() {
    let (owner_out, _owner_folder, _owner_td) = create_test_vault();
    let (alice_out, _alice_folder, _alice_td) = create_test_vault();

    let block_uuid = [0xab; 16];
    let input = single_field_block_input(block_uuid, [0xcd; 16], "k", "v");
    save_block(
        &owner_out.identity,
        &owner_out.manifest,
        input,
        MANIFEST_DEVICE_UUID,
        NOW_MS_BASE,
    )
    .unwrap();

    let alice_bytes = alice_out.manifest.owner_card_bytes().unwrap();
    let garbage = vec![0xffu8; 8];
    let err = share_block(
        &owner_out.identity,
        &owner_out.manifest,
        block_uuid,
        &[garbage],
        &alice_bytes,
        MANIFEST_DEVICE_UUID,
        NOW_MS_BASE + 1,
    )
    .unwrap_err();
    match err {
        FfiVaultError::CardDecodeFailure { detail } => assert!(!detail.is_empty()),
        other => panic!("expected CardDecodeFailure, got {other:?}"),
    }

    // Also test malformed new_recipient.
    let owner_bytes = owner_out.manifest.owner_card_bytes().unwrap();
    let err = share_block(
        &owner_out.identity,
        &owner_out.manifest,
        block_uuid,
        &[owner_bytes],
        &[0xff; 8],
        MANIFEST_DEVICE_UUID,
        NOW_MS_BASE + 2,
    )
    .unwrap_err();
    assert!(matches!(err, FfiVaultError::CardDecodeFailure { .. }));
}
```

- [ ] **Step 2: Run + commit**

Run: `cargo test --release -p secretary-ffi-bridge --test share_block share_block_with_malformed_existing_card -- --nocapture`
Expected: PASS.

```bash
git add ffi/secretary-ffi-bridge/tests/share_block.rs
git commit -m "test(ffi-b4d): CardDecodeFailure for malformed ContactCard bytes

Two assertions: garbage bytes in existing_recipient_cards element AND
garbage bytes in new_recipient both surface CardDecodeFailure with a
non-empty detail string.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: Wiped-manifest + wiped-identity failure-invariant tests

- [ ] **Step 1: Append two tests**

```rust
#[test]
fn share_block_on_wiped_manifest_returns_corrupt_vault() {
    let (owner_out, _owner_folder, _owner_td) = create_test_vault();
    let (alice_out, _alice_folder, _alice_td) = create_test_vault();
    let block_uuid = [0xab; 16];
    let input = single_field_block_input(block_uuid, [0xcd; 16], "k", "v");
    save_block(
        &owner_out.identity,
        &owner_out.manifest,
        input,
        MANIFEST_DEVICE_UUID,
        NOW_MS_BASE,
    )
    .unwrap();

    let owner_bytes = owner_out.manifest.owner_card_bytes().unwrap();
    let alice_bytes = alice_out.manifest.owner_card_bytes().unwrap();
    owner_out.manifest.wipe();
    let err = share_block(
        &owner_out.identity,
        &owner_out.manifest,
        block_uuid,
        &[owner_bytes],
        &alice_bytes,
        MANIFEST_DEVICE_UUID,
        NOW_MS_BASE + 1,
    )
    .unwrap_err();
    match err {
        FfiVaultError::CorruptVault { detail } => {
            assert!(detail.contains("manifest"));
        }
        other => panic!("expected CorruptVault, got {other:?}"),
    }
}

#[test]
fn share_block_on_wiped_identity_returns_corrupt_vault() {
    let (owner_out, _owner_folder, _owner_td) = create_test_vault();
    let (alice_out, _alice_folder, _alice_td) = create_test_vault();
    let block_uuid = [0xab; 16];
    let input = single_field_block_input(block_uuid, [0xcd; 16], "k", "v");
    save_block(
        &owner_out.identity,
        &owner_out.manifest,
        input,
        MANIFEST_DEVICE_UUID,
        NOW_MS_BASE,
    )
    .unwrap();

    let owner_bytes = owner_out.manifest.owner_card_bytes().unwrap();
    let alice_bytes = alice_out.manifest.owner_card_bytes().unwrap();
    owner_out.identity.wipe();
    let err = share_block(
        &owner_out.identity,
        &owner_out.manifest,
        block_uuid,
        &[owner_bytes],
        &alice_bytes,
        MANIFEST_DEVICE_UUID,
        NOW_MS_BASE + 1,
    )
    .unwrap_err();
    match err {
        FfiVaultError::CorruptVault { detail } => {
            assert!(detail.contains("identity"));
        }
        other => panic!("expected CorruptVault, got {other:?}"),
    }
}
```

- [ ] **Step 2: Run + commit**

Run: `cargo test --release -p secretary-ffi-bridge --test share_block wiped -- --nocapture`
Expected: PASS.

```bash
git add ffi/secretary-ffi-bridge/tests/share_block.rs
git commit -m "test(ffi-b4d): wiped-manifest + wiped-identity surface CorruptVault

Two failure-invariant tests pin that share_block on a wiped handle does
not write to disk and surfaces CorruptVault with detail naming which
handle was closed (mirrors B.4c's commit 9fbac18 pattern).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: 16-case round-trip proptest

**Files:**
- Create: `ffi/secretary-ffi-bridge/tests/share_block_proptest.rs` (separate file so the proptest case-budget is independent)

- [ ] **Step 1: Write proptest**

```rust
//! Proptest: round-trip share_block to N ∈ [1..4] random recipients;
//! every recipient reads back identical plaintext.
//!
//! Held to 16 cases — Argon2id-per-case cost dominates wall-clock time.
//! Issue #38 tracks raising the budget via a shared fixture.

mod common;

use common::{create_test_vault, open_test_vault, single_field_block_input, MANIFEST_DEVICE_UUID};
use proptest::prelude::*;
use secretary_ffi_bridge::{read_block, save_block, share_block};

const NOW_MS_BASE: u64 = 1_700_000_000_000;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 16,
        .. ProptestConfig::default()
    })]

    #[test]
    fn share_block_round_trip_to_n_recipients(
        n in 1usize..=4usize,
        plaintext in "[a-zA-Z0-9 ]{1,32}",
    ) {
        let (owner_out, owner_folder, _owner_td) = create_test_vault();

        // Mint N recipient identities + capture their card bytes.
        let recipients: Vec<_> = (0..n).map(|_| create_test_vault()).collect();

        // Owner saves a block with one record.
        let block_uuid = [0xab; 16];
        let input = single_field_block_input(block_uuid, [0xcd; 16], "k", &plaintext);
        save_block(
            &owner_out.identity,
            &owner_out.manifest,
            input,
            MANIFEST_DEVICE_UUID,
            NOW_MS_BASE,
        )
        .unwrap();

        // Owner shares with each recipient sequentially. existing_recipient_cards
        // grows by one element per iteration.
        let mut existing = vec![owner_out.manifest.owner_card_bytes().unwrap()];
        for (i, (rcp_out, _, _)) in recipients.iter().enumerate() {
            let rcp_bytes = rcp_out.manifest.owner_card_bytes().unwrap();
            share_block(
                &owner_out.identity,
                &owner_out.manifest,
                block_uuid,
                &existing,
                &rcp_bytes,
                MANIFEST_DEVICE_UUID,
                NOW_MS_BASE + 1 + i as u64,
            )
            .unwrap();
            existing.push(rcp_bytes);
        }

        // Stage each recipient's vault and verify they can decrypt.
        for (rcp_out, rcp_folder, _) in recipients.iter() {
            common::stage_recipient_vault(&owner_folder, rcp_folder, &owner_out, block_uuid);
            let reopen = open_test_vault(rcp_folder);
            let block = read_block(&reopen.identity, &reopen.manifest, block_uuid).unwrap();
            let rec = block.record_at(0).unwrap();
            let pw = rec.field_by_name("k").unwrap().expose_text().unwrap();
            prop_assert_eq!(pw, plaintext.clone());
        }
    }
}
```

Add `proptest = "..."` to `[dev-dependencies]` in `ffi/secretary-ffi-bridge/Cargo.toml` if not already present (B.4c added it for the save_block proptest — verify).

- [ ] **Step 2: Run proptest**

Run: `cargo test --release -p secretary-ffi-bridge --test share_block_proptest -- --nocapture`
Expected: PASS — 16 cases.

- [ ] **Step 3: Commit**

```bash
git add ffi/secretary-ffi-bridge/tests/share_block_proptest.rs \
        ffi/secretary-ffi-bridge/Cargo.toml \
        ffi/secretary-ffi-bridge/Cargo.lock
git commit -m "test(ffi-b4d): proptest round-trip share_block to N in [1..4] recipients

16-case proptest mints N recipient identities, owner shares the same
block to each sequentially (existing_recipient_cards grows by one per
iteration), and asserts every recipient reads back identical plaintext.

Held to 16 cases — Argon2id-per-case cost is the constraint. Issue #38
tracks raising the budget via a shared fixture.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 11: uniffi `share_block` namespace fn

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/src/secretary.udl` (namespace block)
- Modify: `ffi/secretary-ffi-uniffi/src/namespace.rs` (impl)

- [ ] **Step 1: UDL**

In `ffi/secretary-ffi-uniffi/src/secretary.udl`, inside the existing `namespace secretary { ... }` block (after `save_block`):

```idl
    /// Append one new recipient to an existing block. v1 single-author:
    /// only the vault owner can share blocks they authored.
    /// `existing_recipient_cards` must cover every recipient currently
    /// in the block's recipient table (including the owner if the owner
    /// is also a recipient). For a freshly-saved v1 block, this is
    /// `[manifest.owner_card_bytes()]`. `new_recipient` must NOT
    /// already appear in the existing list.
    [Throws=VaultError]
    void share_block(
        UnlockedIdentity identity,
        OpenVaultManifest manifest,
        bytes block_uuid,
        sequence<bytes> existing_recipient_cards,
        bytes new_recipient,
        bytes device_uuid,
        u64 now_ms,
    );
```

- [ ] **Step 2: namespace.rs impl**

In `ffi/secretary-ffi-uniffi/src/namespace.rs`, find the existing `pub fn save_block(...)` and add a parallel `share_block`:

```rust
#[allow(clippy::too_many_arguments)]
pub fn share_block(
    identity: Arc<UnlockedIdentity>,
    manifest: Arc<OpenVaultManifest>,
    block_uuid: Vec<u8>,
    existing_recipient_cards: Vec<Vec<u8>>,
    new_recipient: Vec<u8>,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> Result<(), VaultError> {
    let block_uuid_arr: [u8; 16] = block_uuid
        .as_slice()
        .try_into()
        .map_err(|_| VaultError::InvalidArgument {
            detail: format!(
                "block_uuid must be exactly 16 bytes, got {}",
                block_uuid.len()
            ),
        })?;
    let device_uuid_arr: [u8; 16] = device_uuid
        .as_slice()
        .try_into()
        .map_err(|_| VaultError::InvalidArgument {
            detail: format!(
                "device_uuid must be exactly 16 bytes, got {}",
                device_uuid.len()
            ),
        })?;
    secretary_ffi_bridge::share_block(
        &identity.inner,
        &manifest.inner,
        block_uuid_arr,
        &existing_recipient_cards,
        &new_recipient,
        device_uuid_arr,
        now_ms,
    )
    .map_err(VaultError::from)
}
```

- [ ] **Step 3: Run uniffi crate tests + build**

Run: `cargo test --release -p secretary-ffi-uniffi`
Expected: clean — uniffi codegen runs at build time; the new namespace fn is exposed.

- [ ] **Step 4: Commit**

```bash
git add ffi/secretary-ffi-uniffi/src/secretary.udl \
        ffi/secretary-ffi-uniffi/src/namespace.rs \
        ffi/secretary-ffi-uniffi/Cargo.lock
git commit -m "feat(ffi-b4d): add share_block namespace fn to uniffi

UDL declaration mirrors the bridge signature: bytes block_uuid + bytes
device_uuid (16-byte arrays validated namespace-side, surface as
InvalidArgument on length mismatch), sequence<bytes>
existing_recipient_cards, bytes new_recipient. Forwards to
secretary_ffi_bridge::share_block; errors translate via the existing
From<FfiVaultError> for VaultError impl.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 12: PyO3 `share_block` #[pyfunction]

**Files:**
- Modify: `ffi/secretary-ffi-py/src/lib.rs`

- [ ] **Step 1: Add pyfunction**

Search for the existing `#[pyfunction] fn save_block(...)` in `ffi/secretary-ffi-py/src/lib.rs`. Add a parallel `share_block` directly below:

```rust
#[pyfunction]
#[pyo3(signature = (
    identity,
    manifest,
    block_uuid,
    existing_recipient_cards,
    new_recipient,
    device_uuid,
    now_ms,
))]
#[allow(clippy::too_many_arguments)]
fn share_block(
    py: Python<'_>,
    identity: PyRef<'_, UnlockedIdentity>,
    manifest: PyRef<'_, OpenVaultManifest>,
    block_uuid: &[u8],
    existing_recipient_cards: Vec<Vec<u8>>,
    new_recipient: &[u8],
    device_uuid: &[u8],
    now_ms: u64,
) -> PyResult<()> {
    let block_uuid_arr: [u8; 16] = block_uuid
        .try_into()
        .map_err(|_| PyValueError::new_err(format!(
            "block_uuid must be exactly 16 bytes, got {}",
            block_uuid.len()
        )))?;
    let device_uuid_arr: [u8; 16] = device_uuid
        .try_into()
        .map_err(|_| PyValueError::new_err(format!(
            "device_uuid must be exactly 16 bytes, got {}",
            device_uuid.len()
        )))?;
    py.allow_threads(|| {
        secretary_ffi_bridge::share_block(
            &identity.inner,
            &manifest.inner,
            block_uuid_arr,
            &existing_recipient_cards,
            new_recipient,
            device_uuid_arr,
            now_ms,
        )
    })
    .map_err(Into::into)
}
```

Match the surrounding patterns: `PyValueError`, `py.allow_threads`, the `.map_err(Into::into)` shape — verify against the existing `save_block` pyfunction.

Register the fn on the module (search for `m.add_function(wrap_pyfunction!(save_block, m)?)?;` and add a parallel line below).

- [ ] **Step 2: Build + run pytest skeleton**

Run from project root:

```bash
( cd ffi/secretary-ffi-py && uv run maturin develop --release --uv )
uv run --directory ffi/secretary-ffi-py python -c "import secretary_ffi_py as s; print(s.share_block)"
```

Expected: prints `<built-in function share_block>` (or similar).

- [ ] **Step 3: Commit**

```bash
git add ffi/secretary-ffi-py/src/lib.rs
git commit -m "feat(ffi-b4d): add share_block #[pyfunction] to PyO3 binding

Length-16 validation on block_uuid + device_uuid at the binding layer
raises ValueError (consistent with B.4c save_block's pattern). Card-
bytes validation happens inside the bridge and surfaces
VaultCardDecodeFailure. Uses py.allow_threads to release the GIL during
the share orchestration.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 13: pytest tests for share_block (8 tests)

**Files:**
- Modify: `ffi/secretary-ffi-py/tests/test_smoke.py`

- [ ] **Step 1: Apply maturin/uv cache fix proactively**

Run:

```bash
rm -rf ffi/secretary-ffi-py/.venv
find ~/.cache/uv -name "*secretary*" -exec rm -rf {} + 2>/dev/null
( cd ffi/secretary-ffi-py && uv sync && uv run maturin develop --release --uv )
```

(Per project memory `project_secretary_maturin_uv_cache.md` — pytest sees stale .so even after maturin rebuild without this nuke step.)

- [ ] **Step 2: Add 8 pytest tests**

In `ffi/secretary-ffi-py/tests/test_smoke.py`, append (matching the surrounding test-file conventions for fresh-vault helpers, `secretary_ffi_py` import alias, `pytest.raises` patterns):

```python
def test_share_block_round_trip_owner_to_alice(tmp_path):
    """Happy path: owner saves a block, shares to Alice, Alice reads it back."""
    owner = _fresh_writable_vault(tmp_path / "owner")
    alice = _fresh_writable_vault(tmp_path / "alice")
    block_uuid = b"\xab" * 16
    record_uuid = b"\xcd" * 16
    device_uuid = b"\x01" * 16
    plaintext = "hunter2"
    s.save_block(
        owner.identity, owner.manifest,
        _single_field_block_input(block_uuid, record_uuid, "password", plaintext),
        device_uuid, 1_700_000_000_000,
    )
    s.share_block(
        owner.identity, owner.manifest,
        block_uuid,
        [owner.manifest.owner_card_bytes()],
        alice.manifest.owner_card_bytes(),
        device_uuid, 1_700_000_000_001,
    )
    _stage_recipient_vault(owner, alice, block_uuid)
    alice_reopen = _open_vault(alice.folder)
    block = s.read_block(alice_reopen.identity, alice_reopen.manifest, block_uuid)
    assert block.record_count() == 1
    rec = block.record_at(0)
    assert rec.field_by_name("password").expose_text() == plaintext


def test_share_block_then_share_to_third_recipient_passes_growing_existing_list(tmp_path):
    """Caller-side recipient tracking: existing_recipient_cards grows by one per share."""
    owner = _fresh_writable_vault(tmp_path / "owner")
    alice = _fresh_writable_vault(tmp_path / "alice")
    bob = _fresh_writable_vault(tmp_path / "bob")
    block_uuid = b"\xab" * 16
    device_uuid = b"\x01" * 16
    s.save_block(
        owner.identity, owner.manifest,
        _single_field_block_input(block_uuid, b"\xcd" * 16, "k", "v"),
        device_uuid, 1_700_000_000_000,
    )
    s.share_block(
        owner.identity, owner.manifest,
        block_uuid,
        [owner.manifest.owner_card_bytes()],
        alice.manifest.owner_card_bytes(),
        device_uuid, 1_700_000_000_001,
    )
    s.share_block(
        owner.identity, owner.manifest,
        block_uuid,
        [owner.manifest.owner_card_bytes(), alice.manifest.owner_card_bytes()],
        bob.manifest.owner_card_bytes(),
        device_uuid, 1_700_000_000_002,
    )


def test_share_block_with_wrong_length_block_uuid_raises_value_error(tmp_path):
    owner = _fresh_writable_vault(tmp_path / "owner")
    alice = _fresh_writable_vault(tmp_path / "alice")
    with pytest.raises(ValueError, match="block_uuid must be exactly 16 bytes"):
        s.share_block(
            owner.identity, owner.manifest,
            b"\x00" * 8,  # wrong length
            [owner.manifest.owner_card_bytes()],
            alice.manifest.owner_card_bytes(),
            b"\x01" * 16, 1_700_000_000_000,
        )


def test_share_block_with_wrong_length_device_uuid_raises_value_error(tmp_path):
    owner = _fresh_writable_vault(tmp_path / "owner")
    alice = _fresh_writable_vault(tmp_path / "alice")
    with pytest.raises(ValueError, match="device_uuid must be exactly 16 bytes"):
        s.share_block(
            owner.identity, owner.manifest,
            b"\xab" * 16,
            [owner.manifest.owner_card_bytes()],
            alice.manifest.owner_card_bytes(),
            b"\x01" * 8,  # wrong length
            1_700_000_000_000,
        )


def test_share_block_called_by_non_author_raises_vault_not_author(tmp_path):
    owner = _fresh_writable_vault(tmp_path / "owner")
    bob = _fresh_writable_vault(tmp_path / "bob")
    alice = _fresh_writable_vault(tmp_path / "alice")
    block_uuid = b"\xab" * 16
    device_uuid = b"\x01" * 16
    s.save_block(
        owner.identity, owner.manifest,
        _single_field_block_input(block_uuid, b"\xcd" * 16, "k", "v"),
        device_uuid, 1_700_000_000_000,
    )
    _stage_recipient_vault(owner, bob, block_uuid)
    bob_reopen = _open_vault(bob.folder)
    with pytest.raises(s.VaultNotAuthor):
        s.share_block(
            bob_reopen.identity, bob_reopen.manifest,
            block_uuid,
            [owner.manifest.owner_card_bytes()],
            alice.manifest.owner_card_bytes(),
            device_uuid, 1_700_000_000_001,
        )


def test_share_block_with_duplicate_recipient_raises_vault_recipient_already_present(tmp_path):
    owner = _fresh_writable_vault(tmp_path / "owner")
    alice = _fresh_writable_vault(tmp_path / "alice")
    block_uuid = b"\xab" * 16
    device_uuid = b"\x01" * 16
    s.save_block(
        owner.identity, owner.manifest,
        _single_field_block_input(block_uuid, b"\xcd" * 16, "k", "v"),
        device_uuid, 1_700_000_000_000,
    )
    s.share_block(
        owner.identity, owner.manifest, block_uuid,
        [owner.manifest.owner_card_bytes()],
        alice.manifest.owner_card_bytes(),
        device_uuid, 1_700_000_000_001,
    )
    with pytest.raises(s.VaultRecipientAlreadyPresent):
        s.share_block(
            owner.identity, owner.manifest, block_uuid,
            [owner.manifest.owner_card_bytes(), alice.manifest.owner_card_bytes()],
            alice.manifest.owner_card_bytes(),
            device_uuid, 1_700_000_000_002,
        )


def test_share_block_with_missing_existing_card_raises_vault_missing_recipient_card(tmp_path):
    owner = _fresh_writable_vault(tmp_path / "owner")
    alice = _fresh_writable_vault(tmp_path / "alice")
    block_uuid = b"\xab" * 16
    device_uuid = b"\x01" * 16
    s.save_block(
        owner.identity, owner.manifest,
        _single_field_block_input(block_uuid, b"\xcd" * 16, "k", "v"),
        device_uuid, 1_700_000_000_000,
    )
    with pytest.raises(s.VaultMissingRecipientCard):
        s.share_block(
            owner.identity, owner.manifest, block_uuid,
            [],  # missing owner card
            alice.manifest.owner_card_bytes(),
            device_uuid, 1_700_000_000_001,
        )


def test_share_block_with_malformed_card_bytes_raises_vault_card_decode_failure(tmp_path):
    owner = _fresh_writable_vault(tmp_path / "owner")
    alice = _fresh_writable_vault(tmp_path / "alice")
    block_uuid = b"\xab" * 16
    device_uuid = b"\x01" * 16
    s.save_block(
        owner.identity, owner.manifest,
        _single_field_block_input(block_uuid, b"\xcd" * 16, "k", "v"),
        device_uuid, 1_700_000_000_000,
    )
    with pytest.raises(s.VaultCardDecodeFailure):
        s.share_block(
            owner.identity, owner.manifest, block_uuid,
            [b"\xff" * 8],  # garbage
            alice.manifest.owner_card_bytes(),
            device_uuid, 1_700_000_000_001,
        )
```

Helpers `_fresh_writable_vault`, `_single_field_block_input`, `_stage_recipient_vault`, `_open_vault` need to be defined in the same file (or in a shared `conftest.py`). Mirror B.4c's helpers from existing test_smoke.py — adapt as needed for the share-recipient staging.

- [ ] **Step 3: Run pytest**

Run: `uv run --directory ffi/secretary-ffi-py pytest -v`
Expected: 58 passed.

- [ ] **Step 4: Commit**

```bash
git add ffi/secretary-ffi-py/tests/test_smoke.py
git commit -m "test(ffi-b4d): add 8 pytest tests for share_block

Round-trip happy path; sequential-share to third recipient (caller-side
list growth); wrong-length block_uuid + device_uuid (ValueError); the
4 new typed VaultError subclasses (VaultNotAuthor /
VaultRecipientAlreadyPresent / VaultMissingRecipientCard /
VaultCardDecodeFailure).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 14: Swift smoke tests

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/tests/swift/main.swift`

- [ ] **Step 1: Add 4 Swift assertions**

Find the existing `// === SAVE_BLOCK ASSERTIONS ===` block in `tests/swift/main.swift`. Below it, add a `// === SHARE_BLOCK ASSERTIONS ===` block with 4 PASS lines mirroring B.4c's commit `889ec57` shape:

```swift
// === SHARE_BLOCK ASSERTIONS (asserts 27-30) ===
do {
    // 27. Happy path: owner shares with Alice; Alice reads.
    let aliceVault = try _freshWritableVault(tag: "alice")
    let blockUuid = Data(repeating: 0xab, count: 16)
    let deviceUuid = Data(repeating: 0x01, count: 16)
    try save_block(
        identity: ownerVault.identity, manifest: ownerVault.manifest,
        input: singleFieldBlockInput(blockUuid: blockUuid, recordUuid: Data(repeating: 0xcd, count: 16), name: "password", value: "hunter2"),
        deviceUuid: deviceUuid, nowMs: 1_700_000_000_000,
    )
    try share_block(
        identity: ownerVault.identity, manifest: ownerVault.manifest,
        blockUuid: blockUuid,
        existingRecipientCards: [ownerVault.manifest.ownerCardBytes()!],
        newRecipient: aliceVault.manifest.ownerCardBytes()!,
        deviceUuid: deviceUuid, nowMs: 1_700_000_000_001,
    )
    _stageRecipientVault(from: ownerVault, to: aliceVault, blockUuid: blockUuid)
    let aliceReopen = try _openVault(aliceVault.folder)
    let block = try read_block(identity: aliceReopen.identity, manifest: aliceReopen.manifest, blockUuid: blockUuid)
    assertPass("share_block insert + alice read: text == hunter2", block.recordAt(idx: 0)?.fieldByName("password")?.exposeText() == "hunter2")

    // 28. NotAuthor on bob impersonator.
    let bobVault = try _freshWritableVault(tag: "bob")
    _stageRecipientVault(from: ownerVault, to: bobVault, blockUuid: blockUuid)
    let bobReopen = try _openVault(bobVault.folder)
    do {
        try share_block(
            identity: bobReopen.identity, manifest: bobReopen.manifest,
            blockUuid: blockUuid,
            existingRecipientCards: [ownerVault.manifest.ownerCardBytes()!],
            newRecipient: aliceVault.manifest.ownerCardBytes()!,
            deviceUuid: deviceUuid, nowMs: 1_700_000_000_002,
        )
        assertFail("share_block by non-author should have raised NotAuthor")
    } catch let VaultError.NotAuthor(expected, got) {
        assertPass("share_block non-author → NotAuthor(\(expected), \(got))", true)
    }

    // 29. RecipientAlreadyPresent.
    do {
        try share_block(
            identity: ownerVault.identity, manifest: ownerVault.manifest,
            blockUuid: blockUuid,
            existingRecipientCards: [ownerVault.manifest.ownerCardBytes()!, aliceVault.manifest.ownerCardBytes()!],
            newRecipient: aliceVault.manifest.ownerCardBytes()!,
            deviceUuid: deviceUuid, nowMs: 1_700_000_000_003,
        )
        assertFail("share_block duplicate alice should have raised RecipientAlreadyPresent")
    } catch VaultError.RecipientAlreadyPresent {
        assertPass("share_block duplicate alice → RecipientAlreadyPresent", true)
    }

    // 30. MissingRecipientCard.
    do {
        try share_block(
            identity: ownerVault.identity, manifest: ownerVault.manifest,
            blockUuid: blockUuid,
            existingRecipientCards: [],
            newRecipient: bobVault.manifest.ownerCardBytes()!,
            deviceUuid: deviceUuid, nowMs: 1_700_000_000_004,
        )
        assertFail("share_block empty existing list should have raised MissingRecipientCard")
    } catch let VaultError.MissingRecipientCard(fp) {
        assertPass("share_block missing card → MissingRecipientCard(\(fp))", fp.count == 32)
    }
}
```

Update the failure-count footer assertion (currently expects 26 passes) to 30.

`_freshWritableVault`, `_stageRecipientVault`, `_openVault`, `singleFieldBlockInput` are existing test-file helpers — extend or add as needed. Match the patterns of B.4c's commit `889ec57`.

- [ ] **Step 2: Run Swift smoke**

Run: `ffi/secretary-ffi-uniffi/tests/swift/run.sh`
Expected: `OK: secretary uniffi Swift smoke runner — all assertions passed.` with 30/30.

- [ ] **Step 3: Commit**

```bash
git add ffi/secretary-ffi-uniffi/tests/swift/main.swift
git commit -m "test(ffi-b4d): add 4 Swift smoke tests for share_block

Asserts 27-30: happy path (insert + share + alice read), NotAuthor
(bob impersonator), RecipientAlreadyPresent (duplicate alice),
MissingRecipientCard (empty existing list).

Footer 26 → 30.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 15: Kotlin smoke tests

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt`

- [ ] **Step 1: Add 4 Kotlin assertions**

Mirror Swift exactly. Find the `// === SAVE_BLOCK ASSERTIONS ===` block, add a parallel `// === SHARE_BLOCK ASSERTIONS (asserts 28-31) ===` block. The 4 cases are identical:

1. Happy path → text == "hunter2"
2. NotAuthor (bob impersonator) → `VaultException.NotAuthor`
3. RecipientAlreadyPresent → `VaultException.RecipientAlreadyPresent`
4. MissingRecipientCard → `VaultException.MissingRecipientCard`

(Note: the Kotlin counter starts at 28 because Kotlin's existing pass count is 27; Swift's is 26. The +4 increment shifts each.)

Update the failure-count footer 27 → 31.

- [ ] **Step 2: Run Kotlin smoke**

Run: `ffi/secretary-ffi-uniffi/tests/kotlin/run.sh`
Expected: `OK: secretary uniffi Kotlin smoke runner — all assertions passed.` with 31/31.

- [ ] **Step 3: Commit**

```bash
git add ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt
git commit -m "test(ffi-b4d): add 4 Kotlin smoke tests for share_block

Asserts 28-31: same coverage as Swift (happy path, NotAuthor,
RecipientAlreadyPresent, MissingRecipientCard).

Footer 27 → 31.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 16: README + ROADMAP updates

**Files:**
- Modify: `README.md`
- Modify: `ROADMAP.md`

- [ ] **Step 1: Update README**

Find the existing B.4c row in the FFI status table (search for `B.4c`). Add a B.4d row below:

```markdown
| B.4d | `share_block` | bridge crate + PyO3 + uniffi | ✓ |
```

Adjust matching prose (test counts: 599 cargo + 58 pytest + 30 Swift + 31 Kotlin).

- [ ] **Step 2: Update ROADMAP**

In `ROADMAP.md`, find the B.4d entry under Sub-project B and mark it as DONE with the merge date once known. Surface B.5 (or whichever the next sub-project is) as the new "Next" item.

- [ ] **Step 3: Commit**

```bash
git add README.md ROADMAP.md
git commit -m "docs(ffi-b4d): mark B.4d shipped in README + ROADMAP

Adds the share_block row to the FFI status table; updates verification
counts (599 cargo + 58 pytest + 30 Swift + 31 Kotlin).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 17: NEXT_SESSION + handoff snapshot

**Files:**
- Modify: `NEXT_SESSION.md`
- Create: `docs/handoffs/2026-05-10-b4d-share-block.md` (EXACT copy of NEXT_SESSION.md)

- [ ] **Step 1: Author NEXT_SESSION.md per the user's `/nextsession` skill rubric**

Replace the entire file with a fresh B.4d-complete handoff:
- §(1) What we shipped — every commit SHA from this session
- §(2) What's next (TBD: brainstorm B.5 in the next session)
- §(3) Open decisions or risks (carry forward issues #35-#38)
- §(4) Exact commands to resume (cd + branch + tests)
- Closing inventory matching B.4c's NEXT_SESSION.md shape

- [ ] **Step 2: Snapshot to docs/handoffs**

```bash
cp NEXT_SESSION.md docs/handoffs/2026-05-10-b4d-share-block.md
```

(MUST be byte-identical per the skill's clarified rule.)

- [ ] **Step 3: Commit**

```bash
git add NEXT_SESSION.md docs/handoffs/2026-05-10-b4d-share-block.md
git commit -m "docs(ffi-b4d): update NEXT_SESSION.md + handoff snapshot

Frozen archive at docs/handoffs/2026-05-10-b4d-share-block.md is
byte-identical to NEXT_SESSION.md per the nextsession skill's rule.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 18: Push + open PR + verify CI

- [ ] **Step 1: Final verification on the feature branch**

Run all gates:

```bash
cargo test --release --workspace 2>&1 | grep "test result:" | python3 -c "
import sys, re
p=f=i=0
for line in sys.stdin:
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'TOTAL: {p} passed; {f} failed; {i} ignored')"

cargo clippy --release --workspace -- -D warnings
cargo fmt --all -- --check
uv run --directory ffi/secretary-ffi-py pytest
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
ffi/secretary-ffi-uniffi/tests/swift/run.sh
ffi/secretary-ffi-uniffi/tests/kotlin/run.sh
```

Expected:
- TOTAL: 599 passed; 0 failed; 9 ignored (±3 acceptable per spec §10)
- clippy: clean
- fmt: clean
- pytest: 58 passed
- conformance: PASS
- spec freshness: PASS
- Swift: 30/30 PASS
- Kotlin: 31/31 PASS

- [ ] **Step 2: Push + open PR**

```bash
git push -u origin feat/ffi-b4d-share-block
gh pr create --title "feat(ffi-b4d): share_block end-to-end through bridge + PyO3 + uniffi" --body "$(cat <<'EOF'
## Summary

- Adds `share_block` to the bridge crate (`secretary-ffi-bridge`), exposed through PyO3 (`secretary-ffi-py`) and uniffi (`secretary-ffi-uniffi`). Mirrors `core::vault::share_block`'s single-recipient-append semantics; foreign callers loop in their own code for N recipients.
- Adds `OpenVaultManifest::owner_card_bytes()` accessor (encode-on-demand) so the v1 owner-only happy path is `existing_recipient_cards = [manifest.owner_card_bytes()]` without a parallel byte cache.
- Adds 4 typed `FfiVaultError` variants atomically across all 3 crates: `NotAuthor`, `RecipientAlreadyPresent`, `MissingRecipientCard`, `CardDecodeFailure`. Foreign callers can pattern-match each for distinct UX reactions.

## Spec + plan

- Spec: `docs/superpowers/specs/2026-05-10-ffi-b4d-share-block-design.md`
- Plan: `docs/superpowers/plans/2026-05-10-ffi-b4d-share-block.md`

## Test plan

- [ ] `cargo test --release --workspace` — 599 passed + 9 ignored
- [ ] `cargo clippy --release --workspace -- -D warnings` — clean
- [ ] `cargo fmt --all -- --check` — OK
- [ ] `uv run --directory ffi/secretary-ffi-py pytest` — 58 passed
- [ ] `uv run core/tests/python/conformance.py` — PASS
- [ ] `uv run core/tests/python/spec_test_name_freshness.py` — PASS
- [ ] Swift smoke (`tests/swift/run.sh`) — 30/30 PASS
- [ ] Kotlin smoke (`tests/kotlin/run.sh`) — 31/31 PASS

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Wait for CI; address review feedback**

(Per project memory `feedback_fix_all_review_issues.md`: fix every review issue before merge — no technical debt; one issue per commit.)

---

## Self-Review

**Spec coverage (§ → tasks):**
- §1 purpose → Tasks 1-15 cover the full surface
- §2 architectural decisions → all 5 are realized: bytes-in (Task 4 decode step), single-recipient (Task 4 signature), 4 typed variants (Task 1), encode-on-demand (Task 2), no caller-zeroize (no zeroize wrappers introduced for ContactCard inputs)
- §3 module structure → Tasks 1-3, 11-12 touch every listed file
- §4 public bridge API → Task 4 (orchestration) + Task 2 (accessor)
- §5 step-by-step orchestration → Task 4 step 3
- §6 error mapping table → Task 1 + Task 4 step 3 (`map_core_vault_error_share`)
- §7 PyO3 binding → Task 12 + Task 1 step 8
- §8 uniffi binding → Task 11 + Task 1 step 6
- §9 test plan → Tasks 4-10 (bridge), 13 (pytest), 14-15 (Swift/Kotlin)
- §10 acceptance gates → Task 18 step 1
- §11 rollout → Tasks 16-17
- §12 open risks → covered by tasks; the v1 ergonomics test in pytest is `test_share_block_then_share_to_third_recipient_passes_growing_existing_list` (Task 13)

**Placeholder scan:** none — every step contains executable content.

**Type consistency:** `share_block` signature appears consistently across Tasks 3 (stub), 4 (real), 11 (uniffi), 12 (PyO3). `existing_recipient_cards` is `&[Vec<u8>]` (bridge) / `sequence<bytes>` (uniffi) / `list[bytes]` (PyO3). `owner_card_bytes()` returns `Option<Vec<u8>>` (bridge) / `bytes?` (uniffi) / `bytes | None` (PyO3) consistently.
