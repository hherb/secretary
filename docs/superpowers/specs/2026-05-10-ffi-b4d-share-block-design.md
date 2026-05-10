# Sub-project B.4d — `share_block` (extend a block's recipient set)

**Date:** 2026-05-10
**Status:** Design approved (brainstormed 2026-05-10; this doc is the input to writing-plans).
**Predecessor:** [B.4c — save_block](2026-05-09-ffi-b4c-save-block-design.md).
**Successor (planned):** B.5 — TBD (record-level CRDT merge surface, pending Sub-project A.7 hardening review).

## 1. Purpose

Add a fallible "encrypt-to-additional-recipient + atomic-persist" entry point to the bridge crate, surfaced through PyO3 (`secretary-ffi-py`) and uniffi (`secretary-ffi-uniffi`). B.4d is the first FFI call where `ContactCard` values cross the foreign boundary as input — B.4c hard-coded `recipients = [owner_card]` because v1 was owner-only.

`core::vault::share_block` already exists at [orchestrators.rs:996](../../../core/src/vault/orchestrators.rs#L996); B.4d is a thin bridge layer that exposes it through foreign FFI surfaces with the canonical-CBOR card wire shape and the same handle-lifecycle / error-mapping discipline B.4a/B.4b/B.4c established.

The bridge function mirrors `core::share_block`'s **single-recipient-append** semantics — each call adds exactly one new recipient. Multi-recipient flows are caller-side loops; the bridge does not batch.

## 2. Architectural decisions (settled in brainstorming)

| Decision | Choice | Rationale |
|---|---|---|
| `ContactCard` wire shape | Bytes-in (canonical CBOR), with a new `owner_card_bytes()` accessor on `OpenVaultManifest` for the v1 owner-only happy path | Cards self-sign over canonical bytes; passing decoded fields and re-encoding at the bridge re-introduces the canonical-fidelity hazard (RFC 8949 §4.2.1 deterministic encoding). Bytes-in keeps cards opaque end-to-end and decode-once at the bridge boundary. The accessor avoids forcing foreign callers to maintain a parallel byte cache for the common `existing_recipient_cards = [owner_card]` case. |
| Recipient-list batching | Mirror core: one `new_recipient` per call; caller loops in foreign code for N recipients | Each `core::share_block` call is its own atomic write (block file + manifest re-sign + atomic rename). Wrapping a multi-recipient loop at the bridge layer breaks atomicity across iterations and forces a partial-success error variant with no real recovery semantics. Foreign-side loop is one `for` statement; failure mode is unambiguous (caller sees which iteration raised; vault state is consistent). |
| Failure-mode typing | 4 new typed `FfiVaultError` variants (`NotAuthor`, `RecipientAlreadyPresent`, `MissingRecipientCard`, `CardDecodeFailure`); none folded under `SaveCryptoFailure`'s umbrella | Each variant maps to a distinct foreign-side UX reaction (cannot share / idempotent already-shared / fetch-card-from-contacts / bad-input). Folding loses the typing core paid for; partial folds (compromise option) help nobody. |
| `owner_card_bytes()` strategy | Encode-on-demand; `to_canonical_cbor()` called per access with `.expect()` justified by the immutable-handle-over-validated-card invariant | Avoids stored cache-vs-truth invariant; per-call cost is one CBOR encode (~hundreds of µs at most), negligible at the human-scale frequency of `share_block` calls. |
| Caller-zeroize discipline | None applies to inputs (ContactCard is non-secret by design) | `core/src/identity/card.rs:163-164` — "All fields are public material plus signatures; nothing in this struct is secret." Internal record secrets re-encrypted by core continue to flow through `SecretString` / `SecretBytes` carriers; no new secret-bearing FFI surface introduced. |

## 3. Module structure

```
ffi/secretary-ffi-bridge/src/
├── share/
│   ├── mod.rs            ~40 LOC, module docs + re-exports
│   └── orchestration.rs  ~200 LOC, share_block free function + error mapping
├── vault.rs              +1 accessor (owner_card_bytes), +1 unit test (round-trip)
├── error.rs              +4 variants (NotAuthor / RecipientAlreadyPresent / MissingRecipientCard / CardDecodeFailure)
│                         +3 arms in From<core::VaultError>
└── lib.rs                +1 re-export line for share::share_block

ffi/secretary-ffi-py/src/lib.rs
                          +1 #[pyfunction] (share_block)
                          +4 PyO3 exception class declarations
                          +1 #[pyfunction] for OpenVaultManifest.owner_card_bytes()

ffi/secretary-ffi-uniffi/
├── secretary.udl         +1 namespace fn (share_block)
│                         +1 method on OpenVaultManifest interface (owner_card_bytes)
│                         +4 VaultError variants (mirroring bridge)
└── src/namespace.rs      +1 namespace fn impl
└── src/wrappers/         (no new wrapper module — share_block takes existing types)
```

The bridge crate already exceeds the 500-line policy on `error.rs` (~822 LOC) and `vault.rs` (~895 LOC); both are tracked in issue #36. B.4d *adds* to `error.rs` (+4 variants ≈ +60 LOC) and `vault.rs` (+1 accessor + 1 test ≈ +30 LOC). For *new* code the proactive-split feedback rule applies — the share_block orchestration goes into a fresh `share/` module mirroring B.4c's `save/` directory layout.

## 4. Public bridge API

```rust
// share/orchestration.rs

/// Add one new recipient to an existing block. v1 single-author: only
/// the vault's owner can share blocks they authored.
///
/// # Arguments
///
/// - `existing_recipient_cards`: canonical-CBOR bytes for EVERY recipient
///   currently in the block's wire-level recipient table, including the
///   author if the author is also a recipient. For a freshly-saved v1
///   block this is `[manifest.owner_card_bytes().unwrap()]`.
/// - `new_recipient`: canonical-CBOR bytes of the contact card being
///   added. Must NOT already appear in the existing list (per
///   fingerprint).
///
/// # Errors
///
/// - [`FfiVaultError::CardDecodeFailure`] — any card byte slice fails
///   `ContactCard::from_canonical_cbor`.
/// - [`FfiVaultError::CorruptVault`] — either handle has been wiped;
///   manifest re-sign failure on already-validated inputs.
/// - [`FfiVaultError::FolderInvalid`] — IO failure during atomic write.
/// - [`FfiVaultError::BlockNotFound`] — `block_uuid` not in
///   `manifest.blocks`.
/// - [`FfiVaultError::NotAuthor`] — the calling identity's user_uuid does
///   not match the block's recorded `author_fingerprint`.
/// - [`FfiVaultError::RecipientAlreadyPresent`] — `new_recipient`'s
///   fingerprint already appears in the wire-level recipient table.
/// - [`FfiVaultError::MissingRecipientCard`] — caller's
///   `existing_recipient_cards` did not cover every recipient currently
///   on disk.
/// - [`FfiVaultError::SaveCryptoFailure`] — crypto / encoding failure
///   on already-validated inputs (clock saturation, KEM key parse,
///   encoder failure).
pub fn share_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: [u8; 16],
    existing_recipient_cards: &[Vec<u8>],
    new_recipient: &[u8],
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError>;
```

```rust
// vault.rs (additive)

impl OpenVaultManifest {
    /// Canonical-CBOR bytes of the vault's `owner_card`. Returns the same
    /// byte sequence as the on-disk `<vault>/contacts/<owner_uuid>.card`
    /// content. Use as the `existing_recipient_cards` element when
    /// calling `share_block` on a v1 owner-only block.
    ///
    /// `None` iff the manifest handle has been wiped.
    ///
    /// Encodes on demand via `ContactCard::to_canonical_cbor`. The
    /// `.expect()` is justified by the open-vault invariant: the card
    /// was decoded + verified during `open_vault` and lives behind an
    /// immutable handle, so re-encoding a previously-validated card
    /// cannot fail (no IO; deterministic encoder over fixed inputs).
    pub fn owner_card_bytes(&self) -> Option<Vec<u8>>;
}
```

## 5. Step-by-step bridge orchestration

Mirrors `save/orchestration.rs` 1-for-1; differences flagged inline.

```rust
pub fn share_block(...) -> Result<(), FfiVaultError> {
    // Step 0 (NEW vs save_block): decode every input card. Any failure
    // surfaces as CardDecodeFailure.
    let existing_decoded: Vec<ContactCard> = existing_recipient_cards
        .iter()
        .map(|b| ContactCard::from_canonical_cbor(b))
        .collect::<Result<_, _>>()
        .map_err(|e| FfiVaultError::CardDecodeFailure { detail: e.to_string() })?;
    let new_decoded = ContactCard::from_canonical_cbor(new_recipient)
        .map_err(|e| FfiVaultError::CardDecodeFailure { detail: e.to_string() })?;

    // Step 1: snapshot manifest (re-uses save's snapshot fn unchanged —
    // returns the same 5-tuple).
    let (manifest_body, manifest_file, owner_card, ibk, vault_folder) =
        manifest.snapshot_for_save_block().ok_or_else(|| ...)?;

    // Step 2: snapshot identity. share_block needs an owned IdentityBundle
    // (for OpenVault construction) AND the signer keys directly (core's
    // share_block takes them as separate &Ed25519Secret + &MlDsa65Secret
    // arguments, unlike save_block which derives them from open_vault.identity).
    let identity_clone = identity.clone_inner_bundle().ok_or_else(|| ...)?;
    let (sk_ed, sk_pq) = identity.signer_secret_keys().ok_or_else(|| ...)?;

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
        &sk_ed,
        &sk_pq,
        &existing_decoded,
        &new_decoded,
        device_uuid,
        now_ms,
        &mut OsRng,
    );

    // Step 5: on Ok, write back via the existing replace_manifest_and_file
    // helper. Failure-invariant matches B.4c verbatim.
    match result {
        Ok(()) => manifest
            .replace_manifest_and_file(open_vault.manifest, open_vault.manifest_file)
            .map_err(|e| FfiVaultError::CorruptVault { detail: e.to_string() }),
        Err(e) => Err(map_core_vault_error_share(e)),
    }
}
```

## 6. Error mapping table

| `core::VaultError` variant | `FfiVaultError` variant | Display string |
|---|---|---|
| `NotAuthor { expected, got }` | `NotAuthor { expected_fingerprint_hex, got_fingerprint_hex }` | `"only the block author can share this block"` |
| `RecipientAlreadyPresent` | `RecipientAlreadyPresent` | `"recipient is already present in the block's recipient set"` |
| `MissingRecipientCard { recipient_fingerprint }` | `MissingRecipientCard { recipient_fingerprint_hex }` | `"missing contact card for recipient: {hex}"` |
| `BlockNotFound { block_uuid }` | `BlockNotFound { uuid_hex }` (existing) | (existing) |
| `Io { context, source }` | `FolderInvalid { detail }` (existing) | (existing) |
| `Block { .. }` from on-disk decode (Step 2 of core::share_block reads `<blocks>/<uuid>.cbor.enc` and decodes it) | `CorruptVault { detail }` (existing — on-disk envelope failed to decode) | (existing) |
| `Manifest { .. }` from re-sign / encode of freshly-built bytes | `CorruptVault { detail }` (existing — same reasoning as B.4c: in-memory re-sign failure) | (existing) |
| `Card { .. }` from in-memory re-encoding (`author_card.to_canonical_cbor()`, recipient `to_canonical_cbor()` for fingerprinting), reached after Step 0 decode passed | `SaveCryptoFailure { detail }` (existing — post-unlock memory-corruption-shaped failure on already-validated inputs) | (existing) |
| KEM encap / AEAD failures during recipient re-wrap | `SaveCryptoFailure { detail }` (existing) | (existing) |
| (bridge-internal) | `CardDecodeFailure { detail }` | `"failed to decode contact card: {detail}"` |

`CardDecodeFailure` is constructed directly inside the bridge — never reachable through `From<core::VaultError>`. Mirrors B.4c's `SaveCryptoFailure` pattern.

## 7. PyO3 binding shape

```python
# ffi/secretary-ffi-py/src/lib.rs additions

@pyfunction
def share_block(
    identity: UnlockedIdentity,
    manifest: OpenVaultManifest,
    block_uuid: bytes,                      # validated len == 16 → ValueError
    existing_recipient_cards: list[bytes],
    new_recipient: bytes,
    device_uuid: bytes,                     # validated len == 16 → ValueError
    now_ms: int,
) -> None: ...

# OpenVaultManifest grows:
def owner_card_bytes(self) -> bytes | None: ...

# 4 new exception classes (each subclasses VaultError, mirroring B.4c's pattern):
class VaultNotAuthor(VaultError):
    expected_fingerprint_hex: str
    got_fingerprint_hex: str

class VaultRecipientAlreadyPresent(VaultError): pass

class VaultMissingRecipientCard(VaultError):
    recipient_fingerprint_hex: str

class VaultCardDecodeFailure(VaultError):
    detail: str
```

UUID length validation happens at the binding layer and raises `ValueError` (matches B.4c). Card-bytes validation happens inside the bridge and raises `VaultCardDecodeFailure` (canonical CBOR is a security-critical contract — validation belongs at the trust boundary, not the FFI seam).

## 8. uniffi binding shape

```idl
// secretary.udl additions

namespace secretary {
    [Throws=VaultError]
    void share_block(
        UnlockedIdentity identity,
        OpenVaultManifest manifest,
        bytes block_uuid,                   // validated len == 16 → InvalidArgument
        sequence<bytes> existing_recipient_cards,
        bytes new_recipient,
        bytes device_uuid,                  // validated len == 16 → InvalidArgument
        u64 now_ms,
    );
};

interface OpenVaultManifest {
    bytes? owner_card_bytes();
};

[Error]
enum VaultError {
    // ... 9 existing variants ...
    "NotAuthor",                            // expected_fingerprint_hex, got_fingerprint_hex
    "RecipientAlreadyPresent",
    "MissingRecipientCard",                 // recipient_fingerprint_hex
    "CardDecodeFailure",                    // detail
};
```

The four new variants follow the existing field-carrying enum pattern (`BlockNotFound { uuid_hex }`, `CorruptVault { detail }` etc.). uniffi 0.31 codegen produces matching Kotlin sealed-class subtypes and Swift enum cases automatically.

## 9. Test plan

| Layer | Tests | Coverage |
|---|---|---|
| Bridge unit (error.rs) | 7 — `Display` pin + `From<core::VaultError>` mapping for each of `NotAuthor` / `RecipientAlreadyPresent` / `MissingRecipientCard` (2 each = 6) + 1 `CardDecodeFailure` constructor smoke (bridge-internal, no `From` arm) | Pin error-table contract |
| Bridge unit (vault.rs) | 2 — `owner_card_bytes()` returns `Some(_)` on live handle, `None` after wipe; round-trip equals `<vault>/contacts/<owner_uuid>.card` on-disk content | Accessor invariant |
| Bridge integration (`tests/share_block.rs`) | 7 — happy path (owner→Alice; Alice reads), `NotAuthor`, `RecipientAlreadyPresent`, `MissingRecipientCard`, wiped-manifest `CorruptVault`, wiped-identity `CorruptVault`, malformed-bytes `CardDecodeFailure` | Functional + failure-invariant |
| Bridge proptest | 1 — round-trip share to N ∈ [1..4] random recipients, every recipient reads back identical plaintext. Hold to 16 cases (Argon2id-per-case cost; same constraint as #38) | Property: shared block decodable by every recipient |
| uniffi pin (errors.rs) | 8 — `Display` pin + variant translation for each of the 4 new variants on the uniffi-side `VaultError` (2 each, mirroring B.4c's commit `a31e6e6` shape) | Pin uniffi mirror against drift |
| pytest | 8 — round-trip insert+share+read-as-recipient; update-then-share; wrong-length block_uuid; wrong-length device_uuid; `VaultNotAuthor`-distinct; `VaultRecipientAlreadyPresent`-distinct; `VaultMissingRecipientCard`-distinct; `VaultCardDecodeFailure`-distinct | Foreign exception class translation |
| Swift smoke | 4 — happy path, `NotAuthor`, `RecipientAlreadyPresent`, `MissingRecipientCard` | Live cdylib end-to-end |
| Kotlin smoke | 4 — same 4 assertions | JVM end-to-end |

Cargo addition total: 7 + 2 + 7 + 1 + 8 = **25 new cargo tests** (14 bridge + 8 uniffi + 1 proptest, with the proptest counted under bridge above).

**Test data shape (happy path):** the share test mints a second identity (Alice) via `create_vault` in a tempdir, extracts her `owner_card_bytes()` via the new accessor, then shares the block from the first vault to Alice. The block file + an Alice-recipient-shaped manifest snippet are then staged into Alice's vault layout (manual file copy in the test; the actual sync mechanism is Sub-project C), and `read_block` from Alice's vault asserts she decrypts the original plaintext.

**Out of scope for B.4d (explicitly):**
- Mid-call wipe race regression test (issue #35; the same concurrent-wipe window exists between Step 1 snapshot and Step 5 write-back as in `save_block`, but pinning it requires the same kind of sequence-point-injection harness #35 is asking for — deferred uniformly).
- File-size policy splits (issue #36; B.4d *adds* to `error.rs` and `vault.rs`, both already over the threshold).
- Share-as-fork (`TODO(share-as-fork)` in core at [orchestrators.rs:1050](../../../core/src/vault/orchestrators.rs#L1050) — future PR; B.4d tests must continue to fail with `NotAuthor` when the calling identity is not the author).

## 10. Acceptance gates at session close

| Check | Target |
|---|---|
| `cargo test --release --workspace` | **599 passed** + 9 ignored (B.4c baseline 574 + 25 new — see §9 breakdown). Acceptable drift: ±3 if implementation reveals a more natural pin-test split. |
| `cargo clippy --release --workspace -- -D warnings` | clean |
| `cargo fmt --all -- --check` | OK |
| `uv run --directory ffi/secretary-ffi-py pytest` | **58 passed** (was 50; +8) |
| `uv run core/tests/python/conformance.py` | PASS (no normative-spec change in B.4d) |
| `uv run core/tests/python/spec_test_name_freshness.py` | PASS |
| Swift smoke (`tests/swift/run.sh`) | **30/30 PASS** (was 26; +4) |
| Kotlin smoke (`tests/kotlin/run.sh`) | **31/31 PASS** (was 27; +4) |

## 11. Rollout notes

- No CLAUDE.md edits expected — B.4d does not touch the documented "v2 zeroize gap" surface (already closed by PR #16) and does not change normative spec sections (`docs/crypto-design.md`, `docs/vault-format.md`, `docs/threat-model.md`).
- README + ROADMAP updates at session close to reflect "B.4d shipped: share_block end-to-end".
- Carry-forward issues from PR #34 (#35 mid-call wipe race, #36 file-size splits, #37 Sub-project C orphan-block contract, #38 proptest case count) remain open after B.4d; the post-B.4d cleanup PR (`chore/b4d-deferred-cleanup` mirroring `chore/b4b-deferred-cleanup`) will revisit #36.

## 12. Open risks

- **`existing_recipient_cards` ergonomics for multi-share.** v1 sees `[owner_card]` only. After the *first* `share_block(owner→Alice)` succeeds, the block has 2 recipients; a subsequent share to Bob requires the caller to pass `[owner_card_bytes, alice_card_bytes]`. The caller is responsible for tracking who they've shared with — there is no bridge-side recipient registry. The pytest test `test_share_block_then_share_to_third_recipient_passes_growing_existing_list` will pin this contract in the foreign API surface.
- **Future `share-as-fork` refactor.** When the future "share-as-fork" path lands (a non-author recipient mints a fork as a new authored block), the v1 `NotAuthor`-on-non-author-share assertion becomes wrong. B.4d's tests cement the v1 semantics; the share-as-fork PR will explicitly relax them — flagged here for cross-reference.
