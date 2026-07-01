# Full security audit — Secretary

- **Date:** 2026-07-02
- **Scope:** Whole repository — Rust cryptographic core, vault/merge layer, FFI surface (bridge + PyO3 + uniffi), Tauri desktop client, native iOS client, native Android client, supply chain / CI / repo hygiene.
- **Method:** Read-only audit. Seven independent auditors, one per domain, each reading the code against the normative specs (`docs/crypto-design.md`, `docs/vault-format.md`, `docs/threat-model.md`) and the internal hardening memos (`docs/manual/contributors/*`). Findings below were consolidated and de-duplicated across domains.
- **Status of the product:** Unreleased, not yet in use. The purpose of this audit is to establish that the vault is safe for users **before** first release.

> **Line/file references** were accurate at audit time (commit at the tip of `claude/strange-mayer-587e77`, main at `8a1113a`). Line numbers drift; treat the surrounding function/symbol names as the durable anchor.

---

## 1. Executive summary

**No Critical or High-severity findings.** The security-critical invariants that the design depends on all hold:

- **Hybrid signatures are enforced as AND** (both Ed25519 *and* ML-DSA-65 must verify) at every signature-verification call site. There is exactly one verification primitive (`crypto::sig::verify`); it propagates both halves' failures with `?` and has no OR path and no swallowed error. The past near-miss where ML-DSA verification failures were swallowed is **not present**.
- **Hybrid KEM decapsulation runs both halves** (X25519 ⊕ ML-KEM-768) unconditionally, with a single AEAD MAC as the rejection oracle and full transcript binding.
- **Verify-before-decrypt** is enforced on all three unlock paths (password, recovery, device-secret): the signed manifest is hybrid-verified *before* any body is decrypted, and `vault.toml [kdf]` is cross-checked against the signed manifest.
- **Atomic writes** route through `io::write_atomic` (temp-write → `sync_all` → `persist`/rename → dir fsync), backed by the exact-pinned `tempfile =3.27.0`.
- **Nonces** are drawn from `OsRng` at every production AEAD site; no nonce reuse path exists; no deterministic RNG outside tests.
- **Dependency tree has 0 RustSec vulnerabilities**; no git dependencies; `#![forbid(unsafe_code)]` covers the workspace; no committed secrets or signing material.

What remains is:

- **One Medium finding with a live exploit path** — an Android path-traversal from a hostile cloud drive that yields an arbitrary file write/delete primitive inside the app sandbox, bypassing the audited Rust core entirely (**A-1**).
- **A cluster of Medium design / crash-consistency / documented-accepted-risk items** (V-1, V-2, V-3, D-1, D-2, S-1, S-2) — no confidentiality break, but worth resolving before release.
- **Low-severity memory-hygiene regressions** in the crypto core and bindings, matching the exact class the memory-hygiene memo exists to prevent (C-1…C-6, F-2, I-1).
- **CI hardening recommendations** for a product that will hold real user secrets (S-1, S-2, S-3, S-4).

### Severity tally

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 8 |
| Low | 9 |
| Info | many (see §8) |

### Recommended order of action

1. **A-1** — Android path-traversal guard. The only finding with a live exploit path.
2. **S-1 / S-2** — Add a scheduled `cargo audit` CI gate and SHA-pin third-party GitHub Actions. Cheap, high leverage for a secrets manager.
3. **C-1 / I-1** — Enable the `ml-kem` `zeroize` feature; redact the recovery-phrase word from the `UnknownWord` error. Small diffs, real wins, and I-1 was reported independently by two auditors.
4. **V-3 / crypto-F4** — Make a documented decision on manifest-rollback-at-open and device-slot revocation semantics.
5. **V-1 / V-2** — Implement the spec's crash-recovery paths when the orchestrator is next touched, and fix the misleading `trash_block` doc comment.
6. Remaining Low / hygiene items.

---

## 2. Cryptographic core (`core/src/crypto`, `core/src/unlock`, `core/src/identity`)

The auditor read both hardening memos first, then every file in scope, following leads into callers in `vault/` and `sync/`.

### Verified clean (with call sites)

- **Hybrid signature AND-verify.** The only verification primitive is `crypto/sig.rs::verify` — Ed25519 `?` then ML-DSA decode-`ok_or`-then-verify-`?`; no OR path, no swallowed error (an ML-DSA `decode → None` maps to `MlDsa65VerifyFailed`). All four production call sites route through it: `card.rs` (`verify_self`), `manifest.rs` (`verify_manifest`), `block.rs` (`verify_block_signature`), and `block.rs` `decrypt_block` step 2 (before any private-key op). Consumers checked: `orchestrators.rs` `?`-propagates, the card-scan skip-on-fail is fail-closed (an unverified card never enters the fingerprint→uuid map), `sync/ingest.rs` returns `None` (rejects the envelope).
- **Hybrid KEM.** `decap` runs both halves unconditionally; the HKDF ikm binds `ss_x‖ss_pq‖ct_x‖ct_pq` plus both public-key bundles; info binds the BLAKE3 transcript; AAD binds `block_uuid‖transcript`; the AEAD MAC is the single rejection oracle. Matches crypto-design §7.
- **Argon2id defaults/floor.** `V1_DEFAULT` = 256 MiB / t=3 / p=1; `V1_MIN_MEMORY_KIB` = 64 MiB; `create_vault` returns a typed `WeakKdfParams`; the open-time non-recheck is intentional and compensated (AEAD + manifest `KdfParamsMismatch`).
- **Constant-time.** State matches the side-channel memo: `subtle` is used only in `secret.rs` `PartialEq` impls; `Sensitive` still has no `PartialEq`; every direct `==` in scope is on public values (fingerprints, UUIDs, magic/version/kind bytes, timestamps, canonical-CBOR equality over already-authenticated plaintext).
- **Nonces.** Every production `aead::encrypt` site draws via `aead::random_nonce(rng)`; `wrap_device_slot`'s nonce parameter is fed by `random_nonce` at its sole production caller.
- **HKDF domain separation.** All tags distinct; the two zero-salt HKDFs (recovery vs device KEK) differ in info and are pinned divergent by a test.
- **RNG.** Production entropy is `rand_core::OsRng` at every boundary; every `ChaCha20Rng::from_seed` is inside `#[cfg(test)]`; `ml-kem`'s `deterministic` feature is used only in KATs. No `thread_rng` anywhere.
- **No secret logging / Debug leaks.** Zero `println!`/`tracing` in crypto/unlock/identity; redacted `Debug` verified on all secret-bearing types.

### Findings

#### C-1 [Low] — `ml-kem` crate's `zeroize` feature is available but not enabled

**File:** `core/Cargo.toml` — `ml-kem = { version = "0.2", features = ["deterministic"] }`

`ml-kem` 0.2.3 ships a `zeroize` feature that gates `impl Zeroize/ZeroizeOnDrop for DecapsulationKey` (wipes `dk_pke` and `z`). It is not enabled, so the `Dk` rehydrated on every `kem::decap` and the `dk` in `generate_ml_kem_768` drop without wiping their internal expanded key state. **Every other secret-bearing dependency** (`x25519-dalek`, `ed25519-dalek`, `ml-dsa`, `bip39`) has its zeroize feature enabled. The memory-hygiene memo (§2) defers this as "upstream-managed, out of our control" — that claim is inaccurate: the upstream control exists and is one Cargo.toml token away.

**Fix:** add `"zeroize"` to the `ml-kem` feature list; correct the memo's deferred-items section.

#### C-2 [Low] — ML-DSA seed stack copy not zeroized in `sign()` and `generate_ml_dsa_65()`; comment claims otherwise

**File:** `core/src/crypto/sig.rs`

`MlDsa65::from_seed(&seed)` takes the seed by reference; the local `seed` (a `hybrid_array::Array<u8, U32>`, no drop-wipe) is a second stack copy that survives un-zeroized to scope end. The comment "`seed` itself ends up inside `pq_kp`" is wrong — a copy of it does. Same pattern in `generate_ml_dsa_65` (`seed_bytes` is zeroized but `seed` is not). The ML-DSA seed is a full long-term signing key; this runs on every block/manifest/card sign.

**Fix:** `seed.zeroize()` after `from_seed`, and correct the comment.

#### C-3 [Low] — ML-KEM stack residues: 2400-byte secret-key copies and shared-secret arrays not zeroized

**File:** `core/src/crypto/kem.rs`

- `generate_ml_kem_768`: `let sk_bytes = dk.as_bytes();` — a 2400-byte `Encoded` stack array holding the full decapsulation key, copied to a `SecretBytes` then dropped un-zeroized (the sister `generate_x25519` two lines up *does* zeroize its `sk_bytes`).
- `decap`: `let dk_arr: Encoded<Dk> = …` — a second 2400-byte stack copy of the secret key, never zeroized after `Dk::from_bytes`.
- `encap`/`decap`: `ss_pq_arr` is copied into the zeroized `ss_pq_bytes` but is not itself zeroized.

The decap-side copy runs on every block read, leaving the long-term PQ secret key in the stack frame.

**Fix:** zeroize `dk_arr` / `sk_bytes` / `ss_pq_arr` after use, mirroring the sister-site discipline.

#### C-4 [Low] — Bundle codec leaves un-zeroized heap+stack copies of the *entire* secret-key set on every vault create and unlock

**Files:** `core/src/unlock/mod.rs` (`create_vault_unchecked`), `core/src/unlock/bundle.rs` (both directions)

`to_canonical_cbor` copies each secret key into `ciborium::Value::Bytes`; the resulting `Vec<u8>` bundle plaintext (all four secret keys, cleartext) drops with no `zeroize()`. On the read side (every unlock), `from_canonical_cbor`'s ciborium `Value` tree holds secret-key copies, `take_fixed_bytes` consumes a `Vec<u8>` of key bytes that deallocates un-wiped, and the two `Option<[u8;32]>` locals still hold key bytes after the `Copy`-move into `Sensitive::new`. The canonicality re-encode produces yet another full un-zeroized plaintext copy. The memory-hygiene memo's carve-out documents this class only for `vault/record.rs`; the identity-bundle instance is strictly worse (every long-term key at once, on every unlock) and is not flagged anywhere.

**Fix:** zeroize `bundle_plaintext` and the canonical re-encode buffer after use; apply the established post-move zeroize to the two fixed-array locals; extend the memo's carve-out to name `bundle.rs`.

#### C-5 [Low] — Mnemonic parse leaves the full 24-word phrase in un-zeroized heap strings

**File:** `core/src/unlock/mnemonic.rs`

`let nfkd: String = words.nfkd().collect();` and the subsequent `normalized` string and per-word lowercase strings all hold recovery-phrase material and drop without zeroize. `Mnemonic` itself carefully zeroizes its `phrase` on drop, so the discipline is inconsistent within the same module.

**Fix:** `nfkd.zeroize(); normalized.zeroize();` (and the intermediate strings) before return.

#### C-6 / I-1 [Low] — `MnemonicError::UnknownWord(String)` copies recovery-phrase input into an error value (also surfaced by the FFI auditor)

**File:** `core/src/unlock/mnemonic.rs` — `#[error("word not in BIP-39 English list: {0}")] UnknownWord(String)`

The offending token is embedded in a `Display`/`Debug` error. This propagates through the FFI bridge (`InvalidMnemonic { detail }`) into Python/Swift/Kotlin exception messages, which routinely reach mobile platform logs, crash reporters, and analytics. A typo of a real word is usually ~1 edit distance away, leaking ≈11 bits of one of 24 words. The design docs correctly note this is not a *decryption* oracle, but log-leakage of near-correct phrase words was evidently not the property being defended. **This was reported independently by both the crypto and FFI auditors.**

**Fix:** carry the word *index* instead of the content (the `bip39` crate already reports by index), or explicitly document the leak as accepted and warn UI layers never to log `InvalidMnemonic.detail`.

### Info-level notes

- **[Info] Unbounded Argon2id parameters from attacker-writable `vault.toml` at open** — `open_with_password` builds `Argon2idParams::new(vt.kdf.memory_kib, …)` with no upper bound; a hostile `vault.toml` can demand ~4 TiB (allocation abort) or 2³² iterations (multi-year hang) before the AEAD wrong-password check runs. DoS is explicitly out of scope in `threat-model.md`, so Info only, but a generous sanity cap (≤ 4 GiB / ≤ 100 iterations) at open converts an abort into a typed error at negligible cost.
- **[Info] `create_vault` floor check doesn't route through `try_new_v1`; `try_new_v1` has zero production callers.** Not exploitable (argon2 rejects 0-values), but the CLAUDE.md invariant nominates `try_new_v1` as the choke-point for future re-wrap/change-password flows — wire it when such a flow lands.
- **[Info] Ed25519 verification uses dalek `verify`, not `verify_strict`.** No exploit path (AND-ed with ML-DSA; signatures live inside the signed envelope, not used as identifiers), but for a decades-frozen format the verification-criteria choice should be pinned in `docs/crypto-design.md` §8 so a clean-room implementation doesn't diverge on edge-case acceptance.
- **[Info] Device revocation is deletion-only** (see V-F4 below for the vault-layer statement).

---

## 3. Vault layer (`core/src/vault`)

### Verified clean

- **Verify-before-decrypt (all three unlock paths).** `read_and_verify_manifest` loads and self-verifies the owner card, cross-checks `author_fingerprint`, runs `verify_manifest` (hybrid Ed25519 ∧ ML-DSA-65) **before** `decrypt_manifest_body`. All of `Unlocker::{Password,Recovery,DeviceSecret}` funnel through the same helper; the device path adds `unlock/device.rs::open_with_device_secret` (checks `vault_uuid`, `device_uuid`, AEAD tag before the shared manifest verify). Block reads verify the hybrid signature before hybrid-decap/AEAD.
- **KDF cross-check.** `manifest_body.kdf_params == vault.toml [kdf]` enforced (`KdfParamsMismatch`), and `kdf_params` is inside the signed manifest body.
- **Atomic writes.** All production vault-state writes route through `io::write_atomic` (temp-write → `sync_all` → `persist` → dir fsync). `tempfile` is exact-pinned `=3.27.0`. The two non-`write_atomic` mutations are `fs::rename` (trash/restore moves, the intended atomic primitive) and best-effort `fs::remove_file` purges.
- **CRDT merge safety.** The death-clock `clamp_death_clock` defends both malformation directions; merge is a `max`-join on `tombstoned_at_ms`; the staleness filter drops `last_mod ≤ death_clock`; the `unknown` map merge is a bounded per-key lex-max join over the union. Resurrection requires a live edit with `last_mod > death_clock`; attacker-crafted clocks cannot force silent overwrite beyond deterministic LWW. The manifest decoder rejects duplicate device/block/trash UUIDs.
- **Untrusted-input parsing.** `device_file.rs`, `block.rs`, `manifest.rs` decoders are bounds-checked (`read_array` length guards; `checked_mul`/`checked_add` on count×len; declared-len vs remaining checks). All `try_into().expect(...)` are preceded by explicit length checks. No unbounded length-field allocation.
- **Path traversal.** All filenames derive from `format_uuid_hyphenated` over fixed `[u8;16]` arrays (hex only); no attacker-controlled string reaches a path component. The trash-suffix parse is strict-canonical `u64`.
- **Restore rollback-freshness (#205/#293).** Restore-target selection binds to the signed `TrashEntry.tombstoned_at_ms` (equality, not largest-suffix) and the `fingerprint` content commitment is checked before decode.

### Findings

#### V-1 [Medium] — Crash between a block-file op and the manifest write leaves the vault unopenable; the `trash_block` doc comment is wrong

**Files:** `core/src/vault/orchestrators.rs` (`open_vault` → `verify_block_fingerprints`; `trash_block`; `save_block`), spec `docs/vault-format.md` §6.5.

`open_vault` unconditionally runs `verify_block_fingerprints`, which `fs::read`s each manifest-listed block and errors on `NotFound`/mismatch, aborting the open. Two crash windows produce exactly that state:

1. `trash_block` renames `blocks/X → trash/X.<ts>` **before** the manifest write. A crash between leaves the on-disk manifest still listing the block → next `open_vault` fails with `Io(NotFound)`. The doc comment claiming this is "harmless because open_vault reads only entries listed in the manifest — the trashed file is then detectable as an orphan" is **wrong**: the entry *is* still listed, so the missing file is fatal, not an orphan.
2. `save_block`/`rewrite_block_with_recipients` write the block first (correct §9 order); a crash before the manifest write → next open fails with `BlockFingerprintMismatch`. The FFI bridge maps this to `CorruptVault` — a terminal-looking error. Spec §6.5 promises "detect the inconsistency on next read, re-load the block, re-fingerprint, and offer to update the manifest"; no such path exists, and the documented sync-based recovery needs an `UnlockedIdentity`, which apps only obtain via the very `open_vault` that refuses to open.

Availability/crash-consistency only — no confidentiality impact (fail-closed). But a power loss at the wrong instant (or a torn cloud sync delivering block-new/manifest-old) locks the user out of the whole vault with an error labelled "corrupt vault".

**Fix:** implement the §6.5 recovery (return a typed *recoverable* state, or an `open_vault` variant that tolerates the inconsistency for repair); fix the incorrect `trash_block` comment; consider tolerating "manifest lists block, file exists in `trash/` with matching fingerprint" as a resumable trash.

#### V-2 [Medium] — `restore_block` crash window wedges the block permanently (spec claims it's retryable)

**Files:** `core/src/vault/orchestrators.rs` (`restore_block`), spec `docs/vault-format.md` §7.1.

After the trash→blocks rename, if the manifest write never lands, the on-disk manifest still carries the `TrashEntry` and no `BlockEntry`. Re-running `restore_block` scans `trash/`, finds no matching file (it was moved), and returns `BlockNotInTrash`. The spec says the crash is "recoverable on next open by re-attempting the restore" — the re-attempt actually fails. The bytes are not lost, but the block is unreachable through the API forever.

**Fix:** in the restore scan, when the manifest `TrashEntry` exists and `blocks/<uuid>.cbor.enc` is already present with bytes matching `TrashEntry.fingerprint`, resume at the manifest-update step instead of erroring.

#### V-3 [Medium] — §10 manifest rollback resistance is not enforced on any app-facing open path

**Files:** `ffi/secretary-ffi-bridge/src/vault/orchestration.rs` (`open_vault(…, None)`), `ffi/secretary-ffi-bridge/src/vault/mod.rs` ("`local_highest_clock` is always `None`; rollback detection deferred to Sub-project C"); threat model `docs/threat-model.md`.

`read_and_verify_manifest` only runs `is_rollback` when `local_highest_clock` is `Some`. Every bridge open passes `None`. The sync layer *does* enforce rollback via its own persisted `highest_vector_clock_seen`, so it's caught when a sync runs — but a cloud host serving an older signed manifest+blocks snapshot to a device that opens **without syncing** is accepted silently. The threat model states rollback rejection as a delivered defense (adversary 2.1, explicitly in scope), and the bridge comment says "deferred to Sub-project C" though C is complete through C.4. Manifest rollback can resurrect revoked recipients' block versions or a rotated password at browse time on a device between syncs.

**Fix:** thread the sync layer's persisted `highest_vector_clock_seen` into the bridge opens, or update the threat-model / bridge docs to state precisely that rollback detection happens only at sync time.

#### V-F4 [Medium, documentation] — Device-slot "revocation" is delete-only; the IBK never rotates, and this residual is undocumented

**Files:** `core/src/vault/device_slot.rs` (`remove_device_slot` = `fs::remove_file`); `docs/adr/0009-per-device-wrap-slot.md`; `docs/crypto-design.md` §5a; `docs/threat-model.md` (no mention).

All device slots wrap the *same* IBK. Removing a wrap file does nothing against: (a) the revoked device itself, which holds its `device_secret` and can trivially retain a copy of its 128-byte wrap file; (b) cloud-provider version history, which retains deleted/old file versions the revoked device could re-fetch. Contrast the block-revocation path (§6.5.1/§7.3), where the forward-secrecy boundary is spelled out explicitly. For device slots, neither crypto-design §5a, vault-format §3a, ADR 0009, nor threat-model.md states that effective revocation of a *compromised* device requires more than deleting the file (v1 has no IBK rotation). Not exploitable beyond an already-compromised device (whose compromise implies full identity-bundle compromise anyway), but the residual should be documented before release so users don't over-trust "remove device".

**Fix:** add the equivalent of the §6.5.1 "forward-secrecy boundary" paragraph to crypto-design §5a / ADR 0009.

**Related [Info]:** `device_uuid` is not in the wrap-file AAD (only `vault_uuid` is); the §3a structural check (`DeviceUuidMismatch`) is the only binding. Impact is nil today (decryption still requires the right `device_secret`), and the code documents the choice, but a wrap header's `device_uuid` field is malleable without breaking the tag.

#### V-5 [Low] — Core `share_block` writes caller-supplied contact-card bytes verbatim; TOFU enforcement lives only in the FFI bridge

**Files:** `core/src/vault/orchestrators.rs` (`rewrite_block_with_recipients`); guard in `ffi/secretary-ffi-bridge/src/share/orchestration.rs`.

`rewrite_block_with_recipients` overwrites `contacts/<uuid>.card` with whatever bytes the caller supplies. The verified-card gate (`read_verified_card`) and the `ContactAlreadyExists` byte-compare TOFU guard exist *solely* in the bridge. Any current or future in-repo caller (the desktop Tauri backend calls core directly, tests, future orchestrators) that passes an unverified or substituted card silently replaces a trusted contact's public keys — every subsequent re-key then wraps the block content key to the attacker's key. A security-critical invariant enforced by convention rather than by the layer that owns the write ("security paths can't rely on assumptions").

**Fix:** move `verify_self` + non-overwrite-on-byte-diff into `rewrite_block_with_recipients`/`share_block` in core, keeping the bridge check as defense in depth.

#### V-6 [Info] — `open_vault` verifies fingerprints of manifest-listed blocks but not the reverse

`verify_block_fingerprints` iterates `manifest.blocks` only. A cloud host can drop arbitrary extra `blocks/*.cbor.enc` files; they are correctly ignored at open (the manifest is the authenticated index) but are never surfaced or cleaned. Confidentiality is fine (unlisted blocks are never decrypted). Hardening/GC gap only.

---

## 4. FFI surface (`ffi/secretary-ffi-bridge`, `ffi/secretary-ffi-py`, `ffi/secretary-ffi-uniffi`)

**Lean-binding guard executed:** `check-lean-binding.sh --self-test` → PASS (positive control fires); `check-lean-binding.sh` → PASS (all three binding crates lean).

### Verified clean

- **Bridge-trusts-caller validation parity holds in BOTH bindings.** Every bridge entry point with fixed-size or semantic constraints has the corresponding check in both the PyO3 wrapper (returns `ValueError`) and the uniffi wrapper (returns `InvalidArgument`): `read_block`, `save_block`, `share_block`/`share_block_to`, `trash_block`/`restore_block`, the record-edit family, `create_block`/`rename_block`, `move_record` (incl. the source≠target guard), `open_with_device_secret` (uuid=16, secret=32, with zeroize on every early return incl. the `[u8;32]` stack copy), `remove_device_slot`, `sync_status`, `sync_commit_decisions`. The bridge `FfiVaultError` has no `InvalidArgument` variant, as designed; non-test `.expect()` calls exist only *after* explicit length checks.
- **Wiped-handle semantics.** Zero-bytes/empty/0/false/None everywhere; extended to poisoned mutexes via `lock_or_recover`; idempotent wipes; `Arc`-clone wipe cascade. Write/read orchestrators fail typed (`CorruptVault`/`HandleWiped`) instead of acting on defaults (see F-4 for the residual read-only footgun).
- **Error mapping is exhaustive and drift-proof.** `From<UnlockError>`/`From<VaultError>` have no wildcard arms (compile-error tripwires); the PyO3 translator maps all 31 `FfiVaultError` variants 1:1 to distinct exception classes; uniffi `From<FfiVaultError>` is 1:1; the Swift `ConformanceErrors.swift` and Kotlin `ConformanceErrors.kt` both enumerate all 31 variants exhaustively. No security-distinct error collapses into a benign one (signature/AEAD/fingerprint failures → `CorruptVault`; the anti-oracle `Wrong{Password,Mnemonic,DeviceSecret}OrCorrupt` conflations are deliberate and pinned by tests).
- **Device-slot FFI.** `DeviceSlotNotFound`/`WrongDeviceSecretOrCorrupt`/`DeviceUuidMismatch` are intercepted *before* the generic unlock fold so they can't degrade to `CorruptVault`; wrong-length uuid/secret is binding-layer `ValueError`/`InvalidArgument` in both bindings; `open_with_device_secret` routes through the same core `open_vault` manifest verify-before-decrypt.
- **Unsafe.** Bridge: `#![forbid(unsafe_code)]` + workspace forbid. PyO3/uniffi crates: crate-local `unsafe_code = "deny"` + a crate-level `#![allow(unsafe_code)]` covering only macro/scaffolding expansion; zero hand-written `unsafe` blocks. No panic/abort paths across the FFI in non-test code.

### Findings

#### F-2 [Low] — PyO3 wrappers drop secret-*output* transients unzeroized (asymmetric with the input-side discipline)

**Files:** `ffi/secretary-ffi-py/src/device.rs` (`take_secret` — 32-byte device secret), `ffi/secretary-ffi-py/src/unlock.rs` (`take_phrase` — 24-word mnemonic), `ffi/secretary-ffi-py/src/record.rs` (`expose_bytes` — record field secret).

The crate meticulously zeroizes *input* transients but the highest-value *outputs* leave a wrapper-side heap residue: `self.0.take_secret().map(|v| PyBytes::new(py, &v))` drops the intermediate `Vec<u8>` without `zeroize()`. Unlike the uniffi wrappers (where the `Vec<u8>` is consumed into an unzeroizable `RustBuffer`, structurally out of reach), in PyO3 it's one line.

**Fix:** `let mut v = …; let b = PyBytes::new(py, &v); v.zeroize(); Some(b)` in `take_secret`/`take_phrase`/`expose_bytes`.

#### F-3 [Low] — `import_contact_card` TOFU no-overwrite guard has a check-then-write race; `persist` clobbers

**File:** `ffi/secretary-ffi-bridge/src/contacts/import.rs`

`if path.exists() { return Err(ContactAlreadyExists) }` followed by `write_card_atomic` (`tmp.persist(path)`). `NamedTempFile::persist` is `rename(2)`, which **replaces** an existing destination. Two concurrent imports of different cards claiming the same `contact_uuid` (two app instances, a sync daemon, or a malicious card delivered while the user imports the legitimate one) both pass the `exists()` check; the loser's trusted card is silently replaced — exactly the TOFU substitution the guard exists to prevent.

**Fix:** use `tempfile`'s `persist_noclobber(path)` and map the `AlreadyExists` error to `ContactAlreadyExists`.

#### F-4 [Info/Low] — Wiped-handle safe defaults remain a #252-class footgun; no FFI-visible `is_wiped()`

The non-throwing zero-default design is implemented consistently and correctly; write paths fail typed rather than acting on defaults. The residual hazard is *read-only* consumers: a caller keying per-vault state by `manifest.vault_uuid()` after a concurrent wipe gets the all-zero UUID (the exact #252 pattern that already bit once), or treats `block_count() == 0` as "empty vault". The only wipe indicator is the redacted `Debug` impl, which is not FFI-exposed.

**Fix:** expose `is_wiped(): bool` on `UnlockedIdentity`/`OpenVaultManifest` through both bindings so consumers can assert before using identity-bearing defaults. Cheap and additive.

#### I-1 [Low] — `InvalidMnemonic` detail embeds a user-typed recovery-phrase word (same root cause as C-6)

See C-6. The FFI auditor traced the leak all the way into Python `args[0]`, Swift/Kotlin `Throwable` messages, and confirmed a bridge test (`invalid_mnemonic_unknown_word_carries_detail`) actively asserts the word is present. Fix at the bridge translation seam and/or the core error type.

#### [Info] — uniffi/GC-side secret exposure is at the documented floor; nothing makes it worse

Passwords/mnemonics/device secrets/field values cross as `Vec<u8>`/`String`; foreign-side copies are unzeroizable (inherent, documented; UDL deliberately uses `bytes` not `sequence<u8>` so Kotlin gets an overwritable `ByteArray`). No aggravators: no logging in any of the three crates' non-test code, all Debug impls redacted, no caching of secret values, error `detail` strings carry only hex UUIDs/fingerprints — with the single exception of I-1.

---

## 5. Desktop client (`desktop/`, Tauri 2)

Command inventory: 32 commands, all routing through `lock_session` + `with_unlocked` where stateful. All backend `detail` fields are `#[serde(skip_serializing)]` (never cross IPC); decryption failures collapse to `WrongPassword` (anti-oracle).

### Verified clean

- **CSP** (`tauri.conf.json`): `default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ipc: tauri:; script-src 'self'`. `script-src 'self'` (no `unsafe-inline`/`eval`), no remote origins, no `withGlobalTauri` (so `window.__TAURI__` not exposed).
- **No frontend XSS sinks, no web/network surface, no updater.** Zero `{@html}`/`innerHTML`/`eval`/`document.write` across `desktop/src`; no `fetch`/`XMLHttpRequest`/`WebSocket`/`sendBeacon`; all revealed secrets rendered via auto-escaped text interpolation; no auto-updater configured. `console.error/warn` sites log `AppError`s/transport errors, not secret values.
- **Clipboard: write-only scope + auto-clear.** `capabilities/default.json` grants only `clipboard-manager:allow-write-text`. Secret and mnemonic copy both schedule a 30 s clear and fire the clear on unmount/lock (so a revealed secret can't survive a lock in the OS clipboard). Reveal auto-re-masks after 20 s.
- **Auto-lock and backend session wipe.** `UnlockedSession::Drop` wipes `manifest` then `identity`; fires on explicit lock, auto-lock, and process exit; the timer fail-secures on a poisoned mutex; only single-record plaintext ever crosses IPC.
- **Supply chain.** Only 3 first-party `@tauri-apps/*` runtime deps; `pnpm-lock.yaml` present (no stray `package-lock.json`); no phone-home deps.
- **Settings cannot downgrade KDF params from the frontend.** In-vault settings are only `autoLockTimeoutMs`, `requirePasswordBeforeEdits`, `reauthGraceWindowMs`; KDF params are not settings; `create_vault` hardcodes `Argon2idParams::V1_DEFAULT`.

### Findings

#### D-1 [Medium] — Write re-auth gate is frontend-only; backend write commands enforce nothing

**Files:** `desktop/src/lib/writeCommands.ts`, `desktop/src/lib/writeGuard.ts`, `desktop/src-tauri/src/commands/reauth.rs`, all `commands/{edit,delete,contacts,settings}.rs`.

`verify_password` is stateless (returns Ok, stores nothing); `lastAuthAtMs` lives only in JS module state. No Rust command checks any re-auth window; `set_settings_impl` accepts `requirePasswordBeforeEdits: false` with no password. Under the stated Tauri threat model (webview = potentially compromised), any script execution in the webview silently disables the re-auth policy and performs every mutating write (tombstone, trash, revoke, share, settings) with no prompt; likewise a local attacker who opens devtools in a debug build. **This is a documented, deliberate accepted risk (#278/#280)** — flagged so the boundary is understood as UX-only, not a missed control.

**Fix (if hardening desired):** move `lastAuthAtMs` into `VaultSession` and have gated `*_impl`s check it; `verify_password` would seed it under the same mutex.

#### D-2 [Medium] — IPC commands accept arbitrary filesystem paths from the webview

**Files:** `desktop/src-tauri/src/commands/contacts.rs`, `commands/create.rs`, `commands/unlock.rs`.

- `import_contact(card_path)` → `std::fs::read` of any path (weak read/parse oracle; content not returned to JS).
- `export_contact_card(dest_dir)` → `std::fs::write` of the (public) owner card into any directory, silently overwriting a same-named file.
- `create_vault(folder_path)` → `create_dir_all` at any path (empty-dir check prevents clobber, but allows arbitrary directory-tree creation).
- `probe_create_target(folder_path)` → full-filesystem existence + emptiness oracle, session-stateless, works while locked.
- `unlock_with_password(folder_path)` → opens any vault path (still requires the password; inherent to the client-only design).

Nothing binds these commands to dialog-returned paths, so a compromised webview gets a filesystem probe + constrained write primitive.

**Fix:** validate paths against the last dialog-returned path (held in Rust state), or at minimum require an unlocked session for `probe_create_target`/`import_contact` and document the residual surface.

#### D-3 [Low] — Auto-lock-timeout increase is not covered by the "security-reducing change" re-auth gate

**File:** `desktop/src/components/SettingsDialog.svelte`

`reducesProtection` triggers only on disabling `requirePasswordBeforeEdits` or widening `reauthGraceWindowMs`. Widening `autoLockTimeoutMs` (up to the backend-enforced 24 h cap — a genuine security reduction) is not gated, so an attacker at an unlocked session can max the idle window.

**Fix:** include an `autoLockTimeoutMs` increase in the `reducesProtection` predicate.

#### D-4 [Info] — CSP includes `style-src 'unsafe-inline'`

Svelte-scoped-style driven, low risk (no script execution), but it slightly weakens defense against CSS-injection exfiltration. Noted for completeness.

---

## 6. iOS client (`ios/`)

### Verified clean

- **Secure Enclave key** uses the strongest flags: `kSecAttrTokenIDSecureEnclave` + `SecAccessControlCreateWithFlags(kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet])` — invalidates on biometric re-enrollment, no passcode fallback, P-256 private key permanent/non-exportable (never leaves SE). Wrapped blob stored as a generic password with `WhenUnlockedThisDeviceOnly`.
- **Keychain audit:** only two `SecItemAdd` sites (SE blob + non-secret enrollment metadata), both `WhenUnlockedThisDeviceOnly`, **no `kSecAttrSynchronizable` anywhere**, no access groups. Nothing uses `AfterFirstUnlock` or omits `ThisDeviceOnly`.
- **Biometric error handling:** cancel/appCancel/systemCancel → `.userCancelled`; unknown codes → generic `.enclave`, **never** `.wrappedSecretCorrupt`; corrupt is asserted only when decrypt returns nil with no CFError (on-device-verified #202/#214 invariant). No silent downgrade to weaker auth.
- **Grace window:** fixed (non-sliding) 30 s window; `lastAuthAt` advances only on successful biometric; in-window writes do not extend it; seeded at unlock only on the biometric-open path; the gate object dies on backgrounding (session wipe + route reset), so it does not survive backgrounding.
- **Secret display lifetime:** reveals are explicit, keyed, auto-hidden after 30 s, dropped on reload/block-switch, dropped on `scenePhase != .active`; the whole session is wiped on `.background`. No `UIPasteboard` usage; no secrets in `UserDefaults`; no secrets in `os_log`.
- **App-switcher/screenshot:** opaque `PrivacyCover` whenever the scene is not `.active`, covering the recovery-phrase wizard and reveals before the iOS snapshot.
- **App config:** no ATS exceptions, no custom URL schemes/universal links (zero remote input surface — the app has no networking), Face ID usage string present, Swift 6 strict concurrency.
- **Cloud vault access:** operates **in place** on the security-scoped provider URL; no working-copy shim, hence no temp files carrying vault data (the only `copyItem` is the public demo fixture).

### Findings

#### iOS-1 [Low] — Transient `Data` copies of password/device-secret not zeroized in `UniffiVaultDeviceSlotPort`

**File:** `ios/SecretaryKit/Sources/SecretaryKit/DeviceUnlock/UniffiVaultDeviceSlotPort.swift`

`addDeviceSlot(…, password: Data(password))` and `openWithDeviceSecret(…, deviceSecret: Data(deviceSecret))` — the `Data(...)` heap copies are never scrubbed. Contrast `UniffiVaultOpenPort.swift`, which wraps every secret in `withZeroizingData`. `addDeviceSlot` is on the production "Remember this device" enroll path, so a heap copy of the master password lingers until ARC frees it.

**Fix:** route both through `withZeroizingData` (already present in SecretaryKit) or `defer { data.resetBytes(...) }`.

#### iOS-2 [Low] — Password `[UInt8]` copies captured in long-lived Tasks are dropped, never zeroized

**Files:** `ios/SecretaryApp/Sources/UnlockScreen.swift`, `ios/SecretaryApp/Sources/SecretaryApp.swift`

`lastPasswordSecret = nil // drop our copy` releases the reference without `resetBytes`; `onUnlocked` then captures the same bytes into two detached `Task`s (sync-at-unlock and the enroll continuation) — neither zeroizes after use. `@State private var password: String` is never reset to `""` after a successful unlock/enroll. The project's own bar (used elsewhere) is overwrite-before-drop; these sites only drop.

**Fix:** zeroize `lastPasswordSecret` before nil-ing; zeroize the captured array after the last Task consumer completes (or hand each Task its own copy scrubbed in a `defer`); set `password = ""` on success.

#### iOS-3 [Low/Info] — Grace-window clock (`DispatchTime.uptimeNanoseconds`) pauses during device sleep

**Files:** `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/MonotonicClock.swift`, `GraceWindowReauthGate.swift`

`DispatchTime.now().uptimeNanoseconds` is `mach_absolute_time`-based and does not advance while the device is asleep, so the 30 s window measures awake-time. Exposure is small (the session is wiped and the gate discarded on `.background`, which a lock-screen sleep normally triggers); the residual case is a device sleeping without the scene reaching `.background`.

**Fix:** stamp from `mach_continuous_time` (`ContinuousClock`) instead; `MonotonicInstant` semantics are unchanged.

#### iOS-4 [Info] — No explicit `NSFileProtection` class on app-created files

Files get the sandbox default `CompleteUntilFirstUserAuthentication`. Materially mitigated (vault content is already encrypted by the core; the device secret is SE-wrapped in the Keychain with `WhenUnlockedThisDeviceOnly`; user-chosen provider folders can't take app-set protection classes anyway). Suggest documenting the accepted default, or setting `.complete` on the sync-state dir and the staged demo vault.

#### iOS-5 [Info] — Encrypted vault + sync state are iCloud-backup-eligible; only the CRDT device-uuid file is excluded

Backup of the *encrypted* vault is consistent with the threat model (cloud sync of ciphertext is a product feature) but isn't explicitly documented as accepted for iOS backups. Docs line only.

#### iOS-6 [Info] — Failed background enroll error is written to a binding the user has likely navigated away from

UX-only; the security effect is that a user may believe biometric unlock is armed when enrollment failed. Self-corrects on the next unlock (no Face ID button shown).

---

## 7. Android client (`android/`)

### Verified clean

- **Keystore-backed device unlock** (`KeystoreDeviceSecretEnclave.kt`): `setUserAuthenticationRequired(true)`; API 30+ `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)` (per-use, biometric-strong only, no device-credential fallback); `setInvalidatedByBiometricEnrollment(true)`; StrongBox attempted with correct fallback; AndroidKeyStore-generated (non-exportable); `KeyPermanentlyInvalidatedException` → `Enclave` not `WrappedSecretCorrupt`; blob app-private under `noBackupFilesDir`.
- **BiometricPrompt is CryptoObject-bound** (`BiometricPromptGate.kt`): every prompt is `authenticate(info, CryptoObject(cipher))`, uses the unlocked cipher from the result, rejects a null cipher; `BIOMETRIC_STRONG` only. The write-reauth path proves presence by actually releasing the secret through the CryptoObject cipher — a real cryptographic gate, not a boolean.
- **#340/#344 write-reauth gate cannot be bypassed by racing vault resolution** (`CloudVaultOpen.kt`, `RetargetableReauthGate.kt`): the gate is retargeted from the *resolved* UUID before `openBrowseWithSync` returns; `cloudReauthRoute` selects GRACE_WINDOW only when the enclave is enrolled AND `metadataVaultId == resolvedVaultId`; NOOP-on-mismatch cannot forge a proof; grace-window advances only on success using a monotonic `elapsedRealtime` clock.
- **Manifest / FLAG_SECURE / exported / backup:** `allowBackup=false`; no `android:debuggable`; single `MainActivity` exported with only the LAUNCHER filter (handles no external data); no exported receivers/providers/services; `FLAG_SECURE` set before `setContent`.
- **SAF working-copy location + URI-permission persistence:** working copy under app-private `filesDir`/`noBackupFilesDir` (never external/shared); `takePersistableUriPermission` scoped read+write to exactly the picked tree, taken before persisting the pref, superseded grants released; push-before-pull + no-manifest-materialize guard prevent an attacker-controlled empty cloud from deleting an un-pushed vault.
- **Secret lifetime:** `ByteArray` credentials zeroized (`fill(0)`) on every exit path; no `rememberSaveable` (so no secret in `savedInstanceState`); no secret logged; unlock-failure messages conflate wrong-password with corruption (no oracle).
- **uniffi wiped-handle handling** (`UniffiVaultOpenPort.kt`): `vaultUuidHex` snapshotted at construction (avoids the #252 all-zero bug); all handle access under `sessionLock` with a `wiped` flag; `write` throws rather than acting on a safe-default.
- **Clipboard:** no copy-secret feature exists at all (reveal is view-only with auto-hide) — nothing to flag, but if added later it must set `ClipDescription.EXTRA_IS_SENSITIVE` + auto-clear.

### Findings

#### A-1 [Medium] — Path traversal from cloud-supplied file names into app-private storage (SAF materialize/delete)

**Files:** `android/vault-access/src/main/kotlin/org/secretary/mirror/VaultMirror.kt` (`writeWorking`/`deleteWorking`), `android/kit/src/main/kotlin/org/secretary/mirror/SafCloudFolderPort.kt` (`walk`).

```kotlin
private fun writeWorking(workingDir: File, relativePath: String, bytes: ByteArray) {
    val target = File(workingDir, relativePath)   // no "../"/absolute-segment rejection
    target.parentFile?.mkdirs()
    target.writeBytes(bytes)
}
```

`relativePath` originates from `cloud.list()` → SAF `DocumentFile.getName()`, i.e. display names reported by the DocumentsProvider. The threat model includes an attacker-controlled cloud drive; a malicious/compromised provider (or one that faithfully syncs attacker-chosen server-side names like `..%2F..`) can return names containing `..` or path separators. `materialize()` then writes attacker bytes to `File(workingDir, "../../…")` — an **arbitrary write/delete primitive anywhere writable in the app sandbox**: the device-secret blob (`noBackupFilesDir/devicesecret/blob`), enrollment metadata, `shared_prefs/…`, or the staged golden vault. It never reaches the audited Rust core (which never sees these paths). No segment validation exists anywhere on this path. **This is the only finding in the whole audit with a live exploit path.**

**Fix:** in `VaultMirror.readWorking/writeWorking/deleteWorking` and/or in `SafCloudFolderPort.walk`, reject any relative path whose split segments contain `""`, `.`, `..`, or that is absolute; canonicalize the resolved `target` and assert `target.canonicalPath.startsWith(workingDir.canonicalPath + File.separator)` before write/delete. Apply the same guard to `resolve`/`findOrCreate` on the cloud (push) side.

#### A-2 [Low/Info] — Working copies of the vault are never cleaned up on forget

**Files:** `android/app/src/main/kotlin/org/secretary/app/ProvisioningRouting.kt`, `android/vault-access/src/main/kotlin/org/secretary/browse/VaultSelectionViewModel.kt` (`chooseDifferent`), `SafVaultLocationStore.clear()`.

`cloudWorkingVaultDir = filesDir/working/<sha256(treeUri)>` is created on every open but `SafVaultLocationStore.clear()` releases the SAF grant and clears the pref without deleting the working dir; `chooseDifferent()`/forget likewise leave it, as does the per-cloud device-secret dir. The working copy holds the full *ciphertext* vault (bounded exposure — same ciphertext already on the cloud drive), but it persists in `filesDir` after the user "forgets" the vault and across app updates, contrary to the "wipe on lock/forget" posture. App-private and excluded from backup (good).

**Fix:** on `clear()`/forget, `deleteRecursively()` the keyed working dir + the per-cloud device-secret dir + the pending-flush marker.

**[Info] design note:** the write-reauth gate is a *presence* control, not an authorization control — an already-unlocked in-memory session on an un-enrolled vault has no write gate (matches the demo path and iOS). Called out as design intent, not a defect.

---

## 8. Supply chain, dependencies, CI, repo hygiene

### Verified clean

- **RustSec: 0 vulnerabilities** (fresh advisory DB, 2026-07-02, against the committed `Cargo.lock`).
- **No git dependencies** anywhere in the workspace (all ~650 packages from `registry+crates.io`).
- **`#![forbid(unsafe_code)]`** at the workspace root, inherited by core, cli, desktop/src-tauri, ffi-bridge, browser-host; `core/fuzz` (workspace-excluded) restores forbid in its own lints. Two deliberate `deny` + `#![allow(unsafe_code)]` downgrades in the PyO3 and uniffi crates (macro-expansion necessity, each documented).
- **Pinning discipline compliant:** `tempfile = "=3.27.0"`, `zeroize = "=1.8.2"`, `psl = "=2.1.137"` — all exact-pinned with rationale comments across every crate that uses them.
- **CI otherwise clean:** no `pull_request_target`, no PR-head-with-secrets checkout, `permissions: contents: read` in all three workflows, no secrets referenced, no `${{ github.event.* }}` interpolated into `run:`, no artifact uploads; PR caches are branch-scoped (can't poison main); Kotlin jars downloaded with hardcoded SHA-256 verification even on cache hit.
- **Repo secret scan clean:** no PEM/private-key blocks; no `.jks`/`.keystore`/`.p12`/`.mobileprovision`/`.env` committed; no credential-shaped assignments outside test/docs; golden-vault KAT material confined to fixture dirs.
- **Frontend/Android deps:** Tauri-official runtime deps only; `pnpm-lock.yaml` with zero off-registry sources and pnpm postinstall-script blocking (`allowBuilds: esbuild` only); Android deps current (biometric 1.1.0, JNA 5.14.0).

### Findings

#### S-1 [Medium] — No automated dependency-advisory gate in CI

No `dependabot.yml`; no workflow runs `cargo audit`/`cargo deny`, npm audit, or Gradle dependency-check (CodeQL default setup does static analysis, not Rust dependency advisories). For a secrets manager with a committed exact `Cargo.lock` (transitives never bump without a human), an advisory against a crypto crate would currently be noticed only by chance.

**Fix:** add a scheduled (`cron`) `cargo audit` (or `cargo deny check advisories`) workflow with the accepted gtk3 chain in an allowlist, plus a Dependabot/`cargo update` cadence for the lockfile. Cheap — ubuntu-only, no GTK deps needed (reads the lockfile).

#### S-2 [Medium] — Third-party GitHub Actions pinned to mutable tags, not SHAs

`Swatinem/rust-cache@v2` (4 uses) and `pnpm/action-setup@v4` run in jobs that build the cryptographic core (and on `push: main`). Tags are mutable; a compromised tag executes arbitrary code in those jobs. The repo already applies exactly this reasoning to the Kotlin jars (SHA-256 verified in-script) — the discipline just wasn't extended to the actions.

**Fix:** pin all third-party `uses:` to full commit SHAs with a `# vX.Y.Z` comment; add the `github-actions` Dependabot ecosystem to keep them fresh.

#### S-3 [Low] — `sudo snap install --classic kotlin` is unpinned

The Kotlin compiler used to build the conformance harness comes from an unpinned, auto-latest snap channel — the one non-reproducible tool acquisition in CI (the jars fetched by the same script are pinned + SHA-256 verified). Conformance job only, `permissions: contents: read`.

**Fix:** `sudo snap install --classic --revision=<N> kotlin`, or install a pinned kotlinc zip with checksum verification like the jars.

#### S-4 [Low] — RustSec warnings: 18, all on two accepted transitive chains — but #218 only tracks one advisory ID

`cargo audit` reports 0 vulnerabilities and 18 warnings:

- **gtk3-rs chain (Linux-only, via Tauri):** `glib 0.18.5` unsound (RUSTSEC-2024-0429 = GHSA-wrw7-89jp-8q8g, the accepted one tracked in #218), plus 10 "unmaintained" gtk-rs crates (RUSTSEC-2024-0411…0420) and `proc-macro-error 1.0.4` (RUSTSEC-2024-0370). Same root cause and acceptance rationale as #218 (blocked until Tauri adopts gtk-rs 0.20), but **#218's text tracks only the glib advisory** — the other 11 IDs are unlisted.
- `unic-*` unmaintained (RUSTSEC-2025-0075/0080/0081/0098/0100) via `urlpattern → tauri-utils`.
- `anyhow 1.0.102` unsound (RUSTSEC-2026-0190, `downcast_mut` unsoundness) — transitive via `uniffi 0.31.1` + Tauri; no secretary crate uses `anyhow` directly.

None touch the crypto path; all are desktop-shell or bindgen tooling.

**Fix:** update #218 to enumerate the full advisory set (or add a `.cargo/audit.toml` ignore-list with rationale comments — this pairs naturally with S-1); `cargo update -p anyhow` when a fixed release lands.

#### S-5 [Info] — Crypto crate provenance

All crates.io, all mainstream. Two pre-1.0 post-quantum crates flagged for the paid external reviewer's attention (not for replacement — no better-audited Rust alternative exists, and the hybrid construction means the classical half must *also* break):

| Primitive | Crate | Version | Note |
|-----------|-------|---------|------|
| X25519 | x25519-dalek / curve25519-dalek | 2.0.1 / 4.1.3 | 4.1.3 includes the RUSTSEC-2024-0344 timing fix |
| ML-KEM-768 | ml-kem | 0.2.3 | pre-1.0, RustCrypto, not independently audited |
| Ed25519 | ed25519-dalek | 2.2.0 | weak-key era long past |
| ML-DSA-65 | ml-dsa | 0.1.0-rc.8 | release-candidate, pre-1.0, unaudited |
| Argon2id | argon2 | 0.5.3 | RustCrypto |
| AEAD | chacha20poly1305 | 0.10.1 | RustCrypto |
| HKDF/hash | hkdf 0.12 / sha2 0.10 / sha3 0.10 / blake3 1.8 | RustCrypto / official |
| BIP-39 | bip39 | 2.2.2 | rust-bitcoin |
| CT compare | subtle | 2.6.1 | dalek |

#### S-6 [Info] — Pinning-policy nuance: crypto primitives are caret-ranged, not exact-pinned

`argon2`/`chacha20poly1305`/`hkdf`/`sha2`/`sha3`/`blake3`/`subtle`/`x25519-dalek`/`ed25519-dalek`/`ml-kem` are caret ranges. Mitigated by the committed lockfile and the CLAUDE.md KAT-re-run mandate, but a casual `cargo update` moves them silently, and KATs catch functional divergence, not side-channel regressions — the same argument used to justify the `tempfile`/`zeroize` exact pins. Consider extending exact pins to `subtle` and the dalek crates (constant-time-sensitive) if the policy is meant to be uniform.

#### S-7 [Info] — CLAUDE.md misstates `conformance.py` as "only the Python standard library"

CLAUDE.md's normative-spec section says the script "uses only the Python standard library," but its PEP 723 header declares `cryptography`, `pynacl`, `pqcrypto`, `argon2-cffi`, `blake3`, `cbor2` (lazy-imported). The clean-room property still holds (top-level imports are stdlib-only; no dependency on `secretary-core`), but `pqcrypto` (a small-maintainer PQClean wrapper) is on the conformance trust path and the internal contradiction will mislead a future reader/external reviewer.

**Fix:** correct the CLAUDE.md wording (the Layout section already describes it correctly).

---

## 9. Appendix — cross-cutting themes

1. **Memory-hygiene regressions on *output/intermediate* secrets.** The codebase is meticulous about zeroizing secret *inputs* but has drifted on outputs and intermediates: the `ml-kem` zeroize feature (C-1), ML-DSA/ML-KEM stack copies (C-2, C-3), the identity-bundle codec (C-4), mnemonic parse strings (C-5), PyO3 output transients (F-2), and iOS `Data`/`[UInt8]` copies (iOS-1, iOS-2). Individually Low; collectively they suggest the memory-hygiene memo's "what is not covered" carve-out should be revisited and the audit re-run against outputs specifically.

2. **Recovery-phrase word leak into logs** (C-6 / I-1) — reported by two independent auditors, traced end-to-end into mobile exception messages. Worth prioritising because mobile logs/crash reporters persist and are outside the vault's normal threat surface.

3. **Controls enforced by convention rather than by the owning layer** — the desktop write-reauth gate (D-1, accepted), the core `share_block` TOFU check living only in the bridge (V-5), and the SAF path validation being absent entirely (A-1). For a pre-release secrets manager, moving each control into the layer that owns the write is the durable fix.

4. **Crash-consistency vs. the spec's promises** (V-1, V-2): the spec documents recovery paths that the code does not yet implement, and one doc comment actively misdescribes the behavior. No confidentiality impact, but "corrupt vault" lockouts are a bad first-release experience.

5. **Documented-accepted-risks** worth an explicit pre-release sign-off: device-slot revocation is delete-only (V-F4), manifest rollback is caught only at sync time (V-3), the desktop write gate is UX-only (D-1). Each is defensible; each should be a conscious, documented decision before users rely on the product.
