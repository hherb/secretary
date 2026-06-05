<p align="center">
  <img src="assets/secretary_logo.png" alt="Secretary" width="180">
</p>

# Secretary

A multi-platform secrets manager for passwords, API keys, secret notes, and similar credentials, designed for personal and family use without depending on any operated service.

---

## Why Secretary

Existing password managers fall into two camps: open-source-but-self-hosted (Bitwarden / Vaultwarden, KeePass), or polished-but-vendor-controlled (1Password, Dashlane, Apple Keychain). Most users need something simple to install, free of charge, with no ongoing service dependency, that supports family sharing including the inheritance case where children retain access to a deceased parent's credentials decades later.

That last requirement is the hard one. A vault that protects a credential for thirty or fifty years must defend against attacks that don't yet exist — most prominently, attacks by future quantum computers against the asymmetric primitives that protect data shared between users. Secretary therefore uses *post-quantum hybrid cryptography* from v1: every recipient-to-recipient key wrap and every signature combines a classical primitive with a NIST-standardized post-quantum primitive, so an attacker must break both to recover plaintext.

## Scope

Secretary is a client-only system. There is no server, no managed service, no hosted backend. Sync between devices uses any folder the user already has — iCloud Drive, Google Drive, Dropbox, OneDrive, a WebDAV mount on a home NAS, or a USB stick. Sharing between users uses any folder both parties can access.

**Target platforms (planned):**
- Desktop: macOS, Linux, Windows — Tauri 2 (Rust backend + Svelte/TypeScript frontend)
- Mobile: iOS, Android — same Tauri 2 codebase via Tauri 2 mobile support
- Browser autofill extensions: future

**Target users:**
- Individuals managing their own credentials
- Families sharing credentials selectively, including across generations (inheritance)
- Small teams, eventually

**Not in scope:**
- Server-mediated sync, real-time push notifications, server-side enforcement of policies
- Anonymity / metadata privacy from the user's chosen cloud-folder host
- Defense against compromise of the OS, hardware, or trusted computing base
- Coercion resistance / plausible deniability (may be added in a future format version)

## Architecture

```
                    ┌──────────────────────────────────────┐
                    │         secretary-core (Rust)        │
                    │                                      │
                    │   • Cryptographic primitives         │
                    │   • Vault format read/write          │
                    │   • Identity, recipients, sharing    │
                    │   • Conflict resolution (CRDT)       │
                    │   • Memory hygiene (zeroize, secret) │
                    └──────────────┬───────────────────────┘
                                   │
                  ┌────────────────┼────────────────────┐
                  │                │                    │
            direct crate dep  PyO3 bindings    uniffi (Swift / Kotlin)
                  │                │                    │
                  ▼                ▼                    ▼
        ┌─────────────────┐  ┌──────────────┐  ┌─────────────────────┐
        │ Tauri 2 client  │  │ Python       │  │ Third-party Swift / │
        │ (Rust backend + │  │ (scripts,    │  │ Kotlin consumers    │
        │ Svelte / TS UI) │  │ automation,  │  │ (Apple Shortcuts,   │
        │                 │  │ analysis)    │  │ Android AutoFill)   │
        │ macOS, Linux,   │  │              │  │                     │
        │ Windows, iOS,   │  │ Sub-project  │  │ Sub-project B-uniffi│
        │ Android         │  │ B            │  │                     │
        └─────────────────┘  └──────────────┘  └─────────────────────┘
```

The Rust core is the single source of truth for everything security-relevant — cryptography, vault parsing, key handling, conflict resolution. The primary UI is a single Tauri 2 codebase (Rust backend + Svelte/TypeScript frontend) targeting all five platforms from one source tree; secrets never leave Rust's deterministic-zeroize address space, and there is no localhost HTTP server (Tauri IPC is in-process via a custom URL scheme). The Python and uniffi-Swift/Kotlin bindings remain in the project as third-party-consumer paths (scripts, Apple Shortcuts integration, Android AutoFill Service) but are no longer the UI path.

**Why this architecture:** see [docs/adr/0001-rust-core.md](docs/adr/0001-rust-core.md) for the original Rust-core decision, and [docs/adr/0007-d-row-tauri.md](docs/adr/0007-d-row-tauri.md) for the 2026-05 pivot of the UI layer from per-platform native (NiceGUI + SwiftUI + Compose) to a single Tauri 2 codebase. The Rust-core layer mirrors the architecture used by Bitwarden, 1Password, Signal, and Mullvad — well-trodden territory.

## Cryptographic design at a glance

| Role | Primitive |
|---|---|
| Password KDF | Argon2id (m=256 MiB, t=3, p=1) |
| Symmetric AEAD | XChaCha20-Poly1305 (24-byte nonces, 256-bit keys) |
| KEM (recipient wraps) | X25519 ⊕ ML-KEM-768 hybrid |
| Signatures | Ed25519 ∧ ML-DSA-65 hybrid (both must verify) |
| Hash | BLAKE3 (general); SHA-256 (HKDF) |
| Recovery mnemonic | BIP-39, 24 words (256 bits) |

All hybrid constructions are designed so that an attacker must break *both* halves to compromise security. ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204) are the NIST-standardized post-quantum primitives at security level 3.

For the full cryptographic specification — sufficient detail to implement an interoperable client from scratch — see [docs/crypto-design.md](docs/crypto-design.md). For the on-disk byte format, see [docs/vault-format.md](docs/vault-format.md). For threats addressed and explicitly not addressed, see [docs/threat-model.md](docs/threat-model.md).

## Vault structure (summary)

A vault is a directory of files:

```
<vault-folder>/
  vault.toml                # cleartext metadata (no secrets)
  identity.bundle.enc       # dual-wrapped identity (master KEK + recovery KEK)
  manifest.cbor.enc         # encrypted, signed top-level index
  contacts/                 # imported public contact cards
  blocks/                   # one file per block (encryption + sharing unit)
  trash/                    # tombstoned blocks awaiting purge
```

A *block* is the unit of both encryption and sharing. A block contains 1 or more records (login, secure note, API key, SSH key, custom). Sharing a block means copying its file into a folder the recipient can access, with the recipient's per-recipient key-wrap added to the file's recipient table.

## Documentation

**Normative specifications** — the source of truth. A clean-room implementation in any language can be built from these alone, without reading the Rust source. This is verified during implementation by a Python conformance script that decrypts a published reference vault using only the spec.

| File | Purpose |
|---|---|
| [docs/glossary.md](docs/glossary.md) | Definitions of all terms used in the specs |
| [docs/threat-model.md](docs/threat-model.md) | Adversaries, attacks, defenses, explicit non-goals |
| [docs/crypto-design.md](docs/crypto-design.md) | Cryptographic constructions in spec-level detail |
| [docs/vault-format.md](docs/vault-format.md) | Byte-level on-disk format (v1) |
| [docs/adr/](docs/adr/) | Architecture decision records — six in total |

**User and contributor manual** — informal companions to the specs.

| File | Purpose |
|---|---|
| [docs/manual/primer/cryptography/](docs/manual/primer/cryptography/index.md) | A thirteen-chapter cryptography primer in plain language for curious users — what symmetric vs. asymmetric encryption is, why post-quantum hybrids matter, and how Secretary uses each idea. No prior background assumed. |
| [docs/manual/hardening-security.md](docs/manual/hardening-security.md) | User-facing guidance for pushing operational security beyond the (already strong) defaults. |
| [docs/manual/contributors/differential-replay-protocol.md](docs/manual/contributors/differential-replay-protocol.md) | The cross-language differential-replay contract used by `core/tests/python/conformance.py --diff-replay` and the fuzz harness. |

## Testing and hardening

### Fuzzing

A coverage-guided fuzz harness for the wire-format decoders lives in
[`core/fuzz/`](core/fuzz/README.md). It uses `cargo-fuzz` on a
path-scoped nightly toolchain and ships with a single-file NiceGUI
dashboard (`core/fuzz/monitor.py`) for running and watching
campaigns. Cross-language differential replay through the Python
conformance script (`conformance.py --diff-replay`) is documented in
[docs/manual/contributors/differential-replay-protocol.md](docs/manual/contributors/differential-replay-protocol.md).
See the [`core/fuzz/README.md`](core/fuzz/README.md) for how to run
it and how to promote findings into durable regression KATs.
Promoted regression inputs live under
[`core/tests/data/fuzz_regressions/`](core/tests/data/fuzz_regressions/)
and replay through
[`core/tests/fuzz_regressions.rs`](core/tests/fuzz_regressions.rs)
under the "must not panic" contract.

## License

AGPL 3.0. A commercial license is available for entities wanting to ship closed-source derivatives. See [LICENSE](LICENSE).

The user-facing application and the source code are *both* free of charge. Only commercial closed-source derivatives require a paid license.

## Project status

Repository initialized April 2026. Sub-project A — the cryptographic foundation, vault format spec, and Rust core — is in active implementation:

| Component | Status |
|---|---|
| Cryptographic design + on-disk format spec (frozen for v1) | ✅ Complete |
| Cryptographic primitives (AEAD, KDF, KEM, sig, hash, identity) | ✅ Complete, NIST KAT-pinned |
| Vault unlock (BIP-39, identity bundle, vault.toml, recovery key) | ✅ Complete (PR #1) |
| Block file format (record CBOR, header, recipients, AEAD, hybrid sig) | ✅ Complete (PR #3) |
| Manifest layer + atomic writes + high-level orchestrators | ✅ Complete (PR #5) |
| `golden_vault_001/` end-to-end §15 conformance fixture (full crypto) | ✅ Complete (PR #5) |
| CRDT merge primitives (`conflict.rs`: `merge_record`, `merge_block`, `clock_relation`, `merge_vector_clocks`) + record-level `tombstoned_at_ms` death-clock for full-domain associativity + commutativity / associativity / idempotence proptests | ✅ Complete (PR-C) |
| CRDT polish: bidirectional defensive death-clock clamp + tag-canonicalisation on LWW-clone path + clean-room Python `py_merge_unknown_map` for record-level `unknown` + 11-vector `conflict_kat.json` cross-language replay + well-formedness Property L proptest | ✅ Complete (PR #9) |
| Coverage-guided fuzz harness (`cargo-fuzz` over six wire-format decoders, NiceGUI dashboard, cross-language differential-replay protocol) | ✅ Complete (PR #8); first artifacts triaged + `display_name` DoS-bound (PR #11); live monitor telemetry (PR #12) |
| Cryptography primer for users / contributors (13 chapters) | ✅ Complete (PR #10) |
| Hardening: side-channel review, memory hygiene audit, threat-model & format-spec doc pass | 🚧 Phase A.7, in progress |
| External cryptographic audit | 🚧 Phase A.7 |
| FFI bindings (PyO3 boilerplate) | ✅ Sub-project B.1 (Python; round-trip pipeline proven, no vault crypto exposed yet) |
| FFI bindings (uniffi for Swift + Kotlin) | ✅ Sub-project B.1.1 (macOS-host Swift smoke runner) and B.1.1.1 (JVM-host Kotlin smoke runner with pinned + SHA-256-verified JNA fetch) |
| FFI bindings (vault unlock — password path) | ✅ Sub-project B.2 (`open_with_password` through PyO3 + uniffi via shared `secretary-ffi-bridge` crate; explicit close + RAII lifecycle) |
| FFI bindings (vault unlock — recovery-phrase path) | ✅ Sub-project B.3a (`open_with_recovery` through the same bridge; thinned 5-variant error type with §13 anti-oracle conflation preserved on both paths; UTF-8-validation seam; mnemonic input as caller-zeroizable bytes) |
| FFI bindings (vault creation + output-direction mnemonic) | ✅ Sub-project B.3b (`create_vault` through PyO3 + uniffi via shared `secretary-ffi-bridge` crate; four-field `CreateVaultOutput` with one-shot `MnemonicOutput` for the recovery phrase; `OsRng` + `Argon2idParams::V1_DEFAULT` instantiated bridge-side; path-neutral `CorruptVault` Display) |
| FFI bindings (folder-based vault open — password + recovery paths) | ✅ Sub-project B.4a (`open_vault_with_password` + `open_vault_with_recovery` through PyO3 + uniffi via shared `secretary-ffi-bridge`; folder-IO model established; 6-variant `FfiVaultError`; `OpenVaultManifest` opaque handle with `BlockSummary` read-only block list) |
| FFI bindings (block read) | ✅ Sub-project B.4b (`read_block` through PyO3 + uniffi via shared `secretary-ffi-bridge`; first mutation-free block-access path; hybrid Record projection with 3 new opaque handles `BlockReadOutput` / `Record` / `FieldHandle`; explicit `expose_text()` / `expose_bytes()` boundary for secret payload; 7-variant `FfiVaultError` adding `BlockNotFound`; bridge-internal `vault_folder` extension; v1 single-author only) |
| FFI bindings (block save) | ✅ Sub-project B.4c (`save_block` through PyO3 + uniffi via shared `secretary-ffi-bridge`; first mutation path with atomic write ordering per §9; 9-variant `FfiVaultError` adding `SaveCryptoFailure`; foreign-side input shape `BlockInput` / `RecordInput` / `FieldInput` / `FieldInputValue` carrying secrets through zeroize-on-drop `SecretString` / `SecretBytes`; failure invariant: bridge in-memory state byte-identical to pre-call on Err; v1 single-author only) |
| FFI bindings (block share) | ✅ Sub-project B.4d (`share_block` through PyO3 + uniffi via the same shared bridge; first FFI call where `ContactCard` values cross the boundary as canonical-CBOR bytes-in via the new `OpenVaultManifest::owner_card_bytes()` accessor; 13-variant `FfiVaultError` adding 4 typed share variants — `NotAuthor` / `RecipientAlreadyPresent` / `MissingRecipientCard` / `CardDecodeFailure`; mirrors core's single-recipient-append signature so atomicity is per-call; v1 single-author only — share-as-fork future PR) |
| FFI bindings (block trash + restore lifecycle pair) | ✅ Sub-project B.5 (`trash_block` + `restore_block` through PyO3 + uniffi via the same shared bridge; 15-variant `FfiVaultError` adding 2 typed restore-side variants — `BlockUuidAlreadyLive` / `BlockNotInTrash`; `RestoreVerificationFailed` folds to `CorruptVault` per the "data on disk doesn't match what we signed" contract; restore reads the largest-timestamp file in `trash/`, full-decrypts + hybrid-verifies (defense in depth) before any manifest mutation, resolves `recipient_fingerprint` → `contact_uuid` by scanning `contacts/*.card`, then renames `trash/` → `blocks/` and purges older copies best-effort; the per-block vector clock is preserved verbatim from the file header for sync correctness; new `docs/vault-format.md` §7.1 normative sequence; v1 owner-as-author only) |
| Sync orchestration (file watching, cloud-folder integration, conflict-detection scheduling — headless, exposed via FFI) | ✅ Sub-project C through C.2: pure-Rust sync state machine (C.1 / C.1.1a / C.1.1b — `sync_once → prepare_merge → commit_with_decisions` over an authenticated `VaultBundle` of sibling conflict-copies, block-first / manifest-last atomic writes with idempotent crash recovery) plus the headless `secretary-sync` CLI (C.2 — `once` and `run` subcommands, `notify`-driven daemon loop with trailing-edge debounce, partial-download size-stability gate, host-local lockfile, two-instance convergence test). Mobile sync adapters (C.3) and cross-device convergence conformance (C.4) ⏳ next. |
| Platform UIs (Tauri-based universal client — Svelte/TypeScript frontend + Rust backend, targeting macOS / Linux / Windows desktop and iOS / Android mobile from one codebase) | 🚧 Sub-project D — pivoted from NiceGUI + SwiftUI + Compose to Tauri 2 in 2026-05 ([ADR 0007](docs/adr/0007-d-row-tauri.md)). D.1.1 walking skeleton (unlock + block-list scaffold + vault-stored auto-lock settings + auto-lock timeout + lock button), D.1.2 (read-only browse — block detail → record list → field viewer with per-field reveal/mask, auto-hide, and copy-with-auto-clear), D.1.3 (vault create wizard — folder pick + probe, credentials, mnemonic backup, Unlock pre-fill + "create a vault here" affordance), D.1.4 (vault edit — add/edit records: native-BlockPlaintext bridge primitives, unknown-preserving lossless write path, IPC commands, record editor UI) shipped 2026-05-30, **D.1.5 (delete/trash — record tombstone/resurrect over the lossless write path, a Rust-gated "show deleted" toggle, whole-block trash/restore, and a Trash view that lists trashed blocks by name) shipped 2026-05-31**, **D.1.6 (share a block — import a peer's contact card, pick it in a share dialog, and append it as a recipient; a bridge-thick contacts subsystem owns all `contacts/` I/O with parse-then-`verify_self` TOFU import and gatekeeper DTOs that keep card bytes/keys server-side) shipped 2026-05-31**, and **D.1.7 (contacts management — export-my-card to a chosen folder + a standalone Contacts pane that lists imported contacts with per-contact recipient counts and a warn-but-allow delete that makes "delete ≠ revoke" explicit) shipped 2026-06-03**, and **D.1.8 (per-block recipients — a read-only "Shared with" banner in the records view listing who a block is shared with: each recipient uuid resolved to a name with the owner shown as "You", and a deleted contact's still-shared block rendered as "Unknown contact (uuid…)" so the residual keyholder stays visible) shipped 2026-06-04**, and **D.1.9 (per-contact reverse map — expand a contact in the Contacts pane to list the blocks they receive and click one to open it; a read-only `contact_blocks` bridge primitive inverts the `shared_block_count` scan, behind a `list_contact_blocks` IPC command and an inline lazily-fetched ContactRow expansion; no core / FfiVaultError / binding change) shipped 2026-06-04**, and **D.1.10 (revoke primitive — the frozen-`core` `revoke_block_recipient` that [#177](https://github.com/hherb/secretary/issues/177) was waiting on: re-keys a block under a fresh content key, re-wraps for the *remaining* recipients only, drops the revoked uuid from the manifest, re-signs Ed25519 ∧ ML-DSA-65 and atomic-writes block-then-manifest; extracts a shared `rewrite_block_with_recipients` engine from `share_block`; a fail-fast `CannotRevokeOwner` guard — the owner is always a recipient and revoking it would brick the block; a bridge `revoke_block_from`; two new typed errors threaded through every binding + the Swift/Kotlin/pyo3 conformance harnesses; `vault-format` §6.5.1 + `crypto-design` §7.3 + a clean-room revoke KAT in `conformance.py`; revocation is forward-only by design) shipped 2026-06-05**, and **D.1.11 (desktop revoke UI — an always-visible "Revoke" ✕ on both share surfaces: the per-block "Shared with" banner (every non-owner recipient row) and the per-contact reverse map (each block a contact receives), gated behind a confirm dialog whose copy states the forward-secrecy boundary explicitly (the former recipient keeps anything they already saw); a `revoke_block_from` IPC command wraps the D.1.10 bridge primitive, the mutation path surfaces typed errors with no read-path leniency, the owner is never offered a control, and a successful revoke refreshes the banner / the contact's shared-block count) shipped 2026-06-05**, and **D.1.12 (desktop polish batch — a vendored inline-SVG icon system replacing every color-emoji icon with eight `currentColor` Lucide components that render identically light/dark and on bare-Linux installs with no runtime dependency, `aria-controls` paired with `aria-expanded` on both disclosure toggles, an `Esc`-pops-a-browse-level affordance behind a pure `shouldPopOnEscape` guard that no-ops at the root / form levels / with a dialog open / in a focused form control, and the duplicated `lock_session` session-lock helper hoisted into `commands::shared` and adopted across all eight command modules; no `core` / `ffi` / bridge change) shipped 2026-06-05**. The L4 end-to-end test is manual-only (not in CI) and deferred ([#161](https://github.com/hherb/secretary/issues/161)). `secretary-ffi-py` and `secretary-ffi-uniffi` remain as third-party-consumer paths (scripts, Shortcuts, AutoFill) — no longer the UI path. |

A clean-room implementation in any language can be built from `docs/` alone. This is verified by [core/tests/python/conformance.py](core/tests/python/conformance.py) — a stdlib-only `uv run`-compatible Python script that performs (1) full hybrid-decap + AEAD-decrypt + hybrid-verify against the `golden_vault_001/` reference vault using only the spec, (2) a cross-language replay of eleven `conflict_kat.json` merge vectors covering each `ClockRelation` branch, the `tombstoned_at_ms` death-clock semantics, the §11.3 identity-metadata override, and record-level `unknown`-map collisions; (3) a case-insensitivity self-test guarding hex-comparison drift in `py_merge_unknown_map`; and (4) a `--diff-replay` mode used by the fuzz harness for cross-language decoder agreement. All halves run from spec docs alone, with no dependencies on the Rust source.

The project is intentionally being built slowly and carefully. Cryptographic systems that handle multi-decade-lifetime secrets are not the right place to optimize for time-to-MVP. See [ROADMAP.md](ROADMAP.md) for the phased plan.

## Contact

This is a personal project by [Horst Herb](https://github.com/hherb). Issues and pull requests on this repository are welcome once the foundation is in place — see the project status above.
