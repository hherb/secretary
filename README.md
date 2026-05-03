<p align="center">
  <img src="assets/secretary_logo.png" alt="Secretary" width="180">
</p>

# Secretary

A multi-platform secrets manager for passwords, API keys, secret notes, and similar credentials, designed for personal and family use without depending on any operated service.

> **Status: pre-alpha, Sub-project A is feature-complete for v1; Phase A.7 hardening + external audit in progress.** Architecture and cryptographic design are complete and frozen for v1. The Rust core covers cryptographic primitives, identity, vault unlock, the block file format, the manifest layer with atomic I/O, the high-level orchestrators (`create_vault`, `open_vault`, `save_block`, `share_block`), and the vector-clock CRDT merge primitives (`merge_record` and `merge_block` with a record-level death-clock that makes the merge associative across arbitrary tombstone histories, plus PR #9's bidirectional defensive clamp, tag canonicalisation, and clean-room Python `py_merge_unknown_map` for record-level `unknown` cross-language). 430+ tests pass, including NIST KATs, four property-based CRDT proofs (commutativity, associativity, idempotence, well-formedness under arbitrary inputs) on the full record domain at proptest defaults, and a stdlib-only Python conformance script that does full hybrid-decap + AEAD-decrypt + hybrid-verify against the `golden_vault_001` fixture and replays eleven merge KATs cross-language. Phase A.7 is underway: a coverage-guided `cargo-fuzz` harness over all six wire-format decoders landed in PR #8, its first batch of artifacts was triaged and closed in PR #11 (libfuzzer false positives promoted as regression tests under [`core/tests/data/fuzz_regressions/`](core/tests/data/fuzz_regressions/) plus a real peer-supplied DoS-bound on the contact-card `display_name` field, capped symmetrically on encode and decode), and PR #12 surfaced live telemetry on the NiceGUI monitor (status badge per Status, `cov / ft / corp / exec-s / rss` per card, elapsed timer + runs/cap progress, global findings tally). PR #10 added a thirteen-chapter [cryptography primer](docs/manual/primer/cryptography/index.md) for users and contributors. What remains in Sub-project A is independent cryptographic review and the side-channel / memory-hygiene audits; FFI bindings (Sub-project B), the headless sync-orchestration layer (Sub-project C), and platform UIs (Sub-project D) come after that. There is no usable application yet. See [docs/](docs/) for the design and [ROADMAP.md](ROADMAP.md) for the phase plan.

---

## Why Secretary

Existing password managers fall into two camps: open-source-but-self-hosted (Bitwarden / Vaultwarden, KeePass), or polished-but-vendor-controlled (1Password, Dashlane, Apple Keychain). Most users need something simple to install, free of charge, with no ongoing service dependency, that supports family sharing including the inheritance case where children retain access to a deceased parent's credentials decades later.

That last requirement is the hard one. A vault that protects a credential for thirty or fifty years must defend against attacks that don't yet exist — most prominently, attacks by future quantum computers against the asymmetric primitives that protect data shared between users. Secretary therefore uses *post-quantum hybrid cryptography* from v1: every recipient-to-recipient key wrap and every signature combines a classical primitive with a NIST-standardized post-quantum primitive, so an attacker must break both to recover plaintext.

## Scope

Secretary is a client-only system. There is no server, no managed service, no hosted backend. Sync between devices uses any folder the user already has — iCloud Drive, Google Drive, Dropbox, OneDrive, a WebDAV mount on a home NAS, or a USB stick. Sharing between users uses any folder both parties can access.

**Target platforms (planned):**
- Desktop: macOS, Windows, Linux (Python with NiceGUI)
- Web: served by the same Python codebase (NiceGUI runs in a browser)
- iOS: native Swift / SwiftUI
- Android: native Kotlin / Jetpack Compose
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
                ┌──────────────────┼──────────────────┐
                │                  │                  │
            PyO3 bindings     uniffi (Swift)    uniffi (Kotlin)
                │                  │                  │
                ▼                  ▼                  ▼
        ┌───────────────┐  ┌──────────────┐  ┌─────────────────┐
        │ Python +      │  │ Swift +      │  │ Kotlin +        │
        │ NiceGUI       │  │ SwiftUI      │  │ Jetpack Compose │
        │               │  │              │  │                 │
        │ Desktop + Web │  │ iOS          │  │ Android         │
        └───────────────┘  └──────────────┘  └─────────────────┘
```

The Rust core is the single source of truth for everything security-relevant — cryptography, vault parsing, key handling, conflict resolution. Each platform has its own native UI written in the language and idiom of that platform; UI is not shared across platforms (different platforms have different conventions, and Rust's GUI ecosystem is not yet mature enough to be the unifier).

**Why this architecture:** see [docs/adr/0001-rust-core.md](docs/adr/0001-rust-core.md). It mirrors the architecture used by Bitwarden, 1Password, Signal, and Mullvad — well-trodden territory.

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
| FFI bindings (vault crypto exposed) | ⏳ Sub-project B.2+ |
| Sync orchestration (file watching, cloud-folder integration, conflict-detection scheduling — headless, exposed via FFI) | ⏳ Sub-project C |
| Platform UIs (NiceGUI desktop/web, SwiftUI iOS, Compose Android) | ⏳ Sub-project D |

451 tests pass + 6 ignored under `cargo test --release --workspace` (448 pre-B.1.1 + 3 from the uniffi unit tests; B.1.1.1's contribution is JVM-side — three Kotlin assertions in `tests/kotlin/Main.kt` running through the cdylib + JNA bridge — and adds no new Rust tests); clippy clean with `-D warnings`; `#![forbid(unsafe_code)]` crate-wide for `core/`. Both FFI crates carry a localized `unsafe_code = "deny"` carve-out — `secretary-ffi-py/` for PyO3 macro expansions and `secretary-ffi-uniffi/` for `uniffi::include_scaffolding!()`'s `unsafe extern "C"` blocks — per the "FFI as isolated reviewed boundary" principle (`forbid` is non-overridable by inner `#[allow]`, so each crate downgrades to `deny` and carries a single crate-level `#![allow]` with rationale). The repository tracks every cryptographic decision in `docs/adr/` and pins every primitive against published KATs (NIST FIPS 203 / FIPS 204, RFC 8032 / 7748, RFC 5869, RFC 9106, BIP-39 Trezor canonical vectors). The CRDT merge layer is additionally proven commutative, associative, idempotent, and well-formed over the full record domain — including arbitrary tombstone-and-resurrection histories and arbitrary record-level `unknown` keys — by four `proptest` properties at default (~256 cases each) under `core/tests/proptest.rs`'s PR-C / PR #9 section.

A clean-room implementation in any language can be built from `docs/` alone. This is verified by [core/tests/python/conformance.py](core/tests/python/conformance.py) — a stdlib-only `uv run`-compatible Python script that performs (1) full hybrid-decap + AEAD-decrypt + hybrid-verify against the `golden_vault_001/` reference vault using only the spec, (2) a cross-language replay of eleven `conflict_kat.json` merge vectors covering each `ClockRelation` branch, the `tombstoned_at_ms` death-clock semantics, the §11.3 identity-metadata override, and record-level `unknown`-map collisions; (3) a case-insensitivity self-test guarding hex-comparison drift in `py_merge_unknown_map`; and (4) a `--diff-replay` mode used by the fuzz harness for cross-language decoder agreement. All halves run from spec docs alone, with no dependencies on the Rust source.

The project is intentionally being built slowly and carefully. Cryptographic systems that handle multi-decade-lifetime secrets are not the right place to optimize for time-to-MVP. See [ROADMAP.md](ROADMAP.md) for the phased plan.

## Contact

This is a personal project by [Horst Herb](https://github.com/hherb). Issues and pull requests on this repository are welcome once the foundation is in place — see the project status above.
