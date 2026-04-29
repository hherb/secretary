# Secretary — Roadmap

This roadmap shows where Secretary is today and what comes next. It is meant for potential contributors deciding whether and where to help, and for users trying to gauge when the project will be usable.

The project is structured as three sequential sub-projects. Each sub-project is a coherent unit of work that can be reviewed end-to-end before the next begins. **Sub-project A** is the Rust cryptographic core and on-disk format. **Sub-project B** is the FFI binding layer (PyO3 + uniffi). **Sub-project C** is the platform UIs.

This ordering is deliberate. The cryptographic core is the only piece where mistakes are hard to walk back — once a vault format is in the wild and people have stored multi-decade secrets in it, you cannot fix a flaw without a forced migration. So the core ships first, with rigour, and only then do the bindings and UIs go on top.

For the full design specifications see [docs/](docs/). For the next-session entry point with concrete TODOs see [secretary_next_session.md](secretary_next_session.md).

---

## Where we are: 2026-04-29

Sub-project A is feature-complete for v1. The manifest layer, atomic I/O, the four high-level orchestrators (`create_vault`, `open_vault`, `save_block`, `share_block`), and the `golden_vault_001/` end-to-end §15 fixture all landed in PR #5. PR #6 cleaned up follow-ups from review (orchestrator-module split, exact-pin of `tempfile` as a security-critical dependency, plus a regression test for an ML-DSA silent-accept bug surfaced in the Python conformance script). What remains for Sub-project A is hardening — fuzz harness, side-channel review, memory-hygiene audit — and an independent external cryptographic audit.

```
[==============================================================  ] Sub-project A — Rust core
[                                                                ] Sub-project B — FFI bindings
[                                                                ] Sub-project C — Platform UIs
```

340+ tests pass. Clippy is clean with `-D warnings`. `#![forbid(unsafe_code)]` is crate-wide. Every cryptographic primitive is pinned against published KATs, and the `golden_vault_001/` fixture is verified end-to-end by both the Rust suite and the stdlib-only Python conformance script.

---

## Sub-project A — Rust cryptographic core

The core lives in [core/](core/) (crate name `secretary-core`). It is the single source of truth for everything security-relevant: cryptographic primitives, identity, vault format read/write, recipient handling, conflict resolution.

### Phase A.1 — Cryptographic primitives ✅ (complete)

NIST KAT-pinned implementations of the v1 cipher suite:

| Primitive | Crate | KAT source |
|---|---|---|
| Argon2id (m=256 MiB, t=3, p=1) | `argon2` | RFC 9106 |
| XChaCha20-Poly1305 | `chacha20poly1305` | libsodium reference |
| HKDF-SHA-256 | `hkdf` + `sha2` | RFC 5869 |
| BLAKE3 | `blake3` | upstream test vectors |
| Ed25519 | `ed25519-dalek` | RFC 8032 |
| X25519 | `x25519-dalek` | RFC 7748 |
| ML-KEM-768 | `ml-kem` | NIST FIPS 203 |
| ML-DSA-65 | `ml-dsa` | NIST FIPS 204 (keygen + sigGen + sigVer) |

Hybrid constructions are implemented and KAT-pinned: X25519 ⊕ ML-KEM-768 KEM, Ed25519 ∧ ML-DSA-65 signatures (both must verify). All vectors live in [core/tests/data/*.json](core/tests/data/) and are loaded by a shared [core/tests/kat_loader.rs](core/tests/kat_loader.rs).

### Phase A.2 — Identity ✅ (complete)

`secretary_core::identity`: identity seed, key derivation per role (auth, KEM, recovery), Contact Cards, recipient fingerprints. Position-specific signature roles (`SigRole::Block`, `SigRole::Manifest`, etc.) so a signature for one purpose cannot be replayed in another.

### Phase A.3 — Unlock module ✅ (complete, PR #1)

`secretary_core::unlock`: BIP-39 24-word mnemonic generate/parse, identity bundle (master KEK + recovery KEK dual wrap), `vault.toml` cleartext metadata, three orchestrators (`create_vault`, `open_with_password`, `open_with_recovery`). Argon2id v1 floor enforced as a typed error.

### Phase A.4 — Vault block format ✅ (complete, PR #3, PR-A)

`secretary_core::vault::{record, block}`:

- `Record` types (login, secure note, API key, SSH key, custom) with canonical CBOR encode/decode (RFC 8949 §4.2.1) and a forward-compat `UnknownValue` opaque wrapper preserving bit-identical round-trips at record + field level.
- Binary block file: header (§6.1, 58 B prefix + vector clock), recipient table (§6.2, 1208 B/entry, sorted by fingerprint), AEAD body under per-block content key (§6.3), trailing hybrid signature suffix (§8).
- `encrypt_block` / `decrypt_block` orchestrators as free `fn`s. Verify-before-decap structurally enforced: a forged file never triggers a private-key operation.
- §15 cross-language conformance: [core/tests/data/block_kat.json](core/tests/data/block_kat.json) parsed wire-format-only by [core/tests/python/conformance.py](core/tests/python/conformance.py) (stdlib-only, `uv run`-compatible).

### Phase A.5 — Vault manifest layer + orchestrators ✅ (complete, PR #5, PR #6)

`secretary_core::vault::{manifest, io, orchestrators, canonical}`:

- **Manifest format** (`docs/vault-format.md` §4): [core/src/vault/manifest.rs](core/src/vault/manifest.rs) — `manifest.cbor.enc` top-level index, recipient table at the manifest level, vector clocks for CRDT merge, canonical CBOR with `UnknownValue` opaque round-tripping.
- **Atomic writes**: [core/src/vault/io.rs](core/src/vault/io.rs) — write-temp + fsync + rename + parent-dir fsync, per ADR-0003. `tempfile` exact-pinned (`=3.27.0`) as a security-critical path dependency.
- **Vector-clock invariants**: tick-on-overflow rejected as a typed error rather than saturating; proptests for vector-clock merge and associativity.
- **High-level orchestrators**: [core/src/vault/orchestrators.rs](core/src/vault/orchestrators.rs) — `create_vault` (atomic four-file initial layout), `open_vault` (verify-then-decrypt with `vault_uuid` and `kdf_params` cross-checks per §4.3), `save_block` (atomic write ordering per §9), `share_block` (author-only re-sign with author-equals-identity precondition; share-as-fork TODO markers pinned for the v2 follow-up).
- **§15 closure**: [core/tests/data/golden_vault_001/](core/tests/data/golden_vault_001/) — deterministic end-to-end fixture (`vault.toml`, `manifest.cbor.enc`, `identity.bundle.enc`, one block, one Contact Card) verified end-to-end by [core/tests/python/conformance.py](core/tests/python/conformance.py) (full hybrid-decap + AEAD-decrypt + hybrid-verify, stdlib-only, `uv run`-compatible). A regression test pins the silent-accept bug found and fixed in the Python ML-DSA-65 verifier during this phase.
- **Shared canonical-CBOR helpers**: [core/src/vault/canonical.rs](core/src/vault/canonical.rs) — `canonical_sort_entries`, `encode_canonical_map`, the float/tag walker, extracted before the third copy could land.

### Phase A.6 — Hardening + audit prep 🚧 (next)

- Independent cryptographic review (paid, external).
- Fuzz harness for the wire-format decoders (`cargo fuzz`).
- Side-channel review (constant-time critical paths).
- Memory hygiene audit (`zeroize`, `secrecy` typestate, drop ordering).
- Documentation pass: `docs/threat-model.md` updated to reference the as-implemented surface; `docs/vault-format.md` clarifications surfaced during implementation.

End of Sub-project A: Rust core is feature-complete for v1, audited, and ready to be wrapped by FFI.

---

## Sub-project B — FFI bindings ⏳ (planned)

The Rust core is exposed to platform languages via two binding paths:

- **PyO3** ([ffi/python](ffi/) — to be created): Python bindings for the desktop / web client. Async-aware where the underlying API is.
- **uniffi**: Swift bindings for iOS, Kotlin bindings for Android — same UDL, two outputs.

Phase plan:

- **B.1** — UDL design + binding boilerplate, hello-world round-trip on each platform.
- **B.2** — Vault unlock + open exposed across all three languages.
- **B.3** — Block save / share / open exposed.
- **B.4** — Conformance: same `golden_vault_001/` test runs in Python and Rust and Swift and Kotlin and produces bit-identical results.

Sub-project B is bounded work — there is no design ambiguity, just careful translation. It can proceed in parallel with the Sub-project A audit if reviewers find a willing volunteer.

---

## Sub-project C — Platform UIs ⏳ (planned)

The UIs are deliberately written natively per platform (see [ADR-0001](docs/adr/0001-rust-core.md)). UI is not shared across platforms — each platform's idiom matters more than code reuse on the UI tier.

Phase plan:

- **C.1 — Desktop / Web (Python + NiceGUI)**: vault create / unlock / browse / add credential / share. NiceGUI runs the same codebase as a native desktop window or as a browser app.
- **C.2 — iOS (Swift + SwiftUI)**: native app with the same feature set, plus Apple Keychain interop and AutoFill provider.
- **C.3 — Android (Kotlin + Jetpack Compose)**: native app with the same feature set, plus Android AutoFill Service.
- **C.4 — Browser autofill extensions**: future, after the platform clients stabilise.

Each platform UI is independent — they can ship in any order and at independent paces. Desktop / web is likely first because Python iteration is fastest and it doubles as the reference UI for spec-conformance testing.

---

## Out of scope for v1

These are explicit non-goals for the first release. Some may move into v2; some are permanently excluded.

- **Server-mediated sync.** No backend. Sync is via cloud folders the user already has (iCloud, Drive, Dropbox, OneDrive, WebDAV, USB stick). See [ADR-0003](docs/adr/0003-cloud-folder-sync.md).
- **Real-time push notifications.** Sync happens on next file-system event from the cloud-folder client.
- **Anonymity / metadata privacy from the cloud-folder host.** The host can see encrypted file sizes, modification times, and recipient counts (the recipient table is part of the file). Plaintext is never visible.
- **Coercion resistance / plausible deniability.** Considered for a future format version.
- **Server-side policy enforcement.** No server, so no enforcement.
- **Defence against compromise of the OS, hardware, or trusted computing base.** Standard assumption for client-side crypto.

---

## How contributors can help

The project is currently a solo effort and intentionally gated on cryptographic correctness — most work happens behind specifications and audited PRs rather than through ad-hoc contributions. That said, helpful avenues right now:

- **Review the design docs.** [docs/threat-model.md](docs/threat-model.md), [docs/crypto-design.md](docs/crypto-design.md), [docs/vault-format.md](docs/vault-format.md), and [docs/adr/](docs/adr/) are the source of truth. Ambiguities or errors there have outsized impact. Open issues against the docs.
- **Build a clean-room implementation.** Use only `docs/` and verify against [core/tests/python/conformance.py](core/tests/python/conformance.py) (full hybrid-decap + AEAD-decrypt + hybrid-verify against `golden_vault_001/`, stdlib-only). If your implementation works without reading the Rust source, the spec is doing its job. If it doesn't, please open an issue.
- **Cryptographic review.** Independent scrutiny of the hybrid constructions, KAT coverage, and AAD/signed-range definitions is welcome. Especially valuable: someone with FIPS 203 / FIPS 204 implementer experience.
- **Wait for Sub-project B / C.** If your interest is the UI layer or platform integration, those phases haven't started. Star the repo and check back.

PRs against the Rust core are accepted but the bar is high: every change must come with KAT-level tests, no `unsafe`, typed errors only, and adherence to the conventions documented in `secretary_next_session.md` and the existing source.

---

## Cadence

This is intentionally a slow project. A vault format that protects multi-decade secrets is not the right place to optimize for time-to-MVP. Releases happen when the work is right, not when a calendar says so.

Rough order-of-magnitude expectations (no commitments):

- **Sub-project A complete + audited**: months, not weeks.
- **Sub-project B (FFI)**: weeks once A is frozen.
- **Sub-project C.1 (desktop/web)**: weeks-to-months on top of B.
- **Sub-project C.2 + C.3 (iOS, Android)**: parallelisable; pace depends on contributors.
- **v1.0 release**: when all of the above ship and the spec has been stable across at least one external review cycle.

The project will not have a "1.0" tag until the cryptographic foundation has stood up to independent scrutiny and the first reference UI is real software people can use to store real secrets.
