# Secretary — Roadmap

This roadmap shows where Secretary is today and what comes next. It is meant for potential contributors deciding whether and where to help, and for users trying to gauge when the project will be usable.

The project is structured as four sequential sub-projects. Each sub-project is a coherent unit of work that can be reviewed end-to-end before the next begins. **Sub-project A** is the Rust cryptographic core and on-disk format. **Sub-project B** is the FFI binding layer (PyO3 + uniffi). **Sub-project C** is the headless sync-orchestration layer — file watching, cloud-folder integration, conflict-detection scheduling — exposed across the FFI so every UI gets the same orchestration semantics for free. **Sub-project D** is the platform UIs.

This ordering is deliberate. The cryptographic core is the only piece where mistakes are hard to walk back — once a vault format is in the wild and people have stored multi-decade secrets in it, you cannot fix a flaw without a forced migration. So the core ships first, with rigour. Sync orchestration sits between FFI and the UIs as its own phase rather than being folded into per-platform UI work, so the orchestration logic is built and tested once (with a headless `secretary sync` CLI as a reference consumer) instead of being re-invented and re-debugged across desktop, iOS, and Android.

For the full design specifications see [docs/](docs/). For the next-session entry point with concrete TODOs see [secretary_next_session.md](secretary_next_session.md).

---

## Where we are: 2026-05-26

- **Sub-project A**: feature-complete for v1. Internal hardening track (fuzzing, threat-model refresh, side-channel audit, memory-hygiene audit) ✅ closed. Only the external paid review track remains.
- **Sub-project B**: complete through B.6 v2. Bridge crate + PyO3 + uniffi (Swift, Kotlin) expose unlock / open / read / save / share / trash / restore. Cross-language conformance KAT (22 vectors, lifecycle-complete) replays Rust ↔ Swift ↔ Kotlin parity.
- **Sub-project C**: C.1 phase 1 (sync detection), C.1.1a (conflict-copy ingestion), C.1.1b (merge layer) ✅ complete. C.2 (headless `secretary-sync` CLI) is in flight — Tasks 1–9 of 10 landed (scaffold, state persistence + lockfile, password sourcing, veto UX, pipeline + lib/bin split, watcher submodule, notify driver + daemon loop, logging + signal handling, `main.rs` end-to-end + `once` integration suite).
- **Sub-project D**: not started.

```
[================================================================] Sub-project A — Rust core (feature-complete; A.7 internal track closed; external review pending)
[================================================================] Sub-project B — FFI bindings (B.1 → B.6 v2 ✅)
[=================================                               ] Sub-project C — Sync orchestration (C.1 + C.1.1a/b ✅; C.2 Tasks 1–9/10 ✅)
[                                                                ] Sub-project D — Platform UIs
```

Test totals as of B.6 v2 / C.1.1b: 800 tests pass + 10 ignored under `cargo test --release --workspace`; 68 pytest; 38 Swift / 39 Kotlin smoke asserts; 22/22 cross-language conformance vectors PASS on both Swift and Kotlin. Clippy clean with `-D warnings --tests`. `#![forbid(unsafe_code)]` workspace-wide except a localized `deny` carve-out in the two binding-flavor crates.

---

## Sub-project A — Rust cryptographic core

The core lives in [core/](core/) (crate name `secretary-core`). It is the single source of truth for everything security-relevant: cryptographic primitives, identity, vault format read/write, recipient handling, conflict resolution.

### Phase A.1 — Cryptographic primitives ✅

NIST KAT-pinned v1 cipher suite: Argon2id (RFC 9106), XChaCha20-Poly1305, HKDF-SHA-256 (RFC 5869), BLAKE3, Ed25519 (RFC 8032), X25519 (RFC 7748), ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204). Hybrid constructions (X25519 ⊕ ML-KEM-768; Ed25519 ∧ ML-DSA-65, AND not OR) KAT-pinned. Vectors in [core/tests/data/](core/tests/data/).

### Phase A.2 — Identity ✅

`secretary_core::identity`: identity seed, per-role key derivation (auth, KEM, recovery), Contact Cards, recipient fingerprints, position-specific signature roles (`SigRole::Block` ≠ `SigRole::Manifest`) so signatures cannot be cross-purpose replayed.

### Phase A.3 — Unlock module ✅

`secretary_core::unlock`: BIP-39 24-word mnemonic, identity bundle (master KEK + recovery KEK dual wrap), `vault.toml` metadata, orchestrators (`create_vault`, `open_with_password`, `open_with_recovery`). Argon2id v1 floor enforced as a typed error (`UnlockError::WeakKdfParams`).

### Phase A.4 — Vault block format ✅

`secretary_core::vault::{record, block}`: typed records with canonical CBOR (RFC 8949 §4.2.1) and a forward-compat `UnknownValue` for bit-identical round-trips; binary block file (header + recipient table + AEAD body + hybrid signature suffix); verify-before-decap structurally enforced. §15 conformance via [block_kat.json](core/tests/data/block_kat.json) replayed by the stdlib-only Python verifier.

### Phase A.5 — Vault manifest + orchestrators ✅

`secretary_core::vault::{manifest, io, orchestrators, canonical}`: manifest format per `docs/vault-format.md` §4; atomic writes via `tempfile::NamedTempFile::persist` (exact-pinned `=3.27.0` as a security-critical dep); typed vector-clock overflow; high-level orchestrators (`create_vault`, `open_vault`, `save_block`, `share_block`) with §9 atomic write ordering. §15 closure via [golden_vault_001/](core/tests/data/golden_vault_001/) end-to-end conformance.

### Phase A.6 — CRDT merge primitives ✅

`secretary_core::vault::conflict`: pure-function vector-clock primitives (`clock_relation`, `merge_vector_clocks`, `merge_record`, `merge_block`); record-level `tombstoned_at_ms` death-clock closes the three-way-merge associativity gap; §11.3 identity-metadata override on tombstone-wins; defensive bidirectional clamp of `tombstoned_at_ms` against malformed peers. Four proptests (commutativity, associativity, idempotence, well-formedness Property L) hold on the full record domain. §15 KAT: 11 vectors in [conflict_kat.json](core/tests/data/conflict_kat.json), replayed cross-language by a clean-room Python `py_merge_record` / `py_merge_unknown_map`.

### Phase A.7 — Hardening + audit prep 🚧 (internal ✅; external pending)

**Internal track (all closed 2026-05-02):**

- **Fuzz harness** ✅ — six `cargo-fuzz` targets (`vault_toml`, `record`, `contact_card`, `bundle_file`, `manifest_file`, `block_file`) under [core/fuzz/](core/fuzz/); promoted regressions replay through `cargo test`. NiceGUI dashboard with live telemetry (`core/fuzz/monitor.py`). Cross-language differential-replay protocol at [`docs/manual/contributors/differential-replay-protocol.md`](docs/manual/contributors/differential-replay-protocol.md).
- **Threat-model refresh** ✅ — `docs/threat-model.md` realigned with implementation; four divergences fixed (notably §3.5 mixed-suite-IDs); §5 verification trace grown to ~30 cited test names, all verified to exist.
- **Side-channel audit** ✅ — memo at [`docs/manual/contributors/side-channel-audit-internal.md`](docs/manual/contributors/side-channel-audit-internal.md). All CT-sensitive comparisons delegate to upstream RustCrypto; principal output is the upstream-assumption list for the paid reviewer.
- **Memory-hygiene audit** ✅ — memo at [`docs/manual/contributors/memory-hygiene-audit-internal.md`](docs/manual/contributors/memory-hygiene-audit-internal.md). Twelve stack-residue gaps closed (`var.zeroize()` after `Sensitive::new(var)` pattern); `RecordFieldValue::{Text, Bytes}` now wrap `SecretString` / `SecretBytes` (PR #16); `MlDsa65Secret` / `MlKem768Secret` newtypes derive `Zeroize, ZeroizeOnDrop`.
- **User-facing primer** (PR #10) ✅ — thirteen-chapter [cryptography primer](docs/manual/primer/cryptography/index.md) + [hardening guide](docs/manual/hardening-security.md).

**External track (pending):**

- **Independent cryptographic review** (paid). Reviewer with FIPS 203 / FIPS 204 implementer experience preferred. Handoff package: `docs/` (specs + threat-model + ADRs) + the two internal-audit memos.
- **Side-channel review** (paid). Constant-time critical paths enumerated in the side-channel memo; verify upstream-crate assumptions, especially for `ml-dsa = "0.1.0-rc.8"` (pre-1.0).

---

## Sub-project B — FFI bindings ✅ (complete through B.6 v2)

The Rust core is exposed to platform languages via two binding paths, both built on top of a shared `secretary-ffi-bridge` crate that holds the FFI-friendly facade of `secretary-core`:

- **`secretary-ffi-bridge`** ([ffi/secretary-ffi-bridge](ffi/secretary-ffi-bridge/)): the single source of FFI code truth. Pure-safe Rust — only the binding-flavor crates need the FFI-macro `unsafe_code = "deny"` carve-out.
- **PyO3** ([ffi/secretary-ffi-py](ffi/secretary-ffi-py/)): Python bindings for the desktop / web client.
- **uniffi** ([ffi/secretary-ffi-uniffi](ffi/secretary-ffi-uniffi/)): one UDL, two outputs — Swift (iOS) and Kotlin (Android). RAII lifecycle via `with` (Python), `defer { wipe() }` (Swift), `.use { }` (Kotlin via uniffi 0.31's auto-generated `AutoCloseable`).

Phase plan (all ✅):

- **B.1 / B.1.1 / B.1.1.1** — Boilerplate proof: `add` / `version` round-trip through PyO3 + maturin, then uniffi → Swift, then uniffi → Kotlin (JVM-host runner via JNA with SHA-256-pinned `jna.jar`).
- **B.2 / B.3a** — `open_with_password` / `open_with_recovery`. First fallible + secret-bearing FFI calls. `FfiUnlockError` 5 variants preserving §13 anti-oracle conflation independently across both paths.
- **B.3b** — `create_vault`. First output-direction secret material; one-shot `MnemonicOutput::take_phrase()`; bridge instantiates `OsRng` + `Argon2idParams::V1_DEFAULT` internally so foreign callers cannot tune either knob.
- **B.4a** — `open_vault_with_password` / `open_vault_with_recovery` (folder-based). First folder-IO entry points; establishes Rust-owned folder-IO model that B.4b/c/d inherit. `OpenVaultManifest` opaque handle with read-only `block_summaries()` / `find_block()`.
- **B.4b** — `read_block`. First mutation-free block access; hybrid Record projection (non-secret metadata value-typed; secret payload via `expose_text` / `expose_bytes`).
- **B.4c** — `save_block`. First mutation path; atomic write per §9 (block-first / manifest-last); `BlockInput` / `RecordInput` / `FieldInput` input shape wraps payloads in `SecretString` / `SecretBytes` at the constructor boundary.
- **B.4d** — `share_block`. First call with `ContactCard` bytes-in; 4 typed share variants (`NotAuthor`, `RecipientAlreadyPresent`, `MissingRecipientCard`, `CardDecodeFailure`) for foreign-side UX dispatch. v1 single-author only (share-as-fork deferred).
- **B.5** — `trash_block` / `restore_block`. First lifecycle pair. `core::vault::trash_block` uses `rename(2)` to `trash/<uuid>.cbor.enc.<unix-millis>`; `restore_block` scans for largest-timestamp file and verifies + AEAD-decrypts + hybrid-verifies before rename-back. New `docs/vault-format.md` §7.1 normative sequence.
- **B.6 v1 / v2** — Cross-language conformance KAT. 22 vectors at [core/tests/data/conformance_kat.json](core/tests/data/conformance_kat.json) (open + read in v1; lifecycle — save / share / trash / restore — in v2). Swift + Kotlin host runners ([ffi/secretary-ffi-uniffi/tests/{swift,kotlin}/run_conformance.sh](ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh)) both replay 22/22 PASS. Replay pins typed Ok/Err + post-call manifest shape rather than AEAD-nonce bytes (all three host runners share the same Rust bridge, so byte parity does not require nonce pinning).

Specs and per-phase plans live under [docs/superpowers/specs/](docs/superpowers/specs/) and [docs/superpowers/plans/](docs/superpowers/plans/).

---

## Sub-project C — Sync orchestration 🚧 (C.1 + C.1.1a/b ✅; C.2 in flight)

This is the layer that turns "the Rust core knows how to merge two manifests" into "two devices sharing a cloud folder converge on the same vault state without user intervention". It sits between the FFI and the platform UIs as its own phase rather than being folded into UI work, so the orchestration logic is built and tested once with a headless reference consumer instead of being re-invented per platform.

Scope:

- **File watching**: cross-platform via the `notify` crate on desktop; per-platform shims on iOS (`NSFilePresenter` / `NSMetadataQuery`) and Android (Storage Access Framework). The state machine that consumes events is the same on every platform.
- **Cloud-folder integration**: wait for the cloud-folder client (iCloud, Drive, Dropbox, OneDrive, WebDAV) to mark a file as fully downloaded before reading it (ADR-0003).
- **Conflict-detection scheduling**: when manifest fingerprints diverge between local and remote, invoke the Sub-project A merge primitives, persist the merged manifest atomically, surface unresolvable conflicts to the UI.
- **Retry / backoff / power-and-network awareness**: especially on mobile.

Phase plan:

- **C.1 — Sync state machine (pure Rust)** ✅. No OS dependencies; property-tested for convergence under random event interleavings.
  - **C.1 phase 1 — sync detection** ✅ — `core::sync::sync_once(folder, &UnlockedIdentity, &SyncState, now_ms)` exposes the §10 rollback-and-fork-detection algorithm as a pure-function dispatch over `clock_relation`. `SyncState` is caller-persisted (canonical-CBOR, sorted/deduped invariant validated symmetrically by constructor and decoder). New `core::vault::read_vault_manifest` lets a sync poll reuse a pre-unlocked identity without re-running Argon2.
  - **C.1.1a — conflict-copy ingestion** ✅ — `SyncOutcome::ConcurrentDetected { bundle, plan, manifest_hash, ... }`. Scans the vault folder for sibling `*.cbor.enc` files (Dropbox / iCloud / Syncthing / OneDrive naming all keep the canonical prefix), authenticates each per spec §1a-D4's five MUST rules (decode + hybrid signature + canonical vault_uuid + canonical owner fingerprint + AEAD-decrypts under the unlocked IBK), and packages canonical + N authenticated copies into a `VaultBundle`. Failures silently drop per spec §1a-D3. New public `core::vault::verify_block_signature`. Quiet-vault fast path pays zero scan cost.
  - **C.1.1b — sync merge layer** ✅ — three-step merge API: `sync_once → prepare_merge → commit_with_decisions`. `prepare_merge` folds diverging-block siblings through `merge_block` and returns a `DraftMerge` with `Vec<RecordTombstoneVeto>` for live-edit-vs-tombstone pairs. `commit_with_decisions` enforces the `vetoes ↔ decisions` bijection (typed `MissingVetoDecision` / `UnknownVetoDecision`), re-checks captured `manifest_hash` for TOCTOU (typed `EvidenceStale` with zero writes on miss), and writes block-first / manifest-last under §9. Partial-commit crash recovery proven by `verify_block_fingerprints` + CRDT idempotence; no orchestrator-side journaling needed. Four merge-layer proptests pin the math (post-commit fixpoint, deterministic merge, decision-order independence, bijection enforcement). 16-vector KAT at [`core/tests/data/sync_kat.json`](core/tests/data/sync_kat.json).
- **C.2 — Headless `secretary-sync` CLI (desktop)** 🚧 — wraps the C.1 state machine + the `notify` crate + Sub-project A. Doubles as the reference consumer for testing and as a real user-facing tool for headless deployments (NAS, server). Spec + 10-task plan landed via PR #111. **Tasks 1–9 complete**: scaffold + exit codes (#112); state persistence + host-local lockfile (#114); TTY + stdin password sourcing (#115); veto UX trait + impls (#116); pipeline (one sync attempt) + lib/bin split (#118); watcher submodule with ready + debounce (#119); notify driver + daemon loop (#121); logging + signal handling (#124); `main.rs` end-to-end dispatch + `once` integration tests (Task 9). `secretary-sync once <folder>` now runs against a real vault end-to-end. **Remaining**: Task 10 (two-instance convergence + `notify` quirk pin + packaging polish + docs).
- **C.3 — Mobile sync adapters** ⏳. iOS adapter using `NSFilePresenter` / `NSMetadataQuery`; Android adapter using the Storage Access Framework + `WorkManager`. Both expose the C.1 state machine via uniffi.
- **C.4 — Cross-device convergence conformance** ⏳. Two simulated devices (or two real CLIs) edit `golden_vault_001/` concurrently through a shared folder; both converge to the same merged manifest fingerprint with no data loss across power-cycle, network-partition, and clock-skew scenarios.

Sub-project C is where shippable software starts to exist. The `secretary sync` CLI alone is enough for a technically inclined user with a NAS to run a real multi-device vault.

---

## Sub-project D — Platform UIs ⏳ (planned)

The UIs are deliberately written natively per platform (see [ADR-0001](docs/adr/0001-rust-core.md)). UI is not shared across platforms — each platform's idiom matters more than code reuse on the UI tier. Each UI consumes Sub-project A (vault crypto + format) and Sub-project C (sync orchestration) through the Sub-project B FFI, so UI code never touches a file watcher or a merge function directly.

Phase plan:

- **D.1 — Desktop / Web (Python + NiceGUI)**: vault create / unlock / browse / add credential / share. NiceGUI runs the same codebase as a native desktop window or as a browser app.
- **D.2 — iOS (Swift + SwiftUI)**: native app with the same feature set, plus Apple Keychain interop and AutoFill provider.
- **D.3 — Android (Kotlin + Jetpack Compose)**: native app with the same feature set, plus Android AutoFill Service.
- **D.4 — Browser autofill extensions**: future, after the platform clients stabilise.

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
- **Wait for Sub-project D.** If your interest is the platform UI layer, that phase hasn't started. Star the repo and check back.

PRs against the Rust core are accepted but the bar is high: every change must come with KAT-level tests, no `unsafe`, typed errors only, and adherence to the conventions documented in `secretary_next_session.md` and the existing source.

---

## Cadence

This is intentionally a slow project. A vault format that protects multi-decade secrets is not the right place to optimize for time-to-MVP. Releases happen when the work is right, not when a calendar says so.

Rough order-of-magnitude expectations (no commitments):

- **Sub-project A complete + audited**: months, not weeks.
- **Sub-project B (FFI)**: weeks once A is frozen.
- **Sub-project C (sync orchestration + headless CLI)**: weeks-to-months on top of B; the C.1 state machine and C.2 CLI are bounded, the C.3 mobile adapters depend on per-platform OS work.
- **Sub-project D.1 (desktop/web)**: weeks on top of C — much of the heavy lifting is done by then.
- **Sub-project D.2 + D.3 (iOS, Android)**: parallelisable; pace depends on contributors.
- **v1.0 release**: when all of the above ship and the spec has been stable across at least one external review cycle.

The project will not have a "1.0" tag until the cryptographic foundation has stood up to independent scrutiny and the first reference UI is real software people can use to store real secrets.
