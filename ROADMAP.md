# Secretary — Roadmap

This roadmap shows where Secretary is today and what comes next. It is meant for potential contributors deciding whether and where to help, and for users trying to gauge when the project will be usable.

The project is structured as four sequential sub-projects. Each sub-project is a coherent unit of work that can be reviewed end-to-end before the next begins. **Sub-project A** is the Rust cryptographic core and on-disk format. **Sub-project B** is the FFI binding layer (PyO3 + uniffi). **Sub-project C** is the headless sync-orchestration layer — file watching, cloud-folder integration, conflict-detection scheduling — exposed across the FFI so every UI gets the same orchestration semantics for free. **Sub-project D** is the platform UIs.

This ordering is deliberate. The cryptographic core is the only piece where mistakes are hard to walk back — once a vault format is in the wild and people have stored multi-decade secrets in it, you cannot fix a flaw without a forced migration. So the core ships first, with rigour. Sync orchestration sits between FFI and the UIs as its own phase rather than being folded into per-platform UI work, so the orchestration logic is built and tested once (with a headless `secretary sync` CLI as a reference consumer) instead of being re-invented and re-debugged across desktop, iOS, and Android.

For the full design specifications see [docs/](docs/). For the next-session entry point with concrete TODOs see [secretary_next_session.md](secretary_next_session.md).

---

## Where we are: 2026-05-03

Sub-project A is feature-complete for v1; Phase A.7's three **internal** hardening passes are closed and the external (paid) review track is the only Phase A.7 work remaining. **Sub-project B is now in flight**: B.1 (FFI binding boilerplate) is complete on the Python side — PyO3 + maturin wired up, two trivial round-trip functions (`sum`, `version`) exposed, two-layer test discipline (Rust unit tests via `cargo test`, Python pytest via `uv run --directory ffi/secretary-ffi-py pytest`) operational. Swift / Kotlin via uniffi is deferred to B.1.1. No vault crypto exposed yet — that's B.2. Phase A.6 / PR-C landed the CRDT merge primitives (`core/src/vault/conflict.rs`: `clock_relation`, `merge_vector_clocks`, `merge_record`, `merge_block`) plus a record-level `tombstoned_at_ms` "death-clock" that closes the three-way-merge associativity gap that naive tombstone-on-tie semantics leave open. PR #9 added the polishing pass: a bidirectional defensive clamp on `tombstoned_at_ms`, tag-canonicalisation on the LWW-clone path, and a clean-room Python `py_merge_unknown_map` for the record-level `unknown` map — extending the §15 cross-language KAT to **eleven** vectors (`core/tests/data/conflict_kat.json`). Definition-of-Done item #3 in the design anchor (commutativity + associativity + idempotence under random sequences of edits) is satisfied across the *full* record domain — arbitrary tombstones, arbitrary resurrection sequences, arbitrary record-level `unknown` keys — proven by four `proptest` properties (commutativity, associativity, idempotence, and PR #9's well-formedness Property L) at default 256 cases each in `core/tests/proptest.rs`.

Phase A.7 work since 2026-05-01:

- **Fuzz harness shake-out**: PR #11 triaged the first six fuzz artifacts (libfuzzer false positives, promoted as regression tests under [`core/tests/data/fuzz_regressions/`](core/tests/data/fuzz_regressions/) plus a real peer-supplied DoS surface capped at 4 KiB on the contact-card `display_name` field). PR #12 then plumbed live telemetry through the NiceGUI dashboard (cov/ft/corp/exec-s/rss readout per card, status badge per Status, global findings tally). A thirteen-commit direct-to-main stabilisation wave addressed issues #13/#14/#15 (pulse-parser Kb form fix, plateau-stop process-group signalling, `Status.DIED` distinct from user stop) plus sparkline + plateau dot strip, `--careful` instead of UBSan, oom-/slow-unit-artifact detection, dedicated heartbeats deque, and mypy hygiene.
- **Three internal A.7 hardening passes (2026-05-02)** all ✅ closed:
  - **Threat-model refresh**: `docs/threat-model.md` updated against the as-implemented surface — four divergences fixed (notably §3.5's "mixed-suite-IDs allowed by design" was factually wrong; v1 rejects any non-v1 suite_id at parse), and the §5 verification trace expanded from 11 entries with 4 stale test names to ~30 entries across 7 sections (primitive KATs, composite invariants, vault format, CRDT, cross-language conformance, fuzzing, structural). Six commits, all cited test names verified to exist before commit.
  - **Side-channel internal pass**: audit memo at [`docs/manual/contributors/side-channel-audit-internal.md`](docs/manual/contributors/side-channel-audit-internal.md). No bugs in our code; all CT-sensitive comparisons delegate to upstream RustCrypto crates. One concrete hardening commit added a `Fingerprint = [u8; 16]` doc-comment explaining it's a public value by design (so future contributors arriving at a `==` see why non-CT is intentional).
  - **Memory-hygiene audit**: audit memo at [`docs/manual/contributors/memory-hygiene-audit-internal.md`](docs/manual/contributors/memory-hygiene-audit-internal.md). Wrapper discipline (`Sensitive<T>` / `SecretBytes`) and composite-type drop ordering verified clean; **twelve stack-residue gaps fixed** (sister sites to already-disciplined ones — the established `var.zeroize()` after `Sensitive::new(var)` pattern). The original audit's largest deferred item — `RecordFieldValue::{Text, Bytes}` not zeroize-on-drop — was resolved by PR #16: both variants now wrap `SecretString` / `SecretBytes` with the wire format and the Python conformance verifier unaffected. The remaining cosmetic gap (`MlDsa65Secret` / `MlKem768Secret` not exposing `.zeroize()` programmatically) was closed by adding `#[derive(Zeroize, ZeroizeOnDrop)]` to both newtypes in a follow-up commit.

PR #10 (earlier, 2026-05-01) added a thirteen-chapter [cryptography primer](docs/manual/primer/cryptography/index.md) and [hardening guide](docs/manual/hardening-security.md) for users and contributors who want the conceptual background without reading the normative spec.

```
[================================================================] Sub-project A — Rust core (feature-complete; A.7 internal track closed; external review pending)
[========                                                        ] Sub-project B — FFI bindings (B.1 Python complete; B.1.1 Swift/Kotlin pending; B.2+ vault crypto pending)
[                                                                ] Sub-project C — Sync orchestration
[                                                                ] Sub-project D — Platform UIs
```

447 tests pass + 6 ignored under `cargo test --release --workspace` (445 + 2 from the new B.1 PyO3 unit tests). Clippy is clean with `-D warnings`. `#![forbid(unsafe_code)]` is crate-wide for `core/` and `secretary-ffi-uniffi/`; the new `secretary-ffi-py/` crate carries a localized `unsafe_code = "deny"` (PyO3 macros expand to unsafe blocks; `forbid` is non-overridable) per CLAUDE.md's "FFI as isolated reviewed boundary" principle. Every cryptographic primitive is pinned against published KATs; the CRDT merge layer is additionally proven on the full record domain (including arbitrary record-level `unknown`) by four `proptest` properties. Both `golden_vault_001/` (full crypto) and `conflict_kat.json` (merge semantics, twelve vectors) are verified end-to-end by the Rust suite and by the stdlib-only Python conformance script. The two internal-audit memos are the principal handoff documents for the paid external review. The Python pytest layer (2 tests, `uv run --directory ffi/secretary-ffi-py pytest`) cross-validates the FFI binding pipeline.

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

### Phase A.6 — Vector-clock CRDT merge primitives ✅ (complete, PR-C)

`secretary_core::vault::conflict`:

- **Pure-function vector-clock primitives** ([core/src/vault/conflict.rs](core/src/vault/conflict.rs)):
  - `clock_relation(local, incoming) -> ClockRelation` — `Equal | IncomingDominates | IncomingDominated | Concurrent`. Anti-symmetric on argument swap, missing-device-as-zero. Used by manifest §10's rollback check (an `IncomingDominated` relation is the rollback signal) and by `merge_block`'s dispatch.
  - `merge_vector_clocks(a, b) -> Vec<VectorClockEntry>` — lattice join (component-wise max), sorted ascending by `device_uuid` per §6.1.
  - `merge_record(local, remote) -> MergedRecord` — field-level LWW with `device_uuid` lex tiebreak; tombstone-on-tie (`T_d ≥ T_l`); `tombstoned_at_ms` death-clock propagation via `max`; staleness filter dropping fields with `last_mod ≤ death_clock`. Concurrent value collisions surfaced as `Vec<FieldCollision>` informational metadata for UIs without serialising a `_conflicts` shadow on disk (`docs/crypto-design.md` §11.4 — Rust API affordance only).
  - `merge_block(local, local_clock, remote, remote_clock, merging_device) -> Result<MergedBlock, ConflictError>` — dispatches on `clock_relation`: returns the dominant side unchanged for `Equal` / `IncomingDominates` / `IncomingDominated`, runs the per-record merge for `Concurrent` and ticks the merging device's component into the merged clock. `block_uuid` mismatch surfaced as a typed error.
- **Death-clock for full-domain associativity** (`docs/crypto-design.md` §11.3): `tombstoned_at_ms` is the high-water mark of every tombstone observation on a record. Itself a CRDT (lattice join via `max`), preserved across resurrection (a live edit at `T_r > tombstoned_at_ms` keeps the prior death clock), and drives the staleness filter that closes the three-way-merge associativity gap that naive tombstone-on-tie semantics leave open. Wire format is backward-compatible (omitted on the wire when zero).
- **§11.3 identity-metadata override**: on `LocalTombstoneWins` / `RemoteTombstoneWins`, the merged record's `tags`, `record_type`, and record-level `unknown` come wholesale from the tombstoning side — so a UI surfacing a tombstoned record (trash bin, undelete prompt) reflects the deleter's view, not a concurrent edit they never saw and not an adversarial sync peer's same-millisecond identity flip.
- **Defensive canonicalisation in `merge_record`**: clamps `tombstoned_at_ms` upward to `last_mod_ms` for any input where `tombstone == true` *before* the lattice join, so a malformed peer (`tombstone = true, tombstoned_at_ms = 0`) cannot suppress the death-clock's advance and let stale fields slip through the staleness filter.
- **CRDT proptests** ([core/tests/proptest.rs](core/tests/proptest.rs) — `mod vault`'s PR-C section): `crdt_merge_record_commutativity`, `_associativity`, `_idempotence`, plus the PR #9 well-formedness Property L on arbitrary inputs, all at proptest defaults (~256 cases). Inputs canonicalised to the §11.5 well-formedness invariants (including populated record-level `unknown` since PR #9), then merged; the four properties hold bit-identically over the *full* record domain — arbitrary `tombstone`, arbitrary `tombstoned_at_ms`, arbitrary fields predating or surviving any tombstone, arbitrary `unknown` keys.
- **§15 cross-language KAT** ([core/tests/data/conflict_kat.json](core/tests/data/conflict_kat.json)): eleven vectors witnessing each `ClockRelation` branch (`Equal`, `IncomingDominates`, `IncomingDominated`, `Concurrent`), the death-clock staleness filter, the §11.3 identity-metadata override, both-tombstoned merges, resurrection-preserves-death-clock, field-level collision reporting, and (added in PR #9) record-level `unknown` collision under lex-larger-CBOR-bytes resolution + tombstone-wins preservation of live unknowns. Replayed by both [core/tests/conflict.rs](core/tests/conflict.rs)::`kat_replays_match_rust_merge` and [core/tests/python/conformance.py](core/tests/python/conformance.py) Section 4 — the Python implementation is a clean-room `py_merge_record` + `py_merge_unknown_map` written from §11 spec docs only, satisfying the §15 / AGPL clean-room contract for the merge layer.
- **VaultError integration**: `ConflictError::{BlockUuidMismatch, ClockOverflow}` propagates through `VaultError::Conflict(#[from] ConflictError)` so orchestrators in Sub-project C can `?` through the umbrella surface.
- **PR #9 follow-up polish**: bidirectional defensive clamp (`tombstoned_at_ms` ≥ `last_mod_ms` whenever `tombstone == true`, applied on *both* sides before the lattice join) so a malformed peer can neither suppress nor inflate the death-clock; canonicalisation of `merge_tags` multiplicity on the LWW-clone path; clean-room `py_merge_unknown_map` covering record-level `unknown` cross-language; conformance script Section 5 case-insensitivity self-test guarding against raw-string-compare drift on hex-encoded blobs.

### Phase A.7 — Hardening + audit prep 🚧 (internal track ✅ closed; external track pending)

**Internal track (all closed 2026-05-02):**

- **Fuzz harness** ✅ — PR #8 (scaffold) + PR #11 (six promoted regression tests + 4 KiB `display_name` cap) + PR #12 (live telemetry on the dashboard) + thirteen-commit direct-to-main stabilisation wave (issues #13/#14/#15 + sparkline / `--careful` / oom-detection / plateau-pulse-only filtering / mypy hygiene). Cross-language differential-replay protocol at [`docs/manual/contributors/differential-replay-protocol.md`](docs/manual/contributors/differential-replay-protocol.md). Six targets, all green; freshly-run campaigns raise no findings.
- **Threat-model refresh** ✅ — `docs/threat-model.md` updated against the as-implemented surface. Four divergences fixed (most material: §3.5's "mixed-suite-IDs allowed by design" was factually wrong; v1 rejects any non-v1 suite_id at parse). §5 verification trace expanded from 11 entries (4 stale) to ~30 entries across 7 sections; every cited test name verified to exist before commit. Six commits.
- **Side-channel internal pass** ✅ — audit memo at [`docs/manual/contributors/side-channel-audit-internal.md`](docs/manual/contributors/side-channel-audit-internal.md). No bugs in our code; all CT-sensitive comparisons delegate to upstream RustCrypto. One hardening commit (`Fingerprint = [u8; 16]` doc-comment) explaining it's a public value by design. Principal output: a list of upstream-crate assumptions for the paid external reviewer.
- **Memory hygiene audit** ✅ — audit memo at [`docs/manual/contributors/memory-hygiene-audit-internal.md`](docs/manual/contributors/memory-hygiene-audit-internal.md). Wrapper discipline (`Sensitive<T>` / `SecretBytes`) sound; composite-type drop ordering verified clean. **Twelve stack-residue gaps fixed** in commit `6054185` (one-line `var.zeroize()` after `Sensitive::new(var)` — sister sites to already-disciplined ones). Two follow-up passes have since closed the audit's deferred items at the type level: PR #16 wrapped `RecordFieldValue::{Text, Bytes}` in `SecretString` / `SecretBytes` (wire format and Python conformance unaffected), and a follow-up commit added `#[derive(Zeroize, ZeroizeOnDrop)]` to the `MlDsa65Secret` / `MlKem768Secret` newtypes so callers can wipe a still-live newtype value programmatically.
- **User-facing primer** (PR #10) ✅ — a thirteen-chapter [cryptography primer](docs/manual/primer/cryptography/index.md) for users and contributors. Bonus material; valuable contributor onboarding now that the spec has stabilised.

**External track (pending; out of any in-session scope):**

- **Independent cryptographic review** (paid). Spec docs are stable enough to send out; reviewer with FIPS 203 / FIPS 204 implementer experience and AAD/signed-range eyes especially valuable. Principal handoff package: `docs/` (normative specs + threat-model + ADRs) plus the two internal-audit memos.
- **Side-channel review** (paid). Constant-time critical paths enumerated in the side-channel internal-audit memo; reviewer should verify upstream-crate assumptions especially for `ml-dsa = "0.1.0-rc.8"` (pre-1.0).

End of Sub-project A: Rust core is feature-complete for v1, audited (internally) for spec divergence + side channels + memory hygiene, and ready to be wrapped by FFI in parallel with the external review track.

---

## Sub-project B — FFI bindings 🚧 (B.1 Python complete; rest planned)

The Rust core is exposed to platform languages via two binding paths:

- **PyO3** ([ffi/secretary-ffi-py](ffi/secretary-ffi-py/)): Python bindings for the desktop / web client. Async-aware where the underlying API is.
- **uniffi** ([ffi/secretary-ffi-uniffi](ffi/secretary-ffi-uniffi/) — stub): Swift bindings for iOS, Kotlin bindings for Android — same UDL, two outputs.

Phase plan:

- **B.1 (Python)** ✅ — PyO3 + maturin binding pipeline proven end-to-end with two trivial round-trip functions (`sum`, `version`). Two-layer test discipline (Rust unit tests + Python pytest) operational. Spec at [docs/superpowers/specs/2026-05-03-ffi-b1-py-bindings-boilerplate-design.md](docs/superpowers/specs/2026-05-03-ffi-b1-py-bindings-boilerplate-design.md); FFI crate README at [ffi/secretary-ffi-py/README.md](ffi/secretary-ffi-py/README.md).
- **B.1.1 (Swift / Kotlin via uniffi)** ⏳ — UDL design + uniffi-bindgen wiring + smoke tests on macOS-host / Android emulator. Same shape as B.1 but on the uniffi crate.
- **B.2** — Vault unlock + open exposed across all three languages. First fallible operations (`PyResult` ergonomics, exception marshalling), first secret-bearing types across the FFI boundary (zeroize discipline through Python's GC).
- **B.3** — Block save / share / open exposed.
- **B.4** — Conformance: same `golden_vault_001/` test runs in Python and Rust and Swift and Kotlin and produces bit-identical results.

Sub-project B is bounded work — there is no design ambiguity, just careful translation. It can proceed in parallel with the Sub-project A external review track.

---

## Sub-project C — Sync orchestration ⏳ (planned)

This is the layer that turns "the Rust core knows how to merge two manifests" into "two devices sharing a cloud folder converge on the same vault state without user intervention". It sits between the FFI and the platform UIs as its own phase rather than being folded into UI work, so the orchestration logic is built and tested once with a headless reference consumer instead of being re-invented per platform.

Scope:

- **File watching**: detect when files in the vault folder change. Cross-platform via the `notify` crate on desktop (FSEvents, inotify, `ReadDirectoryChangesW`); per-platform shims on iOS (`NSFilePresenter` / `NSMetadataQuery` for iCloud Drive) and Android (Storage Access Framework). The state machine that consumes events is the same on every platform.
- **Cloud-folder integration**: wait for the cloud-folder client (iCloud, Drive, Dropbox, OneDrive, WebDAV) to mark a file as fully downloaded before reading it. Per ADR-0003 — the orchestration must not race a partial download.
- **Conflict-detection scheduling**: when manifest fingerprints diverge between local and remote, invoke the Sub-project A merge primitives, persist the merged manifest atomically, surface unresolvable `_conflicts` to the UI layer.
- **Retry / backoff / power-and-network awareness**: especially on mobile, where the OS may suspend the process at any time.

Phase plan:

- **C.1 — Sync state machine in pure Rust**. No OS dependencies. Inputs: manifest-changed event, peer-manifest-fingerprint event. Outputs: merge-needed, persist-merged-manifest, conflict-needs-user. Property-tested for convergence under random event interleavings.
- **C.2 — Headless `secretary sync` CLI (desktop)**. Wraps the state machine + the `notify` crate + Sub-project A core. Doubles as the reference consumer for testing and as a real user-facing tool for headless deployments (NAS, server). Two-instance tests run two CLIs against a shared temp directory and assert convergence.
- **C.3 — Mobile sync adapters**. iOS adapter using `NSFilePresenter` / `NSMetadataQuery`, exposed via uniffi-bound state machine. Android adapter using the Storage Access Framework + `WorkManager`, exposed via uniffi-bound state machine.
- **C.4 — Cross-device convergence conformance**. Two simulated devices (or two real CLIs) edit `golden_vault_001/` concurrently through a shared folder; both converge to the same merged manifest fingerprint with no data loss across power-cycle, network-partition, and clock-skew scenarios.

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
- **Wait for Sub-project B / C / D.** If your interest is the FFI bindings, sync orchestration, or platform UI layer, those phases haven't started. Star the repo and check back.

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
