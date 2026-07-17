# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

**Secretary** is a multi-platform, client-only secrets manager. The Rust cryptographic core and on-disk vault format (**Sub-project A**) are feature-complete and frozen for v1, and all three downstream phases are substantially built on top of it: **Sub-project B** (FFI bindings — the `secretary-ffi-bridge` crate projected onto PyO3 + uniffi) is complete through B.6 v2 and beyond (device-slot ops, record-edit + block-CRUD primitives, sync surface); **Sub-project C** (sync orchestration) is complete through C.4; and **Sub-project D** (platform UIs) ships working apps — a Tauri 2 desktop client (`desktop/`), a native SwiftUI iOS app (`ios/`), and a native Jetpack Compose Android app (`android/`). See [README.md](README.md) "Project status" and [ROADMAP.md](ROADMAP.md) for the authoritative per-slice state. The Rust core remains the single source of truth for everything security-relevant; the platform code consumes it, never reimplements it.

The cryptographic design and on-disk format are **frozen for v1** because vaults written today must remain readable by clients written decades from now. Treat anything in `docs/crypto-design.md`, `docs/vault-format.md`, and `docs/threat-model.md` as the source of truth — the Rust code implements those, not the other way around.

## Layout

```
core/                Rust crate `secretary-core` — the security-critical source of truth
core/src/{crypto,identity,unlock,vault}/   — module per spec section
core/tests/          — integration tests; tests/data/ holds KATs and fuzz regressions
core/tests/python/conformance.py           — clean-room verifier (generic crypto primitives via
                                             PEP 723; no dependency on `secretary-core`); proves
                                             the spec is implementable from `docs/` alone
core/fuzz/           — `cargo-fuzz` harness, EXCLUDED from the workspace; nightly toolchain
docs/                — normative specs (see "Spec is normative" below)
docs/adr/            — architecture decision records, numbered 0001..0010
ffi/secretary-ffi-bridge                        — the single source of FFI code truth (pure-safe Rust)
ffi/secretary-ffi-py, ffi/secretary-ffi-uniffi  — PyO3 / uniffi (Swift + Kotlin) binding crates over the bridge
desktop/             — Tauri 2 desktop client (Rust backend + Svelte/TypeScript frontend)
ios/                 — native SwiftUI app + Swift packages (SecretaryKit / SecretaryVaultAccess / SecretaryDeviceUnlock)
android/             — native Jetpack Compose app + Gradle modules (:app, :kit, :vault-access, :sync-ui, :browse-ui)
test-utils/          — dev-only crate `secretary-test-utils`: THE canonical `copy_dir_recursive` /
                       `copy_dir_to_tempdir` / `core_test_data_dir` / `golden_vault_001_password` (#90) —
                       consume via [dev-dependencies], never hand-roll another fixture-copy walker,
                       never make it a runtime dep
```

## Working directory discipline

Sessions in this repo routinely span multiple `git worktree` checkouts (see [.worktrees/](.worktrees/)) and parallel Claude windows can switch branches under each other. Before running any path-sensitive command (`cargo`, `git push`, `git commit`, `uv run`, fuzz invocations), verify where you are:

```bash
pwd && git branch --show-current && git worktree list
```

- **Shell state does not persist between Bash tool calls.** `cd foo` followed by a separate `cargo test` call runs `cargo test` in the *previous* directory. Either chain in one call (`cd core/fuzz && cargo fuzz run vault_toml`) or use absolute paths.
- **Never run `cargo` / `git push` from the main repo when the work is in a worktree.** A pushed commit on the wrong branch is recoverable but wastes a cycle; an overwritten unstaged edit (parallel session switched branches) needs `git reflog` recovery.
- **If `git status` shows unexpected state** (unfamiliar branch, untracked files you didn't create, missing edits you remember making), stop and investigate before any destructive op — it's almost always a parallel-session collision, not a bug.

## Commands

The workspace uses **stable Rust** ([rust-toolchain.toml](rust-toolchain.toml)). Only `core/fuzz/` uses nightly (separate `rust-toolchain.toml` inside that directory).

```bash
# Build / test the whole workspace (always --release; the crypto crates are slow in debug)
cargo test --release --workspace

# Run one integration test file
cargo test --release --workspace --test fuzz_regressions
cargo test --release --workspace --test conflict

# Cross-language differential replay (requires `uv`; opt-in via Cargo feature)
cargo test --release --workspace --features differential-replay

# Lint — must stay clean with -D warnings (covers both lib + test targets)
cargo clippy --release --workspace --tests -- -D warnings

# Doc links — must stay warning-clean (#92 CI gate; rustdoc only documents the
# cfg-active code, so run on both Linux and macOS to catch platform-gated links)
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace

# Format
cargo fmt --all

# Assert the lean mobile-binding boundary (#189): notify/clap must NOT leak into
# secretary-ffi-{uniffi,py,bridge}. `--self-test` first proves the matcher fires
# on a known-positive control (secretary-cli) so a green guard is never vacuous.
bash ffi/scripts/check-lean-binding.sh --self-test
bash ffi/scripts/check-lean-binding.sh
```

### Python paths

This repo uses `uv` exclusively — **never `pip` / `pip3` / `python -m pip`**.

```bash
# Run the conformance script (proves docs/ alone is sufficient to decrypt the golden vault)
uv run core/tests/python/conformance.py

# Detect drift between docs/*.md test-name citations and core/ Rust code
# (use --self-test to validate the script's own heuristics; --audit-allowlist to
# flag allowlist entries whose underlying citation now resolves)
uv run core/tests/python/spec_test_name_freshness.py

# Run the fuzz monitor's pytest suite (test_monitor imports monitor.py, which
# imports nicegui at module load, so the dashboard dep must be on the path too)
cd core/fuzz && uv run --with pytest --with "nicegui>=2" pytest test_monitor.py -v

# Launch the NiceGUI fuzz dashboard at http://localhost:8080
uv run core/fuzz/monitor.py

# Cross-language conformance KAT replay (B.6 v1; read-only FFI surface).
# Each runner loads core/tests/data/conformance_kat.json and asserts the
# Swift / Kotlin uniffi binding produces the same observable output as
# the Rust bridge replay (which runs every cargo test).
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh

# Regenerate conformance_kat.json after an intentional protocol change
# (diff is human-reviewed before commit; expected diff is scoped to
# read_block_happy.expected.records and nothing else):
cargo test --release --workspace -- --ignored generate_conformance_kat --nocapture
```

### Fuzz harness (`core/fuzz/`)

Has its own `Cargo.toml` and **is excluded from the workspace** (see `[workspace] exclude = ["core/fuzz"]` in the root manifest). Needs a path-scoped nightly toolchain — Homebrew's cargo on macOS will mask rustup's nightly, prepend explicitly:

```bash
cd core/fuzz
PATH="$HOME/.rustup/toolchains/nightly-2026-04-29-aarch64-apple-darwin/bin:$PATH" cargo fuzz run <target>
```

Seven targets: `vault_toml`, `record`, `contact_card`, `bundle_file`, `manifest_file`, `block_file`, `device_file`. Promotion workflow (crash → minimize → durable regression KAT) is in [core/fuzz/README.md](core/fuzz/README.md). Promoted regressions live under `core/tests/data/fuzz_regressions/` and replay through the regular `cargo test` run (no nightly required).

## Architecture you can't get from grepping

### Spec is normative; code implements the spec

`docs/crypto-design.md` and `docs/vault-format.md` are not generated docs — they're the contract. A clean-room implementation in any other language must be possible by reading `docs/` alone, and that property is **enforced every CI run** by `core/tests/python/conformance.py`, which depends on no `secretary` code — only generic crypto primitives declared via its PEP 723 header (`cryptography`, `pynacl`, `pqcrypto`, `argon2-cffi`, `blake3`, `cbor2`; top-level imports stay stdlib-only, these are lazy-imported) — to:

1. Decap + AEAD-decrypt + hybrid-verify the `core/tests/data/golden_vault_001/` reference vault.
2. Replay 11 CRDT merge KATs from `core/tests/data/conflict_kat.json` cross-language.
3. Run the `--diff-replay` mode used by the fuzz harness for decoder-agreement checks.

Practical consequence: when a Rust change alters observable byte format or merge semantics, the spec doc is the first thing to update, and `conformance.py` is the test that proves the docs and code still agree. **Don't fix divergence by changing one side silently.** A disagreement is one of: Rust bug, Python bug, or spec ambiguity — all three need to be resolved explicitly.

### Crypto layering

Each `core/src/{crypto,identity,unlock,vault}` module corresponds to a section of the spec. Hybrid constructions are intentional and live throughout:

- KEM = X25519 ⊕ ML-KEM-768 (both must work for an attacker to recover plaintext).
- Signatures = Ed25519 ∧ ML-DSA-65 (**both** must verify, AND not OR; this is checked at every signature-verification call site).
- Argon2id v1 default is m=256 MiB, t=3, p=1 (`Argon2idParams::V1_DEFAULT`); v1 floor is m=64 MiB (`V1_MIN_MEMORY_KIB`), iter ≥ 1, par ≥ 1. The floor is enforced at **vault creation** as a typed error (`UnlockError::WeakKdfParams` from `create_vault`) — `open_with_password` does NOT re-check the floor at read time (the spec does not require it). A tampered `vault.toml` still can't downgrade cost: a changed KDF param → different Master KEK → `wrap_pw` AEAD fails, and the orchestrator `open_vault` cross-checks `vault.toml [kdf]` against the signed manifest (`KdfParamsMismatch`). The floor would become load-bearing at open only if a future change-password/re-wrap flow re-derives the KEK from `vault.toml` params — that flow must route through `try_new_v1`.
- A **third, optional unlock path** exists as of ADR 0009: per-device wrap files `devices/<uuid>.wrap` (`file_kind 0x0004`) wrap the IBK under `device_kek = HKDF-SHA-256(device_secret)` (crypto-design §5a, vault-format §3a). It is additive — `identity.bundle.enc` is unchanged — and is the core foundation for B.3's Secure-Enclave/biometric key release. Folder ops live in `core/src/vault/device_slot.rs`; pure crypto in `core/src/unlock/device.rs`. The device open is also a first-class FFI **`Unlocker::DeviceSecret`** arm in `core/src/vault/orchestrators.rs::open_vault` (B.2, #201) — it goes through the *same* manifest verify-before-decrypt as the password/recovery paths, so the device path is never a weaker open. The FFI projection (`add_device_slot` / `open_with_device_secret` / `remove_device_slot`) lives in `ffi/secretary-ffi-bridge/src/device.rs` and is exposed on uniffi + pyo3; it surfaces 3 typed `FfiVaultError` variants (`DeviceSlotNotFound` / `WrongDeviceSecretOrCorrupt` / `DeviceUuidMismatch`) with wrong-length `device_uuid`/`device_secret` validated at the binding layer (`InvalidArgument`), since the bridge fns take `&[u8; 16]`/`&[u8; 32]`.

- **iOS device unlock (B.3)** lives in `ios/`: a pure, FFI-free `SecretaryDeviceUnlock` package (`DeviceUnlockCoordinator` over `VaultDeviceSlotPort` / `DeviceSecretEnclave` / `DeviceEnrollmentMetadataStore`, typed `DeviceUnlockError`) host-tested via `swift test`, plus iOS adapters in `SecretaryKit/DeviceUnlock/` (the real uniffi port, the non-exportable Secure-Enclave P-256 conformer behind a biometric `SecAccessControl`, Keychain metadata). The SE conformer is compile-verified on the simulator with a fake enclave; **real Face ID release was proven on an iPhone 13 Pro Max (#202 ✅, 2026-06-11)** via the SwiftUI walking-skeleton app (`ios/SecretaryApp/`, an XcodeGen target over a host-tested `DeviceUnlockViewModel` in `SecretaryDeviceUnlock`'s `SecretaryDeviceUnlockUI` product). On-device, the `SecKeyCreateDecryptedData`-triggered biometric eval funnels cancel/non-match into `LAError.userCancel` (not `NSOSStatusErrorDomain`), and no failure mislabels as `wrappedSecretCorrupt`. The coordinator's `unlock` funnels through the same B.2 `open_with_device_secret` (hence the same manifest verify-before-decrypt) — it is not a weaker open. **iOS app-bundle gotcha:** a bundled folder literally named `Resources/` breaks on-device codesign ("code object is not signed at all"); `ios/SecretaryApp/` stages its demo vault under `Fixtures/` instead.

Whenever you touch a verification or KDF site, preserve the "both halves" property. Past review feedback caught a near-miss where ML-DSA verification failures were being swallowed at the call site; security-critical code reviews must prove enforcement, not assume it.

### CRDT merge: vector clocks + record-level death clock

`core/src/vault/conflict.rs` is the merge layer. The non-obvious bit is `tombstoned_at_ms` — a record-level death clock that closes the associativity gap that naive tombstone-on-tie semantics leave open. Four `proptest` properties (commutativity, associativity, idempotence, well-formedness) hold over the full record domain, including arbitrary tombstone-and-resurrection histories and arbitrary `unknown` keys. The Python clean-room equivalent lives in `conformance.py` as `py_merge_record` / `py_merge_unknown_map`.

If a CRDT change requires the proptests to weaken, that's a design problem. Push back; don't relax the property.

### Crash recovery: repair_vault and the equal-clock invariant (#350)

`core/src/vault/repair.rs` holds the crash-recovery layer: an open-time best-effort sweep completing interrupted trash renames (`trash_block` is **manifest-first** — the signed-manifest write is the commit point; the physical `blocks/ → trash/` move is best-effort), and `repair_vault`, which adopts crash-residue blocks whose fingerprint mismatches the manifest, behind hard gates (hybrid verify ∧ header binding ∧ clock freshness, all-or-nothing). The non-obvious, load-bearing invariant: **equal block clock ⇒ identical plaintext**. Content writes (`save_block`) tick the block vector clock; re-keys (`share_block` / `revoke_block_recipient` via `rewrite_block_with_recipients`) re-encrypt the *unchanged* plaintext and preserve the clock. `repair_vault` therefore refuses to adopt any recipient **widening** regardless of clock relation (fail-closed — re-granting access is never automatic): a legitimate crashed `save_block` re-encrypts to the *existing* recipient set so its `IncomingDominates` residue never adds a recipient, and a crashed re-key lands as `Equal` where only a strict-subset reduction is adopted. This guard is relation-independent on purpose — an earlier Equal-only version left the `IncomingDominates` arm able to re-grant a clock-invisible revoke via a planted owner-signed content-save. Soundness of the Equal tier rests on the equal-clock invariant; it holds *only while* that invariant holds. If you ever make a clock-preserving path mutate the plaintext, you MUST tick the block clock instead (guard comments at `rewrite_block_with_recipients`; normative in vault-format.md §6.5.1). Wall-clock `last_mod_ms` must never be used as a freshness signal — it has no monotonicity guarantee, and a timestamp-gated variant was demonstrated exploitable (revoked-recipient re-grant) during the #350 review.

### Atomic-write contract

`core/src/vault/io.rs::write_atomic` uses `tempfile::NamedTempFile::persist` for `rename(2)` / `MoveFileExW` semantics under the manifest and block writes. The `tempfile` dependency is **pinned to an exact version** (`=3.27.0` in [core/Cargo.toml](core/Cargo.toml)) — not a caret range — so any patch / minor / major bump requires a deliberate edit + changelog review. This is intentional: a regression in `persist` semantics (e.g. silent fallback to a non-atomic copy) would weaken the §9 atomicity guarantee that orchestrator crash-recovery relies on, and Cargo's default `"3"` shorthand would let `cargo update` move the resolved version inside the 3.x range without anyone noticing.

When adding any other dependency on a security-critical path, follow the same pattern (exact pin + a comment explaining why).

### Workspace-wide invariants

- `#![forbid(unsafe_code)]` is set in the root workspace lints — do not introduce `unsafe`. If a primitive truly needs FFI, isolate it in its own crate behind a reviewed boundary.
- Clippy must stay clean with `-D warnings`. Don't ship a PR with new warnings expecting them to be cleaned up later.
- KATs in `core/tests/data/*.json` are pinned against published vectors (NIST FIPS 203 / 204, RFC 8032 / 7748 / 5869 / 9106, BIP-39 Trezor canonical). When upgrading a primitive crate, re-run KATs explicitly — a passing test suite is necessary but not sufficient.

### Memory hygiene: zeroize discipline

Every secret-bearing byte string is wrapped in `Sensitive<T>` or `SecretBytes` ([core/src/crypto/secret.rs](core/src/crypto/secret.rs)) — both derive `Zeroize, ZeroizeOnDrop`. Composite types (`IdentityBundle`, `UnlockedIdentity`, `Mnemonic`) drop their secret fields in source order. Any time you `Sensitive::new(stack_var)` where `stack_var: [u8; N]`, follow with `stack_var.zeroize()` to overwrite the source slot — the move copies (`[u8; N]: Copy`) and the bytes linger otherwise. The pattern lives in `crypto::kem::derive_wrap_key`, `crypto::kdf::derive_master_kek`/`derive_recovery_kek`, `crypto::sig::generate_ed25519`, etc.

**`RecordFieldValue` is zeroize-typed** as of PR #16: `Text(SecretString)` and `Bytes(SecretBytes)` (both `Zeroize, ZeroizeOnDrop`). The previously-unzeroized `Text(String) / Bytes(Vec<u8>)` form has been retired. Don't add new secret-bearing fields to `Record` / `RecordField` without thinking about whether they should be zeroize-typed — and don't widen the existing fields' lifetimes (e.g. by stashing them in caches, hash maps, or async closures) without weighing the same tradeoff.

### Internal audit memos

Phase A.7's internal hardening track produced three contributor-facing memos in [docs/manual/contributors/](docs/manual/contributors/):

- [`differential-replay-protocol.md`](docs/manual/contributors/differential-replay-protocol.md) — cross-language decoder-agreement contract used by the fuzz harness.
- [`side-channel-audit-internal.md`](docs/manual/contributors/side-channel-audit-internal.md) — constant-time-sensitive call sites + upstream-crate assumptions for the paid external reviewer.
- [`memory-hygiene-audit-internal.md`](docs/manual/contributors/memory-hygiene-audit-internal.md) — wrapper discipline + drop ordering + the twelve stack-residue gaps fixed in commit `6054185`.

Together these are the **principal handoff documents** for the paid external review. When you change a secret-handling code site or a constant-time-sensitive comparison, re-read the relevant memo's section first to make sure the change preserves the documented invariants.
