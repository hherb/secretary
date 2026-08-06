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

# Assert no `privacy: .public` log line renders an error by hand (#467): the only
# sanctioned renderer is `diagnosticDetail`. Same `--self-test`-first discipline,
# two-sided here (must fire on a known-positive AND stay silent on a
# known-negative). Pure grep — runs on Linux, wired into test.yml.
bash ios/scripts/check-public-log-hygiene.sh --self-test
bash ios/scripts/check-public-log-hygiene.sh

# Assert no raw Throwable reaches logcat (#472). logcat has NO redaction concept,
# so rule A pins every logcat sink — `android.util.Log` AND the stdout/stderr the
# runtime redirects into it — to one sanctioned file (SecretaryLog) whose
# signatures make the unsafe 3-arg call unrepresentable; rules B1/B2/B3/C deny
# hand-rendering a throwable into a String. Same --self-test-first discipline.
bash android/scripts/check-log-hygiene.sh --self-test
bash android/scripts/check-log-hygiene.sh

# Assert no `core` error variant interpolates a runtime String into its
# #[error] message (#474), AND no bridge-authored `detail`/hex-field carries
# one construction site can't vouch for (#480). RecordError::DuplicateKey
# formatted a decrypted CBOR field name, which is why both platforms once
# redacted whole error arms. `core/src/**` payload types are data-free by
# construction; `ffi/secretary-ffi-bridge/src/**`'s six gated field names
# (`detail`, `uuid_hex`, `block_uuid_hex`, `recipient_fingerprint_hex`,
# `expected_fingerprint_hex`, `got_fingerprint_hex`) are gated by CONSTRUCTION
# SITE instead — every one must route through `error/detail.rs` (rules
# E2/E3/E4). Both scan roots fail in the Rust author's own PR rather than
# degrading a platform two layers away. Default-deny: an unrecognised payload
# type is a FAILURE, not a pass.
uv run scripts/check-error-payload-hygiene.py --self-test
uv run scripts/check-error-payload-hygiene.py
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

### Swift log hygiene: default-deny at `privacy: .public` (#467)

The iOS/macOS tree logs diagnostics at `os.Logger`'s `privacy: .public`, which
disables the unified log's default redaction so a line survives into a sysdiagnose
(#456). That is sound only while no error reaching such a site carries a secret —
and that used to be a doc-comment convention. It is now structural:

- **`SecretFreeError`** ([ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/SecretFreeError.swift](ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/SecretFreeError.swift)) is the allowlist. Conforming a type is a **security decision** — a claim that its diagnostic text carries no vault plaintext, password, mnemonic, or key bytes. It is a *rendering* protocol, not a bare marker: a type safe in most cases but secret-bearing in one overrides `diagnosticDescription` and redacts at source rather than being excluded wholesale.
- **`diagnosticDetail(_:)`** is the only sanctioned renderer, and it **default-denies**: an unconformed type is never described, degrading to `<undisclosed <Type> domain=… code=…>`. `userInfo` is deliberately never read. The `NSError` branch is load-bearing — a Foundation file error arrives in a `catch` with dynamic type `NSError`, so `as? SecretFreeError` fails even when `CocoaError` conforms.
- **`foldDiagnostic(_:)`** ([DiagnosticLog.swift](ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/DiagnosticLog.swift)) applies the policy once at each of the 23 view-model fold sites: it logs the gated detail *and returns it* for the typed error's carried payload, so the two cannot drift apart and a new fold site cannot set a payload without logging.
- `DeviceUnlockError`'s conformance lives in `SecretaryKit`, not `SecretaryVaultAccess` — the latter does not depend on `SecretaryDeviceUnlock`. Swift registers conformances process-globally, so the cast still finds it at runtime.

Adding a new `.public` log site means calling `diagnosticDetail`; adding a new error
type that reaches one means conforming it after review. Forgetting either degrades a
log line — it never leaks. `ios/scripts/check-public-log-hygiene.sh` enforces the
first half; nothing but review enforces the second.

The guard's exceptions live in `ios/scripts/public-log-hygiene-allowlist.txt`, keyed
on the **exact trimmed source line** rather than a substring — a substring entry
exempts every future line in the same file that happens to contain it, which was
demonstrably exploitable. Re-indenting an exempted line keeps the entry valid;
editing its content does not, so a bypass line cannot be quietly repurposed. Adding
an entry is a security decision; rules 1 and 2 deny by default, rule 3 (bare
`"\(error)"` interpolation) is an explicitly-labelled best-effort denylist because
no line-based matcher can cover that class without parsing Swift.

### Kotlin log hygiene: there is no `.public` to opt into (#472)

logcat has **no redaction concept**. There is no `privacy:` qualifier to set —
every line is readable via `adb logcat` on a debuggable build and is captured
into bug reports, so every line is the equivalent of iOS's `privacy: .public`.
The sink itself is therefore what gets guarded, not a marker on it.

- **`SecretFreeThrowable`** ([android/vault-access/src/main/kotlin/org/secretary/diagnostics/SecretFreeThrowable.kt](android/vault-access/src/main/kotlin/org/secretary/diagnostics/SecretFreeThrowable.kt)) is the allowlist, and declaring it is a **security decision** — the same claim `SecretFreeError` makes on iOS. It is a *rendering* interface: an arm that is secret-bearing overrides `diagnosticDescription` and redacts at source instead of the whole type being excluded.
- **Kotlin has no retroactive conformance.** iOS's one real retroactive conformance — [`extension DeviceUnlockError: @retroactive SecretFreeError {}`](ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/SecretFreeErrorConformances.swift) (`SecretFreeErrorConformances.swift:47`) — has no Kotlin equivalent, so JDK, Android-framework and uniffi-generated throwables can *never* implement the interface — and those are exactly the types that arrive at a `catch (e: Exception)`. The deny path is the **normal** path here, not the degenerate one. That is why `diagnosticDetail` appends the **cause chain as fully-qualified type names**: a class name is a compile-time constant and cannot carry runtime data, so the chain is as fail-closed as a bare marker while recovering most of what the stack trace was worth.
- **`SecretaryLog`** ([android/kit/src/main/kotlin/org/secretary/diagnostics/SecretaryLog.kt](android/kit/src/main/kotlin/org/secretary/diagnostics/SecretaryLog.kt)) is the only file in the tree permitted to reference `android.util.Log`, and it has **no overload that hands a `Throwable` to it**. The three-argument `Log.w(tag, msg, throwable)` form prints `toString()` — class name plus message — for the throwable and every cause, so making it unrepresentable at call sites is the whole mechanism. This is the `foldDiagnostic` analogue: policy applied once, in one place.
- **`SaveCryptoFailure` / `CorruptVault` are no longer redacted — and the reason
  they once were is the reason #474 exists.** `BrowseMapping.kt:27` maps
  `SaveCryptoFailure` explicitly and carries the raw Rust detail, which via the
  bridge's fold of `VaultError::Record(_)` was `RecordError::DuplicateKey`'s
  decrypted CBOR field name. Both platforms redacted the arm wholesale, losing
  the detail for every corruption diagnostic rather than just the leaking one.
  #474 fixed it at the source instead: plaintext-bearing `core` error payloads
  carry a `&'static str` map-level hint plus an ordinal, never the key, and the
  `ciborium` message — whose `Display` is its `Debug` form — is discarded at the
  boundary by `core/src/cbor.rs`. **`InvalidArgument` stays redacted on both
  platforms**: its payload is platform-authored — `RecordEditModel.kt:179`/`:193`
  (Kotlin) and `RecordEditViewModel` (Swift) each interpolate a decrypted
  record's field name into it — so #474's data-free-by-construction guarantee
  does not reach it. No issue tracks that payload class itself; #473 / #476
  track the separate question of these carried diagnostics being rendered as
  on-screen copy. Do not sweep it into "align the platforms".

- **Conform the wrapper types you own.** `diagnosticDetail` default-denies, so an internally-authored wrapper left unconformed does not merely lose its own text — every nested wrap that renders it through the gate discards the message it was just built to carry. `CloudFolderException` / `VaultMirrorException` / `DeviceUuidException` were missed in #472 and the entire cloud-sync failure path collapsed to `<undisclosed org.secretary.mirror.CloudFolderException>`, throwing away `SafCloudFolderPort`'s own gating one frame later (fixed in #475). Default-deny is the right default for types you did NOT author; for a type whose every construction site is a fixed Kotlin literal, conforming it is the whole point of the interface. Assert on message CONTENT when you do — the pre-existing mirror tests asserted only on exception TYPE, which is why this shipped unnoticed.

Adding a log site means calling `SecretaryLog`; adding an error type that reaches
one means declaring it `SecretFreeThrowable` after review. Forgetting the second
degrades a log line to `<undisclosed …>` — it never leaks.
`android/scripts/check-log-hygiene.sh` enforces the first; nothing but review
enforces the second.

The allowlist (`android/scripts/log-hygiene-allowlist.txt`) is keyed on the
**exact trimmed source line**, never a substring — same semantics and same
reasoning as #467's. It is split into three sections by review weight: *security
decisions* (rules B1/C — a value that can carry a secret; rule A is an
absolute prohibition enforced by the sanctioned-file constant and never has
entries), *the policy itself* (rule B3 — the two `toString()` self-renders that
ARE the sanctioned rendering), and *non-throwable receivers* (rule B2 only — the
receiver simply is not a `Throwable`). Keeping the first section short is what
keeps its entries meaningful.

**`is_comment_line` is a security control, and it lives in
`scripts/lib/hygiene-allowlist.sh` beside `allowlisted` because both guards need
the same copy.** Everything it calls prose is unscanned against *every* rule, so
its bugs are blanket bypasses. It has had two, and they are the same mistake on
opposite sides of a block comment: `/* */ <code>` (round 1) and `*/ <code>` on
the second line of a two-line comment (#475, which affected the iOS guard too).
Both are pinned by positive controls on both platforms. If you touch it, mutate
it and watch `CM3`-`CM5` / `P19`-`P20` fail.

### Rust error payloads: data-free by construction (#474)

`RecordError::DuplicateKey` used to format a decrypted CBOR field name into its
`#[error]` message. That string reached iOS as `VaultAccessError.corruptVault`
and Android as `VaultBrowseError.SaveCryptoFailure`, and because Rust owned the
only copy of the leak, both platforms had no cheaper fix than redacting those
arms wholesale — losing the detail for every corruption diagnostic, not just
the leaking one. #474 fixed it at the source: every `core` error payload is now
one of three reviewed shapes.

- **Plaintext-bearing.** A field or key name that could echo decrypted content
  is replaced by a `&'static str` map-level hint plus an ordinal (e.g.
  `RecordError::DuplicateKey { field: &'static str, index: usize }`,
  mirrored by `BlockError::DuplicateKey`) — compile-time constants standing in
  for the runtime value, never the value itself.
- **`ciborium` passthrough.** `ciborium`'s `Display` is its `Debug` form, and
  `Error::Semantic` / `Error::Value` each carry a `serde::de::Error::custom`
  message that can embed the offending value. [`core/src/cbor.rs`](core/src/cbor.rs)
  is the **only** place in the tree that ever sees that upstream message —
  `classify_de` / `classify_ser` discard it and project onto a fieldless
  `CborErrorKind` plus an optional byte offset (`CborFault`), so the message
  cannot reach an error variant regardless of what a future `ciborium` version
  does.
- **Already-disclosed.** A handful of variants carry content the threat model
  already treats as public — `vault.toml` is cleartext on disk (vault-format
  §2), and `std::io::Error`'s path + errno is visible to anyone who can read
  the vault folder. These are reviewed, individually justified allowlist
  entries, not a structural exemption.

The guard is [`scripts/check-error-payload-hygiene.py`](scripts/check-error-payload-hygiene.py)
(see the Commands block above), and it fails closed: an unrecognised payload
type is a FAILURE, not a pass. Its allowlist
([`scripts/error-payload-hygiene-allowlist.txt`](scripts/error-payload-hygiene-allowlist.txt))
is sectioned by review weight; the highest-weight section (Section 3) holds
**construction-site claims the guard structurally cannot verify** — it sees
DECLARATIONS (a field's type), not producers (what every call site actually
passes into that field), so an entry there is a point-in-time claim, verified
by reading every current constructor, that no producer interpolates vault
plaintext. Re-verify it whenever a producer changes. #480 closed #478 the
broad way: the guard's scan roots now also cover
`ffi/secretary-ffi-bridge/src/**`, via three more rules (`E2`/`E3`/`E4`).
`E2` permits a bridge error's `String` field only under one of six PINNED
names (`detail`, `uuid_hex`, `block_uuid_hex`, `recipient_fingerprint_hex`,
`expected_fingerprint_hex`, `got_fingerprint_hex`); `E3` requires every
construction site of a gated field to be a literal or a call into
[`ffi/secretary-ffi-bridge/src/error/detail.rs`](ffi/secretary-ffi-bridge/src/error/detail.rs);
`E4` pins every `impl GatedDetail for X` enabling such a call to that one
file, naming a type this guard can see. Gated-field construction is
therefore CI-enforced: a new bridge producer that hand-rolls a `format!`
into a gated field fails in the Rust author's own PR — the same sink-pinning
move `SecretaryLog` (#472) and `diagnosticDetail` (#467) make for their own
platforms.

That does not mean every byte reaching a gated field is CI-verified from
here to its ultimate source — three named residuals are documented LIMITS in
the guard's own docstring and allowlist, not silent gaps:

- **`io::Error` payloads minted from a runtime string.** A bridge site can
  synthesize a `std::io::Error` from a `format!(...)` and hand it to `core`'s
  `VaultError::Io { source }`, which then reaches a gated field via the
  allowlisted `impl GatedDetail for std::io::Error` — `E3` gates the
  *bridge's* initializer expression, not what feeds `core`'s. One production
  site exists today
  ([`ffi/secretary-ffi-bridge/src/repair/orchestration.rs:137-147`](ffi/secretary-ffi-bridge/src/repair/orchestration.rs) —
  content disclosed today: a `StateError` Display plus the state-dir path); a
  second site of the same shape, unreachable from any gated fold since the
  bridge imports only `secretary_cli::{state, pipeline}`, is
  [`cli/src/daemon.rs:424`](cli/src/daemon.rs). Tracked by #487.
- **The three documented laundering shapes.** `E3` is a syntactic match on
  initializer position and field name; a local `let detail = format!(...)`
  re-wrapped via field shorthand, `detail: detail`, or a post-construction
  `x.detail = ...` assignment is invisible to it. Closing this needs local
  dataflow analysis. Tracked by #488.
- **Macro-generated code and trait aliasing.** Like `E1`, this guard reads
  text, not expanded macros — a `macro_rules!`-generated `#[error(...)]` or
  `impl GatedDetail for X` is invisible, and so is
  `use detail::GatedDetail as GD;`-style aliasing of the trait's own name.

The binding wrapper crates (`ffi/secretary-ffi-py`, `ffi/secretary-ffi-uniffi`)
remain entirely unscanned by `E1`-`E4`: `ffi/secretary-ffi-py` constructs zero
gated-field details, and `ffi/secretary-ffi-uniffi`'s non-`InvalidArgument`
sites are censused (2026-08-05) as fixed literals or verbatim pass-throughs
of already-bridge-gated strings. That is a review-only trust boundary today,
not a CI one — tracked by #486.

### Memory hygiene: zeroize discipline

Every secret-bearing byte string is wrapped in `Sensitive<T>` or `SecretBytes` ([core/src/crypto/secret.rs](core/src/crypto/secret.rs)) — both derive `Zeroize, ZeroizeOnDrop`. Composite types (`IdentityBundle`, `UnlockedIdentity`, `Mnemonic`) drop their secret fields in source order. Any time you `Sensitive::new(stack_var)` where `stack_var: [u8; N]`, follow with `stack_var.zeroize()` to overwrite the source slot — the move copies (`[u8; N]: Copy`) and the bytes linger otherwise. The pattern lives in `crypto::kem::derive_wrap_key`, `crypto::kdf::derive_master_kek`/`derive_recovery_kek`, `crypto::sig::generate_ed25519`, etc.

**`RecordFieldValue` is zeroize-typed** as of PR #16: `Text(SecretString)` and `Bytes(SecretBytes)` (both `Zeroize, ZeroizeOnDrop`). The previously-unzeroized `Text(String) / Bytes(Vec<u8>)` form has been retired. Don't add new secret-bearing fields to `Record` / `RecordField` without thinking about whether they should be zeroize-typed — and don't widen the existing fields' lifetimes (e.g. by stashing them in caches, hash maps, or async closures) without weighing the same tradeoff.

### Internal audit memos

Phase A.7's internal hardening track produced three contributor-facing memos in [docs/manual/contributors/](docs/manual/contributors/):

- [`differential-replay-protocol.md`](docs/manual/contributors/differential-replay-protocol.md) — cross-language decoder-agreement contract used by the fuzz harness.
- [`side-channel-audit-internal.md`](docs/manual/contributors/side-channel-audit-internal.md) — constant-time-sensitive call sites + upstream-crate assumptions for the paid external reviewer.
- [`memory-hygiene-audit-internal.md`](docs/manual/contributors/memory-hygiene-audit-internal.md) — wrapper discipline + drop ordering + the twelve stack-residue gaps fixed in commit `6054185`.

Together these are the **principal handoff documents** for the paid external review. When you change a secret-handling code site or a constant-time-sensitive comparison, re-read the relevant memo's section first to make sure the change preserves the documented invariants.
