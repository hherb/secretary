# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

**Secretary** is a multi-platform, client-only secrets manager. The Rust cryptographic core and on-disk vault format (**Sub-project A**) are feature-complete and frozen for v1, and all three downstream phases are substantially built on top of it: **Sub-project B** (FFI bindings — the `secretary-ffi-bridge` crate projected onto PyO3 + uniffi) is complete through B.6 v2 and beyond (device-slot ops, record-edit + block-CRUD primitives, sync surface); **Sub-project C** (sync orchestration) is complete through C.4; and **Sub-project D** (platform UIs) ships working apps — a Tauri 2 desktop client (`desktop/`), a native SwiftUI iOS app (`ios/`), and a native Jetpack Compose Android app (`android/`). See [README.md](README.md) "Project status" and [ROADMAP.md](ROADMAP.md) for the authoritative per-slice state. The Rust core remains the single source of truth for everything security-relevant; the platform code consumes it, never reimplements it.

The cryptographic design and on-disk format are **frozen for v1** because vaults written today must remain readable by clients written decades from now. Treat anything in `docs/crypto-design.md`, `docs/vault-format.md`, and `docs/threat-model.md` as the source of truth — the Rust code implements those, not the other way around.

## Layout

```
core/                Rust crate `secretary-core` — the security-critical source of truth
core/src/{crypto,identity,unlock,vault}/   — module per spec section
core/src/vault/manifest/                   — DIRECTORY module (#564), not manifest.rs; 26 files:
                                             13 production, 11 sibling `tests.rs`, and two
                                             `#[cfg(test)]` files under `test_support/`
core/tests/          — integration tests; tests/data/ holds KATs and fuzz regressions
core/tests/python/conformance.py           — clean-room verifier ENTRYPOINT (136 lines; the PEP
                                             723 header is the sole dependency declaration).
                                             `conformance.py:NNN` citations predating #593 are
                                             stale — the verifier is now a 58-file package.
core/tests/python/conformance_lib/         — DIRECTORY module (#593), the verifier itself: no
                                             dependency on `secretary-core`; proves the spec is
                                             implementable from `docs/` alone. `wire/` parses to
                                             INSPECT, `codec/` parses to RE-EMIT byte-identically,
                                             `merge/` is §11 CRDT, `sections/` holds the replay
                                             drivers and the registry `main()` iterates
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
# cfg-active code, so run on both Linux and macOS to catch platform-gated links).
# Gotcha: widening a `use` can red this gate without touching a single doc
# comment — a bare `[Foo]` shorthand only resolves once `Foo` is imported, and
# once it does, a pre-existing explicit `[Foo](crate::path::Foo)` link becomes
# REDUNDANT and trips `redundant_explicit_links` (#542 hit this: widening
# `use crate::crypto::secret::Sensitive;` to `{SecretBytes, Sensitive}` made a
# neighbouring explicit `[SecretBytes](crate::crypto::secret::SecretBytes)`
# link redundant in the same stroke).
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

# Assert no error payload crossing the FFI carries a runtime String nobody
# has vouched for (#474, #480, #486). RecordError::DuplicateKey formatted a
# decrypted CBOR field name, which is why both platforms once redacted whole
# error arms. Four scan roots (`core/src/**`, the FFI bridge, and the two
# binding wrapper crates) under five rules: E1 data-free-by-construction
# declarations (all four roots); E2 six PINNED gated field names, each
# declared with the type spelling that root accepts (per-root as of #500:
# `Detail` on the bridge, `String` on the two wrappers); E3 gated
# construction sites must be a string literal, a call into that root's
# sanctioned `detail::*` module, or a same-name re-wrap — nothing else
# (bridge + both wrapper roots; a fifth shape, the wrapper-only single-hop
# DTO pass-through, was retired in #497/#500 once all four of its sites
# moved onto a sanctioned constructor); E4 `impl GatedDetail` pinned to one file
# (bridge-only); E5 `format!` confined to each wrapper crate's own detail.rs
# (wrapper-only); E6 the `Detail(` tuple-struct constructor pinned to that
# same one file, and no submodule declared there beyond `private`/`tests`
# (bridge-only, #515 — Rust privacy is module-SUBTREE scoped, so without
# this a one-line `mod ext;` relocates minting into an unreviewed file).
# Default-deny: an unrecognised payload type is a FAILURE, not a pass.
uv run scripts/check-error-payload-hygiene.py --self-test
uv run scripts/check-error-payload-hygiene.py

# Assert the bridge's `test-support` feature is enabled ONLY from a
# [dev-dependencies] section (#500). `Detail::for_test` can mint a `Detail`
# from arbitrary runtime text; it is absent from shipped artifacts ONLY
# because Cargo's resolver v2 declines to unify a DEV-dependency's requested
# features into a non-test build. This guard denies the manifest line that
# would put it back — including via a feature ALIAS that transitively reaches
# it — over a `tomllib` parse, not a line matcher.
uv run scripts/check-test-support-placement.py --self-test
uv run scripts/check-test-support-placement.py

# Assert no move-out construct defeats a zeroize-on-drop wrapper (#521).
# `mem::swap`/`replace`/`take`/`forget` and `ManuallyDrop` do not merely leak —
# they make the wrapper's own wipe VACUOUS, so the code still looks protected.
# Tree-wide over EIGHT roots, NOT scoped to a `build` closure (ManuallyDrop is
# not confined to one), and test code IS scanned: #496 proved a `#[cfg(test)]`
# carve-out is fail-OPEN. Same --self-test-first discipline; probes go to
# `mktemp -d`, never the source tree (cf. #516).
#
# FAILS CLOSED ON ITS OWN WIRING, which the first version did not: a declared
# root that is MISSING or holds no `*.rs`, a `grep` that exits >=2 (unreadable
# file, bad ERE), an unparseable root manifest, and an unrecognised CLI
# argument are each fatal. Every one of those used to print `OK` and exit 0 —
# a tree containing none of the roots reported "OK (6 roots, …)" having read
# nothing, which is #496's `Path.rglob` fail-open restated in bash. The
# self-test now drives `run_guard` itself (not just the matchers) and asserts
# the EXIT CODE in both directions.
#
# ROOT COVERAGE IS CHECKED AGAINST THE MANIFEST, the treatment #505 gave the
# payload guard: a `[workspace] members` entry with a `src/` that is in
# neither SCAN_ROOTS nor UNSCANNED_MEMBERS is a hard failure. That is what the
# first version needed — it hand-listed six roots and omitted
# `browser/secretary-browser-host`, a secret-bearing member (device secret,
# master password) holding two live S1 producers, so its "the census is empty"
# and "ships with an EMPTY allowlist" claims were properties of the root list
# rather than of the tree. The allowlist now carries those two reviewed rows.
#
# LIMITS (see the script's own header for the full text): both rules match by
# SPELLING, not resolved identity. Module/item aliasing is NOT symmetric — a
# `use std::mem as m;` then `m::swap(..)` evades rule S1 entirely (neither the
# import nor the call site contains a `mem::<verb>` substring), while aliasing
# `ManuallyDrop` still requires writing that identifier once on its `use` line,
# which S2 matches — do not flatten the two into one claim. Every rule reads
# TEXT, not expanded macros, so a macro-generated move-out is invisible. Trees
# that are not workspace members are outside the manifest check entirely
# (`core/fuzz` is `exclude`d), as is any non-`src/` directory inside a member —
# so `core/tests/**`, `cli/tests/**`, `ffi/*/tests/**` and `core/examples/` are
# unscanned. Zero live producers of the aliasing evasion today; tracked as
# #545, same root cause as #512/#517. Do not widen the regexes to close it —
# #545 owns that, deliberately deferred so this LIMITS text and the guard's
# actual behaviour don't drift apart.
bash scripts/check-secret-slot-hygiene.sh --self-test
bash scripts/check-secret-slot-hygiene.sh
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

`docs/crypto-design.md` and `docs/vault-format.md` are not generated docs — they're the contract. A clean-room implementation in any other language must be possible by reading `docs/` alone, and that property is enforced by `core/tests/python/conformance.py`, which depends on no `secretary` code — only generic crypto primitives declared via its PEP 723 header (`cryptography`, `pynacl`, `pqcrypto`, `argon2-cffi`, `blake3`, `cbor2`; top-level imports stay stdlib-only, these are lazy-imported) — to:

1. Decap + AEAD-decrypt + hybrid-verify the `core/tests/data/golden_vault_001/` reference vault.
2. Replay 11 CRDT merge KATs from `core/tests/data/conflict_kat.json` cross-language.
3. Run the `--diff-replay` mode used by the fuzz harness for decoder-agreement checks.

Practical consequence: when a Rust change alters observable byte format or merge semantics, the spec doc is the first thing to update, and `conformance.py` is the test that proves the docs and code still agree. **Don't fix divergence by changing one side silently.** A disagreement is one of: Rust bug, Python bug, or spec ambiguity — all three need to be resolved explicitly.

**`conformance.py` is a thin entrypoint over `conformance_lib/` (#593).** The file
was 6849 lines; it is now 136, over a 58-file package whose largest module is still
`merge/records.py` at 383 lines — by ONE line over
`sections/required_key_determinism.py` at 382, so treat that title as contested
rather than settled (52 files at the #593 split; #594 added
`sections/manifest_uniqueness_kat.py`; #597 added three, and its review round a
fourth; #600 added `codec/array_uniqueness.py`). Two properties are
load-bearing and a change that breaks either defeats the point of the split:

- **The PEP 723 header in `conformance.py` is the SOLE dependency declaration.** There
  is no `pyproject.toml` and the package declares nothing of its own. Adding one would
  let the installed set drift from the declared set, which is the clean-room claim.
- **`uv run core/tests/python/conformance.py` must keep working verbatim from any
  working directory.** Three callers depend on the exact invocation — this file, the
  `clean-room conformance` job in `test.yml`, and `core/tests/differential_replay.rs`,
  which shells out to it per fuzz input. The `conformance_lib` import resolves because
  Python puts the ENTRYPOINT's directory on `sys.path[0]`; it is not a CWD property.
  Every fixture path hangs off one anchor (`fixtures.test_data_dir`) rather than being
  re-derived per helper, which is what made the one-level-deeper `__file__` a
  single-line fix instead of nine.

`main()` no longer carries each section three times (call, banner, `FAIL:` line) plus a
term in a 22-term `and` chain — omitting that term was silent and **fail-open**, scoring
a failing section green. `sections/registry.py` declares each section once and derives
all four. Its dual — a section module that exists but is never registered, which
produces no output and no failure — is closed by Section **REG**
(`sections/completeness.py`), which discovers drivers by SHAPE and compares against the
table. Both directions are mutation-proven. Adding a section means one `Section(...)`
row; forgetting it reds REG.

**A rejection detail is deterministic, and that is now a section rather than a
convention (#597).** **Three** of the seven required-key presence checks in
`codec/` were `for k in SOME_REQUIRED_SET: if k not in decoded: raise`, and a set
of strings iterates in hash order — salted once per PROCESS — so an input missing
more than one required key named a different one from run to run. The other four
already wrote `sorted(...)` by hand, which is what a hand-copied rule looks like
after a while: not one rule with a gap, seven independent copies of which three
were wrong. Only the
`detail` text moved (`status` / `error_class` were stable, and
`differential_replay.rs` scores reject-vs-reject as agreement without comparing
`detail`), so no gate was flaky; what it cost was a byte-exact `--diff-replay`
baseline, which needs `PYTHONHASHSEED` pinned — a trap for the one task that
wants such a baseline, proving a refactor changed nothing. All seven sites now
route through `codec/required_keys.py`'s `first_missing_key_in_sorted_order`,
which names the rule so a caller list does not have to remember it, and Section
**DET** pins three things: byte-identical probe output across eight
`PYTHONHASHSEED` values (spawned as subprocesses — a hash salt cannot be varied
from inside one interpreter), the lex-first choice with a per-case ambiguity
control (restoring the reported key must move the rejection onto the next one,
so the fixture's ambiguity is demonstrated by the DECODER rather than asserted
by its table), and both structural directions — every helper call site under
`codec/` has a case, and no `codec/` construct selects a key from a required-key
set without imposing an order first (a `for`, an `async for`, a comprehension, a
generator, or a set difference — the rule keys on the ORDER, not the statement
form).
**The structural half's limits are enumerated in
`sections/required_key_structure.py`, not here** — it was split out of the
section in the #605 review precisely so the rules and their LIMITS block sit in
one file and cannot drift from a summary. Read it there. The short version:
it scans `codec/` recursively and nowhere else; it recognises a required-key set
by NAME SHAPE (`REQUIRED` / `*_KEYS` / `*_FIELDS`, case-insensitively) or as a
bare set literal; it resolves no names, so `sorted` is whatever a module binds
to that identifier; and `ast.Subscript` iterables have no identifier to test.

**That paragraph used to be the overclaim it warns against**, which is worth
keeping on the record because it is this file's most-repeated finding turned on
itself. It opened "since a summary that names only the easy limit is the failure
mode this file keeps re-finding", named three gaps, and missed five — every one
of them a spelling of #597 that scanned GREEN when planted: a generator
expression or comprehension (the check walked `ast.For` only), `for k in
frozenset(X)` / `list(X)` (the docstring reasoned that an `ast.Call` means
"mediated", which is true of `sorted` and false of every other constructor),
`for k in mod.REQUIRED_KEYS` (`ast.Attribute`, not `ast.Name`), and
`absent = REQUIRED - set(d)` then `absent.pop()` — the idiom `wire/card.py`
itself uses, which the probe's docstring holds up as the sanctioned eighth site,
so the likeliest thing for a future author to copy without its `sorted(...)`.
The rules now key on WHAT IMPOSES AN ORDER rather than on which statement form
is written, and each of the five reds.

The census is a two-way set comparison keyed by enclosing function, and it now
also rejects TWO helper calls sharing one key — per-function parity is still
parity, and a second check inside `py_decode_trash_entry` scored GREEN under
`PASS 7 … each matched to its own case`. It matches both `helper(...)` and
`required_keys.helper(...)`; an `import … as` alias is still invisible. The
module defining the helper is no longer skipped, because it never needed to be
— a `def` is not an `ast.Call` — and the skip it replaced was keyed on
BASENAME, which once `rglob` started recursing silently dropped a live call site
in `codec/<sub>/required_keys.py`. `wire/card.py` is the one required-key check
deliberately outside the helper, reporting the whole sorted missing set instead.

**Checks 1 and 2 verify the tree check 3 scanned, and that is now asserted
rather than assumed.** `python -m` puts the child's CWD on `sys.path[0]` ahead
of `PYTHONPATH`, so running the verifier from a directory holding another
`conformance_lib` had the probe measure one tree while the scans read another —
measured PASS, all eight lines, on a tree carrying the verbatim #597 defect. The
child's CWD is pinned and the probe reports the package it loaded. Three sibling
fail-opens closed with it: a probe emitting `[]` skipped check 2 in full with no
issue and no diagnostic; `_HASH_SEEDS = ("0",)` passed while printing "across 1
PYTHONHASHSEED values"; and a row-shape mismatch raised out of `main()` as a
traceback with no `FAIL:` line.

**It runs in CI as the `clean-room conformance` job, and until #546 it did not.** This paragraph used to say the property was "enforced every CI run", which was false: no workflow invoked the script, and its only in-tree invocation — `core/tests/differential_replay.rs` — is `#![cfg(feature = "differential-replay")]`, off by default and never enabled in `test.yml`. The cost of that gap is on the record: `conformance.py` pinned `pqcrypto>=0.3` unbounded, 1.0.0 changed `ml_dsa_65.verify` from returning a bool to **raising** on failure, and every ML-DSA-65 check reported "rejected" — including the golden vault's genuinely valid contact card — on `main`, undetected, until someone ran the script by hand. Fail-closed, so nothing was wrongly accepted, but the gate was non-functional. **The job now BLOCKS**, which this paragraph denied until the #599 review measured it: `clean-room conformance` is one of the 24 required contexts in `main`'s `protect_main` ruleset (`gh api repos/hherb/secretary/rules/branches/main`). The sentence "the job is not in `main`'s `protect_main` ruleset until added there by name, so it runs without blocking" outlived its fact — and a stale claim in this direction is not harmless, because it gets a real gate discounted when someone weighs whether a Python-side-only pin is enough. One standing consequence remains: five of the six PEP 723 deps are still unbounded (`cryptography`, `pynacl`, `argon2-cffi`, `blake3`, `cbor2`), and `ed25519_verify` has the same "no exception means success" shape `ml_dsa_65_verify` had — with `cryptography`'s `Ed25519PublicKey.verify` the failure direction would be fail-**open**. #544 tracks the migration; #550 tracks the `ed25519_verify` regression test.

### Crypto layering

Each `core/src/{crypto,identity,unlock,vault}` module corresponds to a section of the spec. Hybrid constructions are intentional and live throughout:

- KEM = X25519 ⊕ ML-KEM-768 (both must work for an attacker to recover plaintext).
- Signatures = Ed25519 ∧ ML-DSA-65 (**both** must verify, AND not OR; this is checked at every signature-verification call site).
- Argon2id v1 default is m=256 MiB, t=3, p=1 (`Argon2idParams::V1_DEFAULT`); v1 floor is m=64 MiB (`V1_MIN_MEMORY_KIB`), iter ≥ 1, par ≥ 1. The floor is enforced at **vault creation** as a typed error (`UnlockError::WeakKdfParams` from `create_vault`) — `open_with_password` does NOT re-check the floor at read time (the spec does not require it). A tampered `vault.toml` still can't downgrade cost: a changed KDF param → different Master KEK → `wrap_pw` AEAD fails, and the orchestrator `open_vault` cross-checks `vault.toml [kdf]` against the signed manifest (`KdfParamsMismatch`). The floor would become load-bearing at open only if a future change-password/re-wrap flow re-derives the KEK from `vault.toml` params — that flow must route through `try_new_v1`.
- A **third, optional unlock path** exists as of ADR 0009: per-device wrap files `devices/<uuid>.wrap` (`file_kind 0x0004`) wrap the IBK under `device_kek = HKDF-SHA-256(device_secret)` (crypto-design §5a, vault-format §3a). It is additive — `identity.bundle.enc` is unchanged — and is the core foundation for B.3's Secure-Enclave/biometric key release. Folder ops live in `core/src/vault/device_slot.rs`; pure crypto in `core/src/unlock/device.rs`. The device open is also a first-class FFI **`Unlocker::DeviceSecret`** arm in `core/src/vault/orchestrators.rs::open_vault` (B.2, #201) — it goes through the *same* manifest verify-before-decrypt as the password/recovery paths, so the device path is never a weaker open. The FFI projection (`add_device_slot` / `open_with_device_secret` / `remove_device_slot`) lives in `ffi/secretary-ffi-bridge/src/device.rs` and is exposed on uniffi + pyo3; it surfaces 3 typed `FfiVaultError` variants (`DeviceSlotNotFound` / `WrongDeviceSecretOrCorrupt` / `DeviceUuidMismatch`) with wrong-length `device_uuid`/`device_secret` validated at the binding layer (`InvalidArgument`), since the bridge fns take `&[u8; 16]`/`&[u8; 32]`.

- **The owner's identity keys come from the AEAD-authenticated Identity Bundle, never from the vault folder (2026-09 audit, VL-1 / FF-1 / CR-1, Critical).** `contacts/<owner-uuid>.card` sits in the attacker-writable folder and is only self-signed, and the manifest's `author_fingerprint` + both signature halves sit OUTSIDE the AEAD AAD and the §8 signed range (vault-format §4.1). Until the fix, `read_and_verify_manifest` verified the manifest signature against whatever card was on disk, so a hostile cloud host could substitute a card carrying the owner's `contact_uuid` but the attacker's keys, re-sign the unchanged ciphertext under those keys, and have `open_vault` succeed — after which `owner_card` was the KEM recipient identity for every block write (three auditors reproduced plaintext recovery by execution). `read_and_verify_manifest` now requires the card's four public keys to equal `IdentityBundle`'s (`VaultError::OwnerCardKeyMismatch`, folded to `CorruptVault` in the bridge; regression `open_vault_neg.rs::open_vault_substituted_owner_card_key_mismatch_rejected`), and vault-format §4.3 step 7 states it normatively. Do not relax this to a fingerprint or uuid comparison — both are attacker-choosable.
- **Every post-open block read/re-key must go through `orchestrators.rs::read_verified_block_file` (2026-09 audit, VL-2, High).** `verify_block_fingerprints` runs once at open, but the `OpenVault` handle lives for the session; a hostile host can roll `blocks/<uuid>.cbor.enc` back to an older owner-signed version afterwards, and a plain `fs::read` + `decode_block_file` in `share_block`/`revoke_block_recipient` re-encrypted and re-signed the stale bytes as current — laundering the rollback into a fresh manifest signature and breaking the equal-clock invariant `repair_vault` relies on. The helper binds the bytes to the manifest's committed BLAKE3 fingerprint (`BlockFingerprintMismatch`); the bridge's `decrypt_block_plaintext` (read + every edit primitive) does the same. Regression: `share_block.rs::share_block_rejects_post_open_block_rollback`. A new reader that does its own `fs::read` reopens the hole.
- **The browser host's only secret source is dev-only and feature-gated (2026-09 audit, BR-1, High).** `DevFileSecretSource` (device secret from a cleartext hex file) compiles only under `browser/secretary-browser-host`'s `dev-secret-source` feature, enabled for tests through a self dev-dependency (the bridge's `test-support` placement pattern); `cargo build --release` produces a host that fails closed as not-enrollable (`ConfigError::SecretSourceUnavailable`) and no `secretary-browser-enroll` binary. The origin matcher additionally gates `registrable_domain` on `psl::Suffix::is_known()` (BR-2/BR-4): the PSL `*` rule made `1.2.3.4`/`5.6.3.4` and siblings under an unknown TLD "the same site". The KAT is 28 vectors.

- **iOS device unlock (B.3)** lives in `ios/`: a pure, FFI-free `SecretaryDeviceUnlock` package (`DeviceUnlockCoordinator` over `VaultDeviceSlotPort` / `DeviceSecretEnclave` / `DeviceEnrollmentMetadataStore`, typed `DeviceUnlockError`) host-tested via `swift test`, plus iOS adapters in `SecretaryKit/DeviceUnlock/` (the real uniffi port, the non-exportable Secure-Enclave P-256 conformer behind a biometric `SecAccessControl`, Keychain metadata). The SE conformer is compile-verified on the simulator with a fake enclave; **real Face ID release was proven on an iPhone 13 Pro Max (#202 ✅, 2026-06-11)** via the SwiftUI walking-skeleton app (`ios/SecretaryApp/`, an XcodeGen target over a host-tested `DeviceUnlockViewModel` in `SecretaryDeviceUnlock`'s `SecretaryDeviceUnlockUI` product). On-device, the `SecKeyCreateDecryptedData`-triggered biometric eval funnels cancel/non-match into `LAError.userCancel` (not `NSOSStatusErrorDomain`), and no failure mislabels as `wrappedSecretCorrupt`. The coordinator's `unlock` funnels through the same B.2 `open_with_device_secret` (hence the same manifest verify-before-decrypt) — it is not a weaker open. **iOS app-bundle gotcha:** a bundled folder literally named `Resources/` breaks on-device codesign ("code object is not signed at all"); `ios/SecretaryApp/` stages its demo vault under `Fixtures/` instead.

Whenever you touch a verification or KDF site, preserve the "both halves" property. Past review feedback caught a near-miss where ML-DSA verification failures were being swallowed at the call site; security-critical code reviews must prove enforcement, not assume it.

### CRDT merge: vector clocks + record-level death clock

`core/src/vault/conflict.rs` is the merge layer. The non-obvious bit is `tombstoned_at_ms` — a record-level death clock that closes the associativity gap that naive tombstone-on-tie semantics leave open. Four `proptest` properties (commutativity, associativity, idempotence, well-formedness) hold over the full record domain, including arbitrary tombstone-and-resurrection histories and arbitrary `unknown` keys. The Python clean-room equivalent lives in `conformance_lib/merge/records.py` as `py_merge_record` / `py_merge_unknown_map` (#593; it was `conformance.py` before the split).

If a CRDT change requires the proptests to weaken, that's a design problem. Push back; don't relax the property.

### Crash recovery: repair_vault and the equal-clock invariant (#350)

`core/src/vault/repair.rs` holds the crash-recovery layer: an open-time best-effort sweep completing interrupted trash renames (`trash_block` is **manifest-first** — the signed-manifest write is the commit point; the physical `blocks/ → trash/` move is best-effort), and `repair_vault`, which adopts crash-residue blocks whose fingerprint mismatches the manifest, behind hard gates (hybrid verify ∧ header binding ∧ clock freshness, all-or-nothing). The non-obvious, load-bearing invariant: **equal block clock ⇒ identical plaintext**. Content writes (`save_block`) tick the block vector clock; re-keys (`share_block` / `revoke_block_recipient` via `rewrite_block_with_recipients`) re-encrypt the *unchanged* plaintext and preserve the clock. `repair_vault` therefore refuses to adopt any recipient **widening** regardless of clock relation (fail-closed — re-granting access is never automatic): a legitimate crashed `save_block` re-encrypts to the *existing* recipient set so its `IncomingDominates` residue never adds a recipient, and a crashed re-key lands as `Equal` where only a strict-subset reduction is adopted. This guard is relation-independent on purpose — an earlier Equal-only version left the `IncomingDominates` arm able to re-grant a clock-invisible revoke via a planted owner-signed content-save. Soundness of the Equal tier rests on the equal-clock invariant; it holds *only while* that invariant holds. If you ever make a clock-preserving path mutate the plaintext, you MUST tick the block clock instead (guard comments at `rewrite_block_with_recipients`; normative in vault-format.md §6.5.1). Wall-clock `last_mod_ms` must never be used as a freshness signal — it has no monotonicity guarantee, and a timestamp-gated variant was demonstrated exploitable (revoked-recipient re-grant) during the #350 review.

### The manifest module, and what its canonical-input check does not catch

`core/src/vault/manifest/` is a **directory module** (#564) — `manifest.rs`
was 4273 lines and is gone. Any `core/src/vault/manifest.rs:NNN` citation you
find in a doc predates the split and is stale. **Watch for the near-miss:**
`ffi/secretary-ffi-bridge/src/vault/manifest.rs` is a DIFFERENT file that
still exists, and citations to it are valid — only ones resolving under
`core/src/` are stale.

`decode_manifest` re-encodes the parsed `Manifest` and requires a
byte-identical match against its input (#572), which is what `record::decode`
and `block::decode_plaintext` already did. **At this layer the check is
strictly stronger than at those two**, and deliberately so: `encode_manifest`
sorts five arrays on output (`vector_clock`, `blocks`, `trash`, per-block
`recipients`, per-block `vector_clock_summary`), so an array that arrives out
of sort order is rejected too. That is a wider rejection surface than "canonical
CBOR", on the path *every vault open* takes.

**Its rejection now says which rule and where (#590).**
`ManifestError::NonCanonicalEncoding` was fieldless, and its message named
four candidate causes with "e.g." — on that same every-open path, for the
reader most likely to hit it. It now carries a fieldless
`NonCanonicalCause` (`core/src/vault/manifest/cause.rs`) plus the byte
offset of the first divergence. Three things about it are load-bearing:

- **The cause is ADVISORY; the byte comparison is the verdict.**
  `classify_non_canonical` (`manifest/decode/classify.rs`) runs only once
  the comparison has already decided to reject, so even a wrong cause
  changes a diagnostic and never an acceptance. Do not promote it into the
  decision.
- **Advisory does NOT mean positional, and the first version's mistake was
  exactly that.** It read the CBOR head at the first differing byte. That
  is unsound whenever the divergence lands inside a string payload — which
  is where map-key disorder always puts it — so an ordinary character in a
  key (`_` = `0x5F`, `8` = `0x38`, `x` = `0x78`) was read as an
  indefinite-length or non-shortest-form head. `Manifest::unknown` keys are
  **wire data**, so a peer could choose which wrong cause a v1 client
  printed, for a body violating a different rule entirely — strictly worse
  than the message it replaced, which at least listed "key disorder" among
  its four candidates. Every arm is now **decisive**: `ArraySortOrder` off
  the parsed `Manifest`, `IndefiniteLength` / `NonShortestForm` off
  `find_encoding_violation`, an iterative walk of the whole body that skips
  string payloads by their declared length. `ArraySortOrder` still runs
  first, now only because it is cheaper and likelier. Pinned by
  `a_peer_cannot_choose_the_reported_cause_through_unknown_key_names` and
  `a_divergence_landing_on_a_payload_byte_is_unclassified`, both
  mutation-proven against the positional version.
- **`Unclassified` is a real outcome, not a bug.** Map-key disorder
  re-encodes to different bytes while every individual head stays
  canonical, so there is nothing in the body to find. Naming a cause there
  would make the diagnostic worse than silence;
  `decode_manifest_rejects_a_non_canonical_body` asserts the honest answer
  so a future "improvement" that guesses reds.

The `thiserror` derive on `NonCanonicalCause` is **not cosmetic**: the
payload guard credits an enum carrying `#[error(...)]` in its body as
data-free by recursion (tier 2 of `is_data_free`), so the variant needed no
allowlist row and no `DATA_FREE_TYPES` entry — which a plain fieldless
enum WOULD have needed, and which is what `CborFault`, a plain struct, did
need. The `at` offset is the same deliberate length-oracle disclosure
`CborFault::offset` already documents. `manifest_canonicality_kat_replays`
now asserts a cause for each of the **six** rejecting rows that reach the
re-encode, and pins the 6/3 split by count. Say "six", not "every rejecting
row": the corpus has **nine** rejects, and the three `rule4_float` ones are
caught earlier by `reject_floats_and_tags` and deliberately get no cause —
that negative is the whole point of the `FloatWalk` arm. A fact three
handoffs carried only in prose.

**The residual, stated exactly, because the obvious wider claim is false.**
Inside a forward-compat `unknown` subtree the check misses **duplicate map
keys and map-key order — and nothing else.** Every encoding-level
non-canonicality *is* rejected there: indefinite-length maps, arrays, text
and byte strings, and non-shortest-form integer and length prefixes. The
mechanism is the `from_secret_reader` call at the TOP of `decode_manifest`,
not anything on the unknown-key path: `ciborium`'s `Value` reader collapses
indefinite lengths and non-shortest heads at parse time, so any subtree is
already the *normalisation* of the wire bytes by the time it is examined, and
only properties `ciborium::Value` can still represent survive — `Value::Map`
is an ordered `Vec` of pairs, so entry order and repeats do. Do **not**
attribute this to `extract::value_to_unknown`'s re-serialise/re-parse hop;
that hop is an identity on an already-normalised `Value`, and `record.rs`,
which has no such hop, behaves identically. The practical consequence runs
the opposite way to the intuitive one: a v2 client that puts **one
indefinite-length item** inside an extension field makes those vaults
**unopenable by v1**.

**A SECOND residual, at the array level, and it is not an encoding rule at
all.** §4.2 forbids a repeated value in four of the five sorted arrays
(`vector_clock` and each `vector_clock_summary` by `device_uuid`, `blocks`
and `trash` by `block_uuid`); `recipients` is the **explicit exception** —
`parse_recipients` has no uniqueness check and a repeated `contact_uuid`
round-trips, since it denotes no additional grant. The re-encode catches
**none** of the four: sortedness and distinctness are independent — `[x, x]`
**is** sorted — and a body carrying a repeat re-encodes to itself byte for
byte, so the step-4 comparison never fires. They are enforced by explicit
adjacent-equality scans in `manifest/decode/entries.rs`, the same standing-
apart-from-the-re-encode arrangement `reject_floats_and_tags` has for rule 4.
`conformance.py` implemented the sort disciplines, ended with the re-encode,
and therefore **accepted all four repeat shapes** until #594 — the divergence
is now pinned cross-language by `core/tests/data/manifest_uniqueness_kat.json`
(6 rows, replayed by `manifest_uniqueness_kat_replays` and Section MUQ, plus
six `manifest_body` differential-replay seeds). Do **not** "tidy up" the
`recipients` asymmetry into a fifth rejection: that narrows a v1-frozen
decoder, and both `accepts_duplicate_contact_uuid_in_recipients` and the
corpus's `recipients__duplicate_contact_uuid` row exist to red when someone
tries. **#594's own text is unreliable on the spec half** — it reports these
rules as absent from `docs/` on the strength of `grep -c "uniq"` → 0, but the
spec says "Repeated values are forbidden" and has since `e29cb216`.

**The WRITER half is enforced too, as of #600, and the rule now lives in one
place per language.** §4.2 binds writers as well as readers ("writers MUST NOT
emit them and readers MUST reject them") and *neither* implementation enforced
the writer half: `encode_manifest` and `py_encode_manifest` could each emit —
and `sign_manifest` sign — a body their own decoders refuse. Availability, not
confidentiality: the manifest is owner-signed, so the producer is a caller in
this process (merge, repair, block CRUD all build a `Manifest` in memory). But
for a format frozen for decades with a clean-room mandate, an encoder that
emits a signed document its own decoder rejects is a real defect, and #599 had
just made the writer half normative, so the encoder was formally
non-conformant with `docs/`. Four things about the fix:

- **`core/src/vault/manifest/uniqueness.rs` holds the rule once**, and BOTH
  directions call it: `has_repeat` is the adjacent-scan-after-sort the
  decoder had hand-copied three times, and `check_no_repeated_array_values`
  is `encode_manifest`'s new first statement. The Python twin is
  `conformance_lib/codec/array_uniqueness.py`'s `first_repeated_value`,
  shared by `_check_sorted_and_distinct` and the new
  `check_no_repeated_array_values`. Seven hand-copies of one sentence from a
  frozen spec is how two directions drift, which is what #600 *was*.
- **Three NEW `ManifestError` variants**, not a reuse of the decoder's:
  `EncodeDuplicateBlockUuid` / `EncodeDuplicateTrashUuid` /
  `EncodeVectorClockDuplicateDevice`. Same ruling #586 took one slice earlier
  for the map-key twin — "the bytes you gave me repeat a uuid" and "the value
  you asked me to encode repeats one" are different events, and collapsing
  them would leave a caller unable to tell a corrupt file from a malformed
  in-memory manifest.
- **`recipients` is still the exception, on both sides.** Four rules, not
  five. Three Rust tests (one of them the pre-existing decoder test), the
  corpus row, and a Python writer case all red if someone folds it in —
  each verified by mutation. The corpus row needs its own run to see:
  a `cargo test --lib <filter> --test <name>` positional filter applies to
  BOTH targets, so a lib-shaped filter silently runs zero integration
  tests.
- **No fixture was regenerated, and that is the load-bearing evidence.**
  `encode_manifest` can no longer build the corpus's four rejecting bodies,
  so they are now built by post-hoc `ciborium` surgery — and every row's
  bytes are byte-identical to the ones #594 generated, which
  `manifest_uniqueness_kat_replays`'s rebuild-and-compare asserts against the
  committed JSON on every run. `git diff main...HEAD -- core/tests/data/` and
  `-- core/fuzz/seeds/` are both empty.

Three things about that corpus are load-bearing and were **not** true of its
first version (all three found in the #599 review, all three measured rather
than argued):

- **Both sides check the fixture, not just the verdict.** The Rust replay
  rebuilds every row's body from the `CASES` table and requires a byte-identical
  match, and asserts the specific `ManifestError` variant; Section MUQ requires
  each rejecting row to be sorted-with-a-repeat *and* rejected by a message
  naming the repeat. Before that, `is_ok() == expect_accept` was the whole Rust
  assertion — a fixture whose four reject bodies were the single byte `0x00`
  passed, as did one with §4.2's only exception row swapped out.
- **Every array holds THREE entries and repeats are planted at both ends, in
  more than one block.** With two-element arrays a full adjacent scan and an
  `ids[0] == ids[1]` check are the same function; with the nested rows all in
  `blocks[0]`, a reader checking only the first block was conformant against
  the corpus (`if i == 0:` around the Python check left the suite green).
- **The generator no longer depends on `encode_manifest` declining to
  validate uniqueness — #600 closed that, and the tripwire fired exactly as
  the file's module doc predicted.** The doc had cited **#586** for it, which
  was wrong in a way that mattered: #586 was `CanonicalMap` accepting a
  duplicate **map key**, and closing it neither touched duplicate array
  **elements** nor made this generator fail (measured green across that
  change). #600 was the array-element twin, and closing *it* panicked
  `encode_case` at its `encode_manifest` call in both the generator and the
  replay's rebuild-and-compare. The bodies now come from `ciborium` surgery on
  the encoded all-distinct baseline; `Case` keeps its `mutate` column to drive
  the WRITER-side assertion and gains a `plant` column for the bytes, with the
  two ACCEPT rows asserting that surgery and `encode_manifest` agree byte for
  byte (the only cross-check possible — on a REJECT row the encoder produces
  nothing to compare against).

**`CanonicalMap` rejects duplicate map keys, at ONE choke point (#586).**
`CanonicalMap` sorts its keys at serialise time and used to accept a
duplicate silently, so `encode_manifest` could emit — and `sign_manifest`
sign — a body carrying one key twice: **ambiguous**, in the sense that two
conformant readers may resolve it differently while both accepting the
signature. The check lives in `to_canonical_vec`
(`core/src/vault/canonical/value.rs`), the point the **four vault-body**
encode paths funnel through (manifest, record, block, bundle) — not on
`push`, which would put a `?` on **55** production call sites whose keys are
provably-unique `KEY_*` literals to catch a condition only the other **7**
can create. (Measured: "~30" and "only two of them" were undercounts of
~1.8x and ~3x. The 7 are the runtime-keyed pushes in six forward-compat
`unknown` loops plus `record.rs`'s field-name push.) Five things worth
knowing:

- **`CanonicalValue::Borrowed` is deliberately NOT walked.** A duplicate
  key inside a forward-compat `unknown` subtree is the documented v1
  residual (crypto-design §6.2 rules 1 and 5 are scoped to material the
  reader *interprets*). Walking in would narrow a frozen decoder and red
  the `*__rule5_duplicate_key` corpus rows, which assert v1 accepts exactly
  that. `a_duplicate_inside_a_borrowed_unknown_subtree_is_deliberately_allowed`
  fails first and says so.
- **No frozen-spec edit was needed, and that was measured, not assumed.**
  crypto-design §6.2 rule 5 already forbids duplicate map keys flatly and
  states outright that the reader-side scoping is "not a licence for an
  encoder". So this makes the encoder conformant with an already-normative
  rule — the opposite of #600, the array-ELEMENT twin, where §4.2's writer
  half genuinely had to be raised to MUST NOT.
- **"All four production encode paths" is NOT "every canonical encoder in
  the crate", and one of the uncovered ones is signed.**
  `ContactCard::signed_bytes` — what the §8 hybrid self-signature commits
  to — goes through `identity::card`'s own private `encode_map`, and
  `pk_bundle_bytes` / `sync::state::to_canonical_cbor` through
  `legacy::encode_canonical_map`; neither deduplicates, and card.rs's
  `encode_map` is deliberately permissive so its own tests can build
  hostile-peer bytes with a repeated key. Nothing is exposed today — all
  three build their keys from fixed literals — but that is a property of
  today's call sites, not of the encoder, which is the posture #586 exists
  to replace. Tracked as **#602**. A consequence visible in the code:
  the `CanonicalError::DuplicateKey` arm in `canonical_error_to_card_error`
  is structurally **dead**, and says so.
- **The reachable shape is narrow.** `Record.fields` and every `unknown`
  bag are `BTreeMap`s, so the only way to build a duplicate is an
  `unknown` key colliding with a *known* key — §4.2 at the manifest layer,
  and equally §6.3 one layer down (`record.rs`'s field map, `block.rs`'s
  plaintext bag). `decode_manifest` never produces one (it parses such a
  key as the known one), so the producer is always a caller building a
  value in memory. That is what merge, repair and every block-CRUD path
  do.
- **`canonical_order` is now shared** between `Serialize` and the check,
  extracted so the two cannot drift onto different orderings: the check's
  whole claim is that adjacency in *that* order means equality, which is
  what makes one adjacent-pair sweep exhaustive rather than O(n²).

**Two frozen-spec edits were made. No byte on disk changes, and both are
reversible** — but be precise about *whose* behaviour each documents, because
the writer and reader halves have different histories:

- `docs/vault-format.md` §4.2 now states the five array sort disciplines as
  normative, plus the repeated-array-value rules. **Writer side: longstanding**
  — `6e53b49d`, the first manifest commit, already sorted all five and named
  them in its module doc, so every manifest this codebase has ever written is
  sorted. **Reader side: NEW, at `a2da3d24` (#572)** — the same commit that
  added the normative sentence. `main`'s manifest decoder has no
  `ManifestError::NonCanonicalEncoding` variant, no re-encode-and-compare, and
  no array-order check at all (`parse_vector_clock` / `parse_blocks` /
  `parse_trash` sort a *copy* of the ids only to detect duplicates, never the
  input order). So the accepted-manifest set genuinely **narrowed** for
  anything this codebase did not write — do not summarise this as "no reader
  behaviour changed". The sort disciplines were enforced by the encoder and
  written down nowhere, so a clean-room implementer reading `docs/` alone
  would have emitted unsorted arrays and been rejected by the new check —
  exactly the property `conformance.py` exists to gate. The same section carries the
  per-rule split for `unknown` subtrees — a five-row table against
  crypto-design §6.2's five rules, with **2/3/4 enforced and 1/5 not**. Be
  careful with the mechanism, which is not uniform across those three: rules 2
  and 3 are caught by the §4.3 step-4 re-encode *for a normalising-parse
  reader* (a byte-retaining reader must check them directly, and the table's
  row 2 says so); rule 4 is never the re-encode, because a normalising parse
  preserves a tag or a float and re-encodes it identically — it is caught by a
  separate whole-body walk, which in this codebase is
  `reject_floats_and_tags` at `manifest/decode/mod.rs:116`, run before the
  re-encode. Alongside the table sits the byte-preservation MUST that makes
  re-emission possible, stated as a two-part obligation so that every
  representation is admissible on equal terms.
- `docs/crypto-design.md` §6.2 **rules 1 and 5** (map-key order; reject
  duplicate keys) are now scoped to material the reader *interprets*. The Rust
  decoder has always accepted both inside `unknown` subtrees — in `record.rs`
  and `block.rs` as well as here, verified by execution over twelve cases — so
  the unscoped rules had been inconsistent with the implementation since v1.
  Enforcing them instead would break forward-compat and change three modules.

`canonical_sort_entries` **still has a production caller** — the manifest
encoder is no longer it. #569 path 2 moved the manifest encode path onto the
borrowing `CanonicalMap`, but `sync::state::SyncState::to_canonical_cbor`
(`core/src/sync/state.rs:107`) still sorts a two-key vector-clock entry map on
the way to OS-keystore persistence. `encode_canonical_map` likewise keeps
`sync::state` and `identity::card`. Both also remain in use from `#[cfg(test)]`
oracles and fixtures — but not the same files, so do not flatten the two:
`canonical_sort_entries` is called from `record.rs` and the manifest module's
`test_support.rs`; `encode_canonical_map` from `record.rs`, `block.rs` and three
manifest test files. `block.rs` calls `canonical_sort_entries` nowhere, and
`encode_canonical_map` does not reach it either (it has its own inline sort).
Do not delete either as dead.

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
  boundary by `core/src/cbor/mod.rs`. **`InvalidArgument` stays redacted on both
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
  message that can embed the offending value. [`core/src/cbor/mod.rs`](core/src/cbor/mod.rs)
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

The guard is now a package, [`scripts/payload_guard/`](scripts/payload_guard/),
entered via [`scripts/check-error-payload-hygiene.py`](scripts/check-error-payload-hygiene.py)
(see the Commands block above), and it fails closed: an unrecognised payload
type is a FAILURE, not a pass. It covers **four scan roots**, each described
as data in [`payload_guard/roots.py`](scripts/payload_guard/roots.py)'s
`SCAN_ROOTS` — `core/src/**`, `ffi/secretary-ffi-bridge/src/**` (#480), and,
as of #486, the two binding wrapper crates `ffi/secretary-ffi-py/src/**` and
`ffi/secretary-ffi-uniffi/src/**` — with **six rules** (E6 added in #515): `E1` (a variant's
payload type must be data-free by construction; all four roots), `E2` (a
bridge/wrapper gated-prose field is permitted only under one of six PINNED
names — `detail`, `uuid_hex`, `block_uuid_hex`, `recipient_fingerprint_hex`,
`expected_fingerprint_hex`, `got_fingerprint_hex` — **and** only with the
type spelling that root accepts, which is PER-ROOT as of #500: `Detail` on
the bridge, `String` on the two wrappers. The bridge permits **no** `String`
under a gated name; `BP51` pins that denial), `E3` (every CONSTRUCTION
SITE of a gated field must build its value from a sanctioned source — bridge
and both wrapper roots), `E4` (every `impl GatedDetail for X` must live in
[`ffi/secretary-ffi-bridge/src/error/detail.rs`](ffi/secretary-ffi-bridge/src/error/detail.rs)
and name a type the guard scans — **bridge-only**, `GatedDetail` is
`pub(crate)` there so no wrapper crate can implement it), and `E5` (**wrapper-
only**: `format!` is confined to each wrapper crate's own sanctioned
`detail.rs` — the bridge is excluded because most of its `format!` sites
build filenames, a legitimate non-error use), and `E6` (**bridge-only**,
#515: the `Detail(` tuple-struct constructor may be written only in
`error/detail.rs`, and that file may declare no submodule beyond `private`
and `tests` — the second half is the load-bearing one, because a descendant
module inherits the private field's visibility and can live in any file).
Gated-field construction is
therefore CI-enforced across the bridge and both wrapper crates: a new
producer that hand-rolls a `format!` into a gated field fails in the Rust
author's own PR — the same sink-pinning move `SecretaryLog` (#472) and
`diagnosticDetail` (#467) make for their own platforms. Its allowlist
([`scripts/error-payload-hygiene-allowlist.txt`](scripts/error-payload-hygiene-allowlist.txt))
is sectioned by review weight; the highest-weight section (Section 3) holds
**construction-site claims the guard structurally cannot verify** under
`core/src/**`, where `E1` sees only DECLARATIONS (a field's type), not
producers — an entry there is a point-in-time claim, verified by reading
every current constructor, that no producer interpolates vault plaintext.
Re-verify it whenever a producer changes.

#486/#487/#488 closed the three residuals a prior version of this paragraph
named as open, all structurally:

- **#487 — the `io::Error` payload position.** `E3` now reads a FOURTH
  candidate position, beyond a gated field's initializer/`let`/assignment:
  the payload argument of `io::Error::new(kind, PAYLOAD)` /
  `io::Error::other(PAYLOAD)`. The in-tree production site
  ([`ffi/secretary-ffi-bridge/src/repair/orchestration.rs`](ffi/secretary-ffi-bridge/src/repair/orchestration.rs))
  now routes through `detail::io_gated_with_path_and_advice`. (#496
  renamed it: the first spelling put the call site's remediation advice in
  `context` position, i.e. at the HEAD of the message, so the composed
  string read "if that file exists … must be fixed instead: No such file
  or directory; state file path: /…" — the clause preceding the only
  mention of the file. #487's `io_gated`/`io_gated_with_path` pair had no
  other caller and was retired.)
- **#488 — the laundering shapes.** A local `let detail = format!(...)`
  re-wrap and a post-construction `x.detail = ...` assignment are now
  candidates in their own right (`E3`'s second and third forms).
- **#486 — the wrapper-crate boundary.** `ffi/secretary-ffi-py/src/**` and
  `ffi/secretary-ffi-uniffi/src/**` are now scan roots under `E1`/`E2`/`E3`
  plus the new `E5`; previously a review-only trust boundary, now CI-enforced
  under the rule set `roots.py` records for each root (not identical to the
  bridge's — see the paragraph above: the wrapper roots take `E5`, which the
  bridge does not, and do not take `E4` at all. They also used to get an
  extra `E3` acceptance the bridge was denied — shape 5 — retired in
  #497/#500).
- **DEFERRED-INIT regression, found in this branch's own final review.** A
  type-annotated `let` with NO initializer (`let detail: String;`, its
  value written on a later, separate `detail = <expr>;` statement) reads to
  `GATED_INIT_RE` exactly like a genuine declaration, and once #488 added
  `;` as an `initializer_end` terminator its extracted slice went from a
  garbled, accidentally-denied mess to a clean bare `String` — which arm
  3's declaration acceptance then waved through, a real regression against
  the pre-#488 guard (DENIED at merge-base `7fa210c`; ZERO findings before
  this fix). Closed by denying arm 3's bare-`String` acceptance whenever its
  terminator is `;`: none of the three genuine declaration positions
  (struct field, enum field, fn parameter) is ever itself `;`-terminated —
  only a `let` statement is. Pinned by `BP44`.

**#500 — the `Detail` newtype: what the compiler now enforces, and where
that stops.** All **27** gated payload fields in `ffi/secretary-ffi-bridge`
are declared `Detail`
([`error/detail.rs`](ffi/secretary-ffi-bridge/src/error/detail.rs)'s
`pub struct Detail(String)`), whose inner field is private to the
`error::detail` module **and its descendant modules** — Rust privacy is
SUBTREE-scoped, not file-scoped, so `mod ext;` there plus `#[path]` would
hand the minting capability to an unreviewed file while the one-file review
of `detail.rs` saw only the `mod` line (verified by execution: sibling
module `E0423`, descendant module compiles clean, guard silent). This said
"private to that one file" until #515, which made it true by adding guard
rule **E6**: the `Detail(` constructor may be written nowhere else in the
bridge, and no submodule beyond `private` and `tests` may be declared in
`detail.rs`. A `String` therefore does not TYPECHECK in any of those 27
positions, however it was produced — including through all four E3
laundering shapes the bullet below lists as unwatched, and through shapes
nobody has enumerated. `ScanRoot.gated_field_types` was then narrowed to
`{Detail}` on the bridge, so a new bridge error type cannot opt back out by
declaring the old spelling (`BP51` denies, `BN28` accepts). On the bridge,
E3 is now **defence in depth** rather than the enforcement — the same
demotion E4 took when `GatedDetail` was sealed in #496.

**The sentence this invites, and which is wrong, is "laundering is fixed."**
Four boundaries, each stated as a boundary rather than a caveat:

- **The two wrapper crates are UNCHANGED.** `ffi/secretary-ffi-py` and
  `ffi/secretary-ffi-uniffi` keep `detail: String` on their **own** error
  types — uniffi's UDL must project a `string`, PyO3 exceptions take a
  message, and making them `Detail` would need a `custom_type!` conversion
  adding UDL surface for a type unwrapped one line later. Rules E2/E3/E5
  remain their **only** enforcement, at exactly the strength they had
  before. Each pass-through arm gained one unwrap where a bridge payload
  becomes a wrapper `String`, and it sits immediately beside the wrapper's
  own construction site, so it is a **projection, not a gate**. Note the
  spelling, because the obvious one is denied: every gated-field initializer
  **that unwraps a bridge payload** routes through `detail::project(d)`,
  whose whole body is the single `Detail::into_string()` — 25 such sites in
  ffi-uniffi, 2 in ffi-py (`repair_preview.rs:45,83`) — because the inline
  `detail: detail.into_string()` matches no E3 arm and denies (`WP6`; each
  crate's `detail.rs` says so outright). `project` is not a fourth arm: it
  is a call into the crate's sanctioned module, i.e. the `detail::*` arm the
  rule summary above already lists. The wrapper's OWN authored diagnostics
  — which never held a `Detail` — take the other two arms, and ffi-uniffi
  has 19 of them in production: 13 string literals and 6 further `detail::*`
  constructor calls (`arg_len`, `indexed_arg_len`, `nested_indexed_arg_len`,
  `range`). ffi-py's 17 *bare* `.into_string()` calls in `errors.rs` are all
  `new_err(...)` **arguments**, a position E3 does not read at all — of
  those 17, **11** have receiver `detail` and **six** carry another gated
  name (4 `uuid_hex`, 1 `recipient_fingerprint_hex`, 1 `block_uuid_hex`),
  a receiver census corrected in the final review from a flat "17 bare
  `detail.into_string()`" that was right about the count and the position
  and wrong about the receiver. The
  design doc's §4 exists for this sentence — do not flatten the two roots
  into one claim.
- **The guarantee is per DECLARATION, not per root.** It covers the 27
  fields that hold the real type. A NEW bridge error type can still declare
  its gated field through a renaming import — `use std::string::String as
  Detail;` — which compiles, and which **both E2 and E3 pass**: verified by
  execution, that declaration plus an E3 arm-4 parameter re-wrap scans with
  ZERO findings. **That sentence is true of the CLASS but must not be read
  as "#500 opened this"** — the blind spot MOVED SPELLING and SHRANK, and
  both halves are measured, not argued:
    - *Moved.* The guard matches the accepted gated-field type by spelling,
      so the attack is always "import something under the accepted name."
      At merge-base `3775ef5` the accepted spelling was `String`, and that
      exact line — `use std::string::String as Detail;` with `detail:
      Detail` — was **DENIED** (4 findings: E2, E1, E3 x2), while its
      `String`-spelled equivalent `use secret::SecretHolder as String;`
      with `detail: String` was **ACCEPTED** (0 findings). On this branch
      the two swap exactly: `as Detail` accepts (0), `as String` denies (2).
      Same hole, relabelled by the narrowing of `gated_field_types`.
    - *Shrank.* The `type`-ALIAS form of the same attack is now **denied on
      all four roots** where merge-base accepted it. `type String =
      SecretHolder;` with `detail: String` scored 0 findings at merge-base
      and reds the branch (`type Detail = String;` likewise: 2 findings),
      because `run_real_scan`'s `shadowed_type_names` — `alias_candidate_
      names` union `discover_local_detail_decoys`, machinery that does not
      exist at merge-base at all — withdraws a shadowed spelling from the
      carve-out. Both terms of that expression are pinned by `BP57`, one
      probe each.
  What is left is the IMPORT form alone. `discover_local_detail_decoys`
  catches a local *declaration* of a decoy `Detail` anywhere in the root
  **except the root's own sanctioned module**, which it exempts so the real
  declaration does not shadow itself (`BP54`/`BP55` pin the catch, `BN29`
  the exemption) — and it never catches an *import* of one. Nothing in this
  guard resolves a name; `Detail` is matched by spelling throughout. Tracked
  by **#512**, which covers this and its `GatedDetail` twin as one root
  cause.
- **`Detail` says nothing about its neighbours.** It claims one thing: this
  string came out of a reviewed constructor. E2's declaration sweep covers
  `#[error(`-attributed types plus plain-derive types named `*Error` /
  `*Warning`; **`FfiAddedRecipient` and `FfiWideningReport`
  (`repair/preview.rs`) are neither**, so E2 does not sweep them at all and
  for their `uuid_hex` / `block_uuid_hex` fields the newtype is the ONLY
  declaration-level enforcement. Their sibling `display_name` /
  `block_name` fields deliberately carry **decrypted plaintext** and stay
  `String`. A `Detail` beside a plaintext `String` is correct there, not an
  inconsistency to "clean up".
- **It is a claim about the ASSIGNMENT, not about reachability of every
  runtime string.** "A `String` does not typecheck in the position" is not
  "no runtime text reaches a gated field". No sanctioned constructor takes a
  caller-supplied `String`/`&str`, but `gated` and its siblings take `&impl
  GatedDetail`, and one allowlisted impl — `std::io::Error` — is a *carrier*
  whose `Display` renders whatever it was built from, so
  `detail::gated(&io::Error::other(runtime))` still reaches a gated field
  **from inside the bridge crate**. That is the documented,
  control-corpus-accepted class, not a hole the newtype claims to close.
  Downstream crates cannot do it at all: `GatedDetail` is `pub(crate)` and
  sealed. `error/detail.rs`'s own `Detail` doc comment states this scope.

**The `test-support` hatch is a BUILD-CONFIGURATION guarantee, not a
language one.** `Detail::for_test` mints a `Detail` from arbitrary runtime
text and is absent from shipped artifacts only because Cargo's resolver v2
declines to unify a **dev**-dependency's requested features into a non-test
build. **That precondition is itself now pinned** (#515 C1): the root
manifest is VIRTUAL, so deleting `resolver = "2"` from
[`Cargo.toml`](Cargo.toml) drops Cargo to resolver **1** with only a
warning — and under resolver 1 the three already-sanctioned
`[dev-dependencies]` lines put `Detail::for_test` straight back into
`cargo build --release --workspace`, with every guard, the self-test and
the CI build step all still green (verified by execution). The placement
guard now denies any scanned `[workspace]` that does not resolve to v2,
honouring edition inference so `core/fuzz`'s non-virtual root is not a
false positive.
[`scripts/check-test-support-placement.py`](scripts/check-test-support-placement.py)
denies the manifest line (or feature alias) that would put it back — a
`package = "..."` RENAME inherited from the root's
`[workspace.dependencies]` was a hole there until #515 C2, proven with real
Cargo to enable the feature in a release build while the guard printed OK —
and
`cargo build --release --workspace` in CI catches a production *call* to a
hatch that should not exist — but neither is the compiler refusing to
express the thing. **Which gates are blind, measured not assumed:** with a
production call to the hatch planted in the bridge, `cargo test --release
--workspace` and `cargo clippy --release --workspace --tests` each reported
**0** errors — and those are the two a contributor runs by habit. The three
that caught it: `cargo build --release --workspace` (2), `cargo clippy
--release --workspace` without `--tests` (2), and the rustdoc gate (4).
**Do not quote the rustdoc row without its condition:** rustdoc does not
type-check the bodies of the crate it is *documenting*, and catches this
only because `ffi-py`, `ffi-uniffi` and `desktop/src-tauri` depend on the
bridge, so documenting them builds its rmeta. The same leak in a **leaf**
crate — which both wrapper crates are — scans clean. `cargo build` is why
CI carries a separate non-test build step.

What is genuinely **not** closed — stated precisely, not dropped, because the
single most repeated review finding on this branch was documentation
claiming more coverage than the code delivers:

- **Macro-generated code.** Every rule here reads TEXT, not expanded
  macros: a `macro_rules!`-generated `#[error(...)]` is invisible. Inherent
  to a text-based guard. The `GatedDetail` half of this bullet is NO LONGER
  open — #496 made the trait SEALED (`private::Sealed` in
  [`error/detail.rs`](ffi/secretary-ffi-bridge/src/error/detail.rs), nameable
  only from that file), so a macro-generated or alias-spelled
  `impl GatedDetail for X` outside it is a COMPILE error, not merely an E4
  finding. `E4` stays as defence in depth and to check the other half of its
  rule (an impl inside `detail.rs` must name a type the guard scans).
- **`E3`'s remaining laundering shapes — now WRAPPER-ROOT ONLY.** #500's
  newtype closed every shape below **on the bridge**, in the compiler
  (see the `Detail` paragraph above, including the renaming-import boundary
  on that claim). On the two wrapper roots, whose error types keep
  `String`, they remain open at full strength and pinned by nothing. Read
  the rest of this bullet as "wrapper-root gaps, plus bridge
  defence-in-depth". #488 closed the SIMPLE `let` and
  plain-assignment forms only. Still open and pinned by nothing:
  PATTERN-DESTRUCTURING binds of a gated name (tuple, tuple-struct, struct,
  slice), `if let` / `while let` / `for` bindings, BUILD-THEN-MUTATE through
  a method call (`let mut d = "".to_string(); d.push_str(&format!(..));`),
  the function-PARAMETER case, and DOTLESS LOCAL REASSIGNMENT — `detail =
  <expr>;` in statement position, reassigning a local bound WITHOUT a `let`
  this rule can see (a function parameter, or a type-less `let detail;`).
  `GATED_ASSIGN_RE` requires a RECEIVER DOT before the name (it exists for
  `x.detail = <expr>`, a write to a FIELD); a bare local has no receiver, so
  the regex was never scoped to see it. **Two of these shapes are in daily
  use** — a prior version of this bullet claimed "no live producer in the
  tree today", which #496 found to be wrong and is the same overclaim class
  this branch kept re-finding. **Re-censused in #500, and CORRECTED in the
  final whole-branch review:** the pattern-bind form has **three** live
  bridge producers, not the two an intermediate draft claimed —
  `error/conversions.rs:25` and `:27`, plus `error/detail.rs:285`
  (`VaultError::RepairRejected { detail, .. } => Detail(detail.clone())`).
  That third site is shipped code (`detail.rs`'s `#[cfg(test)]` starts at
  line 387) and **this branch created it**: #500 replaced the
  `error/vault/mod.rs:558` site the list used to name with a
  `detail::repair_rejection(e)` call, and the bind moved *into* that
  constructor rather than disappearing. It is not a leak — it destructures
  a `core` payload gated by core's own E1 entry (allowlist Section 3,
  `vault/mod.rs — RepairRejected`), inside the one module whose job is
  minting `Detail`. Every other bridge hit of the census grep is test code,
  an `#[error(…)]` attribute, a **comment of either form** — four plain
  `//` line comments (`repair/orchestration.rs:133`,
  `error/vault/mod.rs:493`, `:501`, `:511`) plus one `///` doc comment
  (`error/unlock.rs:57`), all five shipped rather than test code — or a
  `{detail}` interpolation in an assertion message. None of them a bind.
  ("a doc comment" alone was wrong for four of the five, and is corrected
  rather than generalised away so the split stays reproducible.) On the
  wrapper roots, the figures
  **34** and **37** that stood here are SINGLE-LINE-GREP SUBTOTALS, not
  tree totals — a census that also parses multi-line patterns gives 44 and
  40 (#515 I1). The CONCLUSIONS are unaffected and are what matter: every
  production pattern bind destructures a **bridge** `Ffi*` error, so every
  one binds a `Detail`; the binds of a wrapper's own `String`-typed gated
  field are all inside `#[cfg(test)]` — production count **zero**.
  "Counted exactly" is the phrasing this file flags two bullets earlier as
  how a subtotal gets read as a total. The
  function-parameter form is what every shipped re-wrap site is. All are
  legitimate re-wraps of already-gated values, verified by reading each — but
  "unwatched position in daily use" is a different risk posture from
  "theoretical". What #500 changed is narrow and worth stating exactly: on
  the bridge these positions now carry a `Detail`, so a future producer
  adopting the shape for an ungated value fails to COMPILE; on the two
  wrapper roots it would still be invisible. (The DEFERRED-INIT shape that used
  to share this bullet — `let detail: String;` with the value assigned
  later — is a DIFFERENT gap, and is now closed; see above.) Closing any of
  these needs local dataflow / interprocedural analysis this construction-
  site guard does not do. There is also a documented FALSE POSITIVE,
  fail-closed but worth knowing before reaching for the allowlist: a
  type-annotated legitimate re-wrap (`let detail: String = detail::gated(e);`)
  is itself denied, by the interaction of two rules rather than by design.
- **The `use std::io::Error;` aliasing blind spot**, specific to the NEW
  `io::Error` payload position: the rule matches the type spelled out
  (`io::Error::new(...)`), so an aliased import is invisible to it — the same
  blind spot `E4` has for `GatedDetail`.
- **`E5` covers `format!` only, and that scope is a census finding, not a
  claim that `format!` is the only construct CAPABLE of composing a runtime
  string from several parts.** It is not: `push_str`, `write!`/`writeln!`,
  the `+` operator on an owned `String`, and `.join()` can all do the same
  thing, and none of them is a site `E5` inspects — a producer using any of
  them to build a gated-field argument passes silently. Re-running
  `grep -rnE "push_str|write!\s*\(|\.join\s*\(|String::from\s*\("
  ffi/secretary-ffi-py/src ffi/secretary-ffi-uniffi/src` today returns
  **nine** hits (this said "seven" until the final whole-branch review
  re-ran it) and zero live composition sites: three are `String::from\s*\(`
  matching as a substring of `SecretString::from(`, four are
  `core_test_data_dir().join(...)` — `Path::join`, not `str`/`String`
  `.join()`, all four inside `#[cfg(test)]` — and two are
  `ffi/secretary-ffi-py/src/detail.rs:17-18`, the doc comment that names
  these very constructs, i.e. the census matching its own prose. The
  substance is unchanged: zero live composition sites either way.
  `push_str` / `write!` /
  `writeln!` do not appear at all; `+` string concatenation isn't
  census-able by grep and is named here on its construction merits alone.
  Separately, `.to_string()` — which by itself only ever RENDERS one value —
  IS censused across every production receiver in both wrapper crates: the
  receiver is always one of two shapes that cannot carry runtime secret
  content, an already-gated bridge error type's `Display` or a compile-time
  string literal. Leaving all five constructs out of `E5`'s scope is a
  reviewed, point-in-time decision, not a structural guarantee — if any
  census stops holding, `E5` widens to cover it. **Two spellings of
  `format!` itself also evade it** (found in #496, no live producer): a
  macro RENAME (`use std::format as fmt2;` then `fmt2!(...)`), which is the
  same alias blind spot `E4` has, and `std::fmt::format(format_args!(..))`,
  which is what `format!` expands to. `E5` also SKIPS `#[cfg(test)]` spans —
  ten live sites depend on that, and `WN3` is the only thing pinning it.
- **`E3`'s signature gate, and the two decoy classes it is matched by
  spelling against.** The `&str` half is CLOSED (#496 opened it, #504 closed
  it), and is kept here because prior versions of this file called it open.
  The sanctioned-constructor registry now reads SIGNATURES, not just names —
  before that it was self-authorising, deriving its allowlist from the very
  file it constrains, so one `pub(crate) fn passthrough(x: &str)` added to a
  `detail.rs` sanctioned an arbitrary runtime string at every call site with
  the guard green. Every parameter type must now sit in `SAFE_PARAM_TYPES`.
  **`STR_PARAM_CTOR_EXCEPTIONS` IS NOW EMPTY** (#504). A prior version of
  this bullet read: "it pins two ffi-py constructors (`fingerprint_mismatch`,
  `uuid_prefixed`) … nothing verifies what the two existing ones are
  passed." That is false — both now take `&Detail`, so their inputs are
  gated by TYPE rather than by a point-in-time review claim, and the set is
  `frozenset()`. Any `&str`-taking constructor added to a `detail.rs` from
  here on fails the guard until someone deliberately re-populates it, which
  is a **higher-weight decision than any allowlist row**: a name there
  re-admits an arbitrary runtime `&str` at *every* call site of that
  constructor, present and future, with no per-site key to re-review.
  **EVERY `SAFE_PARAM_TYPES` member is matched by SPELLING and none is
  resolved** — a prior version of this bullet said "two members", which was
  the overclaim, and #515 closed the gap it hid. `&Path`,
  `&std::path::Path`, `ErrorKind`, `io::ErrorKind`, `std::io::ErrorKind`
  and `&secretary_core::vault::VaultError` had NO withdrawal behind them,
  so a wrapper root could decoy any of them; verified by execution against
  the REAL scan, `pub(crate) struct Path(pub String)` plus
  `fn launder(p: &Path) -> String` in a wrapper's own `detail.rs` laundered
  an arbitrary runtime String into a gated field with ZERO findings. The
  withdrawal set is now DERIVED from `SAFE_PARAM_TYPES` itself
  (`SHADOWABLE_PARAM_IDENTS` / `discover_shadowed_param_idents`), so a
  future member brings its own identifiers and cannot be forgotten; `WP12`
  pins it. The two SPECIFIC withdrawals are kept alongside it because they
  alone carry the `owns_detail_type` exemption the bridge's real
  `struct Detail` needs: a locally declared `struct/enum/union/type Detail`
  withdraws `Detail`/`&Detail` (`WP8`, `WP10`) and a locally declared
  `trait GatedDetail` withdraws `&impl GatedDetail` (`WP11`, #504 review
  R3), **both suppressed by that same flag**, so flipping it `True` on a
  wrapper root re-opens two decoy classes, not one. Both share
  one residual, verified by execution: an IMPORT evades them in either
  spelling — the decoy declared in a sibling file of the same crate and
  `use`d into the sanctioned module leaves the laundering constructor
  sanctioned and the whole scan green.
- **`E3`'s shape 5 is CLOSED** (#497, closed by #500) — it is listed here
  because prior versions of this file called it open. It accepted an
  ARBITRARY single-hop receiver on the wrapper roots — `<anything>.detail`,
  not just a bridge DTO — and the recorded justification ("the source is a
  bridge DTO whose fields `E2`/`E3` gate") was a property of the four LIVE
  sites, not of the shape the rule accepts. #500 moved all four onto
  `detail::project(...)`, so the acceptance had zero users and
  `ScanRoot.allow_field_access` is now `False` on every root; `WP7` pins the
  denial. Re-enabling it needs live sites and a fresh review.
- **`&'static str` is not leak-proof, and several rules lean on it.** Safe,
  stable Rust mints one from runtime data via `Box::leak(s.into_boxed_str())`
  or `String::leak()`, and `#![forbid(unsafe_code)]` does not stop either. So
  a `&'static str` in a gated position — `SAFE_PARAM_TYPES`, a sanctioned
  constructor's `context`/`field`/`advice`, a `core` payload's map-level
  hint — DISCOURAGES a runtime string rather than making one
  unrepresentable. **A prior version of this bullet closed with "Every live
  site passes a literal; nothing enforces it." Both halves were false**, and
  both are corrected rather than softened (#498's cheaper half, landed in
  #500):
    - *"Nothing enforces it"* is now wrong for **one** position: `E3`
      requires every HINT-POSITION argument at a sanctioned `detail::*` call
      site to be a string-literal TOKEN, not merely an expression of
      `&'static str` type. Hint positions are derived from each
      constructor's own signature, so the check cannot drift from a
      hand-maintained name list. `BP52` pins the `Box::leak` attack;
      `BN30`/`BN31`/`BN32` pin that plain, raw-string and multi-line
      literals still pass. It is still nothing at all for a `core` payload's
      map-level hint (E1 sees the declaration, never the producer).
    - *"Every live site passes a literal"* is wrong **by six that rule E3
      can see — and by nine in the tree**. Both figures were re-derived by
      grep in the final whole-branch review, where the bare "six" was found
      to state an E3-visible subtotal as if it were the tree total — the
      same overclaim class, in the one bullet this branch rewrote *because
      both its halves were previously false*. Of the **six E3 sees**, FIVE
      pre-date this work; the sixth, `array32_from_vec_into`, was created
      by that work (PR #515, merged as `9c187946`) and inherits the forwarding shape
      verbatim from the by-value `array32_from_vec` it replaced and
      deleted. (#523's first attempt repointed the dangling `9cad5b3c` at
      `2e6dd764`/#520, which is wrong and self-contradicting: `git show
      2e6dd764^:…/namespace/mod.rs | grep -c 'fn array32_from_vec_into'`
      returns 2, so the function already existed in #520's parent, and
      `git log --all -S` puts its introduction in `9c187946`. The giveaway
      is two sentences down — `3775ef5` is `9c187946`'s parent, i.e. the
      merge-base of the branch that actually created it.) A prior version
      said all six pre-date it and cited `git show
      3775ef5:` as confirmation — that command DISPROVES it (`grep -c 'fn
      array32_from_vec_into'` on the merge-base file returns 0), the same
      overclaim class this section keeps re-finding (#515 I3):
      `error/detail.rs`'s own internal re-forward, plus five in
      `ffi/secretary-ffi-uniffi/src/namespace/mod.rs` (`uuid_from_vec`,
      `array32_from_vec_into`, `uuid_from_vec_at`, `array32_from_vec_at`,
      `uuid_from_vec_nested_at`), each forwarding its *own* `&'static str`
      parameter one hop. All **54** production call sites across those six
      enclosing functions were read and do pass a literal; the six are
      recorded as individually justified allowlist entries (Section 5)
      rather than waved through by a wider rule. The **three E3 cannot
      see** are in `ffi/secretary-ffi-py/src/errors.rs` — `:231`,
      `:249-254`, `:265` — forwarding their own `field: &'static str` into
      `crate::detail::arg_len` / `indexed_arg_len` in
      `PyValueError::new_err(...)` **argument** position.
      `_hint_args_are_literal` is reachable only from
      `initializer_is_gated`, so E3 never inspects them: no finding, no
      Section 5 row, and their **43** call sites sit outside the "54 were
      read" claim. The source comments at `errors.rs:224-228` and
      `:237-242` do record a by-hand review, so this is a **scope error,
      not an unreviewed hole** — and it is the same argument-position
      blindness **#498** owns structurally.
  This **watches** the door, it does not remove it, and two evasions of the
  Section 5 entries scan clean today: a caller-side
  `uuid_from_vec(b, e.to_string().leak())` (no `format!`, so `E5` has nothing
  to say either) and a CHAIN — a new pass-through wrapper creates no
  gated-field construction site, so it produces no finding at all. Section
  5's "re-verify when a call site is added" still has **no mechanical
  hook** for a caller in ANOTHER file: the entry is keyed on text inside
  the helper, which that caller does not change. What #515 DID close is the
  same-file half, which was worse and undocumented: the E3 allowlist key
  carried no notion of WHERE the expression sat, so each Section 5 row
  exempted its expression text **anywhere in a 1000+-line file** while its
  justification was a property of one enclosing function. A second producer
  in `namespace/mod.rs` minting a runtime `&'static str` via `Box::leak`
  and calling `detail::arg_len(field, 16, bytes.len())` — the exact `BP52`
  attack — scanned with ZERO findings, and denies now that the key is
  scoped to the enclosing `fn`. **#498 stays OPEN** for the structural fix (a
  closed `enum Context` / `enum ArgField`), which is the only thing that
  would make a leaked `&'static str` unrepresentable.
- **The out-of-root `io::Error` mint.** `cli/src/daemon.rs:424` synthesizes
  a `std::io::Error` from a runtime string in a tree no scan root covers.
  The shape is `std::io::Error::other(err.to_string())` over a
  `notify::Error` — **not a `format!`**, which is what this bullet and the
  guard's own `#494` register both said until the final review re-read the
  file (`cli/src/daemon.rs` contains zero `format!`). The gap is identical
  either way: E3 gates the io payload argument, and nothing gates it out of
  root. Not a live exposure — the bridge imports only
  `secretary_cli::{state, pipeline}`, never `daemon` — but tracked by
  **#494**, and dropped from this list entirely in an earlier draft.

What #496 CLOSED, all fail-open holes in the guard's own wiring rather than
in any scanned source: a scan root whose path moved contributed zero files
silently (`Path.rglob` does not raise), so the bridge and both wrapper roots
could go unscanned with CI green; three of `roots.py`'s five rule flags were
read by nothing, so `E3`/`E4`/`E5` could each be switched off tree-wide with
`--self-test` green; the permissive `#[cfg(...test...)]` matcher was used as
a SKIP LIST by `E2`/`E3`/`E5`, where an over-match is fail-OPEN, so
`#[cfg(not(test))]` or any `#[cfg_attr(test, ...)]` silenced a violation in
one line; a raw C string (`cr#"a " b"#`, Rust 1.77+) desynced the lexer and
blanked the rest of the file; and a typo'd `ControlExpectation` key silently
degraded a control to "something fired".

**Open issues against this guard**, so the list above can be cross-checked
against the tracker rather than trusted: **#494** (the out-of-root
`cli/src/daemon.rs` `io::Error` mint), **#495** (`discovery.py` is two
unrelated parsers in one file), **#498** — its cheaper half landed in #500,
its **structural half stays open** and must not be written as closed —
**#499** (`E5` misses the macro-rename and `format_args!` spellings of
`format!`), **#501** (ffi-py's pytest suite never runs in CI), **#502**
(`desktop/src-tauri` builds its own `AppError { detail: String }` outside
every scan root), **#506** (that script is 1253
lines and wants the `payload_guard/` package treatment), **#508** (`E3`
shape 5's internals are unpinned while `allow_field_access` is `False`),
**#509** (`E3` arm 3 accepts a bare `String` token on the wrapper roots),
**#510** (`Path.rglob` does not recurse symlinked directories — invisible to
EVERY rule), **#512** (a renaming import
defeats the `Detail` newtype's E2 credit — the guarantee is per declaration,
not per root; covers the `GatedDetail` trait twin as one root cause),
**#516** (`--self-test`'s five BP57 wiring probes write `.rs` files into the
LIVE tree; removed in a `finally` and `.gitignore`d, but the window races a
parallel session and hides residue from `git status`), **#517** (`E6` and
the derived `SHADOWABLE_PARAM_IDENTS` set carry E4's alias/macro blind
spots, and unlike `GatedDetail` there is no `Sealed` equivalent for a
tuple-struct constructor — same root cause as #512), and
**#514** (`check-test-support-placement.py`'s manifest discovery carries the
same `rglob` symlink gap plus a `target` path-COMPONENT exclusion that drops
a legitimately-named subtree; #510 is scoped to `payload_guard`, so nothing
tracked the placement guard's copies until this — latent, not live).
**#505** (`DEFAULT_ROOTS` completeness now DERIVED from the root manifest's
`[workspace] members`), **#507** (`lexer.py`'s dangling `BP46` citation
corrected to `BP45`) and **#511** (control-label uniqueness now checked on
BOTH guards) are closed **in code** by #515, alongside that review's six
substantive findings: the `resolver = "2"` precondition is denied when
absent, a workspace-inherited `package = "..."` rename can no longer
smuggle the feature onto a normal edge, EVERY `SAFE_PARAM_TYPES` member
carries a decoy withdrawal, the deny-polarity alias pass no longer inherits
the permissive `#[cfg]` skip, `E3`'s argument splitter no longer
mis-indexes on an unpaired `>` (and gates on ARITY), and an `E3` allowlist
key is scoped to its enclosing FUNCTION rather than exempting its text
file-wide. **#497**, **#503** and **#504** are closed **in code** by #500
and are described above as closed; the GitHub issues may still read OPEN, because
this repo cites fixes as `(#N)` and never `Closes #N`, so an issue outlives
its fix until a human closes it — cross-check the *substance* against the
code, not the issue state.

The same register lives in the guard's own `OPEN ISSUES` block
([`scripts/check-error-payload-hygiene.py`](scripts/check-error-payload-hygiene.py)),
with one clause each. That is a **deliberate two-site register** — a
maintainer reading only the guard should not have to reconstruct it from
prose — so filing or closing one means editing **both**.

Read that file's LIMITS section for the authoritative, current version of
the gap DESCRIPTIONS — this section summarizes them and will drift if the
guard changes without a matching edit here.

### Memory hygiene: zeroize discipline

Every secret-bearing byte string is wrapped in `Sensitive<T>` or `SecretBytes` ([core/src/crypto/secret.rs](core/src/crypto/secret.rs)) — both derive `Zeroize, ZeroizeOnDrop`. Composite types (`IdentityBundle`, `UnlockedIdentity`, `Mnemonic`) drop their secret fields in source order.

**Which constructor a new secret-bearing local needs depends on what sits between its fill and its wrap.** A secret slot is dirty between its last write and its wipe. Three exit classes can leave a function inside that window, and a trailing `.zeroize()` statement covers none of them: **E1** an unwinding panic, **E2** a `?` on a fallible call after the fill, **E3** an explicit `return Err(...)` after the fill.

- **If a fallible or panicking call sits between the fill and the wrap** — an Argon2/HKDF derivation, a bridge call, a foreign-runtime accessor call (`PyBytes::new` et al. can panic), decoding into a fixed-size array behind a length check that can fail — **wrap first, fill through the wrapper**: `Sensitive::try_build(init, |slot| { /* fallible fill; last expr is Result<(), E> */ })`, or `Sensitive::build(init, |slot| { /* infallible fill */ })` if it truly cannot fail (e.g. `rng.fill_bytes`). `Drop` then wipes on every exit — return, `?`, or unwind — with no statement for control flow to skip. **This is the lead choice for any new secret-bearing local live across a fallible call.**
- **Only when the fill is provably adjacent** — nothing panicking or fallible intervenes before the wrap — does the older `let mut stack_var = ...; let s = Sensitive::new(stack_var); stack_var.zeroize();` trailing-wipe form remain correct, and it stays the pattern at sites like `crypto::kem::decap`'s intermediate copies and most `vault::block`/`sync` key-extraction sites. Don't convert a provably-adjacent site to `build`/`try_build` "for consistency" — that's unjustified churn on frozen-adjacent crypto code (design spec for #513, §6). (One adjacent site — `unlock::create_vault_unchecked`'s `ibk` — was converted anyway during #513, but that was a pre-authorised opportunistic call recorded in the design spec at the time, not a "for consistency" cleanup made after the fact; see the memo's "A 50th conversion" note. That distinction is the rule, not an exception to it.)
- **If the secret is incrementally built from several byte slices** (e.g. an HKDF `ikm` concatenating multiple shared secrets) — use `SecretBytes::concat(&[a, b, c, ...])` (#524), not `build`/`try_build`. Wrapping first covers a panic during the fill but **not a reallocation**: if a hand-written capacity is ever wrong, a growing push reallocates, and the allocator frees the *old* buffer unwiped while `Drop` only ever wipes whatever buffer the `Vec` points at when it drops — the new one. `concat` derives capacity and performs every push from the same slice list in one function, so the two cannot drift and no reallocation can occur. Don't "simplify" a `concat` call back to `try_build` — that reintroduces exactly this hazard.
- **If a secret must cross a foreign serialisation boundary** (encoding a `SecretString`/`SecretBytes` into `ciborium::Value`, or parsing untrusted CBOR back into one) — the two hazards above (fill-then-wrap, incremental-build realloc) don't cover this case, because the foreign type's own allocator, not this crate's fill logic, is what's under-controlled. Two mechanisms, matched to which side owns the allocation (#547, #548):
  - **We own the allocation (encoding a secret out)** — prefer a **borrowing mirror** over copying into the foreign type. `CanonicalValue`/`CanonicalMap` ([core/src/vault/canonical/value.rs](core/src/vault/canonical/value.rs)) is a borrowing mirror of the CBOR subset the vault format uses: every leaf borrows straight out of a `SecretString`/`SecretBytes` (`Text(&'a str)`, `Bytes(&'a [u8])`) instead of copying into an owned `ciborium::Value::{Text,Bytes}`, and `CanonicalMap` sorts its keys by `(key.len(), key.as_bytes())` read straight through the borrowed `&str`s, so **no key buffer is ever materialised** (the sort does allocate a small `Vec<usize>` index permutation — pointers and lengths, never key bytes; "allocation-free" overstated it, and `value.rs`'s own module doc has the precise wording) — which matters when the keys themselves are decrypted plaintext (record field names). A copy that never exists needs no wipe and can't be missed by a future caller; elimination is strictly stronger than the wrap below wherever it's achievable.
  - **The foreign type owns the allocation (a parser's output)** — you can't eliminate that copy, only wipe it. `SecretValueTree`/`SecretEntries` ([core/src/cbor/secret_tree/](core/src/cbor/secret_tree/)) wrap a parsed `ciborium::Value` (or entry list) and recursively zeroize `Bytes` and `Text` through `Array`/`Map`/`Tag` on `Drop`, covering the parser's own allocation on every exit — including an early `?` or an unwinding panic — that a bare `Value`'s ordinary drop does not. **What this does not claim:** freed heap is not observable from safe Rust, and a reallocation `ciborium`'s parser performed internally, before the wrapper ever sees the value, predates the wrapper and is not covered. `SecretValueTree` covers the buffer the tree points at when it drops — a value cloned *out* of the tree beforehand is an ordinary, unwiped allocation from that point on. The parser's *scratch* buffer (as opposed to the tree it builds) is a separate gap, closed by `cbor::scratch::from_secret_reader` ([core/src/cbor/scratch.rs](core/src/cbor/scratch.rs)), which owns `ciborium`'s `[0u8; 4096]` staging buffer and wipes it on every exit; five secret-bearing decode sites route through it and the two that do not each say why in source (it was six until #569 path 2 deleted the manifest encoder's `unknown_value_inner`, whose re-parse was the sixth — note the grep that `scratch.rs`'s doc comment names returns six ROWS against five call sites, the sixth row being that doc comment itself). What that does NOT close is the parser growing a payload buffer from capacity 0 above 4 KiB, freeing unwiped prefixes as it doubles (#570).

  See `docs/manual/contributors/memory-hygiene-audit-internal.md`, "Resolved: canonical-CBOR codec-boundary residue (#547, #548)" for the full six-copy trace this pair of mechanisms closes and the four production `SecretValueTree`/`SecretEntries` roots (`record`, `block`, `bundle`, `manifest`); its own "Resolved: cbor-residue-closeout follow-up" section (#561, #565–#569) covers what a later slice closed on top of it (#570 is named there too, but deliberately documented rather than closed) — the `re_encoded` re-check buffer is no longer on that memo's open list; `UnknownValue` having no `Zeroize` impl still is. A third section, "Resolved: manifest-closeout (#571, #569 path 2)", covers the last two encode-side residues: the bundle encoder returning `SecretBytes` and the manifest encode path borrowing rather than copying. Read its "what this does not claim" paragraph before citing either — #571 pins a TYPE and performs no new wipe, and #569 path 2's elimination is ENCODE-side only, leaving manifest DECODE still cloning every `block_name` into a plain, non-zeroizing `String`.
- **If a function's output is *always* secret** (a canonical encoding of decrypted
  content, an AEAD body) — return the wrapper, don't ask callers to apply one.
  `record::encode` / `block::encode_plaintext` / `encode_manifest` return
  `SecretBytes`, and `encrypt_manifest_body` takes `&SecretBytes` (#558, #565).
  A `SecretBytes::new(f()?)` at a call site is deletable with the whole suite
  green — verified by execution — because the derive gives no observable
  signal. Moving the wrapper into the return type makes the deletion a compile
  error. Note the boundary: this is right where the output is *always* secret,
  and wrong for a general primitive. `aead::encrypt` deliberately still takes
  `&[u8]`, because its plaintext genuinely is not always secret — the RFC-vector
  KATs encrypt literals.

**#513/#518/#503 are code-complete (2026-08-11); the tracker issues stay open per the `(#N)`-not-`Closes #N` convention noted elsewhere in this file.** A 101-site census across `core/src` and all three FFI crates found 49 real windows (9 core, 3 ffi-uniffi — the `device_secret` sites #513 originally named — 37 ffi-py) plus a thirteenth stack-residue gap the 2026-05-02 audit had itself missed, and closed all of them — **50 sites in total**, not 49: one further `core/src` site (`create_vault_unchecked`'s `ibk`) was classified ADJACENT, not WINDOW, but converted anyway, pre-authorised opportunistically by the design spec (see the bullet above and the memo's "A 50th conversion" note).

**Do not read that as "50 sites now call `Sensitive::build`."** Only **12** production sites use the new constructor pair (6 `core`, 3 ffi-py, 3 ffi-uniffi). The other 38 — including all 37 ffi-py sites and both #518 fixes — were closed by moving an *existing* `SecretBytes::new` / `SecretString::new` / `Sensitive::new` **earlier**, so the value is wrapped before the call that could panic. For a `Vec<u8>`/`String` argument that arrives already filled, "wrap before **filling**" is the wrong description twice over; what changed is wrap-before-**use**. The memo's per-row "Fixed in" column names the actual mechanism per site — prefer it over any summary, including this one.

**Two later corrections, each falsifying something an earlier version of this section asserted.** (1) A **fourteenth** gap: `from_canonical_cbor`'s `ml_kem_768_sk_bytes` / `ml_dsa_65_sk_bytes` stayed `Option<Vec<u8>>` while their X25519/Ed25519 siblings became `Sensitive`, so an early `?` at any preceding struct-literal field freed a 2400-byte ML-KEM-768 decapsulation key and an ML-DSA-65 secret key to the allocator unwiped — and the comment at that site asserted the opposite. Like the thirteenth, it was invisible to the census because the census greps for `.zeroize()` calls and these never had one: **"has no wipe to find" is its own search, not a corollary of the grep.** (2) The census's four scan roots are not the repo. `desktop/src-tauri/src` sat outside all of them and held two genuine E1 windows — the master password (`secret_arg.rs`) and revealed field plaintext (`reveal.rs`) — now converted; `cli/src` has none. A grep-driven census inherits the blind spots of BOTH its pattern and its roots, and neither is visible from inside it.

`zeroize::Zeroizing<T>` — the fix #513 originally suggested — was **considered and rejected**: `zeroize` 1.8.2 derives `Debug` on it (forwards to the inner value, so a stray `{:?}` prints the secret) and a derived, variable-time `PartialEq` — both properties `Sensitive<T>`/`SecretBytes`/`SecretString` deliberately omit. Full per-site table, the two `catch_unwind` citations proving neither FFI boundary kills the host process on panic, and the corrected gap count: [`memory-hygiene-audit-internal.md`](docs/manual/contributors/memory-hygiene-audit-internal.md), "Panic- and error-safe secret slots." One residual is explicitly **not** fixed by this pass and tracked as **#519**: `ffi/secretary-ffi-uniffi`'s four secret accessors (`take_secret`/`take_phrase`/`expose_text`/`expose_bytes`) have no Rust-side wipe at all — lowering happens in UDL-generated code this crate doesn't own, so there is no local to wrapper-type; needs a custom UDL type with hand-authored `Lower`/`Lift`, or upstream support.

**`RecordFieldValue` is zeroize-typed** as of PR #16: `Text(SecretString)` and `Bytes(SecretBytes)` (both `Zeroize, ZeroizeOnDrop`). The previously-unzeroized `Text(String) / Bytes(Vec<u8>)` form has been retired. Don't add new secret-bearing fields to `Record` / `RecordField` without thinking about whether they should be zeroize-typed — and don't widen the existing fields' lifetimes (e.g. by stashing them in caches, hash maps, or async closures) without weighing the same tradeoff.

### Internal audit memos

Phase A.7's internal hardening track produced three contributor-facing memos in [docs/manual/contributors/](docs/manual/contributors/):

- [`differential-replay-protocol.md`](docs/manual/contributors/differential-replay-protocol.md) — cross-language decoder-agreement contract used by the fuzz harness.
- [`side-channel-audit-internal.md`](docs/manual/contributors/side-channel-audit-internal.md) — constant-time-sensitive call sites + upstream-crate assumptions for the paid external reviewer.
- [`memory-hygiene-audit-internal.md`](docs/manual/contributors/memory-hygiene-audit-internal.md) — wrapper discipline + drop ordering + the stack-residue gaps fixed in commit `6054185` (twelve; a thirteenth found and closed, along with every panic/early-return-unsafe secret slot across `core` and all three FFI crates, on 2026-08-11 — #513/#518/#503).

Together these are the **principal handoff documents** for the paid external review. When you change a secret-handling code site or a constant-time-sensitive comparison, re-read the relevant memo's section first to make sure the change preserves the documented invariants.
