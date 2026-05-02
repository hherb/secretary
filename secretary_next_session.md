# secretary — next session entry point

This file is the entry point for the **next** session, in the same role
the previous `secretary_next_session.md` played until 2026-05-02 (closed
on the merge of PRs #11 and #12 — fuzz-finding triage and the NiceGUI
monitor live-telemetry pass — followed by a thirteen-commit post-PR-#12
**monitor stabilisation wave** landing direct-to-main: pulse parser fix
for libFuzzer's Kb-form corp size, plateau auto-stop reaching the fuzz
subprocess via process-group signalling, `Status.DIED` distinct from
user-driven `STOPPED`, `oom-*` / `slow-unit-*` artefacts surfaced as
findings, dedicated heartbeats deque so plateau detection survives
NEW/REDUCE log traffic, sparkline + plateau dot strip, `--careful`
instead of UBSan, and small mypy / regression hygiene).

**Sub-project A is feature-complete for v1**; Phase A.7 (hardening +
external audit) is in progress. The fuzz-harness sub-track is now
through its post-scaffold shake-out — fresh runs raise no findings,
the dashboard surfaces telemetry correctly, and the six fuzz targets
have stayed green across multiple campaigns. The most concrete
near-term work is the **standing Phase A.7 track**
([Open Item 3](#open-item-3--phase-a7-standing-track) below), with
small entry points called out at the end of that section.

When the items below are done, delete this file and create the next one.

Sub-project A's design anchor lives at
`/Users/hherb/.claude/plans/we-are-starting-with-logical-newt.md` —
re-read at the start of any session that touches Sub-project A code.
The "Verification" section (around line 375, especially the §15
cross-language conformance contract) is the load-bearing part for
Phase A.7.

---

## Phases now closed (kept for context)

### Phase A.1 — Cryptographic primitives ✅ — pre-PR #1

NIST KAT-pinned implementations of the v1 cipher suite:
`crypto::{aead, kdf, hash, sig, kem}`. KATs in
[core/tests/data/*.json](core/tests/data/) loaded by the shared
[core/tests/kat_loader.rs](core/tests/kat_loader.rs).

### Phase A.2 — Identity ✅ — pre-PR #1

[core/src/identity/](core/src/identity/): identity seed, role-keyed
derivation (auth, KEM, recovery), Contact Cards, recipient fingerprints.
Position-specific signature roles (`SigRole::Block`, `SigRole::Manifest`,
…) so a signature for one purpose cannot be replayed in another.

### Phase A.3 — Unlock module ✅ — PR #1, 2026-04-27

[core/src/unlock/](core/src/unlock/): BIP-39 24-word mnemonic
generate/parse, identity bundle (master KEK + recovery KEK dual wrap),
`vault.toml` cleartext metadata, three orchestrators (`create_vault`,
`open_with_password`, `open_with_recovery`). Argon2id v1 floor enforced
as a typed error. BIP-39 recovery KAT in
[core/tests/data/bip39_recovery_kat.json](core/tests/data/bip39_recovery_kat.json)
(4 vectors: all-zero, all-FF, two Trezor canonical 24-word).

### Phase A.4 — Vault block file format ✅ — PR #3 (PR-A), 2026-04-28

[core/src/vault/{record,block}.rs](core/src/vault/):

- `Record` types (login, secure note, API key, SSH key, custom) with
  canonical CBOR encode/decode (RFC 8949 §4.2.1) and a forward-compat
  `UnknownValue` opaque wrapper preserving bit-identical round-trips at
  record + field level.
- Binary block file: header (§6.1, 58 B prefix + vector clock), recipient
  table (§6.2, 1208 B/entry, sorted by fingerprint), AEAD body under
  per-block content key (§6.3), trailing hybrid signature suffix (§8).
- `encrypt_block` / `decrypt_block` orchestrators as free `fn`s.
  Verify-before-decap structurally enforced: a forged file never triggers
  a private-key operation.
- §15 block KAT: [core/tests/data/block_kat.json](core/tests/data/block_kat.json)
  parsed wire-format-only (at the time) by
  [core/tests/python/conformance.py](core/tests/python/conformance.py).
- ML-DSA-65 NIST sigGen KAT (`ml_dsa_65_nist_siggen_kat`,
  [core/tests/sig.rs](core/tests/sig.rs)): 5 ACVP-Server vectors
  asserting NIST signatures come out byte-for-byte through our signer.

### Phase A.5 — Manifest layer + atomic I/O + orchestrators ✅ — PR #5 + PR #6, 2026-04-29

[core/src/vault/{manifest,io,canonical,orchestrators}.rs](core/src/vault/):

- **Manifest** ([manifest.rs](core/src/vault/manifest.rs)):
  AEAD-encrypted under Identity Block Key with AAD = manifest header
  bytes (§4.1), hybrid-signed with `SigRole::Manifest`, per-block
  fingerprint table, vault-level vector clock (`tick_clock` errors on
  `u64::MAX` overflow, does not saturate), `kdf_params`,
  `owner_user_uuid`, trash list. `VectorClockEntry` is re-exported from
  the block layer — same shape, same purpose.
- **Atomic I/O** ([io.rs](core/src/vault/io.rs)): write-temp + fsync +
  rename + parent-dir fsync, per ADR-0003. `tempfile` exact-pinned
  (`=3.27.0`) as a security-critical path dependency.
- **Shared canonical-CBOR helpers** ([canonical.rs](core/src/vault/canonical.rs)):
  `canonical_sort_entries`, `encode_canonical_map`, the float/tag
  walker, extracted before the third copy could land.
- **Orchestrators** ([orchestrators.rs](core/src/vault/orchestrators.rs)):
  `create_vault`, `open_vault`, `save_block`, `share_block`. §4.3
  step 5+6 cross-checks (`vault_uuid`, `kdf_params`); author-equals-
  identity precondition on `share_block`; share-as-fork TODOs pinned
  for the v2 follow-up.
- **§15 closure**: [core/tests/data/golden_vault_001/](core/tests/data/golden_vault_001/)
  end-to-end verified by
  [core/tests/python/conformance.py](core/tests/python/conformance.py)
  (full hybrid-decap + AEAD-decrypt + hybrid-verify, stdlib-only,
  `uv run`-compatible). A regression test pins the silent-accept bug
  found and fixed in the Python ML-DSA-65 verifier during this phase
  (PR #6 commit `1c90852`).

### Phase A.6 — Vector-clock CRDT merge primitives ✅ — PR #7 (PR-C), 2026-04-29; polished PR #9, 2026-05-01

[core/src/vault/conflict.rs](core/src/vault/conflict.rs) — pure
functions, no I/O, no scheduling:

- **Vector-clock primitives**: `clock_relation` (anti-symmetric,
  missing-device-as-zero); `merge_vector_clocks` (lattice join,
  sorted ascending by `device_uuid` per §6.1).
- **Per-record merge** with field-level LWW + record-level death
  clock (`tombstoned_at_ms`); `device_uuid` lex tiebreak on
  `last_mod` ties; tombstone-on-tie; concurrent value collisions
  surfaced as informational `FieldCollision` metadata (no
  `_conflicts` shadow on disk per §11.4).
- **Per-block merge** dispatching on `clock_relation`; ticks the
  merging device into the merged clock for `Concurrent`; `block_uuid`
  mismatch surfaced as a typed error.
- **§11.3 identity-metadata override**: on `LocalTombstoneWins` /
  `RemoteTombstoneWins`, `tags`, `record_type`, and record-level
  `unknown` come wholesale from the tombstoning side.
- **Bidirectional defensive death-clock clamp** (PR #9): both `local`
  and `remote` clamped before lattice join, so a malformed peer
  (`tombstone = true, tombstoned_at_ms = 0`) cannot suppress death-clock
  advance from either side.
- **Tag canonicalisation on the LWW-clone path** (PR #9): well-formedness
  invariant holds bit-identically on every output.
- **CRDT proptests**: commutativity, associativity, idempotence, and
  well-formedness (Property L) at proptest defaults, all four passing
  on the **full record domain** — arbitrary `tombstone`, arbitrary
  `tombstoned_at_ms`, arbitrary `unknown`.
- **§15 cross-language KAT**: 11 vectors in
  [core/tests/data/conflict_kat.json](core/tests/data/conflict_kat.json)
  replayed bit-identically by Rust (`kat_replays_match_rust_merge`)
  and a clean-room Python `py_merge_record` + `py_merge_unknown_map`
  written from §11 spec docs only.

### Fuzz harness + NiceGUI monitor + differential-replay protocol ✅ — PR #8, 2026-05-01

[core/fuzz/](core/fuzz/) — coverage-guided `cargo-fuzz` harness on a
path-scoped nightly toolchain. Phase A.7's first concrete output.

- **Six fuzz targets** ([core/fuzz/fuzz_targets/](core/fuzz/fuzz_targets/)):
  `block_file`, `bundle_file`, `contact_card`, `manifest_file`, `record`,
  `vault_toml`. Each runs the production decoder and asserts `Result`
  rather than panic. Seeded from §15 KAT fixtures plus hand-built golden
  inputs in [core/fuzz/seeds/](core/fuzz/seeds/).
- **NiceGUI monitor** ([core/fuzz/monitor.py](core/fuzz/monitor.py)):
  single-file PEP-723 dashboard, `uv run`-compatible. Spawns
  `cargo +<nightly> fuzz run` per target, parses libFuzzer pulses,
  detects exec/coverage plateaus and SIGTERMs the run. Pure functions
  for parsing / plateau / env / runs-cap; subprocess and UI side held at
  the edges.
- **Differential-replay protocol**: cross-language decoder agreement
  contract documented at
  [docs/manual/contributors/differential-replay-protocol.md](docs/manual/contributors/differential-replay-protocol.md);
  Rust and Python harnesses with per-input timeout bounding the Python
  subprocess so a single pathological input cannot stall a campaign.
- **Operator docs**: [core/fuzz/README.md](core/fuzz/README.md) — how to
  run targets, how to promote findings into durable regression KATs.

### User and contributor manual ✅ — PR #10, 2026-05-01

[docs/manual/](docs/manual/): thirteen-chapter cryptography primer at
[docs/manual/primer/cryptography/](docs/manual/primer/cryptography/index.md)
plus user-facing operational hardening guide at
[docs/manual/hardening-security.md](docs/manual/hardening-security.md).
14 files, +1556 lines, no source changes.

### Fuzz-finding triage + parser-side display_name cap ✅ — PR #11, 2026-05-01

[core/tests/data/fuzz_regressions/](core/tests/data/fuzz_regressions/):
six libfuzzer artefacts (two OOMs in `contact_card`, two OOMs in
`record`, two slow-units in `vault_toml`) promoted as durable regression
tests. None reproduced against current main on direct replay or fresh
campaigns; most plausible cause was libfuzzer's RSS sampler attributing
limit-crossing events to whichever input was running. Fresh 5-minute
campaigns × 3 targets (≈25.7 M total executions) produced zero new
findings.

While reading the contact-card decoder during triage, a real
peer-supplied DoS surface was caught: `display_name` was unbounded
variable-length CBOR text, and the orchestrator at
[core/src/vault/orchestrators.rs:509](core/src/vault/orchestrators.rs#L509)
reads contact-card bytes that may originate from a sync peer. Capped at
4 KiB on parse with a new `CardError::DisplayNameTooLong` variant; cap
enforced **symmetrically on encode** as well, so internal callers can't
accidentally produce an over-cap card.

### Monitor live-telemetry ✅ — PR #12, 2026-05-01

[core/fuzz/monitor.py](core/fuzz/monitor.py) — closed the dashboard
scaffold gap that surfaced when running PR #8's monitor against PR #11's
real campaigns:

- Reactive status badge (per-status colour) driven from the same per-card
  timer that owns crash detection — surfaces `IDLE` / `RUNNING` /
  `PLATEAU` / `CAP_REACHED` / `CRASHED` / `STOPPED` reactively rather
  than only on Start/Stop button presses.
- Per-card live readout: `cov / ft / corp / exec/s / rss` from
  `pulses[-1]`; `—` when pulses is empty (distinguishes "no data yet"
  from "telemetry says zero").
- Elapsed time (`mm:ss`, frozen on terminal status) + `exec_count /
  runs_cap` progress.
- Global findings counter above the grid: scans
  `core/fuzz/artifacts/<target>/` once per second and surfaces a
  per-target tally.
- Runs-cap input label clipping fix (`"runs cap (blank = ∞)"`).

### Post-PR-#12 monitor stabilisation wave ✅ — direct-to-main, 2026-05-01 → 2026-05-02

Thirteen commits landed direct-to-main once PRs #11/#12 were merged and
real campaigns started exercising the dashboard end-to-end. None warranted
a separate PR cycle; each is a focused fix with the linked GitHub issue
giving the failure mode it addressed:

- **`e717ab7` — pulse parser for libFuzzer's `<int>Kb` corp size form
  ([#13](https://github.com/hherb/secretary/issues/13))**: 4 of 6 fuzz
  targets never produced a pulse readout because libFuzzer emits corp
  size in either bytes or kilobytes (`Kb`), and the parser regex only
  matched the byte form. Tightened regex + unit test.
- **`0b14bbe` — signal cargo-fuzz's process group so plateau auto-stop
  fires ([#14](https://github.com/hherb/secretary/issues/14))**: the
  plateau detector was sending SIGTERM to `cargo fuzz`'s parent pid, which
  did not propagate to the grandchild fuzzer process; campaigns with
  long-static cov+corp ran past their plateau threshold indefinitely.
  Switched to `os.killpg(os.getpgid(proc.pid), SIGTERM)` and made the
  fuzz subprocess its own group leader on spawn.
- **`f118b4e` — `Status.DIED` distinct from user-driven `STOPPED`
  ([#15](https://github.com/hherb/secretary/issues/15))**: a fuzzer that
  exited on its own without producing a crash artefact was being
  reported identically to a user-clicked Stop. New `Status.DIED` enum
  variant with a distinct badge colour disambiguates the two.
- **`6892f23` — surface `stop_reason` + last 20 stderr lines per card**:
  when a campaign terminates abnormally, the dashboard now shows why
  inline rather than requiring the user to dig through stderr.
- **`1f7a2a2` — replace ubsan / `--sanitizer=undefined` with
  `cargo fuzz --careful`**: the UBSan-bundled flag was unstable on the
  pinned nightly; `--careful` enables a more reliable subset of extra
  checks.
- **`dd5c21f` + `71f60d2` — plateau check considers pulses only,
  dedicated heartbeats deque**: the plateau detector was being defeated
  by libFuzzer's NEW/REDUCE log lines (each one bumped the heartbeat
  even when no real exec was happening). Filter to pulse events only;
  use a dedicated heartbeats deque so plateau check survives parallel
  NEW/REDUCE traffic.
- **`588d24e` — detect `oom-*` / `slow-unit-*` artefacts as findings**:
  the global findings counter was crash-only; libFuzzer's two other
  artefact prefixes (`oom-*`, `slow-unit-*`) are real findings too,
  surfaced with the same CRASHED badge.
- **`f8ca636` + `f69ee81` — per-card cov sparkline + plateau dot strip
  + design spec**: visual cue for "is coverage still growing?" at a
  glance across six cards.
- **`38d6c05` — fix KeyError when 'both' radio selected**: regression
  in the sanitiser-mode radio button.
- **`a89dac4` — silence pre-existing mypy import-not-found on nicegui +
  pytest**: `# type: ignore[import-not-found]` on the two third-party
  imports that don't ship type stubs, so `mypy core/fuzz/` runs clean.

After this wave: 430 tests pass + 6 ignored; the dashboard reports six
healthy targets with live telemetry under multi-target concurrent
campaigns. Issues #13 / #14 / #15 closed 2026-05-02 with one-line
`gh issue close N -c "Fixed in <sha>"` referring to `e717ab7` /
`0b14bbe` / `f118b4e` respectively (the fix commits had landed
direct-to-main without `Closes #13` / etc. footers).

---

## Open Item 1 — Fuzz-finding triage (from PR #8) ✅ closed

Closed in PR #11 + PR #12 + the post-#12 monitor stabilisation wave.
Step 1 (`.gitignore` gap) was already in place via per-crate
[core/fuzz/.gitignore](core/fuzz/.gitignore). Step 2 (triage the six
findings) found that none reproduced against current main; the inputs
were promoted as committed regression tests anyway, and a real
peer-supplied DoS surface in `display_name` was capped at 4 KiB on
parse + encode. Step 3 (live telemetry) surfaced status, pulse readout,
elapsed time, and a global findings counter — and the post-#12 wave
fixed the four issues that surfaced once real campaigns started using
the dashboard.

Historical record at [docs/TODO_FUZZ_FOLLOWUP.md](docs/TODO_FUZZ_FOLLOWUP.md).

---

## Open Item 2 — Polishing dribbles (from PR #9 review)

Captured in [docs/TODO_FINAL_POLISHING.md](docs/TODO_FINAL_POLISHING.md).
None are regressions or correctness issues — deferred polish to be
picked up when adjacent code is next touched:

1. Replace `# type: ignore[arg-type]` in `py_merge_unknown_map` with an
   explicit `assert r_hex is not None`
   ([conformance.py:955](core/tests/python/conformance.py#L955)).
2. Lift the cross-language hex compare pattern into a
   `hex_lex_compare` / `hex_canonicalise` helper *if* a second
   hex-bearing KAT field appears.
3. Extract a `_record_pass_fail()` helper *if* a Section 6 with five+
   sub-tests lands.
4. Confirm at least one `conflict_kat.json` vector exercises
   block-level `unknown_hex` (not just record-level); add one if
   none does. **Smallest concrete entry point** of the four — pick this
   up first if a session has 30 minutes of slack.

When the file becomes empty, **delete it** in the same commit.

---

## Open Item 3 — Phase A.7 standing track

The hardening + external-audit gate before Sub-project B (FFI) work
can begin. Open Items 1 and 2 are subsets; this is the rest.

### External (paid)

- **Independent cryptographic review**. Engage early — the design has
  been frozen since the PR #1 / #3 / #5 cadence and PR #7 / #9
  polishing has stabilised the merge layer, so the spec docs are stable
  enough to send out. Especially valuable: reviewer with FIPS 203 /
  FIPS 204 implementer experience and AAD/signed-range eyes.
- **Side-channel review**. Constant-time critical paths:
  - All AEAD verify-then-decap flows (already structurally verified
    per PR #3; needs constant-time primitive review).
  - `Fingerprint` comparison and recipient-table lookup.
  - Argon2id comparison sites in unlock paths.

### In-session (concrete entry points)

- **Documentation pass — `docs/threat-model.md`** ✅ closed 2026-05-02.
  Refreshed against the as-implemented surface; six commits
  (`c55ce3e`, `f65185d`, `10c4945`, `e4b3d9c`, `cb1a0b1`, `494b41a`)
  fixing four divergences and refreshing the §5 verification trace.
  Detail in [What previous sessions delivered](#docs-threat-model-refresh--2026-05-02)
  below. The two §6.1 / §6.2 spec-doc annotations that earlier
  next-session files carried forward as "trivial doc tickets" turned
  out to have been shipped in `c47c17c` (2026-04-28); the TODO
  propagated through several next-session generations — surfaced and
  removed 2026-05-02.
- **Side-channel internal pass** ✅ closed 2026-05-02. Audit memo at
  [docs/manual/contributors/side-channel-audit-internal.md](docs/manual/contributors/side-channel-audit-internal.md).
  No bugs in our code; all CT-sensitive comparisons delegate to
  upstream RustCrypto crates. One concrete hardening item applied:
  doc-comment on `Fingerprint = [u8; 16]` explaining it's a public
  value by design (commit `e921e99`). Detail in
  [What previous sessions delivered](#docs-side-channel-audit-internal--2026-05-02)
  below.
- **Memory hygiene audit** ✅ closed 2026-05-02. Audit memo at
  [docs/manual/contributors/memory-hygiene-audit-internal.md](docs/manual/contributors/memory-hygiene-audit-internal.md).
  Wrapper discipline + composite-type drop ordering verified clean.
  Twelve stack-residue gaps fixed in commit `6054185` (one-line
  pattern: `var.zeroize()` after `Sensitive::new(var)` — sister sites
  to existing well-disciplined ones). Detail in
  [What previous sessions delivered](#docs-memory-hygiene-audit-internal--2026-05-02)
  below. **Three deferred items** rolled forward as new follow-ups —
  see "Carry-over dribbles" below.

With all three in-session A.7 entry points closed (threat-model
refresh, side-channel internal pass, memory-hygiene audit), Open Item
3's remaining work is **external-reviewer-facing**: independent crypto
review (paid) and side-channel review (paid). The internal pass
memos at `docs/manual/contributors/side-channel-audit-internal.md`
and `memory-hygiene-audit-internal.md` are the principal handoff
documents — together they enumerate every upstream-crate assumption
and every deferred design decision the external reviewer should know
about.

End of Sub-project A: Rust core is feature-complete for v1, audited,
and ready to be wrapped by FFI in Sub-project B (which then unblocks
Sub-project C — sync orchestration — and Sub-project D — platform UIs).

---

## Carry-over dribbles

Small open items not big enough to merit their own phase. Bundle into
the next PR they touch.

- **`share-as-fork` v2 follow-up.** PR #5 / #6 pinned two TODO markers
  for share-as-fork at the encrypt/decrypt call sites. This is a v2
  vault-format change (out of scope for Sub-project A); PR #7 / #9 did
  not touch them, and the post-PR-#12 monitor wave was Python-side only.
  Re-validate when Sub-project C orchestration brings the share path
  back into focus.
- **`records_to_value` / `take_records` byte round-trip.** Defer until
  profiling shows it on a hot path. The merge primitives operate on
  already-decoded `Record`s.
- **Record-content zeroize-on-drop (v2).** Surfaced by the
  memory-hygiene audit 2026-05-02. `RecordFieldValue::{Text(String),
  Bytes(Vec<u8>)}` hold the user's actual passwords / secret notes /
  API keys *without* zeroize-on-drop — the most-sensitive data in the
  system, only secret-bearing data NOT zeroized. Fix is non-trivial:
  `SecretString`-typing ripples through ~100 test sites + the Python
  conformance verifier. Raise as a v2 design discussion alongside any
  other v2 hardening (e.g. forward secrecy at the block level,
  threat-model §4 limitation 1). Detail at
  [docs/manual/contributors/memory-hygiene-audit-internal.md](docs/manual/contributors/memory-hygiene-audit-internal.md)
  "Deferred items §1".
- **`MlDsa65Secret` / `MlKem768Secret` newtype `Zeroize` derives.**
  Both wrap `SecretBytes` (which IS Zeroize-on-drop) so the bytes
  zeroize correctly on drop, but the newtypes don't expose
  `.zeroize()` programmatically. Cosmetic — no current call site
  needs explicit `.zeroize()`. Pick up alongside any other newtype
  work.
- **`hkdf` 0.12 internal HMAC state residue.** Already documented as
  a SECURITY note in
  [core/src/crypto/kdf.rs:216-223](core/src/crypto/kdf.rs#L216-L223).
  Out of our control until upstream `hkdf` ships zeroize support.
  Watch upstream and re-evaluate when a new release lands.
- **Spec-doc test-name freshness.** Surfaced 2026-05-02: the §5
  verification trace in `docs/threat-model.md` had drifted (4 stale
  test names plus ~20 missing entries) because nothing prevented
  rename-without-spec-update. A small mechanical CI check would catch
  the drift early — extract every `` `<identifier>` `` mention from
  `docs/*.md` whose pattern looks like a Rust function name, then
  `grep -r` for it under `core/`. Anything that doesn't resolve is
  either a stale spec citation or a test that was renamed without
  thinking about the spec. Out of scope for Sub-project A unless the
  next freshness check uncovers material drift; bundle into Sub-
  project B's tooling once the Rust core is closed out.

---

## Housekeeping

One-shot tasks, neither features nor polish — just things to clear
from the queue. Pick up at the start of any session.

- **Worktree hygiene**: `.worktrees/fuzz-triage` and
  `.worktrees/monitor-telemetry` were both pruned 2026-05-02 along
  with their squash-merged local branches. New worktrees go under
  `.worktrees/<topic>/` per the standing preference.
- (No open housekeeping items at session start. Issues #13 / #14 /
  #15 closed 2026-05-02 referencing the in-tree fix commits.)

---

## What previous sessions delivered

### PR #5, `feature/vault-manifest` — 2026-04-28 → 2026-04-29

Phase A.5 in one PR. ~30 commits — manifest + atomic I/O + orchestrators
+ golden-vault. Key shapes: four orchestrators (`create_vault`,
`save_block`, `open_vault`, `share_block`); §4.3 step 5/6 cross-checks;
`tick_clock` errors on `u64::MAX`; `BTreeMap<String, ()>` →
`BTreeSet<String>` for `seen_keys`; 345 tests pass + 6 ignored.

### PR #6, `chore/pr-b-review-followups` — 2026-04-29

PR-B review follow-ups: `8236ae7` orchestrators split into
`orchestrators.rs`; `069c0ce` exact-pin `tempfile = "=3.27.0"` for
the security-critical atomic-write path; `9fda717` + `1c90852` fix and
regression-test for a silent-accept bug in the Python ML-DSA-65
verifier; `121e7c2` + `75390ac` share-as-fork TODO markers pinned for
v2; `19604b6` caller-side nonce generation idiom documented in the
AEAD module.

### PR #7 (PR-C), `feature/vault-conflict` — 2026-04-29

Phase A.6 in one PR plus the death-clock follow-up after review
surfaced a three-way-merge associativity gap. ~19 commits along three
axes: spec first then code (`ca74791`, `de91797`, `94afacf`,
`34a5141`); implementation in step-by-step slices (`6752701`,
`a1e8468`, `7d293fa`, `f4f554b`, `2fc7f4e`, `65def86`, `d058fc9`);
tests at every layer. After merge: 399+ tests pass + 6 ignored.

### PR #8, `feature/fuzz-harness` — 2026-04-30 → 2026-05-01

Phase A.7's first concrete output. ~30+ commits along three axes:
fuzz crate scaffold + six targets seeded from §15 KAT fixtures and
hand-built golden inputs; NiceGUI monitor with pure-function building
blocks (parse pulse, parse targets from Cargo.toml, plateau check,
nightly toolchain locator, env builder, runs-cap parse) and subprocess
/ UI side held at the edges; differential-replay protocol documented
at [docs/manual/contributors/differential-replay-protocol.md](docs/manual/contributors/differential-replay-protocol.md)
with `--diff-replay` mode in `conformance.py` and a Rust harness with
per-input timeout. Findings: 4 (later 6) — all triaged in PR #11 as
libfuzzer false positives.

### PR #10, `docs/cryptography-primer` — 2026-05-01

Thirteen-chapter cryptography primer + user-facing operational hardening
guide. 14 files, +1556 lines, no source changes. Bonus material for
contributor onboarding.

### PR #9, `feature/vault-conflict` (re-used) — 2026-05-01

PR-C polish surfaced during review. Squash-merged as `e8a8d92`;
7 files, +959/-104. Spec changes (drop §11.3 record-level `unknown`
carve-out); implementation (bidirectional defensive death-clock clamp,
tag canonicalisation on the LWW-clone path); cross-language closure
(clean-room Python `py_merge_unknown_map` with case-insensitivity
self-test guarding raw-string-compare drift on hex blobs); test-domain
expansion (well-formedness Property L on arbitrary inputs; tenth and
eleventh KAT vectors). After merge: 425+ tests pass + 6 ignored.

### PR #11, `fix/fuzz-findings-triage` — 2026-05-01

Squash-merged as `20ebc05`. Six artefacts promoted as committed
regression tests under
[core/tests/data/fuzz_regressions/](core/tests/data/fuzz_regressions/);
contact-card `display_name` capped at 4 KiB on parse with a new
`CardError::DisplayNameTooLong` variant; cap enforced symmetrically on
encode (`c12da50`); regression-test contract documented at
[core/tests/fuzz_regressions.rs](core/tests/fuzz_regressions.rs) as
"must not panic" — explicitly **not** time-bounded
(`a6172a9 docs(fuzz-regression): scope contract to panic-bounds, not
time-bounds`).

### PR #12, `feat/monitor-live-telemetry` — 2026-05-01

Squash-merged as `bca091e`. Closed the dashboard scaffold gap:
reactive status badge, per-card live pulse readout, elapsed timer +
runs-cap progress, global findings counter, label-clipping fix. Plus
two non-trivial bug fixes that surfaced during the build:
`fe11a2a` replace `crash_label` class instead of appending (the
class-list was getting `text-positive text-warning text-negative` all
at once after a few transitions); `62664a9` freeze elapsed at actual
stop time, not next tick (the timer ran one extra second past STOP
because the freeze logic compared status *after* the tick computed
elapsed).

### Direct-to-main monitor stabilisation wave — 2026-05-01 → 2026-05-02

Thirteen commits, no PR. Detail in the
[Post-PR-#12 monitor stabilisation wave](#post-pr-12-monitor-stabilisation-wave---direct-to-main-2026-05-01--2026-05-02)
closed-phase entry above. Highlights: pulse-parser Kb form fix (#13),
process-group plateau-stop signalling (#14), `Status.DIED` (#15),
plateau-check pulse-only filtering, sparkline + plateau dot strip,
`--careful` instead of UBSan, `oom-*` / `slow-unit-*` finding
detection, mypy stubs-missing silencing, KeyError regression fix.

### Housekeeping commits — 2026-05-02

- `c75e675 chore: gitignore .playwright-mcp/ cache and root
  monitor-*.png screenshots` — first commit of the session.
- `8e5f41a docs: refresh next-session for post-PR-#12 monitor
  stabilisation wave` — initial refresh of this file.
- Issues #13 / #14 / #15 closed on GitHub referencing `e717ab7` /
  `0b14bbe` / `f118b4e` respectively.
- Pruned the two stale worktrees (`.worktrees/fuzz-triage`,
  `.worktrees/monitor-telemetry`) and their squash-merged local
  branches; added `CLAUDE.md` to `.git/info/exclude` so it stays
  local-only without surfacing as untracked.
- Discovered the §6.1 / §6.2 spec-doc annotation TODO that earlier
  next-session files carried forward had already been shipped in
  `c47c17c` (2026-04-28); removed the stale references from Open
  Item 3 and Carry-overs in this file.

### docs(threat-model): refresh — 2026-05-02

Six commits closing the **Documentation pass** in-session entry of
Open Item 3, surfaced four divergences between the threat-model
document and the as-implemented surface, and refreshed the §5
verification trace from 11 entries (with 4 stale test names) to ~30
entries grouped by primitive KAT / composite invariant / vault
format / CRDT / cross-language / fuzzing / structural.

- `c55ce3e docs(threat-model): fix §3.5 mix-and-match suite ID claim
  — v1 rejects, not allows`. The §3.5 row claimed mixed suite IDs
  were "allowed by design (per-block suite IDs enable gradual
  migration)". The implementation rejects any non-v1 suite_id at
  parse time (`ManifestError::UnsupportedSuiteId` at
  `core/src/vault/manifest.rs:705-706`; `BlockError::UnsupportedSuiteId`
  block-side). The migration capability is real but reserved for
  v2+; reframed the row to reflect v1's actual behaviour.
- `f65185d docs(threat-model): scope §3.4 trust-state claims to
  Sub-project D`. The §3.4 contact-card defenses referenced
  "verification state `unverified`", "prominent UI warning", and
  "user removes the contact" as if they were v1 invariants. They are
  not — v1 Rust core exposes only `ContactCard::from_canonical_cbor`
  + `verify_self` + 12-word fingerprint mnemonic; trust-state
  persistence and the warning UI are Sub-project D responsibilities.
  Reframed three rows to the actual core/UI boundary.
- `10c4945 docs(threat-model): add §3.1 death-clock row + §3.2
  Argon2id floor enforcement detail`. New §3.1 row crediting the
  per-record `tombstoned_at_ms` death clock (PR #7 + #9, §11.3 of
  crypto-design.md) as the defense against tombstone resurrection
  via concurrent-stale-block replay; the existing rollback rows
  cover block-level regressions but didn't enumerate this attack.
  §3.2 Argon2id row now distinguishes the v1 *default* (256 MiB / 3
  / 1, `V1_DEFAULT`) from the v1 *floor* (64 MiB,
  `V1_MIN_MEMORY_KIB`); the floor is enforced as
  `UnlockError::WeakKdfParams` at open time (was previously implicit
  in the threat-model).
- `e4b3d9c docs(threat-model): refresh §5 verification trace against
  current code`. Four stale test names fixed; ~20 missing entries
  added across 7 sections (Primitive KATs, Composite invariants,
  Vault format invariants, CRDT merge invariants, §15 cross-language
  conformance, Coverage-guided fuzzing, Structural invariants). All
  cited names verified against `core/tests/` and `core/src/` before
  commit. The display_name 4 KiB DoS cap (PR #11) is now traced;
  conflict_kat (11 vectors), CRDT proptests (commutativity,
  associativity, idempotence, well-formedness Property L),
  golden_vault_001 + Python `conformance.py`, and the six fuzz
  targets + their `must_not_panic` regression contract are all
  newly traced. Each test name and KAT-file name in §5 is now a
  contract; renaming requires a corresponding update to the trace.
- `cb1a0b1 docs(threat-model): add §4.8 — v1 has no UI; workflow
  defenses are Sub-project D` + `494b41a docs(threat-model): fix
  §4.8 cross-references to §4.3 + §3.4 + §3.5`. Promoted the
  Sub-project D scoping from inline §3.4 footnote to a top-level §4
  known-limitation so a reader who stops at §4 sees the
  core/UI-workflow boundary explicitly. The follow-up commit fixed
  an awkward "row 4 of §3.1" cross-reference to point at the
  correct §4 limitation 3 + §3.4 + §3.5.

After this wave: 430 tests pass + 6 ignored. The threat-model now
matches the as-implemented surface; subsequent material spec changes
should re-run the §5 freshness check (see "Spec-doc test-name
freshness" carry-over).

### docs(side-channel-audit-internal) — 2026-05-02

`e921e99 docs: side-channel internal audit + Fingerprint type-alias
doc-comment` — closes Open Item 3's **Side-channel internal pass**
in-session entry. Walks every constant-time-sensitive call site
flagged in threat-model §3.2/§3.3, identifies the upstream primitive
providing CT discipline, and writes the findings to a contributor-
facing memo at
[docs/manual/contributors/side-channel-audit-internal.md](docs/manual/contributors/side-channel-audit-internal.md).

Findings (all "no bug, but worth flagging"):

- AEAD verify-then-decap → `chacha20poly1305 = "0.10"` (RustCrypto;
  Poly1305 tag verify uses `subtle::ConstantTimeEq` internally).
- Hybrid signature verify → `ed25519-dalek = "2.2"` then
  `ml-dsa = "0.1.0-rc.8"` with `?` propagation between halves; early-
  return-on-Ed25519-fail is intentional and documented at the module
  level (signed messages, signatures, and verification keys are all
  public values).
- Hybrid KEM decap → X25519 + ML-KEM-768 both run unconditionally;
  AEAD MAC verify is the implicit-rejection check; intermediate
  buffers (`ikm`, `okm`, stack-copy `key`, `ss_pq_bytes`, `k`) are
  explicitly zeroized.
- Fingerprint `==` → intentional non-CT; fingerprints are public
  values appearing cleartext in the recipient table and manifest
  signed-headers. A timing leak reveals nothing the attacker cannot
  read off the cloud-folder copy.
- Argon2id unlock path → no equality comparison anywhere; the
  "wrong password" check is AEAD MAC verify on `wrap_pw` (CT in
  `chacha20poly1305`); v1 floor enforced as typed
  `UnlockError::WeakKdfParams` *before* any KDF runs.
- `subtle = "2"` is a direct dependency; the only API surface is
  `Sensitive<T>::ct_eq`. Zero production call sites by design — the
  verify-then-decap pattern means the codebase never has a "compare
  two secret byte strings" moment outside of AEAD MAC verify.

Principal output: a list of upstream-crate assumptions for the
external reviewer to verify, particularly `ml-dsa = "0.1.0-rc.8"`
where pre-1.0 hardening expectations are weaker than for an
established crate.

One concrete hardening item applied alongside the memo:
doc-comment on `Fingerprint = [u8; 16]` at
[core/src/identity/fingerprint.rs:35](core/src/identity/fingerprint.rs#L35)
explaining it's a public value *by design* (in contrast to
`Sensitive<[u8; 16]>` which would wrap a secret), with a pointer
to the audit memo's §4 for the full reasoning. Future contributors
who arrive at a `==` comparison on a `Fingerprint` see immediately
why non-CT is intentional.

After this commit: 430 tests pass + 6 ignored, clippy clean with
`-D warnings`. Side-channel internal pass is now ✅ closed; the
remaining in-session A.7 entry point is the **memory-hygiene
audit**.

### docs(memory-hygiene-audit-internal) — 2026-05-02

`6054185 docs: memory-hygiene internal audit + 12 stack-residue
zeroize fixes` — closes Open Item 3's **Memory hygiene audit**
in-session entry, completing all three internal A.7 hardening passes
(threat-model refresh, side-channel internal pass, memory-hygiene).

**Wrapper discipline verified clean.** `Sensitive<T>` and
`SecretBytes` ([core/src/crypto/secret.rs](core/src/crypto/secret.rs))
both derive `Zeroize, ZeroizeOnDrop`, both have redacting `Debug`
impls, both refuse to derive `Clone`. `Sensitive<T>` intentionally
omits `PartialEq` so callers reaching for byte-equality on a secret
must explicitly write `a.expose()[..].ct_eq(&b.expose()[..])`.

**Composite types verified clean.** `IdentityBundle` drops fields in
source order, each `Sensitive<T>` field zeroizes; `UnlockedIdentity`
composes IBK + IdentityBundle in the right order; `Mnemonic` has a
custom `Drop` that zeroizes the phrase `String` alongside the
`Sensitive<[u8; 32]>` entropy.

**Twelve stack-residue gaps fixed.** Each was a sister site to an
already-disciplined site in the same module. The pattern: a secret
value moved into `Sensitive::new(var)` while the stack slot `var`
retained its bytes (Copy semantics on `[u8; N]`); the established
fix `var.zeroize()` after the move was applied to the missing sites.
Touched files: `crypto/kdf.rs`, `crypto/kem.rs`, `unlock/mnemonic.rs`,
`unlock/mod.rs`, `vault/block.rs`, `vault/orchestrators.rs`. Three
SECURITY notes in `unlock/mod.rs` that acknowledged the residue but
hadn't applied the fix were rewritten to reflect the correction.

**Three deferred items rolled forward as carry-overs:**
- **Record-content zeroize-on-drop** (the largest deferred item):
  `RecordFieldValue::{Text, Bytes}` holds the user's passwords +
  secret notes without zeroize-on-drop. The only secret-bearing data
  in the codebase NOT zeroized. Non-trivial fix; raise as v2.
- **Newtype `Zeroize` derives** on `MlDsa65Secret` / `MlKem768Secret`:
  cosmetic, the inner `SecretBytes` field zeroizes correctly on drop.
- **`hkdf` 0.12 internal HMAC state residue**: upstream-managed,
  watch for a future release with `ZeroizeOnDrop`.

After this commit: 430 tests pass + 6 ignored, clippy clean with
`-D warnings`. Memory-hygiene status: clean for v1's Sub-project A
scope. With the threat-model refresh + side-channel internal pass +
memory-hygiene audit all closed, Open Item 3's remaining work is
external-reviewer-facing — the two contributor-doc memos at
`docs/manual/contributors/{side-channel,memory-hygiene}-audit-internal.md`
are the principal handoff documents for the paid external review.
