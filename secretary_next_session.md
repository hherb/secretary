# secretary — next session entry point

This file is the entry point for the **next** session, in the same role
the previous `secretary_next_session.md` played until 2026-05-02 (closed
on a wave of completed work: PRs #11 + #12 + thirteen direct-to-main
post-#12 monitor stabilisation commits, plus three internal Phase A.7
hardening passes — threat-model refresh, side-channel internal pass,
and memory-hygiene audit).

**Sub-project A is feature-complete for v1**; Phase A.7's three
**internal** hardening passes are now ✅ closed. What remains in Phase
A.7 is the **external (paid)** review track — independent
cryptographic review and side-channel review — and a small set of
in-session pickup items called out below. The spec docs are stable
enough to send to an external reviewer; the two internal-audit memos
at [docs/manual/contributors/side-channel-audit-internal.md](docs/manual/contributors/side-channel-audit-internal.md)
and [docs/manual/contributors/memory-hygiene-audit-internal.md](docs/manual/contributors/memory-hygiene-audit-internal.md)
are the principal handoff documents — together they enumerate every
upstream-crate assumption and every deferred design decision the
external reviewer should know about.

When the items below are done, delete this file and create the next one.

Sub-project A's design anchor lives at
`/Users/hherb/.claude/plans/we-are-starting-with-logical-newt.md` —
re-read at the start of any session that touches Sub-project A code.
The "Verification" section (around line 375, especially the §15
cross-language conformance contract) is the load-bearing part for
Phase A.7.

**Repo state at session start:** 445 tests pass + 6 ignored under
`cargo test --release --workspace`; clippy clean with `-D warnings`;
`#![forbid(unsafe_code)]` crate-wide.

---

## Recommended next concrete unit of work

### Begin Sub-project B.1.1 — uniffi UDL + Swift/Kotlin smoke runners

Sub-project B.1 (Python via PyO3 + maturin) landed in
[PR #20](https://github.com/hherb/secretary/pull/20) at squash-merge
`a2f76b8` on 2026-05-03. The remaining half of B.1 is the uniffi side
(Swift for iOS, Kotlin for Android). Same shape as B.1 Python but on
the [`ffi/secretary-ffi-uniffi/`](ffi/secretary-ffi-uniffi/) crate, which
is still a stub.

**Scope of B.1.1** (per [ROADMAP.md](ROADMAP.md) Sub-project B phase plan):
single uniffi UDL describing one tiny round-trip function (e.g.
`fn add(a: u32, b: u32) -> u32`) wired through to both Swift and
Kotlin bindings via uniffi-bindgen. No vault crypto exposed yet —
mirrors B.1's "prove the binding pipeline" scope. Crypto surface
comes in B.2+.

**Suggested first commit cluster:**

1. Workspace integration: confirm `secretary-ffi-uniffi` builds under
   `cargo build --release --workspace` (it currently builds as an
   empty stub).
2. UDL design: a single uniffi UDL describing
   `fn add(a: u32, b: u32) -> u32`; lint table mirror of
   `secretary-ffi-py/Cargo.toml` (localized `unsafe_code = "deny"`
   per CLAUDE.md's "FFI as isolated reviewed boundary" principle).
3. Build outputs: `secretary_ffi_uniffi.dylib` + `bindings/{Swift,Kotlin}`
   generated with `uniffi-bindgen`. Document where the build products
   live in [`ffi/secretary-ffi-uniffi/README.md`](ffi/secretary-ffi-uniffi/README.md),
   parallel to the Python README's structure.
4. Round-trip tests:
   - Rust unit test in the uniffi crate.
   - macOS-host Swift smoke runner (`main.swift` + the generated
     bindings, no iOS simulator required).
   - Kotlin smoke runner if feasible without an Android emulator —
     **probably defer to a B.1.1.1 follow-up commit** so B.1.1 ships as
     Rust + Swift only.

The FFI work is **bounded** — no design ambiguity, just careful
translation of the Rust API across the boundary. **Estimate:** ~2–3
hours focused. The hardest single sub-question is the Kotlin smoke-
runner cost vs. value (recommend defer).

**Decisions to make at the start of B.1.1:**

1. **uniffi version pin.** uniffi is still pre-1.0 (`0.x`). Pin exactly
   (like `tempfile = "=3.27.0"` for the security-critical path) or use
   a semver range (like `pyo3 = "0.28"` for the FFI-only path)?
   Recommend a semver range — uniffi isn't on the crypto path either.
2. **uniffi UDL location.** With one binding crate today, the trivial
   answer is "one UDL inside `ffi/secretary-ffi-uniffi/`". Worth saying
   out loud so the next contributor doesn't have to re-derive it.
3. **Kotlin smoke runner.** macOS-host Swift loader is essentially free
   (`swiftc main.swift -L bindings/swift ...`). Kotlin requires either
   an emulator or a JVM-only stub harness — defer if no emulator is
   available.

**Why this is the right next thing:** the external paid review is
gated on calendar / availability of a reviewer with FIPS 203 / 204
implementer experience; we don't want to be blocked on it. B.1.1
proceeds in parallel — FFI doesn't touch `core/src/`, so any spec
clarification the external reviewer surfaces can land alongside FFI
work without conflict.

---

## Smaller pickup items (if delaying Sub-project B.1.1)

If a session has less than ~2 hours of focused time and starting B.1.1
feels too large, these are scoped pickup items that fit in one or two
commits each:

1. ✅ **Spec-doc test-name freshness CI check** — landed 2026-05-03.
   Script at [`core/tests/python/spec_test_name_freshness.py`](core/tests/python/spec_test_name_freshness.py)
   plus per-citation allowlist at [`core/tests/python/spec_freshness_allowlist.txt`](core/tests/python/spec_freshness_allowlist.txt).
   Ships in a CI-ready state with `--self-test`, `--quiet`, `--verbose`,
   `--audit-allowlist`, and `--list-files` modes; exit codes mirror
   `conformance.py`. Caught one real drift on first run (`open_block` →
   `share_block` in `memory-hygiene-audit-internal.md` row 6). Allowlist
   currently holds 2 entries (one prose negation in §11.4 of
   crypto-design.md, one KAT vector key referenced in threat-model.md).
   Workflow / pre-commit hook integration deliberately deferred — repo
   has no `.github/workflows/` or `.pre-commit-config.yaml` yet; the
   script's docstring documents the suggested CI invocation for when
   that infrastructure lands.

2. ✅ **`conflict_kat.json` block-level `unknown_hex` coverage** —
   landed 2026-05-03. New 12th vector
   `concurrent_block_unknown_collision_lex_larger_wins` mirrors
   vector #10's shape but at the block level: empty record arrays,
   block-level `unknown_hex` with one collision (lex-larger CBOR
   bytes win) plus two single-side preserved keys. Verified by both
   `core/tests/conflict.rs::kat_replays_match_rust_merge` and
   `conformance.py` Section 4. Closed item #4 from
   [docs/TODO_FINAL_POLISHING.md](docs/TODO_FINAL_POLISHING.md) in
   the same commit. The §11.3 carve-out is record-level only — the
   new vector documents that the block-level §11.2 path is
   unguarded by tombstone semantics.

3. **Remaining Open Item 2 polishing** (sub-item 1 ✅ landed
   2026-05-03 in [PR #19](https://github.com/hherb/secretary/pull/19),
   commit `8280a21`; sub-items 2 and 3 remain conditionally deferred
   at [docs/TODO_FINAL_POLISHING.md](docs/TODO_FINAL_POLISHING.md)):
   - ✅ Replaced `# type: ignore[arg-type]` in `py_merge_unknown_map`
     with an explicit `assert r_hex is not None`. Section 1 dropped
     from `TODO_FINAL_POLISHING.md` per the doc's "drop the section
     in the same commit" instruction. Stale line-number anchors in
     the two surviving sections refreshed at the same time.
   - Lift the cross-language hex compare pattern into a
     `hex_lex_compare` / `hex_canonicalise` helper *if* a second
     hex-bearing KAT field appears. (Conditional defer; no second
     hex-bearing field exists today.)
   - Extract a `_record_pass_fail()` helper *if* a Section 6 with
     5+ sub-tests lands. (Conditional defer; no Section 6 today.)

   The two surviving sub-items have no actionable trigger today;
   `TODO_FINAL_POLISHING.md` deletes itself when both close.

4. ✅ **A.7 doc consolidation** — landed 2026-05-03 in
   [PR #19](https://github.com/hherb/secretary/pull/19),
   commit `56021fd`. New
   [`docs/manual/contributors/index.md`](docs/manual/contributors/index.md)
   gives per-memo scope + "when to read this" guidance for all three
   Phase A.7 outputs (differential-replay protocol, side-channel
   audit, memory-hygiene audit), and explicitly calls out the trio
   as the principal handoff package for the planned external paid
   review. Also documents the maintenance discipline: preserve each
   memo's scope/methodology when extending; new findings outside an
   existing scope go into a new memo, not glued onto the side. Spec-
   freshness check now scans 14 docs (was 13) without false
   positives.

---

## External (paid, time-bound)

Out of scope for any in-session pass — engaging external reviewers is
the user's call, on the user's timeline. Listed here for completeness:

- **Independent cryptographic review.** Spec docs are stable; PRs
  #1 / #3 / #5 / #7 / #9 froze the design. Reviewer with FIPS 203 /
  FIPS 204 implementer experience and AAD/signed-range eyes
  especially valuable. Principal handoff package: `docs/`
  (normative specs + threat-model + ADRs) plus the two internal-
  audit memos.
- **Side-channel review.** Constant-time critical paths enumerated
  in [docs/manual/contributors/side-channel-audit-internal.md](docs/manual/contributors/side-channel-audit-internal.md);
  reviewer should verify upstream-crate assumptions especially for
  `ml-dsa = "0.1.0-rc.8"` (pre-1.0).

These are **out of session scope** but noted so the project status
doesn't read as "all of Phase A.7 is closed."

---

## Carry-over dribbles (defer; document, don't start in-session)

Items deferred for known reasons. Track here so they don't slip; not
candidates for an in-session pass.

### v2 design discussions

- **`share-as-fork` v2 follow-up.** PR #5 / #6 pinned two TODO markers
  for share-as-fork at the encrypt/decrypt call sites. v2 vault-format
  change. Re-validate when Sub-project C orchestration brings the
  share path back into focus.
- ~~**Record-content zeroize-on-drop**~~ — **resolved** while the FFI
  surface had not yet shipped. `RecordFieldValue::{Text, Bytes}` now
  wrap `SecretString` / `SecretBytes`; wire format unchanged, Python
  conformance unaffected. See the
  ["Resolved" section in the memory-hygiene memo](docs/manual/contributors/memory-hygiene-audit-internal.md).

### Performance / profiling

- **`records_to_value` / `take_records` byte round-trip.** Defer until
  profiling shows it on a hot path. The merge primitives operate on
  already-decoded `Record`s.

### Upstream-managed

- **`hkdf` 0.12 internal HMAC state residue.** Documented as a
  SECURITY note in [core/src/crypto/kdf.rs:216-223](core/src/crypto/kdf.rs#L216-L223).
  Watched weekly by the
  [hkdf upstream watch](https://claude.ai/code/routines/trig_017n4sRiiNRg9jMhQpCfM8Y1)
  routine (Mondays 09:00 Australia/Perth). **Latest finding
  (2026-05-02):** `hkdf` 0.13.0 (released 2026-03-30) does **not**
  add zeroize support to internal HMAC state and does introduce a
  breaking type rename (`Hkdf` → `GenericHkdf` with source-compat
  type aliases); the carry-over remains open and the watch's
  effective baseline is now "0.13.x or older without zeroize."
  Complementary watch target flagged by the agent: the upstream
  `hmac` crate (separate from `hkdf` but in the same RustCrypto
  family — `hkdf` 0.13 bumped to `hmac` 0.13). Zeroize support
  could in principle land in `hmac` first and flow through; if a
  weekly run starts reporting churn there, consider adding a
  parallel `hmac upstream watch` routine.

---

## Current state at-a-glance

- 445 tests pass + 6 ignored, clippy clean with `-D warnings`,
  `#![forbid(unsafe_code)]` crate-wide.
- Phase A.7 internal track: ✅ all three passes closed
  (threat-model refresh, side-channel internal, memory-hygiene).
- Phase A.7 external track: pending (paid, time-bound).
- Spec-doc test-name freshness check: ✅ in place at
  [`core/tests/python/spec_test_name_freshness.py`](core/tests/python/spec_test_name_freshness.py)
  (allowlist holds 2 entries; `--audit-allowlist` keeps it
  self-cleaning). Run before docs/ refactors.
- `conflict_kat.json` coverage: ✅ 12 vectors (was 11); both
  record-level and block-level `unknown_hex` paths exercised
  end-to-end through the §15 cross-language conformance contract.
- Pickup-item polishing: ✅ items #3 (sub-item 1) and #4 closed in
  [PR #19](https://github.com/hherb/secretary/pull/19) (2026-05-03).
  `TODO_FINAL_POLISHING.md` down to 2 conditionally-deferred sections;
  contributors' index now anchors the Phase A.7 reviewer-handoff
  package at [`docs/manual/contributors/index.md`](docs/manual/contributors/index.md).
- Sub-project B (FFI): **B.1 Python complete** ([PR #20](https://github.com/hherb/secretary/pull/20),
  squash-merge `a2f76b8`, 2026-05-03). PyO3 + maturin pipeline proven
  end-to-end with two trivial round-trip functions (`add`, `version`);
  two-layer test discipline (Rust `#[cfg(test)]` unit tests added
  3 → 448+6 baseline, plus 3 Python pytests via
  `uv run --directory ffi/secretary-ffi-py pytest`). Spec at
  [`docs/superpowers/specs/2026-05-03-ffi-b1-py-bindings-boilerplate-design.md`](docs/superpowers/specs/2026-05-03-ffi-b1-py-bindings-boilerplate-design.md);
  FFI crate README at [`ffi/secretary-ffi-py/README.md`](ffi/secretary-ffi-py/README.md);
  session handoff at [`docs/handoffs/2026-05-03-b1-ffi-py-bindings.md`](docs/handoffs/2026-05-03-b1-ffi-py-bindings.md).
  [`ffi/secretary-ffi-uniffi/`](ffi/secretary-ffi-uniffi/) remains a
  stub — B.1.1 (uniffi UDL + Swift smoke; Kotlin probably deferred to
  B.1.1.1) recommended as the next concrete unit of work.
- Sub-project C (sync orchestration): not started.
- Sub-project D (platform UIs): not started.

---

## What previous sessions delivered (rolled-up summary)

Detailed retrospectives for each PR / direct-to-main wave live in the
git log. The high-water marks:

- **Phase A.1–A.6**: cryptographic primitives + identity + unlock +
  vault block format + manifest + atomic I/O + orchestrators + CRDT
  merge primitives (PRs #1, #3, #5, #6, #7, #9). 425+ tests after PR #9.
- **Phase A.7 fuzz harness + monitor + differential-replay protocol**:
  PR #8 (scaffold) + PR #11 (six promoted regression tests + 4 KiB
  `display_name` cap) + PR #12 (live telemetry on the dashboard) +
  thirteen-commit direct-to-main monitor stabilisation wave addressing
  issues #13 / #14 / #15 + sparkline / `--careful` / oom-detection /
  plateau-pulse-only filtering / mypy hygiene.
- **Phase A.7 user-facing primer + hardening guide**: PR #10
  (thirteen-chapter [cryptography primer](docs/manual/primer/cryptography/index.md)
  + [hardening guide](docs/manual/hardening-security.md)).
- **Phase A.7 newtype-zeroize follow-up (2026-05-02)**: closed the
  memory-hygiene audit's deferred-item #1 — `MlDsa65Secret` and
  `MlKem768Secret` now `#[derive(Zeroize, ZeroizeOnDrop)]` so callers
  can wipe a still-live newtype value programmatically. Inner
  `SecretBytes` continues to zeroize on scope-end (idempotent with
  the outer derive); change is purely additive on the public API. Two
  integration tests added pinning `.zeroize()` clears the inner
  bytes. Memory-hygiene memo updated; both originally-deferred items
  at the type level are now closed.
- **Phase A.7 internal audit track (2026-05-02)**:
  - Threat-model refresh: 4 divergences fixed (`c55ce3e`, `f65185d`,
    `10c4945`, `e4b3d9c`, `cb1a0b1`, `494b41a`) + §5 verification
    trace expanded from 11 entries to ~30 across 7 sections.
  - Side-channel internal pass: audit memo at
    [docs/manual/contributors/side-channel-audit-internal.md](docs/manual/contributors/side-channel-audit-internal.md);
    no bugs in our code, all CT-sensitive comparisons delegate to
    upstream RustCrypto; one hardening commit (`e921e99`) adding
    `Fingerprint` type-alias doc-comment.
  - Memory-hygiene audit: audit memo at
    [docs/manual/contributors/memory-hygiene-audit-internal.md](docs/manual/contributors/memory-hygiene-audit-internal.md);
    twelve stack-residue gaps fixed in commit `6054185` (sister
    sites to already-disciplined ones).
- **Housekeeping (2026-05-02)**: gitignored `.playwright-mcp/` +
  `monitor-*.png` (`c75e675`); pruned two stale worktrees + their
  squash-merged local branches; closed GitHub issues #13 / #14 / #15
  referencing their fix commits; added `CLAUDE.md` to
  `.git/info/exclude` (local-only); discovered + removed a stale
  carry-over (the §6.1 / §6.2 spec-doc annotations had been shipped
  in `c47c17c` 2026-04-28 but the TODO had propagated through
  several next-session generations).
- **Spec-doc test-name freshness check (2026-05-03)**: closed pickup
  item #1. Script at [`core/tests/python/spec_test_name_freshness.py`](core/tests/python/spec_test_name_freshness.py)
  + allowlist file (`e622365`); five recognisers (RICH `path::name`,
  BRACE `prefix_{a,b,c}`, CONTINUATION strip-N search, QUALIFIED
  `Type::Variant`, PATH_BARE) over docs/{crypto-design,vault-format,
  threat-model,glossary}.md + manual/contributors/* + adr/*.md;
  PATH_BARE restricted to test-citation-dense docs to avoid wire-
  format-field false positives. Caught one real drift on first run:
  row 6 of the memory-hygiene memo had `core/src/vault/orchestrators.rs::open_block`
  but the function never existed — the reader X25519 SK rebind lives
  inside `share_block`. Fix bundled in the same commit. CI / pre-
  commit wiring deliberately deferred (no `.github/workflows/` or
  `.pre-commit-config.yaml` yet); script's docstring documents the
  suggested invocation when CI infrastructure lands. Final live run:
  96 resolved + 0 unresolved + 2 allowlisted.
- **Clippy 1.95.0 follow-up (2026-05-03)**: stable clippy bumped to
  1.95.0 since the 2026-05-02 next-session snapshot, which made
  `unnecessary_sort_by` flag six pre-existing call sites in
  `core/src/vault/{block,manifest}.rs` (all `Copy` byte-array keys
  like `device_uuid`, `block_uuid`, `recipient_fingerprint`).
  Mechanical `sort_by(|a,b| a.X.cmp(&b.X))` → `sort_by_key(|e| e.X)`
  conversion at all six sites (`8699507`); no behaviour change
  (identical ordering on `Copy` total-ordered keys, surrounding
  duplicate-detection invariants unchanged). Restored the project's
  "clippy clean with `-D warnings`" invariant.
- **Block-level `unknown_hex` KAT coverage (2026-05-03)**: closed
  pickup item #2 / [docs/TODO_FINAL_POLISHING.md](docs/TODO_FINAL_POLISHING.md)
  item #4. Added 12th vector
  `concurrent_block_unknown_collision_lex_larger_wins` to
  [`core/tests/data/conflict_kat.json`](core/tests/data/conflict_kat.json)
  — block-level `unknown_hex` with empty record arrays, one
  collision (`v2_collide=05` vs `0a`, lex-larger remote wins), plus
  two single-side preserved keys (`v2_local_only`, `v2_remote_only`).
  No production-code change needed: both `merge_block`'s
  `unknown` propagation and `parse_unknown_map` already wired to
  the block level; Python's `py_merge_block` and `_normalise_block`
  likewise. Verified by `kat_replays_match_rust_merge` (Rust) and
  `conformance.py` Section 4 (Python clean-room). Section #4
  dropped from `TODO_FINAL_POLISHING.md` in the same commit per
  the doc's "drop the section in the same commit" instruction.
- **Pickup items #3 and #4 (2026-05-03)**:
  [PR #19](https://github.com/hherb/secretary/pull/19) — two
  commits closing the smaller pickup items in advance of starting
  Sub-project B.1.
  - **Item #3 sub-item 1 (`8280a21`):** replaced
    `# type: ignore[arg-type]` in `py_merge_unknown_map`'s
    fall-through branch with explicit `assert r_hex is not None`,
    enforcing the documented invariant at runtime and documenting
    it inline. Section 1 dropped from
    `docs/TODO_FINAL_POLISHING.md`; stale line-number anchors in
    the surviving sections refreshed (`py_merge_unknown_map` had
    moved from 921-956 → 1914-1949; Section 5 from 1116-1176 →
    2381-2441). Sub-items 2 and 3 remain conditionally deferred
    (no second hex-bearing KAT field, no Section 6).
  - **Item #4 (`56021fd`):** new
    [`docs/manual/contributors/index.md`](docs/manual/contributors/index.md)
    as the entry point for the Phase A.7 reviewer-handoff package
    (differential-replay protocol, side-channel audit, memory-
    hygiene audit). Per-memo scope + "when to read this" guidance,
    relationship to the planned external paid review, and the
    maintenance discipline (preserve methodology when extending;
    new findings outside an existing scope go into a new memo).
    Spec-freshness check now scans 14 docs (was 13) without
    introducing false positives. User-facing primer + hardening
    guide explicitly cross-linked but distinct.
  - Verification: 445 cargo tests + 6 ignored, clippy clean,
    conformance + spec-freshness PASS.
- **Sub-project B.1 — FFI Python bindings boilerplate (2026-05-03)**:
  [PR #20](https://github.com/hherb/secretary/pull/20) — squash-merge
  `a2f76b8`. PyO3 + maturin pipeline proven end-to-end with two
  trivial round-trip functions (`add`, `version`); no vault crypto
  exposed (B.2+). 15 commits squashed; four mid-stream code-review
  corrections each as their own commit per project policy:
  (1) PyO3 0.28 `extension-module` Cargo feature deprecated in favour
  of the `PYO3_BUILD_EXTENSION_MODULE` env var auto-set by maturin
  ≥ 1.9.4; (2) maturin needed in `[dependency-groups] dev` not just
  `[build-system] requires` so `uv run --directory ... maturin develop`
  resolves; (3) explicit `[tool.pytest.ini_options] testpaths = ["tests"]`
  to pin pytest discovery; (4) replaced broken `[CLAUDE.md](../../CLAUDE.md)`
  link in the FFI README (CLAUDE.md is local-only) with an inline
  conventions summary. Spec at
  [`docs/superpowers/specs/2026-05-03-ffi-b1-py-bindings-boilerplate-design.md`](docs/superpowers/specs/2026-05-03-ffi-b1-py-bindings-boilerplate-design.md);
  plan at
  [`docs/superpowers/plans/2026-05-03-ffi-b1-py-bindings-boilerplate.md`](docs/superpowers/plans/2026-05-03-ffi-b1-py-bindings-boilerplate.md);
  session handoff at
  [`docs/handoffs/2026-05-03-b1-ffi-py-bindings.md`](docs/handoffs/2026-05-03-b1-ffi-py-bindings.md).
  Verification: 448 cargo tests + 6 ignored (445 + 3 from B.1
  PyO3 unit tests), clippy clean, ffi-py pytest 3 passed,
  conformance + spec-freshness PASS. Workspace `unsafe_code` lint
  relaxed from `forbid` to `deny` for `secretary-ffi-py` only (PyO3
  macros expand to unsafe blocks; `forbid` is non-overridable);
  `core/` and `secretary-ffi-uniffi/` remain `#![forbid(unsafe_code)]`.
