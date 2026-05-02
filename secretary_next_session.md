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

**Repo state at session start:** 430 tests pass + 6 ignored under
`cargo test --release --workspace`; clippy clean with `-D warnings`;
`#![forbid(unsafe_code)]` crate-wide.

---

## Recommended next concrete unit of work

### Begin Sub-project B.1 — FFI bindings boilerplate

The natural sequential next phase. Sub-project A is done; Sub-project B
(FFI bindings via PyO3 + uniffi) is the first downstream phase that
unblocks everything else (Sub-project C sync orchestration, Sub-project
D platform UIs).

**Scope of B.1** (per [ROADMAP.md](ROADMAP.md) Sub-project B phase plan):
UDL design + binding boilerplate + a hello-world round-trip on each
platform. No vault crypto exposed yet — just prove the binding pipeline
works end-to-end.

The two binding crates exist as stubs today:

- [ffi/secretary-ffi-py/](ffi/secretary-ffi-py/) — PyO3 bindings (Python
  desktop / web client).
- [ffi/secretary-ffi-uniffi/](ffi/secretary-ffi-uniffi/) — uniffi
  bindings (one UDL → Swift for iOS, Kotlin for Android).

**Suggested first commit cluster** (what an in-session pass would aim
for):

1. Workspace integration: ensure both FFI crates build under
   `cargo build --release --workspace`. The current stubs may or may
   not — verify first.
2. UDL design: a single uniffi UDL describing one tiny round-trip
   function (e.g. `fn sum(a: u32, b: u32) -> u32`) for the
   uniffi crate; the equivalent `#[pyfunction]` in the PyO3 crate.
3. Build outputs: `secretary_ffi_uniffi.dylib` (or `.so`) +
   `bindings/{Swift,Kotlin}` generated with uniffi-bindgen; a
   `secretary_ffi_py.so` Python extension importable as
   `import secretary_ffi_py`.
4. Round-trip tests: a Rust unit test that calls the function directly,
   plus a Python `pytest` and (if feasible in-session) a
   Swift / Kotlin smoke runner that loads the generated bindings and
   asserts the same return value.

The FFI work is **bounded** — no design ambiguity, just careful
translation of the Rust API across the boundary. The hardest single
question is "where does the Python build product live so that
`uv run` can import it" — solvable but worth scoping carefully on the
first attempt.

**Why this is the right next thing:** the external paid review is
gated on calendar / availability of a reviewer with FIPS 203 / 204
implementer experience; we don't want to be blocked on it. Starting
B.1 in parallel keeps progress moving on bounded work, and any spec
clarification the external reviewer surfaces can land alongside FFI
work without conflict (the FFI crate doesn't touch `core/src/` code).

---

## Smaller pickup items (if delaying Sub-project B)

If a session has less than ~2 hours of focused time and starting B.1
feels too large, these are scoped pickup items that fit in one or two
commits each:

1. **Spec-doc test-name freshness CI check.** Surfaced 2026-05-02:
   the §5 verification trace in `docs/threat-model.md` had drifted
   (4 stale test names + ~20 missing entries) before the threat-model
   refresh pass. A small mechanical CI script would catch the drift
   early — extract every backticked identifier from `docs/*.md` whose
   pattern looks like a Rust function name, then `grep -r` for it
   under `core/`. Anything that doesn't resolve is either a stale
   spec citation or a renamed test. Concrete deliverable: a `uv run`
   script at `core/tests/python/spec_test_name_freshness.py` plus a
   workflow / pre-commit hook integration. Low risk, useful guard.

2. **`conflict_kat.json` block-level `unknown_hex` coverage** (from
   [docs/TODO_FINAL_POLISHING.md](docs/TODO_FINAL_POLISHING.md) item
   #4). Audit the eleven KAT vectors and confirm at least one
   exercises non-empty *block-level* `unknown_hex` (not just
   record-level). If none does, add a minimal vector — same shape as
   #10 / #11 but at the block level. Drop item #4 from the polishing
   doc in the same commit.

3. **`MlDsa65Secret` / `MlKem768Secret` newtype `Zeroize`/`ZeroizeOnDrop`
   derives.** Cosmetic gap from the memory-hygiene audit. Both
   newtypes wrap `SecretBytes` (which IS zeroize-on-drop) so the
   bytes correctly zeroize on drop, but `.zeroize()` isn't exposed
   programmatically. Adding `#[derive(Zeroize, ZeroizeOnDrop)]` to
   each (or annotating the inner field) would make the discipline
   uniform across all secret-bearing newtypes.

4. **Remaining Open Item 2 polishing** (3 items at
   [docs/TODO_FINAL_POLISHING.md](docs/TODO_FINAL_POLISHING.md)):
   - Replace `# type: ignore[arg-type]` in `py_merge_unknown_map`
     with an explicit `assert r_hex is not None`.
   - Lift the cross-language hex compare pattern into a
     `hex_lex_compare` / `hex_canonicalise` helper *if* a second
     hex-bearing KAT field appears.
   - Extract a `_record_pass_fail()` helper *if* a Section 6 with
     5+ sub-tests lands.

   None are urgent; pick up when adjacent code is next touched.

5. **A.7 doc consolidation.** The two internal-audit memos at
   [docs/manual/contributors/](docs/manual/contributors/) read in
   isolation today. Worth a small `index.md` (or extending the
   existing primer index) that points at all three Phase A.7 outputs
   — the differential-replay protocol, side-channel audit,
   memory-hygiene audit — as the "what to give the external
   reviewer" handoff package.

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
- **Record-content zeroize-on-drop** ([memory-hygiene memo §1](docs/manual/contributors/memory-hygiene-audit-internal.md)).
  `RecordFieldValue::{Text(String), Bytes(Vec<u8>)}` hold the user's
  actual passwords / secret notes / API keys *without* zeroize-on-drop —
  the most-sensitive data in the system, only secret-bearing data NOT
  zeroized. Fix is non-trivial: `SecretString`-typing ripples through
  ~100 test sites + the Python conformance verifier. Raise alongside
  any other v2 hardening work (e.g. forward secrecy at the block level,
  threat-model §4 limitation 1).

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

- 430 tests pass + 6 ignored, clippy clean with `-D warnings`,
  `#![forbid(unsafe_code)]` crate-wide.
- Phase A.7 internal track: ✅ all three passes closed
  (threat-model refresh, side-channel internal, memory-hygiene).
- Phase A.7 external track: pending (paid, time-bound).
- Sub-project B (FFI): stubs only at [ffi/secretary-ffi-py/](ffi/secretary-ffi-py/)
  and [ffi/secretary-ffi-uniffi/](ffi/secretary-ffi-uniffi/); B.1
  recommended as the next concrete unit of work.
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
