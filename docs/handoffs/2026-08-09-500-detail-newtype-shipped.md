# NEXT_SESSION.md — the `Detail` newtype: typing the gated position

**Session date:** 2026-08-09, from `main` @ `3775ef5`. Branch `feature/500-detail-newtype`; worktree `.worktrees/500-detail-newtype`.

Full brainstorm → spec → 8-task plan → **subagent-driven execution with an independent review after every task and a scoped re-review after every fix round**. User decisions: all six gated names (not just `detail`); fold in **#498**'s cheaper half; **#503** via a secret-only out-param sibling; the test hatch as a `test-support` Cargo feature.

**Tasks 1-5 of 8 are complete and reviewed. Tasks 6, 7, 8 and the whole-branch review remain.** This baton is written mid-plan on purpose — see §2.

## Session-start state

`main` was clean at `3775ef5` with all four CI workflows green (the previous baton's one open item, now closed). PRs #489/#493/#496 had merged during the pause window; the prior worktree was already dropped.

---

## (1) What we shipped

**26 commits, `ecd0ff1..175e74c` (plus this baton), 76 files changed.** No FFI surface change — `git diff main... -- ffi/secretary-ffi-uniffi/src/secretary.udl` is **empty**. No `core/` change, no on-disk format change, no KAT regeneration, no `#[error]` Display string altered.

### The idea

Three slices (#474 → #480 → #486/#496) built a text-matching guard around one invariant, and each shipped a longer LIMITS section than the last, because a guard that reads source text can always be evaded by source text it does not model. CLAUDE.md listed four E3 laundering shapes as needing "local dataflow / interprocedural analysis this construction-site guard does not do" — **two of them in daily use**.

That framing accepted a premise worth rejecting. `detail: format!("{secret}")` was expressible only because the field was declared `String` and Rust enum-variant fields are unconditionally public: the compiler was asked to enforce nothing. All 27 gated bridge fields are now a newtype with a private inner field, so a `String` produced by *any* laundering shape — modelled or not, present or future — does not typecheck. Demonstrated, not asserted:

```
error[E0308]: mismatched types
   --> ffi/secretary-ffi-bridge/src/error/vault/mod.rs:513:25
513 |                 detail: format!("{e}"),
    |                         ^^^^^^^^^^^^^^ expected `Detail`, found `String`
```

### Commits

| SHA | What |
|---|---|
| `ecd0ff1` `b145e6d` | design spec; 8-task plan |
| `18f6b78` `0039a8b` `4e8595c` `69b400e` `0080242` | five plan/spec amendments, each forced by a finding (§3) |
| `62d2b8d`…`6d55909` | **Task 1** — `Detail` type, `test-support` feature, the CI build gate, the placement guard (4 fix rounds) |
| `c4ffe5a` | **Task 2** — guard accepts `Detail` on the bridge (widening only) |
| `4674065`…`ef22740` | **Task 3** — 27 fields → `Detail` across three crates (4 fix rounds) |
| `37a318c`…`564a2ce` | **Task 4** — bridge narrowed to `Detail`-only, alias/decoy denies, wiring pin (2 fix rounds) |
| `3a95c06` | the first version of this baton |
| `d3d09d4` `a905c1b` `175e74c` | **Task 5** — #498's literal hint-argument rule; census correction (1 fix round) |

### What is closed

- **#500** — the newtype itself, through Task 5. Tasks 6-8 remain.
- **#497** (E3 shape 5's unbounded single-hop receiver) — **closed as a side effect**. Task 3 moved all four live sites onto `detail::project(...)`, leaving the acceptance with zero users; `roots.py`'s own rule said granting it where nothing needs it "would open a laundering door for free", so it was switched off on every root rather than merely documented. `WP7` pins the denial.
- **Plan parked minor P6** — `_check_wrapper_roots_agree`'s flag tuple had decayed twice; the compared set is now *derived* from `ScanRoot` minus an explicit exempt list, so a new field is compared unless deliberately exempted.

### Two things worth carrying beyond this branch

**Every layer added was green-by-default until something proved it could go red.** Four separate times the *control*, not the code, was the defect:

- Task 1: the `test-support` feature gate was decorative — `cargo test`, `cargo clippy --tests` and the rustdoc gate all compile a production call to the hatch clean. Only a non-test build catches it, and CI ran none. Fixed by adding `cargo build --release --workspace`.
- Task 4: severing `run_real_scan`'s own `shadowed_type_names` line left `--self-test` **fully green**, the real scan green, and a live decoy went from 47 violations to `OK`. Every control built its own shadow set, so none observed the line production uses. `BP57` now runs `run_real_scan` end-to-end against a planted decoy.
- Two implementers caught their *own* vacuous controls by mutation before any reviewer did.

**Two censuses this branch inherited were wrong, both found only by re-running them.** #486's was wrong in four ways (recorded in the previous baton); #498's was wrong by five — it reported one non-literal hint argument where there are six, five of them predating the branch. A census is a measurement with a date on it, not a fact.

**A silently empty grep is indistinguishable from a clean sweep.** A batched multi-file `grep -B/-A` returned nothing despite matches existing; it was caught only by counting per file. Do not trust a zero-result grep on this tree without a positive control.

---

## (2) What's next — concrete acceptance criteria

**Resume with Task 6.** The plan is authoritative and already amended for everything found so far; the ledger at `.superpowers/sdd/2026-08-09-500-detail-newtype/progress.md` is the recovery map and names every parked item.

- **Task 6 — #504.** ffi-py's `fingerprint_mismatch` / `uuid_prefixed` take `&Detail`; `STR_PARAM_CTOR_EXCEPTIONS` **empties**; add message-content and argument-order tests (they run under `cargo test`, unlike the pytest suite #501 covers).
- **Task 7 — #503.** `array32_from_vec_into(bytes, &mut out, field)` at the three `device_secret` sites only; fix the now-wrong "the transient stack copy" comment at `namespace/mod.rs:580`. **Cross-task hazard, added after Task 5:** the allowlist's Section 5 entries are keyed on *exact construction-site text*, and `array32_from_vec`'s key is `detail: crate::detail::arg_len(field, 32, bytes.len())`. Task 7 edits that function — update the entry in the **same commit** or the real scan reds.
- **Task 8 — docs + identity harness.** The stale-doc list is enumerated in the ledger (**eight items**, longer than the plan anticipated; item 7 is already done). Two matter most: **LIMITS never mentions the alias-shadow deny or `discover_local_detail_decoys` at all**, and its `&'static str` bullet says *"Every live site passes a literal; nothing enforces it"* — **both halves are now false** (six live sites do not, and E3 now does). CLAUDE.md repeats that sentence, and calls LIMITS authoritative. The identity harness will *not* diff empty — every changed line must be attributed to a named rule change, and a line no change predicts is a defect.
- **Then the whole-branch review** on the most capable model, with an **old-vs-new guard differential** (load the guard from `3775ef5` and from HEAD in one process, push fixtures through both). #496's real regression was invisible to every per-task review and surfaced only that way.

**Definition of done** is spec §11: zero gated `String` in the bridge (holds now), the `E0308` demonstration (done), `cargo build --release --workspace` in CI (done), `test-support` only under `[dev-dependencies]` (enforced), `STR_PARAM_CTOR_EXCEPTIONS` empty (Task 6), UDL diff empty (holds), full gate sweep, and CLAUDE.md distinguishing **bridge-closed** from **wrapper-still-open** without flattening the two.

---

## (3) Open decisions and risks

- **§4 of the spec is the sentence most likely to be flattened later.** The compiler guarantee covers the bridge's ~109 construction sites. The wrapper crates keep `String` because uniffi's UDL must project one, so their posture is **unchanged**, and E2/E3/E5 remain their only enforcement. "Laundering is fixed" is the overclaim this branch invites; do not write it.
- **Six issues filed, none blocking.** #505 (`DEFAULT_ROOTS` completeness unproven — the roots *are* the trust boundary; rank above #506), #506 (placement guard is 1253 lines; splitting it mid-fix would have buried the diff, and #496 showed packaging is where fail-open wiring bugs come from), #507 (`lexer.py` cites a control `BP46` that has never existed), #508 (shape 5's internals unpinned now the flag is off — the final-segment test can be *deleted* with the self-test green), #509 (`let String = leak();` launders on the wrapper roots; the bridge is immune because `let Detail = …` is `E0530`), #510 (`Path.rglob` skips symlinked directories — invisible to **every** rule).
- **Two `git` history mishaps, both mine.** I committed while an implementer subagent was live, so its `--amend` hit my commit; then we both did recovery surgery concurrently. No content was ever at risk (all candidate trees verified byte-identical) but it cost real time. **Standing rule now in the ledger: do not commit to the branch while an implementer is live.**
- **One deliberate process deviation, recorded.** The skill escalates fix rounds 4-5 to a fresh implementer on a stronger model, on the rationale that a long loop means the implementer cannot see its own problem. For Task 3's round 4 — a two-line comment in a file the round never touched, from an implementer that had twice caught its own vacuous work — that rationale did not hold, so I resumed rather than escalated. Reasoning is in the ledger; escalate as written if a round 5 arises.
- **`BP57` writes a transient file into the bridge tree during self-test**, cleaned via `finally` (verified clean even on a failing run) and gitignored. A hard `SIGKILL` between write and cleanup could leave residue — the same risk Step 5's plant/revert already accepts.
- **README/ROADMAP:** grepped, no change needed — this slice adds no user-facing feature and no FFI surface. Re-confirm at ship time.

---

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary/.worktrees/500-detail-newtype
pwd && git branch --show-current && git status -s     # expect feature/500-detail-newtype, clean
git log --oneline main..HEAD | head -3                # expect 175e74c at the tip

# The recovery map — read this BEFORE re-dispatching anything:
cat .superpowers/sdd/2026-08-09-500-detail-newtype/progress.md

# Resume the plan at Task 6:
bash ~/.claude/plugins/cache/claude-plugins-official/superpowers/6.2.0/skills/subagent-driven-development/scripts/task-brief \
  docs/superpowers/plans/2026-08-09-500-detail-newtype.md 6

# Gates for this slice:
cargo build --release --workspace          # NEW and load-bearing: the only gate that
                                           # catches a production Detail::for_test call
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
cargo clippy --release --workspace -- -D warnings          # NEW: without --tests too
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
uv run scripts/check-error-payload-hygiene.py --self-test && uv run scripts/check-error-payload-hygiene.py
uv run scripts/check-test-support-placement.py --self-test && uv run scripts/check-test-support-placement.py
uv run core/tests/python/conformance.py
bash ios/scripts/check-public-log-hygiene.sh --self-test && bash ios/scripts/check-public-log-hygiene.sh
bash android/scripts/check-log-hygiene.sh --self-test && bash android/scripts/check-log-hygiene.sh
bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh
(cd desktop && pnpm test && pnpm run svelte-check)
(cd android && ./gradlew :vault-access:test :kit:compileDebugKotlin)
git diff main... -- ffi/secretary-ffi-uniffi/src/secretary.udl    # must be EMPTY
git rebase --exec 'uv run scripts/check-error-payload-hygiene.py' main   # every commit green
```

**Verified at `175e74c`:** guard self-test **41/18/54/32/8/3** · real scan OK across four roots · placement guard 22/22 + OK (11 manifests) · `cargo build --release --workspace` clean · workspace **1846 tests** passing · bridge **334/334 in both feature configurations** · clippy with *and* without `--tests` clean · rustdoc clean · `.udl` diff empty.

**Also verified at `175e74c`:** `conformance.py` **PASS** · iOS log hygiene 21/9 · Android log hygiene 27/14 · lean-binding 3/3 — all self-test-first.

**Not yet verified:** desktop `pnpm test` + `svelte-check` and Gradle `:kit` (no TypeScript/Kotlin changed on this branch, but run them before shipping); `git rebase --exec` over every commit; `core/fuzz` compile (workspace-excluded, nightly). **CI has never run on this branch — nothing is pushed yet.**

---

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch. Do **not** sync to `main` during the pause window. If resuming this branch for fixups: `git fetch origin && git merge origin/main` FIRST (branch version wins on this doc) before editing.

## Closing inventory

- **State on close:** branch open, **not pushed**, 24 commits, Tasks 1-5 of 8 done and reviewed. Net: `Detail` newtype over all 27 gated bridge fields with a private inner field; ten sanctioned constructors returning it; `test-support` hatch absent from every shipped build and CI-enforced; a new `check-test-support-placement.py` guard (22 controls); the payload guard's bridge root narrowed to `Detail`-only with alias-shadow and decoy-declaration denies; and `run_real_scan`'s own wiring pinned. Allowlist 17 → 16 → **22 rows**: Task 3 *deleted* a whole section by closing `from_core_gated` structurally, then Task 5 added six reviewed Section 5 entries for the inherited `&'static str` forwarders (kept deliberately over a wider shape rule — see spec §6.1).
- **Next:** Task 6 (#504) · Task 7 (#503, mind the Section 5 key) · Task 8 (docs + identity harness) · whole-branch review with an old-vs-new differential · push + PR.
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-08-09-500-detail-newtype-shipped.md`.
