# NEXT_SESSION.md — #480 bridge error-payload hygiene: the guard now owns the FFI bridge

**Session date:** 2026-08-06, resuming from `main` @ `3e19ec6` (PR #479 / #474 merged during the pause window). Branch `feature/480-bridge-error-payload-hygiene`; worktree `.worktrees/480-bridge-error-payload-hygiene`.

Full brainstorm → spec → plan → **subagent-driven execution, 10 tasks, an independent review after every one** → final whole-branch review → one 4-line fix wave. User decisions: pick **#480** from the prior baton's menu; fold in **#481 + #478** (one branch, three closures); approach **B** — sanctioned typed constructors + sink-pinning, over scan-and-allowlist and over a Python expression classifier.

## Session-start cleanup

- `main` verified at `3e19ec6`; PR #479 MERGED, #474 CLOSED; dropped the merged `.worktrees/474-error-payload-hygiene` worktree + branch. Two unrelated `.claude/worktrees/` detached checkouts left alone.

## (1) What we shipped

**#480 + #481 + #478.** The #474 guard proved every `core` error payload data-free — and stopped exactly where the platform-visible strings are actually built. The bridge's 16 `detail: String` fields plus 9 hex-named `String` fields were filled at ~130 construction sites gated by review alone, and two of them (**#481**) interpolated **decrypted settings field names**. A third leak found during design census: `SettingsParseError::UnknownVersion` carried the raw decrypted `record_type`, Debug-rendered into a desktop warning.

The branch closes the class the same way this repo closed logcat (#472) and `privacy: .public` (#467): make the unsafe shape unrepresentable, then pin the sink.

- **`ffi/secretary-ffi-bridge/src/error/detail.rs`** — the ONLY place a detail string may be built. 8 constructors (`gated`, `gated_with_context`, `uuid_hex`, `uuid_hyphenated`, `fingerprint_hex`, `gated_for_uuid`, `literal_for_uuid`, `counted`); no parameter can carry a runtime string — `&'static str`, integers, `[u8; 16]`, or `&impl GatedDetail` (a marker trait: "this type's Display is already owned"). Every impl lives in this one file; impl'ing is a security decision.
- **Guard rules E2/E3/E4** in `scripts/check-error-payload-hygiene.py` over a second scan root: E2 sweeps bridge error/warning declarations (a `String` field must bear one of the six pinned gated names); E3 gates every gated-field initializer (literal, `detail::` call, declaration token, or exact passthrough — all else denies); E4 pins `impl GatedDetail` to detail.rs and cross-checks targets against the guard's own registry. Self-test grew 40/18 core + **35/18 bridge** controls, every one mutation-verified. Burn-down was the progress meter: **114 findings → 0**, guard GREEN with 4 reviewed E4 allowlist entries.
- **~110 call sites rewritten** through the constructors (content byte-preserved except two deliberately-reframed restore folds); **#481's sites** now static-hint-plus-ordinal with mutation-proven absence tests; `UnknownVersion` is fieldless (desktop Rust + TS knock-on included); `SettingsParseError`/`ReplaceManifestError` converted to thiserror.
- **Docs:** CLAUDE.md guard section + Commands block rewritten (both roots, six names, honest residuals); 4 citation sites re-pointed (guard docstring, `VaultBrowseError.kt`, `SecretFreeError.swift`, CLAUDE.md); `VaultSyncError.kt`'s content-traced KDoc replaced by a structural claim (**#478 closed the broad way**; `Failed` keeps its detail); `VaultSyncErrorMappingTest.kt` pointer fixed. README/ROADMAP verified unchanged by precedent (grep evidence in the T9 commit).
- **Issues filed:** **#486** (binding wrapper crates unscanned — with a hand-recounted census after the plan's numbers proved wrong twice), **#487** (io::Error minted from runtime strings sits outside the gate: `repair/orchestration.rs:137-147` production, `cli/src/daemon.rs:424` unreachable-from-gate), **#488** (E3's three laundering shapes need dataflow).

### Commits (19, `443f247..146d40e`)

| SHA | What |
|---|---|
| `443f247` `48b334c` | design spec; implementation plan + gated-field-set amendment |
| `9839450` | `error/detail.rs` — trait + constructors |
| `13b0f2e` `950f34e` `a0f761c` | rule E2, then TWO adversarial fix rounds (see below) |
| `34fe806` `dbaab21` | rules E3+E4, then the anchor-inversion fix round |
| `3ee1f15` `cb040fb` `d3e2c7a` | the three rewrite waves (23 + 37 + 41 sites, deltas exact) |
| `e11af90` | settings: #481 zeroed, UnknownVersion fieldless, desktop knock-on |
| `9144368` `fc63e94` | E4 allowlist → **guard GREEN**; fmt/reason-text fix round |
| `d5f5d72` `4f37fc4` | docs + #486/#487/#488; claim-accuracy fix round |
| `b967c7c` `1f3b7c1` | two plan-doc fixes (script name; fused heading) |
| `146d40e` | final-review fix wave (2 KDoc clauses, 2 test assertions) |

### The reviews are the story, again

Every task got a fresh implementer and an independent reviewer; the reviewers verified **by execution** — rustc-compiled witnesses fed through the guard, planted regressions, counterfactual reimplementations of rejected rules.

- **E2 took two fix rounds.** Round 1 found silent `continue`s (fail-open) and a LIVE allowlist-key collision (`SettingsWarning::Corrupt` vs `SettingsParseError::Corrupt` sharing one key). Round 2 REFUTED the implementer's "provably harmless" deviation with a compiling witness (`#[doc = r#"a " b"#]` — `skip_attributes` has no raw-string awareness), found a fourth silent path, and caught the round-1 fix's own name-keyed skip being fail-open (raw-string self-authorization). Both closed with position-keying.
- **E4's regex was one line from useless.** `impl\s+GatedDetail` never matches `impl<...>`, so a blanket `impl<T: Display> GatedDetail for T {}` — which compiles beside the real impls — laundered ANY type, collapsing both new rules. The fix inverted the anchor (`\bGatedDetail\s+for\b`, impl header recovered backwards, UNPARSED when absent), killing the CLASS; the implementer found a sixth shape (qualified trait path) the reviewer had missed.
- **The plan's E4 rule was itself fail-open** — core declares a bare `pub enum Error`, so "last path segment in registry" would have accepted `std::io::Error` silently. Proven by counterfactual (3 vs 4 findings); deviation accepted.
- **Task 9's claim-accuracy review caught two false security claims** in the rewritten `VaultSyncError.kt` KDoc (sweeping `InvalidArgument` into the #480 gate it isn't under; attributing `VaultBrowseError.Failed`'s gating to the Rust guard when all nine producers are Kotlin) and a wrong "ffi-py: zero sites" census in #486.
- **The final review planted three live regressions** (the exact #481 format!, a stray impl, the old `version: String`) — the guard caught all three — and traced three platform paths end-to-end before verdicting.

## (2) What's next

- **#486** — wrapper crates (`ffi-py`/`ffi-uniffi`) unscanned. The final review rated this the highest-value follow-up: the corrected census shows `ffi-py`'s `format!("{block_uuid_hex}: {detail}")` (errors.rs:202) and DTO pass-throughs (`uuid_hex: a.uuid_hex`) fit NONE of E3's accepted shapes, so extending the roots needs new accepted forms designed first. **Acceptance is in the issue.**
- **#487** — io::Error-from-runtime-string outside the gate (one production bridge site). **#488** — laundering shapes need dataflow-lite or a recorded trust decision.
- **#482** — the raw half of `foreign_use_names`' union is STILL unpinned (pre-#480 finding, untouched this session; the P40 control from the #474 baton). **#483** (test_support module) · **#484** (four cosmetic) — untouched.
- **#476** Android on-screen diagnostics · **#477** detekt rule to retire the Kotlin grep guard · **#459** iOS on-device Settings confirmation (repro INSIDE the grace window!) · **#464** CodeQL Swift · **#417**, **#447**, **#443/#444** — all carried unchanged from the prior baton.

## (3) Open decisions and risks

- **The claim discipline is now load-bearing prose.** CLAUDE.md + both platform KDocs state gated-field construction is CI-enforced **with three named residuals** (#487 io::Error carrier, #488 laundering shapes, macro/trait-alias invisibility) plus the wrapper-crate boundary (#486). If any of those issues closes, RE-POINT the prose; if a new residual class appears, ADD it — the T9 review showed how easily "every producer" overclaims.
- **Ledger-parked, riding as-is (final review triaged):** E1's whole-attribute key can collide across two types in one file (pre-existing, documented); `balanced_slice` escaped-quote desync (masks, doesn't open); two-structs-on-one-line evade the already-swept span (rustfmt never emits it); C-like-discriminant enums and string-embedded names produce fail-closed UNPARSED noise (none in tree). All documented in guard docstring/ledger; none blocks.
- **E3 arm 4 (`detail: detail`) is unused but kept** — removing it buys nothing while shorthand exists (equivalent laundering door, #488 owns the class).
- **`%(trailers)` audit gotcha:** on git 2.54 `git log --format='%(trailers:...)'` appends a blank line per commit, so the plan's `awk 'NF<2'` audit never returns empty — use a per-commit check (T10 report documented the substitute).
- **Kotlin block comments NEST** — bit an agent AGAIN this session (caught pre-ship by grep sweep). Never write glob-star path text in a KDoc.
- **Backgrounded builds still stall subagents** — one T4 stall this session (resumed cheaply). Keep instructing foreground + generous timeout.

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After the PR merges (squash leaves the branch "not fully merged"):
#   git worktree remove .worktrees/480-bridge-error-payload-hygiene && git branch -D feature/480-bridge-error-payload-hygiene
git worktree list && git status -s

# Gates for this slice (run from the worktree while the PR is open):
#   cd /Users/hherb/src/secretary/.worktrees/480-bridge-error-payload-hygiene
#   cargo test --release --workspace
#   cargo clippy --release --workspace --tests -- -D warnings
#   RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
#   uv run scripts/check-error-payload-hygiene.py --self-test && uv run scripts/check-error-payload-hygiene.py
#   uv run core/tests/python/conformance.py
#   bash ios/scripts/check-public-log-hygiene.sh --self-test && bash ios/scripts/check-public-log-hygiene.sh
#   bash android/scripts/check-log-hygiene.sh --self-test && bash android/scripts/check-log-hygiene.sh
#   bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh
#   bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
#   bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
#   (cd desktop && pnpm test && pnpm run svelte-check)
#   (cd android && ./gradlew :vault-access:test :kit:compileDebugKotlin)
```

**Acceptance, verified at `146d40e`:** guard **GREEN** (exit 0; self-test 40/18/35/18, 22+ mutation checks) · `cargo test --release --workspace` all green (full re-run at finish) · clippy + rustdoc + fmt `-D warnings` clean · conformance.py pass · both uniffi runners **38/38** (no assertion updates needed) · desktop **674 tests** + svelte-check clean · `:vault-access:test` + `:kit:compileDebugKotlin` green · `git diff main... -- ffi/secretary-ffi-uniffi/src/secretary.udl` **EMPTY** · all 19 commits carry the trailer · **no `FfiVaultError` variant/field change, no KAT regeneration**.

**Still not verified:** CI on the PR (pushed at session end — check first thing); `:app:assembleDebug` (~10 min, not run; `:kit` compile + `:vault-access` tests did run); `core/fuzz` compile (workspace-excluded, nightly).

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch. Do **not** sync to `main` during the pause window. If resuming this branch for fixups: `git fetch origin && git merge origin/main` FIRST (branch version wins on this doc) before editing.

## Closing inventory

- **State on close:** PR open on `feature/480-bridge-error-payload-hygiene`, shipping **#480 + #481 + #478**. Net: `error/detail.rs` + `GatedDetail`; guard rules E2/E3/E4 (35/18 bridge controls); ~110 sites rewritten; settings leaks zeroed with mutation-proofs; 4 E4 allowlist entries; 6 doc sites re-pointed; #486/#487/#488 filed. **No on-disk format change, no FFI surface change, no `.udl` change.**
- **Docs:** README/ROADMAP unchanged by precedent (grep-verified). CLAUDE.md substantially updated (both scan roots, sink-pinning architecture, honest residuals).
- **Next:** **#486** (highest value) · #487 · #488 · #482 · #483 · #484 · #476 · #477 · #459 on-device · #464 · #417 · #447 · #443/#444.
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-08-06-480-bridge-error-payload-hygiene-shipped.md`.
