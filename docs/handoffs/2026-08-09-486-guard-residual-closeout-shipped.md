# NEXT_SESSION.md — the error-payload guard's four residuals, closed

**Session date:** 2026-08-08 → 2026-08-09, resuming from `main` @ `7fa210c`. Branch `feature/486-guard-residual-closeout`; worktree `.worktrees/486-guard-residual-closeout`.

Full brainstorm → spec → plan → **subagent-driven execution, 13 tasks, an independent review after every one** → whole-branch review on the most capable model → one fix wave. User decisions: take the **full guard residual closeout** (#486 + #482 + #487 + #488) over the narrower options; **split the 5035-line guard first**, then add the rules.

## Session-start cleanup

- `main` verified at `7fa210c`; PRs #489 (#480/#481/#478) and #493 (#491) merged during the pause window. Dropped both merged worktrees + branches. Two unrelated `.claude/worktrees/` detached checkouts left alone.

## (1) What we shipped

**#486 + #482 + #487 + #488, plus a new rule E5.** The #480 guard proved every `core` and bridge error payload data-free — and shipped with four documented residuals. All four are now closed structurally, and the guard went from **2 scan roots / 4 rules** to **4 scan roots / 5 rules**, with rule E3 reading **four candidate positions** instead of one.

The headline finding is that **#486's acceptance criteria rested on a census that was wrong in four separate ways**, re-derived here by execution:

| #486 predicted | Measured |
|---|---|
| `uuid_hex: a.uuid_hex` "fits E3's field's-own-name shape unchanged" | **Denies.** `a.uuid_hex` ≠ `uuid_hex`. |
| ~15 uniffi "verbatim pass-through re-wraps" need classifying | **Invisible.** Field *shorthand* — no `detail:` token, E3 never sees them. |
| `InvalidArgument` sites "deliberately out of scope" | **E3 fires on all 10.** |
| ffi-py `format!` combinations are "shape (b)" | **Also invisible** — function arguments, not gated-field initializers. |

And the real defect underneath the bookkeeping: `uuid_from_vec(bytes: &[u8], field: &str)` — a `&str`, not `&'static str`, feeding a `detail` string that reaches both platform UIs and their logs, with 45 call sites and two already passing a runtime `format!`. Structurally what **#481** was, one layer out from where #480 closed it.

### Commits (18, `dcd19e6..820d6fd`)

| SHA | What |
|---|---|
| `dcd19e6` `8db574d` | design spec; 13-task implementation plan |
| `ba44ae6` | **identity harness**, built BEFORE any code motion and mutation-verified |
| `cfad602` `b05ed13` `65f070c` `02d1a06` | the four-slice package split → `scripts/payload_guard/` |
| `357fa56` | **#482** — control **P41** pins the fail-open half of `foreign_use_names` |
| `4ae7844` `e24438d` | **#488** — `let` + assignment candidate positions, then 4 review fixes |
| `57b6586` | **#487** — the `io::Error` payload position + `detail::io_gated_with_path` |
| `cf2e755` `52d249a` | **#486 guard half** — `ScanRoot` model, wrapper roots, E3 shape 5 (single-hop) |
| `19bd02e` | **#486 Rust half** — wrapper `detail.rs`, `field: &str` → `&'static str`; scan RED(10) → GREEN |
| `f39c773` `dd7d7f6` | **rule E5** — `format!` confined to each wrapper crate's `detail.rs`, + 2 review fixes |
| `2990bab` | docs: CLAUDE.md residuals → closed; guard docstring; allowlist preamble |
| `820d6fd` | **final-review fix wave** — a real regression + 5 doc corrections |

### Phase 1 was certified inert, not assumed

`scripts/dev/payload_guard_identity.sh` captures the guard's observable behaviour — self-test output, a clean scan, and a scan with **one planted violation per rule E1-E4**. Its transcript diffs **byte-identical** against a baseline taken from the original 5035-line file. A green self-test would have stayed green if a whole rule silently stopped running; this would not. The harness was itself mutation-verified before being trusted. Entry point: **5035 → 362 lines**.

### The final review earned its keep

Twelve per-task reviews passed. The whole-branch review then ran an **old-vs-new differential** — loading the guard from `7fa210c` and from HEAD in one process and pushing 37 fixtures through both — and found a **real regression**:

```rust
let detail: String;          // annotated let, NO initializer
detail = format!("{e}");     // bare local assignment, no receiver dot
FfiVaultError::Boom { detail }   // shorthand
```
`7fa210c`: 1 finding. HEAD (pre-fix): **0**. Three things interacting from different tasks — Task 7's `;` terminator made the span extract to exactly `String`, arm 3 accepts that as a declaration, and `GATED_ASSIGN_RE` needs a receiver dot so the follow-up assignment is not a candidate. **No per-task reviewer could have seen it**; each task's change was correct in isolation. Fixed by threading the terminator into `initializer_is_gated`, pinned by control `BP44`, and verified not over-eager against seven declaration shapes including the trait-method-signature edge case.

Its companion finding: the `;` terminator shipped under a comment asserting it "changes nothing for `GATED_INIT_RE` candidates" — premise true, conclusion false. **Documentation claiming more coverage than the code delivers was the single most repeated finding of the session, caught in five separate reviews.**

## (2) What's next

- **#494** (filed this session) — `cli/src/daemon.rs:424` mints an `io::Error` from a runtime string and sits outside every scan root. Not a live exposure (the bridge never calls into `cli::daemon`), but it is now the sole manual re-review item on the `impl GatedDetail for std::io::Error` allowlist row. **Acceptance is in the issue**: add `cli/src/**` as a fifth root, add a sanctioned constructor there, or record the decision.
- **#495** (filed this session) — split `payload_guard/discovery.py` (935 lines, two unrelated parsers). The seam is specified concretely: the `use`-tree/foreign-name group, ~215 lines, strictly one-directional. **Gate it on the identity harness diffing empty**, not on a green self-test.
- **E3's remaining laundering shapes** — pattern-destructuring binds (tuple, tuple-struct, struct, slice), `if let`/`while let`/`for`, build-then-mutate via a method call, the dotless statement-position assignment, and the function-parameter case. All enumerated honestly in CLAUDE.md and the guard's LIMITS; none has a live producer (grepped). Closing them needs pattern/dataflow analysis.
- **#483** (test_support module) · **#484** (four cosmetic) — untouched.
- **#473 / #476** on-screen diagnostics · **#477** detekt rule · **#459** iOS on-device Settings · **#464** CodeQL Swift · **#492** CodeQL v3→v4 (Dec 2026 deadline) · **#417**, **#447**, **#443/#444** — all carried unchanged.

## (3) Open decisions and risks

- **The claim discipline is now load-bearing prose in more places than before.** CLAUDE.md, the entry-point LIMITS, `rules/e3.py`, `rules/e5.py` and the allowlist's Section 2b all enumerate what is closed and what is open. If any of #494/#495 closes, or a new residual class appears, **re-point them together** — they cross-reference each other, and the session's most repeated defect was exactly this drifting.
- **Wrapper `detail.rs` constructor signatures are review-gated, not CI-gated.** A `pub(crate) fn passthrough(s: &str)` added there would be accepted by E3 and permitted by E5. The final reviewer confirmed the **bridge behaves identically** (E4 pins `impl GatedDetail`, not fn signatures), so this is a pre-existing property of the sink-pinning design extended to two more crates — not a new asymmetry. Worth knowing before adding a constructor.
- **E5 covers `format!`, not `.to_string()` / `push_str` / `write!` / `+` / `.join()`.** Backed by a census showing zero live composition sites in either wrapper crate. If that census stops holding, E5 widens.
- **Two documented false positives**, both fail-closed: a type-annotated legitimate re-wrap (`let detail: String = detail::gated(e);`) fires, and turbofish/generic commas mis-slice the io-payload span (garbled `field_type`, still denies).
- **`#482`'s acceptance text literally says "P40"**; that label was already taken by a control from PR #479 (#485), so the new one is **P41**. Say so when closing #482.
- **Allowlist budget held**: exactly **1** net-new data row on the whole branch (a test-module `let` site whose `mod` is `#[cfg(test)]`-gated in its parent), against a self-imposed cap of 2.

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After the PR merges (squash leaves the branch "not fully merged"):
#   git worktree remove .worktrees/486-guard-residual-closeout && git branch -D feature/486-guard-residual-closeout
git worktree list && git status -s

# Gates for this slice (run from the worktree while the PR is open):
#   cd /Users/hherb/src/secretary/.worktrees/486-guard-residual-closeout
#   uv run scripts/check-error-payload-hygiene.py --self-test && uv run scripts/check-error-payload-hygiene.py
#   bash scripts/dev/payload_guard_identity.sh /tmp/after.txt   # dev-only harness
#   cargo test --release --workspace
#   cargo clippy --release --workspace --tests -- -D warnings
#   RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
#   uv run core/tests/python/conformance.py
#   bash ios/scripts/check-public-log-hygiene.sh --self-test && bash ios/scripts/check-public-log-hygiene.sh
#   bash android/scripts/check-log-hygiene.sh --self-test && bash android/scripts/check-log-hygiene.sh
#   bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh
#   (cd desktop && pnpm test && pnpm run svelte-check)
#   (cd android && ./gradlew :vault-access:test :kit:compileDebugKotlin)
```

**Acceptance, verified at `820d6fd`:** guard self-test **41/18/44/24/4/3** · real scan **OK across four roots** · `cargo test --release --workspace` all green · clippy + rustdoc + fmt `-D warnings` clean · **`error_payload_hygiene_parity` green AT HEAD** (the final reviewer specifically asked — it had only been run at Tasks 2/3) · conformance.py PASS · iOS log hygiene 21/9 · Android log hygiene 27/14 · lean-binding 3/3 · desktop **674 tests** + svelte-check 0 errors · Gradle `:kit` BUILD SUCCESSFUL · `git diff main... -- ffi/secretary-ffi-uniffi/src/secretary.udl` **EMPTY** · no `FfiVaultError` variant/field change · no KAT regeneration · all 18 commits carry the trailer (checked per commit — on git 2.54 a range `%(trailers:…)` audit never returns empty).

**Still not verified:** CI on the PR (pushed at session end — check first thing); the Swift/Kotlin conformance runners (manual-only, and nothing crossing the FFI surface changed — `.udl` diff is empty); `:app:assembleDebug`; `core/fuzz` compile (workspace-excluded, nightly). The cargo gates were run at `2990bab`; the only later commit touches Python and markdown, so those results still hold.

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch. Do **not** sync to `main` during the pause window. If resuming this branch for fixups: `git fetch origin && git merge origin/main` FIRST (branch version wins on this doc) before editing.

## Closing inventory

- **State on close:** PR open on `feature/486-guard-residual-closeout`, shipping **#486 + #482 + #487 + #488** and rule **E5**. Net: guard split into a package (entry point 5035 → 362 lines); 4 scan roots, 5 rules, 4 E3 candidate positions; two wrapper `detail.rs` modules; `field: &str` → `&'static str`; one real pre-existing bug fixed (`device.rs` read a length after `zeroize()`, always reporting "got 0"); 1 net-new allowlist row; #494/#495 filed. **No on-disk format change, no FFI surface change, no `.udl` change.**
- **Docs:** CLAUDE.md substantially rewritten (four roots, five rules, honest open-limits list). README/ROADMAP verified **unchanged** by grep.
- **Next:** **#494** · **#495** · E3's pattern/dataflow residuals · #483 · #484 · #473/#476 · #477 · #459 · #464 · #492 · #417 · #447 · #443/#444.
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-08-09-486-guard-residual-closeout-shipped.md`.
