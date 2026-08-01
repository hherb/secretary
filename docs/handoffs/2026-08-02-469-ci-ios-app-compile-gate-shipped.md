# NEXT_SESSION.md — #469 CI iOS-app compile gate shipped (PR #470)

**Session date:** 2026-08-02, resuming from `main` @ `0ecc5db` (PR #468 / **#459** merged during the pause window — the prior baton was fully consumed). Branch `feature/469-ci-ios-app-compile-gate`; worktree `.worktrees/469-ci-ios-app-compile-gate`.

Full brainstorm → spec → plan → inline execution → CI proof, all this session. User decisions: pick **#469** from the prior baton's menu; placement **A** (a new CI step calling `build-app.sh`, keeping each script single-purpose) over appending a step 5 to `run-macos-tests.sh`; proof level **local mutation + one deliberately-red CI run**; keep **#464 (CodeQL Swift) out of scope**.

## Session-start cleanup

- `main` fetched + verified in sync; dropped the merged `.worktrees/459-ios-settings-commit-at-save` worktree + `feature/459-ios-settings-commit-at-save` branch.
- Deleted **5 stale local branches**, all verified safe first: `claude/hardcore-robinson-373901` and `claude/laughing-chandrasekhar-367f89` were 0 commits ahead of `origin/main`; `pr-99` / `pr-148` / `pr-303` looked unmerged only because PRs #99 / #148 / #303 were **squash**-merged (all three confirmed MERGED via `gh pr view`).
- **#459 deliberately left OPEN** — it shipped in #468, but its on-device confirmation is still outstanding, so closing it now would close it on an inferred repro. User's call.

### ⚠️ Correction to the previous baton: the `clean_gone` skill is NOT broken

The prior handoff claimed `commit-commands:clean_gone` has a broken grep (`git branch -v | grep '\[gone\]'`) that "fails silently". **That is wrong, and the claim should not be propagated further.**

`git branch -v` **does** print `[gone]`. Git's `-v` shows the upstream *relationship*; `-vv` additionally shows the upstream *name*, which is what renders it as `[origin/foo: gone]`. So the plugin's `-v`-based pattern is correct and the `-vv`-based "fix" was a fix to a non-bug.

Verified empirically against **git 2.54.0** in a throwaway repo with a real gone branch:

```
$ git branch -v          →   feat 7699fb5 [gone] feat
$ git branch -vv         →   feat 7699fb5 [origin/feat: gone] feat
```

Both the old and the "fixed" pattern matched. The plugin file was edited and then **reverted** to pristine; no change shipped. (The prior baton was also internally inconsistent — it said the skill "deleted 4 stale `[gone]` branches" *and* that it silently deletes nothing.)

## (1) What we shipped this session

**#469.** Nothing in CI compiled `ios/SecretaryApp`. `macos-host.yml` covered `SecretaryMac.app`; `test.yml`'s `ios-host` job covered only the two FFI-free host packages; `ios/scripts/run-ios-tests.sh` step 5 does build the iOS app but is wired into no workflow. So all fifteen iOS app-target source files were compile-gated only by a developer remembering to run `build-app.sh` locally — and that is the file class most prone to failing invisibly to host tests, since a SwiftUI type-check ceiling (`xcodebuild` exit 65) has no runtime or unit-test signal. PR #468 changed `SettingsScreen.swift` and relied entirely on a local build for that proof.

- **Design spec** `docs/superpowers/specs/2026-08-02-469-ci-ios-app-compile-gate-design.md` (`29dc62d`, corrected in `8c388ea`).
- **Implementation plan** `docs/superpowers/plans/2026-08-02-469-ci-ios-app-compile-gate.md` (`ded4659`).
- **The change** (`6d6bfc4`) — `.github/workflows/macos-host.yml` only:
  - one new step, `bash ios/scripts/build-app.sh`, **after** the `run-macos-tests.sh` step;
  - workflow `name:` `macOS host` → `macOS host + app compile`; job `name:` → `SecretaryKit macOS host + macOS/iOS app compile`; the runner step renamed to say `macOS app compile` so the two are distinguishable in the UI;
  - header comment recording the gap, the ordering rationale, and `#469`.
- **The red proof** (`5c37a4f`) and **its revert** (`cafd101`).
- **ROADMAP** clause extended (see below).

### Why the step order is load-bearing (not stylistic)

`build-app.sh` opens with `if [[ ! -d "$XCFRAMEWORK" ]]; then bash build-xcframework.sh; fi`. Placed **after** `run-macos-tests.sh` — whose step 2 already builds the xcframework including both iOS simulator slices (`aarch64-apple-ios-sim`, `x86_64-apple-ios`) — that branch is not taken, so the step reduces to `xcodegen` + one signing-free `xcodebuild` (`generic/platform=iOS Simulator` + `CODE_SIGNING_ALLOWED=NO`, no simulator boot). Placed **before**, the fallback fires and the job pays the 4-triple cross-compile twice. The workflow comment says this explicitly, because a reorder would otherwise look harmless.

Everything else in the job was already paid for: `brew install xcodegen` (needed by `build-macos-app.sh`), the `macos-26` + Xcode 26.5 pins, the `ios/** + ffi/** + core/**` path gate, and the 45-minute cap.

### Why the gate was proven red before green

A CI gate never observed failing is indistinguishable from a no-op — the same vacuity hazard `ffi/scripts/check-lean-binding.sh --self-test` already guards against by firing its matcher on a known-positive control before a clean run is trusted. So:

| # | Level | Result |
|---|---|---|
| 1 | `build-app.sh` on the unmodified branch | ✅ `** BUILD SUCCEEDED **`, exit 0 |
| 2 | `build-app.sh` with a broken symbol in `SettingsScreen.swift` | ✅ **exit 65**, `error: cannot find 'deliberatelyUndefinedSymbolForIssue469' in scope` |
| 3 | CI red **on the new step** | ✅ run [30723278616](https://github.com/hherb/secretary/actions/runs/30723278616) — `failure` on `build-app.sh (iOS app compile proof, #469)` |
| 4 | CI green after revert | ✅ (see Acceptance) |

**The most informative single fact in the whole slice:** in the red run, the preceding step `run-macos-tests.sh (SecretaryKit macOS host + macOS app compile)` **succeeded** while the iOS app was broken. That is not just a passing proof — it is direct, independent evidence of the exact gap #469 describes, observed rather than argued.

An **undefined symbol** was chosen over a syntax error (which any tool catches, proving less) and over a deliberate type-check timeout (slow and nondeterministic). It fails in the type-checker — the realistic failure class for this file — deterministically. CI reproduced the identical diagnostic at the identical line (`SettingsScreen.swift:202:13`).

### A wrong claim, caught and corrected mid-session

The spec initially justified reusing locally-cached build artifacts on the grounds that every `core/`/`ffi/` change since they were built was "test-only". **That was false** — `#449`/`#451` moved test-support code through *non-test* source files in `secretary-ffi-bridge` and `secretary-ffi-uniffi`. The `.udl` was untouched, which is a reason to *expect* stable bindings but not a verification of one.

Resolved by regenerating `secretary.swift` at `0ecc5db` and byte-comparing against the 2026-07-16 copy: **identical**. The reuse was in fact harmless — but that is now a checked fact rather than an inference from a false premise. Recorded in the spec (`8c388ea`).

### Local build prerequisites (cost a build cycle to learn — now written down)

`build-xcframework.sh` emits **three** gitignored artifacts, and a fresh worktree has none:

1. `ios/Secretary.xcframework/`
2. `ios/SecretaryKit/Sources/SecretaryKit/secretary.swift` — the generated uniffi bindings
3. `ios/SecretaryKit/Tests/SecretaryKitTests/Resources/` — the staged golden-vault fixtures

Seeding only (1) fails with `cannot find type 'VaultError' / 'OpenVaultOutput' in scope`, because (2) is where those generated types live. All three are required.

## Acceptance (all run this session)

```bash
cd .worktrees/469-ci-ios-app-compile-gate
bash ios/scripts/build-app.sh          # ** BUILD SUCCEEDED ** (exit 0)
actionlint .github/workflows/macos-host.yml   # clean
git diff main... --name-only -- ios/ core/ ffi/   # EMPTY
```

CI: red run [30723278616](https://github.com/hherb/secretary/actions/runs/30723278616) (4m29s, failure isolated to the new step) → green run after the revert.

`git diff --name-only main... | grep -E '^(core|ffi)/'` is **empty** — no Rust surface touched, so the Rust/clippy/conformance gates are not required. No Swift change survives in the merged diff either: `SettingsScreen.swift` is byte-identical to `main`.

**README: no change.** Verified against precedent, not assumed — README tracks *slices* in prose and never enumerates CI coverage; #437, the directly comparable CI-wiring change, does not appear there at all.

**ROADMAP: changed.** Also by precedent — #437 *did* earn a clause inside the D.5.1 prose, and that clause **enumerates what the job guards**, an enumeration this PR would otherwise leave incomplete. Extended in place rather than adding a new entry.

## (2) What's next

- **#459 on-device confirmation** — still outstanding, still the reason #459 is open. **Acceptance:** install on the iPhone, type a new grace value, tap Save **without** dismissing the number pad, re-open Settings, confirm the typed value persisted; then clear a field, tap Save, confirm the "Each field needs a whole number" refusal rather than a silent old-value write. **Run the repro INSIDE the grace window** (save once first, then immediately test) — outside it, the Face ID prompt dismisses the keyboard, which itself resigns first responder and flushes the old binding, so the old build may not reproduce the bug and the test reads as a false "no bug". Also worth one pass with an **Arabic or Persian keyboard** active, since `.numberPad` renders in the active keyboard's numeral system and the non-ASCII digit fold is host-tested but never device-observed.
- **#464** — CodeQL Swift analysis. Deliberately kept out of this slice, but **this slice makes it cheaper**: it answers #464's open "which schemes/targets to analyze" question for the iOS app and proves the build recipe under a pinned toolchain. Still needs its own decisions (matrix leg vs. separate path-gated `codeql-swift.yml`) plus triage of the first batch of public Swift alerts over Keychain / Secure-Enclave / FFI secret-marshalling code. **Acceptance:** `swift` appears in `gh api repos/:owner/:repo/code-scanning/analyses` after it lands on `main`, and the other five languages' results do not regress.
- **#467** — no automated guard that a secret-bearing error can reach the `.public` fold-site log. Decision issue with three options (injected `@MainActor` sink / sanitize-at-source marker protocol / accept-as-documented). **Acceptance:** an automated check, or a recorded decision closing it wontfix.
- **#417** — mobile Trash purge-notice render test; needs a UI-test target. Would retire the "render-untested" caveat on both Settings screens and cover the ~3 lines of view glue #459 left uncovered. **Now partially unblocked:** CI compiles the iOS app target, so an added UI-test target has a build to attach to.
- **#447** — biometric unlock for Tauri desktop (decision issue; needs the ADR-0011 coexistence question first). A brainstorm, not a code slice.
- **#443 / #444** — Linux (fprintd/polkit) / Windows Hello presence providers; not testable on this macOS host.

## (3) Open decisions and risks

- **The PR contains one intentionally-red CI run.** It squash-merges away, and the PR body explains it, but anyone scanning run history will see a red `macos-host` on this branch. That is the point — it is the evidence — but it needs the explanation to not read as a flake.
- **Coverage is compile-only.** This buys the iOS app target a compiler, not a test. `SettingsScreen.swift` remains render-untested (#417); the view glue #459 left uncovered stays uncovered. Do not let a green `macos-host` be mistaken for behavioural coverage of the iOS app.
- **`build-app.sh` also stages fixtures and regenerates the Xcode project** (`rm -rf ios/SecretaryApp/Fixtures`, `xcodegen generate`). Harmless in CI (fresh checkout) and all outputs are gitignored, but it means the step is not a pure compile — a fixture-staging failure would also redden it.
- **`timeout-minutes: 45` is still the provisional #437 value.** The full red run took 4m29s with a warm cargo cache, so the cap is generous. Re-tuning was explicitly out of scope; revisit once several runs exist.
- **Only `macos-host.yml` gates the iOS app**, and it is path-gated to `ios/** + ffi/** + core/** + the workflow file`. A change that breaks the iOS app compile from *outside* those paths would not be caught. No such path is known today.
- **The shell cwd silently reset to the main checkout mid-session**, and a `git checkout main -- ios/…` intended for the worktree ran in `main` instead. It was a no-op there (main was clean), so no damage — but this is the [[feedback_edit_tool_targets_main_not_worktree]] / [[feedback_bash_cwd_persists_verify_before_killing]] hazard firing for real. **Spell out `cd <worktree> && …` on every single call**, including ones that "obviously" follow a previous `cd`.

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After PR #470 merges, drop the branch + worktree (squash-merge leaves it "not fully merged"):
#   git worktree remove .worktrees/469-ci-ios-app-compile-gate && git branch -D feature/469-ci-ios-app-compile-gate
git worktree list && git status -s

# If resuming THIS branch for fixups — bind histories FIRST (closes the add/add gap on the handoff doc):
#   cd .worktrees/469-ci-ios-app-compile-gate && git fetch origin && git merge origin/main

# Gates for this slice (no Rust/Swift surface touched, so no cargo/clippy/conformance run needed):
#   actionlint .github/workflows/macos-host.yml
#   cd .worktrees/469-ci-ios-app-compile-gate && bash ios/scripts/build-app.sh
```

**Cold-worktree note:** a fresh worktree has **none** of the three gitignored build artifacts listed above. The first app build cross-compiles the Rust staticlib for four Apple triples — multi-minute and silent. Warm it at the controller level with `bash ios/scripts/build-xcframework.sh` in the background before anything that needs it ([[project_secretary_ios_xcframework_build_watchdog]]). `swift test` in `SecretaryVaultAccess` needs none of them (FFI-free), so that inner loop stays fast.

**Bash cwd gotcha:** session cwd persists across foreground calls *and can also reset without warning* — spell out `cd <worktree> && …` every time ([[feedback_bash_cwd_persists_verify_before_killing]]). Edit-tool paths must spell out `.worktrees/469-ci-ios-app-compile-gate/…` or they hit MAIN ([[feedback_edit_tool_targets_main_not_worktree]]).

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; the symlink retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). The handoff rides inside the PR — do **not** sync to `main` during the pause window ([[feedback_next_session_main_authoritative]]). If resuming this branch for fixups, `git fetch origin && git merge origin/main` first (branch version wins on this doc) before editing.

## Closing inventory

- **State on close:** PR **#470** on `feature/469-ci-ios-app-compile-gate` (worktree `.worktrees/469-ci-ios-app-compile-gate`), shipping **#469**. Net: **one workflow file changed** (+1 step, 3 `name:` edits, a header comment) plus docs. **No `core` / `ffi` / Swift / FFI-surface / on-disk-format change** — the final `git diff main... -- ios/ core/ ffi/` is empty.
- **Commits:** `29dc62d` (spec) · `8c388ea` (spec correction — bindings verified identical) · `ded4659` (plan) · `6d6bfc4` (**the workflow change**) · `5c37a4f` (deliberate break) · `cafd101` (revert) · ROADMAP + handoff.
- **Acceptance:** `build-app.sh` **BUILD SUCCEEDED** · local mutation **exit 65** · `actionlint` **clean** · CI **red on exactly the new step** ([30723278616](https://github.com/hherb/secretary/actions/runs/30723278616)) → **green after revert** · product diff vs `main` **empty**.
- **Docs:** ROADMAP D.5.1 CI clause extended (precedent: #437). README unchanged (precedent: #437 absent from it).
- **Next:** #459 on-device confirm (INSIDE the grace window; also an Arabic/Persian keyboard pass) · **#464** (CodeQL Swift — now cheaper) · #467 (fold-site privacy guard decision) · #417 (render tests — now partially unblocked) · #447 (Tauri biometric decision) · #443/#444 (Linux/Windows presence).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-08-02-469-ci-ios-app-compile-gate-shipped.md`.
