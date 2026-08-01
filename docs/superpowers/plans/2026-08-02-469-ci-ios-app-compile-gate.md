# CI iOS-App Compile Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make CI compile `ios/SecretaryApp`, so a type-check or API error in an iOS app-target source file fails a PR instead of reaching `main`.

**Architecture:** Add one `bash ios/scripts/build-app.sh` step to the existing `macos-host.yml` job, placed *after* the `run-macos-tests.sh` step so the xcframework (including both iOS simulator slices) is already on disk and `build-app.sh`'s cross-compile fallback is not taken. No script, Swift, or Rust change. The gate is then proven red-before-green at both the command level (local mutation) and the CI level (a deliberately-broken first push).

**Tech Stack:** GitHub Actions, `xcodebuild`, XcodeGen, `actionlint`.

**Spec:** [`docs/superpowers/specs/2026-08-02-469-ci-ios-app-compile-gate-design.md`](../specs/2026-08-02-469-ci-ios-app-compile-gate-design.md)

## Global Constraints

- **Branch / worktree:** `feature/469-ci-ios-app-compile-gate` in `.worktrees/469-ci-ios-app-compile-gate`. Every `cd` must be spelled out; Edit-tool paths must include `.worktrees/469-ci-ios-app-compile-gate/` or they hit the main checkout.
- **The final merged diff must touch exactly one non-doc file:** `.github/workflows/macos-host.yml`. `git diff main... -- ios/ core/ ffi/` must be empty at ship.
- **Do not change** the path gate, `timeout-minutes: 45`, `runs-on: macos-26`, the `setup-xcode` `26.5` pin, the `brew install xcodegen` step, or `ios/scripts/*`.
- **Workflow filename stays `macos-host.yml`** — it is referenced by its own `paths:` entry and by `concurrency.group`.
- **Step order is load-bearing:** the new step goes *after* `run-macos-tests.sh`, never before.
- **Exact new names:** workflow `name: macOS host + app compile`; job `name: SecretaryKit macOS host + macOS/iOS app compile`.
- **Local build prerequisites** (all three gitignored, all three required — seeding only the first fails with `cannot find type 'VaultError' in scope`):
  `ios/Secretary.xcframework/`, `ios/SecretaryKit/Sources/SecretaryKit/secretary.swift`, `ios/SecretaryKit/Tests/SecretaryKitTests/Resources/`.
- **Commit trailer:** every commit ends with `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`.

---

### Task 1: Local red proof — the mutation check

Establishes that `build-app.sh` is a real gate before any CI wiring is written. This is the analogue of "watch the test fail first": a gate never observed failing is indistinguishable from a no-op.

**Files:**
- Modify (transiently, reverted in Step 5): `ios/SecretaryApp/Sources/SettingsScreen.swift`
- No commit in this task — it produces evidence, not a diff.

**Interfaces:**
- Consumes: a green `bash ios/scripts/build-app.sh` baseline (already established: `** BUILD SUCCEEDED **`, exit 0).
- Produces: the recorded non-zero exit code + compiler diagnostic quoted in Task 4's PR body and in the handoff.

- [ ] **Step 1: Confirm the baseline is green**

```bash
cd /Users/hherb/src/secretary/.worktrees/469-ci-ios-app-compile-gate
bash ios/scripts/build-app.sh 2>&1 | tail -3
```

Expected: `** BUILD SUCCEEDED **`. If this fails, stop — the three prerequisite artifacts above are missing or stale; re-seed them before continuing.

- [ ] **Step 2: Introduce an undefined-symbol reference**

In `ios/SecretaryApp/Sources/SettingsScreen.swift`, inside the `save()` method body, add as the first line:

```swift
        _ = deliberatelyUndefinedSymbolForIssue469
```

An undefined symbol is chosen over a syntax error (which any tool catches, proving less) and over a deliberate type-check timeout (slow and nondeterministic). It fails in the type-checker — the realistic failure class for this file — deterministically.

- [ ] **Step 3: Run the gate and capture the failure**

```bash
cd /Users/hherb/src/secretary/.worktrees/469-ci-ios-app-compile-gate
bash ios/scripts/build-app.sh > /tmp/red.log 2>&1; echo "EXIT=$?"
grep -n "error:" /tmp/red.log | head -5
```

Expected: `EXIT=65`, and an `error: cannot find 'deliberatelyUndefinedSymbolForIssue469' in scope` line naming `SettingsScreen.swift`. Record both verbatim.

- [ ] **Step 4: Verify the failure is attributable to the app target**

Confirm the erroring path is under `ios/SecretaryApp/Sources/`, not a package. This matters because Task 3's CI proof requires the *new* step to be the failing one; a break that also fails an earlier step would invalidate it.

- [ ] **Step 5: Revert the break**

```bash
cd /Users/hherb/src/secretary/.worktrees/469-ci-ios-app-compile-gate
git checkout -- ios/SecretaryApp/Sources/SettingsScreen.swift
git status -s   # expect: clean
```

---

### Task 2: Wire the step into `macos-host.yml`

**Files:**
- Modify: `.github/workflows/macos-host.yml` — header comment (lines 1-14), workflow `name:` (line 1), job `name:` (line 40), new step after line 69.

**Interfaces:**
- Consumes: nothing from Task 1 except the confidence that `build-app.sh` gates.
- Produces: the workflow the Task 3 CI proof exercises.

- [ ] **Step 1: Update the workflow `name:` and the header comment**

Workflow `name:` becomes `macOS host + app compile`. Append to the header comment block:

```yaml
# #469: the job also compiles the *iOS* app target (ios/SecretaryApp). Nothing
# in CI built it before — test.yml's ios-host job runs only the two FFI-free
# host packages, and run-ios-tests.sh (which does build it) is not wired into
# any workflow — so every iOS app-target source file was compile-gated only by
# a developer remembering to run build-app.sh locally. That is the file class
# most prone to failing invisibly to host tests: a SwiftUI type-check ceiling
# ("unable to type-check in reasonable time", xcodebuild exit 65) has no
# runtime or unit-test signal.
```

- [ ] **Step 2: Update the job `name:`**

```yaml
    name: SecretaryKit macOS host + macOS/iOS app compile
```

- [ ] **Step 3: Add the step, after the `run-macos-tests.sh` step**

```yaml
      # #469: iOS app-target compile proof. MUST stay AFTER the runner above:
      # run-macos-tests.sh step 2 builds the xcframework including both iOS
      # simulator slices (aarch64-apple-ios-sim + x86_64-apple-ios), so
      # build-app.sh finds it on disk and skips its own build-xcframework.sh
      # fallback — reducing this step to xcodegen + one signing-free
      # xcodebuild (~1-2 min). Reordered before the runner, that fallback
      # fires and the job pays the 4-triple cross-compile twice.
      - name: build-app.sh (iOS app compile proof, #469)
        run: bash ios/scripts/build-app.sh
```

- [ ] **Step 4: Lint the workflow**

```bash
cd /Users/hherb/src/secretary/.worktrees/469-ci-ios-app-compile-gate
actionlint .github/workflows/macos-host.yml && echo "actionlint clean"
```

Expected: no output before `actionlint clean`.

- [ ] **Step 5: Verify the diff is confined to the one file**

```bash
cd /Users/hherb/src/secretary/.worktrees/469-ci-ios-app-compile-gate
git diff --name-only
```

Expected: exactly `.github/workflows/macos-host.yml`.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/469-ci-ios-app-compile-gate
git add .github/workflows/macos-host.yml
git commit -m "ci(469): compile the iOS app target in the macos-host job

$(printf '%s' 'Nothing in CI built ios/SecretaryApp. Placed after run-macos-tests.sh
so the xcframework (incl. both iOS simulator slices) is already on disk
and build-app.sh skips its cross-compile fallback.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>')"
```

---

### Task 3: CI red proof — push the gate failing

The issue's literal acceptance criterion. Task 1 proved the *command* gates; this proves the *wiring* fires.

**Files:**
- Modify (transiently): `ios/SecretaryApp/Sources/SettingsScreen.swift`

**Interfaces:**
- Consumes: the workflow from Task 2.
- Produces: a run URL + the failing step name, quoted in the PR body and handoff.

- [ ] **Step 1: Re-introduce the same break as Task 1 Step 2 and commit it**

```bash
cd /Users/hherb/src/secretary/.worktrees/469-ci-ios-app-compile-gate
# re-apply the `_ = deliberatelyUndefinedSymbolForIssue469` line in save()
git add ios/SecretaryApp/Sources/SettingsScreen.swift
git commit -m "test(469): TEMPORARY deliberate compile error — prove the gate fires

$(printf '%s' 'Reverted in the next commit. A CI gate never observed failing is
indistinguishable from a no-op; this makes the red run a matter of
record rather than an argument.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>')"
```

- [ ] **Step 2: Push the branch**

```bash
cd /Users/hherb/src/secretary/.worktrees/469-ci-ios-app-compile-gate
git push -u origin feature/469-ci-ios-app-compile-gate
```

- [ ] **Step 3: Watch the run and record the failing step**

```bash
cd /Users/hherb/src/secretary/.worktrees/469-ci-ios-app-compile-gate
gh run list --workflow=macos-host.yml --branch=feature/469-ci-ios-app-compile-gate --limit 1 \
  --json databaseId,conclusion,url
```

Poll until `conclusion` is non-null. Expected: `failure`.

- [ ] **Step 4: Assert the failure is on the NEW step, not an earlier one**

```bash
cd /Users/hherb/src/secretary/.worktrees/469-ci-ios-app-compile-gate
gh run view <databaseId> --json jobs \
  -q '.jobs[].steps[] | select(.conclusion=="failure") | .name'
```

Expected: exactly `build-app.sh (iOS app compile proof, #469)`.

**If instead the `run-macos-tests.sh` step failed**, the proof is invalid — that runner does not compile the iOS app target, so a `SettingsScreen.swift` break reaching it means something else broke. Stop and diagnose; do not proceed to Task 4.

---

### Task 4: Green proof + PR

**Files:**
- Modify: `ios/SecretaryApp/Sources/SettingsScreen.swift` (revert to `main` state)

**Interfaces:**
- Consumes: the red run from Task 3.
- Produces: a green run on the same workflow, and the PR.

- [ ] **Step 1: Revert the deliberate break**

```bash
cd /Users/hherb/src/secretary/.worktrees/469-ci-ios-app-compile-gate
git checkout main -- ios/SecretaryApp/Sources/SettingsScreen.swift
git diff main... --name-only -- ios/   # expect: empty
```

- [ ] **Step 2: Commit and push**

```bash
cd /Users/hherb/src/secretary/.worktrees/469-ci-ios-app-compile-gate
git add ios/SecretaryApp/Sources/SettingsScreen.swift
git commit -m "test(469): revert the deliberate compile error

$(printf '%s' 'The red run is recorded; the gate is proven. SettingsScreen.swift is
now byte-identical to main.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>')"
git push
```

- [ ] **Step 3: Confirm the new run is green**

```bash
cd /Users/hherb/src/secretary/.worktrees/469-ci-ios-app-compile-gate
gh run list --workflow=macos-host.yml --branch=feature/469-ci-ios-app-compile-gate --limit 1 \
  --json conclusion,url
```

Expected: `success` — proving the gate passes clean code (no false positive).

- [ ] **Step 4: Assert the final diff touches no product code**

```bash
cd /Users/hherb/src/secretary/.worktrees/469-ci-ios-app-compile-gate
git diff main... --name-only
```

Expected: `.github/workflows/macos-host.yml` plus `docs/` files only. **Nothing** under `ios/`, `core/`, or `ffi/`.

- [ ] **Step 5: Open the PR**

The body must explain the intentionally-red run so it does not read as a flake: link the red run URL, name the failing step, link the green run, and state that the intermediate commit is squashed away on merge.

---

### Task 5: Docs + handoff

**Files:**
- Modify (if warranted): `README.md`, `ROADMAP.md`
- Create: `docs/handoffs/2026-08-02-469-ci-ios-app-compile-gate-shipped.md`
- Retarget: `NEXT_SESSION.md` symlink

- [ ] **Step 1: Decide README/ROADMAP by precedent, not by reflex**

The comparable precedent is #437 (CI wiring of `run-macos-tests.sh` as the `macos-host` job), which *did* earn a clause inside ROADMAP's D.5.1 prose. Check that clause and extend it if #469 fits the same shape; README tracks slices and per-CI-gate entries do not appear there. Record the decision either way — "no change, here is the precedent" is a valid outcome, but an unexamined one is not.

- [ ] **Step 2: Write the handoff**

Path: `docs/handoffs/2026-08-02-469-ci-ios-app-compile-gate-shipped.md`. Must carry: what shipped with commit SHAs; what's next with acceptance criteria; open decisions/risks; exact resume commands (cd, branch, test command).

Must also correct the previous baton's claim that the `clean_gone` skill's grep is broken — it is not. `git branch -v` *does* print `[gone]` (git's `-v` shows the upstream *relationship*; `-vv` adds the upstream *name*, which is what renders it as `[origin/foo: gone]`). Verified against git 2.54.0 in a throwaway repo. Leaving this uncorrected would propagate a false claim into a future session.

- [ ] **Step 3: Retarget the symlink and commit both**

```bash
cd /Users/hherb/src/secretary/.worktrees/469-ci-ios-app-compile-gate
ln -snf docs/handoffs/2026-08-02-469-ci-ios-app-compile-gate-shipped.md NEXT_SESSION.md
ls -la NEXT_SESSION.md && head -3 NEXT_SESSION.md
git add NEXT_SESSION.md docs/handoffs/
git commit -m "docs(469): session handoff baton"
git push
```

---

## Self-Review

**Spec coverage:** every spec section maps to a task — approach + ordering + renames → Task 2; the four-row acceptance table → Task 1 (rows 1-2), Task 3 (row 3), Task 4 (row 4); `actionlint` → Task 2 Step 4; the empty-product-diff criterion → Task 4 Step 4; local build prerequisites → Global Constraints + Task 1 Step 1. Non-goals (#464, durable self-test, #417, Android, timeout re-tune) generate no tasks by design.

**Placeholder scan:** no TBD/TODO. The one deliberate non-literal is `<databaseId>` in Task 3 Steps 3-4, which is a value produced by the preceding command.

**Type consistency:** the symbol `deliberatelyUndefinedSymbolForIssue469` is identical in Task 1 Step 2 and Task 3 Step 1. The step name `build-app.sh (iOS app compile proof, #469)` is identical in Task 2 Step 3 and the Task 3 Step 4 assertion — these must not drift, since the CI proof asserts on that exact string.
