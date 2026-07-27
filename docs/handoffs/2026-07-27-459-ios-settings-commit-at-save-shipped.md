# NEXT_SESSION.md — #459 iOS Settings commit-at-Save shipped (PR opens with this branch)

**Session date:** 2026-07-26 → 2026-07-27, resuming from `main` @ `fee1622` (PR #466 / **#456** merged during the pause window — the prior baton was fully consumed). Branch `feature/459-ios-settings-commit-at-save`; worktree `.worktrees/459-ios-settings-commit-at-save`.

Full brainstorm → spec → plan → inline TDD execution → review, all this session. User decisions: pick **#459** from the prior baton's menu; **host-only** this session (no on-device work); approach **A+** (shared buffer + commit helper) after the user asked which option was safest from a security and maintainability standpoint — which flipped the recommendation away from the VM-owned buffer.

## Session-start cleanup

- `main` ff-checked (already in sync with `origin`); dropped the merged `.worktrees/456-fold-site-logging` worktree + `feature/456-fold-site-logging` branch.
- Closed **#456** (landed as `fee1622` / PR #466, but left open by the "(#N)" ref convention — see [[project_secretary_stale_but_done_issues]]).
- Ran `commit-commands:clean_gone`, which deleted 4 stale `[gone]` branches. **Note: the skill's own command is buggy** — it greps `git branch -v | grep '\[gone\]'`, but `git branch -vv` prints `[origin/foo: gone]`, so the bracket does not immediately precede `gone` and the pattern never matches (it silently reports "no cleanup needed"). The working pattern is `git branch -vv | sed 's/^[+* ]//' | grep ': gone\]'`. Worth fixing in the skill.
- `pr-99` / `pr-148` / `pr-303` remain — they have no upstream at all, so `clean_gone` does not consider them. Offer explicitly next session.
- **#467** was filed at the end of the previous session (the tracked form of that baton's risk 3: no automated guard that a new error source routes a secret to the `.public` fold-site log). Still open, untouched here.

## (1) What we shipped this session

**#459.** `ios/SecretaryApp/Sources/SettingsScreen.swift` bound both numeric inputs with `TextField(value:format:)`, which commits only on Return or focus loss. Two holes: (a) tapping the in-`Form` Save button does not reliably resign first responder, so a typed-then-tapped Save could persist the **previous** value while the field displayed the new one — and `.keyboardType(.numberPad)` has no Return key, so focus loss was the *only* commit trigger on iOS; (b) clearing a field made the parse fail, leaving the bound value untouched, so Save silently re-wrote the old value against a visibly empty box. Both broke the WYSIWYG contract `SettingsViewModel.save()` documents. The grace-window field is the security-relevant one: a user who believes they set grace to `0` (re-authenticate every write) while the old, wider window persisted has a real, if narrow, security-expectation gap.

- **Design spec** `docs/superpowers/specs/2026-07-26-459-ios-settings-commit-at-save-design.md` (`b3ab72d`).
- **Implementation plan** `docs/superpowers/plans/2026-07-26-459-ios-settings-commit-at-save.md` (`a7a866e`).
- **The shared unit** (`55a8c36`, `73f8c4d`) — new `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/SettingsEditBuffer.swift`:
  - `SettingsEdits` — `Equatable, Sendable`, the two parsed but **un-clamped** `Int`s.
  - `SettingsEditBuffer` — `retentionText` / `graceText`, `init()` (empty), `seed(retentionDays:graceMinutes:)` (ungrouped digits only), `parsed() -> SettingsEdits?` (trim + plain `Int(_:)`; `nil` if **either** field fails).
  - `@MainActor commitSettingsEdits(_:into:) -> Bool` — parse → push through the VM's clamping setters → **re-seed the buffer from the clamped VM values** → `true`; `false` writing nothing if unparseable. All-or-nothing.
  - 17 new tests in `SettingsEditBufferTests.swift` (13 before the post-review parse fixes below).
- **Shared input-error copy** (`afd103f`) — `settingsInputErrorMessage()` added to `SettingsErrorMessage.swift` + 1 copy test, lifting the string macOS held inline so the platforms cannot drift.
- **macOS rewired** (`6afc442`) — `MacSettingsView` drops its view-local `commitEdits()` / `syncTextFromViewModel()`. Behaviour-preserving; done **before** the iOS fix on purpose, so a wrong shared unit would fail against a known-good baseline first.
- **The iOS fix** (`0331598`) — `@MainActor` on the struct (matching `MacSettingsView`; `save()` is a plain method calling the `@MainActor` helper), both computed `Binding<Int>`s deleted, both fields switched to `TextField(text: $edits.…)`, Save routed through a `save()` that refuses on bad input, `.onAppear` seeds the buffer, and the message area extracted into a `@ViewBuilder private var messages` carrying macOS's `inputError`-vs-banner precedence rule.
- **Review doc-fix** (`4c65bf1`) — `MacSettingsView`'s type doc still pointed at the deleted `commitEdits`.

### Why `SettingsViewModel` was NOT touched (the security core — verified, not assumed)

The user asked which approach was safest. The asset is `save()`'s ordering invariant: gate against the **current** (pre-save) grace window → re-read persisted settings → write → retarget the gate only on success. That is what stops a user at an unlocked-but-unattended session outside the grace window from widening their own window to self-authorize the widening.

Verified by reading `RetargetableReauthGate`: it holds its **own** window and `authorizeWrite` just delegates to an inner gate constructed with a fixed window — it never reads `viewModel.graceMinutes`. Therefore *when* an edited value is committed is security-neutral; only changing `save()` itself can weaken the invariant. Leaving `save()` byte-identical is a zero-regression-risk choice, and the commit runs **before** the gate, where it can only ever refuse (and avoids raising a Face ID prompt just to fail on garbage input).

The rejected alternative — moving the text buffers into the VM — would give thinner views and let the macOS banner-precedence workaround be deleted, but it introduces a new invariant ("every path that mutates `retentionDays`/`graceMinutes` must also re-seed the text buffer") whose violation is **the same stale-value bug class as #459, relocated into the security-ordered file**. Recorded in the spec's "Why not put the buffer in the view model".

### Post-review fixes (second pass on the open PR)

A `/review` pass over PR #468 surfaced four items; all were fixed in-branch rather than deferred.

- **Locale-digit input regression on iOS (the material one).** The retired `TextField(value:format:)` binding parsed through a locale-aware `FormatStyle`; `Int(_:)` is ASCII-only. iOS renders `.keyboardType(.numberPad)` in the **active keyboard's** numeral system, so an Arabic or Persian keyboard emits U+0660-0669 / U+06F0-06F9 — and since the number pad is the *only* input affordance for these fields on iOS, there is no ASCII digit to fall back to. The row would have been permanently un-saveable behind a message that gives no clue why. `parsed()` now folds decimal digits from any script to ASCII first. The fold is scoped to Unicode general category Nd (`numericType == .decimal`), so non-positional numerals stay refused rather than coerced — verified against the stdlib, not assumed: `Ⅷ` (U+2167) and `௰` (U+0BF0) are `.numeric` carrying numeric values **8.0** and **10.0**, so a `wholeNumberValue`-based fold would have silently turned them into digits (and the 10.0 would have overflowed the ASCII conversion — hence the explicit `(0...9)` range guard). Separators are untouched (U+066C has no numeric type), so grouped input stays a hard reject in every script.
- **`.whitespaces` excludes newlines.** A pasted `"45\n"` was refused on an invisible character; now `.whitespacesAndNewlines`. The existing trim test used `\t`, which *is* in `.whitespaces`, so it did not catch this.
- **macOS input-error `Text` had no `accessibilityIdentifier`** while the iOS one did. Both now carry `settings-input-error`, so #417 can assert once for both platforms.
- **`inputError` now cleared in `.onAppear`** on both screens. The fields are re-seeded from disk there, so a leftover refusal no longer describes anything on screen. Not reachable today (both screens get fresh `@State` on re-appearance) — done so the invariant holds without depending on that.

Two review items were judged **not** defects and deliberately left alone: the sub-frame placeholder flash before `.onAppear` seeds (cosmetic, macOS-shipped, and `.onAppear` fires inside the first render transaction), and the duplicated 4-line `save()` glue (see risks below).

Non-vacuity of the four new tests was proven, not assumed: pre-fix `Int(_:)` returns `nil` for all four folded inputs, and `.whitespaces`-trimming `"45\n"` returns `nil`.

## Acceptance (all run this session, all green)

```bash
cd ios/SecretaryVaultAccess && swift test     # 344 tests, 0 failures (326 baseline + 18 new)
bash ios/scripts/build-app.sh                 # ** BUILD SUCCEEDED **
bash ios/scripts/run-ios-tests.sh             # SecretaryKit 52/0; ** TEST SUCCEEDED **
bash ios/scripts/run-macos-tests.sh           # D.5.1 automated acceptance: PASS (SecretaryKit 52/0 + app compile)
```

`git diff --name-only main... | grep -E '^(core|ffi)/'` is **empty** — no Rust surface touched, so the Rust/clippy/conformance gates are not required. **Code review: two passes.** The first (inline, no subagents — agent dispatch was not authorized) found one doc issue, fixed in-branch (`4c65bf1`). The second, a `/review` pass over the open PR, found four; all fixed in-branch (see "Post-review fixes").

Three things checked that are **not** defects:
- `.onAppear` re-firing would re-seed and clobber in-progress typing — but the old code's `load()` reset the VM values identically, so this is not a regression. The related scenePhase VM-reconstruction issue is already tracked as **#224**.
- Signed input (`"-5"`) parses and is absorbed by the clamp. Unreachable on iOS (number pad has no sign key), reachable on macOS. Unchanged from shipped macOS behaviour; pinned by a test so the split of responsibility stays deliberate.
- Extracting `messages` nests two potential rows under one `Form` child rather than two. SwiftUI flattens this and the screen is render-untested (#417), so cosmetic risk only — flagged rather than churned.

**No README / ROADMAP change.** Verified against precedent rather than assumed: both docs track *slices* (D.5.1, D.5.4…), and the macOS analogue #458 appears only as the D.5.4 slice entry while #456 appears in neither. A per-bug entry would be inconsistent.

## (2) What's next

- **#459 on-device confirmation** — this slice was host-only by decision, so the issue closes on an *inferred* repro. **Acceptance:** install the fixed build on the iPhone, open Settings, type a new grace value, tap Save **without** dismissing the number pad, re-open Settings and confirm the typed value persisted; then clear a field, tap Save, and confirm the "Each field needs a whole number" refusal rather than a silent old-value write. Worth folding into the next on-device session rather than making its own trip.
  - **Run the repro INSIDE the grace window** (save once first, then immediately test), or the *old* build may not reproduce hole (a) and the test reads as a false "no bug". Raising the Face ID prompt dismisses the keyboard, which itself resigns first responder and flushes the old `value:format:` binding — so outside the window the stale value could get committed mid-`save()` by the prompt. That is not a fix, it is a race (see the authorize-then-substitute note on `commitSettingsEdits`); within the window there is no prompt and hence no flush.
  - **Also worth one pass with an Arabic or Persian keyboard active**, now that `parsed()` folds non-ASCII decimal digits — `.numberPad` renders in the active keyboard's numeral system, and that path is host-tested but never device-observed.
- **DRAFTED, NOT YET FILED — "CI never compiles the iOS app target".** Surfaced by the PR #468 review; needs the user's OK before `gh issue create` (per [[feedback_issue_filing_needs_explicit_ok]]).
  > **Title:** CI never compiles the iOS app target (`ios/SecretaryApp`)
  >
  > **Body:** `macos-host.yml` compiles `SecretaryMac.app` (step 4 of `run-macos-tests.sh`), and `test.yml`'s `ios-host` job runs `swift test` on the two FFI-free host packages. Nothing in CI builds `ios/SecretaryApp`. `ios/scripts/run-ios-tests.sh` step 5 does build it, but that script is not wired into any workflow — so every iOS-app-target source file (`SettingsScreen.swift`, `VaultBrowseScreen.swift`, …) is compile-gated only by a developer remembering to run `build-app.sh` locally. This is exactly the class of file most prone to breaking: [[project_secretary_ios_swiftui_typecheck_limit]] records that one extra modifier on `VaultBrowseScreen.body` trips "unable to type-check in reasonable time" (exit 65), which no host test can catch. #468 changed `SettingsScreen.swift` and relied entirely on a local build.
  >
  > **Options:** (a) add an iOS-app compile step to `macos-host.yml` (already path-gated on `ios/**`, already builds the xcframework — marginal cost is one more `xcodebuild build`, no simulator needed); (b) a separate path-gated workflow mirroring `macos-host.yml`; (c) accept and document.
  >
  > **Acceptance:** either CI fails on a deliberately-introduced compile error in `ios/SecretaryApp/Sources/`, or a recorded decision closing as wontfix.
- **#467** — no automated guard that a secret-bearing error can't reach the `.public` fold-site log. Decision issue with three options (injected `@MainActor` sink / sanitize-at-source marker protocol / accept-as-documented). **Acceptance:** either an automated check, or a recorded decision closing it as wontfix.
- **#417** — mobile Trash purge-notice render test; needs a UI-test target. Would also retire the "render-untested" caveat on both Settings screens, including the ~3 lines of view glue this slice deliberately left uncovered.
- **#447** — biometric unlock for Tauri desktop (decision issue; needs the ADR-0011 coexistence question first). A brainstorm, not a code slice.
- **#443 / #444** — Linux (fprintd/polkit) / Windows Hello presence providers; not testable on this macOS host.

## (3) Open decisions and risks

- **The #459 fix is not proven on hardware.** Deliberate (host-only decision). Hole (b), the cleared-field write, is provable by inspection; hole (a), the stale tap-Save, rests on documented SwiftUI first-responder behaviour and was never smoke-observed on iOS. If the on-device check ever shows tap-Save *did* flush, the fix is still correct — it closes hole (b) and converges the platforms — but the issue's framing would need a correction.
- **The view glue is still untested on both platforms** (~3 lines: `guard commitSettingsEdits(…) else { inputError = …; return }`). Deliberate, per the design's non-goals; blocked on #417. A shared `commitSettingsEditsOrError(_:into:) -> String?` would shrink this to ~1 line and make the refusal branch testable today; judged not worth rewriting both views plus the tests for two lines that #417 covers anyway.
- **`SettingsEditBuffer.parsed()` rejects GROUPED input on purpose, in every script** — `"3,650"` and `"٣٬٦٥٠"` are both hard rejects rather than silent coercion. Correct *today* because `seed` only emits ungrouped digits, but it becomes wrong the moment these fields are localized (**#433**). The doc comment says so. Note this is now only about **separators**: the digits themselves fold from any script (post-review fix below).
- **The iOS app target is not compiled by CI.** `macos-host.yml` compiles `SecretaryMac.app`; `test.yml`'s `ios-host` job runs only the two FFI-free host packages. Nothing in CI builds `ios/SecretaryApp` — `run-ios-tests.sh` step 5 does, but that script is not wired into any workflow. So `SettingsScreen.swift`, the file #459 exists to fix, is compile-gated only by a local `build-app.sh`. Pre-existing, not introduced here — **issue drafted in "(2) What's next" below, awaiting the user's OK to file.**
- **`clean_gone` skill has a broken grep** (see Session-start cleanup). It fails silently — reports success while deleting nothing.

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After the PR merges, drop the branch + worktree (squash-merge leaves it "not fully merged"):
#   git worktree remove .worktrees/459-ios-settings-commit-at-save && git branch -D feature/459-ios-settings-commit-at-save
git worktree list && git status -s

# If resuming THIS branch for fixups — bind histories FIRST (closes the add/add gap on the handoff doc):
#   cd .worktrees/459-ios-settings-commit-at-save && git fetch origin && git merge origin/main

# Gates (host suite is fast and needs NO xcframework; the app builds need one):
#   cd .worktrees/459-ios-settings-commit-at-save/ios/SecretaryVaultAccess && swift test     # 344
#   cd .worktrees/459-ios-settings-commit-at-save && bash ios/scripts/build-app.sh
#   cd .worktrees/459-ios-settings-commit-at-save && bash ios/scripts/run-ios-tests.sh
#   cd .worktrees/459-ios-settings-commit-at-save && bash ios/scripts/run-macos-tests.sh
```

**Cold-worktree note:** a fresh worktree has no `Secretary.xcframework`; the first app build cross-compiles the Rust staticlib for the Apple triples — multi-minute and silent. Warm it at the controller level with `bash ios/scripts/build-xcframework.sh` in the background before anything that needs it ([[project_secretary_ios_xcframework_build_watchdog]]). `swift test` in `SecretaryVaultAccess` needs none (FFI-free), so the inner loop stays fast.

**Bash cwd gotcha:** session cwd persists across foreground calls (a `cd` sticks), and a backgrounded script with no `cd` runs from wherever the last foreground `cd` left it — spell out `cd <worktree> && …` every time ([[feedback_bash_cwd_persists_verify_before_killing]]). Edit-tool paths must spell out `.worktrees/459-ios-settings-commit-at-save/…` or they hit MAIN ([[feedback_edit_tool_targets_main_not_worktree]]).

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; the symlink retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). The handoff rides inside the PR — do **not** sync to `main` during the pause window ([[feedback_next_session_main_authoritative]]). If resuming this branch for fixups, `git fetch origin && git merge origin/main` first (branch version wins on this doc) before editing.

## Closing inventory

- **State on close:** PR opening on `feature/459-ios-settings-commit-at-save` (worktree `.worktrees/459-ios-settings-commit-at-save`), shipping **#459**, reviewed twice, all findings fixed in-branch. Net: 1 new source file + 1 new test file + 1 shared copy function + both Settings views rewired — **65 lines deleted from the two views**. **No `core` / `ffi` / FFI-surface / on-disk-format change, and `SettingsViewModel.swift` untouched.**
- **Commits:** `b3ab72d` (spec) · `a7a866e` (plan) · `55a8c36` (buffer + tests) · `73f8c4d` (commit helper + tests) · `afd103f` (shared copy) · `6afc442` (macOS rewire) · `0331598` (**the iOS fix**) · `4c65bf1` (review doc-fix) · handoff.
- **Acceptance:** `swift test` **344/0** · `build-app.sh` **BUILD SUCCEEDED** · `run-ios-tests.sh` **SecretaryKit 52/0, TEST SUCCEEDED** · `run-macos-tests.sh` **D.5.1 acceptance PASS** · review **2 passes, 5 findings, all fixed**.
- **Pre-merge gates:** all cleared. **PR is ready to merge** (you merge). #459 should be closed by hand on merge, per the repo's "(#N)" ref convention.
- **Next:** #459 on-device confirm (fold into the next device session) · #467 (fold-site privacy guard decision) · #417 (render tests) · #447 (Tauri biometric decision) · #443/#444 (Linux/Windows presence).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-07-27-459-ios-settings-commit-at-save-shipped.md`.
