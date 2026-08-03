# NEXT_SESSION.md — #467 fail-closed `.public` log guard shipped

**Session date:** 2026-08-02, resuming from `main` @ `895313e` (PR #470 / **#469** merged during the pause window; the prior baton was fully consumed). Branch `feature/467-public-log-secret-free-guard`; worktree `.worktrees/467-public-log-secret-free-guard`.

Full brainstorm → spec → plan → inline execution → **two-agent adversarial review → fix round**, all this session. User decisions: pick **#467** from the prior baton's menu; close **#469**; scope the guard to **all nine `.public` sinks** (not just the one #467 names); mechanism = **rendering protocol with a defaulted requirement**; gate the **carried payload as well as the log line**; execute **inline**, holding subagents for a review pass at the end.

## Session-start cleanup

- `main` fetched, verified in sync at `895313e`; dropped the merged `.worktrees/469-ci-ios-app-compile-gate` worktree + `feature/469-ci-ios-app-compile-gate` branch.
- **#469 closed** with the merge SHA and the red-then-green evidence. Two unrelated `.claude/worktrees/` detached checkouts were left alone.
- `cargo audit` green on its last three scheduled runs → **#383 is not burning**, contrary to what its open state suggests.

## (1) What we shipped

**#467.** `SecretaryVaultAccessUI` logs folded errors at `privacy: .public`, which deliberately disables the unified log's redaction so a diagnostic survives into a sysdiagnose. That is sound only while no error reaching such a site carries a secret — and that was maintained by a **doc comment**. It is now structural and fail-closed.

Two findings reshaped the slice before a line was written:

- **The issue understates the surface.** It reads as if `DiagnosticLog.swift` were the only `.public` error sink. There are **eight more** (`BookmarkVaultLocationStore` ×2, `SecretaryApp` ×5, `MacUnlockView` ×1), none with the doc comment, pure formatter, or byte-exact test the fold seam has. A guard scoped to the issue's text would have hardened the best-protected site and left the eight bare ones alone.
- **`DeviceUnlockError` reaches a fold arm but lives outside the package.** `BiometricAuthorizer.authorize` throws it, `GraceWindowReauthGate` propagates it untyped — and it is declared in `SecretaryDeviceUnlock`, which `SecretaryVaultAccess` does not depend on. A closed type-switch inside the seam **structurally cannot** cover the reachable set. That, not preference, is why the allowlist is a protocol.

### The mechanism

- **`SecretFreeError`** — a *rendering* protocol, not a bare marker: `var diagnosticDescription: String` defaulted to `String(describing: self)`. Conforming a wholly-safe type is one line; a type safe in most cases and secret-bearing in one overrides and redacts at source. That second form is not decoration — it is used twice (see below).
- **`diagnosticDetail(_:)`** — the only sanctioned renderer, **default-deny**: an unconformed type is never described, degrading to `<undisclosed <Type> domain=… code=…>`. `userInfo` is never read.
- **`foldDiagnostic(_:)`** — applies the policy once per fold site: logs the gated detail *and returns it* for the typed error's payload. The 23 sites went from two lines to one.
- **`ios/scripts/check-public-log-hygiene.sh`** — three fail-closed rules + a two-sided `--self-test`, wired into `test.yml` on ubuntu (~1s, every PR).

### Commits

| SHA | What |
|---|---|
| `9882b37` | design spec |
| `10607bd` | implementation plan |
| `390ed3d` | `SecretFreeError` + `diagnosticDetail` + 5 in-package conformances |
| `b2f886d` | `foldDiagnostic` + all 23 fold sites |
| `2f3b705` | the 7 app-layer sites + `DeviceUnlockError` conformance |
| `897619a` | the hygiene guard + CI job |
| `1014e63` | CLAUDE.md (docs decision — see below) |
| `3327776` | **review round 1** — closed 4 holes |
| `cdfa3ca` | **review round 2** — closed 3 more |

### The review pass is the most important part of this session

Two read-only agents were dispatched after the code was "done": one adversarial ("break this"), one an independent re-audit of the reachable error set. **They found seven real defects in work that had already passed every gate.** Every finding was verified against the code before acting — several prior claims in the codebase turned out to be wrong, so nothing was taken on assertion.

**Round 1 (`3327776`):**

1. **The guard was a denylist and was bypassable eight ways** — including `privacy:.public` with no space, because `PUBLIC_RE` hard-coded exactly one. That is the *same construct as the self-test's own positive control*, differing only in whitespace. Default-allow was the wrong shape for the one component whose entire job is enforcement. Both rules were relabelled allowlists here; round 3 found rule 2 still was not one. The self-test now runs 19 positive and 7 negative controls.
2. **Laundering.** `diagnosticDetail` denies unreviewed **types**, not unreviewed **content**. Pre-rendering an unreviewed error into a `String` and stashing it in a **conformed** error's payload walked it straight through the gate. **Nine live sites.** Eight in `SecretaryKit` now call `diagnosticDetail`; the ninth is in `SecretaryDeviceUnlockUI`, which cannot reach it, so it applies default-deny locally (carries the type name, never the description).
3. **A decrypted record field name inside a conformed error.** `RecordEditViewModel` interpolates `f.name` into `VaultAccessError.invalidArgument`. It was kept out of the log only by catch-arm ordering — true at all 23 sites today, but **untested and unenforced**. Now redacted at source.
4. **A false claim in a security comment.** The script header justified its multi-line blind spot with "swift-format keeps them single-line". **There is no swift-format config and no formatter in CI anywhere in this repo** — the only file mentioning it was that comment.

**Round 2 (`cdfa3ca`):**

5. **The round-1 redaction was incomplete.** `.corruptVault` carries a Rust error string verbatim, and `RecordError::DuplicateKey` (`core/src/vault/record.rs:660`) formats the decrypted CBOR field-name into it. Same plaintext, one layer down.
6. **The `DeviceUnlockError` conformance comment overstated how bounded `.enclave` is** — 4 of its 12 construction sites carry `NSError.localizedDescription` from `default:` arms accepting any domain. Still secret-free; the claim was just wrong, and a wrong security comment is how the original invariant rotted.
7. **`UniffiInternalError` is the most-reachable type and is permanently unconformable** (`fileprivate` in the *generated* bindings). Default-deny handles it correctly, but a Rust panic therefore logs as an opaque marker — safe, and a diagnostic dead end for the failure mode most worth diagnosing.

The audit also *confirmed* two things and they were deliberately left alone: the `CocoaError`/`NSError` bridging comment is correct (verified by execution, including with the conformance declared), and 6 of 23 fold sites are statically unreachable with the production conformers.

**Round 3 (PR review of #471) — the guard was still bypassable five ways.**

Round 1 relabelled both rules "allowlists". Rule 1 was one; **rule 2 was not** — it matched one function name (`String(describing:`) applied to five hard-coded identifier names. A probe tree (synthetic repo, script copied in, one file per attack) confirmed the documented control fired while all five of these passed:

| Bypass | Now |
|---|---|
| `String(describing: caught)` — any other binding name | rule 2 |
| `error.localizedDescription` into a conformed payload | rule 2 |
| `String(reflecting: error)` | rule 2 |
| `"boom: \(error)"` bare interpolation | rule 3 (best effort) |
| two `.public` interpolations on one line, one gated one raw | rule 1 (counting) |

8. **Rule 2 is now construct-based and name-blind** — `String(describing:|String(reflecting:|.localizedDescription`, denied everywhere in scope, opened only by allowlist entry. Seven legitimate uses became recorded entries, including the four `.enclave(nsError.localizedDescription)` arms whose safety had been argued only in a doc comment. That comment's claim is now machine-visible: edit one of those lines and the guard fails until it is re-reviewed.
9. **Rule 1 counts per-interpolation, not per-line.** `n(privacy: .public) > n(diagnosticDetail()` fails. The old "does the line mention `diagnosticDetail` anywhere" form passed a line carrying one gated and one raw render.
10. **The allowlist matched a SUBSTRING, per file.** The entry for `BookmarkVaultLocationStore` (`location.displayName`) exempted *any* future `.public` line in that file mentioning it — proven by probe to include one rendering `err.localizedDescription` raw. Entries now match the **exact trimmed source line**; re-indentation survives, content edits do not. A control pair (A1 exact-match clean / A2 same-file-same-substring caught) pins it.
11. **Rule 3 is a denylist and says so.** Bare `"\(error)"` is `String(describing:)`, but `\(x)` is the most common construct in Swift — matching it wholesale is unusable, so rule 3 names conventional catch bindings. `catch let problem { "\(problem)" }` evades it. Labelled best-effort in the header rather than dressed up as coverage; rules 1 and 2 remain the load-bearing ones.

Rule 3 immediately caught a real site — `DeviceUnlockFailureDisplay.swift:33`, which renders a `VaultSlotError` into on-screen copy. It is **user-facing copy, not a log sink**, so it is carried as a reviewed rule-3 allowlist entry rather than silently excluded; it is a genuine #454 violation in a *package* (so `is_app_ui_path` never covered it) and is filed as **#473**.

## Acceptance (all run this session)

```bash
cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard
(cd ios/SecretaryVaultAccess && swift test)     # 356 tests, 0 failures (344 baseline + 12)
(cd ios/SecretaryDeviceUnlock && swift test)    # 47 tests, 0 failures
(cd ios/SecretaryKit && swift test)             # 54 tests, 0 failures (+2)
bash ios/scripts/build-app.sh                   # ** BUILD SUCCEEDED **
bash ios/scripts/build-macos-app.sh             # ** BUILD SUCCEEDED **
bash ios/scripts/check-public-log-hygiene.sh --self-test   # 19 positive / 7 negative controls
bash ios/scripts/check-public-log-hygiene.sh               # exit 0
shellcheck ios/scripts/check-public-log-hygiene.sh         # clean
actionlint .github/workflows/test.yml                      # clean
git diff main... --name-only -- core/ ffi/                 # EMPTY
```

**Mutation proof**, re-run after the hardening using the *no-space variant that defeated the original matcher*: reintroducing `String(describing: error)` at `MacUnlockView.swift:172` → **exit 1** naming that line; revert → **exit 0**. The self-test alone would not have been enough — it only exercises synthetic files.

**Docs decision, by precedent-grep rather than assumption.** #456/#466 (the seam this hardens) and #189's `check-lean-binding.sh` (the closest analogue guard) appear in **neither** README nor ROADMAP. #437/#469 did earn ROADMAP clauses, but those sit inside the *`macos-host.yml`* prose and this job is in `test.yml` — a clause there would attribute the guard to the wrong workflow. So: **README unchanged, ROADMAP unchanged**, and the guard documented in **CLAUDE.md** beside its analogue, plus an architecture note under "Workspace-wide invariants".

## (2) What's next

- ~~File the three drafted issues~~ **DONE** — filed as #472 / #473 / #474: **Android logs raw `Throwable`s to logcat** with no equivalent gate (`AppRoot.kt:438,572,582`, `CloudVaultOpen.kt:191,298,300`); **carried diagnostics rendered as on-screen copy**, contradicting #454 (6 sites — 5 in app targets plus `DeviceUnlockFailureDisplay.swift:33-34` in a *package*, which `is_app_ui_path` never covered and which rule 3 now surfaces as a reviewed allowlist entry); **`RecordError::DuplicateKey` embeds a decrypted field name** in its message (`core/src/vault/record.rs:661`) where `MnemonicError::UnknownWord` already shows the right pattern (index, not word). **FILED 2026-08-03:** **#472** (Android logcat gate), **#473** (carried diagnostics as on-screen copy), **#474** (`DuplicateKey` field name).
- **#459 on-device confirmation** — still outstanding, still why #459 is open. **Acceptance:** install on the iPhone, type a new grace value, tap Save **without** dismissing the number pad, re-open Settings, confirm it persisted; then clear a field, tap Save, confirm the "Each field needs a whole number" refusal rather than a silent old-value write. **Run the repro INSIDE the grace window** — outside it the Face ID prompt dismisses the keyboard, which itself resigns first responder and flushes the old binding, so the old build may not reproduce and the test reads as a false "no bug". Also worth one pass with an **Arabic or Persian keyboard**, since `.numberPad` renders in the active numeral system and the non-ASCII digit fold is host-tested but never device-observed.
- **#464** — CodeQL Swift analysis. #469 answered its "which targets under the tracer" question and proved the recipe under a pinned toolchain. Still needs the matrix-leg-vs-separate-workflow decision plus triage of the first Swift alert batch. **Acceptance:** `swift` appears in `gh api repos/:owner/:repo/code-scanning/analyses` after it lands on `main`, and the other five languages do not regress.
- **#417** — mobile Trash purge-notice render test; needs a UI-test target. **Acceptance:** a render assertion on the banner in both Compose and SwiftUI.
- **#447** — biometric unlock for Tauri desktop (decision issue; needs the ADR-0011 coexistence question first). A brainstorm, not a code slice.
- **#443 / #444** — Linux (fprintd/polkit) / Windows Hello presence providers; not testable on this macOS host.

## (3) Open decisions and risks

- **The guard is line-based.** A `privacy:` interpolation split across two source lines evades rule 1. Every current site is single-line, but **nothing enforces that** — this repo has no swift-format config and no formatter in CI. The script header states this plainly now; do not let a future reader re-derive the comfortable version.
- **Rule 2 excludes the SwiftUI app targets** (`is_app_ui_path`). Their `String(describing: error)` goes to on-screen `Text(…)`, not a log — a #454 problem tracked separately. **Stated limit:** laundering that happens *in* an app target and is later logged elsewhere is not caught. Closing it needs those five sites cleaned up first.
- **A missing future conformance is not a build error.** It degrades a log line silently. That is the safe direction by design, but it means "did anyone conform the new error type?" is answered by review, not by the compiler. The five in-package conformances and `DeviceUnlockError` are pinned by tests; a seventh would not be.
- **`.corruptVault` is now fully redacted**, which costs the whole detail string for *every* corruption diagnostic, not just the `DuplicateKey` case. That is the fail-closed side of the trade. Fixing `DuplicateKey` in the core (drafted issue 3) would let the redaction be narrowed again.
- **A Rust panic now logs as `<undisclosed UniffiInternalError domain=… code=0>`.** Correct and safe, but it is a diagnostic dead end precisely where diagnosis matters most. Recovering it means catching `UniffiInternalError` in the adapters and re-throwing a typed reviewed error — a separate change, not a conformance (the type is `fileprivate` in generated code and cannot be conformed at all).
- **The app-layer log text changed** from `.localizedDescription` to case-plus-associated-values at six sites. Better in a log, but anyone comparing against an existing sysdiagnose will see different strings.
- **Plan deviation, reversed.** The plan shipped the guard *without* the spec's allowlist file, on YAGNI grounds (it would have been empty). Making the rule fail-closed in review round 1 **reinstated the need for it** — there are two legitimate exceptions (the fold formatter, which is gated one level down; and the `displayName` line, which is not an error). The file exists and is referenced. YAGNI was right for a denylist and wrong for an allowlist.
- **Two review agents found seven defects in code that had already passed every gate.** Worth internalising: the gates prove the code does what it was written to do, not that what it was written to do is sufficient.

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After the PR merges, drop the branch + worktree (squash-merge leaves it "not fully merged"):
#   git worktree remove .worktrees/467-public-log-secret-free-guard && git branch -D feature/467-public-log-secret-free-guard
git worktree list && git status -s

# If resuming THIS branch for fixups — bind histories FIRST (closes the add/add gap on the handoff doc):
#   cd .worktrees/467-public-log-secret-free-guard && git fetch origin && git merge origin/main

# Gates for this slice (no Rust surface touched, so no cargo/clippy/conformance run needed):
#   cd .worktrees/467-public-log-secret-free-guard
#   (cd ios/SecretaryVaultAccess && swift test)   # fast: FFI-free, ~0.06s
#   bash ios/scripts/check-public-log-hygiene.sh --self-test && bash ios/scripts/check-public-log-hygiene.sh
#   shellcheck ios/scripts/check-public-log-hygiene.sh && actionlint .github/workflows/test.yml
#   bash ios/scripts/build-app.sh && bash ios/scripts/build-macos-app.sh   # only these compile the app targets
```

**Cold-worktree note:** a fresh worktree has **none** of the three gitignored build artifacts (`ios/Secretary.xcframework`, `ios/SecretaryKit/Sources/SecretaryKit/secretary.swift`, `ios/SecretaryKit/Tests/SecretaryKitTests/Resources/`). The first build cross-compiles the Rust staticlib for four Apple triples — multi-minute and silent. Warm it at the controller level with `bash ios/scripts/build-xcframework.sh` in the background before anything that needs it ([[project_secretary_ios_xcframework_build_watchdog]]). `swift test` in `SecretaryVaultAccess` and `SecretaryDeviceUnlock` needs none of them.

**Bash cwd gotcha, which fired twice this session:** the session cwd persists across foreground calls *and* is inherited by background ones. A `cd ios/SecretaryKit` earlier in the session silently made a later `bash ios/scripts/…` fail with "No such file or directory". **Spell out the absolute `cd` on every call** ([[feedback_bash_cwd_persists_verify_before_killing]]). Edit-tool paths must spell out `.worktrees/467-public-log-secret-free-guard/…` or they hit MAIN ([[feedback_edit_tool_targets_main_not_worktree]]).

**Commit-message gotcha:** backticks in a `git commit -m "…"` string get command-substituted by zsh — two words were swallowed from `cdfa3ca` before it was amended via `-F`. Use a heredoc'd file for any message containing backticks.

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; the symlink retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). The handoff rides inside the PR — do **not** sync to `main` during the pause window ([[feedback_next_session_main_authoritative]]). If resuming this branch for fixups, `git fetch origin && git merge origin/main` first (branch version wins on this doc) before editing.

## Closing inventory

- **State on close:** PR on `feature/467-public-log-secret-free-guard` (worktree `.worktrees/467-public-log-secret-free-guard`), shipping **#467**. Net: a new protocol + renderer in `SecretaryVaultAccess`, `foldDiagnostic` replacing `logFoldedError` across 23 sites, 7 app-layer sites gated, 9 laundering sites closed, 2 conformance redactions, a new fail-closed CI guard + allowlist, and docs. **No `core` / `ffi` / `.udl` / `FfiVaultError` / on-disk-format change** — `git diff main... -- core/ ffi/` is empty.
- **Commits:** `9882b37` (spec) · `10607bd` (plan) · `390ed3d` (policy) · `b2f886d` (fold sites) · `2f3b705` (app layer) · `897619a` (CI guard) · `1014e63` (CLAUDE.md) · `3327776` (**review round 1** — 4 holes) · `cdfa3ca` (**review round 2** — 3 more).
- **Acceptance:** 356 + 47 + 54 tests **0 failures** · both apps **BUILD SUCCEEDED** · guard self-test **19 positive / 7 negative** · **mutation red → revert green** using the variant that beat the original matcher · `shellcheck` + `actionlint` clean · Rust surface **untouched**.
- **Docs:** README unchanged, ROADMAP unchanged — both by precedent-grep (#456/#466 and #189 appear in neither). CLAUDE.md gained the command block + an architecture note.
- **Next:** #472 / #473 / #474 now open · #459 on-device confirm (INSIDE the grace window; Arabic/Persian keyboard pass) · #464 (CodeQL Swift) · #417 (render tests) · #447 (Tauri biometric decision) · #443/#444 (Linux/Windows presence).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-08-02-467-public-log-secret-free-guard-shipped.md`.
