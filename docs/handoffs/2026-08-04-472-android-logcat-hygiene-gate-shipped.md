# NEXT_SESSION.md — #472 Android logcat hygiene gate shipped

**Session date:** 2026-08-04, resuming from `main` @ `f3be011` (PR #471 / **#467** merged during the pause window). Branch `feature/472-android-log-hygiene-gate`; worktree `.worktrees/472-android-log-hygiene-gate`.

Full brainstorm → spec → plan → **subagent-driven execution with a review after every task** → final whole-branch review → fix wave. User decisions: pick **#472** from the prior baton's menu; full port (sink gate **and** laundering rule); type-name + cause-chain deny rendering; no UI path exclusion; sanctioned-wrapper sink; defer #474; reduce rule B2 friction three ways; **extract** the shared allowlist matcher rather than duplicate it; findings govern over plan text on the guard bypasses.

## Session-start cleanup

- `main` fetched, verified at `f3be011`; dropped the merged `.worktrees/467-public-log-secret-free-guard` worktree + branch.
- **#467 closed** with the merge SHA and the widened-scope evidence. Two unrelated `.claude/worktrees/` detached checkouts left alone.
- Verified the #472 sites were real before starting: 6 raw-`Throwable` `Log.w` calls plus one `Log.i`, all in `:app`.

## (1) What we shipped

**#472.** Android's logcat has **no redaction concept** — no `privacy:` qualifier to opt into, every line readable via `adb logcat` on a debuggable build and captured into bug reports. Six sites passed a raw `Throwable` to `Log.w(tag, msg, t)`, which prints `toString()` — class name **plus message** — for the throwable and every cause. That is now structurally impossible.

Three facts reshaped the slice before code was written, none of which the issue mentions:

- **There is no marker to key on.** iOS rule 1 counts `privacy: .public` interpolations; Android has no such token, so the **sink itself** is what gets guarded.
- **The laundering surface was already live, and larger** — 18 sites, not the handful implied. `BrowseMapping.kt`'s `else` fold is the designated carrier of every Rust `Display` string the explicit arms don't name.
- **Kotlin has no retroactive conformance.** `extension DeviceUnlockError: @retroactive SecretFreeError {}` has no Kotlin equivalent, so JDK / Android-framework / uniffi throwables can *never* implement the interface — and those are exactly what arrives at a `catch (e: Exception)`. **The deny path is the normal path here**, which is why `diagnosticDetail` renders the cause chain as fully-qualified type names (compile-time constants, so provably data-free).

### The exposure was live, and traced end to end

`RecordError::DuplicateKey { key }` (`core/src/vault/record.rs:660`, `key` = decrypted CBOR field name) → `VaultError::Record(_)` → `FfiVaultError::SaveCryptoFailure { detail: format!("{e}") }` (`ffi/.../retention/orchestration.rs:205` + five siblings) → `BrowseMapping.kt:27` → `catch (e: Exception)` → logcat.

### The mechanism

- **`SecretFreeThrowable`** + **`diagnosticDetail`** in the pure-JVM `:vault-access` — default-deny, cause chain as type names.
- **`SecretaryLog`** in `:kit` — the only file permitted to reference `android.util.Log`, with **no overload that hands a `Throwable` to it**, so the stack-trace form is unrepresentable at call sites.
- **18 laundering sites** cleaned: 14 gated, 4 recorded as reviewed allowlist entries (on-screen copy).
- **`android/scripts/check-log-hygiene.sh`** — four fail-closed rules, two-sided `--self-test` (18 positive / 11 negative), wired into `test.yml` on ubuntu (~1s, every PR).
- **`scripts/lib/hygiene-allowlist.sh`** — the exact-line matcher extracted so **both** platform guards share one copy.

### Commits

| SHA | What |
|---|---|
| `4a9c214` `7a43531` `b9186d9` | design spec, B2 friction reduction, payload-origin audit |
| `6945475` `fd3e8e1` `cfe47c8` | implementation plan + two corrections to it |
| `c072272` | the policy (`SecretFreeThrowable` + `diagnosticDetail`) |
| `90d93f5` | five conformances + **three** redactions + the audit doc comment |
| `e8fae04` | **extract** the shared exact-line allowlist matcher |
| `cbb5525` `9df70df` | the guard, landed RED; then three regex bypasses closed |
| `e450011` `a1ca709` | `:vault-access` cleanup + 3 mutation-proven regression tests |
| `2493671` `825c3a7` | `:kit` cleanup + audit-claim correction + 2 more tests |
| `ed54371` | `SecretaryLog` + 7 call sites + hex dedupe — **guard GREEN** |
| `5fdb9b6` | CI job |
| `1a5263e` `7f9e161` | CLAUDE.md; fabricated-citation + rule-A fixes |
| `c69efd4` `4f1fc4e` | final-review fix wave; producer-audit correction |

### The reviews are the story of this session

Every task got a fresh implementer and an independent reviewer. **Four fix rounds plus a final fix wave.** The reviewers verified by *execution* — mutating real source and watching the right thing fail — not by reading.

**The audit found a third redaction before implementation started.** `VaultBrowseError.SaveCryptoFailure` carries the same decrypted field name as `CorruptVault`. A port of iOS's redaction list would have missed it: iOS has no `.saveCryptoFailure` case, so the arm falls to `VaultErrorMapping.swift:53`'s already-gated `default -> .other(diagnosticDetail(e))`, while Android's `BrowseMapping.kt:27` maps it **explicitly** and carried the raw detail. The divergence is in the mapper, not the policy — recorded in CLAUDE.md with a *do not align the platforms by deleting this* note.

**The guard was bypassable four ways, and three were my error.** The plan's own `is_comment_line()` regex skipped any line starting with `/*` without requiring the comment to close, so `/* */ Log.w(TAG, x.toString())` — a complete no-op comment plus real code — defeated **all four rules**. Rule A's `[a-z]+` missed `Log.getStackTraceString`; rule B1's leading dot missed no-receiver calls. The final review then found a fourth: `"str" + e` concatenation, which Kotlin resolves to `toString()`, bypassing `diagnosticDescription` entirely — no iOS analogue, since Swift's `+` won't concatenate an `Error`.

**Four of six findings were about claims, not code.** The `CocoaError` citation in CLAUDE.md was fabricated — no such conformance exists, and Swift 6 requires `@retroactive`. `VaultSyncError.Failed`'s "gated at construction" was false for one producer (safe by *traced content*, a different reason). The `Failed` producer count was corrected twice before it was right — nine sites in three categories, not eight in two. **That is the same failure #467 replaced**: a doc-comment convention that had quietly stopped holding.

**Two gating fixes shipped untested until a reviewer mutation-proved they were.** Reverting a gated site left the whole suite green. Five regression tests were added and each was individually mutation-proven.

## (2) What's next

- **File the follow-ups** (drafted, awaiting your OK — see §3).
- **#459 on-device confirmation** — still outstanding. **Acceptance:** install on the iPhone, type a new grace value, tap Save **without** dismissing the number pad, re-open Settings, confirm it persisted; then clear a field, tap Save, confirm the "Each field needs a whole number" refusal. **Run the repro INSIDE the grace window** — outside it the Face ID prompt dismisses the keyboard, which itself flushes the old binding and reads as a false "no bug". Also one pass with an **Arabic or Persian keyboard**.
- **#464** — CodeQL Swift analysis. #469 proved the recipe. **Acceptance:** `swift` appears in `gh api repos/:owner/:repo/code-scanning/analyses` after it lands on `main`, and the other five languages do not regress.
- **#417** — mobile Trash purge-notice render test. **Acceptance:** a render assertion on the banner in both Compose and SwiftUI.
- **#447** — biometric unlock for Tauri desktop (decision issue; needs the ADR-0011 coexistence question first).
- **#443 / #444** — Linux (fprintd/polkit) / Windows Hello presence providers; not testable on this macOS host.

## (3) Open decisions and risks

- **Rule C is best-effort and name-based, by necessity.** It matches bare `"$e"`/`"${e}"` and `+ e` concatenation for a fixed list of catch-binding names. `catch (problem: Exception) { "$problem" }` evades it. Rules A, B1 and B2 are the load-bearing ones. Labelled as a denylist in the header rather than dressed up.
- **`${e.detail}` passed to `SecretaryLog` evades all four rules.** Deliberate: matching typed-field renders would fire on seven legitimate on-screen copy sites and drown the rule. But `.detail` on the three redacted arms is exactly the payload the redaction removes — direct field access walks around `diagnosticDescription`. **Stated in the script's LIMITS block**, not hidden.
- **The payload-origin audit is a point-in-time claim, and it already caught one.** An arm's payload can change from a Rust edit with **no Kotlin diff at all** — which is exactly how `SaveCryptoFailure` came to carry plaintext. Adding an arm to a Rust umbrella fold is invisible to every gate in this design.
- **A missing future conformance is not a build error.** It degrades a log line to `<undisclosed …>`. Safe by design, but "did anyone declare the new error type?" is answered by review, not the compiler.
- **Converted sites lost their stack traces.** A developer now gets the call-site message, the exception class, and the cause chain — but not the throw site or line. Real diagnostic cost, named in `SecretaryLog`'s doc comment.
- **The shared library is not a silent single point of failure** — verified: `set -euo pipefail` makes a failed `source` fatal *before* any scan, so a missing lib kills both guards loudly rather than passing vacuously.
- **`:app:assembleDebug` takes ~10 minutes** here (cargo-ndk cross-compiles the Rust staticlib for four Android ABIs). Two agents stalled on it. Use `:vault-access:test` + `compileDebugKotlin` on the consumers for iteration; save the full assemble for acceptance.
- **The session cwd drifted to the main checkout twice.** Tooling failed loudly both times and `main` stayed clean at `f3be011`, but one ROADMAP/README precedent-grep silently ran against `android/README.md` and produced a wrong answer until re-run. **Use an absolute `cd` in every call.**

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After the PR merges (squash-merge leaves the branch "not fully merged"):
#   git worktree remove .worktrees/472-android-log-hygiene-gate && git branch -D feature/472-android-log-hygiene-gate
git worktree list && git status -s

# Gates for this slice (no Rust surface touched, so no cargo/clippy/conformance run needed):
#   cd /Users/hherb/src/secretary/.worktrees/472-android-log-hygiene-gate
#   bash android/scripts/check-log-hygiene.sh --self-test && bash android/scripts/check-log-hygiene.sh
#   bash ios/scripts/check-public-log-hygiene.sh --self-test && bash ios/scripts/check-public-log-hygiene.sh
#   shellcheck --severity=warning android/scripts/check-log-hygiene.sh ios/scripts/check-public-log-hygiene.sh scripts/lib/hygiene-allowlist.sh
#   actionlint .github/workflows/test.yml
#   (cd android && ./gradlew :vault-access:test :kit:testDebugUnitTest)   # fast
#   (cd android && ./gradlew :app:assembleDebug)                          # ~10 min, cargo-ndk
```

**Acceptance, all run this session:** Android guard **18 positive / 11 negative**, real run exit 0 · iOS guard **19 / 7 unchanged**, exit 0 · `actionlint` clean · `shellcheck` clean at warning+ · `:vault-access:test` + `:kit:testDebugUnitTest` **503 tests, 0 failures** · `:app:assembleDebug` **BUILD SUCCESSFUL** · `git diff main... -- core/ ffi/` **EMPTY**.

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; the symlink retargeted in the same commit on the feature branch (new path → no add/add conflict). The handoff rides inside the PR — do **not** sync to `main` during the pause window. If resuming this branch for fixups, `git fetch origin && git merge origin/main` first (branch version wins on this doc) before editing.

## Closing inventory

- **State on close:** PR on `feature/472-android-log-hygiene-gate`, shipping **#472**. Net: a new policy + renderer in `:vault-access`, five conformances with three redactions, `SecretaryLog` as the sole logcat sink, 18 laundering sites resolved, a new fail-closed CI guard, a shared allowlist library now used by **both** platform guards, 5 new mutation-proven regression tests, and docs. **No `core` / `ffi` / `.udl` / `FfiVaultError` / on-disk-format change.**
- **Docs:** README and ROADMAP unchanged — by precedent-grep (#467/#456 and #189's `check-lean-binding.sh` appear in neither). CLAUDE.md gained the command pair + an architecture section.
- **Next:** follow-ups to file · #459 on-device confirm · #464 · #417 · #447 · #443/#444.
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-08-04-472-android-logcat-hygiene-gate-shipped.md`.
