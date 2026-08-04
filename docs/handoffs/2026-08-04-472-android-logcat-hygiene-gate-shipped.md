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
- **`android/scripts/check-log-hygiene.sh`** — five fail-closed rules, two-sided `--self-test` (27 positive / 14 negative), wired into `test.yml` on ubuntu (~1s, every PR).
- **`scripts/lib/hygiene-allowlist.sh`** — the exact-line matcher **and** `is_comment_line` extracted so **both** platform guards share one copy of each.

### PR-review fix round (#475)

The whole-branch review found four things, three of them the same shape: a hole closed on one side of a construct and left open on the other.

- **CRITICAL, the mirror of round 1's critical.** Round 1 fixed `is_comment_line` for lines that *open* a block comment and left the *closing* side untouched, so `*/ android.util.Log.w(TAG, "x", e)` — line 2 of a two-line `/*` … `*/` comment, i.e. real code — was still prose. Proven by execution: a file with that shape plus `e.toString()`, `e.message` and `println(e)` passed the whole guard with **exit 0**. The same hole was live in the **iOS** guard. `is_comment_line` now lives in the shared lib, fixed once, with positive controls on both platforms (`CM3`-`CM5`, `P19`/`P20`) — each mutation-proven by restoring the old matcher and watching exactly those fail.
- **Rule B2 was `\.`-anchored** after round 1 `\b`-anchored rule B1 for the identical reason. New **rule B3** covers the no-receiver form; it cannot simply relax B2's anchor because that matches every `override fun toString()` declaration, so B3 skips declaration lines and unconditional B2 keeps `override fun toString() = e.toString()` caught (control `B3c`). B3 fired on two real lines — both the *sanctioned self-render* itself — now a third allowlist section.
- **Rule A guarded `android.util.Log` only.** Android redirects stdout/stderr into logcat, so `println(e)` reached the log naming no `Log` symbol and evaded all four rules. Rule A widened; controls `A7`-`A9` each pin one alternative and trip no other rule (the obvious `System.out.println("x: " + e)` control would have been masked by rule C).
- **Three wrapper types were never conformed** — `CloudFolderException`, `VaultMirrorException`, `DeviceUuidException`. Not a leak: a **diagnostic regression**. Because every wrapper renders its cause through the default-denying `diagnosticDetail`, an unconformed type made each nested wrap discard the message it had just been built to carry. Measured: `list failed after 2 attempts: <undisclosed org.secretary.mirror.CloudFolderException>` where it used to say `quota exceeded on drive` — the entire cloud-sync failure path reduced to a type name, and `SafCloudFolderPort`'s own gating work discarded one frame later by the production wrapper. Every construction site of all three is a fixed Kotlin literal plus a path/filename/op-label or an already-gated render, so conforming them is free. Three new tests assert on message *content*; the pre-existing tests asserted only on exception *type*, which is why it shipped unnoticed.

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

- ~~File the follow-ups~~ **DONE — filed 2026-08-04 as #476 / #477.**
  - **#476** — Android sibling of #473: three sites render a carried diagnostic as on-screen copy (`CreateVaultWizardScreen.kt:81,:93`, `RecordEditForm.kt:62`). No leak — payloads are gated as of #472, so the worst case renders `<undisclosed …>` on screen. `CreateVaultWizardScreen.kt:63` is legitimate and must be left alone (`VaultNameError`'s `message` IS the friendly copy). **Acceptance:** the three render friendly copy, their allowlist entries are removed, and the guard still passes.
  - **#477** — retire the grep rules for a **type-aware detekt rule**. B1/B2/C all approximate "is this receiver a `Throwable`?", which grep structurally cannot answer. Would delete rule B2's four non-throwable allowlist entries, close rule C's name-based gap (`problem.toString()`), and likely close the `${e.detail}` limit. **Acceptance:** catches every `--self-test` positive control *including* the ones rule C cannot, the four entries are deleted, and `check-log-hygiene.sh` is removed in the same change or an explicit decision is recorded for why both remain.
- **#459 on-device confirmation** — still outstanding. **Acceptance:** install on the iPhone, type a new grace value, tap Save **without** dismissing the number pad, re-open Settings, confirm it persisted; then clear a field, tap Save, confirm the "Each field needs a whole number" refusal. **Run the repro INSIDE the grace window** — outside it the Face ID prompt dismisses the keyboard, which itself flushes the old binding and reads as a false "no bug". Also one pass with an **Arabic or Persian keyboard**.
- **#464** — CodeQL Swift analysis. #469 proved the recipe. **Acceptance:** `swift` appears in `gh api repos/:owner/:repo/code-scanning/analyses` after it lands on `main`, and the other five languages do not regress.
- **#417** — mobile Trash purge-notice render test. **Acceptance:** a render assertion on the banner in both Compose and SwiftUI.
- **#447** — biometric unlock for Tauri desktop (decision issue; needs the ADR-0011 coexistence question first).
- **#443 / #444** — Linux (fprintd/polkit) / Windows Hello presence providers; not testable on this macOS host.

## (3) Open decisions and risks

- **Rule C is best-effort and name-based, by necessity.** It matches bare `"$e"`/`"${e}"` and `+ e` concatenation for a fixed list of catch-binding names. `catch (problem: Exception) { "$problem" }` evades it. Rules A, B1, B2 and B3 are the load-bearing ones. Labelled as a denylist in the header rather than dressed up.
- **`VaultSyncError.Failed` is still content-traced, not structurally gated** — the one arm in either sealed type whose safety rests on having read the Rust rather than on construction. A Rust edit can invalidate it with **no Kotlin diff and no failing test on any platform**, which is the same drift class that made `SaveCryptoFailure` unsafe. Neither Kotlin-side "fix" is one: redacting it, or routing it through `diagnosticDetail` (`VaultException` is unconformed), destroys sync diagnostics wholesale without closing the drift — the exact trade #475 had to undo for `CloudFolderException`. The real fix is at the Rust/FFI boundary, out of this branch's scope. A pointer comment now sits on the pinning test; **the follow-up issue is drafted and awaiting an OK to file** (see the #475 fix-round summary in the PR).
- **Rule A now has no allowlist and a wider net.** `println` / `System.out.` / `System.err.` are absolute prohibitions like `android.util.Log`. There are zero such calls in `android/` today and test paths are excluded, so this costs nothing now — but a future legitimate use has no escape hatch by design, and the fix would be to route it through `SecretaryLog`, not to widen the rule.
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

**Acceptance, after the #475 fix round:** Android guard **27 positive / 14 negative**, real run exit 0 · iOS guard **21 / 9** (was 19/7 — the two extra pairs pin the shared `is_comment_line` fix on the iOS side), exit 0 · `actionlint` clean · `shellcheck` clean at warning+ · `:vault-access:test` + `:kit:testDebugUnitTest` **508 tests, 0 failures** · `:app:assembleDebug` **BUILD SUCCESSFUL** · `git diff main... -- core/ ffi/` **EMPTY**.

Mutation-proven in the fix round, each individually: restoring the old `is_comment_line` fails exactly `CM3`-`CM5` and `P19`/`P20`; reverting rule A's widening fails `A7`; dropping rule B3 fails `B3a`/`B3b` while `B3c` stays caught by B2; un-conforming each of the three wrapper types fails its own test. The first pass at the `VaultMirrorException` test was **vacuous** — it asserted on `message`, which already carried the reason via the conformed inner `CloudFolderException`, and only the mutation run exposed it. It now also asserts on `diagnosticDetail` of the outer type, which is the render `SecretaryLog.warn` actually performs.

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; the symlink retargeted in the same commit on the feature branch (new path → no add/add conflict). The handoff rides inside the PR — do **not** sync to `main` during the pause window. If resuming this branch for fixups, `git fetch origin && git merge origin/main` first (branch version wins on this doc) before editing.

## Closing inventory

- **State on close:** PR on `feature/472-android-log-hygiene-gate`, shipping **#472**. Net: a new policy + renderer in `:vault-access`, five conformances with three redactions, `SecretaryLog` as the sole logcat sink, 18 laundering sites resolved, a new fail-closed CI guard, a shared allowlist library now used by **both** platform guards, 5 new mutation-proven regression tests, and docs. **No `core` / `ffi` / `.udl` / `FfiVaultError` / on-disk-format change.**
- **Docs:** README and ROADMAP unchanged — by precedent-grep (#467/#456 and #189's `check-lean-binding.sh` appear in neither). CLAUDE.md gained the command pair + an architecture section.
- **Next:** **#476** / **#477** now open · #459 on-device confirm · #464 · #417 · #447 · #443/#444.
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-08-04-472-android-logcat-hygiene-gate-shipped.md`.
