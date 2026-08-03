# #472 Android logcat hygiene gate — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make it structurally impossible for a raw `Throwable` to reach logcat on Android, closing the live path by which a decrypted CBOR field name is printed today.

**Architecture:** A default-deny rendering policy (`SecretFreeThrowable` + `diagnosticDetail`) in the pure-JVM `:vault-access` module; a single sanctioned sink (`SecretaryLog` in `:kit`) that is the only file permitted to touch `android.util.Log`, with no overload that hands a `Throwable` to it; cleanup of the 18 sites that pre-render a throwable into a `String`; and a fail-closed grep guard wired into CI.

**Tech Stack:** Kotlin (JVM 21 toolchain for `:vault-access`, AGP for `:kit`/`:app`/`:browse-ui`/`:sync-ui`), JUnit 5, Bash + grep, GitHub Actions.

**Spec:** [docs/superpowers/specs/2026-08-03-472-android-log-hygiene-gate-design.md](../specs/2026-08-03-472-android-log-hygiene-gate-design.md) — read it before Task 1. Approved.

## Global Constraints

- **Worktree:** all work happens in `/Users/hherb/src/secretary/.worktrees/472-android-log-hygiene-gate` on branch `feature/472-android-log-hygiene-gate`. Spell out absolute paths in every `cd`; the Bash cwd persists between calls and Edit-tool paths otherwise hit the main checkout.
- **No Rust, FFI, `.udl`, `FfiVaultError`, or on-disk-format change.** `git diff main... --name-only -- core/ ffi/` must stay EMPTY. If a task seems to need one, stop and re-read the spec's Non-goals.
- **New package for the policy:** `org.secretary.diagnostics`, in both `:vault-access` and `:kit`. Matches the existing `org.secretary.{browse,sync,mirror}` convention.
- **Kotlin conformance is in-class.** There is no retroactive/extension conformance — every `implements SecretFreeThrowable` goes in the class declaration itself, and overrides go in the class body.
- **A new arm on a `:vault-access` sealed type breaks exhaustive `when`s in downstream modules that Gradle will not surface unless they are built.** Build `:app` in the same task as any sealed-type change.
- **Test style:** JUnit 5 — `org.junit.jupiter.api.Test`, backtick-quoted test names, `org.junit.jupiter.api.Assertions.assertX` imported individually. Match `vault-access/src/test/kotlin/org/secretary/browse/BlockNamePolicyTest.kt`.
- **Commit messages containing backticks must be passed via `git commit -F <file>`,** never `-m "…"` — zsh command-substitutes backticks inside double quotes and silently swallows words.
- **Sealed-type redaction rule:** an arm whose payload origin cannot be established is redacted, not assumed safe. The completed audit is in the spec; do not re-derive it, but do not extend a `render` verdict to a new arm without doing the same tracing.
- **The iOS guard is a shipped security control.** Task 3 modifies `ios/scripts/check-public-log-hygiene.sh` to source the extracted library. Its `--self-test` must keep reporting **exactly** `19 positive controls caught, 7 negative controls clean`, and its real run must stay green. A changed count means behaviour changed — fix the extraction, never update the expectation.

---

## File Structure

| File | Module | Responsibility |
|---|---|---|
| `vault-access/…/diagnostics/SecretFreeThrowable.kt` | `:vault-access` | The interface + `diagnosticDetail` + cause-chain rendering. Pure, no Android deps. |
| `vault-access/…/diagnostics/SecretFreeThrowableTest.kt` | `:vault-access` | Policy tests (default-deny, chain, cap, cycle). |
| `vault-access/…/browse/SecretFreeConformanceTest.kt` | `:vault-access` | Redaction tests + `message`-intact test. |
| `kit/…/diagnostics/SecretaryLog.kt` | `:kit` | The ONLY file referencing `android.util.Log`. |
| `scripts/lib/hygiene-allowlist.sh` | — | `trim` + `allowlisted` + self-test temp-dir helpers. Sourced by BOTH platform guards; one copy of the security-critical exact-line matcher. |
| `android/scripts/check-log-hygiene.sh` | — | Rules A / B1 / B2 / C + `--self-test`. |
| `android/scripts/log-hygiene-allowlist.txt` | — | Two sections: security decisions, non-throwable receivers. |
| `.github/workflows/test.yml` | — | New `kotlin-log-hygiene` job. |
| `CLAUDE.md` | — | Architecture note beside the #467 section. |

Modified: `ios/scripts/check-public-log-hygiene.sh` (sources the extracted lib), the five sealed error types, 14 laundering sites, 7 log call sites, `HexFormat.kt`, `ProvisioningRouting.kt`.

---

## Task 1: The rendering policy

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/diagnostics/SecretFreeThrowable.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/diagnostics/SecretFreeThrowableTest.kt`

**Interfaces:**
- Consumes: nothing.
- Produces: `interface SecretFreeThrowable { val diagnosticDescription: String }` and `fun diagnosticDetail(error: Throwable): String`, both in package `org.secretary.diagnostics`. Every later task calls `diagnosticDetail`.

- [ ] **Step 1: Write the failing test**

Create `android/vault-access/src/test/kotlin/org/secretary/diagnostics/SecretFreeThrowableTest.kt`:

```kotlin
package org.secretary.diagnostics

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** A sentinel that must never survive into a rendered diagnostic. */
private const val SECRET = "s3cr3t-field-name"

private class UnreviewedError(message: String) : Exception(message)

private class ReviewedError(val detail: String) : Exception(detail), SecretFreeThrowable {
    override fun toString() = "ReviewedError(detail=$detail)"
}

private class RedactingError(val detail: String) : Exception(detail), SecretFreeThrowable {
    override val diagnosticDescription: String get() = "RedactingError(<redacted>)"
}

class SecretFreeThrowableTest {
    @Test
    fun `an unconformed type is never described`() {
        val rendered = diagnosticDetail(UnreviewedError("boom: $SECRET"))
        assertFalse(rendered.contains(SECRET), "leaked the message: $rendered")
        assertTrue(rendered.contains("UnreviewedError"), rendered)
        assertTrue(rendered.startsWith("<undisclosed "), rendered)
    }

    @Test
    fun `a conformed type takes the default rendering, payload included`() {
        assertEquals("ReviewedError(detail=visible)", diagnosticDetail(ReviewedError("visible")))
    }

    @Test
    fun `a conformed type may redact at source`() {
        val rendered = diagnosticDetail(RedactingError(SECRET))
        assertFalse(rendered.contains(SECRET), rendered)
        assertEquals("RedactingError(<redacted>)", rendered)
    }

    @Test
    fun `the cause chain renders as type names, in order`() {
        val root = UnreviewedError("root: $SECRET")
        val mid = Exception("mid: $SECRET", root)
        val top = ReviewedError("visible").initCauseTo(mid)
        val rendered = diagnosticDetail(top)
        assertFalse(rendered.contains(SECRET), "leaked a cause message: $rendered")
        assertEquals(
            "ReviewedError(detail=visible) <- java.lang.Exception " +
                "<- org.secretary.diagnostics.UnreviewedError",
            rendered,
        )
    }

    @Test
    fun `a throwable with no cause renders no arrow`() {
        assertFalse(diagnosticDetail(ReviewedError("x")).contains("<-"))
    }

    @Test
    fun `the chain is depth-capped`() {
        var t: Throwable = Exception("leaf")
        repeat(20) { t = Exception("link", t) }
        val rendered = diagnosticDetail(t)
        assertTrue(rendered.contains("<truncated>"), rendered)
        assertEquals(MAX_CAUSE_DEPTH, rendered.split(" <- ").size - 2, rendered)
    }

    @Test
    fun `a cause cycle terminates`() {
        val a = Exception("a")
        val b = Exception("b", a)
        a.initCause(b)
        val rendered = diagnosticDetail(a)
        assertTrue(rendered.contains("<cycle>"), rendered)
    }
}

/** Test helper: `initCause` returns Throwable, so this keeps the concrete type. */
private fun <T : Throwable> T.initCauseTo(cause: Throwable): T = apply { initCause(cause) }
```

Note the `a cause cycle terminates` test constructs `a -> b -> a`. `Throwable.initCause` rejects self-causation but permits a two-node cycle, which is why the identity guard is needed.

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /Users/hherb/src/secretary/.worktrees/472-android-log-hygiene-gate/android && ./gradlew :vault-access:test --tests '*SecretFreeThrowableTest*'
```

Expected: FAIL — compilation error, `Unresolved reference: SecretFreeThrowable`.

- [ ] **Step 3: Write the implementation**

Create `android/vault-access/src/main/kotlin/org/secretary/diagnostics/SecretFreeThrowable.kt`:

```kotlin
package org.secretary.diagnostics

import java.util.Collections
import java.util.IdentityHashMap

/**
 * Upper bound on cause-chain links rendered by [diagnosticDetail]. A deep chain is
 * a log-volume problem, not a safety one — the guard below is the identity set.
 */
const val MAX_CAUSE_DEPTH: Int = 8

/**
 * A claim, made at the declaration site, that this throwable's diagnostic text
 * carries NO secret — no vault plaintext, password, mnemonic, or key bytes — and
 * is therefore safe to write to logcat (#472).
 *
 * logcat has no redaction concept: every line is readable via `adb logcat` on a
 * debuggable build and is captured into bug reports. Implementing this interface
 * is a SECURITY DECISION, reviewed like any other. Two forms:
 *
 *     // wholly secret-free — take the default rendering
 *     sealed class VaultNameError(...) : Exception(...), SecretFreeThrowable
 *
 *     // secret-free EXCEPT one arm — redact AT SOURCE
 *     override val diagnosticDescription: String get() = when (this) {
 *         is CorruptVault -> "CorruptVault(<redacted>)"
 *         else            -> toString()
 *     }
 *
 * The second form is what makes this a RENDERING interface rather than a bare
 * marker: a type safe in nine arms and secret-bearing in one keeps the nine.
 *
 * Kotlin has no retroactive conformance, so JDK, Android-framework and
 * uniffi-generated throwables can NEVER implement this. That is not a gap —
 * [diagnosticDetail] default-denies, so those render as an opaque marker.
 */
interface SecretFreeThrowable {
    /** Default: the full description, associated values included. */
    val diagnosticDescription: String
        get() = toString()
}

/**
 * Render [error] for logcat. This is the ONLY sanctioned way to do so — enforced
 * by `android/scripts/check-log-hygiene.sh`.
 *
 * DEFAULT-DENY: a type that has not been reviewed and declared
 * [SecretFreeThrowable] is never described. It degrades to a marker naming the
 * type — enough to tell a developer exactly which type to review.
 *
 * The cause chain is appended as fully-qualified TYPE NAMES for conformed and
 * unconformed alike. A class name is a compile-time constant in the binary and
 * cannot carry runtime data, so this is exactly as fail-closed as a bare marker.
 * It is appended for conformed types too because `Throwable.toString()` omits
 * the cause — without it, a conformed wrapper silently discards everything
 * beneath it, which on Android is often the only thing distinguishing one
 * failure from another.
 */
fun diagnosticDetail(error: Throwable): String {
    val head = if (error is SecretFreeThrowable) {
        error.diagnosticDescription
    } else {
        "<undisclosed ${error.javaClass.name}>"
    }
    val chain = causeChain(error)
    return if (chain.isEmpty()) head else head + chain.joinToString("") { " <- $it" }
}

/**
 * Fully-qualified type names of [error]'s causes, outermost first. Identity-set
 * guarded: `Throwable.initCause` rejects self-causation but a two-node cycle
 * (a.cause = b, b.cause = a) is constructible and would otherwise spin forever.
 */
private fun causeChain(error: Throwable): List<String> {
    val names = mutableListOf<String>()
    val seen = Collections.newSetFromMap(IdentityHashMap<Throwable, Boolean>())
    seen.add(error)
    var current = error.cause
    while (current != null) {
        if (!seen.add(current)) {
            names.add("<cycle>")
            return names
        }
        if (names.size == MAX_CAUSE_DEPTH) {
            names.add("<truncated>")
            return names
        }
        names.add(current.javaClass.name)
        current = current.cause
    }
    return names
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd /Users/hherb/src/secretary/.worktrees/472-android-log-hygiene-gate/android && ./gradlew :vault-access:test --tests '*SecretFreeThrowableTest*'
```

Expected: PASS, 7 tests.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/472-android-log-hygiene-gate
git add android/vault-access/src/main/kotlin/org/secretary/diagnostics/ android/vault-access/src/test/kotlin/org/secretary/diagnostics/
git commit -F - <<'EOF'
feat(#472): default-deny throwable rendering for logcat

SecretFreeThrowable + diagnosticDetail in the pure-JVM :vault-access module.
An unreviewed type is never described; the cause chain is appended as
fully-qualified type names, which are compile-time constants and so cannot
carry runtime data.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 2: Conformances and the three redactions

**Files:**
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseError.kt`
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/DeviceUnlockError.kt`
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultProvisioningError.kt`
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultName.kt`
- Modify: `android/vault-access/src/main/kotlin/org/secretary/sync/VaultSyncError.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/SecretFreeConformanceTest.kt`

**Interfaces:**
- Consumes: `SecretFreeThrowable`, `diagnosticDetail` from Task 1.
- Produces: the five sealed types now satisfy `is SecretFreeThrowable`. `VaultBrowseError.diagnosticDescription` redacts `CorruptVault`, `InvalidArgument`, `SaveCryptoFailure`.

- [ ] **Step 1: Write the failing test**

Create `android/vault-access/src/test/kotlin/org/secretary/browse/SecretFreeConformanceTest.kt`:

```kotlin
package org.secretary.browse

import org.secretary.diagnostics.SecretFreeThrowable
import org.secretary.diagnostics.diagnosticDetail
import org.secretary.sync.VaultSyncError
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** Stands in for a decrypted record field name or a Rust-authored detail string. */
private const val SECRET = "s3cr3t-field-name"

class SecretFreeConformanceTest {
    @Test
    fun `all five error families are declared secret-free`() {
        assertTrue(VaultBrowseError.VaultMismatch is SecretFreeThrowable)
        assertTrue(VaultSyncError.InProgress is SecretFreeThrowable)
        assertTrue(DeviceUnlockError.NotEnrolled is SecretFreeThrowable)
        assertTrue(VaultProvisioningError.FolderNotEmpty is SecretFreeThrowable)
        assertTrue(VaultNameError.Blank is SecretFreeThrowable)
    }

    @Test
    fun `CorruptVault is redacted - it carries a Rust-authored string`() {
        val rendered = diagnosticDetail(VaultBrowseError.CorruptVault("duplicate map key: $SECRET"))
        assertFalse(rendered.contains(SECRET), rendered)
        assertEquals("CorruptVault(<redacted>)", rendered)
    }

    @Test
    fun `SaveCryptoFailure is redacted - same Rust fold as CorruptVault`() {
        val rendered = diagnosticDetail(
            VaultBrowseError.SaveCryptoFailure("record CBOR error: duplicate map key: $SECRET"),
        )
        assertFalse(rendered.contains(SECRET), rendered)
        assertEquals("SaveCryptoFailure(<redacted>)", rendered)
    }

    @Test
    fun `InvalidArgument is redacted - RecordEditModel puts a field name in it`() {
        val rendered = diagnosticDetail(VaultBrowseError.InvalidArgument("duplicate field name: $SECRET"))
        assertFalse(rendered.contains(SECRET), rendered)
        assertEquals("InvalidArgument(<redacted>)", rendered)
    }

    @Test
    fun `redaction does not touch message, so on-screen copy is unaffected`() {
        val error = VaultBrowseError.InvalidArgument("field '$SECRET' is not valid hex")
        assertTrue(error.message!!.contains(SECRET), "UI must still name the bad field")
    }

    @Test
    fun `an audited-safe arm still renders in full`() {
        // FolderInvalid carries "{context}: {source}" — a path plus an errno.
        val rendered = diagnosticDetail(VaultBrowseError.FolderInvalid("failed to read vault.toml"))
        assertTrue(rendered.contains("failed to read vault.toml"), rendered)
    }

    @Test
    fun `an arm with no payload renders its name`() {
        assertEquals("WrongPasswordOrCorrupt", diagnosticDetail(VaultBrowseError.WrongPasswordOrCorrupt))
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /Users/hherb/src/secretary/.worktrees/472-android-log-hygiene-gate/android && ./gradlew :vault-access:test --tests '*SecretFreeConformanceTest*'
```

Expected: FAIL — `Unresolved reference` / the `is SecretFreeThrowable` assertions fail.

- [ ] **Step 3: Add the conformances**

In each of the five files, add the import and the interface to the class declaration. Four are one-line changes:

```kotlin
// VaultSyncError.kt, DeviceUnlockError.kt, VaultProvisioningError.kt, VaultName.kt
import org.secretary.diagnostics.SecretFreeThrowable

sealed class VaultSyncError(message: String? = null) : Exception(message), SecretFreeThrowable {
```

`VaultBrowseError.kt` additionally gets the override. Add the import, change the declaration, and insert this as the FIRST member of the class body — above the arms, so a reader meets the redaction before the data:

```kotlin
sealed class VaultBrowseError(message: String? = null) : Exception(message), SecretFreeThrowable {
    /**
     * Secret-free rendering for logcat (#472). Three arms are redacted AT SOURCE.
     *
     * PAYLOAD-ORIGIN AUDIT — each `render` verdict below is a security claim,
     * established by tracing the payload to its construction site. An arm whose
     * origin cannot be established is redacted, not assumed safe.
     *
     * REDACTED:
     * - [CorruptVault]: a Rust-authored `VaultError` Display passed through
     *   verbatim. Its fold includes `VaultError::Record(_)`, which renders as
     *   `"record CBOR error: {0}"` over `RecordError::DuplicateKey { key }`
     *   (`core/src/vault/record.rs:660`) — and `key` is the DECRYPTED CBOR field
     *   name. We do not author these strings, so their content cannot be
     *   reviewed here; that is the "unreviewed content" class this interface
     *   exists to deny. Tracked at the Rust root as #474.
     * - [SaveCryptoFailure]: the SAME plaintext, one arm over. The bridge's
     *   `map_core_vault_error_*` folds `VaultError::Record(_)` and
     *   `VaultError::Block(_)` into `FfiVaultError::SaveCryptoFailure { detail:
     *   format!("{e}") }` (`ffi/.../retention/orchestration.rs:205` plus five
     *   siblings in revoke/trash/purge/restore/save). iOS is NOT exposed here
     *   only because `VaultAccessError` has no `.saveCryptoFailure` case, so the
     *   arm falls to `VaultErrorMapping.swift:53`'s gated
     *   `default -> .other(diagnosticDetail(e))`. Our `BrowseMapping.kt` maps it
     *   EXPLICITLY and carries the raw detail, so the redaction is load-bearing
     *   here in a way it is not there. Do not "align with iOS" by removing it.
     * - [InvalidArgument]: Kotlin-side. `RecordEditModel` interpolates a
     *   decrypted record field name (`"field '<name>' is not valid hex"`,
     *   `"duplicate field name: <name>"`). Redacted regardless of which site
     *   renders it — do NOT rely on catch-arm ordering to keep it out of a log.
     *
     * RENDERED IN FULL, with the evidence:
     * - [InvalidRecoveryPhrase]: `MnemonicError` Display emits a word INDEX
     *   (`core/src/unlock/mnemonic.rs:54`), a word count (`:46`), or the fixed
     *   `"BIP-39 checksum failed"` (`:59`) — never the word itself.
     * - [FolderInvalid]: `format!("{context}: {source}")` — a filesystem path
     *   plus an errno. The threat model already treats paths as disclosed.
     * - [DeviceUuidMismatch]: device UUIDs, a public per-device fingerprint.
     * - [BlockNotFound] / [RecordNotFound]: hex-encoded UUIDs. The
     *   `BlockNotInTrash` / `BlockPurged` folds also `hex::encode`
     *   (`ffi/.../purge/orchestration.rs:153`), so no block NAME reaches them.
     * - [ReauthFailed]: built Android-side at the biometric gate from fixed
     *   labels.
     * - [Failed]: gated at construction — every producer passes
     *   `diagnosticDetail` output.
     *
     * NOTE: this audit is a point-in-time claim. An arm's payload can change
     * from an edit in the Rust core with NO Kotlin diff at all, which is exactly
     * how [SaveCryptoFailure] came to carry plaintext. Re-check when the bridge's
     * error folds change.
     */
    override val diagnosticDescription: String
        get() = when (this) {
            is CorruptVault -> "CorruptVault(<redacted>)"
            is SaveCryptoFailure -> "SaveCryptoFailure(<redacted>)"
            is InvalidArgument -> "InvalidArgument(<redacted>)"
            else -> toString()
        }

    // …existing arms unchanged…
```

- [ ] **Step 4: Run the tests and build `:app`**

```bash
cd /Users/hherb/src/secretary/.worktrees/472-android-log-hygiene-gate/android && ./gradlew :vault-access:test :app:assembleDebug
```

Expected: PASS. `:app` is built in the same step because adding an interface to a sealed type can break a downstream exhaustive `when` that Gradle will not otherwise surface.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/472-android-log-hygiene-gate
git add android/vault-access/src/main/kotlin/org/secretary/ android/vault-access/src/test/kotlin/org/secretary/browse/SecretFreeConformanceTest.kt
git commit -F - <<'EOF'
feat(#472): declare the five error families secret-free, redact three arms

The payload-origin audit ships as a doc comment on VaultBrowseError. It found
SaveCryptoFailure carries the same decrypted CBOR field name as CorruptVault,
via the bridge's map_core_vault_error_* fold of VaultError::Record(_).

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 3: Extract the shared allowlist library

**Files:**
- Create: `scripts/lib/hygiene-allowlist.sh`
- Modify: `ios/scripts/check-public-log-hygiene.sh`

**Interfaces:**
- Consumes: nothing.
- Produces: a sourceable library exporting `trim`, `allowlisted`, and the self-test temp-dir/trap helpers. Task 4's Android guard sources the same file.

**Why this task exists.** `allowlisted()` is the exact-trimmed-line matcher. Its substring predecessor was demonstrably exploitable — an entry chosen for one line exempted every future `.public` line in the same file containing the same needle — and was only fixed in #467's third review round. Two copies of that function can drift, and a fix applied to one would silently not apply to the other. That is precisely the failure class this whole slice exists to prevent, so it gets one copy.

**This task modifies a security control that shipped yesterday.** The bar is therefore *behaviour-identical*, proven by the guard's own two-sided self-test, not by inspection.

- [ ] **Step 1: Capture the baseline**

```bash
cd /Users/hherb/src/secretary/.worktrees/472-android-log-hygiene-gate
bash ios/scripts/check-public-log-hygiene.sh --self-test
bash ios/scripts/check-public-log-hygiene.sh
```

Expected, verbatim — record it, it is the assertion for Step 4:

```
self-test OK — 19 positive controls caught, 7 negative controls clean
OK — .public renders are gated and no value is hand-rendered into a String
```

- [ ] **Step 2: Create the library**

Create `scripts/lib/hygiene-allowlist.sh`. Move these three helpers out of `ios/scripts/check-public-log-hygiene.sh` **unchanged** — do not "improve" them in this task; a behaviour change here is indistinguishable from a regression:

- `trim()` — strips leading/trailing whitespace so an entry survives re-indentation but not a content edit.
- `allowlisted()` — the exact-trimmed-line matcher. It reads `$ALLOWLIST` and `$REPO_ROOT` from the sourcing script's scope; keep that contract and document it at the top of the function, since it is the one piece of coupling the extraction introduces.
- the self-test temp-dir pattern: the script-scoped `SELF_TEST_TMP` declaration and `cleanup_self_test`. Carry the existing comment explaining why `SELF_TEST_TMP` must NOT be `local` — the `EXIT` trap runs after the function frame is gone, so a `local` would be unset by then and `set -u` turns cleanup itself into a non-zero exit that looks exactly like a self-test failure.

Leave `count_matches()` in the iOS script. It exists for iOS rule 1's per-interpolation counting and no Android rule counts, so it is not shared.

Give the library a header stating: what it is, who sources it, the `$ALLOWLIST`/`$REPO_ROOT` contract, and that changing `allowlisted` changes a security control on two platforms at once.

- [ ] **Step 3: Source it from the iOS guard**

```bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../scripts/lib/hygiene-allowlist.sh
source "$SCRIPT_DIR/../../scripts/lib/hygiene-allowlist.sh"
```

Match the `SCRIPT_DIR` pattern already used at `ios/scripts/run-ios-tests.sh:35`. Delete the now-duplicated function bodies from the iOS script.

- [ ] **Step 4: Prove behaviour is identical**

```bash
cd /Users/hherb/src/secretary/.worktrees/472-android-log-hygiene-gate
bash ios/scripts/check-public-log-hygiene.sh --self-test
bash ios/scripts/check-public-log-hygiene.sh
shellcheck ios/scripts/check-public-log-hygiene.sh scripts/lib/hygiene-allowlist.sh
```

The two output lines must match Step 1's **byte for byte** — same control counts, same message. A different count means the extraction changed behaviour; fix it rather than updating the expectation.

Then re-prove the matcher is still live, since a sourcing bug could silently make `allowlisted` a no-op that returns success for everything:

```bash
# Mutate a real site: reintroduce String(describing: error) at MacUnlockView.swift:172
bash ios/scripts/check-public-log-hygiene.sh; echo "expect exit=1"
git checkout ios/SecretaryMacApp/Sources/MacUnlockView.swift
bash ios/scripts/check-public-log-hygiene.sh; echo "expect exit=0"
```

Confirm `git status` is clean before committing.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/472-android-log-hygiene-gate
git add scripts/lib/hygiene-allowlist.sh ios/scripts/check-public-log-hygiene.sh
git commit -F - <<'EOF'
refactor(#472): extract the exact-line allowlist matcher to a shared lib

allowlisted() is the matcher whose substring predecessor was exploitable and
was only fixed in #467's third review round. The Android guard needs the same
logic, and two copies of a security-critical matcher drift — a fix to one
would silently not apply to the other.

Behaviour-identical, proven by the iOS guard's own two-sided self-test
(19 positive / 7 negative, unchanged) plus a mutation cycle on a real site
to rule out a sourcing bug making the matcher vacuous.

count_matches stays in the iOS script — it serves rule 1's per-interpolation
counting and no Android rule counts.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 4: The Android guard script (RED against the real tree)

**Files:**
- Create: `android/scripts/check-log-hygiene.sh`
- Create: `android/scripts/log-hygiene-allowlist.txt`

**Interfaces:**
- Consumes: `scripts/lib/hygiene-allowlist.sh` from Task 3 — `trim`, `allowlisted`, and the self-test temp-dir/trap helpers. Do NOT reimplement any of them; the whole point of Task 3 was that there is one copy.
- Produces: `bash android/scripts/check-log-hygiene.sh [--self-test]`, exit 0 clean / 1 with hits on stderr. Task 8 wires it to CI.

This task deliberately lands the guard **before** the cleanup, so its first real run is a genuine red on live code. A mutation proof alone only ever exercises synthetic files.

- [ ] **Step 1: Source the shared library and write the Kotlin-specific filters**

Source the library exactly as the iOS guard does (Task 3, Step 3):

```bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../scripts/lib/hygiene-allowlist.sh
source "$SCRIPT_DIR/../../scripts/lib/hygiene-allowlist.sh"
```

`allowlisted()` reads `$ALLOWLIST` and `$REPO_ROOT` from the sourcing script's scope, so both must be set **before** any call. `ALLOWLIST` must NOT be `readonly` — `--self-test` retargets it at a synthetic allowlist so the exact-line matching is itself covered by a control pair.

Then write these, which are language-specific and NOT shared with the iOS guard:

- `REPO_ROOT` / `SCAN_ROOT` (`$REPO_ROOT/android`)
- `is_test_path()` — `*/src/test/*` or `*/src/androidTest/*`
- `is_generated_path()` — `*/build/generated/*`, `*/build/*`
- `is_comment_line()` — Kotlin uses `//` and KDoc `/** … */`. **Do NOT use the naive `^[[:space:]]*(//|\*|/\*)`.** That was this plan's original text and it is a CRITICAL bypass: it skips any line merely *starting* with `/*` without requiring the comment to close, so `/* */ Log.w(TAG, x.toString())` — a complete no-op comment followed by real code — is silently unscanned by all four rules. (The iOS guard is unaffected; its `^[[:space:]]*(///?|\*)` never matches `/*`.) Skip `//` lines and `*` continuation lines, and skip a `/*`-opening line ONLY when no code follows the comment's close:

```bash
is_comment_line() {
  local line="$1"
  [[ "$line" =~ ^[[:space:]]*(//|\*) ]] && return 0
  if [[ "$line" =~ ^[[:space:]]*/\* ]]; then
    [[ "$line" =~ \*/[[:space:]]*[^[:space:]] ]] && return 1
    return 0
  fi
  return 1
}
```

Do not port `count_matches()` — it exists for iOS rule 1's per-interpolation counting, and no Android rule counts.

- [ ] **Step 2: Write the rules**

```bash
# The one file permitted to reach logcat. This is the MECHANISM, not an
# exception, so it is a constant rather than an allowlist entry.
readonly SANCTIONED_LOG_FILE="android/kit/src/main/kotlin/org/secretary/diagnostics/SecretaryLog.kt"

# RULE A: any reference to android.util.Log — the import (which also catches
# `import android.util.Log as L`) or a fully-qualified call.
readonly LOG_RE='android\.util\.Log|(^|[^A-Za-z0-9_.])Log\.[A-Za-z_][A-Za-z0-9_]*\('

# RULE B1: throwable-shaped constructs. Name-blind and precise.
readonly LAUNDER_RE='\.message\b|\.localizedMessage\b|\bstackTraceToString\(|\bprintStackTrace\('

# RULE B2: the explicit render. Name-blind by design; the name-based form was
# the demonstrated bypass on iOS.
readonly TOSTRING_RE='\.toString\(\)'

# RULE C: BARE interpolation only. `${e.detail}` is a named typed field — a
# reviewable choice — and is deliberately NOT matched; matching it would fire on
# seven legitimate user-facing copy sites and drown the rule. iOS rule 3 draws
# the same line by requiring the closing paren immediately.
readonly INTERP_RE='\$\{(e|err|error|caught|failure|ex|t)\}|\$(e|err|error|caught|failure|ex|t)([^A-Za-z0-9_.]|$)'
```

Rule A's scan is its own function — it does not use the allowlist:

```bash
# RULE A. Any android.util.Log reference outside the sanctioned file is a hit.
scan_sink() {
  local root="$1" hit path text
  while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    path="${hit%%:*}"; text="${hit#*:}"; text="${text#*:}"
    is_test_path "$path" && continue
    is_generated_path "$path" && continue
    is_comment_line "$text" && continue
    [[ "${path#"$REPO_ROOT"/}" == "$SANCTIONED_LOG_FILE" ]] && continue
    echo "$hit"
  done < <(grep -rn --include='*.kt' -E "$LOG_RE" "$root" 2>/dev/null || true)
}
```

Rules B1/B2/C share one scanner, parameterised exactly as the iOS `scan_launder` is — `scan_launder <root> <rule-id> <ERE>`. There is **no `is_app_ui_path` equivalent**: the spec chose no path exclusion at all, so the Compose sites are individually allowlisted instead.

- [ ] **Step 3: Write the `--self-test` controls**

Positive controls (all must be caught). Rule A:

```bash
write_case A1 'import android.util.Log'
write_case A2 'import android.util.Log as L'
write_case A3 '        android.util.Log.w(TAG, "x", e)'
write_case A4 '        Log.w(TAG, "x", e)'
write_case A5 '        Log.i(TAG, msg)'
```

Rule B1:

```bash
write_case B1a 'throw CloudFolderException("op failed: ${e.message}")'
write_case B1b 'val s = problem.localizedMessage'
write_case B1c 'val s = e.stackTraceToString()'
write_case B1d 'e.printStackTrace()'
```

Rule B2 — including the name-based bypass that motivated making it name-blind:

```bash
write_case B2a 'else -> VaultBrowseError.Failed(e.toString())'
write_case B2b 'else -> VaultBrowseError.Failed(problem.toString())'
```

Rule C — bare only:

```bash
write_case C1 'return Failed("boom: $e")'
write_case C2 'return Failed("boom: ${e}")'
```

Negative controls (must all stay silent):

```bash
write_case N1 'else -> VaultBrowseError.Failed(diagnosticDetail(e))'
write_case N2 'SecretaryLog.warn(TAG, "unlock failed", e)'
write_case N3 'val s = "Couldn'"'"'t authorize the change: ${error.detail}"'   # typed field, not bare
write_case N4 'val s = "failed: ${error::class.simpleName}"'                    # typed field
write_case N5 'label = "$errorCount failures"'                                  # whole-identifier anchor
write_case N6 'val n = counter.toInt()'                                         # not toString
```

`N3`/`N4` are the controls that pin rule C's bare-only boundary — if someone "tightens" the regex to catch `${e.detail}`, these fail and the seven legitimate copy sites would need bogus entries.

`N5` pins the whole-identifier anchor: `$errorCount` is not `$error`.

Then port the iOS **A1/A2 allowlist control pair** verbatim in spirit — ONE file with TWO lines, where line 1 is an exact-line allowlist entry and line 2 is a *different* line in the *same* file sharing line 1's distinctive substring. Line 2 must trip exactly one rule. Assert by line number that line 1 is exempt and line 2 is still reported. Name them `X1`/`X2` here to avoid colliding with the rule-A control names above.

Finish with the count message, e.g. `echo "self-test OK — 13 positive controls caught, 6 negative controls clean"`.

- [ ] **Step 4: Write the allowlist with the four rule-B1 entries only**

Create `android/scripts/log-hygiene-allowlist.txt`. Header explains the format, the exact-trimmed-line semantics, and the two sections. Only the SECURITY DECISIONS section is populated now; the NON-THROWABLE RECEIVERS section is added in Task 7 once the cleanup has settled which `.toString()` calls survive.

```
# ---- SECURITY DECISIONS (rules A, B1, C) ----
# Each entry asserts that a value which CAN carry a secret is safe to render
# here. Reviewed like any other security change.

android/app/src/main/kotlin/org/secretary/app/CreateVaultWizardScreen.kt	B1	nameError?.let { Text(it.message ?: "Invalid name", modifier = Modifier.testTag("wizard-name-error")) }	Not a log and not a carried diagnostic: VaultNameError's arms are data objects whose message IS the user-facing copy ("Enter a name for the vault."). #454-compliant.
android/app/src/main/kotlin/org/secretary/app/CreateVaultWizardScreen.kt	B1	error?.let { Text(it.message ?: "Create failed", modifier = Modifier.testTag("wizard-error")) }	On-screen copy, not a log. VaultProvisioningError.CreateFailed IS a carried diagnostic, so this is a #454 violation — Android sibling of #473, filed not fixed (changing the copy is a UX decision). Payload is gated at construction as of this change.
android/app/src/main/kotlin/org/secretary/app/CreateVaultWizardScreen.kt	B1	error?.let { Text(it.message ?: "Error", modifier = Modifier.testTag("wizard-error")) }	Same as the line above — third wizard step, same VaultProvisioningError, same #473 sibling.
android/browse-ui/src/main/kotlin/org/secretary/browse/ui/RecordEditForm.kt	B1	val detail = it.message?.takeIf(String::isNotBlank) ?: it::class.simpleName	On-screen copy in a PACKAGE module, not a log. Renders a carried VaultBrowseError diagnostic — the clearest #473 sibling. Note the redactions do NOT affect `message`, so the user still sees which field is bad.
```

- [ ] **Step 5: Verify the self-test passes and the real scan is RED**

```bash
cd /Users/hherb/src/secretary/.worktrees/472-android-log-hygiene-gate
bash android/scripts/check-log-hygiene.sh --self-test    # expect: exit 0, "self-test OK"
bash android/scripts/check-log-hygiene.sh; echo "exit=$?"  # expect: exit 1
shellcheck android/scripts/check-log-hygiene.sh            # expect: clean
```

The real scan must exit 1 and report, at minimum: the 7 rule-A sites in `AppRoot.kt` / `CloudVaultOpen.kt` (imports included), the 13 rule-B1 sites less the 4 allowlisted, and the 12 rule-B2 sites. Rule C must report **nothing** — it has no hits in the tree today and is purely preventive.

**Capture the exact hit list** — this is the red half of the red→green evidence and Task 7 turns it green:

```bash
bash android/scripts/check-log-hygiene.sh 2>&1 | sed "s|$PWD/||" > /tmp/472-red.txt
wc -l /tmp/472-red.txt && cat /tmp/472-red.txt
```

Paste that output into the commit message below, replacing the marker line. Do not summarise it — the per-file list is what a reviewer checks the green run against.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/472-android-log-hygiene-gate
git add android/scripts/
git commit -F - <<'EOF'
feat(#472): fail-closed logcat hygiene guard (RED against the live tree)

Four rules: A pins android.util.Log to one file; B1 denies throwable-shaped
constructs name-blind; B2 denies .toString() name-blind; C is a best-effort
denylist on BARE interpolation only, since ${e.detail} is a reviewable typed
field and matching it would drown the rule.

Deliberately landed before the cleanup so its first real run is a genuine red
on live code — a mutation proof alone only exercises synthetic files. Hit list
recorded below; Task 7 turns it green.

<paste the hit list here>

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 5: Laundering cleanup — `:vault-access`

**Files:**
- Modify: `RecordEditModel.kt:116,161`, `VaultBrowseModel.kt:112`, `VaultProvisioningViewModel.kt:71`, `DeviceUuid.kt:59`, `mirror/VaultMirror.kt:72,74`, `mirror/RetryingCloudFolderPort.kt:102,104` — all under `android/vault-access/src/main/kotlin/org/secretary/`
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/HexFormat.kt:10-17`

**Interfaces:**
- Consumes: `diagnosticDetail` from Task 1.
- Produces: `VaultBrowseError.Failed`, `VaultSyncError.Failed` and `VaultProvisioningError.CreateFailed` are now gated at construction — which is what the audit's `render` verdict for those arms depends on.

- [ ] **Step 1: Replace each launder with `diagnosticDetail`**

Add `import org.secretary.diagnostics.diagnosticDetail` to each file, then:

```kotlin
// RecordEditModel.kt:116 and :161, VaultBrowseModel.kt:112
_error.value = VaultBrowseError.Failed(diagnosticDetail(e))

// VaultProvisioningViewModel.kt:71
error = VaultProvisioningError.CreateFailed(diagnosticDetail(e))

// DeviceUuid.kt:59
throw DeviceUuidException("device-uuid store I/O failed for ${file.name}: ${diagnosticDetail(e)}")

// mirror/VaultMirror.kt:72 and :74
throw VaultMirrorException("$label failed: ${diagnosticDetail(e)}")

// mirror/RetryingCloudFolderPort.kt:102
throw CloudFolderException("$op failed after ${policy.maxAttempts} attempts: ${diagnosticDetail(e)}")
// mirror/RetryingCloudFolderPort.kt:104
onRetry("$op attempt $attempt/${policy.maxAttempts} failed: ${diagnosticDetail(e)}")
```

`VaultProvisioningViewModel.kt:71` drops its `e.message ?:` prefix entirely — `diagnosticDetail` already handles the no-message case.

- [ ] **Step 2: Remove one innocent `.toString()` by using `buildString`**

`HexFormat.kt` — this is a readability improvement on its own merits, not a lint dodge:

```kotlin
fun hexOfBytes(bytes: ByteArray): String = buildString(bytes.size * 2) {
    for (b in bytes) {
        val v = b.toInt() and 0xff
        append(HEX_DIGITS[v ushr 4]).append(HEX_DIGITS[v and 0x0f])
    }
}
```

`buildString(capacity)` preserves the pre-sizing the original `StringBuilder(bytes.size * 2)` had.

- [ ] **Step 3: Run the module tests**

```bash
cd /Users/hherb/src/secretary/.worktrees/472-android-log-hygiene-gate/android && ./gradlew :vault-access:test
```

Expected: PASS. **Some existing tests may fail** by asserting on the old detail text (e.g. a test expecting `Failed` to contain an `IOException` message). That is the fix landing, not collateral — update the assertion to expect the gated form (`<undisclosed java.io.IOException>`), and treat a test that cannot be updated that way as a signal you changed behaviour you did not intend.

- [ ] **Step 4: Confirm the guard's remaining hits shrank**

```bash
cd /Users/hherb/src/secretary/.worktrees/472-android-log-hygiene-gate && bash android/scripts/check-log-hygiene.sh; echo "exit=$?"
```

Expected: still exit 1, but with no remaining hits under `vault-access/**` except the four surviving innocent `.toString()` (`VaultMirror.kt:109` — a relativized `Path`) and any `:kit`/`:app` sites still pending.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/472-android-log-hygiene-gate
git add android/vault-access/
git commit -F - <<'EOF'
fix(#472): gate the :vault-access laundering sites

Nine sites pre-rendered a caught throwable into a String that then became a
conformed error's payload — laundering unreviewed CONTENT past a gate that
only denies unreviewed TYPES. All now route through diagnosticDetail, which
is what the audit's `render` verdict for Failed/CreateFailed depends on.

hexOfBytes moves to buildString(capacity), removing an innocent .toString()
rather than allowlisting it.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 6: Laundering cleanup — `:kit`

**Files:**
- Modify: `android/kit/src/main/kotlin/org/secretary/browse/BrowseMapping.kt:47`
- Modify: `android/kit/src/main/kotlin/org/secretary/sync/VaultSyncErrorMapping.kt:29`
- Modify: `android/kit/src/main/kotlin/org/secretary/browse/UniffiVaultCreatePort.kt:68`
- Modify: `android/kit/src/main/kotlin/org/secretary/browse/UniffiVaultOpenPort.kt:252`
- Modify: `android/kit/src/main/kotlin/org/secretary/mirror/SafCloudFolderPort.kt:33`

**Interfaces:**
- Consumes: `diagnosticDetail` from Task 1. `:kit` has `api(project(":vault-access"))`, so it is already on the compile classpath.
- Produces: the FFI else-folds are gated, closing the path by which a Rust `Display` string reached a carried payload.

- [ ] **Step 1: Replace each launder**

Add `import org.secretary.diagnostics.diagnosticDetail` to each file, then:

```kotlin
// BrowseMapping.kt:47 — the FFI mapper's else-fold, i.e. the designated carrier
// of every Rust Display string the explicit arms above do not name.
else -> VaultBrowseError.Failed(diagnosticDetail(e))

// VaultSyncErrorMapping.kt:29
else -> VaultSyncError.Failed(diagnosticDetail(e))

// UniffiVaultCreatePort.kt:68
else -> VaultProvisioningError.CreateFailed(diagnosticDetail(e))

// UniffiVaultOpenPort.kt:252
throw VaultBrowseError.Failed("device-uuid resolve failed: ${diagnosticDetail(e)}")

// SafCloudFolderPort.kt:33
throw CloudFolderException("SAF $op failed: ${diagnosticDetail(e)}")
```

`UniffiVaultCreatePort.kt:68` drops its `e.message ?: (e::class.simpleName ?: "create failed")` chain — `diagnosticDetail` covers all three fallbacks and denies by default.

Leave the explicit arms **above** each `else` alone. `BrowseMapping.kt:21` (`CorruptVault(e.detail)`) and `:26` (`SaveCryptoFailure(e.detail)`) deliberately keep carrying the raw Rust detail — it is redacted at render time by Task 2, which preserves the payload for a future narrowing once #474 lands.

- [ ] **Step 2: Build and test**

```bash
cd /Users/hherb/src/secretary/.worktrees/472-android-log-hygiene-gate/android && ./gradlew :kit:assembleDebug :vault-access:test
```

Expected: BUILD SUCCESSFUL, tests PASS.

- [ ] **Step 3: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/472-android-log-hygiene-gate
git add android/kit/
git commit -F - <<'EOF'
fix(#472): gate the :kit FFI-mapper laundering sites

BrowseMapping's else-fold is the designated carrier of every Rust Display
string the explicit arms do not name — it is the site through which a
decrypted CBOR field name reached logcat. The explicit CorruptVault and
SaveCryptoFailure arms deliberately keep the raw detail; Task 2 redacts them
at render time, which preserves the payload for a narrowing once #474 lands.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 7: The sanctioned sink, the call sites, and GREEN

**Files:**
- Create: `android/kit/src/main/kotlin/org/secretary/diagnostics/SecretaryLog.kt`
- Modify: `android/app/src/main/kotlin/org/secretary/app/AppRoot.kt` — lines 5, 438, 572, 582
- Modify: `android/app/src/main/kotlin/org/secretary/app/CloudVaultOpen.kt` — lines 5, 191, 256, 298, 300
- Modify: `android/app/src/main/kotlin/org/secretary/app/ProvisioningRouting.kt:30-37`
- Modify: `android/scripts/log-hygiene-allowlist.txt`

**Interfaces:**
- Consumes: `diagnosticDetail` from Task 1.
- Produces: `object SecretaryLog { fun warn(tag: String, message: String, error: Throwable); fun warn(tag: String, message: String); fun info(tag: String, message: String) }` in `org.secretary.diagnostics`. It is the only sanctioned logcat sink.

- [ ] **Step 1: Create the sink**

```kotlin
package org.secretary.diagnostics

import android.util.Log

/**
 * The ONLY sanctioned logcat sink (#472). `android/scripts/check-log-hygiene.sh`
 * rule A fails the build if any other file references `android.util.Log`.
 *
 * There is deliberately NO overload taking a `Throwable` through to `Log`. The
 * three-argument `Log.w(tag, msg, throwable)` form prints
 * `Log.getStackTraceString`, which is `throwable.toString()` — class name PLUS
 * MESSAGE — followed by the same for every cause. Routing the throwable through
 * [diagnosticDetail] here makes that form unrepresentable at call sites: the
 * policy is applied once, in one place, rather than remembered 7 times.
 *
 * Not host-tested: `android.util.Log` is a stub that throws in JVM unit tests.
 * Everything it delegates to is tested in `:vault-access`, and rule A plus rule
 * B keep this file itself honest.
 */
object SecretaryLog {
    /** Warn, rendering [error] through the default-deny gate. */
    fun warn(tag: String, message: String, error: Throwable) =
        Log.w(tag, "$message: ${diagnosticDetail(error)}")

    /** Warn with no throwable. */
    fun warn(tag: String, message: String) = Log.w(tag, message)

    /** Informational, no throwable. */
    fun info(tag: String, message: String) = Log.i(tag, message)
}
```

- [ ] **Step 2: Rewrite the seven call sites**

In `AppRoot.kt` and `CloudVaultOpen.kt`, replace `import android.util.Log` with `import org.secretary.diagnostics.SecretaryLog`, then:

```kotlin
// AppRoot.kt:438
SecretaryLog.warn(TAG, "folder-change monitor failed to start", e)
// AppRoot.kt:572
SecretaryLog.warn(TAG, "device enroll failed; password open still succeeded", e)
// AppRoot.kt:582
SecretaryLog.warn(TAG, "unlock/open failed; returning to unlock screen", e)

// CloudVaultOpen.kt:191
SecretaryLog.warn(TAG, "cloud device enroll failed; password open still succeeded", e)
// CloudVaultOpen.kt:256
onRetry = { SecretaryLog.info(TAG, it) },
// CloudVaultOpen.kt:298
SecretaryLog.warn(TAG, "cloud vault CREATED but not synced and not marked for retry — user must not lose it", e)
// CloudVaultOpen.kt:300
SecretaryLog.warn(TAG, "cloud open/create failed; returning to unlock with same target", e)
```

- [ ] **Step 3: Remove the second innocent `.toString()` by deduplicating**

`ProvisioningRouting.kt` reimplements `HexFormat.hexOfBytes` — same loop, same nibble arithmetic, with the hex-digit string inlined as a literal twice. `:app` already depends on `:vault-access`. Replace the whole body:

```kotlin
import org.secretary.browse.hexOfBytes

internal fun cloudVaultKey(treeUri: String): String =
    hexOfBytes(MessageDigest.getInstance("SHA-256").digest(treeUri.toByteArray(Charsets.UTF_8)))
```

Delete the now-unused `StringBuilder` loop. Check whether the `java.security.MessageDigest` import is still needed (it is) and whether any other import became unused.

- [ ] **Step 4: Add the four NON-THROWABLE RECEIVERS entries**

Append to `android/scripts/log-hygiene-allowlist.txt`:

```
# ---- NON-THROWABLE RECEIVERS (rule B2 only) ----
# Each entry asserts ONLY that the receiver is not a Throwable — a two-second
# check against the surrounding code, not a security argument. Kept separate so
# the SECURITY DECISIONS section above stays short enough that its entries keep
# their weight. The durable fix is a type-aware lint; see the spec's Non-goals.

android/app/src/main/kotlin/org/secretary/app/AppRoot.kt	B2	selectionVm.recordSelection(VaultLocation(label, uri.toString()))	Receiver is an android.net.Uri from the SAF picker.
android/app/src/main/kotlin/org/secretary/app/AppRoot.kt	B2	pickedTreeUri = uri.toString()	Receiver is an android.net.Uri from the SAF picker.
android/browse-ui/src/main/kotlin/org/secretary/browse/ui/SettingsScreen.kt	B2	value = value.toString(),	Receiver is a numeric settings value bound to a TextField.
android/vault-access/src/main/kotlin/org/secretary/mirror/VaultMirror.kt	B2	base.relativize(file.toPath()).toString().replace(File.separatorChar, '/') to file.readBytes()	Receiver is a java.nio.file.Path being normalised to a vault-relative key.
```

- [ ] **Step 5: Verify GREEN, and build**

```bash
cd /Users/hherb/src/secretary/.worktrees/472-android-log-hygiene-gate
bash android/scripts/check-log-hygiene.sh --self-test   # exit 0
bash android/scripts/check-log-hygiene.sh; echo "exit=$?" # exit 0 — the green half
cd android && ./gradlew :vault-access:test :app:assembleDebug
```

Expected: guard exits 0 with 8 allowlist entries total; build succeeds. If the guard still reports a hit, fix the code — do not add an entry to make it pass.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/472-android-log-hygiene-gate
git add android/kit/ android/app/ android/scripts/
git commit -F - <<'EOF'
feat(#472): route logcat through SecretaryLog — guard now GREEN

SecretaryLog has no overload that hands a Throwable to android.util.Log, so
the 3-arg stack-trace form (which prints toString() for the throwable AND
every cause) is unrepresentable at call sites. Seven sites migrated; both
android.util.Log imports removed.

cloudVaultKey stops reimplementing hexOfBytes, removing the second innocent
.toString() rather than allowlisting it. Allowlist totals 8 entries, split
into security decisions (4) and non-throwable receivers (4).

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 8: CI wiring and the mutation proof

**Files:**
- Modify: `.github/workflows/test.yml` — new job after `swift-log-hygiene`

**Interfaces:**
- Consumes: `android/scripts/check-log-hygiene.sh` from Task 4.
- Produces: a `kotlin-log-hygiene` CI job.

- [ ] **Step 1: Add the job**

Insert after the `swift-log-hygiene` job, matching its shape:

```yaml
  kotlin-log-hygiene:
    name: kotlin logcat hygiene
    # Asserts no raw Throwable reaches logcat (#472). logcat has NO redaction
    # concept — every line is the equivalent of iOS's `privacy: .public` — so
    # rule A pins `android.util.Log` to one sanctioned file whose signatures make
    # the unsafe call unrepresentable, and rules B1/B2/C deny hand-rendering a
    # throwable into a String (which launders unreviewed CONTENT past a gate
    # that only denies unreviewed TYPES).
    #
    # Pure grep over android/**/*.kt — no JDK, no Android SDK, no Gradle, so it
    # runs on ubuntu in seconds rather than in the ~5min android-host job.
    runs-on: ubuntu-latest
    timeout-minutes: 10   # runaway cap (vs the 6h default); real duration ~1s
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      # --self-test FIRST: a guard never observed failing is indistinguishable
      # from a no-op. Two-sided — the matchers must fire on known-positives AND
      # stay silent on known-negatives.
      #
      # The step names are QUOTED: an unquoted ` #` inside a YAML `name:` starts
      # a comment and silently truncates it — valid YAML, so actionlint stays
      # green. That trap cost a fixup in #470.
      - name: 'check-log-hygiene.sh --self-test'
        run: bash android/scripts/check-log-hygiene.sh --self-test
      - name: 'check-log-hygiene.sh'
        run: bash android/scripts/check-log-hygiene.sh
```

- [ ] **Step 2: Lint the workflow, and read the step names back**

```bash
cd /Users/hherb/src/secretary/.worktrees/472-android-log-hygiene-gate
actionlint .github/workflows/test.yml
python3 -c "import yaml,sys; d=yaml.safe_load(open('.github/workflows/test.yml')); [print(repr(s.get('name'))) for s in d['jobs']['kotlin-log-hygiene']['steps']]"
```

actionlint green is necessary but not sufficient — an unquoted `#` truncates a `name:` silently and stays valid YAML. The readback is what proves the names survived.

- [ ] **Step 3: Run the mutation proof**

The `--self-test` only exercises synthetic files. Prove the guard fires on the real tree, twice, using the constructs that would matter most:

```bash
cd /Users/hherb/src/secretary/.worktrees/472-android-log-hygiene-gate
# (a) reintroduce the 3-arg Log form at a real site
#     AppRoot.kt:582 -> Log.w(TAG, "unlock/open failed…", e)  + restore the import
bash android/scripts/check-log-hygiene.sh; echo "expect exit=1 naming AppRoot.kt"
git checkout android/app/src/main/kotlin/org/secretary/app/AppRoot.kt
bash android/scripts/check-log-hygiene.sh; echo "expect exit=0"

# (b) reintroduce a launder at a real site
#     BrowseMapping.kt:47 -> VaultBrowseError.Failed(e.toString())
bash android/scripts/check-log-hygiene.sh; echo "expect exit=1 naming BrowseMapping.kt"
git checkout android/kit/src/main/kotlin/org/secretary/browse/BrowseMapping.kt
bash android/scripts/check-log-hygiene.sh; echo "expect exit=0"
```

Record both red→green cycles in the commit message. Verify `git status` is clean afterwards — a leftover mutation is the worst possible thing to commit here.

- [ ] **Step 4: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/472-android-log-hygiene-gate
git add .github/workflows/test.yml
git commit -F - <<'EOF'
ci(#472): gate every PR on the Kotlin logcat hygiene guard

Pure grep on ubuntu, ~1s, --self-test first. Step names quoted so an
unquoted `#` cannot silently truncate them.

Mutation proof on the live tree (the self-test only covers synthetic files):
reintroducing the 3-arg Log.w at AppRoot.kt:582 -> exit 1; revert -> exit 0.
Reintroducing e.toString() at BrowseMapping.kt:47 -> exit 1; revert -> 0.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 9: Documentation

**Files:**
- Modify: `CLAUDE.md` — new section after "Swift log hygiene: default-deny at `privacy: .public` (#467)"
- Modify: `CLAUDE.md` — the Commands block
- Check: `README.md`, `ROADMAP.md`

- [ ] **Step 1: Add the commands**

In the Commands block, after the `check-public-log-hygiene.sh` pair:

```bash
# Assert no raw Throwable reaches logcat (#472). logcat has NO redaction concept,
# so rule A pins `android.util.Log` to one sanctioned file (SecretaryLog) whose
# signatures make the unsafe 3-arg call unrepresentable; rules B1/B2/C deny
# hand-rendering a throwable into a String. Same --self-test-first discipline.
bash android/scripts/check-log-hygiene.sh --self-test
bash android/scripts/check-log-hygiene.sh
```

- [ ] **Step 2: Add the architecture section**

Insert immediately after the "Swift log hygiene" section:

```markdown
### Kotlin log hygiene: there is no `.public` to opt into (#472)

logcat has **no redaction concept**. There is no `privacy:` qualifier to set —
every line is readable via `adb logcat` on a debuggable build and is captured
into bug reports, so every line is the equivalent of iOS's `privacy: .public`.
The sink itself is therefore what gets guarded, not a marker on it.

- **`SecretFreeThrowable`** ([android/vault-access/src/main/kotlin/org/secretary/diagnostics/SecretFreeThrowable.kt](android/vault-access/src/main/kotlin/org/secretary/diagnostics/SecretFreeThrowable.kt)) is the allowlist, and declaring it is a **security decision** — the same claim `SecretFreeError` makes on iOS. It is a *rendering* interface: an arm that is secret-bearing overrides `diagnosticDescription` and redacts at source instead of the whole type being excluded.
- **Kotlin has no retroactive conformance.** `extension CocoaError: SecretFreeError {}` has no Kotlin equivalent, so JDK, Android-framework and uniffi-generated throwables can *never* implement the interface — and those are exactly the types that arrive at a `catch (e: Exception)`. The deny path is the **normal** path here, not the degenerate one. That is why `diagnosticDetail` appends the **cause chain as fully-qualified type names**: a class name is a compile-time constant and cannot carry runtime data, so the chain is as fail-closed as a bare marker while recovering most of what the stack trace was worth.
- **`SecretaryLog`** ([android/kit/src/main/kotlin/org/secretary/diagnostics/SecretaryLog.kt](android/kit/src/main/kotlin/org/secretary/diagnostics/SecretaryLog.kt)) is the only file in the tree permitted to reference `android.util.Log`, and it has **no overload that hands a `Throwable` to it**. The three-argument `Log.w(tag, msg, throwable)` form prints `toString()` — class name plus message — for the throwable and every cause, so making it unrepresentable at call sites is the whole mechanism. This is the `foldDiagnostic` analogue: policy applied once, in one place.
- **`VaultBrowseError.SaveCryptoFailure` must stay redacted**, and iOS is not a precedent for removing it. iOS's `VaultAccessError` has no `.saveCryptoFailure` case at all, so the arm falls to `VaultErrorMapping.swift:53`'s `default -> .other(diagnosticDetail(e))`, which is already gated. Android's `BrowseMapping.kt:26` maps it **explicitly** and carries the raw Rust detail — which, via the bridge's fold of `VaultError::Record(_)`, is `RecordError::DuplicateKey`'s decrypted CBOR field name. The divergence is in the mapper, not the policy. Do not "align the platforms" by deleting the redaction.

Adding a log site means calling `SecretaryLog`; adding an error type that reaches
one means declaring it `SecretFreeThrowable` after review. Forgetting the second
degrades a log line to `<undisclosed …>` — it never leaks.
`android/scripts/check-log-hygiene.sh` enforces the first; nothing but review
enforces the second.

The allowlist (`android/scripts/log-hygiene-allowlist.txt`) is keyed on the
**exact trimmed source line**, never a substring — same semantics and same
reasoning as #467's. It is split into two sections by review weight: *security
decisions* (rules A/B1/C — a value that can carry a secret) and *non-throwable
receivers* (rule B2 only — the receiver simply is not a `Throwable`). Keeping
the first section short is what keeps its entries meaningful.
```

- [ ] **Step 3: Decide README / ROADMAP by precedent, not by assumption**

```bash
cd /Users/hherb/src/secretary/.worktrees/472-android-log-hygiene-gate
grep -n '467\|456\|check-lean-binding\|log hygiene' README.md ROADMAP.md
```

#467 concluded, by exactly this grep, that its analogues (#456/#466 and #189's `check-lean-binding.sh`) appear in **neither** file, and left both unchanged. Expect the same answer here and record the grep result either way. If the grep shows otherwise, update the file that precedent says to update — do not assume.

- [ ] **Step 4: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/472-android-log-hygiene-gate
git add CLAUDE.md
git commit -F - <<'EOF'
docs(#472): record the Android logcat hygiene invariant

Beside the #467 Swift section. Emphasises the two things a future reader is
most likely to get wrong: Kotlin has no retroactive conformance, so the deny
path is the normal path; and SaveCryptoFailure must stay redacted even though
iOS does not redact its equivalent (iOS has no such case and its mapping's
default arm is already gated).

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

## Final acceptance

Run all of these before opening the PR:

```bash
cd /Users/hherb/src/secretary/.worktrees/472-android-log-hygiene-gate
bash android/scripts/check-log-hygiene.sh --self-test
bash android/scripts/check-log-hygiene.sh
# The extraction touched a shipped control — re-prove it, byte for byte:
bash ios/scripts/check-public-log-hygiene.sh --self-test   # 19 positive / 7 negative
bash ios/scripts/check-public-log-hygiene.sh
shellcheck android/scripts/check-log-hygiene.sh ios/scripts/check-public-log-hygiene.sh scripts/lib/hygiene-allowlist.sh
actionlint .github/workflows/test.yml
cd android && ./gradlew :vault-access:test :app:assembleDebug
cd /Users/hherb/src/secretary/.worktrees/472-android-log-hygiene-gate
git diff main... --name-only -- core/ ffi/     # MUST be empty
git status -s                                   # MUST be clean (no leftover mutation)
```

**Follow-ups to file at ship time** (batch into one ask — issue creation needs explicit approval):

1. **Android sibling of #473** — three on-screen sites render a carried diagnostic as user-facing copy (`CreateVaultWizardScreen.kt:81,:93`, `RecordEditForm.kt:62`), carried as reviewed allowlist entries.
2. **Type-aware lint** — a detekt custom rule with type resolution would retire grep rules B1/B2/C, delete the four non-throwable allowlist entries, and close rule C's name-based gap.
