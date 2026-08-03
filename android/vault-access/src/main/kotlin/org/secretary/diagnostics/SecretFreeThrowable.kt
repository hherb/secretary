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
