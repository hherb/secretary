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
 *
 * Every member returns `Unit` EXPLICITLY. `android.util.Log`'s methods return an
 * `Int` (bytes written), and an expression body would infer that straight into
 * this façade's public signature — leaking the very type the façade exists to
 * hide, and inviting a call site to branch on it (#475 review).
 */
object SecretaryLog {
    /** Warn, rendering [error] through the default-deny gate. */
    fun warn(tag: String, message: String, error: Throwable) {
        Log.w(tag, "$message: ${diagnosticDetail(error)}")
    }

    /** Warn with no throwable. */
    fun warn(tag: String, message: String) {
        Log.w(tag, message)
    }

    /** Informational, no throwable. */
    fun info(tag: String, message: String) {
        Log.i(tag, message)
    }
}
