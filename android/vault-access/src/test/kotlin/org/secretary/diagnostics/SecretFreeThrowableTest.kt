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
