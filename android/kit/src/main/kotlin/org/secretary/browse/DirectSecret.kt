package org.secretary.browse

import java.nio.ByteBuffer

/**
 * #307 zero-copy secret args: uniffi 0.32's `[ByRef] bytes` parameters cross the FFI as a borrow
 * of a DIRECT [ByteBuffer] (ForeignBytes — pointer + length) instead of copying through a
 * RustBuffer, eliminating the two un-scrubbable marshalling copies the pre-0.32 path allocated
 * (`docs/manual/contributors/ffi-secret-handling-internal.md`).
 *
 * Runs [body] with a fresh direct buffer holding [secret]'s bytes, then overwrites the buffer's
 * native memory before returning — on both success and throw — so the adapter-owned off-heap copy
 * never outlives the call. Direct-buffer memory is off the GC heap, which is exactly why the
 * overwrite is deterministic here (unlike a `ByteArray` the collector may have moved or copied).
 * The caller-owned [secret] `ByteArray` remains the caller's to zeroize, unchanged.
 */
internal inline fun <T> withDirectSecret(secret: ByteArray, body: (ByteBuffer) -> T): T {
    val buf = ByteBuffer.allocateDirect(secret.size)
    buf.put(secret)
    buf.flip()
    try {
        return body(buf)
    } finally {
        for (i in 0 until buf.capacity()) buf.put(i, 0)
    }
}
