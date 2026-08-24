// Incremental decrypt session over an open Pipeline.

package com.everanium.itb.kotlin

import java.io.OutputStream
import com.everanium.itb.DecryptStream as JDecryptStream

/**
 * Incremental decrypt session: wire in through [write], plaintext
 * out through [read] / [copyTo]. All chunking, MAC, envelope, and
 * wire-format decisions stay inside libitb. Closing cancels the
 * session and frees the Go-side state.
 *
 * [parent] pins the owning [Pipeline] so it stays reachable while
 * the session is live.
 */
class DecryptStream internal constructor(
    /** The Pipeline this session runs against. */
    val parent: Pipeline,
    internal val impl: JDecryptStream,
) : AutoCloseable {

    /**
     * Feeds bytes into the session. Blocks until the cipher chain
     * accepts them; errors are sticky.
     */
    fun write(src: ByteArray): Unit = itbCall { impl.write(src) }

    /** Feeds [len] bytes of [src] starting at [off]. */
    fun write(src: ByteArray, off: Int, len: Int): Unit =
        itbCall { impl.write(src, off, len) }

    /**
     * Signals end-of-input. Idempotent; [write] after end fails with
     * [Status.BadInput].
     */
    fun end(): Unit = itbCall { impl.end() }

    /**
     * Drains up to `dst.size` produced bytes into [dst]. A zero
     * [ReadResult.count] before [end] means the chain has nothing
     * spooled yet; after [end], an empty-spool read blocks until the
     * terminal bytes arrive or the session errors.
     */
    fun read(dst: ByteArray): ReadResult = itbCall {
        val n = impl.read(dst)
        ReadResult(n, impl.isFinished)
    }

    /** True once a [read] has reported the session output complete. */
    val isFinished: Boolean
        get() = impl.isFinished

    /**
     * Calls [end] (idempotent) and writes every remaining output
     * byte to [destination].
     */
    fun copyTo(destination: OutputStream) {
        end()
        val buf = ByteArray(COPY_BUF)
        while (true) {
            val r = read(buf)
            if (r.count > 0) {
                destination.write(buf, 0, r.count)
            }
            if (r.finished) {
                destination.flush()
                return
            }
        }
    }

    /** Cancels the session and frees the Go-side state. */
    override fun close(): Unit = impl.close()

    private companion object {
        /** Drain slice size used by [copyTo]. */
        const val COPY_BUF = 1 shl 20
    }
}
