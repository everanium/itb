// Kotlin lifetime wrapper around the Java binding's Pipeline.
//
// Zero FFI of its own — every call lands on the Java binding's
// in-process libitb proxy; this layer adds null-safety, the sealed
// Status re-throw, `use { }`-friendly AutoCloseable shape, and
// coroutine variants of the blocking entry points.

package com.everanium.itb.kotlin

import java.io.InputStream
import java.io.OutputStream
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import com.everanium.itb.Opts as JOpts
import com.everanium.itb.Pipeline as JPipeline

/**
 * A Triple Pipeline session plus its exported blob bytes.
 *
 * The blob carries the session bundle the receiver feeds to [open];
 * [rekey] refreshes it. Closing the Pipeline (or letting `use { }`
 * do it) frees the handle — libitb zeroes key material internally;
 * an unreachable un-closed Pipeline is reclaimed by the Java layer's
 * Cleaner backstop.
 *
 * Streaming-decrypt caveat: chunked Streaming AEAD verifies per
 * chunk, so plaintext of verified chunks is released before a later
 * chunk can fail authentication.
 */
class Pipeline internal constructor(internal val impl: JPipeline) : AutoCloseable {

    /** The exported session bundle bytes for the receiver side. */
    val blob: ByteArray
        get() = itbCall { impl.blob() }

    /**
     * Rotates the parallax + wrapper masters and refreshes [blob].
     * Must not run concurrently with cipher calls or open stream
     * sessions on the same Pipeline.
     */
    fun rekey(permMaster: ByteArray, wrapMaster: ByteArray): Unit =
        itbCall { impl.rekey(permMaster, wrapMaster) }

    /**
     * Zeroes the Pipeline's key material and marks it closed while
     * keeping the handle registered. Idempotent; subsequent cipher
     * calls fail with [Status.TripleClosed]. The handle itself is
     * released by [close].
     */
    fun destroy(): Unit = itbCall { impl.destroy() }

    /** True once [destroy] has run. */
    val isDestroyed: Boolean
        get() = impl.isDestroyed

    /** Single Message encrypt: one call, one self-contained wire. */
    fun encryptMessage(plaintext: ByteArray): ByteArray =
        itbCall { impl.encryptMessage(plaintext) }

    /** Receive-side counterpart of [encryptMessage]. */
    fun decryptMessage(wire: ByteArray): ByteArray =
        itbCall { impl.decryptMessage(wire) }

    /**
     * One-shot stream encrypt for callers holding the whole
     * plaintext in memory. For bounded-memory streaming use
     * [encryptStream] / [encryptStreamPump].
     */
    fun encryptStreamOneShot(plaintext: ByteArray): ByteArray =
        itbCall { impl.encryptStreamOneShot(plaintext) }

    /** Receive-side counterpart of [encryptStreamOneShot]. */
    fun decryptStreamOneShot(wire: ByteArray): ByteArray =
        itbCall { impl.decryptStreamOneShot(wire) }

    /** Opens an incremental encrypt session (plaintext in, wire out). */
    fun encryptStream(): EncryptStream =
        EncryptStream(this, itbCall { impl.encryptStream() })

    /** Opens an incremental decrypt session (wire in, plaintext out). */
    fun decryptStream(): DecryptStream =
        DecryptStream(this, itbCall { impl.decryptStream() })

    /**
     * Pumps [source] through an encrypt session into [destination]
     * with bounded memory: feed a block, drain available wire,
     * repeat; end + final drain on source EOF. The session is freed
     * on return.
     */
    fun encryptStreamPump(source: InputStream, destination: OutputStream): Unit =
        itbCall { impl.encryptStreamPump(source, destination) }

    /** Receive-side counterpart of [encryptStreamPump]. */
    fun decryptStreamPump(source: InputStream, destination: OutputStream): Unit =
        itbCall { impl.decryptStreamPump(source, destination) }

    // Coroutine variants — the blocking call shifted onto
    // Dispatchers.IO. The underlying work is CPU-bound inside
    // libitb; the IO dispatcher keeps it off the caller's coroutine
    // context without capping parallelism at the default
    // dispatcher's core count.

    /** Coroutine variant of [encryptMessage]. */
    suspend fun encryptMessageAsync(plaintext: ByteArray): ByteArray =
        withContext(Dispatchers.IO) { encryptMessage(plaintext) }

    /** Coroutine variant of [decryptMessage]. */
    suspend fun decryptMessageAsync(wire: ByteArray): ByteArray =
        withContext(Dispatchers.IO) { decryptMessage(wire) }

    /** Coroutine variant of [encryptStreamOneShot]. */
    suspend fun encryptStreamOneShotAsync(plaintext: ByteArray): ByteArray =
        withContext(Dispatchers.IO) { encryptStreamOneShot(plaintext) }

    /** Coroutine variant of [decryptStreamOneShot]. */
    suspend fun decryptStreamOneShotAsync(wire: ByteArray): ByteArray =
        withContext(Dispatchers.IO) { decryptStreamOneShot(wire) }

    /** Coroutine variant of [encryptStreamPump]. */
    suspend fun encryptStreamPumpAsync(source: InputStream, destination: OutputStream): Unit =
        withContext(Dispatchers.IO) { encryptStreamPump(source, destination) }

    /** Coroutine variant of [decryptStreamPump]. */
    suspend fun decryptStreamPumpAsync(source: InputStream, destination: OutputStream): Unit =
        withContext(Dispatchers.IO) { decryptStreamPump(source, destination) }

    /** Releases the handle (libitb zeroes key material first). */
    override fun close(): Unit = impl.close()

    companion object {
        /**
         * Constructs a fresh Pipeline against the named profile.
         * Profile names and opts keys are opaque strings validated
         * by the Go side.
         */
        fun init(profile: String, opts: Opts? = null): Pipeline =
            Pipeline(itbCall { JPipeline.init(profile, opts?.impl ?: JOpts()) })

        /**
         * Reconstructs a Pipeline from a blob produced by [init] or
         * [rekey]. Omitting [permMaster] / [wrapMaster] uses the
         * blob-embedded masters; supplying both (non-empty)
         * overrides them.
         */
        fun open(
            profile: String,
            blob: ByteArray,
            opts: Opts? = null,
            permMaster: ByteArray? = null,
            wrapMaster: ByteArray? = null,
        ): Pipeline {
            require((permMaster == null) == (wrapMaster == null)) {
                "permMaster and wrapMaster must be supplied together or not at all"
            }
            return Pipeline(itbCall {
                JPipeline.open(profile, blob, opts?.impl ?: JOpts(), permMaster, wrapMaster)
            })
        }

        /**
         * Registers a user-defined Triple profile under [name] so
         * subsequent [init] / [open] calls resolve it. The opts
         * follow the register-profile grammar validated by Go —
         * build them with [Opts.raw] plus the typed setters where
         * key names coincide. A duplicate name fails with
         * [Status.ProfileExists].
         */
        fun registerProfile(name: String, opts: Opts): Unit =
            itbCall { JPipeline.registerProfile(name, opts.impl) }
    }
}
