// Kotlin-idiom extension surface: scoped-session helpers and the
// Result-returning variants of the cipher entry points.

package com.everanium.itb.kotlin

/**
 * Constructs a Pipeline against [profile], runs [block] with it, and
 * closes it on the way out — `Pipeline.init(...).use { ... }` in one
 * call.
 */
inline fun <R> withPipeline(profile: String, opts: Opts? = null, block: (Pipeline) -> R): R =
    Pipeline.init(profile, opts).use(block)

/**
 * Opens an incremental encrypt session, runs [block] with it, and
 * closes the session on the way out.
 */
inline fun <R> Pipeline.encrypting(block: (EncryptStream) -> R): R =
    encryptStream().use(block)

/**
 * Opens an incremental decrypt session, runs [block] with it, and
 * closes the session on the way out.
 */
inline fun <R> Pipeline.decrypting(block: (DecryptStream) -> R): R =
    decryptStream().use(block)

// Result-returning variants — for call sites that prefer
// `.getOrThrow()` / `.getOrElse { }` railway style over try/catch.
// The captured failure is the same ItbException the throwing
// variant raises.

/** [Pipeline.encryptMessage] captured as a [Result]. */
fun Pipeline.encryptMessageCatching(plaintext: ByteArray): Result<ByteArray> =
    runCatching { encryptMessage(plaintext) }

/** [Pipeline.decryptMessage] captured as a [Result]. */
fun Pipeline.decryptMessageCatching(wire: ByteArray): Result<ByteArray> =
    runCatching { decryptMessage(wire) }

/** [Pipeline.encryptStreamOneShot] captured as a [Result]. */
fun Pipeline.encryptStreamOneShotCatching(plaintext: ByteArray): Result<ByteArray> =
    runCatching { encryptStreamOneShot(plaintext) }

/** [Pipeline.decryptStreamOneShot] captured as a [Result]. */
fun Pipeline.decryptStreamOneShotCatching(wire: ByteArray): Result<ByteArray> =
    runCatching { decryptStreamOneShot(wire) }

/**
 * The [Status] carried by a failed ITB [Result], or null when the
 * result succeeded or failed with a non-ITB exception.
 */
val Result<*>.itbStatus: Status?
    get() = (exceptionOrNull() as? ItbException)?.status
