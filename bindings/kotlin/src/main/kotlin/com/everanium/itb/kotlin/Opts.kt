// Options builder — a Kotlin face over the Java binding's URL-query
// Opts builder.
//
// No validation happens here — every key and value is rendered into
// a percent-encoded query string by the Java layer and passed
// through to Go verbatim; libitb rejects unknown keys or bad values
// with a diagnostic surfaced via ItbException. Primitive / MAC /
// cipher / palette names are opaque strings.

package com.everanium.itb.kotlin

import com.everanium.itb.Opts as JOpts

/**
 * Builder producing the opts string consumed by [Pipeline.init].
 * Setters chain; an empty builder renders the empty query (pure
 * profile defaults). Profile records for [Pipeline.register] are
 * built with [Profile] / [profile].
 *
 * The [opts] DSL entry gives the idiomatic construction:
 *
 * ```kotlin
 * val o = opts {
 *     nonceBits(512)
 *     keyBits(1024)
 * }
 * ```
 */
class Opts {
    internal val impl = JOpts()

    /** Hex-encodes the parallax master override (`pm`). */
    fun permMaster(master: ByteArray): Opts = apply { impl.withPermMaster(master) }

    /** Hex-encodes the wrapper master override (`wm`). */
    fun wrapMaster(master: ByteArray): Opts = apply { impl.withWrapMaster(master) }

    fun parallax(on: Boolean): Opts = apply { impl.withParallax(on) }

    fun wrapper(on: Boolean): Opts = apply { impl.withWrapper(on) }

    fun maxWorkers(n: Long): Opts = apply { impl.withMaxWorkers(n) }

    fun nonceBits(n: Long): Opts = apply { impl.withNonceBits(n) }

    fun barrierFill(n: Long): Opts = apply { impl.withBarrierFill(n) }

    fun chunkSize(n: Long): Opts = apply { impl.withChunkSize(n) }

    fun keyBits(n: Long): Opts = apply { impl.withKeyBits(n) }

    fun parallaxSegmentSize(n: Long): Opts = apply { impl.withParallaxSegmentSize(n) }

    fun macName(name: String): Opts = apply { impl.withMacName(name) }

    fun innerHash(name: String): Opts = apply { impl.withInnerHash(name) }

    /**
     * Per-call override for `Opts.MixedHashes [8]string` on the Go
     * side. Comma-joins the 8 slot names into the `innerHashes`
     * opts-string key. Slot ordering is
     * `[noise, lock, data1, data2, data3, start1, start2, start3]`.
     * Fail-fast validation surfaces at Init on the Go side; a typo'd
     * slot or width mismatch surfaces with an error naming the
     * offending slot. When both this and [innerHash] are set, the
     * mixed override wins on the Go side.
     */
    fun innerHashes(vararg names: String): Opts =
        apply { impl.withInnerHashes(*names) }

    fun outerCipher(name: String): Opts = apply { impl.withOuterCipher(name) }

    /** Comma-joins the palette names (`parallaxPalette`). */
    fun parallaxPalette(vararg names: String): Opts =
        apply { impl.withParallaxPalette(*names) }

    /**
     * Escape hatch appending a raw `key=value` pair. Covers every
     * key the Go side accepts.
     */
    fun raw(key: String, value: String): Opts = apply { impl.withRaw(key, value) }
}

/** DSL constructor for [Opts]. */
fun opts(block: Opts.() -> Unit): Opts = Opts().apply(block)
