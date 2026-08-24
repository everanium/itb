// Shared timing + reporting helpers for the Kotlin binding
// micro-benchmarks. Wall-clock via System.nanoTime; output is a
// fixed-width table:
//
//   bench             size     mb_per_sec
//   message           1 MiB    <n>
//   ...
//
// Bench configuration is driven by environment variables so a
// side-by-side comparison with the root Go bench harness is
// straightforward:
//
//   ITB_NONCE_BITS     nonce width (default 512)
//   ITB_KEY_BITS       key bits (default 1024)
//   ITB_WITH_PARALLAX  parallax layer on/off (default false)
//   ITB_WITH_WRAPPER   wrapper layer on/off (default false)
//   ITB_INNER_HASH     opaque hash name (default: profile's)
//   ITB_PROFILE        profile name override
//   ITB_BENCH_MIN_SEC  per-case wall-clock budget (default 5.0)

package com.everanium.itb.kotlin.bench

import com.everanium.itb.kotlin.Opts
import com.everanium.itb.kotlin.opts
import java.security.SecureRandom

internal object BenchUtil {

    /** Iteration floor per case. */
    private const val MIN_ITERS = 3

    /** Payload sizes exercised by both shapes. */
    val sizes = intArrayOf(1 shl 20, 16 shl 20, 64 shl 20)

    private val csprng = SecureRandom()

    fun minSeconds(): Double =
        System.getenv("ITB_BENCH_MIN_SEC")?.toDoubleOrNull()?.takeIf { it > 0.0 } ?: 5.0

    /**
     * Reads the bench-shape env vars and builds an [Opts]. Defaults
     * match root Go BENCH3.md so numbers are directly comparable.
     */
    fun buildOpts(): Opts = opts {
        nonceBits(envLong("ITB_NONCE_BITS", 512))
        keyBits(envLong("ITB_KEY_BITS", 1024))
        parallax(envBool("ITB_WITH_PARALLAX"))
        wrapper(envBool("ITB_WITH_WRAPPER"))
        System.getenv("ITB_INNER_HASH")?.takeIf { it.isNotEmpty() }?.let { innerHash(it) }
    }

    fun profileName(fallback: String): String =
        System.getenv("ITB_PROFILE")?.takeIf { it.isNotEmpty() } ?: fallback

    fun header() {
        println(String.format("%-17s %-8s %s", "bench", "size", "mb_per_sec"))
    }

    /** CSPRNG-fill so plaintext content matches the root Go bench
     * (crypto/rand). Not called inside timing loops. */
    fun csprngFill(buf: ByteArray) {
        csprng.nextBytes(buf)
    }

    private fun sizeLabel(size: Int): String =
        if (size >= (1 shl 20)) "${size shr 20} MiB" else "${size shr 10} KiB"

    /**
     * Runs [run] until the wall-clock budget is spent (with an
     * iteration floor + one untimed warm-up), then prints one table
     * row.
     */
    fun case(name: String, size: Int, run: () -> Unit) {
        run() // warm-up
        val budgetNanos = (minSeconds() * 1e9).toLong()
        val start = System.nanoTime()
        var iters = 0L
        while (System.nanoTime() - start < budgetNanos || iters < MIN_ITERS) {
            run()
            iters++
        }
        val elapsed = (System.nanoTime() - start) / 1e9
        val mb = size.toDouble() * iters / (1024.0 * 1024.0)
        println(String.format("%-17s %-8s %.1f", name, sizeLabel(size), mb / elapsed))
    }

    private fun envLong(name: String, fallback: Long): Long =
        System.getenv(name)?.toLongOrNull() ?: fallback

    private fun envBool(name: String): Boolean =
        System.getenv(name).let { it == "true" || it == "1" }
}
