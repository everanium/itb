// Plaintext content: the payload modes, the seeded per-worker
// generator, and the buffer fill from the operating-system CSPRNG.

package io.github.everanium.itb3.kotlin.loop

import java.security.SecureRandom

/**
 * Payload mode selector values for the --payload-mode flag.
 *
 *  - Fixed: one CSPRNG-generated buffer per worker, held unchanged
 *    for the whole run (the default).
 *  - Rotating: the buffer is regenerated before every iteration, so
 *    no two encrypt calls see the same plaintext.
 *  - PatternZero / PatternFf: degenerate constant fills (all 0x00 /
 *    all 0xFF) probing minimum-entropy plaintext handling.
 *  - PatternAscii: a repeating 'A'..'Z' ramp probing low-entropy
 *    structured text.
 */
enum class PayloadMode(val label: String) {
    Fixed("fixed"),
    Rotating("rotating"),
    PatternZero("pattern-zero"),
    PatternFf("pattern-ff"),
    PatternAscii("pattern-ascii"),
    ;

    companion object {
        fun parse(s: String): PayloadMode? = entries.firstOrNull { it.label == s }
    }
}

/**
 * The deterministic per-worker generator's state. Kotlin has no
 * by-reference scalar parameter, so the splitmix64 state lives in this
 * one-field holder that the worker owns and the generator advances in
 * place.
 */
class Rng(var state: Long)

/** The operating-system CSPRNG, one instance per calling thread so
 * concurrent payload refills never serialise on one provider. */
private val CSPRNG: ThreadLocal<SecureRandom> = ThreadLocal.withInitial { SecureRandom() }

/**
 * Seeded plaintext. The seed makes plaintext content reproducible so a
 * failing iteration can be replayed with the same bytes; it governs
 * nothing else — pipeline keys, nonces and masters stay CSPRNG-drawn,
 * so a seeded run is a reproduction aid and never a security test.
 * Each worker's stream is domain-separated by its id so seeded workers
 * still hold pairwise-distinct buffers under the fixed and rotating
 * modes. The generator is splitmix64: a few lines in any language,
 * which is why it is the one every binding uses.
 */
fun seedWorker(seed: Long, workerId: Int): Long = seed + workerId + 1

private fun splitmix64(rng: Rng): Long {
    rng.state += -0x61c8864680b583ebL // 0x9E3779B97F4A7C15
    var z = rng.state
    z = (z xor (z ushr 30)) * -0x40a7b892e31b1a47L // 0xBF58476D1CE4E5B9
    z = (z xor (z ushr 27)) * -0x6b2fb644ecceee15L // 0x94D049BB133111EB
    return z xor (z ushr 31)
}

/**
 * Fills [buf] from the operating-system CSPRNG.
 *
 * Kotlin-specific. The JDK's default `SecureRandom` provider on this
 * platform draws from `/dev/urandom` through a file descriptor rather
 * than through the glibc `getrandom` entry, and the platform offers no
 * supported way for a JVM source set to reach that entry — a native
 * declaration of its own is exactly the reach past the binding the
 * utility must not make. One draw still happens per fill; it is
 * observable as a read on that descriptor rather than as a
 * `getrandom` call.
 */
fun fillRandom(buf: ByteArray): Boolean {
    CSPRNG.get().nextBytes(buf)
    return true
}

/**
 * Writes one plaintext buffer according to the payload mode. The fixed
 * and rotating modes draw from the seeded generator when the run is
 * seeded and from the OS CSPRNG otherwise; the pattern modes are
 * deterministic regardless of the seed. False when the CSPRNG fails.
 */
fun fillPayload(mode: PayloadMode, seeded: Boolean, rng: Rng, buf: ByteArray): Boolean {
    when (mode) {
        PayloadMode.Fixed, PayloadMode.Rotating -> {
            if (!seeded) {
                return fillRandom(buf)
            }
            var i = 0
            while (i < buf.size) {
                val v = splitmix64(rng)
                val n = minOf(8, buf.size - i)
                for (k in 0 until n) {
                    buf[i + k] = (v ushr (8 * k)).toByte()
                }
                i += 8
            }
        }
        PayloadMode.PatternZero -> buf.fill(0)
        PayloadMode.PatternFf -> buf.fill(0xFF.toByte())
        PayloadMode.PatternAscii -> for (i in buf.indices) {
            buf[i] = ('A'.code + (i % 26)).toByte()
        }
    }
    return true
}
