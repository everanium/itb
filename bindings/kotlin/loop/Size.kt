// Size and duration parsing and the human renderings of sizes, rates
// and durations. Every rendering here is part of the output contract
// shared with the Go harness and the other bindings' loop utilities,
// so the formats are fixed to the character, not to taste.
//
// Kotlin-specific. Every formatter names Locale.ROOT explicitly. A
// format string that relies on the ambient default renders "1,5MB/s"
// the day someone runs the harness under a comma-decimal locale, and
// the output contract is byte-for-byte.

package io.github.everanium.itb3.kotlin.loop

import java.util.Locale
import kotlin.math.abs

/** Suffix table for [parseSize], matched in order so the longer
 * spellings win over their prefixes. */
private val SIZE_SUFFIXES = listOf(
    "KIB" to (1L shl 10),
    "KB" to (1L shl 10),
    "K" to (1L shl 10),
    "MIB" to (1L shl 20),
    "MB" to (1L shl 20),
    "M" to (1L shl 20),
    "GIB" to (1L shl 30),
    "GB" to (1L shl 30),
    "G" to (1L shl 30),
    "B" to 1L,
)

/**
 * Parses a human byte-size string ("16MB", "1MiB", "512K",
 * "1073741824") into a byte count. Every suffix is a binary multiple:
 * K/KB/KiB = 1024, M/MB/MiB = 1024^2, G/GB/GiB = 1024^3, B or none =
 * bytes; matching is case-insensitive and surrounding whitespace is
 * trimmed. Null on a malformed or negative value.
 */
fun parseSize(s: String): Long? {
    val upper = s.trim().uppercase(Locale.ROOT)
    if (upper.isEmpty()) {
        return null
    }
    var mult = 1L
    var digits = upper
    for ((suffix, m) in SIZE_SUFFIXES) {
        if (upper.endsWith(suffix)) {
            mult = m
            digits = upper.substring(0, upper.length - suffix.length)
            break
        }
    }
    digits = digits.trimEnd()
    if (digits.isEmpty() || digits.any { it < '0' || it > '9' }) {
        return null
    }
    val n = digits.toLongOrNull() ?: return null
    return try {
        Math.multiplyExact(n, mult)
    } catch (e: ArithmeticException) {
        null
    }
}

/** Unit table for [parseDuration], matched in order so "ms" wins over
 * "m" followed by a stray "s". */
private val DURATION_UNITS = listOf(
    "ns" to 1.0,
    "us" to 1e3,
    "ms" to 1e6,
    "s" to 1e9,
    "m" to 60e9,
    "h" to 3600e9,
)

/**
 * Parses the Go duration grammar — a sequence of decimal numbers each
 * followed by a unit (h, m, s, ms, us, ns), such as "30s", "5m",
 * "1h30m", "1.5s" — into nanoseconds. Null on a malformed string.
 */
fun parseDuration(s: String): Long? {
    if (s.isEmpty()) {
        return null
    }
    var rest = s
    var total = 0.0
    while (rest.isNotEmpty()) {
        var numLen = 0
        while (numLen < rest.length && (rest[numLen] in '0'..'9' || rest[numLen] == '.')) {
            numLen++
        }
        if (numLen == 0) {
            return null
        }
        val v = rest.substring(0, numLen).toDoubleOrNull() ?: return null
        rest = rest.substring(numLen)
        var nanos: Double? = null
        for ((unit, ns) in DURATION_UNITS) {
            if (!rest.startsWith(unit)) {
                continue
            }
            val after = rest.substring(unit.length)
            // A unit whose next character is a letter is the prefix of
            // a longer token that is not a unit at all.
            if (after.isNotEmpty() && after[0].isLetter()) {
                continue
            }
            rest = after
            nanos = ns
            break
        }
        total += v * (nanos ?: return null)
    }
    if (total > 9.2e18) {
        return null
    }
    return total.toLong()
}

/** Fixed-decimal float rendering, locale-independent. */
fun f(v: Double, decimals: Int): String = String.format(Locale.ROOT, "%.${decimals}f", v)

/** Renders a byte count with a binary-unit suffix: "1.0GiB",
 * "16.0MiB", "4.0KiB", "512B". */
fun humanBytes(n: Long): String = when {
    n >= 1L shl 30 -> f(n / (1L shl 30).toDouble(), 1) + "GiB"
    n >= 1L shl 20 -> f(n / (1L shl 20).toDouble(), 1) + "MiB"
    n >= 1L shl 10 -> f(n / (1L shl 10).toDouble(), 1) + "KiB"
    else -> "${n}B"
}

/** Renders a possibly-negative byte delta with an explicit sign. */
fun humanBytesSigned(n: Long): String =
    if (n < 0) "-" + humanBytes(-n) else "+" + humanBytes(n)

/** Binary MiB per second over a nanosecond window; zero when the
 * window is unmeasured. */
fun mbPerSec(bytes: Long, ns: Long): Double =
    if (ns <= 0) 0.0 else bytes / (1L shl 20).toDouble() / (ns / 1e9)

/** Renders a throughput as "123.4MB/s" (binary MiB per second) or
 * "n/a" for an unmeasured window. */
fun humanRate(bytes: Long, ns: Long): String =
    if (ns <= 0) "n/a" else f(mbPerSec(bytes, ns), 1) + "MB/s"

/** The fractional part of a nanosecond remainder (0 .. 1e9) as ".ddd"
 * with trailing zeros removed; empty for zero. */
private fun fraction(fracNs: Long): String {
    if (fracNs == 0L) {
        return ""
    }
    return "." + String.format(Locale.ROOT, "%09d", fracNs).trimEnd('0')
}

/**
 * Renders a duration the way Go's `time.Duration` prints: zero as
 * "0s"; below one second as milliseconds ("900ms", "1.5ms");
 * otherwise "[Hh][Mm]Ss" where the hour part appears when non-zero,
 * the minute part when the hour part appears or the minutes are
 * non-zero, and the seconds carry their fraction with trailing zeros
 * removed ("5s", "5.003s", "1m0s", "1m5.25s", "1h0m0s"). The caller
 * rounds first.
 */
fun humanDuration(nanos: Long): String {
    val ns = abs(nanos)
    if (ns == 0L) {
        return "0s"
    }
    if (ns < 1_000_000_000L) {
        val ms = ns / 1_000_000L
        val msFrac = (ns % 1_000_000L) * 1000L // scaled to 9 digits
        return "$ms${fraction(msFrac)}ms"
    }
    val hours = ns / 3_600_000_000_000L
    var rem = ns % 3_600_000_000_000L
    val minutes = rem / 60_000_000_000L
    rem %= 60_000_000_000L
    val seconds = rem / 1_000_000_000L
    val frac = rem % 1_000_000_000L
    val sb = StringBuilder()
    if (hours > 0) {
        sb.append(hours).append('h')
    }
    if (hours > 0 || minutes > 0) {
        sb.append(minutes).append('m')
    }
    sb.append(seconds).append(fraction(frac)).append('s')
    return sb.toString()
}

/** Rounds a nanosecond count to the nearest multiple of [unitNs]. */
fun roundTo(ns: Long, unitNs: Long): Long = (ns + unitNs / 2) / unitNs * unitNs
