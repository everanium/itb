// Size and duration parsing and the human renderings of sizes, rates
// and durations. Every rendering here is part of the output contract
// shared with the Go harness and the other bindings' loop utilities,
// so the formats are fixed to the character, not to taste.
//
// Groovy-specific. Every formatter names Locale.ROOT explicitly. A
// format string that relies on the ambient default renders "1,5MB/s"
// the day someone runs the harness under a comma-decimal locale, and
// the output contract is byte-for-byte.

package io.github.everanium.itb3.groovy.loop

import groovy.transform.CompileStatic

@CompileStatic
final class Size {

    private Size() {
    }

    /** Suffix table for {@link #parseSize}, matched in order so the
     * longer spellings win over their prefixes. */
    private static final List<String> SIZE_SUFFIXES =
            ['KIB', 'KB', 'K', 'MIB', 'MB', 'M', 'GIB', 'GB', 'G', 'B']

    private static final List<Long> SIZE_MULTS = [
        1L << 10, 1L << 10, 1L << 10,
        1L << 20, 1L << 20, 1L << 20,
        1L << 30, 1L << 30, 1L << 30,
        1L,
    ]

    /**
     * Parses a human byte-size string ("16MB", "1MiB", "512K",
     * "1073741824") into a byte count. Every suffix is a binary
     * multiple: K/KB/KiB = 1024, M/MB/MiB = 1024^2, G/GB/GiB = 1024^3,
     * B or none = bytes; matching is case-insensitive and surrounding
     * whitespace is trimmed. Null on a malformed or negative value.
     */
    static Long parseSize(String s) {
        String upper = s.trim().toUpperCase(Locale.ROOT)
        if (upper.isEmpty()) {
            return null
        }
        long mult = 1L
        String digits = upper
        for (int i = 0; i < SIZE_SUFFIXES.size(); i++) {
            String suffix = SIZE_SUFFIXES[i]
            if (upper.endsWith(suffix)) {
                mult = SIZE_MULTS[i]
                digits = upper.substring(0, upper.length() - suffix.length())
                break
            }
        }
        digits = digits.stripTrailing()
        if (digits.isEmpty()) {
            return null
        }
        for (int i = 0; i < digits.length(); i++) {
            char c = digits.charAt(i)
            if (c < ('0' as char) || c > ('9' as char)) {
                return null
            }
        }
        long n
        try {
            n = Long.parseLong(digits)
        } catch (NumberFormatException e) {
            return null
        }
        try {
            return Math.multiplyExact(n, mult)
        } catch (ArithmeticException e) {
            return null
        }
    }

    /** Unit table for {@link #parseDuration}, matched in order so "ms"
     * wins over "m" followed by a stray "s". */
    private static final List<String> DURATION_UNITS = ['ns', 'us', 'ms', 's', 'm', 'h']

    private static final List<Double> DURATION_NANOS = [1.0d, 1e3d, 1e6d, 1e9d, 60e9d, 3600e9d]

    /**
     * Parses the Go duration grammar — a sequence of decimal numbers
     * each followed by a unit (h, m, s, ms, us, ns), such as "30s",
     * "5m", "1h30m", "1.5s" — into nanoseconds. Null on a malformed
     * string.
     */
    static Long parseDuration(String s) {
        if (s.isEmpty()) {
            return null
        }
        String rest = s
        double total = 0.0d
        while (!rest.isEmpty()) {
            int numLen = 0
            while (numLen < rest.length() &&
                    (isDigit(rest.charAt(numLen)) || rest.charAt(numLen) == ('.' as char))) {
                numLen++
            }
            if (numLen == 0) {
                return null
            }
            double v
            try {
                v = Double.parseDouble(rest.substring(0, numLen))
            } catch (NumberFormatException e) {
                return null
            }
            rest = rest.substring(numLen)
            double nanos = -1.0d
            for (int i = 0; i < DURATION_UNITS.size(); i++) {
                String unit = DURATION_UNITS[i]
                if (!rest.startsWith(unit)) {
                    continue
                }
                String after = rest.substring(unit.length())
                // A unit whose next character is a letter is the prefix
                // of a longer token that is not a unit at all.
                if (!after.isEmpty() && isLetter(after.charAt(0))) {
                    continue
                }
                rest = after
                nanos = DURATION_NANOS[i]
                break
            }
            if (nanos < 0.0d) {
                return null
            }
            total += v * nanos
        }
        if (total > 9.2e18d) {
            return null
        }
        return (long) total
    }

    private static boolean isDigit(char c) {
        c >= ('0' as char) && c <= ('9' as char)
    }

    private static boolean isLetter(char c) {
        (c >= ('a' as char) && c <= ('z' as char)) || (c >= ('A' as char) && c <= ('Z' as char))
    }

    /** Fixed-decimal float rendering, locale-independent. */
    static String f(double v, int decimals) {
        String.format(Locale.ROOT, "%.${decimals}f", v)
    }

    /** Renders a byte count with a binary-unit suffix: "1.0GiB",
     * "16.0MiB", "4.0KiB", "512B". */
    static String humanBytes(long n) {
        if (n >= 1L << 30) {
            return f(n / ((double) (1L << 30)), 1) + 'GiB'
        }
        if (n >= 1L << 20) {
            return f(n / ((double) (1L << 20)), 1) + 'MiB'
        }
        if (n >= 1L << 10) {
            return f(n / ((double) (1L << 10)), 1) + 'KiB'
        }
        return "${n}B"
    }

    /** Renders a possibly-negative byte delta with an explicit sign. */
    static String humanBytesSigned(long n) {
        n < 0 ? '-' + humanBytes(-n) : '+' + humanBytes(n)
    }

    /** Binary MiB per second over a nanosecond window; zero when the
     * window is unmeasured. */
    static double mbPerSec(long bytes, long ns) {
        ns <= 0 ? 0.0d : bytes / ((double) (1L << 20)) / (ns / 1e9d)
    }

    /** Renders a throughput as "123.4MB/s" (binary MiB per second) or
     * "n/a" for an unmeasured window. */
    static String humanRate(long bytes, long ns) {
        ns <= 0 ? 'n/a' : f(mbPerSec(bytes, ns), 1) + 'MB/s'
    }

    /** The fractional part of a nanosecond remainder (0 .. 1e9) as
     * ".ddd" with trailing zeros removed; empty for zero. */
    private static String fraction(long fracNs) {
        if (fracNs == 0L) {
            return ''
        }
        String d = String.format(Locale.ROOT, '%09d', fracNs)
        int end = d.length()
        while (end > 0 && d.charAt(end - 1) == ('0' as char)) {
            end--
        }
        return '.' + d.substring(0, end)
    }

    /**
     * Renders a duration the way Go's {@code time.Duration} prints:
     * zero as "0s"; below one second as milliseconds ("900ms",
     * "1.5ms"); otherwise "[Hh][Mm]Ss" where the hour part appears
     * when non-zero, the minute part when the hour part appears or the
     * minutes are non-zero, and the seconds carry their fraction with
     * trailing zeros removed ("5s", "5.003s", "1m0s", "1m5.25s",
     * "1h0m0s"). The caller rounds first.
     */
    static String humanDuration(long nanos) {
        long ns = Math.abs(nanos)
        if (ns == 0L) {
            return '0s'
        }
        if (ns < 1_000_000_000L) {
            long ms = ns.intdiv(1_000_000L)
            long msFrac = (ns % 1_000_000L) * 1000L // scaled to 9 digits
            return "${ms}${fraction(msFrac)}ms"
        }
        long hours = ns.intdiv(3_600_000_000_000L)
        long rem = ns % 3_600_000_000_000L
        long minutes = rem.intdiv(60_000_000_000L)
        rem %= 60_000_000_000L
        long seconds = rem.intdiv(1_000_000_000L)
        long frac = rem % 1_000_000_000L
        StringBuilder sb = new StringBuilder()
        if (hours > 0) {
            sb.append(hours).append('h' as char)
        }
        if (hours > 0 || minutes > 0) {
            sb.append(minutes).append('m' as char)
        }
        sb.append(seconds).append(fraction(frac)).append('s' as char)
        return sb.toString()
    }

    /** Rounds a nanosecond count to the nearest multiple of
     * {@code unitNs}. */
    static long roundTo(long ns, long unitNs) {
        ((long) ((ns + unitNs.intdiv(2)).intdiv(unitNs))) * unitNs
    }
}
