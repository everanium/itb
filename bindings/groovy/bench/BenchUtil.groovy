// Shared timing + reporting helpers for the Groovy binding
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

package dev.everanium.itb.groovy.bench

import groovy.transform.CompileStatic

import java.security.SecureRandom

import dev.everanium.itb.groovy.Opts

@CompileStatic
final class BenchUtil {

    /** Iteration floor per case. */
    private static final int MIN_ITERS = 3

    /** Payload sizes exercised by both shapes. */
    static final List<Integer> SIZES = [1 << 20, 16 << 20, 64 << 20]

    private BenchUtil() {
    }

    private static String env(String name) {
        String v = System.getenv(name)
        (v == null || v.isEmpty()) ? null : v
    }

    static double minSeconds() {
        String v = env('ITB_BENCH_MIN_SEC')
        if (v != null && v.isDouble() && v.toDouble() > 0.0d) {
            return v.toDouble()
        }
        5.0d
    }

    /** Reads the bench-shape env vars and builds an {@link Opts}.
     * Defaults match root Go BENCH3.md so numbers are directly
     * comparable. */
    static Opts buildOpts() {
        Opts opts = new Opts()
                .withNonceBits(envLong('ITB_NONCE_BITS', 512L))
                .withKeyBits(envLong('ITB_KEY_BITS', 1024L))
                .withParallax(envBool('ITB_WITH_PARALLAX'))
                .withWrapper(envBool('ITB_WITH_WRAPPER'))
        String hash = env('ITB_INNER_HASH')
        opts = hash == null ? opts : opts.withInnerHash(hash)
        String macName = env('ITB_MAC_NAME')
        macName == null ? opts : opts.withMacName(macName)
    }

    static String profileName(String fallback) {
        env('ITB_PROFILE') ?: fallback
    }

    static void header() {
        println String.format('%-17s %-8s mb_per_sec', 'bench', 'size')
    }

    private static String sizeLabel(int size) {
        size >= (1 << 20) ? "${size >> 20} MiB" : "${size >> 10} KiB"
    }

    /** Runs {@code run} until the wall-clock budget is spent (with an
     * iteration floor + one untimed warm-up), then prints one table
     * row. */
    static void benchCase(String name, int size, Closure<?> run) {
        run.call() // warm-up
        double budget = minSeconds()
        long start = System.nanoTime()
        long iters = 0L
        while ((System.nanoTime() - start) / 1e9d < budget || iters < MIN_ITERS) {
            run.call()
            iters++
        }
        double elapsed = (System.nanoTime() - start) / 1e9d
        double mb = ((double) size) * iters / (1024.0d * 1024.0d)
        println String.format('%-17s %-8s %.1f', name, sizeLabel(size), mb / elapsed)
    }

    /** CSPRNG-filled payload so plaintext content matches the root Go
     * bench (crypto/rand). Never inside the timing loop. */
    static byte[] payload(int n) {
        byte[] buf = new byte[n]
        new SecureRandom().nextBytes(buf)
        buf
    }

    private static long envLong(String name, long fallback) {
        String v = env(name)
        (v != null && v.isLong()) ? v.toLong() : fallback
    }

    private static boolean envBool(String name) {
        String v = env(name)
        v == 'true' || v == '1'
    }
}
