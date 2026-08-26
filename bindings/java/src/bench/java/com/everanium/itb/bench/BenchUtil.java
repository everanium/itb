// Shared timing + reporting helpers for the Java binding
// micro-benchmarks. Wall-clock via System.nanoTime(); output is a
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

package com.everanium.itb.bench;

import com.everanium.itb.Opts;
import java.util.Locale;

final class BenchUtil {

    /** Iteration floor per case. */
    private static final int MIN_ITERS = 3;

    /** Payload sizes exercised by both shapes. */
    static final int[] SIZES = {1 << 20, 16 << 20, 64 << 20};

    private BenchUtil() {
    }

    static double minSeconds() {
        String raw = System.getenv("ITB_BENCH_MIN_SEC");
        if (raw != null && !raw.isEmpty()) {
            try {
                double v = Double.parseDouble(raw);
                if (v > 0.0) {
                    return v;
                }
            } catch (NumberFormatException ignored) {
                // fall through to the default
            }
        }
        return 5.0;
    }

    /** Reads the bench-shape env vars and builds an {@link Opts}.
     * Defaults match root Go BENCH3.md so numbers are directly
     * comparable. */
    static Opts buildOpts() {
        Opts opts = new Opts()
                .withNonceBits(envLong("ITB_NONCE_BITS", 512))
                .withKeyBits(envLong("ITB_KEY_BITS", 1024))
                .withParallax(envBool("ITB_WITH_PARALLAX"))
                .withWrapper(envBool("ITB_WITH_WRAPPER"));
        String innerHash = System.getenv("ITB_INNER_HASH");
        if (innerHash != null && !innerHash.isEmpty()) {
            opts = opts.withInnerHash(innerHash);
        }
        String macName = System.getenv("ITB_MAC_NAME");
        if (macName != null && !macName.isEmpty()) {
            opts = opts.withMacName(macName);
        }
        return opts;
    }

    static String profileName(String fallback) {
        String env = System.getenv("ITB_PROFILE");
        return env == null || env.isEmpty() ? fallback : env;
    }

    static void header() {
        System.out.printf("%-17s %-8s mb_per_sec%n", "bench", "size");
    }

    private static String sizeLabel(int size) {
        return size >= (1 << 20)
                ? (size >> 20) + " MiB"
                : (size >> 10) + " KiB";
    }

    /** Runs {@code run} until the wall-clock budget is spent (with an
     * iteration floor + one untimed warm-up), then prints one table
     * row. */
    static void benchCase(String name, int size, Runnable run) {
        run.run(); // warm-up
        double budget = minSeconds();
        long start = System.nanoTime();
        long iters = 0;
        while ((System.nanoTime() - start) / 1e9 < budget || iters < MIN_ITERS) {
            run.run();
            iters++;
        }
        double elapsed = (System.nanoTime() - start) / 1e9;
        double mb = (double) size * iters / (1024.0 * 1024.0);
        System.out.printf(Locale.ROOT, "%-17s %-8s %.1f%n",
                name, sizeLabel(size), mb / elapsed);
    }

    private static long envLong(String name, long fallback) {
        String raw = System.getenv(name);
        if (raw != null && !raw.isEmpty()) {
            try {
                return Long.parseLong(raw);
            } catch (NumberFormatException ignored) {
                // fall through to the default
            }
        }
        return fallback;
    }

    private static boolean envBool(String name) {
        String raw = System.getenv(name);
        return "true".equals(raw) || "1".equals(raw);
    }
}
