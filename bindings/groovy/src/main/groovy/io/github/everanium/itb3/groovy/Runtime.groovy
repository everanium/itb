// Process-wide Go runtime knobs, runtime diagnostics, and the
// library version string.

package io.github.everanium.itb3.groovy

import groovy.transform.CompileStatic

import io.github.everanium.itb3.Runtime as JRuntime

/**
 * Accessors for the libitb3 process-wide Go runtime knobs, its
 * runtime diagnostics, and the library version. The knobs are readable at libitb3 load time via
 * env vars ({@code ITB_GOMEMLIMIT}, {@code ITB_GOGC}) and adjustable
 * at any time programmatically; a setter wins over the env var.
 */
@CompileStatic
final class Runtime {

    /** The Groovy binding's own version. */
    static final String BINDING_VERSION = '0.5.1'

    private Runtime() {
    }

    /** Sets the Go runtime's soft heap limit in bytes and returns the
     * previous limit. A negative value queries without changing. */
    static long setMemoryLimit(long bytes) {
        JRuntime.setMemoryLimit(bytes)
    }

    /** Sets the Go GC trigger percentage and returns the previous
     * value. A negative value queries without changing. */
    static int setGCPercent(int pct) {
        JRuntime.setGCPercent(pct)
    }

    /** Sets the Go runtime's GOMAXPROCS and returns the previous
     * value. Zero or a negative value queries without changing. */
    static int setGOMAXPROCS(int n) {
        JRuntime.setGOMAXPROCS(n)
    }

    /**
     * Writes the Go runtime's heap profile (pprof format) to
     * {@code path} after one forced garbage collection. An empty path
     * falls back to the {@code ITB_MEMPROFILE} environment variable
     * inside libitb3; a path that is still empty, or a file-system
     * failure, fails with {@link Status#BAD_INPUT}.
     */
    static void writeHeapProfile(String path) {
        ItbException.relay { JRuntime.writeHeapProfile(path) }
    }

    /** The number of {@code long} slots {@link #poolStats} fills. */
    static int poolStatsLen() {
        JRuntime.poolStatsLen()
    }

    /**
     * One snapshot of the library's pool hit / miss counters. Every
     * counter is a monotonically increasing total since library load,
     * so a per-window figure is the difference of two snapshots.
     *
     * <p>Slot layout, with {@code T} the tier count in slot 0:
     * hash-array tier {@code i} holds starter width, checkouts,
     * constructor misses, regrow replacements and bytes allocated at
     * slots {@code 1 + 5*i .. 1 + 5*i + 4}; the scratch byte pool's
     * get / new / regrow / regrow-bytes follow at {@code 1 + 5*T},
     * and the parallax chunk pool's at {@code 1 + 5*T + 4}. The
     * vector is sized from {@link #poolStatsLen}, never from a
     * constant — the tier ladder is a library-side policy that
     * grows.</p>
     */
    static long[] poolStats() {
        ItbException.relay { JRuntime.poolStats() } as long[]
    }

    /** Returns the libitb3 library version string. */
    static String version() {
        JRuntime.version()
    }
}
