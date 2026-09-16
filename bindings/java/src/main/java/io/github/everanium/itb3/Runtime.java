// Process-wide Go runtime knobs, runtime diagnostics, and the library
// version string.

package io.github.everanium.itb3;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/** Static accessors for the libitb3 process-wide Go runtime knobs, its
 * runtime diagnostics, and the library version. */
public final class Runtime {

    /** The binding's own version. */
    public static final String BINDING_VERSION = "0.5.1";

    private Runtime() {
    }

    /** Sets the Go runtime's soft heap limit in bytes and returns the
     * previous limit. A negative value queries without changing. */
    public static long setMemoryLimit(long bytes) {
        return Native.setMemoryLimit(bytes);
    }

    /** Sets the Go GC trigger percentage and returns the previous
     * value. A negative value queries without changing. */
    public static int setGCPercent(int pct) {
        return Native.setGCPercent(pct);
    }

    /** Sets the Go runtime's GOMAXPROCS and returns the previous value.
     * Zero or a negative value queries without changing. */
    public static int setGOMAXPROCS(int n) {
        return Native.setGOMAXPROCS(n);
    }

    /**
     * Writes the Go runtime's heap profile (pprof format) to
     * {@code path} after one forced garbage collection. An empty path
     * falls back to the {@code ITB_MEMPROFILE} environment variable
     * inside libitb3; a path that is still empty, or a file-system
     * failure, throws with {@link Status#BAD_INPUT}.
     */
    public static void writeHeapProfile(String path) {
        ItbException.check(Native.writeHeapProfile(Native.cstr(path)));
    }

    /** The number of {@code long} slots {@link #poolStats()} fills. */
    public static int poolStatsLen() {
        int n = Native.poolStatsLen();
        return n > 0 ? n : 0;
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
     * get / new / regrow / regrow-bytes follow at {@code 1 + 5*T}, and
     * the parallax chunk pool's at {@code 1 + 5*T + 4}. The buffer is
     * sized from {@link #poolStatsLen()}, never from a constant — the
     * tier ladder is a library-side policy that grows.
     */
    public static long[] poolStats() {
        int cap = poolStatsLen();
        if (cap == 0) {
            return new long[0];
        }
        ByteBuffer buf = ByteBuffer.allocateDirect(cap * Long.BYTES)
                .order(ByteOrder.nativeOrder());
        long[] len = new long[1];
        ItbException.check(Native.poolStats(buf, cap, len));
        int n = (int) Math.min(len[0], cap);
        long[] out = new long[n];
        buf.asLongBuffer().get(out, 0, n);
        return out;
    }

    /** Returns the libitb3 library version string. */
    public static String version() {
        return Native.readCString(Native::version);
    }
}
