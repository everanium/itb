// Process-wide Go runtime knobs, runtime diagnostics, and the
// library version string.

package io.github.everanium.itb3.kotlin

import io.github.everanium.itb3.Runtime as JRuntime

/**
 * Accessors for the libitb3 process-wide Go runtime knobs, its
 * runtime diagnostics, and the library version. Named `ItbRuntime` so
 * unqualified references do not collide with `java.lang.Runtime`.
 */
object ItbRuntime {

    /** The binding's own version. */
    const val BINDING_VERSION: String = "0.5.1"

    /**
     * Sets the Go runtime's soft heap limit in bytes and returns the
     * previous limit. A negative value queries without changing.
     */
    fun setMemoryLimit(bytes: Long): Long = JRuntime.setMemoryLimit(bytes)

    /**
     * Sets the Go GC trigger percentage and returns the previous
     * value. A negative value queries without changing.
     */
    fun setGCPercent(pct: Int): Int = JRuntime.setGCPercent(pct)

    /**
     * Sets the Go runtime's GOMAXPROCS and returns the previous value.
     * Zero or a negative value queries without changing.
     */
    fun setGOMAXPROCS(n: Int): Int = JRuntime.setGOMAXPROCS(n)

    /**
     * Writes the Go runtime's heap profile (pprof format) to [path]
     * after one forced garbage collection. An empty path falls back to
     * the `ITB_MEMPROFILE` environment variable inside libitb3; a path
     * that is still empty, or a file-system failure, fails with
     * [Status.BadInput].
     */
    fun writeHeapProfile(path: String): Unit = itbCall { JRuntime.writeHeapProfile(path) }

    /** The number of `Long` slots [poolStats] fills. */
    fun poolStatsLen(): Int = JRuntime.poolStatsLen()

    /**
     * One snapshot of the library's pool hit / miss counters. Every
     * counter is a monotonically increasing total since library load,
     * so a per-window figure is the difference of two snapshots.
     *
     * Slot layout, with `T` the tier count in slot 0: hash-array tier
     * `i` holds starter width, checkouts, constructor misses, regrow
     * replacements and bytes allocated at slots
     * `1 + 5*i .. 1 + 5*i + 4`; the scratch byte pool's get / new /
     * regrow / regrow-bytes follow at `1 + 5*T`, and the parallax
     * chunk pool's at `1 + 5*T + 4`. The vector is sized from
     * [poolStatsLen], never from a constant — the tier ladder is a
     * library-side policy that grows.
     */
    fun poolStats(): LongArray = itbCall { JRuntime.poolStats() }

    /** Returns the libitb3 library version string. */
    fun version(): String = JRuntime.version()
}
