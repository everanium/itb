// Process-wide Go runtime knobs plus the library version string.

package com.everanium.itb.kotlin

import com.everanium.itb.Runtime as JRuntime

/**
 * Accessors for the libitb process-wide Go runtime knobs and the
 * library version. Named `ItbRuntime` so unqualified references do
 * not collide with `java.lang.Runtime`.
 */
object ItbRuntime {

    /** The binding's own version. */
    const val BINDING_VERSION: String = "0.4.1"

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

    /** Returns the libitb library version string. */
    fun version(): String = JRuntime.version()
}
