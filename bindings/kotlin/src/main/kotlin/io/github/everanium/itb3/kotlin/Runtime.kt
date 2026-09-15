// Process-wide Go runtime knobs plus the library version string.

package io.github.everanium.itb3.kotlin

import io.github.everanium.itb3.Runtime as JRuntime

/**
 * Accessors for the libitb3 process-wide Go runtime knobs and the
 * library version. Named `ItbRuntime` so unqualified references do
 * not collide with `java.lang.Runtime`.
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

    /** Returns the libitb3 library version string. */
    fun version(): String = JRuntime.version()
}
