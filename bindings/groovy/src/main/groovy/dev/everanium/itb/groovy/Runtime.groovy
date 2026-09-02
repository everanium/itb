// Process-wide Go runtime knobs plus the library version string.

package dev.everanium.itb.groovy

import groovy.transform.CompileStatic

import com.everanium.itb.Runtime as JRuntime

/**
 * Accessors for the libitb process-wide Go runtime knobs and the
 * library version. The knobs are readable at libitb load time via
 * env vars ({@code ITB_GOMEMLIMIT}, {@code ITB_GOGC}) and adjustable
 * at any time programmatically; a setter wins over the env var.
 */
@CompileStatic
final class Runtime {

    /** The Groovy binding's own version. */
    static final String BINDING_VERSION = '0.3.4'

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

    /** Returns the libitb library version string. */
    static String version() {
        JRuntime.version()
    }
}
