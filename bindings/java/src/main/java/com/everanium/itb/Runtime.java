// Process-wide Go runtime knobs plus the library version string.

package com.everanium.itb;

/** Static accessors for the libitb process-wide runtime surface. */
public final class Runtime {

    /** The binding's own version. */
    public static final String BINDING_VERSION = "0.3.4";

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

    /** Returns the libitb library version string. */
    public static String version() {
        return Native.readCString(Native::version);
    }
}
