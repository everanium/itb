// Process-wide Go runtime knobs plus the library version string.

package io.github.everanium.itb3;

/** Static accessors for the libitb3 process-wide runtime surface. */
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

    /** Returns the libitb3 library version string. */
    public static String version() {
        return Native.readCString(Native::version);
    }
}
