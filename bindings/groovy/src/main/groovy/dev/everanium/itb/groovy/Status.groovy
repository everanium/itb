// Status codes mirrored from the libitb C ABI. Numeric values are
// stable across releases; the Java binding surfaces them unchanged.

package dev.everanium.itb.groovy

import groovy.transform.CompileStatic

/** Structural status code carried by every failing libitb call. */
@CompileStatic
enum Status {
    OK(0),
    BAD_HASH(1),
    BAD_KEY_BITS(2),
    BAD_HANDLE(3),
    BAD_INPUT(4),
    BUFFER_TOO_SMALL(5),
    ENCRYPT_FAILED(6),
    DECRYPT_FAILED(7),
    SEED_WIDTH_MIX(8),
    BAD_MAC(9),
    MAC_FAILURE(10),
    BLOB_MALFORMED_RECIPE(11),
    RECIPE_PRIMITIVE_UNKNOWN(12),
    UNKNOWN_PROFILE(13),
    BLOB_MODE_MISMATCH(19),
    BLOB_MALFORMED(20),
    BLOB_VERSION_TOO_NEW(21),
    BLOB_TOO_MANY_OPTS(22),
    STREAM_TRUNCATED(23),
    STREAM_AFTER_FINAL(24),
    TRIPLE_CLOSED(25),
    PROFILE_EXISTS(26),
    INTERNAL(99)

    /** The numeric ABI code. */
    final int code

    Status(int code) {
        this.code = code
    }

    private static final Map<Integer, Status> BY_CODE =
            values().collectEntries { [(it.code): it] } as Map<Integer, Status>

    /**
     * Maps a raw libitb return code to the enum; codes without a
     * named constant (reserved ranges, future additions) map to
     * {@link #INTERNAL} — the raw code stays available on the
     * {@link ItbException} that carries it.
     */
    static Status fromCode(int code) {
        BY_CODE.getOrDefault(code, INTERNAL)
    }
}
