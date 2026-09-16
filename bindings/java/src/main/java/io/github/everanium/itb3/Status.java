// Status codes mirrored from the libitb3 C ABI
// (cmd/cshared/internal/capi/errors.go). Numeric values are stable
// across releases. The enum is the structural code only: the human
// wording of a failure arrives already composed in the library's own
// diagnostic, so no wording is restated here.

package io.github.everanium.itb3;

/** Integer status code returned by every libitb3 entry point. */
public enum Status {
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
    RESERVED_14(14),
    RESERVED_15(15),
    RESERVED_16(16),
    RESERVED_17(17),
    BLOB_MODE_MISMATCH(19),
    BLOB_MALFORMED(20),
    BLOB_VERSION_TOO_NEW(21),
    BLOB_TOO_MANY_OPTS(22),
    STREAM_TRUNCATED(23),
    STREAM_AFTER_FINAL(24),
    TRIPLE_CLOSED(25),
    PROFILE_EXISTS(26),
    INTERNAL(99);

    private final int code;

    Status(int code) {
        this.code = code;
    }

    /** The numeric ABI code. */
    public int code() {
        return code;
    }

    /** Maps a raw ABI code onto the enum; an unknown code maps to
     * {@link #INTERNAL} (the raw value stays available on the
     * {@link ItbException} that carries it). */
    public static Status fromCode(int code) {
        for (Status s : values()) {
            if (s.code == code) {
                return s;
            }
        }
        return INTERNAL;
    }
}
