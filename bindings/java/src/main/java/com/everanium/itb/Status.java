// Status codes mirrored from the libitb C ABI
// (cmd/cshared/internal/capi/errors.go). Numeric values are stable
// across releases.

package com.everanium.itb;

/** Integer status code returned by every libitb entry point. */
public enum Status {
    OK(0, "ok"),
    BAD_HASH(1, "unknown hash name"),
    BAD_KEY_BITS(2, "invalid key bits"),
    BAD_HANDLE(3, "invalid handle"),
    BAD_INPUT(4, "invalid input"),
    BUFFER_TOO_SMALL(5, "output buffer too small"),
    ENCRYPT_FAILED(6, "encrypt failed"),
    DECRYPT_FAILED(7, "decrypt failed"),
    SEED_WIDTH_MIX(8, "seed width mismatch"),
    BAD_MAC(9, "unknown MAC name or invalid MAC handle"),
    MAC_FAILURE(10, "MAC verification failed"),
    RESERVED_11(11, "reserved status"),
    RESERVED_12(12, "reserved status"),
    RESERVED_13(13, "reserved status"),
    RESERVED_14(14, "reserved status"),
    RESERVED_15(15, "reserved status"),
    RESERVED_16(16, "reserved status"),
    RESERVED_17(17, "reserved status"),
    BLOB_MODE_MISMATCH(19, "blob mode mismatch"),
    BLOB_MALFORMED(20, "malformed state blob"),
    BLOB_VERSION_TOO_NEW(21, "blob version too new"),
    BLOB_TOO_MANY_OPTS(22, "too many blob export opts"),
    STREAM_TRUNCATED(23, "stream truncated before terminator"),
    STREAM_AFTER_FINAL(24, "stream chunk after terminator"),
    TRIPLE_CLOSED(25, "Triple Pipeline is closed"),
    PROFILE_EXISTS(26, "profile name already registered"),
    INTERNAL(99, "internal error");

    private final int code;
    private final String label;

    Status(int code, String label) {
        this.code = code;
        this.label = label;
    }

    /** The numeric ABI code. */
    public int code() {
        return code;
    }

    /** Short human-readable label for the code. */
    public String label() {
        return label;
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
