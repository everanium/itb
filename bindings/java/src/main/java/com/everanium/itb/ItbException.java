// Unchecked exception carrying the libitb status code plus the
// ITB_LastError diagnostic captured immediately after the failing
// call.

package com.everanium.itb;

/**
 * Thrown by every binding call that receives a non-OK status from
 * libitb.
 *
 * <p>The textual diagnostic is the process-global {@code ITB_LastError}
 * message (last-write-wins — under concurrent FFI use the message may
 * belong to a different call; the status code is always attributable
 * to the immediate return).</p>
 */
public final class ItbException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final Status status;
    private final int rawCode;

    private ItbException(Status status, int rawCode, String message) {
        super(message);
        this.status = status;
        this.rawCode = rawCode;
    }

    /** The mapped status code. */
    public Status status() {
        return status;
    }

    /** The raw ABI code as returned by libitb (identical to
     * {@code status().code()} unless the code was unknown). */
    public int rawCode() {
        return rawCode;
    }

    /** Builds an exception from a raw return code, pulling the
     * ITB_LastError diagnostic at construction time. */
    static ItbException of(int rc) {
        Status status = Status.fromCode(rc);
        String detail = Native.readLastError();
        String message = "itb: status=" + rc + " (" + status.label() + ")"
                + (detail.isEmpty() ? "" : ": " + detail);
        return new ItbException(status, rc, message);
    }

    /** Throws when {@code rc} is not OK. */
    static void check(int rc) {
        if (rc != Status.OK.code()) {
            throw of(rc);
        }
    }
}
