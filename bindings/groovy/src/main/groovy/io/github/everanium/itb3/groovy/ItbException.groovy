// Unchecked exception carrying the libitb3 status code plus the
// diagnostic captured by the Java binding immediately after the
// failing call.

package io.github.everanium.itb3.groovy

import groovy.transform.CompileStatic

import io.github.everanium.itb3.ItbException as JItbException

/**
 * Thrown by every binding call that receives a non-OK status from
 * libitb3.
 *
 * <p>{@code status} carries the structural code; {@code rawCode} is
 * the raw integer, preserved even when it has no named {@link Status}
 * constant. The textual message embeds the process-global
 * {@code ITB_LastError} diagnostic (last-write-wins — under
 * concurrent use the text may belong to a different call; the status
 * code is always attributable to the immediate return).</p>
 */
@CompileStatic
class ItbException extends RuntimeException {

    /** The mapped status code. */
    final Status status

    /** The raw ABI code as returned by libitb3 (identical to
     * {@code status.code} unless the code was unknown). */
    final int rawCode

    private ItbException(Status status, int rawCode, String message) {
        super(message)
        this.status = status
        this.rawCode = rawCode
    }

    /** Converts the Java binding's exception, preserving the raw
     * code. */
    protected static ItbException from(JItbException e) {
        new ItbException(Status.fromCode(e.rawCode()), e.rawCode(),
                e.message ?: "itb: status=${e.rawCode()}".toString())
    }

    /** Runs {@code body}, mapping the Java binding's exception into
     * this binding's exception type. Non-ITB exceptions propagate. */
    protected static <T> T relay(Closure<T> body) {
        try {
            body.call()
        } catch (JItbException e) {
            throw from(e)
        }
    }
}
