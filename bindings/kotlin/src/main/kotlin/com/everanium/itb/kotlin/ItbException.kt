// Exception type shared by every fallible call in the binding.

package com.everanium.itb.kotlin

import com.everanium.itb.ItbException as JItbException

/**
 * Raised when libitb returns a non-OK status. [status] carries the
 * structural code as a sealed [Status]; the message appends the
 * `ITB_LastError` diagnostic captured by the Java layer immediately
 * after the failing call (process-global last-write-wins — the
 * message may belong to a different call under concurrent use; the
 * status code is always attributable).
 */
class ItbException(
    val status: Status,
    message: String? = null,
    cause: Throwable? = null,
) : Exception(format(status, message), cause) {

    private companion object {
        fun format(status: Status, message: String?): String =
            if (message.isNullOrEmpty()) "itb: status=${status.code} ($status)"
            else message
    }
}

/**
 * Runs [block], translating the Java binding's exception into the
 * Kotlin [ItbException] with its sealed [Status]. The raw ABI code
 * is used for the mapping so a code outside the known roster
 * surfaces as [Status.Unknown] rather than collapsing to
 * [Status.Internal].
 */
internal inline fun <T> itbCall(block: () -> T): T =
    try {
        block()
    } catch (e: JItbException) {
        throw ItbException(Status.fromCode(e.rawCode()), e.message, e)
    }
