// Status codes mirrored from the libitb C ABI
// (cmd/cshared/internal/capi/errors.go), modelled as a sealed class
// so `when` matches are exhaustive without an `else` branch on the
// known roster. Numeric values are stable across releases.

package com.everanium.itb.kotlin

/**
 * Integer status code returned by every libitb entry point, surfaced
 * through the Java binding and re-modelled as a Kotlin sealed
 * hierarchy. Every known code is a singleton object; a code outside
 * the roster (a future libitb release) maps to [Unknown] instead of
 * failing.
 */
sealed class Status(val code: Int) {
    object Ok : Status(0)
    object BadHash : Status(1)
    object BadKeyBits : Status(2)
    object BadHandle : Status(3)
    object BadInput : Status(4)
    object BufferTooSmall : Status(5)
    object EncryptFailed : Status(6)
    object DecryptFailed : Status(7)
    object SeedWidthMix : Status(8)
    object BadMac : Status(9)
    object MacFailure : Status(10)
    object BlobMalformedRecipe : Status(11)
    object RecipePrimitiveUnknown : Status(12)
    object UnknownProfile : Status(13)
    object Reserved14 : Status(14)
    object Reserved15 : Status(15)
    object Reserved16 : Status(16)
    object Reserved17 : Status(17)
    object BlobModeMismatch : Status(19)
    object BlobMalformed : Status(20)
    object BlobVersionTooNew : Status(21)
    object BlobTooManyOpts : Status(22)
    object StreamTruncated : Status(23)
    object StreamAfterFinal : Status(24)
    object TripleClosed : Status(25)
    object ProfileExists : Status(26)
    object Internal : Status(99)

    /** A code outside the known roster (future libitb release). */
    class Unknown internal constructor(code: Int) : Status(code) {
        override fun equals(other: Any?): Boolean =
            other is Unknown && other.code == code

        override fun hashCode(): Int = code
    }

    override fun toString(): String = when (this) {
        is Unknown -> "Unknown($code)"
        else -> "${javaClass.simpleName}($code)"
    }

    companion object {
        /** Maps a raw libitb status code to its sealed value. */
        fun fromCode(code: Int): Status = when (code) {
            0 -> Ok
            1 -> BadHash
            2 -> BadKeyBits
            3 -> BadHandle
            4 -> BadInput
            5 -> BufferTooSmall
            6 -> EncryptFailed
            7 -> DecryptFailed
            8 -> SeedWidthMix
            9 -> BadMac
            10 -> MacFailure
            11 -> BlobMalformedRecipe
            12 -> RecipePrimitiveUnknown
            13 -> UnknownProfile
            14 -> Reserved14
            15 -> Reserved15
            16 -> Reserved16
            17 -> Reserved17
            19 -> BlobModeMismatch
            20 -> BlobMalformed
            21 -> BlobVersionTooNew
            22 -> BlobTooManyOpts
            23 -> StreamTruncated
            24 -> StreamAfterFinal
            25 -> TripleClosed
            26 -> ProfileExists
            99 -> Internal
            else -> Unknown(code)
        }
    }
}
