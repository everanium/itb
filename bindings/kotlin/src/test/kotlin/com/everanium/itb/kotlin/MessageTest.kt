// Single Message edge shapes: empty-input rejection, binary
// payload round trip, and the Result-returning variants.

package com.everanium.itb.kotlin

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class MessageTest {

    @Test
    fun emptyPlaintextIsRejectedWithBadInput() {
        // Empty input has no cover story in any cryptographic
        // construction (see triple/doc.go): every Pipeline cipher
        // entry point rejects nil / zero-length plaintext uniformly
        // with StatusBadInput before any wire is produced. Callers
        // who need an empty signal send a marker byte instead.
        Pipeline.init("singlemsg-triple-mac-v1").use { sender ->
            Pipeline.open("singlemsg-triple-mac-v1", sender.blob).use { receiver ->
                val encEx = assertFailsWith<ItbException> {
                    sender.encryptMessage(ByteArray(0))
                }
                assertEquals(Status.BadInput, encEx.status)

                // The symmetric decrypt-side rejection: no
                // zero-length wire is ever produced, so an empty
                // wire is rejected before any parse.
                val decEx = assertFailsWith<ItbException> {
                    receiver.decryptMessage(ByteArray(0))
                }
                assertEquals(Status.BadInput, decEx.status)
            }
        }
    }

    @Test
    fun binaryPayloadRoundTrip() {
        Pipeline.init("singlemsg-triple-mac-v1").use { sender ->
            Pipeline.open("singlemsg-triple-mac-v1", sender.blob).use { receiver ->
                // Full byte-value coverage.
                val plain = ByteArray(4096) { (it % 256).toByte() }
                assertContentEquals(plain, receiver.decryptMessage(sender.encryptMessage(plain)))
            }
        }
    }

    @Test
    fun resultVariantsCarryStatus() {
        Pipeline.init("singlemsg-triple-mac-v1").use { sender ->
            Pipeline.open("singlemsg-triple-mac-v1", sender.blob).use { receiver ->
                val plain = "railway-style payload".encodeToByteArray()
                val wire = sender.encryptMessageCatching(plain).getOrThrow()
                val ok = receiver.decryptMessageCatching(wire)
                assertNull(ok.itbStatus)
                assertContentEquals(plain, ok.getOrThrow())

                // Garbage wire fails as a captured ItbException with a
                // non-OK sealed status.
                val bad = receiver.decryptMessageCatching(ByteArray(64) { 0x5A })
                assertTrue(bad.isFailure)
                val status = bad.itbStatus
                assertTrue(status != null && status != Status.Ok, "expected non-OK status, got $status")
            }
        }
    }

    @Test
    fun oneShotStreamRoundTrip() {
        Pipeline.init("streaming-aead-triple-mac-v1").use { sender ->
            Pipeline.open("streaming-aead-triple-mac-v1", sender.blob).use { receiver ->
                val plain = ByteArray(100_000) { (it * 31 % 251).toByte() }
                val wire = sender.encryptStreamOneShot(plain)
                assertContentEquals(plain, receiver.decryptStreamOneShot(wire))
            }
        }
    }

    @Test
    fun statusMappingIsStable() {
        assertEquals(Status.MacFailure, Status.fromCode(10))
        assertEquals(Status.TripleClosed, Status.fromCode(25))
        assertEquals(Status.Internal, Status.fromCode(99))
        val unknown = Status.fromCode(42)
        assertTrue(unknown is Status.Unknown)
        assertEquals(42, unknown.code)
    }

    @Test
    fun optsInnerHashesOverrideRoundTripsOnWidth512Profile() {
        // Per-call Opts.MixedHashes override over a width-512 shipped
        // base profile; both sides pass the same 8-slot constellation
        // so the receiver Pipeline resolves the same mixed inner-hash
        // bundle as the sender.
        val mix = opts {
            innerHashes(
                "areion512", "blake2b512", "areion512", "blake2b512",
                "areion512", "blake2b512", "areion512", "blake2b512",
            )
        }
        Pipeline.init("singlemsg-triple-mac-v1", mix).use { sender ->
            Pipeline.open("singlemsg-triple-mac-v1", sender.blob, mix).use { receiver ->
                val plain = ByteArray(4096) { (it * 31 % 251).toByte() }
                assertContentEquals(plain, receiver.decryptMessage(sender.encryptMessage(plain)))
            }
        }
    }
}
