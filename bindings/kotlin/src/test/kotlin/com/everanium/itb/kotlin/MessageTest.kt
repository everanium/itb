// Single Message edge shapes: empty plaintext, binary payload, and
// the Result-returning variants.

package com.everanium.itb.kotlin

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class MessageTest {

    @Test
    fun emptyAndBinaryPayloadsRoundTrip() {
        Pipeline.init("singlemsg-triple-mac-v1").use { sender ->
            Pipeline.open("singlemsg-triple-mac-v1", sender.blob).use { receiver ->
                // Zero-length plaintext produces a valid wire.
                val emptyWire = sender.encryptMessage(ByteArray(0))
                assertTrue(emptyWire.isNotEmpty())
                assertContentEquals(ByteArray(0), receiver.decryptMessage(emptyWire))

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
}
