// InputStream -> OutputStream pump round trips (encrypt + decrypt
// sides) over the Streaming AEAD profile, plus the empty-source
// rejection contract shared with the Single Message shape.

package com.everanium.itb.kotlin

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class StreamPumpTest {

    @Test
    fun pumpRoundTrip() {
        Pipeline.init("streaming-aead-triple-mac-v1").use { sender ->
            Pipeline.load(sender.save()).use { receiver ->
                val plain = Random(7).nextBytes(1 shl 20)

                val wireSink = ByteArrayOutputStream(plain.size + plain.size / 4 + 131_072)
                sender.encryptStreamPump(ByteArrayInputStream(plain), wireSink)
                val wire = wireSink.toByteArray()
                assertTrue(wire.size > plain.size)

                val plainSink = ByteArrayOutputStream(plain.size)
                receiver.decryptStreamPump(ByteArrayInputStream(wire), plainSink)
                assertContentEquals(plain, plainSink.toByteArray())
            }
        }
    }

    @Test
    fun pumpEmptySourceIsRejectedWithBadInput() {
        // Empty plaintext stream has no cover story in any
        // cryptographic construction (see triple/doc.go): the
        // encrypt pump is rejected uniformly with StatusBadInput
        // before any wire is produced. Callers who need an empty
        // signal send a marker byte instead.
        Pipeline.init("streaming-noaead-triple-v1").use { sender ->
            val wireSink = ByteArrayOutputStream()
            val ex = assertFailsWith<ItbException> {
                sender.encryptStreamPump(ByteArrayInputStream(ByteArray(0)), wireSink)
            }
            assertEquals(Status.BadInput, ex.status)
            assertTrue(
                wireSink.size() == 0,
                "no wire bytes should have been emitted, got ${wireSink.size()}",
            )
        }
    }
}
