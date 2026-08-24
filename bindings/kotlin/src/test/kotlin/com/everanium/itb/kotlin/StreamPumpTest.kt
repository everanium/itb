// InputStream -> OutputStream pump round trips (encrypt + decrypt
// sides) over the Streaming AEAD profile.

package com.everanium.itb.kotlin

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertTrue

class StreamPumpTest {

    @Test
    fun pumpRoundTrip() {
        Pipeline.init("streaming-aead-triple-mac-v1").use { sender ->
            Pipeline.open("streaming-aead-triple-mac-v1", sender.blob).use { receiver ->
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
    fun pumpEmptySource() {
        Pipeline.init("streaming-noaead-triple-v1").use { sender ->
            Pipeline.open("streaming-noaead-triple-v1", sender.blob).use { receiver ->
                val wireSink = ByteArrayOutputStream()
                sender.encryptStreamPump(ByteArrayInputStream(ByteArray(0)), wireSink)
                val wire = wireSink.toByteArray()
                assertTrue(wire.isNotEmpty())

                val plainSink = ByteArrayOutputStream()
                receiver.decryptStreamPump(ByteArrayInputStream(wire), plainSink)
                assertContentEquals(ByteArray(0), plainSink.toByteArray())
            }
        }
    }
}
