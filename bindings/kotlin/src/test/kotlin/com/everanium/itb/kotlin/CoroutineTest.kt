// Coroutine variants: async Single Message round trip, concurrent
// encrypts on one Pipeline, and the async pump pair.

package com.everanium.itb.kotlin

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking

class CoroutineTest {

    @Test
    fun asyncMessageRoundTrip() = runBlocking {
        Pipeline.init("singlemsg-triple-mac-v1").use { sender ->
            Pipeline.open("singlemsg-triple-mac-v1", sender.blob).use { receiver ->
                val plain = "suspend-path payload".encodeToByteArray()
                val wire = sender.encryptMessageAsync(plain)
                assertContentEquals(plain, receiver.decryptMessageAsync(wire))
            }
        }
    }

    @Test
    fun concurrentEncryptsOnOnePipeline() = runBlocking {
        // The Go-side Pipeline is concurrent-safe for cipher calls;
        // launch several encrypts in flight at once and decrypt each.
        Pipeline.init("singlemsg-triple-mac-v1").use { sender ->
            Pipeline.open("singlemsg-triple-mac-v1", sender.blob).use { receiver ->
                val payloads = (0 until 8).map { i ->
                    ByteArray(10_000) { j -> ((i * 7 + j) % 251).toByte() }
                }
                val wires = payloads.map { p ->
                    async { sender.encryptMessageAsync(p) }
                }.awaitAll()
                wires.forEachIndexed { i, wire ->
                    assertContentEquals(payloads[i], receiver.decryptMessage(wire))
                }
            }
        }
    }

    @Test
    fun asyncPumpRoundTrip() = runBlocking {
        Pipeline.init("streaming-aead-triple-mac-v1").use { sender ->
            Pipeline.open("streaming-aead-triple-mac-v1", sender.blob).use { receiver ->
                val plain = ByteArray(300_000) { (it * 17 % 249).toByte() }
                val wireSink = ByteArrayOutputStream()
                sender.encryptStreamPumpAsync(ByteArrayInputStream(plain), wireSink)
                val plainSink = ByteArrayOutputStream()
                receiver.decryptStreamPumpAsync(
                    ByteArrayInputStream(wireSink.toByteArray()), plainSink)
                assertContentEquals(plain, plainSink.toByteArray())
            }
        }
    }
}
