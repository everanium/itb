// Caller-driven incremental sessions with pathological batch sizes,
// exercised through the `encrypting` / `decrypting` scope helpers
// and the parent-pin invariant.

package com.everanium.itb.kotlin

import java.io.ByteArrayOutputStream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue

class StreamIncrementalTest {

    @Test
    fun oddBatchSizesRoundTrip() {
        Pipeline.init("streaming-aead-triple-mac-v1").use { sender ->
            Pipeline.load(sender.save()).use { receiver ->
                val plain = ByteArray(200_003) { (it * 131 % 241).toByte() }

                // Feed in deliberately awkward batches: 1, 2, 3, 5, 7,
                // 1009, 65537-byte slices in rotation.
                val batches = intArrayOf(1, 2, 3, 5, 7, 1009, 65_537)
                val wire = sender.encrypting { session ->
                    assertSame(sender, session.parent)
                    var off = 0
                    var i = 0
                    while (off < plain.size) {
                        val n = minOf(batches[i % batches.size], plain.size - off)
                        session.write(plain, off, n)
                        off += n
                        i++
                    }
                    val sink = ByteArrayOutputStream()
                    session.copyTo(sink)
                    sink.toByteArray()
                }
                assertTrue(wire.size > plain.size)

                // Drain the decrypt side with a deliberately tiny read
                // buffer so partial drains are exercised.
                val back = receiver.decrypting { session ->
                    assertSame(receiver, session.parent)
                    session.write(wire)
                    session.end()
                    val sink = ByteArrayOutputStream(plain.size)
                    val buf = ByteArray(4093)
                    while (true) {
                        val r = session.read(buf)
                        if (r.count > 0) {
                            sink.write(buf, 0, r.count)
                        }
                        if (r.finished) {
                            break
                        }
                    }
                    sink.toByteArray()
                }
                assertContentEquals(plain, back)
            }
        }
    }
}
