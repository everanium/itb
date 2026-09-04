// Init -> save -> load -> encryptMessage -> decryptMessage round trip.

package com.everanium.itb.kotlin

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SmokeTest {

    @Test
    fun smokeRoundTrip() {
        Pipeline.init("singlemsg-triple-mac-v1").use { sender ->
            assertTrue(sender.save().isNotEmpty())

            Pipeline.load(sender.save()).use { receiver ->
                val plain = "smoke round-trip payload".encodeToByteArray()
                val wire = sender.encryptMessage(plain)
                assertFalse(plain.contentEquals(wire))

                assertContentEquals(plain, receiver.decryptMessage(wire))
            }
        }
    }

    @Test
    fun withPipelineScopesTheSession() {
        val plain = "scoped-session payload".encodeToByteArray()
        // The pipeline handle is released on scope exit; the captured
        // wire still decrypts against the captured blob.
        val (blob, wire) = withPipeline("singlemsg-triple-mac-v1") { pipe ->
            Pair(pipe.save(), pipe.encryptMessage(plain))
        }
        Pipeline.load(blob).use { receiver ->
            assertContentEquals(plain, receiver.decryptMessage(wire))
        }
    }
}
