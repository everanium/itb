// Error-mapping surface: opaque-string relay, destroyed Pipeline,
// duplicate profile registration (with an 8-entry innerHashes
// constellation).

package com.everanium.itb.kotlin

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class ErrorTest {

    @Test
    fun unknownProfileIsBadInputWithDiagnostic() {
        val ex = assertFailsWith<ItbException> { Pipeline.init("no-such-profile") }
        assertEquals(Status.BadInput, ex.status)
        assertFalse(ex.message.isNullOrEmpty())
    }

    @Test
    fun unknownOptsKeyIsBadInput() {
        // Typoed key (lowercase s) — Go rejects unknown keys.
        val bad = opts { raw("chunksize", "4096") }
        val ex = assertFailsWith<ItbException> {
            Pipeline.init("singlemsg-triple-mac-v1", bad)
        }
        assertEquals(Status.BadInput, ex.status)
    }

    @Test
    fun destroyedPipelineReportsTripleClosed() {
        Pipeline.init("singlemsg-triple-mac-v1").use { pipe ->
            pipe.destroy()
            pipe.destroy() // idempotent
            assertTrue(pipe.isDestroyed)
            val ex = assertFailsWith<ItbException> {
                pipe.encryptMessage("payload".encodeToByteArray())
            }
            assertEquals(Status.TripleClosed, ex.status)
        }
    }

    @Test
    fun registerProfileMixedThenDuplicate() {
        // 8-entry width-256 innerHashes constellation, layers off.
        val profile = opts {
            raw("mode", "singlemsg-nomac")
            raw("width", "256")
            raw(
                "innerHashes",
                "blake3,blake2s,areion256,blake2b256,chacha20,blake3,blake2s,areion256",
            )
            raw("keyBits", "1024")
            raw("parallaxOn", "false")
            raw("wrapperOn", "false")
        }
        Pipeline.registerProfile("kotlin-binding-test-mixed", profile)

        // The registered profile round-trips.
        Pipeline.init("kotlin-binding-test-mixed").use { sender ->
            Pipeline.open("kotlin-binding-test-mixed", sender.blob).use { receiver ->
                val plain = "custom profile".encodeToByteArray()
                val wire = sender.encryptMessage(plain)
                assertContentEquals(plain, receiver.decryptMessage(wire))
            }
        }

        // Duplicate name is a distinct status.
        val ex = assertFailsWith<ItbException> {
            Pipeline.registerProfile("kotlin-binding-test-mixed", profile)
        }
        assertEquals(Status.ProfileExists, ex.status)
    }

    @Test
    fun opaquePrimitiveNameRelay() {
        // An unknown inner-hash name is relayed to Go and rejected
        // there — the binding performs no name validation of its own.
        val ex = assertFailsWith<ItbException> {
            Pipeline.init("singlemsg-triple-mac-v1", opts { innerHash("no-such-hash") })
        }
        assertNotEquals(Status.Ok, ex.status)
    }
}
