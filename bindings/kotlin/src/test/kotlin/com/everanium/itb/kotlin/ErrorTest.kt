// Error-mapping surface: opaque-string relay, destroyed Pipeline,
// duplicate profile registration (with an 8-entry mixed
// constellation), unknown lookup, maxWorkers on a destroyed handle.

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
    fun unknownProfileIsUnknownProfileWithDiagnostic() {
        val ex = assertFailsWith<ItbException> { Pipeline.init("no-such-profile") }
        assertEquals(Status.UnknownProfile, ex.status)
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
    fun registerMixedThenDuplicate() {
        // 8-entry width-256 mixed constellation, layers off.
        val profile = profile {
            mode("singlemsg-nomac")
            width(256)
            hashes(
                "blake3", "blake2s", "areion256", "blake2b256",
                "chacha20", "blake3", "blake2s", "areion256",
            )
            keyBits(1024)
            parallax(false)
            wrapper(false)
        }
        Pipeline.register("kotlin-binding-test-mixed", profile)

        // The registered profile round-trips.
        Pipeline.init("kotlin-binding-test-mixed").use { sender ->
            Pipeline.load(sender.save()).use { receiver ->
                val plain = "custom profile".encodeToByteArray()
                val wire = sender.encryptMessage(plain)
                assertContentEquals(plain, receiver.decryptMessage(wire))
            }
        }

        // Duplicate name is a distinct status.
        val ex = assertFailsWith<ItbException> {
            Pipeline.register("kotlin-binding-test-mixed", profile)
        }
        assertEquals(Status.ProfileExists, ex.status)
    }

    @Test
    fun lookupUnknownNameIsUnknownProfile() {
        val ex = assertFailsWith<ItbException> { Pipeline.lookup("no-such-profile") }
        assertEquals(Status.UnknownProfile, ex.status)
    }

    @Test
    fun maxWorkersOnDestroyedPipelineIsTripleClosed() {
        Pipeline.init("singlemsg-triple-mac-v1").use { pipe ->
            pipe.destroy()
            val ex = assertFailsWith<ItbException> { pipe.maxWorkers(2) }
            assertEquals(Status.TripleClosed, ex.status)
        }
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
