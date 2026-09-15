// Session persistence surface: save / load, saveF / loadF, inspect,
// lookup / profiles / register round trip, maxWorkers clamping.

package io.github.everanium.itb3.kotlin

import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PersistTest {

    private val plain = "persisted session payload".encodeToByteArray()

    @Test
    fun saveThenLoadRoundTrip() {
        Pipeline.init("singlemsg-triple-mac-v1").use { sender ->
            val blob = sender.save()
            assertTrue(blob.isNotEmpty())
            assertContentEquals(blob, sender.save())
            Pipeline.load(blob).use { receiver ->
                assertContentEquals(blob, receiver.save())
                assertContentEquals(plain, receiver.decryptMessage(sender.encryptMessage(plain)))
            }
        }
    }

    @Test
    fun saveFThenLoadFRoundTrip() {
        val dir = Files.createTempDirectory("itb-kotlin-")
        val file = dir.resolve("session.blob")
        try {
            Pipeline.init("streaming-aead-triple-mac-v1").use { sender ->
                sender.saveF(file.toString())
                assertContentEquals(sender.save(), Files.readAllBytes(file))
                Pipeline.loadF(file.toString()).use { receiver ->
                    assertContentEquals(
                        plain,
                        receiver.decryptStreamOneShot(sender.encryptStreamOneShot(plain)),
                    )
                }
            }
        } finally {
            Files.deleteIfExists(file)
            Files.deleteIfExists(dir)
        }
    }

    @Test
    fun loadWithMasterOverride() {
        val perm = ByteArray(32) { 0x33 }
        val wrap = ByteArray(32) { 0x44 }
        Pipeline.init("singlemsg-triple-mac-v1").use { sender ->
            val blob = sender.save()
            val rotated = sender.rekey(perm, wrap)
            assertFalse(blob.contentEquals(rotated))
            assertContentEquals(rotated, sender.save())
            Pipeline.load(blob, perm, wrap).use { receiver ->
                assertContentEquals(plain, receiver.decryptMessage(sender.encryptMessage(plain)))
            }
        }
    }

    @Test
    fun inspectReadsTheEmbeddedRecord() {
        Pipeline.init("streaming-aead-triple-mac-v1").use { pipe ->
            val prof = Pipeline.inspect(pipe.save())
            assertEquals("streaming-aead-triple-mac-v1", prof.name())
            assertEquals("streaming-aead", prof.mode())
            assertEquals(512, prof.width())
            // The recipe fields match the registry entry; the two
            // inspection-only fields separate the two records.
            val registry = Pipeline.lookup("streaming-aead-triple-mac-v1")
            assertEquals(registry, Profile.fromJson(prof.toJson()).nonceBits(null).barrierFill(null))
        }
    }

    @Test
    fun inspectCarriesTheRuntimeGlobalsLookupDoesNot() {
        // Defaults: the blob records the compile-in nonce width and
        // barrier fill margin, and inspect surfaces both.
        Pipeline.init("streaming-aead-triple-mac-v1").use { pipe ->
            val prof = Pipeline.inspect(pipe.save())
            assertEquals(512, prof.nonceBits())
            assertEquals(1, prof.barrierFill())
        }

        // Per-Pipeline overrides travel through the blob into inspect.
        val opts = Opts().nonceBits(256).barrierFill(4)
        Pipeline.init("streaming-aead-triple-mac-v1", opts).use { pipe ->
            val prof = Pipeline.inspect(pipe.save())
            assertEquals(256, prof.nonceBits())
            assertEquals(4, prof.barrierFill())
            assertTrue("\"nonce_bits\":256" in prof.toJson())
            assertTrue("\"barrier_fill\":4" in prof.toJson())
        }

        // The registry entry is the recipe alone — neither field is
        // part of it, so both read as absent rather than as zero.
        val registry = Pipeline.lookup("streaming-aead-triple-mac-v1")
        assertNull(registry.nonceBits())
        assertNull(registry.barrierFill())
        assertFalse("nonce_bits" in registry.toJson())
        assertFalse("barrier_fill" in registry.toJson())
    }

    @Test
    fun profilesListsTheCatalogue() {
        val names = Pipeline.profiles()
        assertTrue("singlemsg-triple-mac-v1" in names)
        assertTrue("streaming-aead-triple-mac-v1" in names)
    }

    @Test
    fun registerCopyOfShippedProfile() {
        val copy = Pipeline.lookup("singlemsg-triple-nomac-v1").name("")
        Pipeline.register("kotlin-binding-test-copy", copy)
        val back = Pipeline.lookup("kotlin-binding-test-copy")
        assertEquals("kotlin-binding-test-copy", back.name())
        assertEquals(copy.mode(), back.mode())
        assertTrue("kotlin-binding-test-copy" in Pipeline.profiles())
        Pipeline.init("kotlin-binding-test-copy").use { sender ->
            Pipeline.load(sender.save()).use { receiver ->
                assertContentEquals(plain, receiver.decryptMessage(sender.encryptMessage(plain)))
            }
        }
    }

    @Test
    fun maxWorkersClamps() {
        Pipeline.init("singlemsg-triple-mac-v1", opts { maxWorkers(-1) }).use { pipe ->
            pipe.maxWorkers(2)
            pipe.maxWorkers(-1)
            pipe.maxWorkers(1000)
            assertContentEquals(plain, pipe.decryptMessage(pipe.encryptMessage(plain)))
        }
    }
}
