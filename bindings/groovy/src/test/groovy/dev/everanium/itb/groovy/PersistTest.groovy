// Session persistence surface: save / load, saveF / loadF, inspect,
// lookup / profiles / register round trip, maxWorkers clamping.

package dev.everanium.itb.groovy

import groovy.transform.CompileStatic

import java.nio.file.Files
import java.nio.file.Path

import org.junit.jupiter.api.Test

import static org.junit.jupiter.api.Assertions.assertArrayEquals
import static org.junit.jupiter.api.Assertions.assertEquals
import static org.junit.jupiter.api.Assertions.assertFalse
import static org.junit.jupiter.api.Assertions.assertTrue

@CompileStatic
class PersistTest {

    private static final byte[] PLAIN = 'persisted session payload'.getBytes('UTF-8')

    @Test
    void saveThenLoadRoundTrip() {
        Pipeline.withPipeline('singlemsg-triple-mac-v1') { Pipeline sender ->
            byte[] blob = sender.save()
            assertTrue(blob.length > 0)
            assertArrayEquals(blob, sender.save())
            Pipeline.withLoaded(blob) { Pipeline receiver ->
                assertArrayEquals(blob, receiver.save())
                assertArrayEquals(PLAIN, receiver.decryptMessage(sender.encryptMessage(PLAIN)))
            }
        }
    }

    @Test
    void saveFThenLoadFRoundTrip() {
        Path dir = Files.createTempDirectory('itb-groovy-')
        Path file = dir.resolve('session.blob')
        try {
            Pipeline.withPipeline('streaming-aead-triple-mac-v1') { Pipeline sender ->
                sender.saveF(file.toString())
                assertArrayEquals(sender.save(), Files.readAllBytes(file))
                Pipeline.loadF(file.toString()).withCloseable { Pipeline receiver ->
                    assertArrayEquals(PLAIN,
                            receiver.decryptStreamOneShot(sender.encryptStreamOneShot(PLAIN)))
                }
            }
        } finally {
            Files.deleteIfExists(file)
            Files.deleteIfExists(dir)
        }
    }

    @Test
    void loadWithMasterOverride() {
        byte[] perm = new byte[32]
        byte[] wrap = new byte[32]
        Arrays.fill(perm, (byte) 0x33)
        Arrays.fill(wrap, (byte) 0x44)
        Pipeline.withPipeline('singlemsg-triple-mac-v1') { Pipeline sender ->
            byte[] blob = sender.save()
            byte[] rotated = sender.rekey(perm, wrap)
            assertFalse(Arrays.equals(blob, rotated))
            assertArrayEquals(rotated, sender.save())
            Pipeline.loadWithMasters(blob, perm, wrap).withCloseable { Pipeline receiver ->
                assertArrayEquals(PLAIN, receiver.decryptMessage(sender.encryptMessage(PLAIN)))
            }
        }
    }

    @Test
    void inspectReadsTheEmbeddedRecord() {
        Pipeline.withPipeline('streaming-aead-triple-mac-v1') { Pipeline pipe ->
            def prof = Pipeline.inspect(pipe.save())
            assertEquals('streaming-aead-triple-mac-v1', prof.name())
            assertEquals('streaming-aead', prof.mode())
            assertEquals(512, prof.width())
            assertEquals(Pipeline.lookup('streaming-aead-triple-mac-v1'), prof)
        }
    }

    @Test
    void profilesListsTheCatalogue() {
        List<String> names = Pipeline.profiles()
        assertTrue(names.contains('singlemsg-triple-mac-v1'))
        assertTrue(names.contains('streaming-aead-triple-mac-v1'))
    }

    @Test
    void registerCopyOfShippedProfile() {
        def copy = Pipeline.lookup('singlemsg-triple-nomac-v1').name('')
        Pipeline.register('groovy-binding-test-copy', copy)
        def back = Pipeline.lookup('groovy-binding-test-copy')
        assertEquals('groovy-binding-test-copy', back.name())
        assertEquals(copy.mode(), back.mode())
        assertTrue(Pipeline.profiles().contains('groovy-binding-test-copy'))
        Pipeline.withPipeline('groovy-binding-test-copy') { Pipeline sender ->
            Pipeline.withLoaded(sender.save()) { Pipeline receiver ->
                assertArrayEquals(PLAIN, receiver.decryptMessage(sender.encryptMessage(PLAIN)))
            }
        }
    }

    @Test
    void maxWorkersClamps() {
        Pipeline.withPipeline('singlemsg-triple-mac-v1', new Opts().withMaxWorkers(-1)) { Pipeline pipe ->
            pipe.maxWorkers(2)
            pipe.maxWorkers(-1)
            pipe.maxWorkers(1000)
            assertArrayEquals(PLAIN, pipe.decryptMessage(pipe.encryptMessage(PLAIN)))
        }
    }
}
