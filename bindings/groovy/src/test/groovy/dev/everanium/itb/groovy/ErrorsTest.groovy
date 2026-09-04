// Error-mapping surface: opaque-string relay, closed Pipeline,
// duplicate profile registration (with an 8-entry mixed
// constellation), unknown lookup, maxWorkers on a destroyed handle.

package dev.everanium.itb.groovy

import groovy.transform.CompileStatic

import org.junit.jupiter.api.Test

import static org.junit.jupiter.api.Assertions.assertArrayEquals
import static org.junit.jupiter.api.Assertions.assertEquals
import static org.junit.jupiter.api.Assertions.assertNotEquals
import static org.junit.jupiter.api.Assertions.assertThrows
import static org.junit.jupiter.api.Assertions.assertTrue

@CompileStatic
class ErrorsTest {

    @Test
    void unknownProfileIsUnknownProfileWithDiagnostic() {
        def e = assertThrows(ItbException) { Pipeline.init('no-such-profile') }
        assertEquals(Status.UNKNOWN_PROFILE, e.status)
        assertTrue(!e.message.isEmpty())
    }

    @Test
    void unknownOptsKeyIsBadInput() {
        // Typoed key (lowercase s) — Go rejects unknown keys.
        def opts = new Opts().withRaw('chunksize', '4096')
        def e = assertThrows(ItbException) { Pipeline.init('singlemsg-triple-mac-v1', opts) }
        assertEquals(Status.BAD_INPUT, e.status)
    }

    @Test
    void closedPipelineReportsTripleClosed() {
        Pipeline.withPipeline('singlemsg-triple-mac-v1') { Pipeline pipe ->
            pipe.destroy()
            pipe.destroy() // idempotent
            assertTrue(pipe.destroyed)
            def e = assertThrows(ItbException) {
                pipe.encryptMessage('payload'.getBytes('UTF-8'))
            }
            assertEquals(Status.TRIPLE_CLOSED, e.status)
        }
    }

    @Test
    void registerMixedThenDuplicate() {
        // 8-entry width-256 mixed constellation, layers off, built
        // through the named-argument map form of register.
        def record = [
                mode: 'singlemsg-nomac',
                width: 256,
                hashes: ['blake3', 'blake2s', 'areion256', 'blake2b256',
                         'chacha20', 'blake3', 'blake2s', 'areion256'],
                keyBits: 1024,
                parallax: false,
                wrapper: false] as Map<String, ?>
        Pipeline.register(record, 'groovy-binding-test-mixed')

        // The registered profile round-trips.
        Pipeline.withPipeline('groovy-binding-test-mixed') { Pipeline sender ->
            Pipeline.withLoaded(sender.save()) { Pipeline receiver ->
                byte[] plain = 'custom profile'.getBytes('UTF-8')
                byte[] wire = sender.encryptMessage(plain)
                assertArrayEquals(plain, receiver.decryptMessage(wire))
            }
        }

        // Duplicate name is a distinct status.
        def e = assertThrows(ItbException) {
            Pipeline.register('groovy-binding-test-mixed', Pipeline.profileOf(record))
        }
        assertEquals(Status.PROFILE_EXISTS, e.status)
    }

    @Test
    void lookupUnknownNameIsUnknownProfile() {
        def e = assertThrows(ItbException) { Pipeline.lookup('no-such-profile') }
        assertEquals(Status.UNKNOWN_PROFILE, e.status)
    }

    @Test
    void maxWorkersOnDestroyedPipelineIsTripleClosed() {
        Pipeline.withPipeline('singlemsg-triple-mac-v1') { Pipeline pipe ->
            pipe.destroy()
            def e = assertThrows(ItbException) { pipe.maxWorkers(2) }
            assertEquals(Status.TRIPLE_CLOSED, e.status)
        }
    }

    @Test
    void opaquePrimitiveNameRelay() {
        // An unknown inner-hash name is relayed to Go and rejected
        // there — the binding performs no name validation of its own.
        def opts = new Opts().withInnerHash('no-such-hash')
        def e = assertThrows(ItbException) { Pipeline.init('singlemsg-triple-mac-v1', opts) }
        assertNotEquals(Status.OK, e.status)
    }
}
