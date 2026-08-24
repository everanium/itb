// Error-mapping surface: opaque-string relay, closed Pipeline,
// duplicate profile registration (with an 8-entry innerHashes
// constellation), and the Opts.of map factory.

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
    void unknownProfileIsBadInputWithDiagnostic() {
        def e = assertThrows(ItbException) { Pipeline.init('no-such-profile') }
        assertEquals(Status.BAD_INPUT, e.status)
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
    void registerProfileMixedThenDuplicate() {
        // 8-entry width-256 innerHashes constellation, layers off,
        // built through the Opts.of named-argument map factory.
        def opts = Opts.of(
                mode: 'singlemsg-nomac',
                width: 256,
                innerHashes: 'blake3,blake2s,areion256,blake2b256,chacha20,blake3,blake2s,areion256',
                keyBits: 1024,
                parallaxOn: false,
                wrapperOn: false)
        Pipeline.registerProfile('groovy-binding-test-mixed', opts)

        // The registered profile round-trips.
        Pipeline.withPipeline('groovy-binding-test-mixed') { Pipeline sender ->
            Pipeline.withOpened('groovy-binding-test-mixed', sender.blob) { Pipeline receiver ->
                byte[] plain = 'custom profile'.getBytes('UTF-8')
                byte[] wire = sender.encryptMessage(plain)
                assertArrayEquals(plain, receiver.decryptMessage(wire))
            }
        }

        // Duplicate name is a distinct status.
        def e = assertThrows(ItbException) {
            Pipeline.registerProfile('groovy-binding-test-mixed', opts)
        }
        assertEquals(Status.PROFILE_EXISTS, e.status)
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
