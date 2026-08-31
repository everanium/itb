// Init -> blob -> Open -> encryptMessage -> decryptMessage round
// trip through the withPipeline / withOpened closure scopes.

package dev.everanium.itb.groovy

import groovy.transform.CompileStatic

import org.junit.jupiter.api.Test

import static org.junit.jupiter.api.Assertions.assertArrayEquals
import static org.junit.jupiter.api.Assertions.assertEquals
import static org.junit.jupiter.api.Assertions.assertFalse
import static org.junit.jupiter.api.Assertions.assertTrue

@CompileStatic
class SmokeTest {

    @Test
    void libraryVersionIsNonEmpty() {
        assertTrue(!Runtime.version().isEmpty())
        assertEquals('0.3.1', Runtime.BINDING_VERSION)
    }

    @Test
    void smokeRoundTrip() {
        Pipeline.withPipeline('singlemsg-triple-mac-v1') { Pipeline sender ->
            assertTrue(sender.blob.length > 0)
            Pipeline.withOpened('singlemsg-triple-mac-v1', sender.blob) { Pipeline receiver ->
                byte[] plain = 'smoke round-trip payload'.getBytes('UTF-8')
                byte[] wire = sender.encryptMessage(plain)
                assertFalse(Arrays.equals(wire, plain))
                assertArrayEquals(plain, receiver.decryptMessage(wire))
            }
        }
    }

    @Test
    void tryWithResourcesAlsoScopes() {
        // AutoCloseable composes with Groovy's withCloseable as well
        // as the closure factories.
        Pipeline.init('singlemsg-triple-mac-v1').withCloseable { Pipeline sender ->
            byte[] plain = 'closeable payload'.getBytes('UTF-8')
            Pipeline.open('singlemsg-triple-mac-v1', sender.blob).withCloseable { Pipeline receiver ->
                assertArrayEquals(plain, receiver.decryptMessage(sender.encryptMessage(plain)))
            }
        }
    }
}
