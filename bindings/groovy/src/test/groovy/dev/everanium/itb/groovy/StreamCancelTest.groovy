// Closing an encrypt session mid-flight cleans up and leaves the
// Pipeline usable.

package dev.everanium.itb.groovy

import groovy.transform.CompileStatic

import org.junit.jupiter.api.Test

import static org.junit.jupiter.api.Assertions.assertArrayEquals

@CompileStatic
class StreamCancelTest {

    @Test
    void closeMidFlightThenReusePipeline() {
        Pipeline.withPipeline('streaming-aead-triple-mac-v1') { Pipeline sender ->
            sender.encrypting { EncryptStream session ->
                byte[] block = new byte[100_000]
                Arrays.fill(block, (byte) 0xa5)
                session.write(block)
                // Scope exits here without end() — close cancels and
                // frees the session; the test passing (process not
                // hanging) is the assertion.
            }

            // The Pipeline stays usable after the cancelled session.
            Pipeline.withOpened('streaming-aead-triple-mac-v1', sender.blob) { Pipeline receiver ->
                byte[] plain = 'after cancel'.getBytes('UTF-8')
                byte[] wire = sender.encryptMessage(plain)
                assertArrayEquals(plain, receiver.decryptMessage(wire))
            }
        }
    }
}
