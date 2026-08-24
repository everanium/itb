// Round trips through the InputStream / OutputStream pumps and the
// extension-module sugar on a Streaming AEAD profile.

package dev.everanium.itb.groovy

import groovy.transform.CompileStatic

import org.junit.jupiter.api.Test

import static org.junit.jupiter.api.Assertions.assertArrayEquals
import static org.junit.jupiter.api.Assertions.assertTrue

@CompileStatic
class StreamPumpTest {

    private static final String PROFILE = 'streaming-aead-triple-mac-v1'

    @Test
    void pumpRoundTripOneMiB() {
        Pipeline.withPipeline(PROFILE) { Pipeline sender ->
            Pipeline.withOpened(PROFILE, sender.blob) { Pipeline receiver ->
                byte[] plain = new byte[1 << 20]
                for (int i = 0; i < plain.length; i++) {
                    plain[i] = (byte) (i % 251)
                }

                def wire = new ByteArrayOutputStream()
                sender.encryptStreamPump(new ByteArrayInputStream(plain), wire)
                assertTrue(wire.size() > 0)

                def back = new ByteArrayOutputStream()
                receiver.decryptStreamPump(new ByteArrayInputStream(wire.toByteArray()), back)
                assertArrayEquals(plain, back.toByteArray())
            }
        }
    }

    @Test
    void pumpMatchesOneShot() {
        Pipeline.withPipeline(PROFILE) { Pipeline sender ->
            Pipeline.withOpened(PROFILE, sender.blob) { Pipeline receiver ->
                byte[] plain = MessageTest.payload(65_536, 199)
                byte[] wire = sender.encryptStreamOneShot(plain)

                def back = new ByteArrayOutputStream()
                receiver.decryptStreamPump(new ByteArrayInputStream(wire), back)
                assertArrayEquals(plain, back.toByteArray())

                assertArrayEquals(plain, receiver.decryptStreamOneShot(wire))
            }
        }
    }

    @Test
    void extensionMethodsRoundTrip() {
        Pipeline.withPipeline(PROFILE) { Pipeline sender ->
            Pipeline.withOpened(PROFILE, sender.blob) { Pipeline receiver ->
                // byte[] sugar (Single Message via the singlemsg path
                // is covered elsewhere; here the stream extensions).
                byte[] plain = MessageTest.payload(300_000, 0x5eed)

                def wire = new ByteArrayOutputStream()
                new ByteArrayInputStream(plain).encryptTo(sender, wire)
                assertTrue(wire.size() > 0)

                def back = new ByteArrayOutputStream()
                new ByteArrayInputStream(wire.toByteArray()).decryptTo(receiver, back)
                assertArrayEquals(plain, back.toByteArray())
            }
        }
    }

    @Test
    void byteArrayExtensionRoundTrip() {
        Pipeline.withPipeline('singlemsg-triple-mac-v1') { Pipeline sender ->
            Pipeline.withOpened('singlemsg-triple-mac-v1', sender.blob) { Pipeline receiver ->
                byte[] plain = 'extension sugar payload'.getBytes('UTF-8')
                byte[] wire = plain.encryptWith(sender)
                assertArrayEquals(plain, wire.decryptWith(receiver))
            }
        }
    }
}
