// Init -> rekey -> load receiver from the rotated blob -> round
// trip.

package dev.everanium.itb.groovy

import groovy.transform.CompileStatic

import org.junit.jupiter.api.Test

import static org.junit.jupiter.api.Assertions.assertArrayEquals
import static org.junit.jupiter.api.Assertions.assertFalse

@CompileStatic
class RekeyTest {

    @Test
    void rekeyRoundTrip() {
        Pipeline.withPipeline('singlemsg-triple-mac-v1') { Pipeline sender ->
            byte[] blobBefore = sender.save()

            byte[] perm = new byte[32]
            byte[] wrap = new byte[32]
            Arrays.fill(perm, (byte) 0x11)
            Arrays.fill(wrap, (byte) 0x22)
            sender.rekey(perm, wrap)
            assertFalse(Arrays.equals(blobBefore, sender.save()))

            Pipeline.withLoaded(sender.save()) { Pipeline receiver ->
                byte[] plain = 'post-rekey payload'.getBytes('UTF-8')
                byte[] wire = sender.encryptMessage(plain)
                assertArrayEquals(plain, receiver.decryptMessage(wire))
            }
        }
    }
}
