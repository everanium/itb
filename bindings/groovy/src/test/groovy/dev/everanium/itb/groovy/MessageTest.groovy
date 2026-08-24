// Single Message round trip across every shipped cipher profile at
// small (4 KiB) and medium (256 KiB) payloads. The blob-only profile
// has no cipher surface and is exercised in ErrorsTest instead.

package dev.everanium.itb.groovy

import groovy.transform.CompileStatic

import org.junit.jupiter.api.Test

import static org.junit.jupiter.api.Assertions.assertArrayEquals

@CompileStatic
class MessageTest {

    /** Deterministic non-trivial payload (xorshift fill). */
    static byte[] payload(int n, long seed) {
        byte[] buf = new byte[n]
        long x = seed | 1L
        for (int i = 0; i < n; i++) {
            x ^= x << 13
            x ^= x >>> 7
            x ^= x << 17
            buf[i] = (byte) x
        }
        buf
    }

    private static final List<String> PROFILES = [
        'streaming-aead-triple-mac-v1',
        'streaming-noaead-triple-v1',
        'singlemsg-triple-mac-v1',
        'singlemsg-triple-nomac-v1',
        'streaming-aead-triple-mac-mixed-v1',
        'streaming-noaead-triple-mixed-v1',
        'singlemsg-triple-mac-mixed-v1',
        'singlemsg-triple-nomac-mixed-v1',
    ]

    @Test
    void messageRoundTripOnEveryShippedProfile() {
        PROFILES.each { String profile ->
            Pipeline.withPipeline(profile) { Pipeline sender ->
                Pipeline.withOpened(profile, sender.blob) { Pipeline receiver ->
                    [4 * 1024, 256 * 1024].each { int size ->
                        byte[] plain = payload(size, size)
                        byte[] wire = sender.encryptMessage(plain)
                        assertArrayEquals(plain, receiver.decryptMessage(wire),
                                "round trip mismatch: $profile @ $size")
                    }
                }
            }
        }
    }
}
