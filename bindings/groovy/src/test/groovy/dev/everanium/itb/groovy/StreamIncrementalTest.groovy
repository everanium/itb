// Explicit write / end / read round trip with pathological batch
// sizes (17-byte feed, 23-byte drain) across multiple chunks,
// driven through the encrypting / decrypting session scopes.

package dev.everanium.itb.groovy

import groovy.transform.CompileStatic

import org.junit.jupiter.api.Test

import static org.junit.jupiter.api.Assertions.assertArrayEquals
import static org.junit.jupiter.api.Assertions.assertTrue

@CompileStatic
class StreamIncrementalTest {

    /** Feeds {@code src} in 17-byte writes, ends, drains in 23-byte
     * reads. Works on either session direction. */
    private static byte[] pumpTinyEncrypt(EncryptStream s, byte[] src) {
        for (int off = 0; off < src.length; off += 17) {
            s.write(src, off, Math.min(17, src.length - off))
        }
        s.end()
        drainTiny(s.&read) { s.finished }
    }

    private static byte[] pumpTinyDecrypt(DecryptStream s, byte[] src) {
        for (int off = 0; off < src.length; off += 17) {
            s.write(src, off, Math.min(17, src.length - off))
        }
        s.end()
        drainTiny(s.&read) { s.finished }
    }

    private static byte[] drainTiny(Closure<Integer> read, Closure<Boolean> finished) {
        def spool = new ByteArrayOutputStream()
        byte[] buf = new byte[23]
        boolean done = false
        while (!done) {
            int n = read.call(buf)
            spool.write(buf, 0, n)
            done = finished.call()
        }
        spool.toByteArray()
    }

    @Test
    void incrementalTinyBatches() {
        // Small chunk size so the 64 KiB payload spans many chunks.
        def opts = { new Opts().withChunkSize(4096) }
        Pipeline.withPipeline('streaming-aead-triple-mac-v1', opts()) { Pipeline sender ->
            Pipeline.withLoaded(sender.save()) { Pipeline receiver ->
                byte[] plain = new byte[65_536]
                for (int i = 0; i < plain.length; i++) {
                    plain[i] = (byte) (i % 241)
                }

                byte[] wire = sender.encrypting { EncryptStream s ->
                    pumpTinyEncrypt(s, plain)
                }
                assertTrue(wire.length > 0)

                byte[] back = receiver.decrypting { DecryptStream s ->
                    pumpTinyDecrypt(s, wire)
                }
                assertArrayEquals(plain, back)
            }
        }
    }

    @Test
    void drainToCollectsTerminalOutput() {
        Pipeline.withPipeline('streaming-aead-triple-mac-v1') { Pipeline sender ->
            Pipeline.withLoaded(sender.save()) { Pipeline receiver ->
                byte[] plain = MessageTest.payload(50_000, 7)

                def wireSpool = new ByteArrayOutputStream()
                sender.encrypting { EncryptStream s ->
                    s.write(plain)
                    s.drainTo(wireSpool)
                }
                byte[] wire = wireSpool.toByteArray()
                assertTrue(wire.length > 0)

                def backSpool = new ByteArrayOutputStream()
                receiver.decrypting { DecryptStream s ->
                    s.write(wire)
                    s.drainTo(backSpool)
                }
                assertArrayEquals(plain, backSpool.toByteArray())
            }
        }
    }
}
