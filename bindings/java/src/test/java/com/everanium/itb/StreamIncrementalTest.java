// Explicit write / end / read round trip with pathological batch
// sizes (17-byte feed, 23-byte drain) across multiple chunks.

package com.everanium.itb;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import org.junit.jupiter.api.Test;

class StreamIncrementalTest {

    private static byte[] roundTripSide(StreamSession sess, byte[] input) {
        for (int off = 0; off < input.length; off += 17) {
            sess.write(input, off, Math.min(17, input.length - off));
        }
        sess.end();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[23];
        while (!sess.isFinished()) {
            int n = sess.read(buf);
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    @Test
    void incrementalTinyBatches() {
        // Small chunk size so the 64 KiB payload spans many chunks.
        Opts opts = new Opts().withChunkSize(4096);
        try (Pipeline sender = Pipeline.init("streaming-aead-triple-mac-v1", opts);
                Pipeline receiver = Pipeline.open(
                        "streaming-aead-triple-mac-v1", sender.blob(), opts)) {
            byte[] plain = new byte[65_536];
            for (int i = 0; i < plain.length; i++) {
                plain[i] = (byte) (i % 241);
            }

            byte[] wire;
            try (EncryptStream sess = sender.encryptStream()) {
                wire = roundTripSide(sess, plain);
            }
            assertTrue(wire.length > 0);

            byte[] back;
            try (DecryptStream sess = receiver.decryptStream()) {
                back = roundTripSide(sess, wire);
            }
            assertArrayEquals(plain, back);
        }
    }
}
