// Closing an encrypt session mid-flight cleans up and leaves the
// Pipeline usable.

package com.everanium.itb;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class StreamCancelTest {

    @Test
    void closeMidFlightThenReusePipeline() {
        try (Pipeline sender = Pipeline.init("streaming-aead-triple-mac-v1")) {
            byte[] chunk = new byte[100_000];
            Arrays.fill(chunk, (byte) 0xA5);
            try (EncryptStream sess = sender.encryptStream()) {
                sess.write(chunk);
                // Closed here without end() — close cancels and frees
                // the session; the test passing (process not hanging)
                // is the assertion.
            }

            // The Pipeline stays usable after the cancelled session.
            byte[] plain = "after cancel".getBytes(StandardCharsets.UTF_8);
            try (Pipeline receiver = Pipeline.load(sender.save())) {
                byte[] wire = sender.encryptMessage(plain);
                assertArrayEquals(plain, receiver.decryptMessage(wire));
            }
        }
    }
}
