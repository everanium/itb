// Round trip through the stream pumps on a Streaming AEAD profile.

package com.everanium.itb;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import org.junit.jupiter.api.Test;

class StreamPumpTest {

    private static byte[] modFill(int n, int mod) {
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            out[i] = (byte) (i % mod);
        }
        return out;
    }

    @Test
    void pumpRoundTrip1MiB() {
        try (Pipeline sender = Pipeline.init("streaming-aead-triple-mac-v1");
                Pipeline receiver = Pipeline.load(sender.save())) {
            byte[] plain = modFill(1 << 20, 251);

            ByteArrayOutputStream wire = new ByteArrayOutputStream();
            sender.encryptStreamPump(new ByteArrayInputStream(plain), wire);
            assertTrue(wire.size() > 0);

            ByteArrayOutputStream back = new ByteArrayOutputStream();
            receiver.decryptStreamPump(new ByteArrayInputStream(wire.toByteArray()), back);
            assertArrayEquals(plain, back.toByteArray());
        }
    }

    @Test
    void pumpMatchesOneShot() {
        try (Pipeline sender = Pipeline.init("streaming-aead-triple-mac-v1");
                Pipeline receiver = Pipeline.load(sender.save())) {
            byte[] plain = modFill(65_536, 199);
            byte[] wire = sender.encryptStreamOneShot(plain);

            ByteArrayOutputStream back = new ByteArrayOutputStream();
            receiver.decryptStreamPump(new ByteArrayInputStream(wire), back);
            assertArrayEquals(plain, back.toByteArray());

            byte[] back2 = receiver.decryptStreamOneShot(wire);
            assertArrayEquals(plain, back2);
        }
    }
}
