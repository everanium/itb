// Init → Rekey → load receiver from the rotated blob → round trip.

package com.everanium.itb;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class RekeyTest {

    @Test
    void rekeyRoundTrip() {
        try (Pipeline sender = Pipeline.init("singlemsg-triple-mac-v1")) {
            byte[] blobBefore = sender.save();

            byte[] perm = new byte[32];
            byte[] wrap = new byte[32];
            Arrays.fill(perm, (byte) 0x11);
            Arrays.fill(wrap, (byte) 0x22);
            sender.rekey(perm, wrap);
            assertFalse(Arrays.equals(sender.save(), blobBefore),
                    "rekey must refresh the blob");

            try (Pipeline receiver = Pipeline.load(sender.save())) {
                byte[] plain = "post-rekey payload".getBytes(StandardCharsets.UTF_8);
                byte[] wire = sender.encryptMessage(plain);
                assertArrayEquals(plain, receiver.decryptMessage(wire));
            }
        }
    }
}
