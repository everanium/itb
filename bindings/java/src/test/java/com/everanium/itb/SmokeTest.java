// Init → blob → Open → encryptMessage → decryptMessage round trip.

package com.everanium.itb;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class SmokeTest {

    @Test
    void smokeRoundTrip() {
        byte[] plain = "smoke round-trip payload".getBytes(StandardCharsets.UTF_8);
        try (Pipeline sender = Pipeline.init("singlemsg-triple-mac-v1")) {
            assertTrue(sender.blob().length > 0);
            try (Pipeline receiver = Pipeline.open(
                    "singlemsg-triple-mac-v1", sender.blob(), new Opts())) {
                byte[] wire = sender.encryptMessage(plain);
                assertFalse(java.util.Arrays.equals(wire, plain));
                byte[] back = receiver.decryptMessage(wire);
                assertArrayEquals(plain, back);
            }
        }
    }
}
