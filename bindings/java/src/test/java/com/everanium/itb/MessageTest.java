// Single Message round trip across every shipped cipher profile at
// small (4 KiB) and medium (256 KiB) payloads. The blob-only profile
// has no cipher surface and is exercised in ErrorsTest instead.

package com.everanium.itb;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.junit.jupiter.api.Test;

class MessageTest {

    /** Deterministic non-trivial payload (xorshift fill). */
    static byte[] payload(int n, long seed) {
        long x = seed | 1;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            x ^= x << 13;
            x ^= x >>> 7;
            x ^= x << 17;
            out[i] = (byte) x;
        }
        return out;
    }

    @Test
    void messageRoundTripEveryProfile() {
        String[] profiles = {
            "streaming-aead-triple-mac-v1",
            "streaming-noaead-triple-v1",
            "singlemsg-triple-mac-v1",
            "singlemsg-triple-nomac-v1",
            "streaming-aead-triple-mac-mixed-v1",
            "streaming-noaead-triple-mixed-v1",
            "singlemsg-triple-mac-mixed-v1",
            "singlemsg-triple-nomac-mixed-v1",
        };
        for (String profile : profiles) {
            try (Pipeline sender = Pipeline.init(profile);
                    Pipeline receiver = Pipeline.load(sender.save())) {
                for (int size : new int[] {4 * 1024, 256 * 1024}) {
                    byte[] plain = payload(size, size);
                    byte[] wire = sender.encryptMessage(plain);
                    byte[] back = receiver.decryptMessage(wire);
                    assertArrayEquals(plain, back, profile + " @" + size);
                }
            }
        }
    }

    @Test
    void optsInnerHashesOverrideRoundTripsOnWidth512Profile() {
        // Per-call Opts.MixedHashes override over a width-512 shipped
        // base profile; both sides pass the same 8-slot constellation
        // so the receiver Pipeline resolves the same mixed inner-hash
        // bundle as the sender.
        Opts opts = new Opts().withInnerHashes(
                "areion512", "blake2b512", "areion512", "blake2b512",
                "areion512", "blake2b512", "areion512", "blake2b512");
        try (Pipeline sender = Pipeline.init("singlemsg-triple-mac-v1", opts);
                Pipeline receiver = Pipeline.load(sender.save())) {
            byte[] plain = payload(4096, 42L);
            byte[] wire = sender.encryptMessage(plain);
            byte[] back = receiver.decryptMessage(wire);
            assertArrayEquals(plain, back);
        }
    }
}
