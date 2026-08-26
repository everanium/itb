// Whole-buffer Stream throughput vs plaintext size (Streaming
// Non-AEAD profile) at 1 MiB / 16 MiB / 64 MiB. Times
// encryptStreamOneShot / decryptStreamOneShot, the single FFI
// round-trip surface for callers holding the whole payload in
// memory.

package com.everanium.itb.bench;

import com.everanium.itb.Pipeline;
import java.security.SecureRandom;

public final class BenchStreamOneShot {

    private BenchStreamOneShot() {
    }

    public static void main(String[] args) {
        // Bench-scale allocation churn leaks Go scratch heap
        // unboundedly without a soft memory cap + aggressive GC; the
        // return values report the previous settings, not an error.
        com.everanium.itb.Runtime.setMemoryLimit(512L << 20);
        com.everanium.itb.Runtime.setGCPercent(20);

        SecureRandom rng = new SecureRandom();
        try (Pipeline pipe = Pipeline.init(
                BenchUtil.profileName("streaming-noaead-triple-v1"),
                BenchUtil.buildOpts())) {
            BenchUtil.header();
            for (int size : BenchUtil.SIZES) {
                byte[] plain = new byte[size];
                // CSPRNG-fill so plaintext content matches the root Go
                // bench (crypto/rand). Not in the timing loop.
                rng.nextBytes(plain);
                BenchUtil.benchCase("stream_one_shot", size,
                        () -> pipe.encryptStreamOneShot(plain));
                // Pre-encrypt one wire outside the decrypt timing loop.
                byte[] decWire = pipe.encryptStreamOneShot(plain);
                BenchUtil.benchCase("stream_one_shot-dec", size,
                        () -> pipe.decryptStreamOneShot(decWire));
            }
        }
    }
}
