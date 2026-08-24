// EncryptMessage throughput vs plaintext size (Single Message
// profile) at 1 MiB / 16 MiB / 64 MiB.

package com.everanium.itb.bench;

import com.everanium.itb.Pipeline;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

public final class BenchMessage {

    private BenchMessage() {
    }

    public static void main(String[] args) {
        // Bench-scale allocation churn leaks Go scratch heap
        // unboundedly without a soft memory cap + aggressive GC; the
        // return values report the previous settings, not an error.
        com.everanium.itb.Runtime.setMemoryLimit(512L << 20);
        com.everanium.itb.Runtime.setGCPercent(20);

        SecureRandom rng = new SecureRandom();
        try (Pipeline pipe = Pipeline.init(
                BenchUtil.profileName("singlemsg-triple-nomac-v1"),
                BenchUtil.buildOpts())) {
            BenchUtil.header();
            for (int size : BenchUtil.SIZES) {
                byte[] plain = new byte[size];
                // CSPRNG-fill so plaintext content matches the root Go
                // bench (crypto/rand). Not in the timing loop.
                rng.nextBytes(plain);
                // Pooled direct output scratch sized for the wire
                // expansion envelope; reused across iterations so the
                // timing loop performs no output allocation.
                ByteBuffer wire =
                        ByteBuffer.allocateDirect(size + size / 4 + 131_072);
                BenchUtil.benchCase("message", size, () -> {
                    wire.clear();
                    pipe.encryptMessageInto(plain, wire);
                });
                // Pre-encrypt one wire outside the decrypt timing loop.
                byte[] decWire = pipe.encryptMessage(plain);
                ByteBuffer decOut = ByteBuffer.allocateDirect(size + 131_072);
                BenchUtil.benchCase("message-dec", size, () -> {
                    decOut.clear();
                    pipe.decryptMessageInto(decWire, decOut);
                });
            }
        }
    }
}
