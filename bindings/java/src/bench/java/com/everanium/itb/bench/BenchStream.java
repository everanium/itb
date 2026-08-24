// Stream-pump throughput vs plaintext size (Streaming Non-AEAD
// profile) at 1 MiB / 16 MiB / 64 MiB.
//
// The pump loop is user-driven with pooled direct buffers: the
// plaintext lives in one direct buffer fed to the session in
// chunk-sized windows (zero-copy at the FFI boundary), and the wire
// drains through readInto into one pooled direct scratch — the timing
// loop performs no per-iteration buffer allocation beyond the
// session's own state.

package com.everanium.itb.bench;

import com.everanium.itb.EncryptStream;
import com.everanium.itb.Pipeline;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

public final class BenchStream {

    /** Feed slice size used by the pump loop. */
    private static final int CHUNK = 1 << 20;

    private BenchStream() {
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
                ByteBuffer src = ByteBuffer.allocateDirect(size);
                src.put(plain);
                ByteBuffer out = ByteBuffer.allocateDirect(CHUNK + 131_072);
                BenchUtil.benchCase("stream_pump", size, () -> {
                    try (EncryptStream sess = pipe.encryptStream()) {
                        for (int off = 0; off < size; off += CHUNK) {
                            int n = Math.min(CHUNK, size - off);
                            src.limit(off + n).position(off);
                            sess.write(src);
                            // Drain whatever the chain has produced so
                            // far; a read before end() never blocks.
                            out.clear();
                            while (sess.readInto(out) > 0) {
                                out.clear();
                            }
                        }
                        sess.end();
                        while (!sess.isFinished()) {
                            out.clear();
                            sess.readInto(out);
                        }
                    }
                });
            }
        }
    }
}
