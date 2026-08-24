// Round-trip and guard coverage for the caller-supplied-buffer
// (`*Into` / direct-ByteBuffer) cipher surface.

package com.everanium.itb;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

class IntoTest {

    private static final SecureRandom RNG = new SecureRandom();

    private static byte[] randomPlain(int n) {
        byte[] p = new byte[n];
        RNG.nextBytes(p);
        return p;
    }

    private static byte[] taken(ByteBuffer buf, int from, int len) {
        byte[] out = new byte[len];
        ByteBuffer view = buf.duplicate();
        view.position(from);
        view.get(out, 0, len);
        return out;
    }

    @Test
    void messageIntoRoundTrip() {
        byte[] plain = randomPlain(100_000);
        try (Pipeline pipe = Pipeline.init("singlemsg-triple-nomac-v1")) {
            ByteBuffer wire = ByteBuffer.allocateDirect(
                    plain.length + plain.length / 4 + 131_072);
            int wn = pipe.encryptMessageInto(plain, wire);
            assertEquals(wn, wire.position());
            assertTrue(wn > 0);

            // The Into wire and the allocating wrapper's plaintext
            // agree byte-for-byte after decrypt, both shapes.
            byte[] wireArr = taken(wire, 0, wn);
            assertArrayEquals(plain, pipe.decryptMessage(wireArr));

            ByteBuffer back = ByteBuffer.allocateDirect(plain.length + 131_072);
            int pn = pipe.decryptMessageInto(wireArr, back);
            assertArrayEquals(plain, taken(back, 0, pn));
        }
    }

    @Test
    void messageIntoRespectsPosition() {
        byte[] plain = randomPlain(4096);
        try (Pipeline pipe = Pipeline.init("singlemsg-triple-nomac-v1")) {
            ByteBuffer wire = ByteBuffer.allocateDirect(1 << 20);
            wire.position(777);
            int wn = pipe.encryptMessageInto(plain, wire);
            assertEquals(777 + wn, wire.position());
            assertArrayEquals(plain, pipe.decryptMessage(taken(wire, 777, wn)));
        }
    }

    @Test
    void streamOneShotIntoRoundTrip() {
        byte[] plain = randomPlain(200_000);
        try (Pipeline pipe = Pipeline.init("streaming-noaead-triple-v1")) {
            ByteBuffer wire = ByteBuffer.allocateDirect(
                    plain.length + plain.length / 4 + 131_072);
            int wn = pipe.encryptStreamOneShotInto(plain, wire);
            ByteBuffer back = ByteBuffer.allocateDirect(plain.length + 131_072);
            int pn = pipe.decryptStreamOneShotInto(taken(wire, 0, wn), back);
            assertArrayEquals(plain, taken(back, 0, pn));
        }
    }

    @Test
    void sessionDirectBufferRoundTrip() {
        byte[] plain = randomPlain(3 << 20);
        try (Pipeline pipe = Pipeline.init("streaming-noaead-triple-v1")) {
            ByteBuffer src = ByteBuffer.allocateDirect(plain.length);
            src.put(plain);
            ByteBuffer wire = ByteBuffer.allocateDirect(
                    plain.length + plain.length / 4 + 131_072);

            try (EncryptStream sess = pipe.encryptStream()) {
                int chunk = 1 << 20;
                for (int off = 0; off < plain.length; off += chunk) {
                    src.limit(Math.min(off + chunk, plain.length)).position(off);
                    sess.write(src);
                    assertEquals(src.limit(), src.position());
                    while (sess.readInto(wire) > 0) {
                        // accumulate into wire; position advances
                    }
                }
                sess.end();
                while (!sess.isFinished()) {
                    sess.readInto(wire);
                }
            }

            byte[] wireArr = taken(wire, 0, wire.position());
            try (DecryptStream sess = pipe.decryptStream()) {
                sess.write(wireArr);
                sess.end();
                ByteBuffer back = ByteBuffer.allocateDirect(
                        plain.length + 131_072);
                while (!sess.isFinished()) {
                    sess.readInto(back);
                }
                assertArrayEquals(plain, taken(back, 0, back.position()));
            }
        }
    }

    @Test
    void intoRejectsHeapAndSpentBuffers() {
        byte[] plain = randomPlain(64);
        try (Pipeline pipe = Pipeline.init("singlemsg-triple-nomac-v1")) {
            assertThrows(IllegalArgumentException.class,
                    () -> pipe.encryptMessageInto(plain, ByteBuffer.allocate(1 << 20)));
            assertThrows(IllegalArgumentException.class,
                    () -> pipe.encryptMessageInto(plain, null));
            ByteBuffer spent = ByteBuffer.allocateDirect(64);
            spent.position(64);
            assertThrows(IllegalArgumentException.class,
                    () -> pipe.encryptMessageInto(plain, spent));
        }
        try (Pipeline pipe = Pipeline.init("streaming-noaead-triple-v1");
                EncryptStream sess = pipe.encryptStream()) {
            assertThrows(IllegalArgumentException.class,
                    () -> sess.write(ByteBuffer.allocate(16)));
            assertThrows(IllegalArgumentException.class,
                    () -> sess.readInto(ByteBuffer.allocate(16)));
        }
    }

    @Test
    void intoUndersizedBufferFailsCleanly() {
        byte[] plain = randomPlain(100_000);
        try (Pipeline pipe = Pipeline.init("singlemsg-triple-nomac-v1")) {
            ByteBuffer tiny = ByteBuffer.allocateDirect(64);
            ItbException e = assertThrows(ItbException.class,
                    () -> pipe.encryptMessageInto(plain, tiny));
            assertEquals(Status.BUFFER_TOO_SMALL, e.status());
            assertEquals(0, tiny.position());
        }
    }
}
