// Error-mapping surface: opaque-string relay, destroyed Pipeline,
// duplicate profile registration (with an 8-entry mixed
// constellation), unknown lookup, maxWorkers on a destroyed handle.

package com.everanium.itb;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class ErrorsTest {

    @Test
    void unknownProfileIsUnknownProfileWithDiagnostic() {
        ItbException e = assertThrows(ItbException.class,
                () -> Pipeline.init("no-such-profile"));
        assertEquals(Status.UNKNOWN_PROFILE, e.status());
        assertFalse(e.getMessage().isEmpty());
    }

    @Test
    void unknownOptsKeyIsBadInput() {
        // Typoed key (lowercase s) — Go rejects unknown keys.
        Opts opts = new Opts().withRaw("chunksize", "4096");
        ItbException e = assertThrows(ItbException.class,
                () -> Pipeline.init("singlemsg-triple-mac-v1", opts));
        assertEquals(Status.BAD_INPUT, e.status());
    }

    @Test
    void destroyedPipelineReportsTripleClosed() {
        try (Pipeline p = Pipeline.init("singlemsg-triple-mac-v1")) {
            p.destroy();
            assertTrue(p.isDestroyed());
            p.destroy(); // idempotent
            ItbException e = assertThrows(ItbException.class,
                    () -> p.encryptMessage("payload".getBytes(StandardCharsets.UTF_8)));
            assertEquals(Status.TRIPLE_CLOSED, e.status());
        }
    }

    @Test
    void registerMixedThenDuplicate() {
        // 8-entry width-256 mixed constellation, layers off.
        Profile profile = new Profile()
                .mode("singlemsg-nomac")
                .width(256)
                .hashes("blake3", "blake2s", "areion256", "blake2b256",
                        "chacha20", "blake3", "blake2s", "areion256")
                .keyBits(1024)
                .parallax(false)
                .wrapper(false);
        Pipeline.register("java-binding-test-mixed", profile);

        // The registered profile round-trips.
        byte[] plain = "custom profile".getBytes(StandardCharsets.UTF_8);
        try (Pipeline sender = Pipeline.init("java-binding-test-mixed");
                Pipeline receiver = Pipeline.load(sender.save())) {
            byte[] wire = sender.encryptMessage(plain);
            assertArrayEquals(plain, receiver.decryptMessage(wire));
        }

        // Duplicate name is a distinct status.
        ItbException e = assertThrows(ItbException.class,
                () -> Pipeline.register("java-binding-test-mixed", profile));
        assertEquals(Status.PROFILE_EXISTS, e.status());
    }

    @Test
    void lookupUnknownNameIsUnknownProfile() {
        ItbException e = assertThrows(ItbException.class,
                () -> Pipeline.lookup("no-such-profile"));
        assertEquals(Status.UNKNOWN_PROFILE, e.status());
    }

    @Test
    void maxWorkersOnDestroyedPipelineIsTripleClosed() {
        try (Pipeline p = Pipeline.init("singlemsg-triple-mac-v1")) {
            p.destroy();
            ItbException e = assertThrows(ItbException.class, () -> p.maxWorkers(2));
            assertEquals(Status.TRIPLE_CLOSED, e.status());
        }
    }

    @Test
    void opaquePrimitiveNameRelay() {
        // An unknown inner-hash name is relayed to Go and rejected
        // there — the binding performs no name validation of its own.
        Opts opts = new Opts().withInnerHash("no-such-hash");
        ItbException e = assertThrows(ItbException.class,
                () -> Pipeline.init("singlemsg-triple-mac-v1", opts));
        assertNotEquals(Status.OK, e.status());
    }
}
