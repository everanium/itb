// Session persistence surface: save / load, saveF / loadF, inspect,
// lookup / profiles / register round trip, maxWorkers clamping.

package com.everanium.itb;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PersistTest {

    private static final byte[] PLAIN =
            "persisted session payload".getBytes(StandardCharsets.UTF_8);

    @Test
    void saveThenLoadRoundTrip() {
        try (Pipeline sender = Pipeline.init("singlemsg-triple-mac-v1")) {
            byte[] blob = sender.save();
            assertTrue(blob.length > 0);
            assertArrayEquals(blob, sender.save(), "save is stable between calls");
            try (Pipeline receiver = Pipeline.load(blob)) {
                assertArrayEquals(blob, receiver.save(), "load re-marshals the same blob");
                assertArrayEquals(PLAIN, receiver.decryptMessage(sender.encryptMessage(PLAIN)));
            }
        }
    }

    @Test
    void saveFThenLoadFRoundTrip(@TempDir Path dir) throws IOException {
        Path file = dir.resolve("session.blob");
        try (Pipeline sender = Pipeline.init("streaming-aead-triple-mac-v1")) {
            sender.saveF(file.toString());
            assertArrayEquals(sender.save(), Files.readAllBytes(file));
            try (Pipeline receiver = Pipeline.loadF(file.toString())) {
                assertArrayEquals(PLAIN, receiver.decryptStreamOneShot(
                        sender.encryptStreamOneShot(PLAIN)));
            }
        }
    }

    @Test
    void loadWithMasterOverride() {
        byte[] perm = new byte[32];
        byte[] wrap = new byte[32];
        java.util.Arrays.fill(perm, (byte) 0x33);
        java.util.Arrays.fill(wrap, (byte) 0x44);
        try (Pipeline sender = Pipeline.init("singlemsg-triple-mac-v1")) {
            byte[] blob = sender.save();
            byte[] rotated = sender.rekey(perm, wrap);
            assertFalse(java.util.Arrays.equals(blob, rotated));
            assertArrayEquals(rotated, sender.save());
            try (Pipeline receiver = Pipeline.load(blob, perm, wrap)) {
                assertArrayEquals(PLAIN, receiver.decryptMessage(sender.encryptMessage(PLAIN)));
            }
        }
    }

    @Test
    void inspectReadsTheEmbeddedRecord() {
        try (Pipeline p = Pipeline.init("streaming-aead-triple-mac-v1")) {
            Profile prof = Pipeline.inspect(p.save());
            assertEquals("streaming-aead-triple-mac-v1", prof.name());
            assertEquals("streaming-aead", prof.mode());
            assertEquals(512, prof.width());
            assertEquals(Pipeline.lookup("streaming-aead-triple-mac-v1"), prof);
        }
    }

    @Test
    void profilesListsTheCatalogue() {
        List<String> names = Pipeline.profiles();
        assertTrue(names.contains("singlemsg-triple-mac-v1"));
        assertTrue(names.contains("streaming-aead-triple-mac-v1"));
    }

    @Test
    void registerCopyOfShippedProfile() {
        Profile copy = Pipeline.lookup("singlemsg-triple-nomac-v1").name("");
        Pipeline.register("java-binding-test-copy", copy);
        Profile back = Pipeline.lookup("java-binding-test-copy");
        assertEquals("java-binding-test-copy", back.name());
        assertEquals(copy.mode(), back.mode());
        assertTrue(Pipeline.profiles().contains("java-binding-test-copy"));
        try (Pipeline sender = Pipeline.init("java-binding-test-copy");
                Pipeline receiver = Pipeline.load(sender.save())) {
            assertArrayEquals(PLAIN, receiver.decryptMessage(sender.encryptMessage(PLAIN)));
        }
    }

    @Test
    void profileJsonCodecRoundTrips() {
        Profile p = Pipeline.lookup("streaming-aead-triple-mac-mixed-v1");
        assertEquals(8, p.hashes().size());
        assertEquals(p, Profile.fromJson(p.toJson()));
    }

    @Test
    void maxWorkersClamps() {
        try (Pipeline p = Pipeline.init("singlemsg-triple-mac-v1", new Opts().withMaxWorkers(-1))) {
            p.maxWorkers(2);
            p.maxWorkers(-1);
            p.maxWorkers(1000);
            assertArrayEquals(PLAIN, p.decryptMessage(p.encryptMessage(PLAIN)));
        }
    }
}
