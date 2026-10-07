// Session persistence surface: save / load, saveF / loadF, inspect,
// lookup / profiles / register round trip, maxWorkers clamping.

package io.github.everanium.itb3;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
            // The recipe fields match the registry entry; the
            // inspection-only fields separate the two records.
            Profile registry = Pipeline.lookup("streaming-aead-triple-mac-v1");
            assertEquals(registry, Profile.fromJson(prof.toJson())
                    .nonceBits(null).barrierFill(null).containerMode(null));
        }
    }

    @Test
    void inspectCarriesTheRuntimeGlobalsLookupDoesNot() {
        // Defaults: the blob records the compile-in nonce width and
        // barrier fill margin, and inspect surfaces both.
        try (Pipeline p = Pipeline.init("streaming-aead-triple-mac-v1")) {
            Profile prof = Pipeline.inspect(p.save());
            assertEquals(Integer.valueOf(512), prof.nonceBits());
            assertEquals(Integer.valueOf(1), prof.barrierFill());
        }

        // Per-Pipeline overrides travel through the blob into inspect.
        Opts opts = new Opts().withNonceBits(256).withBarrierFill(4);
        try (Pipeline p = Pipeline.init("streaming-aead-triple-mac-v1", opts)) {
            Profile prof = Pipeline.inspect(p.save());
            assertEquals(Integer.valueOf(256), prof.nonceBits());
            assertEquals(Integer.valueOf(4), prof.barrierFill());
            assertTrue(prof.toJson().contains("\"nonce_bits\":256"));
            assertTrue(prof.toJson().contains("\"barrier_fill\":4"));
        }

        // The registry entry is the recipe alone — neither field is
        // part of it, so both read as absent rather than as zero.
        Profile registry = Pipeline.lookup("streaming-aead-triple-mac-v1");
        assertNull(registry.nonceBits());
        assertNull(registry.barrierFill());
        assertFalse(registry.toJson().contains("nonce_bits"));
        assertFalse(registry.toJson().contains("barrier_fill"));
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

    @Test
    void drbgRoundTripsThroughLoadedBlob() {
        for (String drbg : new String[] {"csprng", "aesitb128"}) {
            try (Pipeline sender = Pipeline.init("singlemsg-triple-mac-v1",
                    new Opts().withDrbg(drbg));
                    Pipeline receiver = Pipeline.load(sender.save())) {
                assertArrayEquals(PLAIN, receiver.decryptMessage(sender.encryptMessage(PLAIN)));
                assertArrayEquals(PLAIN, sender.decryptMessage(receiver.encryptMessage(PLAIN)));
            }
        }
    }

    @Test
    void inspectReportsTheDrbg() {
        try (Pipeline p = Pipeline.init("singlemsg-triple-mac-v1", new Opts().withDrbg("csprng"))) {
            Profile prof = Pipeline.inspect(p.save());
            assertEquals("csprng", prof.drbg());
            assertTrue(prof.toJson().contains("\"drbg\":\"csprng\""));
        }
    }

    @Test
    void unknownDrbgIsRecipePrimitiveUnknown() {
        ItbException e = assertThrows(ItbException.class,
                () -> Pipeline.init("singlemsg-triple-mac-v1", new Opts().withDrbg("nope")));
        assertEquals(Status.RECIPE_PRIMITIVE_UNKNOWN, e.status());
        assertTrue(e.getMessage().contains("nope"));
    }

    @Test
    void defaultDrbgIsAbsent() {
        try (Pipeline p = Pipeline.init("singlemsg-triple-mac-v1")) {
            Profile prof = Pipeline.inspect(p.save());
            assertEquals("", prof.drbg());
            assertFalse(prof.toJson().contains("\"drbg\""));
        }
        assertEquals("", Pipeline.lookup("singlemsg-triple-mac-v1").drbg());
    }

    @Test
    void registerCopyKeepsTheDrbg() {
        try (Pipeline p = Pipeline.init("singlemsg-triple-mac-v1", new Opts().withDrbg("csprng"))) {
            Profile copy = Pipeline.inspect(p.save())
                    .name("").nonceBits(null).barrierFill(null).containerMode(null);
            Pipeline.register("java-binding-test-drbg-copy", copy);
            Profile back = Pipeline.lookup("java-binding-test-drbg-copy");
            assertEquals("csprng", back.drbg());
            try (Pipeline sender = Pipeline.init("java-binding-test-drbg-copy");
                    Pipeline receiver = Pipeline.load(sender.save())) {
                assertEquals("csprng", Pipeline.inspect(sender.save()).drbg());
                assertArrayEquals(PLAIN, receiver.decryptMessage(sender.encryptMessage(PLAIN)));
            }
        }
    }
}
