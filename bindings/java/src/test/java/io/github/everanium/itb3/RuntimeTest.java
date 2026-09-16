// Runtime diagnostics surface: GOMAXPROCS query / set / restore, the
// heap-profile writer, the pool-counter snapshot and its slot layout,
// and the hash-registry enumeration.

package io.github.everanium.itb3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class RuntimeTest {

    @Test
    void gomaxprocsQuerySetRestore() {
        int orig = Runtime.setGOMAXPROCS(0);
        assertTrue(orig > 0);
        assertEquals(orig, Runtime.setGOMAXPROCS(-3));
        assertEquals(orig, Runtime.setGOMAXPROCS(orig + 1));
        assertEquals(orig + 1, Runtime.setGOMAXPROCS(0));
        assertEquals(orig + 1, Runtime.setGOMAXPROCS(orig));
    }

    @Test
    void heapProfileWrittenAndEmptyPathRejected() throws IOException {
        Path dir = Files.createTempDirectory("itb-loop-test-heap-");
        Path profile = dir.resolve("heap.prof");
        Runtime.writeHeapProfile(profile.toString());
        assertTrue(Files.size(profile) > 0);
        Files.delete(profile);
        Files.delete(dir);

        // The empty path falls back to ITB_MEMPROFILE inside libitb3;
        // the test environment sets no such variable, so there is
        // nothing to fall back to.
        ItbException ex = assertThrows(ItbException.class, () -> Runtime.writeHeapProfile(""));
        assertEquals(Status.BAD_INPUT, ex.status());
    }

    @Test
    void poolStatsLayout() {
        int len = Runtime.poolStatsLen();
        assertTrue(len >= 9);
        long[] v = Runtime.poolStats();
        assertEquals(len, v.length);
        long tiers = v[0];
        assertTrue(tiers > 0);
        assertEquals(1 + 5 * tiers + 8, len);
    }

    @Test
    void hashNamesCanonical() {
        List<String> names = Pipeline.hashNames();
        assertEquals("aesitb128", names.get(0));
        assertTrue(names.contains("areion512"));
    }
}
