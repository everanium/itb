// Runtime diagnostics surface: GOMAXPROCS query / set / restore, the
// heap-profile writer, the pool-counter snapshot and its slot layout,
// and the hash-registry enumeration.

package io.github.everanium.itb3.kotlin

import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class RuntimeTest {

    @Test
    fun gomaxprocsQuerySetRestore() {
        val orig = ItbRuntime.setGOMAXPROCS(0)
        assertTrue(orig > 0)
        assertEquals(orig, ItbRuntime.setGOMAXPROCS(-3))
        assertEquals(orig, ItbRuntime.setGOMAXPROCS(orig + 1))
        assertEquals(orig + 1, ItbRuntime.setGOMAXPROCS(0))
        assertEquals(orig + 1, ItbRuntime.setGOMAXPROCS(orig))
    }

    @Test
    fun heapProfileWrittenAndEmptyPathRejected() {
        val dir = Files.createTempDirectory("itb-loop-test-heap-")
        val profile = dir.resolve("heap.prof")
        ItbRuntime.writeHeapProfile(profile.toString())
        assertTrue(Files.size(profile) > 0)
        Files.delete(profile)
        Files.delete(dir)

        // The empty path falls back to ITB_MEMPROFILE inside libitb3;
        // the test environment sets no such variable, so there is
        // nothing to fall back to.
        val e = assertFailsWith<ItbException> { ItbRuntime.writeHeapProfile("") }
        assertEquals(Status.BadInput, e.status)
    }

    @Test
    fun poolStatsLayout() {
        val len = ItbRuntime.poolStatsLen()
        assertTrue(len >= 9)
        val v = ItbRuntime.poolStats()
        assertEquals(len, v.size)
        val tiers = v[0]
        assertTrue(tiers > 0)
        assertEquals(1 + 5 * tiers + 8, len.toLong())
    }

    @Test
    fun hashNamesCanonical() {
        val names = Pipeline.hashNames()
        assertEquals("aesitb128", names[0])
        assertContains(names, "areion512")
    }
}
