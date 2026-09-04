// A decrypt session fed a tampered wire fails with a sticky MAC
// failure. Uses a position probe rather than a single bit flip
// because the over-sized container carries CSPRNG residue in the
// non-payload area — a flip that lands inside the residue is
// architecturally inert (residue is not payload) and the session
// finishes clean. Probing 32 evenly-spaced positions makes the
// all-residue probability negligible; the first position that
// surfaces an error must give Status.MacFailure and remain sticky on
// subsequent reads.

package com.everanium.itb.kotlin

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.test.fail

class StreamStickyTest {

    @Test
    fun tamperedWireStickyFailure() {
        Pipeline.init("streaming-aead-triple-mac-v1").use { sender ->
            Pipeline.load(sender.save()).use { receiver ->
                val plain = ByteArray(65_536) { (it % 227).toByte() }
                val baseWire = sender.encryptStreamOneShot(plain)
                assertTrue(
                    baseWire.size > 128,
                    "wire too short to place a distributed probe: ${baseWire.size} bytes",
                )

                val probes = 32
                // Evenly spread through the wire body; skip the first /
                // last 16 bytes so a hit against the outer envelope
                // framing does not muddy the observation.
                val bodyStart = 16
                val bodyEnd = baseWire.size - 16
                val stride = (bodyEnd - bodyStart) / probes

                for (probe in 0 until probes) {
                    val idx = bodyStart + probe * stride

                    val wire = baseWire.copyOf()
                    wire[idx] = (wire[idx].toInt() xor 0x01).toByte()

                    receiver.decryptStream().use { session ->
                        // Ignore Write / End status — the failure may
                        // surface on either side or only on the drain
                        // that follows.
                        try {
                            session.write(wire)
                            session.end()
                        } catch (_: ItbException) {
                        }

                        val buf = ByteArray(4096)
                        var firstErr: ItbException? = null
                        var finishedClean = false
                        while (true) {
                            try {
                                val r = session.read(buf)
                                if (r.finished) {
                                    finishedClean = true
                                    break
                                }
                            } catch (e: ItbException) {
                                firstErr = e
                                break
                            }
                        }
                        if (finishedClean) {
                            // Residue hit at this offset — next probe.
                            return@use
                        }
                        val err = firstErr ?: fail("neither finished nor errored")
                        assertEquals(
                            Status.MacFailure, err.status,
                            "expected MAC failure on tampered wire at probe $probe " +
                                "(byte $idx), got ${err.status}",
                        )

                        // Sticky: a subsequent read reports the same status.
                        val again = assertFailsWith<ItbException> { session.read(buf) }
                        assertEquals(err.status, again.status)
                        return
                    }
                }
                fail(
                    "no probe among $probes evenly-spaced positions surfaced a MAC " +
                        "failure — either the probe pattern is degenerate or " +
                        "authentication is not covering the wire body it should",
                )
            }
        }
    }
}
