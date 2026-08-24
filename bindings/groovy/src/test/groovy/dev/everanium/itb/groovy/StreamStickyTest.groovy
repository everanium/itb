// A decrypt session fed a tampered wire fails with a sticky MAC
// failure. Uses a position probe rather than a single bit flip
// because the over-sized container carries CSPRNG residue in the
// non-payload area — a flip that lands inside the residue is
// architecturally inert (residue is not payload) and the session
// finishes clean. Probing 32 evenly-spaced positions makes the
// all-residue probability negligible; the first position that
// surfaces an error must give Status.MAC_FAILURE and remain sticky
// on subsequent reads.

package dev.everanium.itb.groovy

import groovy.transform.CompileStatic

import org.junit.jupiter.api.Test

import static org.junit.jupiter.api.Assertions.assertEquals
import static org.junit.jupiter.api.Assertions.assertTrue
import static org.junit.jupiter.api.Assertions.fail

@CompileStatic
class StreamStickyTest {

    @Test
    void tamperedWireStickyFailure() {
        Pipeline.withPipeline('streaming-aead-triple-mac-v1') { Pipeline sender ->
            Pipeline.withOpened('streaming-aead-triple-mac-v1', sender.blob) { Pipeline receiver ->
                byte[] plain = new byte[65_536]
                for (int i = 0; i < plain.length; i++) {
                    plain[i] = (byte) (i % 227)
                }
                byte[] baseWire = sender.encryptStreamOneShot(plain)
                assertTrue(baseWire.length > 128,
                        "wire too short to place a distributed probe: ${baseWire.length} bytes")

                int probes = 32
                // Evenly spread through the wire body; skip the first
                // / last 16 bytes so a hit against the outer envelope
                // framing does not muddy the observation.
                int bodyStart = 16
                int bodyEnd = baseWire.length - 16
                int stride = (bodyEnd - bodyStart).intdiv(probes)

                for (int probe = 0; probe < probes; probe++) {
                    int idx = bodyStart + probe * stride
                    byte[] wire = baseWire.clone()
                    wire[idx] = (byte) (wire[idx] ^ 0x01)

                    ItbException firstErr = receiver.decrypting { DecryptStream session ->
                        // Ignore write / end failures — the error may
                        // surface on either side or only on the drain
                        // that follows.
                        try {
                            session.write(wire)
                            session.end()
                        } catch (ItbException ignored) {
                        }

                        byte[] buf = new byte[4096]
                        while (true) {
                            try {
                                session.read(buf)
                            } catch (ItbException e) {
                                // Sticky: a subsequent read reports
                                // the same status.
                                try {
                                    session.read(buf)
                                    fail('expected the session error to be sticky')
                                } catch (ItbException again) {
                                    assertEquals(e.status, again.status)
                                }
                                return e
                            }
                            if (session.finished) {
                                return null
                            }
                        }
                    }

                    if (firstErr == null) {
                        // Residue hit at this offset — try the next
                        // probe position. (The errored session was
                        // closed by the decrypting scope; a fresh one
                        // opens on the next iteration.)
                        continue
                    }
                    assertEquals(Status.MAC_FAILURE, firstErr.status,
                            "expected MAC failure on tampered wire at probe $probe (byte $idx)")
                    return
                }
                fail("no probe among $probes evenly-spaced positions surfaced a MAC " +
                        'failure — either the probe pattern is degenerate or ' +
                        'authentication is not covering the wire body it should')
            }
        }
    }
}
