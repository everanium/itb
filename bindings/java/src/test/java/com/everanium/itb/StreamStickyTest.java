// A decrypt session fed a tampered wire fails with a sticky MAC
// failure. Uses a position probe rather than a single bit flip
// because the over-sized container carries CSPRNG residue in the
// non-payload area — a flip that lands inside the residue is
// architecturally inert (residue is not payload) and the session
// finishes clean. Probing 32 evenly-spaced positions makes the
// all-residue probability negligible; the first position that
// surfaces an error must give Status.MAC_FAILURE and remain sticky
// on subsequent reads.

package com.everanium.itb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.Test;

class StreamStickyTest {

    private static final int PROBES = 32;

    @Test
    void tamperedWireStickyFailure() {
        try (Pipeline sender = Pipeline.init("streaming-aead-triple-mac-v1");
                Pipeline receiver = Pipeline.open(
                        "streaming-aead-triple-mac-v1", sender.blob(), new Opts())) {
            byte[] plain = new byte[65_536];
            for (int i = 0; i < plain.length; i++) {
                plain[i] = (byte) (i % 227);
            }
            byte[] baseWire = sender.encryptStreamOneShot(plain);
            assertTrue(baseWire.length > 128,
                    "wire too short to place a distributed probe: " + baseWire.length);

            // Evenly spread through the wire body; skip the first /
            // last 16 bytes so a hit against the outer envelope
            // framing does not muddy the observation.
            int bodyStart = 16;
            int bodyEnd = baseWire.length - 16;
            int stride = (bodyEnd - bodyStart) / PROBES;

            for (int probe = 0; probe < PROBES; probe++) {
                int idx = bodyStart + probe * stride;
                byte[] wire = baseWire.clone();
                wire[idx] ^= 0x01;

                try (DecryptStream sess = receiver.decryptStream()) {
                    // Ignore write / end status — the failure may
                    // surface on either side or only on the drain
                    // that follows.
                    try {
                        sess.write(wire);
                        sess.end();
                    } catch (ItbException ignored) {
                        // surfaced early — the drain below re-reports
                    }

                    byte[] buf = new byte[4096];
                    ItbException first = null;
                    boolean finishedClean = false;
                    while (true) {
                        try {
                            sess.read(buf);
                            if (sess.isFinished()) {
                                finishedClean = true;
                                break;
                            }
                        } catch (ItbException e) {
                            first = e;
                            break;
                        }
                    }
                    if (finishedClean) {
                        // Residue hit at this offset — next probe.
                        continue;
                    }
                    assertEquals(Status.MAC_FAILURE, first.status(),
                            "expected MAC failure on tampered wire at probe "
                                    + probe + " (byte " + idx + "), got " + first.status());

                    // Sticky: a subsequent read reports the same status.
                    ItbException again = assertThrows(ItbException.class,
                            () -> sess.read(buf));
                    assertEquals(first.status(), again.status());
                    return;
                }
            }
            fail("no probe among " + PROBES + " evenly-spaced positions surfaced a "
                    + "MAC failure — either the probe pattern is degenerate or "
                    + "authentication is not covering the wire body it should");
        }
    }
}
