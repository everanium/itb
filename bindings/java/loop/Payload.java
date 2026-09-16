// Plaintext content: the payload modes, the seeded per-worker
// generator, and the buffer fill from the operating-system CSPRNG.

package io.github.everanium.itb3.loop;

import java.security.SecureRandom;

final class Payload {

    private Payload() {
    }

    /**
     * Payload mode selector values for the --payload-mode flag.
     *
     * <ul>
     *   <li>FIXED: one CSPRNG-generated buffer per worker, held unchanged
     *       for the whole run (the default).</li>
     *   <li>ROTATING: the buffer is regenerated before every iteration, so
     *       no two encrypt calls see the same plaintext.</li>
     *   <li>PATTERN_ZERO / PATTERN_FF: degenerate constant fills (all 0x00
     *       / all 0xFF) probing minimum-entropy plaintext handling.</li>
     *   <li>PATTERN_ASCII: a repeating 'A'..'Z' ramp probing low-entropy
     *       structured text.</li>
     * </ul>
     */
    enum PayloadMode {
        FIXED("fixed"),
        ROTATING("rotating"),
        PATTERN_ZERO("pattern-zero"),
        PATTERN_FF("pattern-ff"),
        PATTERN_ASCII("pattern-ascii");

        private final String label;

        PayloadMode(String label) {
            this.label = label;
        }

        /** The flag spelling of this mode. */
        String label() {
            return label;
        }
    }

    /**
     * The deterministic per-worker generator's state. Java has no
     * by-reference scalar parameter, so the splitmix64 state lives in
     * this one-field holder that the worker owns and the generator
     * advances in place.
     */
    static final class Rng {
        private long state;

        Rng(long seed) {
            this.state = seed;
        }
    }

    /** The operating-system CSPRNG, one instance per calling thread so
     * concurrent payload refills never serialise on one provider. */
    private static final ThreadLocal<SecureRandom> CSPRNG =
            ThreadLocal.withInitial(SecureRandom::new);

    static PayloadMode parse(String s) {
        for (PayloadMode m : PayloadMode.values()) {
            if (m.label().equals(s)) {
                return m;
            }
        }
        return null;
    }

    /**
     * Seeded plaintext. The seed makes plaintext content reproducible
     * so a failing iteration can be replayed with the same bytes; it
     * governs nothing else — pipeline keys, nonces and masters stay
     * CSPRNG-drawn, so a seeded run is a reproduction aid and never a
     * security test. Each worker's stream is domain-separated by its id
     * so seeded workers still hold pairwise-distinct buffers under the
     * fixed and rotating modes. The generator is splitmix64: a few
     * lines in any language, which is why it is the one every binding
     * uses.
     */
    static long seedWorker(long seed, int workerId) {
        return seed + workerId + 1;
    }

    private static long splitmix64(Rng rng) {
        rng.state += 0x9E3779B97F4A7C15L;
        long z = rng.state;
        z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9L;
        z = (z ^ (z >>> 27)) * 0x94D049BB133111EBL;
        return z ^ (z >>> 31);
    }

    /**
     * Fills {@code buf} from the operating-system CSPRNG.
     *
     * <p>Java-specific. The JDK's default {@code SecureRandom}
     * provider on this platform draws from {@code /dev/urandom}
     * through a file descriptor rather than through the glibc
     * {@code getrandom} entry, and the platform offers no supported
     * way for a pure-Java source set to reach that entry — the
     * foreign-function API is not available on the toolchain's
     * language level, and a JNI declaration of its own is exactly the
     * reach past the binding the utility must not make. One draw still
     * happens per fill; it is observable as a read on that descriptor
     * rather than as a {@code getrandom} call.
     */
    static boolean fillRandom(byte[] buf) {
        CSPRNG.get().nextBytes(buf);
        return true;
    }

    /**
     * Writes one plaintext buffer according to the payload mode. The
     * fixed and rotating modes draw from the seeded generator when the
     * run is seeded and from the OS CSPRNG otherwise; the pattern modes
     * are deterministic regardless of the seed. False when the CSPRNG
     * fails.
     */
    static boolean fill(PayloadMode mode, boolean seeded, Rng rng, byte[] buf) {
        switch (mode) {
            case FIXED:
            case ROTATING:
                if (!seeded) {
                    return fillRandom(buf);
                }
                for (int i = 0; i < buf.length; i += 8) {
                    long v = splitmix64(rng);
                    int n = Math.min(8, buf.length - i);
                    for (int k = 0; k < n; k++) {
                        buf[i + k] = (byte) (v >>> (8 * k));
                    }
                }
                return true;
            case PATTERN_ZERO:
                java.util.Arrays.fill(buf, (byte) 0);
                return true;
            case PATTERN_FF:
                java.util.Arrays.fill(buf, (byte) 0xFF);
                return true;
            default:
                for (int i = 0; i < buf.length; i++) {
                    buf[i] = (byte) ('A' + (i % 26));
                }
                return true;
        }
    }
}
