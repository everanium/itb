// Incremental decrypt session — the mirror of EncryptStream.

package dev.everanium.itb.groovy

import groovy.transform.CompileStatic

import com.everanium.itb.DecryptStream as JDecryptStream

/**
 * Incremental decrypt session: wire in through {@link #write},
 * plaintext out through {@link #read} / {@link #drainTo}. A session
 * is a dumb byte pump — all chunking, MAC, envelope, and wire-format
 * decisions stay inside libitb. {@code close()} cancels the session
 * and frees the Go-side state; the session keeps {@link #parent}
 * reachable while it is live. Obtained from
 * {@link Pipeline#decryptStream} or scoped via
 * {@link Pipeline#decrypting}.
 */
@CompileStatic
final class DecryptStream implements AutoCloseable {

    /** The parent Pipeline this session operates on; the field pins
     * it against GC while the session is live. */
    final Pipeline parent

    private final JDecryptStream underlying

    protected DecryptStream(Pipeline parent, JDecryptStream underlying) {
        this.parent = parent
        this.underlying = underlying
    }

    /** Feeds bytes into the session. Blocks until the cipher chain
     * accepts them; errors are sticky. */
    void write(byte[] chunk) {
        ItbException.relay { underlying.write(chunk) }
    }

    /** Feeds {@code len} bytes of {@code chunk} starting at
     * {@code off}. */
    void write(byte[] chunk, int off, int len) {
        ItbException.relay { underlying.write(chunk, off, len) }
    }

    /** Signals end-of-input. Idempotent; {@link #write} after end
     * fails with {@link Status#BAD_INPUT}. */
    void end() {
        ItbException.relay { underlying.end() }
    }

    /** Drains up to {@code dst.length} produced bytes into
     * {@code dst} and returns the count. Partial drains are normal;
     * before {@link #end} a drain on an empty spool returns zero
     * without blocking, after {@link #end} it blocks until the
     * terminal bytes arrive or the session errors. {@link #finished}
     * reports whether the session output is complete. */
    int read(byte[] dst) {
        ItbException.relay { underlying.read(dst) }
    }

    /** True once a {@link #read} has reported the session output
     * complete. */
    boolean isFinished() {
        underlying.finished
    }

    /** Calls {@link #end} (idempotent) and writes every remaining
     * output byte to {@code destination}. */
    void drainTo(OutputStream destination) {
        end()
        byte[] buf = new byte[1 << 20]
        while (!finished) {
            int n = read(buf)
            if (n > 0) {
                destination.write(buf, 0, n)
            }
        }
        destination.flush()
    }

    /** Cancels the session and frees the Go-side state. Idempotent. */
    @Override
    void close() {
        underlying.close()
    }
}
