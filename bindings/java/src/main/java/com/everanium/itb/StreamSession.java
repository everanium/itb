// Incremental stream sessions over an open Pipeline.
//
// A session is a dumb byte pump: the encrypt side takes plaintext in
// through write() and yields wire through read(); the decrypt side is
// the mirror (wire in, plaintext out). All chunking, MAC, envelope,
// and wire-format decisions stay inside libitb. Closing a session
// (explicitly or via the Cleaner on GC) cancels it and frees the
// Go-side state.

package com.everanium.itb;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.lang.ref.Cleaner;
import java.lang.ref.Reference;
import java.nio.ByteBuffer;

/** Shared body of {@link EncryptStream} / {@link DecryptStream}. */
abstract class StreamSession implements AutoCloseable {

    /** Feed / drain slice size used by the pump loops. */
    private static final int PUMP_BUF = 1 << 20;

    /** Pins the parent Pipeline so GC cannot free it under a live
     * session (the session handle references Go-side state owned by
     * the Pipeline). */
    private final Pipeline parent;

    private final long handle;
    private final Cleaner.Cleanable cleanable;
    private boolean finished;

    // Cached direct scratch buffers, grown on demand — sessions are
    // single-caller by contract, so reuse is safe and keeps the pump
    // loops allocation-free.
    private ByteBuffer scratchIn;
    private ByteBuffer scratchOut;

    /** Cleaner action holding only the raw session handle. */
    private static final class Handle implements Runnable {
        final long value;

        Handle(long value) {
            this.value = value;
        }

        @Override
        public void run() {
            Native.tripleStreamFree(value);
        }
    }

    StreamSession(Pipeline parent, boolean encrypt) {
        this.parent = parent;
        long[] out = new long[1];
        ItbException.check(encrypt
                ? Native.tripleEncryptStreamBegin(parent.rawHandle(), out)
                : Native.tripleDecryptStreamBegin(parent.rawHandle(), out));
        this.handle = out[0];
        this.cleanable = Native.CLEANER.register(this, new Handle(out[0]));
    }

    /** Feeds {@code src} into the session. Blocks until the cipher
     * chain accepts the bytes; errors are sticky. */
    public void write(byte[] src) {
        write(src, 0, src.length);
    }

    /** Feeds {@code len} bytes of {@code src} starting at {@code off}. */
    public void write(byte[] src, int off, int len) {
        ByteBuffer in = growIn(len);
        in.position(0);
        in.put(src, off, len);
        try {
            ItbException.check(Native.tripleStreamWrite(handle, in, len));
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /** Feeds {@code src.remaining()} bytes from a direct
     * {@link ByteBuffer} into the session with no intermediate copy;
     * the position advances to the limit. A heap buffer is rejected
     * with {@link IllegalArgumentException}. */
    public void write(ByteBuffer src) {
        if (src == null || !src.isDirect()) {
            throw new IllegalArgumentException(
                    "itb: src must be a direct ByteBuffer");
        }
        int len = src.remaining();
        // The slice's own base address carries the position offset.
        ByteBuffer window = len == 0 ? null : src.slice();
        try {
            ItbException.check(Native.tripleStreamWrite(handle, window, len));
        } finally {
            Reference.reachabilityFence(this);
        }
        src.position(src.limit());
    }

    /** Signals end-of-input. Idempotent; {@code write} after
     * {@code end} fails with {@link Status#BAD_INPUT}. */
    public void end() {
        try {
            ItbException.check(Native.tripleStreamEnd(handle));
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /** Drains up to {@code dst.length} produced bytes into {@code dst}
     * and returns the count. Partial drains are normal; {@code 0}
     * before {@link #end} means the chain has nothing spooled yet.
     * After {@code end}, an empty-spool read blocks until the terminal
     * bytes arrive or the session errors. {@link #isFinished} reports
     * whether the session output is complete. */
    public int read(byte[] dst) {
        ByteBuffer out = growOut(dst.length);
        long[] n = new long[1];
        int[] fin = new int[1];
        try {
            ItbException.check(Native.tripleStreamRead(handle, out, dst.length, n, fin));
        } finally {
            Reference.reachabilityFence(this);
        }
        finished = fin[0] != 0;
        out.position(0);
        out.get(dst, 0, (int) n[0]);
        return (int) n[0];
    }

    /** Drains up to {@code dst.remaining()} produced bytes directly
     * into a caller-supplied writable direct {@link ByteBuffer} — no
     * drain-side allocation and no copy-out; the position advances by
     * the returned count and libitb never writes past the limit
     * (Ruby-style out-of-bounds guard). Same blocking / completion
     * semantics as {@link #read}; {@link #isFinished} reports whether
     * the session output is complete. A heap, read-only, or spent
     * buffer is rejected with {@link IllegalArgumentException}. */
    public int readInto(ByteBuffer dst) {
        if (dst == null || !dst.isDirect() || dst.isReadOnly()) {
            throw new IllegalArgumentException(
                    "itb: dst must be a writable direct ByteBuffer");
        }
        if (!dst.hasRemaining()) {
            throw new IllegalArgumentException(
                    "itb: dst has no remaining capacity");
        }
        // The slice's own base address carries the position offset.
        ByteBuffer window = dst.slice();
        long[] n = new long[1];
        int[] fin = new int[1];
        try {
            ItbException.check(Native.tripleStreamRead(
                    handle, window, window.capacity(), n, fin));
        } finally {
            Reference.reachabilityFence(this);
        }
        finished = fin[0] != 0;
        dst.position(dst.position() + (int) n[0]);
        return (int) n[0];
    }

    /** True once a {@link #read} has reported the session output
     * complete. */
    public boolean isFinished() {
        return finished;
    }

    /** The parent Pipeline this session operates on. */
    public Pipeline pipeline() {
        return parent;
    }

    /** Pumps {@code src} into {@code dst} with bounded memory: feed a
     * slice, drain available output, repeat; end + final drain on
     * source EOF. */
    void pump(InputStream src, OutputStream dst) {
        byte[] inbuf = new byte[PUMP_BUF];
        byte[] outbuf = new byte[PUMP_BUF];
        try {
            int n;
            while ((n = src.read(inbuf)) > 0) {
                write(inbuf, 0, n);
                // Drain whatever the chain has produced so far; a read
                // before end() never blocks.
                int m;
                while ((m = read(outbuf)) > 0) {
                    dst.write(outbuf, 0, m);
                }
            }
            end();
            while (!isFinished()) {
                int m = read(outbuf);
                if (m > 0) {
                    dst.write(outbuf, 0, m);
                }
            }
            dst.flush();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Cancels the session (if still live) and frees the Go-side
     * state. Idempotent; safe concurrently with GC. */
    @Override
    public void close() {
        cleanable.clean();
    }

    private ByteBuffer growIn(int len) {
        if (scratchIn == null || scratchIn.capacity() < len) {
            scratchIn = ByteBuffer.allocateDirect(Math.max(len, 1));
        }
        return scratchIn;
    }

    private ByteBuffer growOut(int len) {
        if (scratchOut == null || scratchOut.capacity() < len) {
            scratchOut = ByteBuffer.allocateDirect(Math.max(len, 1));
        }
        return scratchOut;
    }
}
