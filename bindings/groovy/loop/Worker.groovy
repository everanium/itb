// The worker: its thread body (one warmup iteration, the warmup
// barrier, the main loop), one iteration, the session pump loop the
// stream shape drives, and the round-trip comparison that decides
// between a worker error and a data mismatch.

package io.github.everanium.itb3.groovy.loop

import groovy.transform.CompileStatic

import java.util.concurrent.BrokenBarrierException
import java.util.regex.Matcher
import java.util.regex.Pattern

import io.github.everanium.itb3.groovy.DecryptStream
import io.github.everanium.itb3.groovy.EncryptStream
import io.github.everanium.itb3.groovy.ItbException
import io.github.everanium.itb3.groovy.Pipeline

/** Cipher surfaces the --shape flag selects. */
@CompileStatic
enum Shape {
    /** Session pump: begin / write / read / end. */
    STREAM('stream'),

    /** Single Message: one whole-buffer call. */
    MESSAGE('message'),

    /** Stream surface, one whole-buffer call. */
    STREAM_ONE_SHOT('stream_one_shot'),

    /** All three, rotating by iteration number. */
    BOTH('both')

    /** The flag spelling of this shape. */
    final String label

    Shape(String label) {
        this.label = label
    }
}

/**
 * A growable output accumulator whose backing array the comparison
 * reads without a copy.
 *
 * <p>Groovy-specific. {@code ByteArrayOutputStream.toByteArray()}
 * copies on every call, which on a 16 MiB payload is one full
 * duplicate per iteration per direction; the protected fields of the
 * base class expose the same bytes in place.</p>
 */
@CompileStatic
final class Acc extends ByteArrayOutputStream {
    Acc(int cap) {
        super(cap)
    }

    /** The backing array; only the first {@link #len} bytes are
     * live. */
    byte[] raw() {
        buf
    }

    /** Live byte count. */
    int len() {
        count
    }
}

/** A failed session call: which entry failed, and with what. */
@CompileStatic
final class PumpFail {
    final String what
    final RuntimeException err

    PumpFail(String what, RuntimeException err) {
        this.what = what
        this.err = err
    }
}

@CompileStatic
final class Worker {

    private Worker() {
    }

    /** Pattern the binding's exception message carries: the status
     * code and, behind it, the library's own diagnostic sentence. */
    private static final Pattern DETAIL_RE =
            Pattern.compile('^itb: status=(-?\\d+)(?:: (.*))?$', Pattern.DOTALL)

    static Shape parseShape(String s) {
        for (Shape sh : Shape.values()) {
            if (sh.label == s) {
                return sh
            }
        }
        return null
    }

    /**
     * Renders a binding error the way every implementation reports a
     * failed library call: {@code status <code>: <last error>}; any
     * other failure carries its own text. No wording of a status code
     * is composed here — the library's diagnostic already opens with
     * the class of failure and, where there is one, the specific case,
     * so it is printed as it arrived.
     *
     * <p>Groovy-specific. That diagnostic is folded into the exception
     * message behind a fixed prefix, so the message is where it is
     * recovered from.</p>
     */
    static String detail(RuntimeException e) {
        if (!(e instanceof ItbException)) {
            String m = e.message
            return m == null ? e.toString() : m
        }
        ItbException ie = (ItbException) e
        int code = ie.rawCode
        String message = ie.message == null ? '' : ie.message
        Matcher m = DETAIL_RE.matcher(message)
        String diagnostic = m.matches() ? (m.group(2) == null ? '' : m.group(2)) : message
        return "status ${code}: ${diagnostic}"
    }

    /** Records the worker's error text (first error wins) and requests
     * a stop of the whole run. */
    static void fail(RunState r, int id, String text) {
        r.workers[id].setError(text)
        r.stop = true
    }

    /**
     * Pump loop. The Go harness hands ITB an io.Reader / io.Writer
     * pair and ITB drives the chunk loop internally; the C ABI has no
     * reader / writer entry, so the caller drives it: open a session,
     * feed slices of at most 1 MiB, drain whatever the session has
     * produced after every write (a read before end never blocks),
     * end, then drain until the session reports finished (after end, a
     * read on an empty spool blocks until the terminal bytes arrive).
     * The whole produced output lands in the worker's reusable
     * accumulator. The loop is written here rather than delegated to
     * the binding's pump convenience so it stands in the utility, at
     * the same place, in every language. On failure the result names
     * the failing call and carries its error.
     */
    private static PumpFail pump(Pipeline pipe, boolean encrypt, byte[] src, int srcLen,
            Acc acc, byte[] scratch) {
        acc.reset()
        EncryptStream es = null
        DecryptStream ds = null
        try {
            try {
                if (encrypt) {
                    es = pipe.encryptStream()
                } else {
                    ds = pipe.decryptStream()
                }
            } catch (RuntimeException e) {
                return new PumpFail('StreamBegin', e)
            }
            // Groovy-specific. The two session directions are distinct
            // final classes with no common supertype on the binding's
            // surface, so every call below branches on which side is
            // open.
            for (int off = 0; off < srcLen; off += Main.PUMP_SLICE) {
                int n = Math.min(Main.PUMP_SLICE, srcLen - off)
                try {
                    if (es != null) {
                        es.write(src, off, n)
                    } else {
                        ds.write(src, off, n)
                    }
                } catch (RuntimeException e) {
                    return new PumpFail('StreamWrite', e)
                }
                while (true) {
                    int m
                    try {
                        m = es != null ? es.read(scratch) : ds.read(scratch)
                    } catch (RuntimeException e) {
                        return new PumpFail('StreamRead', e)
                    }
                    if (m == 0) {
                        break
                    }
                    acc.write(scratch, 0, m)
                }
            }
            try {
                if (es != null) {
                    es.end()
                } else {
                    ds.end()
                }
            } catch (RuntimeException e) {
                return new PumpFail('StreamEnd', e)
            }
            while (true) {
                int m
                boolean finished
                try {
                    if (es != null) {
                        m = es.read(scratch)
                        finished = es.isFinished()
                    } else {
                        m = ds.read(scratch)
                        finished = ds.isFinished()
                    }
                } catch (RuntimeException e) {
                    return new PumpFail('StreamRead', e)
                }
                acc.write(scratch, 0, m)
                if (finished) {
                    break
                }
            }
            return null
        } finally {
            if (es != null) {
                es.close()
            }
            if (ds != null) {
                ds.close()
            }
        }
    }

    /** First offset at which the two ranges differ; the shorter length
     * when one is a prefix of the other. */
    private static int firstDifference(byte[] a, int aLen, byte[] b, int bLen) {
        int n = Math.min(aLen, bLen)
        for (int i = 0; i < n; i++) {
            if (a[i] != b[i]) {
                return i
            }
        }
        return n
    }

    /** Up to 16 bytes of buf from off as lowercase hex, or "-" when
     * buf has no bytes there. */
    private static String hexWindow(byte[] buf, int len, int off) {
        if (off >= len) {
            return '-'
        }
        int n = Math.min(16, len - off)
        StringBuilder sb = new StringBuilder(n * 2)
        for (int i = 0; i < n; i++) {
            int v = ((int) buf[off + i]) & 0xFF
            sb.append(Character.forDigit(v >>> 4, 16)).append(Character.forDigit(v & 0xF, 16))
        }
        return sb.toString()
    }

    private static boolean equalBytes(byte[] a, int aLen, byte[] b, int bLen) {
        if (aLen != bLen) {
            return false
        }
        for (int i = 0; i < aLen; i++) {
            if (a[i] != b[i]) {
                return false
            }
        }
        return true
    }

    /** Records a worker error for a failed cipher call. */
    private static void cipherFail(RunState r, int id, long iter, Shape shape,
            String direction, String what, RuntimeException e) {
        String head = "g${id} iter ${iter} shape=${shape.label}: ${direction}"
        fail(r, id, what == null
                ? "${head}: ${detail(e)}".toString()
                : "${head}: ${what}: ${detail(e)}".toString())
    }

    /**
     * One iteration. In order: refill the plaintext under rotating
     * mode; take the read lock; pick the surface; encrypt (timed);
     * decrypt (timed); compare the round-trip with the plaintext; bump
     * the counters; release the lock. The whole round-trip runs under
     * the read lock so handle-mutating maintenance (rekey, blob
     * reopen) never lands between an encrypt and its matching decrypt
     * — maintenance runs after this returns, from the worker loop.
     * False after recording a worker error.
     */
    private static boolean iterate(RunState r, WorkerState w, long iter) {
        Counters c = r.workers[w.id]
        if (w.payloadMode == PayloadMode.ROTATING &&
                !Payload.fill(PayloadMode.ROTATING, w.seeded, w.rng, w.plaintext)) {
            fail(r, w.id, "g${w.id} iter ${iter}: payload refill: csprng".toString())
            return false
        }

        r.pipesLock.readLock().lock()
        try {
            // Shape dispatch. message is one whole-buffer call on the
            // Single Message Pipeline; stream_one_shot is one
            // whole-buffer call on the streaming Pipeline (the C ABI's
            // ITB_Triple_EncryptStream, which routes to the same
            // whole-buffer stream entry the Go harness calls by name);
            // stream opens a session on the same streaming Pipeline
            // and drives the chunk loop from here. Under both the
            // three rotate by iteration number so the session path and
            // the whole-buffer path alternate on one handle inside
            // every worker — the cross-path state-reuse hazard this
            // harness exists to catch.
            Shape shape = r.cfg.shape
            if (shape == Shape.BOTH) {
                long slot = iter % 3
                shape = slot == 0L ? Shape.STREAM : (slot == 1L ? Shape.MESSAGE : Shape.STREAM_ONE_SHOT)
            }

            // Groovy-specific. The message and one-shot entries return
            // a fresh array per call that the collector reclaims at
            // the end of the iteration; the pump accumulators are the
            // worker's own and are reused. `got` / `gotLen` hold the
            // round-trip output for either posture, so one comparison
            // below serves both.
            byte[] got
            int gotLen
            long t0
            if (shape == Shape.STREAM) {
                Pipeline pipe = r.pipes.stream
                t0 = System.nanoTime()
                PumpFail f = pump(pipe, true, w.plaintext, w.plaintext.length, w.wire, w.scratch)
                if (f != null) {
                    cipherFail(r, w.id, iter, shape, 'encrypt', f.what, f.err)
                    return false
                }
                c.addEncrypt(System.nanoTime() - t0)
                t0 = System.nanoTime()
                f = pump(pipe, false, w.wire.raw(), w.wire.len(), w.plain, w.scratch)
                if (f != null) {
                    cipherFail(r, w.id, iter, shape, 'decrypt', f.what, f.err)
                    return false
                }
                c.addDecrypt(System.nanoTime() - t0)
                got = w.plain.raw()
                gotLen = w.plain.len()
            } else if (shape == Shape.STREAM_ONE_SHOT) {
                Pipeline pipe = r.pipes.stream
                byte[] wire
                t0 = System.nanoTime()
                try {
                    wire = pipe.encryptStreamOneShot(w.plaintext)
                } catch (RuntimeException e) {
                    cipherFail(r, w.id, iter, shape, 'encrypt', null, e)
                    return false
                }
                c.addEncrypt(System.nanoTime() - t0)
                t0 = System.nanoTime()
                try {
                    got = pipe.decryptStreamOneShot(wire)
                } catch (RuntimeException e) {
                    cipherFail(r, w.id, iter, shape, 'decrypt', null, e)
                    return false
                }
                c.addDecrypt(System.nanoTime() - t0)
                gotLen = got.length
            } else {
                Pipeline pipe = r.pipes.msg
                byte[] wire
                t0 = System.nanoTime()
                try {
                    wire = pipe.encryptMessage(w.plaintext)
                } catch (RuntimeException e) {
                    cipherFail(r, w.id, iter, shape, 'encrypt', null, e)
                    return false
                }
                c.addEncrypt(System.nanoTime() - t0)
                t0 = System.nanoTime()
                try {
                    got = pipe.decryptMessage(wire)
                } catch (RuntimeException e) {
                    cipherFail(r, w.id, iter, shape, 'decrypt', null, e)
                    return false
                }
                c.addDecrypt(System.nanoTime() - t0)
                gotLen = got.length
            }

            // Failure model. A cipher call that returns a non-OK
            // status is a worker error: it is recorded, the run is
            // asked to stop, the other workers finish their in-flight
            // iteration, and the error is listed in the summary with
            // the FAIL verdict. A round-trip that returns OK with
            // different bytes is a data mismatch: the process
            // terminates here, without summary or cleanup, because the
            // Pipeline state that produced the wrong bytes is the
            // evidence and nothing that runs afterwards may touch it.
            // Groovy-specific: Runtime.halt is the exit that runs
            // neither the shutdown hooks nor the Cleaner registrations
            // behind the Java layer's handles, which is the point — a
            // cleaner-driven free would release the very state the
            // operator is meant to inspect.
            byte[] want = w.plaintext
            if (!equalBytes(want, want.length, got, gotLen)) {
                int off = firstDifference(want, want.length, got, gotLen)
                System.err.println("loop: DATA MISMATCH g${w.id} iter ${iter} " +
                        "shape=${shape.label}: want ${want.length} bytes, got ${gotLen} bytes, " +
                        "first difference at offset ${off}: " +
                        "want ${hexWindow(want, want.length, off)} " +
                        "got ${hexWindow(got, gotLen, off)}")
                System.err.flush()
                System.out.flush()
                java.lang.Runtime.getRuntime().halt(3)
            }

            c.addIteration((long) want.length, (long) gotLen)
            return true
        } finally {
            r.pipesLock.readLock().unlock()
        }
    }

    /** Marks this worker returned; the last one to return stamps the
     * finish instant and wakes main. */
    private static void done(RunState r) {
        r.doneLock.lock()
        try {
            r.active--
            if (r.active == 0) {
                r.finishNanos = System.nanoTime()
                r.doneCond.signalAll()
            }
        } finally {
            r.doneLock.unlock()
        }
    }

    /**
     * The worker thread body: one warmup iteration, the warmup
     * barrier, then the main loop until a stop is requested or the
     * fixed per-worker iteration budget (warmup included) is spent. A
     * failing warmup still passes both barriers so the launcher never
     * waits on a worker that has already given up.
     */
    static void run(RunState r, WorkerState w) {
        // Warmup iteration — counted in the totals; its completion
        // feeds the post-warmup baselines.
        boolean ok = iterate(r, w, 0L)
        try {
            r.warmupDone.await()
            r.release.await()
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt()
            done(r)
            return
        } catch (BrokenBarrierException e) {
            done(r)
            return
        }
        if (!ok) {
            done(r)
            return
        }

        for (long iter = 1L; ; iter++) {
            if (r.cfg.iterations > 0 && iter >= r.cfg.iterations) {
                break
            }
            if (r.stop) {
                break
            }
            if (!iterate(r, w, iter)) {
                break
            }
            if (!Ops.maintenance(r, w.id, iter)) {
                break
            }
        }
        done(r)
    }
}
