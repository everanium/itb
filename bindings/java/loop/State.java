// The declarations every unit of the utility shares: the resolved
// command line, the Pipeline handles behind their lock, the per-worker
// counters, the per-worker private state, and the run state itself.
//
// Java-specific. These would sit beside the code that owns them, as
// they do in the C reference's shared header; the toolchain's
// warnings-as-errors posture rejects a second top-level class in a
// file that another file reads, so the shared declarations are nested
// inside one carrier type and imported by name.

package io.github.everanium.itb3.loop;

import io.github.everanium.itb3.Pipeline;
import io.github.everanium.itb3.loop.Payload.PayloadMode;
import io.github.everanium.itb3.loop.Payload.Rng;
import io.github.everanium.itb3.loop.Worker.Acc;
import io.github.everanium.itb3.loop.Worker.Shape;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/** Carrier for the declarations shared across the utility's units. */
final class State {

    private State() {
    }

    /** The resolved command line. */
    static final class Config {
        long durationNs;
        long iterations;
        int workersRequested;
        int workers;
        Shape shape;
        String hash = "";
        String mac = "";
        long payload;
        long memlimit;
        boolean memlimitAuto;
        int gogc;
        boolean parallax;
        boolean wrapper;
        String profile = "";
        long keyBits;
        long nonceBits;
        long chunkSize;
        long barrierFill;
        int gomaxprocs;
        long rekeyEvery;
        long blobCycleEvery;
        PayloadMode payloadMode;
        long seed;
        boolean jsonOutput;
        String memprofile = "";
    }

    /** The Pipeline handles and their retained blobs, behind the lock that
     * keeps iterations clear of handle mutation. */
    static final class Pipes {
        Pipeline stream;
        Pipeline msg;

        /** The blob Init handed out, replaced by every rekey; the input of
         * the next blob reopen. */
        byte[] streamBlob = new byte[0];
        byte[] msgBlob = new byte[0];
    }

    /** One worker's counters, read by the summary after every worker has
     * returned, and the error it stopped on. */
    static final class Counters {
        final AtomicLong iters = new AtomicLong();
        final AtomicLong bytesEnc = new AtomicLong();
        final AtomicLong bytesDec = new AtomicLong();
        final AtomicLong nanosEnc = new AtomicLong();
        final AtomicLong nanosDec = new AtomicLong();
        private final Object errorLock = new Object();
        private String error;

        void addEncrypt(long ns) {
            nanosEnc.addAndGet(ns);
        }

        void addDecrypt(long ns) {
            nanosDec.addAndGet(ns);
        }

        void addIteration(long encBytes, long decBytes) {
            iters.incrementAndGet();
            bytesEnc.addAndGet(encBytes);
            bytesDec.addAndGet(decBytes);
        }

        /** Records the first error only. */
        void setError(String text) {
            synchronized (errorLock) {
                if (error == null) {
                    error = text;
                }
            }
        }

        String error() {
            synchronized (errorLock) {
                return error;
            }
        }
    }

    /** One worker's private state, owned by its thread: its plaintext, its
     * reusable pump accumulators, its generator. */
    static final class WorkerState {
        int id;
        byte[] plaintext = new byte[0];
        PayloadMode payloadMode;
        boolean seeded;
        Rng rng;
        final Acc wire = new Acc(1 << 20);
        final Acc plain = new Acc(1 << 20);
        byte[] scratch = new byte[0];
    }

    /** The state every worker shares. */
    static final class RunState {
        Config cfg = new Config();
        String streamProfile = "";
        String msgProfile = "";

        /** Handle mutation. Iterations hold the read side for their whole
         * encrypt → decrypt → compare; rekey and blob reopen take the write
         * side, so no cipher call is in flight while a handle's keying
         * changes or the handle itself is swapped, and no encrypt is
         * separated from its decrypt by either. */
        final ReentrantReadWriteLock pipesLock = new ReentrantReadWriteLock();

        Pipes pipes = new Pipes();
        final AtomicLong rekeys = new AtomicLong();
        final AtomicLong blobCycles = new AtomicLong();
        Counters[] workers = new Counters[0];

        /** Warmup barrier: workers arrive at warmupDone after iteration 0
         * and at release once main has taken the baselines. */
        CyclicBarrier warmupDone = new CyclicBarrier(1);
        CyclicBarrier release = new CyclicBarrier(1);

        /** Set by the duration deadline, by a signal, or by a failing
         * worker; checked by every worker before it starts an iteration. */
        volatile boolean stop;

        final Object doneLock = new Object();
        int active;
        long finishNanos;

        long rssWarmup;
        long rssPeak;
        long rssFinal;
        long[] poolWarmup = new long[0];
        long[] poolSteady = new long[0];
    }
}
