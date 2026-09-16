// The maintenance operations that mutate a live Pipeline handle
// between iterations: master rotation (--rekey-every) and blob reopen
// (--blob-cycle-every).

package io.github.everanium.itb3.loop;

import io.github.everanium.itb3.Pipeline;
import io.github.everanium.itb3.loop.State.Config;
import io.github.everanium.itb3.loop.State.RunState;

final class Ops {

    private Ops() {
    }

    /** Byte length of each fresh master drawn for a rotation. Matches
     * the size Init auto-generates for both the parallax and the
     * wrapper master. */
    private static final int REKEY_MASTER_SIZE = 32;

    /** The empty master a disabled layer passes; Rekey ignores it. */
    private static final byte[] NO_MASTER = new byte[0];

    /**
     * Master rotation. Rotates the parallax + wrapper masters on every
     * active Pipeline under the write lock and retains the refreshed
     * blob for subsequent blob reopens. Masters are drawn fresh from
     * the OS CSPRNG on every rotation regardless of --seed (master
     * rotation is pipeline keying, not plaintext content); a disabled
     * layer passes no bytes, which Rekey ignores. The eight inner seeds
     * and the MAC key are untouched by design — Rekey targets only the
     * two outer-layer master secrets.
     */
    private static boolean rekeyPipes(RunState r, int id, long iter) {
        byte[] perm = NO_MASTER;
        byte[] wrap = NO_MASTER;
        if (r.cfg.parallax) {
            perm = new byte[REKEY_MASTER_SIZE];
            if (!Payload.fillRandom(perm)) {
                Worker.fail(r, id, "g" + id + " iter " + iter + ": csprng: parallax master");
                return false;
            }
        }
        if (r.cfg.wrapper) {
            wrap = new byte[REKEY_MASTER_SIZE];
            if (!Payload.fillRandom(wrap)) {
                Worker.fail(r, id, "g" + id + " iter " + iter + ": csprng: wrapper master");
                return false;
            }
        }

        r.pipesLock.writeLock().lock();
        try {
            if (r.pipes.stream != null) {
                try {
                    r.pipes.streamBlob = r.pipes.stream.rekey(perm, wrap);
                } catch (RuntimeException e) {
                    Worker.fail(r, id, "g" + id + " iter " + iter + ": Rekey("
                            + r.streamProfile + "): " + Worker.detail(e));
                    return false;
                }
            }
            if (r.pipes.msg != null) {
                try {
                    r.pipes.msgBlob = r.pipes.msg.rekey(perm, wrap);
                } catch (RuntimeException e) {
                    Worker.fail(r, id, "g" + id + " iter " + iter + ": Rekey("
                            + r.msgProfile + "): " + Worker.detail(e));
                    return false;
                }
            }
        } finally {
            r.pipesLock.writeLock().unlock();
        }
        long n = r.rekeys.incrementAndGet();
        Main.logLine("rekey: g" + id + " iter " + iter
                + " rotated parallax + wrapper masters (rekey #" + n + ")");
        return true;
    }

    /**
     * Blob reopen. Reopens every active Pipeline from its retained blob
     * under the write lock: a fresh handle is loaded from the blob, the
     * running handle is freed, and the fresh one is swapped in, so
     * every later iteration round-trips through seeds and masters that
     * survived a blob crossing. The input is the blob Init or the
     * latest Rekey handed out, not a fresh Save: that is what a
     * receiver holds, and reopening from it proves the handed-out bytes
     * rather than the live state. The blob carries the Pipeline's full
     * shape, so no override reaches the reopen. On a Load failure the
     * running handle stays and the failure aborts the run.
     */
    private static boolean blobCyclePipes(RunState r, int id, long iter) {
        r.pipesLock.writeLock().lock();
        try {
            if (r.pipes.stream != null) {
                Pipeline fresh;
                try {
                    fresh = Pipeline.load(r.pipes.streamBlob);
                } catch (RuntimeException e) {
                    Worker.fail(r, id, "g" + id + " iter " + iter + ": Load("
                            + r.streamProfile + "): " + Worker.detail(e));
                    return false;
                }
                r.pipes.stream.close();
                r.pipes.stream = fresh;
            }
            if (r.pipes.msg != null) {
                Pipeline fresh;
                try {
                    fresh = Pipeline.load(r.pipes.msgBlob);
                } catch (RuntimeException e) {
                    Worker.fail(r, id, "g" + id + " iter " + iter + ": Load("
                            + r.msgProfile + "): " + Worker.detail(e));
                    return false;
                }
                r.pipes.msg.close();
                r.pipes.msg = fresh;
            }
        } finally {
            r.pipesLock.writeLock().unlock();
        }
        long n = r.blobCycles.incrementAndGet();
        Main.logLine("blob-cycle: g" + id + " iter " + iter
                + " reopened from session blob (cycle #" + n + ")");
        return true;
    }

    /**
     * Handle mutation. Runs the periodic Pipeline-mutating operations
     * after a completed iteration: master rotation (--rekey-every) and
     * blob reopen (--blob-cycle-every). Both intervals count per-worker
     * iterations; the warmup iteration (iter 0) never triggers because
     * the worker loop calls this for iter >= 1 only. Rekey rewrites the
     * outer-layer keying of a live handle and a blob reopen replaces
     * the handle outright; each takes the write lock, so in-flight
     * cipher calls on other workers drain before anything changes and
     * no encrypt is separated from its decrypt by either. False after
     * recording the worker error.
     */
    static boolean maintenance(RunState r, int id, long iter) {
        Config cfg = r.cfg;
        if (cfg.rekeyEvery > 0 && iter % cfg.rekeyEvery == 0 && !rekeyPipes(r, id, iter)) {
            return false;
        }
        if (cfg.blobCycleEvery > 0 && iter % cfg.blobCycleEvery == 0
                && !blobCyclePipes(r, id, iter)) {
            return false;
        }
        return true;
    }
}
