// The maintenance operations that mutate a live Pipeline handle
// between iterations: master rotation (--rekey-every) and blob reopen
// (--blob-cycle-every).

package io.github.everanium.itb3.kotlin.loop

import io.github.everanium.itb3.kotlin.Pipeline

/** Byte length of each fresh master drawn for a rotation. Matches the
 * size Init auto-generates for both the parallax and the wrapper
 * master. */
private const val REKEY_MASTER_SIZE = 32

/** The empty master a disabled layer passes; Rekey ignores it. */
private val NO_MASTER = ByteArray(0)

/**
 * Master rotation. Rotates the parallax + wrapper masters on every
 * active Pipeline under the write lock and retains the refreshed blob
 * for subsequent blob reopens. Masters are drawn fresh from the OS
 * CSPRNG on every rotation regardless of --seed (master rotation is
 * pipeline keying, not plaintext content); a disabled layer passes no
 * bytes, which Rekey ignores. The eight inner seeds and the MAC key
 * are untouched by design — Rekey targets only the two outer-layer
 * master secrets.
 */
private fun rekeyPipes(r: RunState, id: Int, iter: Long): Boolean {
    var perm = NO_MASTER
    var wrap = NO_MASTER
    if (r.cfg.parallax) {
        perm = ByteArray(REKEY_MASTER_SIZE)
        if (!fillRandom(perm)) {
            fail(r, id, "g$id iter $iter: csprng: parallax master")
            return false
        }
    }
    if (r.cfg.wrapper) {
        wrap = ByteArray(REKEY_MASTER_SIZE)
        if (!fillRandom(wrap)) {
            fail(r, id, "g$id iter $iter: csprng: wrapper master")
            return false
        }
    }

    r.pipesLock.writeLock().lock()
    try {
        r.pipes.stream?.let { pipe ->
            try {
                r.pipes.streamBlob = pipe.rekey(perm, wrap)
            } catch (e: Exception) {
                fail(r, id, "g$id iter $iter: Rekey(${r.streamProfile}): ${detail(e)}")
                return false
            }
        }
        r.pipes.msg?.let { pipe ->
            try {
                r.pipes.msgBlob = pipe.rekey(perm, wrap)
            } catch (e: Exception) {
                fail(r, id, "g$id iter $iter: Rekey(${r.msgProfile}): ${detail(e)}")
                return false
            }
        }
    } finally {
        r.pipesLock.writeLock().unlock()
    }
    val n = r.rekeys.incrementAndGet()
    logLine("rekey: g$id iter $iter rotated parallax + wrapper masters (rekey #$n)")
    return true
}

/**
 * Blob reopen. Reopens every active Pipeline from its retained blob
 * under the write lock: a fresh handle is loaded from the blob, the
 * running handle is freed, and the fresh one is swapped in, so every
 * later iteration round-trips through seeds and masters that survived
 * a blob crossing. The input is the blob Init or the latest Rekey
 * handed out, not a fresh Save: that is what a receiver holds, and
 * reopening from it proves the handed-out bytes rather than the live
 * state. The blob carries the Pipeline's full shape, so no override
 * reaches the reopen. On a Load failure the running handle stays and
 * the failure aborts the run.
 */
private fun blobCyclePipes(r: RunState, id: Int, iter: Long): Boolean {
    r.pipesLock.writeLock().lock()
    try {
        r.pipes.stream?.let { running ->
            val fresh: Pipeline = try {
                Pipeline.load(r.pipes.streamBlob)
            } catch (e: Exception) {
                fail(r, id, "g$id iter $iter: Load(${r.streamProfile}): ${detail(e)}")
                return false
            }
            running.close()
            r.pipes.stream = fresh
        }
        r.pipes.msg?.let { running ->
            val fresh: Pipeline = try {
                Pipeline.load(r.pipes.msgBlob)
            } catch (e: Exception) {
                fail(r, id, "g$id iter $iter: Load(${r.msgProfile}): ${detail(e)}")
                return false
            }
            running.close()
            r.pipes.msg = fresh
        }
    } finally {
        r.pipesLock.writeLock().unlock()
    }
    val n = r.blobCycles.incrementAndGet()
    logLine("blob-cycle: g$id iter $iter reopened from session blob (cycle #$n)")
    return true
}

/**
 * Handle mutation. Runs the periodic Pipeline-mutating operations
 * after a completed iteration: master rotation (--rekey-every) and
 * blob reopen (--blob-cycle-every). Both intervals count per-worker
 * iterations; the warmup iteration (iter 0) never triggers because the
 * worker loop calls this for iter >= 1 only. Rekey rewrites the
 * outer-layer keying of a live handle and a blob reopen replaces the
 * handle outright; each takes the write lock, so in-flight cipher
 * calls on other workers drain before anything changes and no encrypt
 * is separated from its decrypt by either. False after recording the
 * worker error.
 */
fun maintenance(r: RunState, id: Int, iter: Long): Boolean {
    val cfg = r.cfg
    if (cfg.rekeyEvery > 0 && iter % cfg.rekeyEvery == 0L && !rekeyPipes(r, id, iter)) {
        return false
    }
    if (cfg.blobCycleEvery > 0 && iter % cfg.blobCycleEvery == 0L && !blobCyclePipes(r, id, iter)) {
        return false
    }
    return true
}
