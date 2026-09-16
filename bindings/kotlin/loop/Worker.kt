// The worker: its thread body (one warmup iteration, the warmup
// barrier, the main loop), one iteration, the session pump loop the
// stream shape drives, and the round-trip comparison that decides
// between a worker error and a data mismatch.

package io.github.everanium.itb3.kotlin.loop

import io.github.everanium.itb3.kotlin.DecryptStream
import io.github.everanium.itb3.kotlin.EncryptStream
import io.github.everanium.itb3.kotlin.ItbException
import io.github.everanium.itb3.kotlin.Pipeline
import java.io.ByteArrayOutputStream
import java.util.concurrent.BrokenBarrierException

/** Cipher surfaces the --shape flag selects. */
enum class Shape(val label: String) {
    /** Session pump: begin / write / read / end. */
    Stream("stream"),

    /** Single Message: one whole-buffer call. */
    Message("message"),

    /** Stream surface, one whole-buffer call. */
    StreamOneShot("stream_one_shot"),

    /** All three, rotating by iteration number. */
    Both("both"),
    ;

    companion object {
        fun parse(s: String): Shape? = entries.firstOrNull { it.label == s }
    }
}

/**
 * A growable output accumulator whose backing array the comparison
 * reads without a copy.
 *
 * Kotlin-specific. `ByteArrayOutputStream.toByteArray()` copies on
 * every call, which on a 16 MiB payload is one full duplicate per
 * iteration per direction; the protected fields of the base class
 * expose the same bytes in place.
 */
class Acc(cap: Int) : ByteArrayOutputStream(cap) {
    /** The backing array; only the first [len] bytes are live. */
    fun raw(): ByteArray = buf

    /** Live byte count. */
    fun len(): Int = count
}

/** Pattern the binding's exception message carries: the status code
 * and, behind it, the library's own diagnostic sentence. */
private val DETAIL_RE = Regex("""^itb: status=(-?\d+)(?:: (.*))?$""", RegexOption.DOT_MATCHES_ALL)

/**
 * Renders a binding error the way every implementation reports a
 * failed library call: `status <code>: <last error>`; any other
 * failure carries its own text. No wording of a status code is
 * composed here — the library's diagnostic already opens with the
 * class of failure and, where there is one, the specific case, so it
 * is printed as it arrived.
 *
 * Kotlin-specific. The binding's sealed `Status` is a type-system
 * enumeration with no human text of its own, and the diagnostic is
 * folded into the exception message behind a fixed prefix, so the
 * message is where it is recovered from.
 */
fun detail(e: Exception): String {
    val message = e.message ?: return e.toString()
    if (e !is ItbException) {
        return message
    }
    val m = DETAIL_RE.find(message) ?: return message
    return "status ${m.groupValues[1]}: ${m.groupValues[2]}"
}

/** Records the worker's error text (first error wins) and requests a
 * stop of the whole run. */
fun fail(r: RunState, id: Int, text: String) {
    r.workers[id].setError(text)
    r.stop = true
}

/** A failed session call: which entry failed, and with what. */
private class PumpFail(val what: String, val err: Exception)

/**
 * Pump loop. The Go harness hands ITB an io.Reader / io.Writer pair
 * and ITB drives the chunk loop internally; the C ABI has no reader /
 * writer entry, so the caller drives it: open a session, feed slices of
 * at most 1 MiB, drain whatever the session has produced after every
 * write (a read before end never blocks), end, then drain until the
 * session reports finished (after end, a read on an empty spool blocks
 * until the terminal bytes arrive). The whole produced output lands in
 * the worker's reusable accumulator. The loop is written here rather
 * than delegated to the binding's pump convenience so it stands in the
 * utility, at the same place, in every language. On failure the result
 * names the failing call and carries its error.
 */
private fun pump(
    pipe: Pipeline,
    encrypt: Boolean,
    src: ByteArray,
    srcLen: Int,
    acc: Acc,
    scratch: ByteArray,
): PumpFail? {
    acc.reset()
    var es: EncryptStream? = null
    var ds: DecryptStream? = null
    try {
        try {
            if (encrypt) es = pipe.encryptStream() else ds = pipe.decryptStream()
        } catch (e: Exception) {
            return PumpFail("StreamBegin", e)
        }
        // Kotlin-specific. The two session directions are distinct
        // classes with no common supertype on the binding's surface,
        // so every call below branches on which side is open.
        var off = 0
        while (off < srcLen) {
            val n = minOf(PUMP_SLICE, srcLen - off)
            try {
                if (es != null) es.write(src, off, n) else ds!!.write(src, off, n)
            } catch (e: Exception) {
                return PumpFail("StreamWrite", e)
            }
            while (true) {
                val m = try {
                    if (es != null) es.read(scratch).count else ds!!.read(scratch).count
                } catch (e: Exception) {
                    return PumpFail("StreamRead", e)
                }
                if (m == 0) {
                    break
                }
                acc.write(scratch, 0, m)
            }
            off += PUMP_SLICE
        }
        try {
            if (es != null) es.end() else ds!!.end()
        } catch (e: Exception) {
            return PumpFail("StreamEnd", e)
        }
        while (true) {
            val res = try {
                if (es != null) es.read(scratch) else ds!!.read(scratch)
            } catch (e: Exception) {
                return PumpFail("StreamRead", e)
            }
            acc.write(scratch, 0, res.count)
            if (res.finished) {
                break
            }
        }
        return null
    } finally {
        es?.close()
        ds?.close()
    }
}

/** First offset at which the two ranges differ; the shorter length
 * when one is a prefix of the other. */
private fun firstDifference(a: ByteArray, aLen: Int, b: ByteArray, bLen: Int): Int {
    val n = minOf(aLen, bLen)
    for (i in 0 until n) {
        if (a[i] != b[i]) {
            return i
        }
    }
    return n
}

/** Up to 16 bytes of buf from off as lowercase hex, or "-" when buf
 * has no bytes there. */
private fun hexWindow(buf: ByteArray, len: Int, off: Int): String {
    if (off >= len) {
        return "-"
    }
    val n = minOf(16, len - off)
    val sb = StringBuilder(n * 2)
    for (i in 0 until n) {
        val v = buf[off + i].toInt() and 0xFF
        sb.append(Character.forDigit(v ushr 4, 16)).append(Character.forDigit(v and 0xF, 16))
    }
    return sb.toString()
}

private fun equalBytes(a: ByteArray, aLen: Int, b: ByteArray, bLen: Int): Boolean {
    if (aLen != bLen) {
        return false
    }
    for (i in 0 until aLen) {
        if (a[i] != b[i]) {
            return false
        }
    }
    return true
}

/** Records a worker error for a failed cipher call. */
private fun cipherFail(
    r: RunState,
    id: Int,
    iter: Long,
    shape: Shape,
    direction: String,
    what: String?,
    e: Exception,
) {
    val head = "g$id iter $iter shape=${shape.label}: $direction"
    fail(r, id, if (what == null) "$head: ${detail(e)}" else "$head: $what: ${detail(e)}")
}

/**
 * One iteration. In order: refill the plaintext under rotating mode;
 * take the read lock; pick the surface; encrypt (timed); decrypt
 * (timed); compare the round-trip with the plaintext; bump the
 * counters; release the lock. The whole round-trip runs under the read
 * lock so handle-mutating maintenance (rekey, blob reopen) never lands
 * between an encrypt and its matching decrypt — maintenance runs after
 * this returns, from the worker loop. False after recording a worker
 * error.
 */
private fun iterate(r: RunState, w: WorkerState, iter: Long): Boolean {
    val c = r.workers[w.id]
    if (w.payloadMode == PayloadMode.Rotating &&
        !fillPayload(PayloadMode.Rotating, w.seeded, w.rng, w.plaintext)
    ) {
        fail(r, w.id, "g${w.id} iter $iter: payload refill: csprng")
        return false
    }

    r.pipesLock.readLock().lock()
    try {
        // Shape dispatch. message is one whole-buffer call on the
        // Single Message Pipeline; stream_one_shot is one whole-buffer
        // call on the streaming Pipeline (the C ABI's
        // ITB_Triple_EncryptStream, which routes to the same
        // whole-buffer stream entry the Go harness calls by name);
        // stream opens a session on the same streaming Pipeline and
        // drives the chunk loop from here. Under both the three rotate
        // by iteration number so the session path and the whole-buffer
        // path alternate on one handle inside every worker — the
        // cross-path state-reuse hazard this harness exists to catch.
        var shape = r.cfg.shape
        if (shape == Shape.Both) {
            shape = when (iter % 3) {
                0L -> Shape.Stream
                1L -> Shape.Message
                else -> Shape.StreamOneShot
            }
        }

        // Kotlin-specific. The message and one-shot entries return a
        // fresh array per call that the collector reclaims at the end
        // of the iteration; the pump accumulators are the worker's own
        // and are reused. `got` / `gotLen` hold the round-trip output
        // for either posture, so one comparison below serves both.
        val got: ByteArray
        val gotLen: Int
        var t0: Long
        when (shape) {
            Shape.Stream -> {
                val pipe = r.pipes.stream!!
                t0 = System.nanoTime()
                var f = pump(pipe, true, w.plaintext, w.plaintext.size, w.wire, w.scratch)
                if (f != null) {
                    cipherFail(r, w.id, iter, shape, "encrypt", f.what, f.err)
                    return false
                }
                c.addEncrypt(System.nanoTime() - t0)
                t0 = System.nanoTime()
                f = pump(pipe, false, w.wire.raw(), w.wire.len(), w.plain, w.scratch)
                if (f != null) {
                    cipherFail(r, w.id, iter, shape, "decrypt", f.what, f.err)
                    return false
                }
                c.addDecrypt(System.nanoTime() - t0)
                got = w.plain.raw()
                gotLen = w.plain.len()
            }

            Shape.StreamOneShot -> {
                val pipe = r.pipes.stream!!
                t0 = System.nanoTime()
                val wire = try {
                    pipe.encryptStreamOneShot(w.plaintext)
                } catch (e: Exception) {
                    cipherFail(r, w.id, iter, shape, "encrypt", null, e)
                    return false
                }
                c.addEncrypt(System.nanoTime() - t0)
                t0 = System.nanoTime()
                got = try {
                    pipe.decryptStreamOneShot(wire)
                } catch (e: Exception) {
                    cipherFail(r, w.id, iter, shape, "decrypt", null, e)
                    return false
                }
                c.addDecrypt(System.nanoTime() - t0)
                gotLen = got.size
            }

            else -> {
                val pipe = r.pipes.msg!!
                t0 = System.nanoTime()
                val wire = try {
                    pipe.encryptMessage(w.plaintext)
                } catch (e: Exception) {
                    cipherFail(r, w.id, iter, shape, "encrypt", null, e)
                    return false
                }
                c.addEncrypt(System.nanoTime() - t0)
                t0 = System.nanoTime()
                got = try {
                    pipe.decryptMessage(wire)
                } catch (e: Exception) {
                    cipherFail(r, w.id, iter, shape, "decrypt", null, e)
                    return false
                }
                c.addDecrypt(System.nanoTime() - t0)
                gotLen = got.size
            }
        }

        // Failure model. A cipher call that returns a non-OK status is
        // a worker error: it is recorded, the run is asked to stop, the
        // other workers finish their in-flight iteration, and the error
        // is listed in the summary with the FAIL verdict. A round-trip
        // that returns OK with different bytes is a data mismatch: the
        // process terminates here, without summary or cleanup, because
        // the Pipeline state that produced the wrong bytes is the
        // evidence and nothing that runs afterwards may touch it.
        // Kotlin-specific: Runtime.halt is the exit that runs neither
        // the shutdown hooks nor the Cleaner registrations behind the
        // Java layer's handles, which is the point — a cleaner-driven
        // free would release the very state the operator is meant to
        // inspect.
        val want = w.plaintext
        if (!equalBytes(want, want.size, got, gotLen)) {
            val off = firstDifference(want, want.size, got, gotLen)
            System.err.println(
                "loop: DATA MISMATCH g${w.id} iter $iter shape=${shape.label}: " +
                    "want ${want.size} bytes, got $gotLen bytes, " +
                    "first difference at offset $off: " +
                    "want ${hexWindow(want, want.size, off)} got ${hexWindow(got, gotLen, off)}",
            )
            System.err.flush()
            System.out.flush()
            java.lang.Runtime.getRuntime().halt(3)
        }

        c.addIteration(want.size.toLong(), gotLen.toLong())
        return true
    } finally {
        r.pipesLock.readLock().unlock()
    }
}

/** Marks this worker returned; the last one to return stamps the
 * finish instant and wakes main. */
private fun done(r: RunState) {
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
 * The worker thread body: one warmup iteration, the warmup barrier,
 * then the main loop until a stop is requested or the fixed per-worker
 * iteration budget (warmup included) is spent. A failing warmup still
 * passes both barriers so the launcher never waits on a worker that
 * has already given up.
 */
fun runWorker(r: RunState, w: WorkerState) {
    // Warmup iteration — counted in the totals; its completion feeds
    // the post-warmup baselines.
    val ok = iterate(r, w, 0)
    try {
        r.warmupDone.await()
        r.release.await()
    } catch (e: InterruptedException) {
        Thread.currentThread().interrupt()
        done(r)
        return
    } catch (e: BrokenBarrierException) {
        done(r)
        return
    }
    if (!ok) {
        done(r)
        return
    }

    var iter = 1L
    while (true) {
        if (r.cfg.iterations > 0 && iter >= r.cfg.iterations) {
            break
        }
        if (r.stop) {
            break
        }
        if (!iterate(r, w, iter)) {
            break
        }
        if (!maintenance(r, w.id, iter)) {
            break
        }
        iter++
    }
    done(r)
}
