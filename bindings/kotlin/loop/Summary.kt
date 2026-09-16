// The final summary in both renderings, and the two measurements it
// folds in that are not per-worker counters: the process resident set
// and the shared library's pool counters.

package io.github.everanium.itb3.kotlin.loop

import io.github.everanium.itb3.kotlin.ItbRuntime
import java.io.File
import java.util.Locale

/** Parses one "Vm...:   1234 kB" line of /proc/self/status into bytes;
 * zero on any parse failure. */
private fun statusKb(line: String): Long {
    val colon = line.indexOf(':')
    if (colon < 0) {
        return 0
    }
    val first = line.substring(colon + 1).trim().split(Regex("\\s+")).firstOrNull() ?: return 0
    return (first.toLongOrNull() ?: 0) * 1024
}

/** The process's current resident set and its high-water mark in
 * bytes, from /proc/self/status (VmRSS and VmHWM, reported in kB).
 * Both are zero on a platform without that file; the figures are
 * informational and never enter the verdict. */
fun readRss(): Pair<Long, Long> {
    val lines = try {
        File("/proc/self/status").readLines()
    } catch (e: Exception) {
        return 0L to 0L
    }
    var current = 0L
    var peak = 0L
    for (line in lines) {
        if (line.startsWith("VmRSS:")) {
            current = statusKb(line)
        } else if (line.startsWith("VmHWM:")) {
            peak = statusKb(line)
        }
    }
    return current to peak
}

/**
 * Pool counters. The shared library keeps process-wide monotonic
 * totals at every pool checkout of its cipher core: per hash-array
 * tier the starter width, checkouts, constructor misses, regrow
 * replacements and bytes allocated; for the scratch byte pool and the
 * parallax chunk pool the checkouts, constructor misses, regrows and
 * regrow bytes. Two snapshots bracketing the main loop are differenced
 * into per-run hit / miss figures that tell whether a pool keeps its
 * items warm between calls or evicts them across GC cycles. The slot
 * layout is read from the library: slot 0 carries the tier count T,
 * tier i occupies the five slots at 1 + 5*i, and the two byte pools
 * occupy the eight slots at 1 + 5*T; the vector is sized by the
 * binding from the library's own length query, never from a constant.
 * Empty when the library is unavailable.
 */
fun poolSnapshot(): LongArray = try {
    ItbRuntime.poolStats()
} catch (e: Exception) {
    LongArray(0)
}

/** One starter tier of the hash-array pool, differenced. */
private class Tier(
    val index: Long,
    val starter: Long,
    val get: Long,
    val fresh: Long,
    val regrow: Long,
    val newBytes: Long,
)

/** One single-size byte pool, differenced. */
private class BytePool(
    val get: Long = 0,
    val fresh: Long = 0,
    val regrow: Long = 0,
    val regrowBytes: Long = 0,
)

private class PoolDelta(
    val tiers: List<Tier> = emptyList(),
    val buf: BytePool = BytePool(),
    val chunk: BytePool = BytePool(),
)

private fun poolDiff(steady: LongArray, warmup: LongArray): PoolDelta {
    if (steady.size < 9 || warmup.size != steady.size) {
        return PoolDelta()
    }
    val tiers = steady[0]
    if (tiers < 0 || 1 + 5 * tiers + 8 > steady.size) {
        return PoolDelta()
    }
    val list = ArrayList<Tier>()
    for (i in 0 until tiers) {
        val b = (1 + 5 * i).toInt()
        if (steady[b] == 0L) {
            continue
        }
        list.add(
            Tier(
                index = i,
                starter = steady[b],
                get = steady[b + 1] - warmup[b + 1],
                fresh = steady[b + 2] - warmup[b + 2],
                regrow = steady[b + 3] - warmup[b + 3],
                newBytes = steady[b + 4] - warmup[b + 4],
            ),
        )
    }
    val t = (1 + 5 * tiers).toInt()
    return PoolDelta(
        tiers = list,
        buf = BytePool(
            get = steady[t] - warmup[t],
            fresh = steady[t + 1] - warmup[t + 1],
            regrow = steady[t + 2] - warmup[t + 2],
            regrowBytes = steady[t + 3] - warmup[t + 3],
        ),
        chunk = BytePool(
            get = steady[t + 4] - warmup[t + 4],
            fresh = steady[t + 5] - warmup[t + 5],
            regrow = steady[t + 6] - warmup[t + 6],
            regrowBytes = steady[t + 7] - warmup[t + 7],
        ),
    )
}

/** Misses over checkouts as a percentage; zero when nothing was
 * checked out. */
private fun missPercent(miss: Long, get: Long): Double =
    if (get <= 0) 0.0 else 100.0 * miss / get

/** Renders s as a JSON string literal with the escapes JSON
 * requires. */
private fun jsonString(s: String): String {
    val sb = StringBuilder(s.length + 2)
    sb.append('"')
    for (ch in s) {
        when {
            ch == '"' -> sb.append("\\\"")
            ch == '\\' -> sb.append("\\\\")
            ch == '\n' -> sb.append("\\n")
            ch == '\r' -> sb.append("\\r")
            ch == '\t' -> sb.append("\\t")
            ch < ' ' -> sb.append(String.format(Locale.ROOT, "\\u%04x", ch.code))
            else -> sb.append(ch)
        }
    }
    sb.append('"')
    return sb.toString()
}

/** The effective GC percentage as the runtime reports it: the query
 * form of the setter (a set-and-restore round trip inside the library)
 * so the field is the same whether the value came from the flag, the
 * environment, or the runtime default. */
private fun effectiveGogc(flag: Int): Int {
    if (flag > 0) {
        return flag
    }
    return try {
        ItbRuntime.setGCPercent(-1)
    } catch (e: Exception) {
        0
    }
}

/**
 * Output contract. Both renderings are shared with the Go harness and
 * every other binding's loop utility field for field: the same lines
 * in the same order, the same keys in the same order, floats with a
 * fixed number of decimals so the JSON is byte-identical across
 * implementations. The Go harness alone adds its runtime-internal
 * lines after rss: and its runtime-internal keys after
 * parallax_chunk_pool; nothing here reproduces them because nothing
 * they read is reachable through the C ABI. Returns the exit code.
 */
fun emitSummary(r: RunState, elapsedNs: Long): Int {
    val cfg = r.cfg
    val workers = cfg.workers.toLong()
    var totalIters = 0L
    var totalEnc = 0L
    var totalDec = 0L
    var nanosEnc = 0L
    var nanosDec = 0L
    val perWorker = ArrayList<Long>(cfg.workers)
    val errors = ArrayList<String>()
    for (c in r.workers) {
        val n = c.iters.get()
        perWorker.add(n)
        totalIters += n
        totalEnc += c.bytesEnc.get()
        totalDec += c.bytesDec.get()
        nanosEnc += c.nanosEnc.get()
        nanosDec += c.nanosDec.get()
        c.error()?.let { errors.add(it) }
    }

    // Throughput. Per-direction throughput divides the sum of every
    // worker's wall time in that direction by the worker count — the
    // equivalent single-stream wall time under N-way concurrency — so
    // each direction reports the aggregate rate it sustained rather
    // than collapsing to combined/2 (every iteration moves equal
    // encrypt and decrypt bytes, so a total-elapsed denominator would
    // give both directions the same figure). The combined rate keeps
    // total elapsed as the one-glance overall figure.
    val avgEnc = if (nanosEnc > 0) nanosEnc / workers else 0L
    val avgDec = if (nanosDec > 0) nanosDec / workers else 0L

    val rssDelta = r.rssFinal - r.rssWarmup
    val rssGrowth = if (r.rssWarmup > 0) 100.0 * rssDelta / r.rssWarmup else 0.0

    val pd = poolDiff(r.poolSteady, r.poolWarmup)
    val pass = errors.isEmpty()
    val rekeys = r.rekeys.get()
    val cycles = r.blobCycles.get()
    val gomaxprocs = try {
        ItbRuntime.setGOMAXPROCS(0)
    } catch (e: Exception) {
        0
    }
    val streamProfile = if (r.pipes.stream != null) r.streamProfile else ""
    val msgProfile = if (r.pipes.msg != null) r.msgProfile else ""

    if (cfg.jsonOutput) {
        val j = StringBuilder()
        j.append("{\"duration_seconds\":").append(f(elapsedNs / 1e9, 3))
        j.append(",\"iterations\":").append(totalIters)
        j.append(",\"per_worker_iterations\":[").append(perWorker.joinToString(",")).append(']')
        j.append(",\"bytes_encrypted\":").append(totalEnc)
        j.append(",\"bytes_decrypted\":").append(totalDec)
        j.append(",\"encrypt_mb_per_sec\":").append(f(mbPerSec(totalEnc, avgEnc), 1))
        j.append(",\"decrypt_mb_per_sec\":").append(f(mbPerSec(totalDec, avgDec), 1))
        j.append(",\"combined_mb_per_sec\":").append(f(mbPerSec(totalEnc + totalDec, elapsedNs), 1))
        j.append(",\"rekeys\":").append(rekeys)
        j.append(",\"blob_cycles\":").append(cycles)
        j.append(",\"worker_errors\":[")
            .append(errors.joinToString(",") { jsonString(it) }).append(']')
        j.append(",\"verdict\":\"").append(if (pass) "PASS" else "FAIL").append('"')
        j.append(",\"shape\":\"").append(cfg.shape.label).append('"')
        j.append(",\"stream_profile\":").append(jsonString(streamProfile))
        j.append(",\"message_profile\":").append(jsonString(msgProfile))
        j.append(",\"hash\":").append(jsonString(cfg.hash))
        j.append(",\"mac\":").append(jsonString(cfg.mac))
        j.append(",\"payload_bytes\":").append(cfg.payload)
        j.append(",\"payload_mode\":\"").append(cfg.payloadMode.label).append('"')
        j.append(",\"seed\":").append(java.lang.Long.toUnsignedString(cfg.seed))
        j.append(",\"key_bits\":").append(cfg.keyBits)
        j.append(",\"nonce_bits\":").append(cfg.nonceBits)
        j.append(",\"chunk_size_bytes\":").append(cfg.chunkSize)
        j.append(",\"barrier_fill\":").append(cfg.barrierFill)
        j.append(",\"parallax\":\"").append(onOff(cfg.parallax)).append('"')
        j.append(",\"wrapper\":\"").append(onOff(cfg.wrapper)).append('"')
        j.append(",\"goroutines_requested\":").append(cfg.workersRequested)
        j.append(",\"goroutines\":").append(cfg.workers)
        j.append(",\"concurrency\":\"").append(CONCURRENCY).append('"')
        j.append(",\"gogc\":\"").append(effectiveGogc(cfg.gogc)).append('"')
        j.append(",\"memlimit_bytes\":").append(cfg.memlimit)
        j.append(",\"gomaxprocs\":").append(gomaxprocs)
        j.append(",\"microbatch_tiers\":").append(jsonString(policyLabel("ITB_MICROBATCH_TIERS")))
        j.append(",\"hashpool_starters\":").append(jsonString(policyLabel("ITB_HASHPOOL_STARTERS")))
        j.append(",\"rss_warmup_bytes\":").append(r.rssWarmup)
        j.append(",\"rss_peak_bytes\":").append(r.rssPeak)
        j.append(",\"rss_final_bytes\":").append(r.rssFinal)
        j.append(",\"rss_growth_percent\":").append(f(rssGrowth, 2))
        j.append(",\"hash_pool_tiers\":[")
        j.append(
            pd.tiers.joinToString(",") { t ->
                "{\"tier\":${t.index}" +
                    ",\"starter\":${t.starter}" +
                    ",\"get\":${t.get}" +
                    ",\"new\":${t.fresh}" +
                    ",\"regrow\":${t.regrow}" +
                    ",\"new_bytes\":${t.newBytes}" +
                    ",\"miss_percent\":${f(missPercent(t.fresh + t.regrow, t.get), 2)}" +
                    "}"
            },
        )
        j.append(']')
        j.append(",\"buf_pool\":{\"get\":").append(pd.buf.get)
            .append(",\"new\":").append(pd.buf.fresh)
            .append(",\"regrow\":").append(pd.buf.regrow)
            .append(",\"regrow_bytes\":").append(pd.buf.regrowBytes)
            .append(",\"miss_percent\":").append(f(missPercent(pd.buf.regrow, pd.buf.get), 2))
            .append('}')
        j.append(",\"parallax_chunk_pool\":{\"get\":").append(pd.chunk.get)
            .append(",\"new\":").append(pd.chunk.fresh)
            .append(",\"regrow\":").append(pd.chunk.regrow)
            .append(",\"regrow_bytes\":").append(pd.chunk.regrowBytes)
            .append(",\"miss_percent\":").append(f(missPercent(pd.chunk.regrow, pd.chunk.get), 2))
            .append('}')
        j.append('}')
        println(j)
        return if (pass) 0 else 1
    }

    logLine("=== FINAL ===")
    logLine("  duration: " + humanDuration(roundTo(elapsedNs, 1_000_000L)))
    logLine("  iterations: " + perWorker.joinToString(" + ") + " = " + totalIters + " total")
    logLine(
        "  throughput: encrypt " + humanRate(totalEnc, avgEnc) +
            ", decrypt " + humanRate(totalDec, avgDec) +
            ", combined " + humanRate(totalEnc + totalDec, elapsedNs),
    )
    logLine(
        "  bytes: " + humanBytes(totalEnc) + " encrypted, " +
            humanBytes(totalDec) + " decrypted",
    )
    logLine("  data integrity: $totalIters/$totalIters PASS")
    logLine(
        "  concurrency: " + CONCURRENCY + ", workers " + cfg.workers +
            " (requested " + cfg.workersRequested + ")",
    )
    logLine(
        "  rss: warmup " + humanBytes(r.rssWarmup) +
            ", peak " + humanBytes(r.rssPeak) +
            ", final " + humanBytes(r.rssFinal) +
            " (delta " + humanBytesSigned(rssDelta) +
            ", " + f(rssGrowth, 1) + "% growth)",
    )
    for (t in pd.tiers) {
        logLine(
            "  hash pool tier " + t.index + " (starter " + t.starter + "): get " + t.get +
                ", miss " + (t.fresh + t.regrow) +
                " (new " + t.fresh + " + regrow " + t.regrow + ")" +
                ", miss " + f(missPercent(t.fresh + t.regrow, t.get), 2) + "%" +
                ", " + humanBytes(t.newBytes) + " allocated",
        )
    }
    logLine(
        "  buf pool: get " + pd.buf.get + ", regrow " + pd.buf.regrow +
            " (of which fresh " + pd.buf.fresh + ")" +
            ", miss " + f(missPercent(pd.buf.regrow, pd.buf.get), 2) + "%" +
            ", " + humanBytes(pd.buf.regrowBytes) + " regrown",
    )
    logLine(
        "  parallax chunk pool: get " + pd.chunk.get + ", regrow " + pd.chunk.regrow +
            " (of which fresh " + pd.chunk.fresh + ")" +
            ", miss " + f(missPercent(pd.chunk.regrow, pd.chunk.get), 2) + "%" +
            ", " + humanBytes(pd.chunk.regrowBytes) + " regrown",
    )
    if (rekeys > 0) {
        logLine("  rekeys: $rekeys")
    }
    if (cycles > 0) {
        logLine("  blob cycles: $cycles")
    }
    for (e in errors) {
        logLine("  ERROR: $e")
    }
    if (pass) {
        logLine("  verdict: PASS")
        return 0
    }
    logLine("  verdict: FAIL (errors=" + errors.size + ")")
    return 1
}
