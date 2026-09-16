// The final summary in both renderings, and the two measurements it
// folds in that are not per-worker counters: the process resident set
// and the shared library's pool counters.

package io.github.everanium.itb3.groovy.loop

import groovy.transform.CompileStatic

import io.github.everanium.itb3.groovy.Runtime as ItbRuntime

/** One starter tier of the hash-array pool, differenced. */
@CompileStatic
final class Tier {
    long index
    long starter
    long get
    long fresh
    long regrow
    long newBytes
}

/** One single-size byte pool, differenced. */
@CompileStatic
final class BytePool {
    long get
    long fresh
    long regrow
    long regrowBytes
}

@CompileStatic
final class PoolDelta {
    final List<Tier> tiers = new ArrayList<Tier>()
    BytePool buf = new BytePool()
    BytePool chunk = new BytePool()
}

@CompileStatic
final class Summary {

    private Summary() {
    }

    /** Parses one "Vm...:   1234 kB" line of /proc/self/status into
     * bytes; zero on any parse failure. */
    private static long statusKb(String line) {
        int colon = line.indexOf(((int) (':' as char)))
        if (colon < 0) {
            return 0L
        }
        String[] parts = line.substring(colon + 1).trim().split('\\s+')
        if (parts.length == 0 || parts[0].isEmpty()) {
            return 0L
        }
        try {
            return Long.parseLong(parts[0]) * 1024L
        } catch (NumberFormatException e) {
            return 0L
        }
    }

    /** The process's current resident set and its high-water mark in
     * bytes, from /proc/self/status (VmRSS and VmHWM, reported in kB).
     * Both are zero on a platform without that file; the figures are
     * informational and never enter the verdict. Index 0 is current,
     * index 1 is peak. */
    static long[] readRss() {
        List<String> lines
        try {
            lines = new File('/proc/self/status').readLines()
        } catch (Exception e) {
            return new long[] { 0L, 0L }
        }
        long current = 0L
        long peak = 0L
        for (String line : lines) {
            if (line.startsWith('VmRSS:')) {
                current = statusKb(line)
            } else if (line.startsWith('VmHWM:')) {
                peak = statusKb(line)
            }
        }
        return new long[] { current, peak }
    }

    /**
     * Pool counters. The shared library keeps process-wide monotonic
     * totals at every pool checkout of its cipher core: per hash-array
     * tier the starter width, checkouts, constructor misses, regrow
     * replacements and bytes allocated; for the scratch byte pool and
     * the parallax chunk pool the checkouts, constructor misses,
     * regrows and regrow bytes. Two snapshots bracketing the main loop
     * are differenced into per-run hit / miss figures that tell
     * whether a pool keeps its items warm between calls or evicts them
     * across GC cycles. The slot layout is read from the library: slot
     * 0 carries the tier count T, tier i occupies the five slots at
     * 1 + 5*i, and the two byte pools occupy the eight slots at
     * 1 + 5*T; the vector is sized by the binding from the library's
     * own length query, never from a constant. Empty when the library
     * is unavailable.
     */
    static long[] poolSnapshot() {
        try {
            return ItbRuntime.poolStats()
        } catch (Exception e) {
            return new long[0]
        }
    }

    private static PoolDelta poolDiff(long[] steady, long[] warmup) {
        PoolDelta d = new PoolDelta()
        if (steady.length < 9 || warmup.length != steady.length) {
            return d
        }
        long tiers = steady[0]
        if (tiers < 0 || 1 + 5 * tiers + 8 > steady.length) {
            return d
        }
        for (long i = 0; i < tiers; i++) {
            int b = (int) (1 + 5 * i)
            if (steady[b] == 0L) {
                continue
            }
            Tier t = new Tier()
            t.index = i
            t.starter = steady[b]
            t.get = steady[b + 1] - warmup[b + 1]
            t.fresh = steady[b + 2] - warmup[b + 2]
            t.regrow = steady[b + 3] - warmup[b + 3]
            t.newBytes = steady[b + 4] - warmup[b + 4]
            d.tiers.add(t)
        }
        int t0 = (int) (1 + 5 * tiers)
        d.buf = new BytePool()
        d.buf.get = steady[t0] - warmup[t0]
        d.buf.fresh = steady[t0 + 1] - warmup[t0 + 1]
        d.buf.regrow = steady[t0 + 2] - warmup[t0 + 2]
        d.buf.regrowBytes = steady[t0 + 3] - warmup[t0 + 3]
        d.chunk = new BytePool()
        d.chunk.get = steady[t0 + 4] - warmup[t0 + 4]
        d.chunk.fresh = steady[t0 + 5] - warmup[t0 + 5]
        d.chunk.regrow = steady[t0 + 6] - warmup[t0 + 6]
        d.chunk.regrowBytes = steady[t0 + 7] - warmup[t0 + 7]
        return d
    }

    /** Misses over checkouts as a percentage; zero when nothing was
     * checked out. */
    private static double missPercent(long miss, long get) {
        get <= 0 ? 0.0d : 100.0d * miss / get
    }

    /** Renders s as a JSON string literal with the escapes JSON
     * requires. */
    private static String jsonString(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 2)
        sb.append('"' as char)
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i)
            if (ch == ('"' as char)) {
                sb.append('\\"')
            } else if (ch == ('\\' as char)) {
                sb.append('\\\\')
            } else if (ch == ('\n' as char)) {
                sb.append('\\n')
            } else if (ch == ('\r' as char)) {
                sb.append('\\r')
            } else if (ch == ('\t' as char)) {
                sb.append('\\t')
            } else if (((int) ch) < 0x20) {
                sb.append(String.format(Locale.ROOT, '\\u%04x', (int) ch))
            } else {
                sb.append(ch)
            }
        }
        sb.append('"' as char)
        return sb.toString()
    }

    /** The effective GC percentage as the runtime reports it: the
     * query form of the setter (a set-and-restore round trip inside
     * the library) so the field is the same whether the value came
     * from the flag, the environment, or the runtime default. */
    private static int effectiveGogc(int flag) {
        if (flag > 0) {
            return flag
        }
        try {
            return ItbRuntime.setGCPercent(-1)
        } catch (Exception e) {
            return 0
        }
    }

    private static String join(List<Long> values, String sep) {
        StringBuilder sb = new StringBuilder()
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                sb.append(sep)
            }
            sb.append(values.get(i).longValue())
        }
        return sb.toString()
    }

    /**
     * Output contract. Both renderings are shared with the Go harness
     * and every other binding's loop utility field for field: the same
     * lines in the same order, the same keys in the same order, floats
     * with a fixed number of decimals so the JSON is byte-identical
     * across implementations. The Go harness alone adds its
     * runtime-internal lines after rss: and its runtime-internal keys
     * after parallax_chunk_pool; nothing here reproduces them because
     * nothing they read is reachable through the C ABI. Returns the
     * exit code.
     */
    static int emit(RunState r, long elapsedNs) {
        Config cfg = r.cfg
        long workers = (long) cfg.workers
        long totalIters = 0L
        long totalEnc = 0L
        long totalDec = 0L
        long nanosEnc = 0L
        long nanosDec = 0L
        List<Long> perWorker = new ArrayList<Long>(cfg.workers)
        List<String> errors = new ArrayList<String>()
        for (Counters c : r.workers) {
            long n = c.iters.get()
            perWorker.add(n)
            totalIters += n
            totalEnc += c.bytesEnc.get()
            totalDec += c.bytesDec.get()
            nanosEnc += c.nanosEnc.get()
            nanosDec += c.nanosDec.get()
            String e = c.error()
            if (e != null) {
                errors.add(e)
            }
        }

        // Throughput. Per-direction throughput divides the sum of
        // every worker's wall time in that direction by the worker
        // count — the equivalent single-stream wall time under N-way
        // concurrency — so each direction reports the aggregate rate
        // it sustained rather than collapsing to combined/2 (every
        // iteration moves equal encrypt and decrypt bytes, so a
        // total-elapsed denominator would give both directions the
        // same figure). The combined rate keeps total elapsed as the
        // one-glance overall figure.
        long avgEnc = nanosEnc > 0 ? nanosEnc.intdiv(workers) : 0L
        long avgDec = nanosDec > 0 ? nanosDec.intdiv(workers) : 0L

        long rssDelta = r.rssFinal - r.rssWarmup
        double rssGrowth = r.rssWarmup > 0 ? 100.0d * rssDelta / r.rssWarmup : 0.0d

        PoolDelta pd = poolDiff(r.poolSteady, r.poolWarmup)
        boolean pass = errors.isEmpty()
        long rekeys = r.rekeys.get()
        long cycles = r.blobCycles.get()
        int gomaxprocs
        try {
            gomaxprocs = ItbRuntime.setGOMAXPROCS(0)
        } catch (Exception e) {
            gomaxprocs = 0
        }
        String streamProfile = r.pipes.stream != null ? r.streamProfile : ''
        String msgProfile = r.pipes.msg != null ? r.msgProfile : ''

        if (cfg.jsonOutput) {
            StringBuilder j = new StringBuilder()
            j.append('{"duration_seconds":').append(Size.f(elapsedNs / 1e9d, 3))
            j.append(',"iterations":').append(totalIters)
            j.append(',"per_worker_iterations":[').append(join(perWorker, ',')).append(']' as char)
            j.append(',"bytes_encrypted":').append(totalEnc)
            j.append(',"bytes_decrypted":').append(totalDec)
            j.append(',"encrypt_mb_per_sec":').append(Size.f(Size.mbPerSec(totalEnc, avgEnc), 1))
            j.append(',"decrypt_mb_per_sec":').append(Size.f(Size.mbPerSec(totalDec, avgDec), 1))
            j.append(',"combined_mb_per_sec":')
                    .append(Size.f(Size.mbPerSec(totalEnc + totalDec, elapsedNs), 1))
            j.append(',"rekeys":').append(rekeys)
            j.append(',"blob_cycles":').append(cycles)
            j.append(',"worker_errors":[')
            for (int i = 0; i < errors.size(); i++) {
                if (i > 0) {
                    j.append(',' as char)
                }
                j.append(jsonString(errors.get(i)))
            }
            j.append(']' as char)
            j.append(',"verdict":"').append(pass ? 'PASS' : 'FAIL').append('"' as char)
            j.append(',"shape":"').append(cfg.shape.label).append('"' as char)
            j.append(',"stream_profile":').append(jsonString(streamProfile))
            j.append(',"message_profile":').append(jsonString(msgProfile))
            j.append(',"hash":').append(jsonString(cfg.hash))
            j.append(',"mac":').append(jsonString(cfg.mac))
            j.append(',"payload_bytes":').append(cfg.payload)
            j.append(',"payload_mode":"').append(cfg.payloadMode.label).append('"' as char)
            j.append(',"seed":').append(Long.toUnsignedString(cfg.seed))
            j.append(',"key_bits":').append(cfg.keyBits)
            j.append(',"nonce_bits":').append(cfg.nonceBits)
            j.append(',"chunk_size_bytes":').append(cfg.chunkSize)
            j.append(',"barrier_fill":').append(cfg.barrierFill)
            j.append(',"parallax":"').append(Main.onOff(cfg.parallax)).append('"' as char)
            j.append(',"wrapper":"').append(Main.onOff(cfg.wrapper)).append('"' as char)
            j.append(',"goroutines_requested":').append(cfg.workersRequested)
            j.append(',"goroutines":').append(cfg.workers)
            j.append(',"concurrency":"').append(Main.CONCURRENCY).append('"' as char)
            j.append(',"gogc":"').append(effectiveGogc(cfg.gogc)).append('"' as char)
            j.append(',"memlimit_bytes":').append(cfg.memlimit)
            j.append(',"gomaxprocs":').append(gomaxprocs)
            j.append(',"microbatch_tiers":')
                    .append(jsonString(Main.policyLabel('ITB_MICROBATCH_TIERS')))
            j.append(',"hashpool_starters":')
                    .append(jsonString(Main.policyLabel('ITB_HASHPOOL_STARTERS')))
            j.append(',"rss_warmup_bytes":').append(r.rssWarmup)
            j.append(',"rss_peak_bytes":').append(r.rssPeak)
            j.append(',"rss_final_bytes":').append(r.rssFinal)
            j.append(',"rss_growth_percent":').append(Size.f(rssGrowth, 2))
            j.append(',"hash_pool_tiers":[')
            for (int i = 0; i < pd.tiers.size(); i++) {
                Tier t = pd.tiers.get(i)
                if (i > 0) {
                    j.append(',' as char)
                }
                j.append('{"tier":').append(t.index)
                        .append(',"starter":').append(t.starter)
                        .append(',"get":').append(t.get)
                        .append(',"new":').append(t.fresh)
                        .append(',"regrow":').append(t.regrow)
                        .append(',"new_bytes":').append(t.newBytes)
                        .append(',"miss_percent":')
                        .append(Size.f(missPercent(t.fresh + t.regrow, t.get), 2))
                        .append('}' as char)
            }
            j.append(']' as char)
            j.append(',"buf_pool":{"get":').append(pd.buf.get)
                    .append(',"new":').append(pd.buf.fresh)
                    .append(',"regrow":').append(pd.buf.regrow)
                    .append(',"regrow_bytes":').append(pd.buf.regrowBytes)
                    .append(',"miss_percent":')
                    .append(Size.f(missPercent(pd.buf.regrow, pd.buf.get), 2))
                    .append('}' as char)
            j.append(',"parallax_chunk_pool":{"get":').append(pd.chunk.get)
                    .append(',"new":').append(pd.chunk.fresh)
                    .append(',"regrow":').append(pd.chunk.regrow)
                    .append(',"regrow_bytes":').append(pd.chunk.regrowBytes)
                    .append(',"miss_percent":')
                    .append(Size.f(missPercent(pd.chunk.regrow, pd.chunk.get), 2))
                    .append('}' as char)
            j.append('}' as char)
            System.out.println(j.toString())
            return pass ? 0 : 1
        }

        Main.logLine('=== FINAL ===')
        Main.logLine('  duration: ' + Size.humanDuration(Size.roundTo(elapsedNs, 1_000_000L)))
        Main.logLine('  iterations: ' + join(perWorker, ' + ') + ' = ' + totalIters + ' total')
        Main.logLine('  throughput: encrypt ' + Size.humanRate(totalEnc, avgEnc) +
                ', decrypt ' + Size.humanRate(totalDec, avgDec) +
                ', combined ' + Size.humanRate(totalEnc + totalDec, elapsedNs))
        Main.logLine('  bytes: ' + Size.humanBytes(totalEnc) + ' encrypted, ' +
                Size.humanBytes(totalDec) + ' decrypted')
        Main.logLine('  data integrity: ' + totalIters + '/' + totalIters + ' PASS')
        Main.logLine('  concurrency: ' + Main.CONCURRENCY + ', workers ' + cfg.workers +
                ' (requested ' + cfg.workersRequested + ')')
        Main.logLine('  rss: warmup ' + Size.humanBytes(r.rssWarmup) +
                ', peak ' + Size.humanBytes(r.rssPeak) +
                ', final ' + Size.humanBytes(r.rssFinal) +
                ' (delta ' + Size.humanBytesSigned(rssDelta) +
                ', ' + Size.f(rssGrowth, 1) + '% growth)')
        for (Tier t : pd.tiers) {
            Main.logLine('  hash pool tier ' + t.index + ' (starter ' + t.starter + '): get ' +
                    t.get + ', miss ' + (t.fresh + t.regrow) +
                    ' (new ' + t.fresh + ' + regrow ' + t.regrow + ')' +
                    ', miss ' + Size.f(missPercent(t.fresh + t.regrow, t.get), 2) + '%' +
                    ', ' + Size.humanBytes(t.newBytes) + ' allocated')
        }
        Main.logLine('  buf pool: get ' + pd.buf.get + ', regrow ' + pd.buf.regrow +
                ' (of which fresh ' + pd.buf.fresh + ')' +
                ', miss ' + Size.f(missPercent(pd.buf.regrow, pd.buf.get), 2) + '%' +
                ', ' + Size.humanBytes(pd.buf.regrowBytes) + ' regrown')
        Main.logLine('  parallax chunk pool: get ' + pd.chunk.get + ', regrow ' + pd.chunk.regrow +
                ' (of which fresh ' + pd.chunk.fresh + ')' +
                ', miss ' + Size.f(missPercent(pd.chunk.regrow, pd.chunk.get), 2) + '%' +
                ', ' + Size.humanBytes(pd.chunk.regrowBytes) + ' regrown')
        if (rekeys > 0) {
            Main.logLine('  rekeys: ' + rekeys)
        }
        if (cycles > 0) {
            Main.logLine('  blob cycles: ' + cycles)
        }
        for (String e : errors) {
            Main.logLine('  ERROR: ' + e)
        }
        if (pass) {
            Main.logLine('  verdict: PASS')
            return 0
        }
        Main.logLine('  verdict: FAIL (errors=' + errors.size() + ')')
        return 1
    }
}
