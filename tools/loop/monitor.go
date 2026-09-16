package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	itb "github.com/everanium/itb"
)

// monitorInterval is the runtime-stat sampling period.
const monitorInterval = 5 * time.Second

// monitor samples runtime state every monitorInterval until the run
// context cancels, printing one compact line per sample and tracking
// heap / goroutine peaks plus anomaly warnings on the shared runState.
// Peaks and the warning counter are written by this goroutine only and
// read by main after the monitor's done channel closes.
func monitor(ctx context.Context, r *runState) {
	ticker := time.NewTicker(monitorInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sample(r)
		}
	}
}

// sample takes one runtime snapshot and prints the periodic stat line.
func sample(r *runState) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	goroutines := runtime.NumGoroutine()
	elapsed := time.Since(r.start)

	if ms.HeapAlloc > r.peakHeap {
		r.peakHeap = ms.HeapAlloc
	}
	if goroutines > r.peakGoroutines {
		r.peakGoroutines = goroutines
	}

	var (
		iterParts                    []string
		totalEnc, totalDec           int64
		totalNanosEnc, totalNanosDec int64
	)
	for _, w := range r.workers {
		iterParts = append(iterParts, fmt.Sprintf("g%d:%d", w.id, w.iters.Load()))
		totalEnc += w.bytesEnc.Load()
		totalDec += w.bytesDec.Load()
		totalNanosEnc += w.nanosEnc.Load()
		totalNanosDec += w.nanosDec.Load()
	}

	// Per-direction throughput uses average per-worker wall-time in that
	// direction (sum-of-nanos ÷ N workers) rather than total elapsed —
	// otherwise the split trivially collapses to combined/2 since each
	// iteration processes equal encrypt + decrypt bytes. The average
	// per-worker time-in-direction yields the true aggregate throughput
	// each direction sustains under N-worker parallelism: each direction
	// typically runs faster than combined/2 because the other direction
	// consumes part of the elapsed wall time. The combined figure below
	// still uses total elapsed as a one-glance overall rate.
	workerCount := int64(len(r.workers))
	avgEncTime := avgWorkerTime(totalNanosEnc, workerCount)
	avgDecTime := avgWorkerTime(totalNanosDec, workerCount)

	// Allocation rate and pool misses since the previous sample: the
	// steady-state trace the final differenced figures summarise.
	now := takeMemSnapshot()
	prev := r.lastSample
	r.lastSample = now
	window := now.at.Sub(prev.at)
	poolDelta := diffPoolVectors(now.pool, prev.pool)
	var hashMiss int64
	for _, t := range poolDelta.tiers {
		hashMiss += t.fresh + t.regrow
	}
	logf("+%s: iters=[%s] heap=%s objects=%d goroutines=%d gcs=%d alloc=%s/s poolmiss=hash:%d buf:%d chunk:%d tput=enc:%s dec:%s combined:%s",
		elapsed.Round(time.Second), strings.Join(iterParts, " "),
		humanBytes(int64(ms.HeapAlloc)), ms.HeapObjects, goroutines, ms.NumGC,
		humanBytes(rateBytes(now.totalAlloc-prev.totalAlloc, window)),
		hashMiss, poolDelta.buf.regrow, poolDelta.chunk.regrow,
		humanRateBare(totalEnc, avgEncTime), humanRateBare(totalDec, avgDecTime),
		humanRate(totalEnc+totalDec, elapsed))

	// Anomaly thresholds calibrated for mid-flight sampling. The itb
	// core spawns transient internal worker goroutines per in-flight
	// Encrypt/Decrypt call (up to GOMAXPROCS each), so the expected
	// mid-run ceiling scales with concurrency; only counts beyond that
	// model indicate a leak. Live HeapAlloc includes garbage awaiting
	// collection, so the mid-run heap warning triggers only past both
	// the 2x post-GC baseline and the configured soft memory limit —
	// the verdict-grade heap check runs post-GC in finalSummary.
	allowedGoroutines := r.warmupGoroutines + r.cfg.workers*itb.SetGOMAXPROCS(0) + 2
	if goroutines > allowedGoroutines {
		r.warnings++
		logf("WARNING: goroutine count %d exceeds transient allowance %d (warmup baseline %d)",
			goroutines, allowedGoroutines, r.warmupGoroutines)
	}
	heapCeiling := max(2*r.warmupHeap, uint64(r.cfg.memlimit))
	if ms.HeapAlloc > heapCeiling {
		r.warnings++
		logf("WARNING: heap alloc %s exceeds ceiling %s (2x warmup baseline / memlimit)",
			humanBytes(int64(ms.HeapAlloc)), humanBytes(int64(heapCeiling)))
	}
}

// finalSummary prints the end-of-run report and returns the process
// exit code. Verdict criteria: zero worker errors (a data mismatch
// terminates the process before reaching this point, so surviving
// iterations all round-tripped byte-exact), final goroutine count
// within +2 of the pre-worker idle baseline, and final heap below 2x
// the post-warmup baseline. The first criterion is the binding-side
// verdict; the other two are this harness's extension.
//
// Output contract. Both renderings are shared with every binding's
// loop utility field for field: the core lines / keys every
// implementation emits, in one fixed order, then this harness's
// Go-runtime extension (goroutine and heap lines, allocation and GC
// figures) at the positions reserved for it — after the rss line and
// after the parallax_chunk_pool key. Floats carry a fixed number of
// decimals so the JSON is byte-identical across implementations.
func finalSummary(r *runState, elapsed time.Duration, finalHeap uint64, finalGoroutines int, workerErrs []error) int {
	var (
		iterParts                    []string
		perWorkerIters               []int64
		totalIters                   int64
		totalEnc, totalDec           int64
		totalNanosEnc, totalNanosDec int64
	)
	for _, w := range r.workers {
		n := w.iters.Load()
		iterParts = append(iterParts, fmt.Sprintf("%d", n))
		perWorkerIters = append(perWorkerIters, n)
		totalIters += n
		totalEnc += w.bytesEnc.Load()
		totalDec += w.bytesDec.Load()
		totalNanosEnc += w.nanosEnc.Load()
		totalNanosDec += w.nanosDec.Load()
	}
	if finalHeap > r.peakHeap {
		r.peakHeap = finalHeap
	}
	if finalGoroutines > r.peakGoroutines {
		r.peakGoroutines = finalGoroutines
	}

	goroutinesOK := finalGoroutines <= r.idleGoroutines+2
	heapOK := finalHeap < 2*r.warmupHeap
	errsOK := len(workerErrs) == 0
	pass := goroutinesOK && heapOK && errsOK

	heapDelta := int64(finalHeap) - int64(r.warmupHeap)
	growthPct := 0.0
	if r.warmupHeap > 0 {
		growthPct = 100 * float64(heapDelta) / float64(r.warmupHeap)
	}
	rssDelta := int64(r.rssFinal) - int64(r.rssWarmup)
	rssGrowthPct := 0.0
	if r.rssWarmup > 0 {
		rssGrowthPct = 100 * float64(rssDelta) / float64(r.rssWarmup)
	}

	// Throughput. Per-direction throughput divides the sum of every
	// worker's wall time in that direction by the worker count — the
	// equivalent single-stream wall time under N-way concurrency — so
	// each direction reports the aggregate rate it sustained rather
	// than collapsing to combined/2 (every iteration moves equal
	// encrypt and decrypt bytes, so a total-elapsed denominator would
	// give both directions the same figure). The combined rate keeps
	// total elapsed as the one-glance overall figure.
	workerCount := int64(len(r.workers))
	avgEncTime := avgWorkerTime(totalNanosEnc, workerCount)
	avgDecTime := avgWorkerTime(totalNanosDec, workerCount)

	am := newAllocMetrics(r, totalIters)

	if r.cfg.jsonOutput {
		return printJSONSummary(r, elapsed, finalHeap, finalGoroutines, workerErrs,
			perWorkerIters, totalIters, totalEnc, totalDec, avgEncTime, avgDecTime,
			growthPct, rssGrowthPct, pass, am)
	}

	logf("=== FINAL ===")
	logf("  duration: %s", elapsed.Round(time.Millisecond))
	logf("  iterations: %s = %d total", strings.Join(iterParts, " + "), totalIters)
	logf("  throughput: encrypt %s, decrypt %s, combined %s",
		humanRate(totalEnc, avgEncTime), humanRate(totalDec, avgDecTime),
		humanRate(totalEnc+totalDec, elapsed))
	logf("  bytes: %s encrypted, %s decrypted", humanBytes(totalEnc), humanBytes(totalDec))
	logf("  data integrity: %d/%d PASS", totalIters, totalIters)
	logf("  concurrency: %s, workers %d (requested %d)", concurrencyMode, len(r.workers), r.cfg.workers)
	logf("  rss: warmup %s, peak %s, final %s (delta %s, %.1f%% growth)",
		humanBytes(int64(r.rssWarmup)), humanBytes(int64(r.rssPeak)),
		humanBytes(int64(r.rssFinal)), humanBytesSigned(rssDelta), rssGrowthPct)
	logf("  goroutines: idle baseline %d, warmup %d, peak %d, final %d (%s)",
		r.idleGoroutines, r.warmupGoroutines, r.peakGoroutines, finalGoroutines,
		stableLabel(goroutinesOK))
	logf("  heap: warmup baseline %s, peak %s, final %s (delta %s, %.1f%% growth)",
		humanBytes(int64(r.warmupHeap)), humanBytes(int64(r.peakHeap)),
		humanBytes(int64(finalHeap)), humanBytesSigned(heapDelta), growthPct)
	logf("  alloc: %s total, %s/s, %s/iteration, %d mallocs/iteration",
		humanBytes(am.AllocTotalBytes), humanBytes(am.AllocBytesPerSec),
		humanBytes(int64(am.AllocBytesPerIteration)), int64(am.MallocsPerIteration))
	logf("  gc: %d cycles (%.1f/s), stw pause %s (%.2f%% of wall), gc cpu fraction %.4f",
		am.GCCount, am.GCPerSec, time.Duration(am.GCPauseTotalNs), am.GCPausePercent, am.GCCPUFraction)
	for _, t := range am.HashPoolTiers {
		logf("  hash pool tier %d (starter %d): get %d, miss %d (new %d + regrow %d), miss %.2f%%, %s allocated",
			t.Tier, t.Starter, t.Get, t.New+t.Regrow, t.New, t.Regrow, t.MissPercent, humanBytes(t.NewBytes))
	}
	logf("  buf pool: get %d, regrow %d (of which fresh %d), miss %.2f%%, %s regrown",
		am.BufPool.Get, am.BufPool.Regrow, am.BufPool.New,
		am.BufPool.MissPercent, humanBytes(am.BufPool.RegrowBytes))
	logf("  parallax chunk pool: get %d, regrow %d (of which fresh %d), miss %.2f%%, %s regrown",
		am.ChunkPool.Get, am.ChunkPool.Regrow, am.ChunkPool.New,
		am.ChunkPool.MissPercent, humanBytes(am.ChunkPool.RegrowBytes))
	if n := r.rekeys.Load(); n > 0 {
		logf("  rekeys: %d", n)
	}
	if n := r.blobCycles.Load(); n > 0 {
		logf("  blob cycles: %d", n)
	}
	if r.warnings > 0 {
		logf("  monitor warnings: %d", r.warnings)
	}
	for _, werr := range workerErrs {
		logf("  ERROR: %v", werr)
	}
	if pass {
		logf("  verdict: PASS")
		return 0
	}
	logf("  verdict: FAIL (errors=%d goroutines_ok=%v heap_ok=%v)",
		len(workerErrs), goroutinesOK, heapOK)
	return 1
}

// stableLabel renders the goroutine-stability verdict fragment.
func stableLabel(ok bool) string {
	if ok {
		return "stable"
	}
	return "UNSTABLE"
}

// avgWorkerTime returns the average per-worker wall time (as a Duration)
// spent inside a given direction (encrypt or decrypt), computed as the
// sum of per-worker time-in-direction nanoseconds divided by the worker
// count. Dividing by workerCount converts the CPU-worker-time sum into
// the equivalent single-worker-parallel wall time so that
// bytes/avgTime yields aggregate throughput sustained by the direction
// under N-worker concurrency. Returns 0 when either operand is zero
// (humanRate handles the guard and prints n/a).
func avgWorkerTime(nanosSum, workerCount int64) time.Duration {
	if nanosSum <= 0 || workerCount <= 0 {
		return 0
	}
	return time.Duration(nanosSum / workerCount)
}

// fixed1 / fixed2 / fixed3 / fixed4 are floats that marshal with
// exactly that many decimals and never in exponent form, so the JSON
// summary is byte-identical across every implementation of the
// contract regardless of the host language's float printer.
type (
	fixed1 float64
	fixed2 float64
	fixed3 float64
	fixed4 float64
)

func (f fixed1) MarshalJSON() ([]byte, error) { return marshalFixed(float64(f), 1) }
func (f fixed2) MarshalJSON() ([]byte, error) { return marshalFixed(float64(f), 2) }
func (f fixed3) MarshalJSON() ([]byte, error) { return marshalFixed(float64(f), 3) }
func (f fixed4) MarshalJSON() ([]byte, error) { return marshalFixed(float64(f), 4) }

func marshalFixed(v float64, decimals int) ([]byte, error) {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		v = 0
	}
	return []byte(strconv.FormatFloat(v, 'f', decimals, 64)), nil
}

// summaryReport is the machine-readable final-summary shape emitted
// under --json-output. The leading block is the core every binding's
// loop utility emits in this key order; the trailing block is this
// harness's Go-runtime extension. Throughput figures are binary MiB
// per second (the same unit the MB/s log rendering uses).
type summaryReport struct {
	DurationSeconds     fixed3   `json:"duration_seconds"`
	Iterations          int64    `json:"iterations"`
	PerWorkerIterations []int64  `json:"per_worker_iterations"`
	BytesEncrypted      int64    `json:"bytes_encrypted"`
	BytesDecrypted      int64    `json:"bytes_decrypted"`
	EncryptMBPerSec     fixed1   `json:"encrypt_mb_per_sec"`
	DecryptMBPerSec     fixed1   `json:"decrypt_mb_per_sec"`
	CombinedMBPerSec    fixed1   `json:"combined_mb_per_sec"`
	Rekeys              int64    `json:"rekeys"`
	BlobCycles          int64    `json:"blob_cycles"`
	WorkerErrors        []string `json:"worker_errors"`
	Verdict             string   `json:"verdict"`

	// The configuration the run executed under, so each summary is
	// self-describing when cells of a sweep are compared.
	Shape            string              `json:"shape"`
	StreamProfile    string              `json:"stream_profile"`
	MessageProfile   string              `json:"message_profile"`
	Hash             string              `json:"hash"`
	Mac              string              `json:"mac"`
	PayloadBytes     int64               `json:"payload_bytes"`
	PayloadMode      string              `json:"payload_mode"`
	Seed             uint64              `json:"seed"`
	KeyBits          int                 `json:"key_bits"`
	NonceBits        int                 `json:"nonce_bits"`
	ChunkSizeBytes   int64               `json:"chunk_size_bytes"`
	BarrierFill      int                 `json:"barrier_fill"`
	Parallax         string              `json:"parallax"`
	Wrapper          string              `json:"wrapper"`
	WorkersRequested int                 `json:"goroutines_requested"`
	Workers          int                 `json:"goroutines"`
	Concurrency      string              `json:"concurrency"`
	GOGC             string              `json:"gogc"`
	MemLimit         int64               `json:"memlimit_bytes"`
	GOMAXPROCS       int                 `json:"gomaxprocs"`
	MicroBatchTiers  string              `json:"microbatch_tiers"`
	HashPoolStarters string              `json:"hashpool_starters"`
	RSSWarmupBytes   uint64              `json:"rss_warmup_bytes"`
	RSSPeakBytes     uint64              `json:"rss_peak_bytes"`
	RSSFinalBytes    uint64              `json:"rss_final_bytes"`
	RSSGrowthPercent fixed2              `json:"rss_growth_percent"`
	HashPoolTiers    []hashPoolTierStats `json:"hash_pool_tiers"`
	BufPool          bufPoolStats        `json:"buf_pool"`
	ChunkPool        bufPoolStats        `json:"parallax_chunk_pool"`

	// Go-runtime extension: nothing below is reachable through the C
	// ABI, so no binding emits it.
	HeapWarmupBytes   uint64 `json:"heap_warmup_bytes"`
	HeapPeakBytes     uint64 `json:"heap_peak_bytes"`
	HeapFinalBytes    uint64 `json:"heap_final_bytes"`
	HeapGrowthPercent fixed2 `json:"heap_growth_percent"`
	GoroutinesIdle    int    `json:"goroutines_idle"`
	GoroutinesWarmup  int    `json:"goroutines_warmup"`
	GoroutinesPeak    int    `json:"goroutines_peak"`
	GoroutinesFinal   int    `json:"goroutines_final"`
	Warnings          int    `json:"warnings"`
	allocMetrics
}

// policyLabel renders an encoder policy env value for the summary:
// the raw string when set, "default" when the shipped ladder applies.
func policyLabel(env string) string {
	if s := strings.TrimSpace(env); s != "" {
		return s
	}
	return "default"
}

// allocMetrics is the allocation-rate / GC-cost block of the summary
// together with the pool hit-miss block. Every figure is differenced
// between the post-warmup baseline and the instant the last worker
// returned, so it describes the main loop only — the settle sleep and
// the forced GCs that precede the leak snapshot are excluded. The one
// exception is GCCPUFraction, which the runtime reports cumulatively
// since process start and which cannot be differenced; the warmup
// phase is short enough for the figure to be dominated by the main
// loop. The pool block is core (every binding emits it); the
// allocation and GC figures are the Go-runtime extension.
type allocMetrics struct {
	AllocTotalBytes        int64  `json:"alloc_total_bytes"`
	AllocBytesPerSec       int64  `json:"alloc_bytes_per_sec"`
	AllocBytesPerIteration fixed1 `json:"alloc_bytes_per_iteration"`
	MallocsPerIteration    fixed1 `json:"mallocs_per_iteration"`
	GCCount                int64  `json:"gc_count"`
	GCPerSec               fixed2 `json:"gc_per_sec"`
	GCPauseTotalNs         int64  `json:"gc_pause_total_ns"`
	GCPausePercent         fixed2 `json:"gc_pause_percent"`
	GCCPUFraction          fixed4 `json:"gc_cpu_fraction"`
	HeapSysPeakBytes       uint64 `json:"heap_sys_bytes"`

	HashPoolTiers []hashPoolTierStats `json:"-"`
	BufPool       bufPoolStats        `json:"-"`
	ChunkPool     bufPoolStats        `json:"-"`
}

// hashPoolTierStats is one starter tier of the itb hash-array pool.
type hashPoolTierStats struct {
	Tier        int    `json:"tier"`
	Starter     int64  `json:"starter"`
	Get         int64  `json:"get"`
	New         int64  `json:"new"`
	Regrow      int64  `json:"regrow"`
	NewBytes    int64  `json:"new_bytes"`
	MissPercent fixed2 `json:"miss_percent"`
}

// bufPoolStats is one single-size byte pool (the itb scratch pool or
// the parallax chunk pool). MissPercent is regrow over get: a New
// item carries the pool's minimal 4 KiB capacity and is regrown by the
// same acquire on any larger request, so counting New separately would
// double-count that checkout.
type bufPoolStats struct {
	Get         int64  `json:"get"`
	New         int64  `json:"new"`
	Regrow      int64  `json:"regrow"`
	RegrowBytes int64  `json:"regrow_bytes"`
	MissPercent fixed2 `json:"miss_percent"`
}

// newAllocMetrics differences the warmup and steady snapshots on r:
// the runtime counters here, the pool counters via diffPoolVectors.
func newAllocMetrics(r *runState, totalIters int64) allocMetrics {
	w, s := r.warmupMem, r.steadyMem
	window := s.at.Sub(w.at)
	allocTotal := int64(s.totalAlloc - w.totalAlloc)
	gcCount := int64(s.numGC - w.numGC)
	pauseNs := int64(s.pauseNs - w.pauseNs)
	am := allocMetrics{
		AllocTotalBytes:  allocTotal,
		AllocBytesPerSec: rateBytes(uint64(allocTotal), window),
		GCCount:          gcCount,
		GCPauseTotalNs:   pauseNs,
		GCCPUFraction:    fixed4(s.gcCPU),
		HeapSysPeakBytes: s.heapSys,
	}
	if window > 0 {
		am.GCPerSec = fixed2(float64(gcCount) / window.Seconds())
		am.GCPausePercent = fixed2(100 * float64(pauseNs) / float64(window.Nanoseconds()))
	}
	if totalIters > 0 {
		am.AllocBytesPerIteration = fixed1(float64(allocTotal) / float64(totalIters))
		am.MallocsPerIteration = fixed1(float64(s.mallocs-w.mallocs) / float64(totalIters))
	}
	pd := diffPoolVectors(s.pool, w.pool)
	for _, pt := range pd.tiers {
		t := hashPoolTierStats{
			Tier: pt.index, Starter: pt.starter,
			Get: pt.get, New: pt.fresh, Regrow: pt.regrow,
			NewBytes: pt.newBytes,
		}
		t.MissPercent = missPercent(t.New+t.Regrow, t.Get)
		am.HashPoolTiers = append(am.HashPoolTiers, t)
	}
	am.BufPool = bufPoolStats{
		Get: pd.buf.get, New: pd.buf.fresh, Regrow: pd.buf.regrow, RegrowBytes: pd.buf.regrowBytes,
	}
	am.BufPool.MissPercent = missPercent(am.BufPool.Regrow, am.BufPool.Get)
	am.ChunkPool = bufPoolStats{
		Get: pd.chunk.get, New: pd.chunk.fresh, Regrow: pd.chunk.regrow, RegrowBytes: pd.chunk.regrowBytes,
	}
	am.ChunkPool.MissPercent = missPercent(am.ChunkPool.Regrow, am.ChunkPool.Get)
	return am
}

// missPercent renders misses over checkouts as a percentage; zero when
// nothing was checked out.
func missPercent(miss, get int64) fixed2 {
	if get <= 0 {
		return 0
	}
	return fixed2(100 * float64(miss) / float64(get))
}

// rateBytes converts a byte delta over a window into bytes per second;
// zero when the window is unmeasured.
func rateBytes(n uint64, d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	return int64(float64(n) / d.Seconds())
}

// printJSONSummary emits the final summary as one compact JSON object
// on stdout and returns the process exit code. Only the final summary
// swaps format under --json-output; the periodic progress lines during
// the run stay human-readable.
func printJSONSummary(r *runState, elapsed time.Duration, finalHeap uint64, finalGoroutines int,
	workerErrs []error, perWorkerIters []int64, totalIters, totalEnc, totalDec int64,
	avgEncTime, avgDecTime time.Duration, growthPct, rssGrowthPct float64, pass bool, am allocMetrics) int {
	errStrs := make([]string, 0, len(workerErrs))
	for _, werr := range workerErrs {
		errStrs = append(errStrs, werr.Error())
	}
	verdict := "PASS"
	if !pass {
		verdict = "FAIL"
	}
	hashTiers := am.HashPoolTiers
	if hashTiers == nil {
		hashTiers = []hashPoolTierStats{}
	}
	var streamProfile, msgProfile string
	if r.streamPipe != nil {
		streamProfile = r.streamProfile
	}
	if r.msgPipe != nil {
		msgProfile = r.msgProfile
	}
	rep := summaryReport{
		DurationSeconds:     fixed3(elapsed.Seconds()),
		Iterations:          totalIters,
		PerWorkerIterations: perWorkerIters,
		BytesEncrypted:      totalEnc,
		BytesDecrypted:      totalDec,
		EncryptMBPerSec:     fixed1(mbPerSec(totalEnc, avgEncTime)),
		DecryptMBPerSec:     fixed1(mbPerSec(totalDec, avgDecTime)),
		CombinedMBPerSec:    fixed1(mbPerSec(totalEnc+totalDec, elapsed)),
		Rekeys:              r.rekeys.Load(),
		BlobCycles:          r.blobCycles.Load(),
		WorkerErrors:        errStrs,
		Verdict:             verdict,
		Shape:               r.cfg.shape,
		StreamProfile:       streamProfile,
		MessageProfile:      msgProfile,
		Hash:                r.cfg.hash,
		Mac:                 r.cfg.mac,
		PayloadBytes:        r.cfg.payload,
		PayloadMode:         r.cfg.payloadMode,
		Seed:                r.cfg.seed,
		KeyBits:             r.cfg.keyBits,
		NonceBits:           r.cfg.nonceBits,
		ChunkSizeBytes:      r.cfg.chunkSize,
		BarrierFill:         r.cfg.barrierFill,
		Parallax:            onOff(r.cfg.parallax),
		Wrapper:             onOff(r.cfg.wrapper),
		WorkersRequested:    r.cfg.workers,
		Workers:             len(r.workers),
		Concurrency:         concurrencyMode,
		GOGC:                gogcLabel(r.cfg.gogc),
		MemLimit:            r.cfg.memlimit,
		GOMAXPROCS:          itb.SetGOMAXPROCS(0),
		MicroBatchTiers:     policyLabel(os.Getenv("ITB_MICROBATCH_TIERS")),
		HashPoolStarters:    policyLabel(os.Getenv("ITB_HASHPOOL_STARTERS")),
		RSSWarmupBytes:      r.rssWarmup,
		RSSPeakBytes:        r.rssPeak,
		RSSFinalBytes:       r.rssFinal,
		RSSGrowthPercent:    fixed2(rssGrowthPct),
		HashPoolTiers:       hashTiers,
		BufPool:             am.BufPool,
		ChunkPool:           am.ChunkPool,
		HeapWarmupBytes:     r.warmupHeap,
		HeapPeakBytes:       r.peakHeap,
		HeapFinalBytes:      finalHeap,
		HeapGrowthPercent:   fixed2(growthPct),
		GoroutinesIdle:      r.idleGoroutines,
		GoroutinesWarmup:    r.warmupGoroutines,
		GoroutinesPeak:      r.peakGoroutines,
		GoroutinesFinal:     finalGoroutines,
		Warnings:            r.warnings,
		allocMetrics:        am,
	}
	b, err := json.Marshal(rep)
	if err != nil {
		fmt.Printf("[loop] json summary marshal: %v\n", err)
		return 1
	}
	fmt.Println(string(b))
	if pass {
		return 0
	}
	return 1
}

// gogcLabel renders the effective GC percentage as the runtime
// reports it through the query form of [itb.SetGCPercent] (the same
// probe the C ABI's ITB_SetGCPercent(-1) runs), which makes the field
// identical across implementations whether the percentage came from
// --gogc, from the GOGC / ITB_GOGC environment, or from the runtime
// default.
func gogcLabel(flag int) string {
	if flag > 0 {
		return fmt.Sprint(flag)
	}
	return fmt.Sprint(itb.SetGCPercent(-1))
}

// mbPerSec converts a byte count over a duration into binary MiB per
// second; zero when the duration is unmeasured.
func mbPerSec(n int64, d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(n) / float64(1<<20) / d.Seconds()
}
