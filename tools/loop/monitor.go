package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/everanium/itb/internal/poolstats"
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
	poolDelta := now.pool.Sub(prev.pool)
	var hashMiss int64
	for i := range poolDelta.HashNew {
		hashMiss += poolDelta.HashNew[i] + poolDelta.HashRegrow[i]
	}
	logf("+%s: iters=[%s] heap=%s objects=%d goroutines=%d gcs=%d alloc=%s/s poolmiss=hash:%d buf:%d chunk:%d tput=enc:%s dec:%s combined:%s",
		elapsed.Round(time.Second), strings.Join(iterParts, " "),
		humanBytes(int64(ms.HeapAlloc)), ms.HeapObjects, goroutines, ms.NumGC,
		humanBytes(rateBytes(now.totalAlloc-prev.totalAlloc, window)),
		hashMiss, poolDelta.BufRegrow, poolDelta.ChunkRegrow,
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
	allowedGoroutines := r.warmupGoroutines + r.cfg.workers*runtime.GOMAXPROCS(0) + 2
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
// panics before reaching this point, so surviving iterations all
// round-tripped byte-exact), final goroutine count within +2 of the
// pre-worker idle baseline, and final heap below 2x the post-warmup
// baseline.
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

	workerCount := int64(len(r.workers))
	avgEncTime := avgWorkerTime(totalNanosEnc, workerCount)
	avgDecTime := avgWorkerTime(totalNanosDec, workerCount)

	am := newAllocMetrics(r, totalIters)

	if r.cfg.jsonOutput {
		return printJSONSummary(r, elapsed, finalHeap, finalGoroutines, workerErrs,
			perWorkerIters, totalIters, totalEnc, totalDec, avgEncTime, avgDecTime,
			growthPct, pass, am)
	}

	logf("=== FINAL ===")
	logf("  duration: %s", elapsed.Round(time.Millisecond))
	logf("  iterations: %s = %d total", strings.Join(iterParts, " + "), totalIters)
	logf("  throughput: encrypt %s, decrypt %s, combined %s",
		humanRate(totalEnc, avgEncTime), humanRate(totalDec, avgDecTime),
		humanRate(totalEnc+totalDec, elapsed))
	logf("  bytes: %s encrypted, %s decrypted", humanBytes(totalEnc), humanBytes(totalDec))
	logf("  data integrity: %d/%d PASS", totalIters, totalIters)
	logf("  goroutines: idle baseline %d, warmup %d, peak %d, final %d (%s)",
		r.idleGoroutines, r.warmupGoroutines, r.peakGoroutines, finalGoroutines,
		stableLabel(goroutinesOK))
	logf("  heap: warmup baseline %s, peak %s, final %s (delta %s, %.1f%% growth)",
		humanBytes(int64(r.warmupHeap)), humanBytes(int64(r.peakHeap)),
		humanBytes(int64(finalHeap)), humanBytesSigned(heapDelta), growthPct)
	logf("  alloc: %s total, %s/s, %s/iteration, %d mallocs/iteration",
		humanBytes(am.AllocTotalBytes), humanBytes(int64(am.AllocBytesPerSec)),
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

// summaryReport is the machine-readable final-summary shape emitted
// under --json-output. Field semantics mirror the human-readable
// summary lines; throughput figures are binary MiB per second (the
// same unit the MB/s log rendering uses).
type summaryReport struct {
	DurationSeconds     float64  `json:"duration_seconds"`
	Iterations          int64    `json:"iterations"`
	PerWorkerIterations []int64  `json:"per_worker_iterations"`
	BytesEncrypted      int64    `json:"bytes_encrypted"`
	BytesDecrypted      int64    `json:"bytes_decrypted"`
	EncryptMBPerSec     float64  `json:"encrypt_mb_per_sec"`
	DecryptMBPerSec     float64  `json:"decrypt_mb_per_sec"`
	CombinedMBPerSec    float64  `json:"combined_mb_per_sec"`
	HeapWarmupBytes     uint64   `json:"heap_warmup_bytes"`
	HeapPeakBytes       uint64   `json:"heap_peak_bytes"`
	HeapFinalBytes      uint64   `json:"heap_final_bytes"`
	HeapGrowthPercent   float64  `json:"heap_growth_percent"`
	GoroutinesIdle      int      `json:"goroutines_idle"`
	GoroutinesWarmup    int      `json:"goroutines_warmup"`
	GoroutinesPeak      int      `json:"goroutines_peak"`
	GoroutinesFinal     int      `json:"goroutines_final"`
	Warnings            int      `json:"warnings"`
	Rekeys              int64    `json:"rekeys"`
	BlobCycles          int64    `json:"blob_cycles"`
	WorkerErrors        []string `json:"worker_errors"`
	Verdict             string   `json:"verdict"`

	// Runtime shaping the run executed under, so each summary is
	// self-describing when cells of a sweep are compared.
	GOGC         string `json:"gogc"`
	MemLimit     int64  `json:"memlimit_bytes"`
	GOMAXPROCS   int    `json:"gomaxprocs"`
	Hash         string `json:"hash"`
	PayloadBytes int64  `json:"payload_bytes"`
	Workers      int    `json:"goroutines"`

	// Encoder policy knobs the process was started with, read from the
	// ITB_MICROBATCH_TIERS / ITB_HASHPOOL_STARTERS env at init ("default"
	// when unset), so every cell of a policy sweep is self-describing.
	MicroBatchTiers  string `json:"microbatch_tiers"`
	HashPoolStarters string `json:"hashpool_starters"`

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

// allocMetrics is the allocation-rate / GC-cost / pool hit-miss block
// of the summary. Every figure is differenced between the post-warmup
// baseline and the instant the last worker returned, so it describes
// the main loop only — the settle sleep and the forced GCs that
// precede the leak snapshot are excluded. The one exception is
// GCCPUFraction, which the runtime reports cumulatively since process
// start and which cannot be differenced; the warmup phase is short
// enough for the figure to be dominated by the main loop.
type allocMetrics struct {
	AllocTotalBytes        int64   `json:"alloc_total_bytes"`
	AllocBytesPerSec       float64 `json:"alloc_bytes_per_sec"`
	AllocBytesPerIteration float64 `json:"alloc_bytes_per_iteration"`
	MallocsPerIteration    float64 `json:"mallocs_per_iteration"`
	GCCount                int64   `json:"gc_count"`
	GCPerSec               float64 `json:"gc_per_sec"`
	GCPauseTotalNs         int64   `json:"gc_pause_total_ns"`
	GCPausePercent         float64 `json:"gc_pause_percent"`
	GCCPUFraction          float64 `json:"gc_cpu_fraction"`
	HeapSysPeakBytes       uint64  `json:"heap_sys_bytes"`

	HashPoolTiers []hashPoolTierStats `json:"hash_pool_tiers"`
	BufPool       bufPoolStats        `json:"buf_pool"`
	ChunkPool     bufPoolStats        `json:"parallax_chunk_pool"`
}

// hashPoolTierStats is one starter tier of the itb hash-array pool.
type hashPoolTierStats struct {
	Tier        int     `json:"tier"`
	Starter     int64   `json:"starter"`
	Get         int64   `json:"get"`
	New         int64   `json:"new"`
	Regrow      int64   `json:"regrow"`
	NewBytes    int64   `json:"new_bytes"`
	MissPercent float64 `json:"miss_percent"`
}

// bufPoolStats is one single-size byte pool (the itb scratch pool or
// the parallax chunk pool). MissPercent is regrow over get: a New
// item carries the pool's minimal 4 KiB capacity and is regrown by the
// same acquire on any larger request, so counting New separately would
// double-count that checkout.
type bufPoolStats struct {
	Get         int64   `json:"get"`
	New         int64   `json:"new"`
	Regrow      int64   `json:"regrow"`
	RegrowBytes int64   `json:"regrow_bytes"`
	MissPercent float64 `json:"miss_percent"`
}

// newAllocMetrics differences the warmup and steady snapshots on r.
func newAllocMetrics(r *runState, totalIters int64) allocMetrics {
	w, s := r.warmupMem, r.steadyMem
	window := s.at.Sub(w.at)
	allocTotal := int64(s.totalAlloc - w.totalAlloc)
	gcCount := int64(s.numGC - w.numGC)
	pauseNs := int64(s.pauseNs - w.pauseNs)
	am := allocMetrics{
		AllocTotalBytes:  allocTotal,
		AllocBytesPerSec: float64(rateBytes(uint64(allocTotal), window)),
		GCCount:          gcCount,
		GCPauseTotalNs:   pauseNs,
		GCCPUFraction:    s.gcCPU,
		HeapSysPeakBytes: s.heapSys,
	}
	if window > 0 {
		am.GCPerSec = float64(gcCount) / window.Seconds()
		am.GCPausePercent = 100 * float64(pauseNs) / float64(window.Nanoseconds())
	}
	if totalIters > 0 {
		am.AllocBytesPerIteration = float64(allocTotal) / float64(totalIters)
		am.MallocsPerIteration = float64(s.mallocs-w.mallocs) / float64(totalIters)
	}
	pd := s.pool.Sub(w.pool)
	for i := 0; i < poolstats.MaxHashTiers; i++ {
		if pd.HashStarter[i] == 0 {
			continue
		}
		t := hashPoolTierStats{
			Tier: i, Starter: pd.HashStarter[i],
			Get: pd.HashGet[i], New: pd.HashNew[i], Regrow: pd.HashRegrow[i],
			NewBytes: pd.HashNewBytes[i],
		}
		t.MissPercent = missPercent(t.New+t.Regrow, t.Get)
		am.HashPoolTiers = append(am.HashPoolTiers, t)
	}
	am.BufPool = bufPoolStats{
		Get: pd.BufGet, New: pd.BufNew, Regrow: pd.BufRegrow, RegrowBytes: pd.BufRegrowBytes,
	}
	am.BufPool.MissPercent = missPercent(am.BufPool.Regrow, am.BufPool.Get)
	am.ChunkPool = bufPoolStats{
		Get: pd.ChunkGet, New: pd.ChunkNew, Regrow: pd.ChunkRegrow, RegrowBytes: pd.ChunkRegrowBytes,
	}
	am.ChunkPool.MissPercent = missPercent(am.ChunkPool.Regrow, am.ChunkPool.Get)
	return am
}

// missPercent renders misses over checkouts as a percentage; zero when
// nothing was checked out.
func missPercent(miss, get int64) float64 {
	if get <= 0 {
		return 0
	}
	return 100 * float64(miss) / float64(get)
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
	avgEncTime, avgDecTime time.Duration, growthPct float64, pass bool, am allocMetrics) int {
	errStrs := make([]string, 0, len(workerErrs))
	for _, werr := range workerErrs {
		errStrs = append(errStrs, werr.Error())
	}
	verdict := "PASS"
	if !pass {
		verdict = "FAIL"
	}
	rep := summaryReport{
		DurationSeconds:     elapsed.Seconds(),
		Iterations:          totalIters,
		PerWorkerIterations: perWorkerIters,
		BytesEncrypted:      totalEnc,
		BytesDecrypted:      totalDec,
		EncryptMBPerSec:     mbPerSec(totalEnc, avgEncTime),
		DecryptMBPerSec:     mbPerSec(totalDec, avgDecTime),
		CombinedMBPerSec:    mbPerSec(totalEnc+totalDec, elapsed),
		HeapWarmupBytes:     r.warmupHeap,
		HeapPeakBytes:       r.peakHeap,
		HeapFinalBytes:      finalHeap,
		HeapGrowthPercent:   growthPct,
		GoroutinesIdle:      r.idleGoroutines,
		GoroutinesWarmup:    r.warmupGoroutines,
		GoroutinesPeak:      r.peakGoroutines,
		GoroutinesFinal:     finalGoroutines,
		Warnings:            r.warnings,
		Rekeys:              r.rekeys.Load(),
		BlobCycles:          r.blobCycles.Load(),
		WorkerErrors:        errStrs,
		Verdict:             verdict,
		GOGC:                gogcLabel(r.cfg.gogc),
		MemLimit:            r.cfg.memlimit,
		GOMAXPROCS:          runtime.GOMAXPROCS(0),
		Hash:                r.cfg.hash,
		PayloadBytes:        r.cfg.payload,
		Workers:             r.cfg.workers,
		MicroBatchTiers:     policyLabel(os.Getenv("ITB_MICROBATCH_TIERS")),
		HashPoolStarters:    policyLabel(os.Getenv("ITB_HASHPOOL_STARTERS")),
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

// gogcLabel renders the effective GC percentage: the --gogc flag when
// set, otherwise the GOGC environment variable the runtime consumed at
// start ("100" when unset, matching the runtime default).
func gogcLabel(flag int) string {
	if flag > 0 {
		return fmt.Sprint(flag)
	}
	if v := os.Getenv("GOGC"); v != "" {
		return v
	}
	return "100"
}

// mbPerSec converts a byte count over a duration into binary MiB per
// second; zero when the duration is unmeasured.
func mbPerSec(n int64, d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(n) / float64(1<<20) / d.Seconds()
}
