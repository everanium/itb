package main

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"
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
		iterParts          []string
		totalEnc, totalDec int64
	)
	for _, w := range r.workers {
		iterParts = append(iterParts, fmt.Sprintf("g%d:%d", w.id, w.iters.Load()))
		totalEnc += w.bytesEnc.Load()
		totalDec += w.bytesDec.Load()
	}

	// Throughput split into encrypt / decrypt lanes so a per-direction
	// asymmetry (typically encrypt lagging decrypt due to the noise-
	// injection CSPRNG cost) is visible in the progress line. The
	// combined figure is retained for a one-glance total.
	logf("+%s: iters=[%s] heap=%s objects=%d goroutines=%d gcs=%d tput=enc:%s dec:%s combined:%s",
		elapsed.Round(time.Second), strings.Join(iterParts, " "),
		humanBytes(int64(ms.HeapAlloc)), ms.HeapObjects, goroutines, ms.NumGC,
		humanRateBare(totalEnc, elapsed), humanRateBare(totalDec, elapsed),
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
		iterParts          []string
		totalIters         int64
		totalEnc, totalDec int64
	)
	for _, w := range r.workers {
		n := w.iters.Load()
		iterParts = append(iterParts, fmt.Sprintf("%d", n))
		totalIters += n
		totalEnc += w.bytesEnc.Load()
		totalDec += w.bytesDec.Load()
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

	logf("=== FINAL ===")
	logf("  duration: %s", elapsed.Round(time.Millisecond))
	logf("  iterations: %s = %d total", strings.Join(iterParts, " + "), totalIters)
	logf("  throughput: encrypt %s, decrypt %s, combined %s",
		humanRate(totalEnc, elapsed), humanRate(totalDec, elapsed),
		humanRate(totalEnc+totalDec, elapsed))
	logf("  bytes: %s encrypted, %s decrypted", humanBytes(totalEnc), humanBytes(totalDec))
	logf("  data integrity: %d/%d PASS", totalIters, totalIters)
	logf("  goroutines: idle baseline %d, warmup %d, peak %d, final %d (%s)",
		r.idleGoroutines, r.warmupGoroutines, r.peakGoroutines, finalGoroutines,
		stableLabel(goroutinesOK))
	logf("  heap: warmup baseline %s, peak %s, final %s (delta %s, %.1f%% growth)",
		humanBytes(int64(r.warmupHeap)), humanBytes(int64(r.peakHeap)),
		humanBytes(int64(finalHeap)), humanBytesSigned(heapDelta), growthPct)
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
