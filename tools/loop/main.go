// Command loop is a long-run concurrency stress harness for a single
// shared [github.com/everanium/itb/triple.Pipeline] instance.
//
// N worker goroutines (default 3, capped at 10) hammer one Pipeline
// with concurrent Encrypt/Decrypt round-trips over a configurable
// duration (or a fixed per-worker iteration count). Every worker owns
// a distinct CSPRNG-generated plaintext buffer held for the whole run,
// so any cross-call state leakage inside the Pipeline surfaces as a
// data mismatch between workers rather than cancelling out. Each
// iteration encrypts the worker's plaintext to wire bytes, decrypts
// the wire back, and compares the round-trip output byte-for-byte
// against the original; a mismatch panics immediately with the worker
// id, iteration number, and SHA-256 digests of both buffers.
//
// The default shape is full production: Streaming AEAD profile with
// parallax on, wrapper on, KMAC256 MAC, Areion-SoEM-512 inner hash,
// 1024-bit keys, and the compile-in 512-bit nonce width.
//
// A monitor goroutine samples runtime state every 5 seconds (heap
// alloc, heap objects, GC count, goroutine count, per-worker iteration
// counters, aggregate throughput) and warns on goroutine-count or
// heap-growth anomalies. The final summary reports totals, peak vs
// final runtime state, and a PASS/FAIL verdict: PASS iff zero data
// mismatches, the final goroutine count settles within +2 of the
// pre-worker idle baseline, and the final heap stays below 2x the
// post-warmup baseline.
//
// Usage:
//
//	loop --duration 5m --goroutines 3 --shape stream --hash areion512 \
//	     --mac kmac256 --payload-size 16MB --memlimit auto \
//	     --parallax on --wrapper on
//
// Ctrl-C triggers a graceful shutdown: in-flight iterations complete,
// then the partial summary prints.
package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/macs"
	"github.com/everanium/itb/triple"
)

// Shape selector values for the --shape flag.
const (
	shapeStream  = "stream"
	shapeMessage = "message"
	shapeBoth    = "both"
)

// maxWorkersFlag caps --goroutines; the harness targets modest hosts
// and each worker pins payload-sized buffers for the whole run.
const maxWorkersFlag = 10

// config carries the resolved CLI surface.
type config struct {
	duration   time.Duration
	iterations int64 // per-worker; 0 = duration-based
	workers    int
	shape      string
	hash       string
	mac        string
	payload    int64
	memlimit   int64 // resolved bytes
	gogc       int   // 0 = leave the runtime default
	parallax   bool
	wrapper    bool
}

// runState is the shared context handed to workers and the monitor.
type runState struct {
	cfg        config
	streamPipe *triple.Pipeline // nil when shape == message
	msgPipe    *triple.Pipeline // nil when shape == stream
	workers    []*worker

	// release is closed by main after the warmup barrier; workers
	// block on it between their warmup iteration and the main loop.
	release chan struct{}

	// start is the main-loop start instant (set when release closes);
	// throughput is measured against it.
	start time.Time

	// Baselines and peaks. idleGoroutines is sampled before any worker
	// launches; warmupHeap / warmupGoroutines after the warmup barrier
	// with a forced GC. Peaks are updated by the monitor goroutine only
	// and read by main after the monitor has stopped.
	idleGoroutines   int
	warmupHeap       uint64
	warmupGoroutines int
	peakHeap         uint64
	peakGoroutines   int
	warnings         int
}

func main() {
	os.Exit(run())
}

func run() int {
	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "loop: %v\n", err)
		return 2
	}

	// Runtime shaping before any allocation-heavy setup.
	debug.SetMemoryLimit(cfg.memlimit)
	if cfg.gogc > 0 {
		debug.SetGCPercent(cfg.gogc)
	}

	logf("start: duration=%s iterations=%d goroutines=%d shape=%s hash=%s mac=%s payload=%s memlimit=%s parallax=%s wrapper=%s",
		cfg.duration, cfg.iterations, cfg.workers, cfg.shape, cfg.hash, cfg.mac,
		humanBytes(cfg.payload), humanBytes(cfg.memlimit), onOff(cfg.parallax), onOff(cfg.wrapper))

	r := &runState{cfg: cfg, release: make(chan struct{})}

	// Pipeline construction — one shared instance per exercised shape.
	opts := triple.Opts{
		InnerHash:    cfg.hash,
		MacName:      cfg.mac,
		WithParallax: &cfg.parallax,
		WithWrapper:  &cfg.wrapper,
	}
	if cfg.shape == shapeStream || cfg.shape == shapeBoth {
		pipe, blob, ierr := triple.Init(triple.ProfileStreamingAEADTripleMACV1, opts)
		if ierr != nil {
			fmt.Fprintf(os.Stderr, "loop: triple.Init(%s): %v\n", triple.ProfileStreamingAEADTripleMACV1, ierr)
			return 1
		}
		defer pipe.Close()
		r.streamPipe = pipe
		logf("pipeline initialised: profile=%s blob=%d bytes", triple.ProfileStreamingAEADTripleMACV1, len(blob))
	}
	if cfg.shape == shapeMessage || cfg.shape == shapeBoth {
		pipe, blob, ierr := triple.Init(triple.ProfileSingleMsgTripleMACV1, opts)
		if ierr != nil {
			fmt.Fprintf(os.Stderr, "loop: triple.Init(%s): %v\n", triple.ProfileSingleMsgTripleMACV1, ierr)
			return 1
		}
		defer pipe.Close()
		r.msgPipe = pipe
		logf("pipeline initialised: profile=%s blob=%d bytes", triple.ProfileSingleMsgTripleMACV1, len(blob))
	}

	// Per-worker distinct plaintexts, generated once and held for the
	// whole run so cross-worker data crossover is detectable.
	r.workers = make([]*worker, cfg.workers)
	for i := range r.workers {
		pt := make([]byte, cfg.payload)
		if _, rerr := rand.Read(pt); rerr != nil {
			fmt.Fprintf(os.Stderr, "loop: crypto/rand: %v\n", rerr)
			return 1
		}
		r.workers[i] = &worker{id: i, plaintext: pt}
	}

	// Signal-aware root context: Ctrl-C / SIGTERM cancels gracefully.
	sigCtx, sigStop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer sigStop()
	ctx, cancel := context.WithCancel(sigCtx)
	defer cancel()

	// Idle goroutine baseline — before any worker exists. The final
	// leak check compares the post-run count against this figure.
	runtime.GC()
	r.idleGoroutines = runtime.NumGoroutine()

	// Launch workers. Each performs one warmup iteration, signals the
	// barrier, and blocks on r.release before entering the main loop.
	var (
		wg       sync.WaitGroup
		warmupWG sync.WaitGroup
		errCh    = make(chan error, cfg.workers)
	)
	warmupStart := time.Now()
	warmupWG.Add(cfg.workers)
	wg.Add(cfg.workers)
	for _, w := range r.workers {
		go func(w *worker) {
			defer wg.Done()
			if err := w.runLoop(ctx, r, &warmupWG); err != nil {
				errCh <- err
				cancel()
			}
		}(w)
	}
	warmupWG.Wait()

	// Post-warmup baselines under a double forced GC so the heap
	// figure reflects retained state: the second cycle drains
	// sync.Pool victim caches that survive a single collection.
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	r.warmupHeap = ms.HeapAlloc
	r.warmupGoroutines = runtime.NumGoroutine()
	r.peakHeap = ms.HeapAlloc
	r.peakGoroutines = r.warmupGoroutines
	logf("warmup: %d goroutines x 1 iter completed in %s (baseline heap=%s, goroutines=%d)",
		cfg.workers, time.Since(warmupStart).Round(100*time.Millisecond),
		humanBytes(int64(r.warmupHeap)), r.warmupGoroutines)

	// Open the gate; arm the duration timer only in duration mode.
	r.start = time.Now()
	close(r.release)
	var durTimer *time.Timer
	if cfg.iterations == 0 {
		durTimer = time.AfterFunc(cfg.duration, cancel)
		defer durTimer.Stop()
	}

	// Monitor loop until every worker returns.
	monDone := make(chan struct{})
	go func() {
		defer close(monDone)
		monitor(ctx, r)
	}()

	wg.Wait()
	elapsed := time.Since(r.start)
	cancel()
	<-monDone

	// Drain worker errors (first error already cancelled the run).
	var workerErrs []error
	for {
		select {
		case werr := <-errCh:
			workerErrs = append(workerErrs, werr)
			continue
		default:
		}
		break
	}

	// Settle before the final leak snapshot: give transient runtime /
	// pipeline goroutines a moment to exit, then double-GC (matching
	// the warmup baseline methodology) so retained-state heap figures
	// compare like for like.
	time.Sleep(200 * time.Millisecond)
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&ms)
	finalHeap := ms.HeapAlloc
	finalGoroutines := runtime.NumGoroutine()

	return finalSummary(r, elapsed, finalHeap, finalGoroutines, workerErrs)
}

// parseFlags builds the resolved config from argv.
func parseFlags(argv []string) (config, error) {
	fs := flag.NewFlagSet("loop", flag.ContinueOnError)
	var (
		duration    = fs.Duration("duration", 5*time.Minute, "run duration (Go format: 30s / 5m / 1h); ignored when --iterations > 0")
		iterations  = fs.Int64("iterations", 0, "fixed per-goroutine iteration count; 0 = duration-based")
		workers     = fs.Int("goroutines", 3, fmt.Sprintf("concurrent worker goroutines (1..%d)", maxWorkersFlag))
		shape       = fs.String("shape", shapeStream, "cipher surface to exercise: stream | message | both")
		hash        = fs.String("hash", "areion512", "inner ITB hash primitive name")
		mac         = fs.String("mac", "kmac256", "MAC primitive name")
		payloadStr  = fs.String("payload-size", "16MB", "per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)")
		memlimitStr = fs.String("memlimit", "auto", "Go heap soft limit: auto (1GiB when goroutines <= 3, else 256MiB) or a size (e.g. 512MB)")
		gogc        = fs.Int("gogc", 0, "GC trigger percentage; 0 = leave the runtime default")
		parallaxStr = fs.String("parallax", "on", "parallax layer: on | off")
		wrapperStr  = fs.String("wrapper", "on", "wrapper (Outer cipher) layer: on | off")
	)
	if err := fs.Parse(argv); err != nil {
		return config{}, err
	}
	if fs.NArg() > 0 {
		return config{}, fmt.Errorf("unexpected positional arguments: %v", fs.Args())
	}

	cfg := config{
		duration:   *duration,
		iterations: *iterations,
		workers:    *workers,
		shape:      *shape,
		hash:       *hash,
		mac:        *mac,
		gogc:       *gogc,
	}
	if cfg.duration <= 0 {
		return config{}, fmt.Errorf("--duration must be positive, got %s", cfg.duration)
	}
	if cfg.iterations < 0 {
		return config{}, fmt.Errorf("--iterations must be >= 0, got %d", cfg.iterations)
	}
	if cfg.workers < 1 || cfg.workers > maxWorkersFlag {
		return config{}, fmt.Errorf("--goroutines must be in 1..%d, got %d", maxWorkersFlag, cfg.workers)
	}
	switch cfg.shape {
	case shapeStream, shapeMessage, shapeBoth:
	default:
		return config{}, fmt.Errorf("--shape must be stream | message | both, got %q", cfg.shape)
	}
	if _, ok := hashes.Find(cfg.hash); !ok {
		return config{}, fmt.Errorf("--hash %q is not a registered hash primitive", cfg.hash)
	}
	if _, ok := macs.Find(cfg.mac); !ok {
		return config{}, fmt.Errorf("--mac %q is not a registered MAC primitive", cfg.mac)
	}

	payload, err := parseSize(*payloadStr)
	if err != nil {
		return config{}, fmt.Errorf("--payload-size: %v", err)
	}
	if payload < 1 {
		return config{}, fmt.Errorf("--payload-size must be at least 1 byte")
	}
	cfg.payload = payload

	if *memlimitStr == "auto" {
		if cfg.workers <= 3 {
			cfg.memlimit = 1 << 30 // 1 GiB
		} else {
			cfg.memlimit = 256 << 20 // 256 MiB
		}
	} else {
		limit, lerr := parseSize(*memlimitStr)
		if lerr != nil {
			return config{}, fmt.Errorf("--memlimit: %v", lerr)
		}
		cfg.memlimit = limit
	}
	if cfg.gogc < 0 {
		return config{}, fmt.Errorf("--gogc must be >= 0, got %d", cfg.gogc)
	}

	cfg.parallax, err = parseOnOff("--parallax", *parallaxStr)
	if err != nil {
		return config{}, err
	}
	cfg.wrapper, err = parseOnOff("--wrapper", *wrapperStr)
	if err != nil {
		return config{}, err
	}
	return cfg, nil
}

// parseOnOff maps "on"/"off" flag values to a bool.
func parseOnOff(name, v string) (bool, error) {
	switch v {
	case "on":
		return true, nil
	case "off":
		return false, nil
	}
	return false, fmt.Errorf("%s must be on | off, got %q", name, v)
}

// onOff renders a bool as the on/off flag vocabulary.
func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// logf prints one prefixed status line to stdout.
func logf(format string, args ...any) {
	fmt.Printf("[loop] "+format+"\n", args...)
}
