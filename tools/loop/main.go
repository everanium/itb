// Long-run stress harness. Command loop hammers one shared
// [github.com/everanium/itb/triple.Pipeline] instance with concurrent
// encrypt → decrypt → compare round-trips for minutes, rotating the
// outer masters and reopening the Pipeline from its session blob on
// a schedule, and reports whether the process survived with every
// byte intact. It is the Go reference for the loop utility every
// binding under bindings/<lang>/loop/ carries: the option surface,
// the round structure and the output format are the same there, so
// a run of either reads the same and a sweep can compare cells across
// the two.
//
// N worker goroutines (default 3, capped at 10) share one Pipeline
// per exercised shape. Every worker owns a distinct CSPRNG-generated
// plaintext buffer held for the whole run, so any cross-call state
// leakage inside the Pipeline surfaces as a data mismatch between
// workers rather than cancelling out. Each iteration encrypts the
// worker's plaintext to wire bytes, decrypts the wire back, and
// compares the round-trip output byte-for-byte against the original;
// a mismatch terminates the process immediately with the worker id,
// iteration number, and the first differing offset.
//
// Three cipher surfaces are exercised under --shape: stream drives
// [triple.Pipeline.EncryptStream] with an io.Reader / io.Writer pair
// (ITB runs the chunk loop), stream_one_shot drives
// [triple.Pipeline.EncryptStreamBytes] with the whole buffer, message
// drives [triple.Pipeline.EncryptMessage]; both rotates through the
// three by iteration number. The default shape is full production:
// Streaming AEAD profile with parallax on, wrapper on, hmac-blake3
// MAC, Areion-SoEM-512 inner hash, 1024-bit keys, and the compile-in
// 512-bit nonce width.
//
// Overrides beyond that shape: --profile exercises one registered
// triple profile in place of the shape-based pair; --key-bits /
// --nonce-bits / --chunk-size / --barrier-fill sweep the corresponding
// [github.com/everanium/itb/triple.Opts] knobs; --gomaxprocs pins CPU
// parallelism; --payload-mode swaps the plaintext content policy
// (rotating CSPRNG refills or degenerate byte patterns — pattern modes
// trade the cross-worker buffer distinctness above for content
// edge-case coverage); --seed makes plaintexts deterministic for bug
// reproduction (pipeline keys stay CSPRNG-drawn); --rekey-every and
// --blob-cycle-every periodically rotate the outer-layer masters and
// reopen the pipeline from its session blob; --json-output prints the
// final summary as one JSON object. Every override defaults to the
// production shape above.
//
// A monitor goroutine samples runtime state every 5 seconds (heap
// alloc, heap objects, GC count, goroutine count, per-worker iteration
// counters, aggregate throughput) and warns on goroutine-count or
// heap-growth anomalies. The monitor is the one part of this harness
// with no binding-side counterpart: nothing it reads is reachable
// through the C ABI. The final summary reports totals, peak vs final
// runtime state, and a PASS/FAIL verdict: PASS iff zero worker
// errors, the final goroutine count settles within +2 of the
// pre-worker idle baseline, and the final heap stays below 2x the
// post-warmup baseline.
//
// Usage:
//
//	loop --duration 5m --goroutines 3 --shape stream --hash areion512 \
//	     --mac hmac-blake3 --payload-size 16MB --memlimit auto \
//	     --parallax on --wrapper on
//
// Ctrl-C triggers a graceful shutdown: in-flight iterations complete,
// then the partial summary prints.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	itb "github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/macs"
	"github.com/everanium/itb/parallax"
	"github.com/everanium/itb/triple"
)

// Shape selector values for the --shape flag.
const (
	shapeStream        = "stream"
	shapeMessage       = "message"
	shapeStreamOneShot = "stream_one_shot"
	shapeBoth          = "both"
)

// concurrencyMode names the concurrency mode this harness implements,
// as every loop utility reports it in its summary (shared-handle /
// independent-handles / single). Concurrency mode. Go goroutines
// share one *triple.Pipeline freely — the Pipeline's cipher path is
// concurrent-safe by construction — so N workers call into the same
// handle and the harness runs the shared-handle stress every binding
// with real threads runs; --goroutines is the worker count verbatim,
// never clamped.
const concurrencyMode = "shared-handle"

// usesStream reports whether the shape exercises the streaming
// Pipeline (stream and stream_one_shot share it); usesMessage whether
// it exercises the Single Message Pipeline.
func usesStream(shape string) bool {
	return shape == shapeStream || shape == shapeStreamOneShot || shape == shapeBoth
}

func usesMessage(shape string) bool {
	return shape == shapeMessage || shape == shapeBoth
}

// maxWorkersFlag caps --goroutines; the harness targets modest hosts
// and each worker pins payload-sized buffers for the whole run.
const maxWorkersFlag = 10

// profileSurface resolves a registered triple profile to the shape
// family its Mode exposes — shapeStream for the streaming modes,
// shapeMessage for the Single Message modes — by reading the profile
// record the registry holds, so every registered name (shipped or
// installed at runtime) is accepted and the surface never has to be
// restated here. The blob-only mode carries no cipher surface and is
// rejected.
func profileSurface(name string) (string, error) {
	p, err := triple.Lookup(name)
	if err != nil {
		return "", fmt.Errorf("--profile %q is not a registered triple profile", name)
	}
	switch {
	case strings.HasPrefix(p.Mode, "streaming"):
		return shapeStream, nil
	case strings.HasPrefix(p.Mode, "singlemsg"):
		return shapeMessage, nil
	}
	return "", fmt.Errorf("--profile %q carries no cipher surface (blob-only mode)", name)
}

// keystreamFillCipher is the primitive the loop supplies for the
// parallax palette and the outer cipher when a profile ships without
// them. AES-CMAC is PRF-grade, so it is sound outside the Interlocked
// Barrier, and it is the closest relative of the AES-based inner
// primitive whose profiles need this fill.
const keystreamFillCipher = "aescmac"

// fillKeystreamLayers folds a keystream primitive into opts for any
// layer the named profile leaves unfilled but the operator asked for.
//
// A profile built around a primitive that is safe only inside the
// Interlocked Barrier ships with an empty parallax palette and no
// outer cipher: both layers run outside the barrier, where that
// primitive would stand bare, so the recipe leaves them unnamed
// rather than naming a primitive that must not key them. Engaging
// either layer therefore needs a keystream-capable primitive supplied
// from outside the recipe; without it construction fails on a palette
// below its minimum or an unnamed outer cipher, and the primitive
// that most deserves stressing becomes the one that cannot be
// stressed with those layers engaged.
//
// Overrides fold into the resolved record the blob carries, so the
// receiver rebuilds the same shape from the blob alone.
func fillKeystreamLayers(name string, opts *triple.Opts, wantParallax, wantWrapper bool) (bool, error) {
	p, err := triple.Lookup(name)
	if err != nil {
		return false, fmt.Errorf("--profile %q is not a registered triple profile", name)
	}
	filled := false
	if wantParallax && len(p.ParallaxPalette) == 0 {
		opts.ParallaxPalette = []string{keystreamFillCipher, keystreamFillCipher, keystreamFillCipher}
		if p.ParallaxSegmentSize == 0 {
			// A recipe that never carried a palette never carried a
			// segment size either, and the schedule rejects zero.
			opts.ParallaxSegmentSize = parallax.DefaultSegmentSize
		}
		filled = true
	}
	if wantWrapper && p.OuterCipher == "" {
		opts.OuterCipher = keystreamFillCipher
		filled = true
	}
	return filled, nil
}

// narrowShape applies a --profile's surface to the requested shape: a
// message-surface profile forces message; a stream-surface profile
// keeps stream or stream_one_shot as requested and turns message or
// both into stream.
func narrowShape(requested, surface string) string {
	if surface == shapeMessage {
		return shapeMessage
	}
	if requested == shapeStreamOneShot {
		return shapeStreamOneShot
	}
	return shapeStream
}

// config carries the resolved CLI surface.
type config struct {
	duration     time.Duration
	iterations   int64 // per-worker; 0 = duration-based
	workers      int
	shape        string
	hash         string
	mac          string
	payload      int64
	memlimit     int64 // resolved bytes; the effective limit once the runtime is shaped
	memlimitAuto bool  // --memlimit auto: cap only when the runtime has no limit
	gogc         int   // 0 = leave the runtime default
	parallax     bool
	wrapper      bool

	profile        string // non-empty = exercise this single registered profile
	keyBits        int    // 0 = profile default
	nonceBits      int    // 0 = profile default
	chunkSize      int64  // 0 = profile default
	barrierFill    int    // 0 = profile default
	gomaxprocs     int    // 0 = inherit from the environment
	rekeyEvery     int64  // per-worker iterations between Rekey calls; 0 = never
	blobCycleEvery int64  // per-worker iterations between blob reopen cycles; 0 = never
	payloadMode    string // plaintext content policy (payload* constants)
	seed           uint64 // deterministic plaintext RNG seed; 0 = crypto/rand
	jsonOutput     bool   // final summary as one JSON object
	memprofile     string // heap-profile output path; empty = none
}

// memSnapshot is one point-in-time capture of the cumulative runtime
// counters the allocation-rate and GC-cost figures are differenced
// from, together with the pool hit / miss counter vector of the itb
// core (see pool.go for its layout).
type memSnapshot struct {
	at         time.Time
	totalAlloc uint64
	mallocs    uint64
	numGC      uint32
	pauseNs    uint64
	gcCPU      float64
	heapSys    uint64
	pool       []int64
}

// takeMemSnapshot reads the runtime counters (via ReadMemStats, which
// stops the world briefly) and the pool counters at one instant.
func takeMemSnapshot() memSnapshot {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return memSnapshot{
		at:         time.Now(),
		totalAlloc: ms.TotalAlloc,
		mallocs:    ms.Mallocs,
		numGC:      ms.NumGC,
		pauseNs:    ms.PauseTotalNs,
		gcCPU:      ms.GCCPUFraction,
		heapSys:    ms.HeapSys,
		pool:       takePoolVector(),
	}
}

// runState is the shared context handed to workers and the monitor.
type runState struct {
	cfg        config
	streamPipe *triple.Pipeline // nil when shape == message
	msgPipe    *triple.Pipeline // nil when shape == stream
	workers    []*worker

	// streamProfile / msgProfile are the profile names the two pipes
	// were initialised against; blob-cycle log lines and errors are
	// labelled with them.
	streamProfile string
	msgProfile    string

	// pipeMu serialises pipeline-mutating maintenance (Rekey, blob
	// cycle) against cipher-path calls, per the [triple.Pipeline.Rekey]
	// thread-safety contract: workers hold the read lock for each
	// iteration, maintenance operations take the write lock.
	pipeMu sync.RWMutex

	// streamBlob / msgBlob hold each pipe's current session blob
	// (produced by Init, refreshed by every Rekey); blob-cycle reopens
	// consume them. Guarded by pipeMu.
	streamBlob []byte
	msgBlob    []byte

	// rekeys / blobCycles count completed maintenance operations
	// across all workers.
	rekeys     atomic.Int64
	blobCycles atomic.Int64

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

	// warmupMem is captured with the post-warmup baseline; steadyMem
	// is captured the instant the last worker returns, before the
	// settle sleep and the forced GCs that precede the leak snapshot,
	// so the differenced figures describe the main loop only.
	warmupMem memSnapshot
	steadyMem memSnapshot

	// rssWarmup / rssFinal are the process resident set at the
	// post-warmup baseline and at shutdown; rssPeak is the kernel's
	// high-water mark read at shutdown. Informational, shared with
	// every binding's summary; the verdict does not read them.
	rssWarmup uint64
	rssPeak   uint64
	rssFinal  uint64

	// lastSample is the previous monitor snapshot; the periodic line
	// prints the allocation rate and pool-miss count since it. Written
	// by the monitor goroutine only.
	lastSample memSnapshot
}

func main() {
	os.Exit(run())
}

func run() int {
	cfg, err := parseFlags(os.Args[1:])
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "loop: %v\n", err)
		return 2
	}

	// Runtime shaping. A long run under allocation churn grows the Go
	// heap without bound unless a soft limit paces the collector, so
	// a limit is always in force: an explicit --memlimit is set as
	// given, and auto caps the heap only when the runtime reports no
	// limit at all (a limit already installed from the environment
	// is left standing). The GC percentage and GOMAXPROCS are set
	// only when their flag is non-zero — a zero flag skips the setter
	// rather than calling it with zero, because zero is a real value
	// to SetGCPercent, and a call would clobber whatever the
	// environment installed. Every knob goes through the itb
	// package's exported setters — the same entries the C ABI wraps
	// for the bindings — so each run of this harness also exercises
	// the path the binding-side utilities depend on. All of it lands
	// before any allocation-heavy setup so the baselines are taken
	// under the shaped runtime.
	if cfg.memlimitAuto {
		if itb.SetMemoryLimit(-1) == math.MaxInt64 {
			itb.SetMemoryLimit(cfg.memlimit)
		}
	} else {
		itb.SetMemoryLimit(cfg.memlimit)
	}
	cfg.memlimit = itb.SetMemoryLimit(-1)
	if cfg.gogc > 0 {
		itb.SetGCPercent(cfg.gogc)
	}
	if cfg.gomaxprocs > 0 {
		itb.SetGOMAXPROCS(cfg.gomaxprocs)
	}

	logf("start: duration=%s iterations=%d goroutines=%d workers=%d concurrency=%s shape=%s hash=%s mac=%s payload=%s memlimit=%s parallax=%s wrapper=%s",
		cfg.duration, cfg.iterations, cfg.workers, cfg.workers, concurrencyMode, cfg.shape, cfg.hash, cfg.mac,
		humanBytes(cfg.payload), humanBytes(cfg.memlimit), onOff(cfg.parallax), onOff(cfg.wrapper))
	logf("overrides: profile=%q key-bits=%d nonce-bits=%d chunk-size=%s barrier-fill=%d gomaxprocs=%d rekey-every=%d blob-cycle-every=%d payload-mode=%s seed=%d json-output=%v",
		cfg.profile, cfg.keyBits, cfg.nonceBits, humanBytes(cfg.chunkSize), cfg.barrierFill,
		cfg.gomaxprocs, cfg.rekeyEvery, cfg.blobCycleEvery, cfg.payloadMode, cfg.seed, cfg.jsonOutput)
	logf("policy: microbatch-tiers=%s hashpool-starters=%s",
		policyLabel(os.Getenv("ITB_MICROBATCH_TIERS")), policyLabel(os.Getenv("ITB_HASHPOOL_STARTERS")))

	r := &runState{cfg: cfg, release: make(chan struct{})}

	// Pipeline construction — one shared instance per exercised shape.
	// --profile narrows cfg.shape to that profile's surface at flag
	// parse, so at most one of the two branches below fires with the
	// override in place.
	opts := triple.Opts{
		InnerHash:    cfg.hash,
		MacName:      cfg.mac,
		WithParallax: &cfg.parallax,
		WithWrapper:  &cfg.wrapper,
		KeyBits:      cfg.keyBits,
		NonceBits:    cfg.nonceBits,
		BarrierFill:  cfg.barrierFill,
		ChunkSize:    int(cfg.chunkSize),
	}
	r.streamProfile = triple.ProfileStreamingAEADTripleMACV1
	r.msgProfile = triple.ProfileSingleMsgTripleMACV1
	if cfg.profile != "" {
		filled, ferr := fillKeystreamLayers(cfg.profile, &opts, cfg.parallax, cfg.wrapper)
		if ferr != nil {
			fmt.Fprintf(os.Stderr, "loop: %v\n", ferr)
			return 1
		}
		if filled {
			fmt.Fprintf(os.Stderr, "loop: %s leaves the requested keystream layers unnamed; %s supplied for them\n",
				cfg.profile, keystreamFillCipher)
		}
		r.streamProfile = cfg.profile
		r.msgProfile = cfg.profile
	}
	if usesStream(cfg.shape) {
		pipe, blob, ierr := triple.Init(r.streamProfile, opts)
		if ierr != nil {
			fmt.Fprintf(os.Stderr, "loop: triple.Init(%s): %v\n", r.streamProfile, ierr)
			return 1
		}
		// Close via the runState pointer: blob-cycle swaps fresh
		// pipelines in (closing the ones they replace), so the
		// instance live at exit is whatever the pointer holds then.
		defer func() {
			r.pipeMu.Lock()
			r.streamPipe.Close()
			r.pipeMu.Unlock()
		}()
		r.streamPipe = pipe
		r.streamBlob = blob
		logf("pipeline initialised: profile=%s blob=%d bytes", r.streamProfile, len(blob))
	}
	if usesMessage(cfg.shape) {
		pipe, blob, ierr := triple.Init(r.msgProfile, opts)
		if ierr != nil {
			fmt.Fprintf(os.Stderr, "loop: triple.Init(%s): %v\n", r.msgProfile, ierr)
			return 1
		}
		defer func() {
			r.pipeMu.Lock()
			r.msgPipe.Close()
			r.pipeMu.Unlock()
		}()
		r.msgPipe = pipe
		r.msgBlob = blob
		logf("pipeline initialised: profile=%s blob=%d bytes", r.msgProfile, len(blob))
	}

	// Allocation posture. Per-worker plaintexts are generated once and
	// held for the whole run (rotating mode refills them in place per
	// iteration); the wire and round-trip buffers live inside each
	// worker and are reused across iterations. Under the default fixed
	// CSPRNG mode every worker's buffer is distinct, so cross-worker
	// data crossover is detectable; pattern modes trade that property
	// for content edge-case coverage.
	r.workers = make([]*worker, cfg.workers)
	for i := range r.workers {
		pt := make([]byte, cfg.payload)
		rng := newWorkerRNG(cfg.seed, i)
		if perr := fillPayload(cfg.payloadMode, rng, pt); perr != nil {
			fmt.Fprintf(os.Stderr, "loop: payload fill: %v\n", perr)
			return 1
		}
		r.workers[i] = &worker{id: i, plaintext: pt, payloadMode: cfg.payloadMode, rng: rng}
	}

	// Graceful stop. Ctrl-C / SIGTERM cancel the root context: every
	// worker checks it before starting an iteration, so a stop request
	// interrupts nothing mid-call — the in-flight encrypt / decrypt /
	// compare completes, the worker returns, and the partial summary
	// prints with the verdict the completed iterations earned.
	sigCtx, sigStop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer sigStop()
	ctx, cancel := context.WithCancel(sigCtx)
	defer cancel()

	// Idle goroutine baseline — before any worker exists. The final
	// leak check compares the post-run count against this figure.
	runtime.GC()
	r.idleGoroutines = runtime.NumGoroutine()

	// Warmup barrier. Each worker performs one iteration, signals the
	// barrier, and blocks on r.release before entering the main loop,
	// so the clock starts only once every worker has paid its first-
	// call costs (pool warm-up, lazy kernel dispatch, page faults on
	// the payload buffers) and the baselines below describe a process
	// that has already run the whole cipher path once per worker.
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
	r.warmupMem = takeMemSnapshot()
	r.lastSample = r.warmupMem
	r.rssWarmup, _ = readRSS()
	logf("warmup: %d workers x 1 iter completed in %s (baseline rss=%s, heap=%s, goroutines=%d)",
		cfg.workers, time.Since(warmupStart).Round(100*time.Millisecond),
		humanBytes(int64(r.rssWarmup)), humanBytes(int64(r.warmupHeap)), r.warmupGoroutines)

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
	r.steadyMem = takeMemSnapshot()
	r.rssFinal, r.rssPeak = readRSS()
	cancel()
	<-monDone

	if cfg.memprofile != "" {
		if perr := itb.WriteHeapProfile(cfg.memprofile); perr != nil {
			fmt.Fprintf(os.Stderr, "loop: memprofile: %v\n", perr)
		} else {
			logf("memprofile: heap profile written to %s", cfg.memprofile)
		}
	}

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
		workers     = fs.Int("goroutines", 3, fmt.Sprintf("concurrent workers (1..%d); on runtimes without parallelism values above 1 are clamped to 1", maxWorkersFlag))
		shape       = fs.String("shape", shapeStream, "cipher surface to exercise: stream | message | stream_one_shot | both")
		hash        = fs.String("hash", "areion512", "inner ITB hash primitive name")
		mac         = fs.String("mac", "hmac-blake3", "MAC primitive name")
		payloadStr  = fs.String("payload-size", "16MB", "per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)")
		memlimitStr = fs.String("memlimit", "auto", "Go heap soft limit: auto (1GiB when goroutines <= 3, else 256MiB, applied only when the runtime has no limit) or a size (e.g. 512MB)")
		gogc        = fs.Int("gogc", 0, "GC trigger percentage; 0 = leave the runtime default")
		parallaxStr = fs.String("parallax", "on", "parallax layer: on | off")
		wrapperStr  = fs.String("wrapper", "on", "wrapper (Outer cipher) layer: on | off")

		profile        = fs.String("profile", "", "exercise this single registered triple profile (overrides --shape with the profile's surface); empty = shape-based profile pair")
		keyBits        = fs.Int("key-bits", 0, "per-seed key width in bits: 512 | 1024 | 2048; 0 = profile default (1024)")
		nonceBits      = fs.Int("nonce-bits", 0, "on-wire nonce width in bits: 128 | 256 | 512; 0 = profile default (512)")
		chunkSizeStr   = fs.String("chunk-size", "0", "streaming chunk-size budget (e.g. 4MB); 0 = profile default; inert for pure message shape")
		barrierFill    = fs.Int("barrier-fill", 0, "DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32; 0 = profile default (1)")
		gomaxprocs     = fs.Int("gomaxprocs", 0, "Go runtime GOMAXPROCS override; 0 = inherit from the environment")
		rekeyEvery     = fs.Int64("rekey-every", 0, "rotate the parallax + wrapper masters via Rekey every N iterations per worker; 0 = never")
		blobCycleEvery = fs.Int64("blob-cycle-every", 0, "reopen each pipeline from its session blob every N iterations per worker; 0 = never")
		payloadMode    = fs.String("payload-mode", payloadFixed, "plaintext content: fixed | rotating | pattern-zero | pattern-ff | pattern-ascii")
		seed           = fs.Uint64("seed", 0, "deterministic plaintext RNG seed for bug reproduction, NOT for security testing (pipeline keys stay CSPRNG-drawn); 0 = crypto/rand plaintexts")
		jsonOutput     = fs.Bool("json-output", false, "print the final summary as one compact JSON object instead of log lines")
		memprofile     = fs.String("memprofile", "", "write a Go runtime heap profile (pprof) to this path at the end of the run; empty = none")
	)
	if err := fs.Parse(argv); err != nil {
		return config{}, err
	}
	if fs.NArg() > 0 {
		return config{}, fmt.Errorf("unexpected positional arguments: %v", fs.Args())
	}

	cfg := config{
		duration:       *duration,
		iterations:     *iterations,
		workers:        *workers,
		shape:          *shape,
		hash:           *hash,
		mac:            *mac,
		gogc:           *gogc,
		profile:        *profile,
		keyBits:        *keyBits,
		nonceBits:      *nonceBits,
		barrierFill:    *barrierFill,
		gomaxprocs:     *gomaxprocs,
		rekeyEvery:     *rekeyEvery,
		blobCycleEvery: *blobCycleEvery,
		payloadMode:    *payloadMode,
		seed:           *seed,
		jsonOutput:     *jsonOutput,
		memprofile:     *memprofile,
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
	case shapeStream, shapeMessage, shapeStreamOneShot, shapeBoth:
	default:
		return config{}, fmt.Errorf("--shape must be stream | message | stream_one_shot | both, got %q", cfg.shape)
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
		cfg.memlimitAuto = true
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

	if cfg.profile != "" {
		surface, serr := profileSurface(cfg.profile)
		if serr != nil {
			return config{}, serr
		}
		// The profile's Mode dictates which cipher surface exists;
		// narrow the shape so worker dispatch targets only that one.
		cfg.shape = narrowShape(cfg.shape, surface)
	}
	switch cfg.keyBits {
	case 0, 512, 1024, 2048:
	default:
		return config{}, fmt.Errorf("--key-bits must be 512 | 1024 | 2048 (or 0 = profile default), got %d", cfg.keyBits)
	}
	switch cfg.nonceBits {
	case 0, 128, 256, 512:
	default:
		return config{}, fmt.Errorf("--nonce-bits must be 128 | 256 | 512 (or 0 = profile default), got %d", cfg.nonceBits)
	}
	switch cfg.barrierFill {
	case 0, 1, 2, 4, 8, 16, 32:
	default:
		return config{}, fmt.Errorf("--barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 (or 0 = profile default), got %d", cfg.barrierFill)
	}
	cfg.chunkSize, err = parseSize(*chunkSizeStr)
	if err != nil {
		return config{}, fmt.Errorf("--chunk-size: %v", err)
	}
	if cfg.gomaxprocs < 0 {
		return config{}, fmt.Errorf("--gomaxprocs must be > 0 when specified, got %d", cfg.gomaxprocs)
	}
	if cfg.rekeyEvery < 0 {
		return config{}, fmt.Errorf("--rekey-every must be >= 0, got %d", cfg.rekeyEvery)
	}
	if cfg.blobCycleEvery < 0 {
		return config{}, fmt.Errorf("--blob-cycle-every must be >= 0, got %d", cfg.blobCycleEvery)
	}
	switch cfg.payloadMode {
	case payloadFixed, payloadRotating, payloadPatternZero, payloadPatternFF, payloadPatternASCII:
	default:
		return config{}, fmt.Errorf("--payload-mode must be fixed | rotating | pattern-zero | pattern-ff | pattern-ascii, got %q", cfg.payloadMode)
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
