// Benchmarks for the parallax horizontal-multiplexing layer.
package parallax_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/everanium/itb/ctr"
	"github.com/everanium/itb/parallax"
)

// baselineStreamChunkSize sets the per-Write payload feeding the
// baseline streaming sub-benches. 128 KiB matches the per-Write
// chunk width streaming benches use elsewhere so the per-Write
// geometry stays uniform across rows.
const baselineStreamChunkSize = 128 * 1024

// chunkedStreamPlaintextMultiplier sets the bench plaintext at
// chunkSize * chunkedStreamPlaintextMultiplier so each sub-bench
// runs ~4 chunks per iteration regardless of chunkSize. The
// multiplier is bounded so the largest chunk does not produce an
// unreasonable plaintext; in practice a 64 MiB chunk times the
// multiplier yields 256 MiB per iteration, large enough to be
// representative without dominating run time.
const chunkedStreamPlaintextMultiplier = 4

// heterogeneousPalette carries the PARALLAX_PALETTE override. When
// non-nil, every bench-side palette builder (streamBenchPalette,
// baselineStreamPalette, baselineHomogeneous) returns the same
// heterogeneous slice verbatim instead of the per-primitive
// homogeneous repetition. The per-primitive subloop becomes a
// repetition over the identical palette so each bench-suite run still
// yields a stable readable measurement; combine with
// PARALLAX_PALETTE_LABEL + -bench=<label> for a focused single-row
// matrix run.
var heterogeneousPalette []string

// envChunkSize carries the PARALLAX_CHUNK_SIZE override. Zero means leave
// the Schedule's chunk size at its default. Bench code consults
// applyEnvChunkSize(schedule) right after building a schedule so the
// override takes effect uniformly across stream-side benches.
var envChunkSize int

// chunkedStreamChunkSizes sweeps representative chunk sizes for
// BenchmarkParallaxChunkedStream. The four widths span from a
// per-chunk budget that pays the EncryptInPlace setup cost across
// several iterations per per-chunk EncryptInPlace (1 MiB) to a
// width that fits the plaintext into a single chunk (16 MiB at
// streamBenchPlaintextLen=4 MiB the largest entries serve only a
// single chunk; values are kept for chunk-size-scaling visibility).
var chunkedStreamChunkSizes = []int{1 << 20, 4 << 20, 16 << 20, 64 << 20}

// benchPlaintextLen is the single plaintext size every parallax bench
// runs at. 4 MiB lands deep in the parallel worker regime where
// steady-state throughput dominates and per-segment dispatch overhead
// is a constant background term — the comparable surface across
// primitives, palettes, segment widths, and worker counts. The size
// also keeps every per-worker slice well above the parallel threshold
// even at the largest segment width in the sweep.
var benchPlaintextLen = 4 * 1024 * 1024

// benchPaletteHomogeneousN is the palette width used by the
// per-primitive homogeneous sweep. N=9 surfaces each primitive's
// intrinsic per-segment cost without mixing-overhead noise from
// neighbouring slot primitives.
var benchPaletteHomogeneousN = 9

// segmentSizeSweep enumerates the segment widths the per-primitive
// homogeneous bench sweeps. Every value is prime and coprime to 504
// (the inner ITB pipeline period); the largest entry sits one prime
// short of the MaxSegmentSize cap. The sequence spans nearly four
// orders of magnitude so the cost amortisation curve is visible per
// primitive.
var segmentSizeSweep = []int{17, 251, 4093, 16381, 65521}

// benchRegistry mirrors the canonical primitive order used elsewhere in the
// project. Held in the bench-only file so the production package code does
// not depend on an enumerated list.
var benchRegistry = []string{
	ctr.CipherAreion256,
	ctr.CipherAreion512,
	ctr.CipherBLAKE2b256,
	ctr.CipherBLAKE2b512,
	ctr.CipherBLAKE2s,
	ctr.CipherBLAKE3,
	ctr.CipherAES128CTR,
	ctr.CipherSipHash24,
	ctr.CipherChaCha20,
}

// benchDefaultPalette is the small mixed palette used by the worker
// scaling baseline. Three distinct primitive families keep the
// baseline representative of a typical deployment without inflating
// per-message setup cost.
var benchDefaultPalette = []string{
	ctr.CipherAES128CTR,
	ctr.CipherChaCha20,
	ctr.CipherBLAKE3,
}

// baselineSegmentSizes enumerates the segment widths the baseline
// single-message Decrypt and streaming sweeps share. Each value is
// prime and coprime to 504 (the inner ITB pipeline period). The
// three widths span the practical deployment band: a tight per-row
// width that exposes per-segment dispatch overhead, a mid width near
// 4 KiB that lands in the typical streaming flush regime, and a
// near-cap width that maximises per-segment amortisation under the
// MaxSegmentSize ceiling.
var baselineSegmentSizes = []int{251, 4093, 16381}

// baselinePaletteN pins the baseline matrix's homogeneous palette
// width at 3 so the per-primitive cost reads cleanly against the
// streaming-side rows in the matrix. PARALLAX_N still overrides
// streamBenchPaletteN / benchPaletteHomogeneousN via TestMain; this
// per-file constant is the baseline default when no override is set.
var baselinePaletteN = 3

// paletteBenchSegSize selects the segment width for the
// heterogeneous-palette bench. Default tracks
// parallax.DefaultSegmentSize; PARALLAX_S overrides via the
// same TestMain knob the rest of the streaming benches consume.
var paletteBenchSegSize = parallax.DefaultSegmentSize

// paletteBenchChunkSize sets the per-Write payload in the bench loop.
// 128 KiB is the default; PARALLAX_CHUNK_SIZE overrides via the same
// TestMain knob that pins Schedule.SetChunkSize, so a single env var
// pins both the wire-frame body width and the per-Write payload width
// to one comparable value.
var paletteBenchChunkSize = 128 * 1024

// streamBenchPlaintextLen pins the streaming bench plaintext at
// 4 MiB to match the existing per-primitive / palette-size sweep.
var streamBenchPlaintextLen = 4 * 1024 * 1024

// streamBenchPrimitives enumerates every PRF-grade registry primitive
// the streaming-surface benches sweep. Each populates a homogeneous
// N=3 palette so the per-primitive cost shows without mixing-overhead
// noise from neighbouring slots; the homogeneous shape is what makes
// the per-primitive numbers directly comparable across the table.
var streamBenchPrimitives = []string{
	ctr.CipherAreion256,
	ctr.CipherAreion512,
	ctr.CipherBLAKE2b256,
	ctr.CipherBLAKE2b512,
	ctr.CipherBLAKE2s,
	ctr.CipherBLAKE3,
	ctr.CipherAES128CTR,
	ctr.CipherSipHash24,
	ctr.CipherChaCha20,
}

// streamBenchPaletteN is the homogeneous palette size used by every
// streaming bench. Default 3; PARALLAX_N overrides via TestMain.
var streamBenchPaletteN = 3

// applyEnvChunkSize applies the PARALLAX_CHUNK_SIZE override to schedule
// if set; otherwise leaves the schedule's chunk size at the
// constructor default.
func applyEnvChunkSize(s *parallax.Schedule) {
	if envChunkSize <= 0 {
		return
	}
	_ = s.SetChunkSize(envChunkSize)
}

func baselineHomogeneous(name string) []string {
	out := make([]string, baselinePaletteN)
	for i := range out {
		out[i] = name
	}
	return out
}

// baselineStreamPalette returns a homogeneous palette of
// baselinePaletteN entries naming primitive name. Mirrors
// baselineHomogeneous from the single-message bench so both sides of
// the baseline matrix share the palette-shape convention.
func baselineStreamPalette(name string) []string {
	out := make([]string, baselinePaletteN)
	for i := range out {
		out[i] = name
	}
	return out
}

// baselineStreamSchedule builds a Schedule at the requested segment
// size and applies the PARALLAX_CHUNK_SIZE override (if set), mirroring
// streamBenchSchedule.
func baselineStreamSchedule(b *testing.B, palette []string, segSize int) *parallax.Schedule {
	b.Helper()
	s, err := parallax.NewSchedule(palette, segSize)
	if err != nil {
		b.Fatalf("NewSchedule(N=%d, S=%d): %v", len(palette), segSize, err)
	}
	applyEnvChunkSize(s)
	return s
}

// writeInChunks feeds plaintext into w in successive chunkSize-sized
// Write calls. The per-Write payload shape stays uniform across the
// baseline streaming sub-benches so the per-Write dispatch cost is
// constant across rows.
func writeInChunks(b *testing.B, w io.Writer, plaintext []byte, chunkSize int) {
	b.Helper()
	cursor := 0
	for cursor < len(plaintext) {
		end := cursor + chunkSize
		if end > len(plaintext) {
			end = len(plaintext)
		}
		if _, err := w.Write(plaintext[cursor:end]); err != nil {
			b.Fatalf("Write: %v", err)
		}
		cursor = end
	}
}

func benchRandom(b *testing.B, n int) []byte {
	b.Helper()
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		b.Fatalf("rand.Read: %v", err)
	}
	return out
}

func benchMaster(b *testing.B) []byte {
	b.Helper()
	master, err := parallax.GenerateMasterKey()
	if err != nil {
		b.Fatalf("GenerateMasterKey: %v", err)
	}
	return master
}

func benchSchedule(b *testing.B, palette []string, segSize int) *parallax.Schedule {
	b.Helper()
	s, err := parallax.NewSchedule(palette, segSize)
	if err != nil {
		b.Fatalf("NewSchedule(N=%d, S=%d): %v", len(palette), segSize, err)
	}
	return s
}

func benchCipherset(b *testing.B, master []byte, s *parallax.Schedule) *parallax.Cipherset {
	b.Helper()
	cs, err := parallax.NewCipherset(master, s)
	if err != nil {
		b.Fatalf("NewCipherset: %v", err)
	}
	return cs
}

// shuffledRegistry returns the canonical list permuted under a
// deterministic seed; every primitive appears exactly once.
func shuffledRegistry(seed uint64) []string {
	r := mrand.New(mrand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	out := append([]string(nil), benchRegistry...)
	r.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// drawWithReplacement returns n names sampled from the canonical
// registry under a deterministic seed.
func drawWithReplacement(seed uint64, n int) []string {
	r := mrand.New(mrand.NewPCG(seed, seed^0xbf58476d1ce4e5b9))
	out := make([]string, n)
	for i := range out {
		out[i] = benchRegistry[r.IntN(len(benchRegistry))]
	}
	return out
}

// homogeneousPalette returns a palette of n identical entries; the slot
// index disambiguates the per-slot subkey via the kdf label.
func homogeneousPalette(name string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = name
	}
	return out
}

// sizeLabel renders a byte count as a benchmark sub-name suffix.
func sizeLabel(n int) string {
	switch {
	case n >= 1024*1024:
		return fmt.Sprintf("%dMiB", n/(1024*1024))
	case n >= 1024:
		return fmt.Sprintf("%dKiB", n/1024)
	default:
		return fmt.Sprintf("%dB", n)
	}
}

func streamBenchPalette(name string) []string {
	if heterogeneousPalette != nil {
		// PARALLAX_PALETTE override: every per-primitive subloop
		// builds the same user-supplied heterogeneous palette, so
		// the bench name's primitive token (also overridden to a
		// synthetic label via PARALLAX_PALETTE_LABEL) decorates a
		// single repeated measurement rather than a per-primitive
		// sweep.
		out := make([]string, len(heterogeneousPalette))
		copy(out, heterogeneousPalette)
		return out
	}
	out := make([]string, streamBenchPaletteN)
	for i := range out {
		out[i] = name
	}
	return out
}

func streamBenchRandom(b *testing.B, n int) []byte {
	b.Helper()
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		b.Fatalf("rand.Read: %v", err)
	}
	return out
}

func streamBenchMaster(b *testing.B) []byte {
	b.Helper()
	master, err := parallax.GenerateMasterKey()
	if err != nil {
		b.Fatalf("GenerateMasterKey: %v", err)
	}
	return master
}

func streamBenchSchedule(b *testing.B, palette []string) *parallax.Schedule {
	b.Helper()
	s, err := parallax.NewSchedule(palette, parallax.DefaultSegmentSize)
	if err != nil {
		b.Fatalf("NewSchedule: %v", err)
	}
	applyEnvChunkSize(s)
	return s
}

func streamBenchCipherset(b *testing.B, master []byte, s *parallax.Schedule) *parallax.Cipherset {
	b.Helper()
	cs, err := parallax.NewCipherset(master, s)
	if err != nil {
		b.Fatalf("NewCipherset: %v", err)
	}
	return cs
}

// TestMain honours a family of PARALLAX_* environment variables that
// retune any benchmark in the package without editing source. Each
// variable left unset preserves the file-level default of the
// corresponding bench parameter.
//
// Bench-side knobs (apply only to benches in this package):
//
//	PARALLAX_S          - overrides the single-message segment size and
//	                      collapses segmentSizeSweep to a single-element
//	                      slice. Must be a positive integer accepted by
//	                      NewSchedule (coprime to the per-mode ITB
//	                      pipeline period).
//	PARALLAX_SIZE       - overrides the plaintext size used by every
//	                      bench in the package: benchPlaintextLen,
//	                      streamBenchPlaintextLen. Positive integer;
//	                      typical values are power-of-two byte counts.
//	PARALLAX_CHUNK_SIZE - overrides the streaming chunk size set on each
//	                      bench's Schedule via SetChunkSize, and pins the
//	                      per-Write payload width consumed by writeInChunks
//	                      in benches that drive the EncryptWriter under a
//	                      sliced Write loop (paletteBenchChunkSize).
//	PARALLAX_N          - overrides the homogeneous palette size used by
//	                      every streaming and per-primitive bench:
//	                      streamBenchPaletteN, benchPaletteHomogeneousN.
//	                      Must satisfy MinPaletteSize <= N <= MaxPaletteSize.
//	PARALLAX_PRIMITIVE  - restricts streamBenchPrimitives to a single
//	                      named primitive. Useful for focused per-primitive
//	                      bottleneck testing.
//	PARALLAX_PALETTE    - overrides the homogeneous palette construction
//	                      in streamBenchPalette / baselineStreamPalette
//	                      / baselineHomogeneous with a user-supplied
//	                      comma-separated cipher list, e.g.
//	                      "aescmac,chacha20,blake3,siphash24,blake2s".
//	                      Palette size = number of names; must satisfy
//	                      MinPaletteSize <= N <= MaxPaletteSize. When
//	                      set, the per-primitive subloop becomes a
//	                      repetition over the same heterogeneous
//	                      palette so the measurement is stable. Names
//	                      must each appear in ctr's registry (the same
//	                      string set streamBenchPrimitives draws on);
//	                      any invalid entry causes the env var to be
//	                      reported to stderr and ignored.
//	PARALLAX_PALETTE_LABEL - when set together with PARALLAX_PALETTE,
//	                      restricts the streamBenchPrimitives subloop to
//	                      a single synthetic name so a focused -bench
//	                      filter yields exactly one row per palette. The
//	                      label is purely a sub-bench name decoration
//	                      and does not have to match any registry entry.
//
// Examples:
//
//	PARALLAX_S=4093 PARALLAX_SIZE=1048576 \
//	    go test -bench=BenchmarkParallaxStream -benchtime=1s ./parallax/
//	PARALLAX_PRIMITIVE=aescmac PARALLAX_S=16381 PARALLAX_CHUNK_SIZE=65536 \
//	    go test -bench=BenchmarkParallaxStream -benchtime=2s ./parallax/
//
// An invalid value is reported to stderr and ignored; the default
// constant in the bench file remains in effect.
func TestMain(m *testing.M) {
	envInt := func(name string, apply func(int)) {
		v := os.Getenv(name)
		if v == "" {
			return
		}
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			fmt.Fprintf(os.Stderr,
				"%s=%q invalid (expected positive integer); ignoring\n", name, v)
			return
		}
		apply(n)
	}

	envInt("PARALLAX_S", func(n int) {
		segmentSizeSweep = []int{n}
	})
	envInt("PARALLAX_SIZE", func(n int) {
		benchPlaintextLen = n
		streamBenchPlaintextLen = n
	})
	envInt("PARALLAX_CHUNK_SIZE", func(n int) {
		envChunkSize = n
		paletteBenchChunkSize = n
	})
	envInt("PARALLAX_N", func(n int) {
		streamBenchPaletteN = n
		benchPaletteHomogeneousN = n
	})

	if v := os.Getenv("PARALLAX_PRIMITIVE"); v != "" {
		// Validate against the canonical bench registry; the value must
		// be one of the names a bench iterates today. Match the literal
		// string (lower-case, as ctr exposes them).
		matched := false
		single := []string{v}
		for _, name := range streamBenchPrimitives {
			if name == v {
				streamBenchPrimitives = single
				matched = true
				break
			}
		}
		if !matched {
			fmt.Fprintf(os.Stderr,
				"PARALLAX_PRIMITIVE=%q not found in any bench registry; ignoring\n", v)
		}
	}

	if v := os.Getenv("PARALLAX_PALETTE"); v != "" {
		raw := strings.Split(v, ",")
		names := make([]string, 0, len(raw))
		for _, r := range raw {
			t := strings.TrimSpace(r)
			if t == "" {
				continue
			}
			names = append(names, t)
		}
		bad := false
		switch {
		case len(names) < parallax.MinPaletteSize:
			fmt.Fprintf(os.Stderr,
				"PARALLAX_PALETTE=%q yields %d names (<MinPaletteSize=%d); ignoring\n",
				v, len(names), parallax.MinPaletteSize)
			bad = true
		case len(names) > parallax.MaxPaletteSize:
			fmt.Fprintf(os.Stderr,
				"PARALLAX_PALETTE=%q yields %d names (>MaxPaletteSize=%d); ignoring\n",
				v, len(names), parallax.MaxPaletteSize)
			bad = true
		default:
			// Validate every entry against the canonical bench
			// registry (the same set streamBenchPrimitives draws
			// on). NewSchedule will reject unknown names with a
			// clearer error than the env-var parser could offer,
			// but pre-validating here keeps the failure on the
			// process-startup path rather than the per-bench
			// fixture path.
			registry := make(map[string]struct{}, len(streamBenchPrimitives))
			for _, n := range streamBenchPrimitives {
				registry[n] = struct{}{}
			}
			for _, n := range names {
				if _, ok := registry[n]; !ok {
					fmt.Fprintf(os.Stderr,
						"PARALLAX_PALETTE=%q includes %q not in bench registry; ignoring\n",
						v, n)
					bad = true
					break
				}
			}
		}
		if !bad {
			heterogeneousPalette = names
			label := os.Getenv("PARALLAX_PALETTE_LABEL")
			if label == "" {
				label = "hetero"
			}
			single := []string{label}
			streamBenchPrimitives = single
		}
	}

	os.Exit(m.Run())
}

// ---------------------------------------------------------------------------
// 1. Per-primitive sweep — homogeneous palette of N=9 identical entries
//    swept across the segment-size axis. Each row isolates one
//    primitive's intrinsic per-segment cost without inter-primitive
//    mixing overhead, and surfaces how segment granularity amortises
//    per-segment dispatch for that primitive.
// ---------------------------------------------------------------------------

func BenchmarkParallaxPerPrimitiveHomogeneous(b *testing.B) {
	plaintext := benchRandom(b, benchPlaintextLen)
	for _, name := range benchRegistry {
		palette := homogeneousPalette(name, benchPaletteHomogeneousN)
		for _, segSize := range segmentSizeSweep {
			schedule := benchSchedule(b, palette, segSize)
			cs := benchCipherset(b, benchMaster(b), schedule)
			label := fmt.Sprintf("%s/S%d", name, segSize)
			b.Run(label+"/encrypt/"+sizeLabel(benchPlaintextLen), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(benchPlaintextLen))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					wire, err := schedule.Encrypt(plaintext, cs)
					if err != nil {
						b.Fatalf("Encrypt: %v", err)
					}
					if len(wire) != parallax.NonceSize+benchPlaintextLen {
						b.Fatalf("wire len=%d want %d", len(wire), parallax.NonceSize+benchPlaintextLen)
					}
				}
			})
			b.Run(label+"/encrypt_inplace/"+sizeLabel(benchPlaintextLen), func(b *testing.B) {
				buf := make([]byte, benchPlaintextLen)
				b.ReportAllocs()
				b.SetBytes(int64(benchPlaintextLen))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					copy(buf, plaintext)
					wire, err := schedule.EncryptInPlace(buf, cs)
					if err != nil {
						b.Fatalf("EncryptInPlace: %v", err)
					}
					if len(wire) != parallax.NonceSize+benchPlaintextLen {
						b.Fatalf("wire len=%d want %d", len(wire), parallax.NonceSize+benchPlaintextLen)
					}
				}
			})
		}
	}
}

// ---------------------------------------------------------------------------
// 2. Palette-size sweep — fixed 1 MiB plaintext, fixed S = Default,
//    varying palette shapes drawn deterministically from the registry.
// ---------------------------------------------------------------------------

// paletteCase carries a named palette for the size-sweep table.
type paletteCase struct {
	label   string
	palette []string
}

func paletteCases() []paletteCase {
	return []paletteCase{
		{"N3", drawWithReplacement(0xa1, 3)},
		{"N9-shuffle-A", shuffledRegistry(42)},
		{"N9-shuffle-B", shuffledRegistry(1337)},
		{"N24", drawWithReplacement(0xc0ffee, 24)},
		{"N36", drawWithReplacement(0xdecaf, 36)},
		{"N254", drawWithReplacement(0xfeedface, 254)},
	}
}

func BenchmarkParallaxPaletteSize(b *testing.B) {
	plaintext := benchRandom(b, benchPlaintextLen)
	for _, pc := range paletteCases() {
		schedule := benchSchedule(b, pc.palette, parallax.DefaultSegmentSize)
		cs := benchCipherset(b, benchMaster(b), schedule)
		b.Run(pc.label+"/encrypt/"+sizeLabel(benchPlaintextLen), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(benchPlaintextLen))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				wire, err := schedule.Encrypt(plaintext, cs)
				if err != nil {
					b.Fatalf("Encrypt: %v", err)
				}
				if len(wire) != parallax.NonceSize+benchPlaintextLen {
					b.Fatalf("wire len=%d want %d", len(wire), parallax.NonceSize+benchPlaintextLen)
				}
			}
		})
		b.Run(pc.label+"/encrypt_inplace/"+sizeLabel(benchPlaintextLen), func(b *testing.B) {
			buf := make([]byte, benchPlaintextLen)
			b.ReportAllocs()
			b.SetBytes(int64(benchPlaintextLen))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				copy(buf, plaintext)
				wire, err := schedule.EncryptInPlace(buf, cs)
				if err != nil {
					b.Fatalf("EncryptInPlace: %v", err)
				}
				if len(wire) != parallax.NonceSize+benchPlaintextLen {
					b.Fatalf("wire len=%d want %d", len(wire), parallax.NonceSize+benchPlaintextLen)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 3. Worker scaling — fixed 1 MiB plaintext under the default mixed
//    palette and default segment size, varying GOMAXPROCS. The internal
//    worker count caps at min(GOMAXPROCS, 32). runtime.GOMAXPROCS is
//    restored after each sub-bench so the surrounding bench harness
//    observes the original setting.
// ---------------------------------------------------------------------------

var workerScalingProcs = []int{1, 2, 4, 8, 16}

func BenchmarkParallaxWorkerScaling(b *testing.B) {
	schedule := benchSchedule(b, benchDefaultPalette, parallax.DefaultSegmentSize)
	cs := benchCipherset(b, benchMaster(b), schedule)
	plaintext := benchRandom(b, benchPlaintextLen)
	for _, procs := range workerScalingProcs {
		label := fmt.Sprintf("P%d/encrypt/%s", procs, sizeLabel(benchPlaintextLen))
		b.Run(label, func(b *testing.B) {
			prev := runtime.GOMAXPROCS(procs)
			defer runtime.GOMAXPROCS(prev)
			b.ReportAllocs()
			b.SetBytes(int64(benchPlaintextLen))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				wire, err := schedule.Encrypt(plaintext, cs)
				if err != nil {
					b.Fatalf("Encrypt: %v", err)
				}
				if len(wire) != parallax.NonceSize+benchPlaintextLen {
					b.Fatalf("wire len=%d want %d", len(wire), parallax.NonceSize+benchPlaintextLen)
				}
			}
		})
	}
}

// BenchmarkParallaxSingleMessageDecrypt sweeps every PRF-grade
// registry primitive under the three baseline segment widths and
// measures the Decrypt entry's per-byte cost on a fresh wire built
// once before the timed loop. The wire is rebuilt per (primitive, S)
// combination so each sub-bench decrypts a payload encrypted under
// its own schedule / cipherset.
func BenchmarkParallaxSingleMessageDecrypt(b *testing.B) {
	plaintext := benchRandom(b, benchPlaintextLen)
	for _, name := range benchRegistry {
		palette := baselineHomogeneous(name)
		for _, segSize := range baselineSegmentSizes {
			schedule := benchSchedule(b, palette, segSize)
			cs := benchCipherset(b, benchMaster(b), schedule)
			wire, err := schedule.Encrypt(plaintext, cs)
			if err != nil {
				b.Fatalf("warm-up Encrypt(%s/S%d): %v", name, segSize, err)
			}
			label := fmt.Sprintf("%s/S%d/decrypt/%s", name, segSize, sizeLabel(benchPlaintextLen))
			b.Run(label, func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(benchPlaintextLen))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					out, err := schedule.Decrypt(wire, cs)
					if err != nil {
						b.Fatalf("Decrypt: %v", err)
					}
					if len(out) != benchPlaintextLen {
						b.Fatalf("plain len=%d want %d", len(out), benchPlaintextLen)
					}
				}
			})
		}
	}
}

// BenchmarkParallaxSingleMessageDecryptInPlace sweeps every PRF-grade
// registry primitive under the three baseline segment widths and
// measures the DecryptInPlace entry's per-byte cost. The wire is
// copied into a per-iteration buffer because DecryptInPlace mutates
// its input; the copy cost is constant across primitives so the
// per-primitive contrast remains representative of the in-place
// decrypt cost. The wire is built once per (primitive, S) combination
// before the timed loop.
func BenchmarkParallaxSingleMessageDecryptInPlace(b *testing.B) {
	plaintext := benchRandom(b, benchPlaintextLen)
	for _, name := range benchRegistry {
		palette := baselineHomogeneous(name)
		for _, segSize := range baselineSegmentSizes {
			schedule := benchSchedule(b, palette, segSize)
			cs := benchCipherset(b, benchMaster(b), schedule)
			wire, err := schedule.Encrypt(plaintext, cs)
			if err != nil {
				b.Fatalf("warm-up Encrypt(%s/S%d): %v", name, segSize, err)
			}
			label := fmt.Sprintf("%s/S%d/decrypt_inplace/%s", name, segSize, sizeLabel(benchPlaintextLen))
			b.Run(label, func(b *testing.B) {
				buf := make([]byte, len(wire))
				b.ReportAllocs()
				b.SetBytes(int64(benchPlaintextLen))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					copy(buf, wire)
					out, err := schedule.DecryptInPlace(buf, cs)
					if err != nil {
						b.Fatalf("DecryptInPlace: %v", err)
					}
					if len(out) != benchPlaintextLen {
						b.Fatalf("plain len=%d want %d", len(out), benchPlaintextLen)
					}
				}
			})
		}
	}
}

// BenchmarkParallaxSingleMessageEncryptSweep mirrors the encrypt side
// of the baseline matrix at the same three baseline segment widths and
// homogeneous palette width. The existing
// BenchmarkParallaxPerPrimitiveHomogeneous covers a five-S sweep at
// N=9 by default; this companion sweep at N=3 over the baseline three
// S values lets the encrypt-side rows of the baseline matrix be read
// alongside the decrypt-side rows in a single run.
func BenchmarkParallaxSingleMessageEncryptSweep(b *testing.B) {
	plaintext := benchRandom(b, benchPlaintextLen)
	for _, name := range benchRegistry {
		palette := baselineHomogeneous(name)
		for _, segSize := range baselineSegmentSizes {
			schedule := benchSchedule(b, palette, segSize)
			cs := benchCipherset(b, benchMaster(b), schedule)
			b.Run(fmt.Sprintf("%s/S%d/encrypt/%s", name, segSize, sizeLabel(benchPlaintextLen)), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(benchPlaintextLen))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					wire, err := schedule.Encrypt(plaintext, cs)
					if err != nil {
						b.Fatalf("Encrypt: %v", err)
					}
					if len(wire) != parallax.NonceSize+benchPlaintextLen {
						b.Fatalf("wire len=%d want %d", len(wire), parallax.NonceSize+benchPlaintextLen)
					}
				}
			})
			b.Run(fmt.Sprintf("%s/S%d/encrypt_inplace/%s", name, segSize, sizeLabel(benchPlaintextLen)), func(b *testing.B) {
				buf := make([]byte, benchPlaintextLen)
				b.ReportAllocs()
				b.SetBytes(int64(benchPlaintextLen))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					copy(buf, plaintext)
					wire, err := schedule.EncryptInPlace(buf, cs)
					if err != nil {
						b.Fatalf("EncryptInPlace: %v", err)
					}
					if len(wire) != parallax.NonceSize+benchPlaintextLen {
						b.Fatalf("wire len=%d want %d", len(wire), parallax.NonceSize+benchPlaintextLen)
					}
				}
			})
		}
	}
}

// BenchmarkParallaxBaselineStreaming sweeps every PRF-grade registry
// primitive × baseline segment width × streaming entry shape under a
// homogeneous N=3 palette at the baseline plaintext size. The
// EncryptWriter / DecryptWriter sub-benches feed the input in
// baselineStreamChunkSize-sized writes; the EncryptReader /
// DecryptReader sub-benches drain via a per-iteration Read loop.
//
// Each (primitive, S) combination warms up one streaming wire outside
// the timed loop body so the per-iteration decrypt cost excludes the
// encrypt cost.
func BenchmarkParallaxBaselineStreaming(b *testing.B) {
	plaintext := streamBenchRandom(b, streamBenchPlaintextLen)
	master := streamBenchMaster(b)
	for _, name := range streamBenchPrimitives {
		palette := baselineStreamPalette(name)
		for _, segSize := range baselineSegmentSizes {
			schedule := baselineStreamSchedule(b, palette, segSize)
			cs := streamBenchCipherset(b, master, schedule)

			b.Run(fmt.Sprintf("%s/S%d/EncryptWriter", name, segSize), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(streamBenchPlaintextLen))
				out := make([]byte, 0, streamBenchPlaintextLen+1024)
				buf := bytes.NewBuffer(out)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					buf.Reset()
					ew, err := schedule.NewEncryptWriter(cs, buf)
					if err != nil {
						b.Fatalf("NewEncryptWriter: %v", err)
					}
					writeInChunks(b, ew, plaintext, baselineStreamChunkSize)
					if err := ew.Close(); err != nil {
						b.Fatalf("Close: %v", err)
					}
				}
			})

			b.Run(fmt.Sprintf("%s/S%d/EncryptReader", name, segSize), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(streamBenchPlaintextLen))
				drain := make([]byte, 64*1024)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					er, err := schedule.NewEncryptReader(cs, bytes.NewReader(plaintext))
					if err != nil {
						b.Fatalf("NewEncryptReader: %v", err)
					}
					for {
						_, rerr := er.Read(drain)
						if rerr == io.EOF {
							break
						}
						if rerr != nil {
							b.Fatalf("Read: %v", rerr)
						}
					}
				}
			})

			// Build a chunked-streaming wire once for the decrypt
			// sub-benches.
			preWireBuf := &bytes.Buffer{}
			{
				ew, err := schedule.NewEncryptWriter(cs, preWireBuf)
				if err != nil {
					b.Fatalf("warm-up encrypt writer: %v", err)
				}
				if _, err := ew.Write(plaintext); err != nil {
					b.Fatalf("warm-up write: %v", err)
				}
				if err := ew.Close(); err != nil {
					b.Fatalf("warm-up close: %v", err)
				}
			}
			preWire := preWireBuf.Bytes()

			b.Run(fmt.Sprintf("%s/S%d/DecryptWriter", name, segSize), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(streamBenchPlaintextLen))
				dst := bytes.NewBuffer(make([]byte, 0, streamBenchPlaintextLen))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					dst.Reset()
					dw, err := schedule.NewDecryptWriter(cs, dst)
					if err != nil {
						b.Fatalf("NewDecryptWriter: %v", err)
					}
					writeInChunks(b, dw, preWire, baselineStreamChunkSize)
					if err := dw.Close(); err != nil {
						b.Fatalf("Close: %v", err)
					}
				}
			})

			b.Run(fmt.Sprintf("%s/S%d/DecryptReader", name, segSize), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(streamBenchPlaintextLen))
				dst := make([]byte, streamBenchPlaintextLen)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					dr, err := schedule.NewDecryptReader(cs, bytes.NewReader(preWire))
					if err != nil {
						b.Fatalf("NewDecryptReader: %v", err)
					}
					if _, err := io.ReadFull(dr, dst); err != nil {
						b.Fatalf("ReadFull: %v", err)
					}
				}
			})
		}
	}
}

// BenchmarkParallaxPaletteStreaming exercises the EncryptWriter
// streaming entry at a caller-pinned segment width across either the
// PARALLAX_PALETTE override or the default per-primitive homogeneous
// N=3 sweep.
func BenchmarkParallaxPaletteStreaming(b *testing.B) {
	segSize := paletteBenchSegSize

	plaintext := streamBenchRandom(b, streamBenchPlaintextLen)
	master := streamBenchMaster(b)
	for _, name := range streamBenchPrimitives {
		palette := streamBenchPalette(name)
		schedule, err := parallax.NewSchedule(palette, segSize)
		if err != nil {
			b.Fatalf("NewSchedule(name=%q, S=%d): %v", name, segSize, err)
		}
		cs := streamBenchCipherset(b, master, schedule)

		b.Run(fmt.Sprintf("%s/S%d/EncryptWriter", name, segSize), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(streamBenchPlaintextLen))
			out := make([]byte, 0, streamBenchPlaintextLen)
			buf := bytes.NewBuffer(out)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				buf.Reset()
				ew, err := schedule.NewEncryptWriter(cs, buf)
				if err != nil {
					b.Fatalf("NewEncryptWriter: %v", err)
				}
				writeInChunks(b, ew, plaintext, paletteBenchChunkSize)
				if err := ew.Close(); err != nil {
					b.Fatalf("Close: %v", err)
				}
			}
		})
	}
}

// BenchmarkParallaxStream is the streaming-surface throughput sweep.
// Each sub-bench runs one streaming entry over a 4 MiB plaintext
// across each PRF-grade registry primitive at DefaultChunkSize. The
// 4 MiB size matches bench_test.go so the streaming numbers contrast
// directly with the parallel one-shot Encrypt numbers under the same
// fixed plaintext.
func BenchmarkParallaxStream(b *testing.B) {
	plaintext := streamBenchRandom(b, streamBenchPlaintextLen)
	master := streamBenchMaster(b)
	for _, name := range streamBenchPrimitives {
		palette := streamBenchPalette(name)
		schedule := streamBenchSchedule(b, palette)
		cs := streamBenchCipherset(b, master, schedule)

		b.Run(fmt.Sprintf("%s/EncryptWriter", name), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(streamBenchPlaintextLen))
			out := make([]byte, 0, streamBenchPlaintextLen+1024)
			buf := bytes.NewBuffer(out)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				buf.Reset()
				ew, err := schedule.NewEncryptWriter(cs, buf)
				if err != nil {
					b.Fatalf("NewEncryptWriter: %v", err)
				}
				if _, err := ew.Write(plaintext); err != nil {
					b.Fatalf("Write: %v", err)
				}
				if err := ew.Close(); err != nil {
					b.Fatalf("Close: %v", err)
				}
			}
		})

		b.Run(fmt.Sprintf("%s/EncryptReader", name), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(streamBenchPlaintextLen))
			drain := make([]byte, 64*1024)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				er, err := schedule.NewEncryptReader(cs, bytes.NewReader(plaintext))
				if err != nil {
					b.Fatalf("NewEncryptReader: %v", err)
				}
				for {
					_, rerr := er.Read(drain)
					if rerr == io.EOF {
						break
					}
					if rerr != nil {
						b.Fatalf("Read: %v", rerr)
					}
				}
			}
		})

		// Build a wire once per primitive for the decrypt sub-benches.
		preWireBuf := &bytes.Buffer{}
		{
			ew, err := schedule.NewEncryptWriter(cs, preWireBuf)
			if err != nil {
				b.Fatalf("warm-up encrypt writer: %v", err)
			}
			if _, err := ew.Write(plaintext); err != nil {
				b.Fatalf("warm-up write: %v", err)
			}
			if err := ew.Close(); err != nil {
				b.Fatalf("warm-up close: %v", err)
			}
		}
		preWire := preWireBuf.Bytes()

		b.Run(fmt.Sprintf("%s/DecryptWriter", name), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(streamBenchPlaintextLen))
			dst := bytes.NewBuffer(make([]byte, 0, streamBenchPlaintextLen))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				dst.Reset()
				dw, err := schedule.NewDecryptWriter(cs, dst)
				if err != nil {
					b.Fatalf("NewDecryptWriter: %v", err)
				}
				if _, err := dw.Write(preWire); err != nil {
					b.Fatalf("Write: %v", err)
				}
				if err := dw.Close(); err != nil {
					b.Fatalf("Close: %v", err)
				}
			}
		})

		b.Run(fmt.Sprintf("%s/DecryptReader", name), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(streamBenchPlaintextLen))
			dst := make([]byte, streamBenchPlaintextLen)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				dr, err := schedule.NewDecryptReader(cs, bytes.NewReader(preWire))
				if err != nil {
					b.Fatalf("NewDecryptReader: %v", err)
				}
				if _, err := io.ReadFull(dr, dst); err != nil {
					b.Fatalf("ReadFull: %v", err)
				}
			}
		})

		// Companion one-shot Encrypt at the same primitive / palette
		// so the streaming row can be read alongside the one-shot row
		// in the same go test -bench run output.
		b.Run(fmt.Sprintf("%s/OneShotEncrypt", name), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(streamBenchPlaintextLen))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				wire, err := schedule.Encrypt(plaintext, cs)
				if err != nil {
					b.Fatalf("Encrypt: %v", err)
				}
				if len(wire) != parallax.NonceSize+streamBenchPlaintextLen {
					b.Fatalf("wire len mismatch")
				}
			}
		})
	}
}

// BenchmarkParallaxChunkedStream sweeps per-primitive throughput
// across chunkSize ∈ chunkedStreamChunkSizes for the EncryptWriter
// streaming shape. Each sub-bench builds a Schedule, applies the
// per-row SetChunkSize, and feeds plaintext sized at chunkSize *
// chunkedStreamPlaintextMultiplier so every chunk boundary is
// exercised inside the timed body.
func BenchmarkParallaxChunkedStream(b *testing.B) {
	master := streamBenchMaster(b)
	for _, name := range streamBenchPrimitives {
		palette := streamBenchPalette(name)
		for _, chunkSize := range chunkedStreamChunkSizes {
			plaintextLen := chunkSize * chunkedStreamPlaintextMultiplier
			plaintext := streamBenchRandom(b, plaintextLen)
			schedule, err := parallax.NewSchedule(palette, parallax.DefaultSegmentSize)
			if err != nil {
				b.Fatalf("NewSchedule: %v", err)
			}
			if err := schedule.SetChunkSize(chunkSize); err != nil {
				b.Fatalf("SetChunkSize(%d): %v", chunkSize, err)
			}
			cs := streamBenchCipherset(b, master, schedule)

			b.Run(fmt.Sprintf("%s/chunk%s/EncryptWriter", name, sizeLabel(chunkSize)), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(plaintextLen))
				out := make([]byte, 0, plaintextLen+1024)
				buf := bytes.NewBuffer(out)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					buf.Reset()
					ew, err := schedule.NewEncryptWriter(cs, buf)
					if err != nil {
						b.Fatalf("NewEncryptWriter: %v", err)
					}
					if _, err := ew.Write(plaintext); err != nil {
						b.Fatalf("Write: %v", err)
					}
					if err := ew.Close(); err != nil {
						b.Fatalf("Close: %v", err)
					}
				}
			})
		}
	}
}
