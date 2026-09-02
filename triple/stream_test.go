package triple

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"
)

// widthCase pairs an inner-hash primitive name with its native width.
// The three widths are reachable through [Opts.InnerHash] overrides
// even though every shipped profile defaults to areion512 (512-bit).
// The single primitive per width is picked to exercise the width path
// with minimal cross-primitive noise — a follow-up may diversify.
type widthCase struct {
	name  string
	hash  string
	width int
}

// widthCases enumerates the (name, innerHash, width) tuples the
// streaming round-trip matrix iterates over.
var widthCases = []widthCase{
	{"w128", "siphash24", 128},
	{"w256", "blake3", 256},
	{"w512", "areion512", 512},
}

// nonceCase pairs a short label with a nonce-bit-width for the
// streaming matrix's Config.NonceBits dimension.
type nonceCase struct {
	name string
	bits int
}

// nonceCases enumerates the (name, bits) pairs the streaming matrix
// iterates over. Every shipped nonce width (128 / 256 / 512) is
// exercised so a per-Pipeline [Config.NonceBits] regression surfaces
// on the streaming surface.
var nonceCases = []nonceCase{
	{"nonce128", 128},
	{"nonce256", 256},
	{"nonce512", 512},
}

// toggleCase encodes one of the four (parallax, wrapper) toggle
// combinations the matrix walks. Both fields carry the concrete
// on/off decision the Opts three-state pointer is expected to
// represent.
type toggleCase struct {
	name     string
	parallax bool
	wrapper  bool
}

var toggleCases = []toggleCase{
	{"paraOn_wrapOn", true, true},
	{"paraOn_wrapOff", true, false},
	{"paraOff_wrapOn", false, true},
	{"paraOff_wrapOff", false, false},
}

// modeCase pairs the two streaming-profile names with a short label
// for the flat sub-test dimension.
type modeCase struct {
	name    string
	profile string
}

var modeCases = []modeCase{
	{"aead", ProfileStreamingAEADTripleMACV1},
	{"nomac", ProfileStreamingNoAEADTripleV1},
}

// plaintextSizes is the matrix's payload-size dimension. 64 MiB is
// intentionally omitted from the default sweep — a follow-up under
// -tags itblong may reintroduce the giant case; keeping the standard
// suite fast is the current priority.
var plaintextSizes = []int{1, 6, 64, 1024, 65536, 1 << 20}

// TestEncryptStreamDecryptStreamRoundTripMatrix walks every
// (width, nonce, toggle, mode, plaintext-size) combination and
// asserts a byte-exact round-trip. Uses [t.Run] per combination so a
// single failure surfaces with a fully-qualified sub-test name.
//
// The plaintext bytes are drawn per iteration from crypto/rand — no
// deterministic fixture is required for a byte-exact round-trip. The
// [*Pipeline] is fresh per iteration so masters / seeds / MAC keys
// stay independent.
func TestEncryptStreamDecryptStreamRoundTripMatrix(t *testing.T) {
	for _, w := range widthCases {
		for _, n := range nonceCases {
			for _, tog := range toggleCases {
				for _, m := range modeCases {
					for _, sz := range plaintextSizes {
						w, n, tog, m, sz := w, n, tog, m, sz
						name := fmt.Sprintf("%s/%s/%s/%s/sz=%d",
							w.name, n.name, tog.name, m.name, sz)
						t.Run(name, func(t *testing.T) {
							runStreamRoundTrip(t, w, n, tog, m, sz)
						})
					}
				}
			}
		}
	}
}

// runStreamRoundTrip is the per-combination body of the matrix. Kept
// in a helper so t.Run's inline body stays scannable.
func runStreamRoundTrip(t *testing.T, w widthCase, n nonceCase, tog toggleCase, m modeCase, sz int) {
	t.Helper()
	opts := Opts{
		InnerHash:    w.hash,
		NonceBits:    n.bits,
		WithParallax: boolPtrHelper(tog.parallax),
		WithWrapper:  boolPtrHelper(tog.wrapper),
	}
	pipe, blob, err := Init(m.profile, opts)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer pipe.Close()

	// Receiver-side Pipeline opened from the sender's blob using the
	// same Opts so the toggle overrides reach both sides identically.
	rx, err := Open(m.profile, blob, opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer rx.Close()

	plaintext := freshBytes(t, sz)

	var wire bytes.Buffer
	if err := pipe.EncryptStream(bytes.NewReader(plaintext), &wire); err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}

	var recovered bytes.Buffer
	if err := rx.DecryptStream(&wire, &recovered); err != nil {
		t.Fatalf("DecryptStream: %v", err)
	}
	if !bytes.Equal(recovered.Bytes(), plaintext) {
		t.Fatalf("recovered %d bytes != plaintext %d bytes",
			recovered.Len(), len(plaintext))
	}
}

// boolPtrHelper is a small helper for building *bool Opts fields
// inline. Distinct from [boolPtr] in toggle_state_test.go only to
// avoid the shadowing that would arise if both files defined the same
// symbol at package scope; kept as a local alias so future refactors
// can consolidate.
func boolPtrHelper(b bool) *bool { return &b }

// TestEncryptStreamDecryptStreamConcurrentSamePipeline spawns N=8
// goroutines each running one Encrypt+Decrypt round-trip against the
// SAME [*Pipeline]. Each goroutine holds its own disjoint plaintext,
// its own bytes.Buffer wire, and its own recovery buffer, so the
// contention target is the shared Pipeline read-side (seeds, parallax
// Cipherset, wrapper key, MAC closure).
//
// A [sync.WaitGroup] gates the release so every goroutine starts
// approximately together, maximising the contention window. The test
// runs unconditionally; the race detector is engaged at the gate
// invocation (`go test -race`).
func TestEncryptStreamDecryptStreamConcurrentSamePipeline(t *testing.T) {
	const (
		numGoroutines = 8
		payloadSize   = 256 * 1024
	)

	pipe, blob, err := Init(ProfileStreamingAEADTripleMACV1, Opts{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer pipe.Close()

	rx, err := Open(ProfileStreamingAEADTripleMACV1, blob, Opts{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer rx.Close()

	// Pre-draw every goroutine's plaintext + a shared start barrier.
	plaintexts := make([][]byte, numGoroutines)
	for i := range plaintexts {
		plaintexts[i] = freshBytes(t, payloadSize)
		// Stamp a distinctive prefix so a cross-goroutine byte swap
		// surfaces as a fail-fast prefix-check.
		plaintexts[i][0] = byte(i + 1)
	}
	var startBarrier sync.WaitGroup
	startBarrier.Add(1)
	var releaseBarrier sync.WaitGroup
	releaseBarrier.Add(numGoroutines)

	errs := make([]error, numGoroutines)
	recovered := make([][]byte, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		i := i
		go func() {
			defer releaseBarrier.Done()
			startBarrier.Wait()

			var wire bytes.Buffer
			if err := pipe.EncryptStream(bytes.NewReader(plaintexts[i]), &wire); err != nil {
				errs[i] = fmt.Errorf("goroutine %d encrypt: %w", i, err)
				return
			}
			var back bytes.Buffer
			if err := rx.DecryptStream(&wire, &back); err != nil {
				errs[i] = fmt.Errorf("goroutine %d decrypt: %w", i, err)
				return
			}
			recovered[i] = back.Bytes()
		}()
	}
	startBarrier.Done()
	releaseBarrier.Wait()

	for i, e := range errs {
		if e != nil {
			t.Fatalf("goroutine %d: %v", i, e)
		}
		if !bytes.Equal(recovered[i], plaintexts[i]) {
			t.Fatalf("goroutine %d recovered %d bytes != plaintext %d bytes",
				i, len(recovered[i]), len(plaintexts[i]))
		}
	}
}

// TestEncryptStreamDecryptStreamConcurrentDistinctPipelines spawns N=8
// independent Pipelines (each built with distinct Opts so their inner
// state — hash width, MaxWorkers, wrapper cipher, whether parallax is
// engaged, MAC vs No MAC — differs across the fleet) and runs one
// concurrent goroutine per Pipeline. Cross-contamination is asserted
// via a "Pipeline A's wire never round-trips through Pipeline B"
// property: after every goroutine finishes, its own wire is fed
// through every OTHER Pipeline's DecryptStream and the recovered bytes
// (if any) are checked NOT to equal any other goroutine's plaintext.
//
// The distinctness matrix picks different (profile, InnerHash,
// MaxWorkers, WithParallax, WithWrapper) tuples so no two Pipelines
// share a full shape.
func TestEncryptStreamDecryptStreamConcurrentDistinctPipelines(t *testing.T) {
	distinctSpecs := []struct {
		name    string
		profile string
		opts    Opts
	}{
		{"pAeadAreion512", ProfileStreamingAEADTripleMACV1, Opts{InnerHash: "areion512"}},
		{"pAeadBlake3", ProfileStreamingAEADTripleMACV1, Opts{InnerHash: "blake3", MaxWorkers: 2}},
		{"pAeadSiphash", ProfileStreamingAEADTripleMACV1, Opts{InnerHash: "siphash24"}},
		{"pAeadNoPara", ProfileStreamingAEADTripleMACV1, Opts{WithParallax: boolPtrHelper(false)}},
		{"pAeadNoWrap", ProfileStreamingAEADTripleMACV1, Opts{WithWrapper: boolPtrHelper(false)}},
		{"pNomacAreion512", ProfileStreamingNoAEADTripleV1, Opts{InnerHash: "areion512"}},
		{"pNomacBlake3", ProfileStreamingNoAEADTripleV1, Opts{InnerHash: "blake3", MaxWorkers: 4}},
		{"pNomacNoPara", ProfileStreamingNoAEADTripleV1, Opts{WithParallax: boolPtrHelper(false)}},
	}
	if len(distinctSpecs) != 8 {
		t.Fatalf("distinctSpecs must have 8 entries, got %d", len(distinctSpecs))
	}

	senders := make([]*Pipeline, len(distinctSpecs))
	receivers := make([]*Pipeline, len(distinctSpecs))
	plaintexts := make([][]byte, len(distinctSpecs))
	for i, spec := range distinctSpecs {
		s, blob, err := Init(spec.profile, spec.opts)
		if err != nil {
			t.Fatalf("Init %s: %v", spec.name, err)
		}
		senders[i] = s
		t.Cleanup(func() { s.Close() })

		r, err := Open(spec.profile, blob, spec.opts)
		if err != nil {
			t.Fatalf("Open %s: %v", spec.name, err)
		}
		receivers[i] = r
		t.Cleanup(func() { r.Close() })

		plaintexts[i] = freshBytes(t, 64*1024)
		plaintexts[i][0] = byte(i + 1)
	}

	// Fire every round-trip concurrently.
	var start sync.WaitGroup
	start.Add(1)
	var done sync.WaitGroup
	done.Add(len(distinctSpecs))

	wires := make([]bytes.Buffer, len(distinctSpecs))
	recovered := make([][]byte, len(distinctSpecs))
	errs := make([]error, len(distinctSpecs))

	for i := range distinctSpecs {
		i := i
		go func() {
			defer done.Done()
			start.Wait()
			if err := senders[i].EncryptStream(bytes.NewReader(plaintexts[i]), &wires[i]); err != nil {
				errs[i] = err
				return
			}
			wire := wires[i].Bytes()
			var back bytes.Buffer
			if err := receivers[i].DecryptStream(bytes.NewReader(wire), &back); err != nil {
				errs[i] = err
				return
			}
			recovered[i] = back.Bytes()
		}()
	}
	start.Done()
	done.Wait()

	// Verify each Pipeline round-tripped its own plaintext byte-exact.
	for i, spec := range distinctSpecs {
		if errs[i] != nil {
			t.Fatalf("%s: %v", spec.name, errs[i])
		}
		if !bytes.Equal(recovered[i], plaintexts[i]) {
			t.Fatalf("%s: recovered != plaintext", spec.name)
		}
	}

	// Cross-check: no OTHER receiver's DecryptStream produces bytes
	// equal to a foreign plaintext, so a Pipeline's ciphertext never
	// crosses over into another Pipeline's plaintext space.
	//
	// Most cross-pairs return an error (MAC mismatch, wrong width,
	// wrong wrapper key) — that already proves isolation. When a
	// cross-pair happens to succeed decoding some bytes (rare — but
	// possible on the No MAC path where the receiver has no tag to
	// verify), the bytes must NOT equal the foreign plaintext.
	for i := range distinctSpecs {
		for j := range distinctSpecs {
			if i == j {
				continue
			}
			var back bytes.Buffer
			err := receivers[j].DecryptStream(bytes.NewReader(wires[i].Bytes()), &back)
			if err != nil {
				continue
			}
			if bytes.Equal(back.Bytes(), plaintexts[i]) {
				t.Fatalf("cross-contamination: Pipeline %d wire decoded to Pipeline %d plaintext through Pipeline %d receiver",
					i, i, j)
			}
		}
	}
}

// TestEncryptStreamNonStreamingProfileRejected verifies that
// EncryptStream / DecryptStream return [ErrProfileNotStreaming] when
// invoked on a Pipeline whose resolved profile mode is Single Message
// or blob-only. Ratifies the guard's coverage of the three non-
// streaming shipped profiles.
func TestEncryptStreamNonStreamingProfileRejected(t *testing.T) {
	nonStreaming := []string{
		ProfileSingleMsgTripleMACV1,
		ProfileSingleMsgTripleNoMACV1,
		ProfileBlobTripleMACV1,
	}
	for _, prof := range nonStreaming {
		prof := prof
		t.Run(prof, func(t *testing.T) {
			pipe, _, err := Init(prof, Opts{})
			if err != nil {
				t.Fatalf("Init(%s): %v", prof, err)
			}
			defer pipe.Close()
			if err := pipe.EncryptStream(bytes.NewReader(nil), &bytes.Buffer{}); !errors.Is(err, ErrProfileNotStreaming) {
				t.Fatalf("EncryptStream on %s: got err=%v, want %v",
					prof, err, ErrProfileNotStreaming)
			}
			if err := pipe.DecryptStream(bytes.NewReader(nil), &bytes.Buffer{}); !errors.Is(err, ErrProfileNotStreaming) {
				t.Fatalf("DecryptStream on %s: got err=%v, want %v",
					prof, err, ErrProfileNotStreaming)
			}
		})
	}
}

// TestEncryptStreamClosed verifies EncryptStream / DecryptStream both
// return [ErrClosed] on a closed Pipeline. The isClosed guard runs
// before the profile-mode check, so the ErrClosed sentinel wins even
// on a non-streaming profile — Init happens on a streaming profile
// here so a regression that swaps the guard order surfaces as a
// specific error.
func TestEncryptStreamClosed(t *testing.T) {
	pipe, _, err := Init(ProfileStreamingAEADTripleMACV1, Opts{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := pipe.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := pipe.EncryptStream(bytes.NewReader(nil), &bytes.Buffer{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("EncryptStream after Close: got err=%v, want %v", err, ErrClosed)
	}
	if err := pipe.DecryptStream(bytes.NewReader(nil), &bytes.Buffer{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("DecryptStream after Close: got err=%v, want %v", err, ErrClosed)
	}
}
