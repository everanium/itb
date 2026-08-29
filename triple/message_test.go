package triple

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"
)

// messageModeCases pairs each cipher-carrying profile with a short
// label for the flat sub-test dimension. The blob-only profile is
// omitted here — it has a dedicated rejection test elsewhere in this
// file.
type messageModeCase struct {
	name    string
	profile string
	// streaming reports whether the profile also accepts
	// [Pipeline.EncryptStream] / [Pipeline.DecryptStream]. Used to
	// gate the streaming-only half of the cross-parity tests.
	streaming bool
}

var messageModeCases = []messageModeCase{
	{"aead", ProfileStreamingAEADTripleMACV1, true},
	{"nomacStream", ProfileStreamingNoAEADTripleV1, true},
	{"singleMAC", ProfileSingleMsgTripleMACV1, false},
	{"singleNoMAC", ProfileSingleMsgTripleNoMACV1, false},
}

// messagePlaintextSizes covers the empty-input case, sub-chunk sizes,
// and up to 1 MiB — mirroring the streaming-matrix size dimension minus
// the giant tail. 0 is included to lock the empty-input rejection
// contract ([ErrEmptyInput]) inside the matrix.
var messagePlaintextSizes = []int{0, 1, 6, 64, 1024, 65536, 1 << 20}

// TestEncryptMessageDecryptMessageRoundTripMatrix walks every
// (width, nonce, toggle, mode, plaintext-size) combination and
// asserts a byte-exact round-trip via [Pipeline.EncryptMessage] and
// [Pipeline.DecryptMessage]. Same matrix shape as the streaming
// counterpart — extended across all four cipher-carrying profile modes
// and with a size=0 row so the empty-plaintext contract is enforced by
// the matrix, not only the dedicated test.
func TestEncryptMessageDecryptMessageRoundTripMatrix(t *testing.T) {
	for _, w := range widthCases {
		for _, n := range nonceCases {
			for _, tog := range toggleCases {
				for _, m := range messageModeCases {
					for _, sz := range messagePlaintextSizes {
						w, n, tog, m, sz := w, n, tog, m, sz
						name := fmt.Sprintf("%s/%s/%s/%s/sz=%d",
							w.name, n.name, tog.name, m.name, sz)
						t.Run(name, func(t *testing.T) {
							runMessageRoundTrip(t, w, n, tog, m, sz)
						})
					}
				}
			}
		}
	}
}

// runMessageRoundTrip is the per-combination body of the matrix,
// factored out so t.Run's inline body stays scannable.
func runMessageRoundTrip(t *testing.T, w widthCase, n nonceCase, tog toggleCase, m messageModeCase, sz int) {
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

	rx, err := Open(m.profile, blob, opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer rx.Close()

	plaintext := freshBytes(t, sz)

	wire, err := pipe.EncryptMessage(plaintext)
	if sz == 0 {
		if !errors.Is(err, ErrEmptyInput) {
			t.Fatalf("EncryptMessage on empty plaintext: got err=%v, want %v",
				err, ErrEmptyInput)
		}
		return
	}
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}

	recovered, err := rx.DecryptMessage(wire)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("recovered %d bytes != plaintext %d bytes",
			len(recovered), len(plaintext))
	}
}

// TestEncryptMessageStreamCrossParityStreamToMessage verifies that
// wire bytes produced by [Pipeline.EncryptStream] round-trip through
// [Pipeline.DecryptMessage] with byte-exact plaintext recovery on
// every cipher-carrying profile. On Single Message profiles the
// sender still uses EncryptMessage (the streaming entry point rejects
// singlemsg profiles with [ErrProfileNotStreaming]); the assertion is
// therefore trivially reflexive in that case — see the parallel test
// below for the streaming→message direction which is meaningful only
// on streaming profiles.
func TestEncryptMessageStreamCrossParityStreamToMessage(t *testing.T) {
	for _, m := range messageModeCases {
		if !m.streaming {
			// EncryptStream rejects Single Message profiles; the
			// stream→message cross-parity assertion is vacuous there.
			continue
		}
		m := m
		t.Run(m.name, func(t *testing.T) {
			opts := Opts{}
			pipe, blob, err := Init(m.profile, opts)
			if err != nil {
				t.Fatalf("Init: %v", err)
			}
			defer pipe.Close()
			rx, err := Open(m.profile, blob, opts)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer rx.Close()

			plaintext := freshBytes(t, 4096)

			var wire bytes.Buffer
			if err := pipe.EncryptStream(bytes.NewReader(plaintext), &wire); err != nil {
				t.Fatalf("EncryptStream: %v", err)
			}
			recovered, err := rx.DecryptMessage(wire.Bytes())
			if err != nil {
				t.Fatalf("DecryptMessage on EncryptStream wire: %v", err)
			}
			if !bytes.Equal(recovered, plaintext) {
				t.Fatalf("stream→message: recovered != plaintext")
			}
		})
	}
}

// TestEncryptMessageStreamCrossParityMessageToStream verifies that
// wire bytes produced by [Pipeline.EncryptMessage] round-trip through
// [Pipeline.DecryptStream] with byte-exact plaintext recovery.
// Meaningful only on streaming profiles — Single Message profiles
// reject DecryptStream with [ErrProfileNotStreaming], so the singlemsg
// iterations skip with a diagnostic message.
func TestEncryptMessageStreamCrossParityMessageToStream(t *testing.T) {
	for _, m := range messageModeCases {
		m := m
		t.Run(m.name, func(t *testing.T) {
			if !m.streaming {
				t.Skip("cross-decode via DecryptStream requires a streaming profile")
			}
			opts := Opts{}
			pipe, blob, err := Init(m.profile, opts)
			if err != nil {
				t.Fatalf("Init: %v", err)
			}
			defer pipe.Close()
			rx, err := Open(m.profile, blob, opts)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer rx.Close()

			plaintext := freshBytes(t, 4096)

			wire, err := pipe.EncryptMessage(plaintext)
			if err != nil {
				t.Fatalf("EncryptMessage: %v", err)
			}
			var recovered bytes.Buffer
			if err := rx.DecryptStream(bytes.NewReader(wire), &recovered); err != nil {
				t.Fatalf("DecryptStream on EncryptMessage wire: %v", err)
			}
			if !bytes.Equal(recovered.Bytes(), plaintext) {
				t.Fatalf("message→stream: recovered != plaintext")
			}
		})
	}
}

// TestEncryptMessageBlobOnlyProfileRejected verifies that the
// blob-only profile — which by construction has no cipher surface —
// rejects both [Pipeline.EncryptMessage] and [Pipeline.DecryptMessage]
// with [ErrProfileNoCipher]. This is the sole rejection reason
// specific to the message surface; the streaming surface additionally
// rejects Single Message profiles via [ErrProfileNotStreaming].
func TestEncryptMessageBlobOnlyProfileRejected(t *testing.T) {
	pipe, _, err := Init(ProfileBlobTripleMACV1, Opts{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer pipe.Close()

	if _, err := pipe.EncryptMessage([]byte("payload")); !errors.Is(err, ErrProfileNoCipher) {
		t.Fatalf("EncryptMessage on blob-only: got err=%v, want %v",
			err, ErrProfileNoCipher)
	}
	if _, err := pipe.DecryptMessage([]byte{0, 1, 2, 3}); !errors.Is(err, ErrProfileNoCipher) {
		t.Fatalf("DecryptMessage on blob-only: got err=%v, want %v",
			err, ErrProfileNoCipher)
	}
}

// TestEncryptMessageClosed verifies that [Pipeline.EncryptMessage] and
// [Pipeline.DecryptMessage] both return [ErrClosed] on a closed
// Pipeline. The [isClosed] guard runs first, so the ErrClosed
// sentinel wins even when the profile mode would otherwise trigger
// [ErrProfileNoCipher] — Init happens on a cipher-carrying profile
// here so a regression that swaps the guard order surfaces as a
// specific-error mismatch rather than a silent pass.
func TestEncryptMessageClosed(t *testing.T) {
	pipe, _, err := Init(ProfileSingleMsgTripleMACV1, Opts{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := pipe.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := pipe.EncryptMessage([]byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("EncryptMessage after Close: got err=%v, want %v",
			err, ErrClosed)
	}
	if _, err := pipe.DecryptMessage([]byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("DecryptMessage after Close: got err=%v, want %v",
			err, ErrClosed)
	}
}

// TestEncryptMessageEmptyInput ratifies the empty-input rejection
// contract spelled out in the [Pipeline.EncryptMessage] doc-comment.
// The round-trip matrix already exercises sz=0, but a dedicated test
// surfaces the intent cleanly: both the nil and the zero-length slice
// forms are rejected with [ErrEmptyInput] on both message-shape entry
// points.
func TestEncryptMessageEmptyInput(t *testing.T) {
	for _, in := range []struct {
		name string
		body []byte
	}{
		{"nilSlice", nil},
		{"emptySlice", []byte{}},
	} {
		in := in
		t.Run(in.name, func(t *testing.T) {
			pipe, blob, err := Init(ProfileSingleMsgTripleMACV1, Opts{})
			if err != nil {
				t.Fatalf("Init: %v", err)
			}
			defer pipe.Close()
			rx, err := Open(ProfileSingleMsgTripleMACV1, blob, Opts{})
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer rx.Close()

			if _, err := pipe.EncryptMessage(in.body); !errors.Is(err, ErrEmptyInput) {
				t.Fatalf("EncryptMessage: got err=%v, want %v", err, ErrEmptyInput)
			}
			if _, err := rx.DecryptMessage(in.body); !errors.Is(err, ErrEmptyInput) {
				t.Fatalf("DecryptMessage: got err=%v, want %v", err, ErrEmptyInput)
			}
		})
	}
}

// TestEncryptMessageConcurrentSamePipeline spawns N=8 goroutines each
// running one EncryptMessage → DecryptMessage round-trip against the
// SAME [*Pipeline] with a 256 KiB payload. Each goroutine holds its
// own disjoint plaintext + recovery buffer, so the contention target
// is the shared Pipeline read-side (seeds, parallax Cipherset,
// wrapper key, MAC closure). Runs under the race detector when the
// suite is gated with -race.
func TestEncryptMessageConcurrentSamePipeline(t *testing.T) {
	const (
		numGoroutines = 8
		payloadSize   = 256 * 1024
	)

	pipe, blob, err := Init(ProfileSingleMsgTripleMACV1, Opts{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer pipe.Close()
	rx, err := Open(ProfileSingleMsgTripleMACV1, blob, Opts{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer rx.Close()

	plaintexts := make([][]byte, numGoroutines)
	for i := range plaintexts {
		plaintexts[i] = freshBytes(t, payloadSize)
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

			wire, err := pipe.EncryptMessage(plaintexts[i])
			if err != nil {
				errs[i] = fmt.Errorf("goroutine %d encrypt: %w", i, err)
				return
			}
			back, err := rx.DecryptMessage(wire)
			if err != nil {
				errs[i] = fmt.Errorf("goroutine %d decrypt: %w", i, err)
				return
			}
			recovered[i] = back
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
