package triple

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

// streamBytesSizes covers the empty-input case, sub-chunk sizes, and a
// 1 MiB tail — the single-chunk direct-path regime under the default
// chunkSize. The multi-chunk regime is exercised separately via a
// ChunkSize override so the matrix stays fast.
var streamBytesSizes = []int{0, 1, 6, 64, 1024, 65536, 1 << 20}

// TestEncryptStreamBytesRoundTripMatrix walks every
// (width, nonce, toggle, size) combination on both Streaming profiles
// and asserts a byte-exact round-trip via
// [Pipeline.EncryptStreamBytes] and [Pipeline.DecryptStreamBytes].
func TestEncryptStreamBytesRoundTripMatrix(t *testing.T) {
	for _, w := range widthCases {
		for _, n := range nonceCases {
			for _, tog := range toggleCases {
				for _, m := range messageModeCases {
					if !m.streaming {
						continue
					}
					for _, sz := range streamBytesSizes {
						w, n, tog, m, sz := w, n, tog, m, sz
						name := fmt.Sprintf("%s/%s/%s/%s/sz=%d",
							w.name, n.name, tog.name, m.name, sz)
						t.Run(name, func(t *testing.T) {
							runStreamBytesRoundTrip(t, w, n, tog, m, sz)
						})
					}
				}
			}
		}
	}
}

// runStreamBytesRoundTrip is the per-combination body of the matrix,
// factored out so t.Run's inline body stays scannable.
func runStreamBytesRoundTrip(t *testing.T, w widthCase, n nonceCase, tog toggleCase, m messageModeCase, sz int) {
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

	wire, err := pipe.EncryptStreamBytes(plaintext)
	if err != nil {
		t.Fatalf("EncryptStreamBytes: %v", err)
	}

	recovered, err := rx.DecryptStreamBytes(wire)
	if err != nil {
		t.Fatalf("DecryptStreamBytes: %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("recovered %d bytes != plaintext %d bytes",
			len(recovered), len(plaintext))
	}
}

// TestStreamBytesCrossParityWithIOStream verifies wire-level parity
// between the whole-buffer entries and the io.Reader / io.Writer
// Streaming surface in both directions, across the toggle matrix and
// across both the single-chunk and multi-chunk regimes (the latter via
// a small ChunkSize override so [Pipeline.EncryptStream] emits a
// multi-chunk wire while [Pipeline.EncryptStreamBytes]'s direct path
// emits a single chunk).
func TestStreamBytesCrossParityWithIOStream(t *testing.T) {
	for _, tog := range toggleCases {
		for _, m := range messageModeCases {
			if !m.streaming {
				continue
			}
			for _, cs := range []int{0, 4096} {
				tog, m, cs := tog, m, cs
				name := fmt.Sprintf("%s/%s/chunkSize=%d", tog.name, m.name, cs)
				t.Run(name, func(t *testing.T) {
					opts := Opts{
						WithParallax: boolPtrHelper(tog.parallax),
						WithWrapper:  boolPtrHelper(tog.wrapper),
						ChunkSize:    cs,
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

					plaintext := freshBytes(t, 64<<10)

					// bytes → io direction
					wireB, err := pipe.EncryptStreamBytes(plaintext)
					if err != nil {
						t.Fatalf("EncryptStreamBytes: %v", err)
					}
					var recIO bytes.Buffer
					if err := rx.DecryptStream(bytes.NewReader(wireB), &recIO); err != nil {
						t.Fatalf("DecryptStream on EncryptStreamBytes wire: %v", err)
					}
					if !bytes.Equal(recIO.Bytes(), plaintext) {
						t.Fatalf("bytes→io: recovered != plaintext")
					}

					// io → bytes direction
					var wireIO bytes.Buffer
					if err := pipe.EncryptStream(bytes.NewReader(plaintext), &wireIO); err != nil {
						t.Fatalf("EncryptStream: %v", err)
					}
					recB, err := rx.DecryptStreamBytes(wireIO.Bytes())
					if err != nil {
						t.Fatalf("DecryptStreamBytes on EncryptStream wire: %v", err)
					}
					if !bytes.Equal(recB, plaintext) {
						t.Fatalf("io→bytes: recovered != plaintext")
					}
				})
			}
		}
	}
}

// TestDecryptStreamBytesDoesNotMutateWire locks the no-mutation
// contract on the caller's wire slice — the wrapper posture unwraps a
// copy, never the caller's bytes.
func TestDecryptStreamBytesDoesNotMutateWire(t *testing.T) {
	for _, tog := range toggleCases {
		tog := tog
		t.Run(tog.name, func(t *testing.T) {
			opts := Opts{
				WithParallax: boolPtrHelper(tog.parallax),
				WithWrapper:  boolPtrHelper(tog.wrapper),
			}
			pipe, blob, err := Init(ProfileStreamingAEADTripleMACV1, opts)
			if err != nil {
				t.Fatalf("Init: %v", err)
			}
			defer pipe.Close()
			rx, err := Open(ProfileStreamingAEADTripleMACV1, blob, opts)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer rx.Close()

			plaintext := freshBytes(t, 4096)
			wire, err := pipe.EncryptStreamBytes(plaintext)
			if err != nil {
				t.Fatalf("EncryptStreamBytes: %v", err)
			}
			snapshot := append([]byte(nil), wire...)
			if _, err := rx.DecryptStreamBytes(wire); err != nil {
				t.Fatalf("DecryptStreamBytes: %v", err)
			}
			if !bytes.Equal(wire, snapshot) {
				t.Fatalf("DecryptStreamBytes mutated the caller's wire slice")
			}
		})
	}
}

// TestStreamBytesTailWrapOversized exercises the tail-wrap encrypt
// path (parallax off, wrapper on, plaintext above the direct-path cap)
// and its tail-unwrap decrypt counterpart, plus cross-parity with the
// io.Reader / io.Writer surface on the same oversized payload.
func TestStreamBytesTailWrapOversized(t *testing.T) {
	if testing.Short() {
		t.Skip("oversized payload matrix skipped in -short mode")
	}
	opts := Opts{
		WithParallax: boolPtrHelper(false),
		WithWrapper:  boolPtrHelper(true),
	}
	pipe, blob, err := Init(ProfileStreamingAEADTripleMACV1, opts)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer pipe.Close()
	rx, err := Open(ProfileStreamingAEADTripleMACV1, blob, opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer rx.Close()

	plaintext := freshBytes(t, messageFastPathMaxBytes+(1<<20))

	wire, err := pipe.EncryptStreamBytes(plaintext)
	if err != nil {
		t.Fatalf("EncryptStreamBytes: %v", err)
	}

	// tail-wrap wire → whole-buffer decode (multi-chunk inner arm)
	recovered, err := rx.DecryptStreamBytes(wire)
	if err != nil {
		t.Fatalf("DecryptStreamBytes: %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("tail-wrap round-trip: recovered != plaintext")
	}

	// tail-wrap wire → io.Reader surface
	var recIO bytes.Buffer
	if err := rx.DecryptStream(bytes.NewReader(wire), &recIO); err != nil {
		t.Fatalf("DecryptStream on tail-wrap wire: %v", err)
	}
	if !bytes.Equal(recIO.Bytes(), plaintext) {
		t.Fatalf("tail-wrap wire via DecryptStream: recovered != plaintext")
	}

	// io.Writer-surface wire → whole-buffer decode
	var wireIO bytes.Buffer
	if err := pipe.EncryptStream(bytes.NewReader(plaintext), &wireIO); err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}
	recB, err := rx.DecryptStreamBytes(wireIO.Bytes())
	if err != nil {
		t.Fatalf("DecryptStreamBytes on EncryptStream wire: %v", err)
	}
	if !bytes.Equal(recB, plaintext) {
		t.Fatalf("io wire via DecryptStreamBytes: recovered != plaintext")
	}
}

// TestStreamBytesNonStreamingProfileRejected verifies both
// whole-buffer entries reject Single Message and blob-only profiles
// with [ErrProfileNotStreaming], matching the io.Reader / io.Writer
// surface's guard.
func TestStreamBytesNonStreamingProfileRejected(t *testing.T) {
	for _, profile := range []string{
		ProfileSingleMsgTripleMACV1,
		ProfileSingleMsgTripleNoMACV1,
		ProfileBlobTripleMACV1,
	} {
		profile := profile
		t.Run(profile, func(t *testing.T) {
			pipe, _, err := Init(profile, Opts{})
			if err != nil {
				t.Fatalf("Init: %v", err)
			}
			defer pipe.Close()

			if _, err := pipe.EncryptStreamBytes([]byte("x")); !errors.Is(err, ErrProfileNotStreaming) {
				t.Fatalf("EncryptStreamBytes: got %v, want ErrProfileNotStreaming", err)
			}
			if _, err := pipe.DecryptStreamBytes([]byte("x")); !errors.Is(err, ErrProfileNotStreaming) {
				t.Fatalf("DecryptStreamBytes: got %v, want ErrProfileNotStreaming", err)
			}
		})
	}
}

// TestStreamBytesClosed verifies both whole-buffer entries return
// [ErrClosed] after [Pipeline.Close].
func TestStreamBytesClosed(t *testing.T) {
	pipe, _, err := Init(ProfileStreamingAEADTripleMACV1, Opts{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := pipe.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := pipe.EncryptStreamBytes([]byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("EncryptStreamBytes: got %v, want ErrClosed", err)
	}
	if _, err := pipe.DecryptStreamBytes([]byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("DecryptStreamBytes: got %v, want ErrClosed", err)
	}
}
