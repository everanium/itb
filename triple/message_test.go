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

	rx, err := Load(blob)
	if err != nil {
		t.Fatalf("Load: %v", err)
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
			rx, err := Load(blob)
			if err != nil {
				t.Fatalf("Load: %v", err)
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
			rx, err := Load(blob)
			if err != nil {
				t.Fatalf("Load: %v", err)
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
			rx, err := Load(blob)
			if err != nil {
				t.Fatalf("Load: %v", err)
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
	rx, err := Load(blob)
	if err != nil {
		t.Fatalf("Load: %v", err)
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

// TestMaxWireSizeEVPNTableAnchors verifies that MaxWireSize and
// MaxWireSizeWithBarrierFill reproduce exact deterministic wire byte
// counts across the eVPN payload spectrum for Mode 1 and Mode 2 under
// KeyBits=1024, NonceBits=512, Parallax=true, and Wrapper=chacha20, and
// that PktBufSize = ebuffers/2 fits under Base64 expansion for all
// BarrierFill in {1, 2, 4}.
func TestMaxWireSizeEVPNTableAnchors(t *testing.T) {
	pipeM1, _, err := Init(ProfileSingleMsgTripleMACV1, Opts{
		Mode:        1,
		KeyBits:     1024,
		NonceBits:   512,
		BarrierFill: 1,
		OuterCipher: "chacha20",
	})
	if err != nil {
		t.Fatalf("Init Mode 1: %v", err)
	}
	defer pipeM1.Close()

	pipeM2, _, err := Init(ProfileSingleMsgTripleMACV1, Opts{
		Mode:        2,
		KeyBits:     1024,
		NonceBits:   512,
		BarrierFill: 1,
		OuterCipher: "chacha20",
	})
	if err != nil {
		t.Fatalf("Init Mode 2: %v", err)
	}
	defer pipeM2.Close()

	for _, plainLen := range []int{5, 100, 1460, 9001, 16384, 32768, 65536, 131072} {
		pt := freshBytes(t, plainLen)
		wireM1, err := pipeM1.EncryptMessage(pt)
		if err != nil {
			t.Fatalf("EncryptMessage Mode 1 (%d): %v", plainLen, err)
		}
		if got := pipeM1.MaxWireSize(plainLen); got != len(wireM1) {
			t.Errorf("Mode 1 BF=1 MaxWireSize(%d) = %d, actual wire len = %d", plainLen, got, len(wireM1))
		}

		wireM2, err := pipeM2.EncryptMessage(pt)
		if err != nil {
			t.Fatalf("EncryptMessage Mode 2 (%d): %v", plainLen, err)
		}
		if got := pipeM2.MaxWireSize(plainLen); got != len(wireM2) {
			t.Errorf("Mode 2 BF=1 MaxWireSize(%d) = %d, actual wire len = %d", plainLen, got, len(wireM2))
		}
		if plainLen <= 1460 && len(wireM2) >= len(wireM1) {
			t.Errorf("Mode 2 wire (%d) not smaller than Mode 1 wire (%d) at small payload %d",
				len(wireM2), len(wireM1), plainLen)
		}
	}

	// Verify PktBufSize = ebuffers/2 fits within ebuffers after Base64
	// expansion for all BarrierFill in {1, 2, 4}.
	for _, ebufKB := range []int{32, 64, 128, 256} {
		ebufBytes := ebufKB * 1024
		pktBufSize := ebufBytes / 2
		for _, bf := range []int{1, 2, 4} {
			wireLen := pipeM2.MaxWireSizeWithBarrierFill(pktBufSize, bf)
			b64Len := ((wireLen + 2) / 3) * 4
			if b64Len > ebufBytes {
				t.Errorf("ebuffers=%dKB bf=%d: Base64(MaxWireSize(%d)) = %d > %d",
					ebufKB, bf, pktBufSize, b64Len, ebufBytes)
			}
			if maxPt := pipeM2.MaxPlaintextSizeWithBarrierFill(wireLen, bf); maxPt < pktBufSize {
				t.Errorf("ebuffers=%dKB bf=%d: MaxPlaintextSizeWithBarrierFill(%d, %d) = %d < %d",
					ebufKB, bf, wireLen, bf, maxPt, pktBufSize)
			}
		}
	}
}

// TestMaxWireSizeAndMaxPlaintextSizeMatrix verifies MaxWireSize,
// MaxWireSizeWithBarrierFill, MaxPlaintextSize, and
// MaxPlaintextSizeWithBarrierFill across BarrierFill in
// {1, 2, 4, 8, 16, 32}, ContainerMode in {1, 2}, KeyBits in
// {512, 1024, 2048}, NonceBits in {128, 256, 512}, and all
// (Parallax x Wrapper x MAC) combinations.
func TestMaxWireSizeAndMaxPlaintextSizeMatrix(t *testing.T) {
	barrierFills := []int{1, 2, 4, 8, 16, 32}
	modes := []int{1, 2}
	keyBitsList := []struct {
		kb   int
		hash string
	}{
		{512, "aescmac"},
		{1024, "blake2b256"},
		{2048, "blake2b512"},
	}

	for _, kb := range keyBitsList {
		for _, mode := range modes {
			for _, bf := range barrierFills {
				for _, tog := range toggleCases {
					for _, prof := range []string{ProfileSingleMsgTripleMACV1, ProfileSingleMsgTripleNoMACV1} {
						opts := Opts{
							Mode:         mode,
							KeyBits:      kb.kb,
							InnerHash:    kb.hash,
							NonceBits:    256,
							BarrierFill:  bf,
							WithParallax: boolPtrHelper(tog.parallax),
							WithWrapper:  boolPtrHelper(tog.wrapper),
						}
						pipe, _, err := Init(prof, opts)
						if err != nil {
							t.Fatalf("Init(kb=%d, mode=%d, bf=%d, tog=%s, prof=%s): %v",
								kb.kb, mode, bf, tog.name, prof, err)
						}

						for _, sz := range []int{1, 37, 1460, 16384} {
							want := pipe.MaxWireSize(sz)
							if want <= sz {
								t.Fatalf("MaxWireSize(%d) = %d <= sz", sz, want)
							}
							if got0 := pipe.MaxWireSizeWithBarrierFill(sz, 0); got0 != want {
								t.Fatalf("MaxWireSizeWithBarrierFill(%d, 0) = %d, want %d", sz, got0, want)
							}
							pt := freshBytes(t, sz)
							wire, err := pipe.EncryptMessage(pt)
							if err != nil {
								t.Fatalf("EncryptMessage(%d): %v", sz, err)
							}
							if len(wire) != want {
								t.Fatalf("kb=%d mode=%d bf=%d tog=%s prof=%s sz=%d: len(wire)=%d != MaxWireSize=%d",
									kb.kb, mode, bf, tog.name, prof, sz, len(wire), want)
							}

							maxPt := pipe.MaxPlaintextSize(want)
							if maxPt < sz {
								t.Fatalf("MaxPlaintextSize(%d) = %d < %d", want, maxPt, sz)
							}
							if pipe.MaxWireSize(maxPt) > want {
								t.Fatalf("MaxWireSize(maxPt=%d) = %d > %d", maxPt, pipe.MaxWireSize(maxPt), want)
							}
							if pipe.MaxWireSize(maxPt+1) <= want {
								t.Fatalf("MaxWireSize(maxPt+1=%d) = %d <= %d (not maximal)",
									maxPt+1, pipe.MaxWireSize(maxPt+1), want)
							}
						}

						minWire := pipe.MaxWireSize(1)
						if got := pipe.MaxPlaintextSize(minWire - 1); got != 0 {
							t.Fatalf("MaxPlaintextSize(minWire-1) = %d, want 0", got)
						}
						if got := pipe.MaxWireSize(0); got != 0 {
							t.Fatalf("MaxWireSize(0) = %d, want 0", got)
						}
						if got := pipe.MaxPlaintextSize(0); got != 0 {
							t.Fatalf("MaxPlaintextSize(0) = %d, want 0", got)
						}
						_ = pipe.Close()
						if got := pipe.MaxWireSize(64); got != 0 {
							t.Fatalf("closed MaxWireSize = %d, want 0", got)
						}
						if got := pipe.MaxPlaintextSize(65536); got != 0 {
							t.Fatalf("closed MaxPlaintextSize = %d, want 0", got)
						}
					}
				}
			}
		}
	}
}

// TestEncryptMessageToAndDecryptMessageTo verifies zero-copy destination
// buffer reuse, cross-surface compatibility (including single-chunk
// Parallax=true), and destination buffer wiping on error.
func TestEncryptMessageToAndDecryptMessageTo(t *testing.T) {
	for _, tog := range toggleCases {
		for _, m := range messageModeCases {
			tog, m := tog, m
			t.Run(tog.name+"/"+m.name, func(t *testing.T) {
				opts := Opts{
					WithParallax: boolPtrHelper(tog.parallax),
					WithWrapper:  boolPtrHelper(tog.wrapper),
				}
				pipe, blob, err := Init(m.profile, opts)
				if err != nil {
					t.Fatalf("Init: %v", err)
				}
				defer pipe.Close()

				rx, err := Load(blob)
				if err != nil {
					t.Fatalf("Load: %v", err)
				}
				defer rx.Close()

				pt := freshBytes(t, 8192)
				maxWire := pipe.MaxWireSize(len(pt))
				encBuf := make([]byte, 0, maxWire+64)
				decBuf := make([]byte, 0, len(pt)+64)

				wire, err := pipe.EncryptMessageTo(encBuf, pt)
				if err != nil {
					t.Fatalf("EncryptMessageTo: %v", err)
				}
				if len(wire) != maxWire {
					t.Fatalf("len(wire) = %d, want MaxWireSize = %d", len(wire), maxWire)
				}
				if &wire[0] != &encBuf[:1][0] {
					t.Fatalf("EncryptMessageTo did not reuse encBuf backing array")
				}

				got, err := rx.DecryptMessageTo(decBuf, wire)
				if err != nil {
					t.Fatalf("DecryptMessageTo: %v", err)
				}
				if !bytes.Equal(got, pt) {
					t.Fatalf("DecryptMessageTo plaintext mismatch")
				}
				if &got[0] != &decBuf[:1][0] {
					t.Fatalf("DecryptMessageTo did not reuse decBuf backing array")
				}

				// Cross-check with streaming surfaces when profile is streaming.
				if m.streaming {
					sWire, err := pipe.encryptStreamBytesTo(encBuf[:0], pt)
					if err != nil {
						t.Fatalf("encryptStreamBytesTo: %v", err)
					}
					if &sWire[0] != &encBuf[:1][0] {
						t.Fatalf("encryptStreamBytesTo did not reuse encBuf backing array")
					}
					sGot, err := rx.DecryptMessageTo(decBuf[:0], sWire)
					if err != nil {
						t.Fatalf("DecryptMessageTo(encryptStreamBytesTo): %v", err)
					}
					if !bytes.Equal(sGot, pt) {
						t.Fatalf("DecryptMessageTo(encryptStreamBytesTo) mismatch")
					}
					bGot, err := rx.decryptStreamBytesTo(decBuf[:0], wire)
					if err != nil {
						t.Fatalf("decryptStreamBytesTo(EncryptMessageTo): %v", err)
					}
					if !bytes.Equal(bGot, pt) {
						t.Fatalf("decryptStreamBytesTo(EncryptMessageTo) mismatch")
					}
					if &bGot[0] != &decBuf[:1][0] {
						t.Fatalf("decryptStreamBytesTo did not reuse decBuf backing array")
					}
				}

				// In-place / overlapping dst and input must round-trip without clobbering.
				inPlace := make([]byte, maxWire+64)
				copy(inPlace, pt)
				ipWire, err := pipe.EncryptMessageTo(inPlace[:0], inPlace[:len(pt)])
				if err != nil {
					t.Fatalf("in-place EncryptMessageTo: %v", err)
				}
				if &ipWire[0] != &inPlace[0] {
					t.Fatalf("in-place EncryptMessageTo did not return inPlace slice")
				}
				ipPlain, err := rx.DecryptMessageTo(inPlace[:0], ipWire)
				if err != nil {
					t.Fatalf("in-place DecryptMessageTo: %v", err)
				}
				if !bytes.Equal(ipPlain, pt) {
					t.Fatalf("in-place DecryptMessageTo plaintext mismatch")
				}
				if &ipPlain[0] != &inPlace[0] {
					t.Fatalf("in-place DecryptMessageTo did not return inPlace slice")
				}

				// Entry pre-checks must not clobber dst before any cipher staging occurs.
				sentinel := make([]byte, 128)
				for i := range sentinel {
					sentinel[i] = 0xAA
				}
				if _, err := pipe.EncryptMessageTo(sentinel[:0], nil); !errors.Is(err, ErrEmptyInput) {
					t.Fatalf("expected ErrEmptyInput, got %v", err)
				}
				for i, b := range sentinel {
					if b != 0xAA {
						t.Fatalf("sentinel[%d] = 0x%02x after EncryptMessageTo pre-check error, want 0xAA", i, b)
					}
				}
				if _, err := rx.DecryptMessageTo(sentinel[:0], nil); !errors.Is(err, ErrEmptyInput) {
					t.Fatalf("expected ErrEmptyInput, got %v", err)
				}
				for i, b := range sentinel {
					if b != 0xAA {
						t.Fatalf("sentinel[%d] = 0x%02x after DecryptMessageTo pre-check error, want 0xAA", i, b)
					}
				}
			})
		}
	}
}

func TestMaxWireSizeTagStubAndOverflowGuards(t *testing.T) {
	// On a MAC-carrying profile, Opts.TagStubSize < 32 must not cause
	// MaxWireSize to under-predict the MAC's actual tag reservation.
	pipe, _, err := Init(ProfileStreamingAEADTripleMACV1, Opts{
		TagStubSize: 16,
	})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer pipe.Close()

	pt := freshBytes(t, 4096)
	wire, err := pipe.EncryptMessage(pt)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	if got := pipe.MaxWireSize(len(pt)); got != len(wire) {
		t.Fatalf("MaxWireSize(%d) with TagStubSize=16 on MAC profile = %d, want len(wire) = %d", len(pt), got, len(wire))
	}

	// Extreme inputs near math.MaxInt must saturate cleanly without negative wrap.
	const maxInt = int(^uint(0) >> 1)
	if got := pipe.MaxWireSize(maxInt); got <= 0 {
		t.Fatalf("MaxWireSize(MaxInt) = %d, want > 0", got)
	}
	if got := pipe.MaxPlaintextSize(maxInt); got <= 0 {
		t.Fatalf("MaxPlaintextSize(MaxInt) = %d, want > 0", got)
	}
	if got := pipe.MaxPlaintextSize(maxInt - 1024); got <= 0 {
		t.Fatalf("MaxPlaintextSize(MaxInt-1024) = %d, want > 0", got)
	}
}
