package triple

import (
	"bytes"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/parallax"
)

// streamParityChunk is the plaintext chunk size of the stream parity
// profiles: small enough that the payloads below span several chunks.
const streamParityChunk = 4096

// streamParityProfiles registers one Streaming AEAD and one Streaming
// Non-AEAD profile per hash width with a small chunk size, once per
// process, and returns them.
func streamParityProfiles(t *testing.T) []prefixParityProfile {
	t.Helper()
	rows := []prefixParityProfile{
		{"userns-stream-parity-128-noaead-v1", 128, false},
		{"userns-stream-parity-128-aead-v1", 128, true},
		{"userns-stream-parity-256-noaead-v1", 256, false},
		{"userns-stream-parity-256-aead-v1", 256, true},
		{"userns-stream-parity-512-noaead-v1", 512, false},
		{"userns-stream-parity-512-aead-v1", 512, true},
	}
	inner := map[int]string{128: "siphash24", 256: "blake3", 512: "areion512"}
	for _, r := range rows {
		if _, err := Lookup(r.name); err == nil {
			continue
		}
		p := Profile{
			Mode:                modeStreamingNoAEAD,
			Width:               r.width,
			ChunkSize:           streamParityChunk,
			InnerHash:           inner[r.width],
			KeyBits:             512,
			OuterCipher:         defaultOuterCipher,
			ParallaxPalette:     defaultParallaxPalette(),
			ParallaxSegmentSize: parallax.DefaultSegmentSize,
		}
		if r.mac {
			p.Mode = modeStreamingAEAD
			p.MacName = defaultMacName
		}
		if err := Register(r.name, p); err != nil {
			t.Fatalf("Register(%s): %v", r.name, err)
		}
	}
	return rows
}

// lowLevelSeeds returns the Pipeline's eight seeds as the untyped
// arguments the width-less Low-Level stream entries take.
func lowLevelSeeds(p *Pipeline) [8]any {
	var s [8]any
	for i := range s {
		s[i] = p.seeds[i]
	}
	return s
}

func lowLevelEncryptStream(p *Pipeline, pt []byte) ([]byte, error) {
	s := lowLevelSeeds(p)
	var out bytes.Buffer
	var err error
	if p.macFunc != nil {
		err = itb.EncryptStreamAuth3xCfg(p.cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], bytes.NewReader(pt), &out, p.macFunc, streamParityChunk)
	} else {
		err = itb.EncryptStream3xCfg(p.cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], bytes.NewReader(pt), &out, streamParityChunk)
	}
	return out.Bytes(), err
}

func lowLevelDecryptStream(p *Pipeline, wire []byte) ([]byte, error) {
	s := lowLevelSeeds(p)
	var out bytes.Buffer
	var err error
	if p.macFunc != nil {
		err = itb.DecryptStreamAuth3xCfg(p.cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], bytes.NewReader(wire), &out, p.macFunc)
	} else {
		err = itb.DecryptStream3xCfg(p.cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], bytes.NewReader(wire), &out)
	}
	return out.Bytes(), err
}

// TestStreamLowLevelTripleMutualDecrypt checks that, with the wrapper
// and parallax layers off, a multi-chunk stream produced by the
// Low-Level stream entries decrypts through [Pipeline.DecryptStream]
// and a stream produced by [Pipeline.EncryptStream] decrypts through
// the Low-Level entries, for Streaming AEAD and Streaming Non-AEAD at
// every hash width, with payloads below, at, and across chunk
// boundaries. Wire lengths must match exactly: the same number of
// chunk records — each a 32-byte prefix and one chunk — of the same
// sizes.
func TestStreamLowLevelTripleMutualDecrypt(t *testing.T) {
	sizes := []int{1, streamParityChunk - 1, streamParityChunk, streamParityChunk + 1, 4 * streamParityChunk, 4*streamParityChunk + 777}
	for _, row := range streamParityProfiles(t) {
		row := row
		t.Run(row.name, func(t *testing.T) {
			p := openPrefixParityPipeline(t, row.name, false)
			for _, sz := range sizes {
				pt := make([]byte, sz)
				for i := range pt {
					pt[i] = byte(i*17 + sz)
				}
				ll, err := lowLevelEncryptStream(p, pt)
				if err != nil {
					t.Fatalf("Low-Level encrypt %d B: %v", sz, err)
				}
				var tw bytes.Buffer
				if err := p.EncryptStream(bytes.NewReader(pt), &tw); err != nil {
					t.Fatalf("EncryptStream %d B: %v", sz, err)
				}
				if len(ll) != tw.Len() {
					t.Fatalf("%d B: Low-Level stream %d B, Triple stream %d B", sz, len(ll), tw.Len())
				}
				var got bytes.Buffer
				if err := p.DecryptStream(bytes.NewReader(ll), &got); err != nil || !bytes.Equal(got.Bytes(), pt) {
					t.Fatalf("DecryptStream(Low-Level stream) %d B: err=%v match=%v", sz, err, bytes.Equal(got.Bytes(), pt))
				}
				back, err := lowLevelDecryptStream(p, tw.Bytes())
				if err != nil || !bytes.Equal(back, pt) {
					t.Fatalf("Low-Level decrypt(Triple stream) %d B: err=%v match=%v", sz, err, bytes.Equal(back, pt))
				}
				if want := (sz + streamParityChunk - 1) / streamParityChunk; sz > 0 {
					if n := countChunks(t, p, ll); n != want {
						t.Fatalf("%d B: %d chunks, want %d", sz, n, want)
					}
				}
			}
		})
	}
}

// countChunks walks a stream wire record by record — every chunk
// behind its own 32-byte prefix — and counts the chunks.
func countChunks(t *testing.T, p *Pipeline, wire []byte) int {
	t.Helper()
	n := 0
	for off := 0; off < len(wire); n++ {
		l, err := itb.ParseChunkLenCfg(p.cfg, wire[off+streamIDPrefixLen:])
		if err != nil {
			t.Fatalf("chunk %d at %d: %v", n, off, err)
		}
		off += streamIDPrefixLen + l
	}
	return n
}
