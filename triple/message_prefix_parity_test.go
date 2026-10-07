package triple

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/parallax"
)

// prefixParityProfile names one Single Message profile per hash width
// and MAC arm for the Low-Level ↔ Triple parity tests below. The
// 512-bit rows are the shipped profiles; the 128- and 256-bit rows are
// registered here over 512-bit keys so every width is covered.
type prefixParityProfile struct {
	name  string
	width int
	mac   bool
}

// prefixParityProfiles registers the non-shipped width rows once per
// process and returns the full matrix.
func prefixParityProfiles(t *testing.T) []prefixParityProfile {
	t.Helper()
	rows := []prefixParityProfile{
		{ProfileSingleMsgTripleNoMACV1, 512, false},
		{ProfileSingleMsgTripleMACV1, 512, true},
		{"userns-prefix-parity-128-nomac-v1", 128, false},
		{"userns-prefix-parity-128-mac-v1", 128, true},
		{"userns-prefix-parity-256-nomac-v1", 256, false},
		{"userns-prefix-parity-256-mac-v1", 256, true},
	}
	inner := map[int]string{128: "siphash24", 256: "blake3"}
	for _, r := range rows[2:] {
		if _, err := Lookup(r.name); err == nil {
			continue
		}
		p := Profile{
			Mode:                modeSingleMsgNoMAC,
			Width:               r.width,
			ChunkSize:           itb.DefaultChunkSize,
			InnerHash:           inner[r.width],
			KeyBits:             512,
			OuterCipher:         defaultOuterCipher,
			ParallaxPalette:     defaultParallaxPalette(),
			ParallaxSegmentSize: parallax.DefaultSegmentSize,
		}
		if r.mac {
			p.Mode = modeSingleMsgMAC
			p.MacName = defaultMacName
		}
		if err := Register(r.name, p); err != nil {
			t.Fatalf("Register(%s): %v", r.name, err)
		}
	}
	return rows
}

// openPrefixParityPipeline opens a Pipeline on the named profile with
// the parallax layer off and the wrapper layer as requested.
func openPrefixParityPipeline(t *testing.T, name string, wrapper bool) *Pipeline {
	t.Helper()
	off := false
	p, _, err := Init(name, Opts{WithParallax: &off, WithWrapper: &wrapper})
	if err != nil {
		t.Fatalf("Init(%s): %v", name, err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

// lowLevelEncrypt produces a Single Message wire through the itb-root
// Low-Level entry matching the Pipeline's width and MAC arm, from the
// Pipeline's own seeds, Config and MAC closure — what an external
// caller holding the same material would call.
func lowLevelEncrypt(p *Pipeline, pt []byte) ([]byte, error) {
	switch p.width {
	case 128:
		s := func(i int) *itb.Seed128 { return p.seeds[i].(*itb.Seed128) }
		if p.macFunc != nil {
			return itb.EncryptAuthenticated3x128Cfg(p.cfg, s(0), s(1), s(2), s(3), s(4), s(5), s(6), s(7), pt, p.macFunc)
		}
		return itb.Encrypt3x128Cfg(p.cfg, s(0), s(1), s(2), s(3), s(4), s(5), s(6), s(7), pt)
	case 256:
		s := func(i int) *itb.Seed256 { return p.seeds[i].(*itb.Seed256) }
		if p.macFunc != nil {
			return itb.EncryptAuthenticated3x256Cfg(p.cfg, s(0), s(1), s(2), s(3), s(4), s(5), s(6), s(7), pt, p.macFunc)
		}
		return itb.Encrypt3x256Cfg(p.cfg, s(0), s(1), s(2), s(3), s(4), s(5), s(6), s(7), pt)
	case 512:
		s := func(i int) *itb.Seed512 { return p.seeds[i].(*itb.Seed512) }
		if p.macFunc != nil {
			return itb.EncryptAuthenticated3x512Cfg(p.cfg, s(0), s(1), s(2), s(3), s(4), s(5), s(6), s(7), pt, p.macFunc)
		}
		return itb.Encrypt3x512Cfg(p.cfg, s(0), s(1), s(2), s(3), s(4), s(5), s(6), s(7), pt)
	}
	return nil, fmt.Errorf("unsupported width %d", p.width)
}

// lowLevelDecrypt is the mirror image of [lowLevelEncrypt].
func lowLevelDecrypt(p *Pipeline, wire []byte) ([]byte, error) {
	switch p.width {
	case 128:
		s := func(i int) *itb.Seed128 { return p.seeds[i].(*itb.Seed128) }
		if p.macFunc != nil {
			return itb.DecryptAuthenticated3x128Cfg(p.cfg, s(0), s(1), s(2), s(3), s(4), s(5), s(6), s(7), wire, p.macFunc)
		}
		return itb.Decrypt3x128Cfg(p.cfg, s(0), s(1), s(2), s(3), s(4), s(5), s(6), s(7), wire)
	case 256:
		s := func(i int) *itb.Seed256 { return p.seeds[i].(*itb.Seed256) }
		if p.macFunc != nil {
			return itb.DecryptAuthenticated3x256Cfg(p.cfg, s(0), s(1), s(2), s(3), s(4), s(5), s(6), s(7), wire, p.macFunc)
		}
		return itb.Decrypt3x256Cfg(p.cfg, s(0), s(1), s(2), s(3), s(4), s(5), s(6), s(7), wire)
	case 512:
		s := func(i int) *itb.Seed512 { return p.seeds[i].(*itb.Seed512) }
		if p.macFunc != nil {
			return itb.DecryptAuthenticated3x512Cfg(p.cfg, s(0), s(1), s(2), s(3), s(4), s(5), s(6), s(7), wire, p.macFunc)
		}
		return itb.Decrypt3x512Cfg(p.cfg, s(0), s(1), s(2), s(3), s(4), s(5), s(6), s(7), wire)
	}
	return nil, fmt.Errorf("unsupported width %d", p.width)
}

// TestSingleMessageLowLevelTripleMutualDecrypt confirms that, with the
// wrapper and parallax layers off, a Low-Level Single Message wire and
// a Triple Single Message wire built from the same seeds, Config and
// MAC are mutually decryptable on both arms at every hash width: the
// Low-Level wire decrypts through [Pipeline.DecryptMessage], the
// Pipeline wire decrypts through the Low-Level decoder, and the two
// wires are the same length.
func TestSingleMessageLowLevelTripleMutualDecrypt(t *testing.T) {
	for _, row := range prefixParityProfiles(t) {
		row := row
		t.Run(row.name, func(t *testing.T) {
			p := openPrefixParityPipeline(t, row.name, false)
			for _, sz := range []int{1, 777, 4096, 64 * 1024} {
				pt := make([]byte, sz)
				for i := range pt {
					pt[i] = byte(i*31 + sz)
				}
				ll, err := lowLevelEncrypt(p, pt)
				if err != nil {
					t.Fatalf("Low-Level encrypt %d B: %v", sz, err)
				}
				tw, err := p.EncryptMessage(pt)
				if err != nil {
					t.Fatalf("EncryptMessage %d B: %v", sz, err)
				}
				if len(ll) != len(tw) {
					t.Fatalf("%d B: Low-Level wire %d B, Triple wire %d B", sz, len(ll), len(tw))
				}
				got, err := p.DecryptMessage(ll)
				if err != nil || !bytes.Equal(got, pt) {
					t.Fatalf("DecryptMessage(Low-Level wire) %d B: err=%v match=%v", sz, err, bytes.Equal(got, pt))
				}
				got, err = lowLevelDecrypt(p, tw)
				if err != nil || !bytes.Equal(got, pt) {
					t.Fatalf("Low-Level decrypt(Triple wire) %d B: err=%v match=%v", sz, err, bytes.Equal(got, pt))
				}
			}
		})
	}
}

// TestEncryptMessageDirectAndStreamingPathsAgree pins the Single
// Message wire shape across the two internal paths of
// [Pipeline.EncryptMessage]: the direct path and the streaming
// fallback produce wires of the same length, each decrypts through the
// other's decoder (the direct decoder claims the fallback wire as a
// one-chunk envelope; the streaming decoder walks the direct wire as a
// one-chunk stream), and with the wrapper off the header sits behind
// the 32-byte prefix and announces exactly the remaining bytes. Both
// MAC arms, wrapper on and off, every hash width.
func TestEncryptMessageDirectAndStreamingPathsAgree(t *testing.T) {
	for _, row := range prefixParityProfiles(t) {
		for _, wrap := range []bool{false, true} {
			row, wrap := row, wrap
			t.Run(fmt.Sprintf("%s/wrapper=%v", row.name, wrap), func(t *testing.T) {
				p := openPrefixParityPipeline(t, row.name, wrap)
				for _, sz := range []int{1, 777, 4096, 64 * 1024} {
					pt := make([]byte, sz)
					for i := range pt {
						pt[i] = byte(i*7 + sz)
					}
					direct, err := p.encryptMessageDirect(pt)
					if err != nil {
						t.Fatalf("direct %d B: %v", sz, err)
					}
					fallback, err := p.encryptMessageStreaming(pt)
					if err != nil {
						t.Fatalf("streaming %d B: %v", sz, err)
					}
					if len(direct) != len(fallback) {
						t.Fatalf("%d B: direct wire %d B, streaming wire %d B", sz, len(direct), len(fallback))
					}

					got, ok, err := p.decryptMessageDirect(fallback)
					if !ok {
						t.Fatalf("%d B: direct decoder did not claim the streaming wire", sz)
					}
					if err != nil || !bytes.Equal(got, pt) {
						t.Fatalf("direct decode of streaming wire %d B: err=%v match=%v", sz, err, bytes.Equal(got, pt))
					}
					got, err = p.decryptMessageStreaming(direct)
					if err != nil || !bytes.Equal(got, pt) {
						t.Fatalf("streaming decode of direct wire %d B: err=%v match=%v", sz, err, bytes.Equal(got, pt))
					}

					if wrap {
						continue
					}
					for name, wire := range map[string][]byte{"direct": direct, "streaming": fallback} {
						n, perr := itb.ParseChunkLenCfg(p.cfg, wire[streamIDPrefixLen:])
						if perr != nil || n != len(wire)-streamIDPrefixLen {
							t.Fatalf("%s wire %d B: chunk behind the prefix announces %d B (err %v), want %d", name, sz, n, perr, len(wire)-streamIDPrefixLen)
						}
					}
				}
			})
		}
	}
}
