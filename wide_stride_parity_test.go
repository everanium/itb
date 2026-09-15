package itb

import (
	"bytes"
	"crypto/rand"
	"sync/atomic"
	"testing"
)

// wide_stride_parity_test.go — the eight-pixel stride of the width-256
// and width-512 pixel pipelines under synthetic eight-lane hooks. No
// shipped primitive needs to carry the hook for the wiring to be
// pinned: a Go closure evaluating the reference cascade lane by lane
// stands in for a kernel, so the tests show that a constellation with
// the hook produces the wire of the same constellation without it, that
// the hooked pipeline actually routes through the hook, that a hook
// declining the input shape falls back cleanly, and that the stride is
// only taken when both seeds of a call carry the hook.

// wideStrideSeeds256 builds eight width-256 seeds over the test hash,
// each with the four-lane BatchHash arm; hooked seeds also carry the
// synthetic eight-lane hook, whose calls are counted. decline makes the
// hook refuse every input (ok=false).
func wideStrideSeeds256(t *testing.T, bits int, comps [8][]uint64, hooked, decline bool, calls *atomic.Int64) [8]*Seed256 {
	t.Helper()
	var out [8]*Seed256
	for i := range out {
		var s *Seed256
		var err error
		if comps[i] == nil {
			s, err = NewSeed256(bits, testHash256)
		} else {
			s, err = SeedFromComponents256(testHash256, comps[i]...)
		}
		if err != nil {
			t.Fatal(err)
		}
		s.BatchHash = synthBatch256(testHash256)
		if hooked {
			s.SetBatchFusedChain8(func(c []uint64, data *[8][]byte) ([8][4]uint64, bool) {
				calls.Add(1)
				var o [8][4]uint64
				if decline {
					return o, false
				}
				for l := range data {
					o[l] = refCascade256(c, data[l])
				}
				return o, true
			})
		}
		out[i] = s
	}
	return out
}

// wideStrideSeeds512 is the width-512 twin of wideStrideSeeds256.
func wideStrideSeeds512(t *testing.T, bits int, comps [8][]uint64, hooked, decline bool, calls *atomic.Int64) [8]*Seed512 {
	t.Helper()
	var out [8]*Seed512
	for i := range out {
		var s *Seed512
		var err error
		if comps[i] == nil {
			s, err = NewSeed512(bits, testHash512)
		} else {
			s, err = SeedFromComponents512(testHash512, comps[i]...)
		}
		if err != nil {
			t.Fatal(err)
		}
		s.BatchHash = synthBatch512(testHash512)
		if hooked {
			s.SetBatchFusedChain8(func(c []uint64, data *[8][]byte) ([8][8]uint64, bool) {
				calls.Add(1)
				var o [8][8]uint64
				if decline {
					return o, false
				}
				for l := range data {
					o[l] = refCascade512(c, data[l])
				}
				return o, true
			})
		}
		out[i] = s
	}
	return out
}

// wideStrideSizes are message sizes whose pixel counts leave eight-,
// four- and single-pixel tails at every nonce width.
var wideStrideSizes = []int{1, 77, 4093, 65_537}

// TestWideStrideParity256 pins the width-256 eight-pixel stride: the
// hooked constellation's wire decrypts through the hook-free twin and
// vice versa at every nonce width, the hook is consulted, and a
// declining hook leaves the wire unchanged while still being consulted.
func TestWideStrideParity256(t *testing.T) {
	var calls atomic.Int64
	x8 := wideStrideSeeds256(t, 512, [8][]uint64{}, true, false, &calls)
	var comps [8][]uint64
	for i := range comps {
		comps[i] = append([]uint64(nil), x8[i].Components...)
	}
	x4 := wideStrideSeeds256(t, 512, comps, false, false, &calls)
	var declineCalls atomic.Int64
	dec := wideStrideSeeds256(t, 512, comps, true, true, &declineCalls)
	for i := range x8 {
		if !useBatch8Seeds256(x8[i], x8[(i+1)%8]) {
			t.Fatalf("seed %d: hooked pair does not take the eight-pixel stride", i)
		}
		if useBatch8Seeds256(x8[i], x4[i]) || useBatch8Seeds256(x4[i], x8[i]) {
			t.Fatalf("seed %d: mixed pair takes the eight-pixel stride", i)
		}
	}
	for _, nb := range []int{128, 256, 512} {
		cfg := &Config{NonceBits: nb}
		for _, size := range wideStrideSizes {
			plain := make([]byte, size)
			rand.Read(plain)
			calls.Store(0)
			wire, err := Encrypt3x256Cfg(cfg, x8[0], x8[1], x8[2], x8[3], x8[4], x8[5], x8[6], x8[7], plain)
			if err != nil {
				t.Fatalf("nb=%d size=%d encrypt(x8): %v", nb, size, err)
			}
			if size >= 64 && calls.Load() == 0 {
				t.Fatalf("nb=%d size=%d: hooked encrypt never consulted the eight-lane hook", nb, size)
			}
			got, err := Decrypt3x256Cfg(cfg, x4[0], x4[1], x4[2], x4[3], x4[4], x4[5], x4[6], x4[7], wire)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("nb=%d size=%d decrypt(x4): err=%v match=%v", nb, size, err, bytes.Equal(got, plain))
			}
			wire4, err := Encrypt3x256Cfg(cfg, x4[0], x4[1], x4[2], x4[3], x4[4], x4[5], x4[6], x4[7], plain)
			if err != nil {
				t.Fatalf("nb=%d size=%d encrypt(x4): %v", nb, size, err)
			}
			got, err = Decrypt3x256Cfg(cfg, x8[0], x8[1], x8[2], x8[3], x8[4], x8[5], x8[6], x8[7], wire4)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("nb=%d size=%d decrypt(x8): err=%v match=%v", nb, size, err, bytes.Equal(got, plain))
			}
			declineCalls.Store(0)
			got, err = Decrypt3x256Cfg(cfg, dec[0], dec[1], dec[2], dec[3], dec[4], dec[5], dec[6], dec[7], wire)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("nb=%d size=%d decrypt(declining hook): err=%v match=%v", nb, size, err, bytes.Equal(got, plain))
			}
			if size >= 64 && declineCalls.Load() == 0 {
				t.Fatalf("nb=%d size=%d: declining hook never consulted", nb, size)
			}
		}
	}
}

// TestWideStrideParity512 is the width-512 twin of TestWideStrideParity256.
func TestWideStrideParity512(t *testing.T) {
	var calls atomic.Int64
	x8 := wideStrideSeeds512(t, 1024, [8][]uint64{}, true, false, &calls)
	var comps [8][]uint64
	for i := range comps {
		comps[i] = append([]uint64(nil), x8[i].Components...)
	}
	x4 := wideStrideSeeds512(t, 1024, comps, false, false, &calls)
	var declineCalls atomic.Int64
	dec := wideStrideSeeds512(t, 1024, comps, true, true, &declineCalls)
	for i := range x8 {
		if !useBatch8Seeds512(x8[i], x8[(i+1)%8]) {
			t.Fatalf("seed %d: hooked pair does not take the eight-pixel stride", i)
		}
		if useBatch8Seeds512(x8[i], x4[i]) || useBatch8Seeds512(x4[i], x8[i]) {
			t.Fatalf("seed %d: mixed pair takes the eight-pixel stride", i)
		}
	}
	for _, nb := range []int{128, 256, 512} {
		cfg := &Config{NonceBits: nb}
		for _, size := range wideStrideSizes {
			plain := make([]byte, size)
			rand.Read(plain)
			calls.Store(0)
			wire, err := Encrypt3x512Cfg(cfg, x8[0], x8[1], x8[2], x8[3], x8[4], x8[5], x8[6], x8[7], plain)
			if err != nil {
				t.Fatalf("nb=%d size=%d encrypt(x8): %v", nb, size, err)
			}
			if size >= 64 && calls.Load() == 0 {
				t.Fatalf("nb=%d size=%d: hooked encrypt never consulted the eight-lane hook", nb, size)
			}
			got, err := Decrypt3x512Cfg(cfg, x4[0], x4[1], x4[2], x4[3], x4[4], x4[5], x4[6], x4[7], wire)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("nb=%d size=%d decrypt(x4): err=%v match=%v", nb, size, err, bytes.Equal(got, plain))
			}
			wire4, err := Encrypt3x512Cfg(cfg, x4[0], x4[1], x4[2], x4[3], x4[4], x4[5], x4[6], x4[7], plain)
			if err != nil {
				t.Fatalf("nb=%d size=%d encrypt(x4): %v", nb, size, err)
			}
			got, err = Decrypt3x512Cfg(cfg, x8[0], x8[1], x8[2], x8[3], x8[4], x8[5], x8[6], x8[7], wire4)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("nb=%d size=%d decrypt(x8): err=%v match=%v", nb, size, err, bytes.Equal(got, plain))
			}
			declineCalls.Store(0)
			got, err = Decrypt3x512Cfg(cfg, dec[0], dec[1], dec[2], dec[3], dec[4], dec[5], dec[6], dec[7], wire)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("nb=%d size=%d decrypt(declining hook): err=%v match=%v", nb, size, err, bytes.Equal(got, plain))
			}
			if size >= 64 && declineCalls.Load() == 0 {
				t.Fatalf("nb=%d size=%d: declining hook never consulted", nb, size)
			}
		}
	}
}

// TestWideStrideBatchChainHashX8 pins the eight-lane batched cascade
// helpers lane by lane against the sequential ChainHash at both widths:
// with no hook (two four-lane calls), with a declining hook, and with a
// hook that answers.
func TestWideStrideBatchChainHashX8(t *testing.T) {
	var calls, declineCalls atomic.Int64
	s256 := wideStrideSeeds256(t, 1024, [8][]uint64{}, false, false, &calls)[0]
	h256 := wideStrideSeeds256(t, 1024, [8][]uint64{append([]uint64(nil), s256.Components...)}, true, false, &calls)[0]
	d256 := wideStrideSeeds256(t, 1024, [8][]uint64{append([]uint64(nil), s256.Components...)}, true, true, &declineCalls)[0]
	s512 := wideStrideSeeds512(t, 2048, [8][]uint64{}, false, false, &calls)[0]
	h512 := wideStrideSeeds512(t, 2048, [8][]uint64{append([]uint64(nil), s512.Components...)}, true, false, &calls)[0]
	d512 := wideStrideSeeds512(t, 2048, [8][]uint64{append([]uint64(nil), s512.Components...)}, true, true, &declineCalls)[0]
	for _, n := range []int{13, 20, 36, 68} {
		var lanes [8][]byte
		for l := range lanes {
			lanes[l] = make([]byte, n)
			for i := range lanes[l] {
				lanes[l][i] = byte(i*3 + l*11 + n)
			}
		}
		var idx [8]int
		for l := range idx {
			idx[l] = 1000*n + l
		}
		for _, seed := range []*Seed256{s256, h256, d256} {
			got := seed.blockHash256x8(&lanes, idx)
			for l := 0; l < 8; l++ {
				if want := s256.blockHash256(lanes[l], idx[l]); got[l] != want {
					t.Fatalf("256 len=%d lane %d: %x != %x", n, l, got[l], want)
				}
			}
		}
		for _, seed := range []*Seed512{s512, h512, d512} {
			got := seed.blockHash512x8(&lanes, idx)
			for l := 0; l < 8; l++ {
				if want := s512.blockHash512(lanes[l], idx[l]); got[l] != want {
					t.Fatalf("512 len=%d lane %d: %x != %x", n, l, got[l], want)
				}
			}
		}
	}
	if calls.Load() == 0 || declineCalls.Load() == 0 {
		t.Fatalf("hooks consulted: answering=%d declining=%d", calls.Load(), declineCalls.Load())
	}
	if h256.BatchFusedChain8() == nil || s256.BatchFusedChain8() != nil || h512.BatchFusedChain8() == nil || s512.BatchFusedChain8() != nil {
		t.Fatal("BatchFusedChain8 accessor disagrees with the attached state")
	}
	h256.SetBatchFusedChain8(nil)
	h512.SetBatchFusedChain8(nil)
	if h256.BatchFusedChain8() != nil || h512.BatchFusedChain8() != nil {
		t.Fatal("SetBatchFusedChain8(nil) left a hook attached")
	}
}
