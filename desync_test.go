package itb

import (
	"bytes"
	"errors"
	"math/bits"
	"math/rand"
	"runtime/debug"
	"testing"
)

func invFullWidthFoldTest(w0, w1 uint64) (hLo, hHi uint64) {
	hHi = w1 ^ bits.RotateLeft64(w0, 19) ^ bits.RotateLeft64(w0, 41)
	mixHi := bits.RotateLeft64(hHi, 25) + bits.RotateLeft64(hHi, 53)
	hLo = w0 - mixHi
	return hLo, hHi
}

func TestFullWidthFoldBijection(t *testing.T) {
	rng := rand.New(rand.NewSource(0xDE594C01))
	for i := 0; i < 4096; i++ {
		lo := rng.Uint64()
		hi := rng.Uint64()
		w0, w1 := fullWidthFold(lo, hi)
		gotLo, gotHi := invFullWidthFoldTest(w0, w1)
		if gotLo != lo || gotHi != hi {
			t.Fatalf("iter %d: invFullWidthFold(fullWidthFold(%#x, %#x)) = (%#x, %#x)", i, lo, hi, gotLo, gotHi)
		}
		lo2, hi2 := fullWidthFold(gotLo, gotHi)
		if lo2 != w0 || hi2 != w1 {
			t.Fatalf("iter %d: right-inverse mismatch", i)
		}
	}

	// Verify FNV-1a 24-bit dead-zone coverage: an active bit in hHi[24..63]
	// reaches every bit position of w0 across rotl64(hHi, 25) + rotl64(hHi, 53).
	var covered uint64
	for b := uint(24); b < 64; b++ {
		hi := uint64(1) << b
		w0, _ := fullWidthFold(0, hi)
		covered |= w0
	}
	if covered != ^uint64(0) {
		t.Fatalf("FNV-1a upper-40-bit coverage mask = %#016x, want all 64 bits set", covered)
	}
}

func TestLayerISubregionScheduleInvariants(t *testing.T) {
	rng := rand.New(rand.NewSource(0xDE594C02))
	regionSizes := []int{147, 148, 200, 364, 365, 408, 409, 1024, 4096}

	for _, totalPixels := range regionSizes {
		for trial := 0; trial < 256; trial++ {
			var w [8]uint64
			for i := range w {
				w[i] = rng.Uint64()
			}
			sp := rng.Intn(totalPixels)
			sched := buildSubregionSchedule(sp, totalPixels, w)

			if totalPixels < mode1DesyncRegionPixels {
				if sched.k < 6 || sched.k > 10 {
					t.Fatalf("Mode 2 totalPixels=%d: k=%d outside [6, 10]", totalPixels, sched.k)
				}
			} else {
				if sched.k < 8 || sched.k > 16 {
					t.Fatalf("Mode 1 totalPixels=%d: k=%d outside [8, 16]", totalPixels, sched.k)
				}
			}

			sumSize := 0
			physVisited := make([]bool, totalPixels)
			for step := 0; step < sched.k; step++ {
				m := sched.size[step]
				off := sched.offset[step]
				s := sched.start[step]
				logStart := sched.logOff[step]

				minAllowed := 13
				if totalPixels >= mode1DesyncRegionPixels {
					minAllowed = 19
				}
				if m < minAllowed {
					t.Fatalf("totalPixels=%d step=%d: size=%d < %d", totalPixels, step, m, minAllowed)
				}
				if s < 0 || s >= m {
					t.Fatalf("totalPixels=%d step=%d: start=%d outside [0, %d)", totalPixels, step, s, m)
				}
				if sched.logOff[step+1] != logStart+m {
					t.Fatalf("totalPixels=%d step=%d: logOff mismatch", totalPixels, step)
				}
				sumSize += m

				eff := effectiveStartPixel(m, s, logStart)
				for q := 0; q < m; q++ {
					pp := logStart + q
					gotLocal := (eff + pp) % m
					wantLocal := (s + q) % m
					if gotLocal != wantLocal {
						t.Fatalf("effectiveStartPixel_compat failed: m=%d s=%d logStart=%d q=%d: got %d, want %d", m, s, logStart, q, gotLocal, wantLocal)
					}
					physIdx := off + gotLocal
					if physIdx < off || physIdx >= off+m || physIdx >= totalPixels {
						t.Fatalf("physIdx=%d out of sub-region bounds [%d, %d)", physIdx, off, off+m)
					}
					if physVisited[physIdx] {
						t.Fatalf("totalPixels=%d: duplicate physical pixel %d", totalPixels, physIdx)
					}
					physVisited[physIdx] = true
				}
			}
			if sumSize != totalPixels || sched.logOff[sched.k] != totalPixels {
				t.Fatalf("totalPixels=%d: sumSize=%d logOff[k]=%d", totalPixels, sumSize, sched.logOff[sched.k])
			}
			for i, v := range physVisited {
				if !v {
					t.Fatalf("totalPixels=%d: unvisited physical pixel %d", totalPixels, i)
				}
			}
		}
	}
}

func TestLayerIILaneDesyncInvariants(t *testing.T) {
	rng := rand.New(rand.NewSource(0xDE594C03))
	chunkCounts := []int{2, 3, 7, 15, 16, 17, 64, 137, 398, 480, 1395, 8500}

	for _, slotBytes := range []int{2, 7} {
		for _, m := range chunkCounts {
			trials := 32
			if m >= 8000 {
				trials = 4
			}
			for trial := 0; trial < trials; trial++ {
				var w [4]uint64
				for i := range w {
					w[i] = rng.Uint64()
				}
				sched := buildLaneDesyncSchedule(m, w)
				if sched.betas[0] == sched.betas[1] {
					t.Fatalf("m=%d: beta0 (%d) == beta1 (%d)", m, sched.betas[0], sched.betas[1])
				}

				bp := lockBatchPRF48{
					desyncWords: func() [4]uint64 { return w },
				}
				laneBytes := m * slotBytes
				orig0 := make([]byte, laneBytes)
				orig1 := make([]byte, laneBytes)
				orig2 := make([]byte, laneBytes)
				for j := 0; j < m; j++ {
					// Stamp unique slot markers into orig0 and orig1 to verify Sigma_0(j) != Sigma_1(j).
					orig0[j*slotBytes] = byte(j + 1)
					orig0[j*slotBytes+1] = byte((j + 1) >> 8)
					orig1[j*slotBytes] = byte(j + 1)
					orig1[j*slotBytes+1] = byte((j + 1) >> 8)
					for b := 2; b < slotBytes; b++ {
						orig0[j*slotBytes+b] = byte(rng.Intn(256))
						orig1[j*slotBytes+b] = orig0[j*slotBytes+b]
					}
					for b := 0; b < slotBytes; b++ {
						orig2[j*slotBytes+b] = byte(rng.Intn(256))
					}
				}

				p0 := bytes.Clone(orig0)
				p1 := bytes.Clone(orig1)
				p2 := bytes.Clone(orig2)
				desyncLaneEncrypt(p0, p1, p2, slotBytes, bp)

				// Since orig0 and orig1 carried identical slot markers at every chunk j,
				// Sigma_0(j) != Sigma_1(j) for all j < m means no slot y has identical
				// 2-byte chunk ID in both p0 and p1.
				if m < 65535 {
					for y := 0; y < m; y++ {
						id0 := uint16(p0[y*slotBytes]) | uint16(p0[y*slotBytes+1])<<8
						id1 := uint16(p1[y*slotBytes]) | uint16(p1[y*slotBytes+1])<<8
						if id0 == id1 {
							t.Fatalf("slotBytes=%d m=%d slot=%d: co-indexed chunk %d in lane 0 and lane 1", slotBytes, m, y, id0)
						}
					}
				}

				// Verify single-pass desyncLaneDecryptOne matches the reference two-pass inverse.
				if sched.kLane > 0 {
					tmp := make([]byte, laneBytes)
					refOut := make([]byte, laneBytes)
					for l, src := range [3][]byte{p0, p1, p2} {
						for step := 0; step < sched.kLane; step++ {
							mk := sched.size[step]
							logStart := sched.logOff[step] * slotBytes
							logEnd := (sched.logOff[step] + mk) * slotBytes
							physStart := sched.offset[step] * slotBytes
							physEnd := (sched.offset[step] + mk) * slotBytes
							shiftSlotsInverse(tmp[logStart:logEnd], src[physStart:physEnd], mk, sched.start[step], slotBytes)
						}
						shiftSlotsInverse(refOut, tmp, m, sched.betas[l], slotBytes)
						want := [3][]byte{orig0, orig1, orig2}[l]
						if !bytes.Equal(refOut, want) {
							t.Fatalf("slotBytes=%d m=%d lane=%d: two-pass reference mismatch", slotBytes, m, l)
						}
					}
				}

				snap0, snap1, snap2 := bytes.Clone(p0), bytes.Clone(p1), bytes.Clone(p2)
				u0, u1, u2, ptr, buf := desyncLaneDecrypt(p0, p1, p2, slotBytes, bp)
				if !bytes.Equal(u0, orig0) || !bytes.Equal(u1, orig1) || !bytes.Equal(u2, orig2) {
					if ptr != nil {
						releaseDesyncStage(ptr, buf)
					}
					t.Fatalf("slotBytes=%d m=%d: desyncLaneDecrypt failed to invert desyncLaneEncrypt", slotBytes, m)
				}
				if ptr != nil {
					releaseDesyncStage(ptr, buf)
				}
				if !bytes.Equal(p0, snap0) || !bytes.Equal(p1, snap1) || !bytes.Equal(p2, snap2) {
					t.Fatalf("slotBytes=%d m=%d: desyncLaneDecrypt mutated caller input slices", slotBytes, m)
				}
			}
		}
	}
}

func TestLayerISubregionsRangeBitExactParity(t *testing.T) {
	rng := rand.New(rand.NewSource(0xDE594C05))
	n128, _, d1_128, _, _, s1_128, _, _ := makeEightSeeds128(512, sipHash128)
	n256, _, d1_256, _, _, s1_256, _, _ := makeEightSeeds256(512, makeBlake3Hash256())
	n512, _, d1_512, _, _, s1_512, _, _ := makeEightSeeds512(512, makeBlake2bHash512())

	nonce := make([]byte, NonceSize)
	rng.Read(nonce)

	for _, totalPixels := range []int{147, 408} {
		dataBytes := (totalPixels * DataBitsPerPixel) / 8
		totalBits := dataBytes * 8
		plain := make([]byte, dataBytes)
		rng.Read(plain)
		origContainer := make([]byte, totalPixels*Channels)
		rng.Read(origContainer)

		sp128 := s1_128.deriveStartPixel(nonce, totalPixels)
		sched128 := s1_128.deriveSubregionSchedule(nonce, sp128, totalPixels)
		sp256 := s1_256.deriveStartPixel(nonce, totalPixels)
		sched256 := s1_256.deriveSubregionSchedule(nonce, sp256, totalPixels)
		sp512 := s1_512.deriveStartPixel(nonce, totalPixels)
		sched512 := s1_512.deriveSubregionSchedule(nonce, sp512, totalPixels)

		// Reference per-step encode via processChunk{128,256,512}
		ref128 := bytes.Clone(origContainer)
		ref256 := bytes.Clone(origContainer)
		ref512 := bytes.Clone(origContainer)
		for step := 0; step < sched128.k; step++ {
			m := sched128.size[step]
			off := sched128.offset[step]
			logStart := sched128.logOff[step]
			logEnd := sched128.logOff[step+1]
			eff := effectiveStartPixel(m, sched128.start[step], logStart)
			processChunk128(nil, n128, d1_128, nonce, ref128[off*Channels:(off+m)*Channels], plain, eff, m, logStart, logEnd, totalBits, 512, true, 0)
		}
		for step := 0; step < sched256.k; step++ {
			m := sched256.size[step]
			off := sched256.offset[step]
			logStart := sched256.logOff[step]
			logEnd := sched256.logOff[step+1]
			eff := effectiveStartPixel(m, sched256.start[step], logStart)
			processChunk256(nil, n256, d1_256, nonce, ref256[off*Channels:(off+m)*Channels], plain, eff, m, logStart, logEnd, totalBits, 512, true, 0)
		}
		for step := 0; step < sched512.k; step++ {
			m := sched512.size[step]
			off := sched512.offset[step]
			logStart := sched512.logOff[step]
			logEnd := sched512.logOff[step+1]
			eff := effectiveStartPixel(m, sched512.start[step], logStart)
			processChunk512(nil, n512, d1_512, nonce, ref512[off*Channels:(off+m)*Channels], plain, eff, m, logStart, logEnd, totalBits, 512, true, 0)
		}

		for _, mb := range []int{512, 32, 13} {
			got128 := bytes.Clone(origContainer)
			got256 := bytes.Clone(origContainer)
			got512 := bytes.Clone(origContainer)
			mid := totalPixels / 2
			processSubregionsRange128(nil, n128, d1_128, nonce, got128, plain, &sched128, 0, mid, totalBits, mb, true, 0)
			processSubregionsRange128(nil, n128, d1_128, nonce, got128, plain, &sched128, mid, totalPixels, totalBits, mb, true, 0)
			if !bytes.Equal(got128, ref128) {
				t.Fatalf("128-bit totalPixels=%d mb=%d: processSubregionsRange128 encode mismatch vs per-step reference", totalPixels, mb)
			}

			processSubregionsRange256(nil, n256, d1_256, nonce, got256, plain, &sched256, 0, mid, totalBits, mb, true, 0)
			processSubregionsRange256(nil, n256, d1_256, nonce, got256, plain, &sched256, mid, totalPixels, totalBits, mb, true, 0)
			if !bytes.Equal(got256, ref256) {
				t.Fatalf("256-bit totalPixels=%d mb=%d: processSubregionsRange256 encode mismatch vs per-step reference", totalPixels, mb)
			}

			processSubregionsRange512(nil, n512, d1_512, nonce, got512, plain, &sched512, 0, mid, totalBits, mb, true, 0)
			processSubregionsRange512(nil, n512, d1_512, nonce, got512, plain, &sched512, mid, totalPixels, totalBits, mb, true, 0)
			if !bytes.Equal(got512, ref512) {
				t.Fatalf("512-bit totalPixels=%d mb=%d: processSubregionsRange512 encode mismatch vs per-step reference", totalPixels, mb)
			}

			dec128 := make([]byte, dataBytes)
			dec256 := make([]byte, dataBytes)
			dec512 := make([]byte, dataBytes)
			processSubregionsRange128(nil, n128, d1_128, nonce, got128, dec128, &sched128, 0, totalPixels, totalBits, mb, false, 0)
			processSubregionsRange256(nil, n256, d1_256, nonce, got256, dec256, &sched256, 0, totalPixels, totalBits, mb, false, 0)
			processSubregionsRange512(nil, n512, d1_512, nonce, got512, dec512, &sched512, 0, totalPixels, totalBits, mb, false, 0)
			if !bytes.Equal(dec128, plain) || !bytes.Equal(dec256, plain) || !bytes.Equal(dec512, plain) {
				t.Fatalf("totalPixels=%d mb=%d: processSubregionsRange decode roundtrip failed", totalPixels, mb)
			}
		}
	}
}

func TestDesyncRoundtripAndModeIncompatibility(t *testing.T) {
	rng := rand.New(rand.NewSource(0xDE594C04))
	plain := make([]byte, 777)
	rng.Read(plain)

	var macKey [32]byte
	rng.Read(macKey[:])
	macFn := func(msg []byte) []byte {
		var out [32]byte
		for i, b := range msg {
			out[i&31] ^= b ^ macKey[(i*7)&31]
		}
		return out[:]
	}

	n128, l128, d1_128, d2_128, d3_128, s1_128, s2_128, s3_128 := makeEightSeeds128(512, sipHash128)
	n256, l256, d1_256, d2_256, d3_256, s1_256, s2_256, s3_256 := makeEightSeeds256(512, makeBlake3Hash256())
	n512, l512, d1_512, d2_512, d3_512, s1_512, s2_512, s3_512 := makeEightSeeds512(512, makeBlake2bHash512())
	s128 := [8]*Seed128{n128, l128, d1_128, d2_128, d3_128, s1_128, s2_128, s3_128}
	s256 := [8]*Seed256{n256, l256, d1_256, d2_256, d3_256, s1_256, s2_256, s3_256}
	s512 := [8]*Seed512{n512, l512, d1_512, d2_512, d3_512, s1_512, s2_512, s3_512}

	for _, cm := range []int{1, 2} {
		cfg := &Config{
			NonceBits:   DefaultNonceBits,
			BarrierFill: DefaultBarrierFill,
			Mode:        cm,
			MaxWorkers:  4,
		}

		// 128-bit Authenticated (Desync ON vs OFF)
		t.Setenv("ITB_BARRIERS_DESYNC", "on")
		ct128On, err := EncryptAuthenticated3x128Cfg(cfg, s128[0], s128[1], s128[2], s128[3], s128[4], s128[5], s128[6], s128[7], plain, macFn)
		if err != nil {
			t.Fatalf("EncryptAuthenticated3x128Cfg (on): %v", err)
		}
		dec128On, err := DecryptAuthenticated3x128Cfg(cfg, s128[0], s128[1], s128[2], s128[3], s128[4], s128[5], s128[6], s128[7], ct128On, macFn)
		if err != nil || !bytes.Equal(dec128On, plain) {
			t.Fatalf("DecryptAuthenticated3x128Cfg (on->on): err=%v", err)
		}

		t.Setenv("ITB_BARRIERS_DESYNC", "off")
		if _, err := DecryptAuthenticated3x128Cfg(cfg, s128[0], s128[1], s128[2], s128[3], s128[4], s128[5], s128[6], s128[7], ct128On, macFn); !errors.Is(err, ErrMACFailure) {
			t.Fatalf("DecryptAuthenticated3x128Cfg (on->off): got err=%v, want ErrMACFailure", err)
		}
		ct128Off, err := EncryptAuthenticated3x128Cfg(cfg, s128[0], s128[1], s128[2], s128[3], s128[4], s128[5], s128[6], s128[7], plain, macFn)
		if err != nil {
			t.Fatalf("EncryptAuthenticated3x128Cfg (off): %v", err)
		}
		dec128Off, err := DecryptAuthenticated3x128Cfg(cfg, s128[0], s128[1], s128[2], s128[3], s128[4], s128[5], s128[6], s128[7], ct128Off, macFn)
		if err != nil || !bytes.Equal(dec128Off, plain) {
			t.Fatalf("DecryptAuthenticated3x128Cfg (off->off): err=%v", err)
		}
		t.Setenv("ITB_BARRIERS_DESYNC", "on")
		if _, err := DecryptAuthenticated3x128Cfg(cfg, s128[0], s128[1], s128[2], s128[3], s128[4], s128[5], s128[6], s128[7], ct128Off, macFn); !errors.Is(err, ErrMACFailure) {
			t.Fatalf("DecryptAuthenticated3x128Cfg (off->on): got err=%v, want ErrMACFailure", err)
		}

		// 256-bit Single Message
		ct256On, err := Encrypt3x256Cfg(cfg, s256[0], s256[1], s256[2], s256[3], s256[4], s256[5], s256[6], s256[7], plain)
		if err != nil {
			t.Fatalf("Encrypt3x256Cfg (on): %v", err)
		}
		dec256On, err := Decrypt3x256Cfg(cfg, s256[0], s256[1], s256[2], s256[3], s256[4], s256[5], s256[6], s256[7], ct256On)
		if err != nil || !bytes.Equal(dec256On, plain) {
			t.Fatalf("Decrypt3x256Cfg (on->on): err=%v", err)
		}
		t.Setenv("ITB_BARRIERS_DESYNC", "off")
		dec256Mismatch, _ := Decrypt3x256Cfg(cfg, s256[0], s256[1], s256[2], s256[3], s256[4], s256[5], s256[6], s256[7], ct256On)
		if bytes.Equal(dec256Mismatch, plain) {
			t.Fatalf("Decrypt3x256Cfg (on->off) unexpectedly recovered plaintext")
		}

		// 512-bit Interlock 168
		t.Setenv("ITB_BARRIERS_DESYNC", "on")
		cfg168 := &Config{
			NonceBits:   DefaultNonceBits,
			BarrierFill: DefaultBarrierFill,
			Mode:        cm,
			MaxWorkers:  4,
			Interlock:   Interlock168,
		}
		ct512On, err := EncryptAuthenticated3x512Cfg(cfg168, s512[0], s512[1], s512[2], s512[3], s512[4], s512[5], s512[6], s512[7], plain, macFn)
		if err != nil {
			t.Fatalf("EncryptAuthenticated3x512Cfg 168 (on): %v", err)
		}
		dec512On, err := DecryptAuthenticated3x512Cfg(cfg168, s512[0], s512[1], s512[2], s512[3], s512[4], s512[5], s512[6], s512[7], ct512On, macFn)
		if err != nil || !bytes.Equal(dec512On, plain) {
			t.Fatalf("DecryptAuthenticated3x512Cfg 168 (on->on): err=%v", err)
		}
		t.Setenv("ITB_BARRIERS_DESYNC", "off")
		if _, err := DecryptAuthenticated3x512Cfg(cfg168, s512[0], s512[1], s512[2], s512[3], s512[4], s512[5], s512[6], s512[7], ct512On, macFn); !errors.Is(err, ErrMACFailure) {
			t.Fatalf("DecryptAuthenticated3x512Cfg 168 (on->off): got err=%v, want ErrMACFailure", err)
		}
	}
}

func TestDesyncPreBodyWipePreventsStackSplit(t *testing.T) {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	defer pixelWipeObserver.Store(nil)

	s128 := &Seed128{
		Components: []uint64{1, 2, 3, 4, 5, 6, 7, 8},
		Hash: func(data []byte, s0, s1 uint64) (uint64, uint64) {
			return s0 ^ 0x1111, s1 ^ 0x2222
		},
	}
	s256 := &Seed256{
		Components: []uint64{1, 2, 3, 4, 5, 6, 7, 8},
		Hash: func(data []byte, s [4]uint64) [4]uint64 {
			return [4]uint64{s[0] ^ 1, s[1] ^ 2, s[2] ^ 3, s[3] ^ 4}
		},
	}
	s512 := &Seed512{
		Components: []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Hash: func(data []byte, s [8]uint64) [8]uint64 {
			return [8]uint64{s[0] ^ 1, s[1] ^ 2, s[2] ^ 3, s[3] ^ 4, s[4] ^ 5, s[5] ^ 6, s[6] ^ 7, s[7] ^ 8}
		},
	}
	nonce := make([]byte, NonceSize)
	bp := buildLockBatchPRF48_128(s128, nonce)
	defer bp.wipe()

	cases := []struct {
		name string
		fn   func()
	}{
		{"Seed128.deriveSubregionSchedule", func() { _ = s128.deriveSubregionSchedule(nonce, 0, 408) }},
		{"Seed256.deriveSubregionSchedule", func() { _ = s256.deriveSubregionSchedule(nonce, 0, 408) }},
		{"Seed512.deriveSubregionSchedule", func() { _ = s512.deriveSubregionSchedule(nonce, 0, 408) }},
		{"evalDesyncWords", func() { _ = evalDesyncWords(bp) }},
	}

	for _, tc := range cases {
		var sps []uintptr
		cb := func(sp uintptr) {
			sps = append(sps, sp)
		}
		pixelWipeObserver.Store(&cb)
		done := make(chan struct{})
		go func() {
			defer close(done)
			tc.fn()
		}()
		<-done
		if len(sps) != 2 {
			t.Fatalf("%s: expected 2 wipePixelCallStack invocations (pre-Body and post-Body), got %d", tc.name, len(sps))
		}
		if sps[0] != sps[1] {
			t.Fatalf("%s: goroutine stack split between pre-Body wipe (%#x) and post-Body wipe (%#x)", tc.name, sps[0], sps[1])
		}
	}
}
