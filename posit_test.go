// Unit, invariant, and full-pipeline integration tests for posit64(es), the
// 512-bit quire512 accumulator, Gauss circle chord sub-region scheduling, and
// Mode 3 container sizing across 128/256/512-bit Single Message and Streaming
// modes.

package itb

import (
	"bytes"
	"math"
	"math/bits"
	"math/rand"
	"testing"
)

func TestPositSpecialValuesAndAlgebraicInvariants(t *testing.T) {
	for _, es := range []uint{1, 2, 3} {
		// NaR propagation across all operations.
		for _, x := range []posit64{positZero, positOne, positMin, positMax, positNaR} {
			if got := positAdd(positNaR, x, es); got != positNaR {
				t.Fatalf("es=%d positAdd(NaR, 0x%016x) = 0x%016x, want NaR", es, x, got)
			}
			if got := positAdd(x, positNaR, es); got != positNaR {
				t.Fatalf("es=%d positAdd(0x%016x, NaR) = 0x%016x, want NaR", es, x, got)
			}
			if got := positSub(positNaR, x, es); got != positNaR {
				t.Fatalf("es=%d positSub(NaR, 0x%016x) = 0x%016x, want NaR", es, x, got)
			}
			if got := positMul(positNaR, x, es); got != positNaR {
				t.Fatalf("es=%d positMul(NaR, 0x%016x) = 0x%016x, want NaR", es, x, got)
			}
			if got := positDiv(positNaR, x, es); got != positNaR {
				t.Fatalf("es=%d positDiv(NaR, 0x%016x) = 0x%016x, want NaR", es, x, got)
			}
			if got := positDiv(x, positZero, es); got != positNaR {
				t.Fatalf("es=%d positDiv(0x%016x, 0) = 0x%016x, want NaR", es, x, got)
			}
		}
		if got := positSqrt(positNaR, es); got != positNaR {
			t.Fatalf("es=%d positSqrt(NaR) = 0x%016x, want NaR", es, got)
		}
		if got := positSqrt(positNeg(positOne), es); got != positNaR {
			t.Fatalf("es=%d positSqrt(-1) = 0x%016x, want NaR", es, got)
		}
		if got := positSqrt(positZero, es); got != positZero {
			t.Fatalf("es=%d positSqrt(0) = 0x%016x, want 0", es, got)
		}
		if got := positSqrt(positOne, es); got != positOne {
			t.Fatalf("es=%d positSqrt(1) = 0x%016x, want positOne", es, got)
		}

		// No-overflow saturation at positMax / -positMax and no-underflow saturation at positMin / -positMin.
		if got := positMul(positMax, positMax, es); got != positMax {
			t.Fatalf("es=%d positMul(positMax, positMax) = 0x%016x, want positMax", es, got)
		}
		if got := positMul(positMax, positNeg(positMax), es); got != positNeg(positMax) {
			t.Fatalf("es=%d positMul(positMax, -positMax) = 0x%016x, want -positMax", es, got)
		}
		if got := positMul(positMin, positMin, es); got != positMin {
			t.Fatalf("es=%d positMul(positMin, positMin) = 0x%016x, want positMin", es, got)
		}
		if got := positMul(positMin, positNeg(positMin), es); got != positNeg(positMin) {
			t.Fatalf("es=%d positMul(positMin, -positMin) = 0x%016x, want -positMin", es, got)
		}
	}

	// positIsqrt128 boundary verification: exact squares vs non-squares in [2^126, 2^128).
	roots := []uint64{
		1 << 63,
		(1 << 63) + 1,
		(1 << 63) + 0x123456789abcdef,
		math.MaxUint64 - 1,
		math.MaxUint64,
	}
	for _, r := range roots {
		sqHi, sqLo := bits.Mul64(r, r)
		gotR, gotSticky := positIsqrt128(sqHi, sqLo)
		if gotR != r || gotSticky != 0 {
			t.Fatalf("positIsqrt128(%#x^2): got (%#x, %d), want (%#x, 0)", r, gotR, gotSticky, r)
		}
		// Add 1 to sqLo (still same integer floor root r, but non-zero remainder -> sticky == 1).
		pLo, carry := bits.Add64(sqLo, 1, 0)
		pHi := sqHi + carry
		gotR2, gotSticky2 := positIsqrt128(pHi, pLo)
		if gotR2 != r || gotSticky2 != 1 {
			t.Fatalf("positIsqrt128(%#x^2 + 1): got (%#x, %d), want (%#x, 1)", r, gotR2, gotSticky2, r)
		}
	}
}

func TestPositGaussCircleFloorAndContainerSizes(t *testing.T) {
	// Verify canonical Mode 3 container floor values for 512, 1024, and 2048-bit keys.
	cases := []struct {
		keyBits      int
		minPx        int
		wantFloor    int
		wantSideBF1  int
		mode2SideBF1 int
		mode1SideBF1 int
	}{
		{keyBits: 512, minPx: 183, wantFloor: 350, wantSideBF1: 20, mode2SideBF1: 15, mode1SideBF1: 25},
		{keyBits: 1024, minPx: 365, wantFloor: 698, wantSideBF1: 28, mode2SideBF1: 21, mode1SideBF1: 35},
		{keyBits: 2048, minPx: 730, wantFloor: 1395, wantSideBF1: 39, mode2SideBF1: 29, mode1SideBF1: 48},
	}

	for _, tc := range cases {
		gotFloor := positGaussCircleFloor(3 * tc.minPx)
		if gotFloor != tc.wantFloor {
			t.Fatalf("KeyBits=%d (minPx=%d): positGaussCircleFloor(%d) = %d, want %d",
				tc.keyBits, tc.minPx, 3*tc.minPx, gotFloor, tc.wantFloor)
		}
		minArr := [3]int{tc.minPx, tc.minPx, tc.minPx}
		cobs := [3]int{10, 10, 10}
		w1, h1 := calcContainerSize3Cfg(&Config{Mode: 1, BarrierFill: 1}, cobs, tc.minPx, minArr, minArr)
		w2, h2 := calcContainerSize3Cfg(&Config{Mode: 2, BarrierFill: 1}, cobs, tc.minPx, minArr, minArr)
		w3, h3 := calcContainerSize3Cfg(&Config{Mode: 3, BarrierFill: 1}, cobs, tc.minPx, minArr, minArr)
		if w1 != h1 || w2 != h2 || w3 != h3 {
			t.Fatalf("non-square container: (%d,%d), (%d,%d), (%d,%d)", w1, h1, w2, h2, w3, h3)
		}
		if w1 != tc.mode1SideBF1 || w2 != tc.mode2SideBF1 || w3 != tc.wantSideBF1 {
			t.Fatalf("KeyBits=%d sides: Mode1=%d, Mode2=%d, Mode3=%d; want %d, %d, %d",
				tc.keyBits, w1, w2, w3, tc.mode1SideBF1, tc.mode2SideBF1, tc.wantSideBF1)
		}
		if !(w2 < w3 && w3 < w1) {
			t.Fatalf("KeyBits=%d: want strict ordering Mode2 (%d) < Mode3 (%d) < Mode1 (%d)",
				tc.keyBits, w2, w3, w1)
		}
	}

	// Verify positDeriveSecretPi sensitivity to w[0] and w[2..7].
	baseW := [8]uint64{
		0x123456789abcdef0,
		0x0fedcba987654321,
		0xa1b2c3d4e5f60718,
		0x1807f6e5d4c3b2a1,
		0x5555aaaa5555aaaa,
		0xaaaa5555aaaa5555,
		0x0123456789abcdef,
		0xfedcba9876543210,
	}
	basePi, baseEs := positDeriveSecretPi(baseW)
	if baseEs < 1 || baseEs > 3 {
		t.Fatalf("positDeriveSecretPi es = %d, want in {1, 2, 3}", baseEs)
	}
	// Perturbing upper bits of w[2], w[3], w[6], or w[7] must alter pi_{K,r}.
	for _, idx := range []int{2, 3, 6, 7} {
		wMod := baseW
		wMod[idx] ^= uint64(1) << 48
		piMod, esMod := positDeriveSecretPi(wMod)
		if esMod != baseEs {
			t.Fatalf("modifying w[%d] changed es from %d to %d", idx, baseEs, esMod)
		}
		if piMod == basePi {
			t.Fatalf("modifying bit 48 of w[%d] left pi_{K,r} unchanged (0x%016x)", idx, basePi)
		}
	}
}

func TestPositSubregionScheduleInvariantsAndFloat64Divergence(t *testing.T) {
	rng := rand.New(rand.NewSource(0x1E3779B97F4A7C15))
	regionSizes := []int{61, 122, 183, 233, 365, 465, 730, 1225, 2400}

	float64Diverged := 0
	totalTrials := 0

	for _, totalPixels := range regionSizes {
		for trial := 0; trial < 80; trial++ {
			totalTrials++
			var w [8]uint64
			for i := range w {
				w[i] = rng.Uint64()
			}
			startPixel := rng.Intn(totalPixels)
			sched := buildSubregionSchedulePosit(startPixel, totalPixels, w)

			if totalPixels < mode1DesyncRegionPixels {
				if sched.k < 6 || sched.k > 10 {
					t.Fatalf("totalPixels=%d: sched.k=%d outside [6, 10]", totalPixels, sched.k)
				}
			} else {
				if sched.k < 8 || sched.k > 16 {
					t.Fatalf("totalPixels=%d: sched.k=%d outside [8, 16]", totalPixels, sched.k)
				}
			}

			// Verify telescopic partition sum(M_j) == totalPixels, M_j >= 2,
			// and bijective coverage of [0, totalPixels).
			visited := make([]bool, totalPixels)
			sumM := 0
			for step := 0; step < sched.k; step++ {
				m := sched.size[step]
				off := sched.offset[step]
				st := sched.start[step]
				logOff := sched.logOff[step]

				if m < 2 {
					t.Fatalf("totalPixels=%d step=%d: size=%d < 2", totalPixels, step, m)
				}
				if logOff != sumM {
					t.Fatalf("totalPixels=%d step=%d: logOff=%d != running sum %d", totalPixels, step, logOff, sumM)
				}
				if st < 0 || st >= m {
					t.Fatalf("totalPixels=%d step=%d: start=%d outside [0, %d)", totalPixels, step, st, m)
				}
				for i := 0; i < m; i++ {
					px := off + (st+i)%m
					if px < 0 || px >= totalPixels {
						t.Fatalf("totalPixels=%d: pixel %d out of range", totalPixels, px)
					}
					if visited[px] {
						t.Fatalf("totalPixels=%d: duplicate pixel %d", totalPixels, px)
					}
					visited[px] = true
				}
				sumM += m
			}
			if sumM != totalPixels || sched.logOff[sched.k] != totalPixels {
				t.Fatalf("totalPixels=%d: sum(M_j)=%d (logOff[k]=%d) != totalPixels", totalPixels, sumM, sched.logOff[sched.k])
			}
			for px, ok := range visited {
				if !ok {
					t.Fatalf("totalPixels=%d: pixel %d not visited", totalPixels, px)
				}
			}

			// Compare chord lengths against an IEEE-754 float64 approximation of the same Gauss circle formula.
			piK, es := positDeriveSecretPi(w)
			sign, _, _, scPi, mPi := positDecode64(piK, es)
			_ = sign
			piF64 := math.Ldexp(float64(mPi), scPi-63)
			rF64 := float64(totalPixels) * piF64
			phase := uint64((w[0] >> 44) & 63)
			flip := ((w[0] >> 52) & 1) != 0
			denF64 := float64(64*sched.k + 32)

			var chordsPosit, chordsF64 [maxDesyncSubregions]uint64
			pTotal := positFromUint64(uint64(totalPixels), es)
			radius := positMul(pTotal, piK, es)
			denPosit := positFromUint64(uint64(64*sched.k+32), es)
			for j := 0; j < sched.k; j++ {
				idx := j
				if flip {
					idx = sched.k - 1 - j
				}
				num := uint64(64*idx+16) + phase
				y := positDiv(positMul(radius, positFromUint64(num, es), es), denPosit, es)
				var q quire512
				q.addProduct(radius, radius, es)
				q.subProduct(y, y, es)
				cPosit := positSqrt(q.toPosit(es), es)
				cBits := uint64(cPosit)
				cFold := cBits ^ (cBits >> 13) ^ (cBits >> 27) ^ (cBits >> 41) ^ (cBits >> 53)
				chordsPosit[j] = positFloorUint64(cPosit, es) + 1 + (cFold & 7)

				yF64 := (rF64 * float64(num)) / denF64
				cF64 := math.Sqrt(rF64*rF64 - yF64*yF64)
				cF64Bits := math.Float64bits(cF64)
				cF64Fold := cF64Bits ^ (cF64Bits >> 13) ^ (cF64Bits >> 27) ^ (cF64Bits >> 41) ^ (cF64Bits >> 53)
				chordsF64[j] = uint64(math.Floor(cF64)) + 1 + (cF64Fold & 7)
			}
			if chordsPosit != chordsF64 {
				float64Diverged++
			}

			// Verify true Gauss semicircle geometry: the equatorial chord
			// exceeds the polar chord by > 1.5x (and reverses under flip).
			if !flip {
				if chordsPosit[0]*2 <= chordsPosit[sched.k-1]*3 {
					t.Fatalf("flip=false: equatorial chord %d not > 1.5x polar chord %d", chordsPosit[0], chordsPosit[sched.k-1])
				}
			} else {
				if chordsPosit[sched.k-1]*2 <= chordsPosit[0]*3 {
					t.Fatalf("flip=true: equatorial chord %d not > 1.5x polar chord %d", chordsPosit[sched.k-1], chordsPosit[0])
				}
			}

			// Verify toggling the flip bit (w[0] bit 52) strictly changes the schedule.
			wFlip := w
			wFlip[0] ^= 1 << 52
			schedFlip := buildSubregionSchedulePosit(startPixel, totalPixels, wFlip)
			if schedFlip == sched {
				t.Fatalf("toggling flip bit (w[0] bit 52) did not change schedule for totalPixels=%d", totalPixels)
			}
		}
	}

	if float64Diverged == 0 {
		t.Fatalf("expected IEEE-754 float64 chord calculation to diverge from posit64+quire512 across %d trials", totalTrials)
	}
}

func TestMode3RoundTripAllWidthsAndModes(t *testing.T) {
	payloads := [][]byte{
		[]byte("a"),
		[]byte("Gauss-Posit Mode 3 Inscribed Circle & Quire512 Chord Slicing!"),
		bytes.Repeat([]byte{0x00, 0xFF, 0xA5, 0x5A, 0x3C}, 400),
	}
	mac := macFuncForTest([32]byte{0x11, 0x22, 0x33, 0x44})

	// 1. 128-bit Single Message (No MAC + MAC) & Streaming (No MAC + AEAD)
	t.Run("128bit", func(t *testing.T) {
		ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
		cfg3 := &Config{Mode: 3, MaxWorkers: 1}
		cfg3Par := &Config{Mode: 3, MaxWorkers: 4}

		for _, msg := range payloads {
			ct, err := Encrypt3x128Cfg(cfg3, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, msg)
			if err != nil {
				t.Fatalf("Encrypt3x128Cfg(Mode=3): %v", err)
			}
			pt, err := Decrypt3x128Cfg(cfg3Par, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct)
			if err != nil || !bytes.Equal(pt, msg) {
				t.Fatalf("Decrypt3x128Cfg(Mode=3) mismatch: err=%v", err)
			}

			// Mode 1 and Mode 2 decryptors must NOT recover the Mode 3 plaintext.
			if pt1, err1 := Decrypt3x128Cfg(&Config{Mode: 1}, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct); err1 == nil && bytes.Equal(pt1, msg) {
				t.Fatal("Mode 1 decryptor unexpectedly recovered Mode 3 ciphertext")
			}
			if pt2, err2 := Decrypt3x128Cfg(&Config{Mode: 2}, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct); err2 == nil && bytes.Equal(pt2, msg) {
				t.Fatal("Mode 2 decryptor unexpectedly recovered Mode 3 ciphertext")
			}

			ctMAC, err := EncryptAuthenticated3x128Cfg(cfg3, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, msg, mac)
			if err != nil {
				t.Fatalf("EncryptAuthenticated3x128Cfg(Mode=3): %v", err)
			}
			ptMAC, err := DecryptAuthenticated3x128Cfg(cfg3Par, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ctMAC, mac)
			if err != nil || !bytes.Equal(ptMAC, msg) {
				t.Fatalf("DecryptAuthenticated3x128Cfg(Mode=3) mismatch: err=%v", err)
			}
			if _, err := DecryptAuthenticated3x128Cfg(&Config{Mode: 2}, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ctMAC, mac); err == nil {
				t.Fatal("Mode 2 MAC decryptor unexpectedly verified Mode 3 ciphertext")
			}
		}

		// Streaming No MAC + Streaming AEAD
		streamMsg := bytes.Repeat([]byte("Mode3-Stream128-"), 300)
		var encBuf, decBuf bytes.Buffer
		if err := EncryptStream3xCfg(cfg3, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(streamMsg), &encBuf, 1024); err != nil {
			t.Fatalf("EncryptStream3xCfg(128, Mode=3): %v", err)
		}
		if err := DecryptStream3xCfg(cfg3Par, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(encBuf.Bytes()), &decBuf); err != nil {
			t.Fatalf("DecryptStream3xCfg(128, Mode=3): %v", err)
		}
		if !bytes.Equal(decBuf.Bytes(), streamMsg) {
			t.Fatal("Stream3xCfg(128, Mode=3) plaintext mismatch")
		}

		encBuf.Reset()
		decBuf.Reset()
		if err := EncryptStreamAuth3xCfg(cfg3, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(streamMsg), &encBuf, mac, 1024); err != nil {
			t.Fatalf("EncryptStreamAuth3xCfg(128, Mode=3): %v", err)
		}
		if err := DecryptStreamAuth3xCfg(cfg3Par, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(encBuf.Bytes()), &decBuf, mac); err != nil {
			t.Fatalf("DecryptStreamAuth3xCfg(128, Mode=3): %v", err)
		}
		if !bytes.Equal(decBuf.Bytes(), streamMsg) {
			t.Fatal("StreamAuth3xCfg(128, Mode=3) plaintext mismatch")
		}
	})

	// 2. 256-bit Single Message (No MAC + MAC) & Streaming (No MAC + AEAD)
	t.Run("256bit", func(t *testing.T) {
		ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds256(512, makeBlake3Hash256())
		cfg3 := &Config{Mode: 3, MaxWorkers: 1}
		cfg3Par := &Config{Mode: 3, MaxWorkers: 4}

		for _, msg := range payloads {
			ct, err := Encrypt3x256Cfg(cfg3, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, msg)
			if err != nil {
				t.Fatalf("Encrypt3x256Cfg(Mode=3): %v", err)
			}
			pt, err := Decrypt3x256Cfg(cfg3Par, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct)
			if err != nil || !bytes.Equal(pt, msg) {
				t.Fatalf("Decrypt3x256Cfg(Mode=3) mismatch: err=%v", err)
			}

			ctMAC, err := EncryptAuthenticated3x256Cfg(cfg3, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, msg, mac)
			if err != nil {
				t.Fatalf("EncryptAuthenticated3x256Cfg(Mode=3): %v", err)
			}
			ptMAC, err := DecryptAuthenticated3x256Cfg(cfg3Par, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ctMAC, mac)
			if err != nil || !bytes.Equal(ptMAC, msg) {
				t.Fatalf("DecryptAuthenticated3x256Cfg(Mode=3) mismatch: err=%v", err)
			}
		}

		streamMsg := bytes.Repeat([]byte("Mode3-Stream256-"), 300)
		var encBuf, decBuf bytes.Buffer
		if err := EncryptStreamAuth3xCfg(cfg3, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(streamMsg), &encBuf, mac, 1024); err != nil {
			t.Fatalf("EncryptStreamAuth3xCfg(256, Mode=3): %v", err)
		}
		if err := DecryptStreamAuth3xCfg(cfg3Par, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(encBuf.Bytes()), &decBuf, mac); err != nil {
			t.Fatalf("DecryptStreamAuth3xCfg(256, Mode=3): %v", err)
		}
		if !bytes.Equal(decBuf.Bytes(), streamMsg) {
			t.Fatal("StreamAuth3xCfg(256, Mode=3) plaintext mismatch")
		}
	})

	// 3. 512-bit Single Message & Streaming across Interlock48 and Interlock168
	t.Run("512bit_Interlock48_and_168", func(t *testing.T) {
		ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds512(512, makeBlake2bHash512())

		for _, il := range []string{Interlock48, Interlock168} {
			cfg3 := &Config{Mode: 3, Interlock: il, MaxWorkers: 1}
			cfg3Par := &Config{Mode: 3, Interlock: il, MaxWorkers: 4}

			for _, msg := range payloads {
				ct, err := Encrypt3x512Cfg(cfg3, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, msg)
				if err != nil {
					t.Fatalf("il=%s Encrypt3x512Cfg(Mode=3): %v", il, err)
				}
				pt, err := Decrypt3x512Cfg(cfg3Par, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct)
				if err != nil || !bytes.Equal(pt, msg) {
					t.Fatalf("il=%s Decrypt3x512Cfg(Mode=3) mismatch: err=%v", il, err)
				}

				ctMAC, err := EncryptAuthenticated3x512Cfg(cfg3, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, msg, mac)
				if err != nil {
					t.Fatalf("il=%s EncryptAuthenticated3x512Cfg(Mode=3): %v", il, err)
				}
				ptMAC, err := DecryptAuthenticated3x512Cfg(cfg3Par, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ctMAC, mac)
				if err != nil || !bytes.Equal(ptMAC, msg) {
					t.Fatalf("il=%s DecryptAuthenticated3x512Cfg(Mode=3) mismatch: err=%v", il, err)
				}
			}

			streamMsg := bytes.Repeat([]byte("Mode3-Stream512-"), 300)
			var encBuf, decBuf bytes.Buffer
			if err := EncryptStreamAuth3xCfg(cfg3, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(streamMsg), &encBuf, mac, 1024); err != nil {
				t.Fatalf("il=%s EncryptStreamAuth3xCfg(512, Mode=3): %v", il, err)
			}
			if err := DecryptStreamAuth3xCfg(cfg3Par, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(encBuf.Bytes()), &decBuf, mac); err != nil {
				t.Fatalf("il=%s DecryptStreamAuth3xCfg(512, Mode=3): %v", il, err)
			}
			if !bytes.Equal(decBuf.Bytes(), streamMsg) {
				t.Fatalf("il=%s StreamAuth3xCfg(512, Mode=3) plaintext mismatch", il)
			}
		}
	})
}

func TestMode3BlobExportImportRoundTrip(t *testing.T) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds512(512, makeBlake2bHash512())
	var k [8][64]byte
	for i := range k {
		for b := range k[i] {
			k[i][b] = byte(i*17 + b + 1)
		}
	}

	// Export via Config{Mode: 3}
	cfgExport := &Config{
		NonceBits:   DefaultNonceBits,
		BarrierFill: DefaultBarrierFill,
		Mode:        3,
		Interlock:   Interlock168,
	}
	var bSrc Blob512
	raw, err := bSrc.Export3Cfg(cfgExport, k[0], k[2], k[3], k[4], k[5], k[6], k[7],
		ns, ds1, ds2, ds3, ss1, ss2, ss3, Blob512Opts{KeyL: k[1], LS: ls})
	if err != nil {
		t.Fatalf("Blob512.Export3Cfg(Config.Mode=3): %v", err)
	}
	if bSrc.Mode != 3 {
		t.Fatalf("bSrc.Mode = %d, want 3", bSrc.Mode)
	}

	var bDst Blob512
	var cfgImport Config
	if err := bDst.Import3Cfg(raw, &cfgImport); err != nil {
		t.Fatalf("Blob512.Import3Cfg(Mode=3): %v", err)
	}
	if bDst.Mode != 3 || cfgImport.Mode != 3 || cfgImport.Interlock != Interlock168 {
		t.Fatalf("imported Mode=(%d, %d) Interlock=%q, want 3 and 168", bDst.Mode, cfgImport.Mode, cfgImport.Interlock)
	}

	// Export via Blob512Opts{Mode: 3} overriding default Config{Mode: 0}
	var bSrc2 Blob512
	raw2, err := bSrc2.Export3Cfg(&Config{NonceBits: DefaultNonceBits, BarrierFill: DefaultBarrierFill},
		k[0], k[2], k[3], k[4], k[5], k[6], k[7],
		ns, ds1, ds2, ds3, ss1, ss2, ss3, Blob512Opts{KeyL: k[1], LS: ls, Mode: 3})
	if err != nil {
		t.Fatalf("Blob512.Export3Cfg(Opts.Mode=3): %v", err)
	}
	if bSrc2.Mode != 3 {
		t.Fatalf("bSrc2.Mode = %d, want 3", bSrc2.Mode)
	}
	var bDst2 Blob512
	var cfgImport2 Config
	if err := bDst2.Import3Cfg(raw2, &cfgImport2); err != nil {
		t.Fatalf("Blob512.Import3Cfg(Opts.Mode=3): %v", err)
	}
	if bDst2.Mode != 3 || cfgImport2.Mode != 3 {
		t.Fatalf("imported Opts.Mode=3 got (%d, %d)", bDst2.Mode, cfgImport2.Mode)
	}
}

func TestMode3DeterministicCrossArchKAT(t *testing.T) {
	w := [8]uint64{
		0x9182736455463728, 0xa293847566574839,
		0xb3a495867768594a, 0xc4b5a69788796a5b,
		0xd5c6b7a8998a7b6c, 0xe6d7c8b9aa9b8c7d,
		0xf7e8d9cabbad9d8e, 0x08f9eadbccbeae9f,
	}
	piK, es := positDeriveSecretPi(w)
	const wantPiK = posit64(0x5999c327a9c26320)
	const wantES = uint(1)
	if piK != wantPiK || es != wantES {
		t.Fatalf("positDeriveSecretPi KAT: got (0x%016x, es=%d), want (0x%016x, es=%d)", piK, es, wantPiK, wantES)
	}

	sched := buildSubregionSchedulePosit(17, 408, w)
	wantOff := [16]int{392, 256, 320, 289, 0, 188, 113, 74, 151, 371, 38, 220, 346}
	wantSize := [16]int{16, 33, 26, 31, 38, 32, 38, 39, 37, 21, 36, 36, 25}
	wantStart := [16]int{5, 15, 12, 23, 14, 11, 10, 0, 31, 13, 0, 15, 15}
	if sched.k != 13 || sched.offset != wantOff || sched.size != wantSize || sched.start != wantStart {
		t.Fatalf("buildSubregionSchedulePosit KAT mismatch:\n got k=%d off=%v size=%v start=%v\nwant k=13 off=%v size=%v start=%v",
			sched.k, sched.offset, sched.size, sched.start, wantOff, wantSize, wantStart)
	}

	// Verify deterministic byte-for-byte container encoding across 32/64-bit and LE/BE targets.
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(i*13 + 7)
	}
	plain := make([]byte, 98) // 98 * 8 = 784 bits = 28 * 28 bits (28 pixels)
	for i := range plain {
		plain[i] = byte(i*29 + 3)
	}
	container := make([]byte, 408*Channels)
	for i := range container {
		container[i] = byte(i*11 + 5)
	}
	cfg3 := &Config{Mode: 3}
	makeDetSeed512 := func(salt uint64) *Seed512 {
		c := make([]uint64, 16)
		for i := range c {
			c[i] = (uint64(i+1) * 0x9E3779B97F4A7C15) ^ salt
		}
		return &Seed512{
			Components: c,
			Hash: func(data []byte, s [8]uint64) [8]uint64 {
				var out [8]uint64
				for i := 0; i < 8; i++ {
					acc := s[i] ^ (uint64(i+1) * 0x517CC1B727220A95) ^ salt
					for _, b := range data {
						acc = bits.RotateLeft64(acc^uint64(b), 13) * 0xBF58476D1CE4E5B9
					}
					out[i] = acc ^ (acc >> 31)
				}
				return out
			},
		}
	}
	n512 := makeDetSeed512(0x1111222233334444)
	d512 := makeDetSeed512(0x5555666677778888)
	s512 := makeDetSeed512(0x9999AAAABBBBCCCC)
	totalBits := len(plain) * 8
	dataPixels := (totalBits + DataBitsPerPixel - 1) / DataBitsPerPixel
	processSubregions512(cfg3, n512, d512, s512, nonce, container, plain, 17, 408, dataPixels, totalBits, 512, true, 1, 0)

	var fnv uint64 = 14695981039346656037
	for _, b := range container {
		fnv = (fnv ^ uint64(b)) * 1099511628211
	}
	const wantFNV = uint64(0x1529417502f503b7)
	if fnv != wantFNV {
		t.Fatalf("processSubregions512(Mode=3) cross-arch FNV-1a = 0x%016x, want 0x%016x", fnv, wantFNV)
	}

	outPlain := make([]byte, len(plain))
	processSubregions512(cfg3, n512, d512, s512, nonce, container, outPlain, 17, 408, dataPixels, totalBits, 512, false, 1, 0)
	if !bytes.Equal(outPlain, plain) {
		t.Fatal("processSubregions512(Mode=3) decode mismatch")
	}
}

func TestMode3RejectsBarriersDesyncOff(t *testing.T) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
	cfg3 := &Config{Mode: 3}
	msg := []byte("Mode 3 requires active Layer I/II desynchronization")

	// Produce a valid Mode 3 wire and blob while desync is active.
	ct, err := Encrypt3x128Cfg(cfg3, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, msg)
	if err != nil {
		t.Fatalf("Encrypt3x128Cfg(Mode=3): %v", err)
	}
	var bSrc Blob128
	blobBytes, err := bSrc.Export3Cfg(&Config{Mode: 3, NonceBits: DefaultNonceBits, BarrierFill: DefaultBarrierFill},
		nil, nil, nil, nil, nil, nil, nil,
		ns, ds1, ds2, ds3, ss1, ss2, ss3, Blob128Opts{LS: ls})
	if err != nil {
		t.Fatalf("Blob128.Export3Cfg(Mode=3): %v", err)
	}

	// Now disable desync via ITB_BARRIERS_DESYNC=off and verify every Mode 3 entry point rejects it.
	t.Setenv("ITB_BARRIERS_DESYNC", "off")

	if _, err := Encrypt3x128Cfg(cfg3, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, msg); err == nil {
		t.Fatal("Encrypt3x128Cfg(Mode=3) succeeded with ITB_BARRIERS_DESYNC=off")
	}
	if _, err := Decrypt3x128Cfg(cfg3, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct); err == nil {
		t.Fatal("Decrypt3x128Cfg(Mode=3) succeeded with ITB_BARRIERS_DESYNC=off")
	}
	if _, err := bSrc.Export3Cfg(&Config{Mode: 3, NonceBits: DefaultNonceBits, BarrierFill: DefaultBarrierFill},
		nil, nil, nil, nil, nil, nil, nil,
		ns, ds1, ds2, ds3, ss1, ss2, ss3, Blob128Opts{LS: ls}); err == nil {
		t.Fatal("Blob128.Export3Cfg(Mode=3) succeeded with ITB_BARRIERS_DESYNC=off")
	}
	var bDst Blob128
	var cfgImport Config
	if err := bDst.Import3Cfg(blobBytes, &cfgImport); err == nil {
		t.Fatal("Blob128.Import3Cfg(Mode=3) succeeded with ITB_BARRIERS_DESYNC=off")
	}

	// Also verify env-driven Mode 3 (ITB_CONTAINER_MODE=3 with nil Config) rejects ITB_BARRIERS_DESYNC=off.
	t.Setenv("ITB_CONTAINER_MODE", "3")
	if _, err := Encrypt3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, msg); err == nil {
		t.Fatal("Encrypt3x128Cfg(nil) succeeded with ITB_CONTAINER_MODE=3 and ITB_BARRIERS_DESYNC=off")
	}
	if _, err := Decrypt3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct); err == nil {
		t.Fatal("Decrypt3x128Cfg(nil) succeeded with ITB_CONTAINER_MODE=3 and ITB_BARRIERS_DESYNC=off")
	}
}
