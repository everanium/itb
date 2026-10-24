package blake2sctr

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"runtime"
	"runtime/debug"
	"testing"
	"unsafe"

	"golang.org/x/crypto/blake2s"
)

func refBlake2s(key, in []byte) [32]byte {
	h, err := blake2s.New256(key)
	if err != nil {
		panic(err)
	}
	_, _ = h.Write(in)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// TestBlake2sKATVectors verifies hardcoded golden hex KAT vectors for
// single-lane Eval, 4-lane BatchPRFx4, and multi-block XORKeyStreamBlocks,
// cross-checked against golang.org/x/crypto/blake2s.New256.
func TestBlake2sKATVectors(t *testing.T) {
	key, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatal(err)
	}
	var hKey, keyWords [8]uint32
	InitKey(key, &hKey, &keyWords)

	kats := []struct {
		name    string
		inHex   string
		wantHex string
	}{
		{
			name:    "empty",
			inHex:   "",
			wantHex: "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49",
		},
		{
			name:    "abc_3B",
			inHex:   "616263",
			wantHex: "a281f725754969a702f6fe36fc591b7def866e4b70173ece402fc01c064d6b65",
		},
		{
			name:    "ctr_24B_lane0",
			inHex:   "101112131415161718191a1b1c1d1e1f0000000000000000",
			wantHex: "1cba6d5810dbd9143748cfdbe29325de2d4f4fbbb8e019fc90f9e2abddb19760",
		},
		{
			name:    "ctr_24B_lane1",
			inHex:   "101112131415161718191a1b1c1d1e1f0100000000000000",
			wantHex: "0739a8b8cbb3a5558598d3cc707209389e002f503f44b07881b0e9de42c95481",
		},
		{
			name:    "ctr_24B_lane2",
			inHex:   "101112131415161718191a1b1c1d1e1f0200000000000000",
			wantHex: "d46fa64c56b0115fd5d19f5c173d4d30c47d1e52a22be59f5703bee8fc6f814f",
		},
		{
			name:    "ctr_24B_lane3",
			inHex:   "101112131415161718191a1b1c1d1e1f0300000000000000",
			wantHex: "dcf83351c671d69152feb444141ce0b0d1efaf636e24f89ed501f2ac394edd5a",
		},
		{
			name:    "block_64B",
			inHex:   "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
			wantHex: "8975b0577fd35566d750b362b0897a26c399136df07bababbde6203ff2954ed4",
		},
	}

	for _, tc := range kats {
		in, err := hex.DecodeString(tc.inHex)
		if err != nil {
			t.Fatal(err)
		}
		ref := refBlake2s(key, in)
		refHex := hex.EncodeToString(ref[:])
		if refHex != tc.wantHex {
			t.Fatalf("%s: KAT constant mismatch with x/crypto/blake2s: got %s, ref %s", tc.name, tc.wantHex, refHex)
		}
		var got [32]byte
		Eval(got[:], in, &hKey, &keyWords)
		if !bytes.Equal(got[:], ref[:]) {
			t.Fatalf("%s: Eval mismatch:\ngot  %x\nwant %x", tc.name, got, ref)
		}
	}

	// Verify 4-lane batch KAT over the 4 24B CTR vectors.
	var batchIn [4][]byte
	var batchDst [4][]byte
	var batchBuf [4][32]byte
	for lane := 0; lane < 4; lane++ {
		b, _ := hex.DecodeString(kats[2+lane].inHex)
		batchIn[lane] = b
		batchDst[lane] = batchBuf[lane][:]
	}
	BatchPRFx4(&batchDst, &batchIn, &hKey, &keyWords)
	for lane := 0; lane < 4; lane++ {
		if hex.EncodeToString(batchDst[lane]) != kats[2+lane].wantHex {
			t.Fatalf("BatchPRFx4 lane %d mismatch:\ngot  %x\nwant %s", lane, batchDst[lane], kats[2+lane].wantHex)
		}
	}

	// Verify XORKeyStreamBlocks over the same 4 blocks against zero src.
	nonce := [4]uint32{0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c}
	var ks [4 * BlockSize]byte
	XORKeyStreamBlocks(ks[:], ks[:], &hKey, &nonce, 0)
	for lane := 0; lane < 4; lane++ {
		if hex.EncodeToString(ks[lane*32:(lane+1)*32]) != kats[2+lane].wantHex {
			t.Fatalf("XORKeyStreamBlocks lane %d mismatch:\ngot  %x\nwant %s", lane, ks[lane*32:(lane+1)*32], kats[2+lane].wantHex)
		}
	}
}

// TestBlake2sEvalParity verifies Eval against golang.org/x/crypto/blake2s.New256
// across input lengths 0..1024 and up to 10000 bytes, and verifies 0 allocs/op.
func TestBlake2sEvalParity(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(0x23 + i*7)
	}
	var hKey, keyWords [8]uint32
	InitKey(key, &hKey, &keyWords)

	lengths := make([]int, 0, 270)
	for n := 0; n <= 260; n++ {
		lengths = append(lengths, n)
	}
	lengths = append(lengths, 511, 512, 513, 1023, 1024, 1025, 4096, 10000)

	buf := make([]byte, 10000)
	for i := range buf {
		buf[i] = byte(i*31 + 17)
	}
	var got [32]byte
	for _, n := range lengths {
		want := refBlake2s(key, buf[:n])
		Eval(got[:], buf[:n], &hKey, &keyWords)
		if got != want {
			t.Fatalf("Eval length %d mismatch:\ngot  %x\nwant %x", n, got, want)
		}
	}

	allocs := testing.AllocsPerRun(100, func() {
		Eval(got[:], buf[:24], &hKey, &keyWords)
		Eval(got[:], buf[:200], &hKey, &keyWords)
	})
	if allocs != 0 {
		t.Fatalf("Eval allocated %v allocs/op, want 0", allocs)
	}
}

// TestBlake2sBatchPRFx4Parity verifies BatchPRFx4 across common lengths 0..256
// and mismatched lane lengths against golang.org/x/crypto/blake2s.New256.
func TestBlake2sBatchPRFx4Parity(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(0x51 + i*11)
	}
	var hKey, keyWords [8]uint32
	InitKey(key, &hKey, &keyWords)

	for n := 0; n <= 256; n++ {
		var in, dst [4][]byte
		var inStore [4][256]byte
		var dstStore [4][32]byte
		for lane := 0; lane < 4; lane++ {
			for i := 0; i < n; i++ {
				inStore[lane][i] = byte(i*19 + lane*53 + n*7 + 3)
			}
			in[lane] = inStore[lane][:n]
			dst[lane] = dstStore[lane][:]
		}
		BatchPRFx4(&dst, &in, &hKey, &keyWords)
		for lane := 0; lane < 4; lane++ {
			want := refBlake2s(key, in[lane])
			if !bytes.Equal(dst[lane], want[:]) {
				t.Fatalf("BatchPRFx4 commonLen=%d lane=%d mismatch:\ngot  %x\nwant %x", n, lane, dst[lane], want)
			}
		}
	}

	// Mismatched lengths fallback.
	var in, dst [4][]byte
	var dstStore [4][32]byte
	in[0] = []byte("short")
	in[1] = make([]byte, 24)
	in[2] = make([]byte, 64)
	in[3] = make([]byte, 100)
	for lane := 0; lane < 4; lane++ {
		dst[lane] = dstStore[lane][:]
	}
	BatchPRFx4(&dst, &in, &hKey, &keyWords)
	for lane := 0; lane < 4; lane++ {
		want := refBlake2s(key, in[lane])
		if !bytes.Equal(dst[lane], want[:]) {
			t.Fatalf("BatchPRFx4 mixed lengths lane=%d mismatch", lane)
		}
	}
}

// TestBlake2sXORKeyStreamBlocksParity verifies XORKeyStreamBlocks and
// scalarXORKeyStreamBlocks against golang.org/x/crypto/blake2s.New256 across
// nBlocks = 1..35, 32-bit counter carry boundaries (0xfffffffe..0x100000005),
// 64-bit counter wraparound (0xfffffffffffffffe), and in-place vs disjoint buffers.
func TestBlake2sXORKeyStreamBlocksParity(t *testing.T) {
	key := make([]byte, KeySize)
	nonceBytes := make([]byte, NonceSize)
	for i := range key {
		key[i] = byte(0x11 + i*7)
	}
	for i := range nonceBytes {
		nonceBytes[i] = byte(0xa3 + i*13)
	}
	var hKey, keyWords [8]uint32
	InitKey(key, &hKey, &keyWords)
	nonceWords := [4]uint32{
		binary.LittleEndian.Uint32(nonceBytes[0:4]),
		binary.LittleEndian.Uint32(nonceBytes[4:8]),
		binary.LittleEndian.Uint32(nonceBytes[8:12]),
		binary.LittleEndian.Uint32(nonceBytes[12:16]),
	}

	counters := []uint64{
		0,
		1,
		7,
		42,
		0xfffffffc,
		0xfffffffe,
		0xffffffff,
		0x100000000,
		0xfffffffffffffffc,
		0xfffffffffffffffe,
	}

	for _, ctr := range counters {
		for nBlocks := 1; nBlocks <= 35; nBlocks++ {
			n := nBlocks * BlockSize
			src := make([]byte, n)
			for i := range src {
				src[i] = byte(i*29 + 5)
			}
			want := make([]byte, n)
			var msg [24]byte
			copy(msg[:16], nonceBytes)
			for b := 0; b < nBlocks; b++ {
				binary.LittleEndian.PutUint64(msg[16:24], ctr+uint64(b))
				ks := refBlake2s(key, msg[:])
				for j := 0; j < BlockSize; j++ {
					want[b*BlockSize+j] = src[b*BlockSize+j] ^ ks[j]
				}
			}

			// Disjoint dst and src.
			gotDispatch := make([]byte, n)
			XORKeyStreamBlocks(gotDispatch, src, &hKey, &nonceWords, ctr)
			if !bytes.Equal(gotDispatch, want) {
				t.Fatalf("dispatch mismatch at ctr=%#x nBlocks=%d", ctr, nBlocks)
			}

			// In-place dst == src.
			gotInPlace := append([]byte(nil), src...)
			XORKeyStreamBlocks(gotInPlace, gotInPlace, &hKey, &nonceWords, ctr)
			if !bytes.Equal(gotInPlace, want) {
				t.Fatalf("in-place mismatch at ctr=%#x nBlocks=%d", ctr, nBlocks)
			}

			// Scalar fallback.
			gotScalar := make([]byte, n)
			scalarXORKeyStreamBlocks(gotScalar, src, &hKey, &nonceWords, ctr)
			if !bytes.Equal(gotScalar, want) {
				t.Fatalf("scalar mismatch at ctr=%#x nBlocks=%d", ctr, nBlocks)
			}
		}
	}
}

// TestBlake2sFourMandatoryInvariants verifies the four mandatory cryptographic
// invariants required for every PRF/keystream primitive:
//  1. Non-affinity: f(a) ^ f(b) ^ f(c) ^ f(a ^ b ^ c) != 0 across input lengths.
//  2. Compression & collision resistance: chunk-swap and trailing-zero-extension
//     inputs do not collide.
//  3. Every key slot is secret: flipping any bit in any of the 8 key words
//     alters the output at both empty and non-empty message lengths.
//  4. Batched and multi-block kernels match the single-block reference exactly.
func TestBlake2sFourMandatoryInvariants(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(0x37 + i*9)
	}
	var hKey, keyWords [8]uint32
	InitKey(key, &hKey, &keyWords)

	// 1. Non-affinity across lengths.
	for _, n := range []int{1, 8, 13, 16, 20, 24, 32, 36, 48, 63, 64, 65, 68, 128, 256} {
		a := make([]byte, n)
		b := make([]byte, n)
		c := make([]byte, n)
		abc := make([]byte, n)
		for i := 0; i < n; i++ {
			a[i] = byte(0x11 + i*3)
			b[i] = byte(0x22 + i*5)
			c[i] = byte(0x44 + i*7)
			abc[i] = a[i] ^ b[i] ^ c[i]
		}
		var fa, fb, fc, fabc [32]byte
		Eval(fa[:], a, &hKey, &keyWords)
		Eval(fb[:], b, &hKey, &keyWords)
		Eval(fc[:], c, &hKey, &keyWords)
		Eval(fabc[:], abc, &hKey, &keyWords)
		var xorSum byte
		for i := 0; i < 32; i++ {
			xorSum |= fa[i] ^ fb[i] ^ fc[i] ^ fabc[i]
		}
		if xorSum == 0 {
			t.Fatalf("affinity check vanished at length %d", n)
		}
	}

	// 2. Compression and collisions: trailing-zero extension and chunk swap.
	for _, baseLen := range []int{0, 1, 16, 23, 24, 32, 63, 64, 65, 127, 128} {
		m1 := make([]byte, baseLen)
		for i := range m1 {
			m1[i] = byte(0x5a + i*13)
		}
		m2 := append(append([]byte(nil), m1...), 0x00)
		var d1, d2 [32]byte
		Eval(d1[:], m1, &hKey, &keyWords)
		Eval(d2[:], m2, &hKey, &keyWords)
		if d1 == d2 {
			t.Fatalf("trailing-zero collision between len %d and %d", baseLen, baseLen+1)
		}
	}
	for _, half := range []int{4, 12, 32, 64} {
		ab := make([]byte, 2*half)
		ba := make([]byte, 2*half)
		for i := 0; i < half; i++ {
			ab[i] = byte(0x10 + i)
			ab[half+i] = byte(0x90 + i)
			ba[i] = ab[half+i]
			ba[half+i] = ab[i]
		}
		var dab, dba [32]byte
		Eval(dab[:], ab, &hKey, &keyWords)
		Eval(dba[:], ba, &hKey, &keyWords)
		if dab == dba {
			t.Fatalf("chunk-swap collision at half=%d", half)
		}
	}

	// 3. Every key slot is secret (all 256 key bits tested at len=0 and len=24).
	msg24 := []byte("0123456789abcdef01234567")
	var base0, base24 [32]byte
	Eval(base0[:], nil, &hKey, &keyWords)
	Eval(base24[:], msg24, &hKey, &keyWords)
	for byteIdx := 0; byteIdx < KeySize; byteIdx++ {
		for bit := 0; bit < 8; bit++ {
			k2 := append([]byte(nil), key...)
			k2[byteIdx] ^= 1 << bit
			var hk2, kw2 [8]uint32
			InitKey(k2, &hk2, &kw2)
			var out0, out24 [32]byte
			Eval(out0[:], nil, &hk2, &kw2)
			Eval(out24[:], msg24, &hk2, &kw2)
			if out0 == base0 {
				t.Fatalf("key byte %d bit %d did not change len=0 output", byteIdx, bit)
			}
			if out24 == base24 {
				t.Fatalf("key byte %d bit %d did not change len=24 output", byteIdx, bit)
			}
		}
	}
}

// TestBlake2sXORKeyStreamBlocksBitSensitivity verifies that flipping any bit
// in hKey, nonce, or counter changes the output across all lane positions
// (15 blocks = 8 + 4 + 3).
func TestBlake2sXORKeyStreamBlocksBitSensitivity(t *testing.T) {
	const nBlocks = 15
	const nBytes = nBlocks * BlockSize
	hKey := [8]uint32{
		0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
		0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
	}
	nonce := [4]uint32{0x23222120, 0x27262524, 0x2b2a2928, 0x2f2e2d2c}
	counter := uint64(5)
	src := make([]byte, nBytes)
	for i := range src {
		src[i] = byte(i*17 + 3)
	}
	base := make([]byte, nBytes)
	XORKeyStreamBlocks(base, src, &hKey, &nonce, counter)

	out := make([]byte, nBytes)
	for w := 0; w < 8; w++ {
		for b := 0; b < 32; b++ {
			hk2 := hKey
			hk2[w] ^= 1 << b
			XORKeyStreamBlocks(out, src, &hk2, &nonce, counter)
			for blk := 0; blk < nBlocks; blk++ {
				if bytes.Equal(out[blk*BlockSize:(blk+1)*BlockSize], base[blk*BlockSize:(blk+1)*BlockSize]) {
					t.Fatalf("hKey word %d bit %d did not change block %d", w, b, blk)
				}
			}
		}
	}
	for w := 0; w < 4; w++ {
		for b := 0; b < 32; b++ {
			n2 := nonce
			n2[w] ^= 1 << b
			XORKeyStreamBlocks(out, src, &hKey, &n2, counter)
			for blk := 0; blk < nBlocks; blk++ {
				if bytes.Equal(out[blk*BlockSize:(blk+1)*BlockSize], base[blk*BlockSize:(blk+1)*BlockSize]) {
					t.Fatalf("nonce word %d bit %d did not change block %d", w, b, blk)
				}
			}
		}
	}
	for b := 0; b < 64; b++ {
		c2 := counter ^ (uint64(1) << b)
		XORKeyStreamBlocks(out, src, &hKey, &nonce, c2)
		if bytes.Equal(out, base) {
			t.Fatalf("counter bit %d did not change output", b)
		}
	}
}

const (
	residueGap      = 1 << 10
	residuePad      = 2 << 10
	residueWindow   = 16 << 10
	residueSentinel = uint64(0x5A5A5A5A5A5A5A5A)
)

var dumpSIMDRegsHook func(dst *[88]uint64)
var dirtySIMDRegHook func(masked uint64)
var genericResidueSink uint64

//go:noinline
func leakyFrameForTest(secret uint64, i int) {
	var frame [8]uint64
	for j := range frame {
		frame[j] = secret
	}
	genericResidueSink = frame[(i+1)%len(frame)]
}

func checkResidueNegativeControls(t *testing.T) {
	t.Helper()
	secret := uint64(0xA5C35A3CF00DCAFE)
	resStack := stackResidue(func() { leakyFrameForTest(secret, 0) })
	stackHits := 0
	for _, w := range resStack[:residueWindow/8] {
		if w == secret {
			stackHits++
		}
	}
	if stackHits == 0 {
		t.Fatal("negative control: stack-residue probe did not see secret stored by leakyFrameForTest")
	}
	if dirtySIMDRegHook != nil {
		resReg := stackResidue(func() { dirtySIMDRegHook(secret ^ 0x5555555555555555) })
		regHits := 0
		for _, w := range resReg[residueWindow/8:] {
			if w == secret {
				regHits++
			}
		}
		if regHits == 0 {
			t.Fatal("negative control: register snapshot did not see leaked register word")
		}
	}
}

func stackResidue(fn func()) []uint64 {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	res := make([]uint64, residueWindow/8+88)
	done := make(chan struct{})
	go func() {
		defer close(done)
		residueGrow(0)
		var regs [88]uint64
		residueProbe(fn, res[:residueWindow/8], &regs)
		copy(res[residueWindow/8:], regs[:])
	}()
	<-done
	return res
}

//go:noinline
func residueGrow(i int) byte {
	var pad [4 * residueWindow]byte
	pad[i] = 1
	return pad[(i+1)%len(pad)]
}

//go:noinline
func residueProbe(fn func(), res []uint64, regs *[88]uint64) {
	var anchor uint64
	top := unsafe.Add(unsafe.Pointer(&anchor), -residueGap)
	for i := range res {
		*(*uint64)(unsafe.Add(top, -8*(i+1))) = residueSentinel
	}
	residueDeep(fn, 0, regs)
	for i := range res {
		res[i] = *(*uint64)(unsafe.Add(top, -8*(i+1)))
	}
}

//go:noinline
func residueDeep(fn func(), i int, regs *[88]uint64) byte {
	var pad [residuePad]byte
	pad[i] = 1
	fn()
	if dumpSIMDRegsHook != nil {
		dumpSIMDRegsHook(regs)
	}
	return pad[(i+7)%len(pad)]
}

func assertNoSecretResidue(t *testing.T, name string, res []uint64, secrets32 map[uint32]string) {
	t.Helper()
	written := 0
	stackWords := residueWindow / 8
	for i, w := range res {
		if i < stackWords && w != residueSentinel {
			written++
		}
		if i >= stackWords && w == 0 {
			continue
		}
		for h, d := range [2]uint32{uint32(w), uint32(w >> 32)} {
			if i >= stackWords && d == 0 {
				continue
			}
			if what, ok := secrets32[d]; ok {
				if i < stackWords {
					t.Errorf("%s: %s (%#x) left in the stack %d bytes below the window top", name, what, d, 8*(i+1)-4*h)
				} else {
					t.Errorf("%s: %s (%#x) left in post-RET register snapshot (word %d half %d)", name, what, d, i-stackWords, h)
				}
			}
		}
	}
	if written == 0 {
		t.Fatalf("%s: no word of the window was written; the probe missed the kernel frame", name)
	}
}

func makeTestSecrets(hKey *[8]uint32, keyWords *[8]uint32, nonce *[4]uint32) map[uint32]string {
	m := make(map[uint32]string, 20)
	for i, w := range hKey {
		m[w] = fmt.Sprintf("hKey[%d]", i)
	}
	for i, w := range keyWords {
		m[w] = fmt.Sprintf("keyWords[%d]", i)
	}
	for i, w := range nonce {
		m[w] = fmt.Sprintf("nonce[%d]", i)
	}
	return m
}

func TestScalarStackAndRegZeroization(t *testing.T) {
	checkResidueNegativeControls(t)
	keyBytes := [32]byte{
		0xef, 0xbe, 0xad, 0xde, 0xbe, 0xba, 0xfe, 0xca,
		0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89,
		0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76,
		0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f,
	}
	var hKey, keyWords [8]uint32
	InitKey(keyBytes[:], &hKey, &keyWords)
	nonce := [4]uint32{0x11223344, 0x55667788, 0x99aabbcc, 0xddeeff11}
	secrets := makeTestSecrets(&hKey, &keyWords, &nonce)

	src := make([]byte, 4*BlockSize)
	dst := make([]byte, 4*BlockSize)
	resScalar := stackResidue(func() {
		scalarXORKeyStreamBlocks(dst, src, &hKey, &nonce, 1)
	})
	assertNoSecretResidue(t, "scalarXORKeyStreamBlocks", resScalar, secrets)

	var digest [32]byte
	msg := make([]byte, 24)
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(msg[i*4:], nonce[i])
	}
	resEval := stackResidue(func() {
		Eval(digest[:], msg, &hKey, &keyWords)
	})
	assertNoSecretResidue(t, "Eval(24B)", resEval, secrets)

	resEvalEmpty := stackResidue(func() {
		Eval(digest[:], nil, &hKey, &keyWords)
	})
	assertNoSecretResidue(t, "Eval(0B)", resEvalEmpty, secrets)

	runtime.KeepAlive(&keyBytes)
	runtime.KeepAlive(&hKey)
	runtime.KeepAlive(&keyWords)
	runtime.KeepAlive(&nonce)
}
