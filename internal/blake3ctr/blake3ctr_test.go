package blake3ctr

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"runtime"
	"runtime/debug"
	"testing"
	"unsafe"

	"github.com/zeebo/blake3"
)

func refBlake3(key, in []byte) [32]byte {
	h, err := blake3.NewKeyed(key)
	if err != nil {
		panic(err)
	}
	_, _ = h.Write(in)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// TestBlake3KATVectors verifies hardcoded golden hex KAT vectors (including
// official BLAKE3 keyed-hash test vectors with key "whats the Elvish word for friend"
// and pattern input[i] = byte(i % 251)) across single-lane Eval, 4-lane
// BatchPRFx4, and multi-block XORKeyStreamBlocks, cross-checked against
// github.com/zeebo/blake3.NewKeyed.
func TestBlake3KATVectors(t *testing.T) {
	// Official BLAKE3 test_vectors.json keyed_hash key.
	officialKey := []byte("whats the Elvish word for friend")
	var officialKeyBytes [32]byte
	copy(officialKeyBytes[:], officialKey)
	var officialKeyWords [8]uint32
	InitKey(officialKey, &officialKeyWords)

	officialCases := []struct {
		length  int
		wantHex string
	}{
		{0, "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26"},
		{1, "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b"},
		{24, "d02210f05bac20b2bc0de1f1814a74a00f190659408f33b6feab7749ad97ade6"},
		{63, "bb1eb5d4afa793c1ebdd9fb08def6c36d10096986ae0cfe148cd101170ce37ae"},
		{64, "ba8ced36f327700d213f120b1a207a3b8c04330528586f414d09f2f7d9ccb7e6"},
		{65, "c0a4edefa2d2accb9277c371ac12fcdbb52988a86edc54f0716e1591b4326e72"},
		{1024, "75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4"},
		{1025, "357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69"},
	}

	input := make([]byte, 10000)
	for i := range input {
		input[i] = byte(i % 251)
	}
	for _, tc := range officialCases {
		in := input[:tc.length]
		ref := refBlake3(officialKey, in)
		if gotHex := hex.EncodeToString(ref[:]); gotHex != tc.wantHex {
			t.Fatalf("official len=%d KAT constant mismatch: got %s, want %s", tc.length, gotHex, tc.wantHex)
		}
		var got [32]byte
		Eval(got[:], in, &officialKeyWords, &officialKeyBytes)
		if got != ref {
			t.Fatalf("official len=%d Eval mismatch:\ngot  %x\nwant %x", tc.length, got, ref)
		}
	}

	// Hardcoded golden hex KAT vectors for key 000102..1f.
	key, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatal(err)
	}
	var keyBytes [32]byte
	copy(keyBytes[:], key)
	var keyWords [8]uint32
	InitKey(key, &keyWords)

	kats := []struct {
		name    string
		inHex   string
		wantHex string
	}{
		{
			name:    "empty",
			inHex:   "",
			wantHex: "73492b19995d71cdb1e9d74decc09809eb732f1b00bc95c27cb15f9dd4d6478f",
		},
		{
			name:    "abc_3B",
			inHex:   "616263",
			wantHex: "6da54495d8152f2bcba87bd7282df70901cdb66b4448ed5f4c7bd2852b8b5532",
		},
		{
			name:    "ctr_24B_lane0",
			inHex:   "101112131415161718191a1b1c1d1e1f0000000000000000",
			wantHex: "ee6eaa3ee3ac11b46ae21802da99a5fd2d606cc9530880f9069c0fa36c808e7d",
		},
		{
			name:    "ctr_24B_lane1",
			inHex:   "101112131415161718191a1b1c1d1e1f0100000000000000",
			wantHex: "8623d5e25590f0c5cebe459f5a68413f7951fe12c3742a0a62dcb438703cd1c8",
		},
		{
			name:    "ctr_24B_lane2",
			inHex:   "101112131415161718191a1b1c1d1e1f0200000000000000",
			wantHex: "43aa0362e1bdd33b905ccc48427ad01b7470bd626e23e889afb79131d591bb82",
		},
		{
			name:    "ctr_24B_lane3",
			inHex:   "101112131415161718191a1b1c1d1e1f0300000000000000",
			wantHex: "ab631114eaeda2cfcd4c19d99ad48bf840731704408aabe6a1ed381f0bea9cca",
		},
		{
			name:    "block_64B",
			inHex:   "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
			wantHex: "cfaf838ff320e0d87301dcba02b1a4bb397d65119f57403df2817a51d4025f9b",
		},
	}

	var wantCTR [4][32]byte
	for idx, tc := range kats {
		in, err := hex.DecodeString(tc.inHex)
		if err != nil {
			t.Fatal(err)
		}
		ref := refBlake3(key, in)
		if refHex := hex.EncodeToString(ref[:]); refHex != tc.wantHex {
			t.Fatalf("%s: KAT constant mismatch: got %s, want %s", tc.name, refHex, tc.wantHex)
		}
		var got [32]byte
		Eval(got[:], in, &keyWords, &keyBytes)
		if got != ref {
			t.Fatalf("%s: Eval mismatch:\ngot  %x\nwant %x", tc.name, got, ref)
		}
		if idx >= 2 && idx < 6 {
			wantCTR[idx-2] = ref
		}
	}

	// Verify 4-lane BatchPRFx4 over the 4 24B CTR vectors.
	var batchIn [4][]byte
	var batchDst [4][]byte
	var batchBuf [4][32]byte
	for lane := 0; lane < 4; lane++ {
		b, _ := hex.DecodeString(kats[2+lane].inHex)
		batchIn[lane] = b
		batchDst[lane] = batchBuf[lane][:]
	}
	BatchPRFx4(&batchDst, &batchIn, &keyWords, &keyBytes)
	for lane := 0; lane < 4; lane++ {
		if !bytes.Equal(batchDst[lane], wantCTR[lane][:]) {
			t.Fatalf("BatchPRFx4 lane %d mismatch:\ngot  %x\nwant %x", lane, batchDst[lane], wantCTR[lane])
		}
	}

	// Verify XORKeyStreamBlocks over the same 4 blocks against zero src.
	nonce := [4]uint32{0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c}
	var ks [4 * BlockSize]byte
	XORKeyStreamBlocks(ks[:], ks[:], &keyWords, &nonce, 0)
	for lane := 0; lane < 4; lane++ {
		if !bytes.Equal(ks[lane*32:(lane+1)*32], wantCTR[lane][:]) {
			t.Fatalf("XORKeyStreamBlocks lane %d mismatch:\ngot  %x\nwant %x", lane, ks[lane*32:(lane+1)*32], wantCTR[lane])
		}
	}
}

// TestBlake3EvalParity verifies Eval against github.com/zeebo/blake3.NewKeyed
// across input lengths 0..1024 and up to 10000 bytes, and verifies 0 allocs/op
// for single-block inputs (len(in) <= 64).
func TestBlake3EvalParity(t *testing.T) {
	var keyBytes [32]byte
	for i := range keyBytes {
		keyBytes[i] = byte(0x23 + i*7)
	}
	var keyWords [8]uint32
	InitKey(keyBytes[:], &keyWords)

	lengths := make([]int, 0, 270)
	for n := 0; n <= 260; n++ {
		lengths = append(lengths, n)
	}
	lengths = append(lengths, 511, 512, 513, 1023, 1024, 1025, 2048, 4096, 10000)

	buf := make([]byte, 10000)
	for i := range buf {
		buf[i] = byte(i*31 + 17)
	}
	var got [32]byte
	for _, n := range lengths {
		want := refBlake3(keyBytes[:], buf[:n])
		Eval(got[:], buf[:n], &keyWords, &keyBytes)
		if got != want {
			t.Fatalf("Eval length %d mismatch:\ngot  %x\nwant %x", n, got, want)
		}
	}

	allocs := testing.AllocsPerRun(100, func() {
		Eval(got[:], nil, &keyWords, &keyBytes)
		Eval(got[:], buf[:24], &keyWords, &keyBytes)
		Eval(got[:], buf[:64], &keyWords, &keyBytes)
	})
	if allocs != 0 {
		t.Fatalf("Eval(<=64B) allocated %v allocs/op, want 0", allocs)
	}
}

// TestBlake3BatchPRFx4Parity verifies BatchPRFx4 across common lengths 0..256
// and mismatched lane lengths against github.com/zeebo/blake3.NewKeyed.
func TestBlake3BatchPRFx4Parity(t *testing.T) {
	var keyBytes [32]byte
	for i := range keyBytes {
		keyBytes[i] = byte(0x51 + i*11)
	}
	var keyWords [8]uint32
	InitKey(keyBytes[:], &keyWords)

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
		BatchPRFx4(&dst, &in, &keyWords, &keyBytes)
		for lane := 0; lane < 4; lane++ {
			want := refBlake3(keyBytes[:], in[lane])
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
	BatchPRFx4(&dst, &in, &keyWords, &keyBytes)
	for lane := 0; lane < 4; lane++ {
		want := refBlake3(keyBytes[:], in[lane])
		if !bytes.Equal(dst[lane], want[:]) {
			t.Fatalf("BatchPRFx4 mixed lengths lane=%d mismatch", lane)
		}
	}
}

// TestBlake3XORKeyStreamBlocksParity verifies XORKeyStreamBlocks and
// scalarXORKeyStreamBlocks against github.com/zeebo/blake3.NewKeyed across
// nBlocks = 1..35, 32-bit counter carry boundaries (0xfffffffe..0x100000005),
// 64-bit counter wraparound (0xfffffffffffffffe), and in-place vs disjoint buffers.
func TestBlake3XORKeyStreamBlocksParity(t *testing.T) {
	key := make([]byte, KeySize)
	nonceBytes := make([]byte, NonceSize)
	for i := range key {
		key[i] = byte(0x11 + i*7)
	}
	for i := range nonceBytes {
		nonceBytes[i] = byte(0xa3 + i*13)
	}
	var keyWords [8]uint32
	InitKey(key, &keyWords)
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
				ks := refBlake3(key, msg[:])
				for j := 0; j < BlockSize; j++ {
					want[b*BlockSize+j] = src[b*BlockSize+j] ^ ks[j]
				}
			}

			// Disjoint dst and src.
			gotDispatch := make([]byte, n)
			XORKeyStreamBlocks(gotDispatch, src, &keyWords, &nonceWords, ctr)
			if !bytes.Equal(gotDispatch, want) {
				t.Fatalf("dispatch mismatch at ctr=%#x nBlocks=%d", ctr, nBlocks)
			}

			// In-place dst == src.
			gotInPlace := append([]byte(nil), src...)
			XORKeyStreamBlocks(gotInPlace, gotInPlace, &keyWords, &nonceWords, ctr)
			if !bytes.Equal(gotInPlace, want) {
				t.Fatalf("in-place mismatch at ctr=%#x nBlocks=%d", ctr, nBlocks)
			}

			// Scalar fallback.
			gotScalar := make([]byte, n)
			scalarXORKeyStreamBlocks(gotScalar, src, &keyWords, &nonceWords, ctr)
			if !bytes.Equal(gotScalar, want) {
				t.Fatalf("scalar mismatch at ctr=%#x nBlocks=%d", ctr, nBlocks)
			}
		}
	}
}

// TestBlake3FourMandatoryInvariants verifies the four mandatory cryptographic
// invariants required for every PRF/keystream primitive:
//  1. Non-affinity: f(a) ^ f(b) ^ f(c) ^ f(a ^ b ^ c) != 0 across input lengths.
//  2. Compression & collision resistance: chunk-swap and trailing-zero-extension
//     inputs do not collide.
//  3. Every key slot is secret: flipping any bit in any of the 8 key words
//     alters the output at both empty and non-empty message lengths.
//  4. Batched and multi-block kernels match the single-block reference exactly.
func TestBlake3FourMandatoryInvariants(t *testing.T) {
	var keyBytes [32]byte
	for i := range keyBytes {
		keyBytes[i] = byte(0x37 + i*9)
	}
	var keyWords [8]uint32
	InitKey(keyBytes[:], &keyWords)

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
		Eval(fa[:], a, &keyWords, &keyBytes)
		Eval(fb[:], b, &keyWords, &keyBytes)
		Eval(fc[:], c, &keyWords, &keyBytes)
		Eval(fabc[:], abc, &keyWords, &keyBytes)
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
		Eval(d1[:], m1, &keyWords, &keyBytes)
		Eval(d2[:], m2, &keyWords, &keyBytes)
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
		Eval(dab[:], ab, &keyWords, &keyBytes)
		Eval(dba[:], ba, &keyWords, &keyBytes)
		if dab == dba {
			t.Fatalf("chunk-swap collision at half=%d", half)
		}
	}

	// 3. Every key slot is secret (all 256 key bits tested at len=0 and len=24).
	msg24 := []byte("0123456789abcdef01234567")
	var base0, base24 [32]byte
	Eval(base0[:], nil, &keyWords, &keyBytes)
	Eval(base24[:], msg24, &keyWords, &keyBytes)
	for byteIdx := 0; byteIdx < KeySize; byteIdx++ {
		for bit := 0; bit < 8; bit++ {
			kb2 := keyBytes
			kb2[byteIdx] ^= 1 << bit
			var kw2 [8]uint32
			InitKey(kb2[:], &kw2)
			var out0, out24 [32]byte
			Eval(out0[:], nil, &kw2, &kb2)
			Eval(out24[:], msg24, &kw2, &kb2)
			if out0 == base0 {
				t.Fatalf("key byte %d bit %d did not change len=0 output", byteIdx, bit)
			}
			if out24 == base24 {
				t.Fatalf("key byte %d bit %d did not change len=24 output", byteIdx, bit)
			}
		}
	}
}

// TestBlake3XORKeyStreamBlocksBitSensitivity verifies that flipping any bit
// in keyWords, nonce, or counter changes the output across all lane positions
// (15 blocks = 8 + 4 + 3).
func TestBlake3XORKeyStreamBlocksBitSensitivity(t *testing.T) {
	const nBlocks = 15
	const nBytes = nBlocks * BlockSize
	keyWords := [8]uint32{
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
	XORKeyStreamBlocks(base, src, &keyWords, &nonce, counter)

	out := make([]byte, nBytes)
	for w := 0; w < 8; w++ {
		for b := 0; b < 32; b++ {
			kw2 := keyWords
			kw2[w] ^= 1 << b
			XORKeyStreamBlocks(out, src, &kw2, &nonce, counter)
			for blk := 0; blk < nBlocks; blk++ {
				if bytes.Equal(out[blk*BlockSize:(blk+1)*BlockSize], base[blk*BlockSize:(blk+1)*BlockSize]) {
					t.Fatalf("keyWords word %d bit %d did not change block %d", w, b, blk)
				}
			}
		}
	}
	for w := 0; w < 4; w++ {
		for b := 0; b < 32; b++ {
			n2 := nonce
			n2[w] ^= 1 << b
			XORKeyStreamBlocks(out, src, &keyWords, &n2, counter)
			for blk := 0; blk < nBlocks; blk++ {
				if bytes.Equal(out[blk*BlockSize:(blk+1)*BlockSize], base[blk*BlockSize:(blk+1)*BlockSize]) {
					t.Fatalf("nonce word %d bit %d did not change block %d", w, b, blk)
				}
			}
		}
	}
	for b := 0; b < 64; b++ {
		c2 := counter ^ (uint64(1) << b)
		XORKeyStreamBlocks(out, src, &keyWords, &nonce, c2)
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

func makeTestSecrets(keyWords *[8]uint32, nonce *[4]uint32) map[uint32]string {
	m := make(map[uint32]string, 12)
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
	var keyWords [8]uint32
	InitKey(keyBytes[:], &keyWords)
	nonce := [4]uint32{0x11223344, 0x55667788, 0x99aabbcc, 0xddeeff11}
	secrets := makeTestSecrets(&keyWords, &nonce)

	src := make([]byte, 4*BlockSize)
	dst := make([]byte, 4*BlockSize)
	resScalar := stackResidue(func() {
		scalarXORKeyStreamBlocks(dst, src, &keyWords, &nonce, 1)
	})
	assertNoSecretResidue(t, "scalarXORKeyStreamBlocks", resScalar, secrets)

	var digest [32]byte
	msg := make([]byte, 24)
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(msg[i*4:], nonce[i])
	}
	resEval := stackResidue(func() {
		Eval(digest[:], msg, &keyWords, &keyBytes)
	})
	assertNoSecretResidue(t, "Eval(24B)", resEval, secrets)

	resEvalEmpty := stackResidue(func() {
		Eval(digest[:], nil, &keyWords, &keyBytes)
	})
	assertNoSecretResidue(t, "Eval(0B)", resEvalEmpty, secrets)

	runtime.KeepAlive(&keyBytes)
	runtime.KeepAlive(&keyWords)
	runtime.KeepAlive(&nonce)
}
