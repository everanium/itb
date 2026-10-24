package blake2bctr

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"runtime"
	"runtime/debug"
	"testing"
	"unsafe"

	"golang.org/x/crypto/blake2b"
)

func refBlake2b256(key, in []byte) [32]byte {
	h, err := blake2b.New256(key)
	if err != nil {
		panic(err)
	}
	h.Write(in)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

func refBlake2b512(key, in []byte) [64]byte {
	h, err := blake2b.New512(key)
	if err != nil {
		panic(err)
	}
	h.Write(in)
	var out [64]byte
	h.Sum(out[:0])
	return out
}

// TestBlake2bRFC7693GoldenKATs verifies 1-lane and 4-lane (counter = 0..3)
// keyed BLAKE2b-256 and BLAKE2b-512 outputs against hardcoded golden hex
// KAT vectors and golang.org/x/crypto/blake2b.
func TestBlake2bRFC7693GoldenKATs(t *testing.T) {
	key, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatal(err)
	}
	nonceBytes, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatal(err)
	}
	nonce := [2]uint64{
		binary.LittleEndian.Uint64(nonceBytes[0:8]),
		binary.LittleEndian.Uint64(nonceBytes[8:16]),
	}

	var hKey256, hKey512 [8]uint64
	var keyBlock256, keyBlock512 [4]uint64
	InitKey256(key, &hKey256, &keyBlock256)
	InitKey512(key, &hKey512, &keyBlock512)

	goldenHex256 := [4]string{
		"7114c1ad2b9b960c3642d62701b8b054e57461cdf7969d441af4f642f341c1f2",
		"33d9e59af9d63d40af372580b91d29369bd22db303cce650a255bf1f0b12e405",
		"7f99bd69839912411ddfc025f5989ba3ac8b3dae849ab5272558c4a088856a35",
		"cf07b3926676c4460e4c5c1938a35fd789af604be09a4295d8555a05b8d6423b",
	}
	goldenHex512 := [4]string{
		"0bc741097b23c8499ea0a7dade0cd3df1ed7f797219685897fb1ce3319986c5379a4eb3bcb9407515faf592ff0edfdb46b42afd177cd057edecf7378eaaf26ec",
		"f652b9b19e8c86d1e06b34c894b563c4fb076b2be66f358a0645309259c7508ead531edd984ef3e3491764e6b83bc7de99e239457a81e3adbe0bf86d286f9ee1",
		"66435744db21b1c0766eeeb624d1ffe40a1bd777a0f7996d86f503f76ae54c9624fcd79ca7396353b28c908090e21738255b34e4d73f55832eaee682c6aa5836",
		"f5b070e2e4d28a29c2c44979a649aa18863ff4e9488a448093a3e9e56e78da8acb327a9a79cdf63d87954156120ff72e9a9882124f6926d48b2dad84db8cc03b",
	}

	var in4 [4][24]byte
	var inSlices [4][]byte
	var want256 [4][32]byte
	var want512 [4][64]byte
	for c := uint64(0); c < 4; c++ {
		copy(in4[c][0:16], nonceBytes)
		binary.LittleEndian.PutUint64(in4[c][16:24], c)
		inSlices[c] = in4[c][:]
		want256[c] = refBlake2b256(key, in4[c][:])
		want512[c] = refBlake2b512(key, in4[c][:])

		kat256, err := hex.DecodeString(goldenHex256[c])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(want256[c][:], kat256) {
			t.Fatalf("KAT256[%d] mismatch:\ngot  %x\nwant %x", c, want256[c], kat256)
		}
		kat512, err := hex.DecodeString(goldenHex512[c])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(want512[c][:], kat512) {
			t.Fatalf("KAT512[%d] mismatch:\ngot  %x\nwant %x", c, want512[c], kat512)
		}

		var gotEval256 [32]byte
		Eval256(gotEval256[:], in4[c][:], &hKey256, &keyBlock256)
		if gotEval256 != want256[c] {
			t.Fatalf("Eval256 mismatch at counter=%d:\ngot  %x\nwant %x", c, gotEval256, want256[c])
		}

		var gotEval512 [64]byte
		Eval512(gotEval512[:], in4[c][:], &hKey512, &keyBlock512)
		if gotEval512 != want512[c] {
			t.Fatalf("Eval512 mismatch at counter=%d:\ngot  %x\nwant %x", c, gotEval512, want512[c])
		}
	}

	var gotBatch256 [4][32]byte
	var gotBatch512 [4][64]byte
	dstSlices256 := [4][]byte{gotBatch256[0][:], gotBatch256[1][:], gotBatch256[2][:], gotBatch256[3][:]}
	dstSlices512 := [4][]byte{gotBatch512[0][:], gotBatch512[1][:], gotBatch512[2][:], gotBatch512[3][:]}
	BatchPRF256x4(&dstSlices256, &inSlices, &hKey256, &keyBlock256)
	BatchPRF512x4(&dstSlices512, &inSlices, &hKey512, &keyBlock512)
	for c := 0; c < 4; c++ {
		if gotBatch256[c] != want256[c] {
			t.Fatalf("BatchPRF256x4 mismatch at lane %d:\ngot  %x\nwant %x", c, gotBatch256[c], want256[c])
		}
		if gotBatch512[c] != want512[c] {
			t.Fatalf("BatchPRF512x4 mismatch at lane %d:\ngot  %x\nwant %x", c, gotBatch512[c], want512[c])
		}
	}

	var zero256, gotKS256 [4 * 32]byte
	XORKeyStreamBlocks256(gotKS256[:], zero256[:], &hKey256, &nonce, 0)
	for c := 0; c < 4; c++ {
		if !bytes.Equal(gotKS256[c*32:(c+1)*32], want256[c][:]) {
			t.Fatalf("XORKeyStreamBlocks256 mismatch at block %d:\ngot  %x\nwant %x", c, gotKS256[c*32:(c+1)*32], want256[c])
		}
	}

	var zero512, gotKS512 [4 * 64]byte
	XORKeyStreamBlocks512(gotKS512[:], zero512[:], &hKey512, &nonce, 0)
	for c := 0; c < 4; c++ {
		if !bytes.Equal(gotKS512[c*64:(c+1)*64], want512[c][:]) {
			t.Fatalf("XORKeyStreamBlocks512 mismatch at block %d:\ngot  %x\nwant %x", c, gotKS512[c*64:(c+1)*64], want512[c])
		}
	}
}

// TestEvalParityAllLengths verifies Eval256 and Eval512 against
// golang.org/x/crypto/blake2b across input lengths 0..512.
func TestEvalParityAllLengths(t *testing.T) {
	var key [KeySize]byte
	for i := range key {
		key[i] = byte(0x23 + i*11)
	}
	var hKey256, hKey512 [8]uint64
	var keyBlock256, keyBlock512 [4]uint64
	InitKey256(key[:], &hKey256, &keyBlock256)
	InitKey512(key[:], &hKey512, &keyBlock512)

	lengths := []int{
		0, 1, 2, 7, 8, 15, 16, 23, 24, 25, 31, 32, 33, 48, 63, 64, 65,
		96, 127, 128, 129, 192, 255, 256, 257, 300, 384, 512,
	}
	for _, n := range lengths {
		in := make([]byte, n)
		for i := range in {
			in[i] = byte(i*37 + 9)
		}
		want256 := refBlake2b256(key[:], in)
		var got256 [32]byte
		Eval256(got256[:], in, &hKey256, &keyBlock256)
		if got256 != want256 {
			t.Fatalf("Eval256 mismatch at len=%d:\ngot  %x\nwant %x", n, got256, want256)
		}

		want512 := refBlake2b512(key[:], in)
		var got512 [64]byte
		Eval512(got512[:], in, &hKey512, &keyBlock512)
		if got512 != want512 {
			t.Fatalf("Eval512 mismatch at len=%d:\ngot  %x\nwant %x", n, got512, want512)
		}
	}
}

// TestBatchPRFx4ParityAllLengths verifies BatchPRF256x4, scalarBatchPRF256x4,
// BatchPRF512x4, and scalarBatchPRF512x4 across equal lengths (0..300) and
// mixed lengths across lanes.
func TestBatchPRFx4ParityAllLengths(t *testing.T) {
	var key [KeySize]byte
	for i := range key {
		key[i] = byte(0x51 + i*13)
	}
	var hKey256, hKey512 [8]uint64
	var keyBlock256, keyBlock512 [4]uint64
	InitKey256(key[:], &hKey256, &keyBlock256)
	InitKey512(key[:], &hKey512, &keyBlock512)

	lengths := []int{
		0, 1, 7, 8, 15, 16, 23, 24, 25, 31, 32, 48, 63, 64, 65,
		96, 120, 127, 128, 129, 200, 255, 256, 257, 300,
	}
	for _, n := range lengths {
		var inSlices [4][]byte
		var want256 [4][32]byte
		var want512 [4][64]byte
		for lane := 0; lane < 4; lane++ {
			buf := make([]byte, n)
			for i := range buf {
				buf[i] = byte(lane*53 + i*19 + 7)
			}
			inSlices[lane] = buf
			want256[lane] = refBlake2b256(key[:], buf)
			want512[lane] = refBlake2b512(key[:], buf)
		}

		var gotDisp256, gotScal256 [4][32]byte
		var gotDisp512, gotScal512 [4][64]byte
		d256 := [4][]byte{gotDisp256[0][:], gotDisp256[1][:], gotDisp256[2][:], gotDisp256[3][:]}
		s256 := [4][]byte{gotScal256[0][:], gotScal256[1][:], gotScal256[2][:], gotScal256[3][:]}
		d512 := [4][]byte{gotDisp512[0][:], gotDisp512[1][:], gotDisp512[2][:], gotDisp512[3][:]}
		s512 := [4][]byte{gotScal512[0][:], gotScal512[1][:], gotScal512[2][:], gotScal512[3][:]}

		BatchPRF256x4(&d256, &inSlices, &hKey256, &keyBlock256)
		scalarBatchPRF256x4(&s256, &inSlices, &hKey256, &keyBlock256)
		BatchPRF512x4(&d512, &inSlices, &hKey512, &keyBlock512)
		scalarBatchPRF512x4(&s512, &inSlices, &hKey512, &keyBlock512)

		for lane := 0; lane < 4; lane++ {
			if gotDisp256[lane] != want256[lane] {
				t.Fatalf("BatchPRF256x4 mismatch at len=%d lane=%d:\ngot  %x\nwant %x", n, lane, gotDisp256[lane], want256[lane])
			}
			if gotScal256[lane] != want256[lane] {
				t.Fatalf("scalarBatchPRF256x4 mismatch at len=%d lane=%d", n, lane)
			}
			if gotDisp512[lane] != want512[lane] {
				t.Fatalf("BatchPRF512x4 mismatch at len=%d lane=%d:\ngot  %x\nwant %x", n, lane, gotDisp512[lane], want512[lane])
			}
			if gotScal512[lane] != want512[lane] {
				t.Fatalf("scalarBatchPRF512x4 mismatch at len=%d lane=%d", n, lane)
			}
		}
	}

	// Mixed lengths across lanes.
	mixedSets := [][4]int{
		{0, 24, 64, 200},
		{24, 24, 24, 25},
		{128, 128, 129, 128},
	}
	for _, lens := range mixedSets {
		var inSlices [4][]byte
		var want256 [4][32]byte
		var want512 [4][64]byte
		for lane := 0; lane < 4; lane++ {
			buf := make([]byte, lens[lane])
			for i := range buf {
				buf[i] = byte(lane*29 + i*17 + 3)
			}
			inSlices[lane] = buf
			want256[lane] = refBlake2b256(key[:], buf)
			want512[lane] = refBlake2b512(key[:], buf)
		}
		var got256 [4][32]byte
		var got512 [4][64]byte
		d256 := [4][]byte{got256[0][:], got256[1][:], got256[2][:], got256[3][:]}
		d512 := [4][]byte{got512[0][:], got512[1][:], got512[2][:], got512[3][:]}
		BatchPRF256x4(&d256, &inSlices, &hKey256, &keyBlock256)
		BatchPRF512x4(&d512, &inSlices, &hKey512, &keyBlock512)
		for lane := 0; lane < 4; lane++ {
			if got256[lane] != want256[lane] {
				t.Fatalf("BatchPRF256x4 mixed %v mismatch on lane %d", lens, lane)
			}
			if got512[lane] != want512[lane] {
				t.Fatalf("BatchPRF512x4 mixed %v mismatch on lane %d", lens, lane)
			}
		}
	}
}

// TestXORKeyStreamBlocksParity verifies XORKeyStreamBlocks256 and
// XORKeyStreamBlocks512 across block counts 1..25, counters including 64-bit
// wraparound (0xffffffffffffffff -> 0), out-of-place, in-place, and unaligned
// buffers against golang.org/x/crypto/blake2b.
func TestXORKeyStreamBlocksParity(t *testing.T) {
	var key [KeySize]byte
	var nonceBytes [NonceSize]byte
	for i := range key {
		key[i] = byte(0x19 + i*7)
	}
	for i := range nonceBytes {
		nonceBytes[i] = byte(0xa5 + i*11)
	}
	nonce := [2]uint64{
		binary.LittleEndian.Uint64(nonceBytes[0:8]),
		binary.LittleEndian.Uint64(nonceBytes[8:16]),
	}
	var hKey256, hKey512 [8]uint64
	var keyBlock256, keyBlock512 [4]uint64
	InitKey256(key[:], &hKey256, &keyBlock256)
	InitKey512(key[:], &hKey512, &keyBlock512)

	counters := []uint64{0, 1, 7, 42, 0xfffffffffffffffe, 0xffffffffffffffff}
	for _, ctr := range counters {
		for nBlocks := 1; nBlocks <= 25; nBlocks++ {
			// BLAKE2b-256
			n256 := nBlocks * BlockSize256
			src256 := make([]byte, n256+7)
			for i := range src256 {
				src256[i] = byte(i*29 + 5)
			}
			s256 := src256[3 : 3+n256]
			want256 := make([]byte, n256)
			for b := 0; b < nBlocks; b++ {
				var msg [24]byte
				copy(msg[0:16], nonceBytes[:])
				binary.LittleEndian.PutUint64(msg[16:24], ctr+uint64(b))
				ks := refBlake2b256(key[:], msg[:])
				for i := 0; i < BlockSize256; i++ {
					want256[b*BlockSize256+i] = s256[b*BlockSize256+i] ^ ks[i]
				}
			}

			gotDisp256Buf := make([]byte, n256+5)
			gotDisp256 := gotDisp256Buf[1 : 1+n256]
			XORKeyStreamBlocks256(gotDisp256, s256, &hKey256, &nonce, ctr)
			if !bytes.Equal(gotDisp256, want256) {
				t.Fatalf("XORKeyStreamBlocks256 mismatch at ctr=%#x nBlocks=%d", ctr, nBlocks)
			}

			gotScal256 := make([]byte, n256)
			scalarXORKeyStreamBlocks256(gotScal256, s256, &hKey256, &nonce, ctr)
			if !bytes.Equal(gotScal256, want256) {
				t.Fatalf("scalarXORKeyStreamBlocks256 mismatch at ctr=%#x nBlocks=%d", ctr, nBlocks)
			}

			// In-place test
			inPlace256 := append([]byte(nil), s256...)
			XORKeyStreamBlocks256(inPlace256, inPlace256, &hKey256, &nonce, ctr)
			if !bytes.Equal(inPlace256, want256) {
				t.Fatalf("XORKeyStreamBlocks256 in-place mismatch at ctr=%#x nBlocks=%d", ctr, nBlocks)
			}

			// BLAKE2b-512
			n512 := nBlocks * BlockSize512
			src512 := make([]byte, n512+7)
			for i := range src512 {
				src512[i] = byte(i*31 + 11)
			}
			s512 := src512[3 : 3+n512]
			want512 := make([]byte, n512)
			for b := 0; b < nBlocks; b++ {
				var msg [24]byte
				copy(msg[0:16], nonceBytes[:])
				binary.LittleEndian.PutUint64(msg[16:24], ctr+uint64(b))
				ks := refBlake2b512(key[:], msg[:])
				for i := 0; i < BlockSize512; i++ {
					want512[b*BlockSize512+i] = s512[b*BlockSize512+i] ^ ks[i]
				}
			}

			gotDisp512Buf := make([]byte, n512+5)
			gotDisp512 := gotDisp512Buf[1 : 1+n512]
			XORKeyStreamBlocks512(gotDisp512, s512, &hKey512, &nonce, ctr)
			if !bytes.Equal(gotDisp512, want512) {
				t.Fatalf("XORKeyStreamBlocks512 mismatch at ctr=%#x nBlocks=%d", ctr, nBlocks)
			}

			gotScal512 := make([]byte, n512)
			scalarXORKeyStreamBlocks512(gotScal512, s512, &hKey512, &nonce, ctr)
			if !bytes.Equal(gotScal512, want512) {
				t.Fatalf("scalarXORKeyStreamBlocks512 mismatch at ctr=%#x nBlocks=%d", ctr, nBlocks)
			}

			// In-place test
			inPlace512 := append([]byte(nil), s512...)
			XORKeyStreamBlocks512(inPlace512, inPlace512, &hKey512, &nonce, ctr)
			if !bytes.Equal(inPlace512, want512) {
				t.Fatalf("XORKeyStreamBlocks512 in-place mismatch at ctr=%#x nBlocks=%d", ctr, nBlocks)
			}
		}
	}
}

// TestNonAffinity verifies Mandatory Invariant Check #1:
// f(a) ^ f(b) ^ f(c) ^ f(a ^ b ^ c) != 0 across all shipped input lengths.
func TestNonAffinity(t *testing.T) {
	var key [KeySize]byte
	for i := range key {
		key[i] = byte(0x37 + i*5)
	}
	var hKey256, hKey512 [8]uint64
	var keyBlock256, keyBlock512 [4]uint64
	InitKey256(key[:], &hKey256, &keyBlock256)
	InitKey512(key[:], &hKey512, &keyBlock512)

	lengths := []int{1, 8, 16, 24, 32, 48, 64, 128, 129, 256}
	for _, n := range lengths {
		a := make([]byte, n)
		b := make([]byte, n)
		c := make([]byte, n)
		abc := make([]byte, n)
		for i := 0; i < n; i++ {
			a[i] = byte(i*17 + 1)
			b[i] = byte(i*31 + 2)
			c[i] = byte(i*47 + 4)
			abc[i] = a[i] ^ b[i] ^ c[i]
		}
		var out256 [4][32]byte
		var out512 [4][64]byte
		d256 := [4][]byte{out256[0][:], out256[1][:], out256[2][:], out256[3][:]}
		d512 := [4][]byte{out512[0][:], out512[1][:], out512[2][:], out512[3][:]}
		in := [4][]byte{a, b, c, abc}
		BatchPRF256x4(&d256, &in, &hKey256, &keyBlock256)
		BatchPRF512x4(&d512, &in, &hKey512, &keyBlock512)

		var xor256 [32]byte
		for i := 0; i < 32; i++ {
			xor256[i] = out256[0][i] ^ out256[1][i] ^ out256[2][i] ^ out256[3][i]
		}
		if xor256 == ([32]byte{}) {
			t.Fatalf("BLAKE2b-256 affine at len=%d", n)
		}

		var xor512 [64]byte
		for i := 0; i < 64; i++ {
			xor512[i] = out512[0][i] ^ out512[1][i] ^ out512[2][i] ^ out512[3][i]
		}
		if xor512 == ([64]byte{}) {
			t.Fatalf("BLAKE2b-512 affine at len=%d", n)
		}
	}
}

// TestCompressionAndLengthNonCollision verifies Mandatory Invariant Check #2:
// chunk-swap and trailing-zero-extension inputs never collide.
func TestCompressionAndLengthNonCollision(t *testing.T) {
	var key [KeySize]byte
	for i := range key {
		key[i] = byte(0x73 + i*9)
	}
	var hKey256, hKey512 [8]uint64
	var keyBlock256, keyBlock512 [4]uint64
	InitKey256(key[:], &hKey256, &keyBlock256)
	InitKey512(key[:], &hKey512, &keyBlock512)

	// Trailing-zero extension check across boundaries.
	for _, n := range []int{0, 1, 7, 8, 15, 16, 23, 24, 31, 32, 63, 64, 127, 128, 255, 256} {
		in1 := make([]byte, n)
		for i := range in1 {
			in1[i] = byte(i*13 + 5)
		}
		in2 := append(append([]byte(nil), in1...), 0x00)

		var o1_256, o2_256 [32]byte
		Eval256(o1_256[:], in1, &hKey256, &keyBlock256)
		Eval256(o2_256[:], in2, &hKey256, &keyBlock256)
		if o1_256 == o2_256 {
			t.Fatalf("Eval256 trailing-zero collision between len=%d and len=%d", n, n+1)
		}

		var o1_512, o2_512 [64]byte
		Eval512(o1_512[:], in1, &hKey512, &keyBlock512)
		Eval512(o2_512[:], in2, &hKey512, &keyBlock512)
		if o1_512 == o2_512 {
			t.Fatalf("Eval512 trailing-zero collision between len=%d and len=%d", n, n+1)
		}
	}

	// Chunk-swap check for 24B, 64B, 128B, and 256B inputs.
	for _, n := range []int{24, 64, 128, 256} {
		in1 := make([]byte, n)
		for i := range in1 {
			in1[i] = byte(i*23 + 1)
		}
		in2 := make([]byte, n)
		half := n / 2
		copy(in2[:half], in1[half:])
		copy(in2[half:], in1[:half])

		var o1_256, o2_256 [32]byte
		Eval256(o1_256[:], in1, &hKey256, &keyBlock256)
		Eval256(o2_256[:], in2, &hKey256, &keyBlock256)
		if o1_256 == o2_256 {
			t.Fatalf("Eval256 chunk-swap collision at len=%d", n)
		}

		var o1_512, o2_512 [64]byte
		Eval512(o1_512[:], in1, &hKey512, &keyBlock512)
		Eval512(o2_512[:], in2, &hKey512, &keyBlock512)
		if o1_512 == o2_512 {
			t.Fatalf("Eval512 chunk-swap collision at len=%d", n)
		}
	}
}

// TestKeyNonceCounterBitSensitivity verifies Mandatory Invariant Check #3:
// flipping any bit of the 256-bit key, 128-bit nonce, or 64-bit counter changes
// every output block across all SIMD lanes and scalar tail (7 blocks = 4 + 3).
func TestKeyNonceCounterBitSensitivity(t *testing.T) {
	const nBlocks = 7
	var key [KeySize]byte
	for i := range key {
		key[i] = byte(0x01 + i*3)
	}
	nonce := [2]uint64{0x0807060504030201, 0x100f0e0d0c0b0a09}
	counter := uint64(5)

	var hKey256, hKey512 [8]uint64
	var keyBlock256, keyBlock512 [4]uint64
	InitKey256(key[:], &hKey256, &keyBlock256)
	InitKey512(key[:], &hKey512, &keyBlock512)

	src256 := make([]byte, nBlocks*BlockSize256)
	base256 := make([]byte, nBlocks*BlockSize256)
	out256 := make([]byte, nBlocks*BlockSize256)
	XORKeyStreamBlocks256(base256, src256, &hKey256, &nonce, counter)

	src512 := make([]byte, nBlocks*BlockSize512)
	base512 := make([]byte, nBlocks*BlockSize512)
	out512 := make([]byte, nBlocks*BlockSize512)
	XORKeyStreamBlocks512(base512, src512, &hKey512, &nonce, counter)

	// Flip each of the 256 key bits.
	for byteIdx := 0; byteIdx < KeySize; byteIdx++ {
		for bit := 0; bit < 8; bit++ {
			k2 := key
			k2[byteIdx] ^= 1 << bit
			var hk256, hk512 [8]uint64
			var kb256, kb512 [4]uint64
			InitKey256(k2[:], &hk256, &kb256)
			InitKey512(k2[:], &hk512, &kb512)
			XORKeyStreamBlocks256(out256, src256, &hk256, &nonce, counter)
			XORKeyStreamBlocks512(out512, src512, &hk512, &nonce, counter)
			for blk := 0; blk < nBlocks; blk++ {
				if bytes.Equal(out256[blk*32:(blk+1)*32], base256[blk*32:(blk+1)*32]) {
					t.Fatalf("256: key byte %d bit %d did not change block %d", byteIdx, bit, blk)
				}
				if bytes.Equal(out512[blk*64:(blk+1)*64], base512[blk*64:(blk+1)*64]) {
					t.Fatalf("512: key byte %d bit %d did not change block %d", byteIdx, bit, blk)
				}
			}
		}
	}

	// Flip each of the 128 nonce bits.
	for w := 0; w < 2; w++ {
		for bit := 0; bit < 64; bit++ {
			n2 := nonce
			n2[w] ^= uint64(1) << bit
			XORKeyStreamBlocks256(out256, src256, &hKey256, &n2, counter)
			XORKeyStreamBlocks512(out512, src512, &hKey512, &n2, counter)
			for blk := 0; blk < nBlocks; blk++ {
				if bytes.Equal(out256[blk*32:(blk+1)*32], base256[blk*32:(blk+1)*32]) {
					t.Fatalf("256: nonce word %d bit %d did not change block %d", w, bit, blk)
				}
				if bytes.Equal(out512[blk*64:(blk+1)*64], base512[blk*64:(blk+1)*64]) {
					t.Fatalf("512: nonce word %d bit %d did not change block %d", w, bit, blk)
				}
			}
		}
	}

	// Flip each of the 64 counter bits.
	for bit := 0; bit < 64; bit++ {
		c2 := counter ^ (uint64(1) << bit)
		XORKeyStreamBlocks256(out256, src256, &hKey256, &nonce, c2)
		XORKeyStreamBlocks512(out512, src512, &hKey512, &nonce, c2)
		if bytes.Equal(out256, base256) {
			t.Fatalf("256: counter bit %d did not change output", bit)
		}
		if bytes.Equal(out512, base512) {
			t.Fatalf("512: counter bit %d did not change output", bit)
		}
	}
}

// TestZeroAllocations verifies that InitKey, Eval, BatchPRFx4, and
// XORKeyStreamBlocks perform zero heap allocations across all input paths.
func TestZeroAllocations(t *testing.T) {
	var key [KeySize]byte
	var hKey256, hKey512 [8]uint64
	var keyBlock256, keyBlock512 [4]uint64
	InitKey256(key[:], &hKey256, &keyBlock256)
	InitKey512(key[:], &hKey512, &keyBlock512)
	nonce := [2]uint64{1, 2}

	var out256 [32]byte
	var out512 [64]byte
	in24 := make([]byte, 24)
	in64 := make([]byte, 64)
	in200 := make([]byte, 200)

	if allocs := testing.AllocsPerRun(100, func() {
		Eval256(out256[:], in24, &hKey256, &keyBlock256)
		Eval256(out256[:], in64, &hKey256, &keyBlock256)
		Eval256(out256[:], in200, &hKey256, &keyBlock256)
		Eval512(out512[:], in24, &hKey512, &keyBlock512)
		Eval512(out512[:], in64, &hKey512, &keyBlock512)
		Eval512(out512[:], in200, &hKey512, &keyBlock512)
	}); allocs != 0 {
		t.Fatalf("Eval allocated %v times per run, want 0", allocs)
	}

	var bOut256 [4][32]byte
	var bOut512 [4][64]byte
	d256 := [4][]byte{bOut256[0][:], bOut256[1][:], bOut256[2][:], bOut256[3][:]}
	d512 := [4][]byte{bOut512[0][:], bOut512[1][:], bOut512[2][:], bOut512[3][:]}
	bIn24 := [4][]byte{in24, in24, in24, in24}
	bIn64 := [4][]byte{in64, in64, in64, in64}
	bIn200 := [4][]byte{in200, in200, in200, in200}

	if allocs := testing.AllocsPerRun(100, func() {
		BatchPRF256x4(&d256, &bIn24, &hKey256, &keyBlock256)
		BatchPRF256x4(&d256, &bIn64, &hKey256, &keyBlock256)
		BatchPRF256x4(&d256, &bIn200, &hKey256, &keyBlock256)
		BatchPRF512x4(&d512, &bIn24, &hKey512, &keyBlock512)
		BatchPRF512x4(&d512, &bIn64, &hKey512, &keyBlock512)
		BatchPRF512x4(&d512, &bIn200, &hKey512, &keyBlock512)
	}); allocs != 0 {
		t.Fatalf("BatchPRFx4 allocated %v times per run, want 0", allocs)
	}

	ks256 := make([]byte, 8*BlockSize256)
	ks512 := make([]byte, 8*BlockSize512)
	if allocs := testing.AllocsPerRun(100, func() {
		XORKeyStreamBlocks256(ks256, ks256, &hKey256, &nonce, 0)
		XORKeyStreamBlocks512(ks512, ks512, &hKey512, &nonce, 0)
	}); allocs != 0 {
		t.Fatalf("XORKeyStreamBlocks allocated %v times per run, want 0", allocs)
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

func makeTestSecrets(keyBlock *[4]uint64, hKey256, hKey512 *[8]uint64, nonce *[2]uint64) map[uint32]string {
	m := make(map[uint32]string, 28)
	add64 := func(w uint64, label string) {
		lo := uint32(w)
		hi := uint32(w >> 32)
		if lo != 0 {
			m[lo] = label + ".lo"
		}
		if hi != 0 {
			m[hi] = label + ".hi"
		}
	}
	for i, w := range keyBlock {
		add64(w, fmt.Sprintf("keyBlock[%d]", i))
	}
	for i := 0; i < 4; i++ {
		add64(hKey256[i], fmt.Sprintf("hKey256[%d]", i))
		add64(hKey512[i], fmt.Sprintf("hKey512[%d]", i))
	}
	for i, w := range nonce {
		add64(w, fmt.Sprintf("nonce[%d]", i))
	}
	return m
}

func TestScalarAndEvalStackZeroization(t *testing.T) {
	checkResidueNegativeControls(t)
	var keyBytes [KeySize]byte
	keyWords := [4]uint64{
		0xdeadbeefcafebabe,
		0x0123456789abcdef,
		0xfedcba9876543210,
		0x4b5a69780f1e2d3c,
	}
	for i, w := range keyWords {
		binary.LittleEndian.PutUint64(keyBytes[i*8:], w)
	}
	var hKey256, hKey512 [8]uint64
	var keyBlock256, keyBlock512 [4]uint64
	InitKey256(keyBytes[:], &hKey256, &keyBlock256)
	InitKey512(keyBytes[:], &hKey512, &keyBlock512)
	nonce := [2]uint64{0x1122334455667788, 0x99aabbccddeeff00}
	secrets := makeTestSecrets(&keyBlock256, &hKey256, &hKey512, &nonce)

	src256 := make([]byte, 4*BlockSize256)
	dst256 := make([]byte, 4*BlockSize256)
	resScalar256 := stackResidue(func() {
		scalarXORKeyStreamBlocks256(dst256, src256, &hKey256, &nonce, 1)
	})
	assertNoSecretResidue(t, "scalarXORKeyStreamBlocks256", resScalar256, secrets)

	src512 := make([]byte, 4*BlockSize512)
	dst512 := make([]byte, 4*BlockSize512)
	resScalar512 := stackResidue(func() {
		scalarXORKeyStreamBlocks512(dst512, src512, &hKey512, &nonce, 1)
	})
	assertNoSecretResidue(t, "scalarXORKeyStreamBlocks512", resScalar512, secrets)

	in200 := make([]byte, 200)
	var out256 [32]byte
	resEval256 := stackResidue(func() {
		Eval256(out256[:], in200, &hKey256, &keyBlock256)
	})
	assertNoSecretResidue(t, "Eval256(200B)", resEval256, secrets)

	var out512 [64]byte
	resEval512 := stackResidue(func() {
		Eval512(out512[:], in200, &hKey512, &keyBlock512)
	})
	assertNoSecretResidue(t, "Eval512(200B)", resEval512, secrets)

	var bOut256 [4][32]byte
	var bOut512 [4][64]byte
	d256 := [4][]byte{bOut256[0][:], bOut256[1][:], bOut256[2][:], bOut256[3][:]}
	d512 := [4][]byte{bOut512[0][:], bOut512[1][:], bOut512[2][:], bOut512[3][:]}
	in24 := make([]byte, 24)
	in64 := make([]byte, 64)
	bIn24 := [4][]byte{in24, in24, in24, in24}
	bIn64 := [4][]byte{in64, in64, in64, in64}

	resBatch24_256 := stackResidue(func() {
		BatchPRF256x4(&d256, &bIn24, &hKey256, &keyBlock256)
	})
	assertNoSecretResidue(t, "BatchPRF256x4(24B)", resBatch24_256, secrets)

	resBatch64_256 := stackResidue(func() {
		BatchPRF256x4(&d256, &bIn64, &hKey256, &keyBlock256)
	})
	assertNoSecretResidue(t, "BatchPRF256x4(64B)", resBatch64_256, secrets)

	resBatch24_512 := stackResidue(func() {
		BatchPRF512x4(&d512, &bIn24, &hKey512, &keyBlock512)
	})
	assertNoSecretResidue(t, "BatchPRF512x4(24B)", resBatch24_512, secrets)

	resBatch64_512 := stackResidue(func() {
		BatchPRF512x4(&d512, &bIn64, &hKey512, &keyBlock512)
	})
	assertNoSecretResidue(t, "BatchPRF512x4(64B)", resBatch64_512, secrets)

	runtime.KeepAlive(&hKey256)
	runtime.KeepAlive(&hKey512)
	runtime.KeepAlive(&keyBlock256)
	runtime.KeepAlive(&keyBlock512)
	runtime.KeepAlive(&nonce)
}
