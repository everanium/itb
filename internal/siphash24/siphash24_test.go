package siphash24

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"runtime"
	"runtime/debug"
	"testing"
	"unsafe"

	"github.com/dchest/siphash"
)

// goldenRef128 holds the 64 reference test vectors of SipHash-2-4-128
// (Aumasson & Bernstein 2012, key = 000102...0f, msg = 00..len-1 for len 0..63).
var goldenRef128 = [64][16]byte{
	{0xa3, 0x81, 0x7f, 0x04, 0xba, 0x25, 0xa8, 0xe6, 0x6d, 0xf6, 0x72, 0x14, 0xc7, 0x55, 0x02, 0x93},
	{0xda, 0x87, 0xc1, 0xd8, 0x6b, 0x99, 0xaf, 0x44, 0x34, 0x76, 0x59, 0x11, 0x9b, 0x22, 0xfc, 0x45},
	{0x81, 0x77, 0x22, 0x8d, 0xa4, 0xa4, 0x5d, 0xc7, 0xfc, 0xa3, 0x8b, 0xde, 0xf6, 0x0a, 0xff, 0xe4},
	{0x9c, 0x70, 0xb6, 0x0c, 0x52, 0x67, 0xa9, 0x4e, 0x5f, 0x33, 0xb6, 0xb0, 0x29, 0x85, 0xed, 0x51},
	{0xf8, 0x81, 0x64, 0xc1, 0x2d, 0x9c, 0x8f, 0xaf, 0x7d, 0x0f, 0x6e, 0x7c, 0x7b, 0xcd, 0x55, 0x79},
	{0x13, 0x68, 0x87, 0x59, 0x80, 0x77, 0x6f, 0x88, 0x54, 0x52, 0x7a, 0x07, 0x69, 0x0e, 0x96, 0x27},
	{0x14, 0xee, 0xca, 0x33, 0x8b, 0x20, 0x86, 0x13, 0x48, 0x5e, 0xa0, 0x30, 0x8f, 0xd7, 0xa1, 0x5e},
	{0xa1, 0xf1, 0xeb, 0xbe, 0xd8, 0xdb, 0xc1, 0x53, 0xc0, 0xb8, 0x4a, 0xa6, 0x1f, 0xf0, 0x82, 0x39},
	{0x3b, 0x62, 0xa9, 0xba, 0x62, 0x58, 0xf5, 0x61, 0x0f, 0x83, 0xe2, 0x64, 0xf3, 0x14, 0x97, 0xb4},
	{0x26, 0x44, 0x99, 0x06, 0x0a, 0xd9, 0xba, 0xab, 0xc4, 0x7f, 0x8b, 0x02, 0xbb, 0x6d, 0x71, 0xed},
	{0x00, 0x11, 0x0d, 0xc3, 0x78, 0x14, 0x69, 0x56, 0xc9, 0x54, 0x47, 0xd3, 0xf3, 0xd0, 0xfb, 0xba},
	{0x01, 0x51, 0xc5, 0x68, 0x38, 0x6b, 0x66, 0x77, 0xa2, 0xb4, 0xdc, 0x6f, 0x81, 0xe5, 0xdc, 0x18},
	{0xd6, 0x26, 0xb2, 0x66, 0x90, 0x5e, 0xf3, 0x58, 0x82, 0x63, 0x4d, 0xf6, 0x85, 0x32, 0xc1, 0x25},
	{0x98, 0x69, 0xe2, 0x47, 0xe9, 0xc0, 0x8b, 0x10, 0xd0, 0x29, 0x93, 0x4f, 0xc4, 0xb9, 0x52, 0xf7},
	{0x31, 0xfc, 0xef, 0xac, 0x66, 0xd7, 0xde, 0x9c, 0x7e, 0xc7, 0x48, 0x5f, 0xe4, 0x49, 0x49, 0x02},
	{0x54, 0x93, 0xe9, 0x99, 0x33, 0xb0, 0xa8, 0x11, 0x7e, 0x08, 0xec, 0x0f, 0x97, 0xcf, 0xc3, 0xd9},
	{0x6e, 0xe2, 0xa4, 0xca, 0x67, 0xb0, 0x54, 0xbb, 0xfd, 0x33, 0x15, 0xbf, 0x85, 0x23, 0x05, 0x77},
	{0x47, 0x3d, 0x06, 0xe8, 0x73, 0x8d, 0xb8, 0x98, 0x54, 0xc0, 0x66, 0xc4, 0x7a, 0xe4, 0x77, 0x40},
	{0xa4, 0x26, 0xe5, 0xe4, 0x23, 0xbf, 0x48, 0x85, 0x29, 0x4d, 0xa4, 0x81, 0xfe, 0xae, 0xf7, 0x23},
	{0x78, 0x01, 0x77, 0x31, 0xcf, 0x65, 0xfa, 0xb0, 0x74, 0xd5, 0x20, 0x89, 0x52, 0x51, 0x2e, 0xb1},
	{0x9e, 0x25, 0xfc, 0x83, 0x3f, 0x22, 0x90, 0x73, 0x3e, 0x93, 0x44, 0xa5, 0xe8, 0x38, 0x39, 0xeb},
	{0x56, 0x8e, 0x49, 0x5a, 0xbe, 0x52, 0x5a, 0x21, 0x8a, 0x22, 0x14, 0xcd, 0x3e, 0x07, 0x1d, 0x12},
	{0x4a, 0x29, 0xb5, 0x45, 0x52, 0xd1, 0x6b, 0x9a, 0x46, 0x9c, 0x10, 0x52, 0x8e, 0xff, 0x0a, 0xae},
	{0xc9, 0xd1, 0x84, 0xdd, 0xd5, 0xa9, 0xf5, 0xe0, 0xcf, 0x8c, 0xe2, 0x9a, 0x9a, 0xbf, 0x69, 0x1c},
	{0x2d, 0xb4, 0x79, 0xae, 0x78, 0xbd, 0x50, 0xd8, 0x88, 0x2a, 0x8a, 0x17, 0x8a, 0x61, 0x32, 0xad},
	{0x8e, 0xce, 0x5f, 0x04, 0x2d, 0x5e, 0x44, 0x7b, 0x50, 0x51, 0xb9, 0xea, 0xcb, 0x8d, 0x8f, 0x6f},
	{0x9c, 0x0b, 0x53, 0xb4, 0xb3, 0xc3, 0x07, 0xe8, 0x7e, 0xae, 0xe0, 0x86, 0x78, 0x14, 0x1f, 0x66},
	{0xab, 0xf2, 0x48, 0xaf, 0x69, 0xa6, 0xea, 0xe4, 0xbf, 0xd3, 0xeb, 0x2f, 0x12, 0x9e, 0xeb, 0x94},
	{0x06, 0x64, 0xda, 0x16, 0x68, 0x57, 0x4b, 0x88, 0xb9, 0x35, 0xf3, 0x02, 0x73, 0x58, 0xae, 0xf4},
	{0xaa, 0x4b, 0x9d, 0xc4, 0xbf, 0x33, 0x7d, 0xe9, 0x0c, 0xd4, 0xfd, 0x3c, 0x46, 0x7c, 0x6a, 0xb7},
	{0xea, 0x5c, 0x7f, 0x47, 0x1f, 0xaf, 0x6b, 0xde, 0x2b, 0x1a, 0xd7, 0xd4, 0x68, 0x6d, 0x22, 0x87},
	{0x29, 0x39, 0xb0, 0x18, 0x32, 0x23, 0xfa, 0xfc, 0x17, 0x23, 0xde, 0x4f, 0x52, 0xc4, 0x3d, 0x35},
	{0x7c, 0x39, 0x56, 0xca, 0x5e, 0xea, 0xfc, 0x3e, 0x36, 0x3e, 0x9d, 0x55, 0x65, 0x46, 0xeb, 0x68},
	{0x77, 0xc6, 0x07, 0x71, 0x46, 0xf0, 0x1c, 0x32, 0xb6, 0xb6, 0x9d, 0x5f, 0x4e, 0xa9, 0xff, 0xcf},
	{0x37, 0xa6, 0x98, 0x6c, 0xb8, 0x84, 0x7e, 0xdf, 0x09, 0x25, 0xf0, 0xf1, 0x30, 0x9b, 0x54, 0xde},
	{0xa7, 0x05, 0xf0, 0xe6, 0x9d, 0xa9, 0xa8, 0xf9, 0x07, 0x24, 0x1a, 0x2e, 0x92, 0x3c, 0x8c, 0xc8},
	{0x3d, 0xc4, 0x7d, 0x1f, 0x29, 0xc4, 0x48, 0x46, 0x1e, 0x9e, 0x76, 0xed, 0x90, 0x4f, 0x67, 0x11},
	{0x0d, 0x62, 0xbf, 0x01, 0xe6, 0xfc, 0x0e, 0x1a, 0x0d, 0x3c, 0x47, 0x51, 0xc5, 0xd3, 0x69, 0x2b},
	{0x8c, 0x03, 0x46, 0x8b, 0xca, 0x7c, 0x66, 0x9e, 0xe4, 0xfd, 0x5e, 0x08, 0x4b, 0xbe, 0xe7, 0xb5},
	{0x52, 0x8a, 0x5b, 0xb9, 0x3b, 0xaf, 0x2c, 0x9c, 0x44, 0x73, 0xcc, 0xe5, 0xd0, 0xd2, 0x2b, 0xd9},
	{0xdf, 0x6a, 0x30, 0x1e, 0x95, 0xc9, 0x5d, 0xad, 0x97, 0xae, 0x0c, 0xc8, 0xc6, 0x91, 0x3b, 0xd8},
	{0x80, 0x11, 0x89, 0x90, 0x2c, 0x85, 0x7f, 0x39, 0xe7, 0x35, 0x91, 0x28, 0x5e, 0x70, 0xb6, 0xdb},
	{0xe6, 0x17, 0x34, 0x6a, 0xc9, 0xc2, 0x31, 0xbb, 0x36, 0x50, 0xae, 0x34, 0xcc, 0xca, 0x0c, 0x5b},
	{0x27, 0xd9, 0x34, 0x37, 0xef, 0xb7, 0x21, 0xaa, 0x40, 0x18, 0x21, 0xdc, 0xec, 0x5a, 0xdf, 0x89},
	{0x89, 0x23, 0x7d, 0x9d, 0xed, 0x9c, 0x5e, 0x78, 0xd8, 0xb1, 0xc9, 0xb1, 0x66, 0xcc, 0x73, 0x42},
	{0x4a, 0x6d, 0x80, 0x91, 0xbf, 0x5e, 0x7d, 0x65, 0x11, 0x89, 0xfa, 0x94, 0xa2, 0x50, 0xb1, 0x4c},
	{0x0e, 0x33, 0xf9, 0x60, 0x55, 0xe7, 0xae, 0x89, 0x3f, 0xfc, 0x0e, 0x3d, 0xcf, 0x49, 0x29, 0x02},
	{0xe6, 0x1c, 0x43, 0x2b, 0x72, 0x0b, 0x19, 0xd1, 0x8e, 0xc8, 0xd8, 0x4b, 0xdc, 0x63, 0x15, 0x1b},
	{0xf7, 0xe5, 0xae, 0xf5, 0x49, 0xf7, 0x82, 0xcf, 0x37, 0x90, 0x55, 0xa6, 0x08, 0x26, 0x9b, 0x16},
	{0x43, 0x8d, 0x03, 0x0f, 0xd0, 0xb7, 0xa5, 0x4f, 0xa8, 0x37, 0xf2, 0xad, 0x20, 0x1a, 0x64, 0x03},
	{0xa5, 0x90, 0xd3, 0xee, 0x4f, 0xbf, 0x04, 0xe3, 0x24, 0x7e, 0x0d, 0x27, 0xf2, 0x86, 0x42, 0x3f},
	{0x5f, 0xe2, 0xc1, 0xa1, 0x72, 0xfe, 0x93, 0xc4, 0xb1, 0x5c, 0xd3, 0x7c, 0xae, 0xf9, 0xf5, 0x38},
	{0x2c, 0x97, 0x32, 0x5c, 0xbd, 0x06, 0xb3, 0x6e, 0xb2, 0x13, 0x3d, 0xd0, 0x8b, 0x3a, 0x01, 0x7c},
	{0x92, 0xc8, 0x14, 0x22, 0x7a, 0x6b, 0xca, 0x94, 0x9f, 0xf0, 0x65, 0x9f, 0x00, 0x2a, 0xd3, 0x9e},
	{0xdc, 0xe8, 0x50, 0x11, 0x0b, 0xd8, 0x32, 0x8c, 0xfb, 0xd5, 0x08, 0x41, 0xd6, 0x91, 0x1d, 0x87},
	{0x67, 0xf1, 0x49, 0x84, 0xc7, 0xda, 0x79, 0x12, 0x48, 0xe3, 0x2b, 0xb5, 0x92, 0x25, 0x83, 0xda},
	{0x19, 0x38, 0xf2, 0xcf, 0x72, 0xd5, 0x4e, 0xe9, 0x7e, 0x94, 0x16, 0x6f, 0xa9, 0x1d, 0x2a, 0x36},
	{0x74, 0x48, 0x1e, 0x96, 0x46, 0xed, 0x49, 0xfe, 0x0f, 0x62, 0x24, 0x30, 0x16, 0x04, 0x69, 0x8e},
	{0x57, 0xfc, 0xa5, 0xde, 0x98, 0xa9, 0xd6, 0xd8, 0x00, 0x64, 0x38, 0xd0, 0x58, 0x3d, 0x8a, 0x1d},
	{0x9f, 0xec, 0xde, 0x1c, 0xef, 0xdc, 0x1c, 0xbe, 0xd4, 0x76, 0x36, 0x74, 0xd9, 0x57, 0x53, 0x59},
	{0xe3, 0x04, 0x0c, 0x00, 0xeb, 0x28, 0xf1, 0x53, 0x66, 0xca, 0x73, 0xcb, 0xd8, 0x72, 0xe7, 0x40},
	{0x76, 0x97, 0x00, 0x9a, 0x6a, 0x83, 0x1d, 0xfe, 0xcc, 0xa9, 0x1c, 0x59, 0x93, 0x67, 0x0f, 0x7a},
	{0x58, 0x53, 0x54, 0x23, 0x21, 0xf5, 0x67, 0xa0, 0x05, 0xd5, 0x47, 0xa4, 0xf0, 0x47, 0x59, 0xbd},
	{0x51, 0x50, 0xd1, 0x77, 0x2f, 0x50, 0x83, 0x4a, 0x50, 0x3e, 0x06, 0x9a, 0x97, 0x3f, 0xbd, 0x7c},
}

func TestOfficialKAT128(t *testing.T) {
	var key [16]byte
	for i := range key {
		key[i] = byte(i)
	}
	k0 := binary.LittleEndian.Uint64(key[:8])
	k1 := binary.LittleEndian.Uint64(key[8:16])

	var in [64]byte
	for i := 0; i < 64; i++ {
		in[i] = byte(i)
		var got [16]byte
		Sum128Into(got[:], k0, k1, in[:i])
		if got != goldenRef128[i] {
			t.Fatalf("len=%d: got %x, want %x", i, got[:], goldenRef128[i][:])
		}
	}
}

func TestParityWithDchestSiphash(t *testing.T) {
	keys := [][16]byte{
		{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
		{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00},
		{0x42, 0x13, 0x37, 0x99, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x23, 0x45, 0x67},
	}

	for ki, key := range keys {
		k0 := binary.LittleEndian.Uint64(key[:8])
		k1 := binary.LittleEndian.Uint64(key[8:16])

		for n := 0; n <= 136; n++ {
			msg := make([]byte, n)
			for i := range msg {
				msg[i] = byte(i*31 + ki*17 + n)
			}

			wantLo, wantHi := siphash.Hash128(k0, k1, msg)
			gotLo, gotHi := Hash128(k0, k1, msg)
			if gotLo != wantLo || gotHi != wantHi {
				t.Fatalf("Hash128(key=%d, len=%d): got (%#x, %#x), want (%#x, %#x)",
					ki, n, gotLo, gotHi, wantLo, wantHi)
			}

			var sumOut [16]byte
			Sum128Into(sumOut[:], k0, k1, msg)
			if binary.LittleEndian.Uint64(sumOut[:8]) != wantLo || binary.LittleEndian.Uint64(sumOut[8:16]) != wantHi {
				t.Fatalf("Sum128Into(key=%d, len=%d) mismatch", ki, n)
			}

			if n == 16 {
				var blkOut [16]byte
				m0 := binary.LittleEndian.Uint64(msg[:8])
				m1 := binary.LittleEndian.Uint64(msg[8:16])
				Block128Into(&blkOut, k0, k1, m0, m1)
				if !bytes.Equal(blkOut[:], sumOut[:]) {
					t.Fatalf("Block128Into(key=%d) = %x, want %x", ki, blkOut[:], sumOut[:])
				}
			}

			refH := siphash.New128(key[:])
			refH.Write(msg)
			wantBytes := refH.Sum(nil)

			h := New128(key[:])
			h.Write(msg)
			gotBytes := h.Sum(nil)
			if !bytes.Equal(gotBytes, wantBytes) {
				t.Fatalf("New128 single Write(key=%d, len=%d): got %x, want %x", ki, n, gotBytes, wantBytes)
			}
			if !bytes.Equal(h.Sum(nil), wantBytes) {
				t.Fatalf("New128 second Sum(key=%d, len=%d) mutated state", ki, n)
			}

			for step := 1; step <= 13; step += 2 {
				h.Reset()
				for off := 0; off < len(msg); off += step {
					end := off + step
					if end > len(msg) {
						end = len(msg)
					}
					h.Write(msg[off:end])
				}
				if !bytes.Equal(h.Sum(nil), wantBytes) {
					t.Fatalf("New128 chunked(step=%d, key=%d, len=%d) mismatch", step, ki, n)
				}
			}

			if c, ok := h.(interface{ Close() error }); ok {
				_ = c.Close()
			}
		}
	}
}

// TestCTRKATAndBatchGoldenVector verifies hardcoded hex KAT vectors for
// single-lane Block128Raw (Aumasson & Bernstein 2012 §2.4 16-byte vector) and
// the 4-lane CTR batch keystream at counters 0..3.
func TestCTRKATAndBatchGoldenVector(t *testing.T) {
	const (
		k0      = uint64(0x0706050403020100)
		k1      = uint64(0x0f0e0d0c0b0a0908)
		nonceHi = uint64(0x0706050403020100)
		nonceLo = uint64(0x0f0e0d0c0b0a0908)
	)
	// Counter 0 makes m0 || m1 = 000102030405060708090a0b0c0d0e0f, which is
	// Aumasson & Bernstein §2.4 len=16 vector: 6ee2a4ca67b054bbfd3315bf85230577.
	// Counters 0..3 form the 64-byte 4-lane CTR batch golden vector.
	const wantBatch4Hex = "" +
		"6ee2a4ca67b054bbfd3315bf85230577" +
		"f9f110d8d9cdd66f12de52c301047810" +
		"420cb7ca084ef149630cf018ef9d0a86" +
		"8b5df3468f58067c287566799fa2a510"

	wantBatch4, err := hex.DecodeString(wantBatch4Hex)
	if err != nil {
		t.Fatal(err)
	}

	var refBatch4 [64]byte
	for b := uint64(0); b < 4; b++ {
		lo, hi := Block128Raw(k0, k1, nonceHi, nonceLo^b)
		binary.LittleEndian.PutUint64(refBatch4[b*16:], lo)
		binary.LittleEndian.PutUint64(refBatch4[b*16+8:], hi)
	}
	if !bytes.Equal(refBatch4[:], wantBatch4) {
		t.Fatalf("Block128Raw 4-lane golden KAT mismatch:\ngot  %x\nwant %x", refBatch4, wantBatch4)
	}

	var zero64 [64]byte
	var gotCTR [64]byte
	XORKeyStreamBlocks(gotCTR[:], zero64[:], k0, k1, nonceHi, nonceLo, 0)
	if !bytes.Equal(gotCTR[:], wantBatch4) {
		t.Fatalf("XORKeyStreamBlocks 4-lane golden KAT mismatch:\ngot  %x\nwant %x", gotCTR, wantBatch4)
	}

	var vInit [4]uint64
	InitCTRState(&vInit, k0, k1, nonceHi)
	var gotState [64]byte
	XORKeyStreamBlocksWithState(gotState[:], zero64[:], &vInit, nonceLo, 0)
	if !bytes.Equal(gotState[:], wantBatch4) {
		t.Fatalf("XORKeyStreamBlocksWithState 4-lane golden KAT mismatch:\ngot  %x\nwant %x", gotState, wantBatch4)
	}

	// Verify 4-lane BatchPRFx4 on the 4-lane CTR messages and on Aumasson & Bernstein §2.4 len=24.
	var in16Buf [4][16]byte
	var dst16Buf [4][16]byte
	for lane := 0; lane < 4; lane++ {
		binary.LittleEndian.PutUint64(in16Buf[lane][0:8], nonceHi)
		binary.LittleEndian.PutUint64(in16Buf[lane][8:16], nonceLo^uint64(lane))
	}
	in16 := [4][]byte{in16Buf[0][:], in16Buf[1][:], in16Buf[2][:], in16Buf[3][:]}
	dst16 := [4][]byte{dst16Buf[0][:], dst16Buf[1][:], dst16Buf[2][:], dst16Buf[3][:]}
	BatchPRFx4(&dst16, &in16, k0, k1)
	for lane := 0; lane < 4; lane++ {
		if !bytes.Equal(dst16[lane], wantBatch4[lane*16:(lane+1)*16]) {
			t.Fatalf("BatchPRFx4(16B) lane %d: got %x, want %x", lane, dst16[lane], wantBatch4[lane*16:(lane+1)*16])
		}
	}

	var in24 [24]byte
	for i := range in24 {
		in24[i] = byte(i)
	}
	in24Lanes := [4][]byte{in24[:], in24[:], in24[:], in24[:]}
	BatchPRFx4(&dst16, &in24Lanes, k0, k1)
	for lane := 0; lane < 4; lane++ {
		if dst16Buf[lane] != goldenRef128[24] {
			t.Fatalf("BatchPRFx4(24B) lane %d: got %x, want %x", lane, dst16Buf[lane], goldenRef128[24])
		}
	}
}

// TestXORKeyStreamBlocksAndBatchPRFx4Parity tests XORKeyStreamBlocks,
// XORKeyStreamBlocksWithState, and BatchPRFx4 across nBlocks = 1..35,
// counter wrap (0xfffffffffffffffe, 0xffffffffffffffff), in-place and disjoint
// buffers, unaligned slices, and equal/mismatched BatchPRFx4 lane lengths.
func TestXORKeyStreamBlocksAndBatchPRFx4Parity(t *testing.T) {
	k0 := uint64(0x0706050403020100)
	k1 := uint64(0x0f0e0d0c0b0a0908)
	nonceHi := uint64(0xa1a2a3a4a5a6a7a8)
	nonceLo := uint64(0xb1b2b3b4b5b6b7b8)

	var vInit [4]uint64
	InitCTRState(&vInit, k0, k1, nonceHi)

	counters := []uint64{
		0, 1, 2, 7, 15, 64,
		0xfffffffffffffffc,
		0xfffffffffffffffe,
		0xffffffffffffffff,
	}

	for _, ctr := range counters {
		for nBlocks := 1; nBlocks <= 35; nBlocks++ {
			n := nBlocks * Size128
			rawSrc := make([]byte, n+16)
			for i := range rawSrc {
				rawSrc[i] = byte(i*29 + int(ctr) + nBlocks)
			}
			src := rawSrc[3 : 3+n]

			// Reference via Block128Raw per block.
			want := make([]byte, n)
			for b := 0; b < nBlocks; b++ {
				lo, hi := Block128Raw(k0, k1, nonceHi, nonceLo^(ctr+uint64(b)))
				sLo := binary.LittleEndian.Uint64(src[b*16:])
				sHi := binary.LittleEndian.Uint64(src[b*16+8:])
				binary.LittleEndian.PutUint64(want[b*16:], sLo^lo)
				binary.LittleEndian.PutUint64(want[b*16+8:], sHi^hi)
			}

			// Disjoint unaligned XORKeyStreamBlocks.
			rawDst1 := make([]byte, n+16)
			dst1 := rawDst1[5 : 5+n]
			XORKeyStreamBlocks(dst1, src, k0, k1, nonceHi, nonceLo, ctr)
			if !bytes.Equal(dst1, want) {
				t.Fatalf("XORKeyStreamBlocks mismatch at ctr=%#x nBlocks=%d", ctr, nBlocks)
			}

			// Disjoint unaligned XORKeyStreamBlocksWithState.
			rawDst2 := make([]byte, n+16)
			dst2 := rawDst2[7 : 7+n]
			XORKeyStreamBlocksWithState(dst2, src, &vInit, nonceLo, ctr)
			if !bytes.Equal(dst2, want) {
				t.Fatalf("XORKeyStreamBlocksWithState mismatch at ctr=%#x nBlocks=%d", ctr, nBlocks)
			}

			// In-place (dst == src) unaligned XORKeyStreamBlocksWithState.
			inPlaceBuf := make([]byte, n+16)
			inPlace := inPlaceBuf[1 : 1+n]
			copy(inPlace, src)
			XORKeyStreamBlocksWithState(inPlace, inPlace, &vInit, nonceLo, ctr)
			if !bytes.Equal(inPlace, want) {
				t.Fatalf("XORKeyStreamBlocksWithState in-place mismatch at ctr=%#x nBlocks=%d", ctr, nBlocks)
			}

			// Scalar reference parity.
			gotScalar := make([]byte, n)
			scalarXORKeyStreamBlocksWithState(gotScalar, src, &vInit, nonceLo, ctr)
			if !bytes.Equal(gotScalar, want) {
				t.Fatalf("scalarXORKeyStreamBlocksWithState mismatch at ctr=%#x nBlocks=%d", ctr, nBlocks)
			}
		}
	}

	// BatchPRFx4 equal-length parity across lengths 0..136.
	for msgLen := 0; msgLen <= 136; msgLen++ {
		var in [4][]byte
		var want [4][16]byte
		var gotBuf [4][24]byte
		var dst [4][]byte
		for lane := 0; lane < 4; lane++ {
			raw := make([]byte, msgLen+16)
			buf := raw[lane+1 : lane+1+msgLen]
			for i := range buf {
				buf[i] = byte(i*37 + lane*19 + msgLen)
			}
			in[lane] = buf
			Sum128Into(want[lane][:], k0, k1, buf)
			dst[lane] = gotBuf[lane][lane+1 : lane+1+16]
		}
		BatchPRFx4(&dst, &in, k0, k1)
		for lane := 0; lane < 4; lane++ {
			if !bytes.Equal(dst[lane], want[lane][:]) {
				t.Fatalf("BatchPRFx4 equal-len=%d lane=%d: got %x, want %x", msgLen, lane, dst[lane], want[lane])
			}
		}
	}

	// BatchPRFx4 mismatched-length fallback parity.
	mismatchedLens := [4]int{0, 13, 24, 68}
	var misIn [4][]byte
	var misWant [4][16]byte
	var misGotBuf [4][16]byte
	misDst := [4][]byte{misGotBuf[0][:], misGotBuf[1][:], misGotBuf[2][:], misGotBuf[3][:]}
	for lane, ln := range mismatchedLens {
		buf := make([]byte, ln)
		for i := range buf {
			buf[i] = byte(i*17 + lane*53 + 11)
		}
		misIn[lane] = buf
		Sum128Into(misWant[lane][:], k0, k1, buf)
	}
	BatchPRFx4(&misDst, &misIn, k0, k1)
	for lane := 0; lane < 4; lane++ {
		if misGotBuf[lane] != misWant[lane] {
			t.Fatalf("BatchPRFx4 mismatched lane=%d (len=%d): got %x, want %x",
				lane, mismatchedLens[lane], misGotBuf[lane], misWant[lane])
		}
	}
}

// TestSipHash24NonAffine verifies Mandatory Invariant Check #1 (Affinity):
// first-order differential f(a) ^ f(b) ^ f(c) ^ f(a ^ b ^ c) must not vanish
// under one key and nonce/seed across all shipped input lengths.
func TestSipHash24NonAffine(t *testing.T) {
	k0 := uint64(0x1122334455667788)
	k1 := uint64(0x99aabbccddeeff00)
	nonceHi := uint64(0x0102030405060708)

	// 1. CTR keystream block function f(m1) = Block128(k0, k1, nonceHi, m1).
	var vInit [4]uint64
	InitCTRState(&vInit, k0, k1, nonceHi)
	mA := uint64(0x13579bdf02468ace)
	mB := uint64(0xfedcba9876543210)
	mC := uint64(0x0f1e2d3c4b5a6978)
	mABC := mA ^ mB ^ mC

	var zero16, ksA, ksB, ksC, ksABC [16]byte
	XORKeyStreamBlocksWithState(ksA[:], zero16[:], &vInit, mA, 0)
	XORKeyStreamBlocksWithState(ksB[:], zero16[:], &vInit, mB, 0)
	XORKeyStreamBlocksWithState(ksC[:], zero16[:], &vInit, mC, 0)
	XORKeyStreamBlocksWithState(ksABC[:], zero16[:], &vInit, mABC, 0)

	var diffCTR [16]byte
	for i := 0; i < 16; i++ {
		diffCTR[i] = ksA[i] ^ ksB[i] ^ ksC[i] ^ ksABC[i]
	}
	if diffCTR == [16]byte{} {
		t.Fatal("CTR block function exhibited affine behavior: f(a)^f(b)^f(c)^f(a^b^c) == 0")
	}

	// 2. BatchPRFx4 across shipped input lengths (8, 13, 16, 20, 24, 32, 36, 64, 68).
	for _, msgLen := range []int{8, 13, 16, 20, 24, 32, 36, 64, 68} {
		a := make([]byte, msgLen)
		b := make([]byte, msgLen)
		c := make([]byte, msgLen)
		abc := make([]byte, msgLen)
		for i := 0; i < msgLen; i++ {
			a[i] = byte(i*19 + 0x11)
			b[i] = byte(i*37 + 0x54)
			c[i] = byte(i*73 + 0x9b)
			abc[i] = a[i] ^ b[i] ^ c[i]
		}
		in := [4][]byte{a, b, c, abc}
		var outBuf [4][16]byte
		dst := [4][]byte{outBuf[0][:], outBuf[1][:], outBuf[2][:], outBuf[3][:]}
		BatchPRFx4(&dst, &in, k0, k1)

		var diff [16]byte
		for i := 0; i < 16; i++ {
			diff[i] = outBuf[0][i] ^ outBuf[1][i] ^ outBuf[2][i] ^ outBuf[3][i]
		}
		if diff == [16]byte{} {
			t.Fatalf("BatchPRFx4(len=%d) exhibited affine behavior: f(a)^f(b)^f(c)^f(a^b^c) == 0", msgLen)
		}
	}
}

// TestSipHash24CompressionAndCollisions verifies Mandatory Invariant Check #2:
// chunk-swap and trailing-zero-extension inputs must not collide, and flipping
// any bit in the 128-bit key or 128-bit nonce alters every output block across
// all lanes.
func TestSipHash24CompressionAndCollisions(t *testing.T) {
	k0 := uint64(0x0123456789abcdef)
	k1 := uint64(0xfedcba9876543210)

	// 1. Chunk-swap: (m0 || m1) vs (m1 || m0) in Block128Raw and BatchPRFx4.
	w0 := uint64(0x1122334455667788)
	w1 := uint64(0x99aabbccddeeff01)
	lo01, hi01 := Block128Raw(k0, k1, w0, w1)
	lo10, hi10 := Block128Raw(k0, k1, w1, w0)
	if lo01 == lo10 && hi01 == hi10 {
		t.Fatal("chunk swap (w0 || w1) vs (w1 || w0) collided in Block128Raw")
	}

	// 2. 24-byte 3-word permutations in BatchPRFx4.
	w2 := uint64(0x55aa55aa12345678)
	var m24 [4][24]byte
	binary.LittleEndian.PutUint64(m24[0][0:8], w0)
	binary.LittleEndian.PutUint64(m24[0][8:16], w1)
	binary.LittleEndian.PutUint64(m24[0][16:24], w2)

	binary.LittleEndian.PutUint64(m24[1][0:8], w1)
	binary.LittleEndian.PutUint64(m24[1][8:16], w0)
	binary.LittleEndian.PutUint64(m24[1][16:24], w2)

	binary.LittleEndian.PutUint64(m24[2][0:8], w0)
	binary.LittleEndian.PutUint64(m24[2][8:16], w2)
	binary.LittleEndian.PutUint64(m24[2][16:24], w1)

	binary.LittleEndian.PutUint64(m24[3][0:8], w2)
	binary.LittleEndian.PutUint64(m24[3][8:16], w1)
	binary.LittleEndian.PutUint64(m24[3][16:24], w0)

	in24 := [4][]byte{m24[0][:], m24[1][:], m24[2][:], m24[3][:]}
	var out24 [4][16]byte
	dst24 := [4][]byte{out24[0][:], out24[1][:], out24[2][:], out24[3][:]}
	BatchPRFx4(&dst24, &in24, k0, k1)
	for i := 0; i < 4; i++ {
		for j := i + 1; j < 4; j++ {
			if out24[i] == out24[j] {
				t.Fatalf("24-byte word permutation %d and %d collided: %x", i, j, out24[i])
			}
		}
	}

	// 3. Trailing-zero extension: msg vs msg||0x00 vs msg||0x00*8.
	baseMsg := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	ext1 := append(append([]byte(nil), baseMsg...), 0x00)
	ext8 := append(append([]byte(nil), baseMsg...), make([]byte, 8)...)
	ext16 := append(append([]byte(nil), baseMsg...), make([]byte, 16)...)
	inExt := [4][]byte{baseMsg, ext1, ext8, ext16}
	var outExt [4][16]byte
	dstExt := [4][]byte{outExt[0][:], outExt[1][:], outExt[2][:], outExt[3][:]}
	BatchPRFx4(&dstExt, &inExt, k0, k1)
	for i := 0; i < 4; i++ {
		for j := i + 1; j < 4; j++ {
			if outExt[i] == outExt[j] {
				t.Fatalf("trailing-zero extension %d and %d collided: %x", i, j, outExt[i])
			}
		}
	}
}

// TestSipHash24KeyAndNonceSlotSecrecy verifies Mandatory Invariant Check #3:
// every bit of k0, k1, nonceHi, nonceLo, and vInit[0..3] alters every block
// across 15 blocks (8 + 4 + 3 lanes), and a public-zero-key negative control
// never matches any keyed output.
func TestSipHash24KeyAndNonceSlotSecrecy(t *testing.T) {
	const nBlocks = 15
	const nBytes = nBlocks * Size128
	k0 := uint64(0x0706050403020100)
	k1 := uint64(0x0f0e0d0c0b0a0908)
	nonceHi := uint64(0x2122232425262728)
	nonceLo := uint64(0x3132333435363738)
	counter := uint64(5)

	src := make([]byte, nBytes)
	base := make([]byte, nBytes)
	XORKeyStreamBlocks(base, src, k0, k1, nonceHi, nonceLo, counter)

	// Negative control: zero key (0, 0) or partially zeroed key (k0, 0) / (0, k1)
	// must not match any block of base.
	for _, trial := range [][2]uint64{{0, 0}, {k0, 0}, {0, k1}} {
		cand := make([]byte, nBytes)
		XORKeyStreamBlocks(cand, src, trial[0], trial[1], nonceHi, nonceLo, counter)
		for blk := 0; blk < nBlocks; blk++ {
			if bytes.Equal(cand[blk*16:(blk+1)*16], base[blk*16:(blk+1)*16]) {
				t.Fatalf("trial key (%#x, %#x) matched keyed block %d", trial[0], trial[1], blk)
			}
		}
	}

	out := make([]byte, nBytes)
	for bit := 0; bit < 64; bit++ {
		mask := uint64(1) << bit

		XORKeyStreamBlocks(out, src, k0^mask, k1, nonceHi, nonceLo, counter)
		for blk := 0; blk < nBlocks; blk++ {
			if bytes.Equal(out[blk*16:(blk+1)*16], base[blk*16:(blk+1)*16]) {
				t.Fatalf("k0 bit %d did not change block %d", bit, blk)
			}
		}

		XORKeyStreamBlocks(out, src, k0, k1^mask, nonceHi, nonceLo, counter)
		for blk := 0; blk < nBlocks; blk++ {
			if bytes.Equal(out[blk*16:(blk+1)*16], base[blk*16:(blk+1)*16]) {
				t.Fatalf("k1 bit %d did not change block %d", bit, blk)
			}
		}

		XORKeyStreamBlocks(out, src, k0, k1, nonceHi^mask, nonceLo, counter)
		for blk := 0; blk < nBlocks; blk++ {
			if bytes.Equal(out[blk*16:(blk+1)*16], base[blk*16:(blk+1)*16]) {
				t.Fatalf("nonceHi bit %d did not change block %d", bit, blk)
			}
		}

		XORKeyStreamBlocks(out, src, k0, k1, nonceHi, nonceLo^mask, counter)
		for blk := 0; blk < nBlocks; blk++ {
			if bytes.Equal(out[blk*16:(blk+1)*16], base[blk*16:(blk+1)*16]) {
				t.Fatalf("nonceLo bit %d did not change block %d", bit, blk)
			}
		}
	}

	// Also verify every bit of every word in BatchPRFx4 (24-byte CTR shape).
	var baseInBuf [4][24]byte
	var baseOutBuf [4][16]byte
	for lane := 0; lane < 4; lane++ {
		binary.LittleEndian.PutUint64(baseInBuf[lane][0:8], nonceHi)
		binary.LittleEndian.PutUint64(baseInBuf[lane][8:16], nonceLo)
		binary.LittleEndian.PutUint64(baseInBuf[lane][16:24], uint64(lane))
	}
	baseIn := [4][]byte{baseInBuf[0][:], baseInBuf[1][:], baseInBuf[2][:], baseInBuf[3][:]}
	baseDst := [4][]byte{baseOutBuf[0][:], baseOutBuf[1][:], baseOutBuf[2][:], baseOutBuf[3][:]}
	BatchPRFx4(&baseDst, &baseIn, k0, k1)

	var modOutBuf [4][16]byte
	modDst := [4][]byte{modOutBuf[0][:], modOutBuf[1][:], modOutBuf[2][:], modOutBuf[3][:]}
	for bit := 0; bit < 64; bit++ {
		mask := uint64(1) << bit
		BatchPRFx4(&modDst, &baseIn, k0^mask, k1)
		for lane := 0; lane < 4; lane++ {
			if modOutBuf[lane] == baseOutBuf[lane] {
				t.Fatalf("BatchPRFx4: k0 bit %d did not change lane %d", bit, lane)
			}
		}
		BatchPRFx4(&modDst, &baseIn, k0, k1^mask)
		for lane := 0; lane < 4; lane++ {
			if modOutBuf[lane] == baseOutBuf[lane] {
				t.Fatalf("BatchPRFx4: k1 bit %d did not change lane %d", bit, lane)
			}
		}
	}
	for byteIdx := 0; byteIdx < 24; byteIdx++ {
		for bit := 0; bit < 8; bit++ {
			var modInBuf [4][24]byte
			for lane := 0; lane < 4; lane++ {
				modInBuf[lane] = baseInBuf[lane]
				modInBuf[lane][byteIdx] ^= byte(1 << bit)
			}
			modIn := [4][]byte{modInBuf[0][:], modInBuf[1][:], modInBuf[2][:], modInBuf[3][:]}
			BatchPRFx4(&modDst, &modIn, k0, k1)
			for lane := 0; lane < 4; lane++ {
				if modOutBuf[lane] == baseOutBuf[lane] {
					t.Fatalf("BatchPRFx4: input byte %d bit %d did not change lane %d", byteIdx, bit, lane)
				}
			}
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

type sipHashSecretDict struct {
	s64 map[uint64]string
	s32 map[uint32]string
}

func makeSipHashSecrets(k0, k1, nonceHi, nonceLo uint64, vInit *[4]uint64) sipHashSecretDict {
	s64 := map[uint64]string{
		k0:          "k0",
		k1:          "k1",
		nonceHi:     "nonceHi",
		nonceLo:     "nonceLo",
		k0 ^ initV0: "k0^initV0",
		k1 ^ initV1: "k1^initV1",
		k0 ^ initV2: "k0^initV2",
		k1 ^ initV3: "k1^initV3",
	}
	for i, w := range vInit {
		s64[w] = fmt.Sprintf("vInit[%d]", i)
	}
	s32 := make(map[uint32]string, len(s64)*2)
	for w, name := range s64 {
		lo := uint32(w)
		hi := uint32(w >> 32)
		if lo != 0 {
			s32[lo] = name + ".lo32"
		}
		if hi != 0 {
			s32[hi] = name + ".hi32"
		}
	}
	return sipHashSecretDict{s64: s64, s32: s32}
}

func assertNoSecretResidue(t *testing.T, name string, res []uint64, secrets sipHashSecretDict) {
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
		if what, ok := secrets.s64[w]; ok {
			if i < stackWords {
				t.Errorf("%s: %s (%#x) left in stack %d bytes below window top", name, what, w, 8*(i+1))
			} else {
				t.Errorf("%s: %s (%#x) left in post-RET register snapshot (word %d)", name, what, w, i-stackWords)
			}
			continue
		}
		for h, d := range [2]uint32{uint32(w), uint32(w >> 32)} {
			if d == 0 {
				continue
			}
			if what, ok := secrets.s32[d]; ok {
				if i < stackWords {
					t.Errorf("%s: %s (%#x) left in stack %d bytes below window top", name, what, d, 8*(i+1)-4*h)
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

func TestSipHash24StackAndRegZeroization(t *testing.T) {
	checkResidueNegativeControls(t)
	const (
		k0      = uint64(0xdeadbeefcafebabe)
		k1      = uint64(0x0123456789abcdef)
		nonceHi = uint64(0xfedcba9876543210)
		nonceLo = uint64(0x4b5a69780f1e2d3c)
	)
	var vInit [4]uint64
	InitCTRState(&vInit, k0, k1, nonceHi)
	secrets := makeSipHashSecrets(k0, k1, nonceHi, nonceLo, &vInit)

	src := make([]byte, 15*Size128)
	dst := make([]byte, 15*Size128)

	resXOR := stackResidue(func() {
		XORKeyStreamBlocks(dst, src, k0, k1, nonceHi, nonceLo, 1)
	})
	assertNoSecretResidue(t, "XORKeyStreamBlocks", resXOR, secrets)

	resXORState := stackResidue(func() {
		XORKeyStreamBlocksWithState(dst, src, &vInit, nonceLo, 1)
	})
	assertNoSecretResidue(t, "XORKeyStreamBlocksWithState", resXORState, secrets)

	resScalarXOR := stackResidue(func() {
		scalarXORKeyStreamBlocksWithState(dst, src, &vInit, nonceLo, 1)
	})
	assertNoSecretResidue(t, "scalarXORKeyStreamBlocksWithState", resScalarXOR, secrets)

	var batchIn24Buf [4][24]byte
	var batchIn13Buf [4][13]byte
	var batchDstBuf [4][16]byte
	for lane := 0; lane < 4; lane++ {
		binary.LittleEndian.PutUint64(batchIn24Buf[lane][0:8], nonceHi)
		binary.LittleEndian.PutUint64(batchIn24Buf[lane][8:16], nonceLo)
		binary.LittleEndian.PutUint64(batchIn24Buf[lane][16:24], uint64(lane+1))
		binary.LittleEndian.PutUint64(batchIn13Buf[lane][0:8], nonceHi)
		binary.LittleEndian.PutUint32(batchIn13Buf[lane][8:12], uint32(lane+1))
		batchIn13Buf[lane][12] = byte(lane)
	}
	batchIn24 := [4][]byte{batchIn24Buf[0][:], batchIn24Buf[1][:], batchIn24Buf[2][:], batchIn24Buf[3][:]}
	batchIn13 := [4][]byte{batchIn13Buf[0][:], batchIn13Buf[1][:], batchIn13Buf[2][:], batchIn13Buf[3][:]}
	batchDst := [4][]byte{batchDstBuf[0][:], batchDstBuf[1][:], batchDstBuf[2][:], batchDstBuf[3][:]}

	resBatch24 := stackResidue(func() {
		BatchPRFx4(&batchDst, &batchIn24, k0, k1)
	})
	assertNoSecretResidue(t, "BatchPRFx4(24)", resBatch24, secrets)

	resBatch13 := stackResidue(func() {
		BatchPRFx4(&batchDst, &batchIn13, k0, k1)
	})
	assertNoSecretResidue(t, "BatchPRFx4(13)", resBatch13, secrets)

	resScalarBatch := stackResidue(func() {
		scalarBatchPRFx4(&batchDst, &batchIn24, k0, k1)
	})
	assertNoSecretResidue(t, "scalarBatchPRFx4(24)", resScalarBatch, secrets)

	runtime.KeepAlive(&vInit)
	runtime.KeepAlive(&batchIn24)
	runtime.KeepAlive(&batchIn13)
	runtime.KeepAlive(&batchDst)
	runtime.KeepAlive(src)
	runtime.KeepAlive(dst)
}

func BenchmarkXORKeyStreamBlocksWithState(b *testing.B) {
	k0 := uint64(0x0706050403020100)
	k1 := uint64(0x0f0e0d0c0b0a0908)
	nonceHi := uint64(0x2122232425262728)
	nonceLo := uint64(0x3132333435363738)
	var vInit [4]uint64
	InitCTRState(&vInit, k0, k1, nonceHi)

	buf := make([]byte, 4096)
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		XORKeyStreamBlocksWithState(buf, buf, &vInit, nonceLo, uint64(i)*256)
	}
}

func BenchmarkBatchPRFx4_24B(b *testing.B) {
	k0 := uint64(0x0706050403020100)
	k1 := uint64(0x0f0e0d0c0b0a0908)
	var inBuf [4][24]byte
	var outBuf [4][16]byte
	in := [4][]byte{inBuf[0][:], inBuf[1][:], inBuf[2][:], inBuf[3][:]}
	dst := [4][]byte{outBuf[0][:], outBuf[1][:], outBuf[2][:], outBuf[3][:]}
	b.SetBytes(4 * 16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BatchPRFx4(&dst, &in, k0, k1)
	}
}
