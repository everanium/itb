package capi

import (
	"encoding/binary"
	"fmt"
	"testing"
)

// TestHeaderSize confirms the capi HeaderSize helper accepts every
// valid nonce-byte value and rejects out-of-range inputs with
// StatusBadInput.
//
// The expected sizes here are a convenience pin, not the drift guard —
// they restate the formula rather than check it, so they stay green
// when this copy and itb.headerSizeCfg diverge together.
// [TestHeaderSizeMatchesWire] is the guard that actually catches drift.
func TestHeaderSize(t *testing.T) {
	cases := []struct {
		nonceBytes int
		want       int
		wantStatus Status
	}{
		{16, 20, StatusOK},
		{32, 36, StatusOK},
		{64, 68, StatusOK},
		{0, 0, StatusBadInput},
		{20, 0, StatusBadInput},
		{128, 0, StatusBadInput},
	}
	for _, c := range cases {
		got, st := HeaderSize(c.nonceBytes)
		if st != c.wantStatus {
			t.Errorf("HeaderSize(%d) status = %v, want %v", c.nonceBytes, st, c.wantStatus)
		}
		if got != c.want {
			t.Errorf("HeaderSize(%d) = %d, want %d", c.nonceBytes, got, c.want)
		}
	}
}

// TestHeaderSizeMatchesWire is the drift guard for the intentional
// formula duplication between itb.headerSizeCfg and [HeaderSize]. The
// FFI adapter keeps its own copy because its C-ABI stability contract
// is decoupled from itb-internal helpers, which means nothing in the
// type system ties the two together.
//
// Rather than restate the formula, this encrypts through the shim at
// each nonce width and locates where the produced bytes actually carry
// their container dimensions. Width and height are unsigned 16-bit
// big-endian and the container that follows is exactly
// width*height*Channels bytes, so scanning for the offset that
// satisfies that identity finds the dimension field without assuming
// anything about what precedes it.
//
// The shim's output is not the bare ITB wire — a constant-size
// envelope precedes it — so the absolute offset is not HeaderSize.
// What is checked instead is the DIFFERENCE across nonce widths, in
// which any constant envelope cancels: growing the nonce by k bytes
// must move the dimension field by exactly k. A copy that had kept a
// doubled nonce term would move it by 2k and fail here, which a
// literal pin in this package cannot detect.
func TestHeaderSizeMatchesWire(t *testing.T) {
	widths := []struct {
		nonceBits  int
		nonceBytes int
	}{{128, 16}, {256, 32}, {512, 64}}

	dimOffset := make(map[int]int, len(widths))
	for _, tc := range widths {
		blobBuf := make([]byte, 1<<15)
		sID, _, st := TripleInit("singlemsg-aesitb-mac-v1",
			fmt.Sprintf("nonceBits=%d", tc.nonceBits), blobBuf)
		if st != StatusOK {
			t.Fatalf("TripleInit(nonceBits=%d): %v (%s)", tc.nonceBits, st, LastError())
		}
		pt := make([]byte, 2048)
		for i := range pt {
			pt[i] = byte(i)
		}
		wire := make([]byte, len(pt)+64<<10)
		wLen, st := TripleEncryptMessage(sID, pt, wire)
		FreeTriple(sID)
		if st != StatusOK {
			t.Fatalf("TripleEncryptMessage(nonceBits=%d): %v (%s)", tc.nonceBits, st, LastError())
		}
		wire = wire[:wLen]

		var found []int
		for off := 4; off+4 <= len(wire); off++ {
			w := int(binary.BigEndian.Uint16(wire[off-4 : off-2]))
			h := int(binary.BigEndian.Uint16(wire[off-2 : off]))
			if w > 0 && h > 0 && w*h*Channels() == len(wire)-off {
				found = append(found, off)
			}
		}
		if len(found) != 1 {
			t.Fatalf("nonceBits=%d: want exactly one offset satisfying w*h*%d == len-off, got %v",
				tc.nonceBits, Channels(), found)
		}
		dimOffset[tc.nonceBytes] = found[0]
	}

	for i := 1; i < len(widths); i++ {
		lo, hi := widths[i-1].nonceBytes, widths[i].nonceBytes
		hLo, _ := HeaderSize(lo)
		hHi, _ := HeaderSize(hi)
		wantDelta := hHi - hLo
		gotDelta := dimOffset[hi] - dimOffset[lo]
		if gotDelta != wantDelta {
			t.Errorf("nonce %d→%d bytes: wire moves its dimension field by %d, HeaderSize predicts %d",
				lo, hi, gotDelta, wantDelta)
		}
	}
}

// TestReadOnlyConstants verifies build-time constants are reachable.
func TestReadOnlyConstants(t *testing.T) {
	if MaxKeyBits() != 2048 {
		t.Errorf("MaxKeyBits = %d, want 2048", MaxKeyBits())
	}
	if Channels() != 8 {
		t.Errorf("Channels = %d, want 8", Channels())
	}
}

// TestDefaultNonceBits confirms the exported compile-in default nonce
// width matches the itb DefaultNonceBits constant (used by bindings
// that need a sentinel for streaming without threading a Config).
func TestDefaultNonceBits(t *testing.T) {
	if got := DefaultNonceBits(); got != 512 {
		t.Errorf("DefaultNonceBits() = %d, want 512", got)
	}
}
