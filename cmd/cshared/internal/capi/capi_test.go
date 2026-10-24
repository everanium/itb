package capi

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
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
// The shim's output is not a bare chunk — the constant-size 32-byte
// prefix precedes it — so the absolute offset is not HeaderSize.
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

func TestCAPITripleOptsAndKeysZeroization(t *testing.T) {
	pmHex := "0123456789abcdef0123456789abcdef112233445566778899aabbccddeeff00"
	wmHex := "fedcba9876543210fedcba9876543210ffeeddccbbaa99887766554433221100"

	// Negative control: hex.DecodeString on a string with a valid 32-byte secret prefix followed by
	// an invalid hex byte returns the decoded 32-byte secret prefix in the error slice.
	neg, negErr := hex.DecodeString(pmHex + "zz")
	if negErr == nil || len(neg) != 32 {
		t.Fatalf("hex.DecodeString malformed: len=%d, err=%v", len(neg), negErr)
	}
	clear(neg)

	opts, err := parseTripleOpts("pm=" + pmHex + "&wm=" + wmHex)
	if err != nil {
		t.Fatalf("parseTripleOpts: %v", err)
	}
	if cap(opts.PermMaster) != len(opts.PermMaster) || len(opts.PermMaster) != 32 {
		t.Fatalf("PermMaster len/cap = %d/%d, want 32/32", len(opts.PermMaster), cap(opts.PermMaster))
	}
	if cap(opts.WrapMaster) != len(opts.WrapMaster) || len(opts.WrapMaster) != 32 {
		t.Fatalf("WrapMaster len/cap = %d/%d, want 32/32", len(opts.WrapMaster), cap(opts.WrapMaster))
	}
	clear(opts.PermMaster)
	clear(opts.WrapMaster)

	// Error path after valid pm/wm must wipe decoded PermMaster and WrapMaster.
	badOpts, badErr := parseTripleOpts("pm=" + pmHex + "&wm=" + wmHex + "&unknownKey=1")
	if badErr == nil {
		t.Fatal("parseTripleOpts with unknownKey expected error")
	}
	for i, b := range badOpts.PermMaster {
		if b != 0 {
			t.Fatalf("parseTripleOpts error path left non-zero PermMaster[%d] = %#x", i, b)
		}
	}
	for i, b := range badOpts.WrapMaster {
		if b != 0 {
			t.Fatalf("parseTripleOpts error path left non-zero WrapMaster[%d] = %#x", i, b)
		}
	}

	// Verify TripleInit, TripleInitKeys, and TripleRekey succeed and handle StatusBufferTooSmall cleanly.
	blobBuf := make([]byte, 1<<15)
	id, blobLen, st := TripleInit("singlemsg-aesitb-mac-v1", "pm="+pmHex+"&wm="+wmHex, blobBuf)
	if st != StatusOK || blobLen == 0 {
		t.Fatalf("TripleInit: %v (%s)", st, LastError())
	}
	defer FreeTriple(id)

	masters := make([][]byte, 8)
	for i := range masters {
		masters[i] = bytes.Repeat([]byte{byte(0x11 + i)}, 32)
	}
	blobOut := make([]byte, 1<<15)
	id2, _, st := TripleInitKeys("singlemsg-aesitb-mac-v1", "pm="+pmHex+"&wm="+wmHex, masters, blobOut)
	if st != StatusOK {
		t.Fatalf("TripleInitKeys: %v (%s)", st, LastError())
	}
	FreeTriple(id2)

	tinyBuf := make([]byte, 8)
	if _, need, st := TripleInitKeys("singlemsg-aesitb-mac-v1", "pm="+pmHex+"&wm="+wmHex, masters, tinyBuf); st != StatusBufferTooSmall || need <= len(tinyBuf) {
		t.Fatalf("TripleInitKeys tiny buffer: status=%v need=%d", st, need)
	}
	for i, b := range tinyBuf {
		if b != 0 {
			t.Fatalf("TripleInitKeys tiny buffer modified at [%d] = %#x", i, b)
		}
	}

	newPM := bytes.Repeat([]byte{0xAA}, 32)
	newWM := bytes.Repeat([]byte{0xBB}, 32)
	if _, st := TripleRekey(id, newPM, newWM, blobOut); st != StatusOK {
		t.Fatalf("TripleRekey: %v (%s)", st, LastError())
	}
}

func TestCAPIStreamSpoolZeroization(t *testing.T) {
	sp := newStreamSpool()
	chunk1 := bytes.Repeat([]byte{0xA5}, 1024)
	if _, err := sp.Write(chunk1); err != nil {
		t.Fatalf("sp.Write(chunk1): %v", err)
	}
	oldBacking := sp.buf[:cap(sp.buf)]
	origCap := cap(sp.buf)

	// Partial read must compact unread bytes and wipe the trailing n bytes without shrinking capacity.
	dst := make([]byte, 300)
	n, drained := sp.read(dst, false)
	if n != 300 || drained {
		t.Fatalf("sp.read = (%d, %v), want (300, false)", n, drained)
	}
	if cap(sp.buf) != origCap {
		t.Fatalf("sp.read shrank capacity from %d to %d", origCap, cap(sp.buf))
	}
	for i := len(sp.buf); i < origCap; i++ {
		if oldBacking[i] != 0 {
			t.Fatalf("sp.read left non-zero byte %#x at oldBacking[%d]", oldBacking[i], i)
		}
	}

	// Trigger growth beyond origCap and verify oldBacking is completely wiped.
	bigChunk := bytes.Repeat([]byte{0x5A}, origCap*2)
	if _, err := sp.Write(bigChunk); err != nil {
		t.Fatalf("sp.Write(bigChunk): %v", err)
	}
	for i, b := range oldBacking {
		if b != 0 {
			t.Fatalf("sp.Write growth left non-zero byte %#x in oldBacking[%d]", b, i)
		}
	}

	// Verify sp.wipe() zeroes the current backing array.
	curBacking := sp.buf[:cap(sp.buf)]
	sp.wipe()
	for i, b := range curBacking {
		if b != 0 {
			t.Fatalf("sp.wipe() left non-zero byte %#x in curBacking[%d]", b, i)
		}
	}

	// Verify TripleStreamRead wipes spool on decrypt error.
	blobBuf := make([]byte, 1<<15)
	id, _, st := TripleInit("streaming-aead-triple-mac-v1", "", blobBuf)
	if st != StatusOK {
		t.Fatalf("TripleInit: %v (%s)", st, LastError())
	}
	defer FreeTriple(id)

	pt := bytes.Repeat([]byte{0x42}, 1024)
	wireBuf := make([]byte, len(pt)+64<<10)
	wLen, st := TripleEncryptStream(id, pt, wireBuf)
	if st != StatusOK {
		t.Fatalf("TripleEncryptStream: %v (%s)", st, LastError())
	}
	wireBuf[wLen-1] ^= 0xFF

	decID, st := TripleDecryptStreamBegin(id)
	if st != StatusOK {
		t.Fatalf("TripleDecryptStreamBegin: %v (%s)", st, LastError())
	}
	defer TripleStreamFree(decID)

	if st := TripleStreamWrite(decID, wireBuf[:wLen]); st != StatusOK {
		t.Fatalf("TripleStreamWrite: %v", st)
	}
	if st := TripleStreamEnd(decID); st != StatusOK {
		t.Fatalf("TripleStreamEnd: %v", st)
	}
	outBuf := make([]byte, 4096)
	got, fin, st := TripleStreamRead(decID, outBuf)
	if st == StatusOK || got != 0 || fin {
		t.Fatalf("TripleStreamRead on tampered stream = (%d, %v, %v), want (0, false, error)", got, fin, st)
	}
}

func TestCAPITripleMaxWireAndPlaintextSize(t *testing.T) {
	blobBuf := make([]byte, 1<<15)
	id, _, st := TripleInit("streaming-aead-triple-mac-v1", "", blobBuf)
	if st != StatusOK {
		t.Fatalf("TripleInit: %v (%s)", st, LastError())
	}
	defer FreeTriple(id)

	if _, st := TripleMaxWireSize(0, 1500, 0); st != StatusBadHandle {
		t.Fatalf("TripleMaxWireSize(0): got %v, want StatusBadHandle", st)
	}
	if _, st := TripleMaxPlaintextSize(0, 65536, 0); st != StatusBadHandle {
		t.Fatalf("TripleMaxPlaintextSize(0): got %v, want StatusBadHandle", st)
	}
	if _, st := TripleMaxWireSize(id, 0, 0); st != StatusBadInput {
		t.Fatalf("TripleMaxWireSize(pt=0): got %v, want StatusBadInput", st)
	}
	if _, st := TripleMaxPlaintextSize(id, 0, 0); st != StatusBadInput {
		t.Fatalf("TripleMaxPlaintextSize(wire=0): got %v, want StatusBadInput", st)
	}

	maxW, st := TripleMaxWireSize(id, 1500, 0)
	if st != StatusOK || maxW <= 1500 {
		t.Fatalf("TripleMaxWireSize(1500) = (%d, %v), want (>1500, StatusOK)", maxW, st)
	}
	pt := bytes.Repeat([]byte{0x5C}, 1500)
	wireDst := make([]byte, maxW)
	wN, st := TripleEncryptMessage(id, pt, wireDst)
	if st != StatusOK || wN != maxW {
		t.Fatalf("TripleEncryptMessage into exact MaxWireSize = (%d, %v), want (%d, StatusOK)", wN, st, maxW)
	}
	plainDst := make([]byte, len(pt))
	pN, st := TripleDecryptMessage(id, wireDst[:wN], plainDst)
	if st != StatusOK || pN != len(pt) || !bytes.Equal(plainDst[:pN], pt) {
		t.Fatalf("TripleDecryptMessage into exact len(pt) = (%d, %v)", pN, st)
	}

	maxPt, st := TripleMaxPlaintextSize(id, maxW, 0)
	if st != StatusOK || maxPt < 1500 {
		t.Fatalf("TripleMaxPlaintextSize(%d) = (%d, %v), want (>=1500, StatusOK)", maxW, maxPt, st)
	}
	// Smaller than minimum wire returns (0, StatusOK).
	smallPt, st := TripleMaxPlaintextSize(id, 8, 0)
	if st != StatusOK || smallPt != 0 {
		t.Fatalf("TripleMaxPlaintextSize(8) = (%d, %v), want (0, StatusOK)", smallPt, st)
	}

	// Sub-slice with len < required but cap >= required must return
	// StatusBufferTooSmall without writing or wiping past len(sub).
	backing := make([]byte, maxW+128)
	for i := range backing {
		backing[i] = 0xA5
	}
	smallLen := 16
	if _, st := TripleEncryptMessage(id, pt, backing[:smallLen]); st != StatusBufferTooSmall {
		t.Fatalf("TripleEncryptMessage(small sub-slice): got %v, want StatusBufferTooSmall", st)
	}
	for i := smallLen; i < len(backing); i++ {
		if backing[i] != 0xA5 {
			t.Fatalf("TripleEncryptMessage modified backing[%d] = %#x past len(sub)", i, backing[i])
		}
	}
	if _, st := TripleEncryptStream(id, pt, backing[:smallLen]); st != StatusBufferTooSmall {
		t.Fatalf("TripleEncryptStream(small sub-slice): got %v, want StatusBufferTooSmall", st)
	}
	for i := smallLen; i < len(backing); i++ {
		if backing[i] != 0xA5 {
			t.Fatalf("TripleEncryptStream modified backing[%d] = %#x past len(sub)", i, backing[i])
		}
	}
	if _, st := TripleDecryptMessage(id, wireDst[:wN], backing[:smallLen]); st != StatusBufferTooSmall {
		t.Fatalf("TripleDecryptMessage(small sub-slice): got %v, want StatusBufferTooSmall", st)
	}
	for i := smallLen; i < len(backing); i++ {
		if backing[i] != 0xA5 {
			t.Fatalf("TripleDecryptMessage modified backing[%d] = %#x past len(sub)", i, backing[i])
		}
	}
	if _, st := TripleDecryptStream(id, wireDst[:wN], backing[:smallLen]); st != StatusBufferTooSmall {
		t.Fatalf("TripleDecryptStream(small sub-slice): got %v, want StatusBufferTooSmall", st)
	}
	for i := smallLen; i < len(backing); i++ {
		if backing[i] != 0xA5 {
			t.Fatalf("TripleDecryptStream modified backing[%d] = %#x past len(sub)", i, backing[i])
		}
	}

	if st := TripleClose(id); st != StatusOK {
		t.Fatalf("TripleClose: %v", st)
	}
	if _, st := TripleMaxWireSize(id, 1500, 0); st != StatusTripleClosed {
		t.Fatalf("closed TripleMaxWireSize = %v, want StatusTripleClosed", st)
	}
	if _, st := TripleMaxPlaintextSize(id, maxW, 0); st != StatusTripleClosed {
		t.Fatalf("closed TripleMaxPlaintextSize = %v, want StatusTripleClosed", st)
	}
}
