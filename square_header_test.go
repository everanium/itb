package itb

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// squareRewrites lists header rewrites of a side×side container that
// keep W·H: every one decodes to the same container bytes, so only the
// square-header rule tells them apart from the genuine header.
func squareRewrites(side int) [][2]int {
	p := side * side
	var out [][2]int
	for w := 1; w <= p; w++ {
		if p%w != 0 || w == side || w > 0xFFFF || p/w > 0xFFFF {
			continue
		}
		out = append(out, [2]int{w, p / w})
	}
	return out
}

// rewriteDims returns a copy of buf with the W/H fields at off replaced.
func rewriteDims(buf []byte, off, w, h int) []byte {
	c := bytes.Clone(buf)
	binary.BigEndian.PutUint16(c[off:], uint16(w))
	binary.BigEndian.PutUint16(c[off+2:], uint16(h))
	return c
}

func wantNonSquare(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "non-square container") {
		t.Fatalf("%s: err = %v, want a non-square container error", what, err)
	}
}

// TestNonSquareHeaderRejected checks that a header rewritten to another
// factorisation of the same W·H is rejected — before the MAC on the
// authenticated arm — by the Low-Level Single Message entries, the
// streaming decoders and ParseChunkLenCfg, at every width, while the
// genuine wire still decrypts.
func TestNonSquareHeaderRejected(t *testing.T) {
	pt := generateData(2000)
	var macCalls int
	inner := newHMACBlake3Bench(bytes.Repeat([]byte{0x5a}, 32))
	// Only non-empty inputs are counted: the authenticated decoder
	// probes the tag size with an empty input before it parses the
	// header, which authenticates nothing.
	mac := func(b []byte) []byte {
		if len(b) > 0 {
			macCalls++
		}
		return inner(b)
	}
	cfg := &Config{}
	dimsOff := streamIDPrefixLen + currentNonceSizeCfg(cfg)

	t.Run("512", func(t *testing.T) {
		ns, ls, d1, d2, d3, s1, s2, s3 := seedFixtures512(t, 1024)
		wire, err := Encrypt3x512Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, pt)
		if err != nil {
			t.Fatal(err)
		}
		side := int(binary.BigEndian.Uint16(wire[dimsOff:]))
		rw := squareRewrites(side)
		if len(rw) == 0 {
			t.Fatalf("no same-product rewrites for side %d", side)
		}
		if back, err := Decrypt3x512Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, wire); err != nil || !bytes.Equal(back, pt) {
			t.Fatalf("genuine No MAC wire: err=%v", err)
		}
		aw, err := EncryptAuthenticated3x512Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, pt, mac)
		if err != nil {
			t.Fatal(err)
		}
		if back, err := DecryptAuthenticated3x512Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, aw, mac); err != nil || !bytes.Equal(back, pt) {
			t.Fatalf("genuine MAC wire: err=%v", err)
		}
		var stream, astream []byte
		if err := EncryptStream3x512Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, pt, 1024, func(c []byte) error { stream = append(stream, c...); return nil }); err != nil {
			t.Fatal(err)
		}
		if err := EncryptStreamAuth3x512Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, pt, 1024, mac, func(c []byte) error { astream = append(astream, c...); return nil }); err != nil {
			t.Fatal(err)
		}
		sside := int(binary.BigEndian.Uint16(stream[dimsOff:]))
		for _, d := range rw {
			_, err := Decrypt3x512Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, rewriteDims(wire, dimsOff, d[0], d[1]))
			wantNonSquare(t, "Decrypt3x512Cfg", err)
			macCalls = 0
			_, err = DecryptAuthenticated3x512Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, rewriteDims(aw, dimsOff, d[0], d[1]), mac)
			wantNonSquare(t, "DecryptAuthenticated3x512Cfg", err)
			if macCalls != 0 {
				t.Fatalf("MAC authenticated %d inputs on a non-square header", macCalls)
			}
			_, err = ParseChunkLenCfg(cfg, rewriteDims(wire, dimsOff, d[0], d[1])[streamIDPrefixLen:])
			wantNonSquare(t, "ParseChunkLenCfg", err)
		}
		for _, d := range squareRewrites(sside) {
			err := DecryptStream3x512Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, rewriteDims(stream, dimsOff, d[0], d[1]), func([]byte) error { return nil })
			wantNonSquare(t, "DecryptStream3x512Cfg", err)
			err = DecryptStreamAuth3x512Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, rewriteDims(astream, dimsOff, d[0], d[1]), mac, func([]byte) error { return nil })
			wantNonSquare(t, "DecryptStreamAuth3x512Cfg", err)
		}
	})

	t.Run("128", func(t *testing.T) {
		ns, ls, d1, d2, d3, s1, s2, s3 := seedFixtures128(t, 1024)
		wire, err := Encrypt3x128Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, pt)
		if err != nil {
			t.Fatal(err)
		}
		aw, err := EncryptAuthenticated3x128Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, pt, mac)
		if err != nil {
			t.Fatal(err)
		}
		side := int(binary.BigEndian.Uint16(wire[dimsOff:]))
		for _, d := range squareRewrites(side) {
			_, err := Decrypt3x128Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, rewriteDims(wire, dimsOff, d[0], d[1]))
			wantNonSquare(t, "Decrypt3x128Cfg", err)
			_, err = DecryptAuthenticated3x128Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, rewriteDims(aw, dimsOff, d[0], d[1]), mac)
			wantNonSquare(t, "DecryptAuthenticated3x128Cfg", err)
		}
	})

	t.Run("256", func(t *testing.T) {
		ns, ls, d1, d2, d3, s1, s2, s3 := seedFixtures256(t, 1024)
		wire, err := Encrypt3x256Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, pt)
		if err != nil {
			t.Fatal(err)
		}
		aw, err := EncryptAuthenticated3x256Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, pt, mac)
		if err != nil {
			t.Fatal(err)
		}
		side := int(binary.BigEndian.Uint16(wire[dimsOff:]))
		for _, d := range squareRewrites(side) {
			_, err := Decrypt3x256Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, rewriteDims(wire, dimsOff, d[0], d[1]))
			wantNonSquare(t, "Decrypt3x256Cfg", err)
			_, err = DecryptAuthenticated3x256Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, rewriteDims(aw, dimsOff, d[0], d[1]), mac)
			wantNonSquare(t, "DecryptAuthenticated3x256Cfg", err)
		}
	})
}
