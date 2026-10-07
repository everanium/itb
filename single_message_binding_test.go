package itb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
)

// TestSingleMessageExactLengthAcrossSizing confirms the exact-length
// rule of the Single Message decoders never rejects a wire the encoders
// produce, whatever sizes the container: both container floor modes,
// several BarrierFill margins and custom tag lengths (TagStubSize on
// the No MAC arm, a MAC of that tag length on the MAC arm), at every
// hash width. Each wire is the prefix plus exactly the chunk its header
// announces and decrypts on its own arm.
func TestSingleMessageExactLengthAcrossSizing(t *testing.T) {
	for _, fx := range smFixtures(t) {
		fx := fx
		for _, mode := range []int{1, 2} {
			for _, fill := range []int{1, 4, 32} {
				for _, ts := range []int{16, 64} {
					cfg := &Config{Mode: mode, BarrierFill: fill, TagStubSize: ts}
					mac := makeTagMAC(ts)
					t.Run(fmt.Sprintf("w%d/mode=%d/fill=%d/tag=%d", fx.width, mode, fill, ts), func(t *testing.T) {
						for _, sz := range []int{1, 1500} {
							data := randomPlaintext(t, sz)
							plain, err := fx.encrypt(cfg, data)
							if err != nil {
								t.Fatalf("No MAC encrypt %d B: %v", sz, err)
							}
							auth, err := fx.encryptAuth(cfg, data, mac)
							if err != nil {
								t.Fatalf("MAC encrypt %d B: %v", sz, err)
							}
							for name, wire := range map[string][]byte{"nomac": plain, "mac": auth} {
								n, perr := ParseChunkLenCfg(cfg, wire[streamIDPrefixLen:])
								if perr != nil || streamIDPrefixLen+n != len(wire) {
									t.Fatalf("%s %d B: chunk behind the prefix announces %d B (err %v), wire %d B", name, sz, n, perr, len(wire))
								}
							}
							if back, err := fx.decrypt(cfg, plain); err != nil || !bytes.Equal(back, data) {
								t.Fatalf("No MAC round-trip %d B: err=%v match=%v", sz, err, bytes.Equal(back, data))
							}
							if back, err := fx.decryptAuth(cfg, auth, mac); err != nil || !bytes.Equal(back, data) {
								t.Fatalf("MAC round-trip %d B: err=%v match=%v", sz, err, bytes.Equal(back, data))
							}
						}
					})
				}
			}
		}
	}
}

// TestSingleMessageAuthBindsOffsetZero pins the cumulative pixel
// offset of the MAC Authenticated Single Message binding: a terminating
// chunk MACed at any offset other than 0, placed behind its own
// streamID, fails verification with [ErrMACFailure] at every hash
// width. A keyed MAC is required — a constant-tag stand-in would verify
// any offset.
func TestSingleMessageAuthBindsOffsetZero(t *testing.T) {
	mac := newHMACBlake3Bench(bytes.Repeat([]byte{0x2B}, 32))
	for _, fx := range smFixtures(t) {
		fx := fx
		t.Run(fmt.Sprintf("w%d", fx.width), func(t *testing.T) {
			data := randomPlaintext(t, 1024)
			streamID, err := generateStreamID()
			if err != nil {
				t.Fatal(err)
			}
			for _, off := range []uint64{1, 1 << 20} {
				chunk, err := fx.encryptChunkAuth(nil, data, mac, streamID, off, true)
				if err != nil {
					t.Fatalf("chunk encrypt at offset %d: %v", off, err)
				}
				wire := append(append([]byte(nil), streamID[:]...), chunk...)
				if _, err := fx.decryptAuth(nil, wire, mac); !errors.Is(err, ErrMACFailure) {
					t.Fatalf("chunk MACed at offset %d: got %v, want %v", off, err, ErrMACFailure)
				}
			}
		})
	}
}

// TestSingleMessageResizedHeaderRejectedBeforeMAC pins the receive side
// of a W / H rewrite that changes the announced container size: a
// shrink leaves bytes past the announced chunk and fails the
// exact-length rule, a growth announces more bytes than the wire holds
// and fails the length check of the chunk decoder. Either way the
// rejection is structural — the MAC closure never runs over a non-empty
// input (the empty-input tag-length probe is not counted).
func TestSingleMessageResizedHeaderRejectedBeforeMAC(t *testing.T) {
	inner := newHMACBlake3Bench(bytes.Repeat([]byte{0x6E}, 32))
	macCalls := 0
	counting := func(b []byte) []byte {
		if len(b) > 0 {
			macCalls++
		}
		return inner(b)
	}
	dims := streamIDPrefixLen + currentNonceSizeCfg(nil)
	for _, fx := range smFixtures(t) {
		fx := fx
		t.Run(fmt.Sprintf("w%d", fx.width), func(t *testing.T) {
			data := randomPlaintext(t, 2048)
			auth, err := fx.encryptAuth(nil, data, inner)
			if err != nil {
				t.Fatalf("MAC encrypt: %v", err)
			}
			w := int(binary.BigEndian.Uint16(auth[dims:]))
			h := int(binary.BigEndian.Uint16(auth[dims+2:]))
			for _, d := range [][2]int{{w - 1, h}, {w, h - 1}, {w + 1, h}, {w, h + 1}} {
				tampered := bytes.Clone(auth)
				binary.BigEndian.PutUint16(tampered[dims:], uint16(d[0]))
				binary.BigEndian.PutUint16(tampered[dims+2:], uint16(d[1]))
				macCalls = 0
				if _, err := fx.decryptAuth(nil, tampered, counting); err == nil {
					t.Fatalf("%dx%d → %dx%d: resized header accepted", w, h, d[0], d[1])
				}
				if macCalls != 0 {
					t.Fatalf("%dx%d → %dx%d: MAC ran %d times; the size checks must precede it", w, h, d[0], d[1], macCalls)
				}
			}
		})
	}
}
