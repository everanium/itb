package macs

import (
	"encoding/binary"
	"runtime"
	"runtime/debug"
	"testing"
	"unsafe"

	"github.com/zeebo/blake3"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
)

const (
	macResidueGap      = 1 << 10
	macResiduePad      = 2 << 10
	macResidueWindow   = 16 << 10
	macResidueSentinel = uint64(0x5A5A5A5A5A5A5A5A)
)

func captureMACStackResidue(t *testing.T, fn func()) []uint64 {
	t.Helper()
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	res := make([]uint64, macResidueWindow/8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		macResidueGrow(0)
		macResidueProbe(fn, res)
	}()
	<-done
	written := 0
	for _, w := range res {
		if w != macResidueSentinel {
			written++
		}
	}
	if written == 0 {
		t.Fatal("captureMACStackResidue: fn stack frames did not overlap with probe window")
	}
	return res
}

//go:noinline
func macResidueGrow(i int) byte {
	var pad [4 * macResidueWindow]byte
	pad[i] = 1
	return pad[(i+1)%len(pad)]
}

//go:noinline
func macResidueProbe(fn func(), res []uint64) {
	var anchor uint64
	top := unsafe.Add(unsafe.Pointer(&anchor), -macResidueGap)
	for i := range res {
		*(*uint64)(unsafe.Add(top, -8*(i+1))) = macResidueSentinel
	}
	macResidueDeep(fn, 0)
	for i := range res {
		res[i] = *(*uint64)(unsafe.Add(top, -8*(i+1)))
	}
}

//go:noinline
func macResidueDeep(fn func(), i int) byte {
	var pad [macResiduePad]byte
	pad[i] = 1
	fn()
	return pad[(i+7)%len(pad)]
}

//go:noinline
func leakyMACKeyFrame(key []byte) uint64 {
	var leak [8]uint64
	for i := 0; i*8+8 <= len(key) && i < len(leak); i++ {
		leak[i] = binary.LittleEndian.Uint64(key[i*8:])
	}
	runtime.KeepAlive(&leak)
	return leak[0]
}

func TestMACStackAndPoolZeroization(t *testing.T) {
	probeKey := make([]byte, 32)
	for i := range probeKey {
		probeKey[i] = byte(0x53 + i*5)
	}

	// Negative control: verify captureMACStackResidue detects an unzeroed key word.
	negWin := captureMACStackResidue(t, func() {
		_ = leakyMACKeyFrame(probeKey)
	})
	wantWord := binary.LittleEndian.Uint64(probeKey[:8])
	foundNeg := false
	for _, w := range negWin {
		if w == wantWord {
			foundNeg = true
			break
		}
	}
	if !foundNeg {
		t.Fatal("negative control failed: leakyMACKeyFrame was not detected in stack residue")
	}

	// 512-byte message so multi-block internal buffers (such as blake3.Hasher's
	// 8 KiB a.buf beyond the first 64 bytes) are exercised.
	msg := make([]byte, 512)
	for i := range msg {
		msg[i] = byte(0x21 + (i*19)&0x7f)
	}
	msgWords := make(map[uint64]bool)
	for off := 0; off+8 <= len(msg); off += 8 {
		w := binary.LittleEndian.Uint64(msg[off:])
		if w != 0 && w != macResidueSentinel {
			msgWords[w] = true
		}
	}

	checkSpec := func(t *testing.T, spec Spec) {
		t.Helper()
		key := make([]byte, spec.KeySize)
		for i := range key {
			key[i] = byte(0x53 + i*5)
		}
		var (
			macFn itb.MACFunc
			incFn itb.MACIncrementalFunc
			err   error
		)
		if spec.MakeMAC != nil {
			macFn, err = spec.MakeMAC(key)
		} else {
			macFn, err = Make(spec.Name, key)
		}
		if err != nil {
			t.Fatalf("MakeMAC(%q): %v", spec.Name, err)
		}
		if spec.MakeIncrementalMAC != nil {
			incFn, err = spec.MakeIncrementalMAC(key)
		} else {
			incFn, err = MakeIncremental(spec.Name, key)
		}
		if err != nil {
			t.Fatalf("MakeIncrementalMAC(%q): %v", spec.Name, err)
		}

		win := captureMACStackResidue(t, func() {
			tag1 := macFn(msg)
			tag2 := incFn(msg[:113], msg[113:])
			clear(tag1)
			clear(tag2)
		})
		for idx, w := range win {
			if msgWords[w] {
				t.Fatalf("%s: MAC evaluation leaked message word %#x at stack slot %d", spec.Name, w, idx)
			}
		}
	}

	for _, spec := range Registry {
		t.Run("registry/"+spec.Name, func(t *testing.T) {
			checkSpec(t, spec)
		})
	}

	for _, hspec := range hashes.Registry {
		if hspec.HashHash != nil {
			t.Run("BuildHMAC/"+hspec.Name, func(t *testing.T) {
				mspec, err := BuildHMAC(hspec.Name, HMACSpec{Name: "test_hmac_" + hspec.Name})
				if err != nil {
					t.Fatalf("BuildHMAC(%q): %v", hspec.Name, err)
				}
				checkSpec(t, mspec)
			})
		}
		if hspec.KeyedHash != nil {
			t.Run("BuildKeyedHash/"+hspec.Name, func(t *testing.T) {
				ks := 32
				if hspec.Name == hashes.CipherSipHash24 {
					ks = 16
				}
				mspec, err := BuildKeyedHash(hspec.Name, KeyedHashSpec{
					Name:    "test_kh_" + hspec.Name,
					KeySize: ks,
				})
				if err != nil {
					t.Fatalf("BuildKeyedHash(%q): %v", hspec.Name, err)
				}
				checkSpec(t, mspec)
			})
		}
	}

	// Verify directly that pooled *blake3.Hasher heap entries in both
	// HMACBLAKE3 and BuildKeyedHash("blake3") retain zero message words
	// across the entire 10.8 KiB blake3.Hasher struct after a 512-byte MAC.
	t.Run("blake3_heap_pool_scrub", func(t *testing.T) {
		tmpl, err := blake3.NewKeyed(probeKey)
		if err != nil {
			t.Fatalf("blake3.NewKeyed: %v", err)
		}
		e := &blake3MACEntry{h: tmpl.Clone()}
		out := make([]byte, 32)
		evalHMACBLAKE3(e, tmpl, out, msg)
		raw := unsafe.Slice((*byte)(unsafe.Pointer(e.h)), unsafe.Sizeof(*e.h))
		for off := 0; off+8 <= len(raw); off += 8 {
			w := binary.LittleEndian.Uint64(raw[off:])
			if msgWords[w] {
				t.Fatalf("blake3MACEntry retained message word %#x at heap offset %d", w, off)
			}
		}

		hspec, _ := hashes.Find(hashes.CipherBLAKE3)
		kh, err := hspec.KeyedHash(probeKey)
		if err != nil {
			t.Fatalf("blake3 KeyedHash: %v", err)
		}
		pe := &pooledMACEntry{h: kh, sum: make([]byte, 32)}
		evalPooledMAC(pe, out, msg)
		for i, b := range pe.sum[:cap(pe.sum)] {
			if b != 0 {
				t.Fatalf("pooledMACEntry.sum[%d] = %#x after scrub, want 0", i, b)
			}
		}
		bh := pe.h.(*blake3.Hasher)
		rawPooled := unsafe.Slice((*byte)(unsafe.Pointer(bh)), unsafe.Sizeof(*bh))
		for off := 0; off+8 <= len(rawPooled); off += 8 {
			w := binary.LittleEndian.Uint64(rawPooled[off:])
			if msgWords[w] {
				t.Fatalf("pooledMACEntry(*blake3.Hasher) retained message word %#x at heap offset %d", w, off)
			}
		}
	})
}
