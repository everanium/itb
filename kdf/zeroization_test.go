package kdf

import (
	"encoding/binary"
	"runtime"
	"runtime/debug"
	"testing"
	"unsafe"

	"github.com/everanium/itb/hashes"
)

const (
	kdfResidueGap      = 1 << 10
	kdfResiduePad      = 2 << 10
	kdfResidueWindow   = 16 << 10
	kdfResidueSentinel = uint64(0x5A5A5A5A5A5A5A5A)
)

func captureKDFStackResidue(t *testing.T, fn func()) []uint64 {
	t.Helper()
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	res := make([]uint64, kdfResidueWindow/8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		kdfResidueGrow(0)
		kdfResidueProbe(fn, res)
	}()
	<-done
	written := 0
	for _, w := range res {
		if w != kdfResidueSentinel {
			written++
		}
	}
	if written == 0 {
		t.Fatal("captureKDFStackResidue: fn stack frames did not overlap with probe window")
	}
	return res
}

//go:noinline
func kdfResidueGrow(i int) byte {
	var pad [4 * kdfResidueWindow]byte
	pad[i] = 1
	return pad[(i+1)%len(pad)]
}

//go:noinline
func kdfResidueProbe(fn func(), res []uint64) {
	var anchor uint64
	top := unsafe.Add(unsafe.Pointer(&anchor), -kdfResidueGap)
	for i := range res {
		*(*uint64)(unsafe.Add(top, -8*(i+1))) = kdfResidueSentinel
	}
	kdfResidueDeep(fn, 0)
	for i := range res {
		res[i] = *(*uint64)(unsafe.Add(top, -8*(i+1)))
	}
}

//go:noinline
func kdfResidueDeep(fn func(), i int) byte {
	var pad [kdfResiduePad]byte
	pad[i] = 1
	fn()
	return pad[(i+7)%len(pad)]
}

//go:noinline
func leakyKDFKeyFrame(master []byte) uint64 {
	var leak [8]uint64
	for i := 0; i*8+8 <= len(master) && i < len(leak); i++ {
		leak[i] = binary.LittleEndian.Uint64(master[i*8:])
	}
	runtime.KeepAlive(&leak)
	return leak[0]
}

func TestDeriveLeavesNoSecretInStack(t *testing.T) {
	master := make([]byte, 64)
	for i := range master {
		master[i] = byte(0x41 + i*3)
	}

	// Negative control: verify captureKDFStackResidue catches an unzeroed master word.
	negWin := captureKDFStackResidue(t, func() {
		_ = leakyKDFKeyFrame(master)
	})
	wantWord := binary.LittleEndian.Uint64(master[:8])
	foundNeg := false
	for _, w := range negWin {
		if w == wantWord {
			foundNeg = true
			break
		}
	}
	if !foundNeg {
		t.Fatal("negative control failed: leakyKDFKeyFrame was not detected in stack residue")
	}

	primitives := []string{
		hashes.CipherAES128CTR,
		hashes.CipherAreion256,
		hashes.CipherAreion512,
		hashes.CipherBLAKE2b256,
		hashes.CipherBLAKE2b512,
		hashes.CipherBLAKE2s,
		hashes.CipherBLAKE3,
		hashes.CipherSipHash24,
		hashes.CipherChaCha20,
	}

	secrets := make(map[uint64]bool)
	for off := 0; off+8 <= len(master); off += 8 {
		w := binary.LittleEndian.Uint64(master[off:])
		if w != 0 && w != kdfResidueSentinel {
			secrets[w] = true
		}
	}

	for _, name := range primitives {
		t.Run(name, func(t *testing.T) {
			var derived []byte
			win := captureKDFStackResidue(t, func() {
				var err error
				derived, err = Derive(name, master, "kdf-zeroization", 64)
				if err != nil {
					t.Fatalf("Derive(%q): %v", name, err)
				}
			})
			for off := 0; off+8 <= len(derived); off += 8 {
				w := binary.LittleEndian.Uint64(derived[off:])
				if w != 0 && w != kdfResidueSentinel {
					secrets[w] = true
				}
			}
			for idx, w := range win {
				if secrets[w] {
					t.Fatalf("%s: Derive leaked secret word %#x at stack slot %d", name, w, idx)
				}
			}
			clear(derived)
		})
	}
}
