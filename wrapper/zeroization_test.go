package wrapper

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"runtime/debug"
	"testing"
	"unsafe"

	"github.com/everanium/itb/hashes"
)

const (
	wrapperResidueGap      = 1 << 10
	wrapperResiduePad      = 2 << 10
	wrapperResidueWindow   = 16 << 10
	wrapperResidueSentinel = uint64(0x5A5A5A5A5A5A5A5A)
)

func captureWrapperStackResidue(t *testing.T, fn func()) []uint64 {
	t.Helper()
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	res := make([]uint64, wrapperResidueWindow/8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		wrapperResidueGrow(0)
		wrapperResidueProbe(fn, res)
	}()
	<-done
	written := 0
	for _, w := range res {
		if w != wrapperResidueSentinel {
			written++
		}
	}
	if written == 0 {
		t.Fatal("stack probe window was not touched by target call")
	}
	return res
}

//go:noinline
func wrapperResidueGrow(i int) byte {
	var pad [4 * wrapperResidueWindow]byte
	pad[i] = 1
	return pad[(i+1)%len(pad)]
}

//go:noinline
func wrapperResidueProbe(fn func(), res []uint64) {
	var anchor uint64
	top := unsafe.Add(unsafe.Pointer(&anchor), -wrapperResidueGap)
	for i := range res {
		*(*uint64)(unsafe.Add(top, -8*(i+1))) = wrapperResidueSentinel
	}
	wrapperResidueDeep(fn, 0)
	for i := range res {
		res[i] = *(*uint64)(unsafe.Add(top, -8*(i+1)))
	}
}

//go:noinline
func wrapperResidueDeep(fn func(), i int) byte {
	var pad [wrapperResiduePad]byte
	pad[i] = 1
	fn()
	return pad[(i+7)%len(pad)]
}

//go:noinline
func leakyWrapperKeyFrame(key []byte) uint64 {
	var leak [8]uint64
	for i := 0; i*8+8 <= len(key) && i < len(leak); i++ {
		leak[i] = binary.LittleEndian.Uint64(key[i*8:])
	}
	runtime.KeepAlive(&leak)
	return leak[0]
}

func TestWrapperStackZeroization(t *testing.T) {
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(0x61 + i*3)
	}
	ciphers := []string{
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

	// Negative control: verify captureWrapperStackResidue detects an unzeroed key word.
	negWin := captureWrapperStackResidue(t, func() {
		_ = leakyWrapperKeyFrame(master)
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
		t.Fatal("negative control failed: leakyWrapperKeyFrame was not detected in stack residue")
	}

	payloadSerial := bytes.Repeat([]byte("wrapper-zeroization-test-block-"), 64)
	payloadParallel := bytes.Repeat([]byte("wrapper-zeroization-test-block-"), 9000)
	for _, c := range ciphers {
		t.Run(c, func(t *testing.T) {
			dk, err := DeriveKey(c, master)
			if err != nil {
				t.Fatalf("DeriveKey(%q): %v", c, err)
			}
			defer clear(dk)

			secrets := make(map[uint64]bool)
			for off := 0; off+8 <= len(dk); off += 8 {
				w := binary.LittleEndian.Uint64(dk[off:])
				if w != 0 && w != wrapperResidueSentinel {
					secrets[w] = true
				}
			}

			win := captureWrapperStackResidue(t, func() {
				wrapped, werr := Wrap(c, dk, payloadSerial)
				if werr != nil {
					t.Fatalf("Wrap(%q): %v", c, werr)
				}
				unwrapped, uerr := Unwrap(c, dk, wrapped)
				if uerr != nil || !bytes.Equal(unwrapped, payloadSerial) {
					t.Fatalf("Unwrap(%q): err=%v", c, uerr)
				}
			})
			for idx, w := range win {
				if secrets[w] {
					t.Fatalf("%s: serial Wrap/Unwrap leaked derived key word %#x at stack slot %d", c, w, idx)
				}
			}

			winPar := captureWrapperStackResidue(t, func() {
				wrapped, werr := Wrap(c, dk, payloadParallel)
				if werr != nil {
					t.Fatalf("Wrap parallel(%q): %v", c, werr)
				}
				unwrapped, uerr := Unwrap(c, dk, wrapped)
				if uerr != nil || !bytes.Equal(unwrapped, payloadParallel) {
					t.Fatalf("Unwrap parallel(%q): err=%v", c, uerr)
				}
			})
			for idx, w := range winPar {
				if secrets[w] {
					t.Fatalf("%s: parallel Wrap/Unwrap leaked derived key word %#x at stack slot %d", c, w, idx)
				}
			}
		})
	}
}
