package parallax

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
	parallaxResidueGap      = 1 << 10
	parallaxResiduePad      = 2 << 10
	parallaxResidueWindow   = 16 << 10
	parallaxResidueSentinel = uint64(0x5A5A5A5A5A5A5A5A)
)

func captureParallaxStackResidue(t *testing.T, fn func()) []uint64 {
	t.Helper()
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	res := make([]uint64, parallaxResidueWindow/8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		parallaxResidueGrow(0)
		parallaxResidueProbe(fn, res)
	}()
	<-done
	written := 0
	for _, w := range res {
		if w != parallaxResidueSentinel {
			written++
		}
	}
	if written == 0 {
		t.Fatal("stack probe window was not touched by target call")
	}
	return res
}

//go:noinline
func parallaxResidueGrow(i int) byte {
	var pad [4 * parallaxResidueWindow]byte
	pad[i] = 1
	return pad[(i+1)%len(pad)]
}

//go:noinline
func parallaxResidueProbe(fn func(), res []uint64) {
	var anchor uint64
	top := unsafe.Add(unsafe.Pointer(&anchor), -parallaxResidueGap)
	for i := range res {
		*(*uint64)(unsafe.Add(top, -8*(i+1))) = parallaxResidueSentinel
	}
	parallaxResidueDeep(fn, 0)
	for i := range res {
		res[i] = *(*uint64)(unsafe.Add(top, -8*(i+1)))
	}
}

//go:noinline
func parallaxResidueDeep(fn func(), i int) byte {
	var pad [parallaxResiduePad]byte
	pad[i] = 1
	fn()
	return pad[(i+7)%len(pad)]
}

//go:noinline
func leakyScheduleSeedFrame(seed *[scheduleSeedSize]byte) uint64 {
	var leak [8]uint64
	for i := 0; i*8+8 <= len(seed); i++ {
		leak[i] = binary.LittleEndian.Uint64(seed[i*8:])
	}
	runtime.KeepAlive(&leak)
	return leak[0]
}

func TestParallaxStackAndHeapZeroization(t *testing.T) {
	master := make([]byte, MasterKeySize)
	for i := range master {
		master[i] = byte(0x91 + i*7)
	}
	palette := []string{
		hashes.CipherAES128CTR,
		hashes.CipherChaCha20,
		hashes.CipherAreion256,
		hashes.CipherBLAKE2b256,
	}
	sched, err := NewSchedule(palette, 67)
	if err != nil {
		t.Fatalf("NewSchedule: %v", err)
	}
	cs, err := NewCipherset(master, sched)
	if err != nil {
		t.Fatalf("NewCipherset: %v", err)
	}

	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(0x33 + i*5)
	}

	var expectedSeed [scheduleSeedSize]byte
	if err := buildScheduleSeed(&expectedSeed, sched, cs, nonce); err != nil {
		t.Fatalf("buildScheduleSeed: %v", err)
	}
	seedWords := make(map[uint64]bool, 8)
	for off := 0; off+8 <= len(expectedSeed); off += 8 {
		w := binary.LittleEndian.Uint64(expectedSeed[off:])
		if w != 0 && w != parallaxResidueSentinel {
			seedWords[w] = true
		}
	}
	for i := range cs.subkeys {
		for off := 0; off+8 <= len(cs.subkeys[i]); off += 8 {
			w := binary.LittleEndian.Uint64(cs.subkeys[i][off:])
			if w != 0 && w != parallaxResidueSentinel {
				seedWords[w] = true
			}
		}
	}
	for off := 0; off+8 <= len(cs.scheduleSubkey); off += 8 {
		w := binary.LittleEndian.Uint64(cs.scheduleSubkey[off:])
		if w != 0 && w != parallaxResidueSentinel {
			seedWords[w] = true
		}
	}

	// Negative control: verify captureParallaxStackResidue detects an unzeroed
	// schedule seed word on the stack.
	negWin := captureParallaxStackResidue(t, func() {
		_ = leakyScheduleSeedFrame(&expectedSeed)
	})
	foundNeg := false
	for _, w := range negWin {
		if seedWords[w] {
			foundNeg = true
			break
		}
	}
	if !foundNeg {
		t.Fatal("negative control failed: leakyScheduleSeedFrame was not detected in stack residue")
	}

	// Positive check 1: buildPermutation wipes scheduleSeed and SplitMix64 state.
	posWin := captureParallaxStackResidue(t, func() {
		perm, perr := buildPermutation(sched, cs, nonce)
		if perr != nil {
			t.Fatalf("buildPermutation: %v", perr)
		}
		clear(perm)
	})
	for idx, w := range posWin {
		if seedWords[w] {
			t.Fatalf("buildPermutation leaked secret word %#x at stack slot %d", w, idx)
		}
	}

	// Positive check 2a: Encrypt / Decrypt wipe worker stack frames (serial path).
	pt := bytes.Repeat([]byte("parallax-zeroization-payload-"), 64)
	encWin := captureParallaxStackResidue(t, func() {
		ct, cerr := sched.Encrypt(pt, cs)
		if cerr != nil {
			t.Fatalf("Encrypt: %v", cerr)
		}
		dec, derr := sched.Decrypt(ct, cs)
		if derr != nil || !bytes.Equal(dec, pt) {
			t.Fatalf("Decrypt: err=%v", derr)
		}
	})
	for idx, w := range encWin {
		if seedWords[w] {
			t.Fatalf("Encrypt/Decrypt (serial) leaked secret word %#x at stack slot %d", w, idx)
		}
	}

	// Positive check 2b: Encrypt / Decrypt wipe worker stack frames (parallel path >= 8 KiB).
	ptPar := bytes.Repeat([]byte("parallax-zeroization-payload-"), 512)
	parWin := captureParallaxStackResidue(t, func() {
		ct, cerr := sched.Encrypt(ptPar, cs)
		if cerr != nil {
			t.Fatalf("Encrypt(parallel): %v", cerr)
		}
		dec, derr := sched.Decrypt(ct, cs)
		if derr != nil || !bytes.Equal(dec, ptPar) {
			t.Fatalf("Decrypt(parallel): err=%v", derr)
		}
	})
	for idx, w := range parWin {
		if seedWords[w] {
			t.Fatalf("Encrypt/Decrypt (parallel) leaked secret word %#x at stack slot %d", w, idx)
		}
	}

	// Positive check 3: Close() zeroes all derived subkeys and scheduleSubkey in place.
	keyAliases := make([][]byte, len(cs.subkeys))
	for i := range cs.subkeys {
		keyAliases[i] = cs.subkeys[i]
	}
	schedKeyAlias := cs.scheduleSubkey
	if err := cs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	for i, k := range keyAliases {
		for j, b := range k {
			if b != 0 {
				t.Fatalf("cs.subkeys[%d][%d] = %#x after Close, want 0", i, j, b)
			}
		}
	}
	for j, b := range schedKeyAlias {
		if b != 0 {
			t.Fatalf("cs.scheduleSubkey[%d] = %#x after Close, want 0", j, b)
		}
	}
}
