package triple

import (
	"encoding/binary"
	"runtime"
	"runtime/debug"
	"testing"
	"unsafe"
)

const (
	tripleResidueGap      = 1 << 10
	tripleResiduePad      = 2 << 10
	tripleResidueWindow   = 16 << 10
	tripleResidueSentinel = uint64(0x5A5A5A5A5A5A5A5A)
)

func captureTripleStackResidue(t *testing.T, fn func()) []uint64 {
	t.Helper()
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	res := make([]uint64, tripleResidueWindow/8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		tripleResidueGrow(0)
		tripleResidueProbe(fn, res)
	}()
	<-done
	written := 0
	for _, w := range res {
		if w != tripleResidueSentinel {
			written++
		}
	}
	if written == 0 {
		t.Fatal("stack probe window did not intersect target frame (written == 0)")
	}
	return res
}

//go:noinline
func tripleResidueGrow(i int) byte {
	var pad [4 * tripleResidueWindow]byte
	pad[i] = 1
	return pad[(i+1)%len(pad)]
}

//go:noinline
func tripleResidueProbe(fn func(), res []uint64) {
	var anchor uint64
	top := unsafe.Add(unsafe.Pointer(&anchor), -tripleResidueGap)
	for i := range res {
		*(*uint64)(unsafe.Add(top, -8*(i+1))) = tripleResidueSentinel
	}
	tripleResidueDeep(fn, 0)
	for i := range res {
		res[i] = *(*uint64)(unsafe.Add(top, -8*(i+1)))
	}
}

//go:noinline
func tripleResidueDeep(fn func(), i int) byte {
	var pad [tripleResiduePad]byte
	pad[i] = 1
	fn()
	return pad[(i+7)%len(pad)]
}

//go:noinline
func leakyTripleSecretFrame(words []uint64) uint64 {
	var leak [8]uint64
	copy(leak[:], words)
	runtime.KeepAlive(&leak)
	return leak[0]
}

func TestTripleStackZeroization(t *testing.T) {
	probeWord := uint64(0x1122334455667788)
	negWin := captureTripleStackResidue(t, func() {
		_ = leakyTripleSecretFrame([]uint64{probeWord})
	})
	foundNeg := false
	for _, w := range negWin {
		if w == probeWord {
			foundNeg = true
			break
		}
	}
	if !foundNeg {
		t.Fatal("negative control failed: leakyTripleSecretFrame was not detected in stack residue")
	}

	addSliceWords := func(secrets map[uint64]bool, b []byte) {
		for off := 0; off+8 <= len(b); off += 8 {
			w := binary.LittleEndian.Uint64(b[off:])
			if w != 0 && w != tripleResidueSentinel {
				secrets[w] = true
			}
		}
	}

	for _, tc := range []struct {
		name      string
		innerHash string
	}{
		{"W128_AESCMAC", "aescmac"},
		{"W256_BLAKE2b256", "blake2b256"},
		{"W512_BLAKE2b512", "blake2b512"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			permMaster := make([]byte, 32)
			wrapMaster := make([]byte, 32)
			for i := range permMaster {
				permMaster[i] = byte(0x21 + i*3)
				wrapMaster[i] = byte(0x83 + i*5)
			}

			var pipe *Pipeline
			var blob []byte
			var initErr error
			winInit := captureTripleStackResidue(t, func() {
				pipe, blob, initErr = Init(ProfileStreamingAEADTripleMACV1, Opts{
					InnerHash:  tc.innerHash,
					PermMaster: permMaster,
					WrapMaster: wrapMaster,
				})
			})
			if initErr != nil {
				t.Fatalf("Init(%s): %v", tc.innerHash, initErr)
			}
			defer pipe.Close()

			secrets := make(map[uint64]bool)
			addSliceWords(secrets, permMaster)
			addSliceWords(secrets, wrapMaster)
			addSliceWords(secrets, pipe.wrapperKey)
			addSliceWords(secrets, pipe.macKey)
			for _, k := range pipe.prfKeys {
				addSliceWords(secrets, k)
			}
			for _, s := range pipe.seeds {
				for _, w := range seedComponentsHandle(s, pipe.width) {
					if w != 0 && w != tripleResidueSentinel {
						secrets[w] = true
					}
				}
			}

			for idx, w := range winInit {
				if secrets[w] {
					t.Fatalf("Init(%s) leaked secret word %#x at stack slot %d", tc.innerHash, w, idx)
				}
			}

			// Verify exportInnerBlob directly.
			winExport := captureTripleStackResidue(t, func() {
				ib, err := exportInnerBlob(pipe.width, pipe.cfg, pipe.seeds, pipe.prfKeys, pipe.macKey, pipe.macName)
				if err != nil {
					t.Errorf("exportInnerBlob: %v", err)
				}
				clear(ib)
			})
			for idx, w := range winExport {
				if secrets[w] {
					t.Fatalf("exportInnerBlob(%s) leaked secret word %#x at stack slot %d", tc.innerHash, w, idx)
				}
			}

			// Verify Load stack residue.
			var loaded *Pipeline
			var loadErr error
			winLoad := captureTripleStackResidue(t, func() {
				loaded, loadErr = Load(blob)
			})
			if loadErr != nil {
				t.Fatalf("Load(%s): %v", tc.innerHash, loadErr)
			}
			defer loaded.Close()
			for idx, w := range winLoad {
				if secrets[w] {
					t.Fatalf("Load(%s) leaked secret word %#x at stack slot %d", tc.innerHash, w, idx)
				}
			}

			// Verify Rekey stack residue.
			newPerm := make([]byte, 32)
			newWrap := make([]byte, 32)
			for i := range newPerm {
				newPerm[i] = byte(0x45 + i*7)
				newWrap[i] = byte(0xA7 + i*11)
			}
			addSliceWords(secrets, newPerm)
			addSliceWords(secrets, newWrap)
			winRekey := captureTripleStackResidue(t, func() {
				b, err := loaded.Rekey(newPerm, newWrap)
				if err != nil {
					t.Errorf("Rekey: %v", err)
				}
				clear(b)
			})
			addSliceWords(secrets, loaded.wrapperKey)
			for idx, w := range winRekey {
				if secrets[w] {
					t.Fatalf("Rekey(%s) leaked secret word %#x at stack slot %d", tc.innerHash, w, idx)
				}
			}

			// Verify Inspect stack residue.
			winInspect := captureTripleStackResidue(t, func() {
				_, err := Inspect(blob)
				if err != nil {
					t.Errorf("Inspect: %v", err)
				}
			})
			for idx, w := range winInspect {
				if secrets[w] {
					t.Fatalf("Inspect(%s) leaked secret word %#x at stack slot %d", tc.innerHash, w, idx)
				}
			}

			// Verify InitKeys stack residue.
			var masters [8][]byte
			for slot := 0; slot < 8; slot++ {
				m := make([]byte, 32)
				for b := range m {
					m[b] = byte(0x13 + slot*29 + b*7)
				}
				masters[slot] = m
				addSliceWords(secrets, m)
			}
			var ikPipe *Pipeline
			var ikErr error
			winIK := captureTripleStackResidue(t, func() {
				var ikBlob []byte
				ikPipe, ikBlob, ikErr = InitKeys(ProfileStreamingAEADTripleMACV1, Opts{
					InnerHash: tc.innerHash,
				}, masters)
				clear(ikBlob)
			})
			if ikErr != nil {
				t.Fatalf("InitKeys(%s): %v", tc.innerHash, ikErr)
			}
			defer ikPipe.Close()
			addSliceWords(secrets, ikPipe.wrapperKey)
			addSliceWords(secrets, ikPipe.macKey)
			for _, k := range ikPipe.prfKeys {
				addSliceWords(secrets, k)
			}
			for _, s := range ikPipe.seeds {
				for _, w := range seedComponentsHandle(s, ikPipe.width) {
					if w != 0 && w != tripleResidueSentinel {
						secrets[w] = true
					}
				}
			}
			for idx, w := range winIK {
				if secrets[w] {
					t.Fatalf("InitKeys(%s) leaked secret word %#x at stack slot %d", tc.innerHash, w, idx)
				}
			}
		})
	}
}
