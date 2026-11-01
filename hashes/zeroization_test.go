package hashes

import (
	"crypto/aes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"runtime"
	"runtime/debug"
	"testing"
	"unsafe"
)

const (
	hashResidueGap      = 1 << 10
	hashResiduePad      = 2 << 10
	hashResidueWindow   = 16 << 10
	hashResidueSentinel = uint64(0x5A5A5A5A5A5A5A5A)
)

func captureHashStackResidue(t *testing.T, fn func() uintptr) []uint64 {
	t.Helper()
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	res := make([]uint64, hashResidueWindow/8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		hashResidueGrow(0)
		hashResidueProbe(fn, res)
	}()
	<-done
	written := 0
	for _, w := range res {
		if w != hashResidueSentinel {
			written++
		}
	}
	if written == 0 {
		t.Fatal("stack probe window did not intersect target frame (written == 0)")
	}
	return res
}

//go:noinline
func hashResidueGrow(i int) byte {
	var pad [4 * hashResidueWindow]byte
	pad[i] = 1
	return pad[(i+1)%len(pad)]
}

//go:noinline
func hashResidueMark() uintptr {
	var marker uint64
	return uintptr(unsafe.Pointer(&marker))
}

//go:noinline
func hashResidueProbe(fn func() uintptr, res []uint64) {
	var anchor uint64
	top := unsafe.Add(unsafe.Pointer(&anchor), -hashResidueGap)
	fillWords := (hashResiduePad + 1024 + hashResidueWindow) / 8
	for i := 0; i < fillWords; i++ {
		*(*uint64)(unsafe.Add(top, -8*(i+1))) = hashResidueSentinel
	}
	calleeSP, sink := hashResidueDeep(fn, 0)
	runtime.KeepAlive(sink)
	scanTop := unsafe.Add(unsafe.Pointer(&anchor), int(calleeSP+24-uintptr(unsafe.Pointer(&anchor))))
	for i := range res {
		res[i] = *(*uint64)(unsafe.Add(scanTop, -8*(i+1)))
	}
}

//go:noinline
func hashResidueDeep(fn func() uintptr, i int) (uintptr, byte) {
	var pad [hashResiduePad]byte
	pad[i] = 1
	sp := fn()
	return sp, pad[(i+7)%len(pad)]
}

//go:noinline
func leakyHashSecretFrame(words []uint64) uint64 {
	var leak [8]uint64
	copy(leak[:], words)
	runtime.KeepAlive(&leak)
	return leak[0]
}

func TestHashesStackAndPoolZeroization(t *testing.T) {
	var key64 [64]byte
	var key32 [32]byte
	var key16 [16]byte
	for i := range key64 {
		key64[i] = byte(0x37 + i*5)
	}
	copy(key32[:], key64[:32])
	copy(key16[:], key64[:16])

	seed256 := [4]uint64{
		0xA1B2C3D4E5F60718,
		0x18293A4B5C6D7E8F,
		0x9FA0B1C2D3E4F506,
		0x061728394A5B6C7D,
	}
	seed512 := [8]uint64{
		seed256[0], seed256[1], seed256[2], seed256[3],
		0x778899AABBCCDDEE, 0xFFEEDDCCBBAA9988,
		0x13579BDF2468ACE0, 0x0ECA8642FDB97531,
	}

	// Negative control: verify captureHashStackResidue detects an unzeroed word.
	negWin := captureHashStackResidue(t, func() uintptr {
		sp := hashResidueMark()
		_ = leakyHashSecretFrame(seed256[:])
		return sp
	})
	foundNeg := false
	for _, w := range negWin {
		if w == seed256[0] {
			foundNeg = true
			break
		}
	}
	if !foundNeg {
		t.Fatal("negative control failed: leakyHashSecretFrame was not detected in stack residue")
	}

	data := make([]byte, 512)
	for i := range data {
		data[i] = byte(0x93 + i*17)
	}
	secrets := make(map[uint64]bool)
	for off := 0; off+8 <= len(data); off += 8 {
		w := binary.LittleEndian.Uint64(data[off:])
		if w != 0 && w != hashResidueSentinel {
			secrets[w] = true
		}
	}
	for _, w := range seed512 {
		secrets[w] = true
	}
	for off := 0; off+8 <= len(key64); off += 8 {
		w := binary.LittleEndian.Uint64(key64[off:])
		if w != 0 && w != hashResidueSentinel {
			secrets[w] = true
		}
	}

	var lanes [4][]byte
	for i := range lanes {
		lanes[i] = data
	}
	seeds128 := [4][2]uint64{
		{seed256[0], seed256[1]},
		{seed256[2], seed256[3]},
		{seed512[4], seed512[5]},
		{seed512[6], seed512[7]},
	}
	seeds256 := [4][4]uint64{seed256, seed256, seed256, seed256}
	seeds512 := [4][8]uint64{seed512, seed512, seed512, seed512}

	checkWin := func(t *testing.T, label string, win []uint64) {
		t.Helper()
		for idx, w := range win {
			if secrets[w] {
				t.Fatalf("%s leaked secret word %#x at stack slot %d", label, w, idx)
			}
		}
	}

	t.Run("AESITB128PairWithKey", func(t *testing.T) {
		single, batched := AESITB128PairWithKey(key16)
		win1 := captureHashStackResidue(t, func() uintptr {
			sp := hashResidueMark()
			_, _ = single(data, seed256[0], seed256[1])
			return sp
		})
		checkWin(t, "AESITB128PairWithKey/single", win1)
		win4 := captureHashStackResidue(t, func() uintptr {
			sp := hashResidueMark()
			out := batched(&lanes, seeds128)
			clear(out[:])
			return sp
		})
		checkWin(t, "AESITB128PairWithKey/batched", win4)
	})

	t.Run("Areion256PairWithKey", func(t *testing.T) {
		single, batched := Areion256PairWithKey(key32)
		win1 := captureHashStackResidue(t, func() uintptr {
			sp := hashResidueMark()
			out1 := single(data, seed256)
			clear(out1[:])
			return sp
		})
		checkWin(t, "Areion256PairWithKey/single", win1)
		win4 := captureHashStackResidue(t, func() uintptr {
			sp := hashResidueMark()
			out4 := batched(&lanes, seeds256)
			clear(out4[:])
			return sp
		})
		checkWin(t, "Areion256PairWithKey/batched", win4)
	})

	t.Run("Areion512PairWithKey", func(t *testing.T) {
		single, batched := Areion512PairWithKey(key64)
		win1 := captureHashStackResidue(t, func() uintptr {
			sp := hashResidueMark()
			out1 := single(data, seed512)
			clear(out1[:])
			return sp
		})
		checkWin(t, "Areion512PairWithKey/single", win1)
		win4 := captureHashStackResidue(t, func() uintptr {
			sp := hashResidueMark()
			out4 := batched(&lanes, seeds512)
			clear(out4[:])
			return sp
		})
		checkWin(t, "Areion512PairWithKey/batched", win4)
	})

	t.Run("BLAKE2b256PairWithKey", func(t *testing.T) {
		single, batched := BLAKE2b256PairWithKey(key32)
		win1 := captureHashStackResidue(t, func() uintptr {
			sp := hashResidueMark()
			out1 := single(data, seed256)
			clear(out1[:])
			return sp
		})
		checkWin(t, "BLAKE2b256PairWithKey/single", win1)
		win4 := captureHashStackResidue(t, func() uintptr {
			sp := hashResidueMark()
			out4 := batched(&lanes, seeds256)
			clear(out4[:])
			return sp
		})
		checkWin(t, "BLAKE2b256PairWithKey/batched", win4)
	})

	t.Run("BLAKE2b512PairWithKey", func(t *testing.T) {
		single, batched := BLAKE2b512PairWithKey(key64)
		win1 := captureHashStackResidue(t, func() uintptr {
			sp := hashResidueMark()
			out1 := single(data, seed512)
			clear(out1[:])
			return sp
		})
		checkWin(t, "BLAKE2b512PairWithKey/single", win1)
		win4 := captureHashStackResidue(t, func() uintptr {
			sp := hashResidueMark()
			out4 := batched(&lanes, seeds512)
			clear(out4[:])
			return sp
		})
		checkWin(t, "BLAKE2b512PairWithKey/batched", win4)
	})

	t.Run("BLAKE2s256PairWithKey", func(t *testing.T) {
		single, batched := BLAKE2s256PairWithKey(key32)
		win1 := captureHashStackResidue(t, func() uintptr {
			sp := hashResidueMark()
			out1 := single(data, seed256)
			clear(out1[:])
			return sp
		})
		checkWin(t, "BLAKE2s256PairWithKey/single", win1)
		win4 := captureHashStackResidue(t, func() uintptr {
			sp := hashResidueMark()
			out4 := batched(&lanes, seeds256)
			clear(out4[:])
			return sp
		})
		checkWin(t, "BLAKE2s256PairWithKey/batched", win4)
	})

	t.Run("BLAKE3256PairWithKey", func(t *testing.T) {
		single, batched := BLAKE3256PairWithKey(key32)
		win1 := captureHashStackResidue(t, func() uintptr {
			sp := hashResidueMark()
			out1 := single(data, seed256)
			clear(out1[:])
			return sp
		})
		checkWin(t, "BLAKE3256PairWithKey/single", win1)
		win4 := captureHashStackResidue(t, func() uintptr {
			sp := hashResidueMark()
			out4 := batched(&lanes, seeds256)
			clear(out4[:])
			return sp
		})
		checkWin(t, "BLAKE3256PairWithKey/batched", win4)
	})

	t.Run("AESCMACPairWithKey", func(t *testing.T) {
		single, batched := AESCMACPairWithKey(key16)
		win1 := captureHashStackResidue(t, func() uintptr {
			sp := hashResidueMark()
			_, _ = single(data, seed256[0], seed256[1])
			return sp
		})
		checkWin(t, "AESCMACPairWithKey/single", win1)
		win4 := captureHashStackResidue(t, func() uintptr {
			sp := hashResidueMark()
			out4 := batched(&lanes, seeds128)
			clear(out4[:])
			return sp
		})
		checkWin(t, "AESCMACPairWithKey/batched", win4)
	})

	t.Run("SipHash24Pair", func(t *testing.T) {
		single, batched := SipHash24Pair()
		win1 := captureHashStackResidue(t, func() uintptr {
			sp := hashResidueMark()
			_, _ = single(data, seed256[0], seed256[1])
			return sp
		})
		checkWin(t, "SipHash24Pair/single", win1)
		win4 := captureHashStackResidue(t, func() uintptr {
			sp := hashResidueMark()
			out4 := batched(&lanes, seeds128)
			clear(out4[:])
			return sp
		})
		checkWin(t, "SipHash24Pair/batched", win4)
	})

	t.Run("ChaCha20256PairWithKey", func(t *testing.T) {
		single, batched := ChaCha20256PairWithKey(key32)
		win1 := captureHashStackResidue(t, func() uintptr {
			sp := hashResidueMark()
			out1 := single(data, seed256)
			clear(out1[:])
			return sp
		})
		checkWin(t, "ChaCha20256PairWithKey/single", win1)
		win4 := captureHashStackResidue(t, func() uintptr {
			sp := hashResidueMark()
			out4 := batched(&lanes, seeds256)
			clear(out4[:])
			return sp
		})
		checkWin(t, "ChaCha20256PairWithKey/batched", win4)
	})

	t.Run("ChainAbsorbBuilders", func(t *testing.T) {
		blk, err := aes.NewCipher(key16[:])
		if err != nil {
			t.Fatal(err)
		}
		cbc128 := BuildCBCMACChainAbsorb128(blk)
		cbc256 := BuildCBCMACChainAbsorb256(blk)
		cbc512 := BuildCBCMACChainAbsorb512(blk)

		perm := func(st []byte) {
			for i := range st {
				st[i] = st[i]*3 + 1
			}
		}
		sp128 := BuildSpongeChainAbsorb128(perm, 16, 16, key16[:])
		sp256 := BuildSpongeChainAbsorb256(perm, 16, 16, key16[:])
		sp512 := BuildSpongeChainAbsorb512(perm, 16, 16, key16[:])

		arx128 := BuildARXChainAbsorb128(sha256.Sum256, key32[:])
		arx256 := BuildARXChainAbsorb256(sha256.Sum256, key32[:])
		arx512 := BuildARXChainAbsorb512(sha512.Sum512, key64[:])

		for _, b128 := range []struct {
			name string
			fn   func([]byte, uint64, uint64) (uint64, uint64)
		}{
			{"cbc128", cbc128},
			{"sp128", sp128},
			{"arx128", arx128},
		} {
			win := captureHashStackResidue(t, func() uintptr {
				sp := hashResidueMark()
				_, _ = b128.fn(data, seed256[0], seed256[1])
				return sp
			})
			checkWin(t, "ChainAbsorbBuilders/"+b128.name, win)
		}
		for _, b256 := range []struct {
			name string
			fn   func([]byte, [4]uint64) [4]uint64
		}{
			{"cbc256", cbc256},
			{"sp256", sp256},
			{"arx256", arx256},
		} {
			win := captureHashStackResidue(t, func() uintptr {
				sp := hashResidueMark()
				o256 := b256.fn(data, seed256)
				clear(o256[:])
				return sp
			})
			checkWin(t, "ChainAbsorbBuilders/"+b256.name, win)
		}
		for _, b512 := range []struct {
			name string
			fn   func([]byte, [8]uint64) [8]uint64
		}{
			{"cbc512", cbc512},
			{"sp512", sp512},
			{"arx512", arx512},
		} {
			win := captureHashStackResidue(t, func() uintptr {
				sp := hashResidueMark()
				o512 := b512.fn(data, seed512)
				clear(o512[:])
				return sp
			})
			checkWin(t, "ChainAbsorbBuilders/"+b512.name, win)
		}

		// Verify BuildSpongeChainAbsorb* and BuildARXChainAbsorb* clone fixedKey so caller clear(key) does not alter output.
		kSp := append([]byte(nil), key16[:]...)
		kArx32 := append([]byte(nil), key32[:]...)
		kArx64 := append([]byte(nil), key64[:]...)
		sp128Iso := BuildSpongeChainAbsorb128(perm, 16, 16, kSp)
		sp256Iso := BuildSpongeChainAbsorb256(perm, 16, 16, kSp)
		sp512Iso := BuildSpongeChainAbsorb512(perm, 16, 16, kSp)
		arx128Iso := BuildARXChainAbsorb128(sha256.Sum256, kArx32)
		arx256Iso := BuildARXChainAbsorb256(sha256.Sum256, kArx32)
		arx512Iso := BuildARXChainAbsorb512(sha512.Sum512, kArx64)
		clear(kSp)
		clear(kArx32)
		clear(kArx64)

		lo1, hi1 := sp128(data, seed256[0], seed256[1])
		lo2, hi2 := sp128Iso(data, seed256[0], seed256[1])
		if lo1 != lo2 || hi1 != hi2 {
			t.Fatal("BuildSpongeChainAbsorb128 mutated when caller cleared key")
		}
		if sp256(data, seed256) != sp256Iso(data, seed256) {
			t.Fatal("BuildSpongeChainAbsorb256 mutated when caller cleared key")
		}
		if sp512(data, seed512) != sp512Iso(data, seed512) {
			t.Fatal("BuildSpongeChainAbsorb512 mutated when caller cleared key")
		}
		lo1, hi1 = arx128(data, seed256[0], seed256[1])
		lo2, hi2 = arx128Iso(data, seed256[0], seed256[1])
		if lo1 != lo2 || hi1 != hi2 {
			t.Fatal("BuildARXChainAbsorb128 mutated when caller cleared key")
		}
		if arx256(data, seed256) != arx256Iso(data, seed256) {
			t.Fatal("BuildARXChainAbsorb256 mutated when caller cleared key")
		}
		if arx512(data, seed512) != arx512Iso(data, seed512) {
			t.Fatal("BuildARXChainAbsorb512 mutated when caller cleared key")
		}
	})
}

func TestCallerKeyWipeIsolationAndFixedKeyInPlaceWipe(t *testing.T) {
	probe := make([]byte, 20)
	for i := range probe {
		probe[i] = byte(0x41 + i*3)
	}
	var lanes4 [4][]byte
	for i := range lanes4 {
		lanes4[i] = probe
	}
	var lanes8 [8][]byte
	for i := range lanes8 {
		lanes8[i] = probe
	}
	comps := make([]uint64, 8)
	for i := range comps {
		comps[i] = 0x0123456789ABCDEF ^ uint64(i)*0x9E3779B97F4A7C15
	}

	for _, spec := range Registry {
		if spec.Name == CipherSipHash24 {
			continue
		}
		t.Run(spec.Name, func(t *testing.T) {
			keyLen := int(spec.Width) / 8
			if spec.Width == W512 {
				keyLen = 64
			}
			refKey := make([]byte, keyLen)
			for i := range refKey {
				refKey[i] = byte(0xA5 ^ (i * 11))
			}
			callerKey := append([]byte(nil), refKey...)
			zeroKey := make([]byte, keyLen)

			switch spec.Width {
			case W128:
				refSeed, err := SeedFromComponents128(spec.Name, refKey, comps...)
				if err != nil {
					t.Fatal(err)
				}
				zeroSeed, _, err := seedFromComponents128WithKey(spec.Name, zeroKey, comps...)
				if err != nil {
					t.Fatal(err)
				}
				dutSeed, fixedKey, err := seedFromComponents128WithKey(spec.Name, callerKey, comps...)
				if err != nil {
					t.Fatal(err)
				}
				// Caller immediately wipes their own input key slice.
				clear(callerKey)

				loRef, hiRef := refSeed.Hash(probe, comps[0], comps[1])
				loDut, hiDut := dutSeed.Hash(probe, comps[0], comps[1])
				if loDut != loRef || hiDut != hiRef {
					t.Fatalf("%s single Hash changed after caller wiped callerKey", spec.Name)
				}
				var s4 [4][2]uint64
				if dutSeed.BatchHash(&lanes4, s4) != refSeed.BatchHash(&lanes4, s4) {
					t.Fatalf("%s BatchHash changed after caller wiped callerKey", spec.Name)
				}
				if dutSeed.FusedChain != nil {
					fLo, fHi, ok := dutSeed.FusedChain(comps, probe)
					rLo, rHi, _ := refSeed.FusedChain(comps, probe)
					if !ok || fLo != rLo || fHi != rHi {
						t.Fatalf("%s FusedChain changed after caller wiped callerKey", spec.Name)
					}
				}
				if dutSeed.BatchFusedChain != nil {
					fOut, ok := dutSeed.BatchFusedChain(comps, &lanes4)
					rOut, _ := refSeed.BatchFusedChain(comps, &lanes4)
					if !ok || fOut != rOut {
						t.Fatalf("%s BatchFusedChain changed after caller wiped callerKey", spec.Name)
					}
				}
				if x8 := dutSeed.BatchFusedChain8(); x8 != nil {
					fOut, ok := x8(comps, &lanes8)
					rOut, _ := refSeed.BatchFusedChain8()(comps, &lanes8)
					if !ok || fOut != rOut {
						t.Fatalf("%s BatchFusedChain8 changed after caller wiped callerKey", spec.Name)
					}
				}

				// Wiping fixedKey in place must zero the key array captured by aesitb128 closures.
				if spec.Name == CipherAESITB128 {
					clear(fixedKey)
					zLo, zHi := zeroSeed.Hash(probe, comps[0], comps[1])
					gLo, gHi := dutSeed.Hash(probe, comps[0], comps[1])
					if gLo != zLo || gHi != zHi {
						t.Fatalf("%s closure key was not zeroed in place when fixedKey was cleared", spec.Name)
					}
				}

			case W256:
				refSeed, err := SeedFromComponents256(spec.Name, refKey, comps...)
				if err != nil {
					t.Fatal(err)
				}
				zeroSeed, _, err := seedFromComponents256WithKey(spec.Name, zeroKey, comps...)
				if err != nil {
					t.Fatal(err)
				}
				dutSeed, fixedKey, err := seedFromComponents256WithKey(spec.Name, callerKey, comps...)
				if err != nil {
					t.Fatal(err)
				}
				// Caller immediately wipes their own input key slice.
				clear(callerKey)

				var s1 [4]uint64
				copy(s1[:], comps[:4])
				if dutSeed.Hash(probe, s1) != refSeed.Hash(probe, s1) {
					t.Fatalf("%s single Hash changed after caller wiped callerKey", spec.Name)
				}
				var s4 [4][4]uint64
				if dutSeed.BatchHash(&lanes4, s4) != refSeed.BatchHash(&lanes4, s4) {
					t.Fatalf("%s BatchHash changed after caller wiped callerKey", spec.Name)
				}
				if dutSeed.FusedChain != nil {
					fOut, ok := dutSeed.FusedChain(comps, probe)
					rOut, _ := refSeed.FusedChain(comps, probe)
					if !ok || fOut != rOut {
						t.Fatalf("%s FusedChain changed after caller wiped callerKey", spec.Name)
					}
				}
				if dutSeed.BatchFusedChain != nil {
					fOut, ok := dutSeed.BatchFusedChain(comps, &lanes4)
					rOut, _ := refSeed.BatchFusedChain(comps, &lanes4)
					if !ok || fOut != rOut {
						t.Fatalf("%s BatchFusedChain changed after caller wiped callerKey", spec.Name)
					}
				}
				if x8 := dutSeed.BatchFusedChain8(); x8 != nil {
					fOut, ok := x8(comps, &lanes8)
					rOut, _ := refSeed.BatchFusedChain8()(comps, &lanes8)
					if !ok || fOut != rOut {
						t.Fatalf("%s BatchFusedChain8 changed after caller wiped callerKey", spec.Name)
					}
				}

				// Wiping fixedKey in place must zero the key array captured by closures.
				if spec.Name != CipherBLAKE3 {
					clear(fixedKey)
					if dutSeed.Hash(probe, s1) != zeroSeed.Hash(probe, s1) {
						t.Fatalf("%s closure key was not zeroed in place when fixedKey was cleared", spec.Name)
					}
				}

			case W512:
				comps512 := append(append([]uint64(nil), comps...), comps...)
				refSeed, err := SeedFromComponents512(spec.Name, refKey, comps512...)
				if err != nil {
					t.Fatal(err)
				}
				zeroSeed, _, err := seedFromComponents512WithKey(spec.Name, zeroKey, comps512...)
				if err != nil {
					t.Fatal(err)
				}
				dutSeed, fixedKey, err := seedFromComponents512WithKey(spec.Name, callerKey, comps512...)
				if err != nil {
					t.Fatal(err)
				}
				// Caller immediately wipes their own input key slice.
				clear(callerKey)

				var s1 [8]uint64
				copy(s1[:], comps512[:8])
				if dutSeed.Hash(probe, s1) != refSeed.Hash(probe, s1) {
					t.Fatalf("%s single Hash changed after caller wiped callerKey", spec.Name)
				}
				var s4 [4][8]uint64
				if dutSeed.BatchHash(&lanes4, s4) != refSeed.BatchHash(&lanes4, s4) {
					t.Fatalf("%s BatchHash changed after caller wiped callerKey", spec.Name)
				}
				if dutSeed.FusedChain != nil {
					fOut, ok := dutSeed.FusedChain(comps512, probe)
					rOut, _ := refSeed.FusedChain(comps512, probe)
					if !ok || fOut != rOut {
						t.Fatalf("%s FusedChain changed after caller wiped callerKey", spec.Name)
					}
				}
				if dutSeed.BatchFusedChain != nil {
					fOut, ok := dutSeed.BatchFusedChain(comps512, &lanes4)
					rOut, _ := refSeed.BatchFusedChain(comps512, &lanes4)
					if !ok || fOut != rOut {
						t.Fatalf("%s BatchFusedChain changed after caller wiped callerKey", spec.Name)
					}
				}
				if x8 := dutSeed.BatchFusedChain8(); x8 != nil {
					fOut, ok := x8(comps512, &lanes8)
					rOut, _ := refSeed.BatchFusedChain8()(comps512, &lanes8)
					if !ok || fOut != rOut {
						t.Fatalf("%s BatchFusedChain8 changed after caller wiped callerKey", spec.Name)
					}
				}

				clear(fixedKey)
				if dutSeed.Hash(probe, s1) != zeroSeed.Hash(probe, s1) {
					t.Fatalf("%s closure key was not zeroed in place when fixedKey was cleared", spec.Name)
				}
			}
		})
	}
}
