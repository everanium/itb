package hashes

import (
	"fmt"
	"os"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/internal/forcetier"
)

// blake2b_cascade_kat_test.go — known-answer vectors of the BLAKE2b-256 /
// -512 ChainHash cascades, produced by the pure-Go cascade under the
// noitbasm build tag and identical on every assembly tier. The vectors
// cover the per-pixel cascade of the 512 / 1024 / 2048-bit keys at the
// four kernel shapes — single lane, four lanes, the single-lane fused
// hook over the prepended lock components of the Interlocked Barrier
// fill — and the batch-16 fill hook at the 13-byte shape across a group
// index base that carries through byte 7 inside the batch. A seed with
// every hook and the same seed on the arms alone are both checked, so
// the table pins the wire as well as every hook against the noitbasm
// reference.

type blake2bCascadeKAT struct {
	width, groups, n int
	single, batched  string
	fused            string
}

var blake2bCascadeKATs = []blake2bCascadeKAT{
	{256, 2, 13, "017cdd8752c95b0f5551db89d04fd527f106155aa28445460e1d344ae5fc3348", "0ae0c1e04f15b1c2", "160339c6f0200d75c7e26623e1aa49a799f635dfd0ea0712dd8467dee6dac624"},
	{256, 2, 20, "2f8b20f6df54b1194b1fc612d7fe6843599e7d6b3eadade7a46ed18a70991d68", "7cfbe77621e2605d", "abf5350a799703897a78f81b259939b5886fb8a4127afe235b94ec6b3c29ac6f"},
	{256, 2, 36, "616afa2c7a6f2e7599e4fd472f500ffa748a1f925d5bf2c4a6841df064428da1", "8def40c739d6e61e", "09b0e4eef9a32d2bd2ab5bb4fd2b3067438279fa0bed68b00fe5ef47336dcc93"},
	{256, 2, 68, "c54541716859dde48030c90b4889d12d1ed7018e7b5b01e9f23fc9590aafea18", "54f1c645574a9ab6", "7ff054dd4dde087e1301c3ca67cd8d28e2d30217c3cefa5e5c64715c2ed8258a"},
	{256, 4, 13, "47c4ff007912f6bebfa73e9ec78a0cacc92bbd5d80e54dc241a9ab8c97638dc7", "155e5305335b7d22", "2aa356692eb3ce802f36cfb4f4385af1ba604a5028b4781fd417baf2006593a1"},
	{256, 4, 20, "9179f1b6e0e7f76a493f2283557cdbcb45eccea5cea15be5f63151c14ee8a39f", "a70e68ffc8a5b780", "7025c70bf086c9c07477de41675074b74051ae40bf06a9d5b9a5d2bcd87fdd6a"},
	{256, 4, 36, "5850dd4e309f5fa97403099f74c72ce52567036aa445be5bf5a6fd3ea0f63923", "5302b8ed89d6caf5", "ffc7c93f5e37b6faf2f6bddccdc366cbb9d5f7947866dbea237a70e65f950c7d"},
	{256, 4, 68, "402590cf25c54ac2c8a65ec5fd43c83e0b6a8180b7652d08fc8bbfe0d1297aa6", "4e209cc374450666", "d3d35812ca2328fdb80828018fbf74faea776718aa8e9911bc0134ef09d5fc63"},
	{256, 8, 13, "11a755e3915d557c78079e172dd0ce038370cc0e37e04c6e849ecc9dc3217a4c", "c9617e141bd52b74", "b339ef4311c3382b98fca872957e946108e8b8a9468c7979f4964a36f7d58125"},
	{256, 8, 20, "f7d842e18c40ef0affe35efcf854187a6db3be341c4027220d3ca725a3322601", "3e57d0d9c99056d1", "182105a22f79674408652ac4e1cadc28ba432bd773129ed305ef04f3a0ff02aa"},
	{256, 8, 36, "8f0bc4ff3bad5d930b7638b4d8d77cd366f7713c567f02c7b7fd57445e7b1ca6", "22d3b51bddc4ff48", "09a52a2a5bc98f34f59b4c95087fefef89e056250b9123b4dd6510eb37453c7f"},
	{256, 8, 68, "77c0ed491d6a8c738a0d8052229ad3d27ca4bc0aa31a4cd604b301c1d40a6a41", "2e16f752f9015158", "82cf8ba600130a13acd4e6d9eb54509ef64c94a5b4ba2615b26a46df38347cba"},
	{512, 1, 13, "539d292bdd3ea452", "17af131929890551", "d7bd2eeff24330d7"},
	{512, 1, 20, "cbe3789ce94e335d", "da1b7262706d9f65", "186b665d0bee1fa8"},
	{512, 1, 36, "c40edf289bdafbcf", "4e197b6ecd0af040", "639eb31c7415a050"},
	{512, 1, 68, "62a17f72cccc2be3", "6b8ecccaea8eb2e4", "ec4df63bc37a1fd6"},
	{512, 2, 13, "db7b844588b5ed4a", "5dd8949ba388923f", "c2f4241132473692"},
	{512, 2, 20, "ad4308461aff1eac", "78810fdc5b21cab5", "c56908a5f5ea8c10"},
	{512, 2, 36, "e035fee08bbb299b", "4e8b71338dc51b0e", "fe777dcfd191b3a1"},
	{512, 2, 68, "f96817d6b2ac5c62", "613cf41a3e2e0e26", "1992643068e94b0e"},
	{512, 4, 13, "4358599c4348bb20", "532bb17a4100e6ae", "2b775b92afc21a2b"},
	{512, 4, 20, "d3488ddd9b68e472", "5d89fe444fff8e78", "5ae67395af01b65e"},
	{512, 4, 36, "86c6d9c2aaffea58", "ccb85c15f9a48157", "4b32a3ab966fb7f0"},
	{512, 4, 68, "5dfe9915ecbfb13a", "c20c2b5a9f6fb299", "f896525e1c575d00"},
}

// blake2bFillKATs are the folds of the batch-16 fill output over the lock
// components at group index base 0x00FFFFFFFFFFFFF8, keyed by width and
// group count.
var blake2bFillKATs = map[[2]int]string{
	{256, 2}: "ab08ca9f606d4d06",
	{256, 4}: "a5a44e416786e923",
	{256, 8}: "352730ee3a5d9722",
	{512, 1}: "d02ec6e6f547a341",
	{512, 2}: "53e7f256470821c7",
	{512, 4}: "49fe63bf88e5dbe5",
}

func blake2bKATKey(width int) []byte {
	key := make([]byte, width/8)
	for i := range key {
		key[i] = byte(0x5A ^ i*13 ^ width)
	}
	return key
}

func blake2bKATComponents(words int) []uint64 {
	comps := make([]uint64, words)
	for i := range comps {
		comps[i] = 0x9E3779B97F4A7C15*uint64(i+1) ^ 0x0123456789ABCDEF
	}
	return comps
}

func blake2bKATLock(width int) []uint64 {
	lock := make([]uint64, width/64)
	for i := range lock {
		lock[i] = 0xC2B2AE3D27D4EB4F*uint64(i+7) ^ 0xFEDCBA9876543210
	}
	return lock
}

func TestBLAKE2bCascadeKAT(t *testing.T) {
	if forcetier.ChainHashSeq() {
		t.Skip("ITB_FORCE_CHAINHASH_SEQ disables the fused hooks")
	}
	printKAT := os.Getenv("ITB_KAT_PRINT") != ""
	for _, kat := range blake2bCascadeKATs {
		t.Run(fmt.Sprintf("%d/%d/%d", kat.width, kat.groups, kat.n), func(t *testing.T) {
			buf := aescmacKATBuf(kat.n, kat.groups)
			var lanes [4][]byte
			for l := range lanes {
				lanes[l] = append([]byte(nil), buf...)
				lanes[l][0] ^= byte(l + 1)
			}
			var singleGot, batchedGot, fusedGot string
			switch kat.width {
			case 256:
				key := blake2bKATKey(256)
				comps := blake2bKATComponents(4 * kat.groups)
				lock := append(blake2bKATLock(256), comps...)
				hooked, err := SeedFromComponents256(CipherBLAKE2b256, key, comps...)
				if err != nil {
					t.Fatal(err)
				}
				plain := armsSeed256(t, CipherBLAKE2b256, key, comps)
				if hooked.FusedChain == nil || hooked.BatchFusedChain == nil || hooked.InterlockFillX16() == nil {
					t.Fatal("blake2b256 seed is missing a hook")
				}
				for label, s := range map[string]*itb.Seed256{"hooked": hooked, "arms-only": plain} {
					h := s.ChainHash256(buf)
					singleGot = fmt.Sprintf("%016x%016x%016x%016x", h[0], h[1], h[2], h[3])
					if !printKAT && singleGot != kat.single {
						t.Errorf("%s ChainHash256 = %s, want %s", label, singleGot, kat.single)
					}
					if s.BatchFusedChain == nil && s.BatchHash == nil {
						// The arms-only seed has no batched arm on this
						// build; the hooked seed's batched path is
						// checked above.
						continue
					}
					b := s.BatchChainHash256(&lanes)
					var acc uint64
					for l := range b {
						acc = foldWords(acc, b[l][:])
					}
					batchedGot = fmt.Sprintf("%016x", acc)
					if !printKAT && batchedGot != kat.batched {
						t.Errorf("%s BatchChainHash256 fold = %s, want %s", label, batchedGot, kat.batched)
					}
				}
				f, ok := hooked.FusedChain(lock, buf)
				if !ok {
					t.Fatal("fused hook declined a kernel shape")
				}
				fusedGot = fmt.Sprintf("%016x%016x%016x%016x", f[0], f[1], f[2], f[3])
				if h := seqCascade256(plain.Hash, lock, buf); h != f {
					t.Errorf("sequential cascade over lock components diverges from the fused hook")
				}
				if kat.n == 13 {
					var out [8][4]uint64
					hooked.InterlockFillX16()(lock, 0x00FFFFFFFFFFFFF8, &out)
					var acc uint64
					for i := range out {
						acc = foldWords(acc, out[i][:])
					}
					for i := range out {
						if want := seqCascade256(plain.Hash, lock, fillBlockKAT(0x00FFFFFFFFFFFFF8+uint64(i))); out[i] != want {
							t.Errorf("batch-16 fill lane %d diverges from the sequential cascade", i)
						}
					}
					got := fmt.Sprintf("%016x", acc)
					if printKAT {
						t.Logf("\t{256, %d}: %q,", kat.groups, got)
					} else if want := blake2bFillKATs[[2]int{256, kat.groups}]; got != want {
						t.Errorf("batch-16 fill fold = %s, want %s", got, want)
					}
				}
			case 512:
				key := blake2bKATKey(512)
				comps := blake2bKATComponents(8 * kat.groups)
				lock := append(blake2bKATLock(512), comps...)
				hooked, err := SeedFromComponents512(CipherBLAKE2b512, key, comps...)
				if err != nil {
					t.Fatal(err)
				}
				plain := armsSeed512(t, CipherBLAKE2b512, key, comps)
				if hooked.FusedChain == nil || hooked.BatchFusedChain == nil || hooked.InterlockFillX16() == nil {
					t.Fatal("blake2b512 seed is missing a hook")
				}
				for label, s := range map[string]*itb.Seed512{"hooked": hooked, "arms-only": plain} {
					h := s.ChainHash512(buf)
					singleGot = fmt.Sprintf("%016x", foldWords(0, h[:]))
					if !printKAT && singleGot != kat.single {
						t.Errorf("%s ChainHash512 fold = %s, want %s", label, singleGot, kat.single)
					}
					if s.BatchFusedChain == nil && s.BatchHash == nil {
						// The arms-only seed has no batched arm on this
						// build; the hooked seed's batched path is
						// checked above.
						continue
					}
					b := s.BatchChainHash512(&lanes)
					var acc uint64
					for l := range b {
						acc = foldWords(acc, b[l][:])
					}
					batchedGot = fmt.Sprintf("%016x", acc)
					if !printKAT && batchedGot != kat.batched {
						t.Errorf("%s BatchChainHash512 fold = %s, want %s", label, batchedGot, kat.batched)
					}
				}
				f, ok := hooked.FusedChain(lock, buf)
				if !ok {
					t.Fatal("fused hook declined a kernel shape")
				}
				fusedGot = fmt.Sprintf("%016x", foldWords(0, f[:]))
				if h := seqCascade512(plain.Hash, lock, buf); h != f {
					t.Errorf("sequential cascade over lock components diverges from the fused hook")
				}
				if kat.n == 13 {
					var out [4][8]uint64
					hooked.InterlockFillX16()(lock, 0x00FFFFFFFFFFFFF8, &out)
					var acc uint64
					for i := range out {
						acc = foldWords(acc, out[i][:])
						if want := seqCascade512(plain.Hash, lock, fillBlockKAT(0x00FFFFFFFFFFFFF8+uint64(i))); out[i] != want {
							t.Errorf("batch-16 fill lane %d diverges from the sequential cascade", i)
						}
					}
					got := fmt.Sprintf("%016x", acc)
					if printKAT {
						t.Logf("\t{512, %d}: %q,", kat.groups, got)
					} else if want := blake2bFillKATs[[2]int{512, kat.groups}]; got != want {
						t.Errorf("batch-16 fill fold = %s, want %s", got, want)
					}
				}
			}
			if !printKAT && fusedGot != kat.fused {
				t.Errorf("FusedChain(lock) = %s, want %s", fusedGot, kat.fused)
			}
			if printKAT {
				t.Logf("\t{%d, %d, %d, %q, %q, %q},", kat.width, kat.groups, kat.n, singleGot, batchedGot, fusedGot)
			}
		})
	}
}

// TestBLAKE2bHooksZeroAlloc asserts that the hooks installed on blake2b256
// / blake2b512 seeds run without a heap allocation per call at every
// kernel shape.
func TestBLAKE2bHooksZeroAlloc(t *testing.T) {
	if forcetier.ChainHashSeq() {
		t.Skip("ITB_FORCE_CHAINHASH_SEQ disables the fused hooks")
	}
	check := func(what string, f func()) {
		t.Helper()
		if n := testing.AllocsPerRun(50, f); n != 0 {
			t.Errorf("%s allocates %.0f objects per call", what, n)
		}
	}
	s256, _, err := NewSeed256(CipherBLAKE2b256, 1024)
	if err != nil {
		t.Fatal(err)
	}
	s512, _, err := NewSeed512(CipherBLAKE2b512, 1024)
	if err != nil {
		t.Fatal(err)
	}
	lock256 := append(blake2bKATLock(256), s256.Components...)
	lock512 := append(blake2bKATLock(512), s512.Components...)
	for _, n := range []int{13, 20, 36, 68} {
		buf := aescmacKATBuf(n, 4)
		var lanes [4][]byte
		for l := range lanes {
			lanes[l] = append([]byte(nil), buf...)
		}
		check(fmt.Sprintf("blake2b256 FusedChain n=%d", n), func() { s256.FusedChain(lock256, buf) })
		check(fmt.Sprintf("blake2b256 BatchFusedChain n=%d", n), func() { s256.BatchFusedChain(s256.Components, &lanes) })
		check(fmt.Sprintf("blake2b512 FusedChain n=%d", n), func() { s512.FusedChain(lock512, buf) })
		check(fmt.Sprintf("blake2b512 BatchFusedChain n=%d", n), func() { s512.BatchFusedChain(s512.Components, &lanes) })
	}
	fill256, fill512 := s256.InterlockFillX16(), s512.InterlockFillX16()
	var out256 [8][4]uint64
	var out512 [4][8]uint64
	check("blake2b256 InterlockFillX16", func() { fill256(lock256, 0x00FFFFFFFFFFFFF8, &out256) })
	check("blake2b512 InterlockFillX16", func() { fill512(lock512, 0x00FFFFFFFFFFFFF8, &out512) })
}

// TestBLAKE2bWideHooksZeroAlloc asserts that the eight-lane per-pixel
// hooks and the width-512 batch-32 fill hook installed on blake2b256 /
// blake2b512 seeds run without a heap allocation per call; the
// eight-lane hooks are present only where the ZMM eight-lane arm is
// selected.
func TestBLAKE2bWideHooksZeroAlloc(t *testing.T) {
	if forcetier.ChainHashSeq() {
		t.Skip("ITB_FORCE_CHAINHASH_SEQ disables the fused hooks")
	}
	check := func(what string, f func()) {
		t.Helper()
		if n := testing.AllocsPerRun(50, f); n != 0 {
			t.Errorf("%s allocates %.0f objects per call", what, n)
		}
	}
	s256, _, err := NewSeed256(CipherBLAKE2b256, 1024)
	if err != nil {
		t.Fatal(err)
	}
	s512, _, err := NewSeed512(CipherBLAKE2b512, 1024)
	if err != nil {
		t.Fatal(err)
	}
	lock256 := append(blake2bKATLock(256), s256.Components...)
	lock512 := append(blake2bKATLock(512), s512.Components...)
	for _, n := range []int{20, 36, 68} {
		buf := aescmacKATBuf(n, 4)
		var lanes [8][]byte
		for l := range lanes {
			lanes[l] = append([]byte(nil), buf...)
		}
		if x8 := s256.BatchFusedChain8(); x8 != nil {
			check(fmt.Sprintf("blake2b256 BatchFusedChain8 n=%d", n), func() { x8(lock256, &lanes) })
		}
		if x8 := s512.BatchFusedChain8(); x8 != nil {
			check(fmt.Sprintf("blake2b512 BatchFusedChain8 n=%d", n), func() { x8(lock512, &lanes) })
		}
	}
	if s256.InterlockFillX32() != nil {
		t.Error("blake2b256 carries a batch-32 fill hook; none is registered")
	}
	fill := s512.InterlockFillX32()
	if fill == nil {
		t.Fatal("blake2b512 carries no batch-32 fill hook")
	}
	var out [8][8]uint64
	check("blake2b512 InterlockFillX32", func() { fill(lock512, 0x00FFFFFFFFFFFFF8, &out) })
}
