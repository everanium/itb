package hashes

import (
	"fmt"
	"os"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/internal/forcetier"
)

// Known-answer vectors of the ChaCha20 ChainHash cascade, produced by the
// pure-Go cascade under the noitbasm build tag and identical on every
// assembly tier. The vectors cover the per-pixel cascade of the 512 /
// 1024 / 2048-bit keys at the four kernel shapes — single lane, four
// lanes, the single-lane fused hook over the prepended lock components of
// the Interlocked Barrier fill — and the batch-16 fill hook at the
// 13-byte shape across a group index base that carries through byte 7
// inside the batch. A seed with every hook and the same seed on the arms
// alone are both checked, so the table pins the wire as well as every
// hook against the noitbasm reference.

type chacha20CascadeKAT struct {
	groups, n       int
	single, batched string
	fused           string
}

var chacha20CascadeKATs = []chacha20CascadeKAT{
	{2, 13, "a13bf1beb4190d6b1005a6344c387554fdbe206aa914eebd9ccf7346f67ab964", "f2daf5d7793a53e3", "12088fbeefec4f92e4972225f86ca84a9c4fbae51d899b404bc45d81a5fac1ab"},
	{2, 20, "6dc31f0e308d3090b39329d738a70507b3640a3e0ef94ba13431e6956e71ae1d", "5fd55585217eede3", "b0b033606f0ba3d8a78113b42dcc70e104be0b93867fc4d577acf44efbc761a8"},
	{2, 36, "f6a8c643230f9065f1a86175c7a1022a44a35cdfb33c43f16eec755ab090c6b9", "4deb724431dda002", "8bb51a962712ec1354198e5f027e05debfd40279d46f5c106a67b4011dfd4eac"},
	{2, 68, "346a6a1580eccaa7b527013a27267ea532269046db516eb441ed22cf3afe7d16", "1c5f8fc605e389e7", "2e2b6be799d03d4a83b6a79ea0a813036ecee511de9878e87d16243c3097fed9"},
	{4, 13, "c7d2358faf6a5300897dfcbb54d1947788dc1278619dbfa72d20301dadd2fc5d", "f1ec64b3ef112aa8", "246f317fb28f5478cb10e5f1a4357a335fac15936bc7b65692f1ed0d29bf3758"},
	{4, 20, "496cb5a0339b9bc338d851e62b61f0479b388d8f29ae9f0f80ef4032e1746bad", "74dd8d1b8bc7a340", "8bc272aaaf1cc510777334f8771bf92fb6aecd84c8317568648c21b0966b4f74"},
	{4, 36, "96232058672a3fd2c9b836971461f82907bc173011851dc219064523928085ce", "e3971e3a8f07ddf6", "c8a8642bf830015adce87ef310c6b853b53591a55213da689e24dad7e7054f52"},
	{4, 68, "7c6ec6c84359bd2f5c28b3c73aaf0e9a8abb38fe0f59b72ac53ef7e38bb30fb3", "e22d31243ffe3863", "4182a036f3010c6c14be4fc580347940478c359b8e04baab9457af54cefafc0d"},
	{8, 13, "0a00793b28e7b429ff7c1f40944088c5c2af963debeb85b6fa963a1877102400", "f7a3c4aa90a1211b", "ebcb69eac1c20b1bdfa7373918676a28f7f6480aacbe3f4564f9d267eb7700b9"},
	{8, 20, "c976c99f5132f8e2b0eb4a113eae0370b1cbb671cf8081450f9699e2ff2af060", "f6adffa57e7b5546", "07a8ada2fc5ae3eb4ab60f7583a7a0dfdb49d14646a0734b402d19d6c647f6b5"},
	{8, 36, "4320dd979e5797992aa782f9cd8973c3c70f720757575e46bddcf12b7979fc13", "8502201dc620dc1d", "00b69da52702951d358a88b9dd5c4fc6c3ffc39c79499767e77de35304af22e1"},
	{8, 68, "f8398e2788b7f59a719346efafccdff1e0a7254546e3d5334d4fe243f1968273", "0f3e874dec2d1b02", "b27a802140df7e08c88aac331a205de562d13d95eaec4516f442e0ee80387e3c"},
}

// chacha20FillKATs are the folds of the batch-16 fill output over the lock
// components at group index base 0x00FFFFFFFFFFFFF8, keyed by group
// count.
var chacha20FillKATs = map[int]string{
	2: "9083f4869136ac26",
	4: "bfa0cf39b42dd459",
	8: "b5acd88a41f23425",
}

func chacha20KATKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0x69 ^ i*7)
	}
	return key
}

func chacha20KATComponents(words int) []uint64 {
	comps := make([]uint64, words)
	for i := range comps {
		comps[i] = 0x9E3779B97F4A7C15*uint64(i+13) ^ 0x7788990011223344
	}
	return comps
}

func chacha20KATLock() []uint64 {
	lock := make([]uint64, 4)
	for i := range lock {
		lock[i] = 0xC2B2AE3D27D4EB4F*uint64(i+3) ^ 0x8899AABBCCDDEEFF
	}
	return lock
}

func TestChaCha20CascadeKAT(t *testing.T) {
	if forcetier.ChainHashSeq() {
		t.Skip("ITB_FORCE_CHAINHASH_SEQ disables the fused hooks")
	}
	printKAT := os.Getenv("ITB_KAT_PRINT") != ""
	key := chacha20KATKey()
	for _, kat := range chacha20CascadeKATs {
		t.Run(fmt.Sprintf("%d/%d", kat.groups, kat.n), func(t *testing.T) {
			buf := aescmacKATBuf(kat.n, kat.groups)
			var lanes [4][]byte
			for l := range lanes {
				lanes[l] = append([]byte(nil), buf...)
				lanes[l][0] ^= byte(l + 1)
			}
			comps := chacha20KATComponents(4 * kat.groups)
			lock := append(chacha20KATLock(), comps...)
			hooked, err := SeedFromComponents256(CipherChaCha20, key, comps...)
			if err != nil {
				t.Fatal(err)
			}
			plain := armsSeed256(t, CipherChaCha20, key, comps)
			if hooked.FusedChain == nil || hooked.BatchFusedChain == nil || hooked.InterlockFillX16() == nil {
				t.Fatal("chacha20 seed is missing a hook")
			}
			var singleGot, batchedGot string
			for label, s := range map[string]*itb.Seed256{"hooked": hooked, "arms-only": plain} {
				h := s.ChainHash256(buf)
				singleGot = fmt.Sprintf("%016x%016x%016x%016x", h[0], h[1], h[2], h[3])
				if !printKAT && singleGot != kat.single {
					t.Errorf("%s ChainHash256 = %s, want %s", label, singleGot, kat.single)
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
			fusedGot := fmt.Sprintf("%016x%016x%016x%016x", f[0], f[1], f[2], f[3])
			if h := seqCascade256(plain.Hash, lock, buf); h != f {
				t.Errorf("sequential cascade over lock components diverges from the fused hook")
			}
			if kat.n == 13 {
				var out [8][4]uint64
				hooked.InterlockFillX16()(lock, 0x00FFFFFFFFFFFFF8, &out)
				var acc uint64
				for i := range out {
					acc = foldWords(acc, out[i][:])
					if want := seqCascade256(plain.Hash, lock, fillBlockKAT(0x00FFFFFFFFFFFFF8+uint64(i))); out[i] != want {
						t.Errorf("batch-16 fill lane %d diverges from the sequential cascade", i)
					}
				}
				got := fmt.Sprintf("%016x", acc)
				if printKAT {
					t.Logf("\t%d: %q,", kat.groups, got)
				} else if want := chacha20FillKATs[kat.groups]; got != want {
					t.Errorf("batch-16 fill fold = %s, want %s", got, want)
				}
			}
			if !printKAT && fusedGot != kat.fused {
				t.Errorf("FusedChain(lock) = %s, want %s", fusedGot, kat.fused)
			}
			if printKAT {
				t.Logf("\t{%d, %d, %q, %q, %q},", kat.groups, kat.n, singleGot, batchedGot, fusedGot)
			}
		})
	}
}

// TestChaCha20HooksZeroAlloc asserts that the hooks installed on chacha20
// seeds run without a heap allocation per call at every kernel shape.
func TestChaCha20HooksZeroAlloc(t *testing.T) {
	if forcetier.ChainHashSeq() {
		t.Skip("ITB_FORCE_CHAINHASH_SEQ disables the fused hooks")
	}
	check := func(what string, f func()) {
		t.Helper()
		if n := testing.AllocsPerRun(50, f); n != 0 {
			t.Errorf("%s allocates %.0f objects per call", what, n)
		}
	}
	s, _, err := NewSeed256(CipherChaCha20, 1024)
	if err != nil {
		t.Fatal(err)
	}
	lock := append(chacha20KATLock(), s.Components...)
	for _, n := range []int{13, 20, 36, 68} {
		buf := aescmacKATBuf(n, 4)
		var lanes [4][]byte
		for l := range lanes {
			lanes[l] = append([]byte(nil), buf...)
		}
		check(fmt.Sprintf("chacha20 FusedChain n=%d", n), func() { s.FusedChain(lock, buf) })
		check(fmt.Sprintf("chacha20 BatchFusedChain n=%d", n), func() { s.BatchFusedChain(s.Components, &lanes) })
	}
	fill := s.InterlockFillX16()
	var out [8][4]uint64
	check("chacha20 InterlockFillX16", func() { fill(lock, 0x00FFFFFFFFFFFFF8, &out) })
}

// TestChaCha20WideHooksZeroAlloc asserts that the eight-lane per-pixel
// hook installed on chacha20 seeds runs without a heap allocation per
// call; the hook is present only where the eight-lane YMM arm is
// selected, and no batch-32 fill hook is registered at width 256.
func TestChaCha20WideHooksZeroAlloc(t *testing.T) {
	if forcetier.ChainHashSeq() {
		t.Skip("ITB_FORCE_CHAINHASH_SEQ disables the fused hooks")
	}
	check := func(what string, f func()) {
		t.Helper()
		if n := testing.AllocsPerRun(50, f); n != 0 {
			t.Errorf("%s allocates %.0f objects per call", what, n)
		}
	}
	s, _, err := NewSeed256(CipherChaCha20, 1024)
	if err != nil {
		t.Fatal(err)
	}
	lock := append(chacha20KATLock(), s.Components...)
	for _, n := range []int{20, 36, 68} {
		buf := aescmacKATBuf(n, 4)
		var lanes [8][]byte
		for l := range lanes {
			lanes[l] = append([]byte(nil), buf...)
		}
		if x8 := s.BatchFusedChain8(); x8 != nil {
			check(fmt.Sprintf("chacha20 BatchFusedChain8 n=%d", n), func() { x8(lock, &lanes) })
		}
	}
	if s.InterlockFillX32() != nil {
		t.Error("chacha20 carries a batch-32 fill hook; none is registered")
	}
}
