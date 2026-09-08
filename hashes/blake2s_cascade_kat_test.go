package hashes

import (
	"fmt"
	"os"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/internal/forcetier"
)

// blake2s_cascade_kat_test.go — known-answer vectors of the BLAKE2s
// ChainHash cascade, produced by the pure-Go cascade under the noitbasm
// build tag and identical on every assembly tier. The vectors cover the
// per-pixel cascade of the 512 / 1024 / 2048-bit keys at the four kernel
// shapes — single lane, four lanes, the single-lane fused hook over the
// prepended lock components of the Interlocked Barrier fill — and the
// batch-16 fill hook at the 13-byte shape across a group index base that
// carries through byte 7 inside the batch. A seed with every hook and the
// same seed on the arms alone are both checked, so the table pins the
// wire as well as every hook against the noitbasm reference.

type blake2sCascadeKAT struct {
	groups, n       int
	single, batched string
	fused           string
}

var blake2sCascadeKATs = []blake2sCascadeKAT{
	{2, 13, "ed56c485f3b57840e5873dd6b2f7c819bc1214a4986f17fcb670822dc9e8064a", "d9d81ee9ada3b166", "da521b4485e6897c7278f456aa19168f519bd1d5fe8b004218383b351dd08b3b"},
	{2, 20, "82edb7801c481da5f4a1339af04900069405e8d8ee34a774be405f2524035675", "2abde27cab5490a1", "b20503eb6c6a0e127a2a6f9c6459e0beb13a2c64d6173cf24c8d666d2cd28648"},
	{2, 36, "d4216c369d9162cf44a8e28fd7646d63ec5e7d38ab17d20d6aac08902e4a1380", "5396c52a753ef425", "0ed2de98582897451917c13ed6e604a5d18eb6360efc89036102813db374cef5"},
	{2, 68, "7874362e55eb8dab8f7bb7464b356f1fca15046924c820fc6416415f81f74afe", "cc52ed5caaf751f3", "26df739ac3388f119be9026d083903393f84ea8b72ce5fd7ee16ccc75f5bb978"},
	{4, 13, "b0d54df0254b358e183cf3ffbfb8671c6f5ccbe0beb5522e638f19fa5309ea95", "3ecbc2956c853ffa", "69e482e1ee0573ab89daee330931061488d344b4060e08553a1d01fb2167b026"},
	{4, 20, "651a6e5221c84cada4740159fa7449d533070af8141e3ad3d19c1728348d30e6", "5d0a9e52254ccc35", "537beb4e30679dc3a5f0717a9f2eed45021e434f940b9cc69b4cd0e1c1285356"},
	{4, 36, "3d0106a3fbe26933e0f172d9fbe9227a88ab714c7a3adccb86dc5d90934e77cf", "3531d8d6b6d54383", "444748d5a2349ee11e5b0144b1a632df8b3b4a848635ad66f87490c6ff52d885"},
	{4, 68, "6902586b5b4bf8e7720de772bf43cea47ea5c174e9a4d0ba5f4e53df07eea1fe", "1b7682916c2ef55a", "915d25810a6d14bddcff6353ab447f0450b95a33dc67ce4b6ed694ad63acf42a"},
	{8, 13, "714021230fd97eaa596f97ffa063b449f6496306775566735ec5fdef41665872", "fd1e3eda035d3210", "3967158cde97c8c0f109f2cf895fac8e95cb383945ab49e9899e53150e88e704"},
	{8, 20, "4d096c93c2656acc2f3400fc30e08ccb559c82b8b75acb6d45a9741886cc51d1", "4b0d0bb713f0ecf8", "809fcfc64ae80fccb0de0d86713915bcb1c334ff75f9c25954a8f74cfeb780b5"},
	{8, 36, "c87057a1e7c027edf747956dcf2b2f14352b18ee4aea21a8dd32898958b67d8d", "d3e135d73fbaacb5", "168a8591f3ad6bc223ef080d2b4ec04002a18db9ac1f494fbb6c02964a39c70f"},
	{8, 68, "21b4d8bb4ac54e5c59f7466632647168f9c14a5cf41eaabfbb3d82f0b7ec519e", "e25ec046c8fcfbe3", "abc3976a05b4cc89bfb4c21369410ee0030297ec741ed067a0bf189e9de198b9"},
}

// blake2sFillKATs are the folds of the batch-16 fill output over the lock
// components at group index base 0x00FFFFFFFFFFFFF8, keyed by group
// count.
var blake2sFillKATs = map[int]string{
	2: "0323c0a9d04805f1",
	4: "23cd2520be9b38a1",
	8: "fbbcc9ca5cf03dce",
}

func blake2sKATKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0xA5 ^ i*11)
	}
	return key
}

func blake2sKATComponents(words int) []uint64 {
	comps := make([]uint64, words)
	for i := range comps {
		comps[i] = 0x9E3779B97F4A7C15*uint64(i+3) ^ 0x0F1E2D3C4B5A6978
	}
	return comps
}

func blake2sKATLock() []uint64 {
	lock := make([]uint64, 4)
	for i := range lock {
		lock[i] = 0xC2B2AE3D27D4EB4F*uint64(i+5) ^ 0x1032547698BADCFE
	}
	return lock
}

func TestBLAKE2sCascadeKAT(t *testing.T) {
	if forcetier.ChainHashSeq() {
		t.Skip("ITB_FORCE_CHAINHASH_SEQ disables the fused hooks")
	}
	printKAT := os.Getenv("ITB_KAT_PRINT") != ""
	key := blake2sKATKey()
	for _, kat := range blake2sCascadeKATs {
		t.Run(fmt.Sprintf("%d/%d", kat.groups, kat.n), func(t *testing.T) {
			buf := aescmacKATBuf(kat.n, kat.groups)
			var lanes [4][]byte
			for l := range lanes {
				lanes[l] = append([]byte(nil), buf...)
				lanes[l][0] ^= byte(l + 1)
			}
			comps := blake2sKATComponents(4 * kat.groups)
			lock := append(blake2sKATLock(), comps...)
			hooked, err := SeedFromComponents256(CipherBLAKE2s, key, comps...)
			if err != nil {
				t.Fatal(err)
			}
			plain := armsSeed256(t, CipherBLAKE2s, key, comps)
			if hooked.FusedChain == nil || hooked.BatchFusedChain == nil || hooked.InterlockFillX16() == nil {
				t.Fatal("blake2s seed is missing a hook")
			}
			var singleGot, batchedGot string
			for label, s := range map[string]*itb.Seed256{"hooked": hooked, "arms-only": plain} {
				h := s.ChainHash256(buf)
				singleGot = fmt.Sprintf("%016x%016x%016x%016x", h[0], h[1], h[2], h[3])
				if !printKAT && singleGot != kat.single {
					t.Errorf("%s ChainHash256 = %s, want %s", label, singleGot, kat.single)
				}
				if s.BatchFusedChain == nil && s.BatchHash == nil {
					// The arms-only twin carries no batched arm on a
					// build without the chain-absorb tiers.
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
				} else if want := blake2sFillKATs[kat.groups]; got != want {
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

// TestBLAKE2sHooksZeroAlloc asserts that the hooks installed on blake2s
// seeds run without a heap allocation per call at every kernel shape.
func TestBLAKE2sHooksZeroAlloc(t *testing.T) {
	if forcetier.ChainHashSeq() {
		t.Skip("ITB_FORCE_CHAINHASH_SEQ disables the fused hooks")
	}
	check := func(what string, f func()) {
		t.Helper()
		if n := testing.AllocsPerRun(50, f); n != 0 {
			t.Errorf("%s allocates %.0f objects per call", what, n)
		}
	}
	s, _, err := NewSeed256(CipherBLAKE2s, 1024)
	if err != nil {
		t.Fatal(err)
	}
	lock := append(blake2sKATLock(), s.Components...)
	for _, n := range []int{13, 20, 36, 68} {
		buf := aescmacKATBuf(n, 4)
		var lanes [4][]byte
		for l := range lanes {
			lanes[l] = append([]byte(nil), buf...)
		}
		check(fmt.Sprintf("blake2s FusedChain n=%d", n), func() { s.FusedChain(lock, buf) })
		check(fmt.Sprintf("blake2s BatchFusedChain n=%d", n), func() { s.BatchFusedChain(s.Components, &lanes) })
	}
	fill := s.InterlockFillX16()
	var out [8][4]uint64
	check("blake2s InterlockFillX16", func() { fill(lock, 0x00FFFFFFFFFFFFF8, &out) })
}

// TestBLAKE2sWideHooksZeroAlloc asserts that the eight-lane per-pixel
// hook installed on blake2s seeds runs without a heap allocation per
// call; the hook is present only where the eight-lane YMM arm is
// selected, and no batch-32 fill hook is registered at width 256.
func TestBLAKE2sWideHooksZeroAlloc(t *testing.T) {
	if forcetier.ChainHashSeq() {
		t.Skip("ITB_FORCE_CHAINHASH_SEQ disables the fused hooks")
	}
	check := func(what string, f func()) {
		t.Helper()
		if n := testing.AllocsPerRun(50, f); n != 0 {
			t.Errorf("%s allocates %.0f objects per call", what, n)
		}
	}
	s, _, err := NewSeed256(CipherBLAKE2s, 1024)
	if err != nil {
		t.Fatal(err)
	}
	lock := append(blake2sKATLock(), s.Components...)
	for _, n := range []int{20, 36, 68} {
		buf := aescmacKATBuf(n, 4)
		var lanes [8][]byte
		for l := range lanes {
			lanes[l] = append([]byte(nil), buf...)
		}
		if x8 := s.BatchFusedChain8(); x8 != nil {
			check(fmt.Sprintf("blake2s BatchFusedChain8 n=%d", n), func() { x8(lock, &lanes) })
		}
	}
	if s.InterlockFillX32() != nil {
		t.Error("blake2s carries a batch-32 fill hook; none is registered")
	}
}
