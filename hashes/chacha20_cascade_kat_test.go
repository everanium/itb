package hashes

import (
	"fmt"
	"os"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/internal/forcetier"
)

// chacha20_cascade_kat_test.go — known-answer vectors of the ChaCha20
// ChainHash cascade, produced by the pure-Go cascade under the noitbasm
// build tag and identical on every assembly tier. The vectors cover the
// per-pixel cascade of the 512 / 1024 / 2048-bit keys at the four kernel
// shapes — single lane, four lanes, the single-lane fused hook over the
// prepended lock components of the Interlocked Barrier fill — and the
// batch-16 fill hook at the 13-byte shape across a group index base that
// carries through byte 7 inside the batch. A seed with every hook and the
// same seed on the arms alone are both checked, so the table pins the
// wire as well as every hook against the noitbasm reference.

type chacha20CascadeKAT struct {
	groups, n       int
	single, batched string
	fused           string
}

var chacha20CascadeKATs = []chacha20CascadeKAT{
	{2, 13, "1f4f8647f7cce5cfd94b352d2ca1f62fa2278cea8f7fd9b1d0ebfae3cca89969", "e7b87cd380febaee", "542cc4ea611fdf2abbb71066776f954bbd6f8dec353361b2fe04c5e111664af8"},
	{2, 20, "7ed5932a30f02a7ffa775cc78f469cf2207845fbe28df90d4638d8859bb49d78", "c849063bfc56b005", "bcb03048c40ada417b3d773a4052938836e868d9aa35fcbb5bf17244bab12dcf"},
	{2, 36, "02fee38bc034c8765f5a10bb418dbb799a1513186a05090c51ed9ad3c1fbb6d6", "2000f843659b2e04", "2ac9e74e816c684754f033a38e6b86ea9398623868812d02f5e313b3632eea18"},
	{2, 68, "069dd53337ccd630488d6bc7be5219545b9ae27c1d3b5a303dc9e508a7067ac1", "102dea79f4348d59", "d5ec45c09fe092dad66777425ac56b97f4449a0e2844d7ce88e37da2db6233b7"},
	{4, 13, "94c6c7a811f047acaaeec6aa9f3ca4c43f7e134bea2535b2413980b8d1387f43", "29232eaa14e8b558", "a5143456df1b08d2ede23335c5b91f0988145efc3fad0f1e715a75e49dfab474"},
	{4, 20, "2d289da1464e85c8e4046eabb743cd3bb6b7150a9c65062604ed6db86f3ffb88", "20b914b3865788ad", "0301b41b12839aabaeb8534f3ca9819db85b5d6ca441027c39ff4fd2ba5b982d"},
	{4, 36, "8353ae1ebc4df139f12f35426d46881d1fa67ddb2aa858aba5b6244f8ce6da4a", "1b9c98ae74ea7002", "bcf978be3ff23e60d9d0a161c878de9dc14113db1d1ea8f8e2e2ffabbc9899fd"},
	{4, 68, "1c9e45af52d1b8821a1d64884975c2ac96ac62d6ea4594bd1410d297b2f53c11", "616d6c9e0052eed8", "61e887a5fb9b35e282d93b97abc96cafbe291feddafcac20d50ce4e713bf87e4"},
	{8, 13, "fe9b07175a7f16247942ed1df4bafdef29b367f674f67f9014488e44d8c02a37", "a4c0fc66a4b34333", "daf3aad800f8ab53fa7cb8c9eca53c2a89e612c73761cc5b8cda507ca654b1a7"},
	{8, 20, "fec2d36f63164e19989e90dd908b54859ed3cd66017a0bb47b5627606f36cb0b", "d99e6a498b0b0c7f", "d84a19443c6f6001e1d9575680f1398cbe68d303e04fe01efee81f41f5defe20"},
	{8, 36, "f5c2f9dd53a919995ca506d9e8914e2dfd90b8d46547fea6e006d3e5ced725f2", "a2a85b909af57353", "d74698c7926ee8f98f4bb00439aa25b0d7255c52a5f0d4c743943eee12026cdc"},
	{8, 68, "e1d5b5b9b24cb7c97a1ffb152d0e6a693164e584eee153082cedf3ca4b3ce134", "dea946e856dc367d", "98670a090e9bc196a430973e9095a1defb0623580192dccd1df4e4cdae439483"},
}

// chacha20FillKATs are the folds of the batch-16 fill output over the lock
// components at group index base 0x00FFFFFFFFFFFFF8, keyed by group
// count.
var chacha20FillKATs = map[int]string{
	2: "ca34bc48c7b040f7",
	4: "ffd433d0434c5aa9",
	8: "2e2b890abf2c6f90",
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
