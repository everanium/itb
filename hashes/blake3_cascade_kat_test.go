package hashes

import (
	"fmt"
	"os"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes/internal/blake3asm"
	"github.com/everanium/itb/internal/forcetier"
)

// blake3_cascade_kat_test.go — known-answer vectors of the BLAKE3
// ChainHash cascade, produced by the pure-Go cascade under the noitbasm
// build tag and identical on every assembly tier. The vectors cover the
// per-pixel cascade of the 512 / 1024 / 2048-bit keys at the four kernel
// shapes — single lane, four lanes, the single-lane fused hook over the
// prepended lock components of the Interlocked Barrier fill — and the
// batch-16 fill hook at the 13-byte shape across a group index base that
// carries through byte 7 inside the batch. A seed with every hook and the
// same seed on the arms alone are both checked, so the table pins the
// wire as well as every hook against the noitbasm reference.

type blake3CascadeKAT struct {
	groups, n       int
	single, batched string
	fused           string
}

var blake3CascadeKATs = []blake3CascadeKAT{
	{2, 13, "dc60d5b047ec36283a8647b2d30d51026a5ce31dbc93a29d3df9abbb5d3d7fe0", "2d823cf8a1e22648", "04d64a823b9c9241a85a3bd1a4cf6d2bf2d0eda94259e0d720a90c505d571688"},
	{2, 20, "b5f5ce410da39651d8ad839fa1b208d61fd19b891651e4ccdcddad1425f0932d", "6a24332eefbc6e3c", "3f39ad14f234193451a215ca1ddb05e66fe4ed6da11d932ab2a86d74114b3c26"},
	{2, 36, "672ba335a4c0df877106b290fd4d29638a53ddf771d196ac8da4eb63ba5c4b38", "ee6c191a1199d7cc", "3824732501795938ded75397e0987de8cdca71535b0c20ba39d9c1bd34fd9cea"},
	{2, 68, "cd09e9333d964fa52bc70dc41425762bafa29a9c68df437f1529e7114706a98b", "9387a7fb4d77a19e", "bbba52fe9bb733fbd48ef59dc98229a642e7a7560c9dcbd6f6d2c64e76e4d6cc"},
	{4, 13, "e91a49b13c0d00bf4baf80fad934395011efe1cc18866e88652107c6e1b524e7", "45c2067cc44c01ae", "27b319509be8f57cd511d4a18e0fb4ba908b3831b2cd1f7d8cef14bbf6232471"},
	{4, 20, "08e30a9e2eb7d1e5834856226091376dfde8fa1a630147195dba88be73d9170c", "fbaca6e2011d77d5", "20bac44b9e93bfa0acf446f81299011db7a80a59c22eca0ea226f2118bd2ebef"},
	{4, 36, "543ff998420e49ae59ff33b0953e1e9321df6dcdf8727c57783cf775ceb34287", "4b6c682daa117b59", "bcc780415774ee767794380d278f607d61123f3cfb7f826f34fe81046960906f"},
	{4, 68, "3523356c18d02d93d23a91c5a12848a87ba602a2785df42a3237535603e91cc8", "5907983ad7005870", "ab759fa50140e5d74320ec62e22286870290a487e6614f452c15c026ac86b209"},
	{8, 13, "01274d9375e42665a7c5804554ec7dedfff6a0a6b6c7879ca686580cd78901fb", "129e777822c7ba4f", "f2f9479cb92edd9a0c5ceabd40374cb34c9156ca70c7597d64a8376c81280836"},
	{8, 20, "1f94b5da97eb1615a8a9af187bce6adf604da17268c73215a5020d0850b05050", "816fd9059738507d", "fd69322ad6ca43727834b6f012a00215e251c43b0142d6bdb4f8eaeb4a934de8"},
	{8, 36, "85e6fae54b07a2aa740838745ecd2ce7cd31cf82331390189d21a92415af02e9", "6577d8975822d775", "283d5450aaf504034c66ebd40458efeb1cdee62330ee176e59a2376cb5f28af3"},
	{8, 68, "03444b98a63206b2f63bfdcc3fe32c40f707d0debde091916196afd1a238bd1f", "7ef748eaa6ee8bfb", "365ca755d73fa6063adc0920671d549f87d378cb94dc926ff4350e0f4ee7b6bf"},
}

// blake3FillKATs are the folds of the batch-16 fill output over the lock
// components at group index base 0x00FFFFFFFFFFFFF8, keyed by group
// count.
var blake3FillKATs = map[int]string{
	2: "018368a1f8d213c0",
	4: "05f4ebdfd9231237",
	8: "1d698bdccb7ce9f8",
}

func blake3KATKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0x3C ^ i*17)
	}
	return key
}

func blake3KATComponents(words int) []uint64 {
	comps := make([]uint64, words)
	for i := range comps {
		comps[i] = 0x9E3779B97F4A7C15*uint64(i+11) ^ 0x2E3D4C5B6A798897
	}
	return comps
}

func blake3KATLock() []uint64 {
	lock := make([]uint64, 4)
	for i := range lock {
		lock[i] = 0xC2B2AE3D27D4EB4F*uint64(i+9) ^ 0x5A4B3C2D1E0F9E8D
	}
	return lock
}

func TestBLAKE3CascadeKAT(t *testing.T) {
	if forcetier.ChainHashSeq() {
		t.Skip("ITB_FORCE_CHAINHASH_SEQ disables the fused hooks")
	}
	printKAT := os.Getenv("ITB_KAT_PRINT") != ""
	key := blake3KATKey()
	for _, kat := range blake3CascadeKATs {
		t.Run(fmt.Sprintf("%d/%d", kat.groups, kat.n), func(t *testing.T) {
			buf := aescmacKATBuf(kat.n, kat.groups)
			var lanes [4][]byte
			for l := range lanes {
				lanes[l] = append([]byte(nil), buf...)
				lanes[l][0] ^= byte(l + 1)
			}
			comps := blake3KATComponents(4 * kat.groups)
			lock := append(blake3KATLock(), comps...)
			hooked, err := SeedFromComponents256(CipherBLAKE3, key, comps...)
			if err != nil {
				t.Fatal(err)
			}
			plain := armsSeed256(t, CipherBLAKE3, key, comps)
			if hooked.FusedChain == nil || hooked.BatchFusedChain == nil || hooked.InterlockFillX16() == nil {
				t.Fatal("blake3 seed is missing a hook")
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
				} else if want := blake3FillKATs[kat.groups]; got != want {
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

// TestBLAKE3HooksZeroAlloc asserts that the hooks installed on blake3
// seeds run without a heap allocation per call at every kernel shape.
func TestBLAKE3HooksZeroAlloc(t *testing.T) {
	if forcetier.ChainHashSeq() {
		t.Skip("ITB_FORCE_CHAINHASH_SEQ disables the fused hooks")
	}
	check := func(what string, f func()) {
		t.Helper()
		if n := testing.AllocsPerRun(50, f); n != 0 {
			t.Errorf("%s allocates %.0f objects per call", what, n)
		}
	}
	if !blake3asm.FusedAvailable() {
		t.Skip("the pure-Go cascade allocates its keyed Hasher through the upstream package")
	}
	s, _, err := NewSeed256(CipherBLAKE3, 1024)
	if err != nil {
		t.Fatal(err)
	}
	lock := append(blake3KATLock(), s.Components...)
	for _, n := range []int{13, 20, 36, 68} {
		buf := aescmacKATBuf(n, 4)
		var lanes [4][]byte
		for l := range lanes {
			lanes[l] = append([]byte(nil), buf...)
		}
		check(fmt.Sprintf("blake3 FusedChain n=%d", n), func() { s.FusedChain(lock, buf) })
		check(fmt.Sprintf("blake3 BatchFusedChain n=%d", n), func() { s.BatchFusedChain(s.Components, &lanes) })
	}
	if !blake3asm.HasAVX512X16 && !blake3asm.HasAVX2X16 && !blake3asm.HasNEONX16 {
		return
	}
	fill := s.InterlockFillX16()
	var out [8][4]uint64
	check("blake3 InterlockFillX16", func() { fill(lock, 0x00FFFFFFFFFFFFF8, &out) })
}

// TestBLAKE3WideHooksZeroAlloc asserts that the eight-lane per-pixel
// hook installed on blake3 seeds runs without a heap allocation per
// call; the hook is present only where the eight-lane YMM arm is
// selected, and no batch-32 fill hook is registered at width 256.
func TestBLAKE3WideHooksZeroAlloc(t *testing.T) {
	if forcetier.ChainHashSeq() {
		t.Skip("ITB_FORCE_CHAINHASH_SEQ disables the fused hooks")
	}
	check := func(what string, f func()) {
		t.Helper()
		if n := testing.AllocsPerRun(50, f); n != 0 {
			t.Errorf("%s allocates %.0f objects per call", what, n)
		}
	}
	if !blake3asm.FusedAvailable() {
		t.Skip("the pure-Go cascade allocates its keyed Hasher through the upstream package")
	}
	s, _, err := NewSeed256(CipherBLAKE3, 1024)
	if err != nil {
		t.Fatal(err)
	}
	lock := append(blake3KATLock(), s.Components...)
	for _, n := range []int{20, 36, 68} {
		buf := aescmacKATBuf(n, 4)
		var lanes [8][]byte
		for l := range lanes {
			lanes[l] = append([]byte(nil), buf...)
		}
		if x8 := s.BatchFusedChain8(); x8 != nil {
			check(fmt.Sprintf("blake3 BatchFusedChain8 n=%d", n), func() { x8(lock, &lanes) })
		}
	}
	if s.InterlockFillX32() != nil {
		t.Error("blake3 carries a batch-32 fill hook; none is registered")
	}
}
