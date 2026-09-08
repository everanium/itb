package hashes

import (
	"fmt"
	"os"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/internal/forcetier"
)

// areion_cascade_kat_test.go — known-answer vectors of the Areion-SoEM-256
// / -512 ChainHash cascades, produced by the pure-Go cascade under the
// noitbasm build tag and identical on every assembly tier. The vectors
// cover the per-pixel cascade of the 512 / 1024 / 2048-bit keys at the
// four kernel shapes — single lane, four lanes, the single-lane fused
// hook over the prepended lock components of the Interlocked Barrier
// fill — and the batch-16 fill hook at the 13-byte shape across a group
// index base that carries through byte 7 inside the batch. A seed with
// every hook and the same seed on the arms alone are both checked, so
// the table pins the wire as well as every hook against the noitbasm
// reference.

type areionCascadeKAT struct {
	width, groups, n int
	single, batched  string
	fused            string
}

var areionCascadeKATs = []areionCascadeKAT{
	{256, 2, 13, "d8287f85bead37d70123f086185ef70686dea5c299883ed71fc57650c3d93713", "c66190d1ac621176", "bb05e22475617945a5999b7cd0790076b1b8985ba3c80dad72330ebd31e789bb"},
	{256, 2, 20, "6c7e4fdd0a88d95a5807316524fd013b64719f9ad7e962a9d3def66995ba84f1", "68737888f130273e", "8e653765067f9d26d08ad8334430458ec7d94f3e5f5d77a7753bf2d15a191386"},
	{256, 2, 36, "8920b649e125afa261663974e77ba5bb0b40677611798f43f8d90278e765af9e", "5e7e9b69b8e1b935", "d4a276e028d6bc1e56c720615c78f4017401abdddd1d7f0f5aef5bb189d81595"},
	{256, 2, 68, "030f70098de7dcba797831e8920be7cf5c1acf262d1a0fb3a129f4e6fa10cc0c", "6f1b3a0fe09d340e", "e71c78ccb090be0d9798924f51e52195f91db50f9e71179cdd191a13d1fa67af"},
	{256, 4, 13, "7952132c3e641b396e92ebc4fd74bb32b8691d27c399538a06bcb03251b12a42", "0581dc59b3cb3bfc", "ecfdb1ee887ccbe72a03a6fa84d9f90b86888ac694a00db3bbcdc5a4a038a464"},
	{256, 4, 20, "8a48a1e2ba24dd317f5129d88b6189c6a81897ddf46a3eacb574fdeb821d2c8d", "47f7abee473aad9d", "47c25d9a93ab44ae171560afb7f40577951382ff67f5152d2fe46d01dfd6ff77"},
	{256, 4, 36, "344bf82ed30a447aeeed4b7e2349ecdfd8050101fc9cf73f4e0c36f553df6d8f", "36e35d6b9a1953fb", "8ee6df218b6a7f13dafd35f3b661fb5c408e3c601e2d4fa2a2c571de7d634f39"},
	{256, 4, 68, "f4f01f2ca4f37f392e70499af94d0fac7beb0234168cac2c0946b3f0bacc1da9", "4d5fabd7558e547e", "ea91051c2e98e3bd2b05472742f55c833da109da3e6b326108d61afb2a146df9"},
	{256, 8, 13, "9b36a146bda865eaf08582dc334a2553fbc39c7c7162d012a02525c4cf8bea22", "16fec9de78bede5c", "7918a020b1de36c4b2b402bddb2f58e3fdf62ddb19261725a85c8b6e6cd2615f"},
	{256, 8, 20, "d9b1dafb5297e06a2a14e7e053b943bb5c5d099f84f5ffdc30dc8f581a899e74", "73daeb61a998dad1", "79f19f8c684bc703e0abcae1dc8959892b5e1a07e0dc16efbdd5dcb7c2432bf0"},
	{256, 8, 36, "ac8ac2fc04c30fa2b0b20e4d4acdd4aa835e3895f58db502f293e5c5cd44cfcd", "556deb6fa3ab7c19", "7fcf2359c9097771dc6231cc42a4154463694471b342d4873500ea451c37d16c"},
	{256, 8, 68, "44e97f1e2de9547a324b8ffa844de11c66f845f391749302a30a2305d55b4b10", "ad60d15c8b7cbf3d", "161eaaf4d1928724044d30cdf24ecd9cd632fbde22ec3e02d16e456ebd74e98a"},
	{512, 1, 13, "ac4b8ea641fcb061", "93fb628ca8edf801", "bab37db50427018a"},
	{512, 1, 20, "030093542938225d", "af8657e3e05fca3c", "c990f7c190de9da5"},
	{512, 1, 36, "422205b7dfab9923", "983d0265063f2585", "7ed5db2315a4b487"},
	{512, 1, 68, "51eeb720d74c6f58", "20d412b498486530", "f55acd24808e2e58"},
	{512, 2, 13, "7c91bf2fc163d43f", "da6e373c4962ee42", "f06de0f938c31624"},
	{512, 2, 20, "0d58aa5f8c66d38b", "c9655231506e3c83", "f7b9bcfd4ca6bc84"},
	{512, 2, 36, "9aa9b780f4bc48b6", "3fc2e5b2956965e7", "99964ee25346adcc"},
	{512, 2, 68, "041a71b78dc7d16a", "b109ceb2d670bd8a", "1b53d585cdeb0abb"},
	{512, 4, 13, "385b15690c4373fa", "e837c564a6ffac31", "058595993009c99a"},
	{512, 4, 20, "0a95a88f5ba34554", "6c1b8f672f67f6c8", "dbe192c09b54669d"},
	{512, 4, 36, "bf64682027e04427", "3a52857dfdcd9484", "bf85ca4a075af6a2"},
	{512, 4, 68, "5a5eb3567e07ddee", "cf59a8ad8acb8037", "57f10f5f983d3594"},
}

// areionFillKATs are the folds of the batch-16 fill output over the lock
// components at group index base 0x00FFFFFFFFFFFFF8, keyed by width and
// group count.
var areionFillKATs = map[[2]int]string{
	{256, 2}: "b2c9347269b7c154",
	{256, 4}: "c980d26ef25ce22e",
	{256, 8}: "2398e05614dd86a8",
	{512, 1}: "fbad8bef07c6d9ff",
	{512, 2}: "67b978892dfcbb66",
	{512, 4}: "c1beb8bd2df2c294",
}

func areionKATKey(width int) []byte {
	key := make([]byte, width/8)
	for i := range key {
		key[i] = byte(0x5A ^ i*13 ^ width)
	}
	return key
}

func areionKATComponents(words int) []uint64 {
	comps := make([]uint64, words)
	for i := range comps {
		comps[i] = 0x9E3779B97F4A7C15*uint64(i+1) ^ 0x0123456789ABCDEF
	}
	return comps
}

func areionKATLock(width int) []uint64 {
	lock := make([]uint64, width/64)
	for i := range lock {
		lock[i] = 0xC2B2AE3D27D4EB4F*uint64(i+7) ^ 0xFEDCBA9876543210
	}
	return lock
}

// seqCascade256 / seqCascade512 run the sequential cascade of the arms
// over a component slice.
func seqCascade256(h itb.HashFunc256, comps []uint64, buf []byte) [4]uint64 {
	var seed [4]uint64
	copy(seed[:], comps[0:4])
	out := h(buf, seed)
	for i := 4; i < len(comps); i += 4 {
		for j := 0; j < 4; j++ {
			seed[j] = comps[i+j] ^ out[j]
		}
		out = h(buf, seed)
	}
	return out
}

func seqCascade512(h itb.HashFunc512, comps []uint64, buf []byte) [8]uint64 {
	var seed [8]uint64
	copy(seed[:], comps[0:8])
	out := h(buf, seed)
	for i := 8; i < len(comps); i += 8 {
		for j := 0; j < 8; j++ {
			seed[j] = comps[i+j] ^ out[j]
		}
		out = h(buf, seed)
	}
	return out
}

func fillBlockKAT(groupIdx uint64) []byte {
	blk := make([]byte, 13)
	blk[0] = 0x03
	for j := 0; j < 8; j++ {
		blk[1+j] = byte(groupIdx >> (8 * j))
	}
	return blk
}

func foldWords(acc uint64, w []uint64) uint64 {
	for i, x := range w {
		acc = acc*0x100000001B3 ^ x ^ uint64(i)
	}
	return acc
}

func TestAreionCascadeKAT(t *testing.T) {
	if forcetier.ChainHashSeq() {
		t.Skip("ITB_FORCE_CHAINHASH_SEQ disables the fused hooks")
	}
	printKAT := os.Getenv("ITB_KAT_PRINT") != ""
	for _, kat := range areionCascadeKATs {
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
				key := areionKATKey(256)
				comps := areionKATComponents(4 * kat.groups)
				lock := append(areionKATLock(256), comps...)
				hooked, err := SeedFromComponents256(CipherAreion256, key, comps...)
				if err != nil {
					t.Fatal(err)
				}
				plain := armsSeed256(t, CipherAreion256, key, comps)
				if hooked.FusedChain == nil || hooked.BatchFusedChain == nil || hooked.InterlockFillX16() == nil {
					t.Fatal("areion256 seed is missing a hook")
				}
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
					} else if want := areionFillKATs[[2]int{256, kat.groups}]; got != want {
						t.Errorf("batch-16 fill fold = %s, want %s", got, want)
					}
				}
			case 512:
				key := areionKATKey(512)
				comps := areionKATComponents(8 * kat.groups)
				lock := append(areionKATLock(512), comps...)
				hooked, err := SeedFromComponents512(CipherAreion512, key, comps...)
				if err != nil {
					t.Fatal(err)
				}
				plain := armsSeed512(t, CipherAreion512, key, comps)
				if hooked.FusedChain == nil || hooked.BatchFusedChain == nil || hooked.InterlockFillX16() == nil {
					t.Fatal("areion512 seed is missing a hook")
				}
				for label, s := range map[string]*itb.Seed512{"hooked": hooked, "arms-only": plain} {
					h := s.ChainHash512(buf)
					singleGot = fmt.Sprintf("%016x", foldWords(0, h[:]))
					if !printKAT && singleGot != kat.single {
						t.Errorf("%s ChainHash512 fold = %s, want %s", label, singleGot, kat.single)
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
					} else if want := areionFillKATs[[2]int{512, kat.groups}]; got != want {
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

// TestAreionHooksZeroAlloc asserts that the hooks installed on areion256
// / areion512 seeds run without a heap allocation per call at every
// kernel shape.
func TestAreionHooksZeroAlloc(t *testing.T) {
	if forcetier.ChainHashSeq() {
		t.Skip("ITB_FORCE_CHAINHASH_SEQ disables the fused hooks")
	}
	check := func(what string, f func()) {
		t.Helper()
		if n := testing.AllocsPerRun(50, f); n != 0 {
			t.Errorf("%s allocates %.0f objects per call", what, n)
		}
	}
	s256, _, err := NewSeed256(CipherAreion256, 1024)
	if err != nil {
		t.Fatal(err)
	}
	s512, _, err := NewSeed512(CipherAreion512, 1024)
	if err != nil {
		t.Fatal(err)
	}
	lock256 := append(areionKATLock(256), s256.Components...)
	lock512 := append(areionKATLock(512), s512.Components...)
	for _, n := range []int{13, 20, 36, 68} {
		buf := aescmacKATBuf(n, 4)
		var lanes [4][]byte
		for l := range lanes {
			lanes[l] = append([]byte(nil), buf...)
		}
		check(fmt.Sprintf("areion256 FusedChain n=%d", n), func() { s256.FusedChain(lock256, buf) })
		check(fmt.Sprintf("areion256 BatchFusedChain n=%d", n), func() { s256.BatchFusedChain(s256.Components, &lanes) })
		check(fmt.Sprintf("areion512 FusedChain n=%d", n), func() { s512.FusedChain(lock512, buf) })
		check(fmt.Sprintf("areion512 BatchFusedChain n=%d", n), func() { s512.BatchFusedChain(s512.Components, &lanes) })
	}
	fill256, fill512 := s256.InterlockFillX16(), s512.InterlockFillX16()
	var out256 [8][4]uint64
	var out512 [4][8]uint64
	check("areion256 InterlockFillX16", func() { fill256(lock256, 0x00FFFFFFFFFFFFF8, &out256) })
	check("areion512 InterlockFillX16", func() { fill512(lock512, 0x00FFFFFFFFFFFFF8, &out512) })
}
