package hashes

import (
	"fmt"
	"os"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/internal/forcetier"
)

// Known-answer vectors of the Areion-SoEM-256 / -512 ChainHash cascades,
// produced by the pure-Go cascade under the noitbasm build tag and
// identical on every assembly tier. The vectors cover the per-pixel
// cascade of the 512 / 1024 / 2048-bit keys at the four kernel shapes —
// single lane, four lanes, the single-lane fused hook over the prepended
// lock components of the Interlocked Barrier fill — and the batch-16 fill
// hook at the 13-byte shape across a group index base that carries through
// byte 7 inside the batch. A seed with every hook and the same seed on the
// arms alone are both checked, so the table pins the wire as well as every
// hook against the noitbasm reference.

type areionCascadeKAT struct {
	width, groups, n int
	single, batched  string
	fused            string
}

var areionCascadeKATs = []areionCascadeKAT{
	{256, 2, 13, "2b13c970a1c903915b0af01b98cf756d68e4378a079e2ebc31fe94853a79c579", "f417125ba6ce70d5", "b5d0ec9dd0ebcffaa07f2147fca3fd0f06d4ba5064a3a57c58b19e195705b5fe"},
	{256, 2, 20, "4f346771a2d7db7f50b1ec61c9174afaab36f286fab9753bd688e6253b5da40e", "00772f039fcf9771", "4ff73f25be704a534f9b9b3a6e0192b3b1ab7c2484a7233f61c4439e76d36ef1"},
	{256, 2, 36, "b8c45498f72752ce6d0251c03e0b3474e492a85717df73696010b7e41724a91c", "6ab442c21cd9cf28", "4c67838deed163ed368dbf3b0ba680c341117779613edd9216c218e80e3293cb"},
	{256, 2, 68, "50e3cd88fe7bf669f72eb5ff344449c2d6226f56f3906f503dfff31bfdc95e62", "5df100a1417ea742", "668aea14289f9d50f49d787185295301e4f23ba8d752a76e8ffc5ed32a4fc80c"},
	{256, 4, 13, "4d7b6837f55ced45e1f25439df2f28b20e0ed1c22a83e8b35a5ffd0ddbdbf3db", "20a7b66c8ad5c0cf", "08584ca3e5589c3cf71dee6ecfef75df9f97b4d9f53f22087bb87fa401681cbb"},
	{256, 4, 20, "a4888ae00bf327fdc45c5f573a1b87a41c12fa75f583859b14417fb4390cf1ab", "4f1b0bbfab485368", "30bdc4ca252009fe879b3c8548eaf55f30e3eea5b30f05d287029464f71ee61d"},
	{256, 4, 36, "56cd922f8a92a3a73107ad4b1e7e25b97201133c658bdb06573c345e4084f2bd", "9a3ed4487cfa0ab3", "28629dc2ad7fda994190044287a2c4aaadb3788de4f998f53ddc575f67f5dfea"},
	{256, 4, 68, "081cb180cc4d76f54912846bd49b2ca9e3515217989e44657365f284f0ba6fb6", "466ee665c0fa46bd", "b891a70cc3afa02bbb6b248d3ee056931e61f32272984f6128b1c9ffd0d5d2c2"},
	{256, 8, 13, "8c781b72ef30a2d5a7b271168c0eda6635f5c8de361e2ff36230d093a19fa0c2", "20afcec51b32e466", "51a3c52e10bf1393299480bdbc7d8bdbc892e268306f85a9550c819d7bc20e61"},
	{256, 8, 20, "07f633cc35c4b0259fce37e0a622a58757fd474fbac4147b119b3653be3b5a0c", "b9302ea9736271dd", "38a1fbcd8925fd86847fe2c1c4c0d93d8c6b8a2f6b122404a233b6025dbbb94e"},
	{256, 8, 36, "30566cdeea0647bd4c4bd23e1bb3bc05543c420f4c455094111cd965f281cf08", "f75682b6c07176c9", "5eec67778947f74144580501bd8222908a9ea1442a92146ffe8be47ad0300fe4"},
	{256, 8, 68, "e25d750c36aa2c893e6c6ef0b1807517bb481a49b9d28d91e2447fa11c0fe8a1", "2e6d7a38d6c0947f", "ae70da96a88f40c2009accb60fc1180ae893808f0902ad5a204108891a7823d0"},
	{512, 1, 13, "4ed5fb4f2dc4f143", "6295b48c779f1ee9", "ba819ecd837864aa"},
	{512, 1, 20, "e9d06bbe343e6f4b", "8c4d4a7d5ccac072", "bda55951870d604e"},
	{512, 1, 36, "6c670276dffaee4e", "349e39acb2d3c78c", "fd6e50bb44501ab4"},
	{512, 1, 68, "bc324b4a25d22628", "5a96b94eb6039d6a", "74bbbcb5b668fdee"},
	{512, 2, 13, "da730a4dee4e2a90", "9a72dc0db49a62ca", "269de0c8a828f7a3"},
	{512, 2, 20, "21bde0d438b58d22", "5daf95d30d5ae4cd", "7c8a6f4ffc97fb25"},
	{512, 2, 36, "6e4fc6368f893dfe", "d729e6a7522735e5", "8c7602081fc9484a"},
	{512, 2, 68, "8b365bc2f7b5174e", "0473fbd392ce891e", "d569412658ef6292"},
	{512, 4, 13, "b0d6a9652b47a4e1", "ff3346aa405b7585", "2311f52a26f7c1d2"},
	{512, 4, 20, "0b61f47065643e4b", "2fca1db42b1bc3ec", "3f2761f0a8062338"},
	{512, 4, 36, "c475e186d423f8b2", "349ecc276c9599aa", "b88148b323cba7f1"},
	{512, 4, 68, "236a090f06c776c3", "2ba2ab2b00831a18", "641c8f5742e39682"},
}

// areionFillKATs are the folds of the batch-16 fill output over the lock
// components at group index base 0x00FFFFFFFFFFFFF8, keyed by width and
// group count.
var areionFillKATs = map[[2]int]string{
	{256, 2}: "3beff9c23dd4ab2b",
	{256, 4}: "760e73aebde31e7e",
	{256, 8}: "e77c0aa5c428dbcc",
	{512, 1}: "bfde2418239391b1",
	{512, 2}: "ad9825acb54d59aa",
	{512, 4}: "d3c0de02b9eea498",
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

// TestAreionWideHooksZeroAlloc asserts that the eight-lane per-pixel
// hooks and the width-512 batch-32 fill hook installed on areion256 /
// areion512 seeds run without a heap allocation per call; the eight-lane
// hooks are present only where the ZMM eight-lane arm is selected.
func TestAreionWideHooksZeroAlloc(t *testing.T) {
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
	for _, n := range []int{20, 36, 68} {
		buf := aescmacKATBuf(n, 4)
		var lanes [8][]byte
		for l := range lanes {
			lanes[l] = append([]byte(nil), buf...)
		}
		if x8 := s256.BatchFusedChain8(); x8 != nil {
			check(fmt.Sprintf("areion256 BatchFusedChain8 n=%d", n), func() { x8(lock256, &lanes) })
		}
		if x8 := s512.BatchFusedChain8(); x8 != nil {
			check(fmt.Sprintf("areion512 BatchFusedChain8 n=%d", n), func() { x8(lock512, &lanes) })
		}
	}
	if s256.InterlockFillX32() != nil {
		t.Error("areion256 carries a batch-32 fill hook; none is registered")
	}
	fill := s512.InterlockFillX32()
	if fill == nil {
		t.Fatal("areion512 carries no batch-32 fill hook")
	}
	var out [8][8]uint64
	check("areion512 InterlockFillX32", func() { fill(lock512, 0x00FFFFFFFFFFFFF8, &out) })
}
