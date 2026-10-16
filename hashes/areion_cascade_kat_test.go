package hashes

import (
	"fmt"
	"os"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/internal/forcetier"
)

// Known-answer vectors of the Areion-SoEM-256 / 512 ChainHash cascades,
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
	{256, 2, 13, "cfbac793d58a754183eb8a690ddf4e74ef261ed8bae33d12516ae0a1d58d0d2c", "230fc6a79f14a240", "eb4a0beb8c12c20550c9473d57243de4c868b371752660b00afccfe5b7367aa4"},
	{256, 2, 20, "24ada5f3fc58b9ab8c39319b27a762074393da6766a5defca4dc11b0457c904a", "b6dc6f6c44dac6d0", "8369b1e4f374001f8e5fc09c8c186489fb36ff54e46f09c38a69c71066bdc54b"},
	{256, 2, 36, "d00d68ac30d6d5b33e1aab1e9c028bb278af815e5ce5d5157704a8bee18f0277", "fa4a3e6bde41fd02", "b6e95d3f4421afd731cb3d935f524dc70fb09f8677e662d4b88ab79d9f9f03a8"},
	{256, 2, 68, "608cef5f22a55ba186d50885ca7e3f038d0acee2fcc54dc2ac6f48238e5a1632", "57ebd6e9ccee2b73", "b0fc418cc5b90dac3d9266862661fea5290b8e7a8c2560f0e964074362f435a8"},
	{256, 4, 13, "7985b93b335dee58dac0d4e42615c6174284d59ee130ec2515f2e4fdfe330986", "c1832b3b0db49581", "221e3847d067721816e46057c7e6fafbb717552b77029fa839e8e23bf9f3d8ff"},
	{256, 4, 20, "255e3ec30047e9dd1481c2ddc482bbf5ba6e7fef035527d13d37e55d72266877", "d88b7311231c4b01", "0983cd28597dd0f0644ee1003b76560d48db6128f429d5dd4b191fc232eed341"},
	{256, 4, 36, "1ad6a5bc2a586c2b6c937fb744bb5035e8e56e6580b2acbf7a7470a0c70d0b51", "1e003f834c60087f", "996983d678764fa40722a9d6b16f108c59076502c08b16a136509a0ba5bf3b4a"},
	{256, 4, 68, "71b29998c67e64967cfe244153c5ca4b665cde24d2ede6e8defdeb3440010809", "73125f2d3115b2e2", "c24a6fded0c121948104791df703442ae33d096915b439b46b7e4fe6b6d98024"},
	{256, 8, 13, "e98afacf92f920fa62a6616a849e4fababb06af9dd5fe709ba341632c0b972f2", "278aacb23fa471f5", "1713ebe84f2b0b96a35f1b2c4bd30e3cfd7a7c65279e4ba7855a57e57bb14ad0"},
	{256, 8, 20, "ba04c32842b5cdcc45e870c83fbe93ebb066d5d0639d73f5e98a5674766dd59a", "4498d9247200bf46", "5b9ceb985ab8505cb3db82d66de9e3180aa20de9be1a8c8948f6b73a8e02dce0"},
	{256, 8, 36, "57276e6980d37dc12796d804f206342ba2ce1fc7cd3a2711b07269eb7949832e", "6437cb8d56447875", "0a3bd3c59d5b94324aba7482f87257ccbab304ce49ed9879d6b3bf5499cbd1e3"},
	{256, 8, 68, "a8fc8f83205418a8caa9077bc154146c460c304d207e8fa4f66657042bb05cc9", "8d9458485cafb58c", "8d2d131e76a1b80241167dccd759e68fede333ab61962939dd69e0056d2854a5"},
	{512, 1, 13, "a65b1ab051ea7a49", "01944dcceaf622e2", "947b569e53c66ec2"},
	{512, 1, 20, "c342a2367d1f8cd2", "8f630471182a0351", "e9fa4a0d167e205e"},
	{512, 1, 36, "1938d77b58f37710", "bde40e3152b8ed90", "01675d8b0a67a640"},
	{512, 1, 68, "6d144e0b3ad5b59d", "fa1d320ff54ad88c", "b7213aee441cf042"},
	{512, 2, 13, "83791100e4c5e411", "69836e9505e2b4d9", "a5bd3694873eed23"},
	{512, 2, 20, "c795af09f96bd8df", "de2292a94de136eb", "cddc06dffd9a678d"},
	{512, 2, 36, "35e184af440e7998", "8a372c0ab25d68cd", "7b24e9cf66b2950a"},
	{512, 2, 68, "d90af2fa09f08b89", "bd7b82f6e642d594", "acdf4297a0b8a8be"},
	{512, 4, 13, "35dce72a596d731b", "56f8d358b4da4e81", "c0c822a066410ddb"},
	{512, 4, 20, "bcee06a02033185c", "65cdded86805a170", "c5b0a73504a5100b"},
	{512, 4, 36, "9391abea22993864", "393cca0615003963", "9a47d0ee927ac2d3"},
	{512, 4, 68, "c01de319cadefe0b", "662cdcb171f04a58", "44ceb14b8bb5eb69"},
}

// areionFillKATs are the folds of the batch-16 fill output over the lock
// components at group index base 0x00FFFFFFFFFFFFF8 under katFillFold, keyed by width and
// group count.
var areionFillKATs = map[[2]int]string{
	{256, 2}: "dc941be9ddad5838",
	{256, 4}: "3777ca979bb287f5",
	{256, 8}: "2c5062e2efd5077a",
	{512, 1}: "f9af12eb0ba23752",
	{512, 2}: "1279dffebb43ad35",
	{512, 4}: "047b6d6fd1749c10",
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

func fillBlockKAT(groupIdx uint64, v uint32) []byte {
	blk := make([]byte, 13)
	blk[0] = 0x03
	for j := 0; j < 8; j++ {
		blk[1+j] = byte(groupIdx >> (8 * j))
	}
	for j := 0; j < 4; j++ {
		blk[9+j] = byte(v >> (8 * j))
	}
	return blk
}

// katFillFold is the interlock-nonce fold every fill KAT is pinned under
// — a fixed nonzero word, so the goldens cover bytes 9..12 of the block.
const katFillFold uint32 = 0x9E3779B9

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
					hooked.InterlockFillX16()(lock, 0x00FFFFFFFFFFFFF8, katFillFold, &out)
					var acc uint64
					for i := range out {
						acc = foldWords(acc, out[i][:])
					}
					for i := range out {
						if want := seqCascade256(plain.Hash, lock, fillBlockKAT(0x00FFFFFFFFFFFFF8+uint64(i), katFillFold)); out[i] != want {
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
					hooked.InterlockFillX16()(lock, 0x00FFFFFFFFFFFFF8, katFillFold, &out)
					var acc uint64
					for i := range out {
						acc = foldWords(acc, out[i][:])
						if want := seqCascade512(plain.Hash, lock, fillBlockKAT(0x00FFFFFFFFFFFFF8+uint64(i), katFillFold)); out[i] != want {
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
	check("areion256 InterlockFillX16", func() { fill256(lock256, 0x00FFFFFFFFFFFFF8, katFillFold, &out256) })
	check("areion512 InterlockFillX16", func() { fill512(lock512, 0x00FFFFFFFFFFFFF8, katFillFold, &out512) })
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
	check("areion512 InterlockFillX32", func() { fill(lock512, 0x00FFFFFFFFFFFFF8, katFillFold, &out) })
}
