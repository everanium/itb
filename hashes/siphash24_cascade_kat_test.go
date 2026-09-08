package hashes

import (
	"encoding/hex"
	"os"
	"testing"

	"github.com/everanium/itb/internal/forcetier"
)

// siphash24_cascade_kat_test.go — known-answer vectors of the SipHash-2-4
// ChainHash128 cascade, produced by the pure-Go cascade under the
// noitbasm build tag and identical on every assembly tier. The vectors
// cover the per-pixel cascade of the 512 / 1024 / 2048-bit keys (4 / 8 /
// 16 component pairs) at the four kernel shapes — single lane, four
// lanes, and the single-lane fused hook over the prepended lock
// components of the Interlocked Barrier fill (5 / 9 / 17 pairs) — and
// the batch-16 fill hook at the 13-byte shape across a group index base
// that carries through byte 7 inside the batch. A seed with every hook
// and the same seed on the arms alone are both checked, so the table
// pins the wire as well as every hook against the noitbasm reference.
// SipHash has no fixed key: the components are the whole key.

type siphash24CascadeKAT struct {
	pairs, n int
	single   string // ChainHash128(buf)
	batched  string // fold of BatchChainHash128 over four lane variants
	fused    string // FusedChain(lockComps, buf): the fill cascade at pairs+1
}

var siphash24CascadeKATs = []siphash24CascadeKAT{
	{4, 13, "2b389628d854a99827d1f378175c0eda", "8e31cc18a78dea81", "7b84f1f4b6e943eafd00c7a90829d539"},
	{4, 20, "cfc4072c46037fd97620c97f62176a49", "05dcb54b34c0ac42", "d802b1accc96ae9fd146661ccecc772f"},
	{4, 36, "fa33759a1e0f4293109c204fd65559da", "c35b87ae7bff5c8d", "06fa3723fe6bd804745c5c395cb7cb30"},
	{4, 68, "73b542175448bc01faa42b2f5e3ca10d", "e68b8581659a1a00", "a7efd2728d0a85ba8cb36ddae4579c40"},
	{8, 13, "27aeb338e57d4863661e10ceb29b9d34", "8169e11d72aad35e", "ef9da99018e2a44fb333a1b2a7ffe169"},
	{8, 20, "45334c43872e2cb19e105520b0b8949d", "07ef26a24e5ec750", "e8bb1ebd97dac65a0c29187521cc0bdf"},
	{8, 36, "d1d7e1a4d1db52a10f17739e81ff1a2b", "38ddc5cb2518511c", "18402e3505d947d6a6ed76b1ca77b0c6"},
	{8, 68, "16bb7a97e00b50b90edcb9fee89ae30c", "fa909be97b8eca8c", "7f9d459de8fc5ac7ecb166426e317eeb"},
	{16, 13, "9963728555bcc4f94a592f99e7000ec1", "38b3e2b4051df74b", "0b47ea304c34dbe051eedd31851caf7d"},
	{16, 20, "583ddb0be702177a656bd35754bbe56e", "cd51c250c68111df", "9ca21b94a33a9a6b0b43ee05b4d43427"},
	{16, 36, "7691ef1d75b75afbbb1b915f61e16fd4", "dcf983ff3998aff4", "34254ce616061fa64bbc83640861ef6b"},
	{16, 68, "feaf78ab9448eaa7d5c05a0dad55400c", "0ab2ef59306658f4", "e587dad486c0d73fead89415c16bb8f7"},
}

// siphash24FillKATs are the folds of the batch-16 fill output over the
// lock components of pairs+1 at group index base 0x00FFFFFFFFFFFFF8.
var siphash24FillKATs = map[int][2]string{
	4:  {"23f82c2d39694b7d", "f574f09a34fdca10"},
	8:  {"589aebad799fafd2", "4c4a6d30e39e9062"},
	16: {"cbae0e9465bde47f", "d792835886fdf26c"},
}

func siphash24KATComponents(pairs int) []uint64 {
	comps := make([]uint64, 2*pairs)
	for i := range comps {
		comps[i] = 0xC2B2AE3D27D4EB4F*uint64(i+1) ^ 0xFEDCBA9876543210
	}
	return comps
}

func TestSipHash24CascadeKAT(t *testing.T) {
	if forcetier.ChainHashSeq() {
		t.Skip("ITB_FORCE_CHAINHASH_SEQ disables the fused hooks")
	}
	printKAT := os.Getenv("ITB_KAT_PRINT") != ""
	for _, pairs := range []int{4, 8, 16} {
		comps := siphash24KATComponents(pairs)
		lockComps := append([]uint64{0x1122334455667788, 0x99AABBCCDDEEFF00}, comps...)
		hooked := manualSeed128(t, CipherSipHash24, nil, comps)
		if err := AttachFused128(hooked, CipherSipHash24, nil); err != nil {
			t.Fatal(err)
		}
		if err := AttachInterlockBatch16(hooked, CipherSipHash24, nil); err != nil {
			t.Fatal(err)
		}
		if hooked.FusedChain == nil || hooked.BatchFusedChain == nil || hooked.InterlockFillX16() == nil {
			t.Fatal("siphash24 seed is missing a hook after AttachFused128 / AttachInterlockBatch16")
		}
		plain := manualSeed128(t, CipherSipHash24, nil, comps)
		for _, kat := range siphash24CascadeKATs {
			if kat.pairs != pairs {
				continue
			}
			buf := aescmacKATBuf(kat.n, pairs)
			var singleGot, batchedGot string
			for label, s := range map[string]interface {
				ChainHash128([]byte) (uint64, uint64)
				BatchChainHash128(*[4][]byte) [4][2]uint64
			}{"hooked": hooked, "arms-only": plain} {
				lo, hi := s.ChainHash128(buf)
				singleGot = hex128(lo, hi)
				if !printKAT && singleGot != kat.single {
					t.Errorf("%s pairs=%d n=%d ChainHash128 = %s, want %s", label, pairs, kat.n, singleGot, kat.single)
				}
				var lanes [4][]byte
				for l := range lanes {
					lanes[l] = append([]byte(nil), buf...)
					lanes[l][0] ^= byte(l + 1)
				}
				b := s.BatchChainHash128(&lanes)
				var acc uint64
				for l := range b {
					acc = acc*0x100000001B3 ^ b[l][0] ^ (b[l][1] << 1)
				}
				batchedGot = hex64(acc)
				if !printKAT && batchedGot != kat.batched {
					t.Errorf("%s pairs=%d n=%d BatchChainHash128 fold = %s, want %s", label, pairs, kat.n, batchedGot, kat.batched)
				}
			}
			flo, fhi, ok := hooked.FusedChain(lockComps, buf)
			if !ok {
				t.Fatalf("pairs=%d n=%d: fused hook declined a kernel shape", pairs, kat.n)
			}
			fusedGot := hex128(flo, fhi)
			if !printKAT && fusedGot != kat.fused {
				t.Errorf("pairs=%d n=%d FusedChain(lockComps) = %s, want %s", pairs, kat.n, fusedGot, kat.fused)
			}
			slo, shi := plain.Hash(buf, lockComps[0], lockComps[1])
			for k := 2; k < len(lockComps); k += 2 {
				slo, shi = plain.Hash(buf, lockComps[k]^slo, lockComps[k+1]^shi)
			}
			if got := hex128(slo, shi); got != fusedGot {
				t.Errorf("pairs=%d n=%d sequential cascade over lockComps = %s, fused hook = %s", pairs, kat.n, got, fusedGot)
			}
			if printKAT {
				t.Logf("\t{%d, %d, %q, %q, %q},", pairs, kat.n, singleGot, batchedGot, fusedGot)
			}
		}
		var out [16][2]uint64
		hooked.InterlockFillX16()(lockComps, 0x00FFFFFFFFFFFFF8, &out)
		var accLo, accHi uint64
		for i := range out {
			accLo = accLo*0x100000001B3 ^ out[i][0]
			accHi = accHi*0x100000001B3 ^ out[i][1]
		}
		if printKAT {
			t.Logf("\t%d:  {%q, %q},", pairs, hex64(accLo), hex64(accHi))
			continue
		}
		want := siphash24FillKATs[pairs]
		if hex64(accLo) != want[0] || hex64(accHi) != want[1] {
			t.Errorf("pairs=%d batch-16 fill fold = %s %s, want %s %s", pairs+1, hex64(accLo), hex64(accHi), want[0], want[1])
		}
	}
	if _, err := hex.DecodeString(siphash24CascadeKATs[0].single); err != nil {
		t.Fatal(err)
	}
}

// TestSipHash24HooksZeroAlloc asserts that the hooks installed on a
// siphash24 seed by AttachFused128 / AttachInterlockBatch16 and the
// eight-lane attach step run without a heap allocation per call at
// every kernel shape — the hooks sit on the per-pixel and per-group hot
// paths of the pipeline.
func TestSipHash24HooksZeroAlloc(t *testing.T) {
	if forcetier.ChainHashSeq() {
		t.Skip("ITB_FORCE_CHAINHASH_SEQ disables the fused hooks")
	}
	const pairs = 8
	comps := siphash24KATComponents(pairs)
	lockComps := append([]uint64{0x1122334455667788, 0x99AABBCCDDEEFF00}, comps...)
	s := manualSeed128(t, CipherSipHash24, nil, comps)
	if err := AttachFused128(s, CipherSipHash24, nil); err != nil {
		t.Fatal(err)
	}
	if err := AttachInterlockBatch16(s, CipherSipHash24, nil); err != nil {
		t.Fatal(err)
	}
	check := func(what string, f func()) {
		t.Helper()
		if n := testing.AllocsPerRun(50, f); n != 0 {
			t.Errorf("%s allocates %.0f objects per call", what, n)
		}
	}
	for _, n := range []int{13, 20, 36, 68} {
		buf := aescmacKATBuf(n, pairs)
		check("FusedChain n="+hex64(uint64(n)), func() { s.FusedChain(lockComps, buf) })
		var lanes [4][]byte
		for l := range lanes {
			lanes[l] = append([]byte(nil), buf...)
		}
		check("BatchFusedChain n="+hex64(uint64(n)), func() { s.BatchFusedChain(comps, &lanes) })
		if b8 := s.BatchFusedChain8(); b8 != nil && n != 13 {
			var lanes8 [8][]byte
			for l := range lanes8 {
				lanes8[l] = append([]byte(nil), buf...)
			}
			check("BatchFusedChain8 n="+hex64(uint64(n)), func() { b8(comps, &lanes8) })
		}
	}
	fill := s.InterlockFillX16()
	var out [16][2]uint64
	check("InterlockFillX16", func() { fill(lockComps, 0x00FFFFFFFFFFFFF8, &out) })
}
