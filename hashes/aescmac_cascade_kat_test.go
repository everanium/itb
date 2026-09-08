package hashes

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/everanium/itb/internal/forcetier"
)

// aescmac_cascade_kat_test.go — known-answer vectors of the AES-CMAC
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

type aescmacCascadeKAT struct {
	pairs, n int
	single   string // ChainHash128(buf)
	batched  string // fold of BatchChainHash128 over four lane variants
	fused    string // FusedChain(lockComps, buf): the fill cascade at pairs+1
}

var aescmacCascadeKATs = []aescmacCascadeKAT{
	{4, 13, "83c5f8e40c02a78b5abebb570fd130f7", "4ba5fc6a23e3eb76", "fc9e9b53320c18ffc62634df0d07b983"},
	{4, 20, "31441877ec877f1b52c9c9e6bef3161b", "d64389e9fb6c42fb", "0527515871744c7ed3293dc85bd17680"},
	{4, 36, "ecb135b0bc480232a10e72a7a1dedc04", "0b806d4330d5013a", "36c5478781b30bfc4e6a2b011091021b"},
	{4, 68, "52c18243530b662907593469b9c83bc3", "11f583f8e190d9b9", "c56a2f5fed699a3f3cbf6649dafeea11"},
	{8, 13, "3d819d0f15287133aa28a0409457a2d3", "042bd7d27f68c640", "d3527d7c9dda15fc12df937c3994938d"},
	{8, 20, "381ac496521dcca08351ed61910d5fe3", "6e0bf305e8854a97", "11f811efd8f28cd8b5619f2cffc588aa"},
	{8, 36, "e6aa1f4b394b37b16ca7ee9cb03d0b6b", "4aef32cbc5e07ca2", "2afb465d968edc603ed4684294b3ef25"},
	{8, 68, "7b661d10440b07a6bc5ce5c6d1a63ab4", "54380d5f25395492", "f4be3e9b8751a2a89f94627b34e00a6a"},
	{16, 13, "b55841d4419525a3db41b5f3d126d256", "8ccc45485da5d7a9", "b27277b1af11d12e81e1c079c27ffab5"},
	{16, 20, "f3d680a35dbff2f53dc53ca73fd1b028", "ee2327a59d5b29ec", "fe363f35a3874dadbf8149228f13a11d"},
	{16, 36, "d458be8065101cb32845e9f572e4bd62", "c367c03f2e4b140f", "84631d5cfb07952d936288684498d5f8"},
	{16, 68, "86c211f688c48687aec359131ac3eae1", "9888fb30644be271", "4a18a1afee9c367f7a6f8bd237b08a1d"},
}

// aescmacFillKATs are the folds of the batch-16 fill output over the
// lock components of pairs+1 at group index base 0x00FFFFFFFFFFFFF8.
var aescmacFillKATs = map[int][2]string{
	4:  {"72ca37c972f7aa49", "5d30564bb43474f9"},
	8:  {"62b97bf70891e080", "954e0d391e843fc7"},
	16: {"5b815f2f5874cb78", "a06407cfa666bfe3"},
}

func aescmacKATKey() []byte {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(0xA5 ^ i*0x31)
	}
	return key
}

func aescmacKATComponents(pairs int) []uint64 {
	comps := make([]uint64, 2*pairs)
	for i := range comps {
		comps[i] = 0x9E3779B97F4A7C15*uint64(i+1) ^ 0x0123456789ABCDEF
	}
	return comps
}

func aescmacKATBuf(n, pairs int) []byte {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = byte(i*7 + n + pairs)
	}
	return buf
}

func hex128(lo, hi uint64) string {
	return fmt.Sprintf("%016x%016x", lo, hi)
}

func hex64(v uint64) string {
	return fmt.Sprintf("%016x", v)
}

// TestAESCMACCascadeKAT checks the vectors on a seed with every hook the
// primitive offers and on the same seed on the arms alone.
func TestAESCMACCascadeKAT(t *testing.T) {
	if forcetier.ChainHashSeq() {
		t.Skip("ITB_FORCE_CHAINHASH_SEQ disables the fused hooks")
	}
	key := aescmacKATKey()
	for _, pairs := range []int{4, 8, 16} {
		comps := aescmacKATComponents(pairs)
		lockComps := append([]uint64{0x1122334455667788, 0x99AABBCCDDEEFF00}, comps...)
		hooked := manualSeed128(t, CipherAES128CTR, key, comps)
		if err := attachFused128(hooked, CipherAES128CTR, key); err != nil {
			t.Fatal(err)
		}
		if err := attachInterlockBatch16(hooked, CipherAES128CTR, key); err != nil {
			t.Fatal(err)
		}
		if hooked.FusedChain == nil || hooked.BatchFusedChain == nil || hooked.InterlockFillX16() == nil {
			t.Fatal("aescmac seed is missing a hook after attachFused128 / attachInterlockBatch16")
		}
		plain := manualSeed128(t, CipherAES128CTR, key, comps)
		for _, kat := range aescmacCascadeKATs {
			if kat.pairs != pairs {
				continue
			}
			buf := aescmacKATBuf(kat.n, pairs)
			for label, s := range map[string]interface {
				ChainHash128([]byte) (uint64, uint64)
				BatchChainHash128(*[4][]byte) [4][2]uint64
			}{"hooked": hooked, "arms-only": plain} {
				lo, hi := s.ChainHash128(buf)
				if got := hex128(lo, hi); got != kat.single {
					t.Errorf("%s pairs=%d n=%d ChainHash128 = %s, want %s", label, pairs, kat.n, got, kat.single)
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
				if got := hex64(acc); got != kat.batched {
					t.Errorf("%s pairs=%d n=%d BatchChainHash128 fold = %s, want %s", label, pairs, kat.n, got, kat.batched)
				}
			}
			flo, fhi, ok := hooked.FusedChain(lockComps, buf)
			if !ok {
				t.Fatalf("pairs=%d n=%d: fused hook declined a kernel shape", pairs, kat.n)
			}
			if got := hex128(flo, fhi); got != kat.fused {
				t.Errorf("pairs=%d n=%d FusedChain(lockComps) = %s, want %s", pairs, kat.n, got, kat.fused)
			}
			slo, shi := plain.Hash(buf, lockComps[0], lockComps[1])
			for k := 2; k < len(lockComps); k += 2 {
				slo, shi = plain.Hash(buf, lockComps[k]^slo, lockComps[k+1]^shi)
			}
			if got := hex128(slo, shi); got != kat.fused {
				t.Errorf("pairs=%d n=%d sequential cascade over lockComps = %s, want %s", pairs, kat.n, got, kat.fused)
			}
		}
		var out [16][2]uint64
		hooked.InterlockFillX16()(lockComps, 0x00FFFFFFFFFFFFF8, &out)
		var accLo, accHi uint64
		for i := range out {
			accLo = accLo*0x100000001B3 ^ out[i][0]
			accHi = accHi*0x100000001B3 ^ out[i][1]
		}
		want := aescmacFillKATs[pairs]
		if hex64(accLo) != want[0] || hex64(accHi) != want[1] {
			t.Errorf("pairs=%d batch-16 fill fold = %s %s, want %s %s", pairs+1, hex64(accLo), hex64(accHi), want[0], want[1])
		}
	}
	if _, err := hex.DecodeString(aescmacCascadeKATs[0].single); err != nil {
		t.Fatal(err)
	}
}
