package hashprf

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"runtime"
	"runtime/debug"
	"testing"
	"unsafe"

	"github.com/everanium/areion"
	"github.com/everanium/itb/hashes"
)

// prims enumerates the supported primitives with their expected key and block
// (output) widths.
var prims = []struct {
	name      string
	keySize   int
	blockSize int
}{
	{hashes.CipherAreion256, 32, 32},
	{hashes.CipherAreion512, 64, 64},
	{hashes.CipherBLAKE2b256, 32, 32},
	{hashes.CipherBLAKE2b512, 32, 64},
	{hashes.CipherBLAKE2s, 32, 32},
	{hashes.CipherBLAKE3, 32, 32},
}

// batchPrims lists the primitives that expose a 4-wide batch PRF (only the
// Areion family; BLAKE has no native SIMD batch path).
var batchPrims = []struct {
	name      string
	keySize   int
	blockSize int
}{
	{hashes.CipherAreion256, 32, 32},
	{hashes.CipherAreion512, 64, 64},
}

// nonBatchPrims lists primitives that do NOT expose a batch path; NewBatch
// must report ok=false with no error for each.
var nonBatchPrims = []struct {
	name    string
	keySize int
}{
	{hashes.CipherBLAKE2b256, 32},
	{hashes.CipherBLAKE2b512, 32},
	{hashes.CipherBLAKE2s, 32},
	{hashes.CipherBLAKE3, 32},
}

// TestKeyBlockSizes verifies the declared key and block sizes and the
// unknown-name error paths.
func TestKeyBlockSizes(t *testing.T) {
	for _, p := range prims {
		ks, err := KeySize(p.name)
		if err != nil {
			t.Fatalf("KeySize(%q): %v", p.name, err)
		}
		if ks != p.keySize {
			t.Errorf("KeySize(%q) = %d, want %d", p.name, ks, p.keySize)
		}
		bs, err := BlockSize(p.name)
		if err != nil {
			t.Fatalf("BlockSize(%q): %v", p.name, err)
		}
		if bs != p.blockSize {
			t.Errorf("BlockSize(%q) = %d, want %d", p.name, bs, p.blockSize)
		}
	}
	if _, err := KeySize("nope"); err == nil {
		t.Error("KeySize(unknown) returned nil error")
	}
	if _, err := BlockSize("nope"); err == nil {
		t.Error("BlockSize(unknown) returned nil error")
	}
	if _, _, err := New("nope", make([]byte, 32)); err == nil {
		t.Error("New(unknown) returned nil error")
	}
}

// TestNewKeyLength rejects keys whose length does not match KeySize.
func TestNewKeyLength(t *testing.T) {
	for _, p := range prims {
		for _, bad := range []int{0, p.keySize - 1, p.keySize + 1} {
			if _, _, err := New(p.name, make([]byte, bad)); err == nil {
				t.Errorf("New(%q) accepted key length %d (want %d)", p.name, bad, p.keySize)
			}
		}
	}
}

// TestPRFShape confirms New returns the declared block size and the PRF
// writes exactly that many bytes, and is deterministic for fixed inputs.
func TestPRFShape(t *testing.T) {
	for _, p := range prims {
		key := bytes.Repeat([]byte{0x5a}, p.keySize)
		prf, bs, err := New(p.name, key)
		if err != nil {
			t.Fatalf("New(%q): %v", p.name, err)
		}
		if bs != p.blockSize {
			t.Errorf("New(%q) blockSize = %d, want %d", p.name, bs, p.blockSize)
		}
		in := []byte("hashprf-input")
		out1 := make([]byte, bs)
		out2 := make([]byte, bs)
		prf(out1, in)
		prf(out2, in)
		if !bytes.Equal(out1, out2) {
			t.Errorf("%s: PRF is not deterministic", p.name)
		}
		// Distinct input yields distinct output.
		other := make([]byte, bs)
		prf(other, []byte("different-input"))
		if bytes.Equal(out1, other) {
			t.Errorf("%s: distinct inputs produced equal output", p.name)
		}
	}
}

// TestPRFRegression pins one output per primitive over a fixed key and
// input as a regression anchor. These vectors were produced by this
// implementation.
func TestPRFRegression(t *testing.T) {
	in := []byte("regression-vector-input")
	cases := []struct {
		name string
		want string
	}{
		{hashes.CipherAreion256, "5f9cde0b712070eb09b3d9ac3dbc8df17b23d3de2873e8c1d1f3e8ca4deac5c1"},
		{hashes.CipherAreion512, "55f77bc43481092d91dc31787d65334ae537c5bd88607959c180adf14014ff97060c8ed54e314af9a6289cdc4567a2781444dd8071c39bd11b38bafd3888e55e"},
		{hashes.CipherBLAKE2b256, "7a172a3e6d568847321a0f43318e77f8fa0566fd38230a0f39232d729a7d2fda"},
		{hashes.CipherBLAKE2b512, "3a8f333fff6613bfc0b0d0490f9529eee4642b91e7df425e4da1bc4f290ba38b36ee17e8f6130916985d38ee0a46ae4a45c03c9018252b770b011552c48c786d"},
		{hashes.CipherBLAKE2s, "45d3b20804c1380a77049cb9c89829e23d7e32a5a98bc15a9aea274fcdf19c97"},
		{hashes.CipherBLAKE3, "7b7b8ae52baa66b5b0b815c6a12f2e20dabb95844d6146abcd98916da653c0d1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ks, _ := KeySize(c.name)
			key := make([]byte, ks)
			for i := range key {
				key[i] = byte(i)
			}
			prf, bs, err := New(c.name, key)
			if err != nil {
				t.Fatal(err)
			}
			out := make([]byte, bs)
			prf(out, in)
			if got := hex.EncodeToString(out); got != c.want {
				t.Errorf("%s PRF = %s, want %s", c.name, got, c.want)
			}
		})
	}
}

// TestNewBatchShape verifies NewBatch returns the declared block size and
// ok=true for batch-capable primitives, and writes exactly blockSize bytes
// into each of the four lanes.
func TestNewBatchShape(t *testing.T) {
	for _, p := range batchPrims {
		key := bytes.Repeat([]byte{0xa5}, p.keySize)
		batch, bs, ok, err := NewBatch(p.name, key)
		if err != nil {
			t.Fatalf("NewBatch(%q): %v", p.name, err)
		}
		if !ok {
			// The Areion batched arm is unavailable on hosts without any
			// VAES-capable asm path (purego / non-amd64 / no-AESNI /
			// -tags noitbasm builds). NewBatch reports ok=false there so
			// callers fall through to the single-block PRF; the batch
			// shape contract only applies when the batch path exists.
			t.Logf("NewBatch(%q): no batch path on this host; skipping shape check", p.name)
			continue
		}
		if bs != p.blockSize {
			t.Errorf("NewBatch(%q) blockSize = %d, want %d", p.name, bs, p.blockSize)
		}
		var in [4][]byte
		var dst [4][]byte
		for lane := 0; lane < 4; lane++ {
			in[lane] = []byte("batch-input-lane-X")
			in[lane][len(in[lane])-1] = byte('0' + lane)
			dst[lane] = make([]byte, bs)
		}
		batch(&dst, &in)
		// Per-lane output is non-zero (PRF over a non-trivial key/input).
		zero := make([]byte, bs)
		for lane := 0; lane < 4; lane++ {
			if bytes.Equal(dst[lane], zero) {
				t.Errorf("%s lane %d: PRF output is all zero", p.name, lane)
			}
		}
		// Distinct lane inputs produce distinct outputs.
		for i := 0; i < 4; i++ {
			for j := i + 1; j < 4; j++ {
				if bytes.Equal(dst[i], dst[j]) {
					t.Errorf("%s: lane %d and lane %d produced equal output", p.name, i, j)
				}
			}
		}
	}
}

// TestNewBatchEqualsSingle is the load-bearing security claim of the batch
// path: each lane's batched output must equal the single-input PRF over the
// same key and input, byte-for-byte. The CTR keystream's batched code path
// relies on this equivalence to remain interoperable with the single-block
// path under the same (key, nonce, counter).
func TestNewBatchEqualsSingle(t *testing.T) {
	for _, p := range batchPrims {
		key := make([]byte, p.keySize)
		for i := range key {
			key[i] = byte(0x10 + i)
		}
		// Build the batched and the single-input PRF over the same key.
		batch, bs, ok, err := NewBatch(p.name, key)
		if err != nil {
			t.Fatalf("NewBatch(%q): %v", p.name, err)
		}
		if !ok {
			// No batch path on this host (non-VAES / -tags noitbasm) —
			// the batched-vs-single equivalence is vacuous there.
			t.Logf("NewBatch(%q): no batch path on this host; skipping equivalence check", p.name)
			continue
		}
		single, sbs, err := New(p.name, key)
		if err != nil {
			t.Fatalf("New(%q): %v", p.name, err)
		}
		if bs != sbs {
			t.Fatalf("%s: batch blockSize %d != single blockSize %d", p.name, bs, sbs)
		}
		// Four distinct inputs of equal length across the batch. The Areion
		// SIMD batch path requires every lane to feed an input of the same
		// length (it interleaves the lanes through one shared permutation
		// pipeline); the canonical caller - the ctr PRF-counter keystream -
		// always supplies four 24-byte (nonce || counter) inputs, so this
		// equivalence test exercises the same regime.
		base := bytes.Repeat([]byte{0x00}, 24)
		inputs := [4][]byte{}
		for lane := 0; lane < 4; lane++ {
			b := append([]byte(nil), base...)
			b[0] = byte(0xa0 + lane) // distinct per lane
			b[8] = byte(lane)        // distinct counter-shaped tail
			inputs[lane] = b
		}
		var batchIn [4][]byte
		var batchOut [4][]byte
		for lane := 0; lane < 4; lane++ {
			batchIn[lane] = inputs[lane]
			batchOut[lane] = make([]byte, bs)
		}
		batch(&batchOut, &batchIn)
		// Single-input PRF over each lane's input.
		for lane := 0; lane < 4; lane++ {
			singleOut := make([]byte, bs)
			single(singleOut, inputs[lane])
			if !bytes.Equal(batchOut[lane], singleOut) {
				t.Errorf("%s lane %d: batched output differs from single-input PRF\n  batch:  %x\n  single: %x",
					p.name, lane, batchOut[lane], singleOut)
			}
		}
	}
}

// TestNewBatchUnsupported verifies NewBatch returns ok=false with no error
// for primitives lacking a SIMD batch path (the BLAKE family). Callers fall
// back to four independent New() invocations in that case.
func TestNewBatchUnsupported(t *testing.T) {
	for _, p := range nonBatchPrims {
		key := bytes.Repeat([]byte{0x42}, p.keySize)
		batch, bs, ok, err := NewBatch(p.name, key)
		if err != nil {
			t.Errorf("NewBatch(%q): unexpected error %v", p.name, err)
		}
		if ok {
			t.Errorf("NewBatch(%q): ok = true, want false (no batch path for this primitive)", p.name)
		}
		if batch != nil {
			t.Errorf("NewBatch(%q): batch != nil for unsupported primitive", p.name)
		}
		if bs != 0 {
			t.Errorf("NewBatch(%q): blockSize = %d, want 0 for unsupported primitive", p.name, bs)
		}
	}
}

// TestNewBatchErrors verifies the unknown-name and wrong-key-length error
// paths of NewBatch.
func TestNewBatchErrors(t *testing.T) {
	if _, _, _, err := NewBatch("nope", make([]byte, 32)); err == nil {
		t.Error("NewBatch(unknown): expected error, got nil")
	}
	for _, p := range batchPrims {
		for _, bad := range []int{0, p.keySize - 1, p.keySize + 1} {
			if _, _, _, err := NewBatch(p.name, make([]byte, bad)); err == nil {
				t.Errorf("NewBatch(%q): accepted key length %d (want %d)", p.name, bad, p.keySize)
			}
		}
	}
	// Unknown-name error path on the BLAKE family side too - NewBatch must
	// reject the name before reaching the ok=false branch.
	for _, p := range nonBatchPrims {
		for _, bad := range []int{0, p.keySize - 1, p.keySize + 1} {
			if _, _, _, err := NewBatch(p.name, make([]byte, bad)); err == nil {
				t.Errorf("NewBatch(%q): accepted key length %d (want %d)", p.name, bad, p.keySize)
			}
		}
	}
}

// soemState256 is the Areion-SoEM-256 CBC-MAC state of a single-round input:
// LE64(len(in)) || in, zero-padded to 32 bytes (len(in) <= 24).
func soemState256(in []byte) [32]byte {
	var m [32]byte
	binary.LittleEndian.PutUint64(m[:8], uint64(len(in)))
	copy(m[8:], in)
	return m
}

// soemState512 is the 64-byte counterpart (len(in) <= 56).
func soemState512(in []byte) [64]byte {
	var m [64]byte
	binary.LittleEndian.PutUint64(m[:8], uint64(len(in)))
	copy(m[8:], in)
	return m
}

// permute2x256 evaluates the second Areion-256 permutation P2 of SoEM22
// through the exported API: under the all-zero key, F(m) = P1(m) ^ P2(m)
// with zero whitening, so P2(m) = F(m) ^ P1(m).
func permute2x256(x [32]byte) [32]byte {
	var zeroKey [64]byte
	f := areion.SoEM256(&zeroKey, &x)
	p1 := x
	areion.Permute256(&p1)
	for i := range f {
		f[i] ^= p1[i]
	}
	return f
}

// permute2x512 is the 512-bit counterpart of permute2x256.
func permute2x512(x [64]byte) [64]byte {
	var zeroKey [128]byte
	f := areion.SoEM512(&zeroKey, &x)
	p1 := x
	areion.Permute512(&p1)
	for i := range f {
		f[i] ^= p1[i]
	}
	return f
}

// recoverK1x256 runs the one-block key-recovery attack against a SoEM-256
// round function whose second subkey is the public value zero and whose
// output carries no whitening: out = P1(m ^ k1) ^ P2(m), so
// k1 = m ^ P1^-1(out ^ P2(m)).
func recoverK1x256(m [32]byte, out []byte) []byte {
	b := permute2x256(m)
	var a [32]byte
	for i := range a {
		a[i] = out[i] ^ b[i]
	}
	areion.InversePermute256(&a)
	k := make([]byte, 32)
	for i := range k {
		k[i] = a[i] ^ m[i]
	}
	return k
}

// recoverK1x512 is the SoEM-512 counterpart of recoverK1x256.
func recoverK1x512(m [64]byte, out []byte) []byte {
	b := permute2x512(m)
	var a [64]byte
	for i := range a {
		a[i] = out[i] ^ b[i]
	}
	areion.InversePermute512(&a)
	k := make([]byte, 64)
	for i := range k {
		k[i] = a[i] ^ m[i]
	}
	return k
}

// TestAreionOneBlockKeyRecovery runs the one-block key-recovery attack that
// applies to a sum of two permutations keyed with a public second subkey and
// no output whitening. The attack must recover the key from such a sum built
// by hand (negative control: it confirms the attack itself is correct), and
// must fail against the registry hash under the zero seed (the SoEM22
// whitening k1 ^ k2 alone leaves a single-key Even-Mansour instance in k1,
// which one block does not invert) and against the hashprf PRF, single and
// batched, whose second subkey is derived from the key. The input is 24
// bytes, the ctr keystream block shape (nonce || counter), which runs the
// single-round CBC-MAC path, so the SoEM input state is fully known to the
// attacker.
func TestAreionOneBlockKeyRecovery(t *testing.T) {
	in := make([]byte, 24)
	for i := range in {
		in[i] = byte(0xc0 + i)
	}

	t.Run(hashes.CipherAreion256, func(t *testing.T) {
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(0x31 * (i + 1))
		}
		var k [32]byte
		copy(k[:], key)
		m := soemState256(in)

		// Negative control: P1(m ^ k1) ^ P2(m), public zero second subkey,
		// no whitening — the sum F(k1 || 0, m) with the whitening k1
		// removed.
		var k10 [64]byte
		copy(k10[:32], key)
		unwhitened := areion.SoEM256(&k10, &m)
		for i := range key {
			unwhitened[i] ^= key[i]
		}
		if got := recoverK1x256(m, unwhitened[:]); !bytes.Equal(got, key) {
			t.Fatalf("negative control: attack failed against the unwhitened zero-subkey sum (got %x)", got)
		}

		// Registry hash under the zero seed: public second subkey, but the
		// whitening is in place.
		hf, _ := hashes.Areion256PairWithKey(k)
		w := hf(in, [4]uint64{})
		zeroOut := make([]byte, 32)
		for i := 0; i < 4; i++ {
			binary.LittleEndian.PutUint64(zeroOut[i*8:], w[i])
		}
		if got := recoverK1x256(m, zeroOut); bytes.Equal(got, key) {
			t.Fatal("one-block key recovery succeeded against the whitened zero-seed hash")
		}

		prf, bs, err := New(hashes.CipherAreion256, key)
		if err != nil {
			t.Fatal(err)
		}
		out := make([]byte, bs)
		prf(out, in)
		if bytes.Equal(out, zeroOut) {
			t.Fatal("PRF output equals the zero-seed output")
		}
		if got := recoverK1x256(m, out); bytes.Equal(got, key) {
			t.Fatal("one-block key recovery succeeded against the PRF")
		}

		batch, bbs, ok, err := NewBatch(hashes.CipherAreion256, key)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Log("no batch path on this host; batched arm not exercised")
			return
		}
		var bin, bout [4][]byte
		for lane := range bin {
			bin[lane] = in
			bout[lane] = make([]byte, bbs)
		}
		batch(&bout, &bin)
		for lane := range bout {
			if !bytes.Equal(bout[lane], out) {
				t.Errorf("batch lane %d differs from the single-input PRF", lane)
			}
			if got := recoverK1x256(m, bout[lane]); bytes.Equal(got, key) {
				t.Errorf("batch lane %d: one-block key recovery succeeded", lane)
			}
		}
	})

	t.Run(hashes.CipherAreion512, func(t *testing.T) {
		key := make([]byte, 64)
		for i := range key {
			key[i] = byte(0x53 * (i + 1))
		}
		var k [64]byte
		copy(k[:], key)
		m := soemState512(in)

		var k10 [128]byte
		copy(k10[:64], key)
		unwhitened := areion.SoEM512(&k10, &m)
		for i := range key {
			unwhitened[i] ^= key[i]
		}
		if got := recoverK1x512(m, unwhitened[:]); !bytes.Equal(got, key) {
			t.Fatalf("negative control: attack failed against the unwhitened zero-subkey sum (got %x)", got)
		}

		hf, _ := hashes.Areion512PairWithKey(k)
		w := hf(in, [8]uint64{})
		zeroOut := make([]byte, 64)
		for i := 0; i < 8; i++ {
			binary.LittleEndian.PutUint64(zeroOut[i*8:], w[i])
		}
		if got := recoverK1x512(m, zeroOut); bytes.Equal(got, key) {
			t.Fatal("one-block key recovery succeeded against the whitened zero-seed hash")
		}

		prf, bs, err := New(hashes.CipherAreion512, key)
		if err != nil {
			t.Fatal(err)
		}
		out := make([]byte, bs)
		prf(out, in)
		if bytes.Equal(out, zeroOut) {
			t.Fatal("PRF output equals the zero-seed output")
		}
		if got := recoverK1x512(m, out); bytes.Equal(got, key) {
			t.Fatal("one-block key recovery succeeded against the PRF")
		}

		batch, bbs, ok, err := NewBatch(hashes.CipherAreion512, key)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Log("no batch path on this host; batched arm not exercised")
			return
		}
		var bin, bout [4][]byte
		for lane := range bin {
			bin[lane] = in
			bout[lane] = make([]byte, bbs)
		}
		batch(&bout, &bin)
		for lane := range bout {
			if !bytes.Equal(bout[lane], out) {
				t.Errorf("batch lane %d differs from the single-input PRF", lane)
			}
			if got := recoverK1x512(m, bout[lane]); bytes.Equal(got, key) {
				t.Errorf("batch lane %d: one-block key recovery succeeded", lane)
			}
		}
	})
}

// TestAreionSubkeyDerivation pins the second-subkey derivation against an
// independent SHA-512 evaluation, so a change to the label, the hash or the
// word order is caught directly rather than only through output vectors.
func TestAreionSubkeyDerivation(t *testing.T) {
	key32 := make([]byte, 32)
	key64 := make([]byte, 64)
	for i := range key64 {
		key64[i] = byte(i)
	}
	copy(key32, key64)

	sum := sha512.Sum512(append([]byte("itb hashprf areion256 subkey"), key32...))
	var s256 [4]uint64
	areionSeed256(key32, &s256)
	for i := range s256 {
		if want := binary.LittleEndian.Uint64(sum[i*8:]); s256[i] != want {
			t.Errorf("areion256 seed word %d = %#x, want %#x", i, s256[i], want)
		}
	}
	sum = sha512.Sum512(append([]byte("itb hashprf areion512 subkey"), key64...))
	var s512 [8]uint64
	areionSeed512(key64, &s512)
	for i := range s512 {
		if want := binary.LittleEndian.Uint64(sum[i*8:]); s512[i] != want {
			t.Errorf("areion512 seed word %d = %#x, want %#x", i, s512[i], want)
		}
	}
}

// TestNonPRFRejected pins the exclusion of the Non-PRF registry entry from
// every keyed-PRF constructor: AES-ITB-128 is one-pair invertible
// standalone, so a keystream, KDF or MAC key derived through it would be
// recoverable from one output block. KeySize, New and NewBatch must all
// refuse it.
func TestNonPRFRejected(t *testing.T) {
	name := hashes.CipherAESITB128
	if _, err := KeySize(name); err == nil {
		t.Errorf("KeySize(%q): expected error", name)
	}
	for _, n := range []int{16, 32, 64} {
		if _, _, err := New(name, make([]byte, n)); err == nil {
			t.Errorf("New(%q, %d-byte key): expected error", name, n)
		}
		if _, _, _, err := NewBatch(name, make([]byte, n)); err == nil {
			t.Errorf("NewBatch(%q, %d-byte key): expected error", name, n)
		}
	}
}

const (
	hashprfResidueGap      = 1 << 10
	hashprfResiduePad      = 2 << 10
	hashprfResidueWindow   = 16 << 10
	hashprfResidueSentinel = uint64(0x5A5A5A5A5A5A5A5A)
)

func captureHashPRFStackResidue(t *testing.T, fn func()) []uint64 {
	t.Helper()
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	res := make([]uint64, hashprfResidueWindow/8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		hashprfResidueGrow(0)
		hashprfResidueProbe(fn, res)
	}()
	<-done
	written := 0
	for _, w := range res {
		if w != hashprfResidueSentinel {
			written++
		}
	}
	if written == 0 {
		t.Fatal("stack probe window was not touched by target call")
	}
	return res
}

//go:noinline
func hashprfResidueGrow(i int) byte {
	var pad [4 * hashprfResidueWindow]byte
	pad[i] = 1
	return pad[(i+1)%len(pad)]
}

//go:noinline
func hashprfResidueProbe(fn func(), res []uint64) {
	var anchor uint64
	top := unsafe.Add(unsafe.Pointer(&anchor), -hashprfResidueGap)
	for i := range res {
		*(*uint64)(unsafe.Add(top, -8*(i+1))) = hashprfResidueSentinel
	}
	hashprfResidueDeep(fn, 0)
	for i := range res {
		res[i] = *(*uint64)(unsafe.Add(top, -8*(i+1)))
	}
}

//go:noinline
func hashprfResidueDeep(fn func(), i int) byte {
	var pad [hashprfResiduePad]byte
	pad[i] = 1
	fn()
	return pad[(i+7)%len(pad)]
}

//go:noinline
func leakyHashPRFKeyFrame(key []byte) uint64 {
	var leak [8]uint64
	for i := 0; i*8+8 <= len(key) && i < len(leak); i++ {
		leak[i] = binary.LittleEndian.Uint64(key[i*8:])
	}
	runtime.KeepAlive(&leak)
	return leak[0]
}

func TestZeroizationWithClose(t *testing.T) {
	probeKey := make([]byte, 32)
	for i := range probeKey {
		probeKey[i] = byte(0x73 + i*5)
	}

	// Negative control: verify captureHashPRFStackResidue detects an unzeroed key word.
	negWin := captureHashPRFStackResidue(t, func() {
		_ = leakyHashPRFKeyFrame(probeKey)
	})
	wantWord := binary.LittleEndian.Uint64(probeKey[:8])
	foundNeg := false
	for _, w := range negWin {
		if w == wantWord {
			foundNeg = true
			break
		}
	}
	if !foundNeg {
		t.Fatal("negative control failed: leakyHashPRFKeyFrame was not detected in stack residue")
	}

	in := []byte("hashprf-zeroization-probe-input!")
	for _, p := range prims {
		t.Run(p.name, func(t *testing.T) {
			key := make([]byte, p.keySize)
			for i := range key {
				key[i] = byte(0x73 + i*5)
			}
			secrets := make(map[uint64]bool)
			for off := 0; off+8 <= len(key); off += 8 {
				w := binary.LittleEndian.Uint64(key[off:])
				if w != 0 && w != hashprfResidueSentinel {
					secrets[w] = true
				}
			}
			for off := 0; off+8 <= len(in); off += 8 {
				w := binary.LittleEndian.Uint64(in[off:])
				if w != 0 && w != hashprfResidueSentinel {
					secrets[w] = true
				}
			}
			if p.name == hashes.CipherAreion256 {
				sum := sha512.Sum512(append([]byte(areion256SubkeyLabel), key...))
				for i := 0; i < 4; i++ {
					secrets[binary.LittleEndian.Uint64(sum[i*8:])] = true
				}
			} else if p.name == hashes.CipherAreion512 {
				sum := sha512.Sum512(append([]byte(areion512SubkeyLabel), key...))
				for i := 0; i < 8; i++ {
					secrets[binary.LittleEndian.Uint64(sum[i*8:])] = true
				}
			}

			var prf func(dst, in []byte)
			var bs int
			var closeFn func()
			var out []byte
			win := captureHashPRFStackResidue(t, func() {
				var err error
				prf, bs, closeFn, err = NewWithClose(p.name, key)
				if err != nil {
					t.Fatalf("NewWithClose(%q): %v", p.name, err)
				}
				out = make([]byte, bs)
				prf(out, in)
			})
			if closeFn == nil {
				t.Fatalf("NewWithClose(%q) returned nil closeFn", p.name)
			}
			if bytes.Equal(out, make([]byte, bs)) {
				t.Fatalf("%s: PRF output before closeFn is all zero", p.name)
			}
			for off := 0; off+8 <= len(out); off += 8 {
				w := binary.LittleEndian.Uint64(out[off:])
				if w != 0 && w != hashprfResidueSentinel {
					secrets[w] = true
				}
			}
			for idx, w := range win {
				if secrets[w] {
					t.Fatalf("%s: PRF evaluation left secret word %#x at stack slot %d", p.name, w, idx)
				}
			}

			// After closeFn(), internal key/hasher state is zeroed so subsequent
			// output differs from the keyed evaluation.
			closeFn()
			outAfter := make([]byte, bs)
			prf(outAfter, in)
			if bytes.Equal(out, outAfter) {
				t.Fatalf("%s: PRF output unchanged after closeFn()", p.name)
			}
		})
	}

	for _, p := range batchPrims {
		t.Run(p.name+"_batch", func(t *testing.T) {
			key := make([]byte, p.keySize)
			for i := range key {
				key[i] = byte(0x91 + i*3)
			}
			secrets := make(map[uint64]bool)
			for off := 0; off+8 <= len(key); off += 8 {
				w := binary.LittleEndian.Uint64(key[off:])
				if w != 0 && w != hashprfResidueSentinel {
					secrets[w] = true
				}
			}
			for off := 0; off+8 <= len(in); off += 8 {
				w := binary.LittleEndian.Uint64(in[off:])
				if w != 0 && w != hashprfResidueSentinel {
					secrets[w] = true
				}
			}
			if p.name == hashes.CipherAreion256 {
				sum := sha512.Sum512(append([]byte(areion256SubkeyLabel), key...))
				for i := 0; i < 4; i++ {
					secrets[binary.LittleEndian.Uint64(sum[i*8:])] = true
				}
			} else if p.name == hashes.CipherAreion512 {
				sum := sha512.Sum512(append([]byte(areion512SubkeyLabel), key...))
				for i := 0; i < 8; i++ {
					secrets[binary.LittleEndian.Uint64(sum[i*8:])] = true
				}
			}

			var batch func(dst, in *[4][]byte)
			var bs int
			var ok bool
			var closeFn func()
			var bin, bout, boutAfter [4][]byte
			win := captureHashPRFStackResidue(t, func() {
				var err error
				batch, bs, ok, closeFn, err = NewBatchWithClose(p.name, key)
				if err != nil {
					t.Fatalf("NewBatchWithClose(%q): %v", p.name, err)
				}
				if !ok {
					return
				}
				for lane := 0; lane < 4; lane++ {
					bin[lane] = in
					bout[lane] = make([]byte, bs)
					boutAfter[lane] = make([]byte, bs)
				}
				batch(&bout, &bin)
			})
			if !ok {
				return
			}
			if closeFn == nil {
				t.Fatalf("NewBatchWithClose(%q) returned nil closeFn", p.name)
			}
			for lane := 0; lane < 4; lane++ {
				for off := 0; off+8 <= len(bout[lane]); off += 8 {
					w := binary.LittleEndian.Uint64(bout[lane][off:])
					if w != 0 && w != hashprfResidueSentinel {
						secrets[w] = true
					}
				}
			}
			for idx, w := range win {
				if secrets[w] {
					t.Fatalf("%s batch: evaluation left secret word %#x at stack slot %d", p.name, w, idx)
				}
			}

			closeFn()
			batch(&boutAfter, &bin)
			for lane := 0; lane < 4; lane++ {
				if bytes.Equal(bout[lane], boutAfter[lane]) {
					t.Fatalf("%s batch lane %d: output unchanged after closeFn()", p.name, lane)
				}
			}
		})
	}
}
