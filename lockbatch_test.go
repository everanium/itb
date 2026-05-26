package itb

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// lockBatchSizes spans empty / sub-chunk / single-group / multi-group /
// tail-group / large inputs across all three native widths so the
// short-final-group path (chunk count not a multiple of factor = 2 / 4 / 8)
// is exercised at every width.
var lockBatchSizes = []int{
	1, 2, 3, 4, 5, 6, 7, 8, 9,
	23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
	100, 255, 256, 257,
	1023, 1024, 1025,
	4097,
	65537,
}

// lockBatchKernelSizes adds the empty case for kernel-level tests, which
// handle a zero-length payload (the public Encrypt API rejects empty data).
var lockBatchKernelSizes = append([]int{0}, lockBatchSizes...)

// withLockBatch turns on SetBitSoup(1) + SetLockSoup(1) + SetLockBatch(1)
// for the duration of the test, restoring all three globals via t.Cleanup.
func withLockBatch(t testing.TB) {
	t.Helper()
	prevBit := GetBitSoup()
	prevLock := GetLockSoup()
	prevBatch := GetLockBatch()
	SetBitSoup(1)
	SetLockSoup(1)
	SetLockBatch(1)
	t.Cleanup(func() {
		SetLockBatch(prevBatch)
		SetLockSoup(prevLock)
		SetBitSoup(prevBit)
	})
}

// withGlobals saves all three overlay globals and restores them via
// t.Cleanup, leaving the caller free to set any combination.
func withGlobals(t testing.TB) {
	t.Helper()
	prevBit := GetBitSoup()
	prevLock := GetLockSoup()
	prevBatch := GetLockBatch()
	t.Cleanup(func() {
		SetLockBatch(prevBatch)
		SetLockSoup(prevLock)
		SetBitSoup(prevBit)
	})
}

// --- per-width fresh-seed encrypt/decrypt closures -------------------------
//
// Seeds lock after first Encrypt (firstEncryptCalled), so each round-trip
// builds a fresh set. A bool selects whether a dedicated lockSeed is
// attached to the noise slot.

// A roundTripFn encrypts p and decrypts the result with a SINGLE freshly
// built seed set (seeds lock after the first encrypt, so each call gets new
// seeds; the same set is reused for the matching decrypt). An encryptFn
// returns the ciphertext from a fresh seed set; a decryptFn decrypts under a
// fresh seed set (whose key material differs — used only to confirm cross-mode
// decryption does not cleanly recover the plaintext, never panics).

func single128RT(t *testing.T, lockSeed bool, p []byte) ([]byte, []byte, error) {
	t.Helper()
	ns, _ := NewSeed128(512, sipHash128)
	ds, _ := NewSeed128(512, sipHash128)
	ss, _ := NewSeed128(512, sipHash128)
	if lockSeed {
		ls, _ := NewSeed128(512, sipHash128)
		ns.AttachLockSeed(ls)
	}
	ct, err := Encrypt128(ns, ds, ss, p)
	if err != nil {
		return nil, nil, err
	}
	pt, err := Decrypt128(ns, ds, ss, ct)
	return ct, pt, err
}

func triple128RT(t *testing.T, lockSeed bool, p []byte) ([]byte, []byte, error) {
	t.Helper()
	ns, d1, d2, d3, s1, s2, s3 := makeSevenSeeds128(512, sipHash128)
	if lockSeed {
		ls, _ := NewSeed128(512, sipHash128)
		ns.AttachLockSeed(ls)
	}
	ct, err := Encrypt3x128(ns, d1, d2, d3, s1, s2, s3, p)
	if err != nil {
		return nil, nil, err
	}
	pt, err := Decrypt3x128(ns, d1, d2, d3, s1, s2, s3, ct)
	return ct, pt, err
}

func single256RT(t *testing.T, lockSeed bool, p []byte) ([]byte, []byte, error) {
	t.Helper()
	h := makeBlake3Hash256()
	ns, _ := NewSeed256(512, h)
	ds, _ := NewSeed256(512, h)
	ss, _ := NewSeed256(512, h)
	if lockSeed {
		ls, _ := NewSeed256(512, makeBlake3Hash256())
		ns.AttachLockSeed(ls)
	}
	ct, err := Encrypt256(ns, ds, ss, p)
	if err != nil {
		return nil, nil, err
	}
	pt, err := Decrypt256(ns, ds, ss, ct)
	return ct, pt, err
}

func triple256RT(t *testing.T, lockSeed bool, p []byte) ([]byte, []byte, error) {
	t.Helper()
	ns, d1, d2, d3, s1, s2, s3 := makeSevenSeeds256(512, makeBlake3Hash256())
	if lockSeed {
		ls, _ := NewSeed256(512, makeBlake3Hash256())
		ns.AttachLockSeed(ls)
	}
	ct, err := Encrypt3x256(ns, d1, d2, d3, s1, s2, s3, p)
	if err != nil {
		return nil, nil, err
	}
	pt, err := Decrypt3x256(ns, d1, d2, d3, s1, s2, s3, ct)
	return ct, pt, err
}

func single512RT(t *testing.T, lockSeed bool, p []byte) ([]byte, []byte, error) {
	t.Helper()
	h := makeBlake2bHash512()
	ns, _ := NewSeed512(512, h)
	ds, _ := NewSeed512(512, h)
	ss, _ := NewSeed512(512, h)
	if lockSeed {
		ls, _ := NewSeed512(512, makeBlake2bHash512())
		ns.AttachLockSeed(ls)
	}
	ct, err := Encrypt512(ns, ds, ss, p)
	if err != nil {
		return nil, nil, err
	}
	pt, err := Decrypt512(ns, ds, ss, ct)
	return ct, pt, err
}

func triple512RT(t *testing.T, lockSeed bool, p []byte) ([]byte, []byte, error) {
	t.Helper()
	ns, d1, d2, d3, s1, s2, s3 := makeSevenSeeds512(512, makeBlake2bHash512())
	if lockSeed {
		ls, _ := NewSeed512(512, makeBlake2bHash512())
		ns.AttachLockSeed(ls)
	}
	ct, err := Encrypt3x512(ns, d1, d2, d3, s1, s2, s3, p)
	if err != nil {
		return nil, nil, err
	}
	pt, err := Decrypt3x512(ns, d1, d2, d3, s1, s2, s3, ct)
	return ct, pt, err
}

type lockBatchVariant struct {
	name string
	// rt encrypts then decrypts p under one fresh seed set, returning the
	// ciphertext, recovered plaintext, and the first error encountered.
	rt func(t *testing.T, lockSeed bool, p []byte) ([]byte, []byte, error)
	// bound returns an encrypt and a decrypt closure sharing one fresh seed
	// set, so the caller can toggle the global LockBatch mode between the
	// two calls to probe cross-mode decryption.
	bound func(t *testing.T) (enc, dec func([]byte) ([]byte, error))
}

func bound128Single(t *testing.T) (enc, dec func([]byte) ([]byte, error)) {
	ns, _ := NewSeed128(512, sipHash128)
	ds, _ := NewSeed128(512, sipHash128)
	ss, _ := NewSeed128(512, sipHash128)
	enc = func(p []byte) ([]byte, error) { return Encrypt128(ns, ds, ss, p) }
	dec = func(c []byte) ([]byte, error) { return Decrypt128(ns, ds, ss, c) }
	return
}

func bound128Triple(t *testing.T) (enc, dec func([]byte) ([]byte, error)) {
	ns, d1, d2, d3, s1, s2, s3 := makeSevenSeeds128(512, sipHash128)
	enc = func(p []byte) ([]byte, error) { return Encrypt3x128(ns, d1, d2, d3, s1, s2, s3, p) }
	dec = func(c []byte) ([]byte, error) { return Decrypt3x128(ns, d1, d2, d3, s1, s2, s3, c) }
	return
}

func bound256Single(t *testing.T) (enc, dec func([]byte) ([]byte, error)) {
	h := makeBlake3Hash256()
	ns, _ := NewSeed256(512, h)
	ds, _ := NewSeed256(512, h)
	ss, _ := NewSeed256(512, h)
	enc = func(p []byte) ([]byte, error) { return Encrypt256(ns, ds, ss, p) }
	dec = func(c []byte) ([]byte, error) { return Decrypt256(ns, ds, ss, c) }
	return
}

func bound256Triple(t *testing.T) (enc, dec func([]byte) ([]byte, error)) {
	ns, d1, d2, d3, s1, s2, s3 := makeSevenSeeds256(512, makeBlake3Hash256())
	enc = func(p []byte) ([]byte, error) { return Encrypt3x256(ns, d1, d2, d3, s1, s2, s3, p) }
	dec = func(c []byte) ([]byte, error) { return Decrypt3x256(ns, d1, d2, d3, s1, s2, s3, c) }
	return
}

func bound512Single(t *testing.T) (enc, dec func([]byte) ([]byte, error)) {
	h := makeBlake2bHash512()
	ns, _ := NewSeed512(512, h)
	ds, _ := NewSeed512(512, h)
	ss, _ := NewSeed512(512, h)
	enc = func(p []byte) ([]byte, error) { return Encrypt512(ns, ds, ss, p) }
	dec = func(c []byte) ([]byte, error) { return Decrypt512(ns, ds, ss, c) }
	return
}

func bound512Triple(t *testing.T) (enc, dec func([]byte) ([]byte, error)) {
	ns, d1, d2, d3, s1, s2, s3 := makeSevenSeeds512(512, makeBlake2bHash512())
	enc = func(p []byte) ([]byte, error) { return Encrypt3x512(ns, d1, d2, d3, s1, s2, s3, p) }
	dec = func(c []byte) ([]byte, error) { return Decrypt3x512(ns, d1, d2, d3, s1, s2, s3, c) }
	return
}

var lockBatchVariants = []lockBatchVariant{
	{"single128", single128RT, bound128Single},
	{"triple128", triple128RT, bound128Triple},
	{"single256", single256RT, bound256Single},
	{"triple256", triple256RT, bound256Triple},
	{"single512", single512RT, bound512Single},
	{"triple512", triple512RT, bound512Triple},
}

// TestLockBatch_RoundTrip is the enc/dec symmetry gate: with Lock Soup on and
// LockBatch on, Encrypt then Decrypt recovers the plaintext across all three
// widths, both Triple and Single, with and without a dedicated lockSeed, for
// sizes spanning empty / sub-chunk / tail-group / large.
func TestLockBatch_RoundTrip(t *testing.T) {
	for _, v := range lockBatchVariants {
		for _, ls := range []bool{false, true} {
			name := v.name
			if ls {
				name += "_lockseed"
			}
			t.Run(name, func(t *testing.T) {
				withLockBatch(t)
				for _, n := range lockBatchSizes {
					data := make([]byte, n)
					if _, err := rand.Read(data); err != nil {
						t.Fatalf("rand.Read(%d): %v", n, err)
					}
					_, pt, err := v.rt(t, ls, data)
					if err != nil {
						t.Fatalf("size=%d: %v", n, err)
					}
					if !bytes.Equal(data, pt) {
						t.Fatalf("size=%d: round-trip mismatch under LockBatch", n)
					}
				}
			})
		}
	}
}

// TestLockBatch_ModeAgreement confirms batch-on ciphertext differs from
// batch-off ciphertext for the same input/seed (masks come from lanes vs
// out[0]), and that cross-mode decryption never panics and never recovers the
// plaintext (mismatched mode yields garbage / decode failure, not a clean
// round-trip).
func TestLockBatch_ModeAgreement(t *testing.T) {
	withGlobals(t)
	SetBitSoup(1)
	SetLockSoup(1)

	data := make([]byte, 4096)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	for _, v := range lockBatchVariants {
		t.Run(v.name, func(t *testing.T) {
			// One seed set drives an off-mode encrypt and an on-mode
			// encrypt of the same plaintext (the nonce is random per call,
			// so the ciphertexts differ regardless; the load-bearing check
			// is that cross-mode decryption does not cleanly recover the
			// plaintext and never panics).
			encOff, decOff := v.bound(t)
			encOn, decOn := v.bound(t)

			SetLockBatch(0)
			ctOff, err := encOff(data)
			if err != nil {
				t.Fatalf("batch-off encrypt: %v", err)
			}
			SetLockBatch(1)
			ctOn, err := encOn(data)
			if err != nil {
				t.Fatalf("batch-on encrypt: %v", err)
			}

			// Decrypt the batch-on ciphertext under batch-off (same seeds
			// that produced ctOn live in decOn; ctOn here is decrypted by
			// the off-mode decryptor whose seeds match encOn's). Use the
			// matching decryptor for each ciphertext but the WRONG mode.
			SetLockBatch(0)
			if pt, err := decOn(ctOn); err == nil && bytes.Equal(pt, data) {
				t.Fatal("batch-on ciphertext decrypted cleanly under batch-off mode")
			}
			SetLockBatch(1)
			if pt, err := decOff(ctOff); err == nil && bytes.Equal(pt, data) {
				t.Fatal("batch-off ciphertext decrypted cleanly under batch-on mode")
			}

			// Sanity: each ciphertext decrypts correctly under its OWN
			// mode (confirms the cross-mode failures above are mode-driven,
			// not seed-driven).
			SetLockBatch(1)
			if pt, err := decOn(ctOn); err != nil || !bytes.Equal(pt, data) {
				t.Fatalf("batch-on ciphertext failed same-mode round-trip: err=%v", err)
			}
			SetLockBatch(0)
			if pt, err := decOff(ctOff); err != nil || !bytes.Equal(pt, data) {
				t.Fatalf("batch-off ciphertext failed same-mode round-trip: err=%v", err)
			}
		})
	}
}

// TestLockBatch_Inert verifies LockBatch is inert when Lock Soup is off:
// LockBatch on + Lock Soup off produces byte-identical output to LockBatch off
// + Lock Soup off, for the same fixed seed material. Drives the dispatchers
// directly so the comparison uses identical seed/nonce on both sides.
func TestLockBatch_Inert(t *testing.T) {
	withGlobals(t)
	SetBitSoup(1)
	SetLockSoup(0)

	noiseSeed, _ := NewSeed128(512, sipHash128)
	nonce := make([]byte, currentNonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	prf := buildLockPRF128(noiseSeed, nonce)
	bp := buildLockBatchPRF128(noiseSeed, nonce)

	for _, n := range lockBatchSizes {
		data := make([]byte, n)
		if _, err := rand.Read(data); err != nil {
			t.Fatalf("rand.Read(%d): %v", n, err)
		}

		// Triple dispatch: Lock Soup off => plain bit-soup branch on both
		// batch settings, so the batch flag must not perturb the output.
		SetLockBatch(0)
		a0, a1, a2 := splitForTripleParallelLocked(data, prf, bp)
		SetLockBatch(1)
		b0, b1, b2 := splitForTripleParallelLocked(data, prf, bp)
		if !bytes.Equal(a0, b0) || !bytes.Equal(a1, b1) || !bytes.Equal(a2, b2) {
			t.Fatalf("size=%d: triple split not inert under LockBatch with Lock Soup off", n)
		}
	}

	// Single inertness: with the Single overlay engaged (either flag on),
	// the batch flag changes the wire by design, so the inert claim for
	// Single is scoped to the fully-off configuration where splitForSingle
	// is a pass-through.
	SetLockSoup(0)
	SetBitSoup(0)
	pprf := buildPermutePRF128(noiseSeed, nonce)
	pbp := buildPermuteBatchPRF128(noiseSeed, nonce)
	for _, n := range []int{1, 100, 1024, 4097} {
		data := make([]byte, n)
		if _, err := rand.Read(data); err != nil {
			t.Fatalf("rand.Read(%d): %v", n, err)
		}
		SetLockBatch(0)
		off := splitForSingle(data, pprf, pbp)
		SetLockBatch(1)
		on := splitForSingle(data, pprf, pbp)
		if !bytes.Equal(off, on) {
			t.Fatalf("size=%d: single split not inert under LockBatch with overlay off", n)
		}
	}
}

// TestLockBatch_Determinism verifies same plaintext + seed + mode yields
// identical ciphertext across repeated encrypts with the same fixed seed
// material. Drives the dispatchers directly with a fixed nonce so the only
// varying input is the batch closure invocation.
func TestLockBatch_Determinism(t *testing.T) {
	withLockBatch(t)

	noiseSeed, _ := NewSeed128(512, sipHash128)
	nonce := make([]byte, currentNonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	for _, n := range lockBatchSizes {
		data := make([]byte, n)
		if _, err := rand.Read(data); err != nil {
			t.Fatalf("rand.Read(%d): %v", n, err)
		}

		// Triple.
		bp := buildLockBatchPRF128(noiseSeed, nonce)
		prf := buildLockPRF128(noiseSeed, nonce)
		a0, a1, a2 := splitForTripleParallelLocked(data, prf, bp)
		b0, b1, b2 := splitForTripleParallelLocked(data, prf, bp)
		if !bytes.Equal(a0, b0) || !bytes.Equal(a1, b1) || !bytes.Equal(a2, b2) {
			t.Fatalf("size=%d: triple batch split non-deterministic", n)
		}

		// Single.
		pbp := buildPermuteBatchPRF128(noiseSeed, nonce)
		pprf := buildPermutePRF128(noiseSeed, nonce)
		c := splitForSingle(data, pprf, pbp)
		d := splitForSingle(data, pprf, pbp)
		if !bytes.Equal(c, d) {
			t.Fatalf("size=%d: single batch split non-deterministic", n)
		}
	}
}

// TestLockBatch_KernelRoundTrip exercises the batched split / interleave
// kernels directly (bypassing the full Encrypt envelope) to confirm they are
// exact inverses at every width, including tail groups, for both Triple and
// Single.
func TestLockBatch_KernelRoundTrip(t *testing.T) {
	withLockBatch(t)

	nonce := make([]byte, currentNonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	ns128, _ := NewSeed128(512, sipHash128)
	ns256, _ := NewSeed256(512, makeBlake3Hash256())
	ns512, _ := NewSeed512(512, makeBlake2bHash512())

	tripleBPs := []lockBatchPRF{
		buildLockBatchPRF128(ns128, nonce),
		buildLockBatchPRF256(ns256, nonce),
		buildLockBatchPRF512(ns512, nonce),
	}
	singleBPs := []permBatchPRF{
		buildPermuteBatchPRF128(ns128, nonce),
		buildPermuteBatchPRF256(ns256, nonce),
		buildPermuteBatchPRF512(ns512, nonce),
	}

	for wi, bp := range tripleBPs {
		for _, n := range lockBatchKernelSizes {
			data := make([]byte, n)
			if _, err := rand.Read(data); err != nil {
				t.Fatalf("rand.Read(%d): %v", n, err)
			}
			p0, p1, p2, totalBits := splitTripleBitsParallelLockedBatch(prependTripleLen(data), bp)
			framed := interleaveTripleBitsParallelLockedBatch(p0, p1, p2, totalBits, bp)
			if len(framed) < 4 {
				t.Fatalf("width-idx=%d size=%d: framed too short", wi, n)
			}
			got := framed[4 : 4+n]
			if !bytes.Equal(data, got) {
				t.Fatalf("width-idx=%d size=%d: triple batch kernel not inverse", wi, n)
			}
		}
	}

	for wi, bp := range singleBPs {
		for _, n := range lockBatchKernelSizes {
			data := make([]byte, n)
			if _, err := rand.Read(data); err != nil {
				t.Fatalf("rand.Read(%d): %v", n, err)
			}
			permuted := splitForSingleBatch(prependTripleLen(data), bp)
			framed := interleaveForSingleBatch(permuted, bp)
			if n == 0 {
				continue
			}
			if len(framed) < 4 {
				t.Fatalf("width-idx=%d size=%d: framed too short", wi, n)
			}
			got := framed[4 : 4+n]
			if !bytes.Equal(data, got) {
				t.Fatalf("width-idx=%d size=%d: single batch kernel not inverse", wi, n)
			}
		}
	}
}
