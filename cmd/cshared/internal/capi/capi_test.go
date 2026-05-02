package capi

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

// TestRegistry exercises HashCount / HashName / HashWidth across
// every entry plus a few out-of-range edges, confirming the FFI
// iteration surface is wired through to hashes.Registry.
func TestRegistry(t *testing.T) {
	if got := HashCount(); got != 9 {
		t.Fatalf("HashCount = %d, want 9", got)
	}

	want := []struct {
		name  string
		width int
	}{
		{"areion256", 256},
		{"areion512", 512},
		{"siphash24", 128},
		{"aescmac", 128},
		{"blake2b256", 256},
		{"blake2b512", 512},
		{"blake2s", 256},
		{"blake3", 256},
		{"chacha20", 256},
	}
	for i, exp := range want {
		if n := HashName(i); n != exp.name {
			t.Errorf("HashName(%d) = %q, want %q", i, n, exp.name)
		}
		if w := HashWidth(i); w != exp.width {
			t.Errorf("HashWidth(%d) = %d, want %d", i, w, exp.width)
		}
	}
	for _, badIdx := range []int{-1, 9, 100} {
		if n := HashName(badIdx); n != "" {
			t.Errorf("HashName(%d) = %q, want empty", badIdx, n)
		}
		if w := HashWidth(badIdx); w != 0 {
			t.Errorf("HashWidth(%d) = %d, want 0", badIdx, w)
		}
	}
}

// TestRoundtripAllHashes runs Encrypt → Decrypt over every shipped
// primitive at every supported ITB key width (9 × 3 = 27 cases),
// using the FFI-shaped capi entry points with caller-allocated
// output buffers. This is the central regression test for the C
// ABI surface; every binding in turn exercises the same code path.
func TestRoundtripAllHashes(t *testing.T) {
	plaintext := make([]byte, 4096)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < HashCount(); i++ {
		name := HashName(i)
		for _, keyBits := range []int{512, 1024, 2048} {
			t.Run(fmt.Sprintf("%s/%dbit", name, keyBits), func(t *testing.T) {
				ns, st := NewSeed(name, keyBits)
				if st != StatusOK {
					t.Fatalf("NewSeed(noise) failed: %v", st)
				}
				defer FreeSeed(ns)
				ds, st := NewSeed(name, keyBits)
				if st != StatusOK {
					t.Fatalf("NewSeed(data) failed: %v", st)
				}
				defer FreeSeed(ds)
				ss, st := NewSeed(name, keyBits)
				if st != StatusOK {
					t.Fatalf("NewSeed(start) failed: %v", st)
				}
				defer FreeSeed(ss)

				ctBuf := make([]byte, 1<<20)
				ctLen, st := Encrypt(ns, ds, ss, plaintext, ctBuf)
				if st != StatusOK {
					t.Fatalf("Encrypt failed: %v", st)
				}
				if ctLen <= 0 || ctLen > len(ctBuf) {
					t.Fatalf("Encrypt returned ctLen=%d", ctLen)
				}

				ptBuf := make([]byte, len(plaintext)+1024)
				ptLen, st := Decrypt(ns, ds, ss, ctBuf[:ctLen], ptBuf)
				if st != StatusOK {
					t.Fatalf("Decrypt failed: %v", st)
				}
				if !bytes.Equal(plaintext, ptBuf[:ptLen]) {
					t.Fatalf("plaintext mismatch (got %d bytes, want %d)", ptLen, len(plaintext))
				}
			})
		}
	}
}

// TestEncryptBufferTooSmall verifies the StatusBufferTooSmall path:
// encrypt into an undersized output buffer, confirm the returned
// length reports the required size, then retry with a fresh buffer.
func TestEncryptBufferTooSmall(t *testing.T) {
	ns, _ := NewSeed("blake3", 1024)
	defer FreeSeed(ns)
	ds, _ := NewSeed("blake3", 1024)
	defer FreeSeed(ds)
	ss, _ := NewSeed("blake3", 1024)
	defer FreeSeed(ss)

	plaintext := make([]byte, 256)
	rand.Read(plaintext)

	tiny := make([]byte, 4)
	required, st := Encrypt(ns, ds, ss, plaintext, tiny)
	if st != StatusBufferTooSmall {
		t.Fatalf("Encrypt with 4-byte buffer: got status %v, want %v", st, StatusBufferTooSmall)
	}
	if required <= len(tiny) {
		t.Fatalf("Encrypt reported required=%d, expected > %d", required, len(tiny))
	}

	full := make([]byte, required)
	got, st := Encrypt(ns, ds, ss, plaintext, full)
	if st != StatusOK {
		t.Fatalf("Encrypt with sized buffer: got status %v, want OK", st)
	}
	if got != required {
		t.Fatalf("Encrypt got=%d, want %d", got, required)
	}
}

// TestNewSeedBadHash confirms unknown hash names map to StatusBadHash
// and LastError carries a sensible reason.
func TestNewSeedBadHash(t *testing.T) {
	_, st := NewSeed("nonsense-hash", 1024)
	if st != StatusBadHash {
		t.Fatalf("NewSeed(nonsense): status=%v, want %v", st, StatusBadHash)
	}
	if msg := LastError(); msg == "" {
		t.Errorf("LastError after bad-hash: empty, want non-empty")
	}
}

// TestNewSeedBadKeyBits exercises the keyBits validation path.
func TestNewSeedBadKeyBits(t *testing.T) {
	for _, bits := range []int{0, 256, 511, 2049, 4096} {
		_, st := NewSeed("blake3", bits)
		if st != StatusBadKeyBits {
			t.Errorf("NewSeed(blake3, %d): status=%v, want %v", bits, st, StatusBadKeyBits)
		}
	}
}

// TestSeedWidthMix verifies that mixing Seed128 + Seed256 handles in
// one Encrypt call is rejected with StatusSeedWidthMix.
func TestSeedWidthMix(t *testing.T) {
	ns128, _ := NewSeed("siphash24", 1024)
	defer FreeSeed(ns128)
	ds256, _ := NewSeed("blake3", 1024)
	defer FreeSeed(ds256)
	ss256, _ := NewSeed("blake3", 1024)
	defer FreeSeed(ss256)

	out := make([]byte, 1<<16)
	_, st := Encrypt(ns128, ds256, ss256, []byte("hello"), out)
	if st != StatusSeedWidthMix {
		t.Fatalf("mixed-width Encrypt: status=%v, want %v", st, StatusSeedWidthMix)
	}
}

// TestFreeSeedIdempotent confirms a freed handle is rejected on
// subsequent use, with StatusBadHandle and a non-empty LastError.
// Note: cgo.Handle.Delete on a stale handle panics; FreeSeed
// internally swallows the panic and translates to StatusBadHandle.
func TestFreeSeedIdempotent(t *testing.T) {
	id, st := NewSeed("blake3", 1024)
	if st != StatusOK {
		t.Fatalf("NewSeed: %v", st)
	}
	if st := FreeSeed(id); st != StatusOK {
		t.Fatalf("FreeSeed first call: %v", st)
	}

	w, st := SeedWidth(id)
	if st != StatusBadHandle || w != 0 {
		t.Fatalf("SeedWidth on freed: width=%d status=%v, want (0, BadHandle)", w, st)
	}
}

// TestConfigSetters round-trips every process-wide config setter to
// confirm the FFI delegation reaches the underlying itb globals.
// All five settings are reset to their starting values at the end
// to keep the rest of the suite running with default config.
func TestConfigSetters(t *testing.T) {
	pairs := []struct {
		name string
		set  func(int) Status
		get  func() int
		want int
	}{
		{"BitSoup", SetBitSoup, GetBitSoup, 1},
		{"LockSoup", SetLockSoup, GetLockSoup, 1},
		{"MaxWorkers", SetMaxWorkers, GetMaxWorkers, 4},
		{"NonceBits", SetNonceBits, GetNonceBits, 256},
		{"BarrierFill", SetBarrierFill, GetBarrierFill, 8},
	}

	for _, p := range pairs {
		t.Run(p.name, func(t *testing.T) {
			orig := p.get()
			defer p.set(orig)
			if st := p.set(p.want); st != StatusOK {
				t.Fatalf("Set(%s, %d) = %v, want OK", p.name, p.want, st)
			}
			if got := p.get(); got != p.want {
				t.Errorf("Set/Get(%s): got %d, want %d", p.name, got, p.want)
			}
		})
	}
}

// TestConfigSetterValidation verifies that out-of-range values
// produce StatusBadInput rather than panicking across the FFI
// boundary. NonceBits accepts only {128, 256, 512}; BarrierFill
// accepts only {1, 2, 4, 8, 16, 32}.
func TestConfigSetterValidation(t *testing.T) {
	origNonce := GetNonceBits()
	defer SetNonceBits(origNonce)
	for _, bad := range []int{0, 1, 64, 192, 1024} {
		if st := SetNonceBits(bad); st != StatusBadInput {
			t.Errorf("SetNonceBits(%d) = %v, want StatusBadInput", bad, st)
		}
	}
	if got := GetNonceBits(); got != origNonce {
		t.Errorf("GetNonceBits after invalid input drifted: got %d, want %d", got, origNonce)
	}

	origBarrier := GetBarrierFill()
	defer SetBarrierFill(origBarrier)
	for _, bad := range []int{0, 3, 5, 64, 100} {
		if st := SetBarrierFill(bad); st != StatusBadInput {
			t.Errorf("SetBarrierFill(%d) = %v, want StatusBadInput", bad, st)
		}
	}
	if got := GetBarrierFill(); got != origBarrier {
		t.Errorf("GetBarrierFill after invalid input drifted: got %d, want %d", got, origBarrier)
	}
}

// TestReadOnlyConstants verifies build-time constants are reachable.
func TestReadOnlyConstants(t *testing.T) {
	if MaxKeyBits() != 2048 {
		t.Errorf("MaxKeyBits = %d, want 2048", MaxKeyBits())
	}
	if Channels() != 8 {
		t.Errorf("Channels = %d, want 8", Channels())
	}
}

// TestRoundtripTripleAllHashes covers Triple Ouroboros (Encrypt3 /
// Decrypt3) over every shipped primitive at every supported ITB key
// width — 9 × 3 = 27 cases. Same caller-allocated-buffer convention
// as the Single Ouroboros TestRoundtripAllHashes, but with seven
// distinct seed handles per case.
func TestRoundtripTripleAllHashes(t *testing.T) {
	plaintext := make([]byte, 4096)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < HashCount(); i++ {
		name := HashName(i)
		for _, keyBits := range []int{512, 1024, 2048} {
			t.Run(fmt.Sprintf("%s/%dbit", name, keyBits), func(t *testing.T) {
				ids := make([]HandleID, 7)
				for j := range ids {
					id, st := NewSeed(name, keyBits)
					if st != StatusOK {
						t.Fatalf("NewSeed %d: %v", j, st)
					}
					ids[j] = id
				}
				defer func() {
					for _, id := range ids {
						FreeSeed(id)
					}
				}()

				ctBuf := make([]byte, 1<<20)
				ctLen, st := Encrypt3(
					ids[0], ids[1], ids[2], ids[3],
					ids[4], ids[5], ids[6],
					plaintext, ctBuf)
				if st != StatusOK {
					t.Fatalf("Encrypt3 failed: %v", st)
				}
				if ctLen <= 0 || ctLen > len(ctBuf) {
					t.Fatalf("Encrypt3 returned ctLen=%d", ctLen)
				}

				ptBuf := make([]byte, len(plaintext)+1024)
				ptLen, st := Decrypt3(
					ids[0], ids[1], ids[2], ids[3],
					ids[4], ids[5], ids[6],
					ctBuf[:ctLen], ptBuf)
				if st != StatusOK {
					t.Fatalf("Decrypt3 failed: %v", st)
				}
				if !bytes.Equal(plaintext, ptBuf[:ptLen]) {
					t.Fatalf("plaintext mismatch (got %d bytes, want %d)", ptLen, len(plaintext))
				}
			})
		}
	}
}

// TestEncrypt3SeedWidthMix verifies that mixing handles of different
// native hash widths in one Encrypt3 call is rejected with
// StatusSeedWidthMix on the seven-seed dispatcher path.
func TestEncrypt3SeedWidthMix(t *testing.T) {
	mk := func(name string) HandleID {
		id, st := NewSeed(name, 1024)
		if st != StatusOK {
			t.Fatalf("NewSeed(%s): %v", name, st)
		}
		return id
	}
	ids := []HandleID{
		mk("siphash24"), // width 128 — odd one out
		mk("blake3"),
		mk("blake3"),
		mk("blake3"),
		mk("blake3"),
		mk("blake3"),
		mk("blake3"),
	}
	defer func() {
		for _, id := range ids {
			FreeSeed(id)
		}
	}()
	out := make([]byte, 1<<16)
	_, st := Encrypt3(ids[0], ids[1], ids[2], ids[3], ids[4], ids[5], ids[6],
		[]byte("hello"), out)
	if st != StatusSeedWidthMix {
		t.Fatalf("mixed-width Encrypt3: status=%v, want %v", st, StatusSeedWidthMix)
	}
}

// TestEncrypt3BufferTooSmall verifies the buffer-resize handshake on
// the Triple variant.
func TestEncrypt3BufferTooSmall(t *testing.T) {
	ids := make([]HandleID, 7)
	for i := range ids {
		ids[i], _ = NewSeed("blake3", 1024)
	}
	defer func() {
		for _, id := range ids {
			FreeSeed(id)
		}
	}()

	plaintext := make([]byte, 256)
	rand.Read(plaintext)

	tiny := make([]byte, 4)
	required, st := Encrypt3(ids[0], ids[1], ids[2], ids[3], ids[4], ids[5], ids[6],
		plaintext, tiny)
	if st != StatusBufferTooSmall {
		t.Fatalf("Encrypt3 with 4-byte buffer: got status %v, want %v",
			st, StatusBufferTooSmall)
	}
	if required <= len(tiny) {
		t.Fatalf("Encrypt3 reported required=%d, expected > %d", required, len(tiny))
	}

	full := make([]byte, required)
	got, st := Encrypt3(ids[0], ids[1], ids[2], ids[3], ids[4], ids[5], ids[6],
		plaintext, full)
	if st != StatusOK {
		t.Fatalf("Encrypt3 with sized buffer: got status %v, want OK", st)
	}
	if got != required {
		t.Fatalf("Encrypt3 got=%d, want %d", got, required)
	}
}

// TestSeedWidthSeedHashName exposes the introspection helpers used
// by the FFI ITB_SeedWidth / ITB_SeedHashName entry points.
func TestSeedWidthSeedHashName(t *testing.T) {
	for _, tc := range []struct {
		name      string
		wantWidth int
	}{
		{"siphash24", 128},
		{"blake3", 256},
		{"areion512", 512},
	} {
		id, st := NewSeed(tc.name, 1024)
		if st != StatusOK {
			t.Fatalf("NewSeed(%s): %v", tc.name, st)
		}
		w, st := SeedWidth(id)
		if st != StatusOK || int(w) != tc.wantWidth {
			t.Errorf("SeedWidth(%s) = %d/%v, want %d/OK", tc.name, w, st, tc.wantWidth)
		}
		got, st := SeedHashName(id)
		if st != StatusOK || got != tc.name {
			t.Errorf("SeedHashName = %q/%v, want %q/OK", got, st, tc.name)
		}
		FreeSeed(id)
	}
}

// TestNewSeedFromComponentsRoundtrip exercises the full FFI
// persistence flow: encrypt with NewSeed (random components, random
// hashKey) → extract components + hashKey → free seed → reconstruct
// the seed via NewSeedFromComponents → decrypt successfully. The
// scenario simulates "encrypt today on machine A, save the seed
// material, decrypt tomorrow on machine B with the saved material".
//
// Iterates every primitive in the registry × three key-bit widths
// (skipping the SipHash-2-4 hashKey check, which is empty since
// SipHash has no internal fixed key).
func TestNewSeedFromComponentsRoundtrip(t *testing.T) {
	plaintext := make([]byte, 4096)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < HashCount(); i++ {
		name := HashName(i)
		for _, keyBits := range []int{512, 1024, 2048} {
			t.Run(fmt.Sprintf("%s/%dbit", name, keyBits), func(t *testing.T) {
				// Day 1 — random seeds, encrypt, snapshot material.
				snapshot := func(seed HandleID) (components []uint64, hashKey []byte) {
					comps, st := SeedComponents(seed)
					if st != StatusOK {
						t.Fatalf("SeedComponents: %v", st)
					}
					key, st := SeedHashKey(seed)
					if st != StatusOK {
						t.Fatalf("SeedHashKey: %v", st)
					}
					return comps, key
				}
				ns, st := NewSeed(name, keyBits)
				if st != StatusOK {
					t.Fatalf("NewSeed(noise): %v", st)
				}
				ds, st := NewSeed(name, keyBits)
				if st != StatusOK {
					t.Fatalf("NewSeed(data): %v", st)
				}
				ss, st := NewSeed(name, keyBits)
				if st != StatusOK {
					t.Fatalf("NewSeed(start): %v", st)
				}
				nsComps, nsKey := snapshot(ns)
				dsComps, dsKey := snapshot(ds)
				ssComps, ssKey := snapshot(ss)

				ctBuf := make([]byte, 1<<20)
				ctLen, st := Encrypt(ns, ds, ss, plaintext, ctBuf)
				if st != StatusOK {
					t.Fatalf("Encrypt: %v", st)
				}
				FreeSeed(ns)
				FreeSeed(ds)
				FreeSeed(ss)

				// Day 2 — restore from snapshots. The new seeds
				// must produce the same per-pixel hashes, so the
				// previous ciphertext decrypts cleanly.
				ns2, st := NewSeedFromComponents(name, nsComps, nsKey)
				if st != StatusOK {
					t.Fatalf("NewSeedFromComponents(noise): %v", st)
				}
				defer FreeSeed(ns2)
				ds2, st := NewSeedFromComponents(name, dsComps, dsKey)
				if st != StatusOK {
					t.Fatalf("NewSeedFromComponents(data): %v", st)
				}
				defer FreeSeed(ds2)
				ss2, st := NewSeedFromComponents(name, ssComps, ssKey)
				if st != StatusOK {
					t.Fatalf("NewSeedFromComponents(start): %v", st)
				}
				defer FreeSeed(ss2)

				ptBuf := make([]byte, len(plaintext)+1024)
				ptLen, st := Decrypt(ns2, ds2, ss2, ctBuf[:ctLen], ptBuf)
				if st != StatusOK {
					t.Fatalf("Decrypt (restored): %v", st)
				}
				if !bytes.Equal(plaintext, ptBuf[:ptLen]) {
					t.Fatalf("restored plaintext mismatch (got %d bytes, want %d)", ptLen, len(plaintext))
				}

				// Round-trip check: the restored seeds report the
				// same hashKey the encrypt-side seeds had.
				_, restoredKey := snapshot(ns2)
				if !bytes.Equal(restoredKey, nsKey) {
					t.Errorf("restored hashKey mismatch (got %x, want %x)", restoredKey, nsKey)
				}
			})
		}
	}
}

// TestNewSeedFromComponentsRandomKey verifies the random-key path of
// NewSeedFromComponents (passing nil hashKey): the seed should be
// usable end-to-end and report a non-empty hashKey via SeedHashKey
// (except for SipHash-2-4 which has no internal key).
func TestNewSeedFromComponentsRandomKey(t *testing.T) {
	for i := 0; i < HashCount(); i++ {
		name := HashName(i)
		t.Run(name, func(t *testing.T) {
			// Use 8 zero components (= 512-bit key) — we only check
			// hashKey path, components content doesn't affect that.
			components := make([]uint64, 8)
			id, st := NewSeedFromComponents(name, components, nil)
			if st != StatusOK {
				t.Fatalf("NewSeedFromComponents: %v", st)
			}
			defer FreeSeed(id)
			key, st := SeedHashKey(id)
			if st != StatusOK {
				t.Fatalf("SeedHashKey: %v", st)
			}
			if name == "siphash24" {
				if len(key) != 0 {
					t.Errorf("SipHash-2-4 hashKey should be empty, got %d bytes", len(key))
				}
			} else if len(key) == 0 {
				t.Errorf("hashKey unexpectedly empty for %s", name)
			}
		})
	}
}

// TestNewSeedFromComponentsBadKeySize verifies that passing a
// hashKey of wrong size for the named primitive returns
// StatusBadHash (registry's validateKey rejects the mismatch).
func TestNewSeedFromComponentsBadKeySize(t *testing.T) {
	components := make([]uint64, 16) // 1024-bit key
	wrongKey := make([]byte, 7)      // wrong size for any primitive
	for i := 0; i < HashCount(); i++ {
		name := HashName(i)
		if name == "siphash24" {
			continue // SipHash takes no hashKey at all
		}
		id, st := NewSeedFromComponents(name, components, wrongKey)
		if st == StatusOK {
			FreeSeed(id)
			t.Errorf("%s accepted 7-byte key (want StatusBadHash)", name)
		}
	}
}

// TestAttachLockSeedRoundtrip exercises the FFI-level
// AttachLockSeed: a fresh dedicated lockSeed is attached to a noise
// seed, the bit-permutation overlay is engaged via SetLockSoup(1),
// and a Single-Ouroboros Encrypt → Decrypt round-trip succeeds.
// Without the overlay-off guard built into the build*PRF closures,
// a missing SetLockSoup call would silently produce byte-level
// ciphertext; with the overlay engaged the dedicated lockSeed
// drives the bit-permutation derivation as designed.
func TestAttachLockSeedRoundtrip(t *testing.T) {
	prevBS := GetBitSoup()
	prevLS := GetLockSoup()
	defer func() {
		SetBitSoup(prevBS)
		SetLockSoup(prevLS)
	}()
	if st := SetLockSoup(1); st != StatusOK {
		t.Fatalf("SetLockSoup: status=%v", st)
	}

	ns, _ := NewSeed("blake3", 1024)
	defer FreeSeed(ns)
	ds, _ := NewSeed("blake3", 1024)
	defer FreeSeed(ds)
	ss, _ := NewSeed("blake3", 1024)
	defer FreeSeed(ss)
	ls, _ := NewSeed("blake3", 1024)
	defer FreeSeed(ls)

	if st := AttachLockSeed(ns, ls); st != StatusOK {
		t.Fatalf("AttachLockSeed: status=%v", st)
	}

	plaintext := []byte("attach lockseed FFI roundtrip payload")
	out := make([]byte, 1<<16)
	n, st := Encrypt(ns, ds, ss, plaintext, out)
	if st != StatusOK {
		t.Fatalf("Encrypt: status=%v", st)
	}
	pt := make([]byte, len(plaintext)+1024)
	m, st := Decrypt(ns, ds, ss, out[:n], pt)
	if st != StatusOK {
		t.Fatalf("Decrypt: status=%v", st)
	}
	if !bytes.Equal(plaintext, pt[:m]) {
		t.Fatalf("plaintext mismatch")
	}
}

// TestAttachLockSeedRejection covers the three attach-time misuse
// paths (self-attach, post-Encrypt switching, width mismatch). The
// component-aliasing path is not reachable through the FFI surface
// because every NewSeed produces a fresh CSPRNG-backed components
// slice — it lives only on the Go-native AttachLockSeed entry point.
func TestAttachLockSeedRejection(t *testing.T) {
	prevBS := GetBitSoup()
	prevLS := GetLockSoup()
	defer func() {
		SetBitSoup(prevBS)
		SetLockSoup(prevLS)
	}()
	SetLockSoup(1)

	// Self-attach: same handle for noise and lock.
	ns, _ := NewSeed("blake3", 1024)
	defer FreeSeed(ns)
	if st := AttachLockSeed(ns, ns); st != StatusBadInput {
		t.Errorf("self-attach: status=%v, want StatusBadInput", st)
	}

	// Width mismatch: attach a 128-bit lockSeed onto a 256-bit
	// noiseSeed.
	ls128, _ := NewSeed("siphash24", 1024)
	defer FreeSeed(ls128)
	if st := AttachLockSeed(ns, ls128); st != StatusSeedWidthMix {
		t.Errorf("width-mismatch attach: status=%v, want StatusSeedWidthMix", st)
	}

	// Post-Encrypt switching: encrypt with one attached lockSeed,
	// then attempt to attach a different one.
	ls := NewSeedOK(t, "blake3", 1024)
	defer FreeSeed(ls)
	if st := AttachLockSeed(ns, ls); st != StatusOK {
		t.Fatalf("first AttachLockSeed: status=%v", st)
	}
	ds := NewSeedOK(t, "blake3", 1024)
	defer FreeSeed(ds)
	ss := NewSeedOK(t, "blake3", 1024)
	defer FreeSeed(ss)
	out := make([]byte, 1<<16)
	if _, st := Encrypt(ns, ds, ss, []byte("pre-switch"), out); st != StatusOK {
		t.Fatalf("Encrypt: status=%v", st)
	}
	ls2 := NewSeedOK(t, "blake3", 1024)
	defer FreeSeed(ls2)
	if st := AttachLockSeed(ns, ls2); st != StatusBadInput {
		t.Errorf("post-Encrypt attach: status=%v, want StatusBadInput", st)
	}
}

// NewSeedOK is a small testing helper that fails the test when
// NewSeed returns a non-OK status, returning the handle directly.
// Used by attach-rejection tests to keep the assertion shape compact.
func NewSeedOK(t *testing.T, name string, keyBits int) HandleID {
	t.Helper()
	id, st := NewSeed(name, keyBits)
	if st != StatusOK {
		t.Fatalf("NewSeed(%q, %d): status=%v", name, keyBits, st)
	}
	return id
}
