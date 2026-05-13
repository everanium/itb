package capi

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

// canonical MAC names — matches macs.Registry FFI ordering.
var macNames = []string{"kmac256", "hmac-sha256", "hmac-blake3"}

// hashByWidth picks one PRF-grade hash per ITB key-width axis for
// the Auth integration matrix. Hash choice is incidental to the
// MAC test — we are exercising MAC composition, not hash
// correctness (the hashes/ package round-trips are the authority
// on that).
var hashByWidth = map[int]string{
	128: "siphash24",
	256: "blake3",
	512: "blake2b512",
}

// makeSeed and makeMACKey32 are local helpers used across the Auth
// tests — keeping them small and explicit avoids the temptation to
// share fixtures across goroutines and accidentally re-use the
// same random key path for multiple subtests.
func makeMACKey32(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func newSingleSeeds(t *testing.T, hashName string, keyBits int) (HandleID, HandleID, HandleID) {
	t.Helper()
	mk := func() HandleID {
		id, st := NewSeed(hashName, keyBits)
		if st != StatusOK {
			t.Fatalf("NewSeed(%s, %d): %v", hashName, keyBits, st)
		}
		return id
	}
	return mk(), mk(), mk()
}

func newSevenSeeds(t *testing.T, hashName string, keyBits int) [7]HandleID {
	t.Helper()
	var ids [7]HandleID
	for i := range ids {
		id, st := NewSeed(hashName, keyBits)
		if st != StatusOK {
			t.Fatalf("NewSeed[%d](%s, %d): %v", i, hashName, keyBits, st)
		}
		ids[i] = id
	}
	return ids
}

func freeAll(ids ...HandleID) {
	for _, id := range ids {
		FreeSeed(id)
	}
}

// TestMACRegistry exercises the introspection surface used by the
// FFI ITB_MACCount / ITB_MACName / ITB_MACKeySize / ITB_MACTagSize /
// ITB_MACMinKeyBytes entry points. Mirrors hashes/ TestRegistry.
func TestMACRegistry(t *testing.T) {
	if got := MACCount(); got != 3 {
		t.Fatalf("MACCount = %d, want 3", got)
	}
	for i, want := range macNames {
		if got := MACRegistryName(i); got != want {
			t.Errorf("MACRegistryName(%d) = %q, want %q", i, got, want)
		}
		if got := MACRegistryTagSize(i); got != 32 {
			t.Errorf("MACRegistryTagSize(%d) = %d, want 32", i, got)
		}
		if got := MACRegistryKeySize(i); got != 32 {
			t.Errorf("MACRegistryKeySize(%d) = %d, want 32", i, got)
		}
	}
	for _, badIdx := range []int{-1, 3, 100} {
		if MACRegistryName(badIdx) != "" {
			t.Errorf("MACRegistryName(%d) should be empty", badIdx)
		}
		if MACRegistryTagSize(badIdx) != 0 {
			t.Errorf("MACRegistryTagSize(%d) should be 0", badIdx)
		}
	}
}

// TestMACLifecycle covers NewMAC / FreeMAC / MACName / MACTagSize.
func TestMACLifecycle(t *testing.T) {
	for _, name := range macNames {
		t.Run(name, func(t *testing.T) {
			key := makeMACKey32(t)
			id, st := NewMAC(name, key)
			if st != StatusOK {
				t.Fatalf("NewMAC: %v", st)
			}
			defer FreeMAC(id)
			gotName, st := MACName(id)
			if st != StatusOK || gotName != name {
				t.Errorf("MACName = %q/%v, want %q/OK", gotName, st, name)
			}
			gotSz, st := MACTagSize(id)
			if st != StatusOK || gotSz != 32 {
				t.Errorf("MACTagSize = %d/%v, want 32/OK", gotSz, st)
			}
		})
	}
}

// TestMACBadName verifies that an unknown name returns StatusBadMAC.
func TestMACBadName(t *testing.T) {
	_, st := NewMAC("nonsense-mac", makeMACKey32(t))
	if st != StatusBadMAC {
		t.Errorf("NewMAC(nonsense): %v, want StatusBadMAC", st)
	}
}

// TestMACShortKey verifies that a key shorter than the primitive's
// MinKeyBytes is rejected with StatusBadInput.
func TestMACShortKey(t *testing.T) {
	for _, name := range macNames {
		t.Run(name, func(t *testing.T) {
			_, st := NewMAC(name, []byte{0x01, 0x02})
			if st != StatusBadInput {
				t.Errorf("NewMAC(%s, 2-byte key): %v, want StatusBadInput", name, st)
			}
		})
	}
}

// TestMACDoubleFree confirms the FFI-side double-free path is safe
// (panic from cgo.Handle.Delete is recovered into StatusBadMAC).
func TestMACDoubleFree(t *testing.T) {
	id, _ := NewMAC("hmac-sha256", makeMACKey32(t))
	if st := FreeMAC(id); st != StatusOK {
		t.Fatalf("first FreeMAC: %v", st)
	}
	if st := FreeMAC(id); st != StatusBadMAC {
		t.Errorf("second FreeMAC: %v, want StatusBadMAC", st)
	}
}

// TestEncryptAuthRoundtripAllMACsAllWidths is the central regression
// test for the Single+Auth FFI surface: 3 MACs × 3 hash widths =
// 9 cases of full encrypt → decrypt round trip with bit-flip tamper
// rejection. Bit-flip span covers 256 contiguous bytes after the
// header so the hit guarantee holds regardless of startPixel offset
// (mirrors the macs/ package integration test).
func TestEncryptAuthRoundtripAllMACsAllWidths(t *testing.T) {
	plaintext := make([]byte, 4096)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	for _, macName := range macNames {
		for _, w := range []int{128, 256, 512} {
			hashName := hashByWidth[w]
			t.Run(fmt.Sprintf("%s/%s", macName, hashName), func(t *testing.T) {
				macID, st := NewMAC(macName, makeMACKey32(t))
				if st != StatusOK {
					t.Fatalf("NewMAC: %v", st)
				}
				defer FreeMAC(macID)

				ns, ds, ss := newSingleSeeds(t, hashName, 1024)
				defer freeAll(ns, ds, ss)

				ctBuf := make([]byte, 1<<20)
				ctLen, st := EncryptAuth(ns, ds, ss, macID, plaintext, ctBuf)
				if st != StatusOK {
					t.Fatalf("EncryptAuth: %v", st)
				}

				ptBuf := make([]byte, len(plaintext)+1024)
				ptLen, st := DecryptAuth(ns, ds, ss, macID, ctBuf[:ctLen], ptBuf)
				if st != StatusOK {
					t.Fatalf("DecryptAuth: %v", st)
				}
				if !bytes.Equal(plaintext, ptBuf[:ptLen]) {
					t.Fatalf("plaintext mismatch")
				}

				tampered := append([]byte(nil), ctBuf[:ctLen]...)
				// Default-config header layout: nonce(16) + width(2) + height(2).
				// Tests run with the default SetNonceBits(128); larger nonce
				// sizes would shift this offset (use HeaderSize() if extending
				// the test to non-default configurations).
				const tStart = 16 + 4
				tEnd := tStart + 256
				if tEnd > len(tampered) {
					tEnd = len(tampered)
				}
				for i := tStart; i < tEnd; i++ {
					tampered[i] ^= 0x01
				}
				_, st = DecryptAuth(ns, ds, ss, macID, tampered, ptBuf)
				if st != StatusMACFailure {
					t.Fatalf("tampered DecryptAuth: %v, want StatusMACFailure", st)
				}
			})
		}
	}
}

// TestEncryptAuth3RoundtripAllMACsAllWidths covers Triple+Auth
// (seven seeds + one MAC) across the same 3 × 3 = 9 matrix.
func TestEncryptAuth3RoundtripAllMACsAllWidths(t *testing.T) {
	plaintext := make([]byte, 4096)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	for _, macName := range macNames {
		for _, w := range []int{128, 256, 512} {
			hashName := hashByWidth[w]
			t.Run(fmt.Sprintf("%s/%s", macName, hashName), func(t *testing.T) {
				macID, st := NewMAC(macName, makeMACKey32(t))
				if st != StatusOK {
					t.Fatalf("NewMAC: %v", st)
				}
				defer FreeMAC(macID)

				ids := newSevenSeeds(t, hashName, 1024)
				defer func() {
					for _, id := range ids {
						FreeSeed(id)
					}
				}()

				ctBuf := make([]byte, 1<<20)
				ctLen, st := EncryptAuth3(
					ids[0], ids[1], ids[2], ids[3],
					ids[4], ids[5], ids[6],
					macID, plaintext, ctBuf)
				if st != StatusOK {
					t.Fatalf("EncryptAuth3: %v", st)
				}

				ptBuf := make([]byte, len(plaintext)+1024)
				ptLen, st := DecryptAuth3(
					ids[0], ids[1], ids[2], ids[3],
					ids[4], ids[5], ids[6],
					macID, ctBuf[:ctLen], ptBuf)
				if st != StatusOK {
					t.Fatalf("DecryptAuth3: %v", st)
				}
				if !bytes.Equal(plaintext, ptBuf[:ptLen]) {
					t.Fatalf("plaintext mismatch")
				}

				tampered := append([]byte(nil), ctBuf[:ctLen]...)
				// Default-config header layout: nonce(16) + width(2) + height(2).
				// Tests run with the default SetNonceBits(128); larger nonce
				// sizes would shift this offset (use HeaderSize() if extending
				// the test to non-default configurations).
				const tStart = 16 + 4
				tEnd := tStart + 256
				if tEnd > len(tampered) {
					tEnd = len(tampered)
				}
				for i := tStart; i < tEnd; i++ {
					tampered[i] ^= 0x01
				}
				_, st = DecryptAuth3(
					ids[0], ids[1], ids[2], ids[3],
					ids[4], ids[5], ids[6],
					macID, tampered, ptBuf)
				if st != StatusMACFailure {
					t.Fatalf("tampered DecryptAuth3: %v, want StatusMACFailure", st)
				}
			})
		}
	}
}

// TestEncryptAuthBadMAC verifies that a stale MAC handle is rejected
// at the FFI boundary with StatusBadMAC, before any cipher work.
func TestEncryptAuthBadMAC(t *testing.T) {
	ns, ds, ss := newSingleSeeds(t, "blake3", 1024)
	defer freeAll(ns, ds, ss)

	macID, _ := NewMAC("hmac-sha256", makeMACKey32(t))
	FreeMAC(macID) // immediately stale

	out := make([]byte, 1<<16)
	_, st := EncryptAuth(ns, ds, ss, macID, []byte("hello"), out)
	if st != StatusBadMAC {
		t.Fatalf("EncryptAuth with stale MAC: %v, want StatusBadMAC", st)
	}
}

// TestEncryptAuthSeedWidthMix verifies the seed width-mix check
// fires before the MAC layer is touched.
func TestEncryptAuthSeedWidthMix(t *testing.T) {
	ns128, _ := NewSeed("siphash24", 1024) // width 128
	defer FreeSeed(ns128)
	ds256, _ := NewSeed("blake3", 1024) // width 256
	defer FreeSeed(ds256)
	ss256, _ := NewSeed("blake3", 1024)
	defer FreeSeed(ss256)

	macID, _ := NewMAC("hmac-sha256", makeMACKey32(t))
	defer FreeMAC(macID)

	out := make([]byte, 1<<16)
	_, st := EncryptAuth(ns128, ds256, ss256, macID, []byte("hello"), out)
	if st != StatusSeedWidthMix {
		t.Fatalf("mixed-width EncryptAuth: %v, want StatusSeedWidthMix", st)
	}
}

// TestDecryptAuthCrossMACRejection: encrypt with one MAC, attempt
// decrypt with a different MAC handle (different primitive) — must
// return StatusMACFailure rather than corrupting the plaintext.
// This is the primary defence the FFI surface offers against
// accidental key-swap on the receiving side.
func TestDecryptAuthCrossMACRejection(t *testing.T) {
	ns, ds, ss := newSingleSeeds(t, "blake3", 1024)
	defer freeAll(ns, ds, ss)

	encMAC, _ := NewMAC("kmac256", makeMACKey32(t))
	defer FreeMAC(encMAC)
	decMAC, _ := NewMAC("hmac-sha256", makeMACKey32(t))
	defer FreeMAC(decMAC)

	plaintext := []byte("authenticated payload")
	ctBuf := make([]byte, 1<<16)
	ctLen, st := EncryptAuth(ns, ds, ss, encMAC, plaintext, ctBuf)
	if st != StatusOK {
		t.Fatalf("EncryptAuth: %v", st)
	}

	ptBuf := make([]byte, len(plaintext)+1024)
	_, st = DecryptAuth(ns, ds, ss, decMAC, ctBuf[:ctLen], ptBuf)
	if st != StatusMACFailure {
		t.Fatalf("Cross-MAC decrypt: %v, want StatusMACFailure", st)
	}
}

// TestMACRegistryMinKeyBytesAllIndices iterates every shipped MAC
// primitive and confirms MACRegistryMinKeyBytes returns a strictly
// positive byte count. Currently every MAC in the registry uses a
// 32-byte minimum (binding-fleet discipline) but the test does not
// hardcode the value — it documents that the field is wired through
// and non-zero, leaving the magnitude check to TestMACRegistry.
func TestMACRegistryMinKeyBytesAllIndices(t *testing.T) {
	if MACCount() == 0 {
		t.Fatal("MACCount = 0, no registry entries to probe")
	}
	for i := 0; i < MACCount(); i++ {
		got := MACRegistryMinKeyBytes(i)
		if got <= 0 {
			t.Errorf("MACRegistryMinKeyBytes(%d) = %d, want > 0", i, got)
		}
	}
}

// TestMACRegistryMinKeyBytesOutOfRange covers the i<0 and i>=N
// branches that the per-index loop above does not reach.
func TestMACRegistryMinKeyBytesOutOfRange(t *testing.T) {
	for _, badIdx := range []int{-1, MACCount(), MACCount() + 1, 100} {
		if got := MACRegistryMinKeyBytes(badIdx); got != 0 {
			t.Errorf("MACRegistryMinKeyBytes(%d) = %d, want 0", badIdx, got)
		}
	}
}

// TestEncryptAuthBufferTooSmall exercises the auth-side buffer
// probe path: encrypt into a tiny buffer, confirm the helper
// reports the required size, then retry with the right size.
func TestEncryptAuthBufferTooSmall(t *testing.T) {
	ns, ds, ss := newSingleSeeds(t, "blake3", 1024)
	defer freeAll(ns, ds, ss)
	macID, _ := NewMAC("kmac256", makeMACKey32(t))
	defer FreeMAC(macID)

	plaintext := make([]byte, 256)
	rand.Read(plaintext)

	tiny := make([]byte, 4)
	required, st := EncryptAuth(ns, ds, ss, macID, plaintext, tiny)
	if st != StatusBufferTooSmall {
		t.Fatalf("EncryptAuth tiny: status=%v, want StatusBufferTooSmall", st)
	}
	if required <= len(tiny) {
		t.Errorf("required=%d, want > %d", required, len(tiny))
	}
	full := make([]byte, required)
	got, st := EncryptAuth(ns, ds, ss, macID, plaintext, full)
	if st != StatusOK {
		t.Errorf("sized buffer: status=%v", st)
	}
	if got != required {
		t.Errorf("got=%d, want %d", got, required)
	}
}

// TestEncryptAuth3BufferTooSmall covers the Triple+Auth buffer-probe
// path on the seven-seed dispatcher.
func TestEncryptAuth3BufferTooSmall(t *testing.T) {
	ids := newSevenSeeds(t, "blake3", 1024)
	defer func() {
		for _, id := range ids {
			FreeSeed(id)
		}
	}()
	macID, _ := NewMAC("kmac256", makeMACKey32(t))
	defer FreeMAC(macID)

	plaintext := make([]byte, 256)
	rand.Read(plaintext)

	tiny := make([]byte, 4)
	required, st := EncryptAuth3(ids[0], ids[1], ids[2], ids[3], ids[4], ids[5], ids[6],
		macID, plaintext, tiny)
	if st != StatusBufferTooSmall {
		t.Fatalf("EncryptAuth3 tiny: status=%v, want StatusBufferTooSmall", st)
	}
	full := make([]byte, required)
	_, st = EncryptAuth3(ids[0], ids[1], ids[2], ids[3], ids[4], ids[5], ids[6],
		macID, plaintext, full)
	if st != StatusOK {
		t.Errorf("sized buffer: status=%v", st)
	}
}

// TestDecryptAuth3BufferTooSmall covers the Triple+Auth decrypt-side
// buffer-probe path.
func TestDecryptAuth3BufferTooSmall(t *testing.T) {
	ids := newSevenSeeds(t, "blake3", 1024)
	defer func() {
		for _, id := range ids {
			FreeSeed(id)
		}
	}()
	macID, _ := NewMAC("kmac256", makeMACKey32(t))
	defer FreeMAC(macID)

	plaintext := make([]byte, 256)
	rand.Read(plaintext)

	ctBuf := make([]byte, 1<<16)
	ctLen, _ := EncryptAuth3(ids[0], ids[1], ids[2], ids[3], ids[4], ids[5], ids[6],
		macID, plaintext, ctBuf)

	tiny := make([]byte, 4)
	required, st := DecryptAuth3(ids[0], ids[1], ids[2], ids[3], ids[4], ids[5], ids[6],
		macID, ctBuf[:ctLen], tiny)
	if st != StatusBufferTooSmall {
		t.Errorf("DecryptAuth3 tiny: status=%v, want StatusBufferTooSmall", st)
	}
	if required != len(plaintext) {
		t.Errorf("required=%d, want %d", required, len(plaintext))
	}
}

// TestEncryptStreamAuthBufferTooSmall covers the Stream+Auth Single
// buffer-probe path.
func TestEncryptStreamAuthBufferTooSmall(t *testing.T) {
	ns, ds, ss := newSingleSeeds(t, "blake3", 1024)
	defer freeAll(ns, ds, ss)
	macID, _ := NewMAC("kmac256", makeMACKey32(t))
	defer FreeMAC(macID)

	plaintext := make([]byte, 256)
	rand.Read(plaintext)

	var sid [32]byte
	rand.Read(sid[:])

	tiny := make([]byte, 4)
	required, st := EncryptStreamAuth(ns, ds, ss, macID, plaintext, tiny, sid, 0, true)
	if st != StatusBufferTooSmall {
		t.Errorf("EncryptStreamAuth tiny: status=%v, want StatusBufferTooSmall", st)
	}
	if required <= len(tiny) {
		t.Errorf("required=%d, want > %d", required, len(tiny))
	}
}

// TestEncryptStreamAuth3BufferTooSmall covers the Stream+Auth Triple
// buffer-probe path.
func TestEncryptStreamAuth3BufferTooSmall(t *testing.T) {
	ids := newSevenSeeds(t, "blake3", 1024)
	defer func() {
		for _, id := range ids {
			FreeSeed(id)
		}
	}()
	macID, _ := NewMAC("kmac256", makeMACKey32(t))
	defer FreeMAC(macID)

	plaintext := make([]byte, 256)
	rand.Read(plaintext)
	var sid [32]byte
	rand.Read(sid[:])

	tiny := make([]byte, 4)
	required, st := EncryptStreamAuth3(ids[0], ids[1], ids[2], ids[3], ids[4], ids[5], ids[6],
		macID, plaintext, tiny, sid, 0, true)
	if st != StatusBufferTooSmall {
		t.Errorf("EncryptStreamAuth3 tiny: status=%v, want StatusBufferTooSmall", st)
	}
	full := make([]byte, required)
	if _, st := EncryptStreamAuth3(ids[0], ids[1], ids[2], ids[3], ids[4], ids[5], ids[6],
		macID, plaintext, full, sid, 0, true); st != StatusOK {
		t.Errorf("sized buffer: status=%v", st)
	}
}

// TestDecryptStreamAuth3BufferTooSmall covers the Stream+Auth Triple
// decrypt-side buffer-probe path.
func TestDecryptStreamAuth3BufferTooSmall(t *testing.T) {
	ids := newSevenSeeds(t, "blake3", 1024)
	defer func() {
		for _, id := range ids {
			FreeSeed(id)
		}
	}()
	macID, _ := NewMAC("kmac256", makeMACKey32(t))
	defer FreeMAC(macID)

	plaintext := make([]byte, 256)
	rand.Read(plaintext)
	var sid [32]byte
	rand.Read(sid[:])

	ctBuf := make([]byte, 1<<16)
	ctLen, st := EncryptStreamAuth3(ids[0], ids[1], ids[2], ids[3], ids[4], ids[5], ids[6],
		macID, plaintext, ctBuf, sid, 0, true)
	if st != StatusOK {
		t.Fatalf("EncryptStreamAuth3: status=%v", st)
	}

	tiny := make([]byte, 4)
	required, _, st := DecryptStreamAuth3(ids[0], ids[1], ids[2], ids[3], ids[4], ids[5], ids[6],
		macID, ctBuf[:ctLen], tiny, sid, 0)
	if st != StatusBufferTooSmall {
		t.Errorf("DecryptStreamAuth3 tiny: status=%v, want StatusBufferTooSmall", st)
	}
	if required != len(plaintext) {
		t.Errorf("required=%d, want %d", required, len(plaintext))
	}
}

// TestEncryptAuthBadSeedHandle covers the stale-noise-handle branch
// on EncryptAuth — fails at resolveTriple before the MAC layer.
func TestEncryptAuthBadSeedHandle(t *testing.T) {
	ns := NewSeedOK(t, "blake3", 1024)
	ds := NewSeedOK(t, "blake3", 1024)
	ss := NewSeedOK(t, "blake3", 1024)
	FreeSeed(ns)
	defer FreeSeed(ds)
	defer FreeSeed(ss)
	macID, _ := NewMAC("kmac256", makeMACKey32(t))
	defer FreeMAC(macID)

	out := make([]byte, 1<<16)
	if _, st := EncryptAuth(ns, ds, ss, macID, []byte("test"), out); st != StatusBadHandle {
		t.Errorf("EncryptAuth(stale seed): status=%v, want StatusBadHandle", st)
	}
}

// TestEncryptAuth3BadSeedHandle is the seven-seed variant of
// TestEncryptAuthBadSeedHandle.
func TestEncryptAuth3BadSeedHandle(t *testing.T) {
	ids := newSevenSeeds(t, "blake3", 1024)
	FreeSeed(ids[0]) // stale
	defer func() {
		for _, id := range ids[1:] {
			FreeSeed(id)
		}
	}()
	macID, _ := NewMAC("kmac256", makeMACKey32(t))
	defer FreeMAC(macID)

	out := make([]byte, 1<<16)
	_, st := EncryptAuth3(ids[0], ids[1], ids[2], ids[3], ids[4], ids[5], ids[6],
		macID, []byte("test"), out)
	if st != StatusBadHandle {
		t.Errorf("EncryptAuth3(stale seed): status=%v, want StatusBadHandle", st)
	}
}
