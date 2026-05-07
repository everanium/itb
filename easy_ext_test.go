package itb_test

import (
	"bytes"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/easy"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/macs"
)

// reconstructSeeds128 rebuilds *itb.Seed128 pointers from the
// component vectors exposed by [easy.Encryptor.SeedComponents]. The
// hash factory must match the encryptor's primitive — these tests pin
// the encryptor to "siphash24" for the 128-bit width since SipHash-2-4
// has no fixed PRF key (the per-call seed components are the sole
// keying material), which makes the reconstruction straightforward
// and avoids cross-key-channel divergence between the two surfaces.
func reconstructSeeds128(t *testing.T, components [][]uint64) []*itb.Seed128 {
	t.Helper()
	h := hashes.SipHash24()
	out := make([]*itb.Seed128, len(components))
	for i, c := range components {
		seed, err := itb.SeedFromComponents128(h, c...)
		if err != nil {
			t.Fatalf("SeedFromComponents128: %v", err)
		}
		out[i] = seed
	}
	return out
}

// macFromKey rebuilds the encryptor's MACFunc from its exposed MAC
// key, using the registered HMAC-BLAKE3 factory. easy.Encryptor binds
// HMAC-BLAKE3 by default; the parity tests stay on that default to
// keep the reconstruction one-line.
func macFromKey(t *testing.T, key []byte) itb.MACFunc {
	t.Helper()
	mac, err := macs.HMACBLAKE3(key)
	if err != nil {
		t.Fatalf("macs.HMACBLAKE3: %v", err)
	}
	return mac
}

// TestExtEasyEncryptAuthDecodableByLowLevel encrypts via the easy
// surface (Encryptor.EncryptAuth) and decrypts via the width-less
// itb.DecryptAuth. The reconstructed low-level seeds + MAC must
// produce the same recovered plaintext, confirming the two surfaces
// share one wire format under a default configuration snapshot.
func TestExtEasyEncryptAuthDecodableByLowLevel(t *testing.T) {
	enc := easy.New("siphash24", 1024, "hmac-blake3")
	defer enc.Close()

	pt := genTestPlaintextExt(t, 4096)
	ct, err := enc.EncryptAuth(pt)
	if err != nil {
		t.Fatalf("easy.EncryptAuth: %v", err)
	}

	seeds := reconstructSeeds128(t, enc.SeedComponents())
	if len(seeds) != 3 {
		t.Fatalf("Single-mode reconstruct: want 3 seeds, got %d", len(seeds))
	}
	mac := macFromKey(t, enc.MACKey())

	out, err := itb.DecryptAuth(seeds[0], seeds[1], seeds[2], ct, mac)
	if err != nil {
		t.Fatalf("itb.DecryptAuth: %v", err)
	}
	if !bytes.Equal(out, pt) {
		t.Fatalf("Single parity: easy-encrypt -> low-level-decrypt mismatch")
	}
}

// TestExtLowLevelEncryptAuthDecodableByEasy reverses the parity
// direction: encrypt via the width-less itb.EncryptAuth on the
// reconstructed seeds + MAC, decrypt via easy.Encryptor.DecryptAuth
// on the same encryptor instance.
func TestExtLowLevelEncryptAuthDecodableByEasy(t *testing.T) {
	enc := easy.New("siphash24", 1024, "hmac-blake3")
	defer enc.Close()

	seeds := reconstructSeeds128(t, enc.SeedComponents())
	mac := macFromKey(t, enc.MACKey())

	pt := genTestPlaintextExt(t, 4096)
	ct, err := itb.EncryptAuth(seeds[0], seeds[1], seeds[2], pt, mac)
	if err != nil {
		t.Fatalf("itb.EncryptAuth: %v", err)
	}

	out, err := enc.DecryptAuth(ct)
	if err != nil {
		t.Fatalf("easy.DecryptAuth: %v", err)
	}
	if !bytes.Equal(out, pt) {
		t.Fatalf("Single parity: low-level-encrypt -> easy-decrypt mismatch")
	}
}

// TestExtEasyEncrypt3xAuthDecodableByLowLevel — Triple Ouroboros
// counterpart of [TestExtEasyEncryptAuthDecodableByLowLevel]. The
// 7-seed reconstruction follows the canonical [noise, data1, data2,
// data3, start1, start2, start3] order shipped through
// [easy.Encryptor.SeedComponents].
func TestExtEasyEncrypt3xAuthDecodableByLowLevel(t *testing.T) {
	enc := easy.New3("siphash24", 1024, "hmac-blake3")
	defer enc.Close()

	pt := genTestPlaintextExt(t, 4096)
	ct, err := enc.EncryptAuth(pt)
	if err != nil {
		t.Fatalf("easy.EncryptAuth (Triple): %v", err)
	}

	seeds := reconstructSeeds128(t, enc.SeedComponents())
	if len(seeds) != 7 {
		t.Fatalf("Triple reconstruct: want 7 seeds, got %d", len(seeds))
	}
	mac := macFromKey(t, enc.MACKey())

	out, err := itb.DecryptAuth3x(seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], ct, mac)
	if err != nil {
		t.Fatalf("itb.DecryptAuth3x: %v", err)
	}
	if !bytes.Equal(out, pt) {
		t.Fatalf("Triple parity: easy-encrypt -> low-level-decrypt mismatch")
	}
}

// TestExtLowLevelEncrypt3xAuthDecodableByEasy reverses the parity
// direction for the Triple variant.
func TestExtLowLevelEncrypt3xAuthDecodableByEasy(t *testing.T) {
	enc := easy.New3("siphash24", 1024, "hmac-blake3")
	defer enc.Close()

	seeds := reconstructSeeds128(t, enc.SeedComponents())
	mac := macFromKey(t, enc.MACKey())

	pt := genTestPlaintextExt(t, 4096)
	ct, err := itb.EncryptAuth3x(seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], pt, mac)
	if err != nil {
		t.Fatalf("itb.EncryptAuth3x: %v", err)
	}
	out, err := enc.DecryptAuth(ct)
	if err != nil {
		t.Fatalf("easy.DecryptAuth (Triple): %v", err)
	}
	if !bytes.Equal(out, pt) {
		t.Fatalf("Triple parity: low-level-encrypt -> easy-decrypt mismatch")
	}
}

// TestExtEasyEncryptStreamAuthDecodableByLowLevel — Streaming AEAD
// parity test: encrypt via [easy.Encryptor.EncryptStreamAuth],
// reconstruct seeds + MAC from the encryptor, decrypt via the
// width-less [itb.DecryptStreamAuth].
func TestExtEasyEncryptStreamAuthDecodableByLowLevel(t *testing.T) {
	enc := easy.New("siphash24", 1024, "hmac-blake3")
	defer enc.Close()

	pt := genTestPlaintextExt(t, 3*4096)
	var ctBuf bytes.Buffer
	emit := func(chunk []byte) error {
		_, err := ctBuf.Write(chunk)
		return err
	}
	if err := enc.EncryptStreamAuth(pt, emit); err != nil {
		t.Fatalf("easy.EncryptStreamAuth: %v", err)
	}

	seeds := reconstructSeeds128(t, enc.SeedComponents())
	mac := macFromKey(t, enc.MACKey())

	var ptBuf bytes.Buffer
	if err := itb.DecryptStreamAuth(seeds[0], seeds[1], seeds[2], bytes.NewReader(ctBuf.Bytes()), &ptBuf, mac); err != nil {
		t.Fatalf("itb.DecryptStreamAuth: %v", err)
	}
	if !bytes.Equal(ptBuf.Bytes(), pt) {
		t.Fatalf("Single stream parity: easy-encrypt -> low-level-decrypt mismatch (got %d bytes, want %d)", ptBuf.Len(), len(pt))
	}
}

// TestExtLowLevelEncryptStreamAuthDecodableByEasy — reverse-direction
// Streaming AEAD parity test.
func TestExtLowLevelEncryptStreamAuthDecodableByEasy(t *testing.T) {
	enc := easy.New("siphash24", 1024, "hmac-blake3")
	defer enc.Close()

	seeds := reconstructSeeds128(t, enc.SeedComponents())
	mac := macFromKey(t, enc.MACKey())

	pt := genTestPlaintextExt(t, 3*4096)
	var ctBuf bytes.Buffer
	if err := itb.EncryptStreamAuth(seeds[0], seeds[1], seeds[2], bytes.NewReader(pt), &ctBuf, mac, 4096); err != nil {
		t.Fatalf("itb.EncryptStreamAuth: %v", err)
	}

	var ptBuf bytes.Buffer
	emit := func(chunk []byte) error {
		_, err := ptBuf.Write(chunk)
		return err
	}
	if err := enc.DecryptStreamAuth(ctBuf.Bytes(), emit); err != nil {
		t.Fatalf("easy.DecryptStreamAuth: %v", err)
	}
	if !bytes.Equal(ptBuf.Bytes(), pt) {
		t.Fatalf("Single stream parity: low-level-encrypt -> easy-decrypt mismatch")
	}
}

// TestExtEasyEncryptStream3xAuthDecodableByLowLevel — Triple
// counterpart of the Streaming AEAD parity test.
func TestExtEasyEncryptStream3xAuthDecodableByLowLevel(t *testing.T) {
	enc := easy.New3("siphash24", 1024, "hmac-blake3")
	defer enc.Close()

	pt := genTestPlaintextExt(t, 3*4096)
	var ctBuf bytes.Buffer
	emit := func(chunk []byte) error {
		_, err := ctBuf.Write(chunk)
		return err
	}
	if err := enc.EncryptStreamAuth(pt, emit); err != nil {
		t.Fatalf("easy.EncryptStreamAuth (Triple): %v", err)
	}

	seeds := reconstructSeeds128(t, enc.SeedComponents())
	mac := macFromKey(t, enc.MACKey())

	var ptBuf bytes.Buffer
	if err := itb.DecryptStreamAuth3x(seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], bytes.NewReader(ctBuf.Bytes()), &ptBuf, mac); err != nil {
		t.Fatalf("itb.DecryptStreamAuth3x: %v", err)
	}
	if !bytes.Equal(ptBuf.Bytes(), pt) {
		t.Fatalf("Triple stream parity: easy-encrypt -> low-level-decrypt mismatch")
	}
}

// TestExtLowLevelEncryptStream3xAuthDecodableByEasy — reverse
// direction.
func TestExtLowLevelEncryptStream3xAuthDecodableByEasy(t *testing.T) {
	enc := easy.New3("siphash24", 1024, "hmac-blake3")
	defer enc.Close()

	seeds := reconstructSeeds128(t, enc.SeedComponents())
	mac := macFromKey(t, enc.MACKey())

	pt := genTestPlaintextExt(t, 3*4096)
	var ctBuf bytes.Buffer
	if err := itb.EncryptStreamAuth3x(seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], bytes.NewReader(pt), &ctBuf, mac, 4096); err != nil {
		t.Fatalf("itb.EncryptStreamAuth3x: %v", err)
	}

	var ptBuf bytes.Buffer
	emit := func(chunk []byte) error {
		_, err := ptBuf.Write(chunk)
		return err
	}
	if err := enc.DecryptStreamAuth(ctBuf.Bytes(), emit); err != nil {
		t.Fatalf("easy.DecryptStreamAuth (Triple): %v", err)
	}
	if !bytes.Equal(ptBuf.Bytes(), pt) {
		t.Fatalf("Triple stream parity: low-level-encrypt -> easy-decrypt mismatch")
	}
}

// TestExtEasyEncryptDecodableByLowLevelPlain — plain-mode parity
// test (no MAC). Verifies the width-less itb.Decrypt and the
// easy.Encryptor.Decrypt path agree on the wire format under a
// default configuration snapshot.
func TestExtEasyEncryptDecodableByLowLevelPlain(t *testing.T) {
	enc := easy.New("siphash24", 1024, "hmac-blake3")
	defer enc.Close()

	pt := genTestPlaintextExt(t, 4096)
	ct, err := enc.Encrypt(pt)
	if err != nil {
		t.Fatalf("easy.Encrypt: %v", err)
	}

	seeds := reconstructSeeds128(t, enc.SeedComponents())
	out, err := itb.Decrypt(seeds[0], seeds[1], seeds[2], ct)
	if err != nil {
		t.Fatalf("itb.Decrypt: %v", err)
	}
	if !bytes.Equal(out, pt) {
		t.Fatalf("Single plain parity: easy-encrypt -> low-level-decrypt mismatch")
	}
}

// TestExtLowLevelEncryptDecodableByEasyPlain — reverse direction for
// the plain-mode parity test.
func TestExtLowLevelEncryptDecodableByEasyPlain(t *testing.T) {
	enc := easy.New("siphash24", 1024, "hmac-blake3")
	defer enc.Close()

	seeds := reconstructSeeds128(t, enc.SeedComponents())

	pt := genTestPlaintextExt(t, 4096)
	ct, err := itb.Encrypt(seeds[0], seeds[1], seeds[2], pt)
	if err != nil {
		t.Fatalf("itb.Encrypt: %v", err)
	}
	out, err := enc.Decrypt(ct)
	if err != nil {
		t.Fatalf("easy.Decrypt: %v", err)
	}
	if !bytes.Equal(out, pt) {
		t.Fatalf("Single plain parity: low-level-encrypt -> easy-decrypt mismatch")
	}
}
