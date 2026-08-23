package itb_test

import (
	"bytes"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/easy"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/macs"
)

// reconstructSeeds128Ext rebuilds *itb.Seed128 pointers from the
// component vectors exposed by [easy.Encryptor.SeedComponents]. The
// hash factory must match the encryptor's primitive — these tests pin
// the encryptor to "siphash24" for the 128-bit width since SipHash-2-4
// has no fixed PRF key (the per-call seed components are the sole
// keying material), which makes the reconstruction straightforward
// and avoids cross-key-channel divergence between the two surfaces.
func reconstructSeeds128Ext(t *testing.T, components [][]uint64) []*itb.Seed128 {
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

// macFromKeyExt rebuilds the encryptor's MACFunc from its exposed MAC
// key, using the registered HMAC-BLAKE3 factory. easy.Encryptor binds
// HMAC-BLAKE3 by default; the parity tests stay on that default to
// keep the reconstruction one-line.
func macFromKeyExt(t *testing.T, key []byte) itb.MACFunc {
	t.Helper()
	mac, err := macs.HMACBLAKE3(key)
	if err != nil {
		t.Fatalf("macs.HMACBLAKE3: %v", err)
	}
	return mac
}

// easyPlaintextExt is a small deterministic plaintext seed for the
// parity tests. Each test seeds its own bytes via crypto/rand through
// genTestPlaintextExt (defined in streams_auth_test.go).

// TestExtEasyEncrypt3xAuthDecodableByLowLevel encrypts via the easy
// surface (Encryptor.EncryptAuth on a Triple encryptor) and decrypts
// via the width-less itb.DecryptAuth3x. The reconstructed 8-seed
// vector + MAC must produce the same recovered plaintext, confirming
// the two surfaces share one wire format under a default configuration
// snapshot.
func TestExtEasyEncrypt3xAuthDecodableByLowLevel(t *testing.T) {
	enc := easy.New3("siphash24", 1024, "hmac-blake3")
	defer enc.Close()

	pt := genTestPlaintextExt(t, 4096)
	ct, err := enc.EncryptAuth(pt)
	if err != nil {
		t.Fatalf("easy.EncryptAuth (Triple): %v", err)
	}

	seeds := reconstructSeeds128Ext(t, enc.SeedComponents())
	if len(seeds) != 8 {
		t.Fatalf("Triple reconstruct: want 8 seeds, got %d", len(seeds))
	}
	mac := macFromKeyExt(t, enc.MACKey())

	out, err := itb.DecryptAuth3x(seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], seeds[7], ct, mac)
	if err != nil {
		t.Fatalf("itb.DecryptAuth3x: %v", err)
	}
	if !bytes.Equal(out, pt) {
		t.Fatalf("Triple parity: easy-encrypt -> low-level-decrypt mismatch")
	}
}

// TestExtLowLevelEncrypt3xAuthDecodableByEasy reverses the parity
// direction: encrypt via the width-less itb.EncryptAuth3x on the
// reconstructed 8-seed vector + MAC, decrypt via
// easy.Encryptor.DecryptAuth on the same encryptor instance.
func TestExtLowLevelEncrypt3xAuthDecodableByEasy(t *testing.T) {
	enc := easy.New3("siphash24", 1024, "hmac-blake3")
	defer enc.Close()

	seeds := reconstructSeeds128Ext(t, enc.SeedComponents())
	mac := macFromKeyExt(t, enc.MACKey())

	pt := genTestPlaintextExt(t, 4096)
	ct, err := itb.EncryptAuth3x(seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], seeds[7], pt, mac)
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

// TestExtEasyEncryptStream3xAuthDecodableByLowLevel — Streaming AEAD
// parity test on the Triple surface: encrypt via
// [easy.Encryptor.EncryptStreamAuth], reconstruct seeds + MAC from
// the encryptor, decrypt via the width-less [itb.DecryptStreamAuth3x].
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

	seeds := reconstructSeeds128Ext(t, enc.SeedComponents())
	mac := macFromKeyExt(t, enc.MACKey())

	var ptBuf bytes.Buffer
	if err := itb.DecryptStreamAuth3x(seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], seeds[7], bytes.NewReader(ctBuf.Bytes()), &ptBuf, mac); err != nil {
		t.Fatalf("itb.DecryptStreamAuth3x: %v", err)
	}
	if !bytes.Equal(ptBuf.Bytes(), pt) {
		t.Fatalf("Triple stream parity: easy-encrypt -> low-level-decrypt mismatch")
	}
}

// TestExtLowLevelEncryptStream3xAuthDecodableByEasy — reverse
// direction for the Triple Streaming AEAD parity test.
func TestExtLowLevelEncryptStream3xAuthDecodableByEasy(t *testing.T) {
	enc := easy.New3("siphash24", 1024, "hmac-blake3")
	defer enc.Close()

	seeds := reconstructSeeds128Ext(t, enc.SeedComponents())
	mac := macFromKeyExt(t, enc.MACKey())

	pt := genTestPlaintextExt(t, 3*4096)
	var ctBuf bytes.Buffer
	if err := itb.EncryptStreamAuth3x(seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], seeds[7], bytes.NewReader(pt), &ctBuf, mac, 4096); err != nil {
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

// TestExtEasyEncrypt3xDecodableByLowLevelPlain — plain-mode parity
// test (no MAC) on the Triple surface. Verifies the width-less
// itb.Decrypt3x and the easy.Encryptor.Decrypt path agree on the
// wire format under a default configuration snapshot.
func TestExtEasyEncrypt3xDecodableByLowLevelPlain(t *testing.T) {
	enc := easy.New3("siphash24", 1024, "hmac-blake3")
	defer enc.Close()

	pt := genTestPlaintextExt(t, 4096)
	ct, err := enc.Encrypt(pt)
	if err != nil {
		t.Fatalf("easy.Encrypt (Triple): %v", err)
	}

	seeds := reconstructSeeds128Ext(t, enc.SeedComponents())
	out, err := itb.Decrypt3x(seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], seeds[7], ct)
	if err != nil {
		t.Fatalf("itb.Decrypt3x: %v", err)
	}
	if !bytes.Equal(out, pt) {
		t.Fatalf("Triple plain parity: easy-encrypt -> low-level-decrypt mismatch")
	}
}

// TestExtLowLevelEncrypt3xDecodableByEasyPlain — reverse direction
// for the Triple plain-mode parity test.
func TestExtLowLevelEncrypt3xDecodableByEasyPlain(t *testing.T) {
	enc := easy.New3("siphash24", 1024, "hmac-blake3")
	defer enc.Close()

	seeds := reconstructSeeds128Ext(t, enc.SeedComponents())

	pt := genTestPlaintextExt(t, 4096)
	ct, err := itb.Encrypt3x(seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], seeds[7], pt)
	if err != nil {
		t.Fatalf("itb.Encrypt3x: %v", err)
	}
	out, err := enc.Decrypt(ct)
	if err != nil {
		t.Fatalf("easy.Decrypt (Triple): %v", err)
	}
	if !bytes.Equal(out, pt) {
		t.Fatalf("Triple plain parity: low-level-encrypt -> easy-decrypt mismatch")
	}
}
