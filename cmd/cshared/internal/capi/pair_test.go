package capi

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// batchedPrimitives lists the canonical names of every shipped hash
// primitive that exposes a non-nil BatchHashFunc through the
// hashes.Make{128,256,512}Pair entry points. After the BLAKE2{b,s} /
// BLAKE3 / ChaCha20 chain-absorb kernels and the W128 batched
// scaffolding landed, every PRF-grade primitive in the registry that
// has a ZMM-batched ASM kernel joins the two Areion-SoEM primitives
// in this set.
//
// Adding a new entry to the set without a non-nil batched arm in
// hashes/registry.go is the regression this list guards against — the
// FFI-surfaced contract is that the seed handle's BatchHash field
// must be wired through whenever the underlying primitive provides
// one, so itb.processChunk picks up the fast path without the C ABI
// caller having to ask for it.
var batchedPrimitives = []string{
	"aescmac",
	"areion256",
	"areion512",
	"blake2b256",
	"blake2b512",
	"blake2s",
	"blake3",
	"chacha20",
	"siphash24",
}

// seedHandleHasBatchHash returns whether a seed handle's underlying
// itb.Seed{N} carries a non-nil BatchHash. Returns false when the
// handle is unresolvable.
func seedHandleHasBatchHash(t *testing.T, id HandleID) bool {
	t.Helper()
	h, st := resolve(id)
	if st != StatusOK || h == nil {
		t.Fatalf("resolve(%v) failed: %v", id, st)
	}
	switch h.width {
	case 128:
		return h.seed128 != nil && h.seed128.BatchHash != nil
	case 256:
		return h.seed256 != nil && h.seed256.BatchHash != nil
	case 512:
		return h.seed512 != nil && h.seed512.BatchHash != nil
	}
	return false
}

// TestNewSeedBatchedDispatchWired locks in the FFI-surfaced contract
// that NewSeed populates Seed.BatchHash for every primitive that
// hashes.Make{256,512}Pair returns a non-nil batched arm for. Without
// this wire-up, the C ABI / Python FFI / Go callers would silently
// fall back to per-pixel dispatch even when the ZMM-batched (Areion)
// or AVX-512-batched (BLAKE2b) ASM kernel is available, leaving the
// throughput uplift on the table.
func TestNewSeedBatchedDispatchWired(t *testing.T) {
	for _, name := range batchedPrimitives {
		t.Run(name, func(t *testing.T) {
			id, st := NewSeed(name, 1024)
			if st != StatusOK {
				t.Fatalf("NewSeed(%s): %v", name, st)
			}
			defer FreeSeed(id)
			if !seedHandleHasBatchHash(t, id) {
				t.Fatalf("Seed.BatchHash is nil for %s — FFI fast path is unwired", name)
			}
		})
	}
}

// TestNewSeedFromComponentsBatchedDispatchWired verifies the same
// contract on the persistence-restore path: ITB_NewSeedFromComponents
// (used after ITB_SeedComponents + ITB_SeedHashKey snapshot) must
// also populate Seed.BatchHash for batched-capable primitives. Were
// this to drift, day-1 encrypts (via NewSeed, batched) and day-2
// decrypts (via NewSeedFromComponents, accidentally non-batched)
// would still work bit-exactly because the parity invariant holds —
// but throughput would silently regress at the restore boundary.
func TestNewSeedFromComponentsBatchedDispatchWired(t *testing.T) {
	for _, name := range batchedPrimitives {
		t.Run(name, func(t *testing.T) {
			seed, st := NewSeed(name, 1024)
			if st != StatusOK {
				t.Fatalf("NewSeed(%s): %v", name, st)
			}
			components, st := SeedComponents(seed)
			if st != StatusOK {
				t.Fatalf("SeedComponents: %v", st)
			}
			hashKey, st := SeedHashKey(seed)
			if st != StatusOK {
				t.Fatalf("SeedHashKey: %v", st)
			}
			FreeSeed(seed)

			restored, st := NewSeedFromComponents(name, components, hashKey)
			if st != StatusOK {
				t.Fatalf("NewSeedFromComponents(%s): %v", name, st)
			}
			defer FreeSeed(restored)
			if !seedHandleHasBatchHash(t, restored) {
				t.Fatalf("Seed.BatchHash is nil after NewSeedFromComponents(%s) — restore path is unwired", name)
			}
		})
	}
}

// TestBatchedRoundtripAcrossNonceSizes drives the C ABI Encrypt/Decrypt
// path for every batched-capable primitive across plaintext sizes
// that exercise every ITB SetNonceBits buf shape (the per-pixel hash
// input is 20 / 36 / 68 bytes for nonce_bits ∈ {128, 256, 512}). The
// length-specialised batched kernels — VAES Areion256/512x4 and
// AVX-512 BLAKE2b256/512 chain-absorb — must produce the same
// ciphertext at every (nonce_bits, plaintext_size) corner; running
// encrypt + decrypt at sizes that span chunk boundaries surfaces any
// bug in the chunk-batched dispatch where the trailing chunk is
// shorter than the four-lane batch factor.
//
// Each (primitive, nonce_bits, plaintext_size) combination must
// roundtrip to bit-identical plaintext. nonce_bits is the
// process-wide global, so the test brackets each setting with a
// SetNonceBits / restore pair.
func TestBatchedRoundtripAcrossNonceSizes(t *testing.T) {
	origNonce := GetNonceBits()
	defer SetNonceBits(origNonce)

	for _, name := range batchedPrimitives {
		for _, nonceBits := range []int{128, 256, 512} {
			for _, ptSize := range []int{4096, 65536, 1 << 20} {
				t.Run(
					fmtCase(name, nonceBits, ptSize),
					func(t *testing.T) {
						if st := SetNonceBits(nonceBits); st != StatusOK {
							t.Fatalf("SetNonceBits(%d): %v", nonceBits, st)
						}
						plaintext := make([]byte, ptSize)
						if _, err := rand.Read(plaintext); err != nil {
							t.Fatal(err)
						}
						ns, st := NewSeed(name, 1024)
						if st != StatusOK {
							t.Fatalf("NewSeed(noise): %v", st)
						}
						defer FreeSeed(ns)
						ds, st := NewSeed(name, 1024)
						if st != StatusOK {
							t.Fatalf("NewSeed(data): %v", st)
						}
						defer FreeSeed(ds)
						ss, st := NewSeed(name, 1024)
						if st != StatusOK {
							t.Fatalf("NewSeed(start): %v", st)
						}
						defer FreeSeed(ss)
						if !seedHandleHasBatchHash(t, ns) {
							t.Skip("batched arm unavailable on this host")
						}

						// Size-query protocol: empty buffer probe to learn
						// the required ciphertext size, then allocate
						// exactly. ITB's ciphertext-expansion factor
						// varies with nonce_bits and per-pixel overhead;
						// the StatusBufferTooSmall code surfaces the
						// exact size in the same return slot the
						// successful path uses.
						required, st := Encrypt(ns, ds, ss, plaintext, nil)
						if st != StatusBufferTooSmall {
							t.Fatalf("Encrypt size probe: status=%v, want StatusBufferTooSmall", st)
						}
						ctBuf := make([]byte, required)
						ctLen, st := Encrypt(ns, ds, ss, plaintext, ctBuf)
						if st != StatusOK {
							t.Fatalf("Encrypt: %v", st)
						}
						ptBuf := make([]byte, ptSize+1024)
						ptLen, st := Decrypt(ns, ds, ss, ctBuf[:ctLen], ptBuf)
						if st != StatusOK {
							t.Fatalf("Decrypt: %v", st)
						}
						if !bytes.Equal(plaintext, ptBuf[:ptLen]) {
							t.Fatalf("plaintext mismatch (size=%d, nonce=%d, %s)", ptSize, nonceBits, name)
						}
					},
				)
			}
		}
	}
}

// fmtCase formats the subtest name without depending on fmt.Sprintf
// in the hot enclosing loop body. Same shape as the existing helper
// in capi_test.go's t.Run blocks; locally inlined to avoid touching
// the rest of the file.
func fmtCase(name string, nonceBits, ptSize int) string {
	return name + "/nonce" + itoa(nonceBits) + "/sz" + itoa(ptSize)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
