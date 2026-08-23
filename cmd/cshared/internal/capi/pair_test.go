package capi

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/everanium/itb/hashes"
)

// primitiveBatchedEngagedOnHost asks the hashes registry whether
// the given primitive's Make*Pair returns a non-nil batched arm
// on the current host — the same dispatch the production NewSeed
// code uses. Tests that assert "Seed.BatchHash is non-nil" must
// gate themselves on this so they pass under both the asm-engaged
// build (where every batched-capable primitive surfaces a batched
// arm) and the no-asm build (where the batched arm nil-routes so
// process_cgo's nil-fallback drives 4 single calls instead of the
// slow scalar 4-lane wrapper).
func primitiveBatchedEngagedOnHost(t *testing.T, name string) bool {
	t.Helper()
	spec, ok := hashes.Find(name)
	if !ok {
		t.Fatalf("hashes.Find(%q): primitive missing from registry", name)
	}
	switch spec.Width {
	case hashes.W128:
		_, batched, _, err := hashes.Make128Pair(name)
		if err != nil {
			t.Fatalf("Make128Pair(%s): %v", name, err)
		}
		return batched != nil
	case hashes.W256:
		_, batched, _, err := hashes.Make256Pair(name)
		if err != nil {
			t.Fatalf("Make256Pair(%s): %v", name, err)
		}
		return batched != nil
	case hashes.W512:
		_, batched, _, err := hashes.Make512Pair(name)
		if err != nil {
			t.Fatalf("Make512Pair(%s): %v", name, err)
		}
		return batched != nil
	}
	t.Fatalf("primitiveBatchedEngagedOnHost(%s): unhandled width %d", name, spec.Width)
	return false
}

// batchedPrimitives lists the canonical names of every shipped hash
// primitive that exposes a non-nil BatchHashFunc through the
// hashes.Make{128,256,512}Pair entry points. Adding a new entry to
// the set without a non-nil batched arm in hashes/registry.go is
// the regression this list guards against — the FFI-surfaced
// contract is that the seed handle's BatchHash field must be wired
// through whenever the underlying primitive provides one, so
// itb.processChunk picks up the fast path without the C ABI caller
// having to ask for it.
var batchedPrimitives = []string{
	"areion256",
	"areion512",
	"blake2b256",
	"blake2b512",
	"blake2s",
	"blake3",
	"aescmac",
	"siphash24",
	"chacha20",
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
			engaged := primitiveBatchedEngagedOnHost(t, name)
			has := seedHandleHasBatchHash(t, id)
			if engaged && !has {
				t.Fatalf("Seed.BatchHash is nil for %s despite hashes.Make*Pair returning a batched arm — FFI fast path is unwired", name)
			}
			if !engaged && has {
				t.Fatalf("Seed.BatchHash is non-nil for %s although hashes.Make*Pair returned nil batched — process_cgo's nil-fallback would be faster than the scalar 4-lane wrapper", name)
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
			engaged := primitiveBatchedEngagedOnHost(t, name)
			has := seedHandleHasBatchHash(t, restored)
			if engaged && !has {
				t.Fatalf("Seed.BatchHash is nil after NewSeedFromComponents(%s) despite hashes.Make*Pair returning a batched arm — restore path is unwired", name)
			}
			if !engaged && has {
				t.Fatalf("Seed.BatchHash is non-nil after NewSeedFromComponents(%s) although hashes.Make*Pair returned nil batched — restore path forces a slow scalar 4-lane wrapper that the live encrypt path would skip", name)
			}
		})
	}
}

// TestBatchedRoundtripAcrossPlaintextSizes drives the C ABI Encrypt3 /
// Decrypt3 path for every batched-capable primitive across plaintext
// sizes that stress the four-lane batched dispatch. The
// length-specialised batched kernels — VAES Areion256/512x4 and
// AVX-512 BLAKE2b256/512 chain-absorb — must produce the same
// ciphertext at every plaintext_size corner; running encrypt +
// decrypt at sizes that span chunk boundaries surfaces any bug in
// the chunk-batched dispatch where the trailing chunk is shorter
// than the four-lane batch factor.
//
// The capi Encrypt3 / Decrypt3 wrappers use the compile-in default
// nonce width (128 bits); explicit per-instance nonce widths ride
// through the Cfg-aware itb entries on the Go side.
func TestBatchedRoundtripAcrossNonceSizes(t *testing.T) {
	const nonceBits = 128
	for _, name := range batchedPrimitives {
		for _, ptSize := range []int{4096, 65536, 1 << 20} {
			{
				t.Run(
					fmtCase(name, nonceBits, ptSize),
					func(t *testing.T) {
						plaintext := make([]byte, ptSize)
						if _, err := rand.Read(plaintext); err != nil {
							t.Fatal(err)
						}
						ids := newEightSeeds(t, name, 1024)
						defer freeAll(ids[:]...)

						if !seedHandleHasBatchHash(t, ids[0]) {
							t.Skip("batched arm unavailable on this host")
						}

						// Size-query protocol: empty buffer probe to learn
						// the required ciphertext size, then allocate
						// exactly. ITB's ciphertext-expansion factor
						// varies with nonce_bits and per-pixel overhead;
						// the StatusBufferTooSmall code surfaces the
						// exact size in the same return slot the
						// successful path uses.
						required, st := Encrypt3(
							ids[0], ids[1], ids[2], ids[3],
							ids[4], ids[5], ids[6], ids[7],
							plaintext, nil)
						if st != StatusBufferTooSmall {
							t.Fatalf("Encrypt3 size probe: status=%v, want StatusBufferTooSmall", st)
						}
						ctBuf := make([]byte, required)
						ctLen, st := Encrypt3(
							ids[0], ids[1], ids[2], ids[3],
							ids[4], ids[5], ids[6], ids[7],
							plaintext, ctBuf)
						if st != StatusOK {
							t.Fatalf("Encrypt3: %v", st)
						}
						ptBuf := make([]byte, ptSize+1024)
						ptLen, st := Decrypt3(
							ids[0], ids[1], ids[2], ids[3],
							ids[4], ids[5], ids[6], ids[7],
							ctBuf[:ctLen], ptBuf)
						if st != StatusOK {
							t.Fatalf("Decrypt3: %v", st)
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
// in the hot enclosing loop body.
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
