# hashes — Cached PRF-grade hash factories for ITB

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

> **See [CONSTRUCTIONS.md](CONSTRUCTIONS.md) for the per-primitive construction descriptions.** Several wrappers diverge from the canonical RFC / NIST form of the underlying primitive in deliberate, documented ways — the registry names (`aescmac`, `chacha20`, `blake2b256`, ...) are short identifiers, not assertions of conformance with the RFC / NIST specification of the same name. Read CONSTRUCTIONS.md before assuming RFC compatibility.

Drop-in factories that produce `itb.HashFunc{128|256|512}` closures
for the nine PRF-grade primitives ITB ships with as built-in
factories for the C / FFI / mobile shared-library distribution.

Every factory pre-keys its primitive once at construction, reuses a
`sync.Pool` of scratch buffers, and is safe to call concurrently from
multiple goroutines. Without this caching, per-pixel hashing would
re-key the underlying primitive on every call — the dominant cost in
ITB's encrypt / decrypt path.

Each factory accepts a variadic optional fixed key:
- pass nothing → CSPRNG-generated key (returned alongside the closure
  for the caller to save — required for cross-process persistence);
- pass a saved key → restore-side reconstruction of the same closure.

`SipHash24` is the one exception: its keying material is the per-call
seed components themselves, so it has no internal fixed key and no
variadic key argument.

## Canonical primitives

In FFI-stable index order:

| # | Name (FFI) | Native width | itb type |
|---|---|---|---|
| 0 | `areion256` | 256 | `HashFunc256` (paired with `BatchHashFunc256`) |
| 1 | `areion512` | 512 | `HashFunc512` (paired with `BatchHashFunc512`) |
| 2 | `siphash24` | 128 | `HashFunc128` (uncached — pure function) |
| 3 | `aescmac` | 128 | `HashFunc128` (cached AES-NI block) |
| 4 | `blake2b256` | 256 | `HashFunc256` |
| 5 | `blake2b512` | 512 | `HashFunc512` |
| 6 | `blake2s` | 256 | `HashFunc256` |
| 7 | `blake3` | 256 | `HashFunc256` |
| 8 | `chacha20` | 256 | `HashFunc256` |

The order is FFI-stable; index 0..8 is exposed through
`ITB_HashName(idx)` in the shared library and re-ordering would
break the ABI.

## Custom user-primitive builders

Beyond the shipped primitives, the package exposes three builder families that wrap a user-supplied PRF into an `itb.HashFunc{128|256|512}` closure **with correct ITB nonce width preservation by construction**. These are for "I want to plug in SHA-256 / Ascon-PRF / Camellia-CMAC / My Own Custom hash primitive as the ITB PRF" use cases.

| Builder | Wraps | Use when |
|---|---|---|
| `BuildCBCMACChainAbsorb{128,256,512}` | `crypto/cipher.Block` (caller-keyed) | You have a block cipher (AES, Camellia, ARIA, SM4, ...) and want CBC-MAC chain-absorb |
| `BuildSpongeChainAbsorb{128,256,512}` | `Permute` + `(rate, capacity, fixedKey)` | You have an unkeyed permutation (Keccak-f, Ascon-PRF, ...) and want a keyed sponge |
| `BuildARXChainAbsorb{128,256,512}` | `Hash256Fn` / `Hash512Fn` (full hash one-shot) | You have a full hash function (SHA-256, SM3, SHA-512, ...) and want safe absorption |

**Why these matter for ITB security.** ITB supports nonce widths of 128, 256 or 512 bits via `SetNonceBits`. The per-call buffer presented to a `HashFunc` closure carries a domain-tag byte plus the configured nonce material — 20, 36, or 68 bytes for the three nonce widths respectively. Every byte of the `data` parameter must reach the digest for ITB's advertised nonce strength to hold.

A naive user-written wrapper can silently truncate the ITB nonce in several ways:

- **`crypto/sha256.Sum256(data)` wrapped naively into `HashFunc512`** — SHA-256 output is 32 bytes; the upper 32 bytes of any returned `[8]uint64` get zero-padded by naive repacking. ChainHash's per-call XOR-chain consumes the full 64-byte intermediate state, so a constant upper half across calls destroys half the entropy.
- **`aes.NewCipher(key).Encrypt(iv, plaintext)` with ITB nonce as `iv`** — AES IV is 16 bytes regardless of how long the ITB nonce is. `SetNonceBits(512)` → effective 128-bit nonce. The advertised property is broken silently.
- **`chacha20.NewUnauthenticatedCipher(key, nonce)` with ITB nonce as `nonce`** — ChaCha20 nonce slot is 12 bytes. Same trap.

The builders sidestep all three traps by construction: the user supplies the primitive in its natural form, the builder absorbs the full `data` parameter through the appropriate chain pattern, the resulting closure preserves the full ITB nonce width by construction. No caller-side knowledge of the chain-absorb pattern is required.

### When the builder is required vs optional

The builders close the silent-truncation trap **constructively**, but they are not always strictly required. A user primitive is safely pluggable as a hand-written closure **without** a builder when **both** of these hold:

1. The primitive has **native variable-length absorb** (Merkle-Damgard tree like BLAKE3, MD chaining like SHA-256/512, sponge with internal absorb loop like Keccak/Ascon — i.e. the primitive's own API accepts arbitrary input length and processes every byte).
2. The primitive's **native output width is at least the required HashFunc width** (32 bytes for `HashFunc256`, 64 bytes for `HashFunc512`).

The existing custom-factory pattern in the main repo [README — "Custom factory pattern (advanced)"](../README.md#custom-factory-pattern-advanced) is the canonical reference for this case: BLAKE3 via `blake3.NewKeyed` + `h.Write(mixed)` satisfies both conditions, so all four seed components are XOR'd into a zero-padded data buffer that BLAKE3 absorbs natively. No chain-absorb needed. The same pattern transfers to BLAKE2b/2s, SHA-256 (for HashFunc256), SHA-512 (for HashFunc512), KangarooTwelve, etc.

A user primitive **requires** a builder when **at least one** of these holds:

1. **Output-width upscaling**: primitive native output is narrower than the required HashFunc width. SHA-256 (32 bytes) → `HashFunc512` (64 bytes) is the classic trap — naive zero-padding of the upper half destroys half the intermediate-state entropy. The builder calls the underlying hash twice with domain separation to fill the full output width safely.
2. **No native variable-length absorb**: primitive only handles fixed-width input in isolation. Raw `cipher.Block` (16-byte block), raw permutation function (320-bit Ascon-p state), block cipher used as a primitive rather than via a higher-level AEAD wrapper. The CBC-MAC or sponge builder constructs the chain externally so all input bytes reach the digest.
3. **Defence against caller-side mistakes**: even when (1) and (2) of the "safe handwritten" conditions hold, a builder removes the opportunity to forget seed-component XOR or output-width matching. Useful for casual users / quick experiments / audit-friendly code.

| Scenario | Builder required? | Why |
|---|---|---|
| BLAKE3 → `HashFunc256` (handwritten via `Write`) | No | Native variable-length absorb + native output 32 B matches |
| BLAKE2b → `HashFunc{256,512}` (handwritten via `Sum`) | No | Same — native variable-length absorb, output width matches |
| SHA-256 → `HashFunc256` | No (but builder simplifies) | Native MD absorb + 32 B output matches; builder still removes seed-injection responsibility |
| SHA-256 → `HashFunc512` | **Yes** | Output-width upscaling — without builder, upper 32 B silently zero-padded |
| SHA-512 → `HashFunc512` | No (but builder simplifies) | Native MD absorb + 64 B output matches |
| AES block cipher → `HashFunc{128,256,512}` | **Yes** | Raw block cipher has no native variable-length absorb |
| Ascon-p / Keccak-f (raw permutation) → `HashFunc{128,256,512}` | **Yes** | Raw permutation has no native variable-length absorb; sponge wrapper needed externally |
| Camellia / SM4 / ARIA block cipher | **Yes** | Same as AES — raw block cipher needs CBC-MAC chain |

### Example — SHA-256 via the ARX builder

```go
import (
    "crypto/rand"
    "crypto/sha256"

    "github.com/everanium/itb"
    "github.com/everanium/itb/hashes"
)

func main() {
    // Long-lived fixed key (persist alongside ITB seeds for cross-process restore).
    var fixedKey [32]byte
    if _, err := rand.Read(fixedKey[:]); err != nil {
        panic(err)
    }

    // SHA-256 wrapped safely. The builder folds {fixedKey, seed,
    // length, domain} into the absorb buffer so the full ITB nonce
    // (up to 64 bytes for SetNonceBits(512)) reaches the digest.
    sha256Hash := hashes.BuildARXChainAbsorb256(sha256.Sum256, fixedKey[:])

    // Use exactly like a built-in primitive — three independent seed
    // instances (one per ITB role: noise / data / start).
    itb.SetNonceBits(512)
    itb.SetBarrierFill(4)

    noiseSeed, _ := itb.NewSeed256(1024, sha256Hash)
    dataSeed,  _ := itb.NewSeed256(1024, sha256Hash)
    startSeed, _ := itb.NewSeed256(1024, sha256Hash)

    plaintext := []byte("hello SHA-256 via ITB builder")
    ct, _ := itb.Encrypt256(noiseSeed, dataSeed, startSeed, plaintext)
    pt, _ := itb.Decrypt256(noiseSeed, dataSeed, startSeed, ct)

    _ = pt // round-trip; bit-exact recovery of plaintext.
}
```

The same pattern works for any 32-byte hash. `SM3` swap-in: substitute `sha256.Sum256` with `func(d []byte) [32]byte { return sm3.Sum(d) }` (using any SM3 implementation that exposes a one-shot 32-byte digest). For 64-byte digests like SHA-512, use `BuildARXChainAbsorb512(sha512.Sum512, fixedKey[:])`.

### Performance note for builders

Builders dispatch through interface callbacks (`cipher.Block.Encrypt`) and `[]byte` state buffers, costing 5-15% throughput vs the inline per-primitive closures shipped here (`aescmac.go`, `chacha20.go`, ...). The built-in closures use stack-allocated fixed-size state arrays (`var state [32]byte`), inlined permutation calls, and `unsafe.Pointer` escape-analysis tricks. The builders are intentionally simpler — they target correctness-by-construction for user primitives, not peak throughput. If you need both correctness *and* peak throughput for a specific primitive, write a dedicated closure following the `hashes/*.go` patterns.

`BatchHash` (4-pixel batched ZMM-asm) is **not** provided by these builders — the batched arm is inherently primitive-specific (VAES for AES, multi-buffer SHA-NI for SHA-256, etc.) and cannot be templated. Seeds constructed from builder closures leave `BatchHash = nil`, which makes ITB fall back silently to the per-pixel scalar loop (`process_generic.go`). Correctness is preserved; throughput on AVX-512 hosts is left on the table.

## Usage

Native Go API — generate fresh random keys, persist the encryptor
material via `itb.Blob{128,256,512}`.

Each Blob type packs every seed's hash key + components plus the
optional dedicated lockSeed and the captured `itb.Set*` globals into
one self-describing JSON blob; ship the resulting `blob_bytes`
alongside the ciphertext (or out-of-band) and rebuild on the
receiver via `Blob{N}.Import` followed by per-slot factory rewiring.

Areion-SoEM has paired (single, batched, fixedKey) constructors so the
AVX-512 batched dispatch path is reachable:

```go

// Sender

import (
	"fmt"
	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
)

func main() {

	itb.SetMaxWorkers(8)    // limit to 8 CPU cores (default: all CPUs)
	itb.SetNonceBits(512)   // 512-bit nonce (default: 128-bit)
	itb.SetBarrierFill(4)   // CSPRNG fill margin (default: 1, valid: 1,2,4,8,16,32)

	itb.SetBitSoup(1)       // optional bit-level split ("bit-soup"; default: 0 = byte-level)
	                        // automatically enabled for Single Ouroboros if
	                        // itb.SetLockSoup(1) is enabled or vice versa

	itb.SetLockSoup(1)      // optional Insane Interlocked Mode: per-chunk PRF-keyed
	                        // bit-permutation overlay on top of bit-soup;
	                        // automatically enabled for Single Ouroboros if
	                        // itb.SetBitSoup(1) is enabled or vice versa

	// Four independent CSPRNG-keyed Areion-SoEM-512 paired closures
	// (3 main seeds + 1 optional dedicated lockSeed). Each Pair
	// returns (single, batched, [64]byte fixedKey).
	fnN, batchN, keyN := hashes.Areion512Pair() // random noise hash key generated
	fnD, batchD, keyD := hashes.Areion512Pair() // random data hash key generated
	fnS, batchS, keyS := hashes.Areion512Pair() // random start hash key generated
	fnL, batchL, keyL := hashes.Areion512Pair() // random lock hash key generated
	//fnN, batchN := hashes.Areion512PairWithKey(keyN) // [64]byte key
	//fnD, batchD := hashes.Areion512PairWithKey(keyD) // [64]byte key
	//fnS, batchS := hashes.Areion512PairWithKey(keyS) // [64]byte key
	//fnL, batchL := hashes.Areion512PairWithKey(keyL) // [64]byte key

	ns, _ := itb.NewSeed512(2048, fnN); ns.BatchHash = batchN // random noise CSPRNG seeds, batch enabled
	ds, _ := itb.NewSeed512(2048, fnD); ds.BatchHash = batchD // random data CSPRNG seeds, batch enabled
	ss, _ := itb.NewSeed512(2048, fnS); ss.BatchHash = batchS // random start CSPRNG seeds, batch enabled
	ls, _ := itb.NewSeed512(2048, fnL); ls.BatchHash = batchL // random lock CSPRNG seeds, batch enabled

	// Optional: dedicated lockSeed for the bit-permutation derivation
	// channel. Engages bit_soup or lock_soup before first encrypt
	// (both already on above).
	ns.AttachLockSeed(ls)

	plaintext := []byte("any text or binary data - including 0x00 bytes")

	// Encrypt into RGBWYOPA container
	encrypted, err := itb.Encrypt512(ns, ds, ss, plaintext)
	if err != nil {
        	panic(err)
	}
	fmt.Printf("encrypted: %d bytes\n", len(encrypted))

	// Cross-process persistence — Blob512 packs every seed's
	// [64]byte hash key + Components ([]uint64) plus the optional
	// dedicated lockSeed and the captured itb.Set* globals into
	// one self-describing JSON blob.
	bSrc := &itb.Blob512{}
	blob, _ := bSrc.Export(keyN, keyD, keyS, ns, ds, ss,
		itb.Blob512Opts{KeyL: keyL, LS: ls})

	// Send encrypted payload + blob

}

// Receiver

import (
	"fmt"
	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
)

func main() {

	itb.SetMaxWorkers(8)    // limit to 8 CPU cores (default: all CPUs)

	// Receive encrypted payload + blob
	// encrypted := ...; blob := ...

	// Blob512.Import restores per-slot hash keys + Components AND
	// applies the captured globals (NonceBits / BarrierFill /
	// BitSoup / LockSoup) via the process-wide setters. Hash /
	// BatchHash on each restored seed stay nil so the caller wires
	// them from the saved Key* bytes through the matching factory.
	bDst := &itb.Blob512{}
	_ = bDst.Import(blob)

	fnN, batchN := hashes.Areion512PairWithKey(bDst.KeyN)
	fnD, batchD := hashes.Areion512PairWithKey(bDst.KeyD)
	fnS, batchS := hashes.Areion512PairWithKey(bDst.KeyS)
	fnL, batchL := hashes.Areion512PairWithKey(bDst.KeyL)
	bDst.NS.Hash, bDst.NS.BatchHash = fnN, batchN
	bDst.DS.Hash, bDst.DS.BatchHash = fnD, batchD
	bDst.SS.Hash, bDst.SS.BatchHash = fnS, batchS
	bDst.LS.Hash, bDst.LS.BatchHash = fnL, batchL
	bDst.NS.AttachLockSeed(bDst.LS)

	// Decrypt from RGBWYOPA container
	decrypted, err := itb.Decrypt512(bDst.NS, bDst.DS, bDst.SS, encrypted)
	if err != nil {
        	panic(err)
	}
	fmt.Printf("decrypted: %d bytes\n", len(decrypted))

}

```

BLAKE2b-512 has paired (single, batched, fixedKey) constructors so the
AVX-512 ZMM-batched chain-absorb dispatch path is reachable:

```go

// Sender

import (
	"fmt"
	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
)

func main() {

	itb.SetMaxWorkers(8)    // limit to 8 CPU cores (default: all CPUs)
	itb.SetNonceBits(512)   // 512-bit nonce (default: 128-bit)
	itb.SetBarrierFill(4)   // CSPRNG fill margin (default: 1, valid: 1,2,4,8,16,32)

	itb.SetBitSoup(1)       // optional bit-level split ("bit-soup"; default: 0 = byte-level)
	                        // automatically enabled for Single Ouroboros if
	                        // itb.SetLockSoup(1) is enabled or vice versa

	itb.SetLockSoup(1)      // optional Insane Interlocked Mode: per-chunk PRF-keyed
	                        // bit-permutation overlay on top of bit-soup;
	                        // automatically enabled for Single Ouroboros if
	                        // itb.SetBitSoup(1) is enabled or vice versa

	// Four independent CSPRNG-keyed BLAKE2b-512 paired closures
	// (3 main seeds + 1 optional dedicated lockSeed). Each Pair
	// returns (single, batched, [64]byte fixedKey).
	fnN, batchN, keyN := hashes.BLAKE2b512Pair() // random noise hash key generated
	fnD, batchD, keyD := hashes.BLAKE2b512Pair() // random data hash key generated
	fnS, batchS, keyS := hashes.BLAKE2b512Pair() // random start hash key generated
	fnL, batchL, keyL := hashes.BLAKE2b512Pair() // random lock hash key generated
	//fnN, batchN := hashes.BLAKE2b512PairWithKey(keyN) // [64]byte key
	//fnD, batchD := hashes.BLAKE2b512PairWithKey(keyD) // [64]byte key
	//fnS, batchS := hashes.BLAKE2b512PairWithKey(keyS) // [64]byte key
	//fnL, batchL := hashes.BLAKE2b512PairWithKey(keyL) // [64]byte key

	ns, _ := itb.NewSeed512(2048, fnN); ns.BatchHash = batchN // random noise CSPRNG seeds, batch enabled
	ds, _ := itb.NewSeed512(2048, fnD); ds.BatchHash = batchD // random data CSPRNG seeds, batch enabled
	ss, _ := itb.NewSeed512(2048, fnS); ss.BatchHash = batchS // random start CSPRNG seeds, batch enabled
	ls, _ := itb.NewSeed512(2048, fnL); ls.BatchHash = batchL // random lock CSPRNG seeds, batch enabled

	// Optional: dedicated lockSeed for the bit-permutation derivation
	// channel — same flow as the Areion-SoEM-512 example above.
	ns.AttachLockSeed(ls)

	plaintext := []byte("any text or binary data - including 0x00 bytes")

	// Encrypt into RGBWYOPA container
	encrypted, err := itb.Encrypt512(ns, ds, ss, plaintext)
	if err != nil {
        	panic(err)
	}
	fmt.Printf("encrypted: %d bytes\n", len(encrypted))

	// Cross-process persistence — Blob512 packs every seed's
	// [64]byte hash key + Components plus the optional dedicated
	// lockSeed and the captured itb.Set* globals into one
	// self-describing JSON blob.
	bSrc := &itb.Blob512{}
	blob, _ := bSrc.Export(keyN, keyD, keyS, ns, ds, ss,
		itb.Blob512Opts{KeyL: keyL, LS: ls})

	// Send encrypted payload + blob

}

// Receiver

import (
	"fmt"
	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
)

func main() {

	itb.SetMaxWorkers(8)    // limit to 8 CPU cores (default: all CPUs)

	// Receive encrypted payload + blob
	// encrypted := ...; blob := ...

	// Blob512.Import restores per-slot hash keys + Components AND
	// applies the captured globals via the process-wide setters.
	// Hash / BatchHash on each restored seed stay nil so the caller
	// wires them from the saved Key* bytes through the matching
	// factory.
	bDst := &itb.Blob512{}
	_ = bDst.Import(blob)

	fnN, batchN := hashes.BLAKE2b512PairWithKey(bDst.KeyN)
	fnD, batchD := hashes.BLAKE2b512PairWithKey(bDst.KeyD)
	fnS, batchS := hashes.BLAKE2b512PairWithKey(bDst.KeyS)
	fnL, batchL := hashes.BLAKE2b512PairWithKey(bDst.KeyL)
	bDst.NS.Hash, bDst.NS.BatchHash = fnN, batchN
	bDst.DS.Hash, bDst.DS.BatchHash = fnD, batchD
	bDst.SS.Hash, bDst.SS.BatchHash = fnS, batchS
	bDst.LS.Hash, bDst.LS.BatchHash = fnL, batchL
	bDst.NS.AttachLockSeed(bDst.LS)

	// Decrypt from RGBWYOPA container
	decrypted, err := itb.Decrypt512(bDst.NS, bDst.DS, bDst.SS, encrypted)
	if err != nil {
        	panic(err)
	}
	fmt.Printf("decrypted: %d bytes\n", len(decrypted))

}

```

SipHash-2-4 has no internal fixed key — paired (single, batched)
constructor returns a 2-tuple without a key element:

```go
import (
	"fmt"
	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
)

func main() {

	itb.SetMaxWorkers(8)    // limit to 8 CPU cores (default: all CPUs)

	fnN, batchN := hashes.SipHash24Pair()
	fnD, batchD := hashes.SipHash24Pair()
	fnS, batchS := hashes.SipHash24Pair()
	fnL, batchL := hashes.SipHash24Pair()

	ns, _ := itb.NewSeed128(1024, fnN); ns.BatchHash = batchN
	ds, _ := itb.NewSeed128(1024, fnD); ds.BatchHash = batchD
	ss, _ := itb.NewSeed128(1024, fnS); ss.BatchHash = batchS
	ls, _ := itb.NewSeed128(1024, fnL); ls.BatchHash = batchL
	ns.AttachLockSeed(ls)

	plaintext := []byte("any text or binary data - including 0x00 bytes")
	encrypted, _ := itb.Encrypt128(ns, ds, ss, plaintext)

	// Cross-process persistence — Blob128 packs every seed's
	// Components ([]uint64; SipHash-2-4 has no fixed PRF key, so
	// KeyN/KeyD/KeyS/KeyL stay nil) plus the optional dedicated
	// lockSeed and the captured itb.Set* globals.
	bSrc := &itb.Blob128{}
	blob, _ := bSrc.Export(nil, nil, nil, ns, ds, ss,
	    itb.Blob128Opts{LS: ls})

	// Receiver — Import + factory rewiring (SipHash-2-4 has no fixed
	// key to thread through the factory; one fresh SipHash24Pair() per
	// slot).
	bDst := &itb.Blob128{}
	_ = bDst.Import(blob)
	fnN2, batchN2 := hashes.SipHash24Pair()
	fnD2, batchD2 := hashes.SipHash24Pair()
	fnS2, batchS2 := hashes.SipHash24Pair()
	fnL2, batchL2 := hashes.SipHash24Pair()
	bDst.NS.Hash, bDst.NS.BatchHash = fnN2, batchN2
	bDst.DS.Hash, bDst.DS.BatchHash = fnD2, batchD2
	bDst.SS.Hash, bDst.SS.BatchHash = fnS2, batchS2
	bDst.LS.Hash, bDst.LS.BatchHash = fnL2, batchL2
	bDst.NS.AttachLockSeed(bDst.LS)

	decrypted, _ := itb.Decrypt128(bDst.NS, bDst.DS, bDst.SS, encrypted)
	_ = decrypted

}
```

Name-keyed dispatch (used by the FFI layer; works for any code that
selects the primitive at runtime). Same variadic key pattern, but key
is `[]byte` (size validated against the primitive's native length):

```go
fn, hashKey, _ := hashes.Make256("blake3") // random
fn, _, _       := hashes.Make256("blake3", saved) // explicit
```

## Easy Mode — Quick start

`easy.New` (Single Ouroboros) and `easy.New3` (Triple Ouroboros)
build a high-level `*easy.Encryptor` around a single hash primitive
chosen from the canonical list above. The constructor allocates
its own seed material + MAC closure, snapshots the global ITB
configuration into a per-instance `*itb.Config`, and exposes
setters that mutate only its own state — two encryptors with
different settings can run concurrently without cross-
contamination. The state blob carries the PRF fixed key, seed
components, MAC key, and (when active) the dedicated lockSeed
material; the receiver constructs a matching encryptor with the
same `(primitive, key_bits, mac, mode)` and calls `Import` to
restore.

```go

// Sender

package main

import (
	"fmt"
	"github.com/everanium/itb"
	"github.com/everanium/itb/easy"
)

func main() {
	itb.SetMaxWorkers(8)    // limit to 8 CPU cores (default: all CPUs)

	// Single-Ouroboros (3 seeds) constructor — variadic args by type:
	// string matching hashes.Registry → primitive, string matching
	// macs.Registry → MAC, int → key_bits. Defaults: "areion512" /
	// 1024 / "hmac-blake3". Triple Ouroboros (7 seeds) → easy.New3(...).
	enc := easy.New("blake3", 1024, "hmac-blake3")
	defer enc.Close()

	// Per-instance configuration.
	enc.SetNonceBits(256)   // 256-bit nonce (default: 128-bit)
	enc.SetBarrierFill(4)   // CSPRNG fill margin (default: 1, valid: 1, 2, 4, 8, 16, 32)

	//enc.SetLockSeed(1)    // optional dedicated lockSeed for the bit-permutation
	                        // derivation channel — separates that PRF's keying material
	                        // from the noiseSeed-driven noise-injection channel; auto-
	                        // couples SetLockSoup(1) + SetBitSoup(1). Adds one extra
	                        // seed slot (3 → 4 for Single, 7 → 8 for Triple). Must be
	                        // called BEFORE the first Encrypt — switching mid-session
	                        // panics with easy.ErrLockSeedAfterEncrypt.

	// For cross-process persistence: enc.Export() returns a single
	// JSON blob carrying PRF keys, seed components, MAC key, and
	// (when active) the dedicated lockSeed material.
	blob := enc.Export()
	fmt.Printf("state blob: %d bytes\n", len(blob))
	fmt.Printf("primitive: %s, key_bits: %d, mode: %d, mac: %s\n",
		enc.Primitive, enc.KeyBits, enc.Mode, enc.MACName)

	plaintext := []byte("any text or binary data - including 0x00 bytes")

	// Authenticated encrypt — 32-byte tag is computed across the
	// entire decrypted capacity and embedded inside the RGBWYOPA
	// container, preserving oracle-free deniability.
	encrypted, err := enc.EncryptAuth(plaintext)
	if err != nil {
		panic(err)
	}
	fmt.Printf("encrypted: %d bytes\n", len(encrypted))

	// Send encrypted payload + state blob

}

// Receiver

package main

import (
	"fmt"
	"github.com/everanium/itb"
	"github.com/everanium/itb/easy"
)

func main() {
	itb.SetMaxWorkers(8)    // limit to 8 CPU cores (default: all CPUs)

	// Receive encrypted payload + state blob
	// var encrypted, blob []byte = ..., ...

	// Optional: peek at the blob's metadata before constructing a
	// matching encryptor. Useful when the receiver multiplexes blobs
	// of different shapes (different primitive / mode / MAC choices).
	prim, keyBits, mode, mac := easy.PeekConfig(blob)
	fmt.Printf("peek: primitive=%s, key_bits=%d, mode=%d, mac=%s\n",
		prim, keyBits, mode, mac)

	var dec *easy.Encryptor
	if mode == 1 {
		dec = easy.New(prim, keyBits, mac)
	} else {
		dec = easy.New3(prim, keyBits, mac)
	}
	defer dec.Close()

	// Restore PRF keys, seed components, MAC key, and the per-instance
	// configuration overrides from the saved blob.
	if err := dec.Import(blob); err != nil {
		panic(err)
	}

	decrypted, err := dec.DecryptAuth(encrypted)
	if err != nil {
		panic(err)
	}
	fmt.Printf("decrypted: %s\n", string(decrypted))

}
```

## Easy Mode — Mixed primitives (different PRF per seed slot)

`easy.NewMixed` and `easy.NewMixed3` accept a per-slot primitive
spec, allowing the noise / data / start (and optional dedicated
lockSeed) seed slots to use different PRF primitives within the
same native hash width. The mix-and-match-PRF freedom of the
lower-level path, surfaced through Easy Mode without forcing the
caller off the high-level constructor. The state blob carries
per-slot primitives + per-slot PRF keys; the receiver constructs a
matching encryptor with the same spec and calls `Import` to
restore.

```go

// Sender

package main

import (
	"fmt"
	"github.com/everanium/itb"
	"github.com/everanium/itb/easy"
)

func main() {
	itb.SetMaxWorkers(8)    // limit to 8 CPU cores (default: all CPUs)

	// Per-slot primitive selection (Single Ouroboros, 3 + 1 slots).
	// Every name must share the same native hash width — mixing
	// widths is rejected at construction with easy.ErrEasyMixedWidth.
	// Triple Ouroboros mirror — easy.NewMixed3(easy.MixedSpec3{...})
	// takes seven per-slot names (noise + 3 data + 3 start) plus
	// the optional PrimitiveL lockSeed.
	enc := easy.NewMixed(easy.MixedSpec{
		PrimitiveN: "blake3",      // noiseSeed:  BLAKE3
		PrimitiveD: "blake2s",     // dataSeed:   BLAKE2s
		PrimitiveS: "areion256",   // startSeed:  Areion-SoEM-256
		PrimitiveL: "blake2b256",  // dedicated lockSeed (optional;
		                           // empty = no lockSeed slot)
		KeyBits:    1024,
		MACName:    "hmac-blake3",
	})
	defer enc.Close()

	// Per-instance configuration applies as for easy.New.
	enc.SetNonceBits(512)
	enc.SetBarrierFill(4)
	// BitSoup + LockSoup are auto-coupled on the on-direction by
	// PrimitiveL above; explicit calls below are unnecessary but
	// harmless if added.
	//enc.SetBitSoup(1)
	//enc.SetLockSoup(1)

	// Per-slot introspection — Primitive returns the "mixed"
	// literal, PrimitiveAt(slot) returns each slot's name,
	// IsMixed() is the typed predicate.
	fmt.Printf("mixed=%v primitive=%s\n", enc.IsMixed(), enc.Primitive)
	for i := 0; i < 4; i++ {
		fmt.Printf("  slot %d: %s\n", i, enc.PrimitiveAt(i))
	}

	blob := enc.Export()
	fmt.Printf("state blob: %d bytes\n", len(blob))

	plaintext := []byte("mixed-primitive Easy Mode payload")

	// Authenticated encrypt — 32-byte tag is computed across the
	// entire decrypted capacity and embedded inside the RGBWYOPA
	// container, preserving oracle-free deniability.
	encrypted, err := enc.EncryptAuth(plaintext)
	if err != nil {
		panic(err)
	}
	fmt.Printf("encrypted: %d bytes\n", len(encrypted))

	// Send encrypted payload + state blob

}

// Receiver

package main

import (
	"fmt"
	"github.com/everanium/itb"
	"github.com/everanium/itb/easy"
)

func main() {
	itb.SetMaxWorkers(8)    // limit to 8 CPU cores (default: all CPUs)

	// Receive encrypted payload + state blob
	// var encrypted, blob []byte = ..., ...

	// Receiver constructs a matching mixed encryptor — every per-
	// slot primitive name plus key_bits and mac must agree with the
	// sender. Import validates each per-slot primitive against the
	// receiver's bound spec; mismatches surface as
	// easy.ErrMismatch{Field: "primitive"}.
	dec := easy.NewMixed(easy.MixedSpec{
		PrimitiveN: "blake3",
		PrimitiveD: "blake2s",
		PrimitiveS: "areion256",
		PrimitiveL: "blake2b256",
		KeyBits:    1024,
		MACName:    "hmac-blake3",
	})
	defer dec.Close()

	// Restore PRF keys, seed components, MAC key, and the per-
	// instance configuration overrides from the saved blob. Mixed
	// blobs carry mixed:true plus a primitives array; Import on a
	// single-primitive receiver (or vice versa) is rejected as a
	// primitive mismatch.
	if err := dec.Import(blob); err != nil {
		panic(err)
	}

	decrypted, err := dec.DecryptAuth(encrypted)
	if err != nil {
		panic(err)
	}
	fmt.Printf("decrypted: %s\n", string(decrypted))

}
```

## Keyed variants

Every cached factory ships a paired `*WithKey` form that takes the
fixed key as a single non-variadic argument and returns just the
closure (no key tuple element):

| variadic-short                | explicit `WithKey`              |
|-------------------------------|---------------------------------|
| `Areion256Pair(...key)`       | `Areion256PairWithKey(key)`     |
| `Areion512Pair(...key)`       | `Areion512PairWithKey(key)`     |
| `AESCMAC(...key)`             | `AESCMACWithKey(key)`           |
| `ChaCha20(...key)`            | `ChaCha20WithKey(key)`          |
| `BLAKE2s(...key)`             | `BLAKE2sWithKey(key)`           |
| `BLAKE2b256(...key)`          | `BLAKE2b256WithKey(key)`        |
| `BLAKE2b512(...key)`          | `BLAKE2b512WithKey(key)`        |
| `BLAKE3(...key)`              | `BLAKE3WithKey(key)`            |

The variadic short form delegates to `WithKey` (Go inliner removes
the wrapper at compile time), so semantics are identical. Pick
whichever reads cleaner at your call site:

- **variadic** when the same call site handles both random-key and
  explicit-key paths (e.g. a config-driven factory that defaults to
  random when no key is in the config);
- **`WithKey`** when the call site is unambiguously explicit-key
  (restore path with the key already in scope) and the bare key
  return value would be redundant noise.

`SipHash24` has no `WithKey` because the seed components themselves
are the entire SipHash key; serializing the seed components is
sufficient.
