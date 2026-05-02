# hashes — cached PRF-grade hash factories for ITB

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

	itb.SetMaxWorkers(8)  // limit to 8 CPU cores (default: all CPUs)
	itb.SetNonceBits(512) // 512-bit nonce (default: 128-bit)
	itb.SetBarrierFill(4) // CSPRNG fill margin (default: 1, valid: 1,2,4,8,16,32)

	itb.SetBitSoup(1)  // optional bit-level split ("bit-soup"; default: 0 = byte-level)
	                   // automatically enabled for Single Ouroboros if
	                   // itb.SetLockSoup(1) is enabled or vice versa

	itb.SetLockSoup(1) // optional Insane Interlocked Mode: per-chunk PRF-keyed
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

	itb.SetMaxWorkers(8) // deployment knob — not serialised by Blob512

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

	itb.SetMaxWorkers(8)  // limit to 8 CPU cores (default: all CPUs)
	itb.SetNonceBits(512) // 512-bit nonce (default: 128-bit)
	itb.SetBarrierFill(4) // CSPRNG fill margin (default: 1, valid: 1,2,4,8,16,32)

	itb.SetBitSoup(1)  // optional bit-level split ("bit-soup"; default: 0 = byte-level)
	                   // automatically enabled for Single Ouroboros if
	                   // itb.SetLockSoup(1) is enabled or vice versa

	itb.SetLockSoup(1) // optional Insane Interlocked Mode: per-chunk PRF-keyed
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

	itb.SetMaxWorkers(8) // deployment knob — not serialised by Blob512

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
itb.SetBitSoup(1) // engage the bit-permutation overlay so the
                  // optional dedicated lockSeed has wire effect

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
```

Name-keyed dispatch (used by the FFI layer; works for any code that
selects the primitive at runtime). Same variadic key pattern, but key
is `[]byte` (size validated against the primitive's native length):

```go
fn, hashKey, _ := hashes.Make256("blake3") // random
fn, _, _       := hashes.Make256("blake3", saved) // explicit
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
