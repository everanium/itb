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

Native Go API — generate a fresh random key, save it for persistence.

The `saveKey(name, bytes)` / `loadKey(name)` key helpers and
`saveSeed(name, components)` / `loadSeed(name)` seed helpers used in the
snippets below are **user-side placeholders** for whatever persistence mechanism
the deployment uses (config file / database / mounted secret / any storage )
example helpers are **not** ITB API. ITB only returns the bytes;
persisting them is the caller's responsibility.

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

	// var keyN [64]byte = ...
	// var keyD [64]byte = ...
	// var keyS [64]byte = ...

	fnN, batchN, keyN := hashes.Areion512Pair() // random noise hash key generated
	fnD, batchD, keyD := hashes.Areion512Pair() // random data hash key generated
	fnS, batchS, keyS := hashes.Areion512Pair() // random start hash key generated
	//fnN, batchN := hashes.Areion512PairWithKey(keyN) // [64]byte key
	//fnD, batchD := hashes.Areion512PairWithKey(keyD) // [64]byte key
	//fnS, batchS := hashes.Areion512PairWithKey(keyS) // [64]byte key

	saveKey("noise-key", keyN[:]) // []byte user-supplied persistence
	saveKey("data-key", keyD[:])  // []byte user-supplied persistence
	saveKey("start-key", keyS[:]) // []byte user-supplied persistence

	ns, _ := itb.NewSeed512(2048, fnN) // random noise CSPRNG seeds generated
	ds, _ := itb.NewSeed512(2048, fnD) // random data CSPRNG seeds generated
	ss, _ := itb.NewSeed512(2048, fnS) // random start CSPRNG seeds generated

	saveSeed("noise-seeds", ns.Components) // []uint64 user-supplied persistence
	saveSeed("data-seeds", ds.Components)  // []uint64 user-supplied persistence
	saveSeed("start-seeds", ss.Components) // []uint64 user-supplied persistence

	ns.BatchHash = batchN // must enable batch
	ds.BatchHash = batchD // must enable batch
	ss.BatchHash = batchS // must enable batch

	plaintext := []byte("any text or binary data - including 0x00 bytes")

	// Encrypt into RGBWYOPA container
	encrypted, err := itb.Encrypt512(ns, ds, ss, plaintext)
	if err != nil {
        	panic(err)
	}
	fmt.Printf("encrypted: %d bytes\n", len(encrypted))

	// Send encrypted payload

}

// Receiver

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

	// Receive encrypted payload

	// encrypted := ...

	// var keyN [64]byte = ...
	// var keyD [64]byte = ...
	// var keyS [64]byte = ...

	fnN, batchN, _ := hashes.Areion512Pair([64]byte(loadKey("noise-key")))
	fnD, batchD, _ := hashes.Areion512Pair([64]byte(loadKey("data-key")))
	fnS, batchS, _ := hashes.Areion512Pair([64]byte(loadKey("start-key")))
	//fnN, batchN := hashes.Areion512PairWithKey(keyN) // [64]byte key
	//fnD, batchD := hashes.Areion512PairWithKey(keyD) // [64]byte key
	//fnS, batchS := hashes.Areion512PairWithKey(keyS) // [64]byte key

	ns, _ := itb.SeedFromComponents512(fnN, loadSeed("noise-seeds")...)
	ds, _ := itb.SeedFromComponents512(fnD, loadSeed("data-seeds")...)
	ss, _ := itb.SeedFromComponents512(fnS, loadSeed("start-seeds")...)

	ns.BatchHash = batchN
	ds.BatchHash = batchD
	ss.BatchHash = batchS

	// Decrypt from RGBWYOPA container
	decrypted, err := itb.Decrypt512(ns, ds, ss, encrypted)
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

	// var keyN [64]byte = ...
	// var keyD [64]byte = ...
	// var keyS [64]byte = ...

	fnN, batchN, keyN := hashes.BLAKE2b512Pair() // random noise hash key generated
	fnD, batchD, keyD := hashes.BLAKE2b512Pair() // random data hash key generated
	fnS, batchS, keyS := hashes.BLAKE2b512Pair() // random start hash key generated
	//fnN, batchN := hashes.BLAKE2b512PairWithKey(keyN) // [64]byte key
	//fnD, batchD := hashes.BLAKE2b512PairWithKey(keyD) // [64]byte key
	//fnS, batchS := hashes.BLAKE2b512PairWithKey(keyS) // [64]byte key

	saveKey("noise-key", keyN[:]) // []byte user-supplied persistence
	saveKey("data-key", keyD[:])  // []byte user-supplied persistence
	saveKey("start-key", keyS[:]) // []byte user-supplied persistence

	ns, _ := itb.NewSeed512(2048, fnN) // random noise CSPRNG seeds generated
	ds, _ := itb.NewSeed512(2048, fnD) // random data CSPRNG seeds generated
	ss, _ := itb.NewSeed512(2048, fnS) // random start CSPRNG seeds generated

	saveSeed("noise-seeds", ns.Components) // []uint64 user-supplied persistence
	saveSeed("data-seeds", ds.Components)  // []uint64 user-supplied persistence
	saveSeed("start-seeds", ss.Components) // []uint64 user-supplied persistence

	ns.BatchHash = batchN // must enable batch
	ds.BatchHash = batchD // must enable batch
	ss.BatchHash = batchS // must enable batch

	plaintext := []byte("any text or binary data - including 0x00 bytes")

	// Encrypt into RGBWYOPA container
	encrypted, err := itb.Encrypt512(ns, ds, ss, plaintext)
	if err != nil {
        	panic(err)
	}
	fmt.Printf("encrypted: %d bytes\n", len(encrypted))

	// Send encrypted payload

}

// Receiver

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

	// Receive encrypted payload

	// encrypted := ...

	// var keyN [64]byte = ...
	// var keyD [64]byte = ...
	// var keyS [64]byte = ...

	fnN, batchN, _ := hashes.BLAKE2b512Pair([64]byte(loadKey("noise-key")))
	fnD, batchD, _ := hashes.BLAKE2b512Pair([64]byte(loadKey("data-key")))
	fnS, batchS, _ := hashes.BLAKE2b512Pair([64]byte(loadKey("start-key")))
	//fnN, batchN := hashes.BLAKE2b512PairWithKey(keyN) // [64]byte key
	//fnD, batchD := hashes.BLAKE2b512PairWithKey(keyD) // [64]byte key
	//fnS, batchS := hashes.BLAKE2b512PairWithKey(keyS) // [64]byte key

	ns, _ := itb.SeedFromComponents512(fnN, loadSeed("noise-seeds")...)
	ds, _ := itb.SeedFromComponents512(fnD, loadSeed("data-seeds")...)
	ss, _ := itb.SeedFromComponents512(fnS, loadSeed("start-seeds")...)

	ns.BatchHash = batchN
	ds.BatchHash = batchD
	ss.BatchHash = batchS

	// Decrypt from RGBWYOPA container
	decrypted, err := itb.Decrypt512(ns, ds, ss, encrypted)
	if err != nil {
        	panic(err)
	}
	fmt.Printf("decrypted: %d bytes\n", len(decrypted))

}

```

SipHash24

```go
fnN := hashes.SipHash24()
fnD := hashes.SipHash24()
fnS := hashes.SipHash24()

ns, _ := itb.NewSeed128(1024, fnN) // random noise CSPRNG seeds generated
ds, _ := itb.NewSeed128(1024, fnD) // random data CSPRNG seeds generated
ss, _ := itb.NewSeed128(1024, fnS) // random start CSPRNG seeds generated

saveSeed("noise-seeds", ns.Components) // []uint64 user-supplied persistence
saveSeed("data-seeds", ds.Components)  // []uint64 user-supplied persistence
saveSeed("start-seeds", ss.Components) // []uint64 user-supplied persistence

plaintext := []byte("any text or binary data - including 0x00 bytes")
// Encrypt into RGBWYOPA container
encrypted, _ := itb.Encrypt128(ns, ds, ss, plaintext)
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
