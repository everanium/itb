# macs — cached PRF-grade MAC factories for ITB Authenticated Encryption

Drop-in factories that produce `itb.MACFunc` closures for the three
shipped MAC primitives. All three produce a 32-byte tag and accept
a 32-byte (or longer for the HMAC variants) key. The fixed 32-byte
tag size lets bindings size their authenticated payload buffer the
same way regardless of which MAC was selected.

Every factory pre-keys its primitive once at construction and is
safe to call concurrently from multiple goroutines.

## Canonical primitives

In FFI-stable index order:

| # | Name (FFI)    | Key size | Tag size | Caching |
|---|---------------|---------:|---------:|---------|
| 0 | `kmac256`     | ≥16 B    | 32 B     | cSHAKE256 template with key absorbed once, `Clone()` per call |
| 1 | `hmac-sha256` | ≥16 B    | 32 B     | `sync.Pool` of `hmac.New(sha256.New, key)` instances |
| 2 | `hmac-blake3` | 32 B     | 32 B     | `blake3.NewKeyed(key)` template with `Clone()` per call |

`kmac256` follows NIST SP 800-185 with output length L = 256 bits.
`hmac-sha256` follows RFC 2104 with SHA-256. `hmac-blake3` uses
BLAKE3's native keyed mode (no nested HMAC wrapper — BLAKE3-keyed
is itself a sound keyed PRF; see BLAKE3 spec section 6).

## Usage

Native Go API — generate a fresh random key, save it for persistence.

The `saveKey(name, bytes)` / `loadKey(name)` key helpers and
`saveSeed(name, components)` / `loadSeed(name)` seed helpers used in the
snippets below are **user-side placeholders** for whatever persistence mechanism
the deployment uses (config file / database / mounted secret / any storage)
example helpers are **not** ITB API. ITB only returns the bytes;
persisting them is the caller's responsibility.

Areion-SoEM has paired (single, batched, fixedKey) constructors so the
AVX-512 batched dispatch path is reachable, paired with KMAC-256 as
the authentication primitive:

```go

// Sender

import (
	"crypto/rand"
	"fmt"
	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/macs"
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

	// KMAC-256 — NIST SP 800-185 keyed XOF, 32-byte key, 32-byte tag.
	var macKey [32]byte
	rand.Read(macKey[:])
	saveKey("mac-key", macKey[:]) // []byte user-supplied persistence

	mac, _ := macs.KMAC256(macKey[:])

	plaintext := []byte("any text or binary data - including 0x00 bytes")

	// Authenticated encrypt — 32-byte tag is computed across the entire
	// decrypted capacity and embedded inside the RGBWYOPA container,
	// preserving oracle-free deniability.
	encrypted, err := itb.EncryptAuthenticated512(ns, ds, ss, plaintext, mac)
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
	"github.com/everanium/itb/macs"
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

	mac, _ := macs.KMAC256(loadKey("mac-key"))

	// Authenticated decrypt — any single-bit tamper triggers MAC failure
	// (no oracle leak about which byte was tampered).
	decrypted, err := itb.DecryptAuthenticated512(ns, ds, ss, encrypted, mac)
	if err != nil {
		panic(err)
	}
	fmt.Printf("decrypted: %d bytes\n", len(decrypted))

}

```

BLAKE2b-512 has paired (single, batched, fixedKey) constructors so the
AVX-512 ZMM-batched chain-absorb dispatch path is reachable, paired with
HMAC-BLAKE3 as the authentication primitive:

```go

// Sender

import (
	"crypto/rand"
	"fmt"
	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/macs"
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

	// HMAC-BLAKE3 — fastest of the three MACs through the AVX-512 ASM kernel.
	var macKey [32]byte
	rand.Read(macKey[:])
	saveKey("mac-key", macKey[:]) // []byte user-supplied persistence

	mac, _ := macs.HMACBLAKE3(macKey[:])

	plaintext := []byte("any text or binary data - including 0x00 bytes")

	// Authenticated encrypt — 32-byte tag is computed across the entire
	// decrypted capacity and embedded inside the RGBWYOPA container,
	// preserving oracle-free deniability.
	encrypted, err := itb.EncryptAuthenticated512(ns, ds, ss, plaintext, mac)
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
	"github.com/everanium/itb/macs"
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

	mac, _ := macs.HMACBLAKE3(loadKey("mac-key"))

	// Authenticated decrypt — any single-bit tamper triggers MAC failure
	// (no oracle leak about which byte was tampered).
	decrypted, err := itb.DecryptAuthenticated512(ns, ds, ss, encrypted, mac)
	if err != nil {
		panic(err)
	}
	fmt.Printf("decrypted: %d bytes\n", len(decrypted))

}

```

SipHash24 + HMAC-SHA256

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

// HMAC-SHA256 — universal interoperability standard (RFC 4231).
var macKey [32]byte
rand.Read(macKey[:])
saveKey("mac-key", macKey[:]) // []byte user-supplied persistence
mac, _ := macs.HMACSHA256(macKey[:])

plaintext := []byte("any text or binary data - including 0x00 bytes")
// Authenticated encrypt into RGBWYOPA container with embedded 32-byte tag
encrypted, _ := itb.EncryptAuthenticated128(ns, ds, ss, plaintext, mac)
```

Name-keyed dispatch (used by the FFI layer; works for any code that
selects the MAC primitive at runtime). The key is `[]byte` (size
validated against the primitive's minimum / fixed length):

```go
mac, _ := macs.Make("hmac-sha256", key)
```

`KMAC256` has a `WithCustomization` counterpart for domain
separation across distinct usages of the same key. `HMACSHA256`
and `HMACBLAKE3` take the key as their only argument — there is
no separate `WithKey` variant since the key is already the only
state the factory holds.

## Why these three

ITB's MAC-Inside-Encrypt construction places the 32-byte tag inside
the encrypted container. The barrier dispersal
(`process128 / 256 / 512`) destroys the plaintext / tag boundary an
attacker could otherwise observe; under `SetLockSoup(1)` the
bit-permutation layer further obscures the payload region. So the
MAC primitive itself only has to be a sound keyed PRF — the
surrounding ITB construction handles placement-hiding,
replay-resistance (per-message nonce), and CCA-resistance.

Three primitives keep the choice tractable:

- **`kmac256`** — modern NIST-standard keyed XOF (SP 800-185), based
  on the well-vetted Keccak permutation.
- **`hmac-sha256`** — universal interoperability standard,
  hardware-accelerated through SHA-NI on amd64 / arm64 where the
  underlying CPU exposes the SHA-256 round instructions.
- **`hmac-blake3`** — fastest of the three through BLAKE3's
  AVX-512 ASM kernel.

## Validation

- `hmac-sha256` is bit-exactly cross-checked against
  RFC 4231 test vectors in `macs_test.go`.
- `hmac-blake3` rests on the upstream `github.com/zeebo/blake3`
  project's own keyed-mode KAT.
- `kmac256` is bit-exactly cross-checked against four KAT
  vectors generated from pycryptodome 3.23.0
  (`Crypto.Hash.KMAC256`, an audited NIST SP 800-185 reference
  implementation): three are L = 256 analogues of NIST SP 800-185
  Annex A samples 4 / 5 / 6 (sample 4 message
  `00 01 02 03`, sample 5 with customization
  `My Tagged Application`, sample 6 with the 200-byte
  `0x00..0xC7` message), plus a degenerate empty-message case.
  Reproduce via the python snippet shown in the test file.
- All three primitives pass `TestITBAuthIntegration` (3 MACs × 3
  hash widths × encrypt/decrypt round trip + bit-flip tamper
  rejection).
