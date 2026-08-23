// Package itb implements ITB (Information-Theoretic Barrier): a parameterized
// symmetric cipher construction that makes hash output unobservable
// under passive observation through an information-theoretic barrier.
//
// # Security Notice
//
// ITB is an experimental construction without peer review or formal certification.
// The information-theoretic barrier is a SOFTWARE-LEVEL property, reinforced by
// two independent barrier mechanisms: noise absorption from CSPRNG, and
// encoding ambiguity (56^P without CCA, 7^P under CCA) from triple-seed
// isolation. Architectural layers deny the point of application: independent
// startSeed and 8-noisePos ambiguity from independent noiseSeed under Full
// KPA, plus gcd(7,8)=1 byte-splitting under Partial KPA. Full KPA defense is
// 3-factor under PRF assumption (4-factor under Partial KPA) — see PROOFS.md
// Proof 4a. It provides NO guarantees against hardware-level attacks
// including: power analysis (DPA/SPA), microarchitectural side-channels
// (Spectre, Meltdown, Rowhammer, cache timing), undiscovered side-channel
// leakages, or CSPRNG implementation weaknesses.
//
// PRF-grade hash functions are required. No warranty is provided.
//
// ITB encrypts arbitrary binary data into raw RGBWYOPA pixel containers
// generated from crypto/rand. Each pixel has 8 channels (Red, Green, Blue,
// White, Yellow, Orange, Purple, Alpha) with 7 data bits and 1 noise bit per
// channel, yielding 56 data bits per pixel at 1.14× overhead. The random container
// creates a barrier between the construction's internal state and the observer:
// hash outputs are consumed by modifications of random pixel values and are
// not reconstructible from observations.
//
// # Central Design Idea
//
// The random container creates an information-theoretic barrier: hash output
// is consumed by a modification of a random pixel, making it unobservable.
// PRF required. PRF closes the candidate-verification step; under Full KPA,
// barrier and architectural layers (triple-seed isolation, encoding
// ambiguity, independent startSeed) deny the point of application — 3-factor
// combination under PRF assumption; gcd(7,8)=1 byte-splitting adds a 4th
// factor under Partial KPA (see PROOFS.md Proof 4a).
//
// # Architecture
//
// The construction is parameterized by:
//
//   - Hash function: pluggable, zero built-in dependencies. Three width variants:
//     [HashFunc128] (128-bit), [HashFunc256] (256-bit), [HashFunc512] (512-bit).
//     Users supply Areion-SoEM-256, Areion-SoEM-512, SipHash-2-4, AES-CMAC,
//     BLAKE2b, BLAKE2s, BLAKE3, or any other conforming PRF function.
//
//   - Key size: minimum 512 bits (8 components) per seed, up to [MaxKeyBits]
//     (2048). Three independent seeds: noiseSeed, dataSeed, startSeed.
//     Create seeds with [NewSeed128] / [NewSeed256] / [NewSeed512] (random)
//     or [SeedFromComponents128] / [SeedFromComponents256] /
//     [SeedFromComponents512] (deterministic).
//     Effective security depends on the hash width:
//     128-bit hash → 1024-bit max, 256-bit hash → 2048-bit max,
//     512-bit hash → 2048-bit max.
//
//   - Nonce: configurable per-message nonce generated internally from
//     crypto/rand. Default [NonceSize] = 128-bit; call [SetNonceBits] to
//     select 128, 256, or 512 bits. Mandatory — prevents configuration
//     reuse across messages. Birthday collision at ~2^(nonceBits/2) messages.
//
// # Easter egg
//
// MD5 128-bit + ITB + 512-bit nonce — arithmetically "safe" (2^-256 gate never fires).
// Mathematically correct. Cryptographically a joke. Do not ship.
// Look Phase 2a in REDTEAM.md
//
// # Hash Width Variants
//
// The library provides three parallel API sets for different hash output widths:
//
//   - 128-bit ([Seed128], [Encrypt128], [Decrypt128]): uses [HashFunc128]
//     with 128-bit intermediate state (2 components per round).
//     Effective max key: 1024 bits. Targets: SipHash-2-4, AES-CMAC.
//
//   - 256-bit ([Seed256], [Encrypt256], [Decrypt256]): uses [HashFunc256]
//     with 256-bit intermediate state (4 components per round).
//     Effective max key: 2048 bits. Targets: Areion-SoEM-256, BLAKE3.
//
//   - 512-bit ([Seed512], [Encrypt512], [Decrypt512]): uses [HashFunc512]
//     with 512-bit intermediate state (8 components per round).
//     Effective max key: 2048 bits (with current [MaxKeyBits]).
//     Targets: Areion-SoEM-512, BLAKE2b-512 (native 512-bit key and output).
//
// All three variants share the same RGBWYOPA pixel format, COBS framing,
// triple-seed architecture, and security properties. The wider hash output
// is truncated to uint64 for per-pixel config extraction (only 62 bits needed).
// The benefit is in ChainHash intermediate state width, not per-pixel extraction.
//
// # RGBWYOPA Pixel Format
//
// Each pixel has 8 channels × 8 bits = 64 bits total:
//
//   - 7 data bits per channel (56 data bits per pixel)
//   - 1 noise bit per channel (8 noise bits per pixel)
//   - Overhead: 64/56 = 1.14×
//
// Triple-seed architecture: noiseSeed determines the noise bit position
// (any of 0-7), dataSeed determines data rotation (0-6) and per-bit
// XOR masks, startSeed determines pixel start offset. All three seeds
// are independent — compromise of one does not reveal the others.
// dataSeed has zero software-observable side-channel exposure (register-only operations).
// Config per pixel: 3 bits from noiseSeed + 59 bits from dataSeed
// (3 rotation + 56 XOR) = 62 total.
//
// # Effective Key Size by Hash Function
//
// The chained hash construction passes intermediate state through the hash
// function's output width, creating a bottleneck:
//
//	ITB Single Ouroboros
//
//	Hash function          | Hash key | API        | Recommended
//	Areion-SoEM-256        | 256 bits | Encrypt256 | 1024 bits
//	Areion-SoEM-512        | 512 bits | Encrypt512 | 1024 bits
//	SipHash-2-4, AES-CMAC  | 128 bits | Encrypt128 | 1024 bits
//	BLAKE2b-256, BLAKE2s   | 256 bits | Encrypt256 | 1024 bits
//	BLAKE3, ChaCha20       | 256 bits | Encrypt256 | 1024 bits
//	BLAKE2b-512            | 512 bits | Encrypt512 | 1024 bits

//
//	ITB Triple Ouroboros

//	Hash function          | Hash key | API          | Recommended
//	Areion-SoEM-256        | 256 bits | Encrypt3x256 | 1024 bits
//	Areion-SoEM-512        | 512 bits | Encrypt3x512 | 1024 bits
//	SipHash-2-4, AES-CMAC  | 128 bits | Encrypt3x128 | 1024 bits
//	BLAKE2b-256, BLAKE2s   | 256 bits | Encrypt3x256 | 1024 bits
//	BLAKE3, ChaCha20       | 256 bits | Encrypt3x256 | 1024 bits
//	BLAKE2b-512            | 512 bits | Encrypt3x512 | 1024 bits

// # Security Properties
//
//   - Information-theoretic barrier: hash output consumed by modification of
//     random pixels — not reconstructible from observations. Any hash function
//     with non-invertible, non-affine, avalanche mixing surviving the
//     XOR-chain is sufficient. PRF required; PRF and barrier are complementary —
//     neither sufficient alone (see PROOFS.md Proof 4a).
//
//   - Known-plaintext resistance (3-factor under PRF assumption, 4-factor under Partial KPA): even with
//     fully known plaintext, the attacker cannot derive hash outputs because
//     original container pixel values are unknown (crypto/rand, never
//     transmitted). Under Full KPA, defense is 3-factor: PRF non-invertibility
//
//   - independent startSeed + 7-rotation × 8-noisePos per-pixel ambiguity.
//     gcd(7,8)=1 byte-splitting is a 4th factor effective only under Partial
//     KPA (see PROOFS.md Proof 4a).
//
//   - Oracle-free deniability: no size headers, no checksums. COBS + null
//     terminator under encryption. Wrong seed produces random-looking output
//     with no verification oracle for brute-force.
//
//   - Per-message nonce (default 128-bit, configurable to 256 or 512 via
//     [SetNonceBits]) prevents configuration reuse. Birthday collision
//     bounds depend on nonce size: ~2^64 messages at 128-bit, ~2^128 at
//     256-bit, ~2^256 at 512-bit. Practically safe collision probability
//     (~2^{-33}): ~2^48 / ~2^112 / ~2^240 messages respectively.
//
//   - Triple-seed isolation: CCA reveals noiseSeed config only (MAC + Reveal
//     only) (noise positions), cache side-channel reveals startPixel only
//     (pixel offset derived from startSeed). dataSeed config (rotation + XOR) is completely
//     independent, register-only, and unobservable. After CCA removes noise bits,
//     guaranteed CSPRNG residue in data positions preserves ambiguity (Proof 10).
//
//   - Information-theoretic barrier of 2^(8P) where P = pixel count.
//     Minimum container sized so encoding ambiguity exceeds key space:
//     [MinPixels] = ceil(keyBits / log2(56)) for Encrypt/Decrypt/Stream
//     (56^P > 2^keyBits); [MinPixelsAuth] = ceil(keyBits / log2(7)) for
//     authenticated variants (7^P > 2^keyBits, CCA-resistant).
//     At 1024-bit: MinPixels=177, MinPixelsAuth=365.
//     Noise barrier at MinPixels=177 (P=196 after square rounding): 2^(8×196) = 2^1568,
//     far beyond the Landauer limit of ~2^306.
//
// # Quick Start (Recommended) — triple.Pipeline
//
// The high-level [github.com/everanium/itb/triple.Pipeline] replaces
// the low-level setup ceremony (per-seed PRF closures, BatchHash
// wiring, MAC factory, parallax + wrapper masters) with one
// [github.com/everanium/itb/triple.Init] call. The Pipeline
// allocates the eight ITB seeds + optional parallax layer + optional
// wrapper layer + MAC closure, snapshots the global configuration
// into a per-instance [Config], and exposes the two cipher shapes
// (message, stream) plus a lifecycle
// (Init / Open / Rekey / Close). Cross-process persistence is one
// method call per side: [github.com/everanium/itb/triple.Init]
// returns the session blob, [github.com/everanium/itb/triple.Open]
// reconstructs the receiver.
//
// A single triple.Pipeline is safe for concurrent
// [github.com/everanium/itb/triple.Pipeline.EncryptStream] /
// [github.com/everanium/itb/triple.Pipeline.EncryptMessage] calls
// from multiple goroutines; per-call state lives on the caller's
// stack. Rekey mutates Pipeline state and must be serialised against
// concurrent cipher-path calls. The low-level free functions
// [Encrypt128Cfg] / [EncryptAuthenticated128Cfg] (and the 256 / 512
// width counterparts) take read-only Seed pointers and allocate
// output per call — they are thread-safe under concurrent invocation
// on the same seeds; only the shared [Config] pointer requires
// caller-side serialisation when setters race with readers.
//
//	import "github.com/everanium/itb"
//	import "github.com/everanium/itb/triple"
//
//	itb.SetMaxWorkers(8)    // limit to 8 CPU cores (default: all CPUs)
//
//	// Full-stack Streaming AEAD Triple (MAC Authenticated, parallax + wrapper on).
//	sender, blob, err := triple.Init(triple.ProfileStreamingAEADTripleMACV1, triple.Opts{
//		NonceBits: 512, BarrierFill: 4,
//	})
//	if err != nil {
//		panic(err)
//	}
//	defer sender.Close()
//
//	receiver, err := triple.Open(triple.ProfileStreamingAEADTripleMACV1, blob, triple.Opts{})
//	if err != nil {
//		panic(err)
//	}
//	defer receiver.Close()
//
//	wire, _ := sender.EncryptMessage(plaintext)
//	recovered, _ := receiver.DecryptMessage(wire)
//
//	// Streaming shape (io.Reader / io.Writer) is available on the
//	// same Pipeline via triple.Pipeline.EncryptStream /
//	// triple.Pipeline.DecryptStream.
//
// Streaming on the triple surface is driven end-to-end by the
// Pipeline: hand
// [github.com/everanium/itb/triple.Pipeline.EncryptStream] an
// [io.Reader] over the plaintext and an [io.Writer] over the wire
// and it drives the chunk loop internally (parallax
// encrypt-Reader → itb Triple 8-seed Streaming AEAD → wrapper
// wrap-Writer). The receiver mirrors with
// [github.com/everanium/itb/triple.Pipeline.DecryptStream]. Callers
// that only have a byte slice at hand use
// [github.com/everanium/itb/triple.Pipeline.EncryptMessage] /
// [github.com/everanium/itb/triple.Pipeline.DecryptMessage] — the
// byte shape is identical when the plaintext fits in one chunk.
//
// # Quick Start (low-level)
//
//	import (
//	    "github.com/everanium/itb"
//	    "github.com/everanium/itb/hashes"
//	)
//
//	// Optional: global configuration (all thread-safe, atomic)
//	itb.SetMaxWorkers(4)    // limit to 4 CPU cores (default: all CPUs)
//	itb.SetNonceBits(256)   // 256-bit nonce (default: 128-bit)
//	itb.SetBarrierFill(4)   // CSPRNG fill margin (default: 1, valid: 1,2,4,8,16,32)
//
//	// The 48-bit interlock overlay is always engaged for Triple
//	// Ouroboros and non-disableable by construction.
//
//	// Areion-SoEM-256 with built-in batched VAES dispatch — fastest 256-bit
//	// PRF wiring, recommended default. The paired factory returns (single,
//	// batched, fixedKey) sharing the same fixed key; ITB processChunk256
//	// dispatches per-pixel hashing four pixels per batched call. The
//	// runtime CPU detection picks the most capable VAES tier available —
//	// AVX-512+VAES on ZMM (Intel Ice Lake+, AMD Zen 4+), AVX2+VAES on
//	// YMM (AMD Zen 3, Alder Lake E-cores), or a portable Go fallback via
//	// aes.Round4HW on hardware without VAES (correctness preserved on
//	// every platform).
//	//
//	// Pass nothing for a CSPRNG-generated key (returned alongside the
//	// closure for cross-process persistence — save it!) or pass a saved
//	// [32]byte key on the restore path. Three independent factory calls
//	// give three independent fixed keys.
//	fnN, batchN, keyN := itb.MakeAreionSoEM256Hash()
//	fnD, batchD, keyD := itb.MakeAreionSoEM256Hash()
//	fnS, batchS, keyS := itb.MakeAreionSoEM256Hash()
//	saveKey("noise-key", keyN[:]) // persistence — write to config / KMS
//	saveKey("data-key", keyD[:]) // persistence — write to config / KMS
//	saveKey("start-key", keyS[:]) // persistence — write to config / KMS
//	ns256, _ := itb.NewSeed256(1024, fnN)
//	ds256, _ := itb.NewSeed256(1024, fnD)
//	ss256, _ := itb.NewSeed256(1024, fnS)
//	ns256.BatchHash = batchN
//	ds256.BatchHash = batchD
//	ss256.BatchHash = batchS
//	// (analogous wiring for ns256, ds256, ss256 — three independent (hashFn, batchFn, hashKey)
//	// triples, three independent saved keys)
//
//	encrypted, _ := itb.Encrypt256(ns256, ds256, ss256, plaintext)
//	decrypted, _ := itb.Decrypt256(ns256, ds256, ss256, encrypted)
//
//	// Areion-SoEM-512 with batched VAES dispatch — same factory pattern,
//	// 64-byte key, 64-byte input, 8 × uint64 seed. Use itb.NewSeed512 +
//	// itb.Encrypt512 / itb.Decrypt512 in place of the 256-bit variants.
//	fnN, batchN, keyN := itb.MakeAreionSoEM512Hash()
//	fnD, batchD, keyD := itb.MakeAreionSoEM512Hash()
//	fnS, batchS, keyS := itb.MakeAreionSoEM512Hash()
//	saveKey("noise-key", keyN[:]) // persistence — write to config / KMS
//	saveKey("data-key", keyD[:]) // persistence — write to config / KMS
//	saveKey("start-key", keyS[:]) // persistence — write to config / KMS
//	ns512, _ := itb.NewSeed512(2048, fnN)
//	ds512, _ := itb.NewSeed512(2048, fnD)
//	ss512, _ := itb.NewSeed512(2048, fnS)
//	ns512.BatchHash = batchN
//	ds512.BatchHash = batchD
//	ss512.BatchHash = batchS
//	// (analogous wiring for ns512, ds512, ss512 — three independent (hashFn, batchFn, hashKey)
//	// triples, three independent saved keys)
//
//	encrypted, _ := itb.Encrypt512(ns512, ds512, ss512, plaintext)
//	decrypted, _ := itb.Decrypt512(ns512, ds512, ss512, encrypted)
//
//	// Other PRF primitives — use the hashes/ subpackage. Same variadic
//	// pattern: pass nothing for random key, pass a saved key for restore.
//	// Returned key is always emitted as the second value — capture it
//	// for persistence (test fixtures discard via `_`).
//
//	// SipHash-2-4 (128-bit hash, 1024-bit effective key) — exception:
//	// no internal fixed key (keying material is the seed components),
//	// so this is the only factory that returns just one value.
//	ns, _ := itb.NewSeed128(1024, hashes.SipHash24())
//	ds, _ := itb.NewSeed128(1024, hashes.SipHash24())
//	ss, _ := itb.NewSeed128(1024, hashes.SipHash24())
//
//	encrypted, _ := itb.Encrypt128(ns, ds, ss, plaintext)
//	decrypted, _ := itb.Decrypt128(ns, ds, ss, encrypted)
//
//	// AES-CMAC (128-bit hash, 1024-bit effective key, AES-NI hardware
//	// path on amd64 / arm64 hosts that expose the AES round instructions)
//	aesFn, aesKey := hashes.AESCMAC()
//	saveKey("aescmac-noise", aesKey[:])
//	ns, _ = itb.NewSeed128(1024, aesFn)
//	// (repeat for ds, ss with independent keys; saveKey omitted in subsequent
//	// snippets for brevity — but always required on the persistence path)
//
//	// BLAKE3 keyed (256-bit hash, 2048-bit effective key)
//	b3Fn, b3Key := hashes.BLAKE3()
//	_ = b3Key
//	ns256, _ = itb.NewSeed256(2048, b3Fn)
//
//	// BLAKE2b-512 (512-bit hash, 2048-bit effective key, native 512-bit
//	// output and up to 64-byte key)
//	b2Fn, b2Key := hashes.BLAKE2b512()
//	_ = b2Key
//	ns512, _ = itb.NewSeed512(2048, b2Fn)
//
//	// Custom factory pattern (advanced) — write your own HashFunc when
//	// you need a primitive not covered by the hashes/ subpackage, or
//	// want a different keying / pooling strategy. The pattern below
//	// is what hashes.BLAKE3() itself ships, reproduced here as a
//	// reference. Three techniques worth noting:
//	//
//	//   - sync.Pool amortises per-call allocation of the scratch buffer
//	//   - blake3.NewKeyed produces a hasher template; Clone() per call
//	//     sidesteps the data race that Reset() on a shared hasher would
//	//     cause under ITB's parallel goroutines in process256
//	//   - the payload region is zero-padded out to seedInjectBytes (32)
//	//     so all four seed uint64's contribute even when len(data) is
//	//     shorter than 32 (e.g. a 20-byte ITB pixel input would
//	//     otherwise drop seed[2..3] silently)
//	func makeBlake3Hash() itb.HashFunc256 {
//	    var key [32]byte
//	    rand.Read(key[:])
//	    template, _ := blake3.NewKeyed(key[:])
//	    pool := &sync.Pool{New: func() any { b := make([]byte, 0, 128); return &b }}
//
//	    return func(data []byte, seed [4]uint64) [4]uint64 {
//	        h := template.Clone()
//	        const seedInjectBytes = 32
//	        payloadLen := len(data)
//	        if payloadLen < seedInjectBytes { payloadLen = seedInjectBytes }
//	        ptr := pool.Get().(*[]byte)
//	        mixed := *ptr
//	        if cap(mixed) < payloadLen { mixed = make([]byte, payloadLen) } else { mixed = mixed[:payloadLen] }
//	        for i := len(data); i < payloadLen; i++ { mixed[i] = 0 }
//	        copy(mixed[:len(data)], data)
//	        for i := 0; i < 4; i++ {
//	            off := i * 8
//	            binary.LittleEndian.PutUint64(mixed[off:], binary.LittleEndian.Uint64(mixed[off:])^seed[i])
//	        }
//	        h.Write(mixed)
//	        *ptr = mixed; pool.Put(ptr)
//	        var buf [32]byte
//	        h.Sum(buf[:0])
//	        return [4]uint64{
//	            binary.LittleEndian.Uint64(buf[0:]),  binary.LittleEndian.Uint64(buf[8:]),
//	            binary.LittleEndian.Uint64(buf[16:]), binary.LittleEndian.Uint64(buf[24:]),
//	        }
//	    }
//	}
//
//	ns256, _ = itb.NewSeed256(2048, makeBlake3Hash())
//	ds256, _ = itb.NewSeed256(2048, makeBlake3Hash())
//	ss256, _ = itb.NewSeed256(2048, makeBlake3Hash())
//
// # Authenticated Encryption (MAC-Inside-Encrypt)
//
// The core construction provides confidentiality only. For integrity
// protection, use [EncryptAuthenticated128] (or 256/512 variant) which encrypts
// a MAC tag inside the container, preserving oracle-free deniability. The MAC
// function is pluggable:
//
//	encrypted, _ := itb.EncryptAuthenticated128(ns, ds, ss, plaintext, myMACFunc)
//	decrypted, _ := itb.DecryptAuthenticated128(ns, ds, ss, encrypted, myMACFunc)
//
// [MACFunc] is defined as func([]byte) []byte — any function that takes data
// and returns a fixed-size tag. The MAC covers the entire decrypted capacity
// (COBS + null terminator + fill), preventing CCA spatial pattern leaks.
//
// Authenticated variants are available for all three widths:
// [EncryptAuthenticated128], [EncryptAuthenticated256], [EncryptAuthenticated512],
// [DecryptAuthenticated128], [DecryptAuthenticated256], [DecryptAuthenticated512].
//
// Triple Ouroboros authenticated variants (7 seeds):
// [EncryptAuthenticated3x128], [EncryptAuthenticated3x256], [EncryptAuthenticated3x512],
// [DecryptAuthenticated3x128], [DecryptAuthenticated3x256], [DecryptAuthenticated3x512].
//
// Each authenticated entry point has a Cfg counterpart taking a
// [Config] first argument for per-instance overrides
// ([EncryptAuthenticated128Cfg] / [DecryptAuthenticated128Cfg] and
// the 256/512 mirrors, plus the Triple-Ouroboros
// [EncryptAuthenticated3x128Cfg] / [DecryptAuthenticated3x128Cfg]
// and mirrors). See [Config] / [SnapshotGlobals].
//
// # Short-name aliases
//
// Every authenticated entry point is also reachable under a shorter
// name with the [EncryptAuthenticated] / [DecryptAuthenticated]
// prefix collapsed to [EncryptAuth] / [DecryptAuth] — for example
// [EncryptAuth128] forwards to [EncryptAuthenticated128] and
// [DecryptAuth3x256Cfg] forwards to [DecryptAuthenticated3x256Cfg].
// The alias surface covers all 24 entry points and is allocation-free.
//
// # Width-less convenience helpers
//
// The width-suffixed entry points ([Encrypt128] / [Encrypt256] /
// [Encrypt512] and the corresponding Decrypt / authenticated /
// streaming counterparts) require the caller to pick the correct
// suffix for the chosen seed type. The width-less helpers [Encrypt],
// [Decrypt], [Encrypt3x], [Decrypt3x], [EncryptAuth], [DecryptAuth],
// [EncryptAuth3x], [DecryptAuth3x], [EncryptStream], [DecryptStream],
// [EncryptStream3x], [DecryptStream3x], [EncryptStreamAuth],
// [DecryptStreamAuth], [EncryptStreamAuth3x], and
// [DecryptStreamAuth3x] accept the seed bundle as `any` and dispatch
// internally on the concrete pointer type. All seeds in the bundle
// must carry one matching `*Seed{N}` width; mixing widths returns an
// error. The dispatcher resolves the width once per call and
// forwards verbatim — no allocation beyond what the underlying
// width-suffixed call would do anyway. Callers using a single seed
// width across the application can freeze on the width-less helpers
// without losing performance.
//
// # Streaming (Chunked Encryption)
//
// For large data that exceeds available memory, use the streaming API.
// Data is split into chunks, each encrypted as a self-contained ITB message
// with its own nonce. Chunks can be concatenated and later decrypted
// sequentially. [ChunkSize] selects an appropriate chunk size automatically
// (default [DefaultChunkSize] = 16 MB).
//
//	err := itb.EncryptStream128(ns, ds, ss, largeData, 0, func(chunk []byte) error {
//	    _, err := file.Write(chunk)
//	    return err
//	})
//
//	var result []byte
//	err = itb.DecryptStream128(ns, ds, ss, fileData, func(chunk []byte) error {
//	    result = append(result, chunk...)
//	    return nil
//	})
//
// Streaming variants are available for all three widths:
// [EncryptStream128], [EncryptStream256], [EncryptStream512],
// [DecryptStream128], [DecryptStream256], [DecryptStream512].
//
// Triple Ouroboros streaming variants (7 seeds):
// [EncryptStream3x128], [EncryptStream3x256], [EncryptStream3x512],
// [DecryptStream3x128], [DecryptStream3x256], [DecryptStream3x512].
//
// [ParseChunkLen] inspects the first 20 bytes of a chunk header and
// reports the chunk's total length on the wire, letting external
// streaming consumers (FFI bindings, custom file-format wrappers)
// walk a concatenated chunk stream one chunk at a time without
// buffering the whole stream in memory. The function is also
// exposed through the C ABI as ITB_ParseChunkLen.
//
// Each streaming entry point has a Cfg counterpart taking a
// [Config] first argument for per-instance overrides
// ([EncryptStream128Cfg] / [DecryptStream128Cfg] and the 256/512
// mirrors, plus the Triple-Ouroboros [EncryptStream3x128Cfg] /
// [DecryptStream3x128Cfg] and mirrors). [ParseChunkLenCfg] is the
// matching per-instance chunk-header reader, honouring the cfg's
// own NonceBits when walking a stream produced by an encryptor that
// overrides the global. See [Config] / [SnapshotGlobals].
//
// The width-less plain-stream entry points [EncryptStream] and
// [DecryptStream] (plus the Triple counterparts [EncryptStream3x] /
// [DecryptStream3x]) accept seed pointers typed as `any` and drive
// the read/write loop internally via [io.Reader] / [io.Writer]. They
// dispatch on the concrete seed pointer type to the matching
// width-suffixed per-chunk path. The on-wire bytes are identical to
// the callback-driven helpers above; choice between the two is a
// caller-side ergonomic preference.
//
// # Streaming AEAD (chunked authenticated encryption)
//
// The Streaming AEAD construction binds every chunk's MAC tag to a
// 32-byte CSPRNG-fresh stream anchor (written once as a wire prefix
// preceding chunk 0), the cumulative pixel offset of every preceding
// chunk, and a final-flag bit recovered from inside the encrypted
// container — defending against chunk reorder, replay within or
// across streams sharing the PRF / MAC key, silent mid-stream drop,
// and truncate-tail. The wire format adds 32 bytes of stream prefix
// plus one byte of trailing flag per chunk inside the deniable
// container layout; no externally visible MAC tag.
//
// Per-chunk primitives (one chunk per call, caller drives the loop):
// [EncryptStreamAuthenticated128] / [EncryptStreamAuthenticated256] /
// [EncryptStreamAuthenticated512] and the corresponding
// [DecryptStreamAuthenticated128] / [DecryptStreamAuthenticated256] /
// [DecryptStreamAuthenticated512] entry points, plus the
// Triple-Ouroboros 7-seed variants
// [EncryptStreamAuthenticated3x128] / [EncryptStreamAuthenticated3x256] /
// [EncryptStreamAuthenticated3x512] and decrypt mirrors. Each takes
// the streamID, the running cumulative pixel offset, and finalFlag
// (true on the terminating chunk, false otherwise) explicitly. The
// Cfg counterparts ([EncryptStreamAuthenticated128Cfg] etc., 24 in
// total across width × Single+Triple × Encrypt+Decrypt × no-Cfg+Cfg)
// honour a per-instance [Config] override.
//
// Higher-level helpers covering the per-chunk loop server-side:
// [EncryptStreamAuth128] / [EncryptStreamAuth256] /
// [EncryptStreamAuth512] (and the [EncryptStreamAuth3x{N}] variants)
// drive a per-chunk emit callback under fixed seed handles, drawing
// the 32-byte stream anchor, advancing cumulative pixel offset, and
// flipping finalFlag on the last chunk. The width-less
// [EncryptStreamAuth] / [DecryptStreamAuth] (plus the Triple
// counterparts [EncryptStreamAuth3x] / [DecryptStreamAuth3x])
// instead consume an [io.Reader] and write to an [io.Writer]
// directly, dispatching on the concrete seed pointer type.
// Aliasing follows the same `Authenticated` → `Auth` collapse rule
// used by the Single Message family.
//
// [ErrStreamTruncated] and [ErrStreamAfterFinal] are the two
// stream-specific sentinel errors. Decrypt-side helpers return
// [ErrStreamTruncated] when the on-wire transcript exhausts before
// a chunk with finalFlag = true is observed, and
// [ErrStreamAfterFinal] when additional chunk bytes follow the
// terminating chunk. Either error condition leaves any plaintext
// emitted earlier in the stream trustworthy as far as it went; the
// trailing data after the failure point is rejected verbatim.
//
// # Streaming bindings asymmetry
//
// For the No-MAC paths, the Go core and the
// [github.com/everanium/itb/triple] package expose [io.Reader] /
// [io.Writer] entry points ([EncryptStream] / [DecryptStream] and
// the corresponding [github.com/everanium/itb/triple.Pipeline.EncryptStream] /
// [github.com/everanium/itb/triple.Pipeline.DecryptStream] methods)
// that drive the read/write loop internally. The official bindings
// to other languages expose the No-MAC stream surface as per-chunk
// free functions only and let the caller drive the loop. The two
// patterns produce identical on-wire bytes; choice between them is
// a Go-side convenience.
//
// # Triple Ouroboros (7-seed variant)
//
// Triple Ouroboros splits plaintext into 3 parts at the byte level (every 3rd
// byte), encrypting each into 1/3 of the pixel data with independent dataSeed
// and startSeed, sharing noiseSeed. Output format is identical to standard ITB.
// Security: P × 2^(3×keyBits) under CCA. 7 seeds: 3×dataSeed + 3×startSeed +
// 1×noiseSeed. All seven seeds must be distinct pointers.
//
//	encrypted, _ := itb.Encrypt3x512(noiseSeed, dataSeed1, dataSeed2, dataSeed3,
//	    startSeed1, startSeed2, startSeed3, plaintext)
//	decrypted, _ := itb.Decrypt3x512(noiseSeed, dataSeed1, dataSeed2, dataSeed3,
//	    startSeed1, startSeed2, startSeed3, encrypted)
//
// Available for all three hash widths:
// [Encrypt3x128], [Encrypt3x256], [Encrypt3x512],
// [Decrypt3x128], [Decrypt3x256], [Decrypt3x512].
//
// Each Triple Ouroboros entry point has a Cfg counterpart taking a
// [Config] first argument for per-instance overrides
// ([Encrypt3x128Cfg] / [Decrypt3x128Cfg] and the 256/512 mirrors).
// See [Config] / [SnapshotGlobals].
//
// For best throughput, use 512-bit ITB key — security becomes P × 2^1536
// (3 × 512), stronger than Single 1024-bit, while ChainHash runs at 512-bit
// speed. See [ITB3.md] for accessible explanation and [BENCH3.md] for benchmarks.
//
// # 48-bit Interlock Overlay (Triple Ouroboros)
//
// Every Triple Ouroboros plaintext is driven through a 48-bit
// interlock overlay: each 6-byte chunk is split into three disjoint
// 16-of-48 balanced masks derived from a per-chunk PRF output keyed by
// the noiseSeed-derived (or, when attached, the dedicated lockSeed-
// derived) inter-lock seed and the nonce. The overlay is a
// non-disableable part of the Triple kernel — there is no engage knob
// and no off-branch.
//
// The overlay relocates the SAT-cryptanalysis barrier from the
// computational layer to the instance-formulation layer. Standard
// cryptanalytic intuition pictures SAT recovery as a solver-speed
// problem: "given a defined NP instance, how fast can the attacker
// solve it." The overlay targets the prior question: "does the
// attacker have enough observation to define the instance." Under
// Partial KPA + realistic protocol traffic, the per-snake SAT
// instance is information-theoretically under-determined at typical
// crib coverage — multiple joint (seed, startPixel) tuples satisfy the
// sparse constraint set. Faster solvers, including any hypothetical
// shortcut to PRF inversion, do not widen the crib or convert
// under-determination into determination. This is orthogonal to, not
// stronger than, computational hardness.
//
// Applies uniformly to every Triple Ouroboros variant — [Encrypt3x128] /
// [Decrypt3x128], the 256- / 512-bit mirrors, [EncryptAuthenticated3x128] /
// [DecryptAuthenticated3x128] and their mirrors, and [EncryptStream3x128] /
// [DecryptStream3x128] and mirrors. The ciphertext wire format is
// identical in all configurations.
//
// See [ITB.md] / [ITB3.md] for accessible explanation and [REDTEAM.md]
// for the defensive framing in the SAT attack context.
//
// # Per-instance configuration ([Config], Cfg variants)
//
// Every public encrypt / decrypt entry point has a Cfg counterpart
// taking a [Config] first argument: [Encrypt128Cfg] /
// [Decrypt128Cfg] and the 256/512 mirrors for Single Ouroboros,
// [Encrypt3x128Cfg] / [Decrypt3x128Cfg] and mirrors for Triple
// Ouroboros, the matching authenticated and streaming counterparts,
// and [ParseChunkLenCfg]. A nil cfg falls through to the
// process-global setter state, preserving the legacy entry-point
// behaviour bit-exactly. A non-nil cfg overrides NonceBits /
// BarrierFill / LockSeed on a per-call basis without mutating the
// process globals — multiple encryptors with distinct configurations
// can coexist in one process.
//
// [SnapshotGlobals] returns a fresh [Config] initialised from the
// current global setter state, pinning the per-instance value to
// the global at snapshot time. Subsequent global mutations do not
// leak into a previously-snapshotted [Config]; subsequent mutations
// of a snapshotted [Config] do not leak back into the globals. The
// [github.com/everanium/itb/triple.Pipeline] surface uses this at
// [github.com/everanium/itb/triple.Init] time to seed each
// Pipeline's own [Config] copy.
//
// # State persistence — Blob
//
// [Blob128] / [Blob256] / [Blob512] pack the native-API encryptor
// material (per-seed hash key + Components + optional dedicated
// lockSeed + optional MAC key + name) plus the captured
// process-wide configuration into one self-describing JSON blob.
// Export / Export3 produce the blob; Import / Import3 reverse it,
// applying the captured globals via [SetNonceBits] /
// [SetBarrierFill] before populating the struct's public
// Key* / Components fields. The
// receiver wires Hash / BatchHash from the saved key bytes through
// the matching factory (e.g. [MakeAreionSoEM512HashWithKey]),
// keeping the pluggable-PRF philosophy of the native API. Optional
// LockSeed and MAC slots ride in the trailing [Blob128Opts] /
// [Blob256Opts] / [Blob512Opts] options struct. The
// [github.com/everanium/itb/triple] facade is the high-level
// alternative for callers that prefer constructor-bound primitive
// selection plus auto-coupling of parallax + wrapper masters.
//
// # Dedicated lockSeed
//
// Every Triple Ouroboros entry point takes an eight-seed
// constellation: (noiseSeed, lockSeed, dataSeed1..3, startSeed1..3).
// The lockSeed slot keys the 48-bit interlock overlay's per-chunk
// bit-permutation derivation, and its keying material stays
// independent of the noiseSeed slot's material.
//
// The per-chunk PRF closure captures BOTH the lockSeed's Components
// (independent keying material) AND its Hash function, so the
// overlay channel may legitimately run a different PRF primitive
// from the noise-injection channel within the same native width
// (the *Seed{N} type signatures enforce width match). This yields
// keying-material isolation AND algorithm diversity for
// defence-in-depth on the bit-permutation overlay.
//
// The 48-bit interlock overlay is always engaged, so the lockSeed
// argument is consumed on every Encrypt / Decrypt call — there is
// no toggle to disable the overlay.
//
//	fnN, batchN, _ := itb.MakeAreionSoEM512Hash()
//	fnL, batchL, _ := itb.MakeAreionSoEM512Hash()
//	ns, _ := itb.NewSeed512(2048, fnN); ns.BatchHash = batchN
//	ls, _ := itb.NewSeed512(2048, fnL); ls.BatchHash = batchL
//	// ... ds1..3, ss1..3 as usual, all independently allocated.
//	ct, _ := itb.Encrypt3x512(ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, plaintext)
//
// The [github.com/everanium/itb/triple.Pipeline] surface
// auto-allocates the lockSeed slot at
// [github.com/everanium/itb/triple.Init] time and persists it
// across the exported blob so
// [github.com/everanium/itb/triple.Open] reconstructs the same
// slot — no caller-side bookkeeping required on the high-level path.
//
// # Parallelism Control
//
// Pixel processing is parallelized across available CPU cores by default.
// To limit CPU usage (e.g., on shared servers), use [SetMaxWorkers]:
//
//	itb.SetMaxWorkers(4) // use at most 4 cores
//
// Pass 0 to use all available CPUs (default). Valid range: 0 to 256.
// The setting is global and thread-safe (atomic).
// Query the current limit with [GetMaxWorkers].
//
// # Nonce Configuration
//
// By default the nonce is 128 bits ([NonceSize] = 16 bytes). For higher
// collision resistance, increase the nonce size with [SetNonceBits]:
//
//	itb.SetNonceBits(256) // 256-bit nonce (~2^128 birthday bound)
//
// Valid values: 128, 256, 512. The setting is global and thread-safe (atomic).
// Both sender and receiver must use the same nonce size.
// Query the current setting with [GetNonceBits].
//
// # Barrier Fill (CSPRNG Margin)
//
// The container side is increased by a configurable margin to guarantee
// CSPRNG residue in every container (Proof 10: No Perfect Fill). The gap
// between pixel capacity and data requirement ensures that some pixel
// channels carry only CSPRNG random data, even after CCA eliminates
// noise bits. Default margin is 1. To increase the CSPRNG fill margin:
//
//	itb.SetBarrierFill(4) // side += 4 instead of side += 1
//
// Valid values: 1, 2, 4, 8, 16, 32. Panics on invalid input.
// Asymmetric: the receiver does not need the same value as the sender,
// because the container dimensions are stored in the header.
// The setting is global and thread-safe (atomic).
// Query the current value with [GetBarrierFill].
package itb
