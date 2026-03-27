// Package itb implements ITB (Information-Theoretic Barrier): a parameterized
// symmetric cipher construction that makes hash output unobservable
// under passive observation through an information-theoretic barrier.
//
// # Security Notice
//
// ITB is an experimental construction without peer review or formal certification.
// The information-theoretic barrier is a SOFTWARE-LEVEL property, reinforced by
// two independent mechanisms: noise absorption (CSPRNG) and encoding ambiguity
// (rotation from triple-seed isolation). It provides NO guarantees against
// hardware-level attacks including: power analysis (DPA/SPA),
// microarchitectural side-channels (Spectre, Meltdown, Rowhammer, cache timing),
// undiscovered side-channel leakages, or CSPRNG implementation weaknesses.
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
// PRF-grade hash functions are required. The barrier provides additional
// architectural hardening by making hash output unobservable.
//
// # Architecture
//
// The construction is parameterized by:
//
//   - Hash function: pluggable, zero built-in dependencies. Three width variants:
//     [HashFunc128] (128-bit), [HashFunc256] (256-bit), [HashFunc512] (512-bit).
//     Users supply SipHash-2-4, AES-CMAC, BLAKE2b, BLAKE2s, BLAKE3, or any
//     other conforming PRF function.
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
//     Effective max key: 2048 bits. Targets: BLAKE3 keyed.
//
//   - 512-bit ([Seed512], [Encrypt512], [Decrypt512]): uses [HashFunc512]
//     with 512-bit intermediate state (8 components per round).
//     Effective max key: 2048 bits (with current [MaxKeyBits]).
//     Targets: BLAKE2b-512 (native 512-bit key and output).
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
//	Hash function             | State width | API            | Effective max key
//	SipHash-2-4, AES-CMAC     | 128 bits    | Encrypt128     | 1024 bits
//	BLAKE2b-256, BLAKE2s,     |             |                |
//	  BLAKE3 keyed             | 256 bits    | Encrypt256     | 2048 bits
//	BLAKE2b-512                | 512 bits    | Encrypt512     | 2048 bits
//
// # Security Properties
//
//   - Information-theoretic barrier: hash output consumed by modification of
//     random pixels — not reconstructible from observations. Any hash function
//     with non-invertible, non-affine, avalanche mixing surviving the
//     XOR-chain is sufficient. PRF required; the barrier hardens PRF
//     by making hash output unobservable.
//
//   - Known-plaintext resistance (under passive observation): even with fully known plaintext,
//     the attacker cannot derive hash outputs because original container pixel
//     values are unknown (crypto/rand, never transmitted).
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
// # Quick Start
//
//	import (
//	    "github.com/dchest/siphash"
//	    "github.com/everanium/itb"
//	)
//
//	// Optional: global configuration (all thread-safe, atomic)
//	itb.SetMaxWorkers(4)    // limit to 4 CPU cores (default: all CPUs)
//	itb.SetNonceBits(256)   // 256-bit nonce (default: 128-bit)
//	itb.SetBarrierFill(4)   // CSPRNG fill margin (default: 1, valid: 1,2,4,8,16,32)
//
//	// SipHash-2-4 (128-bit hash, 1024-bit effective key)
//	func sipHash128(data []byte, seed0, seed1 uint64) (uint64, uint64) {
//	    return siphash.Hash128(seed0, seed1, data)
//	}
//
//	ns, _ := itb.NewSeed128(1024, sipHash128)
//	ds, _ := itb.NewSeed128(1024, sipHash128)
//	ss, _ := itb.NewSeed128(1024, sipHash128)
//
//	encrypted, _ := itb.Encrypt128(ns, ds, ss, plaintext)
//	decrypted, _ := itb.Decrypt128(ns, ds, ss, encrypted)
//
//	// AES-NI Cached (128-bit hash, 1024-bit effective key, stdlib)
//	func makeAESHash() itb.HashFunc128 {
//	    var key [16]byte
//	    rand.Read(key[:])
//	    block, _ := aes.NewCipher(key[:])
//
//	    return func(data []byte, seed0, seed1 uint64) (uint64, uint64) {
//	        var b [16]byte
//	        copy(b[:], data)
//	        binary.LittleEndian.PutUint64(b[0:], binary.LittleEndian.Uint64(b[0:])^seed0)
//	        binary.LittleEndian.PutUint64(b[8:], binary.LittleEndian.Uint64(b[8:])^seed1)
//	        block.Encrypt(b[:], b[:])
//	        for j := 16; j < len(data); j++ { b[j-16] ^= data[j] }
//	        block.Encrypt(b[:], b[:])
//	        return binary.LittleEndian.Uint64(b[:8]), binary.LittleEndian.Uint64(b[8:])
//	    }
//	}
//
//	ns, _ = itb.NewSeed128(1024, makeAESHash())
//	ds, _ = itb.NewSeed128(1024, makeAESHash())  // independent key per seed
//	ss, _ = itb.NewSeed128(1024, makeAESHash())
//
//	// BLAKE3 Keyed Cached (256-bit hash, 2048-bit effective key, sync.Pool)
//	func makeBlake3Hash() itb.HashFunc256 {
//	    var key [32]byte
//	    rand.Read(key[:])
//	    template, _ := blake3.NewKeyed(key[:])
//	    pool := &sync.Pool{New: func() any { b := make([]byte, 0, 128); return &b }}
//
//	    return func(data []byte, seed [4]uint64) [4]uint64 {
//	        h := template.Clone()
//	        ptr := pool.Get().(*[]byte)
//	        mixed := *ptr
//	        if cap(mixed) < len(data) { mixed = make([]byte, len(data)) } else { mixed = mixed[:len(data)] }
//	        copy(mixed, data)
//	        for i := 0; i < 4; i++ {
//	            off := i * 8
//	            if off+8 <= len(mixed) {
//	                binary.LittleEndian.PutUint64(mixed[off:], binary.LittleEndian.Uint64(mixed[off:])^seed[i])
//	            }
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
//	ns256, _ := itb.NewSeed256(2048, makeBlake3Hash())
//	ds256, _ := itb.NewSeed256(2048, makeBlake3Hash())
//	ss256, _ := itb.NewSeed256(2048, makeBlake3Hash())
//
//	encrypted, _ = itb.Encrypt256(ns256, ds256, ss256, plaintext)
//	decrypted, _ = itb.Decrypt256(ns256, ds256, ss256, encrypted)
//
//	// BLAKE2b-512 Keyed Cached (512-bit hash, 2048-bit effective key, sync.Pool)
//	func makeBlake2bHash512() itb.HashFunc512 {
//	    var key [64]byte
//	    rand.Read(key[:])
//	    pool := &sync.Pool{New: func() any { b := make([]byte, 0, 128); return &b }}
//
//	    return func(data []byte, seed [8]uint64) [8]uint64 {
//	        need := 64 + len(data)
//	        ptr := pool.Get().(*[]byte)
//	        buf := *ptr
//	        if cap(buf) < need { buf = make([]byte, need) } else { buf = buf[:need] }
//	        copy(buf[:64], key[:])
//	        copy(buf[64:], data)
//	        for i := 0; i < 8; i++ {
//	            off := 64 + i*8
//	            if off+8 <= len(buf) {
//	                binary.LittleEndian.PutUint64(buf[off:], binary.LittleEndian.Uint64(buf[off:])^seed[i])
//	            }
//	        }
//	        digest := blake2b.Sum512(buf)
//	        *ptr = buf; pool.Put(ptr)
//	        var result [8]uint64
//	        for i := range result {
//	            result[i] = binary.LittleEndian.Uint64(digest[i*8:])
//	        }
//	        return result
//	    }
//	}
//
//	ns512, _ := itb.NewSeed512(2048, makeBlake2bHash512())
//	ds512, _ := itb.NewSeed512(2048, makeBlake2bHash512())
//	ss512, _ := itb.NewSeed512(2048, makeBlake2bHash512())
//
//	encrypted, _ = itb.Encrypt512(ns512, ds512, ss512, plaintext)
//	decrypted, _ = itb.Decrypt512(ns512, ds512, ss512, encrypted)
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
// For best throughput, use 512-bit ITB key — security becomes P × 2^1536
// (3 × 512), stronger than Single 1024-bit, while ChainHash runs at 512-bit
// speed. See [ITB3.md] for accessible explanation and [BENCH3.md] for benchmarks.
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
