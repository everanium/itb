// Package itb implements ITB (Information-Theoretic Barrier): a parameterized
// symmetric cipher construction that achieves known-plaintext resistance
// under passive observation through an information-theoretic barrier.
//
// # Security Notice
//
// ITB is an experimental construction without peer review or formal certification.
// The information-theoretic barrier is a SOFTWARE-LEVEL property — it provides
// NO guarantees against hardware-level attacks including: power analysis (DPA/SPA),
// microarchitectural side-channels (Spectre, Meltdown, Rowhammer, cache timing),
// undiscovered side-channel leakages, or CSPRNG implementation weaknesses.
//
// The ability to use non-cryptographic hash functions is a theoretical property
// that has NOT been independently verified and provides NO security guarantees.
// For critical applications (government, military, financial, medical,
// critical infrastructure), use ONLY PRF-grade hash functions (SipHash-2-4,
// AES-CMAC, BLAKE2b, BLAKE2s, BLAKE3). Non-cryptographic hash functions (XXH3,
// HighwayHash) are intended solely for research and educational purposes;
// using them in any real-world application is potentially dangerous.
// No warranty of any kind is provided. Use at your own risk.
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
// The random container creates an information-theoretic barrier. PRF-grade
// hash functions are strongly recommended for production use. The construction's
// architecture theoretically permits hash functions satisfying only five weaker
// requirements (full input sensitivity, chain survival, non-affine mixing,
// avalanche, non-invertibility) for research and educational purposes.
//
// # Architecture
//
// The construction is parameterized by:
//
//   - Hash function: pluggable, zero built-in dependencies. Four width variants:
//     [HashFunc] (64-bit), [HashFunc128] (128-bit), [HashFunc256] (256-bit),
//     [HashFunc512] (512-bit).
//     Users supply XXH3, SipHash-2-4, AES-CMAC, HighwayHash, BLAKE2b, BLAKE2s,
//     BLAKE3, or any other conforming function.
//
//   - Key size: minimum 512 bits (8 components) per seed, up to [MaxKeyBits]
//     (2048). Three independent seeds: noiseSeed, dataSeed, startSeed.
//     Create seeds with [NewSeed] / [NewSeed128] / [NewSeed256] / [NewSeed512] (random)
//     or [SeedFromComponents] / [SeedFromComponents128] / [SeedFromComponents256] /
//     [SeedFromComponents512] (deterministic).
//     Effective security depends on the hash width:
//     64-bit hash → 512-bit max, 128-bit hash → 1024-bit max,
//     256-bit hash → 2048-bit max, 512-bit hash → 2048-bit max.
//     Seed methods: [Seed.Bits], [Seed.MinPixels], [Seed.MinSide], [Seed.ChainHash].
//
//   - Nonce: [NonceSize] (128-bit) per-message, generated internally from
//     crypto/rand. Mandatory — prevents configuration reuse across messages.
//
// # Hash Width Variants
//
// The library provides four parallel API sets for different hash output widths:
//
//   - 64-bit ([Seed], [Encrypt], [Decrypt]): uses [HashFunc] with 64-bit
//     intermediate ChainHash state. Effective max key: 512 bits.
//     Targets: XXH3, XXH64.
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
// All four variants share the same RGBWYOPA pixel format, COBS framing,
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
//	XXH3, HighwayHash-64      | 64 bits     | Encrypt        | 512 bits
//	SipHash-2-4, AES-CMAC,   |             |                |
//	  HighwayHash-128         | 128 bits    | Encrypt128     | 1024 bits
//	HighwayHash-256, BLAKE2b, |             |                |
//	  BLAKE2s, BLAKE3 keyed   | 256 bits    | Encrypt256     | 2048 bits
//	BLAKE2b-512               | 512 bits    | Encrypt512     | 2048 bits
//
// # Security Properties
//
//   - Information-theoretic barrier: hash output consumed by modification of
//     random pixels — not reconstructible from observations. Any hash function
//     with non-invertible, non-affine, avalanche mixing surviving the
//     XOR-chain is sufficient. PRF/PRP/PRG properties are relaxed under
//     the random-container model (PRF-grade hash functions recommended).
//
//   - Known-plaintext resistance (under passive observation): even with fully known plaintext,
//     the attacker cannot derive hash outputs because original container pixel
//     values are unknown (crypto/rand, never transmitted).
//
//   - Oracle-free deniability: no size headers, no checksums. COBS + null
//     terminator under encryption. Wrong seed produces random-looking output
//     with no verification oracle for brute-force.
//
//   - Per-message 128-bit nonce prevents configuration reuse. Birthday
//     collision after ~2^64 messages; ~2^48 messages for negligible probability.
//
//   - Triple-seed isolation: CCA reveals noiseSeed config only (noise
//     positions), cache side-channel reveals startSeed only (pixel
//     offset). dataSeed config (rotation + XOR) is completely
//     independent, register-only, and unobservable.
//
//   - Information-theoretic barrier of 2^(8P) where P = pixel count.
//     Minimum container sized so barrier > key space: 2^648 for 512-bit
//     key (81 pixels), far beyond the Landauer limit of ~2^306.
//
// # Quick Start
//
//	import (
//	    "github.com/everanium/itb"
//	    "github.com/zeebo/xxh3"
//	)
//
//	// 64-bit hash (512-bit effective key)
//	noiseSeed, _ := itb.NewSeed(512, xxh3.HashSeed)
//	dataSeed, _ := itb.NewSeed(512, xxh3.HashSeed)
//	startSeed, _ := itb.NewSeed(512, xxh3.HashSeed)
//
//	encrypted, _ := itb.Encrypt(noiseSeed, dataSeed, startSeed, plaintext)
//	decrypted, _ := itb.Decrypt(noiseSeed, dataSeed, startSeed, encrypted)
//
//	// 128-bit hash (1024-bit effective key)
//	ns128, _ := itb.NewSeed128(1024, mySipHash128)
//	ds128, _ := itb.NewSeed128(1024, mySipHash128)
//	ss128, _ := itb.NewSeed128(1024, mySipHash128)
//
//	encrypted, _ = itb.Encrypt128(ns128, ds128, ss128, plaintext)
//	decrypted, _ = itb.Decrypt128(ns128, ds128, ss128, encrypted)
//
//	// 256-bit hash (2048-bit effective key)
//	ns256, _ := itb.NewSeed256(2048, myBlake3Hash256)
//	ds256, _ := itb.NewSeed256(2048, myBlake3Hash256)
//	ss256, _ := itb.NewSeed256(2048, myBlake3Hash256)
//
//	encrypted, _ = itb.Encrypt256(ns256, ds256, ss256, plaintext)
//	decrypted, _ = itb.Decrypt256(ns256, ds256, ss256, encrypted)
//
// # Authenticated Encryption (MAC-inside-encrypt)
//
// The core construction provides confidentiality only. For integrity
// protection, use [EncryptAuthenticated] which encrypts a MAC tag inside the
// container, preserving oracle-free deniability. The MAC function is pluggable:
//
//	encrypted, _ := itb.EncryptAuthenticated(ns, ds, ss, plaintext, myMACFunc)
//	decrypted, _ := itb.DecryptAuthenticated(ns, ds, ss, encrypted, myMACFunc)
//
// [MACFunc] is defined as func([]byte) []byte — any function that takes data
// and returns a fixed-size tag. The MAC covers the entire decrypted capacity
// (COBS + null terminator + fill), preventing CCA spatial pattern leaks.
//
// Authenticated variants are available for all four widths:
// [EncryptAuthenticated], [EncryptAuthenticated128], [EncryptAuthenticated256],
// [EncryptAuthenticated512],
// [DecryptAuthenticated], [DecryptAuthenticated128], [DecryptAuthenticated256],
// [DecryptAuthenticated512].
//
// # Streaming (Chunked Encryption)
//
// For large data that exceeds available memory, use the streaming API.
// Data is split into chunks, each encrypted as a self-contained ITB message
// with its own nonce. Chunks can be concatenated and later decrypted
// sequentially. [ChunkSize] selects an appropriate chunk size automatically
// (default [DefaultChunkSize] = 16 MB).
//
//	err := itb.EncryptStream(ns, ds, ss, largeData, 0, func(chunk []byte) error {
//	    _, err := file.Write(chunk)
//	    return err
//	})
//
//	var result []byte
//	err = itb.DecryptStream(ns, ds, ss, fileData, func(chunk []byte) error {
//	    result = append(result, chunk...)
//	    return nil
//	})
//
// Streaming variants are available for all four widths:
// [EncryptStream], [EncryptStream128], [EncryptStream256], [EncryptStream512],
// [DecryptStream], [DecryptStream128], [DecryptStream256], [DecryptStream512].
package itb
