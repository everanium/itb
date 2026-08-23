// Package itb implements ITB (Information-Theoretic Barrier): a parameterized
// symmetric cipher construction that makes hash output unobservable
// under passive observation through an information-theoretic barrier.
//
// # Security Notice
//
// ITB is an experimental construction without peer review or formal certification.
// The information-theoretic barrier is a SOFTWARE-LEVEL property, reinforced by
// two independent barrier mechanisms: noise absorption from CSPRNG, and
// encoding ambiguity (7^P under the unified CCA-resistant envelope) from
// 8-seed isolation. Architectural layers deny the point of application:
// independent startSeeds and 8-noisePos ambiguity from an independent
// noiseSeed under Full KPA, plus gcd(7,8)=1 byte-splitting under Partial
// KPA. Full KPA defense is 3-factor under PRF assumption (4-factor under
// Partial KPA) — see PROOFS.md Proof 4a. It provides NO guarantees against
// hardware-level attacks including: power analysis (DPA/SPA),
// microarchitectural side-channels (Spectre, Meltdown, Rowhammer, cache
// timing), undiscovered side-channel leakages, or CSPRNG implementation
// weaknesses.
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
// barrier and architectural layers (8-seed isolation, encoding ambiguity,
// independent startSeeds) deny the point of application — 3-factor
// combination under PRF assumption; gcd(7,8)=1 byte-splitting adds a 4th
// factor under Partial KPA (see PROOFS.md Proof 4a).
//
// # Architecture
//
// The construction is parameterized by:
//
//   - Hash function: pluggable, zero built-in dependencies. Three width variants:
//     [HashFunc128] (128-bit), [HashFunc256] (256-bit), [HashFunc512] (512-bit).
//     Users supply any conforming PRF closure; the [github.com/everanium/itb/hashes]
//     subpackage ships built-in factories for the canonical PRF-grade primitives.
//
//   - Key size: minimum 512 bits (8 components) per seed, up to [MaxKeyBits]
//     (2048). Effective security depends on the hash width:
//     128-bit hash → 1024-bit max, 256-bit hash → 2048-bit max,
//     512-bit hash → 2048-bit max. Create seeds with
//     [NewSeed128] / [NewSeed256] / [NewSeed512] (random)
//     or [SeedFromComponents128] / [SeedFromComponents256] /
//     [SeedFromComponents512] (deterministic).
//
//   - Nonce: configurable per-message nonce generated internally from
//     crypto/rand. Default [NonceSize] = 512-bit; set [Config.NonceBits]
//     to 128, 256, or 512 to select the width. Mandatory — prevents
//     configuration reuse across messages. Birthday collision at
//     ~2^(nonceBits/2) messages.
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
//   - 128-bit ([Seed128], [Encrypt3x128Cfg], [Decrypt3x128Cfg]): uses [HashFunc128]
//     with 128-bit intermediate state (2 components per round).
//     Effective max key: 1024 bits. Targets: SipHash-2-4, AES-CMAC.
//
//   - 256-bit ([Seed256], [Encrypt3x256Cfg], [Decrypt3x256Cfg]): uses [HashFunc256]
//     with 256-bit intermediate state (4 components per round).
//     Effective max key: 2048 bits. Targets: Areion-SoEM-256, BLAKE3.
//
//   - 512-bit ([Seed512], [Encrypt3x512Cfg], [Decrypt3x512Cfg]): uses [HashFunc512]
//     with 512-bit intermediate state (8 components per round).
//     Effective max key: 2048 bits (with current [MaxKeyBits]).
//     Targets: Areion-SoEM-512, BLAKE2b-512 (native 512-bit key and output).
//
// All three variants share the same RGBWYOPA pixel format, COBS framing,
// eight-seed architecture, and security properties. The wider hash output
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
// 8-seed architecture: noiseSeed determines the noise bit position
// (any of 0-7), each dataSeed determines data rotation (0-6) and per-bit
// XOR masks for its 3-snake slot, each startSeed determines that slot's
// pixel start offset, and lockSeed keys the always-on 48-bit Interlocked
// Barrier overlay. All eight seeds are independent — compromise of one
// does not reveal the others.
// dataSeed has zero software-observable side-channel exposure (register-only operations).
// Config per pixel: 3 bits from noiseSeed + 59 bits from dataSeed
// (3 rotation + 56 XOR) = 62 total.
//
// # Effective Key Size by Hash Function
//
// The chained hash construction passes intermediate state through the hash
// function's output width, creating a bottleneck. See BENCH3.md and the
// registry in [github.com/everanium/itb/hashes] for the per-primitive
// hash-output-width / recommended-ITB-key-size table for Triple Ouroboros
// entry points ([Encrypt3x128Cfg] / [Encrypt3x256Cfg] / [Encrypt3x512Cfg]).
//
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
//   - independent startSeeds + 7-rotation × 8-noisePos per-pixel ambiguity.
//     gcd(7,8)=1 byte-splitting is a 4th factor effective only under Partial
//     KPA (see PROOFS.md Proof 4a).
//
//   - Oracle-free deniability: no size headers, no checksums. COBS + null
//     terminator under encryption. Wrong seed produces random-looking output
//     with no verification oracle for brute-force.
//
//   - Per-message nonce (default 512-bit, configurable to 128 or 256 via
//     [Config.NonceBits]) prevents configuration reuse. Birthday collision
//     bounds depend on nonce size: ~2^64 messages at 128-bit, ~2^128 at
//     256-bit, ~2^256 at 512-bit. Practically safe collision probability
//     (~2^{-33}): ~2^48 / ~2^112 / ~2^240 messages respectively.
//
//   - 8-seed isolation: CCA reveals noiseSeed config only (MAC + Reveal
//     only) (noise positions), cache side-channel reveals startPixel only
//     (pixel offset derived from each startSeed). dataSeed config (rotation + XOR) is completely
//     independent, register-only, and unobservable. After CCA removes noise bits,
//     guaranteed CSPRNG residue in data positions preserves ambiguity (Proof 10).
//
//   - Information-theoretic barrier of 2^(8P) where P = pixel count.
//     Minimum container sized so encoding ambiguity exceeds key space:
//     [MinPixels] = ceil(keyBits / log2(7)) (aliases [MinPixelsAuth]) —
//     the plain and authenticated envelopes share one unified CCA-resistant
//     floor so the container does not distinguish mode on tiny payloads.
//     At 1024-bit: MinPixels = 365 (P = 400 after square rounding).
//     Noise barrier at MinPixels = 365 (P = 400 after square rounding):
//     2^(8×400) = 2^3200, far beyond the Landauer limit of ~2^306.
//
// # Quick Start (Recommended) — triple.Pipeline
//
// The high-level [github.com/everanium/itb/triple.Pipeline] replaces
// the low-level setup ceremony (per-seed PRF closures, BatchHash
// wiring, MAC factory, parallax + wrapper masters) with one
// [github.com/everanium/itb/triple.Init] call. The Pipeline
// allocates the eight ITB seeds + optional parallax layer + optional
// wrapper layer + MAC closure, snapshots per-instance settings into a
// private [Config], and exposes the two cipher shapes (message,
// stream) plus a lifecycle (Init / Open / Rekey / Close).
// Cross-process persistence is one method call per side:
// [github.com/everanium/itb/triple.Init] returns the session blob,
// [github.com/everanium/itb/triple.Open] reconstructs the receiver.
//
// A single triple.Pipeline is safe for concurrent
// [github.com/everanium/itb/triple.Pipeline.EncryptStream] /
// [github.com/everanium/itb/triple.Pipeline.EncryptMessage] calls
// from multiple goroutines; per-call state lives on the caller's
// stack. Rekey mutates Pipeline state and must be serialised against
// concurrent cipher-path calls. The low-level free functions
// [Encrypt3x128Cfg] / [EncryptAuthenticated3x128Cfg] (and the 256 /
// 512 width counterparts) take read-only Seed pointers and allocate
// output per call — they are thread-safe under concurrent invocation
// on the same seeds; only the shared [Config] pointer requires
// caller-side serialisation when a writer races with readers.
//
//	import "github.com/everanium/itb/triple"
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
// # Quick Start (Low-Level)
//
// The Low-Level surface takes eight seed pointers and a plaintext
// slice per call. Every entry point is Cfg-suffixed and takes a
// [Config] first argument for per-encryptor overrides (nil = compile-in
// defaults).
//
//	import (
//	    "github.com/everanium/itb"
//	    "github.com/everanium/itb/hashes"
//	)
//
//	// The 48-bit Interlocked Barrier is always engaged for Triple
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
//	// [32]byte key on the restore path. Independent factory calls yield
//	// independent fixed keys — the Triple 8-seed constellation needs
//	// distinct keying material per slot.
//	fnN, batchN, keyN := itb.MakeAreionSoEM256Hash()
//	fnL, batchL, keyL := itb.MakeAreionSoEM256Hash()
//	fnD1, batchD1, keyD1 := itb.MakeAreionSoEM256Hash()
//	// (analogous for D2, D3, S1, S2, S3 — eight independent
//	// (hashFn, batchFn, hashKey) triples, eight independent saved keys)
//	saveKey("noise-key", keyN[:])
//	saveKey("lock-key", keyL[:])
//	saveKey("data-key-1", keyD1[:])
//	// ...
//	ns, _ := itb.NewSeed256(1024, fnN); ns.BatchHash = batchN
//	ls, _ := itb.NewSeed256(1024, fnL); ls.BatchHash = batchL
//	d1, _ := itb.NewSeed256(1024, fnD1); d1.BatchHash = batchD1
//	// ... d2, d3, s1, s2, s3 same shape
//
//	encrypted, _ := itb.Encrypt3x256Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, plaintext)
//	decrypted, _ := itb.Decrypt3x256Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, encrypted)
//
//	// Areion-SoEM-512 with batched VAES dispatch — same factory pattern,
//	// 64-byte key, 64-byte input, 8 × uint64 seed. Use itb.NewSeed512 +
//	// itb.Encrypt3x512Cfg / itb.Decrypt3x512Cfg in place of the 256-bit
//	// variants.
//
//	// Other PRF primitives — use the hashes/ subpackage. Same variadic
//	// pattern: pass nothing for random key, pass a saved key for restore.
//	// Returned key is always emitted as the second value — capture it
//	// for persistence (test fixtures discard via `_`).
//
//	// SipHash-2-4 (128-bit hash, 1024-bit effective key) — exception:
//	// no internal fixed key (keying material is the seed components),
//	// so this is the only factory that returns just one value.
//	fn128 := hashes.SipHash24()
//
//	// AES-CMAC (128-bit hash, 1024-bit effective key, AES-NI hardware
//	// path on amd64 / arm64 hosts that expose the AES round instructions)
//	aesFn, aesKey := hashes.AESCMAC()
//	saveKey("aescmac-noise", aesKey[:])
//
//	// BLAKE3 keyed (256-bit hash, 2048-bit effective key)
//	b3Fn, b3Key := hashes.BLAKE3()
//	_ = b3Key
//
//	// BLAKE2b-512 (512-bit hash, 2048-bit effective key, native 512-bit
//	// output and up to 64-byte key)
//	b2Fn, b2Key := hashes.BLAKE2b512()
//	_ = b2Key
//
// # Authenticated Encryption (MAC-Inside-Encrypt)
//
// The core construction provides confidentiality only. For integrity
// protection, use [EncryptAuthenticated3x128Cfg] (or 256/512 variant) which
// encrypts a MAC tag inside the container, preserving oracle-free deniability.
// The MAC function is pluggable:
//
//	encrypted, _ := itb.EncryptAuthenticated3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, plaintext, myMACFunc)
//	decrypted, _ := itb.DecryptAuthenticated3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, encrypted, myMACFunc)
//
// [MACFunc] is defined as func([]byte) []byte — any function that takes data
// and returns a fixed-size tag. The MAC covers the entire decrypted capacity
// (COBS + null terminator + fill), preventing CCA spatial pattern leaks.
//
// Authenticated Triple Ouroboros variants (8 seeds):
// [EncryptAuthenticated3x128Cfg], [EncryptAuthenticated3x256Cfg],
// [EncryptAuthenticated3x512Cfg], [DecryptAuthenticated3x128Cfg],
// [DecryptAuthenticated3x256Cfg], [DecryptAuthenticated3x512Cfg].
//
// # Short-name aliases
//
// Every authenticated entry point is also reachable under a shorter
// name with the Authenticated / DecryptAuthenticated prefix collapsed
// to Auth / DecryptAuth — for example [EncryptAuth3x128Cfg] forwards
// to [EncryptAuthenticated3x128Cfg] and [DecryptAuth3x256Cfg] forwards
// to [DecryptAuthenticated3x256Cfg]. The alias surface covers every
// authenticated entry point and is allocation-free.
//
// # Streaming (Chunked Encryption)
//
// For large data that exceeds available memory, use the streaming API.
// Data is split into chunks, each encrypted as a self-contained ITB message
// with its own nonce. Chunks can be concatenated and later decrypted
// sequentially. [ChunkSize] selects an appropriate chunk size automatically
// (default [DefaultChunkSize] = 16 MB).
//
//	err := itb.EncryptStream3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, largeData, 0, func(chunk []byte) error {
//	    _, err := file.Write(chunk)
//	    return err
//	})
//
//	var result []byte
//	err = itb.DecryptStream3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, fileData, func(chunk []byte) error {
//	    result = append(result, chunk...)
//	    return nil
//	})
//
// Triple Ouroboros streaming variants (8 seeds):
// [EncryptStream3x128Cfg], [EncryptStream3x256Cfg], [EncryptStream3x512Cfg],
// [DecryptStream3x128Cfg], [DecryptStream3x256Cfg], [DecryptStream3x512Cfg].
//
// [ParseChunkLenCfg] inspects the first 20 bytes of a chunk header and
// reports the chunk's total length on the wire, letting external
// streaming consumers (FFI bindings, custom file-format wrappers)
// walk a concatenated chunk stream one chunk at a time without
// buffering the whole stream in memory. The function is also
// exposed through the C ABI as ITB_ParseChunkLen.
//
// The width-less IO-Driven entry points [EncryptStream3xCfg] and
// [DecryptStream3xCfg] accept seed pointers typed as `any` and drive
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
// [EncryptStreamAuthenticated3x128Cfg] /
// [EncryptStreamAuthenticated3x256Cfg] /
// [EncryptStreamAuthenticated3x512Cfg] and the corresponding
// [DecryptStreamAuthenticated3x128Cfg] /
// [DecryptStreamAuthenticated3x256Cfg] /
// [DecryptStreamAuthenticated3x512Cfg] entry points. Each takes the
// streamID, the running cumulative pixel offset, and finalFlag (true
// on the terminating chunk, false otherwise) explicitly.
//
// Higher-level helpers covering the per-chunk loop server-side:
// [EncryptStreamAuth3x128Cfg] / [EncryptStreamAuth3x256Cfg] /
// [EncryptStreamAuth3x512Cfg] drive a per-chunk emit callback under
// fixed seed handles, drawing the 32-byte stream anchor, advancing
// cumulative pixel offset, and flipping finalFlag on the last chunk.
// The width-less [EncryptStreamAuth3xCfg] / [DecryptStreamAuth3xCfg]
// instead consume an [io.Reader] and write to an [io.Writer] directly,
// dispatching on the concrete seed pointer type. Aliasing follows the
// same Authenticated → Auth collapse rule used by the Single Message
// family.
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
// [io.Writer] entry points ([EncryptStream3xCfg] /
// [DecryptStream3xCfg] and the corresponding
// [github.com/everanium/itb/triple.Pipeline.EncryptStream] /
// [github.com/everanium/itb/triple.Pipeline.DecryptStream] methods)
// that drive the read/write loop internally. The official bindings
// to other languages expose the No-MAC stream surface as per-chunk
// free functions only and let the caller drive the loop. The two
// patterns produce identical on-wire bytes; choice between them is
// a Go-side convenience.
//
// # Triple Ouroboros (8-seed constellation)
//
// Triple Ouroboros splits plaintext into 3 parts at the byte level (every 3rd
// byte), encrypting each into 1/3 of the pixel data with independent dataSeed
// and startSeed, sharing noiseSeed. Output format is identical to standard ITB.
// Security: P × 2^(3×keyBits) under CCA. Eight seeds: 1×noiseSeed +
// 1×lockSeed + 3×dataSeed + 3×startSeed. All eight seeds must be distinct
// pointers.
//
//	encrypted, _ := itb.Encrypt3x512Cfg(nil, noiseSeed, lockSeed,
//	    dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, plaintext)
//	decrypted, _ := itb.Decrypt3x512Cfg(nil, noiseSeed, lockSeed,
//	    dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, encrypted)
//
// Available for all three hash widths:
// [Encrypt3x128Cfg], [Encrypt3x256Cfg], [Encrypt3x512Cfg],
// [Decrypt3x128Cfg], [Decrypt3x256Cfg], [Decrypt3x512Cfg].
//
// For best throughput, use 512-bit ITB key — security becomes P × 2^1536
// (3 × 512), while ChainHash runs at 512-bit speed. See ITB.md for the
// accessible explanation and BENCH3.md for benchmarks.
//
// # 48-bit Interlocked Barrier (Triple Ouroboros)
//
// Every Triple Ouroboros plaintext is driven through a 48-bit
// Interlocked Barrier overlay: each 6-byte chunk is split into three
// disjoint 16-of-48 balanced masks derived from a per-chunk PRF output
// keyed by the lockSeed-derived inter-lock seed and the nonce. The
// overlay is a non-disableable part of the Triple kernel — there is no
// engage knob and no off-branch.
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
// Applies uniformly to every Triple Ouroboros variant — [Encrypt3x128Cfg] /
// [Decrypt3x128Cfg], the 256- / 512-bit mirrors,
// [EncryptAuthenticated3x128Cfg] / [DecryptAuthenticated3x128Cfg] and their
// mirrors, and [EncryptStream3x128Cfg] / [DecryptStream3x128Cfg] and mirrors.
// The ciphertext wire format is identical in all configurations.
//
// See ITB.md for accessible explanation and REDTEAM.md for the
// defensive framing in the SAT attack context.
//
// # Per-instance configuration ([Config])
//
// Every public encrypt / decrypt entry point is Cfg-suffixed and takes
// a [Config] first argument for per-instance overrides:
// [Encrypt3x128Cfg] / [Decrypt3x128Cfg] and the 256/512 mirrors, the
// matching authenticated and streaming counterparts, and
// [ParseChunkLenCfg]. A nil cfg falls through to the compile-in
// defaults ([DefaultNonceBits] / [DefaultBarrierFill] and
// runtime.NumCPU for parallelism). A non-nil cfg overrides
// NonceBits / BarrierFill / MaxWorkers on a per-call basis; multiple
// encryptors with distinct configurations coexist in one process
// without any shared mutable state.
//
// # State persistence — Blob
//
// [Blob128] / [Blob256] / [Blob512] pack the native-API encryptor
// material (per-seed hash key + Components + dedicated
// lockSeed + optional MAC key + name) plus the per-instance
// configuration into one self-describing JSON blob.
// Export3Cfg produces the blob; Import3Cfg reverses it,
// populating the struct's public Key* / Components fields and returning
// the captured [Config]. The receiver wires Hash / BatchHash from the
// saved key bytes through the matching factory (e.g.
// [MakeAreionSoEM512HashWithKey]), keeping the pluggable-PRF
// philosophy of the native API. Optional dedicated lockSeed and MAC
// slots ride in the trailing [Blob128Opts] / [Blob256Opts] /
// [Blob512Opts] options struct. The
// [github.com/everanium/itb/triple] facade is the high-level
// alternative for callers that prefer constructor-bound primitive
// selection plus auto-coupling of parallax + wrapper masters.
//
// # Dedicated lockSeed
//
// Every Triple Ouroboros entry point takes an eight-seed
// constellation: (noiseSeed, lockSeed, dataSeed1..3, startSeed1..3).
// The lockSeed slot keys the 48-bit Interlocked Barrier overlay's
// per-chunk bit-permutation derivation, and its keying material stays
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
// The 48-bit Interlocked Barrier overlay is always engaged, so the
// lockSeed argument is consumed on every Encrypt / Decrypt call —
// there is no toggle to disable the overlay.
//
//	fnN, batchN, _ := itb.MakeAreionSoEM512Hash()
//	fnL, batchL, _ := itb.MakeAreionSoEM512Hash()
//	ns, _ := itb.NewSeed512(2048, fnN); ns.BatchHash = batchN
//	ls, _ := itb.NewSeed512(2048, fnL); ls.BatchHash = batchL
//	// ... ds1..3, ss1..3 as usual, all independently allocated.
//	ct, _ := itb.Encrypt3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, plaintext)
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
// To limit CPU usage (e.g., on shared servers), set [Config.MaxWorkers]
// on the [Config] threaded through a Cfg-suffixed entry point:
//
//	cfg := &itb.Config{MaxWorkers: 4} // use at most 4 cores
//	encrypted, _ := itb.Encrypt3x256Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, plaintext)
//
// Zero (the default) uses all available CPUs. Valid range: 0 to 256;
// values above 256 are clamped at consumption.
//
// # Nonce Configuration
//
// By default the nonce is 512 bits ([NonceSize] = 64 bytes). For lower
// collision resistance, set [Config.NonceBits] on the [Config] threaded
// through the Cfg-suffixed entry point:
//
//	cfg := &itb.Config{NonceBits: 256} // 256-bit nonce (~2^128 birthday bound)
//
// Valid values: 128, 256, 512 (or 0 to inherit [DefaultNonceBits]).
// Both sender and receiver must use the same nonce size.
//
// # Barrier Fill (CSPRNG Margin)
//
// The container side is increased by a configurable margin to guarantee
// CSPRNG residue in every container (Proof 10: No Perfect Fill). The gap
// between pixel capacity and data requirement ensures that some pixel
// channels carry only CSPRNG random data, even after CCA eliminates
// noise bits. Default margin is 1. To increase the CSPRNG fill margin
// set [Config.BarrierFill] on the [Config] threaded through the
// Cfg-suffixed entry point:
//
//	cfg := &itb.Config{BarrierFill: 4} // side += 4 instead of side += 1
//
// Valid values: 1, 2, 4, 8, 16, 32 (or 0 to inherit [DefaultBarrierFill]).
// Asymmetric: the receiver does not need the same value as the sender,
// because the container dimensions are stored in the header.
package itb
