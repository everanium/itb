// Package itb implements ITB (Information-Theoretic Barrier): a
// parameterized symmetric cipher construction that makes hash output
// unobservable under passive observation through an
// information-theoretic barrier.
//
// Arbitrary binary data is encrypted into raw RGBWYOPA pixel
// containers generated from crypto/rand. Each pixel has 8 channels
// (Red, Green, Blue, White, Yellow, Orange, Purple, Alpha) carrying 7
// data bits and 1 noise bit per channel — 56 data bits per pixel at
// 1.14× overhead. Hash output is consumed by modification of random
// pixel values and is not reconstructible from observations. Every
// plaintext is additionally routed through the always-on 48-bit
// Interlocked Barrier: each 6-byte chunk is re-mapped into three
// disjoint 16-of-48 lanes by a per-chunk PRF-keyed mask triple drawn
// from a ≈ 2^70.20 balanced-partition space.
//
// # Security notice
//
// ITB is an experimental construction without peer review or
// independent cryptanalysis. PRF-grade hash functions are required.
// No warranty is provided. See SECURITY.md for the threat-model
// reference, HWTHREATS.md for the hardware-level boundary, PROOFS.md
// for the security proofs, SCIENCE.md for the architectural
// argument, and REDTEAM.md for empirical adversarial validation.
//
// # Recommended entry point — triple.Pipeline
//
// The [github.com/everanium/itb/triple] facade is the shipped
// user-facing surface. One
// [github.com/everanium/itb/triple.Init] call allocates the 8 ITB
// seeds, the optional parallax + wrapper layers, and the optional
// MAC, and exposes the Single Message and Streaming shapes (AEAD and
// Non-AEAD) plus the [github.com/everanium/itb/triple.Load] /
// [github.com/everanium/itb/triple.Pipeline.Rekey] /
// [github.com/everanium/itb/triple.Pipeline.Close] lifecycle. See the
// project README.md for worked examples across every shipped profile.
//
// # Low-Level Cfg surface
//
// Callers that need the raw 8-seed handoff — custom key management,
// unusual PRF combinations, in-process integration with existing seed
// material — consume the Low-Level Cfg free functions directly. Every
// entry takes a [*Config] first argument (nil = compile-in defaults)
// and the 8-seed Triple Ouroboros constellation (noiseSeed, lockSeed,
// dataSeed1..3, startSeed1..3):
//
//   - Single Message: [Encrypt3x128Cfg] / [Decrypt3x128Cfg] and the
//     256 / 512 mirrors.
//   - Single Message MAC Authenticated:
//     [EncryptAuthenticated3x128Cfg] /
//     [DecryptAuthenticated3x128Cfg] and 256 / 512 mirrors, with the
//     [EncryptAuth3x128Cfg] / [DecryptAuth3x128Cfg] short-name aliases.
//   - Streaming No MAC: [EncryptStream3x128Cfg] /
//     [DecryptStream3x128Cfg] and 256 / 512 mirrors, plus the
//     width-agnostic IO-Driven [EncryptStream3xCfg] /
//     [DecryptStream3xCfg] entries.
//   - Streaming AEAD (MAC Authenticated):
//     [EncryptStreamAuth3x128Cfg] / [DecryptStreamAuth3x128Cfg] and
//     256 / 512 mirrors, plus the width-agnostic IO-Driven
//     [EncryptStreamAuth3xCfg] / [DecryptStreamAuth3xCfg] entries.
//
// [ParseChunkLenCfg] inspects the first 20 bytes of a chunk header
// and reports the chunk's total length on the wire, letting external
// streaming consumers walk a concatenated chunk stream one chunk at a
// time. Also exposed through the C ABI as ITB_ParseChunkLen.
//
// Empty input (nil or zero-length plaintext / wire) is rejected
// uniformly with [ErrEmptyInput] across every Low-Level Cfg entry
// point before any wire is produced or parsed.
//
// # Hash width variants
//
// Three parallel API sets cover the shipped hash output widths:
// [Seed128] / [HashFunc128] (128-bit), [Seed256] / [HashFunc256]
// (256-bit), [Seed512] / [HashFunc512] (512-bit). All three share the
// same RGBWYOPA pixel format, wire framing, and security properties;
// the difference is in ChainHash intermediate state width. Users
// supply any conforming PRF closure; the
// [github.com/everanium/itb/hashes] subpackage ships paired factories
// for the shipped PRF-grade primitives.
//
// # State persistence — Blob
//
// [Blob128] / [Blob256] / [Blob512] pack the native-API encryptor
// material (per-seed hash key + Components + dedicated lockSeed +
// optional MAC key + name) plus the per-instance configuration into
// one self-describing JSON blob. Export3Cfg produces the blob;
// Import3Cfg reverses it, populating the struct's public Key* /
// Components fields and returning the captured [Config]. The receiver
// wires Hash / BatchHash from the saved key bytes through the
// matching factory. The [github.com/everanium/itb/triple] facade is
// the high-level alternative for callers that prefer
// constructor-bound primitive selection plus auto-coupling of
// parallax + wrapper masters.
//
// # Per-instance configuration ([Config])
//
// A nil [*Config] falls through to the compile-in defaults
// ([DefaultNonceBits] / [DefaultBarrierFill] and runtime.NumCPU for
// parallelism). A non-nil cfg overrides NonceBits, BarrierFill,
// MaxWorkers, and MACIncremental on a per-call basis; multiple
// encryptors with distinct configurations coexist in one process
// without any shared mutable state. Valid NonceBits: 128, 256, 512
// (default 512). Valid BarrierFill: 1, 2, 4, 8, 16, 32 (default 1).
// Valid MaxWorkers: 0 (runtime.NumCPU fallback) or 1..256.
//
// # Wire format
//
// The on-wire layout is main_nonce ‖ interlock_nonce ‖ W ‖ H ‖
// pixel_container. Both nonces are drawn independently from
// crypto/rand on each call (N = 16 / 32 / 64 bytes for 128 / 256 /
// 512-bit nonce respectively); W and H are unsigned 16-bit big-endian
// container dimensions; the pixel container carries the RGBWYOPA
// payload routed through the Interlocked Barrier. The byte layout is
// identical across all three hash width variants and across Single
// Message vs Streaming shapes at the byte level — a single-chunk
// stream is byte-shape-identical to a Single Message wire. See
// README.md for the offset-level table.
//
// # Concurrency
//
// The Low-Level free functions take read-only Seed pointers and
// allocate output per call — they are thread-safe under concurrent
// invocation on the same seeds. Concurrent mutation of the shared
// [*Config] pointer requires caller-side serialisation.
//
// # Runtime tuning
//
// [SetMemoryLimit] and [SetGCPercent] wrap runtime/debug's
// process-wide memory-limit and GC-percent pacing knobs. Both are
// process-global; pass -1 to either setter to query the current value
// without changing it. The knobs are also readable from the
// environment at libitb load time via ITB_GOMEMLIMIT / ITB_GOGC, and
// reachable through the C ABI as ITB_SetMemoryLimit /
// ITB_SetGCPercent.
//
// # See also
//
//   - FAQ.md — plain-language cryptanalytic walkthroughs.
//   - ITB.md — accessible explanation of how the barrier works.
//   - PROOFS.md — formal security proofs.
//   - SCIENCE.md — architectural argument.
//   - SECURITY.md — threat-model reference.
//   - HWTHREATS.md — hardware-level threat boundary.
//   - REDTEAM.md — empirical adversarial validation.
//   - HARNESS.md — adversarial testing methodology and calibration.
//   - README.md — full API surface, worked examples, primitive registry.
//   - BENCH3.md — benchmark tables across primitives and CPUs.
package itb
