// Package triple is a thin facade over the [github.com/everanium/itb]
// root package, [github.com/everanium/itb/parallax], and
// [github.com/everanium/itb/wrapper] plus [github.com/everanium/itb/macs].
// One [Pipeline] bundles the Interlocked Barrier Triple 8-seed state,
// an optional parallax layer, an optional wrapper (Outer cipher) layer,
// and an optional MAC into a single object with a small lifecycle API
// ([Init] / [Open] / [Pipeline.Rekey] / [Pipeline.Close]) and four
// cipher entry points ([Pipeline.EncryptStream] /
// [Pipeline.DecryptStream] / [Pipeline.EncryptMessage] /
// [Pipeline.DecryptMessage]).
//
// The Streaming AEAD IO-Driven surface is the primary use case. The
// Single Message surface ([Pipeline.EncryptMessage] /
// [Pipeline.DecryptMessage]) is a thin convenience wrapper around the
// streaming surface plus a [bytes.Buffer]. Users who want the direct
// Low-Level surface consume the corresponding *Cfg-bearing free
// functions in the itb root package.
//
// Five profiles ship in the initial catalogue: two Streaming shapes
// (MAC Authenticated and Non-AEAD, both parallax on + wrapper on), two
// Single Message shapes (MAC Authenticated and No MAC, both parallax
// on + wrapper on), and one blob-only bundle profile that carries
// session state without exposing a cipher surface. Users select a
// profile by name at [Init]; every profile-supplied default is
// overridable via [Opts] on both [Init] and [Open].
//
// Under N-concurrent-instance construction, contention-safety is
// by-design; individual per-instance encryption strength inherits the
// underlying Interlocked Barrier + Triple properties documented in
// `.ITB-48.md §2 + §3`.
//
// A [Pipeline] carries a private [github.com/everanium/itb.Config] so
// two Pipelines with distinct NonceBits / BarrierFill / MaxWorkers
// overrides coexist in the same process without cross-contamination.
// The process-global setters ([github.com/everanium/itb.SetNonceBits] /
// [github.com/everanium/itb.SetBarrierFill] /
// [github.com/everanium/itb.SetMaxWorkers]) remain in place as the
// explicit fallback consulted when the corresponding [Opts] field is
// left at zero.
//
// Reader notice — this package supersedes the earlier
// [github.com/everanium/itb/easy] facade with a stricter surface. The
// pre-v0.3.0 Bit Soup / Lock Soup / Lock Batch overlay knobs +
// AttachLockSeed dance + Single Message API + permSeedCfg helpers are
// absent by construction, since v0.3.0 retired them from the itb root
// (see the CLAUDE.md primary-terminology section for the current
// canonical Interlocked Barrier naming).
package triple
