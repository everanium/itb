// Package triple is a thin facade over the [github.com/everanium/itb]
// root package, [github.com/everanium/itb/parallax], and
// [github.com/everanium/itb/wrapper] plus [github.com/everanium/itb/macs].
// One [Pipeline] bundles the Interlocked Barrier Triple 8-seed state,
// an optional parallax layer, an optional wrapper (Outer cipher) layer,
// and an optional MAC into a single object with a small lifecycle API
// ([Init] / [Open] / [Pipeline.Rekey] / [Pipeline.Close]) and four
// cipher entry points ([Pipeline.EncryptStream] /
// [Pipeline.DecryptStream] / [Pipeline.EncryptMessage] /
// [Pipeline.DecryptMessage]). Callers who need a configuration outside
// the shipped catalogue install a [Profile] literal at process init
// via [RegisterProfile] and reference the registered name at [Init]
// like any shipped profile.
//
// The Streaming AEAD IO-Driven surface is the primary use case. The
// Single Message surface ([Pipeline.EncryptMessage] /
// [Pipeline.DecryptMessage]) is a thin convenience wrapper around the
// streaming surface plus a [bytes.Buffer]. Users who want the direct
// Low-Level surface consume the corresponding *Cfg-bearing free
// functions in the itb root package.
//
// The shipped catalogue covers both single-primitive and
// mixed-primitive constellations. Single-primitive profiles bind one
// [github.com/everanium/itb/hashes.Registry] entry to every seed
// slot; mixed-primitive profiles bind a per-slot constellation via
// [Profile.MixedHashes] with uniform width per profile (repeats
// permitted). The catalogue spans every combination of streaming vs
// single-message shape and MAC vs No MAC posture, both dispatch
// paths, plus one blob-only bundle profile that carries session
// state without exposing a cipher surface. Users select a profile
// by name at [Init]; every profile-supplied default is overridable
// via [Opts] on both [Init] and [Open].
//
// Under N-concurrent-instance construction, contention-safety is
// by-design; individual per-instance encryption strength inherits the
// underlying Interlocked Barrier + Triple properties documented in the
// project's PROOFS.md and SCIENCE.md.
//
// A [Pipeline] carries a private [github.com/everanium/itb.Config] so
// two Pipelines with distinct NonceBits / BarrierFill / MaxWorkers
// overrides coexist in the same process without cross-contamination.
// When an [Opts] field is left at zero the corresponding compile-in
// default applies (see [github.com/everanium/itb.DefaultNonceBits] /
// [github.com/everanium/itb.DefaultBarrierFill]).
//
// Empty input (nil or zero-length plaintext / wire) is rejected
// uniformly with [ErrEmptyInput] across every Pipeline cipher entry
// point — Encrypt and Decrypt, Message and Stream shapes alike —
// before any wire is produced or parsed. An empty message has no
// cover story in any cryptographic construction: it is always
// distinguishable at some layer (wire length, timing, traffic count),
// so no zero-payload wire exists on this surface. Callers for whom an
// empty signal is meaningful send a marker byte instead.
//
// Reader notice — the Interlocked Barrier is always on and
// non-disableable; the Triple 3-snake payload split is the only
// cipher mode. There are no runtime overlay toggles and no
// engage/disengage knobs — the package exposes one lifecycle
// (Init/Open/Rekey/Close) plus one cipher pair per shape
// (message, stream).
package triple
