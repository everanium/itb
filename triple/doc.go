// Package triple is a thin facade over the [github.com/everanium/itb]
// root package, [github.com/everanium/itb/parallax], and
// [github.com/everanium/itb/wrapper] plus [github.com/everanium/itb/macs].
// One [Pipeline] bundles the Interlocked Barrier Triple 8-seed state,
// an optional parallax layer, an optional wrapper (Outer cipher) layer,
// and an optional MAC into a single object with a small lifecycle API
// ([Init] / [Load] / [LoadF] / [Pipeline.Save] / [Pipeline.SaveF] /
// [Pipeline.Rekey] / [Pipeline.Close]) plus the cipher entry points:
// [Pipeline.EncryptStream] /
// [Pipeline.DecryptStream] (Reader/Writer),
// [Pipeline.EncryptStreamBytes] / [Pipeline.DecryptStreamBytes]
// (whole-buffer convenience over the streaming wire), and
// [Pipeline.EncryptMessage] / [Pipeline.DecryptMessage] (Single
// Message shape). Callers who need a configuration outside the shipped
// catalogue install a [Profile] literal at process init via
// [Register] and reference the registered name at [Init] like any
// shipped profile; [Lookup] and [Profiles] read the catalogue back.
//
// # Reopen contract
//
// The blob [Init] returns (and [Pipeline.Save] / [Pipeline.Rekey]
// re-emit) is self-describing: its wrap-layer carries the resolved
// [Profile] record — profile defaults with the [Opts] overrides folded
// in — alongside the inner Low-Level blob and the two masters. [Load]
// (bytes) and [LoadF] (file path) rebuild a Pipeline from that record
// alone; the profile registry is never consulted on the reopen path,
// no Opts are taken, and the record's Name is the sender's label,
// carried for display and never used to look anything up. [Inspect]
// returns the record without opening a Pipeline. A receiver that wants
// the shape under a name for its own [Init] calls registers the
// Inspect result explicitly.
//
// A record naming a primitive the local build lacks fails [Load] with
// [ErrRecipePrimitiveUnknown]; primitives installed at runtime through
// hashes.Register / macs.Register transport end-to-end when the
// receiver registers the same primitive under the same name first.
//
// # Wrap-layer key set (schema version 2)
//
//	v   schema version, always 2
//	p   the Profile record (key set below)
//	ib  the inner Blob{N} JSON object, embedded verbatim
//	pm  parallax master, base64; present iff p.parallax
//	wm  wrapper master, base64; present iff p.wrapper
//
// The decoder is strict: an unknown key or trailing content is
// [ErrBlobMalformed]; any version other than 2 — blobs produced by
// earlier releases carry version 1 — is [ErrBlobVersion] from every
// entry point, with no fallback. The inner blob keeps its own schema
// and its own strict decoder; the worker cap is not part of it.
//
// # Profile record key set
//
// [Profile.MarshalJSON] / [Profile.UnmarshalJSON] implement the one
// encoding shared by the wire, [Inspect], and the FFI register /
// inspect entries:
//
//	name      Name                 omitted when empty
//	mode      Mode                 always
//	width     Width                always
//	hash      InnerHash            omitted when empty (mixed profiles)
//	hashes    MixedHashes          omitted when every slot is empty;
//	                               otherwise exactly eight strings
//	keybits   KeyBits              always
//	mac       MacName              omitted when empty (No MAC)
//	tagstub   TagStubSize          omitted when 0
//	chunk     ChunkSize            omitted when 0
//	wrapper   Wrapper              always
//	outer     OuterCipher          omitted when empty
//	parallax  Parallax             always
//	palette   ParallaxPalette      omitted when empty
//	segment   ParallaxSegmentSize  omitted when 0
//
// A producer clears the inert fields of a disabled layer (outer when
// wrapper is false; palette and segment when parallax is false), so
// the record carries no dead information.
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
// Single Message shape and MAC vs No MAC posture, both dispatch
// paths, plus one blob-only bundle profile that carries session
// state without exposing a cipher surface. Users select a profile
// by name at [Init]; every profile-supplied default is overridable
// via [Opts] at [Init]. The [Opts.MixedHashes] override mirrors
// [Profile.MixedHashes] at the per-call layer — a single-primitive
// base profile can be switched to a mixed constellation, or one mixed
// profile to a different mixed shape, for one [Pipeline] instance
// without registering a new named profile. The resolved
// constellation travels in the blob's record, so [Load] reconstructs
// the same effective constellation as [Init] without the receiver
// repeating the override.
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
// [github.com/everanium/itb.DefaultBarrierFill]); the value in force
// is snapshotted into the blob at [Init] and restored by [Load], so
// the wire shape never depends on the receiver's defaults. The worker
// cap is the one runtime-mutable value: set at [Init] from
// [Opts.MaxWorkers], auto on a loaded Pipeline, overridable at any
// time through [Pipeline.MaxWorkers], never written to the blob.
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
// (Init/Load/Save/Rekey/Close) plus one cipher pair per shape
// (message, stream).
package triple
