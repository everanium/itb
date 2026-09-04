package triple

import (
	"errors"
	"sync"
	"sync/atomic"

	"github.com/everanium/itb"
	"github.com/everanium/itb/parallax"
)

// Sentinel errors returned by the lifecycle surface. Each is a
// package-level [error] value; callers compare via [errors.Is].
var (
	// ErrClosed is returned by every [Pipeline] method invoked after
	// [Pipeline.Close] has run.
	ErrClosed = errors.New("triple: pipeline is closed")

	// ErrIdenticalMasters is returned by [Init], [Load], and
	// [Pipeline.Rekey] when the resolved PermMaster and WrapMaster
	// compare bytewise-equal. The check protects callers from
	// accidentally passing the same slice to both master parameters.
	ErrIdenticalMasters = errors.New("triple: perm master must differ from wrap master")

	// ErrMissingMasters is returned by [Load] when the blob's record
	// has parallax and/or wrapper enabled but neither the blob nor the
	// trailing variadic argument supplies the master bytes required
	// to rebuild the corresponding layer.
	ErrMissingMasters = errors.New("triple: required masters absent from blob and no override supplied")

	// ErrMastersArity is returned by [Load] when the trailing
	// variadic master argument has an invalid arity — accepted arities
	// are 0 (use the blob's masters) or 2 (perm master then wrap
	// master, overriding the blob).
	ErrMastersArity = errors.New("triple: trailing masters must be either 0 or 2 slices")

	// ErrUnknownProfile is returned by [Init] and [Lookup] when the
	// named profile is not in the registered profile catalogue.
	ErrUnknownProfile = errors.New("triple: unknown profile")

	// ErrBlobVersion is returned by [Load] and [Inspect] when the
	// blob's wrap-layer version field carries a value other than the
	// one this build encodes. Blobs produced by earlier releases carry
	// wrap-layer version 1 and are not loadable; regenerate them with
	// the current release.
	ErrBlobVersion = errors.New("triple: unsupported blob wrap-layer version")

	// ErrBlobMalformed is returned by [Load] and [Inspect] when the
	// blob's wrap-layer bytes fail to parse or carry structurally-
	// invalid content: size cap exceeded, JSON parse failure, unknown
	// key, trailing content, or a missing record / inner blob.
	ErrBlobMalformed = errors.New("triple: blob malformed")

	// ErrBlobMalformedRecipe is returned by [Load] when the blob's
	// embedded [Profile] record decodes but fails the profile field
	// rules (the same rules [Register] applies — mode, width, key
	// bits, palette bounds, segment-size coprimality, chunk-size
	// ceiling, tag-stub envelope, InnerHash / MixedHashes exclusivity
	// and width match) or disagrees with the inner blob (MAC name or
	// key width mismatch).
	ErrBlobMalformedRecipe = errors.New("triple: blob profile record invalid")

	// ErrRecipePrimitiveUnknown is returned by [Load] when the blob's
	// embedded [Profile] record names a primitive not present in the
	// local hashes / macs / wrapper registries. Runtime-registered
	// primitives on the sender must be registered under the same name
	// on the receiver before the blob can be loaded. [Inspect] does
	// not probe availability and returns the name unchanged.
	ErrRecipePrimitiveUnknown = errors.New("triple: blob profile record names a primitive absent from the local registries")

	// ErrNotYetImplemented is returned by the cipher-path stubs
	// ([Pipeline.EncryptStream] / [Pipeline.DecryptStream] /
	// [Pipeline.EncryptMessage] / [Pipeline.DecryptMessage]) until
	// their implementations land in the follow-up phases.
	ErrNotYetImplemented = errors.New("triple: cipher path not yet implemented")

	// ErrEmptyInput is returned by every [Pipeline] cipher entry point
	// ([Pipeline.EncryptMessage] / [Pipeline.DecryptMessage] /
	// [Pipeline.EncryptStream] / [Pipeline.DecryptStream] /
	// [Pipeline.EncryptStreamBytes] / [Pipeline.DecryptStreamBytes])
	// when the plaintext or wire input is empty (nil or zero-length),
	// before any wire is produced or parsed. An empty message has no
	// cover story in any cryptographic construction — it is always
	// distinguishable at some layer (wire length, timing, traffic
	// count) — so no zero-payload wire exists on this surface; callers
	// for whom an empty signal is meaningful send a marker byte
	// instead.
	ErrEmptyInput = errors.New("triple: empty input")

	// ErrBadKeyBits is the sentinel [Init] and [Load] wrap when the
	// resolved [Opts.KeyBits] override lands outside the per-primitive
	// key-width enum. The FFI [capi] layer maps [errors.Is]-matches on
	// this sentinel to the shared StatusBadKeyBits status code so a
	// binding sees the same "invalid key bits" surface produced by the
	// direct [github.com/everanium/itb.NewSeed*] entry points.
	ErrBadKeyBits = errors.New("triple: invalid key bits")
)

// Opts carries per-call overrides for [Init]. Every field is
// optional; a zero-value field defers to the profile default. Where a
// nil pointer type differs from a zero-value non-pointer type (the two
// layer toggles below), the pointer form disambiguates "user did not
// set this field" from "user explicitly requested false".
//
// The resolved shape — profile defaults with these overrides folded
// in — is recorded in the blob [Init] returns, so the reopen path
// ([Load] / [LoadF]) takes no Opts: every structural field is rebuilt
// from the record, and the per-instance NonceBits / BarrierFill are
// restored from the inner blob's Config snapshot. The one runtime
// knob, the worker cap, is set after construction through
// [Pipeline.MaxWorkers].
type Opts struct {
	// PermMaster overrides the auto-generated parallax master. When
	// non-nil, [Init] uses these bytes directly rather than drawing
	// a fresh master from [parallax.GenerateMasterKey].
	PermMaster []byte

	// WrapMaster overrides the auto-generated wrapper master. When
	// non-nil, [Init] uses these bytes directly rather than drawing a
	// fresh 32-byte CSPRNG master.
	WrapMaster []byte

	// WithParallax overrides whether the parallax layer is engaged
	// for this Pipeline. A nil pointer defers to the profile default;
	// a non-nil pointer forces the chosen setting.
	WithParallax *bool

	// WithWrapper overrides whether the wrapper (Outer cipher) layer
	// is engaged for this Pipeline. A nil pointer defers to the
	// profile default; a non-nil pointer forces the chosen setting.
	WithWrapper *bool

	// MaxWorkers sets the Pipeline's per-instance worker cap at
	// [Init] time. The value is clamped into the Pipeline's
	// [itb.Config] envelope: n ≤ 0 selects auto (runtime.NumCPU at
	// consumption), 1 ≤ n ≤ 256 pins the cap, n > 256 is treated as
	// 256. The cap is per-machine performance tuning, not wire shape:
	// it is never written to the blob, a loaded Pipeline starts at
	// auto, and [Pipeline.MaxWorkers] overrides it after construction
	// on either side.
	MaxWorkers int

	// NonceBits overrides the profile's on-wire nonce width in bits.
	// A zero value defers to the profile default.
	NonceBits int

	// BarrierFill overrides the profile's CSPRNG barrier fill margin.
	// A zero value defers to the profile default.
	BarrierFill int

	// ChunkSize overrides the profile's streaming chunk-size budget
	// (bytes). A zero value defers to the profile default.
	ChunkSize int

	// MacName overrides the profile's MAC primitive name (e.g.
	// "hmac-blake3"). An empty string defers to the profile default.
	// MAC-less profiles ignore this field.
	MacName string

	// TagStubSize overrides the profile's [Profile.TagStubSize]. A
	// zero value defers to the profile default; non-zero values must
	// fall in [16, 64] — [Init] rejects anything else fail-fast. Meaningful only for No MAC profiles paired with a
	// custom-tag-size MAC counterpart; see [Profile.TagStubSize] for
	// the resolution chain.
	TagStubSize int

	// InnerHash overrides the profile's ITB hash primitive name (e.g.
	// "areion512"). An empty string defers to the profile default.
	InnerHash string

	// MixedHashes overrides the profile's per-slot primitive
	// constellation for this Pipeline. A zero-value array (all slots
	// empty) defers to the profile default. When any slot is
	// non-empty, all eight slots must be non-empty, every entry must
	// resolve via [github.com/everanium/itb/hashes.Find], and every
	// entry's primitive width must equal the effective width — the
	// [allocEightSeedsMixed] helper enforces this at [Init] time, so
	// a typo'd slot or a width mismatch surfaces fail-fast rather
	// than silently corrupting the seed constellation. The resolved
	// constellation travels in the blob's record and is reproduced by
	// [Load].
	//
	// Slot ordering matches [Profile.MixedHashes]:
	// [0]noiseSeed [1]lockSeed [2]dataSeed1 [3]dataSeed2 [4]dataSeed3
	// [5]startSeed1 [6]startSeed2 [7]startSeed3.
	//
	// When both [Opts.InnerHash] and Opts.MixedHashes are set,
	// MixedHashes wins (mixed dispatch is chosen and the InnerHash
	// override is ignored) — same mutual-exclusion rule the
	// [Profile] fields obey.
	MixedHashes [8]string

	// KeyBits overrides the profile's per-seed key width in bits (one
	// of 512 / 1024 / 2048; must be an integer multiple of the
	// primitive's native hash width). A zero value defers to the
	// profile default.
	KeyBits int

	// OuterCipher overrides the profile's wrapper (Outer cipher) name
	// (e.g. "chacha20"). An empty string defers to the profile
	// default. Wrapper-off profiles ignore this field.
	OuterCipher string

	// ParallaxPalette overrides the profile's parallax palette. An
	// empty (or nil) slice defers to the profile default.
	// Parallax-off profiles ignore this field.
	ParallaxPalette []string

	// ParallaxSegmentSize overrides the profile's parallax segment
	// size. A zero value defers to the profile default. Parallax-off
	// profiles ignore this field.
	ParallaxSegmentSize int
}

// Pipeline is the opaque triple facade session. One Pipeline owns:
//
//   - the resolved [Profile] record it was constructed from (the
//     shape recorded in its blob);
//   - a per-instance [github.com/everanium/itb.Config] carrying
//     NonceBits / BarrierFill / MaxWorkers;
//   - the current wrap-layer blob, returned by [Pipeline.Save];
//   - eight typed ITB seeds (noise + lock + three data + three start)
//     matching the profile's inner hash width;
//   - the parallax [parallax.Schedule] + [parallax.Cipherset] when
//     the parallax layer is engaged, else nil;
//   - the wrapper derived key + cipher name when the wrapper layer is
//     engaged, else nil;
//   - the MAC closure + key + name when the profile carries a MAC,
//     else nil;
//   - a Close guard managed via [sync/atomic].
//
// Concurrency posture: post-[Init] and post-[Load], all Pipeline
// state relevant to encryption is read-only. Concurrent
// [Pipeline.EncryptStream] / [Pipeline.DecryptStream] /
// [Pipeline.EncryptMessage] / [Pipeline.DecryptMessage] calls on the
// same Pipeline are safe by construction; per-call state lives in
// caller-provided buffers and per-call scratch. [Pipeline.Rekey] and
// [Pipeline.MaxWorkers] do mutate Pipeline state and MUST be
// serialised against concurrent cipher calls by the caller — see the
// [Pipeline.Rekey] doc-comment.
// [Pipeline.Close] wipes secret material and marks the Pipeline
// closed via atomic; subsequent method calls return [ErrClosed].
type Pipeline struct {
	// resolved holds the profile defaults merged with any Opts
	// overrides supplied at [Init] time, or the record decoded from
	// the blob at [Load] time. Its Name is the label carried in the
	// blob. Not user-mutable.
	resolved Profile

	// blob is the current wrap-layer blob describing this Pipeline —
	// set by [Init], [Load], and [Pipeline.Rekey]; returned as a copy
	// by [Pipeline.Save]; zeroed by [Pipeline.Close].
	blob []byte

	// width caches the ITB hash primitive's native width (128 / 256 /
	// 512). Equal to resolved.Width.
	width int

	// cfg carries this Pipeline's per-instance
	// [github.com/everanium/itb.Config] snapshot. Threaded into every
	// itb-root *Cfg entry point.
	cfg *itb.Config

	// seeds holds the eight typed seed pointers in canonical order:
	// [noise, lock, data1, data2, data3, start1, start2, start3].
	// Each entry is *itb.Seed128, *itb.Seed256, or *itb.Seed512 to
	// match width.
	seeds [8]any

	// prfKeys holds the per-seed fixed PRF key bytes parallel to
	// seeds. nil for primitives with no fixed PRF key (siphash24);
	// otherwise each entry carries the primitive's native key length.
	prfKeys [8][]byte

	// parallaxSched / parallaxCS are the parallax layer handles.
	// Both are nil when the parallax layer is disabled.
	parallaxSched *parallax.Schedule
	parallaxCS    *parallax.Cipherset

	// wrapperKey is the wrapper-derived per-Pipeline key produced via
	// [github.com/everanium/itb/wrapper.DeriveKey]. wrapperCipher is
	// the canonical wrapper cipher name. Both are zero when the
	// wrapper layer is disabled.
	wrapperKey    []byte
	wrapperCipher string

	// macKey / macFunc / macName carry the MAC state. All three are
	// zero when the profile is No MAC.
	macKey  []byte
	macFunc itb.MACFunc
	macName string

	// closed is set to true by [Pipeline.Close]; every method
	// consulted checks it via atomic-load before touching seed / key
	// material. Uses [sync/atomic] rather than a mutex so cipher-path
	// stubs remain lock-free.
	closed atomic.Bool

	// closeMu serialises the Close body against a racing second Close
	// caller. Cipher-path methods do NOT take this lock; the atomic
	// flag above is sufficient for the check-then-run posture. Rekey
	// callers are responsible for their own serialisation against
	// in-flight cipher calls (see [Pipeline.Rekey]).
	closeMu sync.Mutex
}

// isClosed reports whether [Pipeline.Close] has run against this
// Pipeline. Used by every public method as the first guard.
func (p *Pipeline) isClosed() bool {
	return p.closed.Load()
}

// maxWorkersCap is the upper bound of the [itb.Config.MaxWorkers]
// envelope; values above it are clamped by [clampWorkers].
const maxWorkersCap = 256

// clampWorkers maps a caller-supplied worker count onto the
// [itb.Config.MaxWorkers] envelope: n ≤ 0 → 0 (auto, runtime.NumCPU at
// consumption), 1 ≤ n ≤ 256 → n, n > 256 → 256. One rule shared by the
// [Init] snapshot of [Opts.MaxWorkers] and by [Pipeline.MaxWorkers].
func clampWorkers(n int) int {
	switch {
	case n <= 0:
		return 0
	case n > maxWorkersCap:
		return maxWorkersCap
	}
	return n
}

// MaxWorkers overrides this Pipeline's worker cap for every subsequent
// cipher call, replacing the value [Init] snapshotted from
// [Opts.MaxWorkers] or the auto default a loaded Pipeline starts with.
// Values are clamped to the envelope [github.com/everanium/itb.Config]
// documents for its MaxWorkers field: n ≤ 0 selects auto
// (runtime.NumCPU at call time), 1 ≤ n ≤ 256 pins the cap, n > 256 is
// treated as 256. Works identically on a Pipeline returned by [Init]
// and by [Load] / [LoadF] — the worker cap is a performance property
// of the machine running the Pipeline, has no effect on the wire, is
// never written to the blob, and is the only Config value that may
// change after construction. A call on a closed Pipeline is ignored;
// the next cipher call reports [ErrClosed].
//
// THREAD-SAFETY. MaxWorkers mutates Pipeline state. The caller is
// responsible for serialising this call against every concurrent
// cipher-path call on the same Pipeline (same contract as
// [Pipeline.Rekey]; a sync.RWMutex with the write lock around
// MaxWorkers is the recommended pattern).
func (p *Pipeline) MaxWorkers(n int) {
	if p.isClosed() {
		return
	}
	p.cfg.MaxWorkers = clampWorkers(n)
}
