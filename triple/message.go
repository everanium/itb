package triple

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"unsafe"

	"github.com/everanium/itb"
	"github.com/everanium/itb/internal/triplewire"
	"github.com/everanium/itb/internal/wipe"
	"github.com/everanium/itb/macs"
	"github.com/everanium/itb/wrapper"
)

// ErrProfileNoCipher is returned by [Pipeline.EncryptMessage] /
// [Pipeline.DecryptMessage] when the [Pipeline]'s resolved profile
// mode does not expose ANY cipher surface — the shipped blob-only
// profile ([ProfileBlobTripleMACV1]) is the current sole trigger:
// its role is to bundle session state on the wire, not to encrypt or
// decrypt payload bytes.
//
// Distinct from [ErrProfileNotStreaming]: the streaming guard rejects
// Single Message + blob-only profiles from [Pipeline.EncryptStream] /
// [Pipeline.DecryptStream] because those profiles surface their cipher
// path through [Pipeline.EncryptMessage] / [Pipeline.DecryptMessage]
// instead (or through nothing at all, for blob-only). The message
// guard rejects only the blob-only profile — Single Message and
// Streaming profiles both accept message-shape calls, since the byte
// shape produced by [Pipeline.EncryptStream] on a Streaming profile is
// identical to the byte shape produced by [Pipeline.EncryptMessage]
// when the plaintext fits in one chunk.
//
// The sentinel lives beside its check site here rather than in
// [pipeline.go]'s sentinel block since it is scoped to the message
// surface — colocates a guard's error with the guard itself.
var ErrProfileNoCipher = errors.New("triple: profile does not expose any cipher surface")

// messageFastPathMaxBytes caps the plaintext size accepted by the
// direct whole-buffer fast path. Matches the itb-root Single Message
// cipher cap so oversized payloads fall through to the streaming
// fallback (which chunks the plaintext at [Pipeline.resolved.ChunkSize]
// granularity). Held as an explicit constant here rather than reading
// the itb-root cap so the message surface has a single, self-documenting
// gate for the fast path.
const messageFastPathMaxBytes = 64 << 20

// parallaxFrameHeaderBytes is the per-frame header overhead added by
// the parallax layer: 4-byte little-endian plaintext length + 16-byte
// per-chunk nonce.
const parallaxFrameHeaderBytes = 20

const maxCachedTripleScratch = 8

// tripleScratchPool recycles transient byte buffers used by the
// single-chunk parallax frame assembly and in-place wrapper unwrapping.
// Every checkout is wiped via [wipe.Bytes] before return to the pool.
var (
	tripleScratchPool  sync.Pool
	tripleScratchMu    sync.Mutex
	tripleScratchCache []*[]byte
)

func acquireTripleScratch(n int) (*[]byte, []byte) {
	tripleScratchMu.Lock()
	if m := len(tripleScratchCache); m > 0 {
		for i := m - 1; i >= 0; i-- {
			bp := tripleScratchCache[i]
			if cap(*bp) >= n {
				tripleScratchCache[i] = tripleScratchCache[m-1]
				tripleScratchCache[m-1] = nil
				tripleScratchCache = tripleScratchCache[:m-1]
				tripleScratchMu.Unlock()
				return bp, (*bp)[:n]
			}
		}
		bp := tripleScratchCache[m-1]
		tripleScratchCache[m-1] = nil
		tripleScratchCache = tripleScratchCache[:m-1]
		tripleScratchMu.Unlock()
		b := make([]byte, n)
		*bp = b
		return bp, b
	}
	tripleScratchMu.Unlock()

	if v := tripleScratchPool.Get(); v != nil {
		bp := v.(*[]byte)
		if cap(*bp) >= n {
			b := (*bp)[:n]
			return bp, b
		}
		b := make([]byte, n)
		*bp = b
		return bp, b
	}
	b := make([]byte, n)
	return &b, b
}

func releaseTripleScratch(bp *[]byte, b []byte) {
	if bp == nil {
		return
	}
	wipe.Bytes(b)
	*bp = b[:cap(b)]
	tripleScratchMu.Lock()
	if len(tripleScratchCache) < maxCachedTripleScratch {
		tripleScratchCache = append(tripleScratchCache, bp)
		tripleScratchMu.Unlock()
		return
	}
	tripleScratchMu.Unlock()
	tripleScratchPool.Put(bp)
}

// canEncryptDirect reports whether a plaintext of length plaintextLen
// can be encrypted as a single ITB chunk via the direct whole-buffer
// path. When parallax is disengaged, any plaintext up to
// [messageFastPathMaxBytes] qualifies. When parallax is engaged, the
// single-frame parallax output (plaintextLen + 20 bytes) must fit
// within a single resolved chunkSize as well as [messageFastPathMaxBytes]
// so the resulting single-chunk wire is identical to the streaming path.
func (p *Pipeline) canEncryptDirect(plaintextLen int) bool {
	if !p.resolved.Parallax {
		return plaintextLen <= messageFastPathMaxBytes
	}
	cs := p.resolved.ChunkSize
	if cs <= 0 {
		cs = itb.DefaultChunkSize
	}
	framedLen := plaintextLen + parallaxFrameHeaderBytes
	return framedLen <= cs && framedLen <= messageFastPathMaxBytes
}

func slicesOverlap(a, b []byte) bool {
	if cap(a) == 0 || len(b) == 0 {
		return false
	}
	aFull := a[:cap(a)]
	aStart := uintptr(unsafe.Pointer(&aFull[0]))
	aEnd := aStart + uintptr(len(aFull))
	bStart := uintptr(unsafe.Pointer(&b[0]))
	bEnd := bStart + uintptr(len(b))
	return aStart < bEnd && bStart < aEnd
}

// EncryptMessage encrypts a single message and returns its wire bytes.
//
// Two internal paths compose the same on-wire envelope:
//
//  1. Direct whole-buffer path — chosen when the parallax layer is
//     disengaged for this Pipeline. The plaintext feeds a single
//     itb-root Single Message entry ([itb.Encrypt3x{128,256,512}Cfg]
//     on the No MAC arm, [itb.EncryptAuthenticated3x{128,256,512}Cfg]
//     on the MAC arm), whose wire — the 32-byte prefix followed by one
//     chunk — is exactly the one-chunk transcript the streaming
//     encoders produce, so the per-chunk io.Reader / io.Writer
//     machinery of [Pipeline.EncryptStream] is bypassed for the
//     message surface. The wrapper layer, when engaged, is composed as
//     a [wrapper.WrapInPlace] over that inner wire.
//  2. Streaming-fallback path — chosen when the parallax layer is
//     engaged, when the plaintext exceeds [messageFastPathMaxBytes],
//     or when the resolved profile carries a mode the direct path does
//     not cover. Composes the same Triple chain the
//     [Pipeline.EncryptStream] surface uses, with the plaintext driven
//     through a [bytes.Reader] into a [bytes.Buffer] wire sink.
//
// The Single Message vs Streaming distinction is a naming / UX choice:
// the byte shape produced by either path is a stream that fits in a
// single chunk when the plaintext is at or below the resolved
// chunkSize. Wire bytes produced by [Pipeline.EncryptStream] on a
// Streaming profile remain consumable by [Pipeline.DecryptMessage]
// on the same profile, and vice versa (Streaming profiles only for the
// message→stream direction, since Single Message profiles reject
// [Pipeline.DecryptStream] with [ErrProfileNotStreaming]).
//
// Accepted profile modes: Streaming AEAD, Streaming Non-AEAD, Single
// Message MAC, Single Message No MAC. The blob-only profile has no
// cipher surface and returns [ErrProfileNoCipher].
//
// Concurrent-safe on one [*Pipeline]: per-call state lives on the
// caller's stack, and the Pipeline's post-[Init] cipher-relevant state
// is read-only. Multiple goroutines may call EncryptMessage against
// the same [*Pipeline] simultaneously.
//
// Empty plaintext (nil or zero-length) is rejected upfront with
// [ErrEmptyInput] before any wire is produced.
//
// Returns [ErrClosed] when [Pipeline.Close] has already run;
// [ErrProfileNoCipher] when the resolved profile mode is blob-only;
// [ErrEmptyInput] on empty plaintext.
func (p *Pipeline) EncryptMessage(plaintext []byte) ([]byte, error) {
	return p.EncryptMessageTo(nil, plaintext)
}

// EncryptMessageTo encrypts plaintext and writes the resulting wire
// bytes into dst[:0], returning the populated slice. When cap(dst) is
// sufficient to hold the wire envelope, no output slice is allocated on
// the heap; otherwise a fresh slice is allocated and returned. On any
// cipher failure after output staging begins, any candidate bytes
// written into dst are wiped before return.
func (p *Pipeline) EncryptMessageTo(dst, plaintext []byte) ([]byte, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	if hasNoCipherSurface(p.resolved.Mode) {
		return nil, ErrProfileNoCipher
	}
	if len(plaintext) == 0 {
		return nil, ErrEmptyInput
	}
	if p.canEncryptDirect(len(plaintext)) {
		return p.encryptMessageDirectTo(dst, plaintext)
	}
	if p.resolved.Wrapper {
		return p.encryptStreamBytesTailWrapTo(dst, plaintext)
	}
	return p.encryptMessageStreamingTo(dst, plaintext)
}

// DecryptMessage is the receive-side counterpart of
// [Pipeline.EncryptMessage]. Two internal paths compose the same
// on-wire decoding contract:
//
//  1. Direct whole-buffer path — chosen when the parallax layer is
//     disengaged AND the wire parses as a single-chunk envelope
//     (the 32-byte prefix followed by exactly one chunk whose
//     header-announced length equals the remaining wire length after
//     any wrapper unwrap). Dispatches into
//     [itb.Decrypt3x{128,256,512}Cfg] on the No MAC arm or
//     [itb.DecryptAuthenticated3x{128,256,512}Cfg] on the MAC arm,
//     each consuming the prefix-plus-chunk wire whole.
//  2. Streaming-fallback path — chosen when the parallax layer is
//     engaged or the wire carries a multi-chunk envelope (as produced
//     by [Pipeline.EncryptStream] on plaintext larger than the
//     resolved chunkSize). Feeds the wire bytes through a
//     [bytes.Reader] into the reverse Triple chain.
//
// Same concurrency posture as [Pipeline.EncryptMessage]: safe for
// concurrent invocation on one [*Pipeline]. Wire bytes produced by
// [Pipeline.EncryptStream] on a Streaming profile are consumable here
// as long as the profile mode matches; wire bytes produced by
// EncryptMessage are consumable by [Pipeline.DecryptStream] on the
// same profile provided the profile is a Streaming profile (Single
// Message profiles reject [Pipeline.DecryptStream] with
// [ErrProfileNotStreaming]).
//
// Empty wire (nil or zero-length) is rejected upfront with
// [ErrEmptyInput] before any parse.
//
// Returns [ErrClosed] when [Pipeline.Close] has already run;
// [ErrProfileNoCipher] when the resolved profile mode is blob-only;
// [ErrEmptyInput] on empty wire.
func (p *Pipeline) DecryptMessage(wire []byte) ([]byte, error) {
	return p.DecryptMessageTo(nil, wire)
}

// DecryptMessageTo decrypts wire and writes the recovered plaintext
// into dst[:0], returning the populated slice. When cap(dst) is
// sufficient, no output slice is allocated on the heap; otherwise a
// fresh slice is allocated and returned. On any cipher failure after
// output staging begins, any candidate bytes written into dst are wiped
// before return.
func (p *Pipeline) DecryptMessageTo(dst, wire []byte) ([]byte, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	if hasNoCipherSurface(p.resolved.Mode) {
		return nil, ErrProfileNoCipher
	}
	if len(wire) == 0 {
		return nil, ErrEmptyInput
	}
	if p.resolved.Wrapper {
		return p.decryptStreamBytesTailUnwrapTo(dst, wire)
	}
	plain, ok, err := p.decryptInnerSingleChunkTo(dst, wire)
	if ok {
		return plain, err
	}
	return p.decryptMessageStreamingTo(dst, wire)
}

// encryptMessageDirect implements the direct whole-buffer encrypt
// path. Precondition: [Pipeline.canEncryptDirect] holds for
// len(plaintext). Produces the same wire envelope as the streaming
// fallback when the payload fits in a single ITB chunk.
func (p *Pipeline) encryptMessageDirect(plaintext []byte) ([]byte, error) {
	return p.encryptMessageDirectTo(nil, plaintext)
}

func (p *Pipeline) encryptMessageDirectTo(dst, plaintext []byte) ([]byte, error) {
	// Public entry points reject empty input with ErrEmptyInput
	// upfront; this branch is a defensive guard if an internal caller
	// passes an empty slice on the No MAC arm.
	if len(plaintext) == 0 && p.macFunc == nil && !p.resolved.Parallax {
		if p.resolved.Wrapper {
			nonce, err := wrapper.WrapInPlace(p.wrapperCipher, p.wrapperKey, nil)
			if err != nil {
				return nil, fmt.Errorf("triple: wrapper.WrapInPlace: %w", err)
			}
			if cap(dst) >= len(nonce) {
				out := dst[:len(nonce)]
				copy(out, nonce)
				wipe.Bytes(nonce)
				return out, nil
			}
			return nonce, nil
		}
		if cap(dst) > 0 {
			return dst[:0], nil
		}
		return []byte{}, nil
	}

	innerPlain := plaintext
	if p.resolved.Parallax {
		frameLen := parallaxFrameHeaderBytes + len(plaintext)
		framePtr, frame := acquireTripleScratch(frameLen)
		defer releaseTripleScratch(framePtr, frame)
		nonce, err := p.parallaxSched.EncryptInto(frame[parallaxFrameHeaderBytes:], plaintext, p.parallaxCS)
		if err != nil {
			return nil, fmt.Errorf("triple: parallax.EncryptInto: %w", err)
		}
		binary.LittleEndian.PutUint32(frame[:4], uint32(len(plaintext)))
		copy(frame[4:parallaxFrameHeaderBytes], nonce)
		innerPlain = frame
	}

	nlen := 0
	if p.resolved.Wrapper {
		var err error
		nlen, err = wrapper.NonceSize(p.wrapperCipher)
		if err != nil {
			return nil, fmt.Errorf("triple: wrapper.NonceSize: %w", err)
		}
	}
	lead := nlen + streamIDPrefixLen

	// The itb-root Single Message *Into entries reserve lead bytes
	// ahead of the chunk and write the 32-byte streamID (or No MAC
	// dummy) into out[lead-32 : lead]. When Wrapper is engaged, the
	// leading nlen bytes hold the wrapper nonce slot and WrapInPlace
	// seals out[nlen:] in place without a second allocation or copy.
	var (
		out []byte
		err error
	)
	if p.macFunc != nil {
		out, err = encryptMessageAuthInto(p, dst, lead, innerPlain)
	} else {
		out, err = encryptMessageNoMACInto(p, dst, lead, innerPlain)
	}
	if err != nil {
		return nil, err
	}
	if p.resolved.Wrapper {
		nonce, werr := wrapper.WrapInPlace(p.wrapperCipher, p.wrapperKey, out[nlen:])
		if werr != nil {
			wipe.Bytes(out)
			return nil, fmt.Errorf("triple: wrapper.WrapInPlace: %w", werr)
		}
		copy(out[:nlen], nonce)
	}
	if cap(dst) >= len(out) && len(out) > 0 && &out[0] != &dst[:1][0] {
		res := dst[:len(out)]
		copy(res, out)
		wipe.Bytes(out)
		return res, nil
	}
	return out, nil
}

// decryptMessageDirect attempts the direct whole-buffer decrypt path.
// Returns (plaintext, true, err) when the wire has been fully claimed
// by this path (successfully decoded or terminally rejected). Returns
// (nil, false, nil) when the wire does not parse as a single-chunk
// envelope, signalling the caller to fall through to the streaming
// fallback.
func (p *Pipeline) decryptMessageDirect(wire []byte) ([]byte, bool, error) {
	return p.decryptMessageDirectTo(nil, wire)
}

func (p *Pipeline) decryptMessageDirectTo(dst, wire []byte) ([]byte, bool, error) {
	inner := wire
	if p.resolved.Wrapper {
		// Public entry points reject empty wire with ErrEmptyInput
		// upfront; this branch is a defensive guard if an internal
		// caller passes an empty slice under wrapper-on.
		if len(wire) == 0 {
			if p.macFunc == nil && !p.resolved.Parallax {
				if cap(dst) > 0 {
					return dst[:0], true, nil
				}
				return []byte{}, true, nil
			}
			return nil, false, nil
		}
		nlen, err := wrapper.NonceSize(p.wrapperCipher)
		if err != nil {
			return nil, false, nil
		}
		if len(wire) < nlen {
			return nil, false, nil
		}
		bufPtr, buf := acquireTripleScratch(len(wire))
		defer releaseTripleScratch(bufPtr, buf)
		copy(buf, wire)
		unwrapped, uerr := wrapper.UnwrapInPlace(p.wrapperCipher, p.wrapperKey, buf)
		if uerr != nil {
			return nil, false, nil
		}
		inner = unwrapped
	}
	return p.decryptInnerSingleChunkTo(dst, inner)
}

// encryptMessageNoMAC width-dispatches to the No MAC Single Message
// encrypt entry. Threads the Pipeline's per-instance Config so nonce
// width / barrier fill / max-workers overrides land on the underlying
// call site.
func encryptMessageNoMAC(p *Pipeline, plaintext []byte) ([]byte, error) {
	return encryptMessageNoMACInto(p, nil, streamIDPrefixLen, plaintext)
}

func encryptMessageNoMACInto(p *Pipeline, dst []byte, lead int, plaintext []byte) ([]byte, error) {
	switch p.width {
	case 128, 256, 512:
		return triplewire.EncryptNoMACInto(p.width, p.cfg, dst, lead,
			p.seeds[0], p.seeds[1], p.seeds[2], p.seeds[3],
			p.seeds[4], p.seeds[5], p.seeds[6], p.seeds[7],
			plaintext,
		)
	}
	return nil, fmt.Errorf("triple: unsupported inner width %d", p.width)
}

// encryptMessageAuth width-dispatches to the MAC Authenticated Single
// Message encrypt entry, which binds its CSPRNG streamID prefix into
// the MAC with cumulative offset 0 and finalFlag true — the same
// per-chunk binding the streaming fallback emits when the plaintext
// fits in one chunk.
func encryptMessageAuth(p *Pipeline, plaintext []byte) ([]byte, error) {
	return encryptMessageAuthInto(p, nil, streamIDPrefixLen, plaintext)
}

func encryptMessageAuthInto(p *Pipeline, dst []byte, lead int, plaintext []byte) ([]byte, error) {
	switch p.width {
	case 128, 256, 512:
		return triplewire.EncryptAuthInto(p.width, p.cfg, dst, lead,
			p.seeds[0], p.seeds[1], p.seeds[2], p.seeds[3],
			p.seeds[4], p.seeds[5], p.seeds[6], p.seeds[7],
			plaintext, p.macFunc,
		)
	}
	return nil, fmt.Errorf("triple: unsupported inner width %d", p.width)
}

// decryptMessageNoMAC width-dispatches to the No MAC Single Message
// decrypt entry. Mirror image of [encryptMessageNoMAC]; inner is the
// whole prefix-plus-chunk wire.
func decryptMessageNoMAC(p *Pipeline, inner []byte) ([]byte, error) {
	return decryptMessageNoMACInto(p, nil, inner)
}

func decryptMessageNoMACInto(p *Pipeline, dst, inner []byte) ([]byte, error) {
	switch p.width {
	case 128, 256, 512:
		return triplewire.DecryptNoMACInto(p.width, p.cfg, dst,
			p.seeds[0], p.seeds[1], p.seeds[2], p.seeds[3],
			p.seeds[4], p.seeds[5], p.seeds[6], p.seeds[7],
			inner,
		)
	}
	return nil, fmt.Errorf("triple: unsupported inner width %d", p.width)
}

// decryptMessageAuth width-dispatches to the MAC Authenticated Single
// Message decrypt entry, the mirror image of [encryptMessageAuth]:
// the root entry reads the streamID prefix, verifies the chunk at
// cumulative offset 0 and rejects a non-terminating chunk with
// [itb.ErrStreamTruncated]. inner is the whole prefix-plus-chunk wire.
func decryptMessageAuth(p *Pipeline, inner []byte) ([]byte, error) {
	return decryptMessageAuthInto(p, nil, inner)
}

func decryptMessageAuthInto(p *Pipeline, dst, inner []byte) ([]byte, error) {
	switch p.width {
	case 128, 256, 512:
		return triplewire.DecryptAuthInto(p.width, p.cfg, dst,
			p.seeds[0], p.seeds[1], p.seeds[2], p.seeds[3],
			p.seeds[4], p.seeds[5], p.seeds[6], p.seeds[7],
			inner, p.macFunc,
		)
	}
	return nil, fmt.Errorf("triple: unsupported inner width %d", p.width)
}

// encryptMessageStreaming is the fallback encrypt path. Chains the
// plaintext through the same io.Reader / io.Writer surface the
// [Pipeline.EncryptStream] method uses, chunking at
// [Pipeline.resolved.ChunkSize] granularity. Covers the parallax-on
// case (where the parallax reader's per-chunk frame envelope must be
// preserved) and oversized plaintexts (larger than
// [messageFastPathMaxBytes]).
func (p *Pipeline) encryptMessageStreaming(plaintext []byte) ([]byte, error) {
	return p.encryptMessageStreamingTo(nil, plaintext)
}

func (p *Pipeline) encryptMessageStreamingTo(dst, plaintext []byte) ([]byte, error) {
	need := p.MaxWireSize(len(plaintext))
	var wire *bytes.Buffer
	if need > 0 && cap(dst) >= need && !slicesOverlap(dst, plaintext) {
		wire = bytes.NewBuffer(dst[:0:cap(dst)])
	} else {
		wire = &bytes.Buffer{}
		wire.Grow(need)
	}
	innerSrc, innerDst, closeFn, err := buildEncryptChain(p, bytes.NewReader(plaintext), wire)
	if err != nil {
		return nil, err
	}

	var cipherErr error
	if p.macFunc != nil {
		cipherErr = itb.EncryptStreamAuth3xCfg(
			p.cfg,
			p.seeds[0], p.seeds[1],
			p.seeds[2], p.seeds[3], p.seeds[4],
			p.seeds[5], p.seeds[6], p.seeds[7],
			innerSrc, innerDst, p.macFunc, p.resolved.ChunkSize,
		)
	} else {
		cipherErr = itb.EncryptStream3xCfg(
			p.cfg,
			p.seeds[0], p.seeds[1],
			p.seeds[2], p.seeds[3], p.seeds[4],
			p.seeds[5], p.seeds[6], p.seeds[7],
			innerSrc, innerDst, p.resolved.ChunkSize,
		)
	}
	if err := joinCloseError(cipherErr, closeFn()); err != nil {
		if c, ok := innerDst.(io.Closer); ok {
			_ = c.Close()
		}
		b := wire.Bytes()
		wipe.Bytes(b[:cap(b)])
		return nil, err
	}
	// Public entry points reject empty input with ErrEmptyInput
	// upfront; FinishWrapStream flushes any pending wrapper state on
	// close (no-op when wrapper is disengaged or body bytes were
	// already emitted).
	if err := wrapper.FinishWrapStream(innerDst); err != nil {
		b := wire.Bytes()
		wipe.Bytes(b[:cap(b)])
		return nil, err
	}
	out := wire.Bytes()
	if cap(dst) >= len(out) && len(out) > 0 && &out[0] != &dst[:1][0] && !slicesOverlap(dst, plaintext) {
		res := dst[:len(out)]
		copy(res, out)
		wipe.Bytes(out[:cap(out)])
		return res, nil
	}
	return out, nil
}

// decryptMessageStreaming is the fallback decrypt path. Mirror image
// of [encryptMessageStreaming] — feeds the wire through a
// [bytes.Reader] into the reverse Triple chain. Covers parallax-on
// and multi-chunk wires.
func (p *Pipeline) decryptMessageStreaming(wire []byte) ([]byte, error) {
	return p.decryptMessageStreamingTo(nil, wire)
}

func (p *Pipeline) decryptMessageStreamingTo(dst, wire []byte) ([]byte, error) {
	growHint := p.MaxPlaintextSize(len(wire))
	if growHint <= 0 {
		growHint = len(wire)
	}
	var plain *bytes.Buffer
	if cap(dst) >= growHint && !slicesOverlap(dst, wire) {
		plain = bytes.NewBuffer(dst[:0:cap(dst)])
	} else {
		plain = &bytes.Buffer{}
		plain.Grow(growHint)
	}
	innerSrc, innerDst, closeFn, err := buildDecryptChain(p, bytes.NewReader(wire), plain)
	if err != nil {
		return nil, err
	}

	var cipherErr error
	if p.macFunc != nil {
		cipherErr = itb.DecryptStreamAuth3xCfg(
			p.cfg,
			p.seeds[0], p.seeds[1],
			p.seeds[2], p.seeds[3], p.seeds[4],
			p.seeds[5], p.seeds[6], p.seeds[7],
			innerSrc, innerDst, p.macFunc,
		)
	} else {
		cipherErr = itb.DecryptStream3xCfg(
			p.cfg,
			p.seeds[0], p.seeds[1],
			p.seeds[2], p.seeds[3], p.seeds[4],
			p.seeds[5], p.seeds[6], p.seeds[7],
			innerSrc, innerDst,
		)
	}
	if err := joinCloseError(cipherErr, closeFn()); err != nil {
		b := plain.Bytes()
		wipe.Bytes(b[:cap(b)])
		return nil, err
	}
	out := plain.Bytes()
	if cap(dst) >= len(out) && len(out) > 0 && &out[0] != &dst[:1][0] && !slicesOverlap(dst, wire) {
		res := dst[:len(out)]
		copy(res, out)
		wipe.Bytes(out[:cap(out)])
		return res, nil
	}
	return out, nil
}

// hasNoCipherSurface reports whether the resolved profile mode
// exposes no cipher path at all. The blob-only profile is the sole
// trigger today; kept as a helper so [EncryptMessage] and
// [DecryptMessage] share one guard branch verbatim, parallel to
// [isStreamingMode]'s role for the streaming guard.
func hasNoCipherSurface(mode string) bool {
	return mode == modeBlobOnly
}

// streamIDPrefixLen is the on-wire byte length of the prefix every
// chunk travels behind, emitted by the itb-root streaming encoders and
// Single Message entries and consumed by their decoders. Held here as
// a local mirror of the
// itb-root constant so the Triple message surface stays
// self-documenting without a cross-package import for a single byte
// count.
const streamIDPrefixLen = 32

// MaxWireSize returns the deterministic wire byte length that
// [Pipeline.EncryptMessage] produces for a plaintext of length
// plaintextLen (> 0) under this Pipeline's resolved profile and Config
// (including Wrapper nonce, 32-byte prefix, NonceBits header,
// ContainerMode 1/2 floor, BarrierFill, MAC tag reservation, COBS
// bound, and Parallax framing). Returns 0 when p is nil, closed, has
// no cipher surface, or plaintextLen <= 0.
func (p *Pipeline) MaxWireSize(plaintextLen int) int {
	if p == nil {
		return 0
	}
	return p.MaxWireSizeWithBarrierFill(plaintextLen, p.effectiveBarrierFill())
}

func addSat(a, b int) int {
	if b > math.MaxInt-a {
		return math.MaxInt
	}
	return a + b
}

func mulSat(a, b int) int {
	if a <= 0 || b <= 0 {
		return 0
	}
	if a > math.MaxInt/b {
		return math.MaxInt
	}
	return a * b
}

// MaxWireSizeWithBarrierFill returns the deterministic wire byte length
// that [Pipeline.EncryptMessage] produces for a plaintext of length
// plaintextLen (> 0) when evaluated under maxBarrierFill. When
// maxBarrierFill <= 0, the Pipeline's configured BarrierFill (or
// [itb.DefaultBarrierFill] = 1) is used; positive values are rounded up
// to the valid ITB BarrierFill set {1, 2, 4, 8, 16, 32} (clamped at 32).
func (p *Pipeline) MaxWireSizeWithBarrierFill(plaintextLen, maxBarrierFill int) int {
	if p == nil || p.isClosed() || hasNoCipherSurface(p.resolved.Mode) || plaintextLen <= 0 {
		return 0
	}
	bf := p.resolveBarrierFill(maxBarrierFill)

	var total int
	if p.canEncryptDirect(plaintextLen) {
		innerLen := plaintextLen
		if p.resolved.Parallax {
			innerLen += parallaxFrameHeaderBytes
		}
		total = p.chunkWireSize(innerLen, bf)
	} else {
		cs := p.resolved.ChunkSize
		if cs <= 0 {
			cs = itb.DefaultChunkSize
		}
		innerLen := plaintextLen
		if p.resolved.Parallax {
			numFrames := 1 + (plaintextLen-1)/cs
			innerLen = addSat(plaintextLen, mulSat(numFrames, parallaxFrameHeaderBytes))
			if innerLen == math.MaxInt {
				return math.MaxInt
			}
		}
		fullChunks := innerLen / cs
		rem := innerLen % cs
		if fullChunks > 0 {
			total = addSat(total, mulSat(fullChunks, p.chunkWireSize(cs, bf)))
		}
		if rem > 0 {
			total = addSat(total, p.chunkWireSize(rem, bf))
		}
	}

	if p.resolved.Wrapper {
		if nlen, err := wrapper.NonceSize(p.wrapperCipher); err == nil {
			total = addSat(total, nlen)
		}
	}
	return total
}

// MaxPlaintextSize is the monotone inverse of [Pipeline.MaxWireSize]:
// it returns the largest plaintext byte length whose encrypted wire
// envelope does not exceed maxWireBytes, or 0 if even a 1-byte
// plaintext exceeds maxWireBytes.
func (p *Pipeline) MaxPlaintextSize(maxWireBytes int) int {
	if p == nil {
		return 0
	}
	return p.MaxPlaintextSizeWithBarrierFill(maxWireBytes, p.effectiveBarrierFill())
}

// MaxPlaintextSizeWithBarrierFill is the monotone inverse of
// [Pipeline.MaxWireSizeWithBarrierFill]: it returns the largest
// plaintext byte length whose encrypted wire envelope under
// maxBarrierFill does not exceed maxWireBytes, or 0 if even a 1-byte
// plaintext exceeds maxWireBytes.
func (p *Pipeline) MaxPlaintextSizeWithBarrierFill(maxWireBytes, maxBarrierFill int) int {
	if p == nil || p.isClosed() || hasNoCipherSurface(p.resolved.Mode) || maxWireBytes <= 0 {
		return 0
	}
	if p.MaxWireSizeWithBarrierFill(1, maxBarrierFill) > maxWireBytes {
		return 0
	}
	lo, hi := 1, maxWireBytes
	if hi == math.MaxInt {
		hi = math.MaxInt - 1
	}
	for lo < hi {
		mid := lo + (hi-lo+1)/2
		w := p.MaxWireSizeWithBarrierFill(mid, maxBarrierFill)
		if w < mid || w > maxWireBytes {
			hi = mid - 1
		} else {
			lo = mid
		}
	}
	return lo
}

func (p *Pipeline) effectiveBarrierFill() int {
	if p.cfg != nil && p.cfg.BarrierFill > 0 {
		return p.cfg.BarrierFill
	}
	return itb.DefaultBarrierFill
}

func (p *Pipeline) resolveBarrierFill(maxBarrierFill int) int {
	if maxBarrierFill <= 0 {
		return p.effectiveBarrierFill()
	}
	switch {
	case maxBarrierFill <= 1:
		return 1
	case maxBarrierFill <= 2:
		return 2
	case maxBarrierFill <= 4:
		return 4
	case maxBarrierFill <= 8:
		return 8
	case maxBarrierFill <= 16:
		return 16
	default:
		return 32
	}
}

func (p *Pipeline) chunkWireSize(chunkPlainLen, bf int) int {
	laneLen := 2 * ((chunkPlainLen + 4 + 5) / 6)
	nonceLen := itb.DefaultNonceBits / 8
	if p.cfg != nil && p.cfg.NonceBits > 0 {
		nonceLen = p.cfg.NonceBits / 8
	}
	lens := [3]int{nonceLen / 3, nonceLen / 3, nonceLen / 3}
	for i := 0; i < nonceLen%3; i++ {
		lens[i]++
	}
	tagSize := 32
	if p.macFunc != nil {
		if spec, ok := macs.Find(p.resolved.MacName); ok && spec.TagSize > 0 {
			tagSize = spec.TagSize
		} else if tag := p.macFunc(nil); len(tag) > 0 {
			tagSize = len(tag)
			wipe.Bytes(tag)
		}
	} else if p.cfg != nil && p.cfg.TagStubSize > 0 {
		tagSize = p.cfg.TagStubSize
	}
	reserve := tagSize + 1

	cobsBound := func(n int) int {
		if n <= 0 {
			return 1
		}
		return n + n/254 + 2
	}
	cobsLens := [3]int{
		cobsBound(lens[0] + laneLen),
		cobsBound(lens[1] + laneLen),
		cobsBound(lens[2]+laneLen) + reserve,
	}

	minPx := (p.resolved.KeyBits*10000 + 28074 - 1) / 28074
	var totalPixels int
	if p.cfg != nil && p.cfg.Mode == 2 {
		maxDataThirdPixels := 0
		for i := 0; i < 3; i++ {
			needed := cobsLens[i] + 1
			pixels := (needed*8 + itb.DataBitsPerPixel - 1) / itb.DataBitsPerPixel
			if pixels > maxDataThirdPixels {
				maxDataThirdPixels = pixels
			}
		}
		totalPixels = 3 * maxDataThirdPixels
		if totalPixels < minPx {
			totalPixels = minPx
		}
	} else {
		maxThirdPixels := 0
		for i := 0; i < 3; i++ {
			needed := cobsLens[i] + 1
			pixels := (needed*8 + itb.DataBitsPerPixel - 1) / itb.DataBitsPerPixel
			if pixels < minPx {
				pixels = minPx
			}
			if pixels > maxThirdPixels {
				maxThirdPixels = pixels
			}
		}
		totalPixels = 3 * maxThirdPixels
	}

	side := ceilSqrt(totalPixels) + bf
	hdrLen := nonceLen + 4
	return streamIDPrefixLen + hdrLen + side*side*itb.Channels
}

func ceilSqrt(n int) int {
	if n <= 1 {
		return 1
	}
	s := int(math.Sqrt(float64(n)))
	for s*s < n {
		s++
	}
	for (s-1)*(s-1) >= n {
		s--
	}
	return s
}
