package triple

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/everanium/itb"
	"github.com/everanium/itb/internal/triplewire"
	"github.com/everanium/itb/internal/wipe"
	"github.com/everanium/itb/wrapper"
)

func init() {
	triplewire.EncryptStreamBytesTo = func(pipe any, dst, plaintext []byte) ([]byte, error) {
		return pipe.(*Pipeline).encryptStreamBytesTo(dst, plaintext)
	}
	triplewire.DecryptStreamBytesTo = func(pipe any, dst, wire []byte) ([]byte, error) {
		return pipe.(*Pipeline).decryptStreamBytesTo(dst, wire)
	}
}

// EncryptStreamBytes is the whole-buffer convenience form of
// [Pipeline.EncryptStream]: the entire plaintext is available up front
// as one in-memory slice and the entire wire is returned as one slice.
// The on-wire contract is the Streaming surface's — the returned bytes
// are consumable by [Pipeline.DecryptStream] and
// [Pipeline.DecryptStreamBytes] (and, on Streaming profiles, by
// [Pipeline.DecryptMessage]).
//
// Internal dispatch, in order:
//
//  1. Direct whole-buffer path — when the payload fits within a single
//     ITB chunk (plaintext at or below [messageFastPathMaxBytes] when
//     parallax is disengaged, or len(plaintext)+20 <= chunkSize and
//     <= [messageFastPathMaxBytes] when parallax is engaged), the
//     call composes the same single-chunk emission as
//     [Pipeline.EncryptMessage]'s direct path (one itb-root Single
//     Message entry, whose wire is the 32-byte prefix plus one chunk;
//     wrapper composed via [wrapper.WrapInPlace] when engaged). A
//     single-chunk wire is a valid Streaming wire: the streaming
//     decoder accepts one final-flag chunk of any length within the
//     itb-root Single Message cap, independent of the resolved
//     chunkSize.
//  2. Tail-wrap path — when the wrapper layer is engaged and the
//     payload exceeds the single-chunk direct threshold, the inner
//     multi-chunk stream is encoded directly into one buffer with the
//     wrapper nonce slot reserved up front, then sealed via
//     [wrapper.WrapInPlace] over the assembled inner bytes. The wire is
//     identical in structure to the [wrapper.NewWrapWriter] emission
//     (nonce || keystream-XOR(inner) under one logical keystream); the
//     in-place variant XORs the whole body in one parallel pass instead
//     of per-Write keystream reseats.
//  3. Streaming fallback — every other posture (multi-chunk plaintext
//     with the wrapper disengaged) drives the same chain
//     [Pipeline.EncryptStream] composes, with the plaintext read from a
//     [bytes.Reader] into a [bytes.Buffer] wire sink.
//
// Same concurrency posture as [Pipeline.EncryptStream]: safe for
// concurrent invocation on one [*Pipeline]. Returns [ErrClosed] when
// [Pipeline.Close] has already run; [ErrProfileNotStreaming] when the
// resolved profile mode is Single Message or blob-only;
// [ErrEmptyInput] on empty plaintext (nil or zero-length) — rejected
// before any wire is produced, matching every other Pipeline cipher
// entry point.
func (p *Pipeline) EncryptStreamBytes(plaintext []byte) ([]byte, error) {
	return p.encryptStreamBytesTo(nil, plaintext)
}

// encryptStreamBytesTo is like [Pipeline.EncryptStreamBytes] but writes
// the resulting wire bytes into dst[:0] when cap(dst) is sufficient,
// avoiding an output slice allocation on the single-chunk fast path.
func (p *Pipeline) encryptStreamBytesTo(dst, plaintext []byte) ([]byte, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	if !isStreamingMode(p.resolved.Mode) {
		return nil, ErrProfileNotStreaming
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

// DecryptStreamBytes is the whole-buffer convenience form of
// [Pipeline.DecryptStream]: the entire wire is available up front as
// one in-memory slice and the entire plaintext is returned as one
// slice. Accepts every wire shape the Streaming surface produces —
// single-chunk (as emitted by [Pipeline.EncryptStreamBytes]'s direct
// path or [Pipeline.EncryptMessage]) and multi-chunk (as emitted by
// [Pipeline.EncryptStream] on plaintext larger than the resolved
// chunkSize). The caller's wire slice is never mutated.
//
// Internal dispatch, in order:
//
//  1. Wrapper engaged — the wire is copied once into a pooled scratch
//     buffer and unwrapped via [wrapper.UnwrapInPlace] (one parallel
//     keystream pass), then the inner bytes take the single-chunk
//     direct decode when they parse as one chunk (including single-chunk
//     parallax frames), or the streaming decode otherwise — without a
//     second unwrap in either arm. Wires that fail the structural
//     pre-checks (shorter than the wrapper nonce, or failing the unwrap
//     itself) route through the streaming fallback so its canonical
//     diagnostics surface.
//  2. Wrapper off — single-chunk wires take the direct decode;
//     multi-chunk wires take the streaming fallback.
//
// Same concurrency posture as [Pipeline.DecryptStream]: safe for
// concurrent invocation on one [*Pipeline]. Returns [ErrClosed] when
// [Pipeline.Close] has already run; [ErrProfileNotStreaming] when the
// resolved profile mode is Single Message or blob-only;
// [ErrEmptyInput] on empty wire (nil or zero-length) — rejected
// before any parse, since no valid Pipeline wire is empty.
func (p *Pipeline) DecryptStreamBytes(wire []byte) ([]byte, error) {
	return p.decryptStreamBytesTo(nil, wire)
}

// decryptStreamBytesTo is like [Pipeline.DecryptStreamBytes] but writes
// the recovered plaintext into dst[:0] when cap(dst) is sufficient,
// avoiding an output slice allocation on the single-chunk fast path.
func (p *Pipeline) decryptStreamBytesTo(dst, wire []byte) ([]byte, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	if !isStreamingMode(p.resolved.Mode) {
		return nil, ErrProfileNotStreaming
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

// encryptStreamBytesTailWrap implements the tail-wrap encrypt path.
// Precondition: wrapper on, plaintext exceeds the single-chunk direct
// threshold. The inner multi-chunk stream is encoded into a buffer
// whose leading bytes reserve the wrapper nonce slot;
// [wrapper.WrapInPlace] then seals the assembled inner bytes in one
// pass and the returned nonce fills the reserved slot.
func (p *Pipeline) encryptStreamBytesTailWrap(plaintext []byte) ([]byte, error) {
	return p.encryptStreamBytesTailWrapTo(nil, plaintext)
}

func (p *Pipeline) encryptStreamBytesTailWrapTo(dst, plaintext []byte) ([]byte, error) {
	nlen, err := wrapper.NonceSize(p.wrapperCipher)
	if err != nil {
		return nil, fmt.Errorf("triple: wrapper.NonceSize: %w", err)
	}

	need := p.MaxWireSize(len(plaintext))
	var wire *bytes.Buffer
	if need > 0 && cap(dst) >= need && !slicesOverlap(dst, plaintext) {
		wire = bytes.NewBuffer(dst[:0:cap(dst)])
	} else {
		wire = &bytes.Buffer{}
		wire.Grow(need)
	}
	var zeroNonce [64]byte
	if nlen <= len(zeroNonce) {
		wire.Write(zeroNonce[:nlen])
	} else {
		wire.Write(make([]byte, nlen))
	}

	var src io.Reader = bytes.NewReader(plaintext)
	closeFn := func() error { return nil }
	if p.resolved.Parallax {
		r, rerr := p.parallaxSched.NewEncryptReader(p.parallaxCS, src)
		if rerr != nil {
			b := wire.Bytes()
			wipe.Bytes(b[:cap(b)])
			return nil, fmt.Errorf("triple: parallax.NewEncryptReader: %w", rerr)
		}
		src = r
		closeFn = r.Close
	}

	var cipherErr error
	if p.macFunc != nil {
		cipherErr = itb.EncryptStreamAuth3xCfg(
			p.cfg,
			p.seeds[0], p.seeds[1],
			p.seeds[2], p.seeds[3], p.seeds[4],
			p.seeds[5], p.seeds[6], p.seeds[7],
			src, wire, p.macFunc, p.resolved.ChunkSize,
		)
	} else {
		cipherErr = itb.EncryptStream3xCfg(
			p.cfg,
			p.seeds[0], p.seeds[1],
			p.seeds[2], p.seeds[3], p.seeds[4],
			p.seeds[5], p.seeds[6], p.seeds[7],
			src, wire, p.resolved.ChunkSize,
		)
	}
	if err := joinCloseError(cipherErr, closeFn()); err != nil {
		b := wire.Bytes()
		wipe.Bytes(b[:cap(b)])
		return nil, err
	}

	out := wire.Bytes()
	nonce, werr := wrapper.WrapInPlace(p.wrapperCipher, p.wrapperKey, out[nlen:])
	if werr != nil {
		wipe.Bytes(out[:cap(out)])
		return nil, fmt.Errorf("triple: wrapper.WrapInPlace: %w", werr)
	}
	copy(out[:nlen], nonce)
	if cap(dst) >= len(out) && len(out) > 0 && &out[0] != &dst[:1][0] && !slicesOverlap(dst, plaintext) {
		res := dst[:len(out)]
		copy(res, out)
		wipe.Bytes(out[:cap(out)])
		return res, nil
	}
	return out, nil
}

// decryptStreamBytesTailUnwrap implements the tail-unwrap decrypt
// path. Precondition: wrapper on. The wire is copied once into a
// pooled scratch buffer (the caller's slice must stay intact) and
// unwrapped via [wrapper.UnwrapInPlace]; the inner bytes then take the
// single-chunk direct decode or the streaming decode, each without a
// second unwrap. Structurally short or unwrap-rejected wires route
// through the streaming fallback so its canonical diagnostics surface.
func (p *Pipeline) decryptStreamBytesTailUnwrap(wire []byte) ([]byte, error) {
	return p.decryptStreamBytesTailUnwrapTo(nil, wire)
}

func (p *Pipeline) decryptStreamBytesTailUnwrapTo(dst, wire []byte) ([]byte, error) {
	nlen, err := wrapper.NonceSize(p.wrapperCipher)
	if err != nil || len(wire) < nlen {
		return p.decryptMessageStreamingTo(dst, wire)
	}

	bufPtr, buf := acquireTripleScratch(len(wire))
	defer releaseTripleScratch(bufPtr, buf)
	copy(buf, wire)
	inner, uerr := wrapper.UnwrapInPlace(p.wrapperCipher, p.wrapperKey, buf)
	if uerr != nil {
		return p.decryptMessageStreamingTo(dst, wire)
	}

	plain, ok, derr := p.decryptInnerSingleChunkTo(dst, inner)
	if ok {
		return plain, derr
	}
	return p.decryptInnerStreamingTo(dst, inner)
}

// decryptInnerSingleChunk attempts the single-chunk direct decode on
// an inner byte sequence that has already passed any wrapper unwrap.
// Returns (plaintext, true, err) when the inner has been fully claimed
// by this path (successfully decoded or terminally rejected); returns
// (nil, false, nil) when the inner does not parse as a single-chunk
// envelope, signalling the caller to fall through to a streaming
// decode. Precondition: wrapper layer already stripped (or disengaged).
func (p *Pipeline) decryptInnerSingleChunk(inner []byte) ([]byte, bool, error) {
	return p.decryptInnerSingleChunkTo(nil, inner)
}

func (p *Pipeline) decryptInnerSingleChunkTo(dst, inner []byte) ([]byte, bool, error) {
	if len(inner) == 0 {
		if p.macFunc == nil && !p.resolved.Parallax {
			if cap(dst) > 0 {
				return dst[:0], true, nil
			}
			return []byte{}, true, nil
		}
		return nil, false, nil
	}
	if len(inner) < streamIDPrefixLen {
		return nil, false, nil
	}

	body := inner[streamIDPrefixLen:]
	chunkLen, perr := itb.ParseChunkLenCfg(p.cfg, body)
	if perr != nil || chunkLen != len(body) {
		return nil, false, nil
	}

	// A one-chunk inner is a Single Message wire, so the itb-root
	// Single Message entries consume it whole, prefix included. On the
	// MAC arm the root entry rejects a chunk whose final flag is not
	// set with [itb.ErrStreamTruncated] — the same diagnostic the
	// streaming decode produces for a transcript that ends before its
	// terminator.
	if p.resolved.Parallax {
		rawPtr, rawBuf := acquireTripleScratch(len(inner))
		defer releaseTripleScratch(rawPtr, rawBuf)
		var (
			rawPlain []byte
			derr     error
		)
		if p.macFunc != nil {
			rawPlain, derr = decryptMessageAuthInto(p, rawBuf[:1], inner)
		} else {
			rawPlain, derr = decryptMessageNoMACInto(p, rawBuf[:1], inner)
		}
		if derr != nil {
			return nil, true, derr
		}
		if !slicesOverlap(rawPlain, rawBuf) {
			defer wipe.Bytes(rawPlain)
		}
		if len(rawPlain) < parallaxFrameHeaderBytes {
			return nil, false, nil
		}
		framePlainLen := int(binary.LittleEndian.Uint32(rawPlain[:4]))
		cs := p.resolved.ChunkSize
		if cs <= 0 {
			cs = itb.DefaultChunkSize
		}
		if framePlainLen <= 0 || framePlainLen > cs || parallaxFrameHeaderBytes+framePlainLen != len(rawPlain) {
			return nil, false, nil
		}
		var out []byte
		if cap(dst) >= framePlainLen {
			out = dst[:framePlainLen]
		} else {
			out = make([]byte, framePlainLen)
		}
		if _, err := p.parallaxSched.DecryptInto(out, rawPlain[4:], p.parallaxCS); err != nil {
			wipe.Bytes(out)
			return nil, true, fmt.Errorf("triple: parallax.DecryptInto: %w", err)
		}
		return out, true, nil
	}

	var dstCap []byte
	if cap(dst) > 0 {
		dstCap = dst[:0:cap(dst)]
	}
	var (
		rawPlain []byte
		derr     error
	)
	if p.macFunc != nil {
		rawPlain, derr = decryptMessageAuthInto(p, dstCap, inner)
	} else {
		rawPlain, derr = decryptMessageNoMACInto(p, dstCap, inner)
	}
	if derr != nil {
		return nil, true, derr
	}
	return rawPlain, true, nil
}

// decryptInnerStreaming stream-decodes an inner multi-chunk byte
// sequence that has already passed any wrapper unwrap. Precondition:
// wrapper layer already stripped (or disengaged) — the itb-root IO
// entry consumes the inner bytes directly, composing only the parallax
// decrypt writer when parallax is engaged.
func (p *Pipeline) decryptInnerStreaming(inner []byte) ([]byte, error) {
	return p.decryptInnerStreamingTo(nil, inner)
}

func (p *Pipeline) decryptInnerStreamingTo(dst, inner []byte) ([]byte, error) {
	growHint := p.MaxPlaintextSize(len(inner))
	if growHint <= 0 {
		growHint = len(inner)
	}
	var plain *bytes.Buffer
	if cap(dst) >= growHint && !slicesOverlap(dst, inner) {
		plain = bytes.NewBuffer(dst[:0:cap(dst)])
	} else {
		plain = &bytes.Buffer{}
		plain.Grow(growHint)
	}

	var plainDst io.Writer = plain
	closeFn := func() error { return nil }
	if p.resolved.Parallax {
		w, werr := p.parallaxSched.NewDecryptWriter(p.parallaxCS, plain)
		if werr != nil {
			return nil, fmt.Errorf("triple: parallax.NewDecryptWriter: %w", werr)
		}
		plainDst = w
		closeFn = w.Close
	}

	var cipherErr error
	src := bytes.NewReader(inner)
	if p.macFunc != nil {
		cipherErr = itb.DecryptStreamAuth3xCfg(
			p.cfg,
			p.seeds[0], p.seeds[1],
			p.seeds[2], p.seeds[3], p.seeds[4],
			p.seeds[5], p.seeds[6], p.seeds[7],
			src, plainDst, p.macFunc,
		)
	} else {
		cipherErr = itb.DecryptStream3xCfg(
			p.cfg,
			p.seeds[0], p.seeds[1],
			p.seeds[2], p.seeds[3], p.seeds[4],
			p.seeds[5], p.seeds[6], p.seeds[7],
			src, plainDst,
		)
	}
	if err := joinCloseError(cipherErr, closeFn()); err != nil {
		b := plain.Bytes()
		wipe.Bytes(b[:cap(b)])
		return nil, err
	}
	out := plain.Bytes()
	if cap(dst) >= len(out) && len(out) > 0 && &out[0] != &dst[:1][0] && !slicesOverlap(dst, inner) {
		res := dst[:len(out)]
		copy(res, out)
		wipe.Bytes(out[:cap(out)])
		return res, nil
	}
	return out, nil
}
