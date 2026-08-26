package triple

import (
	"bytes"
	"fmt"

	"github.com/everanium/itb"
	"github.com/everanium/itb/wrapper"
)

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
//  1. Direct whole-buffer path — when the parallax layer is disengaged
//     and the plaintext is at or below [messageFastPathMaxBytes], the
//     call composes the same single-chunk emission as
//     [Pipeline.EncryptMessage]'s direct path (one itb-root Cfg-aware
//     entry, wrapper composed via [wrapper.WrapInPlace] when engaged).
//     A single-chunk wire is a valid Streaming wire: the streaming
//     decoder accepts one final-flag chunk of any length within the
//     itb-root single-message cap, independent of the resolved
//     chunkSize.
//  2. Tail-wrap path — when the parallax layer is disengaged, the
//     wrapper layer is engaged, and the plaintext exceeds
//     [messageFastPathMaxBytes], the inner multi-chunk stream is
//     encoded directly into one buffer with the wrapper nonce slot
//     reserved up front, then sealed via [wrapper.WrapInPlace] over the
//     assembled inner bytes. The wire is identical in structure to the
//     [wrapper.NewWrapWriter] emission (nonce || keystream-XOR(inner)
//     under one logical keystream); the in-place variant XORs the whole
//     body in one parallel pass instead of per-Write keystream reseats.
//  3. Streaming fallback — every other posture (parallax engaged, or
//     oversized plaintext with the wrapper disengaged) drives the same
//     chain [Pipeline.EncryptStream] composes, with the plaintext read
//     from a [bytes.Reader] into a [bytes.Buffer] wire sink.
//
// Same concurrency posture as [Pipeline.EncryptStream]: safe for
// concurrent invocation on one [*Pipeline]. Returns [ErrClosed] when
// [Pipeline.Close] has already run; [ErrProfileNotStreaming] when the
// resolved profile mode is Single Message or blob-only.
func (p *Pipeline) EncryptStreamBytes(plaintext []byte) ([]byte, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	if !isStreamingMode(p.resolved.mode) {
		return nil, ErrProfileNotStreaming
	}
	if p.resolved.parallaxOn {
		return p.encryptMessageStreaming(plaintext)
	}
	if len(plaintext) <= messageFastPathMaxBytes {
		return p.encryptMessageDirect(plaintext)
	}
	if p.resolved.wrapperOn {
		return p.encryptStreamBytesTailWrap(plaintext)
	}
	return p.encryptMessageStreaming(plaintext)
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
//  1. Parallax engaged — streaming fallback through the same reverse
//     chain [Pipeline.DecryptStream] composes.
//  2. Wrapper engaged (parallax off) — the wire is copied once and
//     unwrapped via [wrapper.UnwrapInPlace] (one parallel keystream
//     pass), then the inner bytes take the single-chunk direct decode
//     when they parse as one chunk, or the streaming decode otherwise —
//     without a second unwrap in either arm. Wires that fail the
//     structural pre-checks (shorter than the wrapper nonce, or failing
//     the unwrap itself) route through the streaming fallback so its
//     canonical diagnostics surface.
//  3. Both layers off — single-chunk wires take the direct decode;
//     multi-chunk wires take the streaming fallback.
//
// Same concurrency posture as [Pipeline.DecryptStream]: safe for
// concurrent invocation on one [*Pipeline]. Returns [ErrClosed] when
// [Pipeline.Close] has already run; [ErrProfileNotStreaming] when the
// resolved profile mode is Single Message or blob-only.
func (p *Pipeline) DecryptStreamBytes(wire []byte) ([]byte, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	if !isStreamingMode(p.resolved.mode) {
		return nil, ErrProfileNotStreaming
	}
	if p.resolved.parallaxOn {
		return p.decryptMessageStreaming(wire)
	}
	if p.resolved.wrapperOn {
		return p.decryptStreamBytesTailUnwrap(wire)
	}
	plain, ok, err := p.decryptInnerSingleChunk(wire)
	if ok {
		return plain, err
	}
	return p.decryptMessageStreaming(wire)
}

// encryptStreamBytesTailWrap implements the tail-wrap encrypt path.
// Precondition: parallax off, wrapper on, plaintext larger than
// [messageFastPathMaxBytes]. The inner multi-chunk stream is encoded
// into a buffer whose leading bytes reserve the wrapper nonce slot;
// [wrapper.WrapInPlace] then seals the assembled inner bytes in one
// pass and the returned nonce fills the reserved slot.
func (p *Pipeline) encryptStreamBytesTailWrap(plaintext []byte) ([]byte, error) {
	nlen, err := wrapper.NonceSize(p.wrapperCipher)
	if err != nil {
		return nil, fmt.Errorf("triple: wrapper.NonceSize: %w", err)
	}

	var wire bytes.Buffer
	wire.Grow(nlen + len(plaintext) + len(plaintext)/4 + 65536)
	wire.Write(make([]byte, nlen))

	var cipherErr error
	src := bytes.NewReader(plaintext)
	if p.macFunc != nil {
		cipherErr = itb.EncryptStreamAuth3xCfg(
			p.cfg,
			p.seeds[0], p.seeds[1],
			p.seeds[2], p.seeds[3], p.seeds[4],
			p.seeds[5], p.seeds[6], p.seeds[7],
			src, &wire, p.macFunc, p.resolved.chunkSize,
		)
	} else {
		cipherErr = itb.EncryptStream3xCfg(
			p.cfg,
			p.seeds[0], p.seeds[1],
			p.seeds[2], p.seeds[3], p.seeds[4],
			p.seeds[5], p.seeds[6], p.seeds[7],
			src, &wire, p.resolved.chunkSize,
		)
	}
	if cipherErr != nil {
		return nil, cipherErr
	}

	out := wire.Bytes()
	nonce, werr := wrapper.WrapInPlace(p.wrapperCipher, p.wrapperKey, out[nlen:])
	if werr != nil {
		return nil, fmt.Errorf("triple: wrapper.WrapInPlace: %w", werr)
	}
	copy(out[:nlen], nonce)
	return out, nil
}

// decryptStreamBytesTailUnwrap implements the tail-unwrap decrypt
// path. Precondition: parallax off, wrapper on. The wire is copied
// once (the caller's slice must stay intact) and unwrapped via
// [wrapper.UnwrapInPlace]; the inner bytes then take the single-chunk
// direct decode or the streaming decode, each without a second unwrap.
// Structurally short or unwrap-rejected wires route through the
// streaming fallback so its canonical diagnostics surface.
func (p *Pipeline) decryptStreamBytesTailUnwrap(wire []byte) ([]byte, error) {
	nlen, err := wrapper.NonceSize(p.wrapperCipher)
	if err != nil || len(wire) < nlen {
		return p.decryptMessageStreaming(wire)
	}

	buf := make([]byte, len(wire))
	copy(buf, wire)
	inner, uerr := wrapper.UnwrapInPlace(p.wrapperCipher, p.wrapperKey, buf)
	if uerr != nil {
		return p.decryptMessageStreaming(wire)
	}

	plain, ok, derr := p.decryptInnerSingleChunk(inner)
	if ok {
		return plain, derr
	}
	return p.decryptInnerStreaming(inner)
}

// decryptInnerSingleChunk attempts the single-chunk direct decode on
// an inner byte sequence that has already passed any wrapper unwrap.
// Returns (plaintext, true, err) when the inner has been fully claimed
// by this path (successfully decoded or terminally rejected); returns
// (nil, false, nil) when the inner does not parse as a single-chunk
// envelope, signalling the caller to fall through to a streaming
// decode. Precondition: parallax layer disengaged, wrapper layer
// already stripped (or disengaged).
func (p *Pipeline) decryptInnerSingleChunk(inner []byte) ([]byte, bool, error) {
	if len(inner) == 0 {
		if p.macFunc == nil {
			return []byte{}, true, nil
		}
		return nil, false, nil
	}
	if len(inner) < streamIDPrefixLen {
		return nil, false, nil
	}

	var streamID [streamIDPrefixLen]byte
	copy(streamID[:], inner[:streamIDPrefixLen])
	body := inner[streamIDPrefixLen:]

	chunkLen, perr := itb.ParseChunkLenCfg(p.cfg, body)
	if perr != nil || chunkLen != len(body) {
		return nil, false, nil
	}

	if p.macFunc != nil {
		plain, finalFlag, derr := decryptSingleChunkAuth(p, body, streamID)
		if derr != nil {
			return nil, true, derr
		}
		// The streaming decode surfaces [itb.ErrStreamTruncated] when
		// the final chunk's flag is not set; mirror that diagnostic so
		// a non-terminating chunk fed to this surface is rejected with
		// the same error the streaming surface would have produced.
		if !finalFlag {
			return nil, true, itb.ErrStreamTruncated
		}
		return plain, true, nil
	}
	plain, derr := decryptSingleChunkNoMAC(p, body)
	return plain, true, derr
}

// decryptInnerStreaming stream-decodes an inner multi-chunk byte
// sequence that has already passed any wrapper unwrap. Precondition:
// parallax layer disengaged, wrapper layer already stripped (or
// disengaged) — the itb-root IO entry consumes the inner bytes
// directly, with no chain layers composed on either side.
func (p *Pipeline) decryptInnerStreaming(inner []byte) ([]byte, error) {
	var plain bytes.Buffer
	plain.Grow(len(inner))

	var cipherErr error
	src := bytes.NewReader(inner)
	if p.macFunc != nil {
		cipherErr = itb.DecryptStreamAuth3xCfg(
			p.cfg,
			p.seeds[0], p.seeds[1],
			p.seeds[2], p.seeds[3], p.seeds[4],
			p.seeds[5], p.seeds[6], p.seeds[7],
			src, &plain, p.macFunc,
		)
	} else {
		cipherErr = itb.DecryptStream3xCfg(
			p.cfg,
			p.seeds[0], p.seeds[1],
			p.seeds[2], p.seeds[3], p.seeds[4],
			p.seeds[5], p.seeds[6], p.seeds[7],
			src, &plain,
		)
	}
	if cipherErr != nil {
		return nil, cipherErr
	}
	return plain.Bytes(), nil
}
