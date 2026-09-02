package triple

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/everanium/itb"
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
// direct whole-buffer fast path. Matches the itb-root single-message
// cipher cap so oversized payloads fall through to the streaming
// fallback (which chunks the plaintext at [Pipeline.resolved.chunkSize]
// granularity). Held as an explicit constant here rather than reading
// the itb-root cap so the message surface has a single, self-documenting
// gate for the fast path.
const messageFastPathMaxBytes = 64 << 20

// EncryptMessage encrypts a single message and returns its wire bytes.
//
// Two internal paths compose the same on-wire envelope:
//
//  1. Direct whole-buffer path — chosen when the parallax layer is
//     disengaged for this Pipeline. The plaintext feeds a single
//     itb-root Cfg-aware entry ([itb.Encrypt3x{128,256,512}Cfg] on the
//     No MAC arm, [itb.EncryptStreamAuthenticated3x{128,256,512}Cfg]
//     with cumulative offset 0 and finalFlag true on the MAC arm) so
//     the per-chunk io.Reader / io.Writer machinery of
//     [Pipeline.EncryptStream] is bypassed for the message surface.
//     The wrapper layer, when engaged, is composed as a
//     [wrapper.WrapInPlace] over the assembled inner blob.
//  2. Streaming-fallback path — chosen when the parallax layer is
//     engaged, when the plaintext exceeds [messageFastPathMaxBytes],
//     or when the resolved profile carries a mode the direct path does
//     not cover. Composes the same triple chain the
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
// Empty plaintext (nil or zero-length) is rejected with
// [ErrEmptyInput] before any wire is produced — no zero-payload wire
// exists on the Pipeline surface, so wire length never separates the
// MAC and No MAC arms on an empty message. Callers for whom an empty
// signal is meaningful send a marker byte instead.
//
// Returns [ErrClosed] when [Pipeline.Close] has already run;
// [ErrProfileNoCipher] when the resolved profile mode is blob-only;
// [ErrEmptyInput] on empty plaintext.
func (p *Pipeline) EncryptMessage(plaintext []byte) ([]byte, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	if hasNoCipherSurface(p.resolved.mode) {
		return nil, ErrProfileNoCipher
	}
	if len(plaintext) == 0 {
		return nil, ErrEmptyInput
	}
	if !p.resolved.parallaxOn && len(plaintext) <= messageFastPathMaxBytes {
		return p.encryptMessageDirect(plaintext)
	}
	return p.encryptMessageStreaming(plaintext)
}

// DecryptMessage is the receive-side counterpart of
// [Pipeline.EncryptMessage]. Two internal paths compose the same
// on-wire decoding contract:
//
//  1. Direct whole-buffer path — chosen when the parallax layer is
//     disengaged AND the wire parses as a single-chunk envelope
//     (streamID prefix followed by exactly one itb-root ciphertext
//     whose header-announced chunk length equals the remaining wire
//     length after any wrapper unwrap). Dispatches into
//     [itb.Decrypt3x{128,256,512}Cfg] on the No MAC arm or
//     [itb.DecryptStreamAuthenticated3x{128,256,512}Cfg] with
//     cumulative offset 0 on the MAC arm.
//  2. Streaming-fallback path — chosen when the parallax layer is
//     engaged or the wire carries a multi-chunk envelope (as produced
//     by [Pipeline.EncryptStream] on plaintext larger than the
//     resolved chunkSize). Feeds the wire bytes through a
//     [bytes.Reader] into the reverse triple chain.
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
// Empty wire (nil or zero-length) is rejected with [ErrEmptyInput]
// before any parse — symmetric with [Pipeline.EncryptMessage]'s
// empty-plaintext rejection, since no valid Pipeline wire is empty.
//
// Returns [ErrClosed] when [Pipeline.Close] has already run;
// [ErrProfileNoCipher] when the resolved profile mode is blob-only;
// [ErrEmptyInput] on empty wire.
func (p *Pipeline) DecryptMessage(wire []byte) ([]byte, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	if hasNoCipherSurface(p.resolved.mode) {
		return nil, ErrProfileNoCipher
	}
	if len(wire) == 0 {
		return nil, ErrEmptyInput
	}
	if !p.resolved.parallaxOn {
		plain, ok, err := p.decryptMessageDirect(wire)
		if ok {
			return plain, err
		}
	}
	return p.decryptMessageStreaming(wire)
}

// encryptMessageDirect implements the direct whole-buffer encrypt
// path. Precondition: parallax layer disengaged and len(plaintext)
// within [messageFastPathMaxBytes]. Produces the same wire envelope as
// the streaming fallback when the plaintext fits in a single chunk.
func (p *Pipeline) encryptMessageDirect(plaintext []byte) ([]byte, error) {
	// Empty plaintext on the No MAC arm carries no inner bytes: the
	// wire is the outer cipher envelope alone when the wrapper layer
	// is engaged (nonce-only — [wrapper.UnwrapInPlace] and
	// [wrapper.NewUnwrapReader] decode it back to an empty inner
	// stream), or empty when it is not (mirrors the underlying stream
	// helpers' empty-input contract).
	if len(plaintext) == 0 && p.macFunc == nil {
		if p.resolved.wrapperOn {
			nonce, err := wrapper.WrapInPlace(p.wrapperCipher, p.wrapperKey, nil)
			if err != nil {
				return nil, fmt.Errorf("triple: wrapper.WrapInPlace: %w", err)
			}
			return nonce, nil
		}
		return []byte{}, nil
	}

	var streamID [streamIDPrefixLen]byte
	if _, err := rand.Read(streamID[:]); err != nil {
		return nil, fmt.Errorf("triple: crypto/rand: %w", err)
	}

	var chunk []byte
	var err error
	if p.macFunc != nil {
		chunk, err = encryptSingleChunkAuth(p, plaintext, streamID)
	} else {
		chunk, err = encryptSingleChunkNoMAC(p, plaintext)
	}
	if err != nil {
		return nil, err
	}

	// Assemble inner = streamID || chunk. The buffer is sized to the
	// final wire so the wrapper wrap (when engaged) can operate in
	// place without a second allocation.
	wireLen := streamIDPrefixLen + len(chunk)
	if p.resolved.wrapperOn {
		nlen, err := wrapper.NonceSize(p.wrapperCipher)
		if err != nil {
			return nil, fmt.Errorf("triple: wrapper.NonceSize: %w", err)
		}
		out := make([]byte, nlen+wireLen)
		body := out[nlen:]
		copy(body, streamID[:])
		copy(body[streamIDPrefixLen:], chunk)
		nonce, werr := wrapper.WrapInPlace(p.wrapperCipher, p.wrapperKey, body)
		if werr != nil {
			return nil, fmt.Errorf("triple: wrapper.WrapInPlace: %w", werr)
		}
		copy(out[:nlen], nonce)
		return out, nil
	}
	out := make([]byte, wireLen)
	copy(out, streamID[:])
	copy(out[streamIDPrefixLen:], chunk)
	return out, nil
}

// decryptMessageDirect attempts the direct whole-buffer decrypt path.
// Returns (plaintext, true, err) when the wire has been fully claimed
// by this path (successfully decoded or terminally rejected). Returns
// (nil, false, nil) when the wire does not parse as a single-chunk
// envelope, signalling the caller to fall through to the streaming
// fallback. Precondition: parallax layer disengaged.
func (p *Pipeline) decryptMessageDirect(wire []byte) ([]byte, bool, error) {
	inner := wire
	if p.resolved.wrapperOn {
		// Empty wire under wrapper-on maps to empty plaintext on the
		// No MAC arm (mirrors the empty-input encrypt contract). The
		// MAC arm requires the streamID + final chunk envelope and
		// cannot decode an empty wire; delegating to the streaming
		// fallback surfaces the appropriate error there.
		if len(wire) == 0 {
			if p.macFunc == nil {
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
		buf := make([]byte, len(wire))
		copy(buf, wire)
		unwrapped, uerr := wrapper.UnwrapInPlace(p.wrapperCipher, p.wrapperKey, buf)
		if uerr != nil {
			return nil, false, nil
		}
		inner = unwrapped
	}

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

	// Try to parse a single chunk header at the body start. If the
	// header parses AND the announced chunk length equals the entire
	// remaining body, the wire carries exactly one chunk and the fast
	// path applies. Multi-chunk wires (produced by EncryptStream on
	// plaintext larger than chunkSize, or by legacy Message encrypts
	// pre-dating the direct path) fail this equality and route to the
	// streaming fallback.
	chunkLen, perr := itb.ParseChunkLenCfg(p.cfg, body)
	if perr != nil || chunkLen != len(body) {
		return nil, false, nil
	}

	if p.macFunc != nil {
		plain, finalFlag, derr := decryptSingleChunkAuth(p, body, streamID)
		if derr != nil {
			return nil, true, derr
		}
		// The streaming fallback surfaces [itb.ErrStreamTruncated]
		// when the final chunk's flag is not set; mirror that
		// diagnostic here so a non-terminating chunk fed to the
		// message surface is rejected with the same error the
		// streaming surface would have produced.
		if !finalFlag {
			return nil, true, itb.ErrStreamTruncated
		}
		return plain, true, nil
	}
	plain, derr := decryptSingleChunkNoMAC(p, body)
	return plain, true, derr
}

// encryptSingleChunkNoMAC width-dispatches to the No MAC single-chunk
// encrypt entry. Threads the Pipeline's per-instance Config so nonce
// width / barrier fill / max-workers overrides land on the underlying
// call site.
func encryptSingleChunkNoMAC(p *Pipeline, plaintext []byte) ([]byte, error) {
	switch p.width {
	case 128:
		return itb.Encrypt3x128Cfg(p.cfg,
			p.seeds[0].(*itb.Seed128), p.seeds[1].(*itb.Seed128),
			p.seeds[2].(*itb.Seed128), p.seeds[3].(*itb.Seed128), p.seeds[4].(*itb.Seed128),
			p.seeds[5].(*itb.Seed128), p.seeds[6].(*itb.Seed128), p.seeds[7].(*itb.Seed128),
			plaintext,
		)
	case 256:
		return itb.Encrypt3x256Cfg(p.cfg,
			p.seeds[0].(*itb.Seed256), p.seeds[1].(*itb.Seed256),
			p.seeds[2].(*itb.Seed256), p.seeds[3].(*itb.Seed256), p.seeds[4].(*itb.Seed256),
			p.seeds[5].(*itb.Seed256), p.seeds[6].(*itb.Seed256), p.seeds[7].(*itb.Seed256),
			plaintext,
		)
	case 512:
		return itb.Encrypt3x512Cfg(p.cfg,
			p.seeds[0].(*itb.Seed512), p.seeds[1].(*itb.Seed512),
			p.seeds[2].(*itb.Seed512), p.seeds[3].(*itb.Seed512), p.seeds[4].(*itb.Seed512),
			p.seeds[5].(*itb.Seed512), p.seeds[6].(*itb.Seed512), p.seeds[7].(*itb.Seed512),
			plaintext,
		)
	}
	return nil, fmt.Errorf("triple: unsupported inner width %d", p.width)
}

// encryptSingleChunkAuth width-dispatches to the Streaming AEAD
// single-chunk encrypt entry with cumulative offset 0 and finalFlag
// true, matching the per-chunk MAC binding that the streaming fallback
// emits when the plaintext fits in one chunk.
func encryptSingleChunkAuth(p *Pipeline, plaintext []byte, streamID [streamIDPrefixLen]byte) ([]byte, error) {
	switch p.width {
	case 128:
		return itb.EncryptStreamAuthenticated3x128Cfg(p.cfg,
			p.seeds[0].(*itb.Seed128), p.seeds[1].(*itb.Seed128),
			p.seeds[2].(*itb.Seed128), p.seeds[3].(*itb.Seed128), p.seeds[4].(*itb.Seed128),
			p.seeds[5].(*itb.Seed128), p.seeds[6].(*itb.Seed128), p.seeds[7].(*itb.Seed128),
			plaintext, p.macFunc, streamID, 0, true,
		)
	case 256:
		return itb.EncryptStreamAuthenticated3x256Cfg(p.cfg,
			p.seeds[0].(*itb.Seed256), p.seeds[1].(*itb.Seed256),
			p.seeds[2].(*itb.Seed256), p.seeds[3].(*itb.Seed256), p.seeds[4].(*itb.Seed256),
			p.seeds[5].(*itb.Seed256), p.seeds[6].(*itb.Seed256), p.seeds[7].(*itb.Seed256),
			plaintext, p.macFunc, streamID, 0, true,
		)
	case 512:
		return itb.EncryptStreamAuthenticated3x512Cfg(p.cfg,
			p.seeds[0].(*itb.Seed512), p.seeds[1].(*itb.Seed512),
			p.seeds[2].(*itb.Seed512), p.seeds[3].(*itb.Seed512), p.seeds[4].(*itb.Seed512),
			p.seeds[5].(*itb.Seed512), p.seeds[6].(*itb.Seed512), p.seeds[7].(*itb.Seed512),
			plaintext, p.macFunc, streamID, 0, true,
		)
	}
	return nil, fmt.Errorf("triple: unsupported inner width %d", p.width)
}

// decryptSingleChunkNoMAC width-dispatches to the No MAC single-chunk
// decrypt entry. Mirror image of [encryptSingleChunkNoMAC].
func decryptSingleChunkNoMAC(p *Pipeline, chunk []byte) ([]byte, error) {
	switch p.width {
	case 128:
		return itb.Decrypt3x128Cfg(p.cfg,
			p.seeds[0].(*itb.Seed128), p.seeds[1].(*itb.Seed128),
			p.seeds[2].(*itb.Seed128), p.seeds[3].(*itb.Seed128), p.seeds[4].(*itb.Seed128),
			p.seeds[5].(*itb.Seed128), p.seeds[6].(*itb.Seed128), p.seeds[7].(*itb.Seed128),
			chunk,
		)
	case 256:
		return itb.Decrypt3x256Cfg(p.cfg,
			p.seeds[0].(*itb.Seed256), p.seeds[1].(*itb.Seed256),
			p.seeds[2].(*itb.Seed256), p.seeds[3].(*itb.Seed256), p.seeds[4].(*itb.Seed256),
			p.seeds[5].(*itb.Seed256), p.seeds[6].(*itb.Seed256), p.seeds[7].(*itb.Seed256),
			chunk,
		)
	case 512:
		return itb.Decrypt3x512Cfg(p.cfg,
			p.seeds[0].(*itb.Seed512), p.seeds[1].(*itb.Seed512),
			p.seeds[2].(*itb.Seed512), p.seeds[3].(*itb.Seed512), p.seeds[4].(*itb.Seed512),
			p.seeds[5].(*itb.Seed512), p.seeds[6].(*itb.Seed512), p.seeds[7].(*itb.Seed512),
			chunk,
		)
	}
	return nil, fmt.Errorf("triple: unsupported inner width %d", p.width)
}

// decryptSingleChunkAuth width-dispatches to the Streaming AEAD
// single-chunk decrypt entry with cumulative offset 0, matching the
// per-chunk MAC binding produced by [encryptSingleChunkAuth].
func decryptSingleChunkAuth(p *Pipeline, chunk []byte, streamID [streamIDPrefixLen]byte) ([]byte, bool, error) {
	switch p.width {
	case 128:
		return itb.DecryptStreamAuthenticated3x128Cfg(p.cfg,
			p.seeds[0].(*itb.Seed128), p.seeds[1].(*itb.Seed128),
			p.seeds[2].(*itb.Seed128), p.seeds[3].(*itb.Seed128), p.seeds[4].(*itb.Seed128),
			p.seeds[5].(*itb.Seed128), p.seeds[6].(*itb.Seed128), p.seeds[7].(*itb.Seed128),
			chunk, p.macFunc, streamID, 0,
		)
	case 256:
		return itb.DecryptStreamAuthenticated3x256Cfg(p.cfg,
			p.seeds[0].(*itb.Seed256), p.seeds[1].(*itb.Seed256),
			p.seeds[2].(*itb.Seed256), p.seeds[3].(*itb.Seed256), p.seeds[4].(*itb.Seed256),
			p.seeds[5].(*itb.Seed256), p.seeds[6].(*itb.Seed256), p.seeds[7].(*itb.Seed256),
			chunk, p.macFunc, streamID, 0,
		)
	case 512:
		return itb.DecryptStreamAuthenticated3x512Cfg(p.cfg,
			p.seeds[0].(*itb.Seed512), p.seeds[1].(*itb.Seed512),
			p.seeds[2].(*itb.Seed512), p.seeds[3].(*itb.Seed512), p.seeds[4].(*itb.Seed512),
			p.seeds[5].(*itb.Seed512), p.seeds[6].(*itb.Seed512), p.seeds[7].(*itb.Seed512),
			chunk, p.macFunc, streamID, 0,
		)
	}
	return nil, false, fmt.Errorf("triple: unsupported inner width %d", p.width)
}

// encryptMessageStreaming is the fallback encrypt path. Chains the
// plaintext through the same io.Reader / io.Writer surface the
// [Pipeline.EncryptStream] method uses, chunking at
// [Pipeline.resolved.chunkSize] granularity. Covers the parallax-on
// case (where the parallax reader's per-chunk frame envelope must be
// preserved) and oversized plaintexts (larger than
// [messageFastPathMaxBytes]).
func (p *Pipeline) encryptMessageStreaming(plaintext []byte) ([]byte, error) {
	var wire bytes.Buffer
	wire.Grow(len(plaintext) + len(plaintext)/4 + 65536)
	innerSrc, innerDst, closeFn, err := buildEncryptChain(p, bytes.NewReader(plaintext), &wire)
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
			innerSrc, innerDst, p.macFunc, p.resolved.chunkSize,
		)
	} else {
		cipherErr = itb.EncryptStream3xCfg(
			p.cfg,
			p.seeds[0], p.seeds[1],
			p.seeds[2], p.seeds[3], p.seeds[4],
			p.seeds[5], p.seeds[6], p.seeds[7],
			innerSrc, innerDst, p.resolved.chunkSize,
		)
	}
	if err := joinCloseError(cipherErr, closeFn()); err != nil {
		return nil, err
	}
	// An inner stream that produced no bytes (empty plaintext on the
	// No MAC arm) leaves the wrapper writer's nonce pending; finalize
	// so the wire still carries the outer cipher envelope. No-op when
	// the wrapper layer is disengaged or any body byte has been
	// emitted.
	if err := wrapper.FinishWrapStream(innerDst); err != nil {
		return nil, err
	}
	return wire.Bytes(), nil
}

// decryptMessageStreaming is the fallback decrypt path. Mirror image
// of [encryptMessageStreaming] — feeds the wire through a
// [bytes.Reader] into the reverse triple chain. Covers parallax-on
// and multi-chunk wires.
func (p *Pipeline) decryptMessageStreaming(wire []byte) ([]byte, error) {
	var plain bytes.Buffer
	plain.Grow(len(wire))
	innerSrc, innerDst, closeFn, err := buildDecryptChain(p, bytes.NewReader(wire), &plain)
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
		return nil, err
	}
	return plain.Bytes(), nil
}

// hasNoCipherSurface reports whether the resolved profile mode
// exposes no cipher path at all. The blob-only profile is the sole
// trigger today; kept as a helper so [EncryptMessage] and
// [DecryptMessage] share one guard branch verbatim, parallel to
// [isStreamingMode]'s role for the streaming guard.
func hasNoCipherSurface(mode string) bool {
	return mode == modeBlobOnly
}

// streamIDPrefixLen is the on-wire byte length of the per-message
// streamID prefix emitted by the itb-root streaming encoders and
// consumed by their decoders. Held here as a local mirror of the
// itb-root constant so the triple message surface stays
// self-documenting without a cross-package import for a single byte
// count.
const streamIDPrefixLen = 32
