// streams.go — width-less io.Reader / io.Writer streaming helpers
// for plain and authenticated stream cipher modes. The width is
// determined by the supplied seed type via the same any-typed
// dispatch path used by the single-shot helpers in itb.go / auth.go.
//
// Each helper drains src to EOF, encrypts or decrypts chunk-by-chunk,
// and writes the resulting wire chunks (encrypt) or recovered
// plaintext (decrypt) to dst. The encrypt-side helpers consume a
// chunkSize parameter; the decrypt-side helpers recover chunk extents
// from the on-wire header per chunk.
//
// Behaviour parity with the binding-side stream helpers (e.g. the
// Rust binding's encrypt_stream / decrypt_stream / encrypt_stream_auth
// / decrypt_stream_auth functions in bindings/rust/src/streams.rs):
// streamID 32-byte CSPRNG prefix on the auth path, cumulative pixel
// offset bound into every per-chunk MAC input, finalFlag flipped on
// the terminating chunk, ErrStreamTruncated / ErrStreamAfterFinal
// surfaced verbatim from the underlying single-chunk path.

package itb

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

// readExact reads len(buf) bytes from src into buf. Treats EOF as a
// malformed-input signal when fewer than len(buf) bytes have been
// drawn (mid-chunk truncation). Returns nil error on the clean
// "no bytes drawn at start of chunk" case so the caller can detect
// stream end on a chunk boundary.
func readExact(src io.Reader, buf []byte) (int, error) {
	n, err := io.ReadFull(src, buf)
	if err == io.EOF && n == 0 {
		return 0, io.EOF
	}
	if err == io.ErrUnexpectedEOF {
		return n, fmt.Errorf("itb: unexpected EOF mid-chunk: read %d of %d bytes", n, len(buf))
	}
	return n, err
}

// readUpTo reads up to len(buf) bytes from src into buf, returning the
// number of bytes drawn and io.EOF when src has been fully drained.
// io.ErrUnexpectedEOF is treated as a clean partial-read indication
// at the tail (the encrypt-side loop accepts a smaller-than-chunkSize
// final chunk).
func readUpTo(src io.Reader, buf []byte) (int, error) {
	n, err := io.ReadFull(src, buf)
	if err == nil {
		return n, nil
	}
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		if n == 0 {
			return 0, io.EOF
		}
		return n, nil
	}
	return n, err
}

// readChunkParse drains a header window from src, parses W / H to
// compute the announced chunk length, and reads the remaining body
// to assemble a single complete wire chunk. Returns io.EOF on a
// clean end-of-stream when no header bytes are available.
func readChunkParse(src io.Reader) ([]byte, error) {
	hdrLen := headerSize()
	hdr := make([]byte, hdrLen)
	n, err := readExact(src, hdr)
	if err == io.EOF {
		return nil, io.EOF
	}
	if err != nil {
		return nil, err
	}
	if n != hdrLen {
		return nil, fmt.Errorf("itb: short header read: %d of %d bytes", n, hdrLen)
	}

	nonceLen := currentNonceSize()
	width := int(binary.BigEndian.Uint16(hdr[nonceLen:]))
	height := int(binary.BigEndian.Uint16(hdr[nonceLen+2:]))
	if width <= 0 || height <= 0 {
		return nil, fmt.Errorf("itb: invalid dimensions %dx%d", width, height)
	}
	if width > math.MaxInt/height {
		return nil, fmt.Errorf("itb: dimensions %dx%d overflow", width, height)
	}
	totalPixels := width * height
	if totalPixels > math.MaxInt/Channels {
		return nil, fmt.Errorf("itb: container too large: %d pixels", totalPixels)
	}
	if totalPixels > maxTotalPixels {
		return nil, fmt.Errorf("itb: chunk too large: %d pixels exceeds maximum %d", totalPixels, maxTotalPixels)
	}

	bodyLen := totalPixels * Channels
	full := make([]byte, hdrLen+bodyLen)
	copy(full, hdr)
	body := full[hdrLen:]
	nb, berr := readExact(src, body)
	if berr != nil && berr != io.EOF {
		return nil, berr
	}
	if nb != bodyLen {
		return nil, fmt.Errorf("itb: short body read: %d of %d bytes", nb, bodyLen)
	}
	// Re-validate the assembled chunk so any future ParseChunkLen
	// invariant is enforced consistently.
	if _, err := ParseChunkLen(full); err != nil {
		return nil, err
	}
	return full, nil
}

// validateChunkSize centralises the chunk-size precondition for the
// streaming-encrypt helpers. Returns errSeedWidthMix-shaped output is
// out of scope; this guard surfaces the same fmt.Errorf shape as the
// existing stream.go / stream_auth.go paths.
func validateChunkSize(chunkSize int) (int, error) {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	if chunkSize > maxDataSize {
		return 0, fmt.Errorf("itb: chunk size %d exceeds maximum %d bytes", chunkSize, maxDataSize)
	}
	return chunkSize, nil
}

// EncryptStream is the width-less plain-stream Encrypt entry point.
// Reads from src in up-to-chunkSize-byte windows, encrypts each
// non-empty window via the matching width-suffixed single-shot path,
// and writes the resulting wire chunk to dst. Empty src input emits
// nothing (the single-shot path rejects empty plaintext; the
// streaming helper preserves that semantic by simply not emitting any
// chunk).
//
// Dispatches by concrete pointer type of the supplied seeds; mixing
// widths returns an error matching [Encrypt] / [Decrypt].
func EncryptStream(noiseSeed, dataSeed, startSeed any, src io.Reader, dst io.Writer, chunkSize int) error {
	if _, err := dispatchWidthSingle(noiseSeed, dataSeed, startSeed); err != nil {
		return err
	}
	cs, err := validateChunkSize(chunkSize)
	if err != nil {
		return err
	}
	buf := make([]byte, cs)
	for {
		n, err := readUpTo(src, buf)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		ct, encErr := Encrypt(noiseSeed, dataSeed, startSeed, buf[:n])
		if encErr != nil {
			return encErr
		}
		if _, werr := dst.Write(ct); werr != nil {
			return werr
		}
	}
}

// DecryptStream is the width-less plain-stream Decrypt entry point.
// Walks src one chunk at a time using the on-wire header to recover
// each chunk's extent, decrypts the chunk via the matching
// width-suffixed single-shot path, and writes the recovered plaintext
// to dst.
func DecryptStream(noiseSeed, dataSeed, startSeed any, src io.Reader, dst io.Writer) error {
	if _, err := dispatchWidthSingle(noiseSeed, dataSeed, startSeed); err != nil {
		return err
	}
	for {
		chunk, err := readChunkParse(src)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		pt, decErr := Decrypt(noiseSeed, dataSeed, startSeed, chunk)
		if decErr != nil {
			return decErr
		}
		if _, werr := dst.Write(pt); werr != nil {
			return werr
		}
	}
}

// EncryptStream3x is the width-less Triple-Ouroboros plain-stream
// Encrypt entry point. Behaviour parity with [EncryptStream] modulo
// the 7-seed dispatch path.
func EncryptStream3x(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 any, src io.Reader, dst io.Writer, chunkSize int) error {
	if _, err := dispatchWidthTriple(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return err
	}
	cs, err := validateChunkSize(chunkSize)
	if err != nil {
		return err
	}
	buf := make([]byte, cs)
	for {
		n, err := readUpTo(src, buf)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		ct, encErr := Encrypt3x(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, buf[:n])
		if encErr != nil {
			return encErr
		}
		if _, werr := dst.Write(ct); werr != nil {
			return werr
		}
	}
}

// DecryptStream3x is the width-less Triple-Ouroboros plain-stream
// Decrypt entry point.
func DecryptStream3x(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 any, src io.Reader, dst io.Writer) error {
	if _, err := dispatchWidthTriple(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return err
	}
	for {
		chunk, err := readChunkParse(src)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		pt, decErr := Decrypt3x(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, chunk)
		if decErr != nil {
			return decErr
		}
		if _, werr := dst.Write(pt); werr != nil {
			return werr
		}
	}
}

// streamAuthEncryptSingle is the per-chunk dispatch helper for the
// single-Ouroboros Streaming AEAD encrypt path. Resolved width is
// passed in by the caller after dispatchWidthSingle has approved the
// seed bundle.
func streamAuthEncryptSingle(width int, noiseSeed, dataSeed, startSeed any, plaintext []byte, mac MACFunc, streamID [streamIDPrefixLen]byte, cumulative uint64, finalFlag bool) ([]byte, error) {
	switch width {
	case 128:
		return EncryptStreamAuthenticated128(noiseSeed.(*Seed128), dataSeed.(*Seed128), startSeed.(*Seed128), plaintext, mac, streamID, cumulative, finalFlag)
	case 256:
		return EncryptStreamAuthenticated256(noiseSeed.(*Seed256), dataSeed.(*Seed256), startSeed.(*Seed256), plaintext, mac, streamID, cumulative, finalFlag)
	case 512:
		return EncryptStreamAuthenticated512(noiseSeed.(*Seed512), dataSeed.(*Seed512), startSeed.(*Seed512), plaintext, mac, streamID, cumulative, finalFlag)
	}
	return nil, errSeedWidthMix
}

// streamAuthDecryptSingle is the per-chunk dispatch helper for the
// single-Ouroboros Streaming AEAD decrypt path.
func streamAuthDecryptSingle(width int, noiseSeed, dataSeed, startSeed any, chunk []byte, mac MACFunc, streamID [streamIDPrefixLen]byte, cumulative uint64) ([]byte, bool, error) {
	switch width {
	case 128:
		return DecryptStreamAuthenticated128(noiseSeed.(*Seed128), dataSeed.(*Seed128), startSeed.(*Seed128), chunk, mac, streamID, cumulative)
	case 256:
		return DecryptStreamAuthenticated256(noiseSeed.(*Seed256), dataSeed.(*Seed256), startSeed.(*Seed256), chunk, mac, streamID, cumulative)
	case 512:
		return DecryptStreamAuthenticated512(noiseSeed.(*Seed512), dataSeed.(*Seed512), startSeed.(*Seed512), chunk, mac, streamID, cumulative)
	}
	return nil, false, errSeedWidthMix
}

// streamAuthEncryptTriple is the per-chunk dispatch helper for the
// Triple-Ouroboros Streaming AEAD encrypt path.
func streamAuthEncryptTriple(width int, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 any, plaintext []byte, mac MACFunc, streamID [streamIDPrefixLen]byte, cumulative uint64, finalFlag bool) ([]byte, error) {
	switch width {
	case 128:
		return EncryptStreamAuthenticated3x128(noiseSeed.(*Seed128), dataSeed1.(*Seed128), dataSeed2.(*Seed128), dataSeed3.(*Seed128), startSeed1.(*Seed128), startSeed2.(*Seed128), startSeed3.(*Seed128), plaintext, mac, streamID, cumulative, finalFlag)
	case 256:
		return EncryptStreamAuthenticated3x256(noiseSeed.(*Seed256), dataSeed1.(*Seed256), dataSeed2.(*Seed256), dataSeed3.(*Seed256), startSeed1.(*Seed256), startSeed2.(*Seed256), startSeed3.(*Seed256), plaintext, mac, streamID, cumulative, finalFlag)
	case 512:
		return EncryptStreamAuthenticated3x512(noiseSeed.(*Seed512), dataSeed1.(*Seed512), dataSeed2.(*Seed512), dataSeed3.(*Seed512), startSeed1.(*Seed512), startSeed2.(*Seed512), startSeed3.(*Seed512), plaintext, mac, streamID, cumulative, finalFlag)
	}
	return nil, errSeedWidthMix
}

// streamAuthDecryptTriple is the per-chunk dispatch helper for the
// Triple-Ouroboros Streaming AEAD decrypt path.
func streamAuthDecryptTriple(width int, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 any, chunk []byte, mac MACFunc, streamID [streamIDPrefixLen]byte, cumulative uint64) ([]byte, bool, error) {
	switch width {
	case 128:
		return DecryptStreamAuthenticated3x128(noiseSeed.(*Seed128), dataSeed1.(*Seed128), dataSeed2.(*Seed128), dataSeed3.(*Seed128), startSeed1.(*Seed128), startSeed2.(*Seed128), startSeed3.(*Seed128), chunk, mac, streamID, cumulative)
	case 256:
		return DecryptStreamAuthenticated3x256(noiseSeed.(*Seed256), dataSeed1.(*Seed256), dataSeed2.(*Seed256), dataSeed3.(*Seed256), startSeed1.(*Seed256), startSeed2.(*Seed256), startSeed3.(*Seed256), chunk, mac, streamID, cumulative)
	case 512:
		return DecryptStreamAuthenticated3x512(noiseSeed.(*Seed512), dataSeed1.(*Seed512), dataSeed2.(*Seed512), dataSeed3.(*Seed512), startSeed1.(*Seed512), startSeed2.(*Seed512), startSeed3.(*Seed512), chunk, mac, streamID, cumulative)
	}
	return nil, false, errSeedWidthMix
}

// EncryptStreamAuth is the width-less single-Ouroboros Streaming AEAD
// Encrypt entry point. Generates a fresh 32-byte CSPRNG streamID,
// writes it as the wire prefix, then drains src in chunkSize windows
// and emits each encrypted chunk through the matching single-shot
// per-chunk implementation. The terminating chunk carries
// finalFlag = true; an empty src draws and emits the streamID prefix
// followed by a single zero-length terminating chunk.
//
// Mirrors the binding-side encrypt_stream_auth helpers in shape and
// in error semantics — chunk-by-chunk dispatch through the
// EncryptStreamAuthenticated* / DecryptStreamAuthenticated* family
// rather than per-chunk EncryptAuth.
func EncryptStreamAuth(noiseSeed, dataSeed, startSeed any, src io.Reader, dst io.Writer, mac MACFunc, chunkSize int) error {
	width, err := dispatchWidthSingle(noiseSeed, dataSeed, startSeed)
	if err != nil {
		return err
	}
	if mac == nil {
		return fmt.Errorf("itb: macFunc must not be nil")
	}
	cs, err := validateChunkSize(chunkSize)
	if err != nil {
		return err
	}

	var streamID [streamIDPrefixLen]byte
	if _, err := rand.Read(streamID[:]); err != nil {
		return fmt.Errorf("itb: crypto/rand: %w", err)
	}
	if _, werr := dst.Write(streamID[:]); werr != nil {
		return werr
	}

	stage := make([]byte, cs)
	var pending []byte // held chunk awaiting emission with finalFlag set on EOF
	var cumulative uint64

	for {
		n, rerr := readUpTo(src, stage)
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
		if pending != nil {
			chunk, encErr := streamAuthEncryptSingle(width, noiseSeed, dataSeed, startSeed, pending, mac, streamID, cumulative, false)
			if encErr != nil {
				return encErr
			}
			pixels, pxErr := chunkPixelCount(chunk)
			if pxErr != nil {
				return pxErr
			}
			if _, werr := dst.Write(chunk); werr != nil {
				return werr
			}
			cumulative += pixels
		}
		// Hold the freshly-read content for the next iteration so
		// finalFlag can be flipped on EOF without an extra zero-byte
		// probing read.
		held := make([]byte, n)
		copy(held, stage[:n])
		pending = held
	}

	if pending == nil {
		// Empty input: emit a single zero-length terminating chunk.
		chunk, encErr := streamAuthEncryptSingle(width, noiseSeed, dataSeed, startSeed, nil, mac, streamID, 0, true)
		if encErr != nil {
			return encErr
		}
		if _, werr := dst.Write(chunk); werr != nil {
			return werr
		}
		return nil
	}
	chunk, encErr := streamAuthEncryptSingle(width, noiseSeed, dataSeed, startSeed, pending, mac, streamID, cumulative, true)
	if encErr != nil {
		return encErr
	}
	if _, werr := dst.Write(chunk); werr != nil {
		return werr
	}
	return nil
}

// DecryptStreamAuth is the width-less single-Ouroboros Streaming AEAD
// Decrypt entry point. Reads the 32-byte streamID prefix, walks the
// remaining bytes one chunk at a time, dispatches each chunk through
// the matching single-shot DecryptStreamAuthenticated* path with the
// running cumulative pixel offset, and writes recovered plaintext to
// dst. Returns [ErrStreamTruncated] when the transcript exhausts
// without a terminating chunk and [ErrStreamAfterFinal] when chunks
// follow a terminator-flagged chunk.
func DecryptStreamAuth(noiseSeed, dataSeed, startSeed any, src io.Reader, dst io.Writer, mac MACFunc) error {
	width, err := dispatchWidthSingle(noiseSeed, dataSeed, startSeed)
	if err != nil {
		return err
	}
	if mac == nil {
		return fmt.Errorf("itb: macFunc must not be nil")
	}

	var streamID [streamIDPrefixLen]byte
	n, perr := io.ReadFull(src, streamID[:])
	if perr == io.EOF || perr == io.ErrUnexpectedEOF || n != streamIDPrefixLen {
		// Distinguish a stream cut before the 32-byte prefix lands
		// from a generic mid-chunk EOF wrapped further down by
		// readExact. The Rust / C / D bindings emit a specific
		// "stream prefix incomplete" / "EOF before 32-byte stream_id
		// prefix" diagnostic on this path; this Go-core path follows
		// the same shape.
		return fmt.Errorf("itb: stream too short for stream prefix")
	}
	if perr != nil {
		return perr
	}

	var cumulative uint64
	seenFinal := false
	for {
		chunk, cerr := readChunkParse(src)
		if cerr == io.EOF {
			break
		}
		if cerr != nil {
			return cerr
		}
		if seenFinal {
			return ErrStreamAfterFinal
		}
		plain, finalFlag, decErr := streamAuthDecryptSingle(width, noiseSeed, dataSeed, startSeed, chunk, mac, streamID, cumulative)
		if decErr != nil {
			return decErr
		}
		pixels, pixErr := chunkPixelCount(chunk)
		if pixErr != nil {
			return pixErr
		}
		if _, werr := dst.Write(plain); werr != nil {
			return werr
		}
		cumulative += pixels
		if finalFlag {
			seenFinal = true
		}
	}
	if !seenFinal {
		return ErrStreamTruncated
	}
	return nil
}

// EncryptStreamAuth3x is the width-less Triple-Ouroboros Streaming AEAD
// Encrypt entry point. Behaviour parity with [EncryptStreamAuth] modulo
// the 7-seed per-chunk dispatch path.
func EncryptStreamAuth3x(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 any, src io.Reader, dst io.Writer, mac MACFunc, chunkSize int) error {
	width, err := dispatchWidthTriple(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3)
	if err != nil {
		return err
	}
	if mac == nil {
		return fmt.Errorf("itb: macFunc must not be nil")
	}
	cs, err := validateChunkSize(chunkSize)
	if err != nil {
		return err
	}

	var streamID [streamIDPrefixLen]byte
	if _, err := rand.Read(streamID[:]); err != nil {
		return fmt.Errorf("itb: crypto/rand: %w", err)
	}
	if _, werr := dst.Write(streamID[:]); werr != nil {
		return werr
	}

	stage := make([]byte, cs)
	var pending []byte
	var cumulative uint64

	for {
		n, rerr := readUpTo(src, stage)
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
		if pending != nil {
			chunk, encErr := streamAuthEncryptTriple(width, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, pending, mac, streamID, cumulative, false)
			if encErr != nil {
				return encErr
			}
			pixels, pxErr := chunkPixelCount(chunk)
			if pxErr != nil {
				return pxErr
			}
			if _, werr := dst.Write(chunk); werr != nil {
				return werr
			}
			cumulative += pixels
		}
		held := make([]byte, n)
		copy(held, stage[:n])
		pending = held
	}

	if pending == nil {
		chunk, encErr := streamAuthEncryptTriple(width, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, nil, mac, streamID, 0, true)
		if encErr != nil {
			return encErr
		}
		if _, werr := dst.Write(chunk); werr != nil {
			return werr
		}
		return nil
	}
	chunk, encErr := streamAuthEncryptTriple(width, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, pending, mac, streamID, cumulative, true)
	if encErr != nil {
		return encErr
	}
	if _, werr := dst.Write(chunk); werr != nil {
		return werr
	}
	return nil
}

// DecryptStreamAuth3x is the width-less Triple-Ouroboros
// Streaming AEAD Decrypt entry point.
func DecryptStreamAuth3x(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 any, src io.Reader, dst io.Writer, mac MACFunc) error {
	width, err := dispatchWidthTriple(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3)
	if err != nil {
		return err
	}
	if mac == nil {
		return fmt.Errorf("itb: macFunc must not be nil")
	}

	var streamID [streamIDPrefixLen]byte
	n, perr := io.ReadFull(src, streamID[:])
	if perr == io.EOF || perr == io.ErrUnexpectedEOF || n != streamIDPrefixLen {
		return fmt.Errorf("itb: stream too short for stream prefix")
	}
	if perr != nil {
		return perr
	}

	var cumulative uint64
	seenFinal := false
	for {
		chunk, cerr := readChunkParse(src)
		if cerr == io.EOF {
			break
		}
		if cerr != nil {
			return cerr
		}
		if seenFinal {
			return ErrStreamAfterFinal
		}
		plain, finalFlag, decErr := streamAuthDecryptTriple(width, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, chunk, mac, streamID, cumulative)
		if decErr != nil {
			return decErr
		}
		pixels, pixErr := chunkPixelCount(chunk)
		if pixErr != nil {
			return pixErr
		}
		if _, werr := dst.Write(plain); werr != nil {
			return werr
		}
		cumulative += pixels
		if finalFlag {
			seenFinal = true
		}
	}
	if !seenFinal {
		return ErrStreamTruncated
	}
	return nil
}
