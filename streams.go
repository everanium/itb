// streams.go — width-less io.Reader / io.Writer streaming helpers
// for plain and authenticated stream cipher modes. The width is
// determined by the supplied seed type via the same any-typed
// dispatch path used by the Single Message helpers.
//
// Each helper drains src to EOF, encrypts or decrypts chunk-by-chunk,
// and writes the resulting wire chunks (encrypt) or recovered
// plaintext (decrypt) to dst. The encrypt-side helpers consume a
// chunkSize parameter; the decrypt-side helpers recover chunk extents
// from the on-wire header per chunk.
//
// Behaviour parity with the binding-side stream helpers: streamID
// 32-byte CSPRNG prefix on the auth path, cumulative pixel offset
// bound into every per-chunk MAC input, finalFlag flipped on the
// terminating chunk, ErrStreamTruncated / ErrStreamAfterFinal surfaced
// verbatim from the underlying single-chunk path.

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

// validateChunkSize centralises the chunk-size precondition for the
// streaming-encrypt helpers.
func validateChunkSize(chunkSize int) (int, error) {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	if chunkSize > maxDataSize {
		return 0, fmt.Errorf("itb: chunk size %d exceeds maximum %d bytes", chunkSize, maxDataSize)
	}
	return chunkSize, nil
}

// readChunkParseCfg drains a header window from src, parses W / H to
// compute the announced chunk length, and reads the remaining body
// to assemble a single complete wire chunk. Consults cfg for the
// per-encryptor nonce-bits override so a non-nil cfg with an explicit
// NonceBits is honoured. Returns io.EOF on a clean end-of-stream when
// no header bytes are available.
func readChunkParseCfg(cfg *Config, src io.Reader) ([]byte, error) {
	hdrLen := headerSizeCfg(cfg)
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

	nonceLen := currentNonceSizeCfg(cfg)
	width := int(binary.BigEndian.Uint16(hdr[2*nonceLen:]))
	height := int(binary.BigEndian.Uint16(hdr[2*nonceLen+2:]))
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
	if _, err := ParseChunkLenCfg(cfg, full); err != nil {
		return nil, err
	}
	return full, nil
}

// singleMessageEncryptTripleCfg is the per-chunk dispatch helper for
// the width-less No MAC Triple Ouroboros Encrypt path when a Config
// override is threaded per Pipeline.
func singleMessageEncryptTripleCfg(cfg *Config, width int, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 any, data []byte) ([]byte, error) {
	switch width {
	case 128:
		return Encrypt3x128Cfg(cfg, noiseSeed.(*Seed128), lockSeed.(*Seed128), dataSeed1.(*Seed128), dataSeed2.(*Seed128), dataSeed3.(*Seed128), startSeed1.(*Seed128), startSeed2.(*Seed128), startSeed3.(*Seed128), data)
	case 256:
		return Encrypt3x256Cfg(cfg, noiseSeed.(*Seed256), lockSeed.(*Seed256), dataSeed1.(*Seed256), dataSeed2.(*Seed256), dataSeed3.(*Seed256), startSeed1.(*Seed256), startSeed2.(*Seed256), startSeed3.(*Seed256), data)
	case 512:
		return Encrypt3x512Cfg(cfg, noiseSeed.(*Seed512), lockSeed.(*Seed512), dataSeed1.(*Seed512), dataSeed2.(*Seed512), dataSeed3.(*Seed512), startSeed1.(*Seed512), startSeed2.(*Seed512), startSeed3.(*Seed512), data)
	}
	return nil, errSeedWidthMix
}

// singleMessageDecryptTripleCfg is the per-chunk dispatch helper for
// the width-less No MAC Triple Ouroboros Decrypt path when a Config
// override is threaded per Pipeline.
func singleMessageDecryptTripleCfg(cfg *Config, width int, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 any, chunk []byte) ([]byte, error) {
	switch width {
	case 128:
		return Decrypt3x128Cfg(cfg, noiseSeed.(*Seed128), lockSeed.(*Seed128), dataSeed1.(*Seed128), dataSeed2.(*Seed128), dataSeed3.(*Seed128), startSeed1.(*Seed128), startSeed2.(*Seed128), startSeed3.(*Seed128), chunk)
	case 256:
		return Decrypt3x256Cfg(cfg, noiseSeed.(*Seed256), lockSeed.(*Seed256), dataSeed1.(*Seed256), dataSeed2.(*Seed256), dataSeed3.(*Seed256), startSeed1.(*Seed256), startSeed2.(*Seed256), startSeed3.(*Seed256), chunk)
	case 512:
		return Decrypt3x512Cfg(cfg, noiseSeed.(*Seed512), lockSeed.(*Seed512), dataSeed1.(*Seed512), dataSeed2.(*Seed512), dataSeed3.(*Seed512), startSeed1.(*Seed512), startSeed2.(*Seed512), startSeed3.(*Seed512), chunk)
	}
	return nil, errSeedWidthMix
}

// streamAuthEncryptTripleCfg is the per-chunk dispatch helper for the
// Triple Ouroboros Streaming AEAD encrypt path when a Config override
// is threaded per Pipeline.
func streamAuthEncryptTripleCfg(cfg *Config, width int, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 any, plaintext []byte, mac MACFunc, streamID [streamIDPrefixLen]byte, cumulative uint64, finalFlag bool) ([]byte, error) {
	switch width {
	case 128:
		return EncryptStreamAuthenticated3x128Cfg(cfg, noiseSeed.(*Seed128), lockSeed.(*Seed128), dataSeed1.(*Seed128), dataSeed2.(*Seed128), dataSeed3.(*Seed128), startSeed1.(*Seed128), startSeed2.(*Seed128), startSeed3.(*Seed128), plaintext, mac, streamID, cumulative, finalFlag)
	case 256:
		return EncryptStreamAuthenticated3x256Cfg(cfg, noiseSeed.(*Seed256), lockSeed.(*Seed256), dataSeed1.(*Seed256), dataSeed2.(*Seed256), dataSeed3.(*Seed256), startSeed1.(*Seed256), startSeed2.(*Seed256), startSeed3.(*Seed256), plaintext, mac, streamID, cumulative, finalFlag)
	case 512:
		return EncryptStreamAuthenticated3x512Cfg(cfg, noiseSeed.(*Seed512), lockSeed.(*Seed512), dataSeed1.(*Seed512), dataSeed2.(*Seed512), dataSeed3.(*Seed512), startSeed1.(*Seed512), startSeed2.(*Seed512), startSeed3.(*Seed512), plaintext, mac, streamID, cumulative, finalFlag)
	}
	return nil, errSeedWidthMix
}

// streamAuthDecryptTripleCfg is the per-chunk dispatch helper for the
// Triple Ouroboros Streaming AEAD decrypt path when a Config override
// is threaded per Pipeline.
func streamAuthDecryptTripleCfg(cfg *Config, width int, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 any, chunk []byte, mac MACFunc, streamID [streamIDPrefixLen]byte, cumulative uint64) ([]byte, bool, error) {
	switch width {
	case 128:
		return DecryptStreamAuthenticated3x128Cfg(cfg, noiseSeed.(*Seed128), lockSeed.(*Seed128), dataSeed1.(*Seed128), dataSeed2.(*Seed128), dataSeed3.(*Seed128), startSeed1.(*Seed128), startSeed2.(*Seed128), startSeed3.(*Seed128), chunk, mac, streamID, cumulative)
	case 256:
		return DecryptStreamAuthenticated3x256Cfg(cfg, noiseSeed.(*Seed256), lockSeed.(*Seed256), dataSeed1.(*Seed256), dataSeed2.(*Seed256), dataSeed3.(*Seed256), startSeed1.(*Seed256), startSeed2.(*Seed256), startSeed3.(*Seed256), chunk, mac, streamID, cumulative)
	case 512:
		return DecryptStreamAuthenticated3x512Cfg(cfg, noiseSeed.(*Seed512), lockSeed.(*Seed512), dataSeed1.(*Seed512), dataSeed2.(*Seed512), dataSeed3.(*Seed512), startSeed1.(*Seed512), startSeed2.(*Seed512), startSeed3.(*Seed512), chunk, mac, streamID, cumulative)
	}
	return nil, false, errSeedWidthMix
}

// EncryptStream3xCfg is the width-less Triple Ouroboros plain-stream
// Encrypt entry point with a per-encryptor Config override.
//
// The streamID prefix and the first chunk body are emitted as a single
// atomic dst.Write call. Batching closes a race where a concurrent
// reader draining the destination between two separate writes could
// consume-and-discard the prefix independently, leaving the receiving
// side's wire 32 bytes short and unable to parse the opening header.
func EncryptStream3xCfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 any, src io.Reader, dst io.Writer, chunkSize int) error {
	width, err := dispatchWidthTriple(noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3)
	if err != nil {
		return err
	}
	cs, err := validateChunkSize(chunkSize)
	if err != nil {
		return err
	}
	buf := make([]byte, cs)
	var prefix [streamIDPrefixLen]byte
	if _, rerr := rand.Read(prefix[:]); rerr != nil {
		return fmt.Errorf("itb: crypto/rand: %w", rerr)
	}
	prefixPending := true
	for {
		n, err := readUpTo(src, buf)
		if err == io.EOF {
			if prefixPending {
				return ErrEmptyInput
			}
			return nil
		}
		if err != nil {
			return err
		}
		ct, encErr := singleMessageEncryptTripleCfg(cfg, width, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, buf[:n])
		if encErr != nil {
			return encErr
		}
		if prefixPending {
			combined := make([]byte, streamIDPrefixLen+len(ct))
			copy(combined, prefix[:])
			copy(combined[streamIDPrefixLen:], ct)
			if _, werr := dst.Write(combined); werr != nil {
				return werr
			}
			prefixPending = false
			continue
		}
		if _, werr := dst.Write(ct); werr != nil {
			return werr
		}
	}
}

// DecryptStream3xCfg is the width-less Triple Ouroboros plain-stream
// Decrypt entry point with a per-encryptor Config override.
func DecryptStream3xCfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 any, src io.Reader, dst io.Writer) error {
	width, err := dispatchWidthTriple(noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3)
	if err != nil {
		return err
	}
	var prefix [streamIDPrefixLen]byte
	n, perr := io.ReadFull(src, prefix[:])
	if perr == io.EOF && n == 0 {
		return ErrEmptyInput
	}
	if perr == io.ErrUnexpectedEOF || (perr == io.EOF && n != streamIDPrefixLen) {
		return fmt.Errorf("itb: stream too short for stream prefix")
	}
	if perr != nil {
		return perr
	}
	for {
		chunk, err := readChunkParseCfg(cfg, src)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		pt, decErr := singleMessageDecryptTripleCfg(cfg, width, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, chunk)
		if decErr != nil {
			return decErr
		}
		if _, werr := dst.Write(pt); werr != nil {
			return werr
		}
	}
}

// EncryptStreamAuth3xCfg is the width-less Triple Ouroboros Streaming
// AEAD Encrypt entry point with a per-encryptor Config override.
//
// The streamID prefix and the first emitted chunk are combined into a
// single atomic dst.Write call. Batching closes the same
// concurrent-drain race documented on [EncryptStream3xCfg]: without it,
// a reader draining the destination between the prefix write and the
// first chunk body write can consume-and-discard the prefix
// independently, and the receiving side sees a wire missing the
// 32-byte opening.
func EncryptStreamAuth3xCfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 any, src io.Reader, dst io.Writer, mac MACFunc, chunkSize int) error {
	width, err := dispatchWidthTriple(noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3)
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
	prefixPending := true

	// emitChunk writes one produced chunk to dst, prepending the
	// streamID prefix on the first invocation so prefix and first
	// chunk land in one atomic dst.Write.
	emitChunk := func(chunk []byte) error {
		if prefixPending {
			combined := make([]byte, streamIDPrefixLen+len(chunk))
			copy(combined, streamID[:])
			copy(combined[streamIDPrefixLen:], chunk)
			if _, werr := dst.Write(combined); werr != nil {
				return werr
			}
			prefixPending = false
			return nil
		}
		_, werr := dst.Write(chunk)
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
			chunk, encErr := streamAuthEncryptTripleCfg(cfg, width, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, pending, mac, streamID, cumulative, false)
			if encErr != nil {
				return encErr
			}
			pixels, pxErr := chunkPixelCountCfg(cfg, chunk)
			if pxErr != nil {
				return pxErr
			}
			if werr := emitChunk(chunk); werr != nil {
				return werr
			}
			cumulative += pixels
		}
		held := make([]byte, n)
		copy(held, stage[:n])
		pending = held
	}

	if pending == nil {
		chunk, encErr := streamAuthEncryptTripleCfg(cfg, width, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, nil, mac, streamID, 0, true)
		if encErr != nil {
			return encErr
		}
		return emitChunk(chunk)
	}
	chunk, encErr := streamAuthEncryptTripleCfg(cfg, width, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, pending, mac, streamID, cumulative, true)
	if encErr != nil {
		return encErr
	}
	return emitChunk(chunk)
}

// DecryptStreamAuth3xCfg is the width-less Triple Ouroboros Streaming
// AEAD Decrypt entry point with a per-encryptor Config override.
func DecryptStreamAuth3xCfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 any, src io.Reader, dst io.Writer, mac MACFunc) error {
	width, err := dispatchWidthTriple(noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3)
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
		chunk, cerr := readChunkParseCfg(cfg, src)
		if cerr == io.EOF {
			break
		}
		if cerr != nil {
			return cerr
		}
		if seenFinal {
			return ErrStreamAfterFinal
		}
		plain, finalFlag, decErr := streamAuthDecryptTripleCfg(cfg, width, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, chunk, mac, streamID, cumulative)
		if decErr != nil {
			return decErr
		}
		pixels, pixErr := chunkPixelCountCfg(cfg, chunk)
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
