// Width-less io.Reader / io.Writer streaming helpers for plain and
// authenticated stream cipher modes. The width is determined by the
// supplied seed type via an any-typed dispatch over the per-chunk
// helpers behind the Single Message entries.
//
// Each helper drains src to EOF, encrypts or decrypts chunk-by-chunk,
// and writes the resulting wire chunks (encrypt) or recovered
// plaintext (decrypt) to dst. The encrypt-side helpers consume a
// chunkSize parameter; the decrypt-side helpers recover chunk extents
// from the on-wire header per chunk.
//
// Every chunk travels behind its own 32-byte prefix and is written to
// dst together with it in one call, so every record on the wire is
// [prefix(32)][main nonce][W][H][container] — the shape of a Single
// Message wire. Behaviour parity with the binding-side stream helpers:
// the streamID ahead of chunk 0 and a fresh CSPRNG chunk prefix ahead
// of every later chunk on the auth path, both bound into the chunk's
// MAC input together with the cumulative pixel offset, a CSPRNG dummy
// ahead of every chunk on the No MAC path, finalFlag flipped on the
// terminating chunk, ErrStreamTruncated / ErrStreamAfterFinal surfaced
// verbatim from the underlying single-chunk path.

package itb

import (
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

// readFirstPrefix reads the 32-byte prefix that opens the first chunk
// record into prefix. Returns io.EOF when src is empty and an error
// naming the stream prefix when src ends inside it.
func readFirstPrefix(src io.Reader, prefix *[streamIDPrefixLen]byte) error {
	n, err := io.ReadFull(src, prefix[:])
	if err == io.EOF && n == 0 {
		return io.EOF
	}
	if err == io.ErrUnexpectedEOF {
		return fmt.Errorf("itb: stream too short for stream prefix")
	}
	return err
}

// readChunkPrefix reads the 32-byte prefix that opens every later
// chunk record into prefix. Returns io.EOF when src is exhausted
// before the first prefix byte — a clean end of stream on a record
// boundary — and an error when the prefix is cut short.
func readChunkPrefix(src io.Reader, prefix *[streamIDPrefixLen]byte) error {
	n, err := io.ReadFull(src, prefix[:])
	if err == io.EOF && n == 0 {
		return io.EOF
	}
	if err == io.ErrUnexpectedEOF {
		return fmt.Errorf("itb: short chunk prefix read: %d of %d bytes", n, streamIDPrefixLen)
	}
	return err
}

// readRecordChunkCfg reads the chunk behind a prefix that has already
// been read. The stream may not end between a prefix and its chunk, so
// a clean end of src here is an error rather than io.EOF.
func readRecordChunkCfg(cfg *Config, src io.Reader) ([]byte, error) {
	chunk, err := readChunkParseCfg(cfg, src)
	if err == io.EOF {
		return nil, fmt.Errorf("itb: stream ends after a chunk prefix")
	}
	return chunk, err
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
	width := int(binary.BigEndian.Uint16(hdr[nonceLen:]))
	height := int(binary.BigEndian.Uint16(hdr[nonceLen+2:]))
	if width <= 0 || height <= 0 {
		return nil, fmt.Errorf("itb: invalid dimensions %dx%d", width, height)
	}
	// The encoder only emits square containers; a non-square header
	// with the same W·H would otherwise decode to the same plaintext.
	if width != height {
		return nil, fmt.Errorf("itb: non-square container %dx%d", width, height)
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

// chunkEncryptTripleCfg is the per-chunk dispatch helper for the
// width-less No MAC Triple Ouroboros Encrypt path when a Config
// override is threaded per Pipeline. It returns one chunk record —
// a fresh 32-byte CSPRNG dummy prefix followed by the chunk, in one
// buffer — the same bytes the No MAC Single Message entries produce.
func chunkEncryptTripleCfg(cfg *Config, width int, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 any, data []byte) ([]byte, error) {
	var rec []byte
	var err error
	switch width {
	case 128:
		rec, err = encrypt3x128Cfg(cfg, noiseSeed.(*Seed128), lockSeed.(*Seed128), dataSeed1.(*Seed128), dataSeed2.(*Seed128), dataSeed3.(*Seed128), startSeed1.(*Seed128), startSeed2.(*Seed128), startSeed3.(*Seed128), data, streamIDPrefixLen)
	case 256:
		rec, err = encrypt3x256Cfg(cfg, noiseSeed.(*Seed256), lockSeed.(*Seed256), dataSeed1.(*Seed256), dataSeed2.(*Seed256), dataSeed3.(*Seed256), startSeed1.(*Seed256), startSeed2.(*Seed256), startSeed3.(*Seed256), data, streamIDPrefixLen)
	case 512:
		rec, err = encrypt3x512Cfg(cfg, noiseSeed.(*Seed512), lockSeed.(*Seed512), dataSeed1.(*Seed512), dataSeed2.(*Seed512), dataSeed3.(*Seed512), startSeed1.(*Seed512), startSeed2.(*Seed512), startSeed3.(*Seed512), data, streamIDPrefixLen)
	default:
		return nil, errSeedWidthMix
	}
	if err != nil {
		return nil, err
	}
	if err := fillNomacPrefix(rec[:streamIDPrefixLen]); err != nil {
		return nil, err
	}
	return rec, nil
}

// chunkDecryptTripleCfg is the per-chunk dispatch helper for the
// width-less No MAC Triple Ouroboros Decrypt path when a Config
// override is threaded per Pipeline. Mirror image of
// [chunkEncryptTripleCfg].
func chunkDecryptTripleCfg(cfg *Config, width int, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 any, chunk []byte) ([]byte, error) {
	switch width {
	case 128:
		return decrypt3x128Cfg(cfg, noiseSeed.(*Seed128), lockSeed.(*Seed128), dataSeed1.(*Seed128), dataSeed2.(*Seed128), dataSeed3.(*Seed128), startSeed1.(*Seed128), startSeed2.(*Seed128), startSeed3.(*Seed128), chunk)
	case 256:
		return decrypt3x256Cfg(cfg, noiseSeed.(*Seed256), lockSeed.(*Seed256), dataSeed1.(*Seed256), dataSeed2.(*Seed256), dataSeed3.(*Seed256), startSeed1.(*Seed256), startSeed2.(*Seed256), startSeed3.(*Seed256), chunk)
	case 512:
		return decrypt3x512Cfg(cfg, noiseSeed.(*Seed512), lockSeed.(*Seed512), dataSeed1.(*Seed512), dataSeed2.(*Seed512), dataSeed3.(*Seed512), startSeed1.(*Seed512), startSeed2.(*Seed512), startSeed3.(*Seed512), chunk)
	}
	return nil, errSeedWidthMix
}

// streamAuthEncryptTripleCfg is the per-chunk dispatch helper for the
// Triple Ouroboros Streaming AEAD encrypt path when a Config override
// is threaded per Pipeline. It returns one chunk record — the prefix
// the chunk travels behind (the streamID when chunkPrefix is empty,
// chunkPrefix otherwise) followed by the chunk, in one buffer.
func streamAuthEncryptTripleCfg(cfg *Config, width int, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 any, plaintext []byte, mac MACFunc, streamID [streamIDPrefixLen]byte, chunkPrefix []byte, cumulative uint64, finalFlag bool) ([]byte, error) {
	var rec []byte
	var err error
	switch width {
	case 128:
		rec, err = encryptStreamAuthenticated3x128Cfg(cfg, noiseSeed.(*Seed128), lockSeed.(*Seed128), dataSeed1.(*Seed128), dataSeed2.(*Seed128), dataSeed3.(*Seed128), startSeed1.(*Seed128), startSeed2.(*Seed128), startSeed3.(*Seed128), plaintext, mac, streamID, chunkPrefix, cumulative, finalFlag, streamIDPrefixLen)
	case 256:
		rec, err = encryptStreamAuthenticated3x256Cfg(cfg, noiseSeed.(*Seed256), lockSeed.(*Seed256), dataSeed1.(*Seed256), dataSeed2.(*Seed256), dataSeed3.(*Seed256), startSeed1.(*Seed256), startSeed2.(*Seed256), startSeed3.(*Seed256), plaintext, mac, streamID, chunkPrefix, cumulative, finalFlag, streamIDPrefixLen)
	case 512:
		rec, err = encryptStreamAuthenticated3x512Cfg(cfg, noiseSeed.(*Seed512), lockSeed.(*Seed512), dataSeed1.(*Seed512), dataSeed2.(*Seed512), dataSeed3.(*Seed512), startSeed1.(*Seed512), startSeed2.(*Seed512), startSeed3.(*Seed512), plaintext, mac, streamID, chunkPrefix, cumulative, finalFlag, streamIDPrefixLen)
	default:
		return nil, errSeedWidthMix
	}
	if err != nil {
		return nil, err
	}
	putChunkPrefix(rec, streamID, chunkPrefix)
	return rec, nil
}

// streamAuthDecryptTripleCfg is the per-chunk dispatch helper for the
// Triple Ouroboros Streaming AEAD decrypt path when a Config override
// is threaded per Pipeline. chunk excludes the prefix; chunkPrefix is
// empty for chunk 0 and the prefix read ahead of every later chunk.
func streamAuthDecryptTripleCfg(cfg *Config, width int, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 any, chunk []byte, mac MACFunc, streamID [streamIDPrefixLen]byte, chunkPrefix []byte, cumulative uint64) ([]byte, bool, error) {
	switch width {
	case 128:
		return DecryptStreamAuthenticated3x128Cfg(cfg, noiseSeed.(*Seed128), lockSeed.(*Seed128), dataSeed1.(*Seed128), dataSeed2.(*Seed128), dataSeed3.(*Seed128), startSeed1.(*Seed128), startSeed2.(*Seed128), startSeed3.(*Seed128), chunk, mac, streamID, chunkPrefix, cumulative)
	case 256:
		return DecryptStreamAuthenticated3x256Cfg(cfg, noiseSeed.(*Seed256), lockSeed.(*Seed256), dataSeed1.(*Seed256), dataSeed2.(*Seed256), dataSeed3.(*Seed256), startSeed1.(*Seed256), startSeed2.(*Seed256), startSeed3.(*Seed256), chunk, mac, streamID, chunkPrefix, cumulative)
	case 512:
		return DecryptStreamAuthenticated3x512Cfg(cfg, noiseSeed.(*Seed512), lockSeed.(*Seed512), dataSeed1.(*Seed512), dataSeed2.(*Seed512), dataSeed3.(*Seed512), startSeed1.(*Seed512), startSeed2.(*Seed512), startSeed3.(*Seed512), chunk, mac, streamID, chunkPrefix, cumulative)
	}
	return nil, false, errSeedWidthMix
}

// EncryptStream3xCfg is the width-less Triple Ouroboros No MAC stream
// Encrypt entry point with a per-encryptor Config override.
//
// Every chunk and the 32-byte CSPRNG dummy prefix ahead of it are
// built in one buffer and written as a single atomic dst.Write call.
// One write per record closes a race where a concurrent reader
// draining the destination between two separate writes could
// consume-and-discard a prefix independently, leaving the receiving
// side's wire 32 bytes short and unable to parse the next header.
func EncryptStream3xCfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 any, src io.Reader, dst io.Writer, chunkSize int) error {
	width, err := dispatchWidthTriple(noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3)
	if err != nil {
		return err
	}
	if err := validateConfigCfg(cfg); err != nil {
		return err
	}
	cs, err := validateChunkSize(chunkSize)
	if err != nil {
		return err
	}
	// Chunk-budget read stage drawn from stagePool — same discipline as
	// the Streaming AEAD arm: only buf[:n] is read back after readUpTo
	// fills it, and the release wipes the high-water mark of bytes
	// staged.
	bufPtr, buf := acquireStage(cs)
	bufUsed := 0
	defer func() { releaseStage(bufPtr, buf, bufUsed) }()
	first := true
	for {
		n, err := readUpTo(src, buf)
		if n > bufUsed {
			bufUsed = n
		}
		if err == io.EOF {
			if first {
				return ErrEmptyInput
			}
			return nil
		}
		if err != nil {
			return err
		}
		rec, encErr := chunkEncryptTripleCfg(cfg, width, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, buf[:n])
		if encErr != nil {
			return encErr
		}
		if _, werr := dst.Write(rec); werr != nil {
			return werr
		}
		first = false
	}
}

// DecryptStream3xCfg is the width-less Triple Ouroboros No MAC stream
// Decrypt entry point with a per-encryptor Config override.
func DecryptStream3xCfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 any, src io.Reader, dst io.Writer) error {
	width, err := dispatchWidthTriple(noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3)
	if err != nil {
		return err
	}
	// Every record is a 32-byte dummy prefix, discarded, followed by
	// one chunk. A clean end of src on a record boundary ends the
	// stream; an empty stream is ErrEmptyInput.
	var prefix [streamIDPrefixLen]byte
	for first := true; ; first = false {
		read := readChunkPrefix
		if first {
			read = readFirstPrefix
		}
		if perr := read(src, &prefix); perr != nil {
			if perr != io.EOF {
				return perr
			}
			if first {
				return ErrEmptyInput
			}
			return nil
		}
		chunk, err := readRecordChunkCfg(cfg, src)
		if err != nil {
			return err
		}
		pt, decErr := chunkDecryptTripleCfg(cfg, width, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, chunk)
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
// Every chunk and the 32-byte prefix ahead of it — the streamID on
// chunk 0, a fresh CSPRNG chunk prefix bound into the chunk's MAC on
// every later chunk — are built in one buffer and written as a single
// atomic dst.Write call, which closes the same concurrent-drain race
// documented on [EncryptStream3xCfg].
func EncryptStreamAuth3xCfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 any, src io.Reader, dst io.Writer, mac MACFunc, chunkSize int) error {
	width, err := dispatchWidthTriple(noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3)
	if err != nil {
		return err
	}
	if mac == nil {
		return fmt.Errorf("itb: macFunc must not be nil")
	}
	if err := validateConfigCfg(cfg); err != nil {
		return err
	}
	cs, err := validateChunkSize(chunkSize)
	if err != nil {
		return err
	}

	streamID, err := generateStreamID()
	if err != nil {
		return err
	}
	first := true

	// encryptRecord produces one chunk record — prefix and chunk in
	// one buffer — drawing the chunk prefix before the chunk is
	// encrypted so the bytes bound into the MAC are the bytes written.
	encryptRecord := func(plaintext []byte, cumulative uint64, finalFlag bool) ([]byte, error) {
		chunkPrefix, perr := drawChunkPrefix(first)
		if perr != nil {
			return nil, perr
		}
		rec, encErr := streamAuthEncryptTripleCfg(cfg, width, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, plaintext, mac, streamID, chunkPrefix, cumulative, finalFlag)
		if encErr != nil {
			return nil, encErr
		}
		first = false
		return rec, nil
	}

	// The read stage is chunk-budget sized (cs, independent of the
	// payload) and lives for the whole stream, so it is drawn from the
	// process-wide stagePool instead of being allocated per call. Only
	// stage[:n] is ever read back after readUpTo fills it, so no zero
	// pass is needed on borrow; the wipe on release covers the
	// high-water mark of bytes staged.
	stagePtr, stage := acquireStage(cs)
	stageUsed := 0
	defer func() { releaseStage(stagePtr, stage, stageUsed) }()
	var pending []byte
	var cumulative uint64

	for {
		n, rerr := readUpTo(src, stage)
		if n > stageUsed {
			stageUsed = n
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
		if pending != nil {
			rec, encErr := encryptRecord(pending, cumulative, false)
			if encErr != nil {
				return encErr
			}
			pixels, pxErr := chunkPixelCountCfg(cfg, rec[streamIDPrefixLen:])
			if pxErr != nil {
				return pxErr
			}
			if _, werr := dst.Write(rec); werr != nil {
				return werr
			}
			cumulative += pixels
		}
		held := make([]byte, n)
		copy(held, stage[:n])
		pending = held
	}

	if pending == nil {
		rec, encErr := encryptRecord(nil, 0, true)
		if encErr != nil {
			return encErr
		}
		_, werr := dst.Write(rec)
		return werr
	}
	rec, encErr := encryptRecord(pending, cumulative, true)
	if encErr != nil {
		return encErr
	}
	_, werr := dst.Write(rec)
	return werr
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

	// Every record is a 32-byte prefix followed by one chunk: the
	// streamID ahead of chunk 0, a chunk prefix bound into the chunk's
	// MAC ahead of every later chunk. A clean end of src on a record
	// boundary ends the stream; truncation is caught by the final flag.
	var streamID [streamIDPrefixLen]byte
	if perr := readFirstPrefix(src, &streamID); perr != nil {
		if perr == io.EOF {
			return fmt.Errorf("itb: stream too short for stream prefix")
		}
		return perr
	}

	var cumulative uint64
	seenFinal := false
	var prefix [streamIDPrefixLen]byte
	for first := true; ; first = false {
		var chunkPrefix []byte
		if !first {
			if perr := readChunkPrefix(src, &prefix); perr != nil {
				if perr == io.EOF {
					break
				}
				return perr
			}
			chunkPrefix = prefix[:]
		}
		chunk, cerr := readRecordChunkCfg(cfg, src)
		if cerr != nil {
			return cerr
		}
		if seenFinal {
			return ErrStreamAfterFinal
		}
		plain, finalFlag, decErr := streamAuthDecryptTripleCfg(cfg, width, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, chunk, mac, streamID, chunkPrefix, cumulative)
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
