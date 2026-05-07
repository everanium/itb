package itb

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// streamIDPrefixLen is the on-wire length of the per-stream
// CSPRNG-fresh anchor preceding chunk 0 of a Streaming AEAD
// transcript.
const streamIDPrefixLen = 32

// generateStreamID draws a CSPRNG-fresh 32-byte stream anchor that
// the encoder helper writes once at stream start and reuses across
// every chunk's MAC input.
func generateStreamID() ([streamIDPrefixLen]byte, error) {
	var sid [streamIDPrefixLen]byte
	if _, err := rand.Read(sid[:]); err != nil {
		return sid, fmt.Errorf("itb: crypto/rand: %w", err)
	}
	return sid, nil
}

// chunkPixelCount reads the W and H header values from a streaming
// chunk's wire bytes and returns W * H. The caller has already used
// ParseChunkLen / ParseChunkLenCfg to validate the buffer; the values
// are re-read here to advance cumulativePixelOffset between chunks.
func chunkPixelCount(chunk []byte) (uint64, error) {
	if len(chunk) < headerSize() {
		return 0, fmt.Errorf("itb: chunk too short for header")
	}
	width := uint64(binary.BigEndian.Uint16(chunk[currentNonceSize():]))
	height := uint64(binary.BigEndian.Uint16(chunk[currentNonceSize()+2:]))
	if width == 0 || height == 0 {
		return 0, fmt.Errorf("itb: invalid dimensions %dx%d", width, height)
	}
	return width * height, nil
}

// chunkPixelCountCfg is the Cfg variant of [chunkPixelCount]: respects
// the per-Config nonce-bits override at the chunk-header parse site.
func chunkPixelCountCfg(cfg *Config, chunk []byte) (uint64, error) {
	if len(chunk) < headerSizeCfg(cfg) {
		return 0, fmt.Errorf("itb: chunk too short for header")
	}
	nonceLen := currentNonceSizeCfg(cfg)
	width := uint64(binary.BigEndian.Uint16(chunk[nonceLen:]))
	height := uint64(binary.BigEndian.Uint16(chunk[nonceLen+2:]))
	if width == 0 || height == 0 {
		return 0, fmt.Errorf("itb: invalid dimensions %dx%d", width, height)
	}
	return width * height, nil
}

// ErrStreamTruncated is returned when DecryptStreamAuthenticated*
// exhausts its input without observing a chunk whose recovered
// finalFlag equals 0xFF. The transcript has been truncated at or
// before the terminating chunk; no plaintext after the last
// successfully verified chunk is trustworthy.
var ErrStreamTruncated = fmt.Errorf("itb: Streaming AEAD transcript truncated before terminator")

// ErrStreamAfterFinal is returned when DecryptStreamAuthenticated*
// observes additional chunk bytes after a chunk whose recovered
// finalFlag equals 0xFF. The transcript carries trailing data after
// the terminator; the encoder helper would not produce this layout.
var ErrStreamAfterFinal = fmt.Errorf("itb: Streaming AEAD chunk after terminator")

// streamFlagByte translates the Streaming AEAD finalFlag boolean to
// the on-wire flag byte: 0xFF for the terminating chunk, 0x00 for
// every preceding chunk. The decoder uses an exact equality test on
// 0xFF when classifying the recovered flag.
func streamFlagByte(finalFlag bool) byte {
	if finalFlag {
		return 0xFF
	}
	return 0x00
}

// --- 128-bit variants ---

// EncryptStreamAuth128 is the wide-stream entry point for
// Streaming AEAD using 128-bit hash seeds. Generates a fresh 32-byte
// stream anchor, emits it as the first wire chunk, then loops over
// data in chunks of chunkSize bytes calling
// [EncryptStreamAuthenticated128] per chunk with the running
// cumulative pixel offset and finalFlag = true on the last chunk.
//
// Empty input is permitted: the helper emits the stream prefix
// followed by a single terminating chunk built from a 0-byte
// plaintext with finalFlag = true.
func EncryptStreamAuth128(noiseSeed, dataSeed, startSeed *Seed128, data []byte, chunkSize int, macFunc MACFunc, emit func(chunk []byte) error) error {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
	}
	if macFunc == nil {
		return fmt.Errorf("itb: macFunc must not be nil")
	}
	if chunkSize <= 0 {
		if len(data) == 0 {
			chunkSize = DefaultChunkSize
		} else {
			chunkSize = ChunkSize(len(data))
		}
	}
	if chunkSize > maxDataSize {
		return fmt.Errorf("itb: chunk size %d exceeds maximum %d bytes", chunkSize, maxDataSize)
	}

	streamID, err := generateStreamID()
	if err != nil {
		return err
	}
	if err := emit(streamID[:]); err != nil {
		return err
	}

	if len(data) == 0 {
		chunk, emitErr := EncryptStreamAuthenticated128(noiseSeed, dataSeed, startSeed, nil, macFunc, streamID, 0, true)
		if emitErr != nil {
			return fmt.Errorf("itb: empty-stream chunk: %w", emitErr)
		}
		return emit(chunk)
	}

	var cumulative uint64
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		finalFlag := end == len(data)
		chunk, chunkErr := EncryptStreamAuthenticated128(noiseSeed, dataSeed, startSeed, data[off:end], macFunc, streamID, cumulative, finalFlag)
		if chunkErr != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, chunkErr)
		}
		pixels, chunkErr := chunkPixelCount(chunk)
		if chunkErr != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, chunkErr)
		}
		if err := emit(chunk); err != nil {
			return err
		}
		cumulative += pixels
	}
	return nil
}

// DecryptStreamAuth128 is the wide-stream entry point for
// Streaming AEAD using 128-bit hash seeds. Reads the leading 32-byte
// stream anchor from data, walks the remaining bytes through
// [ParseChunkLen] one chunk at a time, calls
// [DecryptStreamAuthenticated128] per chunk with the cumulative
// pixel offset, and emits each recovered plaintext through the
// supplied emit callback. Returns [ErrStreamTruncated] when the
// transcript exhausts without observing a chunk whose finalFlag is
// true, and [ErrStreamAfterFinal] when additional chunk bytes follow
// the terminator.
func DecryptStreamAuth128(noiseSeed, dataSeed, startSeed *Seed128, data []byte, macFunc MACFunc, emit func(chunk []byte) error) error {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
	}
	if macFunc == nil {
		return fmt.Errorf("itb: macFunc must not be nil")
	}
	if len(data) < streamIDPrefixLen {
		return fmt.Errorf("itb: stream too short for stream prefix")
	}

	var streamID [streamIDPrefixLen]byte
	copy(streamID[:], data[:streamIDPrefixLen])

	var cumulative uint64
	seenFinal := false
	for off := streamIDPrefixLen; off < len(data); {
		chunkLen, err := ParseChunkLen(data[off:])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if seenFinal {
			return ErrStreamAfterFinal
		}
		plain, finalFlag, err := DecryptStreamAuthenticated128(noiseSeed, dataSeed, startSeed, data[off:off+chunkLen], macFunc, streamID, cumulative)
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		pixels, err := chunkPixelCount(data[off : off+chunkLen])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if err := emit(plain); err != nil {
			return err
		}
		cumulative += pixels
		if finalFlag {
			seenFinal = true
		}
		off += chunkLen
	}
	if !seenFinal {
		return ErrStreamTruncated
	}
	return nil
}

// --- 256-bit variants ---

// EncryptStreamAuth256 mirrors [EncryptStreamAuth128] for 256-bit
// hash seeds.
func EncryptStreamAuth256(noiseSeed, dataSeed, startSeed *Seed256, data []byte, chunkSize int, macFunc MACFunc, emit func(chunk []byte) error) error {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
	}
	if macFunc == nil {
		return fmt.Errorf("itb: macFunc must not be nil")
	}
	if chunkSize <= 0 {
		if len(data) == 0 {
			chunkSize = DefaultChunkSize
		} else {
			chunkSize = ChunkSize(len(data))
		}
	}
	if chunkSize > maxDataSize {
		return fmt.Errorf("itb: chunk size %d exceeds maximum %d bytes", chunkSize, maxDataSize)
	}

	streamID, err := generateStreamID()
	if err != nil {
		return err
	}
	if err := emit(streamID[:]); err != nil {
		return err
	}

	if len(data) == 0 {
		chunk, emitErr := EncryptStreamAuthenticated256(noiseSeed, dataSeed, startSeed, nil, macFunc, streamID, 0, true)
		if emitErr != nil {
			return fmt.Errorf("itb: empty-stream chunk: %w", emitErr)
		}
		return emit(chunk)
	}

	var cumulative uint64
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		finalFlag := end == len(data)
		chunk, chunkErr := EncryptStreamAuthenticated256(noiseSeed, dataSeed, startSeed, data[off:end], macFunc, streamID, cumulative, finalFlag)
		if chunkErr != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, chunkErr)
		}
		pixels, chunkErr := chunkPixelCount(chunk)
		if chunkErr != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, chunkErr)
		}
		if err := emit(chunk); err != nil {
			return err
		}
		cumulative += pixels
	}
	return nil
}

// DecryptStreamAuth256 mirrors [DecryptStreamAuth128] for 256-bit
// hash seeds.
func DecryptStreamAuth256(noiseSeed, dataSeed, startSeed *Seed256, data []byte, macFunc MACFunc, emit func(chunk []byte) error) error {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
	}
	if macFunc == nil {
		return fmt.Errorf("itb: macFunc must not be nil")
	}
	if len(data) < streamIDPrefixLen {
		return fmt.Errorf("itb: stream too short for stream prefix")
	}

	var streamID [streamIDPrefixLen]byte
	copy(streamID[:], data[:streamIDPrefixLen])

	var cumulative uint64
	seenFinal := false
	for off := streamIDPrefixLen; off < len(data); {
		chunkLen, err := ParseChunkLen(data[off:])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if seenFinal {
			return ErrStreamAfterFinal
		}
		plain, finalFlag, err := DecryptStreamAuthenticated256(noiseSeed, dataSeed, startSeed, data[off:off+chunkLen], macFunc, streamID, cumulative)
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		pixels, err := chunkPixelCount(data[off : off+chunkLen])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if err := emit(plain); err != nil {
			return err
		}
		cumulative += pixels
		if finalFlag {
			seenFinal = true
		}
		off += chunkLen
	}
	if !seenFinal {
		return ErrStreamTruncated
	}
	return nil
}

// --- 512-bit variants ---

// EncryptStreamAuth512 mirrors [EncryptStreamAuth128] for 512-bit
// hash seeds.
func EncryptStreamAuth512(noiseSeed, dataSeed, startSeed *Seed512, data []byte, chunkSize int, macFunc MACFunc, emit func(chunk []byte) error) error {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
	}
	if macFunc == nil {
		return fmt.Errorf("itb: macFunc must not be nil")
	}
	if chunkSize <= 0 {
		if len(data) == 0 {
			chunkSize = DefaultChunkSize
		} else {
			chunkSize = ChunkSize(len(data))
		}
	}
	if chunkSize > maxDataSize {
		return fmt.Errorf("itb: chunk size %d exceeds maximum %d bytes", chunkSize, maxDataSize)
	}

	streamID, err := generateStreamID()
	if err != nil {
		return err
	}
	if err := emit(streamID[:]); err != nil {
		return err
	}

	if len(data) == 0 {
		chunk, emitErr := EncryptStreamAuthenticated512(noiseSeed, dataSeed, startSeed, nil, macFunc, streamID, 0, true)
		if emitErr != nil {
			return fmt.Errorf("itb: empty-stream chunk: %w", emitErr)
		}
		return emit(chunk)
	}

	var cumulative uint64
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		finalFlag := end == len(data)
		chunk, chunkErr := EncryptStreamAuthenticated512(noiseSeed, dataSeed, startSeed, data[off:end], macFunc, streamID, cumulative, finalFlag)
		if chunkErr != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, chunkErr)
		}
		pixels, chunkErr := chunkPixelCount(chunk)
		if chunkErr != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, chunkErr)
		}
		if err := emit(chunk); err != nil {
			return err
		}
		cumulative += pixels
	}
	return nil
}

// DecryptStreamAuth512 mirrors [DecryptStreamAuth128] for 512-bit
// hash seeds.
func DecryptStreamAuth512(noiseSeed, dataSeed, startSeed *Seed512, data []byte, macFunc MACFunc, emit func(chunk []byte) error) error {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
	}
	if macFunc == nil {
		return fmt.Errorf("itb: macFunc must not be nil")
	}
	if len(data) < streamIDPrefixLen {
		return fmt.Errorf("itb: stream too short for stream prefix")
	}

	var streamID [streamIDPrefixLen]byte
	copy(streamID[:], data[:streamIDPrefixLen])

	var cumulative uint64
	seenFinal := false
	for off := streamIDPrefixLen; off < len(data); {
		chunkLen, err := ParseChunkLen(data[off:])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if seenFinal {
			return ErrStreamAfterFinal
		}
		plain, finalFlag, err := DecryptStreamAuthenticated512(noiseSeed, dataSeed, startSeed, data[off:off+chunkLen], macFunc, streamID, cumulative)
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		pixels, err := chunkPixelCount(data[off : off+chunkLen])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if err := emit(plain); err != nil {
			return err
		}
		cumulative += pixels
		if finalFlag {
			seenFinal = true
		}
		off += chunkLen
	}
	if !seenFinal {
		return ErrStreamTruncated
	}
	return nil
}

// --- Triple Ouroboros (7-seed) variants ---

// EncryptStreamAuth3x128 mirrors [EncryptStreamAuth128] for the
// Triple Ouroboros (7-seed) variant at 128-bit hash width.
func EncryptStreamAuth3x128(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed128, data []byte, chunkSize int, macFunc MACFunc, emit func(chunk []byte) error) error {
	if err := checkSevenSeeds128(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return err
	}
	if macFunc == nil {
		return fmt.Errorf("itb: macFunc must not be nil")
	}
	if chunkSize <= 0 {
		if len(data) == 0 {
			chunkSize = DefaultChunkSize
		} else {
			chunkSize = ChunkSize(len(data))
		}
	}
	if chunkSize > maxDataSize {
		return fmt.Errorf("itb: chunk size %d exceeds maximum %d bytes", chunkSize, maxDataSize)
	}

	streamID, err := generateStreamID()
	if err != nil {
		return err
	}
	if err := emit(streamID[:]); err != nil {
		return err
	}

	if len(data) == 0 {
		chunk, emitErr := EncryptStreamAuthenticated3x128(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, nil, macFunc, streamID, 0, true)
		if emitErr != nil {
			return fmt.Errorf("itb: empty-stream chunk: %w", emitErr)
		}
		return emit(chunk)
	}

	var cumulative uint64
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		finalFlag := end == len(data)
		chunk, chunkErr := EncryptStreamAuthenticated3x128(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:end], macFunc, streamID, cumulative, finalFlag)
		if chunkErr != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, chunkErr)
		}
		pixels, chunkErr := chunkPixelCount(chunk)
		if chunkErr != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, chunkErr)
		}
		if err := emit(chunk); err != nil {
			return err
		}
		cumulative += pixels
	}
	return nil
}

// DecryptStreamAuth3x128 mirrors [DecryptStreamAuth128] for Triple
// Ouroboros (7-seed) at 128-bit hash width.
func DecryptStreamAuth3x128(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed128, data []byte, macFunc MACFunc, emit func(chunk []byte) error) error {
	if err := checkSevenSeeds128(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return err
	}
	if macFunc == nil {
		return fmt.Errorf("itb: macFunc must not be nil")
	}
	if len(data) < streamIDPrefixLen {
		return fmt.Errorf("itb: stream too short for stream prefix")
	}

	var streamID [streamIDPrefixLen]byte
	copy(streamID[:], data[:streamIDPrefixLen])

	var cumulative uint64
	seenFinal := false
	for off := streamIDPrefixLen; off < len(data); {
		chunkLen, err := ParseChunkLen(data[off:])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if seenFinal {
			return ErrStreamAfterFinal
		}
		plain, finalFlag, err := DecryptStreamAuthenticated3x128(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:off+chunkLen], macFunc, streamID, cumulative)
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		pixels, err := chunkPixelCount(data[off : off+chunkLen])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if err := emit(plain); err != nil {
			return err
		}
		cumulative += pixels
		if finalFlag {
			seenFinal = true
		}
		off += chunkLen
	}
	if !seenFinal {
		return ErrStreamTruncated
	}
	return nil
}

// EncryptStreamAuth3x256 mirrors [EncryptStreamAuth128] for Triple
// Ouroboros (7-seed) at 256-bit hash width.
func EncryptStreamAuth3x256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed256, data []byte, chunkSize int, macFunc MACFunc, emit func(chunk []byte) error) error {
	if err := checkSevenSeeds256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return err
	}
	if macFunc == nil {
		return fmt.Errorf("itb: macFunc must not be nil")
	}
	if chunkSize <= 0 {
		if len(data) == 0 {
			chunkSize = DefaultChunkSize
		} else {
			chunkSize = ChunkSize(len(data))
		}
	}
	if chunkSize > maxDataSize {
		return fmt.Errorf("itb: chunk size %d exceeds maximum %d bytes", chunkSize, maxDataSize)
	}

	streamID, err := generateStreamID()
	if err != nil {
		return err
	}
	if err := emit(streamID[:]); err != nil {
		return err
	}

	if len(data) == 0 {
		chunk, emitErr := EncryptStreamAuthenticated3x256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, nil, macFunc, streamID, 0, true)
		if emitErr != nil {
			return fmt.Errorf("itb: empty-stream chunk: %w", emitErr)
		}
		return emit(chunk)
	}

	var cumulative uint64
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		finalFlag := end == len(data)
		chunk, chunkErr := EncryptStreamAuthenticated3x256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:end], macFunc, streamID, cumulative, finalFlag)
		if chunkErr != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, chunkErr)
		}
		pixels, chunkErr := chunkPixelCount(chunk)
		if chunkErr != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, chunkErr)
		}
		if err := emit(chunk); err != nil {
			return err
		}
		cumulative += pixels
	}
	return nil
}

// DecryptStreamAuth3x256 mirrors [DecryptStreamAuth128] for Triple
// Ouroboros (7-seed) at 256-bit hash width.
func DecryptStreamAuth3x256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed256, data []byte, macFunc MACFunc, emit func(chunk []byte) error) error {
	if err := checkSevenSeeds256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return err
	}
	if macFunc == nil {
		return fmt.Errorf("itb: macFunc must not be nil")
	}
	if len(data) < streamIDPrefixLen {
		return fmt.Errorf("itb: stream too short for stream prefix")
	}

	var streamID [streamIDPrefixLen]byte
	copy(streamID[:], data[:streamIDPrefixLen])

	var cumulative uint64
	seenFinal := false
	for off := streamIDPrefixLen; off < len(data); {
		chunkLen, err := ParseChunkLen(data[off:])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if seenFinal {
			return ErrStreamAfterFinal
		}
		plain, finalFlag, err := DecryptStreamAuthenticated3x256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:off+chunkLen], macFunc, streamID, cumulative)
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		pixels, err := chunkPixelCount(data[off : off+chunkLen])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if err := emit(plain); err != nil {
			return err
		}
		cumulative += pixels
		if finalFlag {
			seenFinal = true
		}
		off += chunkLen
	}
	if !seenFinal {
		return ErrStreamTruncated
	}
	return nil
}

// EncryptStreamAuth3x512 mirrors [EncryptStreamAuth128] for Triple
// Ouroboros (7-seed) at 512-bit hash width.
func EncryptStreamAuth3x512(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed512, data []byte, chunkSize int, macFunc MACFunc, emit func(chunk []byte) error) error {
	if err := checkSevenSeeds512(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return err
	}
	if macFunc == nil {
		return fmt.Errorf("itb: macFunc must not be nil")
	}
	if chunkSize <= 0 {
		if len(data) == 0 {
			chunkSize = DefaultChunkSize
		} else {
			chunkSize = ChunkSize(len(data))
		}
	}
	if chunkSize > maxDataSize {
		return fmt.Errorf("itb: chunk size %d exceeds maximum %d bytes", chunkSize, maxDataSize)
	}

	streamID, err := generateStreamID()
	if err != nil {
		return err
	}
	if err := emit(streamID[:]); err != nil {
		return err
	}

	if len(data) == 0 {
		chunk, emitErr := EncryptStreamAuthenticated3x512(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, nil, macFunc, streamID, 0, true)
		if emitErr != nil {
			return fmt.Errorf("itb: empty-stream chunk: %w", emitErr)
		}
		return emit(chunk)
	}

	var cumulative uint64
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		finalFlag := end == len(data)
		chunk, chunkErr := EncryptStreamAuthenticated3x512(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:end], macFunc, streamID, cumulative, finalFlag)
		if chunkErr != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, chunkErr)
		}
		pixels, chunkErr := chunkPixelCount(chunk)
		if chunkErr != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, chunkErr)
		}
		if err := emit(chunk); err != nil {
			return err
		}
		cumulative += pixels
	}
	return nil
}

// DecryptStreamAuth3x512 mirrors [DecryptStreamAuth128] for Triple
// Ouroboros (7-seed) at 512-bit hash width.
func DecryptStreamAuth3x512(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed512, data []byte, macFunc MACFunc, emit func(chunk []byte) error) error {
	if err := checkSevenSeeds512(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return err
	}
	if macFunc == nil {
		return fmt.Errorf("itb: macFunc must not be nil")
	}
	if len(data) < streamIDPrefixLen {
		return fmt.Errorf("itb: stream too short for stream prefix")
	}

	var streamID [streamIDPrefixLen]byte
	copy(streamID[:], data[:streamIDPrefixLen])

	var cumulative uint64
	seenFinal := false
	for off := streamIDPrefixLen; off < len(data); {
		chunkLen, err := ParseChunkLen(data[off:])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if seenFinal {
			return ErrStreamAfterFinal
		}
		plain, finalFlag, err := DecryptStreamAuthenticated3x512(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:off+chunkLen], macFunc, streamID, cumulative)
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		pixels, err := chunkPixelCount(data[off : off+chunkLen])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if err := emit(plain); err != nil {
			return err
		}
		cumulative += pixels
		if finalFlag {
			seenFinal = true
		}
		off += chunkLen
	}
	if !seenFinal {
		return ErrStreamTruncated
	}
	return nil
}

// --- Cfg variants ---

// EncryptStreamAuth128Cfg is the Cfg variant of [EncryptStreamAuth128]:
// drives each chunk through [EncryptStreamAuthenticated128Cfg] so
// per-encryptor NonceBits / BarrierFill / BitSoup / LockSoup / LockSeed
// overrides are honoured chunk-by-chunk. Body otherwise identical.
func EncryptStreamAuth128Cfg(cfg *Config, noiseSeed, dataSeed, startSeed *Seed128, data []byte, chunkSize int, macFunc MACFunc, emit func(chunk []byte) error) error {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
	}
	if macFunc == nil {
		return fmt.Errorf("itb: macFunc must not be nil")
	}
	if chunkSize <= 0 {
		if len(data) == 0 {
			chunkSize = DefaultChunkSize
		} else {
			chunkSize = ChunkSize(len(data))
		}
	}
	if chunkSize > maxDataSize {
		return fmt.Errorf("itb: chunk size %d exceeds maximum %d bytes", chunkSize, maxDataSize)
	}

	streamID, err := generateStreamID()
	if err != nil {
		return err
	}
	if err := emit(streamID[:]); err != nil {
		return err
	}

	if len(data) == 0 {
		chunk, emitErr := EncryptStreamAuthenticated128Cfg(cfg, noiseSeed, dataSeed, startSeed, nil, macFunc, streamID, 0, true)
		if emitErr != nil {
			return fmt.Errorf("itb: empty-stream chunk: %w", emitErr)
		}
		return emit(chunk)
	}

	var cumulative uint64
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		finalFlag := end == len(data)
		chunk, chunkErr := EncryptStreamAuthenticated128Cfg(cfg, noiseSeed, dataSeed, startSeed, data[off:end], macFunc, streamID, cumulative, finalFlag)
		if chunkErr != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, chunkErr)
		}
		pixels, chunkErr := chunkPixelCountCfg(cfg, chunk)
		if chunkErr != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, chunkErr)
		}
		if err := emit(chunk); err != nil {
			return err
		}
		cumulative += pixels
	}
	return nil
}

// DecryptStreamAuth128Cfg is the Cfg variant of [DecryptStreamAuth128].
func DecryptStreamAuth128Cfg(cfg *Config, noiseSeed, dataSeed, startSeed *Seed128, data []byte, macFunc MACFunc, emit func(chunk []byte) error) error {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
	}
	if macFunc == nil {
		return fmt.Errorf("itb: macFunc must not be nil")
	}
	if len(data) < streamIDPrefixLen {
		return fmt.Errorf("itb: stream too short for stream prefix")
	}

	var streamID [streamIDPrefixLen]byte
	copy(streamID[:], data[:streamIDPrefixLen])

	var cumulative uint64
	seenFinal := false
	for off := streamIDPrefixLen; off < len(data); {
		chunkLen, err := ParseChunkLenCfg(cfg, data[off:])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if seenFinal {
			return ErrStreamAfterFinal
		}
		plain, finalFlag, err := DecryptStreamAuthenticated128Cfg(cfg, noiseSeed, dataSeed, startSeed, data[off:off+chunkLen], macFunc, streamID, cumulative)
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		pixels, err := chunkPixelCountCfg(cfg, data[off:off+chunkLen])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if err := emit(plain); err != nil {
			return err
		}
		cumulative += pixels
		if finalFlag {
			seenFinal = true
		}
		off += chunkLen
	}
	if !seenFinal {
		return ErrStreamTruncated
	}
	return nil
}

// EncryptStreamAuth256Cfg is the Cfg variant of [EncryptStreamAuth256].
func EncryptStreamAuth256Cfg(cfg *Config, noiseSeed, dataSeed, startSeed *Seed256, data []byte, chunkSize int, macFunc MACFunc, emit func(chunk []byte) error) error {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
	}
	if macFunc == nil {
		return fmt.Errorf("itb: macFunc must not be nil")
	}
	if chunkSize <= 0 {
		if len(data) == 0 {
			chunkSize = DefaultChunkSize
		} else {
			chunkSize = ChunkSize(len(data))
		}
	}
	if chunkSize > maxDataSize {
		return fmt.Errorf("itb: chunk size %d exceeds maximum %d bytes", chunkSize, maxDataSize)
	}

	streamID, err := generateStreamID()
	if err != nil {
		return err
	}
	if err := emit(streamID[:]); err != nil {
		return err
	}

	if len(data) == 0 {
		chunk, emitErr := EncryptStreamAuthenticated256Cfg(cfg, noiseSeed, dataSeed, startSeed, nil, macFunc, streamID, 0, true)
		if emitErr != nil {
			return fmt.Errorf("itb: empty-stream chunk: %w", emitErr)
		}
		return emit(chunk)
	}

	var cumulative uint64
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		finalFlag := end == len(data)
		chunk, chunkErr := EncryptStreamAuthenticated256Cfg(cfg, noiseSeed, dataSeed, startSeed, data[off:end], macFunc, streamID, cumulative, finalFlag)
		if chunkErr != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, chunkErr)
		}
		pixels, chunkErr := chunkPixelCountCfg(cfg, chunk)
		if chunkErr != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, chunkErr)
		}
		if err := emit(chunk); err != nil {
			return err
		}
		cumulative += pixels
	}
	return nil
}

// DecryptStreamAuth256Cfg is the Cfg variant of [DecryptStreamAuth256].
func DecryptStreamAuth256Cfg(cfg *Config, noiseSeed, dataSeed, startSeed *Seed256, data []byte, macFunc MACFunc, emit func(chunk []byte) error) error {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
	}
	if macFunc == nil {
		return fmt.Errorf("itb: macFunc must not be nil")
	}
	if len(data) < streamIDPrefixLen {
		return fmt.Errorf("itb: stream too short for stream prefix")
	}

	var streamID [streamIDPrefixLen]byte
	copy(streamID[:], data[:streamIDPrefixLen])

	var cumulative uint64
	seenFinal := false
	for off := streamIDPrefixLen; off < len(data); {
		chunkLen, err := ParseChunkLenCfg(cfg, data[off:])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if seenFinal {
			return ErrStreamAfterFinal
		}
		plain, finalFlag, err := DecryptStreamAuthenticated256Cfg(cfg, noiseSeed, dataSeed, startSeed, data[off:off+chunkLen], macFunc, streamID, cumulative)
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		pixels, err := chunkPixelCountCfg(cfg, data[off:off+chunkLen])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if err := emit(plain); err != nil {
			return err
		}
		cumulative += pixels
		if finalFlag {
			seenFinal = true
		}
		off += chunkLen
	}
	if !seenFinal {
		return ErrStreamTruncated
	}
	return nil
}

// EncryptStreamAuth512Cfg is the Cfg variant of [EncryptStreamAuth512].
func EncryptStreamAuth512Cfg(cfg *Config, noiseSeed, dataSeed, startSeed *Seed512, data []byte, chunkSize int, macFunc MACFunc, emit func(chunk []byte) error) error {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
	}
	if macFunc == nil {
		return fmt.Errorf("itb: macFunc must not be nil")
	}
	if chunkSize <= 0 {
		if len(data) == 0 {
			chunkSize = DefaultChunkSize
		} else {
			chunkSize = ChunkSize(len(data))
		}
	}
	if chunkSize > maxDataSize {
		return fmt.Errorf("itb: chunk size %d exceeds maximum %d bytes", chunkSize, maxDataSize)
	}

	streamID, err := generateStreamID()
	if err != nil {
		return err
	}
	if err := emit(streamID[:]); err != nil {
		return err
	}

	if len(data) == 0 {
		chunk, emitErr := EncryptStreamAuthenticated512Cfg(cfg, noiseSeed, dataSeed, startSeed, nil, macFunc, streamID, 0, true)
		if emitErr != nil {
			return fmt.Errorf("itb: empty-stream chunk: %w", emitErr)
		}
		return emit(chunk)
	}

	var cumulative uint64
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		finalFlag := end == len(data)
		chunk, chunkErr := EncryptStreamAuthenticated512Cfg(cfg, noiseSeed, dataSeed, startSeed, data[off:end], macFunc, streamID, cumulative, finalFlag)
		if chunkErr != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, chunkErr)
		}
		pixels, chunkErr := chunkPixelCountCfg(cfg, chunk)
		if chunkErr != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, chunkErr)
		}
		if err := emit(chunk); err != nil {
			return err
		}
		cumulative += pixels
	}
	return nil
}

// DecryptStreamAuth512Cfg is the Cfg variant of [DecryptStreamAuth512].
func DecryptStreamAuth512Cfg(cfg *Config, noiseSeed, dataSeed, startSeed *Seed512, data []byte, macFunc MACFunc, emit func(chunk []byte) error) error {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
	}
	if macFunc == nil {
		return fmt.Errorf("itb: macFunc must not be nil")
	}
	if len(data) < streamIDPrefixLen {
		return fmt.Errorf("itb: stream too short for stream prefix")
	}

	var streamID [streamIDPrefixLen]byte
	copy(streamID[:], data[:streamIDPrefixLen])

	var cumulative uint64
	seenFinal := false
	for off := streamIDPrefixLen; off < len(data); {
		chunkLen, err := ParseChunkLenCfg(cfg, data[off:])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if seenFinal {
			return ErrStreamAfterFinal
		}
		plain, finalFlag, err := DecryptStreamAuthenticated512Cfg(cfg, noiseSeed, dataSeed, startSeed, data[off:off+chunkLen], macFunc, streamID, cumulative)
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		pixels, err := chunkPixelCountCfg(cfg, data[off:off+chunkLen])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if err := emit(plain); err != nil {
			return err
		}
		cumulative += pixels
		if finalFlag {
			seenFinal = true
		}
		off += chunkLen
	}
	if !seenFinal {
		return ErrStreamTruncated
	}
	return nil
}

// EncryptStreamAuth3x128Cfg is the Cfg variant of [EncryptStreamAuth3x128].
func EncryptStreamAuth3x128Cfg(cfg *Config, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed128, data []byte, chunkSize int, macFunc MACFunc, emit func(chunk []byte) error) error {
	if err := checkSevenSeeds128(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return err
	}
	if macFunc == nil {
		return fmt.Errorf("itb: macFunc must not be nil")
	}
	if chunkSize <= 0 {
		if len(data) == 0 {
			chunkSize = DefaultChunkSize
		} else {
			chunkSize = ChunkSize(len(data))
		}
	}
	if chunkSize > maxDataSize {
		return fmt.Errorf("itb: chunk size %d exceeds maximum %d bytes", chunkSize, maxDataSize)
	}

	streamID, err := generateStreamID()
	if err != nil {
		return err
	}
	if err := emit(streamID[:]); err != nil {
		return err
	}

	if len(data) == 0 {
		chunk, emitErr := EncryptStreamAuthenticated3x128Cfg(cfg, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, nil, macFunc, streamID, 0, true)
		if emitErr != nil {
			return fmt.Errorf("itb: empty-stream chunk: %w", emitErr)
		}
		return emit(chunk)
	}

	var cumulative uint64
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		finalFlag := end == len(data)
		chunk, chunkErr := EncryptStreamAuthenticated3x128Cfg(cfg, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:end], macFunc, streamID, cumulative, finalFlag)
		if chunkErr != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, chunkErr)
		}
		pixels, chunkErr := chunkPixelCountCfg(cfg, chunk)
		if chunkErr != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, chunkErr)
		}
		if err := emit(chunk); err != nil {
			return err
		}
		cumulative += pixels
	}
	return nil
}

// DecryptStreamAuth3x128Cfg is the Cfg variant of [DecryptStreamAuth3x128].
func DecryptStreamAuth3x128Cfg(cfg *Config, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed128, data []byte, macFunc MACFunc, emit func(chunk []byte) error) error {
	if err := checkSevenSeeds128(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return err
	}
	if macFunc == nil {
		return fmt.Errorf("itb: macFunc must not be nil")
	}
	if len(data) < streamIDPrefixLen {
		return fmt.Errorf("itb: stream too short for stream prefix")
	}

	var streamID [streamIDPrefixLen]byte
	copy(streamID[:], data[:streamIDPrefixLen])

	var cumulative uint64
	seenFinal := false
	for off := streamIDPrefixLen; off < len(data); {
		chunkLen, err := ParseChunkLenCfg(cfg, data[off:])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if seenFinal {
			return ErrStreamAfterFinal
		}
		plain, finalFlag, err := DecryptStreamAuthenticated3x128Cfg(cfg, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:off+chunkLen], macFunc, streamID, cumulative)
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		pixels, err := chunkPixelCountCfg(cfg, data[off:off+chunkLen])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if err := emit(plain); err != nil {
			return err
		}
		cumulative += pixels
		if finalFlag {
			seenFinal = true
		}
		off += chunkLen
	}
	if !seenFinal {
		return ErrStreamTruncated
	}
	return nil
}

// EncryptStreamAuth3x256Cfg is the Cfg variant of [EncryptStreamAuth3x256].
func EncryptStreamAuth3x256Cfg(cfg *Config, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed256, data []byte, chunkSize int, macFunc MACFunc, emit func(chunk []byte) error) error {
	if err := checkSevenSeeds256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return err
	}
	if macFunc == nil {
		return fmt.Errorf("itb: macFunc must not be nil")
	}
	if chunkSize <= 0 {
		if len(data) == 0 {
			chunkSize = DefaultChunkSize
		} else {
			chunkSize = ChunkSize(len(data))
		}
	}
	if chunkSize > maxDataSize {
		return fmt.Errorf("itb: chunk size %d exceeds maximum %d bytes", chunkSize, maxDataSize)
	}

	streamID, err := generateStreamID()
	if err != nil {
		return err
	}
	if err := emit(streamID[:]); err != nil {
		return err
	}

	if len(data) == 0 {
		chunk, emitErr := EncryptStreamAuthenticated3x256Cfg(cfg, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, nil, macFunc, streamID, 0, true)
		if emitErr != nil {
			return fmt.Errorf("itb: empty-stream chunk: %w", emitErr)
		}
		return emit(chunk)
	}

	var cumulative uint64
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		finalFlag := end == len(data)
		chunk, chunkErr := EncryptStreamAuthenticated3x256Cfg(cfg, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:end], macFunc, streamID, cumulative, finalFlag)
		if chunkErr != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, chunkErr)
		}
		pixels, chunkErr := chunkPixelCountCfg(cfg, chunk)
		if chunkErr != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, chunkErr)
		}
		if err := emit(chunk); err != nil {
			return err
		}
		cumulative += pixels
	}
	return nil
}

// DecryptStreamAuth3x256Cfg is the Cfg variant of [DecryptStreamAuth3x256].
func DecryptStreamAuth3x256Cfg(cfg *Config, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed256, data []byte, macFunc MACFunc, emit func(chunk []byte) error) error {
	if err := checkSevenSeeds256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return err
	}
	if macFunc == nil {
		return fmt.Errorf("itb: macFunc must not be nil")
	}
	if len(data) < streamIDPrefixLen {
		return fmt.Errorf("itb: stream too short for stream prefix")
	}

	var streamID [streamIDPrefixLen]byte
	copy(streamID[:], data[:streamIDPrefixLen])

	var cumulative uint64
	seenFinal := false
	for off := streamIDPrefixLen; off < len(data); {
		chunkLen, err := ParseChunkLenCfg(cfg, data[off:])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if seenFinal {
			return ErrStreamAfterFinal
		}
		plain, finalFlag, err := DecryptStreamAuthenticated3x256Cfg(cfg, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:off+chunkLen], macFunc, streamID, cumulative)
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		pixels, err := chunkPixelCountCfg(cfg, data[off:off+chunkLen])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if err := emit(plain); err != nil {
			return err
		}
		cumulative += pixels
		if finalFlag {
			seenFinal = true
		}
		off += chunkLen
	}
	if !seenFinal {
		return ErrStreamTruncated
	}
	return nil
}

// EncryptStreamAuth3x512Cfg is the Cfg variant of [EncryptStreamAuth3x512].
func EncryptStreamAuth3x512Cfg(cfg *Config, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed512, data []byte, chunkSize int, macFunc MACFunc, emit func(chunk []byte) error) error {
	if err := checkSevenSeeds512(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return err
	}
	if macFunc == nil {
		return fmt.Errorf("itb: macFunc must not be nil")
	}
	if chunkSize <= 0 {
		if len(data) == 0 {
			chunkSize = DefaultChunkSize
		} else {
			chunkSize = ChunkSize(len(data))
		}
	}
	if chunkSize > maxDataSize {
		return fmt.Errorf("itb: chunk size %d exceeds maximum %d bytes", chunkSize, maxDataSize)
	}

	streamID, err := generateStreamID()
	if err != nil {
		return err
	}
	if err := emit(streamID[:]); err != nil {
		return err
	}

	if len(data) == 0 {
		chunk, emitErr := EncryptStreamAuthenticated3x512Cfg(cfg, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, nil, macFunc, streamID, 0, true)
		if emitErr != nil {
			return fmt.Errorf("itb: empty-stream chunk: %w", emitErr)
		}
		return emit(chunk)
	}

	var cumulative uint64
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		finalFlag := end == len(data)
		chunk, chunkErr := EncryptStreamAuthenticated3x512Cfg(cfg, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:end], macFunc, streamID, cumulative, finalFlag)
		if chunkErr != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, chunkErr)
		}
		pixels, chunkErr := chunkPixelCountCfg(cfg, chunk)
		if chunkErr != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, chunkErr)
		}
		if err := emit(chunk); err != nil {
			return err
		}
		cumulative += pixels
	}
	return nil
}

// DecryptStreamAuth3x512Cfg is the Cfg variant of [DecryptStreamAuth3x512].
func DecryptStreamAuth3x512Cfg(cfg *Config, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed512, data []byte, macFunc MACFunc, emit func(chunk []byte) error) error {
	if err := checkSevenSeeds512(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return err
	}
	if macFunc == nil {
		return fmt.Errorf("itb: macFunc must not be nil")
	}
	if len(data) < streamIDPrefixLen {
		return fmt.Errorf("itb: stream too short for stream prefix")
	}

	var streamID [streamIDPrefixLen]byte
	copy(streamID[:], data[:streamIDPrefixLen])

	var cumulative uint64
	seenFinal := false
	for off := streamIDPrefixLen; off < len(data); {
		chunkLen, err := ParseChunkLenCfg(cfg, data[off:])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if seenFinal {
			return ErrStreamAfterFinal
		}
		plain, finalFlag, err := DecryptStreamAuthenticated3x512Cfg(cfg, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:off+chunkLen], macFunc, streamID, cumulative)
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		pixels, err := chunkPixelCountCfg(cfg, data[off:off+chunkLen])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if err := emit(plain); err != nil {
			return err
		}
		cumulative += pixels
		if finalFlag {
			seenFinal = true
		}
		off += chunkLen
	}
	if !seenFinal {
		return ErrStreamTruncated
	}
	return nil
}
