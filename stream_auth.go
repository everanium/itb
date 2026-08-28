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

// chunkPixelCountCfg reads the W and H header values from a streaming
// chunk's wire bytes and returns W * H. Consults cfg for the
// per-encryptor nonce-bits override at the chunk-header parse site.
func chunkPixelCountCfg(cfg *Config, chunk []byte) (uint64, error) {
	if len(chunk) < headerSizeCfg(cfg) {
		return 0, fmt.Errorf("itb: chunk too short for header")
	}
	nonceLen := currentNonceSizeCfg(cfg)
	width := uint64(binary.BigEndian.Uint16(chunk[2*nonceLen:]))
	height := uint64(binary.BigEndian.Uint16(chunk[2*nonceLen+2:]))
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

// --- Triple Ouroboros (7-seed) Cfg variants ---

// EncryptStreamAuth3x128Cfg mirrors the wide-stream User-Driven Loop
// encrypt shape for Triple Ouroboros (7-seed) at 128-bit hash width.
// Generates a fresh 32-byte stream anchor, emits it as the first wire
// chunk, then loops over data in chunkSize windows calling
// [EncryptStreamAuthenticated3x128Cfg] per chunk with the running
// cumulative pixel offset and finalFlag = true on the last chunk. nil
// cfg falls back to the compile-in defaults.
func EncryptStreamAuth3x128Cfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed128, data []byte, chunkSize int, macFunc MACFunc, emit func(chunk []byte) error) error {
	if err := checkEightSeeds128(noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
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
		chunk, emitErr := EncryptStreamAuthenticated3x128Cfg(cfg, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, nil, macFunc, streamID, 0, true)
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
		chunk, chunkErr := EncryptStreamAuthenticated3x128Cfg(cfg, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:end], macFunc, streamID, cumulative, finalFlag)
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

// DecryptStreamAuth3x128Cfg is the inverse of [EncryptStreamAuth3x128Cfg].
func DecryptStreamAuth3x128Cfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed128, data []byte, macFunc MACFunc, emit func(chunk []byte) error) error {
	if err := checkEightSeeds128(noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
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
		plain, finalFlag, err := DecryptStreamAuthenticated3x128Cfg(cfg, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:off+chunkLen], macFunc, streamID, cumulative)
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

// EncryptStreamAuth3x256Cfg mirrors [EncryptStreamAuth3x128Cfg] for
// Triple Ouroboros (7-seed) at 256-bit hash width.
func EncryptStreamAuth3x256Cfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed256, data []byte, chunkSize int, macFunc MACFunc, emit func(chunk []byte) error) error {
	if err := checkEightSeeds256(noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
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
		chunk, emitErr := EncryptStreamAuthenticated3x256Cfg(cfg, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, nil, macFunc, streamID, 0, true)
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
		chunk, chunkErr := EncryptStreamAuthenticated3x256Cfg(cfg, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:end], macFunc, streamID, cumulative, finalFlag)
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

// DecryptStreamAuth3x256Cfg is the inverse of [EncryptStreamAuth3x256Cfg].
func DecryptStreamAuth3x256Cfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed256, data []byte, macFunc MACFunc, emit func(chunk []byte) error) error {
	if err := checkEightSeeds256(noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
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
		plain, finalFlag, err := DecryptStreamAuthenticated3x256Cfg(cfg, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:off+chunkLen], macFunc, streamID, cumulative)
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

// EncryptStreamAuth3x512Cfg mirrors [EncryptStreamAuth3x128Cfg] for
// Triple Ouroboros (7-seed) at 512-bit hash width.
func EncryptStreamAuth3x512Cfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed512, data []byte, chunkSize int, macFunc MACFunc, emit func(chunk []byte) error) error {
	if err := checkEightSeeds512(noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
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
		chunk, emitErr := EncryptStreamAuthenticated3x512Cfg(cfg, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, nil, macFunc, streamID, 0, true)
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
		chunk, chunkErr := EncryptStreamAuthenticated3x512Cfg(cfg, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:end], macFunc, streamID, cumulative, finalFlag)
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

// DecryptStreamAuth3x512Cfg is the inverse of [EncryptStreamAuth3x512Cfg].
func DecryptStreamAuth3x512Cfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed512, data []byte, macFunc MACFunc, emit func(chunk []byte) error) error {
	if err := checkEightSeeds512(noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
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
		plain, finalFlag, err := DecryptStreamAuthenticated3x512Cfg(cfg, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:off+chunkLen], macFunc, streamID, cumulative)
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
