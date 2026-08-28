package itb

import (
	"encoding/binary"
	"fmt"
	"math"
)

// DefaultChunkSize is the default chunk size for streaming encryption (16 MB).
const DefaultChunkSize = 16 << 20

// ChunkSize returns an appropriate chunk size for the given total data length.
// For small data (≤16 MB): encrypts in a single chunk.
// For medium data (≤256 MB): uses 16 MB chunks.
// For large data (>256 MB): uses 64 MB chunks.
func ChunkSize(dataLen int) int {
	if dataLen <= DefaultChunkSize {
		return dataLen
	}
	if dataLen <= 256<<20 {
		return DefaultChunkSize
	}
	return 64 << 20
}

// ParseChunkLenCfg reads a chunk header and returns the total chunk
// size in bytes. Consults cfg for the per-encryptor nonce-bits
// override so a non-nil cfg with an explicit NonceBits is honoured at
// the header parse site. The chunk wire format is:
//
//	[main nonce][interlock nonce][2-byte width BE][2-byte height BE][W*H*8 container]
//
// Returns an error when the supplied buffer is shorter than the
// fixed header size, the dimensions are zero / overflow / exceed
// the container cap, or the buffer does not contain enough trailing
// bytes for the announced container body.
//
// Streaming consumers use ParseChunkLenCfg to walk a concatenated
// stream of ITB ciphertexts on disk or over the wire one chunk at
// a time without buffering the entire stream in memory: read the
// fixed header, call ParseChunkLenCfg to learn the chunk size, read
// that many bytes, hand them to the matching Decrypt*Cfg entry point,
// repeat.
func ParseChunkLenCfg(cfg *Config, data []byte) (int, error) {
	if len(data) < headerSizeCfg(cfg) {
		return 0, fmt.Errorf("data too short for header")
	}

	nonceLen := currentNonceSizeCfg(cfg)
	width := int(binary.BigEndian.Uint16(data[2*nonceLen:]))
	height := int(binary.BigEndian.Uint16(data[2*nonceLen+2:]))

	if width == 0 || height == 0 {
		return 0, fmt.Errorf("invalid dimensions %dx%d", width, height)
	}
	if width > math.MaxInt/height {
		return 0, fmt.Errorf("dimensions %dx%d overflow", width, height)
	}
	totalPixels := width * height
	if totalPixels > math.MaxInt/Channels {
		return 0, fmt.Errorf("container too large: %d pixels", totalPixels)
	}
	if totalPixels > maxTotalPixels {
		return 0, fmt.Errorf("chunk too large: %d pixels exceeds maximum %d", totalPixels, maxTotalPixels)
	}

	chunkLen := headerSizeCfg(cfg) + totalPixels*Channels
	if len(data) < chunkLen {
		return 0, fmt.Errorf("data too short: need %d, have %d", chunkLen, len(data))
	}

	return chunkLen, nil
}

// --- Triple Ouroboros streaming (7-seed) ---

// EncryptStream3x128Cfg encrypts data in chunks using Triple Ouroboros
// (128-bit variant). Emits a 32-byte CSPRNG dummy prefix ahead of the
// chunk stream so the envelope shape matches the Streaming AEAD
// variant bit-for-bit — a wire observer cannot distinguish the two.
func EncryptStream3x128Cfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed128, data []byte, chunkSize int, emit func(chunk []byte) error) error {
	if err := checkEightSeeds128(noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("itb: empty data")
	}
	if chunkSize <= 0 {
		chunkSize = ChunkSize(len(data))
	}
	if chunkSize > maxDataSize {
		return fmt.Errorf("itb: chunk size %d exceeds maximum %d bytes", chunkSize, maxDataSize)
	}
	prefix, err := nomacStreamPrefix()
	if err != nil {
		return err
	}
	if err := emit(prefix); err != nil {
		return err
	}
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk, err := Encrypt3x128Cfg(cfg, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:end])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if err := emit(chunk); err != nil {
			return err
		}
	}
	return nil
}

// DecryptStream3x128Cfg decrypts concatenated chunks produced by
// [EncryptStream3x128Cfg]. Skips the 32-byte envelope prefix at the
// front of data; an empty data slice is treated as a clean
// end-of-stream before the prefix arrives.
func DecryptStream3x128Cfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed128, data []byte, emit func(chunk []byte) error) error {
	if err := checkEightSeeds128(noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	if len(data) < streamIDPrefixLen {
		return fmt.Errorf("itb: stream too short for stream prefix")
	}
	for off := streamIDPrefixLen; off < len(data); {
		chunkLen, err := ParseChunkLenCfg(cfg, data[off:])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		decrypted, err := Decrypt3x128Cfg(cfg, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:off+chunkLen])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if err := emit(decrypted); err != nil {
			return err
		}
		off += chunkLen
	}
	return nil
}

// EncryptStream3x256Cfg encrypts data in chunks using Triple Ouroboros
// (256-bit variant). See [EncryptStream3x128Cfg] for the envelope shape.
func EncryptStream3x256Cfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed256, data []byte, chunkSize int, emit func(chunk []byte) error) error {
	if err := checkEightSeeds256(noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("itb: empty data")
	}
	if chunkSize <= 0 {
		chunkSize = ChunkSize(len(data))
	}
	if chunkSize > maxDataSize {
		return fmt.Errorf("itb: chunk size %d exceeds maximum %d bytes", chunkSize, maxDataSize)
	}
	prefix, err := nomacStreamPrefix()
	if err != nil {
		return err
	}
	if err := emit(prefix); err != nil {
		return err
	}
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk, err := Encrypt3x256Cfg(cfg, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:end])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if err := emit(chunk); err != nil {
			return err
		}
	}
	return nil
}

// DecryptStream3x256Cfg decrypts concatenated chunks produced by
// [EncryptStream3x256Cfg]. See [DecryptStream3x128Cfg] for the envelope
// contract.
func DecryptStream3x256Cfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed256, data []byte, emit func(chunk []byte) error) error {
	if err := checkEightSeeds256(noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	if len(data) < streamIDPrefixLen {
		return fmt.Errorf("itb: stream too short for stream prefix")
	}
	for off := streamIDPrefixLen; off < len(data); {
		chunkLen, err := ParseChunkLenCfg(cfg, data[off:])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		decrypted, err := Decrypt3x256Cfg(cfg, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:off+chunkLen])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if err := emit(decrypted); err != nil {
			return err
		}
		off += chunkLen
	}
	return nil
}

// EncryptStream3x512Cfg encrypts data in chunks using Triple Ouroboros
// (512-bit variant). See [EncryptStream3x128Cfg] for the envelope shape.
func EncryptStream3x512Cfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed512, data []byte, chunkSize int, emit func(chunk []byte) error) error {
	if err := checkEightSeeds512(noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("itb: empty data")
	}
	if chunkSize <= 0 {
		chunkSize = ChunkSize(len(data))
	}
	if chunkSize > maxDataSize {
		return fmt.Errorf("itb: chunk size %d exceeds maximum %d bytes", chunkSize, maxDataSize)
	}
	prefix, err := nomacStreamPrefix()
	if err != nil {
		return err
	}
	if err := emit(prefix); err != nil {
		return err
	}
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk, err := Encrypt3x512Cfg(cfg, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:end])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if err := emit(chunk); err != nil {
			return err
		}
	}
	return nil
}

// DecryptStream3x512Cfg decrypts concatenated chunks produced by
// [EncryptStream3x512Cfg]. See [DecryptStream3x128Cfg] for the envelope
// contract.
func DecryptStream3x512Cfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed512, data []byte, emit func(chunk []byte) error) error {
	if err := checkEightSeeds512(noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	if len(data) < streamIDPrefixLen {
		return fmt.Errorf("itb: stream too short for stream prefix")
	}
	for off := streamIDPrefixLen; off < len(data); {
		chunkLen, err := ParseChunkLenCfg(cfg, data[off:])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		decrypted, err := Decrypt3x512Cfg(cfg, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:off+chunkLen])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if err := emit(decrypted); err != nil {
			return err
		}
		off += chunkLen
	}
	return nil
}
