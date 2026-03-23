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

// --- 128-bit variants ---

// EncryptStream128 encrypts data in chunks using 128-bit hash seeds.
func EncryptStream128(noiseSeed, dataSeed, startSeed *Seed128, data []byte, chunkSize int, emit func(chunk []byte) error) error {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
	}
	if len(data) == 0 {
		return fmt.Errorf("itb: empty data")
	}
	if chunkSize <= 0 {
		chunkSize = ChunkSize(len(data))
	}

	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk, err := Encrypt128(noiseSeed, dataSeed, startSeed, data[off:end])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if err := emit(chunk); err != nil {
			return err
		}
	}
	return nil
}

// DecryptStream128 decrypts concatenated chunks produced by EncryptStream128.
func DecryptStream128(noiseSeed, dataSeed, startSeed *Seed128, data []byte, emit func(chunk []byte) error) error {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
	}

	for off := 0; off < len(data); {
		chunkLen, err := parseChunkLen(data[off:])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		decrypted, err := Decrypt128(noiseSeed, dataSeed, startSeed, data[off:off+chunkLen])
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

// --- 256-bit variants ---

// EncryptStream256 encrypts data in chunks using 256-bit hash seeds.
func EncryptStream256(noiseSeed, dataSeed, startSeed *Seed256, data []byte, chunkSize int, emit func(chunk []byte) error) error {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
	}
	if len(data) == 0 {
		return fmt.Errorf("itb: empty data")
	}
	if chunkSize <= 0 {
		chunkSize = ChunkSize(len(data))
	}

	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk, err := Encrypt256(noiseSeed, dataSeed, startSeed, data[off:end])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if err := emit(chunk); err != nil {
			return err
		}
	}
	return nil
}

// DecryptStream256 decrypts concatenated chunks produced by EncryptStream256.
func DecryptStream256(noiseSeed, dataSeed, startSeed *Seed256, data []byte, emit func(chunk []byte) error) error {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
	}

	for off := 0; off < len(data); {
		chunkLen, err := parseChunkLen(data[off:])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		decrypted, err := Decrypt256(noiseSeed, dataSeed, startSeed, data[off:off+chunkLen])
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

// --- 512-bit variants ---

// EncryptStream512 encrypts data in chunks using 512-bit hash seeds.
func EncryptStream512(noiseSeed, dataSeed, startSeed *Seed512, data []byte, chunkSize int, emit func(chunk []byte) error) error {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
	}
	if len(data) == 0 {
		return fmt.Errorf("itb: empty data")
	}
	if chunkSize <= 0 {
		chunkSize = ChunkSize(len(data))
	}

	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk, err := Encrypt512(noiseSeed, dataSeed, startSeed, data[off:end])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if err := emit(chunk); err != nil {
			return err
		}
	}
	return nil
}

// DecryptStream512 decrypts concatenated chunks produced by EncryptStream512.
func DecryptStream512(noiseSeed, dataSeed, startSeed *Seed512, data []byte, emit func(chunk []byte) error) error {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
	}

	for off := 0; off < len(data); {
		chunkLen, err := parseChunkLen(data[off:])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		decrypted, err := Decrypt512(noiseSeed, dataSeed, startSeed, data[off:off+chunkLen])
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

// parseChunkLen reads a chunk header and returns the total chunk size in bytes.
// Format: [16-byte nonce][2-byte width BE][2-byte height BE][W*H*8 container]
func parseChunkLen(data []byte) (int, error) {
	if len(data) < headerSize {
		return 0, fmt.Errorf("data too short for header")
	}

	width := int(binary.BigEndian.Uint16(data[NonceSize:]))
	height := int(binary.BigEndian.Uint16(data[NonceSize+2:]))

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

	chunkLen := headerSize + totalPixels*Channels
	if len(data) < chunkLen {
		return 0, fmt.Errorf("data too short: need %d, have %d", chunkLen, len(data))
	}

	return chunkLen, nil
}
