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
	if chunkSize > maxDataSize {
		return fmt.Errorf("itb: chunk size %d exceeds maximum %d bytes", chunkSize, maxDataSize)
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
		chunkLen, err := ParseChunkLen(data[off:])
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
	if chunkSize > maxDataSize {
		return fmt.Errorf("itb: chunk size %d exceeds maximum %d bytes", chunkSize, maxDataSize)
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
		chunkLen, err := ParseChunkLen(data[off:])
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
	if chunkSize > maxDataSize {
		return fmt.Errorf("itb: chunk size %d exceeds maximum %d bytes", chunkSize, maxDataSize)
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
		chunkLen, err := ParseChunkLen(data[off:])
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

// ParseChunkLen reads a chunk header and returns the total chunk size
// in bytes. The chunk wire format is identical to a single-chunk
// ITB ciphertext:
//
//	[16-byte nonce][2-byte width BE][2-byte height BE][W*H*8 container]
//
// Returns an error when the supplied buffer is shorter than the
// fixed header size, the dimensions are zero / overflow / exceed
// the container cap, or the buffer does not contain enough trailing
// bytes for the announced container body.
//
// Streaming consumers use ParseChunkLen to walk a concatenated
// stream of ITB ciphertexts on disk or over the wire one chunk at
// a time without buffering the entire stream in memory: read the
// fixed header, call ParseChunkLen to learn the chunk size, read
// that many bytes, hand them to Decrypt{128,256,512} (or the
// matching Decrypt3x* / DecryptAuthenticated* / etc.), repeat. The
// FFI surface re-exports the same function as ITB_ParseChunkLen.
func ParseChunkLen(data []byte) (int, error) {
	if len(data) < headerSize() {
		return 0, fmt.Errorf("data too short for header")
	}

	width := int(binary.BigEndian.Uint16(data[currentNonceSize():]))
	height := int(binary.BigEndian.Uint16(data[currentNonceSize()+2:]))

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

	chunkLen := headerSize() + totalPixels*Channels
	if len(data) < chunkLen {
		return 0, fmt.Errorf("data too short: need %d, have %d", chunkLen, len(data))
	}

	return chunkLen, nil
}

// --- Triple Ouroboros streaming (7-seed) ---

// EncryptStream3x128 encrypts data in chunks using Triple Ouroboros (128-bit variant).
func EncryptStream3x128(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed128, data []byte, chunkSize int, emit func(chunk []byte) error) error {
	if err := checkSevenSeeds128(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
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
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk, err := Encrypt3x128(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:end])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if err := emit(chunk); err != nil {
			return err
		}
	}
	return nil
}

// DecryptStream3x128 decrypts concatenated chunks produced by EncryptStream3x128.
func DecryptStream3x128(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed128, data []byte, emit func(chunk []byte) error) error {
	if err := checkSevenSeeds128(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return err
	}
	for off := 0; off < len(data); {
		chunkLen, err := ParseChunkLen(data[off:])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		decrypted, err := Decrypt3x128(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:off+chunkLen])
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

// EncryptStream3x256 encrypts data in chunks using Triple Ouroboros (256-bit variant).
func EncryptStream3x256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed256, data []byte, chunkSize int, emit func(chunk []byte) error) error {
	if err := checkSevenSeeds256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
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
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk, err := Encrypt3x256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:end])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if err := emit(chunk); err != nil {
			return err
		}
	}
	return nil
}

// DecryptStream3x256 decrypts concatenated chunks produced by EncryptStream3x256.
func DecryptStream3x256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed256, data []byte, emit func(chunk []byte) error) error {
	if err := checkSevenSeeds256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return err
	}
	for off := 0; off < len(data); {
		chunkLen, err := ParseChunkLen(data[off:])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		decrypted, err := Decrypt3x256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:off+chunkLen])
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

// EncryptStream3x512 encrypts data in chunks using Triple Ouroboros (512-bit variant).
func EncryptStream3x512(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed512, data []byte, chunkSize int, emit func(chunk []byte) error) error {
	if err := checkSevenSeeds512(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
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
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk, err := Encrypt3x512(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:end])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if err := emit(chunk); err != nil {
			return err
		}
	}
	return nil
}

// DecryptStream3x512 decrypts concatenated chunks produced by EncryptStream3x512.
func DecryptStream3x512(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed512, data []byte, emit func(chunk []byte) error) error {
	if err := checkSevenSeeds512(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return err
	}
	for off := 0; off < len(data); {
		chunkLen, err := ParseChunkLen(data[off:])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		decrypted, err := Decrypt3x512(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:off+chunkLen])
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

// ParseChunkLenCfg is the Cfg variant of [ParseChunkLen]: consults
// [currentNonceSizeCfg] and [headerSizeCfg] so a non-nil cfg with an
// explicit NonceBits override is honoured at the chunk-header parse
// site. Body otherwise identical.
func ParseChunkLenCfg(cfg *Config, data []byte) (int, error) {
	if len(data) < headerSizeCfg(cfg) {
		return 0, fmt.Errorf("data too short for header")
	}

	nonceLen := currentNonceSizeCfg(cfg)
	width := int(binary.BigEndian.Uint16(data[nonceLen:]))
	height := int(binary.BigEndian.Uint16(data[nonceLen+2:]))

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

// EncryptStream128Cfg is the Cfg variant of [EncryptStream128]: drives
// each chunk through [Encrypt128Cfg] so per-encryptor NonceBits /
// BarrierFill / BitSoup / LockSoup / LockSeed overrides are honoured
// chunk-by-chunk. Body otherwise identical.
func EncryptStream128Cfg(cfg *Config, noiseSeed, dataSeed, startSeed *Seed128, data []byte, chunkSize int, emit func(chunk []byte) error) error {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
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

	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk, err := Encrypt128Cfg(cfg, noiseSeed, dataSeed, startSeed, data[off:end])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if err := emit(chunk); err != nil {
			return err
		}
	}
	return nil
}

// DecryptStream128Cfg is the Cfg variant of [DecryptStream128].
func DecryptStream128Cfg(cfg *Config, noiseSeed, dataSeed, startSeed *Seed128, data []byte, emit func(chunk []byte) error) error {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
	}

	for off := 0; off < len(data); {
		chunkLen, err := ParseChunkLenCfg(cfg, data[off:])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		decrypted, err := Decrypt128Cfg(cfg, noiseSeed, dataSeed, startSeed, data[off:off+chunkLen])
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

// EncryptStream256Cfg is the Cfg variant of [EncryptStream256].
func EncryptStream256Cfg(cfg *Config, noiseSeed, dataSeed, startSeed *Seed256, data []byte, chunkSize int, emit func(chunk []byte) error) error {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
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

	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk, err := Encrypt256Cfg(cfg, noiseSeed, dataSeed, startSeed, data[off:end])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if err := emit(chunk); err != nil {
			return err
		}
	}
	return nil
}

// DecryptStream256Cfg is the Cfg variant of [DecryptStream256].
func DecryptStream256Cfg(cfg *Config, noiseSeed, dataSeed, startSeed *Seed256, data []byte, emit func(chunk []byte) error) error {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
	}

	for off := 0; off < len(data); {
		chunkLen, err := ParseChunkLenCfg(cfg, data[off:])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		decrypted, err := Decrypt256Cfg(cfg, noiseSeed, dataSeed, startSeed, data[off:off+chunkLen])
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

// EncryptStream512Cfg is the Cfg variant of [EncryptStream512].
func EncryptStream512Cfg(cfg *Config, noiseSeed, dataSeed, startSeed *Seed512, data []byte, chunkSize int, emit func(chunk []byte) error) error {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
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

	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk, err := Encrypt512Cfg(cfg, noiseSeed, dataSeed, startSeed, data[off:end])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if err := emit(chunk); err != nil {
			return err
		}
	}
	return nil
}

// DecryptStream512Cfg is the Cfg variant of [DecryptStream512].
func DecryptStream512Cfg(cfg *Config, noiseSeed, dataSeed, startSeed *Seed512, data []byte, emit func(chunk []byte) error) error {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
	}

	for off := 0; off < len(data); {
		chunkLen, err := ParseChunkLenCfg(cfg, data[off:])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		decrypted, err := Decrypt512Cfg(cfg, noiseSeed, dataSeed, startSeed, data[off:off+chunkLen])
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

// EncryptStream3x128Cfg is the Cfg variant of [EncryptStream3x128].
func EncryptStream3x128Cfg(cfg *Config, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed128, data []byte, chunkSize int, emit func(chunk []byte) error) error {
	if err := checkSevenSeeds128(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
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
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk, err := Encrypt3x128Cfg(cfg, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:end])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if err := emit(chunk); err != nil {
			return err
		}
	}
	return nil
}

// DecryptStream3x128Cfg is the Cfg variant of [DecryptStream3x128].
func DecryptStream3x128Cfg(cfg *Config, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed128, data []byte, emit func(chunk []byte) error) error {
	if err := checkSevenSeeds128(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return err
	}
	for off := 0; off < len(data); {
		chunkLen, err := ParseChunkLenCfg(cfg, data[off:])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		decrypted, err := Decrypt3x128Cfg(cfg, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:off+chunkLen])
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

// EncryptStream3x256Cfg is the Cfg variant of [EncryptStream3x256].
func EncryptStream3x256Cfg(cfg *Config, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed256, data []byte, chunkSize int, emit func(chunk []byte) error) error {
	if err := checkSevenSeeds256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
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
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk, err := Encrypt3x256Cfg(cfg, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:end])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if err := emit(chunk); err != nil {
			return err
		}
	}
	return nil
}

// DecryptStream3x256Cfg is the Cfg variant of [DecryptStream3x256].
func DecryptStream3x256Cfg(cfg *Config, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed256, data []byte, emit func(chunk []byte) error) error {
	if err := checkSevenSeeds256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return err
	}
	for off := 0; off < len(data); {
		chunkLen, err := ParseChunkLenCfg(cfg, data[off:])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		decrypted, err := Decrypt3x256Cfg(cfg, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:off+chunkLen])
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

// EncryptStream3x512Cfg is the Cfg variant of [EncryptStream3x512].
func EncryptStream3x512Cfg(cfg *Config, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed512, data []byte, chunkSize int, emit func(chunk []byte) error) error {
	if err := checkSevenSeeds512(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
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
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk, err := Encrypt3x512Cfg(cfg, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:end])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		if err := emit(chunk); err != nil {
			return err
		}
	}
	return nil
}

// DecryptStream3x512Cfg is the Cfg variant of [DecryptStream3x512].
func DecryptStream3x512Cfg(cfg *Config, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed512, data []byte, emit func(chunk []byte) error) error {
	if err := checkSevenSeeds512(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return err
	}
	for off := 0; off < len(data); {
		chunkLen, err := ParseChunkLenCfg(cfg, data[off:])
		if err != nil {
			return fmt.Errorf("itb: chunk at offset %d: %w", off, err)
		}
		decrypted, err := Decrypt3x512Cfg(cfg, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data[off:off+chunkLen])
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
