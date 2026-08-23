// Package-level short-name aliases for the EncryptAuthenticated* /
// DecryptAuthenticated* family. Each alias forwards directly to the
// long-name implementation; the alias surface is allocation-free.

package itb

// --- 128-bit variants ---

// EncryptAuth3x128Cfg is an alias for [EncryptAuthenticated3x128Cfg].
func EncryptAuth3x128Cfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed128, data []byte, macFunc MACFunc) ([]byte, error) {
	return EncryptAuthenticated3x128Cfg(cfg, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data, macFunc)
}

// DecryptAuth3x128Cfg is an alias for [DecryptAuthenticated3x128Cfg].
func DecryptAuth3x128Cfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed128, fileData []byte, macFunc MACFunc) ([]byte, error) {
	return DecryptAuthenticated3x128Cfg(cfg, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, fileData, macFunc)
}

// --- 256-bit variants ---

// EncryptAuth3x256Cfg is an alias for [EncryptAuthenticated3x256Cfg].
func EncryptAuth3x256Cfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed256, data []byte, macFunc MACFunc) ([]byte, error) {
	return EncryptAuthenticated3x256Cfg(cfg, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data, macFunc)
}

// DecryptAuth3x256Cfg is an alias for [DecryptAuthenticated3x256Cfg].
func DecryptAuth3x256Cfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed256, fileData []byte, macFunc MACFunc) ([]byte, error) {
	return DecryptAuthenticated3x256Cfg(cfg, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, fileData, macFunc)
}

// --- 512-bit variants ---

// EncryptAuth3x512Cfg is an alias for [EncryptAuthenticated3x512Cfg].
func EncryptAuth3x512Cfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed512, data []byte, macFunc MACFunc) ([]byte, error) {
	return EncryptAuthenticated3x512Cfg(cfg, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data, macFunc)
}

// DecryptAuth3x512Cfg is an alias for [DecryptAuthenticated3x512Cfg].
func DecryptAuth3x512Cfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed512, fileData []byte, macFunc MACFunc) ([]byte, error) {
	return DecryptAuthenticated3x512Cfg(cfg, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, fileData, macFunc)
}
