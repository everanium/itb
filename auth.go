package itb

// MACFunc is the pluggable MAC function interface.
//
// The function must accept a byte slice and return a fixed-size tag.
// The MAC key management is the caller's responsibility — the MACFunc
// closure should capture the key.
//
// The tag is computed over the entire encrypted payload (COBS + null
// terminator + random padding), not just the plaintext. Given a secure
// MAC function, flipping any data bit in the container causes MAC failure,
// preventing the CCA spatial pattern that would otherwise distinguish
// padding from data regions (see SCIENCE.md Section 4.3).
//
// Example wrappers:
//
//	// HMAC-SHA256 (crypto/hmac + crypto/sha256)
//	func hmacSHA256(key []byte) itb.MACFunc {
//	    return func(data []byte) []byte {
//	        h := hmac.New(sha256.New, key)
//	        h.Write(data)
//	        return h.Sum(nil)
//	    }
//	}
//
//	// BLAKE3 MAC (github.com/zeebo/blake3)
//	func blake3MAC(key []byte) itb.MACFunc {
//	    return func(data []byte) []byte {
//	        h := blake3.DeriveKey(key, data)
//	        return h[:32]
//	    }
//	}
type MACFunc func(data []byte) []byte

// constantTimeEqual compares two byte slices in constant time.
func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// EncryptAuth is the width-less Single Message authenticated Encrypt
// entry point. Dispatches to [EncryptAuthenticated128] /
// [EncryptAuthenticated256] / [EncryptAuthenticated512] based on the
// concrete pointer type of the supplied seeds. Every seed must carry
// the same concrete *SeedN type; mixing widths returns an itb-wrapped
// error.
//
// Accepts seeds typed as any (interface{}) so a single signature
// covers all three primitive widths. The internal type-switch
// resolves the width once and forwards verbatim to the matching
// width-suffixed implementation; the supplied [MACFunc] closure is
// passed through unchanged.
func EncryptAuth(noiseSeed, dataSeed, startSeed any, data []byte, macFunc MACFunc) ([]byte, error) {
	w, err := dispatchWidthSingle(noiseSeed, dataSeed, startSeed)
	if err != nil {
		return nil, err
	}
	switch w {
	case 128:
		return EncryptAuthenticated128(noiseSeed.(*Seed128), dataSeed.(*Seed128), startSeed.(*Seed128), data, macFunc)
	case 256:
		return EncryptAuthenticated256(noiseSeed.(*Seed256), dataSeed.(*Seed256), startSeed.(*Seed256), data, macFunc)
	case 512:
		return EncryptAuthenticated512(noiseSeed.(*Seed512), dataSeed.(*Seed512), startSeed.(*Seed512), data, macFunc)
	}
	return nil, errSeedWidthMix
}

// DecryptAuth is the width-less Single Message authenticated Decrypt
// entry point. Mirrors [EncryptAuth]; dispatches to
// [DecryptAuthenticated128] / [DecryptAuthenticated256] /
// [DecryptAuthenticated512].
func DecryptAuth(noiseSeed, dataSeed, startSeed any, fileData []byte, macFunc MACFunc) ([]byte, error) {
	w, err := dispatchWidthSingle(noiseSeed, dataSeed, startSeed)
	if err != nil {
		return nil, err
	}
	switch w {
	case 128:
		return DecryptAuthenticated128(noiseSeed.(*Seed128), dataSeed.(*Seed128), startSeed.(*Seed128), fileData, macFunc)
	case 256:
		return DecryptAuthenticated256(noiseSeed.(*Seed256), dataSeed.(*Seed256), startSeed.(*Seed256), fileData, macFunc)
	case 512:
		return DecryptAuthenticated512(noiseSeed.(*Seed512), dataSeed.(*Seed512), startSeed.(*Seed512), fileData, macFunc)
	}
	return nil, errSeedWidthMix
}

// EncryptAuth3x is the width-less Single Message Triple-Ouroboros
// authenticated Encrypt entry point. Dispatches to
// [EncryptAuthenticated3x128] / [EncryptAuthenticated3x256] /
// [EncryptAuthenticated3x512] based on the concrete pointer type of
// the supplied seeds. All seven seeds must share one concrete *SeedN
// type; mixing widths returns an itb-wrapped error.
func EncryptAuth3x(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 any, data []byte, macFunc MACFunc) ([]byte, error) {
	w, err := dispatchWidthTriple(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3)
	if err != nil {
		return nil, err
	}
	switch w {
	case 128:
		return EncryptAuthenticated3x128(noiseSeed.(*Seed128), dataSeed1.(*Seed128), dataSeed2.(*Seed128), dataSeed3.(*Seed128), startSeed1.(*Seed128), startSeed2.(*Seed128), startSeed3.(*Seed128), data, macFunc)
	case 256:
		return EncryptAuthenticated3x256(noiseSeed.(*Seed256), dataSeed1.(*Seed256), dataSeed2.(*Seed256), dataSeed3.(*Seed256), startSeed1.(*Seed256), startSeed2.(*Seed256), startSeed3.(*Seed256), data, macFunc)
	case 512:
		return EncryptAuthenticated3x512(noiseSeed.(*Seed512), dataSeed1.(*Seed512), dataSeed2.(*Seed512), dataSeed3.(*Seed512), startSeed1.(*Seed512), startSeed2.(*Seed512), startSeed3.(*Seed512), data, macFunc)
	}
	return nil, errSeedWidthMix
}

// DecryptAuth3x is the width-less Single Message Triple-Ouroboros
// authenticated Decrypt entry point. Mirrors [EncryptAuth3x];
// dispatches to [DecryptAuthenticated3x128] /
// [DecryptAuthenticated3x256] / [DecryptAuthenticated3x512].
func DecryptAuth3x(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 any, fileData []byte, macFunc MACFunc) ([]byte, error) {
	w, err := dispatchWidthTriple(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3)
	if err != nil {
		return nil, err
	}
	switch w {
	case 128:
		return DecryptAuthenticated3x128(noiseSeed.(*Seed128), dataSeed1.(*Seed128), dataSeed2.(*Seed128), dataSeed3.(*Seed128), startSeed1.(*Seed128), startSeed2.(*Seed128), startSeed3.(*Seed128), fileData, macFunc)
	case 256:
		return DecryptAuthenticated3x256(noiseSeed.(*Seed256), dataSeed1.(*Seed256), dataSeed2.(*Seed256), dataSeed3.(*Seed256), startSeed1.(*Seed256), startSeed2.(*Seed256), startSeed3.(*Seed256), fileData, macFunc)
	case 512:
		return DecryptAuthenticated3x512(noiseSeed.(*Seed512), dataSeed1.(*Seed512), dataSeed2.(*Seed512), dataSeed3.(*Seed512), startSeed1.(*Seed512), startSeed2.(*Seed512), startSeed3.(*Seed512), fileData, macFunc)
	}
	return nil, errSeedWidthMix
}
