package itb

import "errors"

// ErrEmptyInput is returned by every Low-Level Cfg entry point
// (Encrypt3x{128,256,512}Cfg / Decrypt3x{128,256,512}Cfg /
// EncryptAuth3x{128,256,512}Cfg / DecryptAuth3x{128,256,512}Cfg /
// EncryptStream3x{128,256,512}Cfg / DecryptStream3x{128,256,512}Cfg /
// EncryptStreamAuth3xCfg / DecryptStreamAuth3xCfg) when the supplied
// plaintext or wire payload is nil or zero-length.
//
// This sentinel is the Low-Level surface's peer to
// [github.com/everanium/itb/triple.ErrEmptyInput]; both signal the
// same policy, kept as two distinct package-scoped vars because the
// root itb package cannot import triple (triple depends on itb).
// The policy itself is uniform across every ITB cipher entry point:
// no zero-payload wire exists on the shipped surface — an empty
// message has no cover story in any cryptographic construction and
// is always distinguishable at some layer (wire length, timing,
// traffic count). Callers who need to signal "no data" send a
// marker byte instead.
var ErrEmptyInput = errors.New("itb: empty input")
