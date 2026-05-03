package itb

import "errors"

// ErrMACFailure is returned by every authenticated-decrypt entry
// point ([DecryptAuthenticated128] / [DecryptAuthenticated256] /
// [DecryptAuthenticated512] and the Triple-Ouroboros mirrors
// [DecryptAuthenticated3x128] / [DecryptAuthenticated3x256] /
// [DecryptAuthenticated3x512]) when the embedded MAC tag does not
// match the recomputed tag over the recovered plaintext.
//
// The sentinel value lets capi / FFI layers detect the integrity
// failure with [errors.Is] rather than substring-matching the
// error message, which would silently regress if the message was
// ever rewritten. The C ABI maps this to
// `cmd/cshared/internal/capi.StatusMACFailure`.
//
// Authenticated-decrypt errors that are NOT MAC failures (decode
// errors, malformed container, key-mismatch garbage that survives
// MAC because the receiver wired the wrong MAC closure but
// happened to verify against the same tag space) surface through
// distinct error paths and do not wrap this sentinel.
var ErrMACFailure = errors.New("itb: MAC verification failed (tampered or wrong key)")
