package triplewire

// Function hooks wired at package init time by root package itb and
// package triple so zero-copy destination buffer helpers can be called
// across package boundaries without expanding the frozen public API.
var (
	EncryptNoMACInto func(width int, cfg any, dst []byte, lead int, s0, s1, s2, s3, s4, s5, s6, s7 any, data []byte) ([]byte, error)
	DecryptNoMACInto func(width int, cfg any, dst []byte, s0, s1, s2, s3, s4, s5, s6, s7 any, fileData []byte) ([]byte, error)
	EncryptAuthInto  func(width int, cfg any, dst []byte, lead int, s0, s1, s2, s3, s4, s5, s6, s7 any, data []byte, mac func([]byte) []byte) ([]byte, error)
	DecryptAuthInto  func(width int, cfg any, dst []byte, s0, s1, s2, s3, s4, s5, s6, s7 any, fileData []byte, mac func([]byte) []byte) ([]byte, error)

	EncryptStreamBytesTo func(pipe any, dst, plaintext []byte) ([]byte, error)
	DecryptStreamBytesTo func(pipe any, dst, wire []byte) ([]byte, error)
)
