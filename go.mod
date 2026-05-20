module github.com/everanium/itb

go 1.26

require (
	github.com/dchest/siphash v1.2.3
	github.com/jedisct1/go-aes v0.1.1
	github.com/zeebo/blake3 v0.2.4
	golang.org/x/crypto v0.49.0
	golang.org/x/sys v0.42.0
)

require (
	github.com/klauspost/cpuid/v2 v2.2.10 // indirect
	github.com/zeebo/assert v1.3.0 // indirect
)

retract v0.1.0 // documentation fixes only; use v0.1.1 or later
