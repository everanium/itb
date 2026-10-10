module github.com/everanium/itb

go 1.27

require (
	github.com/dchest/siphash v1.2.3
	github.com/klauspost/cpuid/v2 v2.2.10
	github.com/spf13/cobra v1.10.2
	github.com/zeebo/blake3 v0.2.4
	golang.org/x/crypto v0.49.0
	golang.org/x/sys v0.42.0
	golang.org/x/term v0.41.0
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	github.com/zeebo/assert v1.3.0 // indirect
)

retract (
	[v0.1.0, v0.5.1] // superseded by v0.5.5
)
