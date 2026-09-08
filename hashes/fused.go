package hashes

import (
	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes/internal/aescmacasm"
	"github.com/everanium/itb/hashes/internal/siphashasm"
	"github.com/everanium/itb/internal/aesitbasm"
)

// fused.go — the cross-primitive eight-lane attach step of the fused
// ChainHash cascade. The per-primitive hook factories live beside their
// primitives (aesitb.go, aescmac.go, siphash24.go); this file holds the
// one switch that knows which primitives carry an eight-lane kernel on
// the selected tier.

// attachFused128x8 installs the eight-lane fused cascade hook on a seed
// of a primitive whose selected tier carries an eight-lane kernel
// (aesitbasm.FusedX8Active / aescmacasm.FusedX8Active: VAES + AVX-512
// silicon; siphashasm.FusedX8Active: AVX-512F silicon; in every case
// ITB_FORCE_HASH_TIER unset or avx512, ITB_FORCE_CHAINHASH_X4 unset).
// Called from [AttachFused128] once the four-lane hooks are in place,
// so every shipping constructor path — the C ABI seed constructors and
// the triple package's Init / Load seed builders — carries the hook
// under one attach step; a seed left without it keeps the four-lane
// pixel stride. Other primitives and other hosts leave the seed
// unchanged. The hook is a performance path only: the wire is identical
// with and without it (pinned by the root fused-cascade parity tests).
//
// The eight-lane hook exists at width 128 only: the width-256 / 512
// seed types carry no eight-lane setter, so the switch is complete at
// the three width-128 primitives with an eight-lane kernel.
func attachFused128x8(s *itb.Seed128, name string, key []byte) {
	if name == CipherSipHash24 {
		if len(key) == 0 && siphashasm.FusedX8Active() {
			s.SetBatchFusedChain8(sipHash24FusedChainHash8())
		}
		return
	}
	if len(key) != 16 {
		return
	}
	var k [16]byte
	copy(k[:], key)
	switch name {
	case CipherAESITB128:
		if aesitbasm.FusedX8Active() {
			s.SetBatchFusedChain8(aesITB128FusedChainHash8(k))
		}
	case CipherAES128CTR:
		if aescmacasm.FusedX8Active() {
			s.SetBatchFusedChain8(aesCMACFusedChainHash8(aescmacasm.NewSchedule(k)))
		}
	}
}
