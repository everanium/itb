package ctr

import (
	"crypto/rand"

	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/internal/drbg"
)

// The DRBG fill arms of the keystream primitives.
//
// internal/drbg sits beneath the hashes registry in the import graph
// (the itb root imports it, and hashes imports the root), so it cannot
// construct a keystream by registry name itself. This package can, and
// installs one fill arm per keystream-eligible registry primitive at
// init, in canonical registry order, so drbg.Names reports them in that
// order. Each arm draws a key and a nonce of the primitive's own sizes
// from crypto/rand on every call and expands the keystream over dst
// through [New] — the same constructor the wrapper and parallax layers
// use, so one definition of each counter-mode construction serves all
// three roles. AES-ITB-128 stays out of this set: [New] refuses it, and
// its noise-fill arm is built into internal/drbg from the aesitb
// package.
func init() {
	for _, name := range hashes.KeystreamNames() {
		name := name
		keySize, err := KeySize(name)
		if err != nil {
			panic(err)
		}
		nonceSize, err := NonceSize(name)
		if err != nil {
			panic(err)
		}
		fill := func(dst []byte) error {
			seed := make([]byte, keySize+nonceSize)
			if _, err := rand.Read(seed); err != nil {
				return err
			}
			ks, err := New(name, seed[:keySize], seed[keySize:])
			if err != nil {
				clear(seed)
				return err
			}
			ks.XORKeyStream(dst, dst)
			clear(seed)
			return nil
		}
		if err := drbg.Register(name, fill); err != nil {
			panic(err)
		}
	}
}
