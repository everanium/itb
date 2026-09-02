// Package macs provides cached, pre-keyed wrappers around the
// PRF-grade Message Authentication Codes that ITB ships with as
// built-in factories for the C / FFI / mobile shared-library
// distribution.
//
// Every shipped MAC produces a 32-byte tag and accepts a 32-byte
// (or longer in the HMAC case) key. The shared 32-byte tag size
// means consumers do not have to vary their authenticated-payload
// layout based on which MAC was selected — a binding-friendly
// invariant.
//
// Canonical names (FFI-stable iteration order, exposed via the
// shared library's ITB_MACName entry point):
//
//	kmac256, hmac-sha256, hmac-blake3
//
// Every factory takes a key byte slice and returns a closure
// matching itb.MACFunc (`func(data []byte) []byte`). The closure
// pre-keys its primitive once (cached cSHAKE256 absorb-state for
// KMAC256, sync.Pool of pre-keyed hmac.Hash instances for
// HMAC-SHA256, blake3.Hasher template for HMAC-BLAKE3) so per-call
// invocation carries no key-derivation overhead.
//
// # Runtime dispatch
//
// The shipped set is discoverable at runtime via [Registry] — an
// immutable array of [Spec] entries in canonical iteration order.
// [Find] resolves a canonical name to its [Spec]; [Make] and
// [MakeIncremental] dispatch by name to the appropriate
// one-shot / incremental factory closure. A caller that wants
// runtime primitive selection (per-configuration MAC choice from a
// user string) reaches for [Make]; a caller that ships a fixed MAC
// per profile constructs the factory closure directly (e.g.
// [HMACBLAKE3], [KMAC256], [HMACSHA256]).
//
// The incremental variants ([HMACBLAKE3Incremental],
// [HMACSHA256Incremental], [KMAC256Incremental],
// [KMAC256IncrementalWithCustomization]) return an
// [itb.MACIncrementalFunc] closure — a Writer-shaped MAC that
// absorbs successive chunks and finalises to the 32-byte tag on
// demand. Used by [github.com/everanium/itb.EncryptStreamAuth3xCfg]
// so a Streaming AEAD wire authenticates without buffering the
// whole plaintext.
//
// The KMAC256-With-Customization pair ([KMAC256WithCustomization],
// [KMAC256IncrementalWithCustomization]) exposes the NIST SP 800-185
// customization-string parameter for callers who want per-application
// domain separation baked into the MAC rather than injected via a
// per-call label; the customization byte string is public and pinned
// per profile / per session.
//
// Standards conformance:
//   - kmac256       — NIST SP 800-185 Section 4.3.1, output L = 256
//     bits; bit-exact KAT cross-checked against
//     pycryptodome's KMAC256 implementation.
//   - hmac-sha256   — RFC 2104 / FIPS 198-1 with SHA-256;
//     bit-exact KAT against RFC 4231 vectors.
//   - hmac-blake3   — BLAKE3 native keyed mode (BLAKE3 spec §6),
//     covered by upstream zeebo/blake3 keyed-mode
//     KAT and the ITB Auth round-trip integration
//     test in this package.
//
// Rationale for the shipped set. ITB's MAC-Inside-Encrypt construction
// places the 32-byte tag inside the encrypted container, where the ITB
// barrier dispersal already destroys any plaintext / tag boundary the
// attacker could see, and the Triple Ouroboros 48-bit interlock overlay
// further obscures the payload region. Combined, this means the MAC
// primitive itself only has to be a sound keyed PRF — the surrounding
// ITB construction takes care of placement-hiding, replay-resistance
// (via the per-message nonce), and CCA-resistance.
//
// Every shipped factory is PRF-grade and stateless across the FFI
// boundary; concurrent goroutines may call the returned closure in
// parallel.
//
// # Runtime registration
//
// [Register] adds a user-supplied custom MAC primitive to the runtime
// registry under a caller-chosen name. A registered primitive
// resolves through [Find] / [Make] / [MakeIncremental] /
// [MakeMACPair] exactly like a shipped one and — transitively —
// through every consumer that resolves MACs by name, including
// triple profile MacName resolution: a registered profile whose
// MacName references the custom primitive initialises, encrypts,
// decrypts, and round-trips seed blobs with no further plumbing.
// [Registry] itself is not extended — user entries live in a
// separate mutex-guarded store — so the FFI iteration surface
// (ITB_MACCount / ITB_MACName) is unaffected. Runtime registration
// is a Go-native API only; bindings are triple-only and do not
// expose custom-MAC plug.
//
// A seed blob exported under a custom MAC name records the name, not
// the construction: the name is a promise. Opening such a blob in
// another process requires that process to have registered the same
// name with the same construction beforehand; a missing registration
// fails blob open with an unknown-MAC error, and a divergent
// construction under the same name surfaces as a MAC failure at
// decrypt — indistinguishable from tampering by design.
//
// # Custom-MAC builders
//
// [BuildHMAC] and [BuildKeyedHash] produce a [Spec] ready for
// [Register] from a hash-registry primitive name — shipped or
// user-registered via hashes.Register — closing the contract traps
// of hand-written factories (non-constant tag length,
// non-determinism, incremental-arm drift) by construction:
//
//	spec, err := macs.BuildKeyedHash("blake2b512", macs.KeyedHashSpec{
//		Name: "b2b512_mac",
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//	if err := macs.Register(spec); err != nil {
//		log.Fatal(err)
//	}
//	// "b2b512_mac" now resolves via Find / Make / MakeIncremental
//	// and can serve as a registered triple profile's MacName.
//
// [BuildHMAC] wraps a primitive's unkeyed hash.Hash form in the HMAC
// construction (RFC 2104); [BuildKeyedHash] uses a primitive's
// native keyed mode directly, for primitives whose keyed form is
// itself a sound PRF. Each builder requires the matching optional
// composition field on the resolved hashes.Spec — HashHash for
// [BuildHMAC], KeyedHash for [BuildKeyedHash]; a primitive that
// leaves the field nil is rejected with an error naming the missing
// form. Fully hand-rolled factories remain supported — a [Spec] with
// caller-written MakeMAC / MakeIncrementalMAC closures registers the
// same way, subject to the closure contracts documented on
// [Register] — and are the path for primitives without either
// composition form.
package macs
