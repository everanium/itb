# Vendored go-aes subset (Areion and the AES-round layer)

This directory is an in-module copy of a subset of
[`github.com/jedisct1/go-aes`](https://github.com/jedisct1/go-aes) at
**v0.1.1 (commit 8feea7e4)**, with one patch applied. The package name is
`aes`, as upstream; the import path is `github.com/everanium/itb/third/goaes`.
The copy is a package of this module rather than a `replace` directive
because a `replace` in a library's `go.mod` is ignored by every consumer of
the library.

## Why a patched copy

Upstream `AreionSoEM256` / `AreionSoEM512` evaluate one Areion permutation
in both branches of the Sum of Even-Mansour, `F(m) = P(m ⊕ k1) ⊕ P(m ⊕ k2 ⊕ d)`,
so `F(m) = F(m ⊕ k1 ⊕ k2 ⊕ d)` for every `m` and the PRF advantage is capped
at the birthday bound. The ~170 / ~341-bit figure quoted upstream is the
Chen–Lambooij–Mennink bound (CRYPTO 2019; ePrint 2019/554) for SoEM22, which
needs two independent permutations and two independent keys; it is not
reachable in that construction. Reported as
<https://github.com/jedisct1/go-aes/issues/1>.

ITB uses Areion-SoEM as a keyed PRF (`ctr`, `kdf`, `wrapper`, `parallax`,
the DRBG) and as the round function of its Areion ChainHash, so the copy
carries the SoEM22 construction instead:

    F(m) = P1(m ⊕ k1) ⊕ P2(m ⊕ k2) ⊕ k1 ⊕ k2

`P1` is Areion under the existing round constants (unchanged); `P2` is
Areion under a second constant table `areionRoundConstants2` — the next
fifteen 128-bit words of the hexadecimal digits of π, little-endian, in the
same format — modelled as a permutation independent of `P1`. This is
CLM19 Eq. (4) with its output whitening; CLM19 Theorem 1 proves it a PRF up
to about 2^(2n/3) queries in the random-permutation model, with both
subkeys secret and independently random. The domain constant `d` is
removed.

## What is included

- `LICENSE` — MIT, Copyright (c) 2026 Frank Denis. Every copied file keeps
  its upstream content and headers.
- Areion: `areion.go`, `areion_hw.go`, `areion_purego.go`,
  `areion_amd64.go`, `areion_amd64.s`, `areion_arm64.go`, `areion_arm64.s`
  (the `Areion256` / `Areion512` types, forward and inverse permutations,
  Even-Mansour helpers, `AreionSoEM256` / `AreionSoEM512`).
- The AES-round layer these and ITB use: `aes.go` (`Block`, the round
  functions, `XorBlock*`), `parallel.go` (`Block2` / `Block4`, `Key2` /
  `Key4`, the 2- and 4-block round functions), `keyschedule.go`
  (referenced by `aes.go`), `cpu.go` (feature detection), `aesni_amd64.go`
  / `aesni_amd64.s` / `aesni_other.go`, `vaes_amd64.go` / `vaes_amd64.s` /
  `vaes_other.go`, `armcrypto_arm64.go` / `armcrypto_arm64.s`,
  `armcrypto_parallel_arm64.go` / `armcrypto_parallel_arm64.s`.
- Upstream tests for the kept code: `aes_test.go`, `parallel_test.go`,
  `areion_test.go` (with the patch's new tests).

Left out: Deoxys, Haraka, Pholkos, Vistrutah, KIASU, ButterKnife, the AES
PRF, the multi-round layer (`multirounds*`), `examples/`, `bench.sh`,
`go.mod` / `go.sum`, `README.md`, `doc.go`. Further parts are added from
upstream when needed.

## Cuts forced by the subset

- `aes.go`: the complete-AES block API `EncryptBlockAES128` / `192` / `256`,
  `EncryptBlockAES` and `EncryptBlocksAES128` / `192` / `256` is removed.
  It is the only user of the multi-round layer (`RoundKeys10`,
  `Rounds10WithFinalHW`, …), which is not vendored, and nothing in ITB
  calls it. No test referenced it.

## Re-deriving the copy

    v0.1.1 subset (files listed above, with the cut) + patches/soem22.patch

`patches/soem22.patch` is the exact diff applied; `git apply` it on the
subset base to reproduce this directory. The patch touches only
`areion*.go`, `areion_amd64.s`, `areion_arm64.s` and `areion_test.go`.

## Notes

- `cpu.go` reads CPU features through `golang.org/x/sys/cpu` for the
  package's own dispatch (`CPU.HasAESNI`, `CPU.HasARMCrypto`, `CPU.HasVAES`,
  …). ITB's own kernel dispatch does not read these; it uses
  `internal/cpuid`.
- The upstream test file `areion_test.go` references the assembly entry
  points directly and therefore does not build under `-tags purego`
  (upstream behaves the same); the package itself builds under `purego`.
