# Vendored go-aes subset (AES-round layer)

This directory is an in-module copy of the single-block and parallel AES-round
subset of [`github.com/jedisct1/go-aes`](https://github.com/jedisct1/go-aes) at
**v0.1.1 (commit 8feea7e4)**, with one portability patch applied. The package
name is `aes`, as upstream; the import path is
`github.com/everanium/itb/third/goaes`.

Areion-256, Areion-512, and the SoEM22 PRF construction (`SoEM256` / `SoEM512`)
live in the standalone [`github.com/everanium/areion`](https://github.com/everanium/areion)
module. `third/goaes` retains the low-level AES round building blocks consumed
by `AES-ITB-128` (`aes.Block`, `aes.Round`, `aes.RoundHW`, `aes.FinalRoundHW`,
`aes.UseHardwareAcceleration`) and by ITB's 4-lane batched Areion fallback and
SoA buffer types (`aes.Block4`, `aes.Key4`, `aes.Round4HW`, `aes.FinalRound4HW`,
`aes.XorBlock4`).

## What is included

- `LICENSE` — MIT, Copyright (c) 2026 Frank Denis. Every copied file keeps
  its upstream content and headers.
- The AES-round layer: `aes.go` (`Block`, the round functions, `XorBlock*`),
  `parallel.go` (`Block2` / `Block4`, `Key2` / `Key4`, the 2- and 4-block round
  functions), `keyschedule.go` (referenced by `aes.go`), `cpu.go` (feature
  detection), `aesni_amd64.go` / `aesni_amd64.s` / `aesni_other.go`,
  `vaes_amd64.go` / `vaes_amd64.s` / `vaes_other.go`, `armcrypto_arm64.go` /
  `armcrypto_arm64.s`, `armcrypto_parallel_arm64.go` /
  `armcrypto_parallel_arm64.s`.
- Upstream tests for the kept code: `aes_test.go` and `parallel_test.go`.

Left out: Areion (provided by `github.com/everanium/areion`), Deoxys, Haraka,
Pholkos, Vistrutah, KIASU, ButterKnife, the AES PRF, the multi-round layer
(`multirounds*`), `examples/`, `bench.sh`, `go.mod` / `go.sum`, `README.md`,
`doc.go`.

## Cuts forced by the subset

- `aes.go`: the complete-AES block API `EncryptBlockAES128` / `192` / `256`,
  `EncryptBlockAES` and `EncryptBlocksAES128` / `192` / `256` is removed.
  It is the only user of the multi-round layer (`RoundKeys10`,
  `Rounds10WithFinalHW`, …), which is not vendored, and nothing in ITB
  calls it. No test referenced it.

## Re-deriving the copy

    v0.1.1 subset (files listed above, with the cut)
      + patches/portable.patch

`git apply patches/portable.patch` on the subset base reproduces the package:

- `AddRoundKey` and `XorBlock` / `XorBlock2` / `XorBlock4` dereferenced
  byte-array blocks as `uint64` words, and the key expansion did the same
  with `uint32` words. Byte arrays carry no alignment, and targets without
  unaligned access must not see such a dereference. The XORs load and
  store through `encoding/binary`; the key expansion keeps native byte order
  through `binary.NativeEndian`, so its layout is unchanged.

## Notes

- `cpu.go` reads CPU features through `golang.org/x/sys/cpu` for the
  package's own dispatch (`CPU.HasAESNI`, `CPU.HasARMCrypto`, `CPU.HasVAES`,
  …). ITB's own kernel dispatch does not read these; it uses
  `internal/cpuid`.
- The tests build under `-tags purego` and on every architecture.
