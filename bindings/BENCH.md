# ITB Binding Fleet Benchmark Results

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

## Purpose

These per-binding benchmarks measure **FFI overhead**, not primitive
performance. The primitive-comparison surface lives in
[BENCH3.md](../BENCH3.md) and is the shipped Go authority for
"which hash is fastest at which key width". Each binding here
runs one shared canonical configuration so cross-binding
throughput numbers form a single comparable table anchored on the
same root Go bench row.

## Canonical configuration

Every binding under `bindings/<lang>/` runs its benchmarks at
this fixed shape:

| Dimension       | Value                              | Env-var             |
|-----------------|------------------------------------|---------------------|
| Primitive       | Areion-SoEM-512                    | `ITB_INNER_HASH`    |
| Key width       | 1024 bits                          | `ITB_KEY_BITS`      |
| Nonce width     | 512 bits (v0.3.0 secure default)   | `ITB_NONCE_BITS`    |
| Parallax        | off                                | `ITB_WITH_PARALLAX` |
| Wrapper         | off                                | `ITB_WITH_WRAPPER`  |
| Message profile | `singlemsg-triple-nomac-v1`        | `ITB_PROFILE`       |
| Stream profile  | `streaming-noaead-triple-v1`       | `ITB_PROFILE`       |
| Wall-clock      | 5 s per case                       | `ITB_BENCH_MIN_SEC` |
| Sizes           | 1 MB, 16 MB, 64 MB                 | (hard-coded)        |
| Go runtime cap  | 512 MiB soft heap, 20% GC          | `ITB_GOMEMLIMIT` / `ITB_GOGC` |

The pin matches the root Go BENCH3.md `BenchmarkExtTripleAreion512_1024bit_*`
row so any binding's throughput is directly comparable to the
Go native number.

## Intel Core i7-11700K (Rocket Lake, 16 HT, VMware CGO mode)

### Message shape (buffer-in / buffer-out, single FFI call per iteration)

| Binding                              | 1 MB | 16 MB | 64 MB |
|--------------------------------------|-----:|------:|------:|
| **Go native** (`Encrypt3x512Cfg`)    |   77 |   161 |   171 |
| **Rust** (thin proxy)                |   86 |   142 |   143 |
| **C** (thin proxy)                   |   76 |   141 |   144 |

### Stream pump shape (multi-call session — Begin / Write / End / Read / Free)

| Binding                              | 1 MB | 16 MB | 64 MB |
|--------------------------------------|-----:|------:|------:|
| **Go native** (`Encrypt3x512Cfg`)    |   77 |   161 |   171 |
| **Rust** (stream pump)               |   72 |   142 |   141 |
| **C** (stream pump)                  |   82 |   137 |   143 |

Throughput in MB/s. Go native row is [BENCH3.md](../BENCH3.md)
Triple 1024-bit Areion-SoEM-512 Encrypt at `ITB_NONCE_BITS=512`
with the same heap caps applied. The 1 MB column carries visible
GC-cycle noise across reruns; the 16 MB and 64 MB columns are
stable.

## FFI overhead

Rust and C both sit at 84–88% of native Go throughput at 16 MB
and 64 MB, and roughly at parity or better at 1 MB (where Go
carries GC-cycle overhead the alloc-friendly binding runtimes do
not). Rust vs C parity within measurement noise confirms the
thin-proxy shape adds no measurable language-side overhead on
top of the shared FFI boundary — both languages hit the same
capi + `triple.Pipeline` cost floor.

The ~15% shortfall vs native Go at large payloads is not
FFI-crossing overhead alone: the binding path traverses
`triple.Pipeline.EncryptMessage`, which is an extra Go-side
layer over the raw `Encrypt3x512Cfg` entry the root Go bench
drives directly. That layer has no direct bench in the shipped Go
suite and is the subject of a dedicated pre-Phase-3 performance
investigation.

## Reproduction

Both bindings expose the same env-var surface; `run_bench.sh`
sets defaults that reproduce the canonical config, and the caller
can override any field on the command line.

### Rust

```sh
./bindings/rust/run_bench.sh
```

Runs `cargo bench --bench bench_message` + `bench_stream` with
Criterion at 5 s wall-clock per case, sample size 10.

### C

```sh
./bindings/c/run_bench.sh
```

Runs `make bench` after `build.sh` (builds `libitb.so` +
`libitb_c.a` + bench binaries) and prints a plain MB/s table.

## Extension

Every new binding under `bindings/<lang>/` lands with the same
env-var surface + canonical config baked into its `run_bench.sh`
defaults, and a row per shape (Message + Stream) added to the
tables above.
