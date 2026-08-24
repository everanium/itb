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
| **Rust** (thin proxy)                |   89 |   150 |   155 |
| **C** (thin proxy)                   |   86 |   148 |   154 |
| **C++** (thin proxy)                 |   86 |   143 |   144 |
| **Ada** (thin proxy)                 |   89 |   148 |   143 |
| **D** (thin proxy)                   |   88 |   152 |   156 |
| **C#** (thin proxy)                  |   83 |   147 |   142 |
| **Python** (thin proxy)              |   76 |   138 |   144 |
| **Node.js** (thin proxy)             |   84 |   147 |   150 |
| **Fortran** (thin proxy)             |   90 |   149 |   147 |

### Stream pump shape (multi-call session — Begin / Write / End / Read / Free)

| Binding                              | 1 MB | 16 MB | 64 MB |
|--------------------------------------|-----:|------:|------:|
| **Go native** (`Encrypt3x512Cfg`)    |   77 |   161 |   171 |
| **Rust** (stream pump)               |   76 |   144 |   146 |
| **C** (stream pump)                  |   83 |   140 |   148 |
| **C++** (stream pump)                |   77 |   128 |   132 |
| **Ada** (stream pump)                |   79 |   130 |   139 |
| **D** (stream pump)                  |   89 |   147 |   149 |
| **C#** (stream pump)                 |   84 |   144 |   143 |
| **Python** (stream pump)             |   70 |   142 |   138 |
| **Node.js** (stream pump)            |   72 |   135 |   134 |
| **Fortran** (stream pump)            |   69 |   116 |   109 |

Throughput in MB/s. Go native row is [BENCH3.md](../BENCH3.md)
Triple 1024-bit Areion-SoEM-512 Encrypt at `ITB_NONCE_BITS=512`
with the same heap caps applied. Plaintext is CSPRNG-filled on
every side (`crypto/rand` on Go, `rand::rng().fill_bytes` on
Rust, `getrandom(2)` on C / C++ / D / Ada / Fortran,
`RandomNumberGenerator.Fill` on C#, `secrets.token_bytes` on
Python, `crypto.randomFillSync` on Node.js) so the COBS path
handles identical byte-content distributions across all rows.
The 1 MB column carries visible GC-cycle noise across reruns;
the 16 MB and 64 MB columns are stable. Numbers are
single-run — the sequential bench harness runs one binding at a
time so parallel benches never interfere.

## FFI overhead

Message shape at 64 MB, as a percentage of native Go:
D 91%, Rust 91%, C 90%, Node.js 88%, C++ 84%, Ada 84%,
Python 84%, C# 83%, Fortran 86%. Stream pump shape at 64 MB:
D 87%, C 87%, Rust 85%, C# 84%, Python 81%, Ada 81%, C++ 77%,
Node.js 78%, Fortran 64%.

**All nine bindings sit in a tight 83–91% band on the Message
shape at 64 MB**, confirming the thin-proxy design puts every
language on the same capi + `triple.Pipeline` cost floor. D
leads the fleet after the `pragma(crt_constructor)` GC-parallel-
disable patch (see the D README Limitations section) — the
druntime helper threads no longer contend with libitb's Go
worker pool. Rust and C follow within noise. Ada, C++, C#,
Python, Fortran cluster within 1–4 percentage points of each
other; Node.js sits between them via koffi's sync FFI.

Stream pump numbers spread wider than Message. Every session
call crosses the FFI boundary (Begin / Write / End / Read /
Free = ≥5 calls per drain cycle vs one call for Message), so
per-call FFI overhead affects the stream shape more visibly.
The capi spool in `capi/triple_stream.go` also carries an
allocation ladder not covered by the wire-buffer pre-sizing
patch; a follow-up pre-sizing of the session spool is a
candidate to close another ~5–8 percentage points on the
stream shape across the fleet.

**~9–17% residual vs native Go** at the top of the band splits
into two roughly equal halves: the `triple.Pipeline` layer
(an extra Go-side wrap over the raw `Encrypt3x512Cfg` entry the
root Go bench drives directly), addressed by the wire-buffer
pre-sizing patch already in the shipped `triple/message.go` +
`capi/triple.go`; and the c-shared / cgo runtime itself
(signal + scheduler mechanics plus GC work when the main
thread is external) which is not addressable with a minimal
Go-side patch.

## Reproduction

Both bindings expose the same env-var surface; `run_bench.sh`
sets defaults that reproduce the canonical config, and the caller
can override any field on the command line.

Every binding accepts the same env vars:

| env var             | default                       |
|---------------------|-------------------------------|
| `ITB_INNER_HASH`    | `areion512`                   |
| `ITB_KEY_BITS`      | `1024`                        |
| `ITB_NONCE_BITS`    | `512`                         |
| `ITB_WITH_PARALLAX` | `false`                       |
| `ITB_WITH_WRAPPER`  | `false`                       |
| `ITB_PROFILE`       | Message: `singlemsg-triple-nomac-v1` / Stream: `streaming-noaead-triple-v1` |
| `ITB_BENCH_MIN_SEC` | `5`                           |
| `ITB_GOMEMLIMIT`    | `512MiB`                      |
| `ITB_GOGC`          | `20`                          |

Nine language-native run scripts:

```sh
./bindings/rust/run_bench.sh       # cargo bench (Criterion)
./bindings/c/run_bench.sh          # make bench + plain MB/s
./bindings/cpp/run_bench.sh        # make bench + plain MB/s
./bindings/ada/run_bench.sh        # alr build + Ada Real_Time timing
./bindings/dlang/run_bench.sh      # dub build (defaults to LDC2) + MonoTime
./bindings/csharp/run_bench.sh     # dotnet run Itb.Bench + Stopwatch
./bindings/python/run_bench.sh     # ctypes + perf_counter
./bindings/nodejs/run_bench.sh     # koffi + performance.now
./bindings/fortran/run_bench.sh    # gfortran + system_clock
```

Output format stays language-native (Criterion prose for Rust,
plain MB/s table for the seven that share `bench_util`'s table
shape, Ada / Node.js print their own formatted table). A
cross-binding aggregator script that parses each format into
a single table lands as a Phase 4 follow-up.

## Extension

Every new binding under `bindings/<lang>/` lands with the same
env-var surface + canonical config baked into its `run_bench.sh`
defaults, and a row per shape (Message + Stream) added to the
tables above.
