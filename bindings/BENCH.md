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
| **Rust** (thin proxy)                |   88 |   145 |   145 |
| **C** (thin proxy)                   |   88 |   148 |   154 |
| **C++** (thin proxy)                 |   87 |   146 |   150 |
| **Ada** (thin proxy)                 |   87 |   143 |   147 |
| **D** (thin proxy)                   |   86 |   147 |   154 |
| **C#** (thin proxy)                  |   82 |   146 |   151 |
| **Python** (thin proxy)              |   76 |   134 |   140 |
| **Node.js** (thin proxy)             |   84 |   143 |   147 |
| **Fortran** (thin proxy)             |   88 |   148 |   152 |
| **Swift** (thin proxy)               |   84 |   138 |   143 |
| **Java** (thin proxy)                |   88 |   148 |   152 |
| **Zig** (thin proxy)                 |   85 |   149 |   154 |
| **Kotlin** (JVM)                     |   86 |   137 |   142 |
| **Erlang** (NIF)                     |   84 |   138 |   150 |
| **Scala** (JVM)                      |   88 |   126 |   140 |
| **Groovy** (JVM)                     |   84 |   145 |   141 |
| **Elixir** (BEAM over Erlang NIF)    |   82 |   142 |   146 |
| **PowerShell** (over C#)             |   77 |   145 |   151 |
| **Clojure** (JVM)                    |   83 |   140 |   148 |
| **F#** (over C#)                     |   83 |   146 |   144 |
| **VB.NET** (over C#)                 |   82 |   141 |   140 |
| **Gleam** (BEAM over Erlang NIF)     |   84 |   145 |   147 |
| **LFE** (BEAM over Erlang NIF)       |   84 |   143 |   149 |
| **PHP** (FFI)                        |   89 |   152 |   156 |
| **Ruby** (ffi gem)                   |   75 |   127 |   125 |
| **Dart** (dart:ffi)                  |   88 |   149 |   147 |
| **Lua** (C module)                   |   86 |   149 |   150 |
| **Nim** (thin proxy)                 |   86 |   144 |   152 |
| **Crystal** (thin proxy)             |   90 |   150 |   155 |
| **Julia** (ccall)                    |   82 |   146 |   147 |
| **OCaml** (ocaml-ctypes)             |   89 |   147 |   145 |
| **Haskell** (foreign import ccall)   |   90 |   152 |   158 |
| **R** (.Call via C shim)             |   82 |   147 |   142 |

### Stream pump shape (multi-call session — Begin / Write / End / Read / Free)

| Binding                              | 1 MB | 16 MB | 64 MB |
|--------------------------------------|-----:|------:|------:|
| **Go native** (`Encrypt3x512Cfg`)    |   77 |   161 |   171 |
| **Rust** (stream pump)               |   76 |   145 |   146 |
| **C** (stream pump)                  |   85 |   139 |   145 |
| **C++** (stream pump)                |   86 |   144 |   147 |
| **Ada** (stream pump)                |   90 |   144 |   143 |
| **D** (stream pump)                  |   88 |   145 |   145 |
| **C#** (stream pump)                 |   84 |   142 |   145 |
| **Python** (stream pump)             |   66 |   136 |   137 |
| **Node.js** (stream pump)            |   76 |   130 |   133 |
| **Fortran** (stream pump)            |   88 |   145 |   146 |
| **Swift** (stream pump)              |   88 |   138 |   140 |
| **Java** (stream pump)               |   92 |   146 |   148 |
| **Zig** (stream pump)                |   80 |   135 |   136 |
| **Kotlin** (stream pump)             |   80 |   142 |   145 |
| **Erlang** (stream pump)             |   86 |   147 |   142 |
| **Scala** (stream pump)              |   81 |   141 |   146 |
| **Groovy** (stream pump)             |   78 |   140 |   144 |
| **Elixir** (stream pump)             |   85 |   144 |   146 |
| **PowerShell** (stream pump)         |   81 |   142 |   145 |
| **Clojure** (stream pump)            |   77 |   141 |   141 |
| **F#** (stream pump)                 |   79 |   141 |   142 |
| **VB.NET** (stream pump)             |   80 |   141 |   144 |
| **Gleam** (stream pump)              |   85 |   143 |   145 |
| **LFE** (stream pump)                |   86 |   145 |   140 |
| **PHP** (stream session)             |   93 |   149 |   151 |
| **Ruby** (stream)                    |   90 |   124 |   125 |
| **Dart** (stream pump)               |   85 |   146 |   146 |
| **Lua** (stream)                     |   79 |   145 |   147 |
| **Nim** (stream)                     |   91 |   145 |   147 |
| **Crystal** (stream)                 |   90 |   146 |   149 |
| **Julia** (stream)                   |   92 |   146 |   150 |
| **OCaml** (stream)                   |   92 |   147 |   149 |
| **Haskell** (stream)                 |   91 |   151 |   150 |
| **R** (stream)                       |   91 |   147 |   147 |

### Message shape — full production (MAC on, parallax on, wrapper on)

Same 34 rows under `ITB_WITH_MAC=true ITB_WITH_PARALLAX=true ITB_WITH_WRAPPER=true`, exercising the shipped `singlemsg-triple-mac-v1` profile with parallax and wrapper overlays engaged.

| Binding                              | 1 MB | 16 MB | 64 MB |
|--------------------------------------|-----:|------:|------:|
| **Go native** (`Encrypt3x512Cfg`)    |   77 |   161 |   171 |
| **Rust** (thin proxy)                |   53 |   116 |   118 |
| **C** (thin proxy)                   |   53 |   112 |   114 |
| **C++** (thin proxy)                 |   53 |   117 |   126 |
| **Ada** (thin proxy)                 |   55 |   114 |   121 |
| **D** (thin proxy)                   |   54 |   118 |   123 |
| **C#** (thin proxy)                  |   52 |   112 |   108 |
| **Python** (thin proxy)              |   48 |   103 |   112 |
| **Node.js** (thin proxy)             |   53 |   112 |   120 |
| **Fortran** (thin proxy)             |   54 |   117 |   125 |
| **Swift** (thin proxy)               |   52 |   114 |   123 |
| **Java** (thin proxy)                |   54 |   111 |   124 |
| **Zig** (thin proxy)                 |   53 |   113 |   124 |
| **Kotlin** (JVM)                     |   53 |   109 |   121 |
| **Erlang** (NIF)                     |   52 |   114 |   121 |
| **Scala** (JVM)                      |   52 |   112 |   121 |
| **Groovy** (JVM)                     |   53 |   113 |   121 |
| **Elixir** (BEAM over Erlang NIF)    |   52 |   114 |   125 |
| **PowerShell** (over C#)             |   50 |   113 |   122 |
| **Clojure** (JVM)                    |   54 |   111 |   123 |
| **F#** (over C#)                     |   51 |   112 |   122 |
| **VB.NET** (over C#)                 |   51 |   112 |   123 |
| **Gleam** (BEAM over Erlang NIF)     |   50 |   115 |   123 |
| **LFE** (BEAM over Erlang NIF)       |   52 |   113 |   123 |
| **PHP** (FFI)                        |   54 |   116 |   127 |
| **Ruby** (ffi gem)                   |   42 |    90 |   104 |
| **Dart** (dart:ffi)                  |   56 |   114 |   117 |
| **Lua** (C module)                   |   53 |   113 |   121 |
| **Nim** (thin proxy)                 |   54 |   115 |   124 |
| **Crystal** (thin proxy)             |   49 |   111 |   123 |
| **Julia** (ccall)                    |   53 |   114 |   121 |
| **OCaml** (ocaml-ctypes)             |   54 |   114 |   121 |
| **Haskell** (foreign import ccall)   |   54 |   118 |   125 |
| **R** (.Call via C shim)             |   52 |   114 |   119 |

### Stream pump shape — full production (AEAD on, parallax on, wrapper on)

Same 34 rows under `ITB_WITH_MAC=true ITB_WITH_PARALLAX=true ITB_WITH_WRAPPER=true`, exercising `streaming-aead-triple-mac-v1` with parallax and wrapper overlays engaged.

| Binding                              | 1 MB | 16 MB | 64 MB |
|--------------------------------------|-----:|------:|------:|
| **Go native** (`Encrypt3x512Cfg`)    |   77 |   161 |   171 |
| **Rust** (stream pump)               |   ~  |   ~   |   118 |
| **C** (stream pump)                  |   47 |   104 |   117 |
| **C++** (stream pump)                |   52 |   114 |   122 |
| **Ada** (stream pump)                |   51 |   112 |   120 |
| **D** (stream pump)                  |   52 |   114 |   121 |
| **C#** (stream pump)                 |   50 |   109 |   117 |
| **Python** (stream pump)             |   44 |   107 |   115 |
| **Node.js** (stream pump)            |   49 |   102 |   113 |
| **Fortran** (stream pump)            |   50 |   116 |   124 |
| **Swift** (stream pump)              |   51 |   108 |   108 |
| **Java** (stream pump)               |   54 |   114 |   122 |
| **Zig** (stream pump)                |   49 |   106 |   121 |
| **Kotlin** (stream pump)             |   52 |   106 |   116 |
| **Erlang** (stream pump)             |   50 |   111 |   120 |
| **Scala** (stream pump)              |   52 |   109 |   119 |
| **Groovy** (stream pump)             |   54 |   107 |   118 |
| **Elixir** (stream pump)             |   51 |   111 |   122 |
| **PowerShell** (stream pump)         |   50 |   107 |   117 |
| **Clojure** (stream pump)            |   53 |   107 |   117 |
| **F#** (stream pump)                 |   50 |   108 |   119 |
| **VB.NET** (stream pump)             |   50 |   110 |   119 |
| **Gleam** (stream pump)              |   52 |   111 |   120 |
| **LFE** (stream pump)                |   53 |   112 |   122 |
| **PHP** (stream session)             |   52 |   115 |   124 |
| **Ruby** (stream)                    |   42 |    90 |   103 |
| **Dart** (stream pump)               |   54 |   111 |   121 |
| **Lua** (stream)                     |   50 |   112 |   121 |
| **Nim** (stream)                     |   49 |   114 |   122 |
| **Crystal** (stream)                 |   52 |   115 |   121 |
| **Julia** (stream)                   |   53 |   115 |   124 |
| **OCaml** (stream)                   |   54 |   113 |   121 |
| **Haskell** (stream)                 |   50 |   115 |   125 |
| **R** (stream)                       |   53 |   111 |   122 |

Rust stream row shows only 64 MB — Criterion's histogram output emits only the largest configured size at a compact throughput window; the 1 MB and 16 MB rows are truncated in this pass.

Production shape throughputs sit at ~68–75% of the canonical (non-authenticated / no-overlay) numbers — the parallax and wrapper overlays add per-chunk cost on both encrypt and decrypt paths; ~25–30% of the canonical FFI-only throughput is the composite overhead of the full production wire.

Throughput in MB/s. Go native row is [BENCH3.md](../BENCH3.md)
Triple 1024-bit Areion-SoEM-512 Encrypt at `ITB_NONCE_BITS=512`
with the same heap caps applied. Plaintext is CSPRNG-filled on
every side (`crypto/rand` on Go, `rand::rng().fill_bytes` on
Rust, `getrandom(2)` on the C-family and native-compiled rows,
`RandomNumberGenerator.Fill` on the .NET family, `secrets.token_bytes`
on Python, `crypto.randomFillSync` on Node.js, `SecureRandom` on
JVM-family rows, `crypto/rand` in Go NIF hosts on the BEAM family,
`Random.SystemRandom` on Erlang, `Random.rand!` on Julia) so the
COBS path handles identical byte-content distributions across all
rows. The 1 MB column carries visible GC-cycle noise across reruns;
the 16 MB and 64 MB columns are stable. Numbers are single-run —
the sequential bench harness runs one binding at a time so parallel
benches never interfere.

## FFI overhead

Message shape at 64 MB, as a percentage of native Go (171 MB/s):
Haskell 92%, C 90%, D / Crystal 90%, Zig 90%, Nim 89%, Rust 85%,
Fortran 89%, Java / C# / PowerShell 88%, Ada 86%,
Elixir / Erlang / Julia / Lua / LFE 87–88%, Clojure 87%, F# 84%,
Gleam 86%, Node.js 86%, OCaml 85%, VB.NET 82%, PHP 91%, Groovy 82%,
Swift 84%, Kotlin 83%, Dart 86%, Python 82%, Scala 82%, R 83%,
Ruby 73%.

Stream pump at 64 MB: Julia / Haskell 88%, PHP 88%, R / Crystal 86%,
Java / Lua 87%, C++ / Elixir / Nim / OCaml 86%, Ada 84%,
Rust / D / Kotlin / PowerShell 85%, C 85%, Zig 80%, Dart 85%,
F# / Erlang / Gleam / VB.NET 84%, Groovy 84%, Clojure / Scala /
LFE 82–85%, C# 85%, Swift 82%, Fortran 86%, Python 80%, Node.js 78%,
Ruby 73%.

**Every binding now sits in the same 82–92% band on both shapes
at 64 MB**, converging after the Wave 3 perf-fix cascade
(pooled scratch + zero-copy `_into` primitives + reusable bench
buffers landed across ten bindings — Julia, Ruby, R, Fortran, C++,
Dart, PHP, Nim, OCaml, Java, plus JVM cascade to Kotlin, Groovy,
Clojure, Scala via the shared Java jar). Julia's Stream row
improved 71% → 88% (+17 pp), R's Stream 63% → 86% (+23 pp),
Fortran's Stream 72% → 86% (+14 pp), C++ Stream 78% → 86% (+8 pp).
Ruby remains the fleet floor at ~73% both shapes — MRI FFI
allocator plus per-call `ObjectSpace.define_finalizer` handle
chain is the language ceiling; documented in the Ruby binding's
Limitations section.

**~9–18% residual vs native Go** at the top of the band splits
into two roughly equal halves: the `triple.Pipeline` layer (an
extra Go-side wrap over the raw `Encrypt3x512Cfg` entry the root
Go bench drives directly), addressed by the wire-buffer pre-sizing
patch already in the shipped `triple/message.go` + `capi/triple.go`;
and the c-shared / cgo runtime itself (signal + scheduler
mechanics plus GC work when the main thread is external) which
is not addressable with a minimal Go-side patch.

## Reproduction

Every binding exposes the same env-var surface; `run_bench.sh`
sets defaults that reproduce the canonical config, and the caller
can override any field on the command line.

Every binding accepts the same env vars:

| env var             | default                       |
|---------------------|-------------------------------|
| `ITB_INNER_HASH`    | `areion512`                   |
| `ITB_KEY_BITS`      | `1024`                        |
| `ITB_NONCE_BITS`    | `512`                         |
| `ITB_WITH_MAC`      | `false`                       |
| `ITB_WITH_PARALLAX` | `false`                       |
| `ITB_WITH_WRAPPER`  | `false`                       |
| `ITB_PROFILE`       | Message: `singlemsg-triple-nomac-v1` / Stream: `streaming-noaead-triple-v1` (both switch to `-mac-v1` / `-aead-triple-mac-v1` when `ITB_WITH_MAC=true`) |
| `ITB_MSG_PROFILE`   | Message-shape override — falls back to `ITB_PROFILE`, then the derived MAC/no-MAC default |
| `ITB_STREAM_PROFILE`| Stream-shape override — same fallback chain as `ITB_MSG_PROFILE` |
| `ITB_BENCH_MIN_SEC` | `5`                           |
| `ITB_GOMEMLIMIT`    | `512MiB`                      |
| `ITB_GOGC`          | `20`                          |

`ITB_WITH_MAC=true` is the single knob that switches Message from the no-MAC profile to the MAC-authenticated profile AND simultaneously switches Stream from the non-AEAD profile to the AEAD profile — one boolean covers "authentication ON" on both shapes symmetrically. Expert callers pass `ITB_PROFILE=<name>` to force any specific profile (bypasses derivation), or `ITB_MSG_PROFILE` / `ITB_STREAM_PROFILE` for per-shape fine-grained overrides (e.g. MAC Message + non-AEAD Stream in one call). The full-production tables above run with `ITB_WITH_MAC=true ITB_WITH_PARALLAX=true ITB_WITH_WRAPPER=true`.

Per-binding run scripts:

```sh
./bindings/rust/run_bench.sh          # cargo bench (Criterion)
./bindings/c/run_bench.sh             # make bench + plain MB/s
./bindings/cpp/run_bench.sh           # make bench + plain MB/s
./bindings/ada/run_bench.sh           # alr build + Ada Real_Time timing
./bindings/dlang/run_bench.sh         # dub build + MonoTime
./bindings/csharp/run_bench.sh        # dotnet run Itb.Bench + Stopwatch
./bindings/python/run_bench.sh        # ctypes + perf_counter
./bindings/nodejs/run_bench.sh        # koffi + performance.now
./bindings/fortran/run_bench.sh       # gfortran + system_clock
./bindings/swift/run_bench.sh         # swift build -c release + DispatchTime
./bindings/java/run_bench.sh          # gradle :runBench + System.nanoTime
./bindings/zig/run_bench.sh           # zig build -Doptimize=ReleaseFast + std.time.Instant
./bindings/kotlin/run_bench.sh        # gradle :runBench + System.nanoTime
./bindings/erlang/run_bench.sh        # rebar3 escript + erlang:monotonic_time
./bindings/scala/run_bench.sh         # sbt bench/run + System.nanoTime
./bindings/groovy/run_bench.sh        # gradle :runBench + System.nanoTime
./bindings/elixir/run_bench.sh        # mix run bench.exs + System.monotonic_time
./bindings/powershell/run_bench.sh    # pwsh Invoke-Bench + Stopwatch
./bindings/clojure/run_bench.sh       # clojure -M:bench + System.nanoTime
./bindings/fsharp/run_bench.sh        # dotnet run --project bench + Stopwatch
./bindings/vbnet/run_bench.sh         # dotnet run --project bench + Stopwatch
./bindings/gleam/run_bench.sh         # gleam run -m itb_bench
./bindings/lfe/run_bench.sh           # rebar3 lfe run
./bindings/php/run_bench.sh           # php bench/bench.php + microtime
./bindings/ruby/run_bench.sh          # ruby bench/bench.rb + Process.clock_gettime
./bindings/dart/run_bench.sh          # dart run bench/bench.dart + Stopwatch
./bindings/lua/run_bench.sh           # lua bench/bench.lua + itb.now
./bindings/nim/run_bench.sh           # nim c -d:release + monoTimes
./bindings/crystal/run_bench.sh       # crystal build --release + Time.monotonic
./bindings/julia/run_bench.sh         # julia --project bench/bench.jl + time_ns
./bindings/ocaml/run_bench.sh         # dune exec bench/bench.exe + Unix.gettimeofday
./bindings/haskell/run_bench.sh       # cabal bench + getMonotonicTime
./bindings/r/run_bench.sh             # Rscript bench/bench.R + Sys.time
```

Output format stays language-native (Criterion prose for Rust,
plain MB/s table for rows that share `bench_util`'s table shape,
runtime-specific tables for the remainder). A cross-binding
aggregator script that parses each format into a single table
lands as a follow-up.

## Extension

Every new binding under `bindings/<lang>/` lands with the same
env-var surface + canonical config baked into its `run_bench.sh`
defaults, and a row per shape (Message + Stream) added to the
tables above.
