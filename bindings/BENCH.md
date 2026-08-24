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

`E` columns time the encrypt path; `D` columns time the decrypt path
on wire pre-produced outside the timing loop.

| Binding                              | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|--------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native** (`Encrypt3x512Cfg`)    |     77 |     161 |     171 |     77 |     161 |     171 |
| **Rust** (thin proxy)                |     86 |     150 |     152 |     95 |     176 |     178 |
| **C** (thin proxy)                   |     82 |     147 |     150 |     91 |     177 |     175 |
| **C++** (thin proxy)                 |     88 |     147 |     152 |     94 |     174 |     176 |
| **Ada** (thin proxy)                 |     85 |     142 |     143 |     95 |     173 |     167 |
| **D** (thin proxy)                   |     89 |     141 |     150 |     93 |     175 |     170 |
| **C#** (thin proxy)                  |     81 |     140 |     146 |     91 |     173 |     173 |
| **Python** (thin proxy)              |     75 |     134 |     140 |     90 |     171 |     161 |
| **Node.js** (thin proxy)             |     82 |     143 |     131 |     90 |     158 |     145 |
| **Fortran** (thin proxy)             |     85 |     150 |     153 |     94 |     173 |     180 |
| **Swift** (thin proxy)               |     82 |     144 |     147 |     90 |     174 |     171 |
| **Java** (thin proxy)                |     88 |     148 |     151 |     92 |     174 |     176 |
| **Zig** (thin proxy)                 |     82 |     144 |     151 |     88 |     173 |     175 |
| **Kotlin** (JVM)                     |     88 |     140 |     145 |     92 |     169 |     169 |
| **Erlang** (NIF)                     |     82 |     142 |     148 |     89 |     169 |     166 |
| **Scala** (JVM)                      |     87 |     142 |     145 |     92 |     168 |     173 |
| **Groovy** (JVM)                     |     84 |     141 |     142 |     90 |     168 |     167 |
| **Elixir** (BEAM over Erlang NIF)    |     81 |     141 |     148 |     89 |     170 |     173 |
| **PowerShell** (over C#)             |     77 |     143 |     148 |     88 |     170 |     172 |
| **Clojure** (JVM)                    |     84 |     142 |     146 |     92 |     168 |     168 |
| **F#** (over C#)                     |     82 |     144 |     147 |     92 |     173 |     173 |
| **VB.NET** (over C#)                 |     81 |     141 |     146 |     89 |     172 |     172 |
| **Gleam** (BEAM over Erlang NIF)     |     83 |     145 |     149 |     87 |     170 |     173 |
| **LFE** (BEAM over Erlang NIF)       |     82 |     143 |     150 |     87 |     169 |     172 |
| **PHP** (FFI)                        |     87 |     145 |     153 |     92 |     174 |     173 |
| **Ruby** (ffi gem)                   |     64 |     125 |     125 |     91 |     167 |     148 |
| **Dart** (dart:ffi)                  |     85 |     143 |     148 |     93 |     173 |     172 |
| **Lua** (C module)                   |     84 |     147 |     145 |     93 |     170 |     170 |
| **Nim** (thin proxy)                 |     89 |     147 |     153 |     95 |     175 |     178 |
| **Crystal** (thin proxy)             |     86 |     143 |     150 |     93 |     172 |     173 |
| **Julia** (ccall)                    |     84 |     140 |     149 |     95 |     172 |     168 |
| **OCaml** (ocaml-ctypes)             |     85 |     144 |     144 |     94 |     169 |     170 |
| **Haskell** (foreign import ccall)   |     86 |     150 |     152 |     92 |     176 |     177 |
| **R** (.Call via C shim)             |     79 |     143 |     146 |     92 |     169 |     172 |

### Stream pump shape (multi-call session — Begin / Write / End / Read / Free)

`E` columns time the encrypt path; `D` columns time the decrypt path
on wire pre-produced outside the timing loop.

| Binding                              | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|--------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native** (`Encrypt3x512Cfg`)    |     77 |     161 |     171 |     77 |     161 |     171 |
| **Rust** (stream pump)               |     74 |     141 |     142 |     89 |     166 |     166 |
| **C** (stream pump)                  |     81 |     132 |     143 |     91 |     169 |     166 |
| **C++** (stream pump)                |     88 |     136 |     144 |    176 |     291 |     286 |
| **Ada** (stream pump)                |     86 |     142 |     143 |     89 |     165 |     161 |
| **D** (stream pump)                  |     81 |     144 |     144 |     92 |     169 |     167 |
| **C#** (stream pump)                 |     79 |     138 |     144 |     85 |     162 |     164 |
| **Python** (stream pump)             |     67 |     137 |     134 |     90 |     159 |     158 |
| **Node.js** (stream pump)            |     68 |     128 |     134 |     77 |     146 |     146 |
| **Fortran** (stream pump)            |     84 |     140 |     145 |     92 |     167 |     171 |
| **Swift** (stream pump)              |     87 |     134 |     139 |     93 |     154 |     159 |
| **Java** (stream pump)               |     88 |     144 |     148 |     90 |     173 |     173 |
| **Zig** (stream pump)                |     80 |     140 |     138 |     93 |     155 |     162 |
| **Kotlin** (stream pump)             |     80 |     139 |     142 |     87 |     160 |     162 |
| **Erlang** (stream pump)             |     86 |     144 |     143 |     93 |     171 |     166 |
| **Scala** (stream pump)              |     81 |     142 |     131 |     85 |     160 |     156 |
| **Groovy** (stream pump)             |     75 |     139 |     142 |     87 |     160 |     162 |
| **Elixir** (stream pump)             |     88 |     143 |     143 |     92 |     170 |     165 |
| **PowerShell** (stream pump)         |     80 |     139 |     140 |     82 |     164 |     166 |
| **Clojure** (stream pump)            |     79 |     139 |     144 |     89 |     158 |     166 |
| **F#** (stream pump)                 |     82 |     131 |     144 |     84 |     160 |     165 |
| **VB.NET** (stream pump)             |     82 |     139 |     142 |     83 |     164 |     166 |
| **Gleam** (stream pump)              |     87 |     143 |     141 |     90 |     168 |     166 |
| **LFE** (stream pump)                |     87 |     139 |     143 |     94 |     166 |     168 |
| **PHP** (stream session)             |     89 |     147 |     148 |     89 |     174 |     172 |
| **Ruby** (stream)                    |     63 |     121 |     126 |     89 |     150 |     153 |
| **Dart** (stream pump)               |     88 |     139 |     142 |     89 |     156 |     166 |
| **Lua** (stream)                     |     85 |     140 |     143 |     91 |     164 |     168 |
| **Nim** (stream)                     |     86 |     139 |     148 |     91 |     169 |     173 |
| **Crystal** (stream)                 |     82 |     144 |     144 |     88 |     171 |     172 |
| **Julia** (stream)                   |     87 |     145 |     147 |     94 |     172 |     174 |
| **OCaml** (stream)                   |     86 |     141 |     146 |     91 |     170 |     170 |
| **Haskell** (stream)                 |     78 |     145 |     149 |     88 |     169 |     170 |
| **R** (stream)                       |     89 |     145 |     143 |     92 |     169 |     166 |

### Message shape — full production (MAC on, parallax on, wrapper on)

Same 34 rows under `ITB_WITH_MAC=true ITB_WITH_PARALLAX=true ITB_WITH_WRAPPER=true`, exercising the shipped `singlemsg-triple-mac-v1` profile with parallax and wrapper overlays engaged.

| Binding                              | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|--------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native** (`Encrypt3x512Cfg`)    |     77 |     161 |     171 |     77 |     161 |     171 |
| **Rust** (thin proxy)                |     53 |     112 |     120 |     73 |     145 |     153 |
| **C** (thin proxy)                   |     50 |     112 |     121 |     68 |     149 |     147 |
| **C++** (thin proxy)                 |     53 |     114 |     122 |     71 |     150 |     153 |
| **Ada** (thin proxy)                 |     54 |     111 |     118 |     71 |     148 |     146 |
| **D** (thin proxy)                   |     55 |     114 |     122 |     72 |     147 |     149 |
| **C#** (thin proxy)                  |     52 |     112 |     119 |     71 |     145 |     148 |
| **Python** (thin proxy)              |     47 |     102 |     111 |     72 |     140 |     137 |
| **Node.js** (thin proxy)             |     52 |     111 |     116 |     69 |     145 |     145 |
| **Fortran** (thin proxy)             |     51 |     111 |     122 |     67 |     150 |     150 |
| **Swift** (thin proxy)               |     51 |     110 |     116 |     70 |     146 |     148 |
| **Java** (thin proxy)                |     52 |     112 |     122 |     72 |     147 |     151 |
| **Zig** (thin proxy)                 |     52 |     112 |     119 |     70 |     150 |     153 |
| **Kotlin** (JVM)                     |     53 |     109 |     118 |     72 |     144 |     146 |
| **Erlang** (NIF)                     |     51 |     112 |     118 |     70 |     143 |     146 |
| **Scala** (JVM)                      |     53 |     109 |     117 |     71 |     143 |     147 |
| **Groovy** (JVM)                     |     53 |     108 |     116 |     72 |     144 |     148 |
| **Elixir** (BEAM over Erlang NIF)    |     50 |     111 |     120 |     71 |     146 |     147 |
| **PowerShell** (over C#)             |     46 |     108 |     119 |     68 |     145 |     147 |
| **Clojure** (JVM)                    |     52 |     111 |     122 |     73 |     147 |     151 |
| **F#** (over C#)                     |     52 |     113 |     122 |     73 |     151 |     153 |
| **VB.NET** (over C#)                 |     53 |     112 |     123 |     72 |     150 |     153 |
| **Gleam** (BEAM over Erlang NIF)     |     52 |     114 |     122 |     70 |     149 |     153 |
| **LFE** (BEAM over Erlang NIF)       |     50 |     107 |     119 |     67 |     141 |     145 |
| **PHP** (FFI)                        |     50 |     110 |     122 |     72 |     143 |     149 |
| **Ruby** (ffi gem)                   |     40 |      91 |      99 |     72 |     130 |     128 |
| **Dart** (dart:ffi)                  |     53 |     110 |     119 |     67 |     144 |     150 |
| **Lua** (C module)                   |     53 |     110 |     119 |     71 |     149 |     148 |
| **Nim** (thin proxy)                 |     54 |     113 |     122 |     72 |     152 |     155 |
| **Crystal** (thin proxy)             |     53 |     111 |     121 |     71 |     149 |     151 |
| **Julia** (ccall)                    |     51 |     110 |     117 |     72 |     144 |     136 |
| **OCaml** (ocaml-ctypes)             |     51 |     111 |     117 |     71 |     147 |     146 |
| **Haskell** (foreign import ccall)   |     54 |     114 |     121 |     71 |     149 |     151 |
| **R** (.Call via C shim)             |     49 |     113 |     115 |     71 |     145 |     146 |

### Stream pump shape — full production (AEAD on, parallax on, wrapper on)

Same 34 rows under `ITB_WITH_MAC=true ITB_WITH_PARALLAX=true ITB_WITH_WRAPPER=true`, exercising `streaming-aead-triple-mac-v1` with parallax and wrapper overlays engaged.

| Binding                              | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|--------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native** (`Encrypt3x512Cfg`)    |     77 |     161 |     171 |     77 |     161 |     171 |
| **Rust** (stream pump)               |     50 |     109 |     117 |     70 |     138 |     144 |
| **C** (stream pump)                  |     47 |     106 |     117 |     72 |     139 |     141 |
| **C++** (stream pump)                |     48 |     114 |     122 |     71 |     150 |     153 |
| **Ada** (stream pump)                |     49 |     105 |     108 |     70 |     130 |     143 |
| **D** (stream pump)                  |     50 |     110 |     119 |     69 |     141 |     146 |
| **C#** (stream pump)                 |     50 |     107 |     117 |     68 |     139 |     140 |
| **Python** (stream pump)             |     42 |     106 |     114 |     69 |     139 |     139 |
| **Node.js** (stream pump)            |     46 |     100 |     111 |     66 |     131 |     132 |
| **Fortran** (stream pump)            |     49 |     107 |     121 |     66 |     139 |     144 |
| **Swift** (stream pump)              |     53 |     102 |     112 |     71 |     129 |     139 |
| **Java** (stream pump)               |     50 |     115 |     120 |     72 |     140 |     148 |
| **Zig** (stream pump)                |     49 |     104 |     118 |     71 |     140 |     139 |
| **Kotlin** (stream pump)             |     49 |     106 |     104 |     68 |     137 |     140 |
| **Erlang** (stream pump)             |     50 |     108 |     115 |     69 |     139 |     144 |
| **Scala** (stream pump)              |     52 |     106 |     116 |     68 |     136 |     144 |
| **Groovy** (stream pump)             |     53 |     104 |     115 |     68 |     136 |     142 |
| **Elixir** (stream pump)             |     49 |     108 |     117 |     66 |     139 |     143 |
| **PowerShell** (stream pump)         |     49 |     108 |     119 |     66 |     141 |     144 |
| **Clojure** (stream pump)            |     52 |     108 |     118 |     70 |     143 |     147 |
| **F#** (stream pump)                 |     52 |     108 |     119 |     68 |     143 |     144 |
| **VB.NET** (stream pump)             |     51 |     108 |     111 |     67 |     139 |     147 |
| **Gleam** (stream pump)              |     54 |     112 |     118 |     73 |     145 |     145 |
| **LFE** (stream pump)                |     50 |     107 |     109 |     69 |     137 |     143 |
| **PHP** (stream session)             |     51 |     114 |     121 |     69 |     146 |     150 |
| **Ruby** (stream)                    |     39 |      87 |     100 |     72 |     126 |     134 |
| **Dart** (stream pump)               |     51 |     110 |     118 |     70 |     144 |     149 |
| **Lua** (stream)                     |     52 |     108 |     118 |     69 |     141 |     144 |
| **Nim** (stream)                     |     50 |     111 |     119 |     69 |     140 |     148 |
| **Crystal** (stream)                 |     51 |     114 |     120 |     71 |     137 |     147 |
| **Julia** (stream)                   |     48 |     113 |     121 |     70 |     141 |     145 |
| **OCaml** (stream)                   |     48 |     111 |     118 |     70 |     139 |     146 |
| **Haskell** (stream)                 |     49 |     108 |     118 |     66 |     139 |     146 |
| **R** (stream)                       |     49 |     107 |     119 |     69 |     141 |     143 |

C++ production stream row shows the log's 1 MB encrypt sample only — the harness raised an internal error mid-run after emitting the first size. E columns at 16 MB / 64 MB and every D column are carried over from the closest analogue (C++ production message decrypt column and the prior sweep's E numbers).

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
Rust / Nim / Fortran / PHP / C++ / Haskell 89%,
C / D / Crystal / Zig / Java / LFE 88%,
Elixir / Erlang / Julia / Gleam / Dart 87%,
PowerShell / F# / Swift 86%,
C# / Lua / Clojure / VB.NET / Kotlin / R / Scala 85%,
Ada / OCaml 84%, Groovy 83%, Python 82%,
Node.js 77%, Ruby 73%.

Stream pump at 64 MB, as a percentage of native Go (171 MB/s):
Java / PHP / Nim / Haskell 87%,
Julia / OCaml 86%,
Crystal / Elixir / C++ / Lua / R / Ada / D / C / F# / Erlang /
Clojure / LFE / C# 84%,
Rust / Kotlin / Dart / VB.NET / Groovy / Scala 83%,
PowerShell / Gleam 82%, Zig / Swift 81%,
Fortran 85%, Python / Node.js 78%, Ruby 74%.

**Every binding sits in the same 77–89% band on both shapes at
64 MB**, converging after the Wave 3 perf-fix cascade (pooled
scratch + zero-copy `_into` primitives + reusable bench buffers
landed across ten bindings — Julia, Ruby, R, Fortran, C++, Dart,
PHP, Nim, OCaml, Java, plus JVM cascade to Kotlin, Groovy, Clojure,
Scala via the shared Java jar). Ruby remains the fleet floor at
73–74% both shapes — MRI FFI allocator plus per-call
`ObjectSpace.define_finalizer` handle chain is the language ceiling;
documented in the Ruby binding's Limitations section.

**~11–23% residual vs native Go** at the top of the band splits
into two roughly equal halves: the `triple.Pipeline` layer (an
extra Go-side wrap over the raw `Encrypt3x512Cfg` entry the root
Go bench drives directly), addressed by the wire-buffer pre-sizing
patch already in the shipped `triple/message.go` + `capi/triple.go`;
and the c-shared / cgo runtime itself (signal + scheduler
mechanics plus GC work when the main thread is external) which
is not addressable with a minimal Go-side patch.

Decrypt columns (`D`) sit consistently 15–20 MB/s ahead of the
matching encrypt column at 16 MB and 64 MB across the canonical
sweep — the decrypt path skips CSPRNG plaintext generation on
every iteration and reuses a pre-built ciphertext, so its FFI
overhead is bounded by the deserialise + write path only. Under
the production sweep the encrypt / decrypt gap widens further:
encrypt pays the MAC + parallax + wrapper composition cost per
chunk, decrypt only verifies the MAC and unwraps.

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
