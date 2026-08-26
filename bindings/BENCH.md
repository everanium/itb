# ITB Binding Fleet Benchmark Results

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

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
| **Go native** (message)              |     98 |     187 |     200 |    113 |     244 |     250 |
| **Rust** (thin proxy)                |     89 |     156 |     179 |    103 |     203 |     219 |
| **C** (thin proxy)                   |     88 |     168 |     180 |    100 |     223 |     226 |
| **C++** (thin proxy)                 |     91 |     170 |     180 |    105 |     224 |     223 |
| **Ada** (thin proxy)                 |     91 |     163 |     169 |    107 |     222 |     211 |
| **D** (thin proxy)                   |     93 |     168 |     176 |    107 |     220 |     218 |
| **C#** (thin proxy)                  |     84 |     165 |     174 |    102 |     212 |     213 |
| **Python** (thin proxy)              |     80 |     151 |     164 |    103 |     212 |     198 |
| **Node.js** (thin proxy)             |     85 |     156 |     167 |     99 |     207 |     210 |
| **Fortran** (thin proxy)             |     92 |     165 |     176 |    107 |     226 |     221 |
| **Swift** (thin proxy)               |     88 |     165 |     173 |     99 |     215 |     213 |
| **Java** (thin proxy)                |     86 |     164 |     175 |    103 |     215 |     213 |
| **Zig** (thin proxy)                 |     86 |     166 |     179 |     99 |     215 |     219 |
| **Kotlin** (JVM)                     |     92 |     159 |     159 |    103 |     207 |     204 |
| **Erlang** (NIF)                     |     88 |     163 |     177 |     98 |     217 |     219 |
| **Scala** (JVM)                      |     90 |     162 |     169 |    104 |     213 |     210 |
| **Groovy** (JVM)                     |     91 |     158 |     169 |    102 |     208 |     207 |
| **Elixir** (BEAM over Erlang NIF)    |     86 |     166 |     178 |     99 |     215 |     213 |
| **PowerShell** (over C#)             |     84 |     159 |     172 |     98 |     210 |     210 |
| **Clojure** (JVM)                    |     89 |     159 |     171 |    102 |     190 |     209 |
| **F#** (over C#)                     |     88 |     167 |     177 |    102 |     214 |     216 |
| **VB.NET** (over C#)                 |     82 |     158 |     170 |    102 |     216 |     217 |
| **Gleam** (BEAM over Erlang NIF)     |     88 |     160 |     173 |     98 |     212 |     216 |
| **LFE** (BEAM over Erlang NIF)       |     88 |     166 |     176 |     97 |     213 |     216 |
| **PHP** (FFI)                        |     93 |     167 |     178 |    107 |     209 |     210 |
| **Ruby** (ffi gem)                   |     73 |     138 |     140 |    102 |     206 |     177 |
| **Dart** (dart:ffi)                  |     93 |     163 |     174 |    104 |     218 |     216 |
| **Lua** (C module)                   |     92 |     152 |     165 |    104 |     192 |     187 |
| **Nim** (thin proxy)                 |     90 |     166 |     178 |    106 |     225 |     220 |
| **Crystal** (thin proxy)             |     90 |     164 |     178 |    103 |     214 |     218 |
| **Julia** (ccall)                    |     89 |     166 |     178 |    105 |     218 |     216 |
| **OCaml** (ocaml-ctypes)             |     89 |     164 |     170 |    101 |     216 |     206 |
| **Haskell** (foreign import ccall)   |     92 |     166 |     183 |    107 |     225 |     226 |
| **R** (.Call via C shim)             |     83 |     167 |     173 |    101 |     211 |     208 |

### Stream pump shape (multi-call session — Begin / Write / End / Read / Free)

`E` columns time the encrypt path; `D` columns time the decrypt path
on wire pre-produced outside the timing loop.

| Binding                              | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|--------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native** (stream)               |    104 |     189 |     204 |    132 |     249 |     257 |
| **Rust** (stream pump)               |     81 |     162 |     166 |    100 |     202 |     202 |
| **C** (stream pump)                  |     86 |     154 |     170 |    104 |     205 |     211 |
| **C++** (stream pump)                |     92 |     163 |     173 |    100 |     212 |     214 |
| **Ada** (stream pump)                |     96 |     166 |     164 |    102 |     209 |     200 |
| **D** (stream pump)                  |     96 |     161 |     168 |    102 |     206 |     204 |
| **C#** (stream pump)                 |     91 |     155 |     165 |     92 |     200 |     204 |
| **Python** (stream pump)             |     73 |     158 |     157 |    102 |     192 |     191 |
| **Node.js** (stream pump)            |     82 |     146 |     154 |     91 |     181 |     169 |
| **Fortran** (stream pump)            |     97 |     167 |     173 |    104 |     212 |     215 |
| **Swift** (stream pump)              |     82 |     158 |     164 |    102 |     187 |     201 |
| **Java** (stream pump)               |     94 |     165 |     172 |    102 |     207 |     210 |
| **Zig** (stream pump)                |     87 |     156 |     164 |    102 |     204 |     203 |
| **Kotlin** (stream pump)             |     88 |     158 |     166 |     98 |     200 |     199 |
| **Erlang** (stream pump)             |     93 |     164 |     168 |    104 |     209 |     202 |
| **Scala** (stream pump)              |     89 |     157 |     166 |     96 |     175 |     199 |
| **Groovy** (stream pump)             |     87 |     157 |     164 |     98 |     198 |     198 |
| **Elixir** (stream pump)             |     94 |     165 |     171 |    103 |     210 |     203 |
| **PowerShell** (stream pump)         |     88 |     160 |     167 |     94 |     200 |     200 |
| **Clojure** (stream pump)            |     90 |     152 |     162 |     98 |     200 |     205 |
| **F#** (stream pump)                 |     86 |     162 |     167 |     93 |     200 |     206 |
| **VB.NET** (stream pump)             |     87 |     160 |     153 |     94 |     199 |     203 |
| **Gleam** (stream pump)              |     93 |     163 |     166 |    102 |     208 |     208 |
| **LFE** (stream pump)                |     92 |     160 |     169 |    103 |     206 |     215 |
| **PHP** (stream session)             |     92 |     163 |     168 |    102 |     212 |     212 |
| **Ruby** (stream)                    |     74 |     133 |     142 |     98 |     180 |     184 |
| **Dart** (stream pump)               |     92 |     159 |     166 |     97 |     205 |     209 |
| **Lua** (stream)                     |     83 |     154 |     166 |     97 |     204 |     204 |
| **Nim** (stream)                     |     92 |     156 |     165 |    100 |     203 |     206 |
| **Crystal** (stream)                 |     85 |     145 |     168 |     94 |     208 |     210 |
| **Julia** (stream)                   |     95 |     166 |     175 |    102 |     212 |     217 |
| **OCaml** (stream)                   |     94 |     165 |     168 |    101 |     204 |     206 |
| **Haskell** (stream)                 |     95 |     164 |     171 |    100 |     209 |     212 |
| **R** (stream)                       |     94 |     165 |     174 |    103 |     208 |     216 |

### Message shape — full production (MAC on, parallax on, wrapper on)

Same 34 rows under `ITB_WITH_MAC=true ITB_WITH_PARALLAX=true ITB_WITH_WRAPPER=true`, exercising the shipped `singlemsg-triple-mac-v1` profile with parallax and wrapper overlays engaged.

| Binding                              | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|--------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native** (message)              |     60 |     138 |     157 |     92 |     195 |     205 |
| **Rust** (thin proxy)                |     54 |     124 |     139 |     79 |     175 |     179 |
| **C** (thin proxy)                   |     53 |     126 |     140 |     76 |     164 |     181 |
| **C++** (thin proxy)                 |     54 |     126 |     142 |     79 |     177 |     189 |
| **Ada** (thin proxy)                 |     54 |     125 |     135 |     78 |     175 |     176 |
| **D** (thin proxy)                   |     53 |     126 |     143 |     80 |     178 |     184 |
| **C#** (thin proxy)                  |     52 |     122 |     134 |     76 |     172 |     177 |
| **Python** (thin proxy)              |     48 |     116 |     131 |     78 |     170 |     171 |
| **Node.js** (thin proxy)             |     50 |     121 |     130 |     75 |     167 |     173 |
| **Fortran** (thin proxy)             |     53 |     126 |     142 |     79 |     176 |     185 |
| **Swift** (thin proxy)               |     50 |     123 |     134 |     77 |     176 |     181 |
| **Java** (thin proxy)                |     52 |     125 |     126 |     78 |     170 |     181 |
| **Zig** (thin proxy)                 |     50 |     124 |     142 |     76 |     175 |     185 |
| **Kotlin** (JVM)                     |     52 |     121 |     136 |     77 |     168 |     176 |
| **Erlang** (NIF)                     |     51 |     124 |     139 |     76 |     172 |     178 |
| **Scala** (JVM)                      |     52 |     117 |     135 |     77 |     166 |     172 |
| **Groovy** (JVM)                     |     52 |     118 |     133 |     76 |     168 |     174 |
| **Elixir** (BEAM over Erlang NIF)    |     51 |     121 |     136 |     76 |     156 |     180 |
| **PowerShell** (over C#)             |     48 |     121 |     137 |     75 |     171 |     177 |
| **Clojure** (JVM)                    |     52 |     119 |     135 |     78 |     164 |     176 |
| **F#** (over C#)                     |     52 |     122 |     134 |     78 |     171 |     178 |
| **VB.NET** (over C#)                 |     49 |     123 |     137 |     76 |     172 |     178 |
| **Gleam** (BEAM over Erlang NIF)     |     51 |     125 |     137 |     75 |     170 |     179 |
| **LFE** (BEAM over Erlang NIF)       |     51 |     117 |     135 |     75 |     151 |     172 |
| **PHP** (FFI)                        |     55 |     126 |     134 |     78 |     170 |     166 |
| **Ruby** (ffi gem)                   |     40 |      97 |     110 |     79 |     155 |     149 |
| **Dart** (dart:ffi)                  |     51 |     120 |     138 |     74 |     168 |     178 |
| **Lua** (C module)                   |     52 |     123 |     134 |     78 |     174 |     172 |
| **Nim** (thin proxy)                 |     52 |     126 |     142 |     79 |     173 |     184 |
| **Crystal** (thin proxy)             |     52 |     123 |     138 |     78 |     170 |     184 |
| **Julia** (ccall)                    |     53 |     125 |     135 |     80 |     174 |     178 |
| **OCaml** (ocaml-ctypes)             |     50 |     124 |     134 |     77 |     171 |     174 |
| **Haskell** (foreign import ccall)   |     55 |     127 |     142 |     79 |     176 |     186 |
| **R** (.Call via C shim)             |     50 |     123 |     135 |     81 |     174 |     175 |

### Stream pump shape — full production (AEAD on, parallax on, wrapper on)

Same 34 rows under `ITB_WITH_MAC=true ITB_WITH_PARALLAX=true ITB_WITH_WRAPPER=true`, exercising `streaming-aead-triple-mac-v1` with parallax and wrapper overlays engaged.

| Binding                              | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|--------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native** (stream)               |     60 |     140 |     158 |     99 |     194 |     211 |
| **Rust** (stream pump)               |     50 |     119 |     133 |     76 |     166 |     170 |
| **C** (stream pump)                  |     51 |     114 |     124 |     76 |     147 |     171 |
| **C++** (stream pump)                |     56 |     124 |     135 |     78 |     166 |     174 |
| **Ada** (stream pump)                |     57 |     120 |     135 |     78 |     165 |     172 |
| **D** (stream pump)                  |     53 |     124 |     134 |     76 |     168 |     173 |
| **C#** (stream pump)                 |     54 |     119 |     134 |     70 |     164 |     172 |
| **Python** (stream pump)             |     45 |     116 |     116 |     76 |     163 |     162 |
| **Node.js** (stream pump)            |     50 |     105 |     120 |     67 |     146 |     156 |
| **Fortran** (stream pump)            |     54 |     119 |     138 |     78 |     153 |     176 |
| **Swift** (stream pump)              |     49 |     117 |     126 |     78 |     153 |     166 |
| **Java** (stream pump)               |     54 |     123 |     137 |     78 |     171 |     178 |
| **Zig** (stream pump)                |     50 |     118 |     132 |     76 |     164 |     169 |
| **Kotlin** (stream pump)             |     56 |     116 |     132 |     74 |     164 |     173 |
| **Erlang** (stream pump)             |     51 |     121 |     133 |     77 |     166 |     176 |
| **Scala** (stream pump)              |     57 |     114 |     130 |     76 |     158 |     171 |
| **Groovy** (stream pump)             |     53 |     115 |     129 |     73 |     161 |     172 |
| **Elixir** (stream pump)             |     54 |     119 |     133 |     77 |     168 |     175 |
| **PowerShell** (stream pump)         |     51 |     117 |     132 |     74 |     165 |     172 |
| **Clojure** (stream pump)            |     54 |     116 |     131 |     75 |     165 |     171 |
| **F#** (stream pump)                 |     52 |     117 |     132 |     74 |     161 |     171 |
| **VB.NET** (stream pump)             |     50 |     115 |     130 |     69 |     163 |     169 |
| **Gleam** (stream pump)              |     53 |     120 |     132 |     78 |     166 |     170 |
| **LFE** (stream pump)                |     52 |     119 |     130 |     76 |     165 |     175 |
| **PHP** (stream session)             |     58 |     123 |     136 |     79 |     174 |     182 |
| **Ruby** (stream)                    |     42 |      96 |     114 |     75 |     150 |     160 |
| **Dart** (stream pump)               |     52 |     121 |     134 |     75 |     172 |     176 |
| **Lua** (stream)                     |     51 |     116 |     132 |     74 |     158 |     172 |
| **Nim** (stream)                     |     50 |     116 |     132 |     75 |     159 |     176 |
| **Crystal** (stream)                 |     57 |     124 |     135 |     78 |     170 |     175 |
| **Julia** (stream)                   |     55 |     125 |     136 |     78 |     169 |     176 |
| **OCaml** (stream)                   |     50 |     125 |     136 |     77 |     168 |     175 |
| **Haskell** (stream)                 |     57 |     122 |     133 |     78 |     168 |     176 |
| **R** (stream)                       |     54 |     123 |     134 |     77 |     170 |     175 |

Production shape throughputs sit at ~72–86% of the canonical (non-authenticated / no-overlay) numbers at 64 MB Encrypt across the fleet — the parallax and wrapper overlays plus the MAC composition add per-chunk cost on both encrypt and decrypt paths; the residual reflects the composite overhead of the full production wire.

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

Message shape at 64 MB, as a percentage of native Go (200 MB/s):
Haskell 92%,
Rust / C / C++ / Zig 90%,
Elixir / PHP / Nim / Crystal / Julia 89%,
D / Fortran / Java / Erlang / F# / LFE 88%,
C# / Dart 87%,
Swift / PowerShell / Clojure / Gleam / R 86%,
VB.NET / OCaml 85%,
Ada / Node.js / Scala / Groovy 84%,
Python / Lua 82%, Kotlin 80%, Ruby 70%.

Stream pump at 64 MB, as a percentage of native Go (204 MB/s):
Julia 86%, C++ / Fortran / R 85%,
Java / Elixir / Haskell 84%,
C / LFE 83%,
D / Erlang / PowerShell / F# / PHP / Crystal / OCaml 82%,
Rust / C# / Kotlin / Scala / Gleam / Dart / Lua / Nim 81%,
Ada / Swift / Zig / Groovy 80%, Clojure 79%,
Python 77%, Node.js / VB.NET 75%, Ruby 70%.

**Every binding sits in the 70–92% band across both shapes at
64 MB**. Ruby sits at the fleet floor (70% both shapes) — MRI FFI
allocator plus per-call `ObjectSpace.define_finalizer` handle chain
is the language ceiling; documented in the Ruby binding's Limitations
section. The top of the band tracks languages with the leanest FFI
crossing (Haskell / Rust / C / C++ / Zig on Message, Julia / C++ /
Fortran / R on Stream).

**~8–20% residual vs native Go** at the top of the band splits
into two roughly equal halves: the `triple.Pipeline` layer (an
extra Go-side wrap over the raw `Encrypt3x512Cfg` entry the root
Go bench drives directly), addressed by the wire-buffer pre-sizing
patch already in the shipped `triple/message.go` + `capi/triple.go`;
and the c-shared / cgo runtime itself (signal + scheduler
mechanics plus GC work when the main thread is external) which
is not addressable with a minimal Go-side patch.

Decrypt columns (`D`) sit consistently 40–65 MB/s ahead of the
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
