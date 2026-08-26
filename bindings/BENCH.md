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
| **Rust** (thin proxy)                |     78 |     176 |     190 |    131 |     237 |     250 |
| **C** (thin proxy)                   |     75 |     176 |     192 |    122 |     239 |     251 |
| **C++** (thin proxy)                 |     77 |     177 |     190 |    125 |     239 |     255 |
| **Ada** (thin proxy)                 |     77 |     171 |     180 |    128 |     241 |     239 |
| **D** (thin proxy)                   |     77 |     176 |     191 |    128 |     243 |     251 |
| **C#** (thin proxy)                  |     76 |     173 |     187 |    124 |     236 |     249 |
| **Python** (thin proxy)              |     67 |     156 |     176 |    122 |     233 |     223 |
| **Node.js** (thin proxy)             |     75 |     170 |     182 |    113 |     226 |     233 |
| **Fortran** (thin proxy)             |     77 |     174 |     195 |    131 |     245 |     256 |
| **Swift** (thin proxy)               |     75 |     170 |     181 |    115 |     232 |     242 |
| **Java** (thin proxy)                |     78 |     174 |     192 |    124 |     236 |     247 |
| **Zig** (thin proxy)                 |     75 |     173 |     192 |    122 |     230 |     249 |
| **Kotlin** (JVM)                     |     78 |     170 |     170 |    124 |     230 |     241 |
| **Erlang** (NIF)                     |     74 |     170 |     188 |    121 |     237 |     248 |
| **Scala** (JVM)                      |     76 |     167 |     178 |    121 |     227 |     234 |
| **Groovy** (JVM)                     |     75 |     170 |     183 |    126 |     229 |     240 |
| **Elixir** (BEAM over Erlang NIF)    |     75 |     172 |     190 |    120 |     236 |     247 |
| **PowerShell** (over C#)             |     73 |     169 |     146 |    118 |     223 |     246 |
| **Clojure** (JVM)                    |     75 |     166 |     178 |    124 |     226 |     232 |
| **F#** (over C#)                     |     75 |     174 |     186 |    123 |     235 |     250 |
| **VB.NET** (over C#)                 |     75 |     168 |     115 |    122 |     231 |     245 |
| **Gleam** (BEAM over Erlang NIF)     |     74 |     170 |     189 |    117 |     230 |     241 |
| **LFE** (BEAM over Erlang NIF)       |     73 |     168 |     182 |    115 |     236 |     235 |
| **PHP** (FFI)                        |     77 |     179 |     196 |    131 |     234 |     245 |
| **Ruby** (ffi gem)                   |     74 |     148 |     148 |    126 |     228 |     221 |
| **Dart** (dart:ffi)                  |     75 |     173 |     187 |    125 |     235 |     246 |
| **Lua** (C module)                   |     76 |     168 |     177 |    125 |     239 |     226 |
| **Nim** (thin proxy)                 |     77 |     154 |     190 |    124 |     228 |     259 |
| **Crystal** (thin proxy)             |     77 |     173 |     190 |    126 |     238 |     250 |
| **Julia** (ccall)                    |     75 |     174 |     191 |    127 |     236 |     251 |
| **OCaml** (ocaml-ctypes)             |     77 |     173 |     182 |    126 |     242 |     242 |
| **Haskell** (foreign import ccall)   |     77 |     179 |     196 |    128 |     242 |     255 |
| **R** (.Call via C shim)             |     72 |     172 |     183 |    126 |     232 |     241 |

### Stream pump shape (multi-call session — Begin / Write / End / Read / Free)

`E` columns time the encrypt path; `D` columns time the decrypt path
on wire pre-produced outside the timing loop.

| Binding                              | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|--------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native** (stream)               |    104 |     189 |     204 |    132 |     249 |     257 |
| **Rust** (stream pump)               |     84 |     160 |     168 |    101 |     202 |     202 |
| **C** (stream pump)                  |     87 |     154 |     166 |    103 |     203 |     204 |
| **C++** (stream pump)                |     94 |     166 |     171 |    102 |     214 |     214 |
| **Ada** (stream pump)                |     88 |     164 |     170 |    106 |     213 |     213 |
| **D** (stream pump)                  |     88 |     167 |     171 |    104 |     211 |     208 |
| **C#** (stream pump)                 |     93 |     161 |     168 |     96 |     200 |     204 |
| **Python** (stream pump)             |     71 |     153 |     155 |    103 |     189 |     184 |
| **Node.js** (stream pump)            |     74 |     140 |     153 |     83 |     175 |     178 |
| **Fortran** (stream pump)            |     96 |     164 |     176 |    104 |     214 |     215 |
| **Swift** (stream pump)              |     77 |     156 |     156 |    103 |     186 |     188 |
| **Java** (stream pump)               |     95 |     166 |     176 |    106 |     213 |     212 |
| **Zig** (stream pump)                |     86 |     157 |     164 |    105 |     207 |     204 |
| **Kotlin** (stream pump)             |     90 |     159 |     166 |     98 |     195 |     200 |
| **Erlang** (stream pump)             |     96 |     162 |     165 |    106 |     211 |     214 |
| **Scala** (stream pump)              |     92 |     159 |     166 |     97 |     198 |     202 |
| **Groovy** (stream pump)             |     90 |     161 |     167 |     96 |     199 |     202 |
| **Elixir** (stream pump)             |     96 |     166 |     172 |    104 |     210 |     202 |
| **PowerShell** (stream pump)         |     88 |     160 |     169 |     93 |     197 |     203 |
| **Clojure** (stream pump)            |     87 |     157 |     165 |     98 |     195 |     199 |
| **F#** (stream pump)                 |     92 |     162 |     166 |     96 |     198 |     208 |
| **VB.NET** (stream pump)             |     89 |     158 |     167 |     94 |     201 |     207 |
| **Gleam** (stream pump)              |     92 |     164 |     170 |    105 |     207 |     210 |
| **LFE** (stream pump)                |     90 |     163 |     170 |    104 |     204 |     211 |
| **PHP** (stream pump)                |    110 |     171 |     176 |     98 |     218 |     217 |
| **Ruby** (stream pump)               |    102 |     139 |     135 |    101 |     177 |     183 |
| **Dart** (stream pump)               |    111 |     164 |     173 |     97 |     206 |     210 |
| **Lua** (stream pump)                |    109 |     164 |     163 |    100 |     197 |     198 |
| **Nim** (stream pump)                |    111 |     168 |     174 |    104 |     211 |     211 |
| **Crystal** (stream pump)            |     93 |     169 |     177 |    102 |     213 |     213 |
| **Julia** (stream pump)              |     94 |     169 |     176 |    102 |     216 |     218 |
| **OCaml** (stream pump)              |    108 |     163 |     174 |    106 |     212 |     210 |
| **Haskell** (stream pump)            |    100 |     169 |     178 |    100 |     209 |     215 |
| **R** (stream pump)                  |    106 |     165 |     171 |    101 |     210 |     211 |

### Message shape — full production (MAC on, parallax on, wrapper on)

Same rows as above under `ITB_WITH_MAC=true ITB_WITH_PARALLAX=true ITB_WITH_WRAPPER=true`, exercising the shipped `singlemsg-triple-mac-v1` profile with parallax and wrapper overlays engaged.

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

Same rows as above under `ITB_WITH_MAC=true ITB_WITH_PARALLAX=true ITB_WITH_WRAPPER=true`, exercising `streaming-aead-triple-mac-v1` with parallax and wrapper overlays engaged.

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
| **PHP** (stream pump)                |     58 |     123 |     136 |     79 |     174 |     182 |
| **Ruby** (stream pump)               |     42 |      96 |     114 |     75 |     150 |     160 |
| **Dart** (stream pump)               |     52 |     121 |     134 |     75 |     172 |     176 |
| **Lua** (stream pump)                |     51 |     116 |     132 |     74 |     158 |     172 |
| **Nim** (stream pump)                |     50 |     116 |     132 |     75 |     159 |     176 |
| **Crystal** (stream pump)            |     57 |     124 |     135 |     78 |     170 |     175 |
| **Julia** (stream pump)              |     55 |     125 |     136 |     78 |     169 |     176 |
| **OCaml** (stream pump)              |     50 |     125 |     136 |     77 |     168 |     175 |
| **Haskell** (stream pump)            |     57 |     122 |     133 |     78 |     168 |     176 |
| **R** (stream pump)                  |     54 |     123 |     134 |     77 |     170 |     175 |

Production shape throughputs sit below the canonical (non-authenticated / no-overlay) numbers across the fleet — the parallax and wrapper overlays plus the MAC composition add per-chunk cost on both encrypt and decrypt paths.

Throughput in MB/s. Go native row is [BENCH3.md](../BENCH3.md) Triple 1024-bit Areion-SoEM-512 Encrypt at `ITB_NONCE_BITS=512` with the same heap caps applied. Plaintext is CSPRNG-filled per binding via each language's standard secure-random API so the COBS path sees identical byte-content distributions across rows. The 1 MB column carries visible GC-cycle noise; the 16 MB and 64 MB columns are stable. Runs are sequential — one binding at a time so parallel benches never interfere.

## FFI overhead

Per-binding throughputs across both shapes sit in a band as a percentage of native Go at 64 MB; the raw numbers are the tables above. Ruby sits at the fleet floor — the MRI FFI allocator plus the per-call `ObjectSpace.define_finalizer` handle chain is the language ceiling, documented in the Ruby binding's Limitations section. The top of the band tracks languages with the leanest FFI crossing (Haskell / Rust / C / C++ / Zig on Message; Julia / C++ / Fortran / R on Stream).

The residual vs native Go at the top of the band traces to the c-shared / cgo runtime boundary itself: signal handling, scheduler mechanics, and GC work when the main thread is external — not addressable with a Go-side patch.

Decrypt columns (`D`) sit consistently ahead of the matching encrypt column at 16 MB and 64 MB across the canonical sweep — the decrypt path skips CSPRNG plaintext generation and reuses a pre-built ciphertext, so its FFI overhead is bounded by the deserialise + write path only. Under the production sweep the encrypt / decrypt gap widens further: encrypt pays the MAC + parallax + wrapper composition cost per chunk, decrypt only verifies the MAC and unwraps.

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
