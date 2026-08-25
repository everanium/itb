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
| **Go native** (message)              |     95 |     164 |     175 |    104 |     203 |     207 |
| **Rust** (thin proxy)                |     79 |     132 |     137 |     88 |     169 |     175 |
| **C** (thin proxy)                   |     82 |     147 |     156 |     93 |     182 |     185 |
| **C++** (thin proxy)                 |     83 |     139 |     152 |     89 |     182 |     180 |
| **Ada** (thin proxy)                 |     84 |     145 |     150 |     94 |     184 |     163 |
| **D** (thin proxy)                   |     87 |     148 |     155 |     98 |     183 |     182 |
| **C#** (thin proxy)                  |     78 |     144 |     134 |     91 |     175 |     180 |
| **Python** (thin proxy)              |     73 |     132 |     138 |     95 |     178 |     169 |
| **Node.js** (thin proxy)             |     73 |     130 |     138 |     83 |     166 |     156 |
| **Fortran** (thin proxy)             |     86 |     151 |     155 |     97 |     182 |     185 |
| **Swift** (thin proxy)               |     82 |     142 |     150 |     90 |     179 |     180 |
| **Java** (thin proxy)                |     85 |     146 |     154 |     94 |     182 |     184 |
| **Zig** (thin proxy)                 |     80 |     146 |     157 |     88 |     179 |     171 |
| **Kotlin** (JVM)                     |     85 |     141 |     138 |     94 |     170 |     174 |
| **Erlang** (NIF)                     |     78 |     140 |     152 |     87 |     174 |     179 |
| **Scala** (JVM)                      |     84 |     140 |     152 |     94 |     179 |     181 |
| **Groovy** (JVM)                     |     84 |     115 |     145 |     95 |     175 |     177 |
| **Elixir** (BEAM over Erlang NIF)    |     83 |     144 |     153 |     91 |     178 |     176 |
| **PowerShell** (over C#)             |     71 |     129 |     142 |     81 |     161 |     163 |
| **Clojure** (JVM)                    |     83 |     139 |     132 |     94 |     178 |     169 |
| **F#** (over C#)                     |     83 |     146 |     153 |     94 |     177 |     174 |
| **VB.NET** (over C#)                 |     72 |     128 |     132 |     86 |     157 |     158 |
| **Gleam** (BEAM over Erlang NIF)     |     78 |     144 |     153 |     91 |     181 |     180 |
| **LFE** (BEAM over Erlang NIF)       |     78 |     138 |     147 |     87 |     176 |     177 |
| **PHP** (FFI)                        |     86 |     149 |     156 |     96 |     181 |     178 |
| **Ruby** (ffi gem)                   |     78 |     124 |     128 |     94 |     178 |     157 |
| **Dart** (dart:ffi)                  |     82 |     146 |     152 |     94 |     178 |     181 |
| **Lua** (C module)                   |     85 |     147 |     153 |     96 |     183 |     180 |
| **Nim** (thin proxy)                 |     84 |     148 |     153 |     93 |     179 |     176 |
| **Crystal** (thin proxy)             |     83 |     144 |     157 |     93 |     179 |     184 |
| **Julia** (ccall)                    |     80 |     139 |     154 |    100 |     184 |     183 |
| **OCaml** (ocaml-ctypes)             |     85 |     145 |     151 |     95 |     179 |     175 |
| **Haskell** (foreign import ccall)   |     86 |     152 |     161 |     97 |     186 |     189 |
| **R** (.Call via C shim)             |     70 |     134 |     135 |     84 |     163 |     176 |

### Stream pump shape (multi-call session — Begin / Write / End / Read / Free)

`E` columns time the encrypt path; `D` columns time the decrypt path
on wire pre-produced outside the timing loop.

| Binding                              | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|--------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native** (stream)               |     98 |     168 |     178 |    124 |     209 |     213 |
| **Rust** (stream pump)               |     74 |     132 |     140 |     89 |     163 |     169 |
| **C** (stream pump)                  |     81 |     136 |     146 |     96 |     173 |     173 |
| **C++** (stream pump)                |     87 |     144 |     147 |     93 |     177 |     178 |
| **Ada** (stream pump)                |     87 |     148 |     151 |     95 |     178 |     175 |
| **D** (stream pump)                  |     88 |     144 |     148 |     95 |     176 |     177 |
| **C#** (stream pump)                 |     83 |     142 |     146 |     86 |     171 |     173 |
| **Python** (stream pump)             |     69 |     139 |     141 |     94 |     166 |     166 |
| **Node.js** (stream pump)            |     66 |     123 |     122 |     79 |     139 |     144 |
| **Fortran** (stream pump)            |     88 |     144 |     150 |     95 |     175 |     177 |
| **Swift** (stream pump)              |     76 |     139 |     142 |     94 |     159 |     170 |
| **Java** (stream pump)               |     92 |     146 |     135 |     97 |     176 |     181 |
| **Zig** (stream pump)                |     76 |     126 |     135 |     86 |     158 |     154 |
| **Kotlin** (stream pump)             |     80 |     140 |     144 |     89 |     167 |     154 |
| **Erlang** (stream pump)             |     86 |     144 |     147 |     96 |     176 |     179 |
| **Scala** (stream pump)              |     84 |     140 |     148 |     91 |     163 |     172 |
| **Groovy** (stream pump)             |     78 |     138 |     146 |     85 |     165 |     167 |
| **Elixir** (stream pump)             |     89 |     143 |     151 |     99 |     176 |     171 |
| **PowerShell** (stream pump)         |     74 |     133 |     141 |     80 |     161 |     165 |
| **Clojure** (stream pump)            |     77 |     130 |     137 |     84 |     157 |     165 |
| **F#** (stream pump)                 |     76 |     141 |     148 |     88 |     170 |     172 |
| **VB.NET** (stream pump)             |     76 |     133 |     136 |     80 |     162 |     165 |
| **Gleam** (stream pump)              |     89 |     140 |     148 |     95 |     177 |     177 |
| **LFE** (stream pump)                |     85 |     142 |     148 |     93 |     172 |     179 |
| **PHP** (stream session)             |     88 |     148 |     151 |     93 |     182 |     179 |
| **Ruby** (stream)                    |     82 |     120 |     126 |     91 |     156 |     156 |
| **Dart** (stream pump)               |     79 |     142 |     148 |     88 |     171 |     174 |
| **Lua** (stream)                     |     90 |     142 |     148 |     91 |     170 |     161 |
| **Nim** (stream)                     |     88 |     147 |     138 |     91 |     162 |     181 |
| **Crystal** (stream)                 |     87 |     145 |     152 |     94 |     178 |     170 |
| **Julia** (stream)                   |     89 |     147 |     154 |     95 |     180 |     182 |
| **OCaml** (stream)                   |     87 |     144 |     153 |     96 |     178 |     178 |
| **Haskell** (stream)                 |     88 |     148 |     154 |     95 |     178 |     180 |
| **R** (stream)                       |     89 |     147 |     154 |     95 |     178 |     183 |

### Message shape — full production (MAC on, parallax on, wrapper on)

Same 34 rows under `ITB_WITH_MAC=true ITB_WITH_PARALLAX=true ITB_WITH_WRAPPER=true`, exercising the shipped `singlemsg-triple-mac-v1` profile with parallax and wrapper overlays engaged.

| Binding                              | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|--------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native** (message)              |     58 |     125 |     140 |     87 |     159 |     170 |
| **Rust** (thin proxy)                |     49 |     115 |     127 |    138 |     156 |     159 |
| **C** (thin proxy)                   |     50 |     114 |     124 |     71 |     151 |     159 |
| **C++** (thin proxy)                 |     50 |     113 |     126 |     73 |     152 |     156 |
| **Ada** (thin proxy)                 |     50 |     111 |     122 |     75 |     154 |     153 |
| **D** (thin proxy)                   |     51 |     114 |     124 |     73 |     155 |     158 |
| **C#** (thin proxy)                  |     49 |     112 |     117 |     72 |     150 |     154 |
| **Python** (thin proxy)              |     41 |     100 |     102 |     66 |     140 |     130 |
| **Node.js** (thin proxy)             |     47 |     103 |     120 |     70 |     143 |     138 |
| **Fortran** (thin proxy)             |     51 |     114 |     127 |     75 |     155 |     157 |
| **Swift** (thin proxy)               |     47 |     112 |     123 |     70 |     149 |     137 |
| **Java** (thin proxy)                |     53 |     115 |     120 |     73 |     152 |     157 |
| **Zig** (thin proxy)                 |     47 |      89 |     110 |     64 |     130 |     145 |
| **Kotlin** (JVM)                     |     49 |      97 |     110 |     67 |     130 |     139 |
| **Erlang** (NIF)                     |     49 |     111 |     122 |     70 |     150 |     154 |
| **Scala** (JVM)                      |     51 |     108 |     115 |     73 |     144 |     142 |
| **Groovy** (JVM)                     |     51 |     104 |     118 |     73 |     147 |     154 |
| **Elixir** (BEAM over Erlang NIF)    |     50 |     112 |     124 |     72 |     153 |     157 |
| **PowerShell** (over C#)             |     47 |     106 |     113 |     69 |     144 |     139 |
| **Clojure** (JVM)                    |     48 |      89 |     110 |     68 |     114 |     147 |
| **F#** (over C#)                     |     50 |     109 |     122 |     71 |     151 |     153 |
| **VB.NET** (over C#)                 |     46 |     103 |     115 |     68 |     143 |     141 |
| **Gleam** (BEAM over Erlang NIF)     |     51 |     112 |     124 |     73 |     153 |     157 |
| **LFE** (BEAM over Erlang NIF)       |     48 |     112 |     123 |     72 |     152 |     159 |
| **PHP** (FFI)                        |     52 |     104 |     113 |     74 |     134 |     143 |
| **Ruby** (ffi gem)                   |     40 |      89 |     103 |     71 |     134 |     128 |
| **Dart** (dart:ffi)                  |     51 |     110 |     125 |     73 |     152 |     153 |
| **Lua** (C module)                   |     47 |      98 |     107 |     62 |     145 |     138 |
| **Nim** (thin proxy)                 |     51 |     105 |     128 |     73 |     154 |     154 |
| **Crystal** (thin proxy)             |     51 |     113 |     123 |     72 |     149 |     158 |
| **Julia** (ccall)                    |     51 |     113 |     122 |     75 |     153 |     158 |
| **OCaml** (ocaml-ctypes)             |     50 |     113 |     122 |     72 |     151 |     151 |
| **Haskell** (foreign import ccall)   |     52 |     115 |     129 |     75 |     158 |     162 |
| **R** (.Call via C shim)             |     49 |     113 |     121 |     73 |     155 |     158 |

### Stream pump shape — full production (AEAD on, parallax on, wrapper on)

Same 34 rows under `ITB_WITH_MAC=true ITB_WITH_PARALLAX=true ITB_WITH_WRAPPER=true`, exercising `streaming-aead-triple-mac-v1` with parallax and wrapper overlays engaged.

| Binding                              | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|--------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native** (stream)               |     59 |     129 |     142 |     91 |     165 |     179 |
| **Rust** (stream pump)               |     49 |     103 |     120 |     71 |     146 |     150 |
| **C** (stream pump)                  |     48 |     107 |     120 |     75 |     144 |     147 |
| **C++** (stream pump)                |     49 |     112 |     124 |     73 |     144 |     151 |
| **Ada** (stream pump)                |     52 |     109 |     118 |     72 |     145 |     150 |
| **D** (stream pump)                  |     50 |     108 |     118 |     72 |     146 |     149 |
| **C#** (stream pump)                 |     50 |     107 |     120 |     66 |     143 |     149 |
| **Python** (stream pump)             |     41 |      96 |      99 |     65 |     130 |     128 |
| **Node.js** (stream pump)            |     43 |      96 |     102 |     64 |     128 |     133 |
| **Fortran** (stream pump)            |     51 |     114 |     125 |     72 |     143 |     152 |
| **Swift** (stream pump)              |     45 |      96 |     107 |     67 |     119 |     134 |
| **Java** (stream pump)               |     50 |     109 |     113 |     71 |     146 |     154 |
| **Zig** (stream pump)                |     45 |      92 |     112 |     68 |     133 |     131 |
| **Kotlin** (stream pump)             |     44 |      95 |     110 |     61 |     129 |     140 |
| **Erlang** (stream pump)             |     52 |     110 |     120 |     73 |     145 |     150 |
| **Scala** (stream pump)              |     49 |     108 |     119 |     68 |     143 |     148 |
| **Groovy** (stream pump)             |     53 |     104 |     119 |     69 |     143 |     150 |
| **Elixir** (stream pump)             |     53 |     114 |     122 |     74 |     142 |     146 |
| **PowerShell** (stream pump)         |     45 |     108 |     119 |     65 |     143 |     150 |
| **Clojure** (stream pump)            |     50 |     102 |     108 |     68 |     135 |     130 |
| **F#** (stream pump)                 |     51 |     106 |     119 |     71 |     144 |     150 |
| **VB.NET** (stream pump)             |     48 |     108 |     119 |     64 |     144 |     148 |
| **Gleam** (stream pump)              |     50 |     111 |     119 |     72 |     148 |     151 |
| **LFE** (stream pump)                |     50 |     107 |     119 |     73 |     145 |     147 |
| **PHP** (stream session)             |     47 |     100 |     109 |     69 |     134 |     137 |
| **Ruby** (stream)                    |     37 |      84 |      97 |     64 |     123 |     133 |
| **Dart** (stream pump)               |     50 |     110 |     116 |     71 |     148 |     153 |
| **Lua** (stream)                     |     49 |     100 |     116 |     68 |     137 |     144 |
| **Nim** (stream)                     |     49 |     111 |     114 |     72 |     144 |     136 |
| **Crystal** (stream)                 |     53 |     103 |     121 |     73 |     133 |     152 |
| **Julia** (stream)                   |     56 |     113 |     123 |     72 |     146 |     151 |
| **OCaml** (stream)                   |     49 |     113 |     122 |     71 |     147 |     151 |
| **Haskell** (stream)                 |     51 |     113 |     124 |     74 |     147 |     156 |
| **R** (stream)                       |     54 |     112 |     122 |     73 |     146 |     155 |

Production shape throughputs sit at ~70–93% of the canonical (non-authenticated / no-overlay) numbers at 64 MB Encrypt across the fleet — the parallax and wrapper overlays plus the MAC composition add per-chunk cost on both encrypt and decrypt paths; the residual reflects the composite overhead of the full production wire.

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

Message shape at 64 MB, as a percentage of native Go (175 MB/s):
Haskell 92%,
Zig / Crystal 90%,
C / D / Fortran / PHP 89%,
Java / Julia 88%,
C++ / Erlang / Scala / Elixir / F# / Gleam / Dart / Lua / Nim 87%,
Ada / Swift / OCaml 86%, LFE 84%, Groovy 83%,
PowerShell 81%,
Python / Node.js / Kotlin 79%, Rust 78%,
C# / R 77%, Clojure / VB.NET 75%, Ruby 73%.

Stream pump at 64 MB, as a percentage of native Go (178 MB/s):
Julia / Haskell / R 87%, OCaml 86%,
Ada / Elixir / PHP / Crystal 85%, Fortran 84%,
C++ / D / Erlang / Scala / F# / Gleam / LFE / Dart / Lua 83%,
C / C# / Groovy 82%, Kotlin 81%, Swift 80%,
Rust / Python / PowerShell 79%, Nim 78%, Clojure 77%,
Java / Zig / VB.NET 76%, Ruby 71%, Node.js 69%.

**Every binding sits in the 69–92% band across both shapes at
64 MB**. Ruby (71–73%) and Node.js (69% Stream) sit at the fleet
floor — MRI FFI allocator plus per-call `ObjectSpace.define_finalizer`
handle chain on the Ruby side, and V8 GC + Buffer.alloc per-op cost
on the Node.js Stream side; both are documented in the respective
binding's Limitations section. The top of the band tracks languages
with the leanest FFI crossing (Haskell / Zig / Crystal / C / D /
Fortran / PHP on Message, Julia / Haskell / R / OCaml on Stream).

**~8–27% residual vs native Go** at the top of the band splits
into two roughly equal halves: the `triple.Pipeline` layer (an
extra Go-side wrap over the raw `Encrypt3x512Cfg` entry the root
Go bench drives directly), addressed by the wire-buffer pre-sizing
patch already in the shipped `triple/message.go` + `capi/triple.go`;
and the c-shared / cgo runtime itself (signal + scheduler
mechanics plus GC work when the main thread is external) which
is not addressable with a minimal Go-side patch.

Decrypt columns (`D`) sit consistently 30–40 MB/s ahead of the
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
