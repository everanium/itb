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
| **Rust** (thin proxy)                |     78 |     156 |     195 |    127 |     241 |     253 |
| **C** (thin proxy)                   |     76 |     175 |     193 |    122 |     243 |     254 |
| **C++** (thin proxy)                 |     77 |     174 |     194 |    130 |     246 |     249 |
| **Ada** (thin proxy)                 |     75 |     171 |     183 |    126 |     236 |     241 |
| **D** (thin proxy)                   |     77 |     178 |     192 |    128 |     247 |     253 |
| **C#** (thin proxy)                  |     75 |     174 |     190 |    123 |     235 |     250 |
| **Python** (thin proxy)              |     67 |     158 |     177 |    125 |     236 |     225 |
| **Node.js** (thin proxy)             |     73 |     168 |     178 |    118 |     229 |     221 |
| **Fortran** (thin proxy)             |     77 |     180 |     197 |    128 |     247 |     255 |
| **Swift** (thin proxy)               |     73 |     174 |     181 |    120 |     224 |     241 |
| **Java** (thin proxy)                |     77 |     171 |     193 |    128 |     236 |     252 |
| **Zig** (thin proxy)                 |     74 |     177 |     193 |    121 |     240 |     253 |
| **Kotlin** (JVM)                     |     75 |     168 |     169 |    119 |     226 |     208 |
| **Erlang** (NIF)                     |     69 |     170 |     188 |    117 |     238 |     248 |
| **Scala** (JVM)                      |     75 |     167 |     183 |    122 |     228 |     239 |
| **Groovy** (JVM)                     |     74 |     165 |     186 |    123 |     229 |     243 |
| **Elixir** (BEAM over Erlang NIF)    |     74 |     173 |     186 |    114 |     238 |     248 |
| **PowerShell** (over C#)             |     72 |     166 |     185 |    113 |     221 |     243 |
| **Clojure** (JVM)                    |     72 |     171 |     185 |    121 |     230 |     240 |
| **F#** (over C#)                     |     72 |     156 |     184 |    113 |     215 |     246 |
| **VB.NET** (over C#)                 |     76 |     173 |     181 |    122 |     236 |     240 |
| **Gleam** (BEAM over Erlang NIF)     |     73 |     173 |     190 |    117 |     239 |     248 |
| **LFE** (BEAM over Erlang NIF)       |     74 |     166 |     185 |    117 |     227 |     240 |
| **PHP** (FFI)                        |     76 |     174 |     195 |    125 |     233 |     241 |
| **Ruby** (ffi gem)                   |     75 |     148 |     150 |    126 |     237 |     222 |
| **Dart** (dart:ffi)                  |     78 |     173 |     188 |    125 |     233 |     245 |
| **Lua** (C module)                   |     75 |     172 |     185 |    124 |     244 |     244 |
| **Nim** (thin proxy)                 |     76 |     174 |     174 |    131 |     245 |     235 |
| **Crystal** (thin proxy)             |     76 |     176 |     194 |    122 |     236 |     254 |
| **Julia** (ccall)                    |     74 |     174 |     193 |    125 |     243 |     252 |
| **OCaml** (ocaml-ctypes)             |     76 |     174 |     185 |    124 |     246 |     246 |
| **Haskell** (foreign import ccall)   |     77 |     179 |     195 |    129 |     246 |     259 |
| **R** (.Call via C shim)             |     68 |     171 |     169 |    120 |     220 |     211 |

### Stream pump shape (multi-call session — Begin / Write / End / Read / Free)

`E` columns time the encrypt path; `D` columns time the decrypt path
on wire pre-produced outside the timing loop.

| Binding                              | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|--------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native** (stream)               |    104 |     189 |     204 |    132 |     249 |     257 |
| **Rust** (stream pump)               |     83 |     161 |     168 |     98 |     200 |     205 |
| **C** (stream pump)                  |     86 |     153 |     166 |    102 |     202 |     204 |
| **C++** (stream pump)                |     90 |     164 |     175 |     94 |     210 |     216 |
| **Ada** (stream pump)                |     92 |     165 |     170 |    104 |     209 |     205 |
| **D** (stream pump)                  |     94 |     162 |     170 |    104 |     208 |     208 |
| **C#** (stream pump)                 |     87 |     160 |     151 |     92 |     202 |     188 |
| **Python** (stream pump)             |     71 |     158 |     159 |    101 |     199 |     196 |
| **Node.js** (stream pump)            |     75 |     145 |     156 |     84 |     175 |     180 |
| **Fortran** (stream pump)            |     97 |     167 |     172 |    102 |     211 |     214 |
| **Swift** (stream pump)              |     81 |     151 |     158 |     96 |     173 |     194 |
| **Java** (stream pump)               |     94 |     167 |     177 |    104 |     209 |     214 |
| **Zig** (stream pump)                |     86 |     159 |     166 |    102 |     200 |     206 |
| **Kotlin** (stream pump)             |     86 |     156 |     165 |     95 |     199 |     200 |
| **Erlang** (stream pump)             |     89 |     164 |     167 |    102 |     210 |     209 |
| **Scala** (stream pump)              |     82 |     152 |     151 |     98 |     197 |     172 |
| **Groovy** (stream pump)             |     86 |     156 |     150 |     97 |     189 |     195 |
| **Elixir** (stream pump)             |     93 |     161 |     171 |    100 |     213 |     202 |
| **PowerShell** (stream pump)         |     84 |     157 |     164 |     91 |     197 |     182 |
| **Clojure** (stream pump)            |     79 |     159 |     167 |     95 |     199 |     202 |
| **F#** (stream pump)                 |     89 |     160 |     169 |     94 |     202 |     208 |
| **VB.NET** (stream pump)             |     85 |     149 |     147 |     92 |     183 |     195 |
| **Gleam** (stream pump)              |     86 |     168 |     172 |    102 |     211 |     212 |
| **LFE** (stream pump)                |     92 |     145 |     152 |    102 |     179 |     213 |
| **PHP** (stream pump)                |     95 |     171 |     176 |     99 |     207 |     216 |
| **Ruby** (stream pump)               |    108 |     136 |     145 |     99 |     182 |     193 |
| **Dart** (stream pump)               |     89 |     165 |     174 |     94 |     207 |     212 |
| **Lua** (stream pump)                |     95 |     164 |     173 |    103 |     199 |     208 |
| **Nim** (stream pump)                |    114 |     167 |     175 |    102 |     214 |     212 |
| **Crystal** (stream pump)            |     97 |     169 |     176 |    104 |     216 |     219 |
| **Julia** (stream pump)              |     90 |     151 |     174 |     99 |     198 |     215 |
| **OCaml** (stream pump)              |     96 |     166 |     173 |    100 |     214 |     214 |
| **Haskell** (stream pump)            |    129 |     172 |     178 |    118 |     208 |     214 |
| **R** (stream pump)                  |     97 |     169 |     177 |    101 |     212 |     223 |

### Stream one-shot shape (single FFI call, whole plaintext through `encrypt_stream_one_shot`)

The one-shot Stream API surface (`encrypt_stream_one_shot(plain) → wire` and its decrypt counterpart) reaches the same direct whole-buffer fast path as the Message shape when parallax is off — the produced wire is a single-chunk Streaming wire, byte-shape-identical to Message wire at the file level. Callers holding the whole plaintext in memory pick this path over the incremental pump session.

| Binding                              | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|--------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native** (stream one-shot)      |     98 |     187 |     200 |    113 |     244 |     250 |
| **Rust** (thin proxy)                |     76 |     168 |     193 |    123 |     239 |     245 |
| **C** (thin proxy)                   |     74 |     176 |     191 |    119 |     236 |     220 |
| **C++** (thin proxy)                 |     76 |     180 |     198 |    131 |     248 |     262 |
| **Ada** (thin proxy)                 |     76 |     173 |     181 |    129 |     236 |     238 |
| **D** (thin proxy)                   |     76 |     175 |     191 |    130 |     237 |     251 |
| **C#** (thin proxy)                  |     71 |     169 |     188 |    121 |     238 |     247 |
| **Python** (thin proxy)              |     66 |     155 |     166 |    126 |     231 |     222 |
| **Node.js** (thin proxy)             |     69 |     169 |     186 |    112 |     239 |     244 |
| **Fortran** (thin proxy)             |     76 |     176 |     194 |    132 |     242 |     258 |
| **Swift** (thin proxy)               |     73 |     172 |     188 |    120 |     235 |     245 |
| **Java** (thin proxy)                |     75 |     170 |     186 |    122 |     230 |     240 |
| **Zig** (thin proxy)                 |     73 |     173 |     189 |    120 |     237 |     244 |
| **Kotlin** (JVM)                     |     76 |     168 |     182 |    126 |     230 |     238 |
| **Erlang** (NIF)                     |     73 |     172 |     190 |    117 |     235 |     246 |
| **Scala** (JVM)                      |     76 |     166 |     185 |    120 |     227 |     238 |
| **Groovy** (JVM)                     |     75 |     168 |     183 |    124 |     230 |     240 |
| **Elixir** (BEAM over Erlang NIF)    |     72 |     167 |     188 |    116 |     232 |     222 |
| **PowerShell** (over C#)             |     72 |     169 |     162 |    114 |     234 |     242 |
| **Clojure** (JVM)                    |     75 |     169 |     185 |    124 |     234 |     245 |
| **F#** (over C#)                     |     73 |     173 |     187 |    126 |     238 |     251 |
| **VB.NET** (over C#)                 |     75 |     169 |     188 |    125 |     237 |     250 |
| **Gleam** (BEAM over Erlang NIF)     |     74 |     170 |     189 |    118 |     237 |     248 |
| **LFE** (BEAM over Erlang NIF)       |     73 |     170 |     188 |    119 |     237 |     247 |
| **PHP** (FFI)                        |     78 |     152 |     183 |    127 |     203 |     249 |
| **Ruby** (ffi gem)                   |     75 |     150 |     146 |    125 |     232 |     218 |
| **Dart** (dart:ffi)                  |     72 |     171 |     186 |    112 |     228 |     243 |
| **Lua** (C module)                   |     76 |     168 |     186 |    124 |     241 |     240 |
| **Nim** (thin proxy)                 |     77 |     175 |     197 |    131 |     244 |     260 |
| **Crystal** (thin proxy)             |     77 |     171 |     192 |    127 |     237 |     252 |
| **Julia** (ccall)                    |     75 |     176 |     190 |    124 |     238 |     247 |
| **OCaml** (ocaml-ctypes)             |     77 |     174 |     184 |    124 |     236 |     243 |
| **Haskell** (foreign import ccall)   |     78 |     179 |     197 |    128 |     244 |     257 |
| **R** (.Call via C shim)             |     71 |     169 |     185 |    121 |     238 |     242 |

### Message shape — full production (MAC on, parallax on, wrapper on)

Same rows as above under `ITB_WITH_MAC=true ITB_WITH_PARALLAX=true ITB_WITH_WRAPPER=true`, exercising the shipped `singlemsg-triple-mac-v1` profile with parallax and wrapper overlays engaged.

| Binding                              | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|--------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native** (message)              |     60 |     138 |     157 |     92 |     195 |     205 |
| **Rust** (thin proxy)                |     55 |     131 |     151 |     83 |     185 |     186 |
| **C** (thin proxy)                   |     52 |     129 |     147 |     78 |     181 |     181 |
| **C++** (thin proxy)                 |     51 |     115 |     131 |     77 |     162 |     170 |
| **Ada** (thin proxy)                 |     51 |     110 |     127 |     75 |     156 |     159 |
| **D** (thin proxy)                   |     55 |     126 |     146 |     79 |     178 |     188 |
| **C#** (thin proxy)                  |     54 |     129 |     143 |     79 |     176 |     188 |
| **Python** (thin proxy)              |     48 |     116 |     132 |     77 |     174 |     167 |
| **Node.js** (thin proxy)             |     53 |     126 |     138 |     79 |     180 |     176 |
| **Fortran** (thin proxy)             |     55 |     131 |     151 |     83 |     187 |     192 |
| **Swift** (thin proxy)               |     54 |     124 |     144 |     77 |     180 |     185 |
| **Java** (thin proxy)                |     54 |     127 |     147 |     80 |     183 |     188 |
| **Zig** (thin proxy)                 |     52 |     126 |     142 |     76 |     178 |     184 |
| **Kotlin** (JVM)                     |     54 |     126 |     139 |     80 |     162 |     173 |
| **Erlang** (NIF)                     |     54 |     128 |     146 |     77 |     182 |     185 |
| **Scala** (JVM)                      |     54 |     123 |     145 |     80 |     176 |     182 |
| **Groovy** (JVM)                     |     50 |     112 |     128 |     73 |     153 |     157 |
| **Elixir** (BEAM over Erlang NIF)    |     50 |     126 |     143 |     72 |     179 |     187 |
| **PowerShell** (over C#)             |     52 |     126 |     142 |     74 |     173 |     178 |
| **Clojure** (JVM)                    |     53 |     127 |     139 |     80 |     170 |     182 |
| **F#** (over C#)                     |     52 |     111 |     125 |     76 |     158 |     164 |
| **VB.NET** (over C#)                 |     53 |     130 |     147 |     79 |     180 |     175 |
| **Gleam** (BEAM over Erlang NIF)     |     50 |     124 |     141 |     72 |     174 |     181 |
| **LFE** (BEAM over Erlang NIF)       |     52 |     119 |     141 |     73 |     171 |     180 |
| **PHP** (FFI)                        |     53 |     126 |     145 |     78 |     173 |     179 |
| **Ruby** (ffi gem)                   |     42 |     104 |     116 |     79 |     168 |     157 |
| **Dart** (dart:ffi)                  |     54 |     129 |     150 |     80 |     182 |     182 |
| **Lua** (C module)                   |     50 |     119 |     144 |     75 |     178 |     181 |
| **Nim** (thin proxy)                 |     53 |     118 |     140 |     79 |     169 |     174 |
| **Crystal** (thin proxy)             |     52 |     114 |     132 |     77 |     158 |     172 |
| **Julia** (ccall)                    |     55 |     124 |     145 |     80 |     182 |     185 |
| **OCaml** (ocaml-ctypes)             |     54 |     117 |     144 |     79 |     170 |     185 |
| **Haskell** (foreign import ccall)   |     56 |     127 |     147 |     82 |     184 |     192 |
| **R** (.Call via C shim)             |     50 |     125 |     135 |     80 |     178 |     181 |

### Stream pump shape — full production (AEAD on, parallax on, wrapper on)

Same rows as above under `ITB_WITH_MAC=true ITB_WITH_PARALLAX=true ITB_WITH_WRAPPER=true`, exercising `streaming-aead-triple-mac-v1` with parallax and wrapper overlays engaged.

| Binding                              | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|--------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native** (stream)               |     60 |     140 |     158 |     99 |     194 |     211 |
| **Rust** (stream pump)               |     56 |     128 |     136 |     79 |     168 |     174 |
| **C** (stream pump)                  |     50 |     107 |     126 |     73 |     151 |     156 |
| **C++** (stream pump)                |     54 |     118 |     130 |     74 |     152 |     160 |
| **Ada** (stream pump)                |     54 |     115 |     131 |     74 |     154 |     159 |
| **D** (stream pump)                  |     57 |     131 |     145 |     80 |     172 |     178 |
| **C#** (stream pump)                 |     53 |     122 |     144 |     72 |     168 |     178 |
| **Python** (stream pump)             |     47 |     120 |     126 |     74 |     157 |     158 |
| **Node.js** (stream pump)            |     47 |     112 |     134 |     67 |     154 |     159 |
| **Fortran** (stream pump)            |     58 |     131 |     144 |     81 |     172 |     178 |
| **Swift** (stream pump)              |     53 |     123 |     130 |     79 |     124 |     171 |
| **Java** (stream pump)               |     56 |     126 |     147 |     79 |     165 |     176 |
| **Zig** (stream pump)                |     50 |     122 |     138 |     78 |     163 |     170 |
| **Kotlin** (stream pump)             |     51 |     112 |     134 |     73 |     158 |     166 |
| **Erlang** (stream pump)             |     53 |     130 |     146 |     78 |     168 |     180 |
| **Scala** (stream pump)              |     53 |     125 |     144 |     77 |     164 |     175 |
| **Groovy** (stream pump)             |     53 |     123 |     133 |     75 |     166 |     169 |
| **Elixir** (stream pump)             |     54 |     130 |     147 |     78 |     171 |     178 |
| **PowerShell** (stream pump)         |     52 |     122 |     140 |     71 |     162 |     173 |
| **Clojure** (stream pump)            |     53 |     123 |     142 |     75 |     163 |     175 |
| **F#** (stream pump)                 |     50 |     107 |     137 |     69 |     160 |     174 |
| **VB.NET** (stream pump)             |     53 |     126 |     144 |     74 |     167 |     175 |
| **Gleam** (stream pump)              |     54 |     128 |     138 |     78 |     172 |     161 |
| **LFE** (stream pump)                |     54 |     123 |     136 |     75 |     161 |     172 |
| **PHP** (stream pump)                |     55 |     128 |     140 |     79 |     175 |     182 |
| **Ruby** (stream pump)               |     44 |     103 |     125 |     79 |     157 |     165 |
| **Dart** (stream pump)               |     58 |     129 |     144 |     80 |     175 |     185 |
| **Lua** (stream pump)                |     50 |     120 |     140 |     76 |     162 |     170 |
| **Nim** (stream pump)                |     53 |     125 |     138 |     74 |     164 |     172 |
| **Crystal** (stream pump)            |     54 |     122 |     148 |     72 |     174 |     183 |
| **Julia** (stream pump)              |     57 |     131 |     146 |     77 |     174 |     184 |
| **OCaml** (stream pump)              |     58 |     130 |     145 |     80 |     173 |     181 |
| **Haskell** (stream pump)            |     58 |     132 |     147 |     84 |     175 |     182 |
| **R** (stream pump)                  |     57 |     131 |     145 |     83 |     174 |     180 |

### Stream one-shot shape — full production (AEAD on, parallax on, wrapper on)

Same rows as above under `ITB_WITH_MAC=true ITB_WITH_PARALLAX=true ITB_WITH_WRAPPER=true`. Under production overlays the whole-buffer fast path falls through to the streaming fallback (parallax multiplexer engages), so the numbers land within a few percent of the Stream pump baseline; the shipping API surface for callers holding a whole plaintext in memory stays symmetric with the pump path.

| Binding                              | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|--------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native** (stream one-shot)      |     60 |     140 |     158 |     99 |     194 |     211 |
| **Rust** (thin proxy)                |     57 |     126 |     153 |     82 |     185 |     191 |
| **C** (thin proxy)                   |     52 |     115 |     147 |     74 |     180 |     187 |
| **C++** (thin proxy)                 |     53 |     116 |     133 |     77 |     162 |     167 |
| **Ada** (thin proxy)                 |     52 |     114 |     127 |     77 |     158 |     160 |
| **D** (thin proxy)                   |     55 |     131 |     150 |     81 |     185 |     190 |
| **C#** (thin proxy)                  |     54 |     129 |     147 |     80 |     184 |     187 |
| **Python** (thin proxy)              |     48 |     120 |     137 |     79 |     176 |     167 |
| **Node.js** (thin proxy)             |     53 |     126 |     142 |     78 |     176 |     180 |
| **Fortran** (thin proxy)             |     54 |     134 |     148 |     81 |     188 |     190 |
| **Swift** (thin proxy)               |     56 |     130 |     144 |     77 |     182 |     187 |
| **Java** (thin proxy)                |     54 |     124 |     146 |     79 |     173 |     181 |
| **Zig** (thin proxy)                 |     52 |     126 |     146 |     75 |     177 |     184 |
| **Kotlin** (JVM)                     |     52 |     110 |     124 |     75 |     159 |     162 |
| **Erlang** (NIF)                     |     53 |     129 |     143 |     78 |     179 |     188 |
| **Scala** (JVM)                      |     54 |     126 |     145 |     82 |     178 |     183 |
| **Groovy** (JVM)                     |     54 |     127 |     140 |     80 |     175 |     185 |
| **Elixir** (BEAM over Erlang NIF)    |     51 |     126 |     141 |     76 |     178 |     189 |
| **PowerShell** (over C#)             |     51 |     123 |     139 |     76 |     175 |     180 |
| **Clojure** (JVM)                    |     55 |     124 |     128 |     80 |     164 |     160 |
| **F#** (over C#)                     |     53 |     125 |     130 |     79 |     172 |     170 |
| **VB.NET** (over C#)                 |     53 |     126 |     144 |     79 |     180 |     180 |
| **Gleam** (BEAM over Erlang NIF)     |     50 |     122 |     128 |     73 |     156 |     162 |
| **LFE** (BEAM over Erlang NIF)       |     51 |     123 |     137 |     75 |     164 |     174 |
| **PHP** (FFI)                        |     54 |     121 |     137 |     81 |     176 |     182 |
| **Ruby** (ffi gem)                   |     43 |     105 |     119 |     83 |     170 |     156 |
| **Dart** (dart:ffi)                  |     54 |     126 |     139 |     78 |     175 |     184 |
| **Lua** (C module)                   |     52 |     125 |     134 |     78 |     174 |     164 |
| **Nim** (thin proxy)                 |     54 |     117 |     138 |     79 |     171 |     192 |
| **Crystal** (thin proxy)             |     57 |     130 |     152 |     83 |     185 |     191 |
| **Julia** (ccall)                    |     55 |     120 |     140 |     82 |     182 |     171 |
| **OCaml** (ocaml-ctypes)             |     53 |     128 |     135 |     81 |     175 |     174 |
| **Haskell** (foreign import ccall)   |     56 |     131 |     149 |     83 |     182 |     192 |
| **R** (.Call via C shim)             |     52 |     126 |     145 |     82 |     182 |     183 |

Production shape throughputs sit below the canonical (non-authenticated / no-overlay) numbers across the fleet — the parallax and wrapper overlays plus the MAC composition add per-chunk cost on both encrypt and decrypt paths.

Throughput in MB/s. Go native row is [BENCH3.md](../BENCH3.md) Triple 1024-bit Areion-SoEM-512 Encrypt at `ITB_NONCE_BITS=512` with the same heap caps applied. Plaintext is CSPRNG-filled per binding via each language's standard secure-random API so the COBS path sees identical byte-content distributions across rows. The 1 MB column carries visible GC-cycle noise; the 16 MB and 64 MB columns are stable. Runs are sequential — one binding at a time so parallel benches never interfere.

## FFI overhead

Per-binding throughputs across every shape sit in a band as a percentage of native Go at 64 MB; the raw numbers are the tables above. Ruby sits at the fleet floor — the MRI FFI allocator plus the per-call `ObjectSpace.define_finalizer` handle chain is the language ceiling, documented in the Ruby binding's Limitations section. The top of the band tracks languages with the leanest FFI crossing (Haskell / C++ / Fortran on Message and Stream one-shot; Haskell / Fortran / OCaml / R on Stream pump).

The whole-buffer Message and Stream one-shot shapes cluster together — both reach the direct fast path in `triple.Pipeline` when parallax is off — while the Stream pump shape sits ~15-20 MB/s below at the same primitive because the incremental session pays per-chunk container and MAC-binding costs. Under production overlays the parallax multiplexer engages on every path and the three shapes converge into a single band.

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
defaults, and a row per shape (Message, Stream pump, Stream one-shot)
added to the tables above.
