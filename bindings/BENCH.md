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
| Nonce width     | 512 bits (secure default)          | `ITB_NONCE_BITS`    |
| Parallax        | off                                | `ITB_WITH_PARALLAX` |
| Wrapper         | off                                | `ITB_WITH_WRAPPER`  |
| Message profile | `singlemsg-triple-nomac-v1`        | `ITB_PROFILE`       |
| Stream profile  | `streaming-noaead-triple-v1`       | `ITB_PROFILE`       |
| Wall-clock      | 5 s per case                       | `ITB_BENCH_MIN_SEC` |
| Sizes           | 1 MB, 16 MB, 64 MB                 | (hard-coded)        |
| Go runtime cap  | 512 MiB soft heap, 20% GC          | `ITB_GOMEMLIMIT` / `ITB_GOGC` |

The pin matches the root Go BENCH3.md `BenchmarkExtTripleAreion512_1024bit_*`
row so any binding's throughput is directly comparable to the Go native number.

## Intel Core i7-11700K 8C/16HT

### Message shape (buffer-in / buffer-out, single FFI call per iteration)

`E` columns time the encrypt path; `D` columns time the decrypt path
on wire pre-produced outside the timing loop.

| Binding                              | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|--------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native**                        |    117 |     191 |     225 |    238 |     281 |     326 |
| **Rust** (thin proxy)               |    109 |     178 |     213 |    216 |     245 |     286 |
| **C** (thin proxy)                  |    103 |     177 |     211 |    203 |     245 |     292 |
| **C++** (thin proxy)                |    110 |     179 |     212 |    225 |     250 |     297 |
| **Ada** (thin proxy)                |    107 |     176 |     188 |    218 |     238 |     260 |
| **D** (thin proxy)                  |    109 |     183 |     209 |    237 |     249 |     281 |
| **C#** (thin proxy)                 |    100 |     175 |     203 |    210 |     248 |     286 |
| **Python** (thin proxy)             |     88 |     160 |     188 |    217 |     232 |     243 |
| **Node.js** (thin proxy)            |    101 |     170 |     199 |    196 |     233 |     269 |
| **Fortran** (thin proxy)            |    111 |     179 |     213 |    219 |     249 |     289 |
| **Swift** (thin proxy)              |    103 |     178 |     203 |    192 |     238 |     277 |
| **Java** (thin proxy)               |    108 |     175 |     205 |    204 |     238 |     279 |
| **Zig** (thin proxy)                |    105 |     180 |     207 |    205 |     245 |     285 |
| **Kotlin** (JVM)                    |    105 |     167 |     198 |    216 |     225 |     267 |
| **Erlang** (NIF)                    |    100 |     170 |     205 |    196 |     236 |     277 |
| **Scala** (JVM)                     |    107 |     170 |     195 |    212 |     231 |     269 |
| **Groovy** (JVM)                    |    105 |     169 |     201 |    215 |     235 |     273 |
| **Elixir** (BEAM over Erlang NIF)   |    101 |     172 |     206 |    200 |     239 |     282 |
| **PowerShell** (over C#)            |     97 |     176 |     206 |    195 |     239 |     282 |
| **Clojure** (JVM)                   |    109 |     173 |     205 |    216 |     232 |     274 |
| **F#** (over C#)                    |    104 |     177 |     207 |    196 |     244 |     283 |
| **VB.NET** (over C#)                |    101 |     174 |     202 |    210 |     229 |     282 |
| **Gleam** (BEAM over Erlang NIF)    |    100 |     172 |     201 |    195 |     239 |     278 |
| **LFE** (BEAM over Erlang NIF)      |     98 |     174 |     202 |    192 |     238 |     284 |
| **PHP** (FFI)                       |    109 |     179 |     219 |    223 |     236 |     272 |
| **Ruby** (ffi gem)                  |    105 |     149 |     154 |    218 |     229 |     244 |
| **Dart** (dart:ffi)                 |    108 |     170 |     208 |    217 |     240 |     279 |
| **Lua** (C module)                  |    108 |     180 |     200 |    227 |     248 |     277 |
| **Nim** (thin proxy)                |    108 |     182 |     215 |    206 |     251 |     300 |
| **Crystal** (thin proxy)            |    106 |     179 |     210 |    203 |     238 |     289 |
| **Julia** (ccall)                   |    105 |     177 |     204 |    216 |     241 |     281 |
| **OCaml** (ocaml-ctypes)            |    105 |     178 |     201 |    218 |     246 |     275 |
| **Haskell** (foreign import ccall)  |    112 |     182 |     215 |    231 |     251 |     298 |
| **R** (.Call via C shim)            |     95 |     178 |     196 |    206 |     246 |     273 |

### Stream pump shape (multi-call session — Begin / Write / End / Read / Free)

`E` columns time the encrypt path; `D` columns time the decrypt path
on wire pre-produced outside the timing loop.

**Stream pump E 1 MB baseline shift.** The 1 MB Encrypt cell for a subset of bindings (Crystal / F# / Groovy / Haskell / Lua / Nim / R / Ruby / Rust) sits 8-34 % below the earlier baseline. The shift traces to the microBatch adaptive baseline retune (promote commit `3f38abe`) which reshapes how each binding's FFI layer amortises per-chunk work through the shared `libitb.so`. Bindings with a shared-session-many-writes iteration pattern in their bench harness absorb the retune silently or gain from it (25 of the 33 shipped bindings). The shift is not a regression in shipping cipher code — it is confined to the 1 MB Stream pump cell and does not appear on Message shape or Stream one-shot at any width. Every other cell across the fleet either holds or lifts, driven by the full ASM optimisation cycle culminating in the bridge-free ZMM interlock kernel rewrite.

| Binding                              | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|--------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native**                        |    100 |     189 |     201 |    209 |     256 |     271 |
| **Rust** (thin proxy)               |     74 |     165 |     167 |    140 |     212 |     211 |
| **C** (thin proxy)                  |     81 |     158 |     172 |    144 |     221 |     214 |
| **C++** (thin proxy)                |     90 |     164 |     179 |    140 |     221 |     221 |
| **Ada** (thin proxy)                |     87 |     170 |     174 |    148 |     214 |     217 |
| **D** (thin proxy)                  |     87 |     166 |     174 |    150 |     218 |     212 |
| **C#** (thin proxy)                 |     79 |     165 |     170 |    139 |     211 |     214 |
| **Python** (thin proxy)             |     64 |     153 |     153 |    144 |     189 |     194 |
| **Node.js** (thin proxy)            |     75 |     149 |     154 |    129 |     182 |     184 |
| **Fortran** (thin proxy)            |     88 |     168 |     178 |    146 |     221 |     223 |
| **Swift** (thin proxy)              |     76 |     160 |     164 |    155 |     197 |     206 |
| **Java** (thin proxy)               |     88 |     168 |     176 |    151 |     217 |     220 |
| **Zig** (thin proxy)                |     80 |     162 |     169 |    149 |     218 |     215 |
| **Kotlin** (JVM)                    |     78 |     158 |     170 |    142 |     205 |     206 |
| **Erlang** (NIF)                    |     84 |     166 |     169 |    148 |     218 |     219 |
| **Scala** (JVM)                     |     79 |     162 |     169 |    144 |     206 |     208 |
| **Groovy** (JVM)                    |     79 |     158 |     170 |    148 |     204 |     212 |
| **Elixir** (BEAM over Erlang NIF)   |     84 |     168 |     172 |    150 |     217 |     212 |
| **PowerShell** (over C#)            |     79 |     162 |     169 |    124 |     210 |     214 |
| **Clojure** (JVM)                   |     81 |     160 |     169 |    140 |     208 |     208 |
| **F#** (over C#)                    |     79 |     162 |     172 |    140 |     213 |     215 |
| **VB.NET** (over C#)                |     78 |     161 |     170 |    134 |     212 |     209 |
| **Gleam** (BEAM over Erlang NIF)    |     85 |     164 |     171 |    155 |     219 |     214 |
| **LFE** (BEAM over Erlang NIF)      |     86 |     168 |     174 |    148 |     223 |     225 |
| **PHP** (FFI)                       |     87 |     174 |     179 |    148 |     227 |     228 |
| **Ruby** (ffi gem)                  |     71 |     137 |     148 |    150 |     196 |     201 |
| **Dart** (dart:ffi)                 |     85 |     164 |     173 |    147 |     215 |     218 |
| **Lua** (C module)                  |     84 |     166 |     175 |    140 |     214 |     214 |
| **Nim** (thin proxy)                |     88 |     173 |     180 |    152 |     219 |     223 |
| **Crystal** (thin proxy)            |     87 |     172 |     181 |    150 |     224 |     226 |
| **Julia** (ccall)                   |     88 |     172 |     178 |    153 |     220 |     223 |
| **OCaml** (ocaml-ctypes)            |     88 |     171 |     180 |    155 |     220 |     224 |
| **Haskell** (foreign import ccall)  |     88 |     172 |     180 |    145 |     218 |     222 |
| **R** (.Call via C shim)            |     86 |     171 |     178 |    137 |     224 |     246 |

### Stream one-shot shape (single FFI call, whole plaintext through `encrypt_stream_one_shot`)

The one-shot Stream API surface (`encrypt_stream_one_shot(plain) → wire` and its decrypt counterpart) reaches the same direct whole-buffer fast path as the Message shape when parallax is off — the produced wire is a single-chunk Streaming wire, byte-shape-identical to Message wire at the file level. Callers holding the whole plaintext in memory pick this path over the incremental pump session.

| Binding                              | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|--------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native**                        |    117 |     191 |     225 |    238 |     281 |     326 |
| **Rust** (thin proxy)               |    107 |     177 |     202 |    204 |     245 |     279 |
| **C** (thin proxy)                  |    104 |     179 |     210 |    205 |     243 |     286 |
| **C++** (thin proxy)                |    111 |     180 |     213 |    227 |     247 |     293 |
| **Ada** (thin proxy)                |    108 |     176 |     200 |    224 |     244 |     276 |
| **D** (thin proxy)                  |    110 |     182 |     208 |    231 |     248 |     286 |
| **C#** (thin proxy)                 |    106 |     176 |     201 |    210 |     238 |     281 |
| **Python** (thin proxy)             |     90 |     160 |     189 |    212 |     230 |     249 |
| **Node.js** (thin proxy)            |    101 |     173 |     197 |    203 |     238 |     266 |
| **Fortran** (thin proxy)            |    110 |     180 |     208 |    221 |     249 |     290 |
| **Swift** (thin proxy)              |    102 |     174 |     200 |    202 |     239 |     275 |
| **Java** (thin proxy)               |    106 |     167 |     198 |    219 |     230 |     267 |
| **Zig** (thin proxy)                |    101 |     179 |     208 |    204 |     245 |     290 |
| **Kotlin** (JVM)                    |    107 |     170 |     200 |    216 |     234 |     266 |
| **Erlang** (NIF)                    |     99 |     171 |     204 |    192 |     236 |     278 |
| **Scala** (JVM)                     |    103 |     171 |     198 |    202 |     229 |     266 |
| **Groovy** (JVM)                    |    107 |     168 |     202 |    205 |     232 |     272 |
| **Elixir** (BEAM over Erlang NIF)   |    102 |     171 |     202 |    190 |     241 |     281 |
| **PowerShell** (over C#)            |    102 |     169 |     204 |    203 |     237 |     279 |
| **Clojure** (JVM)                   |    107 |     167 |     201 |    214 |     231 |     274 |
| **F#** (over C#)                    |    104 |     174 |     203 |    209 |     240 |     277 |
| **VB.NET** (over C#)                |    104 |     175 |     202 |    187 |     242 |     279 |
| **Gleam** (BEAM over Erlang NIF)    |    103 |     171 |     201 |    187 |     233 |     272 |
| **LFE** (BEAM over Erlang NIF)      |    102 |     169 |     206 |    190 |     237 |     282 |
| **PHP** (FFI)                       |    108 |     174 |     203 |    222 |     240 |     280 |
| **Ruby** (ffi gem)                  |    106 |     149 |     155 |    232 |     232 |     243 |
| **Dart** (dart:ffi)                 |     98 |     169 |     201 |    185 |     230 |     274 |
| **Lua** (C module)                  |    106 |     176 |     202 |    232 |     246 |     275 |
| **Nim** (thin proxy)                |    108 |     180 |     210 |    226 |     254 |     300 |
| **Crystal** (thin proxy)            |    108 |     179 |     211 |    230 |     246 |     289 |
| **Julia** (ccall)                   |    107 |     179 |     207 |    234 |     246 |     279 |
| **OCaml** (ocaml-ctypes)            |    105 |     178 |     203 |    218 |     241 |     278 |
| **Haskell** (foreign import ccall)  |    110 |     181 |     213 |    220 |     254 |     298 |
| **R** (.Call via C shim)            |     95 |     181 |     197 |    206 |     232 |     267 |

### Message shape — full production (MAC on, parallax on, wrapper on)

Same rows as above under `ITB_WITH_MAC=true ITB_WITH_PARALLAX=true ITB_WITH_WRAPPER=true`, exercising the shipped `singlemsg-triple-mac-v1` profile with parallax and wrapper overlays engaged.

| Binding                              | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|--------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native**                        |     60 |     138 |     157 |     92 |     195 |     205 |
| **Rust** (thin proxy)               |     55 |     131 |     151 |     83 |     185 |     186 |
| **C** (thin proxy)                  |     52 |     129 |     147 |     78 |     181 |     181 |
| **C++** (thin proxy)                |     51 |     115 |     131 |     77 |     162 |     170 |
| **Ada** (thin proxy)                |     51 |     110 |     127 |     75 |     156 |     159 |
| **D** (thin proxy)                  |     55 |     126 |     146 |     79 |     178 |     188 |
| **C#** (thin proxy)                 |     54 |     129 |     143 |     79 |     176 |     188 |
| **Python** (thin proxy)             |     48 |     116 |     132 |     77 |     174 |     167 |
| **Node.js** (thin proxy)            |     53 |     126 |     138 |     79 |     180 |     176 |
| **Fortran** (thin proxy)            |     55 |     131 |     151 |     83 |     187 |     192 |
| **Swift** (thin proxy)              |     54 |     124 |     144 |     77 |     180 |     185 |
| **Java** (thin proxy)               |     54 |     127 |     147 |     80 |     183 |     188 |
| **Zig** (thin proxy)                |     52 |     126 |     142 |     76 |     178 |     184 |
| **Kotlin** (JVM)                    |     54 |     126 |     139 |     80 |     162 |     173 |
| **Erlang** (NIF)                    |     54 |     128 |     146 |     77 |     182 |     185 |
| **Scala** (JVM)                     |     54 |     123 |     145 |     80 |     176 |     182 |
| **Groovy** (JVM)                    |     50 |     112 |     128 |     73 |     153 |     157 |
| **Elixir** (BEAM over Erlang NIF)   |     50 |     126 |     143 |     72 |     179 |     187 |
| **PowerShell** (over C#)            |     52 |     126 |     142 |     74 |     173 |     178 |
| **Clojure** (JVM)                   |     53 |     127 |     139 |     80 |     170 |     182 |
| **F#** (over C#)                    |     52 |     111 |     125 |     76 |     158 |     164 |
| **VB.NET** (over C#)                |     53 |     130 |     147 |     79 |     180 |     175 |
| **Gleam** (BEAM over Erlang NIF)    |     50 |     124 |     141 |     72 |     174 |     181 |
| **LFE** (BEAM over Erlang NIF)      |     52 |     119 |     141 |     73 |     171 |     180 |
| **PHP** (FFI)                       |     53 |     126 |     145 |     78 |     173 |     179 |
| **Ruby** (ffi gem)                  |     42 |     104 |     116 |     79 |     168 |     157 |
| **Dart** (dart:ffi)                 |     54 |     129 |     150 |     80 |     182 |     182 |
| **Lua** (C module)                  |     50 |     119 |     144 |     75 |     178 |     181 |
| **Nim** (thin proxy)                |     53 |     118 |     140 |     79 |     169 |     174 |
| **Crystal** (thin proxy)            |     52 |     114 |     132 |     77 |     158 |     172 |
| **Julia** (ccall)                   |     55 |     124 |     145 |     80 |     182 |     185 |
| **OCaml** (ocaml-ctypes)            |     54 |     117 |     144 |     79 |     170 |     185 |
| **Haskell** (foreign import ccall)  |     56 |     127 |     147 |     82 |     184 |     192 |
| **R** (.Call via C shim)            |     50 |     125 |     135 |     80 |     178 |     181 |

### Stream pump shape — full production (AEAD on, parallax on, wrapper on)

Same rows as above under `ITB_WITH_MAC=true ITB_WITH_PARALLAX=true ITB_WITH_WRAPPER=true`, exercising `streaming-aead-triple-mac-v1` with parallax and wrapper overlays engaged.

| Binding                              | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|--------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native**                        |     60 |     140 |     158 |     99 |     194 |     211 |
| **Rust** (thin proxy)               |     56 |     128 |     136 |     79 |     168 |     174 |
| **C** (thin proxy)                  |     50 |     107 |     126 |     73 |     151 |     156 |
| **C++** (thin proxy)                |     54 |     118 |     130 |     74 |     152 |     160 |
| **Ada** (thin proxy)                |     54 |     115 |     131 |     74 |     154 |     159 |
| **D** (thin proxy)                  |     57 |     131 |     145 |     80 |     172 |     178 |
| **C#** (thin proxy)                 |     53 |     122 |     144 |     72 |     168 |     178 |
| **Python** (thin proxy)             |     47 |     120 |     126 |     74 |     157 |     158 |
| **Node.js** (thin proxy)            |     47 |     112 |     134 |     67 |     154 |     159 |
| **Fortran** (thin proxy)            |     58 |     131 |     144 |     81 |     172 |     178 |
| **Swift** (thin proxy)              |     53 |     123 |     130 |     79 |     124 |     171 |
| **Java** (thin proxy)               |     56 |     126 |     147 |     79 |     165 |     176 |
| **Zig** (thin proxy)                |     50 |     122 |     138 |     78 |     163 |     170 |
| **Kotlin** (JVM)                    |     51 |     112 |     134 |     73 |     158 |     166 |
| **Erlang** (NIF)                    |     53 |     130 |     146 |     78 |     168 |     180 |
| **Scala** (JVM)                     |     53 |     125 |     144 |     77 |     164 |     175 |
| **Groovy** (JVM)                    |     53 |     123 |     133 |     75 |     166 |     169 |
| **Elixir** (BEAM over Erlang NIF)   |     54 |     130 |     147 |     78 |     171 |     178 |
| **PowerShell** (over C#)            |     52 |     122 |     140 |     71 |     162 |     173 |
| **Clojure** (JVM)                   |     53 |     123 |     142 |     75 |     163 |     175 |
| **F#** (over C#)                    |     50 |     107 |     137 |     69 |     160 |     174 |
| **VB.NET** (over C#)                |     53 |     126 |     144 |     74 |     167 |     175 |
| **Gleam** (BEAM over Erlang NIF)    |     54 |     128 |     138 |     78 |     172 |     161 |
| **LFE** (BEAM over Erlang NIF)      |     54 |     123 |     136 |     75 |     161 |     172 |
| **PHP** (FFI)                       |     55 |     128 |     140 |     79 |     175 |     182 |
| **Ruby** (ffi gem)                  |     44 |     103 |     125 |     79 |     157 |     165 |
| **Dart** (dart:ffi)                 |     58 |     129 |     144 |     80 |     175 |     185 |
| **Lua** (C module)                  |     50 |     120 |     140 |     76 |     162 |     170 |
| **Nim** (thin proxy)                |     53 |     125 |     138 |     74 |     164 |     172 |
| **Crystal** (thin proxy)            |     54 |     122 |     148 |     72 |     174 |     183 |
| **Julia** (ccall)                   |     57 |     131 |     146 |     77 |     174 |     184 |
| **OCaml** (ocaml-ctypes)            |     58 |     130 |     145 |     80 |     173 |     181 |
| **Haskell** (foreign import ccall)  |     58 |     132 |     147 |     84 |     175 |     182 |
| **R** (.Call via C shim)            |     57 |     131 |     145 |     83 |     174 |     180 |

### Stream one-shot shape — full production (AEAD on, parallax on, wrapper on)

Same rows as above under `ITB_WITH_MAC=true ITB_WITH_PARALLAX=true ITB_WITH_WRAPPER=true`. Under production overlays the whole-buffer fast path falls through to the streaming fallback (parallax multiplexer engages), so the numbers land within a few percent of the Stream pump baseline; the shipping API surface for callers holding a whole plaintext in memory stays symmetric with the pump path.

| Binding                              | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|--------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native**                        |     60 |     140 |     158 |     99 |     194 |     211 |
| **Rust** (thin proxy)               |     57 |     126 |     153 |     82 |     185 |     191 |
| **C** (thin proxy)                  |     52 |     115 |     147 |     74 |     180 |     187 |
| **C++** (thin proxy)                |     53 |     116 |     133 |     77 |     162 |     167 |
| **Ada** (thin proxy)                |     52 |     114 |     127 |     77 |     158 |     160 |
| **D** (thin proxy)                  |     55 |     131 |     150 |     81 |     185 |     190 |
| **C#** (thin proxy)                 |     54 |     129 |     147 |     80 |     184 |     187 |
| **Python** (thin proxy)             |     48 |     120 |     137 |     79 |     176 |     167 |
| **Node.js** (thin proxy)            |     53 |     126 |     142 |     78 |     176 |     180 |
| **Fortran** (thin proxy)            |     54 |     134 |     148 |     81 |     188 |     190 |
| **Swift** (thin proxy)              |     56 |     130 |     144 |     77 |     182 |     187 |
| **Java** (thin proxy)               |     54 |     124 |     146 |     79 |     173 |     181 |
| **Zig** (thin proxy)                |     52 |     126 |     146 |     75 |     177 |     184 |
| **Kotlin** (JVM)                    |     52 |     110 |     124 |     75 |     159 |     162 |
| **Erlang** (NIF)                    |     53 |     129 |     143 |     78 |     179 |     188 |
| **Scala** (JVM)                     |     54 |     126 |     145 |     82 |     178 |     183 |
| **Groovy** (JVM)                    |     54 |     127 |     140 |     80 |     175 |     185 |
| **Elixir** (BEAM over Erlang NIF)   |     51 |     126 |     141 |     76 |     178 |     189 |
| **PowerShell** (over C#)            |     51 |     123 |     139 |     76 |     175 |     180 |
| **Clojure** (JVM)                   |     55 |     124 |     128 |     80 |     164 |     160 |
| **F#** (over C#)                    |     53 |     125 |     130 |     79 |     172 |     170 |
| **VB.NET** (over C#)                |     53 |     126 |     144 |     79 |     180 |     180 |
| **Gleam** (BEAM over Erlang NIF)    |     50 |     122 |     128 |     73 |     156 |     162 |
| **LFE** (BEAM over Erlang NIF)      |     51 |     123 |     137 |     75 |     164 |     174 |
| **PHP** (FFI)                       |     54 |     121 |     137 |     81 |     176 |     182 |
| **Ruby** (ffi gem)                  |     43 |     105 |     119 |     83 |     170 |     156 |
| **Dart** (dart:ffi)                 |     54 |     126 |     139 |     78 |     175 |     184 |
| **Lua** (C module)                  |     52 |     125 |     134 |     78 |     174 |     164 |
| **Nim** (thin proxy)                |     54 |     117 |     138 |     79 |     171 |     192 |
| **Crystal** (thin proxy)            |     57 |     130 |     152 |     83 |     185 |     191 |
| **Julia** (ccall)                   |     55 |     120 |     140 |     82 |     182 |     171 |
| **OCaml** (ocaml-ctypes)            |     53 |     128 |     135 |     81 |     175 |     174 |
| **Haskell** (foreign import ccall)  |     56 |     131 |     149 |     83 |     182 |     192 |
| **R** (.Call via C shim)            |     52 |     126 |     145 |     82 |     182 |     183 |

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
