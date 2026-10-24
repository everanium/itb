## ITB Binding Fleet Benchmark Results

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
| Go runtime cap  | 4 GiB soft heap, 100% GC           | `ITB_GOMEMLIMIT` / `ITB_GOGC` |

The pin matches the root Go BENCH3.md `BenchmarkExtTripleAreion512_1024bit_*`
row so any binding's throughput is directly comparable to the Go native number.

## Intel Core i7-11700K 8C/16HT

### Message shape (buffer-in / buffer-out, single FFI call per iteration)

`E` columns time the encrypt path; `D` columns time the decrypt path
on wire pre-produced outside the timing loop.

| Binding                             | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|-------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native**                       |    262 |     323 |     356 |    272 |     328 |     369 |
| **Rust** (thin proxy)               |    225 |     310 |     335 |    248 |     309 |     323 |
| **C** (thin proxy)                  |    205 |     307 |     342 |    225 |     310 |     331 |
| **C++** (thin proxy)                |    261 |     321 |     329 |    264 |     317 |     350 |
| **Ada** (thin proxy)                |    254 |     292 |     306 |    251 |     308 |     314 |
| **D** (thin proxy)                  |    213 |     309 |     337 |    225 |     307 |     324 |
| **C#** (thin proxy)                 |    229 |     303 |     308 |    235 |     293 |     321 |
| **Python** (thin proxy)             |    152 |     253 |     278 |    233 |     270 |     277 |
| **Node.js** (thin proxy)            |    199 |     278 |     301 |    205 |     273 |     283 |
| **Fortran** (thin proxy)            |    258 |     322 |     342 |    258 |     312 |     334 |
| **Swift** (thin proxy)              |    211 |     291 |     232 |    200 |     281 |     224 |
| **Java** (thin proxy)               |    236 |     280 |     328 |    243 |     294 |     312 |
| **Zig** (thin proxy)                |    187 |     256 |     295 |    185 |     250 |     287 |
| **Kotlin** (JVM)                    |    225 |     277 |     287 |    227 |     266 |     282 |
| **Erlang** (NIF)                    |    220 |     287 |     316 |    203 |     287 |     306 |
| **Scala** (JVM)                     |    223 |     239 |     285 |    228 |     257 |     285 |
| **Groovy** (JVM)                    |    224 |     278 |     304 |    218 |     278 |     310 |
| **Elixir** (BEAM over Erlang NIF)   |    215 |     296 |     303 |    207 |     263 |     322 |
| **PowerShell** (over C#)            |    175 |     286 |     317 |    184 |     284 |     309 |
| **Clojure** (JVM)                   |    214 |     256 |     301 |    219 |     252 |     288 |
| **F#** (over C#)                    |    223 |     304 |     303 |    232 |     293 |     322 |
| **VB.NET** (over C#)                |    192 |     245 |     267 |    188 |     243 |     281 |
| **Gleam** (BEAM over Erlang NIF)    |    182 |     295 |     306 |    207 |     273 |     311 |
| **LFE** (BEAM over Erlang NIF)      |    185 |     272 |     309 |    211 |     262 |     309 |
| **PHP** (FFI)                       |    238 |     295 |     319 |    189 |     263 |     303 |
| **Ruby** (ffi gem)                  |    210 |     285 |     216 |    233 |     283 |     232 |
| **Dart** (dart:ffi)                 |    247 |     296 |     314 |    245 |     278 |     298 |
| **Lua** (C module)                  |    247 |     302 |     315 |    250 |     308 |     299 |
| **Nim** (thin proxy)                |    239 |     308 |     292 |    254 |     300 |     304 |
| **Crystal** (thin proxy)            |    245 |     315 |     314 |    242 |     280 |     322 |
| **Julia** (ccall)                   |    241 |     322 |     328 |    247 |     325 |     328 |
| **OCaml** (ocaml-ctypes)            |    245 |     292 |     294 |    240 |     292 |     290 |
| **Haskell** (foreign import ccall)  |    262 |     302 |     350 |    271 |     309 |     332 |
| **R** (.Call via C shim)            |    231 |     292 |     308 |    215 |     288 |     284 |

### Stream shape (multi-call session — Begin / Write / End / Read / Free)

`E` columns time the encrypt path; `D` columns time the decrypt path
on wire pre-produced outside the timing loop.

| Binding                             | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|-------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native**                       |    247 |     293 |     310 |    261 |     317 |     317 |
| **Rust** (thin proxy)               |    157 |     203 |     202 |    209 |     215 |     218 |
| **C** (thin proxy)                  |    162 |     198 |     209 |    215 |     230 |     224 |
| **C++** (thin proxy)                |    219 |     267 |     280 |    231 |     268 |     285 |
| **Ada** (thin proxy)                |    209 |     214 |     221 |    220 |     248 |     217 |
| **D** (thin proxy)                  |    195 |     207 |     202 |    219 |     221 |     226 |
| **C#** (thin proxy)                 |    172 |     207 |     216 |    192 |     222 |     225 |
| **Python** (thin proxy)             |    137 |     190 |     186 |    190 |     196 |     190 |
| **Node.js** (thin proxy)            |    127 |     155 |     174 |    136 |     158 |     146 |
| **Fortran** (thin proxy)            |    212 |     258 |     266 |    219 |     275 |     259 |
| **Swift** (thin proxy)              |     90 |     163 |     161 |    152 |     157 |     195 |
| **Java** (thin proxy)               |    196 |     231 |     233 |    228 |     220 |     246 |
| **Zig** (thin proxy)                |    126 |     174 |     183 |    169 |     195 |     186 |
| **Kotlin** (JVM)                    |    138 |     148 |     186 |    148 |     182 |     204 |
| **Erlang** (NIF)                    |    173 |     213 |     206 |    197 |     215 |     232 |
| **Scala** (JVM)                     |    129 |     184 |     198 |    159 |     214 |     197 |
| **Groovy** (JVM)                    |    138 |     185 |     181 |    152 |     206 |     213 |
| **Elixir** (BEAM over Erlang NIF)   |    182 |     199 |     206 |    196 |     214 |     205 |
| **PowerShell** (over C#)            |    137 |     194 |     206 |    156 |     210 |     220 |
| **Clojure** (JVM)                   |    135 |     194 |     188 |    179 |     201 |     216 |
| **F#** (over C#)                    |    156 |     195 |     215 |    147 |     222 |     207 |
| **VB.NET** (over C#)                |    158 |     200 |     189 |    172 |     216 |     223 |
| **Gleam** (BEAM over Erlang NIF)    |    175 |     205 |     198 |    198 |     233 |     230 |
| **LFE** (BEAM over Erlang NIF)      |    167 |     175 |     201 |    187 |     219 |     222 |
| **PHP** (FFI)                       |    211 |     208 |     140 |    220 |     233 |     157 |
| **Ruby** (ffi gem)                  |    167 |     185 |     184 |    180 |     212 |     202 |
| **Dart** (dart:ffi)                 |    193 |     235 |     239 |    190 |     250 |     244 |
| **Lua** (C module)                  |    197 |     185 |     222 |    206 |     180 |     223 |
| **Nim** (thin proxy)                |    201 |     202 |     207 |    201 |     216 |     232 |
| **Crystal** (thin proxy)            |    215 |     220 |     234 |    210 |     238 |     226 |
| **Julia** (ccall)                   |    213 |     207 |     219 |    210 |     223 |     225 |
| **OCaml** (ocaml-ctypes)            |    186 |     183 |     220 |    200 |     208 |     245 |
| **Haskell** (foreign import ccall)  |    174 |     246 |     248 |    210 |     250 |     244 |
| **R** (.Call via C shim)            |    209 |     248 |     244 |    207 |     266 |     233 |

### Stream one-shot shape (single FFI call, whole plaintext through `encrypt_stream_one_shot`)

The one-shot Stream API surface (`encrypt_stream_one_shot(plain) → wire` and its decrypt counterpart) reaches the same direct whole-buffer fast path as the Message shape when parallax is off — the produced wire is a single-chunk Streaming wire, byte-shape-identical to Message wire at the file level. Callers holding the whole plaintext in memory pick.

| Binding                             | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|-------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native**                       |    262 |     323 |     356 |    272 |     328 |     369 |
| **Rust** (thin proxy)               |    260 |     314 |     325 |    258 |     312 |     334 |
| **C** (thin proxy)                  |    230 |     265 |     344 |    206 |     291 |     334 |
| **C++** (thin proxy)                |    259 |     319 |     319 |    273 |     309 |     315 |
| **Ada** (thin proxy)                |    244 |     299 |     306 |    244 |     298 |     305 |
| **D** (thin proxy)                  |    256 |     294 |     337 |    257 |     296 |     316 |
| **C#** (thin proxy)                 |    223 |     294 |     309 |    223 |     294 |     331 |
| **Python** (thin proxy)             |    148 |     256 |     287 |    216 |     296 |     300 |
| **Node.js** (thin proxy)            |    182 |     286 |     310 |    180 |     268 |     296 |
| **Fortran** (thin proxy)            |    249 |     314 |     328 |    254 |     309 |     333 |
| **Swift** (thin proxy)              |    179 |     253 |     278 |    175 |     247 |     272 |
| **Java** (thin proxy)               |    226 |     270 |     303 |    216 |     286 |     292 |
| **Zig** (thin proxy)                |    181 |     236 |     285 |    182 |     237 |     284 |
| **Kotlin** (JVM)                    |    220 |     263 |     262 |    184 |     263 |     269 |
| **Erlang** (NIF)                    |    207 |     301 |     328 |    208 |     286 |     295 |
| **Scala** (JVM)                     |    234 |     278 |     302 |    235 |     278 |     298 |
| **Groovy** (JVM)                    |    224 |     278 |     305 |    228 |     273 |     272 |
| **Elixir** (BEAM over Erlang NIF)   |    221 |     254 |     280 |    211 |     242 |     287 |
| **PowerShell** (over C#)            |    177 |     289 |     287 |    184 |     296 |     308 |
| **Clojure** (JVM)                   |    227 |     282 |     301 |    238 |     277 |     281 |
| **F#** (over C#)                    |    225 |     283 |     312 |    224 |     297 |     322 |
| **VB.NET** (over C#)                |    232 |     292 |     315 |    207 |     303 |     315 |
| **Gleam** (BEAM over Erlang NIF)    |    198 |     300 |     314 |    200 |     286 |     307 |
| **LFE** (BEAM over Erlang NIF)      |    190 |     263 |     310 |    198 |     259 |     309 |
| **PHP** (FFI)                       |    238 |     301 |     310 |    253 |     274 |     320 |
| **Ruby** (ffi gem)                  |    237 |     280 |     234 |    247 |     303 |     225 |
| **Dart** (dart:ffi)                 |    190 |     271 |     299 |    194 |     277 |     293 |
| **Lua** (C module)                  |    187 |     238 |     262 |    192 |     242 |     258 |
| **Nim** (thin proxy)                |    235 |     305 |     333 |    261 |     284 |     336 |
| **Crystal** (thin proxy)            |    222 |     318 |     337 |    250 |     309 |     325 |
| **Julia** (ccall)                   |    254 |     312 |     308 |    261 |     298 |     314 |
| **OCaml** (ocaml-ctypes)            |    234 |     286 |     301 |    226 |     306 |     291 |
| **Haskell** (foreign import ccall)  |    236 |     298 |     331 |    229 |     294 |     334 |
| **R** (.Call via C shim)            |    181 |     282 |     296 |    224 |     297 |     300 |

### Message shape — full production (MAC on, parallax on, wrapper on)

Same rows as above under `ITB_WITH_MAC=true ITB_WITH_PARALLAX=true ITB_WITH_WRAPPER=true`, exercising the shipped `singlemsg-triple-mac-v1` profile with parallax and wrapper overlays engaged.

| Binding                             | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|-------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native**                       |    225 |     230 |     247 |    210 |     237 |     244 |
| **Rust** (thin proxy)               |    218 |     228 |     229 |    219 |     236 |     238 |
| **C** (thin proxy)                  |    181 |     213 |     238 |    182 |     226 |     232 |
| **C++** (thin proxy)                |    215 |     234 |     240 |    209 |     247 |     240 |
| **Ada** (thin proxy)                |    211 |     220 |     220 |    205 |     232 |     222 |
| **D** (thin proxy)                  |    213 |     234 |     240 |    216 |     226 |     242 |
| **C#** (thin proxy)                 |    185 |     218 |     227 |    188 |     231 |     235 |
| **Python** (thin proxy)             |    139 |     201 |     197 |    181 |     232 |     219 |
| **Node.js** (thin proxy)            |    172 |     215 |     232 |    175 |     224 |     236 |
| **Fortran** (thin proxy)            |    178 |     208 |     233 |    190 |     220 |     238 |
| **Swift** (thin proxy)              |    189 |     225 |     228 |    199 |     223 |     232 |
| **Java** (thin proxy)               |    191 |     229 |     230 |    207 |     232 |     239 |
| **Zig** (thin proxy)                |    182 |     230 |     242 |    193 |     247 |     243 |
| **Kotlin** (JVM)                    |    195 |     212 |     200 |    194 |     216 |     221 |
| **Erlang** (NIF)                    |    177 |     215 |     225 |    190 |     217 |     227 |
| **Scala** (JVM)                     |    193 |     203 |     224 |    194 |     234 |     224 |
| **Groovy** (JVM)                    |    188 |     201 |     227 |    184 |     225 |     220 |
| **Elixir** (BEAM over Erlang NIF)   |    179 |     216 |     228 |    182 |     232 |     230 |
| **PowerShell** (over C#)            |    162 |     214 |     236 |    171 |     235 |     206 |
| **Clojure** (JVM)                   |    158 |     213 |     215 |    174 |     223 |     228 |
| **F#** (over C#)                    |    169 |     213 |     214 |    170 |     232 |     233 |
| **VB.NET** (over C#)                |    190 |     221 |     234 |    200 |     234 |     226 |
| **Gleam** (BEAM over Erlang NIF)    |    174 |     212 |     236 |    176 |     233 |     226 |
| **LFE** (BEAM over Erlang NIF)      |    180 |     220 |     226 |    182 |     239 |     226 |
| **PHP** (FFI)                       |    218 |     232 |     242 |    216 |     228 |     237 |
| **Ruby** (ffi gem)                  |    186 |     219 |     176 |    195 |     218 |     188 |
| **Dart** (dart:ffi)                 |    199 |     223 |     230 |    197 |     227 |     232 |
| **Lua** (C module)                  |    214 |     222 |     234 |    211 |     240 |     232 |
| **Nim** (thin proxy)                |    207 |     243 |     224 |    214 |     248 |     234 |
| **Crystal** (thin proxy)            |    182 |     212 |     225 |    201 |     207 |     233 |
| **Julia** (ccall)                   |    206 |     235 |     236 |    185 |     231 |     231 |
| **OCaml** (ocaml-ctypes)            |    207 |     229 |     232 |    197 |     230 |     239 |
| **Haskell** (foreign import ccall)  |    212 |     232 |     240 |    205 |     245 |     240 |
| **R** (.Call via C shim)            |    198 |     230 |     211 |    197 |     229 |     231 |

### Stream shape — full production (AEAD on, parallax on, wrapper on)

Same rows as above under `ITB_WITH_MAC=true ITB_WITH_PARALLAX=true ITB_WITH_WRAPPER=true`, exercising `streaming-aead-triple-mac-v1` with parallax and wrapper overlays engaged.

| Binding                             | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|-------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native**                       |    204 |     234 |     250 |    204 |     242 |     268 |
| **Rust** (thin proxy)               |    130 |     181 |     177 |    170 |     197 |     180 |
| **C** (thin proxy)                  |    133 |     147 |     184 |    166 |     184 |     176 |
| **C++** (thin proxy)                |    178 |     204 |     210 |    184 |     222 |     230 |
| **Ada** (thin proxy)                |    162 |     176 |     177 |    172 |     188 |     182 |
| **D** (thin proxy)                  |    177 |     177 |     187 |    184 |     200 |     171 |
| **C#** (thin proxy)                 |    143 |     172 |     181 |    147 |     185 |     182 |
| **Python** (thin proxy)             |    127 |     164 |     168 |    174 |     177 |     171 |
| **Node.js** (thin proxy)            |    115 |     139 |     140 |    124 |     154 |     137 |
| **Fortran** (thin proxy)            |    145 |     188 |     199 |    172 |     223 |     228 |
| **Swift** (thin proxy)              |    180 |     164 |     176 |    159 |     178 |     170 |
| **Java** (thin proxy)               |    170 |     171 |     195 |    180 |     200 |     199 |
| **Zig** (thin proxy)                |    172 |     166 |     181 |    183 |     179 |     183 |
| **Kotlin** (JVM)                    |    124 |     168 |     180 |    155 |     185 |     161 |
| **Erlang** (NIF)                    |    171 |     181 |     186 |    169 |     188 |     178 |
| **Scala** (JVM)                     |    130 |     160 |     178 |    148 |     175 |     180 |
| **Groovy** (JVM)                    |    125 |     160 |     178 |    149 |     175 |     172 |
| **Elixir** (BEAM over Erlang NIF)   |    164 |     172 |     174 |    161 |     189 |     180 |
| **PowerShell** (over C#)            |    117 |     163 |     166 |    134 |     188 |     182 |
| **Clojure** (JVM)                   |    126 |     166 |     175 |    147 |     189 |     174 |
| **F#** (over C#)                    |    146 |     167 |     185 |    151 |     188 |     185 |
| **VB.NET** (over C#)                |    151 |     173 |     181 |    164 |     198 |     184 |
| **Gleam** (BEAM over Erlang NIF)    |    159 |     160 |     182 |    163 |     183 |     173 |
| **LFE** (BEAM over Erlang NIF)      |    169 |     169 |     173 |    167 |     192 |     190 |
| **PHP** (FFI)                       |    171 |     176 |     173 |    176 |     212 |     138 |
| **Ruby** (ffi gem)                  |    159 |     157 |     180 |    158 |     175 |     172 |
| **Dart** (dart:ffi)                 |    164 |     190 |     200 |    169 |     210 |     201 |
| **Lua** (C module)                  |    167 |     173 |     180 |    180 |     194 |     167 |
| **Nim** (thin proxy)                |    176 |     172 |     191 |    177 |     195 |     184 |
| **Crystal** (thin proxy)            |    177 |     170 |     187 |    175 |     207 |     183 |
| **Julia** (ccall)                   |    178 |     181 |     191 |    186 |     180 |     197 |
| **OCaml** (ocaml-ctypes)            |    173 |     181 |     187 |    182 |     202 |     191 |
| **Haskell** (foreign import ccall)  |    180 |     209 |     212 |    188 |     216 |     212 |
| **R** (.Call via C shim)            |    172 |     196 |     211 |    181 |     225 |     223 |

### Stream one-shot shape — full production (AEAD on, parallax on, wrapper on)

Same rows as above under `ITB_WITH_MAC=true ITB_WITH_PARALLAX=true ITB_WITH_WRAPPER=true`. Under production overlays the whole-buffer fast path falls through to the streaming fallback (parallax multiplexer engages), so the numbers land within a few percent of the Stream baseline. Callers holding the whole plaintext in memory pick.

| Binding                             | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|-------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native**                       |    204 |     234 |     250 |    204 |     242 |     268 |
| **Rust** (thin proxy)               |    216 |     235 |     238 |    208 |     243 |     237 |
| **C** (thin proxy)                  |    185 |     230 |     235 |    203 |     228 |     236 |
| **C++** (thin proxy)                |    202 |     228 |     236 |    204 |     240 |     227 |
| **Ada** (thin proxy)                |    204 |     208 |     207 |    204 |     211 |     219 |
| **D** (thin proxy)                  |    217 |     231 |     202 |    208 |     239 |     222 |
| **C#** (thin proxy)                 |    188 |     232 |     223 |    184 |     228 |     224 |
| **Python** (thin proxy)             |    140 |     207 |     199 |    193 |     227 |     218 |
| **Node.js** (thin proxy)            |    170 |     216 |     226 |    168 |     226 |     232 |
| **Fortran** (thin proxy)            |    196 |     213 |     236 |    193 |     242 |     245 |
| **Swift** (thin proxy)              |    175 |     216 |     221 |    199 |     230 |     237 |
| **Java** (thin proxy)               |    197 |     215 |     225 |    196 |     212 |     216 |
| **Zig** (thin proxy)                |    182 |     235 |     240 |    204 |     238 |     238 |
| **Kotlin** (JVM)                    |    175 |     195 |     209 |    167 |     196 |     222 |
| **Erlang** (NIF)                    |    165 |     219 |     218 |    182 |     235 |     227 |
| **Scala** (JVM)                     |    170 |     212 |     226 |    194 |     213 |     220 |
| **Groovy** (JVM)                    |    179 |     214 |     222 |    187 |     214 |     228 |
| **Elixir** (BEAM over Erlang NIF)   |    175 |     223 |     231 |    193 |     228 |     228 |
| **PowerShell** (over C#)            |    149 |     221 |     230 |    163 |     226 |     243 |
| **Clojure** (JVM)                   |    153 |     215 |     226 |    154 |     219 |     219 |
| **F#** (over C#)                    |    192 |     222 |     235 |    190 |     226 |     226 |
| **VB.NET** (over C#)                |    184 |     218 |     237 |    178 |     224 |     231 |
| **Gleam** (BEAM over Erlang NIF)    |    177 |     222 |     229 |    197 |     238 |     234 |
| **LFE** (BEAM over Erlang NIF)      |    178 |     223 |     230 |    186 |     235 |     237 |
| **PHP** (FFI)                       |    208 |     219 |     232 |    205 |     235 |     232 |
| **Ruby** (ffi gem)                  |    205 |     221 |     172 |    210 |     232 |     193 |
| **Dart** (dart:ffi)                 |    150 |     213 |     224 |    168 |     212 |     229 |
| **Lua** (C module)                  |    207 |     222 |     226 |    202 |     236 |     230 |
| **Nim** (thin proxy)                |    200 |     230 |     247 |    193 |     237 |     239 |
| **Crystal** (thin proxy)            |    212 |     236 |     233 |    208 |     229 |     240 |
| **Julia** (ccall)                   |    201 |     234 |     225 |    221 |     246 |     242 |
| **OCaml** (ocaml-ctypes)            |    206 |     233 |     217 |    206 |     218 |     216 |
| **Haskell** (foreign import ccall)  |    195 |     235 |     237 |    219 |     243 |     244 |
| **R** (.Call via C shim)            |    154 |     218 |     218 |    202 |     237 |     232 |

Production shape throughputs sit below the canonical (non-authenticated / no-overlay) numbers across the fleet — the parallax and wrapper overlays plus the MAC composition add per-chunk cost on both encrypt and decrypt paths.

Throughput in MB/s. The canonical Message and Stream one-shot Go native rows come from [BENCH3.md](../BENCH3.md) Triple 1024-bit Areion-SoEM-512 at `ITB_NONCE_BITS=512`; the remaining Go native rows come from the `BenchmarkFleetGoNative_*` cohort under the same heap caps. Plaintext is CSPRNG-filled per binding via each language's standard secure-random API so the COBS path sees identical byte-content distributions across rows. The 1 MB column carries visible GC-cycle noise; the 16 MB and 64 MB columns are stable. Runs are sequential — one binding at a time so parallel benches never interfere.

## FFI overhead

Per-binding throughputs across every shape sit in a band as a percentage of native Go at 64 MB; the raw numbers are the tables above. Ruby sits at the fleet floor — the MRI FFI allocator plus the per-call `ObjectSpace.define_finalizer` handle chain is the language ceiling, documented in the Ruby binding's Limitations section. The top of the band tracks languages with the leanest FFI crossing (Haskell / C++ / Fortran on Message and Stream one-shot; Haskell / Fortran / OCaml / R on Stream).

The Message and Stream one-shot shapes cluster together — both reach the direct fast path in `triple.Pipeline` when parallax is off — while the Stream shape sits ~15-20 MB/s below at the same primitive because the incremental session pays per-chunk container and MAC-binding costs. Under production overlays the parallax multiplexer engages on every path and the three shapes converge into a single band.

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
| `ITB_MSG_PROFILE`   | Message-shape override — falls back to `ITB_PROFILE`, then the derived MAC / No MAC default |
| `ITB_STREAM_PROFILE`| Stream-shape override — same fallback chain as `ITB_MSG_PROFILE` |
| `ITB_BENCH_MIN_SEC` | `5`                           |
| `ITB_GOMEMLIMIT`    | `4GiB`                        |
| `ITB_GOGC`          | `100`                         |

`ITB_WITH_MAC=true` is the single knob that switches Message from the No MAC profile to the MAC Authenticated profile AND simultaneously switches Stream from the Non-AEAD profile to the AEAD profile — one boolean covers "authentication ON" on both shapes symmetrically. Expert callers pass `ITB_PROFILE=<name>` to force any specific profile (bypasses derivation), or `ITB_MSG_PROFILE` / `ITB_STREAM_PROFILE` for per-shape fine-grained overrides (e.g. MAC Message + Non-AEAD Stream in one call). The full-production tables above run with `ITB_WITH_MAC=true ITB_WITH_PARALLAX=true ITB_WITH_WRAPPER=true`.

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
defaults, and a row per shape (Message, Stream, Stream one-shot)
added to the tables above.
