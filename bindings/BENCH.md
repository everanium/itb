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
| Go runtime cap  | 4 GiB soft heap, 100% GC           | `ITB_GOMEMLIMIT` / `ITB_GOGC` |

The pin matches the root Go BENCH3.md `BenchmarkExtTripleAreion512_1024bit_*`
row so any binding's throughput is directly comparable to the Go native number.

## Intel Core i7-11700K 8C/16HT

### Message shape (buffer-in / buffer-out, single FFI call per iteration)

`E` columns time the encrypt path; `D` columns time the decrypt path
on wire pre-produced outside the timing loop.

| Binding                             | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|-------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native**                       |    333 |     373 |     398 |    346 |     393 |     424 |
| **Rust** (thin proxy)               |    294 |     330 |     353 |    317 |     366 |     384 |
| **C** (thin proxy)                  |    235 |     328 |     343 |    278 |     362 |     390 |
| **C++** (thin proxy)                |    295 |     332 |     361 |    308 |     363 |     396 |
| **Ada** (thin proxy)                |    268 |     302 |     290 |    301 |     341 |     356 |
| **D** (thin proxy)                  |    296 |     332 |     343 |    319 |     368 |     370 |
| **C#** (thin proxy)                 |    229 |     297 |     300 |    278 |     347 |     361 |
| **Python** (thin proxy)             |    179 |     270 |     288 |    291 |     333 |     313 |
| **Node.js** (thin proxy)            |    253 |     313 |     313 |    251 |     340 |     358 |
| **Fortran** (thin proxy)            |    295 |     333 |     352 |    319 |     366 |     393 |
| **Swift** (thin proxy)              |    246 |     307 |     315 |    269 |     347 |     353 |
| **Java** (thin proxy)               |    291 |     323 |     344 |    308 |     352 |     375 |
| **Zig** (thin proxy)                |    243 |     327 |     341 |    268 |     352 |     384 |
| **Kotlin** (JVM)                    |    272 |     290 |     305 |    298 |     333 |     353 |
| **Erlang** (NIF)                    |    242 |     311 |     320 |    263 |     346 |     369 |
| **Scala** (JVM)                     |    268 |     282 |     298 |    290 |     323 |     340 |
| **Groovy** (JVM)                    |    272 |     300 |     317 |    298 |     334 |     354 |
| **Elixir** (BEAM over Erlang NIF)   |    243 |     314 |     335 |    264 |     348 |     374 |
| **PowerShell** (over C#)            |    235 |     312 |     310 |    262 |     346 |     372 |
| **Clojure** (JVM)                   |    272 |     292 |     300 |    297 |     321 |     351 |
| **F#** (over C#)                    |    208 |     313 |     312 |    255 |     348 |     367 |
| **VB.NET** (over C#)                |    246 |     316 |     306 |    287 |     342 |     348 |
| **Gleam** (BEAM over Erlang NIF)    |    241 |     312 |     331 |    266 |     349 |     363 |
| **LFE** (BEAM over Erlang NIF)      |    240 |     308 |     318 |    261 |     343 |     371 |
| **PHP** (FFI)                       |    293 |     332 |     350 |    311 |     346 |     368 |
| **Ruby** (ffi gem)                  |    273 |     308 |     276 |    303 |     346 |     318 |
| **Dart** (dart:ffi)                 |    277 |     312 |     328 |    298 |     346 |     369 |
| **Lua** (C module)                  |    288 |     314 |     318 |    312 |     341 |     355 |
| **Nim** (thin proxy)                |    294 |     331 |     356 |    319 |     375 |     405 |
| **Crystal** (thin proxy)            |    276 |     319 |     340 |    293 |     343 |     374 |
| **Julia** (ccall)                   |    284 |     320 |     342 |    312 |     361 |     378 |
| **OCaml** (ocaml-ctypes)            |    276 |     321 |     316 |    300 |     357 |     347 |
| **Haskell** (foreign import ccall)  |    294 |     325 |     351 |    313 |     370 |     393 |
| **R** (.Call via C shim)            |    211 |     322 |     328 |    299 |     338 |     360 |

### Stream shape (multi-call session — Begin / Write / End / Read / Free)

`E` columns time the encrypt path; `D` columns time the decrypt path
on wire pre-produced outside the timing loop.

| Binding                             | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|-------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native**                       |    299 |     335 |     357 |    320 |     359 |     365 |
| **Rust** (thin proxy)               |    176 |     283 |     283 |    244 |     305 |     296 |
| **C** (thin proxy)                  |    197 |     264 |     298 |    256 |     315 |     307 |
| **C++** (thin proxy)                |    254 |     282 |     296 |    252 |     305 |     316 |
| **Ada** (thin proxy)                |    245 |     289 |     299 |    257 |     315 |     306 |
| **D** (thin proxy)                  |    200 |     288 |     305 |    254 |     312 |     312 |
| **C#** (thin proxy)                 |    200 |     271 |     278 |    205 |     296 |     278 |
| **Python** (thin proxy)             |    165 |     270 |     270 |    228 |     287 |     271 |
| **Node.js** (thin proxy)            |    177 |     245 |     259 |    185 |     261 |     253 |
| **Fortran** (thin proxy)            |    252 |     286 |     312 |    263 |     316 |     315 |
| **Swift** (thin proxy)              |    172 |     265 |     283 |    252 |     261 |     286 |
| **Java** (thin proxy)               |    254 |     301 |     321 |    264 |     324 |     321 |
| **Zig** (thin proxy)                |    200 |     275 |     292 |    260 |     305 |     298 |
| **Kotlin** (JVM)                    |    203 |     266 |     290 |    223 |     299 |     296 |
| **Erlang** (NIF)                    |    240 |     292 |     289 |    257 |     319 |     320 |
| **Scala** (JVM)                     |    201 |     269 |     285 |    225 |     298 |     289 |
| **Groovy** (JVM)                    |    197 |     273 |     291 |    222 |     299 |     296 |
| **Elixir** (BEAM over Erlang NIF)   |    241 |     291 |     310 |    257 |     318 |     303 |
| **PowerShell** (over C#)            |    197 |     279 |     291 |    203 |     301 |     305 |
| **Clojure** (JVM)                   |    201 |     266 |     290 |    221 |     291 |     297 |
| **F#** (over C#)                    |    204 |     279 |     291 |    212 |     301 |     305 |
| **VB.NET** (over C#)                |    186 |     220 |     279 |    180 |     297 |     301 |
| **Gleam** (BEAM over Erlang NIF)    |    219 |     287 |     301 |    251 |     310 |     299 |
| **LFE** (BEAM over Erlang NIF)      |    232 |     285 |     294 |    248 |     305 |     303 |
| **PHP** (FFI)                       |    251 |     300 |     307 |    263 |     328 |     315 |
| **Ruby** (ffi gem)                  |    238 |     274 |     291 |    245 |     296 |     296 |
| **Dart** (dart:ffi)                 |    233 |     285 |     311 |    250 |     307 |     311 |
| **Lua** (C module)                  |    242 |     279 |     291 |    247 |     295 |     300 |
| **Nim** (thin proxy)                |    258 |     297 |     319 |    266 |     323 |     322 |
| **Crystal** (thin proxy)            |    249 |     296 |     305 |    259 |     322 |     312 |
| **Julia** (ccall)                   |    250 |     292 |     316 |    257 |     323 |     320 |
| **OCaml** (ocaml-ctypes)            |    249 |     279 |     313 |    244 |     320 |     313 |
| **Haskell** (foreign import ccall)  |    250 |     297 |     314 |    258 |     314 |     316 |
| **R** (.Call via C shim)            |    248 |     293 |     313 |    256 |     316 |     344 |

### Stream one-shot shape (single FFI call, whole plaintext through `encrypt_stream_one_shot`)

The one-shot Stream API surface (`encrypt_stream_one_shot(plain) → wire` and its decrypt counterpart) reaches the same direct whole-buffer fast path as the Message shape when parallax is off — the produced wire is a single-chunk Streaming wire, byte-shape-identical to Message wire at the file level. Callers holding the whole plaintext in memory pick.

| Binding                             | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|-------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native**                       |    333 |     373 |     398 |    346 |     393 |     424 |
| **Rust** (thin proxy)               |    283 |     334 |     352 |    318 |     356 |     380 |
| **C** (thin proxy)                  |    254 |     323 |     347 |    273 |     355 |     392 |
| **C++** (thin proxy)                |    295 |     336 |     357 |    317 |     368 |     400 |
| **Ada** (thin proxy)                |    286 |     310 |     255 |    314 |     315 |     341 |
| **D** (thin proxy)                  |    301 |     339 |     346 |    323 |     370 |     390 |
| **C#** (thin proxy)                 |    239 |     296 |     311 |    276 |     336 |     363 |
| **Python** (thin proxy)             |    179 |     262 |     290 |    290 |     326 |     320 |
| **Node.js** (thin proxy)            |    248 |     311 |     321 |    254 |     340 |     348 |
| **Fortran** (thin proxy)            |    296 |     340 |     358 |    320 |     366 |     397 |
| **Swift** (thin proxy)              |    249 |     303 |     319 |    268 |     331 |     353 |
| **Java** (thin proxy)               |    272 |     301 |     304 |    288 |     329 |     348 |
| **Zig** (thin proxy)                |    252 |     318 |     343 |    269 |     349 |     373 |
| **Kotlin** (JVM)                    |    280 |     292 |     313 |    298 |     326 |     352 |
| **Erlang** (NIF)                    |    240 |     306 |     327 |    263 |     342 |     368 |
| **Scala** (JVM)                     |    273 |     289 |     302 |    293 |     327 |     347 |
| **Groovy** (JVM)                    |    273 |     300 |     309 |    293 |     329 |     347 |
| **Elixir** (BEAM over Erlang NIF)   |    241 |     292 |     315 |    246 |     345 |     366 |
| **PowerShell** (over C#)            |    235 |     303 |     314 |    250 |     350 |     368 |
| **Clojure** (JVM)                   |    272 |     296 |     316 |    296 |     332 |     353 |
| **F#** (over C#)                    |    262 |     309 |     326 |    287 |     348 |     375 |
| **VB.NET** (over C#)                |    231 |     304 |     310 |    272 |     322 |     359 |
| **Gleam** (BEAM over Erlang NIF)    |    239 |     316 |     329 |    261 |     342 |     375 |
| **LFE** (BEAM over Erlang NIF)      |    242 |     308 |     331 |    268 |     343 |     368 |
| **PHP** (FFI)                       |    275 |     311 |     327 |    308 |     340 |     376 |
| **Ruby** (ffi gem)                  |    275 |     305 |     268 |    299 |     344 |     312 |
| **Dart** (dart:ffi)                 |    216 |     302 |     318 |    229 |     319 |     351 |
| **Lua** (C module)                  |    282 |     313 |     316 |    305 |     339 |     349 |
| **Nim** (thin proxy)                |    293 |     333 |     355 |    322 |     377 |     409 |
| **Crystal** (thin proxy)            |    282 |     323 |     335 |    308 |     354 |     379 |
| **Julia** (ccall)                   |    280 |     324 |     332 |    307 |     353 |     373 |
| **OCaml** (ocaml-ctypes)            |    275 |     319 |     316 |    303 |     357 |     357 |
| **Haskell** (foreign import ccall)  |    283 |     327 |     340 |    310 |     359 |     387 |
| **R** (.Call via C shim)            |    209 |     293 |     314 |    287 |     344 |     357 |

### Message shape — full production (MAC on, parallax on, wrapper on)

Same rows as above under `ITB_WITH_MAC=true ITB_WITH_PARALLAX=true ITB_WITH_WRAPPER=true`, exercising the shipped `singlemsg-triple-mac-v1` profile with parallax and wrapper overlays engaged.

| Binding                             | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|-------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native**                       |    193 |     228 |     257 |    222 |     267 |     270 |
| **Rust** (thin proxy)               |    179 |     212 |     233 |    205 |     245 |     241 |
| **C** (thin proxy)                  |    159 |     202 |     225 |    184 |     236 |     248 |
| **C++** (thin proxy)                |    177 |     214 |     233 |    206 |     232 |     250 |
| **Ada** (thin proxy)                |    171 |     198 |     216 |    198 |     236 |     231 |
| **D** (thin proxy)                  |    183 |     217 |     226 |    211 |     238 |     243 |
| **C#** (thin proxy)                 |    152 |     204 |     217 |    189 |     233 |     240 |
| **Python** (thin proxy)             |    125 |     180 |     201 |    189 |     228 |     210 |
| **Node.js** (thin proxy)            |    154 |     197 |     210 |    170 |     227 |     230 |
| **Fortran** (thin proxy)            |    180 |     210 |     234 |    211 |     253 |     255 |
| **Swift** (thin proxy)              |    155 |     199 |     219 |    176 |     236 |     238 |
| **Java** (thin proxy)               |    174 |     210 |     228 |    204 |     240 |     247 |
| **Zig** (thin proxy)                |    160 |     205 |     228 |    186 |     235 |     240 |
| **Kotlin** (JVM)                    |    162 |     194 |     212 |    196 |     232 |     227 |
| **Erlang** (NIF)                    |    156 |     208 |     225 |    183 |     229 |     244 |
| **Scala** (JVM)                     |    164 |     183 |     206 |    197 |     229 |     229 |
| **Groovy** (JVM)                    |    168 |     200 |     217 |    199 |     232 |     234 |
| **Elixir** (BEAM over Erlang NIF)   |    157 |     205 |     226 |    182 |     240 |     244 |
| **PowerShell** (over C#)            |    150 |     202 |     215 |    178 |     225 |     237 |
| **Clojure** (JVM)                   |    164 |     193 |     208 |    194 |     229 |     236 |
| **F#** (over C#)                    |    147 |     204 |     216 |    193 |     240 |     244 |
| **VB.NET** (over C#)                |    146 |     201 |     223 |    188 |     238 |     241 |
| **Gleam** (BEAM over Erlang NIF)    |    157 |     204 |     228 |    181 |     237 |     238 |
| **LFE** (BEAM over Erlang NIF)      |    156 |     186 |     179 |    177 |     228 |     223 |
| **PHP** (FFI)                       |    179 |     217 |     240 |    202 |     241 |     237 |
| **Ruby** (ffi gem)                  |    160 |     193 |     195 |    198 |     231 |     204 |
| **Dart** (dart:ffi)                 |    169 |     207 |     224 |    200 |     237 |     244 |
| **Lua** (C module)                  |    178 |     212 |     223 |    206 |     242 |     237 |
| **Nim** (thin proxy)                |    173 |     212 |     239 |    180 |     249 |     227 |
| **Crystal** (thin proxy)            |    168 |     203 |     228 |    193 |     238 |     242 |
| **Julia** (ccall)                   |    162 |     203 |     227 |    202 |     245 |     246 |
| **OCaml** (ocaml-ctypes)            |    165 |     204 |     217 |    190 |     242 |     237 |
| **Haskell** (foreign import ccall)  |    182 |     216 |     238 |    211 |     253 |     256 |
| **R** (.Call via C shim)            |    141 |     206 |     220 |    196 |     238 |     238 |

### Stream shape — full production (AEAD on, parallax on, wrapper on)

Same rows as above under `ITB_WITH_MAC=true ITB_WITH_PARALLAX=true ITB_WITH_WRAPPER=true`, exercising `streaming-aead-triple-mac-v1` with parallax and wrapper overlays engaged.

| Binding                             | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|-------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native**                       |    198 |     241 |     264 |    232 |     278 |     282 |
| **Rust** (thin proxy)               |    134 |     196 |     216 |    184 |     234 |     231 |
| **C** (thin proxy)                  |    146 |     184 |     219 |    189 |     230 |     230 |
| **C++** (thin proxy)                |    175 |     214 |     230 |    190 |     234 |     241 |
| **Ada** (thin proxy)                |    174 |     201 |     218 |    186 |     218 |     227 |
| **D** (thin proxy)                  |    169 |     202 |     227 |    189 |     234 |     226 |
| **C#** (thin proxy)                 |    152 |     194 |     213 |    159 |     220 |     233 |
| **Python** (thin proxy)             |    124 |     183 |     201 |    171 |     224 |     216 |
| **Node.js** (thin proxy)            |    130 |     173 |     200 |    153 |     202 |     196 |
| **Fortran** (thin proxy)            |    177 |     215 |     237 |    195 |     237 |     242 |
| **Swift** (thin proxy)              |    135 |     191 |     211 |    187 |     203 |     222 |
| **Java** (thin proxy)               |    175 |     212 |     232 |    193 |     240 |     243 |
| **Zig** (thin proxy)                |    144 |     187 |     222 |    186 |     225 |     228 |
| **Kotlin** (JVM)                    |    147 |     188 |     213 |    170 |     227 |     231 |
| **Erlang** (NIF)                    |    169 |     203 |     230 |    187 |     233 |     242 |
| **Scala** (JVM)                     |    141 |     188 |     216 |    168 |     221 |     232 |
| **Groovy** (JVM)                    |    142 |     193 |     220 |    162 |     229 |     232 |
| **Elixir** (BEAM over Erlang NIF)   |    169 |     204 |     228 |    187 |     235 |     241 |
| **PowerShell** (over C#)            |    148 |     194 |     221 |    156 |     224 |     231 |
| **Clojure** (JVM)                   |    143 |     189 |     215 |    170 |     229 |     233 |
| **F#** (over C#)                    |    153 |     196 |     221 |    168 |     230 |     237 |
| **VB.NET** (over C#)                |    149 |     195 |     217 |    168 |     230 |     236 |
| **Gleam** (BEAM over Erlang NIF)    |    165 |     206 |     227 |    187 |     233 |     239 |
| **LFE** (BEAM over Erlang NIF)      |    167 |     200 |     226 |    185 |     235 |     239 |
| **PHP** (FFI)                       |    174 |     209 |     230 |    198 |     247 |     249 |
| **Ruby** (ffi gem)                  |    165 |     184 |     212 |    180 |     218 |     226 |
| **Dart** (dart:ffi)                 |    168 |     202 |     220 |    192 |     241 |     245 |
| **Lua** (C module)                  |    173 |     202 |     224 |    186 |     232 |     237 |
| **Nim** (thin proxy)                |    172 |     203 |     233 |    182 |     235 |     238 |
| **Crystal** (thin proxy)            |    174 |     206 |     229 |    189 |     238 |     238 |
| **Julia** (ccall)                   |    174 |     209 |     234 |    189 |     236 |     238 |
| **OCaml** (ocaml-ctypes)            |    172 |     208 |     234 |    189 |     231 |     238 |
| **Haskell** (foreign import ccall)  |    180 |     211 |     239 |    201 |     241 |     247 |
| **R** (.Call via C shim)            |    174 |     201 |     232 |    186 |     230 |     237 |

### Stream one-shot shape — full production (AEAD on, parallax on, wrapper on)

Same rows as above under `ITB_WITH_MAC=true ITB_WITH_PARALLAX=true ITB_WITH_WRAPPER=true`. Under production overlays the whole-buffer fast path falls through to the streaming fallback (parallax multiplexer engages), so the numbers land within a few percent of the Stream baseline. Callers holding the whole plaintext in memory pick.

| Binding                             | E 1 MB | E 16 MB | E 64 MB | D 1 MB | D 16 MB | D 64 MB |
|-------------------------------------|-------:|--------:|--------:|-------:|--------:|--------:|
| **Go native**                       |    198 |     241 |     264 |    232 |     278 |     282 |
| **Rust** (thin proxy)               |    179 |     213 |     234 |    203 |     251 |     251 |
| **C** (thin proxy)                  |    160 |     202 |     225 |    181 |     232 |     249 |
| **C++** (thin proxy)                |    175 |     214 |     236 |    208 |     247 |     248 |
| **Ada** (thin proxy)                |    172 |     200 |     207 |    202 |     235 |     228 |
| **D** (thin proxy)                  |    169 |     212 |     220 |    198 |     245 |     245 |
| **C#** (thin proxy)                 |    159 |     199 |     214 |    184 |     230 |     243 |
| **Python** (thin proxy)             |    119 |     181 |     205 |    192 |     232 |     218 |
| **Node.js** (thin proxy)            |    152 |     200 |     221 |    181 |     234 |     230 |
| **Fortran** (thin proxy)            |    181 |     215 |     241 |    212 |     251 |     253 |
| **Swift** (thin proxy)              |    158 |     204 |     221 |    185 |     238 |     239 |
| **Java** (thin proxy)               |    170 |     202 |     217 |    198 |     228 |     236 |
| **Zig** (thin proxy)                |    159 |     206 |     228 |    181 |     240 |     243 |
| **Kotlin** (JVM)                    |    168 |     194 |     214 |    194 |     228 |     226 |
| **Erlang** (NIF)                    |    157 |     203 |     225 |    186 |     240 |     245 |
| **Scala** (JVM)                     |    163 |     191 |     209 |    196 |     227 |     223 |
| **Groovy** (JVM)                    |    164 |     196 |     215 |    196 |     232 |     228 |
| **Elixir** (BEAM over Erlang NIF)   |    158 |     205 |     226 |    184 |     238 |     245 |
| **PowerShell** (over C#)            |    150 |     204 |     224 |    174 |     238 |     227 |
| **Clojure** (JVM)                   |    164 |     191 |     210 |    195 |     228 |     229 |
| **F#** (over C#)                    |    161 |     204 |     216 |    192 |     242 |     246 |
| **VB.NET** (over C#)                |    161 |     206 |     222 |    190 |     240 |     238 |
| **Gleam** (BEAM over Erlang NIF)    |    157 |     208 |     228 |    184 |     238 |     247 |
| **LFE** (BEAM over Erlang NIF)      |    157 |     203 |     226 |    176 |     238 |     241 |
| **PHP** (FFI)                       |    171 |     199 |     216 |    199 |     231 |     242 |
| **Ruby** (ffi gem)                  |    159 |     191 |     198 |    198 |     225 |     211 |
| **Dart** (dart:ffi)                 |    144 |     199 |     226 |    165 |     231 |     235 |
| **Lua** (C module)                  |    173 |     214 |     222 |    205 |     244 |     236 |
| **Nim** (thin proxy)                |    173 |     205 |     233 |    205 |     244 |     249 |
| **Crystal** (thin proxy)            |    172 |     209 |     227 |    203 |     237 |     244 |
| **Julia** (ccall)                   |    163 |     207 |     224 |    194 |     246 |     244 |
| **OCaml** (ocaml-ctypes)            |    168 |     212 |     217 |    198 |     246 |     236 |
| **Haskell** (foreign import ccall)  |    178 |     219 |     239 |    206 |     254 |     254 |
| **R** (.Call via C shim)            |    143 |     201 |     219 |    167 |     242 |     235 |

Production shape throughputs sit below the canonical (non-authenticated / no-overlay) numbers across the fleet — the parallax and wrapper overlays plus the MAC composition add per-chunk cost on both encrypt and decrypt paths.

Throughput in MB/s. The canonical Message and Stream one-shot Go native rows come from [BENCH3.md](../BENCH3.md) Triple 1024-bit Areion-SoEM-512 at `ITB_NONCE_BITS=512`; the remaining Go native rows come from the `BenchmarkFleetGoNative_*` cohort under the same heap caps. Plaintext is CSPRNG-filled per binding via each language's standard secure-random API so the COBS path sees identical byte-content distributions across rows. The 1 MB column carries visible GC-cycle noise; the 16 MB and 64 MB columns are stable. Runs are sequential — one binding at a time so parallel benches never interfere.

## FFI overhead

Per-binding throughputs across every shape sit in a band as a percentage of native Go at 64 MB; the raw numbers are the tables above. Ruby sits at the fleet floor — the MRI FFI allocator plus the per-call `ObjectSpace.define_finalizer` handle chain is the language ceiling, documented in the Ruby binding's Limitations section. The top of the band tracks languages with the leanest FFI crossing (Haskell / C++ / Fortran on Message and Stream one-shot; Haskell / Fortran / OCaml / R on Stream).

The whole-buffer Message and Stream one-shot shapes cluster together — both reach the direct fast path in `triple.Pipeline` when parallax is off — while the Stream shape sits ~15-20 MB/s below at the same primitive because the incremental session pays per-chunk container and MAC-binding costs. Under production overlays the parallax multiplexer engages on every path and the three shapes converge into a single band.

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
| `ITB_GOMEMLIMIT`    | `4GiB`                        |
| `ITB_GOGC`          | `100`                         |

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
defaults, and a row per shape (Message, Stream, Stream one-shot)
added to the tables above.
