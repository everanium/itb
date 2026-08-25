# ITB binding fleet

Every binding under this directory is a **thin proxy** over the
same `ITB_Triple_*` FFI surface exposed by the C shared library
(`cmd/cshared`). No ITB construction logic lives in a binding —
every hash-name / MAC-name / cipher-name / profile-name is an
opaque string passed through to Go for validation.

## Layout

Each binding directory carries the same set of concerns, with
per-language naming variations:

- `src/` (or language-equivalent) — the FFI shim, the handle-
  lifetime wrapper, the Opts URL-query builder, the status-code
  table, and the `io.Reader` / `io.Writer` (or language-native
  equivalent) adapters for the stream-pump surface.
- `tests/` — round-trip + error-path coverage against the shipped
  Go core. Small footprint by design; the deep test suite lives
  in Go under the shipped tree.
- `benches/` — Triple micro-benchmarks matching BENCH3.md shape.
- `examples/` — short usage snippets.
- `eitb/` — a small command-line utility mirroring the shipped
  `tools/eitb` Go tool so each binding can be smoke-tested from
  the shell.
- `build.sh` / `run_tests.sh` / `run_bench.sh` — driver scripts
  that build `libitb.so` once and then hand off to the binding's
  native toolchain.
- `README.md` — build recipe + minimal usage example, structured
  identically across bindings so a reader who knows one binding
  reads the next in a minute.

## Tier model

- **Tier 1 Thin (14 bindings)** — direct in-process consumers of
  `libitb.so` / `.dylib` / `.dll`. Language-idiomatic handle
  lifetime, `io`-style adapters, status-code table.
- **Tier 2 Relay (19 bindings)** — small out-of-process relay
  speaking the `ITB_Triple_*` shim over one of four backends
  (C / Java / C# / BEAM) for language runtimes that cannot embed
  the shared library directly.

The pre-rework bindings tree — larger surface, per-binding Low-
Level + wrapper + parallax exports — is preserved verbatim under
[`../bindings-old/`](../bindings-old/) as a reference for style,
tests, benchmarks, and build scripts during the fleet rework. It
does not compile against the current shipped Go core (wire
hard-fork at v0.3.0 changed the ABI); check out a pre-v0.3.0 tree
to reproduce its build.

## Fleet listing

| Language | Directory | Tier |
|----------|-----------|:----:|
| Go (core) | [`../`](../) (root Go module) | native |
| Rust | [`rust/`](rust/) | 1 native |
| C | [`c/`](c/) | 1 native |
| C++ | [`cpp/`](cpp/) | 1 native |
| Ada | [`ada/`](ada/) | 1 native |
| D | [`dlang/`](dlang/) | 1 native |
| C# | [`csharp/`](csharp/) | 1 native |
| Python | [`python/`](python/) | 1 native |
| Node.js | [`nodejs/`](nodejs/) | 1 native |
| Fortran | [`fortran/`](fortran/) | 1 native |
| Swift | [`swift/`](swift/) | 1 native |
| Java | [`java/`](java/) | 1 native |
| Zig | [`zig/`](zig/) | 1 native |
| Kotlin | [`kotlin/`](kotlin/) | 2 relay (over Java jar) |
| Erlang | [`erlang/`](erlang/) | 1 native (NIF) |
| Scala | [`scala/`](scala/) | 2 relay (over Java jar) |
| Groovy | [`groovy/`](groovy/) | 2 relay (over Java jar) |
| Elixir | [`elixir/`](elixir/) | 2 relay (over Erlang NIF) |
| PowerShell | [`powershell/`](powershell/) | 2 relay (over C# Itb.dll) |
| Clojure | [`clojure/`](clojure/) | 2 relay (over Java jar) |
| F# | [`fsharp/`](fsharp/) | 2 relay (over C# Itb.dll) |
| VB.NET | [`vbnet/`](vbnet/) | 2 relay (over C# Itb.dll) |
| Gleam | [`gleam/`](gleam/) | 2 relay (over Erlang NIF) |
| LFE | [`lfe/`](lfe/) | 2 relay (over Erlang NIF) |
| PHP | [`php/`](php/) | 2 relay (over C FFI) |
| Ruby | [`ruby/`](ruby/) | 2 relay (over C FFI via `ffi` gem) |
| Dart | [`dart/`](dart/) | 2 relay (over C FFI via `dart:ffi`) |
| Lua | [`lua/`](lua/) | 2 relay (C module for Lua 5.4) |
| Nim | [`nim/`](nim/) | 1 native (`{.importc, dynlib.}`) |
| Crystal | [`crystal/`](crystal/) | 1 native |
| Julia | [`julia/`](julia/) | 2 relay (ccall) |
| OCaml | [`ocaml/`](ocaml/) | 1 native (ocaml-ctypes) |
| Haskell | [`haskell/`](haskell/) | 1 native (`foreign import ccall`) |
| R | [`r/`](r/) | 2 relay (`.Call` C shim) |

34 rows total (Go core + 33 language bindings).

Each binding ships as source in this repository; build via the
per-binding `build.sh` script under its directory. No binding is
published to a package registry yet — that is a future milestone.
