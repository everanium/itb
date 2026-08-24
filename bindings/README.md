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

| Language | Directory | Tier | Approx. Registry Target | Install (post-registry-publish) |
|----------|-----------|:----:|-------------------------|---------------------------------|
| Go (core) | [`../`](../) (root Go module) | native | pkg.go.dev | `go get github.com/everanium/itb` |
| Rust | [`rust/`](rust/) | 1 native | crates.io | `cargo add itb` |
| C | [`c/`](c/) | 1 native | source only (Conan / vcpkg recipe TBD) | make from source |
| C++ | [`cpp/`](cpp/) | 1 native | source only | make from source |
| Ada | [`ada/`](ada/) | 1 native | Alire (`alire.ada.dev`) | `alr with itb` |
| D | [`dlang/`](dlang/) | 1 native | dub registry (`code.dlang.org`) | `dub add itb` |
| C# | [`csharp/`](csharp/) | 1 native | NuGet | `dotnet add package Everanium.Itb` |
| Python | [`python/`](python/) | 1 native | PyPI | `pip install itb` |
| Node.js | [`nodejs/`](nodejs/) | 1 native | npm | `npm install itb` |
| Fortran | [`fortran/`](fortran/) | 1 native | Fortran Package Manager (fpm) | `fpm add itb` |
| Swift | [`swift/`](swift/) | 1 native | SwiftPM (git URL, no central registry) | Package.swift dep on the git URL |
| Java | [`java/`](java/) | 1 native | Maven Central (Sonatype OSSRH) | `com.everanium:itb-java` |
| Zig | [`zig/`](zig/) | 1 native | zon (build.zig.zon, no central registry) | `zig fetch --save` |
| Kotlin | [`kotlin/`](kotlin/) | 2 relay (over Java jar) | Maven Central | `dev.everanium:itb-kotlin` |
| Erlang | [`erlang/`](erlang/) | 1 native (NIF) | Hex.pm | `rebar.config` `{itb, "~> 0.3"}` |
| Scala | [`scala/`](scala/) | 2 relay (over Java jar) | Maven Central | `dev.everanium %% itb-scala` |
| Groovy | [`groovy/`](groovy/) | 2 relay (over Java jar) | Maven Central | `dev.everanium:itb-groovy` |
| Elixir | [`elixir/`](elixir/) | 2 relay (over Erlang NIF) | Hex.pm | `{:itb, "~> 0.3"}` |
| PowerShell | [`powershell/`](powershell/) | 2 relay (over C# Itb.dll) | PowerShell Gallery | `Install-Module Itb` |
| Clojure | [`clojure/`](clojure/) | 2 relay (over Java jar) | Clojars | `dev.everanium/itb {:mvn/version "0.3.0"}` |
| F# | [`fsharp/`](fsharp/) | 2 relay (over C# Itb.dll) | NuGet | `dotnet add package EveraniumItb.FSharp` |
| VB.NET | [`vbnet/`](vbnet/) | 2 relay (over C# Itb.dll) | NuGet | `dotnet add package EveraniumItb.VisualBasic` |
| Gleam | [`gleam/`](gleam/) | 2 relay (over Erlang NIF) | Hex.pm | `gleam add itb_gleam` |
| LFE | [`lfe/`](lfe/) | 2 relay (over Erlang NIF) | Hex.pm | `rebar.config` `{itb_lfe, "~> 0.3"}` |
| PHP | [`php/`](php/) | 2 relay (over C FFI) | Packagist | `composer require everanium/itb` |
| Ruby | [`ruby/`](ruby/) | 2 relay (over C FFI via `ffi` gem) | RubyGems | `gem install itb` |
| Dart | [`dart/`](dart/) | 2 relay (over C FFI via `dart:ffi`) | pub.dev | `dart pub add itb` |
| Lua | [`lua/`](lua/) | 2 relay (C module for Lua 5.4) | LuaRocks | `luarocks install itb` |
| Nim | [`nim/`](nim/) | 1 native (`{.importc, dynlib.}`) | nimble | `nimble install itb` |
| Crystal | [`crystal/`](crystal/) | 1 native | shards.info (git tag, no central registry) | `shards.yml` `dev.everanium/itb` |
| Julia | [`julia/`](julia/) | 2 relay (ccall) | Julia General Registry | `Pkg.add("ITB")` |
| OCaml | [`ocaml/`](ocaml/) | 1 native (ocaml-ctypes) | opam-repository | `opam install itb` |
| Haskell | [`haskell/`](haskell/) | 1 native (`foreign import ccall`) | Hackage | `cabal install itb` |
| R | [`r/`](r/) | 2 relay (`.Call` C shim) | CRAN or GitHub source | `install.packages("itb")` |

34 rows total (Go core + 33 language bindings).

**Registry status**: no binding is published to its native package
registry yet. The `Install` column shows what the install command
will look like once each registry publish lands; the publish plan
is a follow-up milestone.
