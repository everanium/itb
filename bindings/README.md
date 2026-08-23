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
