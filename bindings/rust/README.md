# ITB Rust Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the libitb shared library's `ITB_Triple_*` surface
(`cmd/cshared`). Runtime FFI via the `libloading` crate — no C
compiler at install time, no compile-time link; the `.so` / `.dylib`
/ `.dll` is resolved and dispatched at first use. Every hash-name /
MAC-name / cipher-name / profile-name is an opaque string passed
through to Go for validation; the binding carries no ITB construction
logic. The public surface is one `Pipeline` type (Init / Open / Rekey
/ Close, Single Message encrypt / decrypt, one-shot and incremental
stream sessions with `io::Read` / `io::Write` pumps), an
`OptsBuilder` query-string builder, `register_profile`, and the Go
runtime knobs.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go rustup cargo
```

Generic Linux / macOS: a Go toolchain plus a stable Rust toolchain
(rustup). Windows: the same via the MSVC or GNU toolchains; libitb
builds as `libitb.dll`.

## Build the shared library

The convenience driver builds `libitb.so` plus the Rust crate's
release artefact in one step:

```bash
./bindings/rust/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
cd bindings/rust && cargo build --release
```

## Library lookup order

1. `ITB_LIBITB_PATH` environment variable (path to the shared
   library file).
2. `<repo>/dist/<os>-<arch>/libitb.<ext>` resolved from the crate
   manifest directory (in-repo builds).
3. The OS default loader path (`LD_LIBRARY_PATH`, `ld.so.cache`,
   `DYLD_LIBRARY_PATH`, `PATH`).

## Usage example

```rust,no_run
use itb::{OptsBuilder, Pipeline};

let opts = OptsBuilder::new();
let sender = Pipeline::init("singlemsg-triple-mac-v1", &opts)?;
let receiver = Pipeline::open("singlemsg-triple-mac-v1", sender.blob(), &opts, None)?;

let wire = sender.encrypt_message(b"any text or binary data")?;
let plain = receiver.decrypt_message(&wire)?;
assert_eq!(plain, b"any text or binary data");
# Ok::<(), itb::ItbError>(())
```

`OptsBuilder` overrides the profile default per call (chunk size,
outer cipher, parallax on/off, wrapper on/off, MAC name, palette):

```rust,no_run
# use itb::{OptsBuilder, Pipeline};
let opts = OptsBuilder::new()
    .with_chunk_size(65536)
    .with_wrapper(false);
let mut sender = Pipeline::init("singlemsg-triple-mac-v1", &opts)?;
let _receiver = Pipeline::open("singlemsg-triple-mac-v1", sender.blob(), &opts, None)?;
# Ok::<(), itb::ItbError>(())
```

`Pipeline::rekey` rotates the parallax + wrapper masters mid-session
(the eight ITB seeds and MAC key are fixed for the session lifetime
by design); the receiver picks up the new masters via a fresh
`sender.blob()` handshake:

```rust,no_run
# use itb::{OptsBuilder, Pipeline};
# let opts = OptsBuilder::new();
# let mut sender = Pipeline::init("singlemsg-triple-mac-v1", &opts)?;
let perm = [0x11u8; 32];
let wrap = [0x22u8; 32];
sender.rekey(&perm, &wrap)?;
let _receiver = Pipeline::open("singlemsg-triple-mac-v1", sender.blob(), &opts, None)?;
# Ok::<(), itb::ItbError>(())
```

Runnable version: `cargo run --example round_trip --release`. For
bounded-memory streaming, `encrypt_stream_pump` / `decrypt_stream_pump`
move any `io::Read` source into any `io::Write` sink through an
incremental session; the explicit `encrypt_stream` / `decrypt_stream`
sessions expose `write` / `end` / `read` for caller-driven loops.

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string surfaces as `ItbError` carrying the
status code plus the `ITB_LastError` diagnostic.

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable at
libitb load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass `-1` to query without
changing:

```rust,no_run
itb::set_memory_limit(512 << 20)?;
itb::set_gc_percent(20)?;
# Ok::<(), itb::ItbError>(())
```

## Testing

```bash
./bindings/rust/run_tests.sh
```

The harness builds `libitb.so`, exports `ITB_LIBITB_PATH`, and
invokes `cargo test --release`. Positional arguments are forwarded to
cargo (e.g. `./run_tests.sh --test smoke`). The suite covers Single
Message round trips per shipped profile, stream pumps, incremental
sessions with pathological batch sizes, tampered-wire failure
stickiness, mid-flight cancellation, rekey, profile registration, and
error mapping — surface parity checks; the deep suite lives in Go
under the shipped tree.

## Benchmarking

```bash
./bindings/rust/run_bench.sh
```

Criterion micro-benches: `encrypt_message` and `encrypt_stream_pump`
throughput at 1 KiB / 64 KiB / 1 MiB / 16 MiB. Positional arguments
are forwarded to the Criterion harness (e.g.
`./run_bench.sh --measurement-time 5`).

## eitb utility

A small CLI under `bindings/rust/eitb/` mirrors the shipped Go
`tools/eitb` scope for shell smoke tests:

```bash
cd bindings/rust/eitb && cargo build --release
./target/release/eitb version
./target/release/eitb hashes
./target/release/eitb encrypt singlemsg-triple-mac-v1 in.bin out.bin  # blob hex on stderr
./target/release/eitb decrypt singlemsg-triple-mac-v1 <blob-hex> out.bin back.bin
```

## Limitations

- The binding wraps the Triple Pipeline surface only. The Low-Level
  seed / MAC / blob / wrapper / parallax APIs are not exposed — use
  the shipped Go core for those.
- Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication.
- `ITB_LastError` is process-global last-write-wins; the textual
  diagnostic attached to an `ItbError` may belong to a different call
  under concurrent FFI use. The status code is always attributable.
- `Rekey` must not run concurrently with cipher calls or open stream
  sessions on the same `Pipeline`.
- libitb must be reachable at runtime through the lookup order above.
