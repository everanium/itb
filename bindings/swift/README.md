# ITB Swift Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the C binding's public surface
([`bindings/c/include/itb.h`](../c/include/itb.h), `libitb_c`),
which in turn wraps the libitb shared library's `ITB_Triple_*`
surface (`cmd/cshared`). The C header is imported as the Swift
module `CItb` through a SwiftPM system-library target
(`Sources/CItb/module.modulemap`); both native libraries are
**linked at compile time** (`-litb_c -litb` with embedded RPATHs) —
no runtime symbol loading. Every hash-name / MAC-name / cipher-name
/ profile-name is an opaque string passed through to Go for
validation; the binding carries no ITB construction logic. Buffer
sizing (the caller-allocated-buffer convention with the retry-once
on `BUFFER_TOO_SMALL`) lives in the C layer; the Swift layer moves
opaque bytes and relays status codes.

The public surface is one `Pipeline` class (init / open / rekey,
Single Message encrypt / decrypt, whole-buffer stream pumps,
incremental `EncryptStream` / `DecryptStream` sessions with
write / end / read), an `Opts` query-string builder,
`registerProfile`, and the Go runtime knobs under `ItbRuntime`.
Every fallible entry `throws ItbError`; `Result`-shaped and
`async` variants wrap the same calls, and `AsyncSequence`
adapters cover streaming (`session.chunks()`,
`pipeline.encryptStream(from:)` / `decryptStream(from:)`).
Handle lifetime is ARC-managed: `Pipeline` and stream sessions
release their C handles on deinit (key material is zeroed
Go-side), and a session strongly pins its parent `Pipeline`.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go gcc make
paru -S swift-bin        # Swift 6+ (AUR)
```

Generic Linux: a Go toolchain, a C11 compiler, GNU make, and a
Swift 6+ toolchain (swift.org tarball or distribution package).
macOS: the same via Xcode; libitb builds as `libitb.dylib`.

## Build

The convenience driver builds `libitb.so`, the C binding library
(`libitb_c`), and the Swift package in release configuration:

```bash
./bindings/swift/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
make -C bindings/c build/libitb_c.a build/libitb_c.so
cd bindings/swift && swift build -c release
```

`Package.swift` derives the `-L` / RPATH flags from its own
location, so the package builds from any checkout path without
`LD_LIBRARY_PATH`.

## Usage example

```swift
import Itb

let sender = try Pipeline(profile: "singlemsg-triple-mac-v1")
let receiver = try Pipeline(open: "singlemsg-triple-mac-v1",
                            blob: sender.blob)

let wire = try sender.encryptMessage(Data("any text or binary data".utf8))
let plain = try receiver.decryptMessage(wire)
```

`Opts` overrides the profile default per call (chunk size, outer
cipher, parallax on/off, wrapper on/off, MAC name, palette); every
setter goes through `set(key, value)`:

```swift
let opts = try Opts()
try opts.set("chunkSize", "65536")
try opts.set("withWrapper", "false")
let sender = try Pipeline(profile: "singlemsg-triple-mac-v1", opts: opts)
let receiver = try Pipeline(open: "singlemsg-triple-mac-v1",
                            blob: sender.blob, opts: opts)
```

`Pipeline.rekey` rotates the parallax + wrapper masters mid-session
(the eight ITB seeds and MAC key are fixed for the session lifetime
by design); the receiver picks up the new masters through a fresh
`sender.blob` handshake:

```swift
try sender.rekey(permMaster: Data(repeating: 0x11, count: 32),
                 wrapMaster: Data(repeating: 0x22, count: 32))
let receiver2 = try Pipeline(open: "singlemsg-triple-mac-v1",
                             blob: sender.blob)
```

The same calls carry `async` variants (`try await
sender.encryptMessage(...)`) that hop the blocking FFI call onto a
background task, and `Result`-shaped variants
(`encryptMessageResult` returning `Result<Data, ItbError>`).

For bounded-memory streaming, `encryptStreamPump` /
`decryptStreamPump` move a whole buffer through an incremental
session; the explicit `encryptStream()` / `decryptStream()`
sessions expose `write` / `end` / `read` for caller-driven loops
plus a `chunks()` `AsyncSequence` for the drain side. The
transform shape consumes any async chunk source:

```swift
for try await wireChunk in sender.encryptStream(from: plainChunks) {
    // forward wireChunk
}
```

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string surfaces as a thrown `ItbError`
carrying the status code plus the `itb_last_error()` diagnostic.

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable
at libitb load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass `-1` to query without
changing. Long-running or allocation-heavy workloads (benchmarks,
bulk encryption) should set both — without a soft cap + aggressive
GC the Go scratch heap grows unboundedly under allocation churn:

```swift
ItbRuntime.setMemoryLimit(512 << 20) // 512 MiB soft cap
ItbRuntime.setGCPercent(20)          // aggressive GC
```

## Testing

```bash
./bindings/swift/run_tests.sh
```

The harness builds `libitb.so` + the C binding library and invokes
`swift test` (XCTest). Positional arguments are forwarded (e.g.
`./run_tests.sh --filter Smoke`). The suite covers Single Message
round trips per shipped profile, stream pumps, incremental sessions
with pathological batch sizes, tampered-wire failure stickiness,
mid-flight cancellation, rekey, profile registration, error
mapping, and the async / `Result` / `AsyncSequence` surfaces —
surface parity checks; the deep suite lives in Go under the shipped
tree.

## Benchmarking

```bash
./bindings/swift/run_bench.sh            # both shapes
./bindings/swift/run_bench.sh message    # Single Message only
./bindings/swift/run_bench.sh stream     # stream pump only
```

Micro-benches: `message` (encryptMessage) and `stream_pump`
(encryptStreamPump) throughput at 1 MiB / 16 MiB / 64 MiB, reported
as an MB/s table on stdout. The runner exports
`ITB_GOMEMLIMIT=512MiB` + `ITB_GOGC=20` defaults (respecting caller
overrides) and the bench main applies the same caps
programmatically; the bench shape follows the fleet-canonical
env-var surface documented in [`bindings/BENCH.md`](../BENCH.md).

## eitb utility

A small CLI mirrors the shipped Go `tools/eitb` scope for shell
smoke tests:

```bash
cd bindings/swift && swift build -c release
.build/release/eitb version
.build/release/eitb hashes
.build/release/eitb encrypt singlemsg-triple-mac-v1 in.bin out.bin   # blob hex on stderr
.build/release/eitb decrypt singlemsg-triple-mac-v1 <blob-hex> out.bin back.bin
```

## Limitations

- The binding wraps the Triple Pipeline surface only. The Low-Level
  seed / MAC / blob / wrapper / parallax APIs are not exposed — use
  the shipped Go core for those.
- Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication.
- The `itb_last_error()` text is process-global last-write-wins on
  the Go side; the `message` attached to an `ItbError` may belong
  to a different call under concurrent FFI use. The status code is
  always attributable.
- `rekey` must not run concurrently with cipher calls or open
  stream sessions on the same `Pipeline`.
- A stream session strongly references its `Pipeline`, so the
  Pipeline cannot be released while a session is alive; sessions
  free their C handle on deinit or on an explicit `free()`
  (idempotent — later calls fail with `.badInput`).
- The `CItb` module resolves the C header by relative path inside
  the monorepo; the package is built in-repo, not as a standalone
  registry package.
