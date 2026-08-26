# ITB Dart Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the libitb shared library's `ITB_Triple_*` surface
(`cmd/cshared`). Runtime FFI via the SDK's built-in `dart:ffi` —
no build step, no C compiler at install time, one small pub
dependency (`ffi` for UTF-8 marshalling and the malloc allocator);
the `.so` / `.dylib` / `.dll` is resolved and dispatched at first
use. Every hash-name / MAC-name / cipher-name / profile-name is an
opaque string passed through to Go for validation; the binding
carries no ITB construction logic. The public surface is one
`Pipeline` class (create / open / rekey / close, Single Message
encrypt / decrypt, whole-buffer and incremental stream sessions with
chunk pumps), the `Itb` facade (create / open / hashes / profiles /
version / runtime knobs), an `Opts` query-string builder,
`registerProfile`, and `ItbException`.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go dart
```

Generic Linux / macOS: a Go toolchain plus Dart SDK 3.0+. Windows:
the same; libitb builds as `libitb.dll`.

## Build the shared library

The convenience driver builds `libitb.so`, resolves the pub
dependencies, and analyzes the Dart sources in one step:

```bash
./bindings/dart/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
cd bindings/dart && dart pub get
```

The package is importable directly from `bindings/dart/` (no build
step — `dart:ffi` loads the shared library at runtime); depend on it
from another package via a `path:` dependency.

## Library lookup order

1. `ITB_LIBITB_PATH` environment variable (path to the shared
   library file).
2. `<repo>/dist/<os>-<arch>/libitb.<ext>` found by walking up from
   the current working directory (in-repo builds).
3. The OS default loader path (`LD_LIBRARY_PATH`, `ld.so.cache`,
   `DYLD_LIBRARY_PATH`, `PATH`).

## Usage example

```dart
import 'dart:convert';
import 'dart:typed_data';

import 'package:itb/itb.dart';

void main() {
  final sender = Itb.create('singlemsg-triple-mac-v1');
  final receiver = Itb.open('singlemsg-triple-mac-v1', sender.blob);

  final plain = Uint8List.fromList(utf8.encode('any text or binary data'));
  final wire = sender.encryptMessage(plain);
  final back = receiver.decryptMessage(wire);
  assert(utf8.decode(back) == 'any text or binary data');

  sender.free();
  receiver.free();
}
```

The `Opts` builder overrides the profile default per call (chunk
size, outer cipher, parallax on/off, wrapper on/off, MAC name,
palette):

```dart
final opts = Opts()
    ..withChunkSize(65536)
    ..withWrapper(false);
final sender = Itb.create('singlemsg-triple-mac-v1', opts);
final receiver = Itb.open('singlemsg-triple-mac-v1', sender.blob, opts: opts);
```

`Pipeline.rekey` rotates the parallax + wrapper masters mid-session
(the eight ITB seeds and MAC key are fixed for the session lifetime
by design); the receiver picks up the new masters through a fresh
`sender.blob` handshake:

```dart
sender.rekey(Uint8List(32)..fillRange(0, 32, 0x11),
             Uint8List(32)..fillRange(0, 32, 0x22));
final receiver2 = Itb.open('singlemsg-triple-mac-v1', sender.blob);
```

`Pipeline.free()` releases the Go-side handle deterministically; a
`Finalizer` backstop frees on garbage collection for the non-`free`
path (libitb zeroes key material internally). For bounded-memory
streaming, `encryptStream()` / `decryptStream()` open incremental
sessions exposing `write` / `end` / `read` / `drainAll` for
caller-driven loops plus a `pump` helper that moves an iterable of
chunks into a sink through one reused native buffer pair. A session
holds a reference to its parent `Pipeline`, so the Pipeline handle
cannot be finalized while a session is live.

Hot-loop callers that own their buffers use the caller-buffer
siblings: `encryptMessageInto(plain, dst)` / `decryptMessageInto(wire,
dst)` write into a reusable `Uint8List` and return the byte count
(no retry — an undersized `dst` throws `Status.bufferTooSmall`; the
pre-allocation formula `payload * 5 / 4 + 65536` typically suffices),
and the session `read(dst)` drains into a reusable buffer. Every
cipher / stream call runs on grow-only pooled native scratch owned by
its `Pipeline` / session, so steady-state dispatch performs no native
allocation; `free()` releases the pools with the handle.

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string throws `ItbException` carrying the
status code (`statusCode`, see `Status`) plus the `ITB_LastError`
diagnostic (`lastError`).

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable at
libitb load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass `-1` to query without
changing:

```dart
Itb.setMemoryLimit(512 << 20);
Itb.setGcPercent(20);
```

## Testing

```bash
./bindings/dart/run_tests.sh
```

The harness builds `libitb.so`, exports `ITB_LIBITB_PATH`, and
invokes `dart test`. Positional arguments are forwarded (e.g.
`./run_tests.sh --name 'round trip'`). The suite covers the version
and hash-roster surfaces, Single Message round trips per shipped
cipher profile, incremental stream sessions with pathological batch
sizes, stream pumps, rekey, tampered-wire failure, profile
registration, and error mapping — surface parity checks; the deep
suite lives in Go under the shipped tree.

## Benchmarking

```bash
./bindings/dart/run_bench.sh
```

Micro-benches: `encryptMessageInto` and stream-pump throughput at 1 MiB /
16 MiB / 64 MiB. Shape and budget are driven by env vars
(`ITB_PROFILE`, `ITB_INNER_HASH`, `ITB_KEY_BITS`, `ITB_NONCE_BITS`,
`ITB_WITH_PARALLAX`, `ITB_WITH_WRAPPER`, `ITB_BENCH_MIN_SEC`); the
script pins the same defaults as the root Go BENCH3.md table.

## eitb utility

A small CLI under `bindings/dart/eitb/` mirrors the shipped Go
`tools/eitb` scope for shell smoke tests:

```bash
./bindings/dart/eitb/eitb version
./bindings/dart/eitb/eitb hashes
./bindings/dart/eitb/eitb profiles
./bindings/dart/eitb/eitb encrypt singlemsg-triple-mac-v1 in.bin out.bin  # blob hex on stderr
./bindings/dart/eitb/eitb decrypt singlemsg-triple-mac-v1 <blob-hex> out.bin back.bin
```

## Limitations

- The binding wraps the Triple Pipeline surface only. The Low-Level
  seed / MAC / blob / wrapper / parallax APIs are not exposed — use
  the shipped Go core for those.
- Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication.
- `ITB_LastError` is process-global last-write-wins; the textual
  diagnostic attached to an `ItbException` may belong to a different
  call under concurrent FFI use. The status code is always
  attributable.
- `rekey` must not run concurrently with cipher calls or open stream
  sessions on the same `Pipeline`.
- FFI calls are synchronous and run on the calling isolate's thread;
  a large cipher call blocks that isolate until it returns. Dispatch
  from a worker isolate (`Isolate.run`) when the main isolate must
  stay responsive — but keep any one `Pipeline` on a single isolate:
  handles are plain integers and are not safe to share across
  isolates concurrently.
- Input buffers are copied into native memory at the FFI boundary;
  outputs are freshly-allocated `Uint8List`s.
- libitb must be reachable at runtime through the lookup order above.
