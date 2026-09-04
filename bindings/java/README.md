# ITB Java Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the libitb shared library's `ITB_Triple_*` surface
(`cmd/cshared`). JNI-based FFI: a small C shim (`src/main/jni/itb_jni.c`)
is compiled against libitb.so and loaded by the `com.everanium.itb`
package at class-initialisation time. JNI (rather than the Panama
foreign-function API) keeps the binding compatible with JDK 17 LTS and
Android-class runtimes. Every hash-name / MAC-name / cipher-name /
profile-name is an opaque string passed through to Go for validation;
the binding carries no ITB construction logic. The public surface is
one `Pipeline` type (init / load / save / rekey / destroy, Single
Message encrypt / decrypt, whole-buffer and incremental stream
sessions with `InputStream` / `OutputStream` pumps), an `Opts`
query-string builder, a `Profile` record with the registry entries
`Pipeline.register` / `lookup` / `profiles` and the blob reader
`Pipeline.inspect`, and the Go runtime knobs.

Handle lifetime is managed with `java.lang.ref.Cleaner`: `Pipeline`
and the stream sessions implement `AutoCloseable` (explicit `close()`
frees the Go-side handle) with a Cleaner registration as the GC
backstop. A stream session holds a strong reference to its parent
`Pipeline`, so a Pipeline can never be collected under a live session.
Buffers cross the JNI boundary as direct `ByteBuffer`s (zero-copy at
the shim layer; heap byte arrays are copied in and out on the Java
side).

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go jdk17-openjdk gcc
```

Generic Linux: a Go toolchain, JDK 17+, and a C compiler. Gradle is
provided by the checked-in wrapper (`./gradlew`), which downloads the
pinned distribution on first use. The binding targets Java 17.

## Build the shared library

The convenience driver builds `libitb.so`, the JNI shim, and the jars
in one step:

```bash
./bindings/java/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
cd bindings/java && ./gradlew assemble
```

## Library lookup order

1. `ITB_JNI_PATH` environment variable (absolute path to the compiled
   `libitb_jni.so` shim).
2. `System.loadLibrary("itb_jni")` over `java.library.path`.

libitb.so itself is a link-time dependency of the shim, resolved via
the shim's RPATH (the repository `dist/linux-amd64/` directory) or the
OS loader path (`LD_LIBRARY_PATH`, `ld.so.cache`).

## Usage example

```java
import com.everanium.itb.Opts;
import com.everanium.itb.Pipeline;

try (Pipeline sender = Pipeline.init("singlemsg-triple-mac-v1");
        Pipeline receiver = Pipeline.load(sender.save())) {
    byte[] wire = sender.encryptMessage("any text or binary data".getBytes());
    byte[] plain = receiver.decryptMessage(wire);
}
// Or persist the session to disk and reopen it later:
//   sender.saveF("/path/session.blob");
//   Pipeline receiver = Pipeline.loadF("/path/session.blob");
```

The `Opts` builder overrides the profile default at `init` (chunk
size, outer cipher, parallax on/off, wrapper on/off, MAC name,
palette, `maxWorkers`); the blob the receiver loads carries the
resolved shape, so `load` takes no opts:

```java
Opts opts = new Opts().withChunkSize(65536).withWrapper(false);
try (Pipeline sender = Pipeline.init("singlemsg-triple-mac-v1", opts);
        Pipeline receiver = Pipeline.load(sender.save())) {
    // ...
}
```

`Pipeline.rekey` rotates the parallax + wrapper masters mid-session
(the eight ITB seeds and MAC key are fixed for the session lifetime
by design) and returns the refreshed blob; the receiver picks up the
new masters through a fresh `save()` / `load` handshake:

```java
byte[] perm = new byte[32]; byte[] wrap = new byte[32];
// populate perm / wrap with fresh material
byte[] rotated = sender.rekey(perm, wrap);
Pipeline receiver2 = Pipeline.load(rotated);
```

## Persisting sessions

The blob `save()` returns is self-describing: it carries the profile
record (the resolved pipeline shape) alongside the key material, so
a receiver reconstructs the session from the blob alone.

```java
byte[] blob = sender.save();                    // current session blob
sender.saveF("/path/session.blob");             // same bytes, written by the library (mode 0600)
Pipeline a = Pipeline.load(blob);               // reopen from bytes
Pipeline b = Pipeline.loadF("/path/session.blob"); // reopen from a file
Pipeline c = Pipeline.load(blob, perm, wrap);   // reopen with a master override
Profile p = Pipeline.inspect(blob);             // metadata only, no Pipeline opened
```

Load works for blobs generated with shipped primitives (every entry
in the shipped catalogue). Blobs generated by Go programs that use
`hashes.Register` or `macs.Register` to install custom primitives
cannot be loaded through this binding — the receiver must use the Go
library directly and register the same custom primitive under the
same name before opening. Attempting to `load` such a blob through
this binding surfaces `Status.RECIPE_PRIMITIVE_UNKNOWN`. A blob from
an earlier wrap-layer version surfaces `Status.BAD_INPUT`; a record
that fails the profile field rules surfaces
`Status.BLOB_MALFORMED_RECIPE`.

The profile registry is reachable through the same `Profile` record:

```java
List<String> names = Pipeline.profiles();       // sorted registry names
Profile shipped = Pipeline.lookup("singlemsg-triple-nomac-v1");
Profile custom = new Profile()
        .mode("singlemsg-nomac").width(512).hash("areion512").keyBits(1024)
        .wrapper(false).parallax(false);
Pipeline.register("my-profile", custom);        // validated by Go; duplicate -> PROFILE_EXISTS
```

`Profile` is a plain record plus JSON codec — no validation happens
in Java. `inspect` / `lookup` return it; `register` accepts it; an
unknown name at `init` / `lookup` surfaces `Status.UNKNOWN_PROFILE`.

Runtime tuning: `pipeline.maxWorkers(n)` sets the worker cap for
every subsequent cipher call (`n <= 0` selects auto, `n > 256` is
clamped to 256); the receiver may pick its own worker cap after
`load` — the cap is per-machine and never written to the blob.

For bounded-memory streaming, `encryptStreamPump` / `decryptStreamPump`
move any `InputStream` source into any `OutputStream` sink through an
incremental session; the explicit `encryptStream()` / `decryptStream()`
sessions expose `write` / `end` / `read` / `isFinished` for
caller-driven loops.

For allocation-free hot loops, every cipher entry has an `*Into`
variant (`encryptMessageInto`, `decryptMessageInto`,
`encryptStreamOneShotInto`, `decryptStreamOneShotInto`) that writes
the output between `position()` and `limit()` of a caller-supplied
writable direct `ByteBuffer` — no output allocation, no copy-out, and
libitb never writes past the limit. Stream sessions likewise accept a
direct-buffer feed (`write(ByteBuffer)`) and drain
(`readInto(ByteBuffer)`), both zero-copy at the FFI boundary. Size
Message / one-shot output buffers for the wire-expansion envelope
`max(131072, len * 5/4 + 131072)`; an undersized buffer fails with
`Status.BUFFER_TOO_SMALL`, and a heap, read-only, or spent buffer is
rejected with `IllegalArgumentException`.

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string surfaces as an `ItbException` carrying
the status code plus the `ITB_LastError` diagnostic.

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable at
libitb load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass `-1` to query without
changing:

```java
com.everanium.itb.Runtime.setMemoryLimit(512L << 20);
com.everanium.itb.Runtime.setGCPercent(20);
```

## Testing

```bash
./bindings/java/run_tests.sh
```

The harness builds `libitb.so` + the JNI shim, then invokes the
JUnit 5 suite through Gradle. Positional arguments are forwarded to
Gradle (e.g. `./run_tests.sh --tests '*SmokeTest'`). The suite covers
Single Message round trips per shipped profile, stream pumps,
incremental sessions with pathological batch sizes, tampered-wire
failure stickiness, mid-flight cancellation, rekey, session
persistence (save / load, saveF / loadF, inspect, lookup / profiles
/ register, maxWorkers), and error mapping — surface parity checks;
the deep suite lives in Go under the shipped tree.

## Benchmarking

```bash
./bindings/java/run_bench.sh
```

Plain-table micro-benches: `message` (Single Message encrypt) and
`stream_pump` throughput at 1 MiB / 16 MiB / 64 MiB. The script
exports the canonical bench env defaults (`ITB_GOMEMLIMIT=512MiB`,
`ITB_GOGC=20`, `ITB_NONCE_BITS=512`, `ITB_KEY_BITS=1024`,
`ITB_WITH_PARALLAX=false`, `ITB_WITH_WRAPPER=false`,
`ITB_INNER_HASH=areion512`); override any of them before invocation.
`ITB_BENCH_MIN_SEC` adjusts the per-case wall-clock budget.

## Related — `itb3` CLI

The Go core ships an openssl-style CLI utility
[`itb3`](../../cmd/itb3/) that generates session blobs on disk
(`itb3 genblob <mode> <hash> -o blob.json`); this binding reopens
such blobs via `Pipeline.loadF`. `itb3` also encrypts / decrypts
payloads directly on disk (`-i` / `-o`) or through stdin / stdout,
rotates outer masters, and inspects stored blobs. See
[`cmd/itb3/README.md`](../../cmd/itb3/README.md) for the full
subcommand reference.

## eitb utility

A small CLI mirrors the shipped Go `tools/eitb` scope for shell smoke
tests:

```bash
./bindings/java/eitb/eitb version
./bindings/java/eitb/eitb profiles
./bindings/java/eitb/eitb encrypt singlemsg-triple-mac-v1 in.bin out.bin  # blob hex on stderr
./bindings/java/eitb/eitb decrypt singlemsg-triple-mac-v1 <blob-hex> out.bin back.bin
```

Equivalent direct invocation: `java -jar build/libs/eitb.jar version`
(with `ITB_JNI_PATH` pointing at the compiled shim).

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
- The Go side of a `Pipeline` is safe for concurrent use; the Java
  wrapper's one-shot cipher calls are likewise safe from multiple
  threads. A stream session is single-caller: its scratch buffers are
  not synchronised.
- The JNI shim must be compiled for the running platform; the build
  currently targets Linux (`libitb_jni.so`).
