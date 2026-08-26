# ITB Scala Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin idiomatic layer over the Java binding
([`../java/`](../java/)) — plain JVM bytecode interop, no FFI hop of
its own; the Java binding carries the JNI shim over the libitb
`ITB_Triple_*` surface. Every hash-name / MAC-name / cipher-name /
profile-name is an opaque string passed through to Go for
validation; the binding carries no ITB construction logic.

The public surface wraps the Java `Pipeline` / `Opts` in Scala 3
idiom: every fallible call returns `Either[ItbError, _]` (the error
value is also a `RuntimeException`, so throw-based interop stays a
one-liner), results are case classes, `Opts` is an immutable
chainable value, and `Pipeline` / stream sessions are `AutoCloseable`
for `scala.util.Using.resource`. The stream sessions additionally
expose `Iterator[Array[Byte]] => Iterator[Array[Byte]]` /
`LazyList` chunk adapters for functional pipelines; an `fs2.Stream`
/ ZIO wrapper is a straightforward lift of the iterator adapter or
the `Either`-surface `write` / `end` / `read` calls into the effect
type of choice, and is deliberately left to the consumer so the
binding stays dependency-free.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go jdk17-openjdk gradle gcc sbt
```

Generic Linux: a Go toolchain, JDK 17+, Gradle, a C compiler (for
the Java binding's JNI shim), and sbt 1.9+.

## Build

The convenience driver builds the Java binding first (libitb.so +
JNI shim + jars via `../java/build.sh`), then compiles the Scala
library, test, bench, and eitb projects:

```bash
./bindings/scala/build.sh
```

The Java jar is consumed as an sbt unmanaged jar from
`../java/build/libs/`; `ITB_JAVA_LIBS_DIR` overrides that location
(e.g. an installed copy of the Java binding).

## Library lookup order

Native resolution is inherited from the Java binding:

1. `ITB_JNI_PATH` environment variable (path to the JNI shim,
   `bindings/java/build/jni/libitb_jni.so` for in-repo builds).
2. `System.loadLibrary("itb_jni")` over `java.library.path`.

The shim locates `libitb.so` through its RPATH (the repository
`dist/linux-amd64/` directory) or the OS loader path.

## Usage example

```scala
import scala.util.Using
import dev.everanium.itb.{Opts, Pipeline}

Using.resource(Pipeline.init("singlemsg-triple-mac-v1").fold(throw _, identity)) { sender =>
  Using.resource(Pipeline.open("singlemsg-triple-mac-v1", sender.blob).fold(throw _, identity)) { receiver =>
    val result =
      for
        wire  <- sender.encryptMessage("any text or binary data".getBytes("UTF-8"))
        plain <- receiver.decryptMessage(wire)
      yield plain
  }
}
```

`Opts` overrides the profile default per call (chunk size, outer
cipher, parallax on/off, wrapper on/off, MAC name, palette); the
immutable case class chains `with*` calls:

```scala
val opts = Opts().withChunkSize(65536L).withWrapper(false)
val sender = Pipeline.init("singlemsg-triple-mac-v1", opts).fold(throw _, identity)
val receiver = Pipeline.open("singlemsg-triple-mac-v1", sender.blob, opts).fold(throw _, identity)
```

`Pipeline.rekey` rotates the parallax + wrapper masters mid-session
(the eight ITB seeds and MAC key are fixed for the session lifetime
by design); the receiver picks up the new masters through a fresh
`sender.blob` handshake:

```scala
sender.rekey(Array.fill[Byte](32)(0x11), Array.fill[Byte](32)(0x22))
val receiver2 = Pipeline.open("singlemsg-triple-mac-v1", sender.blob).fold(throw _, identity)
```

For bounded-memory streaming, `encryptStreamPump` /
`decryptStreamPump` move any `java.io.InputStream` source into any
`java.io.OutputStream` sink through an incremental session. The
explicit `beginEncryptStream()` / `beginDecryptStream()` sessions
expose `write` / `end` / `read` for caller-driven loops plus the
`transform` / `toLazyList` chunk-iterator adapters:

```scala
Using.resource(pipe.beginEncryptStream().fold(throw _, identity)) { session =>
  val wireChunks: Iterator[Array[Byte]] = session.transform(plaintextChunks)
  wireChunks.foreach(sink)
}
```

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string surfaces as a `Left(ItbError)`
carrying the [`Status`](src/main/scala/dev/everanium/itb/Status.scala)
code plus the `ITB_LastError` diagnostic.

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable
at libitb load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass `-1` to query without
changing:

```scala
dev.everanium.itb.Runtime.setMemoryLimit(512L * 1024 * 1024)
dev.everanium.itb.Runtime.setGCPercent(20)
```

## Testing

```bash
./bindings/scala/run_tests.sh
```

The harness builds everything, exports `ITB_JNI_PATH`, and invokes
`sbt test` (MUnit). The suite covers Single Message round trips per
shipped profile, stream pumps and the chunk-iterator adapters,
incremental sessions with pathological batch sizes, tampered-wire
failure stickiness, mid-flight cancellation, rekey, profile
registration, and error mapping — surface parity checks; the deep
test suite lives in Go under the shipped tree.

## Benchmarking

```bash
./bindings/scala/run_bench.sh            # both shapes
./bindings/scala/run_bench.sh message    # Single Message shape only
./bindings/scala/run_bench.sh stream     # stream-pump shape only
```

Wall-clock micro-benches: `encryptMessage` and stream-pump
throughput at 1 MiB / 16 MiB / 64 MiB. Shape and budget are driven
by the `ITB_*` env vars listed in
`bench/src/main/scala/dev/everanium/itb/bench/BenchUtil.scala`;
defaults match the root Go BENCH3.md pin.

## eitb utility

The `eitb/eitb` launcher compiles on first use, caches the runtime
classpath, and mirrors the shipped Go `tools/eitb` scope for shell
smoke tests:

```bash
cd bindings/scala
eitb/eitb version
eitb/eitb hashes
eitb/eitb encrypt singlemsg-triple-mac-v1 in.bin out.bin   # blob hex on stderr
eitb/eitb decrypt singlemsg-triple-mac-v1 <blob-hex> out.bin back.bin
```

## Limitations

- The binding wraps the Triple Pipeline surface only. The Low-Level
  seed / MAC / blob / wrapper / parallax APIs are not exposed — use
  the shipped Go core for those.
- Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication.
- `ITB_LastError` is process-global last-write-wins; the textual
  diagnostic attached to an `ItbError` may belong to a different
  call under concurrent use. The status code is always attributable.
- `rekey` must not run concurrently with cipher calls or open stream
  sessions on the same `Pipeline`.
- The `transform` / `toLazyList` adapters are single-pass: traverse
  the returned iterator at most once and do not interleave it with
  direct `write` / `read` calls on the same session.
- The Java binding (and through it the JNI shim + libitb) must be
  built and reachable per the lookup order above.
