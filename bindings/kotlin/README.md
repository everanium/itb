# ITB Kotlin Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the sibling [Java binding](../java/) — plain JVM
bytecode interop, no FFI layer of its own. The Java binding carries
the JNI shim and the libitb `ITB_Triple_*` handle lifetime; this
layer re-shapes that surface into idiomatic Kotlin: a sealed
`Status` hierarchy for exhaustive `when` matching, `AutoCloseable`
types built for `use { }` scoping, an `opts { }` builder DSL,
`Result`-returning cipher variants for railway-style call sites,
and `suspend` variants of the blocking entry points on
`Dispatchers.IO`. Every hash-name / MAC-name / cipher-name /
profile-name remains an opaque string passed through to Go for
validation; no ITB construction logic lives on the JVM side.

The public surface is one `Pipeline` type (init / open / rekey /
destroy, Single Message encrypt / decrypt, one-shot and incremental
stream sessions with `java.io` stream pumps), an `Opts` builder,
`Pipeline.registerProfile`, and the Go runtime knobs on
`ItbRuntime`. Stream sessions pin their parent `Pipeline` (the
`parent` property), so a pipeline stays reachable while a session
on it is live; unreachable un-closed handles are reclaimed by the
Java layer's `Cleaner` backstop.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go jdk17-openjdk kotlin gradle gcc
```

Generic Linux: a Go toolchain, JDK 17+, and gcc (for the Java
binding's JNI shim). The Gradle wrapper pins the build's Gradle
version; the Kotlin compiler and every jar dependency resolve
through it.

## Build

The convenience driver builds the whole stack — `libitb.so`, the
Java binding (JNI shim + jar), then the Kotlin classes and the eitb
jar:

```bash
./bindings/kotlin/build.sh
```

Equivalent manual invocation:

```bash
./bindings/java/build.sh
cd bindings/kotlin && ./gradlew assemble
```

## Library lookup order

Native resolution happens entirely in the Java layer:

1. `ITB_JNI_PATH` environment variable (path to `libitb_jni.so`);
   the driver scripts and Gradle tasks default it to the sibling
   Java build's output.
2. `System.loadLibrary("itb_jni")` over `java.library.path`.

`libitb.so` itself is found through the shim's RPATH (the
repository dist directory) or the OS loader path.

## Usage example

```kotlin
import com.everanium.itb.kotlin.*

Pipeline.init("singlemsg-triple-mac-v1").use { sender ->
    Pipeline.open("singlemsg-triple-mac-v1", sender.blob).use { receiver ->
        val wire = sender.encryptMessage("any text or binary data".encodeToByteArray())
        val plain = receiver.decryptMessage(wire)
    }
}
```

The `Opts` DSL overrides the profile default per call (chunk size,
outer cipher, parallax on/off, wrapper on/off, MAC name, palette):

```kotlin
val cfg = opts { chunkSize(65536); wrapper(false) }
Pipeline.init("singlemsg-triple-mac-v1", cfg).use { sender ->
    Pipeline.open("singlemsg-triple-mac-v1", sender.blob, cfg).use { receiver ->
        // ...
    }
}
```

`Pipeline.rekey` rotates the parallax + wrapper masters mid-session
(the eight ITB seeds and MAC key are fixed for the session lifetime
by design); the receiver picks up the new masters through a fresh
`sender.blob` handshake:

```kotlin
sender.rekey(ByteArray(32) { 0x11 }, ByteArray(32) { 0x22 })
Pipeline.open("singlemsg-triple-mac-v1", sender.blob).use { receiver -> /* ... */ }
```

For bounded-memory streaming, `encryptStreamPump` /
`decryptStreamPump` move any `java.io.InputStream` source into any
`java.io.OutputStream` sink through an incremental session; the
explicit `encryptStream()` / `decryptStream()` sessions expose
`write` / `end` / `read` / `copyTo` for caller-driven loops, and
the `encrypting { }` / `decrypting { }` extensions scope a session
the way `use { }` scopes a pipeline.

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string surfaces as `ItbException` carrying
the sealed `Status` plus the `ITB_LastError` diagnostic.

### Result variants

Each cipher entry point has a `...Catching` extension returning
`kotlin.Result`, with the failure's sealed status readable through
`itbStatus`:

```kotlin
val plain = receiver.decryptMessageCatching(wire).getOrElse { e ->
    if ((e as? ItbException)?.status == Status.MacFailure) ByteArray(0) else throw e
}
```

### Coroutines

`...Async` variants suspend on `Dispatchers.IO` instead of blocking
the caller:

```kotlin
val wire = sender.encryptMessageAsync(plain)   // suspend fun
```

The Go-side Pipeline is concurrent-safe for cipher calls, so
several `async { }` encrypts may be in flight on one `Pipeline`;
`rekey` must not run concurrently with cipher calls or open stream
sessions.

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable
at libitb load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass `-1` to query without
changing:

```kotlin
ItbRuntime.setMemoryLimit(512L shl 20)
ItbRuntime.setGCPercent(20)
```

## Testing

```bash
./bindings/kotlin/run_tests.sh
```

The harness builds the full stack and invokes the JUnit 5 suite
through Gradle (arguments forwarded, e.g. `./run_tests.sh --tests
'*SmokeTest'`). The suite covers Single Message round trips, stream
pumps, incremental sessions with pathological batch sizes,
tampered-wire failure stickiness, mid-flight cancellation, rekey,
profile registration, error mapping, the Result variants, and the
coroutine surface — surface parity checks; the deep suite lives in
Go under the shipped tree.

## Benchmarking

```bash
./bindings/kotlin/run_bench.sh            # both shapes
./bindings/kotlin/run_bench.sh message    # Single Message shape only
./bindings/kotlin/run_bench.sh stream     # stream-pump shape only
```

Wall-clock micro-benches: `encryptMessage` and stream-pump
throughput at 1 MiB / 16 MiB / 64 MiB. Shape and budget are driven
by the `ITB_*` env vars listed in `bench/BenchUtil.kt`; defaults
match the root Go BENCH3.md pin.

## eitb utility

The launcher mirrors the shipped Go `tools/eitb` scope for shell
smoke tests:

```bash
cd bindings/kotlin
./eitb/eitb version
./eitb/eitb hashes
./eitb/eitb encrypt singlemsg-triple-mac-v1 in.bin out.bin   # blob hex on stderr
./eitb/eitb decrypt singlemsg-triple-mac-v1 <blob-hex> out.bin back.bin
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
  call under concurrent use. The status code is always attributable.
- `rekey` must not run concurrently with cipher calls or open stream
  sessions on the same `Pipeline`.
- The sibling Java binding must be built first (its jar and JNI shim
  are this binding's runtime); `build.sh` handles the ordering.
