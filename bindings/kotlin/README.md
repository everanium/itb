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

The public surface is one `Pipeline` type (init / load / save /
rekey / destroy, Single Message encrypt / decrypt, one-shot and
incremental stream sessions with `java.io` stream pumps), an `Opts`
builder, a `Profile` record with the registry entries
`Pipeline.register` / `lookup` / `profiles` and the blob reader
`Pipeline.inspect`, and the Go runtime knobs on `ItbRuntime`. Stream sessions pin their parent `Pipeline` (the
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
    Pipeline.load(sender.save()).use { receiver ->
        val wire = sender.encryptMessage("any text or binary data".encodeToByteArray())
        val plain = receiver.decryptMessage(wire)
    }
}
// Or persist the session to disk and reopen it later:
//   sender.saveF("/path/session.blob")
//   Pipeline.loadF("/path/session.blob").use { receiver -> /* ... */ }
```

The `Opts` DSL overrides the profile default at `init` (chunk size,
outer cipher, parallax on/off, wrapper on/off, MAC name, palette,
`maxWorkers`); the blob the receiver loads carries the resolved
shape, so `load` takes no opts:

```kotlin
val cfg = opts { chunkSize(65536); wrapper(false) }
Pipeline.init("singlemsg-triple-mac-v1", cfg).use { sender ->
    Pipeline.load(sender.save()).use { receiver ->
        // ...
    }
}
```

`Pipeline.rekey` rotates the parallax + wrapper masters mid-session
(the eight ITB seeds and MAC key are fixed for the session lifetime
by design) and returns the refreshed blob; the receiver picks up
the new masters through a fresh `save()` / `load` handshake:

```kotlin
val rotated = sender.rekey(ByteArray(32) { 0x11 }, ByteArray(32) { 0x22 })
Pipeline.load(rotated).use { receiver -> /* ... */ }
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

## Persisting sessions

The blob `save()` returns is self-describing: it carries the profile
record (the resolved pipeline shape) alongside the key material, so
a receiver reconstructs the session from the blob alone.

```kotlin
val blob = sender.save()                        // current session blob
sender.saveF("/path/session.blob")              // same bytes, written by the library (mode 0600)
val a = Pipeline.load(blob)                     // reopen from bytes
val b = Pipeline.loadF("/path/session.blob")    // reopen from a file
val c = Pipeline.load(blob, perm, wrap)         // reopen with a master override
val p: Profile = Pipeline.inspect(blob)         // metadata only, no Pipeline opened
```

Load works for blobs generated with shipped primitives (every entry
in the shipped catalogue). Blobs generated by Go programs that use
`hashes.Register` or `macs.Register` to install custom primitives
cannot be loaded through this binding — the receiver must use the Go
library directly and register the same custom primitive under the
same name before opening. Attempting to load such a blob through
this binding surfaces `Status.RecipePrimitiveUnknown`. A blob from an earlier wrap-layer
version surfaces `Status.BadInput`; a record that fails the profile field
rules surfaces `Status.BlobMalformedRecipe`.

The profile registry is reachable through the same `Profile`
record:

```kotlin
val names: List<String> = Pipeline.profiles()   // sorted registry names
val shipped = Pipeline.lookup("singlemsg-triple-nomac-v1")
val custom = profile {
    mode("singlemsg-nomac"); width(512); hash("areion512"); keyBits(1024)
    wrapper(false); parallax(false)
}
Pipeline.register("my-profile", custom)        // validated by Go; duplicate -> ProfileExists
```

`Profile` is a plain record plus JSON codec — no validation happens
on the binding side. `inspect` / `lookup` return it; `register`
accepts it; an unknown name at `init` / `lookup` surfaces `Status.UnknownProfile`.

Runtime tuning: `pipeline.maxWorkers(n)` sets the worker cap for every
subsequent cipher call (`n <= 0` selects auto, `n > 256` is clamped
to 256); the receiver may pick its own worker cap after `load` — the
cap is per-machine and never written to the blob.

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
session persistence (save / load, saveF / loadF, inspect, lookup / profiles / register, maxWorkers), error mapping, the Result variants, and the
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

The launcher mirrors the shipped Go `tools/eitb` scope for shell
smoke tests:

```bash
cd bindings/kotlin
./eitb/eitb version
./eitb/eitb profiles
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
