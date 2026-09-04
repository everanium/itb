# ITB Groovy Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the sibling [Java binding](../java/) — plain JVM
bytecode interop, no FFI layer of its own. The Java binding carries
the JNI shim and the libitb `ITB_Triple_*` handle lifetime; this
layer re-shapes that surface into idiomatic Groovy: closure-scoped
lifetimes (`withPipeline { }`, `encrypting { }` / `decrypting { }`),
a named-argument `Opts.of(key: value, …)` map factory beside the
chainable builder, and extension-module methods on `byte[]` /
`InputStream` for one-line cipher calls. Every class is
`@CompileStatic`, so cipher and stream calls compile to plain JVM
bytecode with no metaclass dispatch on the hot paths. Every
hash-name / MAC-name / cipher-name / profile-name remains an opaque
string passed through to Go for validation; no ITB construction
logic lives on the JVM side.

The public surface is one `Pipeline` type (init / load / save / rekey /
destroy, Single Message encrypt / decrypt, whole-buffer and
incremental stream sessions with `java.io` stream pumps), an `Opts`
builder,
a `Profile` record with the registry entries `Pipeline.register` /
`lookup` / `profiles` and the blob reader `Pipeline.inspect`, and the
Go runtime knobs on `Runtime`.
Stream sessions pin their parent `Pipeline` (the `parent` field), so
a pipeline stays reachable while a session on it is live;
unreachable un-closed handles are reclaimed by the Java layer's
`Cleaner` backstop.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go jdk17-openjdk groovy gradle gcc
```

Generic Linux: a Go toolchain, JDK 17+, and gcc (for the Java
binding's JNI shim). The Gradle wrapper pins the build's Gradle
version; the Groovy compiler and every jar dependency resolve
through it.

## Build

The convenience driver builds the whole stack — `libitb.so`, the
Java binding (JNI shim + jar), then the Groovy classes and the eitb
jar:

```bash
./bindings/groovy/build.sh
```

Equivalent manual invocation:

```bash
./bindings/java/build.sh
cd bindings/groovy && ./gradlew assemble
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

```groovy
import dev.everanium.itb.groovy.Pipeline

Pipeline.withPipeline('singlemsg-triple-mac-v1') { sender ->
    Pipeline.withLoaded(sender.save()) { receiver ->
        byte[] wire = sender.encryptMessage('any text or binary data'.bytes)
        byte[] plain = receiver.decryptMessage(wire)
    }
}
// Or persist the session to disk and reopen it later:
//   sender.saveF('/path/session.blob')
//   Pipeline.loadF('/path/session.blob').withCloseable { receiver -> /* ... */ }
```

`Pipeline` is `AutoCloseable`, so Groovy's `withCloseable { }` and
Java-style try-with-resources scope it equally well; the
`withPipeline` / `withLoaded` factories fold init (or load) + close
into one closure.

The `Opts` builder overrides the profile default at `init` (chunk
size, outer cipher, parallax on/off, wrapper on/off, MAC name,
palette, `maxWorkers`); the blob the receiver loads carries the
resolved shape, so `load` takes no opts:

```groovy
def opts = new Opts().withChunkSize(65536).withWrapper(false)
Pipeline.withPipeline('singlemsg-triple-mac-v1', opts) { sender ->
    Pipeline.withLoaded(sender.save()) { receiver ->
        // ...
    }
}
```

`Pipeline#rekey` rotates the parallax + wrapper masters mid-session
(the eight ITB seeds and MAC key are fixed for the session lifetime
by design) and returns the refreshed blob; the receiver picks up
the new masters through a fresh `save()` / `load` handshake:

```groovy
byte[] rotated = sender.rekey(new byte[32].tap { Arrays.fill(it, (byte) 0x11) },
                              new byte[32].tap { Arrays.fill(it, (byte) 0x22) })
def receiver2 = Pipeline.load(rotated)
```

For bounded-memory streaming, `encryptStreamPump` /
`decryptStreamPump` move any `java.io.InputStream` source into any
`java.io.OutputStream` sink through an incremental session; the
explicit `encryptStream()` / `decryptStream()` sessions expose
`write` / `end` / `read` / `drainTo` for caller-driven loops, and
the `encrypting { }` / `decrypting { }` closures scope a session the
way `withPipeline { }` scopes a pipeline.

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string surfaces as `ItbException` carrying
the structural `Status` plus the `ITB_LastError` diagnostic.

### Extension methods

The jar registers a Groovy extension module, so `byte[]` and
`InputStream` values gain cipher sugar wherever the binding is on
the classpath:

```groovy
byte[] wire  = plainBytes.encryptWith(pipe)     // Single Message
byte[] plain = wire.decryptWith(pipe)

srcStream.encryptTo(pipe, dstStream)            // bounded-memory pump
wireStream.decryptTo(pipe, plainStream)
```

### Named-argument opts

Beside the chainable builder, `Opts.of` accepts a Groovy
named-argument map — byte-array values are hex-encoded, everything
else is rendered with `toString()`:

```groovy
def opts = Opts.of(chunkSize: 4096, withParallax: false)
```

## Persisting sessions

The blob `save()` returns is self-describing: it carries the profile
record (the resolved pipeline shape) alongside the key material, so
a receiver reconstructs the session from the blob alone.

```groovy
byte[] blob = sender.save()                       // current session blob
sender.saveF('/path/session.blob')                // same bytes, written by the library (mode 0600)
def a = Pipeline.load(blob)                       // reopen from bytes
def b = Pipeline.loadF('/path/session.blob')      // reopen from a file
def c = Pipeline.loadWithMasters(blob, perm, wrap) // reopen with a master override
def p = Pipeline.inspect(blob)                    // com.everanium.itb.Profile; no Pipeline opened
Pipeline.withLoaded(blob) { receiver -> /* ... */ } // load + close in one closure
```

Load works for blobs generated with shipped primitives (every entry
in the shipped catalogue). Blobs generated by Go programs that use
`hashes.Register` or `macs.Register` to install custom primitives
cannot be loaded through this binding — the receiver must use the Go
library directly and register the same custom primitive under the
same name before opening. Attempting to load such a blob through
this binding surfaces `Status.RECIPE_PRIMITIVE_UNKNOWN`. A blob from an earlier wrap-layer
version surfaces `Status.BAD_INPUT`; a record that fails the profile field
rules surfaces `Status.BLOB_MALFORMED_RECIPE`.

The profile registry is reachable through the same `com.everanium.itb.Profile`
record:

```groovy
List<String> names = Pipeline.profiles()          // sorted registry names
def shipped = Pipeline.lookup('singlemsg-triple-nomac-v1')
Pipeline.register('my-profile',                   // named-argument map form ...
        mode: 'singlemsg-nomac', width: 512, hash: 'areion512', keyBits: 1024,
        wrapper: false, parallax: false)
Pipeline.register('other-profile', Pipeline.profileOf(mode: 'singlemsg-nomac', width: 512,
        hash: 'areion512', keyBits: 1024))       // ... or an explicit Profile record
```

`com.everanium.itb.Profile` is a plain record plus JSON codec — no validation happens
on the binding side. `inspect` / `lookup` return it; `register`
accepts it; an unknown name at `init` / `lookup` surfaces `Status.UNKNOWN_PROFILE`.

Runtime tuning: `pipeline.maxWorkers(n)` sets the worker cap for every
subsequent cipher call (`n <= 0` selects auto, `n > 256` is clamped
to 256); the receiver may pick its own worker cap after `load` — the
cap is per-machine and never written to the blob.

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable
at libitb load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass `-1` to query without
changing:

```groovy
import dev.everanium.itb.groovy.Runtime

Runtime.setMemoryLimit(512L << 20)
Runtime.setGCPercent(20)
```

## Testing

```bash
./bindings/groovy/run_tests.sh
```

The harness builds the full stack and invokes the JUnit 5 suite
through Gradle (arguments forwarded, e.g. `./run_tests.sh --tests
'*SmokeTest'`). The suite covers Single Message round trips, stream
pumps, incremental sessions with pathological batch sizes,
tampered-wire failure stickiness, mid-flight cancellation, rekey,
session persistence (save / load, saveF / loadF, inspect, lookup / profiles / register, maxWorkers), error mapping, the extension-module sugar,
and the `Opts` builders — surface parity checks; the deep suite
lives in Go under the shipped tree.

## Benchmarking

```bash
./bindings/groovy/run_bench.sh            # both shapes
./bindings/groovy/run_bench.sh message    # Single Message shape only
./bindings/groovy/run_bench.sh stream     # stream-pump shape only
```

Wall-clock micro-benches: `encryptMessage` and stream-pump
throughput at 1 MiB / 16 MiB / 64 MiB. Shape and budget are driven
by the `ITB_*` env vars listed in `bench/BenchUtil.groovy`; defaults
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
cd bindings/groovy
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
