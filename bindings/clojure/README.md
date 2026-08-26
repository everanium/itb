# ITB Clojure Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the sibling [Java binding](../java/) — plain JVM
bytecode interop, no FFI layer of its own. The Java binding carries
the JNI shim and the libitb `ITB_Triple_*` handle lifetime; this
layer re-shapes that surface into idiomatic Clojure: a `Pipeline`
record and session types implementing `AutoCloseable` for
`with-open` scoping, keyword opts maps in place of a builder,
ex-info errors carrying status keywords for plain `=` / `case`
matching, and a `Session` protocol over the incremental stream
surface. Every hash-name / MAC-name / cipher-name / profile-name
remains an opaque string passed through to Go for validation; no
ITB construction logic lives on the JVM side.

The public surface is the `core` namespace (`init` / `open` /
`rekey!` / `destroy!`, Single Message encrypt / decrypt, one-shot
and incremental stream sessions with `java.io` stream pumps),
keyword opts maps rendered by the `opts` namespace,
`register-profile!`, and the Go runtime knobs in the `runtime`
namespace. Stream sessions pin their parent `Pipeline` (the
`session-parent` accessor), so a pipeline stays reachable while a
session on it is live; unreachable un-closed handles are reclaimed
by the Java layer's `Cleaner` backstop.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go jdk17-openjdk clojure gcc
```

Generic Linux: a Go toolchain, JDK 17+, the Clojure CLI (`clojure`
/ `clj`), and gcc (for the Java binding's JNI shim). The Java
binding's Gradle wrapper pins its build; `deps.edn` pins Clojure
1.12.5 and resolves it through the CLI.

## Build

The convenience driver builds the whole stack — `libitb.so`, the
Java binding (JNI shim + jars), then prepares the Clojure classpath
and compile-checks every namespace with reflection warnings treated
as errors:

```bash
./bindings/clojure/build.sh
```

Equivalent manual invocation:

```bash
./bindings/java/build.sh
cd bindings/clojure && clojure -Sforce -P -M:test:bench:eitb
```

## Library lookup order

Native resolution happens entirely in the Java layer:

1. `ITB_JNI_PATH` environment variable (path to `libitb_jni.so`);
   the driver scripts default it to the sibling Java build's
   output.
2. `System.loadLibrary("itb_jni")` over `java.library.path`.

`libitb.so` itself is found through the shim's RPATH (the
repository dist directory) or the OS loader path.

## Usage example

```clojure
(require '[dev.everanium.itb.clojure.core :as itb])

(with-open [sender (itb/init "singlemsg-triple-mac-v1")]
  (with-open [receiver (itb/open "singlemsg-triple-mac-v1" (itb/blob sender))]
    (let [wire (itb/encrypt-message sender (.getBytes "any text or binary data"))
          plain (itb/decrypt-message receiver wire)]
      ...)))
```

Opts are plain keyword maps overriding the profile default per call
(see the `opts` namespace docstring for the roster; `:raw` passes
any `key=value` pair through verbatim, including the
register-profile grammar):

```clojure
(let [opts {:chunk-size 65536 :wrapper? false}]
  (with-open [sender (itb/init "singlemsg-triple-mac-v1" opts)]
    (with-open [receiver (itb/open "singlemsg-triple-mac-v1" (itb/blob sender) opts)]
      ...)))
```

`rekey!` rotates the parallax + wrapper masters mid-session (the
eight ITB seeds and MAC key are fixed for the session lifetime by
design); the receiver picks up the new masters through a fresh
`(itb/blob sender)` handshake:

```clojure
(itb/rekey! sender (byte-array 32 (repeat 0x11)) (byte-array 32 (repeat 0x22)))
(with-open [receiver (itb/open "singlemsg-triple-mac-v1" (itb/blob sender))]
  ...)
```

For bounded-memory streaming, `encrypt-stream-pump` /
`decrypt-stream-pump` move any `java.io.InputStream` source into
any `java.io.OutputStream` sink through an incremental session; the
explicit `encrypt-stream` / `decrypt-stream` sessions expose the
`Session` protocol (`write!` / `end!` / `read!` / `finished?`) plus
`copy-to!` for caller-driven loops, and close under `with-open`
like a pipeline.

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string surfaces as an ex-info whose data
map carries the status keyword:

```clojure
(require '[dev.everanium.itb.clojure.error :as err])

(try
  (itb/decrypt-message receiver wire)
  (catch clojure.lang.ExceptionInfo e
    (when-not (= :mac-failure (err/error-status e))
      (throw e))
    (byte-array 0)))
```

The data map is `{:type ::err/itb, :status <keyword>, :code <raw
ABI code>}` — `:code` stays attributable even when `:status` is
`:unknown` (a future libitb release).

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable
at libitb load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass `-1` to query without
changing:

```clojure
(require '[dev.everanium.itb.clojure.runtime :as runtime])

(runtime/set-memory-limit! (bit-shift-left 512 20))
(runtime/set-gc-percent! 20)
```

## Testing

```bash
./bindings/clojure/run_tests.sh
```

The harness builds the full stack and invokes the clojure.test
suite (arguments narrow the run, e.g. `./run_tests.sh smoke-test`).
The suite covers Single Message round trips across every shipped
cipher profile, stream pumps, incremental sessions with
pathological batch sizes, tampered-wire failure stickiness,
mid-flight cancellation, rekey, profile registration, and error
mapping — surface parity checks; the deep suite lives in Go under
the shipped tree.

## Benchmarking

```bash
./bindings/clojure/run_bench.sh            # both shapes
./bindings/clojure/run_bench.sh message    # Single Message shape only
./bindings/clojure/run_bench.sh stream     # stream-pump shape only
```

Wall-clock micro-benches: `encrypt-message` and stream-pump
throughput at 1 MiB / 16 MiB / 64 MiB. Shape and budget are driven
by the `ITB_*` env vars listed in `bench/.../bench_util.clj`;
defaults match the root Go BENCH3.md pin.

## eitb utility

The launcher mirrors the shipped Go `tools/eitb` scope for shell
smoke tests:

```bash
cd bindings/clojure
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
  diagnostic attached to an error may belong to a different call
  under concurrent use. The status code is always attributable.
- `rekey!` must not run concurrently with cipher calls or open
  stream sessions on the same `Pipeline`.
- The sibling Java binding must be built first (its jars and JNI
  shim are this binding's runtime); `build.sh` handles the
  ordering, and `deps.edn` resolves the jars by relative path — the
  classpath is computed after the Java build exists.
