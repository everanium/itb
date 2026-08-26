# ITB F# Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin idiomatic layer over the C# binding ([`../csharp/`](../csharp/))
— plain CLR bytecode interop, no FFI hop of its own; the C# binding
carries the source-generated P/Invoke over the libitb `ITB_Triple_*`
surface plus the buffer-sizing retry and the SafeHandle lifetime.
Every hash-name / MAC-name / cipher-name / profile-name is an opaque
string passed through to Go for validation; the binding carries no
ITB construction logic.

The public surface wraps the C# `Pipeline` / `Opts` in F# idiom:
every fallible call returns `Result<_, ItbError>`, `Status` is a
discriminated union (unnamed codes surface as `Unknown` with the raw
code preserved), `Opts` is an immutable pipeable value, and
`Pipeline` / stream `Session` values are `IDisposable` for `use` /
`use!` bindings. The `itb { }` computation expression composes a
whole encrypt / decrypt flow as straight-line code with `let!` /
`use!` short-circuiting into the error channel; the stream sessions
additionally expose a lazy `seq<byte[]> -> seq<byte[]>` `transform`
chunk adapter. Callers preferring exceptions unwrap with
`ItbError.get`, which raises `ItbFailure` carrying the same error
value.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go dotnet-sdk
```

Generic Linux / macOS: a Go toolchain plus the .NET SDK (net10.0
target framework; F# ships with the SDK). Windows: the same; libitb
builds as `libitb.dll`.

## Build

The convenience driver builds `libitb.so` plus the solution (the C#
`Itb` library project is a solution member, so one dotnet build
covers both layers):

```bash
./bindings/fsharp/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
cd bindings/fsharp && dotnet build EveraniumItb.FSharp.sln -c Release
```

## Library lookup order

Native resolution is inherited from the C# binding:

1. `ITB_LIBITB_PATH` environment variable (path to the shared
   library file).
2. `<repo>/dist/<os>-<arch>/libitb.<ext>` located by walking up from
   the assembly directory (in-repo builds).
3. The OS default loader path (`LD_LIBRARY_PATH`, `ld.so.cache`,
   `DYLD_LIBRARY_PATH`, `PATH`).

## Usage example

```fsharp
open EveraniumItb.FSharp

let result =
    itb {
        use! sender = Pipeline.init "singlemsg-triple-mac-v1" Opts.empty
        use! receiver =
            Pipeline.openBlob "singlemsg-triple-mac-v1" (Pipeline.blob sender) Opts.empty
        let! wire = Pipeline.encryptMessage sender "any text or binary data"B
        let! plain = Pipeline.decryptMessage receiver wire
        return plain
    }
```

`Opts` overrides the profile default per call (chunk size, outer
cipher, parallax on/off, wrapper on/off, MAC name, palette); values
compose through the pipeline operator:

```fsharp
let opts =
    Opts.empty
    |> Opts.withChunkSize 65536L
    |> Opts.withWrapper false
let result =
    itb {
        use! sender = Pipeline.init "singlemsg-triple-mac-v1" opts
        use! receiver =
            Pipeline.openBlob "singlemsg-triple-mac-v1" (Pipeline.blob sender) opts
        return ()
    }
```

`Pipeline.rekey` rotates the parallax + wrapper masters mid-session
(the eight ITB seeds and MAC key are fixed for the session lifetime
by design); the receiver picks up the new masters through a fresh
`Pipeline.blob sender` handshake:

```fsharp
Pipeline.rekey sender (Array.create 32 0x11uy) (Array.create 32 0x22uy) |> ItbError.get
use receiver2 =
    Pipeline.openBlob "singlemsg-triple-mac-v1" (Pipeline.blob sender) Opts.empty
    |> ItbError.get
```

For bounded-memory streaming, `Stream.pumpEncrypt` /
`Stream.pumpDecrypt` move any `System.IO.Stream` source into any
`System.IO.Stream` sink through an incremental session. The explicit
`Stream.beginEncrypt` / `Stream.beginDecrypt` sessions expose
`write` / `finish` / `read` for caller-driven loops plus the lazy
`transform` chunk adapter:

```fsharp
use session = ItbError.get (Stream.beginEncrypt pipe)
let wireChunks: seq<byte[]> = Stream.transform session plaintextChunks
wireChunks |> Seq.iter sink
```

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string surfaces as an `Error (ItbError ...)`
carrying the [`Status`](src/EveraniumItb.FSharp/Status.fs) case plus
the `ITB_LastError` diagnostic.

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable
at libitb load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass `-1` to query without
changing:

```fsharp
Runtime.setMemoryLimit (512L * 1024L * 1024L) |> ignore
Runtime.setGCPercent 20 |> ignore
```

## Testing

```bash
./bindings/fsharp/run_tests.sh
```

The harness builds `libitb.so`, exports `ITB_LIBITB_PATH`, and
invokes `dotnet test -c Release` (xUnit). Positional arguments are
forwarded to dotnet test (e.g. `./run_tests.sh --filter
FullyQualifiedName~Smoke`). The suite covers Single Message round
trips per shipped profile, stream pumps and the transform adapter,
incremental sessions with pathological batch sizes, tampered-wire
failure stickiness, mid-flight cancellation, rekey, profile
registration, error / Status mapping, and Opts pair accumulation —
surface parity checks; the deep suite lives in Go under the shipped
tree.

## Benchmarking

```bash
./bindings/fsharp/run_bench.sh            # both shapes
./bindings/fsharp/run_bench.sh message    # Single Message shape only
./bindings/fsharp/run_bench.sh stream     # stream-pump shape only
```

`Stopwatch`-timed micro-benches: `encryptMessage` and stream-pump
throughput at 1 MiB / 16 MiB / 64 MiB. Shape and budget are driven
by the `ITB_*` env vars listed in
`bench/EveraniumItb.FSharp.Bench/BenchUtil.fs`; defaults match the
root Go BENCH3.md pin.

## eitb utility

The `EveraniumItb.FSharp.Eitb` console project mirrors the shipped
Go `tools/eitb` scope for shell smoke tests:

```bash
cd bindings/fsharp
dotnet run -c Release --project eitb/EveraniumItb.FSharp.Eitb -- version
dotnet run -c Release --project eitb/EveraniumItb.FSharp.Eitb -- hashes
dotnet run -c Release --project eitb/EveraniumItb.FSharp.Eitb -- encrypt singlemsg-triple-mac-v1 in.bin out.bin  # blob hex on stderr
dotnet run -c Release --project eitb/EveraniumItb.FSharp.Eitb -- decrypt singlemsg-triple-mac-v1 <blob-hex> out.bin back.bin
```

The `hashes` diagnostic iterates the registry through the eitb
project's own P/Invoke triple (the C# binding's diagnostic surface
is internal to its own assemblies) — the binding library itself
deliberately exposes no primitive enumeration.

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
- The `transform` adapter is single-pass: traverse the returned
  sequence at most once and do not interleave it with direct
  `write` / `read` calls on the same session.
- The C# binding (and through it libitb) must be built and reachable
  per the lookup order above.
