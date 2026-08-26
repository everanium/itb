# ITB VB.NET Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the sibling [C# binding](../csharp/) — plain CLR
bytecode interop against the `Itb.dll` assembly, no FFI layer of its
own. The C# binding carries the source-generated P/Invoke surface,
the libitb lookup order, the SafeHandle lifetime (finalizer
backstop), and the buffer pre-allocation with the BufferTooSmall
retry-once; this layer re-shapes that surface into idiomatic VB.NET:
`Using` blocks over `IDisposable` types, structured
`Try ... Catch ex As ItbException` error handling with the binding's
own `Status` enum, `Byte()` signatures throughout, and chaining
`Opts` setters. Every hash-name / MAC-name / cipher-name /
profile-name remains an opaque string passed through to Go for
validation; no ITB construction logic lives on the .NET side.

The public surface is one `Pipeline` type (Init / Open / Rekey /
Close, Single Message encrypt / decrypt, one-shot and incremental
stream sessions with `System.IO.Stream` pumps), an `Opts` builder,
`Pipeline.RegisterProfile`, and the Go runtime knobs on `Library`.
Stream sessions pin their parent `Pipeline` (the `Parent` property),
so a pipeline stays reachable while a session on it is live;
unreachable un-disposed handles are reclaimed by the C# layer's
SafeHandle finalizer.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go dotnet-sdk
```

Generic Linux / macOS: a Go toolchain plus the .NET SDK (net10.0
target framework; Visual Basic ships with the SDK). Windows: the
same; libitb builds as `libitb.dll`.

## Build

The convenience driver builds `libitb.so` plus the solution (the
ProjectReference chain pulls the sibling C# binding library in
automatically):

```bash
./bindings/vbnet/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
cd bindings/vbnet && dotnet build EveraniumItb.VisualBasic.sln -c Release
```

## Library lookup order

Native resolution happens entirely in the C# layer:

1. `ITB_LIBITB_PATH` environment variable (path to the shared
   library file).
2. `<repo>/dist/<os>-<arch>/libitb.<ext>` located by walking up from
   the assembly directory (in-repo builds).
3. The OS default loader path (`LD_LIBRARY_PATH`, `ld.so.cache`,
   `DYLD_LIBRARY_PATH`, `PATH`).

## Usage example

```vb
Imports Everanium.Itb.VisualBasic

Using sender As Pipeline = Pipeline.Init("singlemsg-triple-mac-v1")
    Using receiver As Pipeline = Pipeline.Open("singlemsg-triple-mac-v1", sender.Blob)
        Dim wire As Byte() = sender.EncryptMessage(
            Text.Encoding.UTF8.GetBytes("any text or binary data"))
        Dim plain As Byte() = receiver.DecryptMessage(wire)
    End Using
End Using
```

The `Opts` builder overrides the profile default per call (chunk
size, outer cipher, parallax on/off, wrapper on/off, MAC name,
palette):

```vb
Dim opts As Opts = New Opts().WithChunkSize(65536).WithWrapper(False)
Using sender As Pipeline = Pipeline.Init("singlemsg-triple-mac-v1", opts)
    Using receiver As Pipeline = Pipeline.Open("singlemsg-triple-mac-v1", sender.Blob, opts)
        ' ...
    End Using
End Using
```

`Pipeline.Rekey` rotates the parallax + wrapper masters mid-session
(the eight ITB seeds and MAC key are fixed for the session lifetime
by design); the receiver picks up the new masters through a fresh
`sender.Blob` handshake:

```vb
Dim perm(31) As Byte : Array.Fill(perm, CByte(&H11))
Dim wrap(31) As Byte : Array.Fill(wrap, CByte(&H22))
sender.Rekey(perm, wrap)
Using receiver As Pipeline = Pipeline.Open("singlemsg-triple-mac-v1", sender.Blob)
End Using
```

For bounded-memory streaming, `EncryptStreamPump` /
`DecryptStreamPump` move any `System.IO.Stream` source into any
`System.IO.Stream` sink through an incremental session; the explicit
`BeginEncryptStream` / `BeginDecryptStream` sessions expose `Write`
/ `End` / `Read` for caller-driven loops.

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string surfaces as `ItbException` carrying
the `Status` code plus the `ITB_LastError` diagnostic:

```vb
Try
    Using pipe As Pipeline = Pipeline.Init("no-such-profile")
    End Using
Catch ex As ItbException
    Console.Error.WriteLine($"{ex.Status}: {ex.Message}")
End Try
```

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable
at libitb load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass `-1` to query without
changing:

```vb
Library.SetMemoryLimit(512L * 1024 * 1024)
Library.SetGCPercent(20)
```

## Testing

```bash
./bindings/vbnet/run_tests.sh
```

The harness builds `libitb.so`, exports `ITB_LIBITB_PATH`, and
invokes `dotnet test -c Release`. Positional arguments are forwarded
to dotnet test (e.g. `./run_tests.sh --filter
FullyQualifiedName~Smoke`). The suite covers Single Message round
trips per shipped profile, stream pumps, incremental sessions with
pathological batch sizes, tampered-wire failure stickiness,
mid-flight cancellation, rekey, profile registration, error mapping,
and Opts query rendering — surface parity checks; the deep suite
lives in Go under the shipped tree.

## Benchmarking

```bash
./bindings/vbnet/run_bench.sh            # both shapes
./bindings/vbnet/run_bench.sh message    # Single Message shape only
./bindings/vbnet/run_bench.sh stream     # stream-pump shape only
```

`Stopwatch`-timed micro-benches: `EncryptMessage` and stream-pump
throughput at 1 MiB / 16 MiB / 64 MiB. Shape and budget are driven
by the `ITB_*` env vars listed in
`bench/EveraniumItb.VisualBasic.Bench/BenchUtil.vb`; defaults match
the root Go BENCH3.md pin.

## eitb utility

The `EveraniumItb.VisualBasic.Eitb` console project mirrors the
shipped Go `tools/eitb` scope for shell smoke tests:

```bash
cd bindings/vbnet
dotnet run -c Release --project eitb/EveraniumItb.VisualBasic.Eitb -- version
dotnet run -c Release --project eitb/EveraniumItb.VisualBasic.Eitb -- hashes
dotnet run -c Release --project eitb/EveraniumItb.VisualBasic.Eitb -- encrypt singlemsg-triple-mac-v1 in.bin out.bin  # blob hex on stderr
dotnet run -c Release --project eitb/EveraniumItb.VisualBasic.Eitb -- decrypt singlemsg-triple-mac-v1 <blob-hex> out.bin back.bin
```

The `hashes` diagnostic iterates the registry through the C#
layer's internal relay (InternalsVisibleTo) — the binding library
itself deliberately exposes no primitive enumeration.

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
- `Rekey` must not run concurrently with cipher calls or open stream
  sessions on the same `Pipeline`.
- `Pipeline.Blob` returns a fresh copy on each access (the C# layer
  exposes a span; Visual Basic consumes it as `Byte()`).
- The sibling C# binding source (`bindings/csharp/Itb`) must be
  present — the solution builds it via ProjectReference — and libitb
  must be reachable at runtime through the lookup order above.
