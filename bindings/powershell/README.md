# ITB PowerShell Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the C# binding ([`../csharp/`](../csharp/)) — plain
CLR interop via `Add-Type`, no FFI hop of its own; the C# `Itb.dll`
assembly carries the source-generated P/Invoke surface over the
libitb `ITB_Triple_*` C ABI, including the BUFFER_TOO_SMALL
retry-once path and the native-library resolver. Every hash-name /
MAC-name / cipher-name / profile-name is an opaque string passed
through to Go for validation; the binding carries no ITB
construction logic.

The public surface is a Verb-Noun cmdlet set over the C# `Pipeline`
type: `New-ItbPipeline` / `Open-ItbPipeline` / `Get-ItbBlob` /
`Invoke-ItbRekey` / `Register-ItbProfile` / `Close-ItbPipeline` for
the lifecycle, `Invoke-ItbEncrypt` / `Invoke-ItbDecrypt` for Single
Message, `Invoke-ItbEncryptStream` / `Invoke-ItbDecryptStream`
(one-shot bytes, file-to-file, or stream-to-stream pumps) and
`New-ItbEncryptStream` / `New-ItbDecryptStream` (caller-driven
incremental sessions) for streaming, `New-ItbOpts` for the opts
pass-through, and `Get-ItbVersion` / `Set-ItbMemoryLimit` /
`Set-ItbGCPercent` for diagnostics and the Go runtime knobs. The
underlying CLR objects (`[Itb.Pipeline]`, `[Itb.Opts]`, session
types) are returned as-is, so direct method calls
(`$pipeline.EncryptMessage($bytes)`, `$session.Write($bytes)`)
remain available alongside the cmdlets. Errors surface as
`[Itb.ItbException]` (unwrapped from PowerShell's method-invocation
wrapper) carrying the structural `Status` code plus the
`ITB_LastError` diagnostic — catch with `try` / `catch
[Itb.ItbException]` and inspect `$_.Exception.Status`.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go dotnet-sdk
paru -S powershell-bin        # pwsh 7.4+ (AUR)
pwsh -Command 'Install-Module Pester -Scope CurrentUser -Force'   # tests only
```

Generic Linux / macOS: a Go toolchain, the .NET SDK (net10.0 target
framework, for the C# peer), and PowerShell 7.4+. Windows: the same;
libitb builds as `libitb.dll`.

## Build

The binding itself is a script module with no compilation step. The
convenience driver builds the C# peer (libitb.so + `Itb.dll` via
`../csharp/build.sh`) and verifies the module imports cleanly:

```bash
./bindings/powershell/build.sh
```

## Assembly and library lookup order

The C# `Itb.dll` assembly is located at module import time:

1. `ITB_CSHARP_DLL` environment variable (path to `Itb.dll`).
2. The sibling C# binding's `bin/Release` then `bin/Debug` output,
   relative to the module (in-repo builds).

Native libitb resolution is inherited from the C# binding's
resolver: `ITB_LIBITB_PATH`, then `<repo>/dist/<os>-<arch>/` located
by walking up from the assembly directory, then the OS default
loader path.

## Usage example

```powershell
Import-Module ./bindings/powershell/Itb/Itb.psd1

$sender   = New-ItbPipeline -Profile 'singlemsg-triple-mac-v1'
$receiver = Open-ItbPipeline -Profile 'singlemsg-triple-mac-v1' `
    -Blob (Get-ItbBlob $sender)

$wire  = Invoke-ItbEncrypt -Pipeline $sender -Data 'any text or binary data'
$plain = Invoke-ItbDecrypt -Pipeline $receiver -Data $wire
[System.Text.Encoding]::UTF8.GetString($plain)

Close-ItbPipeline $sender
Close-ItbPipeline $receiver
```

Opts override the profile default per call (chunk size, outer
cipher, parallax on/off, wrapper on/off, MAC name, palette) as a
hashtable passed to `-Opts`:

```powershell
$opts = @{ chunkSize = 65536; withWrapper = $false }
$sender   = New-ItbPipeline -Profile 'singlemsg-triple-mac-v1' -Opts $opts
$receiver = Open-ItbPipeline -Profile 'singlemsg-triple-mac-v1' `
    -Blob (Get-ItbBlob $sender) -Opts $opts
```

`Invoke-ItbRekey` rotates the parallax + wrapper masters mid-session
(the eight ITB seeds and MAC key are fixed for the session lifetime
by design); the receiver picks up the new masters through a fresh
`Get-ItbBlob` handshake:

```powershell
$perm = [byte[]]::new(32); $wrap = [byte[]]::new(32)
Invoke-ItbRekey -Pipeline $sender -PermMaster $perm -WrapMaster $wrap
$receiver = Open-ItbPipeline -Profile 'singlemsg-triple-mac-v1' `
    -Blob (Get-ItbBlob $sender)
```

For bounded-memory streaming, the pump shapes move a file or any
`System.IO.Stream` source into a sink through an incremental
session:

```powershell
Invoke-ItbEncryptStream -Pipeline $sender -InFile big.bin -OutFile big.itb
Invoke-ItbDecryptStream -Pipeline $receiver -InFile big.itb -OutFile back.bin
```

The explicit `New-ItbEncryptStream` / `New-ItbDecryptStream`
sessions expose `Write` / `End` / `Read` for caller-driven loops;
`Read` takes a `[ref]` finished flag:

```powershell
$session = New-ItbEncryptStream -Pipeline $sender
$session.Write($bytes)
$session.End()
$buf = [byte[]]::new(65536)
$finished = $false
while (-not $finished) {
    $n = $session.Read($buf, [ref]$finished)
    # consume $buf[0..($n-1)]
}
$session.Dispose()
```

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string surfaces as `[Itb.ItbException]`
carrying the `Status` code plus the `ITB_LastError` diagnostic.
Opts are passed as hashtables (rendered pair-wise into the
URL-query opts string: booleans as `true` / `false`, byte arrays as
lowercase hex, arrays comma-joined) or as a prebuilt `[Itb.Opts]`:

```powershell
$pipe = New-ItbPipeline -Profile 'streaming-aead-triple-mac-v1' `
    -Opts @{ chunkSize = 65536; innerHash = 'blake3' }
```

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable
at libitb load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass a negative value to
query without changing:

```powershell
Set-ItbMemoryLimit -Bytes 512MB
Set-ItbGCPercent -Percent 20
```

## Testing

```bash
./bindings/powershell/run_tests.sh
```

The harness builds the C# peer, exports `ITB_LIBITB_PATH`, and
invokes Pester over `Tests/Itb.Tests`. Positional arguments narrow
the run to matching test files (e.g. `./run_tests.sh Smoke`). The
suite covers Single Message round trips per shipped profile, stream
pumps (file and stream shapes), incremental sessions with
pathological batch sizes, tampered-wire failure stickiness,
mid-flight cancellation, rekey, profile registration, error mapping,
and opts rendering — surface parity checks; the deep suite lives in
Go under the shipped tree.

## Benchmarking

```bash
./bindings/powershell/run_bench.sh            # both shapes
./bindings/powershell/run_bench.sh message    # Single Message shape only
./bindings/powershell/run_bench.sh stream     # stream-pump shape only
```

`Stopwatch`-timed micro-benches: `EncryptMessage` and stream-pump
throughput at 1 MiB / 16 MiB / 64 MiB. Shape and budget are driven
by the `ITB_*` env vars listed in `Bench/BenchUtil.ps1`; defaults
match the root Go BENCH3.md pin. The cipher work runs on the .NET /
Go side, so PowerShell adds one scriptblock hop per whole-payload
iteration — negligible at MiB scale.

## eitb utility

The `eitb/eitb.ps1` script mirrors the shipped Go `tools/eitb` scope
for shell smoke tests:

```bash
cd bindings/powershell/eitb
./eitb.ps1 version
./eitb.ps1 hashes
./eitb.ps1 encrypt singlemsg-triple-mac-v1 in.bin out.bin  # blob hex on stderr
./eitb.ps1 decrypt singlemsg-triple-mac-v1 <blob-hex> out.bin back.bin
```

## Limitations

- The binding wraps the Triple Pipeline surface only. The Low-Level
  seed / MAC / blob / wrapper / parallax APIs are not exposed — use
  the shipped Go core for those.
- PowerShell cannot hold ByRef-like values (`ReadOnlySpan` /
  `Span`), so the C# `Pipeline.Blob` property is unreadable from
  script — `Get-ItbBlob` bridges it (reflection over the backing
  array, defensive copy). Passing `byte[]` arguments into
  span-typed parameters is handled by the PowerShell binder.
- Cipher cmdlets return `byte[]` as a single pipeline item
  (`Write-Output -NoEnumerate`); when piping a byte array INTO a
  cmdlet, prefix with a comma (`,$wire | Invoke-ItbDecrypt ...`) or
  pass it via `-Data` — an unwrapped array is accumulated
  element-wise, which is correct but slow for large payloads.
- Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication.
- `ITB_LastError` is process-global last-write-wins; the textual
  diagnostic attached to an `ItbException` may belong to a different
  call under concurrent use. The status code is always attributable.
- `Invoke-ItbRekey` must not run concurrently with cipher calls or
  open stream sessions on the same Pipeline.
- `Itb.dll` and libitb must be reachable at runtime through the
  lookup order above.
