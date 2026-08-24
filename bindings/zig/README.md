# ITB Zig Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin Zig proxy over the ITB C binding (`bindings/c`), which in turn
wraps the libitb shared library's `ITB_Triple_*` surface
(`cmd/cshared`). The binding `@cImport`s the C binding's public
`itb.h` and **links `libitb_c.a` + `libitb.so` at compile time** (an
absolute RPATH into `dist/` is embedded) — no runtime symbol loading.
Every hash-name / MAC-name / cipher-name / profile-name is an opaque
string passed through to Go for validation; the binding carries no
ITB construction logic, and buffer sizing plus the BufferTooSmall
retry-once dance live in the C layer. The public surface is an
allocator-parametric `Pipeline` (init / open / rekey / deinit, Single
Message encrypt / decrypt, whole-buffer stream pumps, incremental
`EncryptStream` / `DecryptStream` sessions with write / end / read /
drainAll), an `Opts` query-string builder, `registerProfile`, a Zig
`error{...}` set mirroring the C status codes, and the Go runtime
knobs.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go gcc make zig
```

Generic Linux: a Go toolchain, a C11 compiler, GNU make, and Zig
0.16+ (the build uses the current `std.Build` module API).

## Build

The convenience driver builds `libitb.so`, the C binding static
archive, and the Zig binaries (eitb + benches) in one step:

```bash
./bindings/zig/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
make -C bindings/c build/libitb_c.a
cd bindings/zig && zig build
```

## Add to a Zig project

`build.zig` exposes the library as a named module `itb`; from another
project, create the module against `src/itb.zig` with the C include
path, the `libitb_c.a` object, and the `-litb` link input attached:

```zig
const itb_mod = b.createModule(.{
    .root_source_file = b.path("path/to/bindings/zig/src/itb.zig"),
    .target = target,
    .optimize = optimize,
    .link_libc = true,
});
itb_mod.addIncludePath(b.path("path/to/bindings/c/include"));
itb_mod.addObjectFile(b.path("path/to/bindings/c/build/libitb_c.a"));
itb_mod.addLibraryPath(dist); // dist/linux-amd64 with libitb.so
itb_mod.addRPath(dist);       // absolute, so binaries run anywhere
itb_mod.linkSystemLibrary("itb", .{});
exe.root_module.addImport("itb", itb_mod);
```

## Usage example

```zig
const itb = @import("itb");

var sender = try itb.Pipeline.init(allocator, "singlemsg-triple-mac-v1", null);
defer sender.deinit();

var receiver = try itb.Pipeline.open(
    allocator, "singlemsg-triple-mac-v1", sender.blob(), null, null);
defer receiver.deinit();

const wire = try sender.encryptMessage("data");
defer allocator.free(wire);

const plain = try receiver.decryptMessage(wire);
defer allocator.free(plain);
```

`Opts` overrides the profile default per call (chunk size, outer
cipher, parallax on/off, wrapper on/off, MAC name, palette); every
setter goes through `set(key, value)`:

```zig
var opts = try itb.Opts.init();
defer opts.deinit();
try opts.set("chunkSize", "65536");
try opts.set("withWrapper", "false");
var sender = try itb.Pipeline.init(allocator, "singlemsg-triple-mac-v1", opts);
var receiver = try itb.Pipeline.open(
    allocator, "singlemsg-triple-mac-v1", sender.blob(), opts, null);
```

`Pipeline.rekey` rotates the parallax + wrapper masters mid-session
(the eight ITB seeds and MAC key are fixed for the session lifetime
by design); the receiver picks up the new masters through a fresh
`sender.blob()` handshake:

```zig
try sender.rekey(&[_]u8{0x11} ** 32, &[_]u8{0x22} ** 32);
var receiver2 = try itb.Pipeline.open(
    allocator, "singlemsg-triple-mac-v1", sender.blob(), null, null);
```

Every cipher output is allocated from the `Allocator` handed to
`Pipeline.init` / `Pipeline.open` and owned by the caller — release
with `allocator.free`. For bounded-memory streaming,
`encryptStreamPump` / `decryptStreamPump` move a whole buffer through
an incremental session; the explicit `encryptStream` /
`decryptStream` sessions expose `write` / `end` / `read` /
`drainAll` for caller-driven loops. A session holds a `parent`
pointer to its Pipeline and must be deinited before it.

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string surfaces as a Zig error (for example
`error.BadInput`) with the diagnostic available via
`itb.lastError()`.

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable at
libitb load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass `-1` to query without
changing. Long-running or allocation-heavy workloads (benchmarks,
bulk encryption) should set both — without a soft cap + aggressive GC
the Go scratch heap grows unboundedly under allocation churn:

```zig
_ = itb.setMemoryLimit(512 << 20); // 512 MiB soft cap
_ = itb.setGcPercent(20);          // aggressive GC
```

## Testing

```bash
./bindings/zig/run_tests.sh
```

The harness builds the prerequisites, compiles every `tests/*.zig` to
its own test binary, and runs them sequentially as separate
processes; per-process isolation gives every test file a fresh libitb
global state, and `std.testing.allocator` leak-checks every
allocator-owned buffer. The suite covers Single Message round trips
per shipped profile (empty plaintext included), stream pumps,
incremental sessions with pathological batch sizes, tampered-wire
failure stickiness, mid-flight cancellation, rekey, profile
registration, opts-builder encoding, and error mapping — surface
parity checks; the deep suite lives in Go under the shipped tree.

## Benchmarking

```bash
./bindings/zig/run_bench.sh
```

Micro-benches (always ReleaseFast): `message` (encryptMessage) and
`stream_pump` (encrypt stream pump) throughput at 1 MiB / 16 MiB /
64 MiB, reported as an MB/s table on stdout. The runner exports
`ITB_GOMEMLIMIT=512MiB` + `ITB_GOGC=20` defaults plus the canonical
bench-shape env vars (`ITB_NONCE_BITS` / `ITB_KEY_BITS` /
`ITB_WITH_PARALLAX` / `ITB_WITH_WRAPPER` / `ITB_INNER_HASH` /
`ITB_PROFILE` / `ITB_BENCH_MIN_SEC`), respecting caller overrides;
the bench binaries apply the same heap caps programmatically.

## eitb utility

A small CLI under `bindings/zig/eitb/` mirrors the shipped Go
`tools/eitb` scope for shell smoke tests:

```bash
cd bindings/zig && zig build
./zig-out/bin/eitb version
./zig-out/bin/eitb hashes
./zig-out/bin/eitb encrypt singlemsg-triple-mac-v1 in.bin out.bin   # blob hex on stderr
./zig-out/bin/eitb decrypt singlemsg-triple-mac-v1 <blob-hex> out.bin back.bin
```

The blob-hex argument to `decrypt` is parsed tolerantly:
case-insensitive, optional `0x` prefix, embedded whitespace accepted.

## Limitations

- The binding wraps the Triple Pipeline surface only. The Low-Level
  seed / MAC / blob / wrapper / parallax APIs are not exposed — use
  the shipped Go core for those.
- Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication.
- The `itb.lastError()` text is process-global last-write-wins on
  the Go side; fetch it immediately after the failing call. The
  error value is always attributable.
- The wrapper adds no synchronisation of its own: concurrent cipher
  calls on one Pipeline are safe (the Go side serialises what needs
  serialising), but `rekey` and `deinit` must not run concurrently
  with cipher calls or open stream sessions on the same Pipeline.
- Handles are released exactly once (`Pipeline.deinit` /
  session `deinit`); a stream session must not outlive its Pipeline.
