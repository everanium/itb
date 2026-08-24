# ITB LFE Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the ITB Erlang binding's Triple Pipeline surface
(`bindings/erlang`) via **native BEAM bytecode interop** — the LFE
layer calls the Erlang `itb` module directly and adds no FFI hop of
its own. The only native code in the stack is the Erlang binding's
NIF shim, consumed here as a rebar3 checkout dependency (the
committed `_checkouts/itb` symlink). Every hash-name / MAC-name /
cipher-name / profile-name is an opaque string passed through to Go
for validation; the binding carries no ITB construction logic.

The public surface is the `itb-lfe` module (`init` / `open` /
`rekey` / `free`, Single Message encrypt / decrypt, incremental
stream sessions with `stream-write` / `stream-end` / `stream-read`),
`register-profile`, and the Go runtime knobs — the Erlang surface
under LFE-idiomatic kebab-case names. The module is named `itb-lfe`
rather than `itb` because the Erlang binding's `itb` module shares
the code path; a same-named module would collide on load. Handles
are opaque NIF resources; the cipher entries run on dirty CPU
schedulers so multi-megabyte calls never stall the regular BEAM
schedulers.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go gcc make erlang rebar3
```

Generic Linux: a Go toolchain, a C11 compiler, GNU make, Erlang/OTP
27+, and rebar3. The LFE compiler is **not** a system prerequisite —
it arrives as the `lfe` hex dependency and the `rebar3_lfe` plugin
drives it. macOS: the same via Homebrew; libitb builds as
`libitb.dylib`.

## Build the shared library

The convenience driver builds `libitb.so`, the C binding's static
archive, the Erlang backend (NIF shim included), and the rebar3
project in one step:

```bash
./bindings/lfe/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
make -C bindings/c build/libitb_c.a
cd bindings/lfe && rebar3 compile
```

## Add to an LFE project

The binding is a standard rebar3 + `rebar3_lfe` project that pulls
the Erlang binding through the `_checkouts/itb` symlink. From
another rebar3 project, consume both the same way — symlink
`bindings/erlang` as `_checkouts/itb` and `bindings/lfe` as
`_checkouts/itb_lfe`, and declare bare `itb` / `itb_lfe` deps.

The compiled NIF (`bindings/erlang/priv/itb_nif.so`) resolves
`libitb.so` through its embedded RPATH into the repo `dist/`
directory, so no `LD_LIBRARY_PATH` is needed at runtime.

## Usage example

```lisp
(let* ((`#(ok ,sender) (itb-lfe:init #"singlemsg-triple-mac-v1"))
       (`#(ok ,blob) (itb-lfe:blob sender))
       (`#(ok ,receiver) (itb-lfe:open #"singlemsg-triple-mac-v1" blob))
       (`#(ok ,wire) (itb-lfe:encrypt-message sender
                                              #"any text or binary data"))
       (`#(ok ,plain) (itb-lfe:decrypt-message receiver wire)))
  (itb-lfe:free receiver)
  (itb-lfe:free sender)
  plain)
```

Opts override the profile default per call (chunk size, outer
cipher, parallax on/off, wrapper on/off, MAC name, palette) as a
map passed to `init/2` / `open/3`:

```lisp
(let* ((opts (map #"chunkSize" 65536 #"withWrapper" 'false))
       (`#(ok ,sender) (itb-lfe:init #"singlemsg-triple-mac-v1" opts))
       (`#(ok ,blob) (itb-lfe:blob sender))
       (`#(ok ,receiver) (itb-lfe:open #"singlemsg-triple-mac-v1" blob opts)))
  ...)
```

`rekey/3` rotates the parallax + wrapper masters mid-session (the
eight ITB seeds and MAC key are fixed for the session lifetime by
design); the receiver picks up the new masters through a fresh
`(itb-lfe:blob sender)` handshake:

```lisp
(itb-lfe:rekey sender (binary:copy #b(#x11) 32) (binary:copy #b(#x22) 32))
(let ((`#(ok ,blob2) (itb-lfe:blob sender)))
  (itb-lfe:open #"singlemsg-triple-mac-v1" blob2))
```

### Caller-driven stream sessions

```lisp
(let ((`#(ok ,session) (itb-lfe:encrypt-stream sender)))
  (itb-lfe:stream-write session chunk1)
  (itb-lfe:stream-write session chunk2)
  (itb-lfe:stream-end session)
  ;; Drain until #(ok data true):
  (let ((`#(ok ,wire-piece ,finished) (itb-lfe:stream-read session 1048576)))
    ...)
  (itb-lfe:stream-free session))
```

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string surfaces as
`#(error #(status detail))` — `status` an atom mirroring the C
binding's status table (e.g. `mac_failure`, `bad_input`,
`profile_exists`), `detail` the Go-side diagnostic binary. Opts are
a map or property list (`(map #"keyBits" 1024 #"nonceBits" 512)`)
rendered into the URL-query string libitb consumes.

Handle lifetime is garbage-collected: dropping every term reference
releases the Go-side state through the NIF resource destructor, and
`free/1` / `stream-free/1` release eagerly (both idempotent). A
stream session pins its parent pipeline resource, so the pipeline is
never collected under a live session.

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable
at libitb load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass `-1` to query without
changing. Long-running or allocation-heavy workloads (benchmarks,
bulk encryption) should set both — without a soft cap + aggressive
GC the Go scratch heap grows unboundedly under allocation churn:

```lisp
(itb-lfe:set-memory-limit (* 512 1024 1024)) ;; 512 MiB soft cap
(itb-lfe:set-gc-percent 20)                  ;; aggressive GC
```

## Testing

```bash
./bindings/lfe/run_tests.sh
```

The harness builds `libitb.so` + the C archive + the Erlang backend
+ the rebar3 project, then invokes `rebar3 eunit` (the LFE test
module is written with the ltest macros and registered explicitly in
`rebar.config` — EUnit cannot auto-discover `.lfe` sources). The
suite covers the Single Message round trip, stream pumps, the hash
primitive roster in canonical registry order, runtime knobs, profile
registration, and error mapping (unknown profile, tampered wire,
freed handles) — surface parity checks; the deep suite lives in Go
under the shipped tree.

## Benchmarking

```bash
./bindings/lfe/run_bench.sh
```

Micro-benches: `message` (encrypt-message) and `stream_pump`
(incremental encrypt session) throughput at 1 MiB / 16 MiB /
64 MiB, reported as an MB/s table on stdout. The runner exports
`ITB_GOMEMLIMIT=512MiB` + `ITB_GOGC=20` defaults (respecting caller
overrides) and the bench module applies the same caps
programmatically. `./run_bench.sh message` / `./run_bench.sh
stream` runs one shape.

## eitb utility

An executable script under `bindings/lfe/eitb/` mirrors the shipped
Go `tools/eitb` scope for shell smoke tests (build the binding
first):

```bash
cd bindings/lfe
./eitb/eitb version
./eitb/eitb hashes
./eitb/eitb encrypt singlemsg-triple-mac-v1 in.bin out.bin  # blob hex on stderr
./eitb/eitb decrypt singlemsg-triple-mac-v1 <blob-hex> out.bin back.bin
```

## Limitations

- The binding wraps the Triple Pipeline surface only. The Low-Level
  seed / MAC / blob / wrapper / parallax APIs are not exposed — use
  the shipped Go core for those.
- Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication.
- The `detail` text in an error tuple comes from a process-global
  last-write-wins store on the Go side; under concurrent use it may
  belong to a different call. The status atom is always
  attributable.
- `rekey/3` must not run concurrently with cipher calls or open
  stream sessions on the same Pipeline.
- Single-owner discipline per handle: do not call `free/1` /
  `stream-free/1` while another process is mid-call on the same
  handle — free from the owning process, or drop every reference
  and let the resource destructor release.
- After `stream-end/1`, an empty-spool `stream-read/2` blocks (on a
  dirty scheduler) until the terminal bytes arrive or the session
  errors; the regular schedulers are unaffected.
