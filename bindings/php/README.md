# ITB PHP Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the libitb shared library's `ITB_Triple_*` surface
(`cmd/cshared`). Runtime FFI via PHP's built-in `FFI` extension — no
C compiler at install time, no compile-time link, no third-party
dependencies; the `.so` / `.dylib` / `.dll` is resolved and
dispatched at first use. Every hash-name / MAC-name / cipher-name /
profile-name is an opaque string passed through to Go for validation;
the binding carries no ITB construction logic. The public surface is
the `Itb` facade (`create` / `open` / `registerProfile` / `hashes` /
`profiles` / `version` and the Go runtime knobs), a `Pipeline` class
(rekey / close, Single Message encrypt / decrypt, whole-buffer and
incremental stream sessions), and the `StreamEncryptor` /
`StreamDecryptor` session classes.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go php
```

Composer is optional (`sudo pacman -S composer`) — the in-repo entry
points use the bundled `autoload.php` and need no `composer install`.
Generic Linux / macOS: a Go toolchain plus PHP 7.4+ with the FFI
extension available. Windows: the same; libitb builds as
`libitb.dll`.

The FFI extension ships with PHP but may not be enabled by default.
Either enable `extension=ffi` in `php.ini`, or run with
`php -d extension=ffi -d ffi.enable=1` — the `run_tests.sh` /
`run_bench.sh` / `eitb` entry points add these flags automatically
when the host PHP lacks them.

## Build the shared library

The convenience driver builds `libitb.so` and lint-checks the PHP
sources in one step:

```bash
./bindings/php/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
```

The package is usable directly from `bindings/php/` (no build step —
FFI loads the shared library at runtime); composer consumers get the
same PSR-4 mapping (`Everanium\Itb\` → `src/`) from `composer.json`.

## Library lookup order

1. `ITB_LIBITB_PATH` environment variable (path to the shared
   library file).
2. `<repo>/dist/<os>-<arch>/libitb.<ext>` resolved from the package
   directory (in-repo builds).
3. The OS default loader path (`LD_LIBRARY_PATH`, `ld.so.cache`,
   `DYLD_LIBRARY_PATH`, `PATH`).

The FFI declarations are read from `include/itb.h` — a hand-cleaned,
preprocessor-free copy of the generated `dist/<os>-<arch>/libitb.h`
(PHP's FFI parser accepts plain declarations only).

## Usage example

```php
require 'bindings/php/autoload.php';

use Everanium\Itb\Itb;

$sender = Itb::create('singlemsg-triple-mac-v1');
$receiver = Itb::open('singlemsg-triple-mac-v1', $sender->blob());

$wire = $sender->encryptMessage('any text or binary data');
$plain = $receiver->decryptMessage($wire);
assert($plain === 'any text or binary data');
```

Opts overrides the profile default per call (chunk size, outer
cipher, parallax on/off, wrapper on/off, MAC name, palette) as a
plain `key => value` array passed to `create` / `open`:

```php
$opts = ['chunkSize' => 65536, 'withWrapper' => false];
$sender = Itb::create('singlemsg-triple-mac-v1', $opts);
$receiver = Itb::open('singlemsg-triple-mac-v1', $sender->blob(), $opts);
```

`Pipeline::rekey` rotates the parallax + wrapper masters mid-session
(the eight ITB seeds and MAC key are fixed for the session lifetime
by design); the receiver picks up the new masters through a fresh
`$sender->blob()` handshake:

```php
$sender->rekey(str_repeat("\x11", 32), str_repeat("\x22", 32));
$receiver = Itb::open('singlemsg-triple-mac-v1', $sender->blob());
```

`Pipeline` and the stream sessions free their Go-side handles on
garbage collection via `__destruct`; an explicit `free()` releases
them deterministically. For streaming, `encryptStream()` /
`decryptStream()` open incremental sessions exposing `write` / `end`
/ `read` / `drainAll` / `isFinished` for caller-driven loops; the
`encryptStreamOneShot` / `decryptStreamOneShot` calls cover
whole-buffer streaming wires in a single call each. A live session holds a reference to its
parent `Pipeline`, so the parent cannot be collected out from under
it. All byte inputs and outputs are plain PHP byte-strings.

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string throws
`Everanium\Itb\ItbException` carrying the status code
(`Everanium\Itb\Status` constants, via `getStatus()`) plus the
`ITB_LastError` diagnostic (via `getDetail()`).

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable at
libitb load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass `-1` to query without
changing:

```php
Itb::setMemoryLimit(512 << 20);
Itb::setGcPercent(20);
```

Large payloads pass through PHP strings, so the PHP-side
`memory_limit` must accommodate plaintext plus wire copies; the bench
and eitb entry points lift it via `ini_set('memory_limit', '-1')`.

## Testing

```bash
./bindings/php/run_tests.sh
```

The harness builds `libitb.so`, exports `ITB_LIBITB_PATH`, resolves
PHPUnit (`$ITB_PHPUNIT`, PATH, `vendor/bin/phpunit`, or
`tools/phpunit.phar`, in that order), and runs the `tests/` tree.
Positional arguments are forwarded to PHPUnit (e.g.
`./run_tests.sh --filter StreamTest`). The suite covers Single
Message round trips (including >1 MiB payloads and the
buffer-retry-once path), incremental and chunked stream sessions,
session-parent pinning, tampered-wire MAC failure, rekey, profile
registration, and error mapping — surface parity checks; the deep
suite lives in Go under the shipped tree.

## Benchmarking

```bash
./bindings/php/run_bench.sh
```

Micro-benches: `encryptMessage` and stream-session encrypt throughput
at 1 MiB / 16 MiB / 64 MiB. Shape and budget are driven by env vars
(`ITB_PROFILE`, `ITB_INNER_HASH`, `ITB_KEY_BITS`, `ITB_NONCE_BITS`,
`ITB_WITH_PARALLAX`, `ITB_WITH_WRAPPER`, `ITB_BENCH_MIN_SEC`); the
script pins the same defaults as the root Go BENCH3.md table.

## eitb utility

A small CLI under `bindings/php/eitb/` mirrors the shipped Go
`tools/eitb` scope for shell smoke tests:

```bash
./bindings/php/eitb/eitb version
./bindings/php/eitb/eitb hashes
./bindings/php/eitb/eitb profiles
./bindings/php/eitb/eitb encrypt singlemsg-triple-mac-v1 in.bin out.bin  # blob hex on stderr
./bindings/php/eitb/eitb decrypt singlemsg-triple-mac-v1 <blob-hex> out.bin back.bin
```

## Limitations

- The binding wraps the Triple Pipeline surface only. The Low-Level
  seed / MAC / blob / wrapper / parallax APIs are not exposed — use
  the shipped Go core for those.
- Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication.
- All binary data (blobs, wires, plaintexts, master keys) crosses the
  boundary as PHP byte-strings; no integer-array or GMP representation
  is used or required. 64-bit platforms only — handles and sizes
  assume a 64-bit PHP build (the standard on every supported OS).
- `ITB_LastError` is process-global last-write-wins; the textual
  diagnostic attached to an `ItbException` may belong to a different
  call under concurrent FFI use. The status code is always
  attributable.
- `rekey` must not run concurrently with cipher calls or open stream
  sessions on the same `Pipeline`.
- Inputs are borrowed zero-copy at the FFI boundary for the duration
  of a call; outputs are freshly-allocated PHP strings copied out of
  the FFI buffer.
- The profile roster returned by `Itb::profiles()` is pinned
  binding-side (the C ABI exposes no profile enumeration); profiles
  registered at runtime are not included.
- libitb must be reachable at runtime through the lookup order above.
