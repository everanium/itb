# ITB D Binding - Easy Mode Benchmark Results

Throughput (MB/s) of `Encryptor.encrypt` / `decrypt` / `encryptAuth`
/ `decryptAuth` over the libitb c-shared library through the D
`extern (C)` link-time FFI surface emitted by DMD / LDC2 / GDC.
Single + Triple Ouroboros at 1024-bit ITB key width on a 16 MiB
non-deterministic-fill payload, four ops per primitive. The MAC
slot is bound to **HMAC-BLAKE3** - the lightest authenticated-mode
overhead among the three shipping MACs (the `encryptAuth` row sits
within a few percent of the matching `encrypt` row, and well below
HMAC-SHA256's ~15 % and KMAC-256's ~44 % overheads).

The harness lives under [bench/](bench/) - see
[bench/README.md](bench/README.md) for invocation, environment
variables, and the per-case output format. The default measurement
window is 5 seconds per case (`ITB_BENCH_MIN_SEC=5`), wide enough
to absorb the cold-cache / warm-up transient that distorts shorter
windows on the 16 MiB encrypt / decrypt path.

## FFI overhead vs. native Go

The D path adds an `extern (C)` symbol resolution per call, the C
ABI crossing into Go, and a result-copy from the c-shared output
buffer back into a D `ubyte[]` slice. The binding caches a
per-encryptor output buffer and pre-allocates from a 1.25x upper
bound on the empirical ITB ciphertext-expansion factor (<= 1.155
across every primitive / mode / nonce / payload-size combination)
so the hot loop avoids the size-probe round-trip the
process-global FFI helpers use. The cache is wiped on grow and on
`close` / destruction, so residual ciphertext / plaintext cannot
linger in heap garbage between cipher calls.

The numbers below ride the default build (no opt-out tags). On
hosts without AVX-512+VL the Go side automatically nil-routes the
4-lane batched chain-absorb arm so the per-pixel hash falls
through to the upstream stdlib asm via the single Func - see the
build-tag table in the [Python binding README](../python/README.md)
for the `-tags=purego` / `-tags=noitbasm` opt-outs (the same tags
apply to the D binding's libitb.so build).

## Intel Core i7-11700K (16 HT, native Linux, c-shared mode)

### ITB Single 1024-bit (security: P x 2^1024)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 135 | 188 | 124 | 176 |
| **Areion-SoEM-512** | 512 | PRF | 139 | 193 | 135 | 183 |
| **SipHash-2-4** | 128 | PRF | 153 | 198 | 143 | 189 |
| **AES-CMAC** | 128 | PRF | 189 | 267 | 174 | 249 |
| **BLAKE2b-512** | 512 | PRF | 98 | 119 | 92 | 164 |
| **BLAKE2b-256** | 256 | PRF | 69 | 80 | 66 | 77 |
| **BLAKE2s** | 256 | PRF | 100 | 119 | 98 | 115 |
| **BLAKE3** | 256 | PRF | 122 | 149 | 116 | 144 |
| **ChaCha20** | 256 | PRF | 110 | 131 | 105 | 124 |
| **Mixed** | 256 | PRF | 110 | 129 | 104 | 127 |

### ITB Triple 1024-bit (security: P x 2^(3x1024) = P x 2^3072)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 169 | 195 | 143 | 184 |
| **Areion-SoEM-512** | 512 | PRF | 172 | 206 | 152 | 193 |
| **SipHash-2-4** | 128 | PRF | 186 | 212 | 175 | 200 |
| **AES-CMAC** | 128 | PRF | 250 | 252 | 188 | 278 |
| **BLAKE2b-512** | 512 | PRF | 111 | 120 | 101 | 176 |
| **BLAKE2b-256** | 256 | PRF | 75 | 80 | 72 | 78 |
| **BLAKE2s** | 256 | PRF | 115 | 123 | 109 | 119 |
| **BLAKE3** | 256 | PRF | 144 | 155 | 134 | 150 |
| **ChaCha20** | 256 | PRF | 127 | 134 | 119 | 131 |
| **Mixed** | 256 | PRF | 124 | 133 | 119 | 132 |

## Intel Core i7-11700K (16 HT, native Linux, c-shared mode, LockSeed mode)

The dedicated lockSeed channel (`Encryptor.setLockSeed(1)` /
`ITB_LOCKSEED=1`) auto-couples bit-soup + lock-soup on the
on-direction. Numbers below run with all three overlays active.

### ITB Single 1024-bit (security: P x 2^1024)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 58 | 68 | 59 | 68 |
| **Areion-SoEM-512** | 512 | PRF | 49 | 54 | 44 | 51 |
| **SipHash-2-4** | 128 | PRF | 69 | 74 | 64 | 74 |
| **AES-CMAC** | 128 | PRF | 74 | 86 | 74 | 85 |
| **BLAKE2b-512** | 512 | PRF | 42 | 49 | 42 | 44 |
| **BLAKE2b-256** | 256 | PRF | 40 | 40 | 40 | 39 |
| **BLAKE2s** | 256 | PRF | 43 | 46 | 41 | 44 |
| **BLAKE3** | 256 | PRF | 41 | 46 | 41 | 44 |
| **ChaCha20** | 256 | PRF | 46 | 50 | 37 | 44 |
| **Mixed** | 256 | PRF | 48 | 55 | 48 | 47 |

### ITB Triple 1024-bit (security: P x 2^(3x1024) = P x 2^3072)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 62 | 67 | 61 | 64 |
| **Areion-SoEM-512** | 512 | PRF | 53 | 55 | 52 | 55 |
| **SipHash-2-4** | 128 | PRF | 68 | 70 | 67 | 72 |
| **AES-CMAC** | 128 | PRF | 76 | 80 | 72 | 61 |
| **BLAKE2b-512** | 512 | PRF | 46 | 50 | 45 | 48 |
| **BLAKE2b-256** | 256 | PRF | 43 | 44 | 42 | 43 |
| **BLAKE2s** | 256 | PRF | 44 | 45 | 43 | 45 |
| **BLAKE3** | 256 | PRF | 43 | 44 | 41 | 43 |
| **ChaCha20** | 256 | PRF | 48 | 50 | 40 | 43 |
| **Mixed** | 256 | PRF | 49 | 52 | 46 | 50 |

## Notes

- The first row in every Single-Ouroboros pass typically shows a
  transient asymmetry between encrypt and decrypt. This is the
  cold-cache + first-iteration warmup absorbed imperfectly even at
  5-second windows; subsequent rows in the same pass run on warm
  caches and report symmetric encrypt-vs-decrypt numbers. Re-running
  the same primitive in isolation
  (`ITB_BENCH_FILTER=areion256 ITB_BENCH_MIN_SEC=20 ./bench/bin/itb-bench-single`)
  normalises the asymmetry.
- The LockSeed arms cap throughput in the 40-80 MB/s band because
  the dedicated lockseed slot auto-engages BitSoup + LockSoup; the
  bit-level split + per-chunk PRF-keyed bit-permutation overlay
  together dominate the per-byte cost.
- Triple Ouroboros exceeds Single Ouroboros throughput on most
  primitives because the seven-seed split exposes additional
  internal parallelism opportunities to libitb's worker pool while
  the on-the-wire chunk count remains the same.
- Bench cases run sequentially per pass; libitb's internal worker
  pool (`itb.setMaxWorkers(0)` -> all CPUs) processes each case's
  chunk-level parallelism within the case's wall-clock window.
