# ITB Python Binding — Easy Mode Benchmark Results

Throughput (MB/s) of `itb.Encryptor.encrypt` / `decrypt` /
`encrypt_auth` / `decrypt_auth` over the libitb c-shared library
through the cffi binding. Single + Triple Ouroboros at 1024-bit
ITB key width on a 16 MiB CSPRNG-filled payload, four ops per
primitive.

The harness lives in this directory — see [README.md](README.md)
for invocation, environment variables, and the per-case output
format.

## FFI overhead vs. native Go

The Python path adds buffer-protocol marshalling, a cgo crossing
per call, and a result-copy from the c-shared output buffer back
into a Python `bytes` object. After the binding-side optimisations
landed (`60033eb` — bench infrastructure, `15a08de` — output-buffer
cache + skip the size-probe round-trip + pass-through input
handling) the typical primitive lands in the **84 % – 95 %**
throughput band relative to the matching Go bench in the root
[BENCH.md](../../../../BENCH.md). For applications where every
percent of throughput matters, the native
[github.com/everanium/itb/easy](../../../../easy) Go API
delivers the full asm-accelerated speed of the encrypt /
decrypt path.

The numbers below ride the default build (no opt-out tags). On
hosts without AVX-512+VL the Go side automatically nil-routes
the 4-lane batched chain-absorb arm so the per-pixel hash falls
through to the upstream stdlib asm via the single Func — see the
build-tag table in the [Python binding README](../../README.md)
for the `-tags=purego` / `-tags=noitbasm` opt-outs.

## Intel Core i7-11700K (16 HT, VMware, c-shared mode)

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 187 | 279 | 91 | 168 |
| **Areion-SoEM-512** | 512 | PRF | 107 | 296 | 120 | 171 |
| **SipHash-2-4** | 128 | PRF | 153 | 199 | 112 | 135 |
| **AES-CMAC** | 128 | PRF | 189 | 274 | 127 | 162 |
| **BLAKE2b-512** | 512 | PRF | 138 | 176 | 103 | 123 |
| **BLAKE2b-256** | 256 | PRF | 97 | 113 | 79 | 91 |
| **BLAKE2s** | 256 | PRF | 105 | 123 | 84 | 97 |
| **BLAKE3** | 256 | PRF | 112 | 150 | 95 | 113 |
| **ChaCha20** | 256 | PRF | 114 | 132 | 88 | 103 |
| **Mixed** | 256 | PRF | 52 | 57 | 46 | 50 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 274 | 333 | 153 | 180 |
| **Areion-SoEM-512** | 512 | PRF | 286 | 345 | 160 | 187 |
| **SipHash-2-4** | 128 | PRF | 190 | 213 | 127 | 143 |
| **AES-CMAC** | 128 | PRF | 254 | 296 | 151 | 173 |
| **BLAKE2b-512** | 512 | PRF | 165 | 183 | 117 | 130 |
| **BLAKE2b-256** | 256 | PRF | 109 | 116 | 85 | 90 |
| **BLAKE2s** | 256 | PRF | 118 | 127 | 91 | 99 |
| **BLAKE3** | 256 | PRF | 146 | 158 | 107 | 117 |
| **ChaCha20** | 256 | PRF | 129 | 138 | 95 | 105 |
| **Mixed** | 256 | PRF | 50 | 51 | 44 | 45 |

## Intel Core i7-11700K (16 HT, VMware, c-shared mode, LockSeed mode)

The dedicated lockSeed channel (`set_lock_seed(1)` / `ITB_LOCKSEED=1`)
auto-couples Bit Soup + Lock Soup on the on-direction. Numbers
below run with all three overlays active.

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 58 | 71 | 52 | 58 |
| **Areion-SoEM-512** | 512 | PRF | 49 | 55 | 45 | 49 |
| **SipHash-2-4** | 128 | PRF | 67 | 74 | 58 | 63 |
| **AES-CMAC** | 128 | PRF | 72 | 82 | 62 | 69 |
| **BLAKE2b-512** | 512 | PRF | 43 | 50 | 40 | 44 |
| **BLAKE2b-256** | 256 | PRF | 42 | 45 | 38 | 41 |
| **BLAKE2s** | 256 | PRF | 43 | 46 | 39 | 41 |
| **BLAKE3** | 256 | PRF | 43 | 45 | 39 | 40 |
| **ChaCha20** | 256 | PRF | 46 | 50 | 34 | 39 |
| **Mixed** | 256 | PRF | 50 | 56 | 44 | 47 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 60 | 64 | 53 | 55 |
| **Areion-SoEM-512** | 512 | PRF | 53 | 53 | 45 | 48 |
| **SipHash-2-4** | 128 | PRF | 66 | 71 | 59 | 59 |
| **AES-CMAC** | 128 | PRF | 75 | 80 | 62 | 67 |
| **BLAKE2b-512** | 512 | PRF | 46 | 46 | 43 | 44 |
| **BLAKE2b-256** | 256 | PRF | 42 | 43 | 38 | 39 |
| **BLAKE2s** | 256 | PRF | 44 | 46 | 39 | 41 |
| **BLAKE3** | 256 | PRF | 44 | 44 | 38 | 39 |
| **ChaCha20** | 256 | PRF | 50 | 51 | 36 | 42 |
| **Mixed** | 256 | PRF | 50 | 52 | 43 | 44 |
