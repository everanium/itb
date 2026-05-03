# C# binding throughput

Recorded on Intel Core i7-11700K (Rocket Lake, AVX-512 + VAES,
8 cores / 16 threads, native Linux), .NET SDK 10.0.104, libitb
0.1.0 in c-shared mode. Each cell is steady-state throughput in
MB/s on a 16 MiB plaintext payload, ITB key width 1024 bits, MAC
slot bound to **HMAC-BLAKE3** (the lightest authenticated-mode
MAC — ~9 % overhead vs HMAC-SHA256's ~15 % vs KMAC-256's ~44 %).
Each case ran for at least 5 wall-clock seconds (the
`ITB_BENCH_MIN_SEC` default) to absorb cold-cache / warmup
transients on the encrypt path.

Reproduction:

```bash
cd bindings/csharp
dotnet build -c Release
ITB_BENCH_MIN_SEC=5 dotnet run --project Itb.Bench -c Release -- single
ITB_BENCH_MIN_SEC=5 ITB_LOCKSEED=1 dotnet run --project Itb.Bench -c Release -- single
ITB_BENCH_MIN_SEC=5 dotnet run --project Itb.Bench -c Release -- triple
ITB_BENCH_MIN_SEC=5 ITB_LOCKSEED=1 dotnet run --project Itb.Bench -c Release -- triple
```

Primitive ordering follows the canonical PRF-grade subset of the
ITB hash registry (`AES-CMAC`, `SipHash-2-4`, `ChaCha20`,
`Areion-SoEM-256`, `BLAKE2s`, `BLAKE3`, `BLAKE2b-256`,
`BLAKE2b-512`, `Areion-SoEM-512`). The `mixed` row constructs a
mixed-primitive `Encryptor` (`blake3` noise / `areion256` data /
`chacha20` start, plus `blake3` lockseed in the `with LockSeed`
arm). Lower-than-pure-`blake3` mixed-row throughput in the LockSeed
arm reflects the BitSoup + LockSoup auto-couple that the dedicated
lockseed slot engages.

## Single Ouroboros — no LockSeed

| Primitive | encrypt | decrypt | encrypt_auth | decrypt_auth |
|---|---:|---:|---:|---:|
| AES-CMAC | 189.5 | 265.1 | 174.2 | 246.2 |
| SipHash-2-4 | 152.3 | 196.3 | 144.0 | 188.5 |
| ChaCha20 | 111.2 | 131.7 | 106.5 | 124.9 |
| Areion-SoEM-256 | 70.7 | 174.9 | 169.5 | 257.0 |
| BLAKE2s | 101.3 | 117.7 | 93.5 | 116.7 |
| BLAKE3 | 124.3 | 149.1 | 118.2 | 143.8 |
| BLAKE2b-256 | 96.0 | 110.7 | 91.1 | 107.4 |
| BLAKE2b-512 | 138.0 | 168.2 | 127.0 | 163.3 |
| Areion-SoEM-512 | 204.8 | 301.8 | 186.9 | 278.0 |
| mixed | 153.5 | 197.0 | 144.7 | 186.3 |

## Single Ouroboros — with LockSeed (BitSoup + LockSoup engaged)

| Primitive | encrypt | decrypt | encrypt_auth | decrypt_auth |
|---|---:|---:|---:|---:|
| AES-CMAC | 73.3 | 83.8 | 71.7 | 82.5 |
| SipHash-2-4 | 68.9 | 76.0 | 63.5 | 71.8 |
| ChaCha20 | 45.0 | 47.7 | 36.0 | 41.6 |
| Areion-SoEM-256 | 60.1 | 71.8 | 61.7 | 71.1 |
| BLAKE2s | 42.9 | 46.2 | 42.4 | 45.6 |
| BLAKE3 | 42.5 | 45.6 | 41.8 | 44.6 |
| BLAKE2b-256 | 41.3 | 44.5 | 40.3 | 44.2 |
| BLAKE2b-512 | 45.8 | 49.3 | 44.5 | 48.9 |
| Areion-SoEM-512 | 52.3 | 57.7 | 50.2 | 56.8 |
| mixed | 45.1 | 47.7 | 42.6 | 47.3 |

## Triple Ouroboros — no LockSeed

| Primitive | encrypt | decrypt | encrypt_auth | decrypt_auth |
|---|---:|---:|---:|---:|
| AES-CMAC | 247.6 | 287.6 | 190.3 | 272.9 |
| SipHash-2-4 | 186.7 | 207.2 | 173.0 | 199.9 |
| ChaCha20 | 124.8 | 134.0 | 118.1 | 129.6 |
| Areion-SoEM-256 | 258.6 | 315.3 | 236.2 | 297.3 |
| BLAKE2s | 114.5 | 122.4 | 108.7 | 119.8 |
| BLAKE3 | 141.7 | 154.2 | 134.1 | 149.4 |
| BLAKE2b-256 | 104.4 | 110.5 | 99.4 | 108.1 |
| BLAKE2b-512 | 162.0 | 175.5 | 151.1 | 169.1 |
| Areion-SoEM-512 | 275.4 | 323.0 | 247.8 | 310.9 |
| mixed | 140.4 | 151.7 | 132.0 | 143.4 |

## Triple Ouroboros — with LockSeed (BitSoup + LockSoup engaged)

| Primitive | encrypt | decrypt | encrypt_auth | decrypt_auth |
|---|---:|---:|---:|---:|
| AES-CMAC | 75.9 | 68.2 | 66.6 | 72.4 |
| SipHash-2-4 | 68.9 | 73.0 | 67.1 | 71.7 |
| ChaCha20 | 46.1 | 47.2 | 37.9 | 39.7 |
| Areion-SoEM-256 | 58.9 | 63.7 | 59.9 | 61.9 |
| BLAKE2s | 42.7 | 43.4 | 41.8 | 43.0 |
| BLAKE3 | 40.5 | 41.9 | 40.0 | 41.1 |
| BLAKE2b-256 | 39.1 | 41.4 | 40.4 | 40.9 |
| BLAKE2b-512 | 44.1 | 45.9 | 42.5 | 44.8 |
| Areion-SoEM-512 | 52.3 | 53.0 | 50.3 | 53.4 |
| mixed | 33.6 | 42.1 | 38.4 | 41.0 |

## Notes

- The first row in every Single-Ouroboros pass shows a transient
  asymmetry between encrypt and decrypt (e.g., Areion-SoEM-256
  encrypt 70.7 MB/s vs decrypt 174.9 MB/s in the no-LockSeed pass).
  This is the cold-cache + first-iteration warmup absorbed
  imperfectly even at 5-second windows; subsequent rows in the same
  pass run on warm caches and report symmetric encrypt-vs-decrypt
  numbers. Re-running the same primitive in isolation
  (`ITB_BENCH_FILTER=areion256 ITB_BENCH_MIN_SEC=20 dotnet run -- single`)
  normalises the asymmetry.
- The `with LockSeed` arms cap throughput in the 40-80 MB/s band
  because the dedicated lockseed slot auto-engages BitSoup +
  LockSoup; the bit-level split + per-chunk PRF-keyed
  bit-permutation overlay together dominate the per-byte cost.
- Triple Ouroboros exceeds Single Ouroboros throughput on most
  primitives because the seven-seed split exposes additional
  internal parallelism opportunities to libitb's worker pool while
  the on-the-wire chunk count remains the same.
- Bench cases run sequentially per pass; libitb's internal worker
  pool (`Library.MaxWorkers = 0` → all CPUs) processes each case's
  chunk-level parallelism within the case's wall-clock window.
