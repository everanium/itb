# ITB Triple Ouroboros — Accessible Explanation

> For the core ITB construction (Single Ouroboros, 3 seeds), see [ITB.md](ITB.md).
> Triple Ouroboros inherits all security properties from Single Ouroboros.

## What Is Triple Ouroboros?

Triple Ouroboros is a mode of ITB that uses **7 seeds** instead of 3. Plaintext is split at the byte level — every 3rd byte goes to a different "ring" — and each ring is encrypted independently with its own dataSeed and startSeed, sharing one noiseSeed.

The output format is **identical** to standard ITB: `[nonce][W][H][pixels]`. An observer cannot distinguish Single from Triple Ouroboros.

## How It Works: Step by Step

### 1. Plaintext Split

Plaintext bytes are distributed round-robin across three parts:

```
Plaintext: "Hello World!"   (12 bytes)

Index:  0  1  2  3  4  5  6  7  8  9  10 11
Byte:   H  e  l  l  o     W  o  r  l  d  !

Part 0 (bytes 0,3,6,9):   H  l  W  l
Part 1 (bytes 1,4,7,10):  e  o  o  d
Part 2 (bytes 2,5,8,11):  l     r  !
```

No part contains readable text. "HlWl", "eood", "l r!" — meaningless fragments. For a long document, each part is every 3rd character — pure gibberish.

### 2. Three Independent CSPRNG Regions

One container is allocated (`W×H×8` bytes). Three parallel goroutines fill it with crypto/rand — each writes to its own region:

```
Container (one allocation, three parallel fills):

┌──────────────┬──────────────┬──────────────┐
│  Region 0    │  Region 1    │  Region 2    │
│  crypto/rand │  crypto/rand │  crypto/rand │
│  goroutine 1 │  goroutine 2 │  goroutine 3 │
└──────────────┴──────────────┴──────────────┘
  pixels 0..P/3  pixels P/3..2P/3  pixels 2P/3..P
```

ASIC-ready: three independent DRBG can fill three regions in parallel.

### 3. Three Parallel Encrypt Pipelines

Each part is COBS-encoded, null-terminated, filled with CSPRNG residue, then encrypted into its region with its own seeds:

```
Part 0 → COBS → [cobs|0x00|fill] → dataSeed1 + startSeed1 + noiseSeed → Region 0
Part 1 → COBS → [cobs|0x00|fill] → dataSeed2 + startSeed2 + noiseSeed → Region 1
Part 2 → COBS → [cobs|0x00|fill] → dataSeed3 + startSeed3 + noiseSeed → Region 2
                                    ─────────────────────────────────
                                    3 goroutines, each with numCPU/3 workers
```

Each pipeline is a complete ITB encryption: per-pixel ChainHash, rotation 0-6, 56-bit XOR mask, noise bit at unknown position, startPixel wrap-around — all within its region.

### 4. Per-Pixel Bit-Level Processing

Inside each region, the standard ITB per-pixel processing applies. Here's what happens to "H" (0x48 = 01001000) from Part 0:

```
"H" = 01001000 (8 bits)

Channel 0:  0100100  ← 7 bits extracted from bit stream
            ⊕ XOR mask from dataSeed1 (7 bits per channel)
            = encrypted 7 bits
            rotate(encrypted, rotation1)  ← rotation 0-6 from dataSeed1
            insert into pixel, preserving noise bit at noisePos (from noiseSeed)

Channel 1:  0?????? ← next 7 bits (from "H" + next byte "l")
            ... same XOR + rotate + insert ...
```

Each byte is split across 2 channels (gcd(7,8)=1). Each channel has 7 encrypted data bits + 1 noise bit. The attacker sees 8 random-looking bits per channel.

### 5. What the Attacker Sees

```
Output: [nonce][W][H][uniform random pixels]

┌──────────────────────────────────────────────────────┐
│ dddddddddddddddddddddddddddddddddddddddddddddddddd │
│ dddddddddddddddddddddddddddddddddddddddddddddddddd │
│ dddddddddddddddddddddddddddddddddddddddddddddddddd │
└──────────────────────────────────────────────────────┘
  ← one continuous block of uniform random bytes →

  No visible boundary between regions.
  No visible startPixel markers (three different, all hidden).
  No visible data/fill boundary (three different, all hidden).
  No way to know if this is Single (3 seeds) or Triple (7 seeds).
```

### 6. Decrypt: Reassembly

Decrypt3x knows it's Triple (separate function with 7 seed parameters):

1. Read `[nonce][W][H]` — standard header
2. Split pixel data into thirds (same integer division as encrypt)
3. Three parallel goroutines decode each region with respective seeds
4. COBS decode each part → Part 0, Part 1, Part 2
5. Interleave: `result[0]=Part0[0], result[1]=Part1[0], result[2]=Part2[0], result[3]=Part0[1], ...`
6. Return original plaintext

## Security

Triple Ouroboros inherits all security properties from Single Ouroboros ([ITB.md](ITB.md), [SCIENCE.md](SCIENCE.md), [PROOFS.md](PROOFS.md)). We do not duplicate the full scientific analysis here — the core construction is identical within each region.

**What changes:**

| Property | Single Ouroboros | Triple Ouroboros |
|---|---|---|
| Seeds | 3 (noiseSeed, dataSeed, startSeed) | 7 (noiseSeed, 3×dataSeed, 3×startSeed) |
| Classical brute-force (CCA) | P × 2^keyBits | P × 2^(3×keyBits) |
| Grover (CCA) | √P × 2^(keyBits/2) | √P × 2^(3×keyBits/2) |
| CCA leak | 4.8% (noisePos only) | 4.8% (same — shared noiseSeed) |
| Encoding ambiguity per region | 7^P | 7^(P/3) per region, independent |
| Output format | `[nonce][W][H][pixels]` | `[nonce][W][H][pixels]` — identical |
| Distinguishable from Single? | — | No (passive observation) |

**What stays the same:**
- Noise absorption (mechanism 1): 12.5% noise bits per region, same noiseSeed
- Encoding ambiguity (mechanism 2): rotation 0-6 per pixel, different dataSeed per region
- CSPRNG residue ([Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)): guaranteed fill in each region, covered by MAC
- Per-bit XOR (1:1): 56 independent mask bits per pixel
- Byte-splitting: gcd(7,8)=1, every byte split across 2 channels
- KPA defense: Full KPA is 3-factor under PRF assumption — PRF non-invertibility + 7-rotation × 8-noisePos + independent startSeed per ring combine conjunctively (see [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)). Each ring has independent dataSeed and startSeed, so obstacles (1), (2), (3) of Proof 4a apply per ring. noiseSeed is shared across rings, so the 8-noisePos layer applies once to the whole container, not replicated per ring. gcd(7,8)=1 byte-splitting is a 4th factor effective only under Partial KPA.
- Oracle-free deniability: wrong seeds → garbage, no verification oracle
- MAC-Inside-Encrypt: tag encrypted in region 2, covers all fill bytes of all 3 regions

## Performance

**Note:** For maximum throughput, use **512-bit ITB key** with Triple Ouroboros. Security becomes P × 2^1536 (3 × 512) — stronger than Single 1024-bit (P × 2^1024) — while ChainHash runs at 512-bit speed (fewer rounds per pixel).

Triple Ouroboros achieves near-Single performance through parallelism:

- **Encrypt:** 3×CSPRNG fills regions in parallel + 3 goroutines process pixels in parallel
- **Decrypt:** 3 goroutines decode regions in parallel (no CSPRNG needed)
- **Worker distribution:** each goroutine uses numCPU/3 workers — no oversubscription

On multi-core CPUs (96+ cores), Triple can be **faster** than Single at the same key size because three independent pipelines utilize more cores effectively.

**Sweet spot:** Triple Ouroboros with 512-bit keys:
- Performance close to Single 512-bit
- Security P × 2^1536 — exceeds Single 1024-bit (P × 2^1024)
- Best throughput-to-security ratio

Full benchmark results: **[BENCH3.md](BENCH3.md)**

## Bit Soup (bit-level split, opt-in)

Triple Ouroboros has an additional switch: **`SetBitSoup(1)`** — a process-wide flag that changes the split from byte level to **bit level**. Every third bit of the plaintext goes to a different snake. Three consecutive bits are assembled into a garbage byte, meaningless without the other two snakes, and this garbage byte passes through the standard ITB encoding pipeline unchanged. On the decrypt side, garbage bytes from the three snakes are disassembled back into real bits and reassembled into the original plaintext.

No real byte of plaintext exists in any one snake's payload. No header token, no JSON `{`, no HTML tag, no COBS framing boundary an attacker could latch onto. Just unreconstructible garbage per snake.

### What happens to "Hello World!" under Bit Soup

Same input as the byte-level example above (12 bytes of plaintext).

**Step A — prepend a 4-byte BE length prefix.** The decoder needs the exact plaintext byte count to recover the original data after bit-level reassembly, so `SetBitSoup(1)` adds a `uint32(len(data))` big-endian header in front of the plaintext:

```
data' = 00 00 00 0C | H  e  l  l  o     W  o  r  l  d  !    (16 bytes = 128 bits)
        └─ length ─┘   └──────── "Hello World!" ────────┘
        uint32(12) BE
```

**Step B — interleave at the bit level.** Instead of every 3rd byte, every 3rd bit of the 128-bit stream goes to a different snake:

```
bit #:     0 1 2  3 4 5  6 7 8  9 10 11  12 13 14  15 16 17 ...
snake →:   0 1 2  0 1 2  0 1 2  0  1  2   0  1  2   0  1  2 ...
```

**Step C — pack into garbage bytes.** Each 8 consecutive bits of a snake become one "garbage byte". A single garbage byte contains 3 bits from source byte k, 3 bits from k+1, and 2 bits from k+2 of `data'`. No contiguous plaintext byte survives.

Result:

```
Snake 0:  00  C2  C6  D8  C4  01
Snake 1:  00  A0  F8  E8  9B  00
Snake 2:  00  19  3B  36  1A  02
```

Side-by-side with the byte-level example above:

| Mode | Snake 0 payload | Snake 1 payload | Snake 2 payload |
|---|---|---|---|
| Triple Byte Level | `H  l  W  l` | `e  o  o  d` | `l     r  !` |
| Triple Bit Soup | `00 C2 C6 D8 C4 01` | `00 A0 F8 E8 9B 00` | `00 19 3B 36 1A 02` |

Under byte-level, each snake carries readable letters from the plaintext. Under Bit Soup, nothing in any snake maps back to a recognisable character — every byte is a bit-level scramble across three adjacent source bytes.

**Why Snake 0 byte 1 = `0xC2`.** Those 8 output bits come from 3 different source bytes of `data'`:

| output bit (LSB → MSB) | source position | source byte | bit value |
|---|---|---|---|
| 0 | bit 24 | `0x0C` (length byte) bit 0 | 0 |
| 1 | bit 27 | `0x0C` bit 3 | **1** |
| 2 | bit 30 | `0x0C` bit 6 | 0 |
| 3 | bit 33 | `H` (0x48) bit 1 | 0 |
| 4 | bit 36 | `H` bit 4 | 0 |
| 5 | bit 39 | `H` bit 7 | 0 |
| 6 | bit 42 | `e` (0x65) bit 2 | **1** |
| 7 | bit 45 | `e` bit 5 | **1** |

Packed LSB-first: `0b11000010` = `0xC2`. One garbage byte of Snake 0 has mixed bits from three different source bytes — the length header, `H`, and `e` — with no way for a reader holding just this byte to isolate a recognisable character.

The first byte of every snake is `0x00` because it falls entirely inside the length prefix (bytes 0–2 of `data'` are the MSBs of `uint32(12)` and are all zero). Starting from byte 1, the bit-mixing becomes visible.

Everything downstream (COBS framing, CSPRNG fill, per-region ChainHash encryption, container assembly) is identical to byte-level Triple Ouroboros.

**Why this matters.** SAT-based cryptanalysis needs a **crib** — a known fragment of plaintext — to set up the equations a solver will work on. In byte-level Triple Ouroboros, every third byte of the real plaintext sits inside a given snake, and those bytes carry whatever schema structure the protocol happens to have (JSON braces, HTML tags, fixed header fields). Under Bit Soup, every snake sees garbage. The attacker does not have enough observation to build a useful constraint system in the first place. The barrier is about **what the attacker can observe**, not about how fast a solver can run — faster solvers do not widen the crib. Against PRF-grade primitives, the SAT-way is effectively off the table for the foreseeable future.

**Cost.** End-to-end throughput is within ±5 % of byte-level Triple Ouroboros on commodity hardware, and on high-core-count systems Bit Soup can be slightly faster on some primitives because the chunk-parallel split kernel scales beyond byte-level's 3-lane limit. The bit-level split is implemented as a 24-bit-chunk permutation kernel (`chunk24` / `unchunk24`) that aligns to byte boundaries every 3 input bytes, distributed across CPU cores via period-3-byte chunking with disjoint output writes — no per-bit loop, no synchronisation. Architectural barrier (instance-formulation under-determination) is added at no measurable throughput penalty. See [BENCH3.md](BENCH3.md) for per-primitive encrypt / decrypt numbers across `keyBits = 512 / 1024 / 2048` in both modes on Intel Core i7-11700K and AMD EPYC 9655P.

**How to enable:**

```go
itb.SetBitSoup(1) // whole-process opt-in; default is 0 (byte-level)
```

The ciphertext wire format is identical to byte-level Triple Ouroboros. An observer cannot distinguish the two modes. Callers must agree on the mode across both ends of the channel.

Applies uniformly to `Encrypt3x*`, `EncryptAuthenticated3x*`, `EncryptStream3x*` and their decrypt counterparts.

## API

```go
// Triple Ouroboros — 7-seed encryption
encrypted, err := itb.Encrypt3x512(noiseSeed, dataSeed1, dataSeed2, dataSeed3,
    startSeed1, startSeed2, startSeed3, plaintext)

decrypted, err := itb.Decrypt3x512(noiseSeed, dataSeed1, dataSeed2, dataSeed3,
    startSeed1, startSeed2, startSeed3, encrypted)

// Authenticated Triple Ouroboros
encrypted, err := itb.EncryptAuthenticated3x512(noiseSeed, dataSeed1, dataSeed2, dataSeed3,
    startSeed1, startSeed2, startSeed3, plaintext, macFunc)

// Streaming Triple Ouroboros
err := itb.EncryptStream3x512(noiseSeed, dataSeed1, dataSeed2, dataSeed3,
    startSeed1, startSeed2, startSeed3, data, chunkSize, emitFunc)
```

Available for all three hash widths: 128-bit (`Encrypt3x128`), 256-bit (`Encrypt3x256`), 512-bit (`Encrypt3x512`).
Available for all three hash widths: 128-bit (`Decrypt3x128`), 256-bit (`Decrypt3x256`), 512-bit (`Decrypt3x512`).
