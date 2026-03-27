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
- CSPRNG residue (Proof 10): guaranteed fill in each region, covered by MAC
- Per-bit XOR (1:1): 56 independent mask bits per pixel
- Byte-splitting: gcd(7,8)=1, every byte split across 2 channels
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

**Note (Crazy Mode — bit-level split).** It is possible to go further: instead of splitting plaintext at the byte level, split at the **bit level** — every 3rd bit goes to a different snake. Three consecutive bits are assembled into a garbage byte (meaningless without the other two snakes), and this garbage byte passes through the standard ITB encoding pipeline. On the decrypt side, garbage bytes from three snakes are disassembled back into real bits and reassembled into the original plaintext. No single snake holds a single real byte — only unreconstructible garbage. The functions `splitTripleBits`/`interleaveTripleBits` are already implemented and tested. Performance cost: ~20× slower than byte-level split (30 MB/s vs 568 MB/s for split+interleave alone on 64 MB). If there is demand from the research community, we can add dedicated `Encrypt3Bits`/`Decrypt3Bits` functions for bit-level Triple Ouroboros in the future. Unreconstructible garbage. Can we do it? Yes. But why?

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
