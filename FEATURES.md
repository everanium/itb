# ITB Features

> **Disclaimer.** ITB is an experimental construction without peer review or formal certification. The information-theoretic barrier is a software-level property, reinforced by two independent mechanisms: noise absorption (CSPRNG) and encoding ambiguity (rotation from triple-seed isolation). It provides no guarantees against hardware-level attacks (DPA/SPA, Spectre, Meltdown, cache timing). PRF-grade hash functions are required. No warranty is provided.

## Core Construction

- **Chained Hash Architecture.** N independent uint64 key components processed sequentially through a pluggable hash function. Each round feeds the previous output XOR'd with the next component. Each component is independent (no key-schedule relationships between components) — compromising one component reveals nothing about others. Designed to resist meet-in-the-middle attacks through three independent barriers: unobservable hash output, non-invertibility, and multi-call key discrimination.

- **Pluggable Hash Function.** The library accepts hash functions at three widths: `HashFunc128` (128-bit), `HashFunc256` (256-bit), `HashFunc512` (512-bit). No built-in hash implementations, no external dependencies. Users supply SipHash-2-4, BLAKE3, AES-CMAC, BLAKE2b, or any conforming PRF function. PRF-grade hash functions are required. The random-container barrier provides additional architectural hardening by making hash output unobservable (see [SCIENCE.md Section 2.4](SCIENCE.md#24-information-theoretic-barrier-and-hash-requirements), [2.10](SCIENCE.md#210-hash-function-requirements-analysis)).

- **Three Hash Width Variants.** Parallel API sets for 128-bit (`Encrypt128`/`Decrypt128`), 256-bit (`Encrypt256`/`Decrypt256`), and 512-bit (`Encrypt512`/`Decrypt512`). All share the same pixel format, COBS framing, and security properties. ChainHash128 uses 2 components per round (128-bit intermediate state), ChainHash256 uses 4 components per round (256-bit intermediate state), ChainHash512 uses 8 components per round (512-bit intermediate state). Wider intermediate state enables higher effective key sizes.

- **Dynamic Key Size.** 512 to 2048 bits. Alignment depends on hash width: 128-bit multiples for `Seed128`, 256-bit multiples for `Seed256`, 512-bit multiples for `Seed512`. Effective security upper-bounded by `min(keyBits, hashInternalState × numRounds)`. With BLAKE3 (256-bit internal state): 2048-bit effective security (no bottleneck). With AES/SipHash-2-4 (128-bit): 1024 bits.

- **Per-Message Nonce (128/256/512-bit).** Generated from `crypto/rand` on every encryption call. Default 128-bit; configurable to 256 or 512 via `SetNonceBits`. Mixed into every hash invocation. Mandatory — prevents pixel configuration reuse across messages. Birthday collision after ~2^64 messages (128-bit), ~2^128 (256-bit), ~2^256 (512-bit).

- **COBS Binary Framing.** Internal Consistent Overhead Byte Stuffing encodes arbitrary binary data (including 0x00 bytes) so that 0x00 never appears in encoded output. Overhead ~0.4%. Enables null terminator as unambiguous message boundary. Encrypt files, archives, images, executables, protocol buffers, or any binary format.

## Information-Theoretic Barrier

- **Random Container.** Container pixels generated from `crypto/rand`. The marginal distribution of individual pixel values is indistinguishable from uniform before and after embedding, because both container and modifications are random.

- **Encoding Ambiguity.** Each pixel has 7 rotation candidates (0–6) from an independent dataSeed. Across P pixels: 7^P unverifiable combinations (for P = 196: 7^196 ≈ 2^550 in Encrypt/Stream; for P = 400: 7^400 ≈ 2^1123 in Auth). This mechanism survives CCA — even if noise positions are revealed, rotation ambiguity remains intact through triple-seed isolation (dataSeed is independent of noiseSeed). See [SCIENCE.md §2.9.2](SCIENCE.md#292-why-kpa-candidates-do-not-break-the-barrier).

- **Guaranteed CSPRNG Residue.** The `side += barrierFill` container construction (`SetBarrierFill`, default 1) ensures capacity always exceeds payload — at least (2s+1)×7 bytes of CSPRNG fill are present in every container (≥203 bytes at 1024-bit key). These fill bytes are encrypted by dataSeed identically to plaintext (same rotation + XOR). After CCA removes noise bits, the data channel still contains this CSPRNG residue — the attacker cannot distinguish fill from plaintext, cannot determine where one ends and the other begins. Perfect fill is mathematically impossible. This preserves information-theoretic ambiguity within the data bits even when noise absorption is bypassed. See [Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill).

- **Hash Independence.** The random container creates an information-theoretic barrier: the hash output is consumed by a modification of a random pixel and is not reconstructible from passive observations (COA, KPA). PRF-grade hash functions are required. The barrier provides additional architectural hardening by making hash output unobservable (see [SCIENCE.md Section 2.4](SCIENCE.md#24-information-theoretic-barrier-and-hash-requirements), [Definition 2](SCIENCE.md#5-formal-definitions)).

- **Known-Plaintext Resistance (under passive observation).** Even with fully known plaintext, the attacker cannot derive hash outputs because original container pixel values are unknown (crypto/rand, never transmitted). Attack degrades to brute-force regardless of hash function.

- **Plausible Deniability.** Decryption with any seed always produces output — there is no structural difference between correct and incorrect decryption. Wrong seeds produce random-looking bytes indistinguishable from valid plaintext without external context. The number of plausible decryptions equals the key space — every seed is a valid candidate. This is a property of the encoding architecture, not of the encryption: data is embedded into a random container, and extraction always succeeds regardless of seed correctness. Classical brute-force and Grover both face an astronomical number of candidates with no efficient way to distinguish the real one (Core ITB / MAC + Silent Drop).

These barrier properties hold fully under Core ITB and MAC + Silent Drop (no oracle). Under MAC + Reveal, noiseSeed config is leaked via CCA (noise **bits** removed — attacker can strip the 1 noise bit per channel), but dataSeed remains fully protected (encoding ambiguity intact). Crucially, removing noise bits does not give the attacker clean plaintext-only data: the remaining data bits contain both encrypted plaintext and encrypted CSPRNG fill, both processed identically by dataSeed. Perfect fill is impossible — the `side += barrierFill` construction (`SetBarrierFill`, default 1) guarantees ≥(2s+1)×7 bytes of CSPRNG residue ([Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)). The information-theoretic barrier is partially preserved within the data channel even after CCA. Plausible deniability is preserved in all three modes — even with CCA, decoding with a wrong dataSeed still produces output (garbage indistinguishable from valid plaintext), and the MAC tag encrypted inside the container makes MAC verification failure indistinguishable from "no MAC present" or "wrong seed entirely."

- **Chosen-Plaintext Resistance.** Attacker can encrypt with their own seed and study their own configuration map. Knowledge of one seed's map provides zero information about any other seed's map, assuming independently generated seeds.

## RGBWYOPA Pixel Format

- **8-Channel Architecture.** Each pixel has 8 channels (Red, Green, Blue, White, Yellow, Orange, Purple, Alpha — mnemonic labels for an 8-byte unit; the format is not tied to image processing) × 8 bits = 64 bits. Each channel carries 7 data bits and 1 noise bit, yielding 56 data bits per pixel at 1.14× overhead (64/56). 8 channels ensures DataBitsPerPixel (56) is byte-aligned, enabling race-free parallel encode and decode.

- **Dynamic Noise Position.** Per-pixel choice of noise bit position (any of 0-7) in each channel, determined by chained hash of seed + nonce + pixel index. No bit position is deterministically data from the public format, eliminating FORMAT+KPA attack surface.

- **Per-Bit XOR.** Each data bit has its own independent XOR mask bit (56 XOR bits per pixel). This ensures any observed channel value is consistent with any plaintext under some XOR configuration, providing information-theoretic known-plaintext resistance. Total configuration: 62 bits per pixel (3 noise-position from noiseSeed + 59 from dataSeed: 3 rotation + 56 XOR).

- **Seed-Dependent Start Pixel.** Data embedding begins at a pseudo-random pixel offset derived from startSeed + nonce, wrapping around the container.

- **Full Container Utilization.** Every pixel in the container participates — no boundary between "data region" and "empty region."

- **Per-Pixel Hashing.** Two ChainHash calls per pixel (noiseSeed: 3 of 64 bits; dataSeed: 59 of 64 bits), plus one per message (startSeed: pixel offset). Ensures every data bit receives an independent XOR mask.

## Oracle-Free Deniability

- No magic bytes or file format signatures.
- No message length header.
- No checksum or MAC in the core construction. Integrity via `EncryptAuthenticated128` / `EncryptAuthenticated256` / `EncryptAuthenticated512`. MAC encrypted inside container, preserving deniability.
- Null terminator encrypted — invisible without correct seed.
- No padding required — triple-seed rotation barrier provides protection without padding schemes.
- Wrong seed produces random-looking output with no verification oracle.

MAC + Silent Drop also preserves oracle-free deniability — the attacker receives no verification response.

## Map Space Exceeds Key Space

Direct guessing of the per-pixel configuration map requires 2^(62P) attempts where P = pixel count (62 config bits per pixel: 3 noise-position + 3 data-rotation + 56 per-bit XOR). Minimum pixel count depends on mode: `ceil(keyBits / log₂(56))` for Encrypt/Stream (guarantees 56^P > 2^keyBits), `ceil(keyBits / log₂(7))` for Auth (guarantees 7^P > 2^keyBits). For 1024-bit key: 177 pixels (P = 196 at 14×14) for Encrypt/Stream, 365 pixels (P = 400 at 20×20) for Auth. Map space 2^12152 (P=196) to 2^24800 (P=400) >> 2^1024 key space. Brute-forcing the seed is the attacker's most efficient known path.

## Triple-Seed Isolation Validation

- **Runtime enforcement.** All 36 public functions (Encrypt/Decrypt/EncryptAuthenticated/DecryptAuthenticated/EncryptStream/DecryptStream × 3 widths × 2 modes: Single Ouroboros with 3-seed validation, Triple Ouroboros with 7-seed validation) validate that all seed pointers are distinct. Passing the same seed as multiple parameters returns an error, preventing accidental nullification of seed isolation.

## Design Principles

- **Zero Dependencies.** Only Go standard library packages. Hash functions are user-supplied.
- **Single Package.** All types and functions in one flat package.
- **Explicit Over Implicit.** No default hash function. User must explicitly choose their hash function, hash width, and key size.
- **Binary Safe.** Arbitrary data including 0x00 bytes — not limited to text.
- **No Code Sharing Between Widths.** Each hash width variant (128/256/512) has its own process/processChunk implementation. This avoids virtual dispatch per pixel and ensures maximum performance at the cost of ~160 lines of duplicated logic.
