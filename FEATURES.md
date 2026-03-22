# ITB Features

> **Disclaimer.** ITB is an experimental construction without peer review or formal certification. The information-theoretic barrier is a software-level property — it provides no guarantees against hardware-level attacks (DPA/SPA, Spectre, Meltdown, cache timing). Non-cryptographic hash functions are intended solely for research purposes; using them in any real-world application is potentially dangerous and may compromise all security properties. For production use, only PRF-grade hash functions are recommended. No warranty is provided.

## Core Construction

- **Chained Hash Architecture.** N independent uint64 key components processed sequentially through a pluggable hash function. Each round feeds the previous output XOR'd with the next component. Each component is independent (no key-schedule relationships between components) — compromising one component reveals nothing about others. Designed to resist meet-in-the-middle attacks through three independent barriers: unobservable hash output, non-invertibility, and multi-call key discrimination.

- **Pluggable Hash Function.** The library accepts hash functions at four widths: `HashFunc` (64-bit), `HashFunc128` (128-bit), `HashFunc256` (256-bit), `HashFunc512` (512-bit). No built-in hash implementations, no external dependencies. Users supply XXH3, SipHash-2-4, BLAKE3, AES-CMAC, or any conforming function. The construction requires only five properties: full input sensitivity, chain survival, non-affine mixing, avalanche, and non-invertibility — PRF/PRP/PRG properties are relaxed under the random-container model, though PRF-grade hash functions are recommended for production use (see SCIENCE.md Section 2.4, 2.10).

- **Four Hash Width Variants.** Parallel API sets for 64-bit (`Encrypt`/`Decrypt`), 128-bit (`Encrypt128`/`Decrypt128`), 256-bit (`Encrypt256`/`Decrypt256`), and 512-bit (`Encrypt512`/`Decrypt512`). All share the same pixel format, COBS framing, and security properties. ChainHash128 uses 2 components per round (128-bit intermediate state), ChainHash256 uses 4 components per round (256-bit intermediate state), ChainHash512 uses 8 components per round (512-bit intermediate state). Wider intermediate state enables higher effective key sizes.

- **Dynamic Key Size.** 512 to 2048 bits. Alignment depends on hash width: 64-bit multiples for `Seed`, 128-bit multiples for `Seed128`, 256-bit multiples for `Seed256`, 512-bit multiples for `Seed512`. Effective security upper-bounded by `min(keyBits, hashInternalState × numRounds)`. With BLAKE3 (256-bit internal state): 2048-bit effective security (no bottleneck). With AES/SipHash-2-4 (128-bit): 1024 bits. With XXH3 (64-bit): 512 bits.

- **128-bit Per-Message Nonce.** Generated from `crypto/rand` on every encryption call. Mixed into every hash invocation. Mandatory — prevents pixel configuration reuse across messages. Birthday collision after ~2^64 messages.

- **COBS Binary Framing.** Internal Consistent Overhead Byte Stuffing encodes arbitrary binary data (including 0x00 bytes) so that 0x00 never appears in encoded output. Overhead ~0.4%. Enables null terminator as unambiguous message boundary. Encrypt files, archives, images, executables, protocol buffers, or any binary format.

## Information-Theoretic Barrier

- **Random Container.** Container pixels generated from `crypto/rand`. The distribution of pixel values is identical before and after embedding, because both container and modifications are random.

- **Hash Independence.** The random container creates an information-theoretic barrier: the hash output is consumed by a modification of a random pixel and is not reconstructible from passive observations (COA, KPA). PRF-grade hash functions are strongly recommended for production use. The construction's architecture theoretically permits weaker hash functions (satisfying only Requirements 1-5) for research purposes. Five requirements — all universally applied, weaker than PRF/PRP/PRG — are needed for active attack resistance (CCA, MITM, side-channel): (1) full input sensitivity, (2) chain survival, (3) non-affine mixing, (4) avalanche, (5) non-invertibility. The excluded class: constant, XOR-cancelling, partial-input, affine, non-avalanche, and invertible functions (see SCIENCE.md Section 2.4, Definition 2).

- **Known-Plaintext Resistance (under passive observation).** Even with fully known plaintext, the attacker cannot derive hash outputs because original container pixel values are unknown (crypto/rand, never transmitted). Attack degrades to brute-force regardless of hash function.

- **Chosen-Plaintext Resistance.** Attacker can encrypt with their own seed and study their own configuration map. Knowledge of one seed's map provides zero information about any other seed's map, assuming independently generated seeds.

## RGBWYOPA Pixel Format

- **8-Channel Architecture.** Each pixel has 8 channels (Red, Green, Blue, White, Yellow, Orange, Purple, Alpha) × 8 bits = 64 bits. Each channel carries 7 data bits and 1 noise bit, yielding 56 data bits per pixel at 1.14× overhead (64/56). 8 channels ensures DataBitsPerPixel (56) is byte-aligned, enabling race-free parallel encode and decode.

- **Dynamic Noise Position.** Per-pixel choice of noise bit position (any of 0-7) in each channel, determined by chained hash of seed + nonce + pixel index. No bit position is deterministically data from the public format, eliminating FORMAT+KPA attack surface.

- **Per-Bit XOR.** Each data bit has its own independent XOR mask bit (56 XOR bits per pixel). This ensures any observed channel value is consistent with any plaintext under some XOR configuration, providing information-theoretic known-plaintext resistance. Total configuration: 62 bits per pixel (3 noise-position from noiseSeed + 59 from dataSeed: 3 rotation + 56 XOR).

- **Seed-Dependent Start Pixel.** Data embedding begins at a pseudo-random pixel offset derived from startSeed + nonce, wrapping around the container.

- **Full Container Utilization.** Every pixel in the container participates — no boundary between "data region" and "empty region."

- **Per-Pixel Hashing.** Two ChainHash calls per pixel (noiseSeed: 3 of 64 bits; dataSeed: 59 of 64 bits), plus one per message (startSeed: pixel offset). Ensures every data bit receives an independent XOR mask.

## Oracle-Free Deniability

- No magic bytes or file format signatures.
- No message length header.
- No checksum or MAC in the core construction. Integrity via `EncryptAuthenticated` / `EncryptAuthenticated128` / `EncryptAuthenticated256` / `EncryptAuthenticated512`. MAC encrypted inside container, preserving deniability.
- Null terminator encrypted — invisible without correct seed.
- No padding required — triple-seed rotation barrier provides protection without padding schemes.
- Wrong seed produces random-looking output with no verification oracle.

## Map Space Exceeds Key Space

Direct guessing of the per-pixel configuration map requires 2^(62P) attempts where P = pixel count (62 config bits per pixel: 3 noise-position + 3 data-rotation + 56 per-bit XOR). Minimum pixel count for full key utilization: `ceil(keyBits / (Channels - 1))` — for 512-bit key with 8 channels: 74 pixels (P = 81 at 9×9). Map space 2^5022 >> 2^512 key space. Brute-forcing the seed is the attacker's most efficient known path.

## Triple-Seed Isolation Validation

- **Runtime enforcement.** All 24 public functions (Encrypt/Decrypt/EncryptAuthenticated/DecryptAuthenticated/EncryptStream/DecryptStream × 4 widths) validate that all three seed pointers are distinct. Passing the same seed as multiple parameters returns an error, preventing accidental nullification of triple-seed isolation.

## Design Principles

- **Zero Dependencies.** Only Go standard library packages. Hash functions are user-supplied.
- **Single Package.** All types and functions in one flat package.
- **Explicit Over Implicit.** No default hash function. User must explicitly choose their hash function, hash width, and key size.
- **Binary Safe.** Arbitrary data including 0x00 bytes — not limited to text.
- **No Code Sharing Between Widths.** Each hash width variant (64/128/256/512) has its own process/processChunk implementation. This avoids virtual dispatch per pixel and ensures maximum performance at the cost of ~240 lines of duplicated logic.
