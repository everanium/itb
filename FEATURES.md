# ITB Features

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

## Core Construction

- **Triple Ouroboros.** The shipped surface is Triple: every message is split across three independent Ouroboros snakes (three independent dataSeeds plus three independent startSeeds, bound alongside one noiseSeed and one lockSeed at the API surface — 8 mandatory seeds total). Byte-splitting distributes plaintext bytes across the three snakes so any single-snake compromise reveals a non-contiguous slice; the shared noiseSeed / lockSeed slots key the CCA barrier and the Interlocked Barrier overlay.

- **Interlocked Barrier (always-on, non-disableable overlay).** A per-chunk PRF-keyed bit-permutation overlay operates over 48-bit chunks with a mask-triple popcount of 16-of-48 each. The mask-space cardinality per chunk is ≈ 2^70.20 (product of arrangement count A = 2,254,848,913,647 and reduction constant B = 601,080,390), drawn deterministically from the lockSeed and nonce via one PRF call per chunk group (BMI2 PEXT / PDEP hardware path on x86, pure-Go fallback elsewhere). A and B are chosen so that gcd(A, B) = 66,861 — a designed anti-collapse trap that denies attackers a small quotient group they could enumerate to reduce the effective mask space. Under any realistic crib coverage the SAT-cryptanalysis instance becomes under-determined at the mask-formulation layer: solver speed is not the bottleneck when the instance itself has no unique solution. The overlay is engaged on every encrypt / decrypt call at every width; there is no runtime toggle to disable it. Build tag `-tags noitbasm` selects the pure-Go path when the assembly kernels cannot be engaged.

- **Microarchitecture floor.** The AVX-512F + AVX-512DQ + VAES + BMI2 assembly path targets Intel Rocket Lake and later (11th-gen i7-11700K minimum) and AMD Zen 4 and later; Zen 3 hosts fall onto the intermediate VAES-only YMM (AVX2) tier for the Areion permutation and take the portable Go path for the remaining ChainHash / Interlocked Barrier kernels. The CGO per-pixel kernel adds a runtime-dispatched GFNI tier on top of that — Tier A (AVX-512F + AVX-512BW + AVX-512VL + GFNI + AVX-512VBMI, 8-pixel batch; Ice Lake+ / Zen 4+) or Tier B (AVX2 + GFNI, 4-pixel batch); hosts below both tiers fall through to portable scalar C. Older x86 microarchitectures and AArch64 hosts run through the pure-Go path for the Interlocked Barrier and ChainHash kernels; the Interlocked Barrier does not currently ship an AArch64 SIMD assembly kernel (Go's assembler carries no SVE2 support).

- **8-Seed Model.** The Triple API consumes 8 independently-keyed ITB seeds per encrypt / decrypt call: `noiseSeed`, `lockSeed`, `dataSeed1..3`, `startSeed1..3`. Compromising any one seed reveals nothing about the others (independent key components; no key-schedule relationships). The lockSeed routes the per-chunk Interlocked Barrier PRF closure through its own dedicated seed slot, isolating the bit-permutation channel's keying material and PRF primitive from the noiseSeed's.

- **Areion-SoEM-256/512 PRF (recommended default).** Beyond-birthday-bound formally proven PRF based on AES round functions (Sum-of-Even-Mansour construction). Built-in 4-way batched dispatch (`AreionSoEM256x4` / `AreionSoEM512x4`) selects the most capable hardware-AES tier at runtime — AVX-512+VAES on ZMM (one VAESENC per round across 4 lanes simultaneously), AVX2+VAES on YMM (two 2-block VAESENC per round, covers AMD Zen 3 and Alder Lake E-cores), ARM Crypto Extension on AArch64 (4-lane parallel `AESE` / `AESMC` across NEON registers; AWS Graviton 2+, Apple M1+, Neoverse N1+ / V1+ / V2+), or portable Go fallback via `aes.Round4HW` on hosts without any of the above. Bit-exact parity invariant `BatchHash(data)[i] == Hash(data[i])` holds across all four tiers, verified by direct-call parity tests per tier plus a 3-way cross-path parity test on hosts where all implementations are runnable. Recommended primary primitive for production deployments — top-tier throughput at every width plus substantially stronger security guarantees than the lightweight PRF tier.

- **Chained Hash Architecture.** N independent uint64 key components processed sequentially through a pluggable hash function. Each round feeds the previous output XOR'd with the next component. Each component is independent (no key-schedule relationships between components) — compromising one component reveals nothing about others. Designed to resist meet-in-the-middle attacks through three independent barriers: unobservable hash output, non-invertibility, and multi-call key discrimination.

- **Pluggable Hash Function.** The library accepts hash functions at three widths: `HashFunc128` (128-bit), `HashFunc256` (256-bit), `HashFunc512` (512-bit), each paired with a matching `BatchHashFunc{128,256,512}` for the 4-lane batched dispatch on the per-pixel hot path. No built-in hash implementation is compiled in as a default; every registry primitive is opt-in through the shipped `hashes.Make{128,256,512}Pair(name)` factory. Custom primitives plug in at the Low-Level surface by constructing `HashFunc{N}` + `BatchHashFunc{N}` closures and passing them directly to the `*Cfg` entries; the Triple facade does not expose custom primitive injection. PRF required. PRF closes the candidate-verification step; under Full KPA, barrier and architectural layers (eight-seed isolation, encoding ambiguity, independent startSeed) deny the point of application — 3-factor combination under PRF assumption; gcd(7,8)=1 byte-splitting adds a 4th factor under Partial KPA (see [SCIENCE.md Section 2.4](SCIENCE.md#24-information-theoretic-barrier-and-hash-requirements), [2.10](SCIENCE.md#210-hash-function-requirements-analysis), [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)).

- **Three Hash Width Variants.** Parallel Cfg API sets for 128-bit (`Encrypt3x128Cfg` / `Decrypt3x128Cfg` and their authenticated / streaming counterparts), 256-bit (`Encrypt3x256Cfg` / `Decrypt3x256Cfg` and counterparts), and 512-bit (`Encrypt3x512Cfg` / `Decrypt3x512Cfg` and counterparts). All share the same pixel format, COBS framing, and security properties. ChainHash128 uses 2 components per round (128-bit intermediate state), ChainHash256 uses 4 components per round (256-bit intermediate state), ChainHash512 uses 8 components per round (512-bit intermediate state). Wider intermediate state enables higher effective key sizes.

- **Dynamic Key Size.** 512 to 2048 bits. Alignment depends on hash width: 128-bit multiples for `Seed128`, 256-bit multiples for `Seed256`, 512-bit multiples for `Seed512`. Effective security upper-bounded by `min(keyBits, hashInternalState × numRounds)`. With BLAKE3 (256-bit internal state): 2048-bit effective security (no bottleneck). With AES-CMAC / SipHash-2-4 (128-bit): 1024 bits.

- **Per-Message Nonce (128/256/512-bit).** Generated from `crypto/rand` on every encryption call. Default 512-bit (`itb.DefaultNonceBits`) — the birthday bound (~2^256 messages) is mathematically unreachable on any foreseeable hardware, so the safety-out-of-box is maximal without caller override; configurable down to 128 or 256 bits per-Pipeline via `*itb.Config{NonceBits: N}`. Mixed into every hash invocation. Mandatory — prevents pixel configuration reuse across messages.

- **COBS Binary Framing.** Internal Consistent Overhead Byte Stuffing encodes arbitrary binary data (including 0x00 bytes) so that 0x00 never appears in encoded output. Overhead ~0.4%. Enables null terminator as unambiguous message boundary. Encrypt files, archives, images, executables, protocol buffers, or any binary format.

## Shipped Profiles (`triple/` facade)

The `triple.Pipeline` facade ships a catalogue of named profiles covering single-primitive and mixed-primitive constellations; every user-facing example instantiates a pipeline from one of them, and all default to the parallax multiplexer plus the format-deniability wrapper engaged.

1. `streaming-aead-triple-mac-v1` — Streaming AEAD Triple with MAC.
2. `streaming-noaead-triple-v1` — Streaming Non-AEAD Triple.
3. `singlemsg-triple-mac-v1` — Single Message Triple with MAC.
4. `singlemsg-triple-nomac-v1` — Single Message Triple No MAC.
5. `blob-triple-mac-v1` — MAC-authenticated blob-only profile (no cipher surface; used by `Init` / `Rekey` to bundle session state).

## Low-Level Surface (advanced)

Callers that need per-call tuning bypass the facade and drive the `*Cfg` entries directly (`Encrypt3x{128,256,512}Cfg`, `EncryptAuthenticated3x{128,256,512}Cfg`, `EncryptStream3xCfg`, `EncryptStreamAuth3xCfg`, `Blob{128,256,512}.Export3Cfg` / `Import3Cfg`). Every entry takes a `*itb.Config` (nil selects the compile-in defaults from `itb.DefaultNonceBits` / `itb.DefaultBarrierFill` / `MaxWorkers` = auto) plus the 8 seeds explicitly. Custom PRF injection lives here and only here.

## C ABI

The C-shared library exports the Triple facade as 8 `ITB_Triple_*` entries (see `cmd/cshared/main.go`). Every FFI entry that consumes a nonce carries the on-wire nonce byte length as an explicit parameter (`nonce_bytes`) — `ITB_HeaderSize(nonce_bytes)` and `ITB_ParseChunkLen(buf, len, nonce_bytes, out)` are ABI breaks against any pre-v0.3.0 export whose per-instance nonce length was carried by a process-global setter. The default nonce byte length is available through `ITB_DefaultNonceBits()`. The Low-Level `*Cfg` entries do not ship in the C ABI — they remain a Go-native advanced surface.

## Information-Theoretic Barrier

- **Random Container.** Container pixels generated from `crypto/rand`. The marginal distribution of individual pixel values is indistinguishable from uniform before and after embedding, because both container and modifications are random.

- **Encoding Ambiguity.** Each pixel has 7 rotation candidates (0–6) from an independent dataSeed. Across P pixels: 7^P unverifiable combinations (for P = 400 at the unified CCA-resistant envelope floor: 7^400 ≈ 2^1123). This mechanism survives CCA — even if noise positions are revealed, rotation ambiguity remains intact through eight-seed isolation (dataSeed is independent of noiseSeed). See [SCIENCE.md §2.9.2](SCIENCE.md#292-why-kpa-candidates-do-not-break-the-barrier).

- **Guaranteed CSPRNG Residue.** The `side += barrierFill` container construction (`*itb.Config{BarrierFill: N}`, default 1) ensures capacity always exceeds payload — at least (2s+1)×7 bytes of CSPRNG fill are present in every container (≥203 bytes at 1024-bit key). These fill bytes are encrypted by dataSeed identically to plaintext (same rotation + XOR). After CCA removes noise bits, the data channel still contains this CSPRNG residue — the attacker cannot distinguish fill from plaintext, cannot determine where one ends and the other begins. Perfect fill is mathematically impossible. This preserves information-theoretic ambiguity within the data bits even when noise absorption is bypassed. See [Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill).

- **Hash Independence.** The random container creates an information-theoretic barrier: the hash output is consumed by a modification of a random pixel and is not reconstructible from passive observations (COA, KPA). PRF required. PRF closes the candidate-verification step; under Full KPA, barrier and architectural layers (eight-seed isolation, encoding ambiguity, independent startSeed) deny the point of application — 3-factor combination under PRF assumption; gcd(7,8)=1 byte-splitting adds a 4th factor under Partial KPA (see [SCIENCE.md Section 2.4](SCIENCE.md#24-information-theoretic-barrier-and-hash-requirements), [Definition 2](SCIENCE.md#5-formal-definitions), [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)).

- **Known-Plaintext Resistance (under passive observation).** Even with fully known plaintext, the attacker cannot derive hash outputs because original container pixel values are unknown (crypto/rand, never transmitted). Attack degrades to brute-force regardless of hash function. Under Full KPA, the defense is 3-factor under PRF assumption: PRF non-invertibility (candidate verification), independent startSeed (point-of-application isolation — startPixel not transmitted), and 7-rotation × 8-noisePos encoding ambiguity at signal/noise 1:1 per candidate. gcd(7,8)=1 byte-splitting is a 4th factor effective only under Partial KPA (blocks per-channel candidate formulation when adjacent bytes are unknown). A partial weakening of any single layer is not sufficient to mount Full KPA (see [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)).

- **Plausible Deniability.** Decryption with any seed always produces output — there is no structural difference between correct and incorrect decryption. Wrong seeds produce random-looking bytes indistinguishable from valid plaintext without external context. The number of plausible decryptions equals the key space — every seed is a valid candidate. This is a property of the encoding architecture, not of the encryption: data is embedded into a random container, and extraction always succeeds regardless of seed correctness. Classical brute-force and Grover both face an astronomical number of candidates with no efficient way to distinguish the real one (Core ITB / MAC + Silent Drop).

These barrier properties hold fully under Core ITB and MAC + Silent Drop (no oracle). Under MAC + Reveal, noiseSeed config is leaked via CCA (noise **bits** removed — attacker can strip the 1 noise bit per channel), but dataSeed remains fully protected (encoding ambiguity intact). Crucially, removing noise bits does not give the attacker clean plaintext-only data: the remaining data bits contain both encrypted plaintext and encrypted CSPRNG fill, both processed identically by dataSeed. Perfect fill is impossible — the `side += barrierFill` construction (`*itb.Config{BarrierFill: N}`, default 1) guarantees ≥(2s+1)×7 bytes of CSPRNG residue ([Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)). The information-theoretic barrier is partially preserved within the data channel even after CCA. Plausible deniability is preserved in all three modes — even with CCA, decoding with a wrong dataSeed still produces output (garbage indistinguishable from valid plaintext), and the MAC tag encrypted inside the container makes MAC verification failure indistinguishable from "no MAC present" or "wrong seed entirely."

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
- No checksum or MAC in the core construction. Integrity via `EncryptAuthenticated3x{128,256,512}Cfg` (Low-Level) or the `singlemsg-triple-mac-v1` / `streaming-aead-triple-mac-v1` profiles under `triple/`. MAC encrypted inside container, preserving deniability.
- Null terminator encrypted — invisible without correct seed.
- No padding required — the rotation barrier from the independent dataSeeds provides protection without padding schemes.
- Wrong seed produces random-looking output with no verification oracle.

MAC + Silent Drop also preserves oracle-free deniability — the attacker receives no verification response.

## Map Space Exceeds Key Space

Direct guessing of the per-pixel configuration map requires 2^(62P) attempts where P = pixel count (62 config bits per pixel: 3 noise-position + 3 data-rotation + 56 per-bit XOR). Pixel count derives from the unified CCA-resistant envelope floor `ceil(keyBits / log₂(7))` (guarantees 7^P > 2^keyBits). For 1024-bit key: 365 pixels (P = 400 at 20×20). Map space 2^24800 (P = 400) >> 2^1024 key space. Brute-forcing the seed is the attacker's most efficient known path.

## Triple-Seed Isolation Validation

- **Runtime enforcement.** Every Triple `*Cfg` entry (`Encrypt3x{128,256,512}Cfg`, `Decrypt3x{128,256,512}Cfg`, `EncryptAuthenticated3x{128,256,512}Cfg`, `DecryptAuthenticated3x{128,256,512}Cfg`, `EncryptStream3xCfg`, `EncryptStreamAuth3xCfg` and their decrypt counterparts, plus `Blob{128,256,512}.Export3Cfg` / `Import3Cfg`) validates that all 8 seed pointers are distinct. Passing the same seed as multiple parameters returns an error, preventing accidental nullification of seed isolation.

## Design Principles

- **Zero Dependencies.** Only Go standard library packages. Hash functions are user-supplied through the shipped `hashes.Make{128,256,512}Pair` factory or user-plugged custom `HashFunc{N}` + `BatchHashFunc{N}` closures.
- **Single Package.** Core types and functions in one flat package; the `triple/` facade wraps them into the shipped profiles.
- **Explicit Over Implicit.** No default hash function. The user must explicitly choose a hash function, hash width, and key size.
- **Binary Safe.** Arbitrary data including 0x00 bytes — not limited to text.
- **No Code Sharing Between Widths.** Each hash width variant (128/256/512) has its own process / processChunk implementation. This avoids virtual dispatch per pixel and ensures maximum performance at the cost of ~160 lines of duplicated logic.
