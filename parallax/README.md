# parallax — Horizontal cipher multiplexing over a configurable palette

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB and parallax are configured with, not conferred by either construction itself.

## What parallax does

Parallax does **not** strengthen any individual cipher's per-segment keystream. Plaintext is split into fixed-size segments and each segment is XORed under one counter-mode keystream chosen from a user-configured palette by a per-message keyed schedule. The **per-segment floor** is the cipher assigned to that segment — for a segment encrypted under slot k, the adversary's task on that segment is no harder than breaking cipher k in isolation. The package's value is **vendor and jurisdictional diversity**: a deployed pipeline can avoid baking in a single foreign algorithm by mixing regionally-certified primitives across slots so that no one certifier owns the keystream layer.

The defense-in-depth contribution is **multiplicative across the palette**. The anchor primitive `palette[0]` drives the KDF that derives every per-slot subkey and the scheduling subkey from the master; under the PRF assumption on the anchor's KDF, a key-recovery attack against one palette cipher recovers only that slot's subkey — not the master, not the scheduling subkey, not any other slot's subkey. The recovered slot then exposes only the segments that fall on it, and identifying those segments requires brute-forcing the schedule permutation (`log₂(N!)` bits — small but non-zero) combined with a plaintext-validity oracle. Parallax is best understood as a transparent envelope that dilutes exposure to a single primitive's catastrophic break across the full palette, not as a cryptographic upgrade over a single strong primitive.

Parallax is **Non-AEAD** by design. The single-message wire is `nonce(16) ‖ ciphertext_body`; the streaming wire is a concatenation of per-chunk frames whose 4-byte length prefix is unauthenticated. MAC composition is an upstream concern; compose parallax under ITB's authenticated transport (Easy Mode or Streaming AEAD) when wire integrity is required.

## No baked foreign algorithm

The schedule subkey, every per-slot subkey, and the Fisher-Yates seed all derive through `palette[0]` — the **anchor primitive**. Every byte of control material (per-slot keys for the keystream layer, the seed expanded into a per-message slot permutation) is produced by the anchor's KDF construction; no other primitive participates in the schedule's derivation path. A palette whose anchor is a regionally-certified primitive therefore carries zero foreign algorithm anywhere in parallax's control logic. The slot keystreams themselves are each cipher's own construction; the mix is the user's choice.

## Palette selection

Any primitive registered with the `ctr` package — that is, every entry accepted by `ctr.NewResettable` — is a valid palette slot. The palette is order-sensitive: `palette[0]` is the anchor primitive used as the KDF PRF for every slot derivation and as the keystream for the per-message schedule seed. The remaining slots are referenced by their position in the palette under the per-message schedule. Duplicate names in distinct slots are accepted and draw independently-keyed instances — useful when the deployment requires a homogeneous palette (for example a fully-AES palette for jurisdictional reasons), in which case the palette stays safe but the vendor-diversity goal is forgone.

Per-cipher key and nonce sizes are owned by `ctr`; see [`../ctr/README.md`](../ctr/README.md) and [`../ctr/CONSTRUCTIONS.md`](../ctr/CONSTRUCTIONS.md) for the authoritative sizing reference. Parallax does not need a separate per-cipher table — the on-wire nonce is always 16 bytes regardless of palette mix and is truncated to each slot cipher's native width internally.

## Public API

```go
type Schedule struct{ /* … */ }
type Cipherset struct{ /* … */ }

const (
    NonceSize          = 16
    MasterKeySize      = 32
    DefaultSegmentSize = 4093
    DefaultChunkSize   = 16 << 20
    MinPaletteSize     = 3
    MaxPaletteSize     = 255
    MaxCipherNameLen   = 12
    MaxSegmentSize     = 65535
    MaxChunkSize       = 256 << 20
)

func NewSchedule(palette []string, segmentSize int) (*Schedule, error)
func GenerateMasterKey() ([]byte, error)
func NewCipherset(master []byte, schedule *Schedule) (*Cipherset, error)

func (s *Schedule) Palette() []string
func (s *Schedule) PaletteSize() int
func (s *Schedule) SegmentSize() int
func (s *Schedule) SetSegmentSize(n int) error
func (s *Schedule) ChunkSize() int
func (s *Schedule) SetChunkSize(n int) error

func (s *Schedule) Encrypt(plaintext []byte, cs *Cipherset) ([]byte, error)
func (s *Schedule) Decrypt(ciphertext []byte, cs *Cipherset) ([]byte, error)
func (s *Schedule) EncryptInPlace(buf []byte, cs *Cipherset) ([]byte, error)
func (s *Schedule) DecryptInPlace(wire []byte, cs *Cipherset) ([]byte, error)

func (s *Schedule) NewEncryptWriter(cs *Cipherset, dst io.Writer) (io.WriteCloser, error)
func (s *Schedule) NewDecryptWriter(cs *Cipherset, dst io.Writer) (io.WriteCloser, error)
func (s *Schedule) NewEncryptReader(cs *Cipherset, src io.Reader) (io.ReadCloser, error)
func (s *Schedule) NewDecryptReader(cs *Cipherset, src io.Reader) (io.ReadCloser, error)
```

- **`Schedule`** is the message-shaped half of the configuration: validated palette, segment size, and streaming chunk size. It is opaque; construct one with `NewSchedule`. Read-only accessors (`Palette`, `PaletteSize`, `SegmentSize`, `ChunkSize`) return its parameters; `SetSegmentSize` and `SetChunkSize` atomically swap one knob without affecting in-flight calls or in-flight streams.
- **`Cipherset`** carries per-slot subkeys and a separate scheduling subkey derived from the master under the schedule's palette. It is opaque; construct one with `NewCipherset`. The same cipherset may be reused across many messages provided the master itself stays in scope and the schedule is unchanged.
- **`NewSchedule`** validates the palette (size, name registry membership, per-name length) and the segment size (positive, at most `MaxSegmentSize`, coprime to the per-mode ITB pipeline period) and returns a `*Schedule` whose single-message API and per-chunk streaming encrypts both route through the supplied `segmentSize`. The streaming chunk size is initialised to `DefaultChunkSize` and is independently adjustable via `SetChunkSize`. The palette is copied; the caller may free or mutate the input slice after the call returns.
- **`GenerateMasterKey`** draws a fresh `MasterKeySize`-byte (32-byte) CSPRNG master secret suitable for `NewCipherset`. The 32-byte length is the **minimum** accepted by `NewCipherset`; callers that already hold a high-entropy secret of any length ≥ 32 bytes (an ML-KEM shared secret, a 64-byte HKDF output, a wrapped key from `wrapper/`) may pass that directly instead. `kdf.Derive` owns the per-anchor truncate / expand policy: bytes past the anchor primitive's KDF key length are not consumed, so passing a 64-byte master under a 32-byte anchor keys the schedule from the first 32 bytes.
- **`NewCipherset`** derives the scheduling subkey under the label `"schedule:0"` and one per-slot subkey per palette entry under the label `"<slot-name>:<1-based-index>"`. The anchor `palette[0]` is the KDF PRF for every derivation; identical palette entries in distinct slots produce distinct subkeys via the index suffix.
- **`Encrypt`** allocates a fresh wire of the form `nonce ‖ ciphertext_body`, draws a 16-byte per-message nonce from `crypto/rand`, copies the plaintext into the body region, and XORs the segment keystreams over it. The returned slice owns its bytes; the input plaintext is untouched.
- **`Decrypt`** reverses `Encrypt`. The 16-byte leading nonce is read from the wire and the body is decrypted into a freshly allocated buffer. A nonce-only wire round-trips as an empty plaintext.
- **`EncryptInPlace`** mutates the supplied buffer: on success the buffer holds the ciphertext body, byte-identical to `wire[NonceSize:]`; on error the buffer is left unchanged. The returned wire is a fresh allocation that prepends the nonce. Suited to hot paths where the caller has just produced a plaintext that need not survive the call.
- **`DecryptInPlace`** strips the leading 16-byte nonce from the wire and decrypts the remainder in place. The wire is mutated; the returned slice is `wire[NonceSize:]`, fully decrypted.
- **`NewEncryptWriter` / `NewDecryptWriter` / `NewEncryptReader` / `NewDecryptReader`** — see "Streaming variants" below.

### Wire format

The single-message on-wire layout is `nonce(16) ‖ ciphertext_body`. The body length matches the plaintext length exactly — parallax adds no per-segment framing, no length prefix, no padding inside a single message. The 16-byte on-wire nonce is independent of palette composition; every slot's keystream consumes its own native nonce width as a leading-byte truncation of the wire nonce.

The streaming surface frames each chunk as `u32_LE(body_len) ‖ nonce(16) ‖ encrypted_body(body_len)` and concatenates frames on the wire; the chunk size is set on the Schedule via `ChunkSize` / `SetChunkSize` (see "Streaming chunk size" below). The decoder rejects any frame whose parsed body length exceeds `MaxChunkSize` before allocating the body buffer, so a truncated or corrupted prefix cannot drive an unbounded allocation. The streaming length prefix is unauthenticated — a single-bit modification to any prefix desynchronises every subsequent frame on the stream; integrity is the caller's responsibility, typically by composing parallax under an authenticated transport.

### Anchor primitive guidance

Because `palette[0]` is doubly loaded — it drives the KDF for every slot and supplies the schedule keystream — pick one of the strongest registered primitives as the anchor. The remaining slots may then mix in regional or below-anchor primitives to satisfy the deployment's diversity requirements without weakening the derivation path.

## Segment size

Segment size `S` must satisfy `0 < S ≤ MaxSegmentSize` (65535) and `gcd(S, 504) == 1`, where 504 is the per-mode ITB pipeline-period upper bound. The coprime constraint prevents resonant alignment between parallax segment boundaries and the inner ITB pipeline period across every supported mode; the cap itself fails the coprime check (`gcd(65535, 504) = 3`), so the largest accepted value is `65533`. Throughput grows with `S` and plateaus before the cap; small values keep per-segment cipher granularity high at a measurable per-byte cost.

| S | gcd(S, 504) | accepted |
|---|---:|:---:|
| 4093 (`DefaultSegmentSize`) | 1 | yes |
| 11, 13, 17, 19, 23, 251 | 1 | yes |
| 16381, 65521 | 1 | yes |
| 14, 15, 18, 21 | >1 | no |

Any positive coprime value within the upper bound is accepted; prime choices in the 17–64 range are reasonable when a tighter per-segment cipher granularity is needed than the default offers.

### Streaming chunk size

The streaming surface operates as a loop over the Single Message path: each chunk is independently encrypted via `EncryptInPlace` and framed on the wire as a 4-byte little-endian body-length prefix followed by the 16-byte nonce and the encrypted body. The plaintext budget per chunk is the Schedule's `ChunkSize`, initialised to `DefaultChunkSize` (16 MiB) to mirror ITB's `DefaultChunkSize`. `SetChunkSize(n)` swaps the value for subsequently-constructed streams; in-flight streams keep the value captured at construction time, and `n` must satisfy `0 < n ≤ MaxChunkSize` (256 MiB). Each frame self-describes its body length, so the decrypt side does not need to know the encrypter's chunk size — a stream produced under any chunk size decrypts under any chunk size on the receiving Schedule.

`MaxChunkSize` is a parallax-internal sanity cap and is independent of any surrounding transport's chunk-size limit. The two layers exchange a byte stream — parallax frame boundaries are invisible to the outer transport — so the chunk sizes do not need to match. For parallax composed under an authenticated transport (ITB Easy Mode or Streaming AEAD), the effective ceiling is `min(parallax.MaxChunkSize, transport.MaxChunkSize)`; setting parallax's chunk size above the transport's cap pays memory pressure on the parallax writer's accumulator with no observable benefit downstream. A practical default for the composed case is to match parallax's chunk size to the surrounding transport's chunk size.

## Palette size

Palette size `N` satisfies `MinPaletteSize ≤ N ≤ MaxPaletteSize` (3 ≤ N ≤ 255). The upper bound fits the slot index inside a single byte and keeps the derivation label suffix bounded. Each palette name is non-empty and at most `MaxCipherNameLen` (12) characters. Duplicates are permitted: a deployment that requires a homogeneous palette of one cipher repeated across every slot (for instance for jurisdictional reasons) is accepted by the construction — the diversity goal is then forgone, but the encryption itself remains safe at the floor of `min(palette)`, which in that case is simply the one palette cipher.

### Heterogeneous-palette guidance

Throughput of a mixed palette is dominated by the multiset of primitives populating its slots rather than by the palette size. A palette of top-rank PRFs runs ~60 % above a palette of slower primitives at the same N; permutation order is essentially noise once the multiset is fixed. Practical implications:

- Pick primitives close in throughput when possible. A palette that mixes a strong PRF with a noticeably slower one drags the per-message wall time toward the slower entry.
- Choose the registry's fastest entry as `palette[0]` when possible — the anchor's per-message work (schedule-seed expansion + per-slot KDF derivation) is amortised across every encrypt under the cipherset, and a fast anchor keeps that one-time cost negligible.
- Permutation order does not measurably change throughput; place the KDF anchor in slot 0 and order the remaining slots for readability.

See [BENCH.md](./BENCH.md) for the empirical heterogeneous-palette numbers across `fast-mix` / `balanced` / `slow-mix` compositions and for the per-primitive contribution to mixed-palette throughput.

## Threat model

- **Per-byte floor.** Each segment is XORed under exactly one slot's keystream. An adversary recovering one segment's plaintext under the slot-s cipher does so at the cost of breaking cipher `s` in isolation; the floor across all segments is the weakest cipher in the palette.
- **Schedule entropy.** The per-message schedule selects a permutation of `{0, …, N-1}` from a 16-byte seed expanded by `palette[0]` under the message nonce. The schedule contributes at most `log₂(N!)` bits of unknown-to-the-adversary structure per message — small. Treat the schedule as defense-in-depth, not as a primary source of confidentiality.
- **Nonce uniqueness.** Every `Encrypt` / `EncryptInPlace` call draws a fresh 16-byte CSPRNG nonce. Each slot's keystream consumes a truncation of that nonce as its native nonce; under a fresh per-message wire nonce, every per-slot stream is fresh as well. Do not reuse the wire nonce across messages — the helpers always generate one internally, so caller-side discipline is reduced to "do not bypass the helpers".
- **Defense-in-depth scope.** Recovery of one slot's subkey through a key-recovery attack on the corresponding cipher does not yield the master, the scheduling subkey, or any other slot's subkey — under the PRF assumption on the anchor primitive's KDF, the per-slot derivations are pairwise independent labels under one master. Plaintext recovery from a single recovered slot subkey is therefore bounded by the schedule permutation entropy (`log₂(N!)` bits, `~18` for N=9) plus the requirement that the attacker can identify schedule guesses through a plaintext-validity oracle, and exposes only the segments that fall on the recovered slot.
- **No integrity.** Parallax does not authenticate. The single-message wire carries a nonce and a ciphertext body and nothing else; the streaming wire adds an unauthenticated length prefix per frame. Composing a MAC at an outer layer — or using the ITB AEAD path — is the source of integrity when both layers are in use.

## Performance characterization

Throughput cost is approximately `N` times a single-cipher CTR pass divided by N parallel workers: each slot's keystream is advanced through its assigned share of the body, and a per-slot share averages `1/N` of the total bytes. Each per-worker keystream-setup step constructs one resettable keystream per palette entry; segments dispatch to their assigned slot's keystream and reseat its counter to the segment's absolute byte offset before XOR. The construction is worker-parallel up to `min(GOMAXPROCS, 32)`, capped independently of palette size `N`; below an internal byte threshold the loop runs serially in the caller's goroutine to avoid amortising the per-worker keystream-setup cost over too few segments.

The in-place entries (`EncryptInPlace`, `DecryptInPlace`) are the zero-body-allocation path. `EncryptInPlace` does one fresh allocation for the returned wire (to expose the encrypted body in a contiguous nonce-prefixed slice); the body XOR itself touches no fresh heap. `DecryptInPlace` makes no body allocation at all and returns a sub-slice of the wire. Empirical EncryptInPlace and Encrypt run within a few percent of each other across the registry — see [BENCH.md](./BENCH.md) for the per-primitive numbers.

## Usage

```go
package main

import (
    "fmt"

    "github.com/everanium/itb/parallax"
)

func main() {
    // Three-slot palette mixing two families. Pick a strong anchor —
    // palette[0] is doubly loaded (KDF PRF + schedule keystream).
    palette := []string{"areion512", "chacha20", "aescmac"}

    schedule, err := parallax.NewSchedule(palette, parallax.DefaultSegmentSize)
    if err != nil {
        panic(err)
    }

    master, err := parallax.GenerateMasterKey()
    if err != nil {
        panic(err)
    }
    // Alternative — pass an externally-derived secret directly. Any high-
    // entropy byte slice is accepted; per-primitive key sizing happens
    // inside kdf.Derive, parallax does not pre-process the master.
    // master := sharedSecret // e.g. 32 bytes from crypto/mlkem (Encapsulate)

    cs, err := parallax.NewCipherset(master, schedule)
    if err != nil {
        panic(err)
    }
    // After NewCipherset returns, cs holds only the derived per-slot
    // subkeys and the scheduling subkey; the master itself is no longer
    // needed. Zeroize it before it leaves scope to keep its bytes off the
    // heap residue:
    // for i := range master { master[i] = 0 }

    plaintext := []byte("any text or binary data — including 0x00 bytes")

    wire, err := schedule.Encrypt(plaintext, cs)
    if err != nil {
        panic(err)
    }
    // wire is `nonce(16) || ciphertext_body`, len(wire) = 16 + len(plaintext).

    recovered, err := schedule.Decrypt(wire, cs)
    if err != nil {
        panic(err)
    }

    // Rotation — feed a fresh master through the same schedule; the old
    // cipherset and its subkeys are simply dropped. The Schedule itself
    // (palette + segment size) is deployment-config and survives rotation:
    // newMaster := nextSharedSecret // e.g. a follow-up ML-KEM encapsulation
    // csRotated, _ := parallax.NewCipherset(newMaster, schedule)
    // for i := range newMaster { newMaster[i] = 0 }

    fmt.Printf("round-trip ok: %t\n", string(recovered) == string(plaintext))
}
```

### In-place variant

```go
buf := append([]byte(nil), plaintext...) // owned copy the caller may mutate

wire, err := schedule.EncryptInPlace(buf, cs)
if err != nil {
    panic(err)
}
// After the call, buf holds the ciphertext body and equals wire[parallax.NonceSize:].

recovered, err := schedule.DecryptInPlace(wire, cs)
if err != nil {
    panic(err)
}
// recovered aliases wire[parallax.NonceSize:]; the wire is mutated in place.
_ = recovered
```

### Streaming variants

Four `io.ReadCloser` / `io.WriteCloser` constructors layer a per-chunk framing over the Single Message path. The Reader-shape pair (`NewEncryptReader` / `NewDecryptReader`) wraps an upstream `io.Reader`; the Writer-shape pair (`NewEncryptWriter` / `NewDecryptWriter`) wraps a downstream `io.Writer`. Each chunk of up to `ChunkSize` plaintext bytes is one independent `EncryptInPlace` call; its output on the wire is `u32_LE(body_len) || nonce(16) || encrypted_body(body_len)`, and the whole stream is the concatenation of those frames.

`Close` on the writer variants flushes any pending partial chunk and releases pooled scratch space; it must be called whenever the total plaintext is not a multiple of the chunk size. A second `Close` returns nil (idempotent). Once a writer surfaces an underlying error (encrypt failure, length-prefix outside the accepted range, `dst.Write` failure), it enters a sticky-failed state: every subsequent `Write` and the first `Close` return the same error and no further frames are emitted. `Close` on the reader variants releases pool buffers; callers that always read to `io.EOF` may omit it, but early-termination callers must call `Close` to avoid pool-buffer pressure. Repeated calls to `Close` are idempotent.

```go
// Pre-inner ITB compose — Reader-side encrypt feeds an outer
// (*easy.Encryptor).EncryptStreamAuthIO src argument; parallax wraps the plaintext
// side so each segment hits one cipher from the palette before the inner
// construction sees it.
src := bytes.NewReader(plaintext)
encReader, err := schedule.NewEncryptReader(cs, src)
if err != nil {
    panic(err)
}
defer encReader.Close() // releases pool buffers; harmless to call after EOF
// Pass encReader as the src to enc.EncryptStreamAuthIO(..., encReader, &dst, ...),
// where enc is an *easy.Encryptor constructed earlier in the program.

// Pre-inner ITB compose — Writer-side decrypt drains the recovered plaintext from
// (*easy.Encryptor).DecryptStreamAuthIO into a parallax decrypt writer; the writer
// reverses the per-segment XOR and forwards the original plaintext to dst.
var dst bytes.Buffer
decWriter, err := schedule.NewDecryptWriter(cs, &dst)
if err != nil {
    panic(err)
}
defer decWriter.Close() // required to flush the trailing partial-chunk tail
// Pass decWriter as the dst to enc.DecryptStreamAuthIO(..., src, decWriter, ...).
```

## Notes on master-key management

The package does not address master-key distribution; `GenerateMasterKey` exists for self-test and demonstration. In a real deployment the master is shared out-of-band or derived via a separate key-exchange step (an ML-KEM shared secret, for example) and is independent of any ITB seed material the surrounding pipeline carries. The master is passed verbatim to `NewCipherset`; per-primitive key sizing — truncating a longer master to the anchor's required width, or deterministically stretching a 32-byte master to 64 bytes for the wider PRFs — is the job of `kdf.Derive`, not of this package. Any high-entropy byte slice of at least `MasterKeySize` bytes is therefore a valid master regardless of the anchor primitive's native key width.

The same master MAY be reused across many messages under one schedule provided each message draws a fresh CSPRNG nonce — the helpers always generate one internally, so the contract is enforced by construction. The master may be zeroized in caller scope as soon as `NewCipherset` returns; the cipherset retains only the derived subkeys. Rotating the master is a fresh `NewCipherset(newMaster, schedule)` against the unchanged schedule — the old cipherset is dropped along with its subkeys, and the schedule's palette and segment size are preserved.

## What this is not

- Not an integrity layer. Parallax does not authenticate; the wire carries only the nonce and the ciphertext body, plus the unauthenticated per-frame length prefix on the streaming surface. Compose a MAC at an outer layer, or use the ITB AEAD path, when integrity is required.
- Not a cryptographic upgrade over its strongest palette member. The per-segment floor is the cipher assigned to that segment. The package's contribution is vendor and jurisdictional diversity (regulatory posture across the palette) plus a multiplicative defense-in-depth in which recovery of one slot's subkey does not yield the master, the scheduling subkey, or any other slot's subkey under the PRF assumption on the anchor primitive's KDF.
- Not a substitute for ITB's content-deniability. ITB still provides the unconditional content-deniability against a wire-side adversary; parallax adds vendor-diversity on top of that property when configured with a mixed palette.
