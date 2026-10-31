## Building Real Applications with ITB

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB composes established, standardized primitives rather than introducing new cryptographic designs. Security properties and regulatory status are inherited from the underlying primitives; see [README.md](README.md) for jurisdictional certification details.

---

## 1. Architectural Rule: Never Transmit the Secret Session Blob

The byte slice returned by `triple.Init()`, `triple.InitKeys()`, `Pipeline.Save()`, and `Pipeline.Rekey()` is a **secret persistence bundle** (`blobWrapV2`). Alongside the outer profile recipe, it embeds the complete inner `Blob{N}` state: all eight seeds' `Components` tables, the eight per-slot PRF keys, the authentication MAC key, `PermMaster`, and `WrapMaster`.

> **Critical rule for networked applications.** Never transmit the session blob over a network socket or store it on an untrusted relay server — even inside an encrypted transport. Concentrating all eight seed components and layer masters into a single network payload creates a single point of compromise. The session blob exists strictly for local disk persistence via `Pipeline.SaveF` / `triple.LoadF` (`0600` permissions).

In networked protocols such as end-to-end encrypted (E2EE) messaging, peers establish shared key material without ever putting a session blob on the wire:

1. **Deterministic Seed Agreement (`triple.InitKeys`)**: Both endpoints independently derive an identical array of eight 64-byte slot master keys `masters [8][]byte` from an asymmetric key-encapsulation handshake and pass them to `triple.InitKeys(profile, opts, masters)`.
2. **Secret-Free Topology Extraction (`triple.Inspect`)**: When the initiating peer generates a dynamic per-epoch configuration via `triple.Opts`, it passes the returned `blob` to `prof, err := triple.Inspect(blob)` to extract **only** the non-secret `triple.Profile` recipe (primitive names, widths, segment size, container mode, nonce width, and barrier fill) and **immediately zeroes `blob` in memory** (`clear(blob)`).
3. **Split Configuration Transport**: The extracted `triple.Profile` contains zero keys or seed components. Its serialized bytes are sliced into three fragments and masked across three parallel asymmetric channels so that neither the network relay nor a partial asymmetric break can observe the active ITB topology.

```
┌────────────────────────────────────────────────────────────────────────────┐
│                   LOCAL DISK PERSISTENCE vs. NETWORK E2EE                  │
├─────────────────────────────────────┬──────────────────────────────────────┤
│ Local At-Rest Storage (Disk Only)   │ Networked E2EE Protocol (Zero-Blob)  │
├─────────────────────────────────────┼──────────────────────────────────────┤
│ pipe, blob, _ := triple.Init(...)   │ pipe, blob, _ := triple.InitKeys(..) │
│ pipe.SaveF("session.blob") // 0600  │ prof, _ := triple.Inspect(blob)      │
│ clear(blob)                         │ clear(blob) // Wiped immediately!    │
│                                     │                                      │
│ // Blob holds all 8 seeds + keys.   │ // Only non-secret prof fragments    │
│ // Never leaves the local host.     │ // cross the wire (masked by 3 KEMs) │
└─────────────────────────────────────┴──────────────────────────────────────┘
```

---

## 2. Multi-Assurance `3-to-8` Key Agreement (`InitKeys`)

`triple.InitKeys` requires eight pairwise-distinct master keys (`masters[0..7]`), one for each canonical seed slot in the **Triple Ouroboros** bundle:

| Slot Index | Canonical Seed Role | Subsystem Function |
|---|---|---|
| `masters[0]` | `noiseSeed` | Per-pixel 3-bit noise-position selector (`noiseFold3`) |
| `masters[1]` | `lockSeed` | Per-chunk **Rank Barrier** permutation (`48`-bit or `168`-bit under `Interlock = "168"`) |
| `masters[2]` | `dataSeed1` | Region 0 **Pixel Barrier** channel XOR and bit-rotation stream |
| `masters[3]` | `dataSeed2` | Region 1 **Pixel Barrier** channel XOR and bit-rotation stream |
| `masters[4]` | `dataSeed3` | Region 2 **Pixel Barrier** channel XOR and bit-rotation stream |
| `masters[5]` | `startSeed1` | Region 0 container start-pixel offset derivation |
| `masters[6]` | `startSeed2` | Region 1 container start-pixel offset derivation |
| `masters[7]` | `startSeed3` | Region 2 container start-pixel offset derivation |

Running eight separate asymmetric key exchanges per epoch is prohibitive in packet size and latency. Instead, an application runs **three parallel asymmetric KEM channels** chosen from mathematically orthogonal hardness assumptions and expands their three shared secrets into `masters[0..7]` through a two-stage **`3-to-8` Tri-KDF XOR-Fold**:

- **Channel 0 (Classical Elliptic Curve)**: `X25519` ephemeral key exchange → shared secret `kem[0]`, paired with KDF `"blake3"`.
- **Channel 1 (Post-Quantum Structured Lattice)**: `ML-KEM-1024` (FIPS 203) → shared secret `kem[1]`, paired with KDF `"areion512"`.
- **Channel 2 (Post-Quantum Code-Based)**: `HQC-1` (or `Classic-McEliece`) → shared secret `kem[2]`, paired with KDF `"blake2b512"`.

### Two-Stage `3-to-8` Derivation Construction

To guarantee that **compromising any two of the three asymmetric primitives reveals zero bits about any of the eight ITB seeds**, the derivation combines a **7-Subset Combinatorial Partition** with a **3-of-3 Per-Slot Tri-KDF XOR-Fold**:

1. **Stage A — 7 Non-Empty Subset PRKs**: A 3-element set `{0, 1, 2}` has `2^3 - 1 = 7` non-empty subsets (`mask ∈ {1..7}`). Each of the eight ITB seed slots is bound to a canonical subset mask (`slotSubsets = [8]int{1, 2, 4, 6, 5, 3, 7, 7}`), where `subsetPRK[mask]` XOR-folds 64-byte `kdf.Derive` outputs from the channels present in `mask`.
2. **Stage B — 3-of-3 Per-Slot Tri-KDF XOR-Fold**: Every slot `slot ∈ {0..7}` XOR-folds `subsetPRK[slotSubsets[slot]]` with **three independent 64-byte shares** derived from all three KEM secrets across three distinct KDF constructions (`"blake3"`, `"areion512"`, `"blake2b512"`), each bound to the slot index, subset ID, channel ID, and epoch transcript:

```
Channel 0: X25519       ──► kem[0] ──► kdf.Derive("blake3",     kem[0], label[0,slot], 64) ──┐
                                                                                             ├──► (XOR) ──► masters[slot]
Channel 1: ML-KEM-1024  ──► kem[1] ──► kdf.Derive("areion512",  kem[1], label[1,slot], 64) ──┤              (64 bytes)
                                                                                             │
Channel 2: HQC-1        ──► kem[2] ──► kdf.Derive("blake2b512", kem[2], label[2,slot], 64) ──┤
                                                                                             │
7-Subset Partition PRK  ──► subsetPRK[slotSubsets[slot]] ────────────────────────────────────┘
```

### Security under a 2-of-3 Asymmetric Break

- **All-or-Nothing Seed Secrecy**: Because every `masters[slot]` (`slot = 0..7`) is the bitwise XOR of `subsetPRK[slotSubsets[slot]]` and three per-slot 512-bit pseudorandom outputs produced by `"blake3"` on `kem[0]`, `"areion512"` on `kem[1]`, and `"blake2b512"` on `kem[2]`, under the PRF assumption on the unbroken channel's KDF, an adversary who completely breaks **any two of the three** KEMs still faces an independent 512-bit pseudorandom mask from the unbroken third KEM on **every single slot**.
- **All-or-Nothing Layer Master Secrecy**: Inside `triple.InitKeys`, when `Opts.PermMaster` and `Opts.WrapMaster` are omitted, `PermMaster`, `WrapMaster`, and `macKey` are automatically derived via an 8-way XOR fold across all eight slot KDF outputs (`deriveCombinedKey`). Consequently, every inner seed, Parallax schedule, Wrapper key, and MAC key inherits the full 3-of-3 asymmetric security bound.

---

## 3. 3-Part Configuration Slicing via `triple.Inspect`

In a static deployment, both peers hardcode a shipped profile name (such as `triple.ProfileStreamingAEADTripleMACV1`). In an advanced dynamic deployment (**Chameleon Epochs**), the epoch initiator randomizes the ITB topology on every epoch — picking a fresh 8-slot `MixedHashes` constellation, a randomized `ParallaxPalette` and coprime `ParallaxSegmentSize` (for example, `17` bytes so even short chat messages traverse multiple Parallax cipher segments), a fresh `OuterCipher`, `MacName`, `DRBG`, and `BarrierFill`.

To communicate this dynamic topology without leaking it to the relay server or to an attacker who breaks two of the three KEMs, the initiator executes the **Inspect-Slice-Mask** pipeline:

1. **Extract Non-Secret Recipe**: Call `prof, err := triple.Inspect(blob)` and immediately wipe `blob` (`clear(blob)`). The `triple.Profile` struct contains only structural parameters:

| Logical Configuration Domain | `triple.Profile` Fields |
|---|---|
| **Domain 1 — Inner Barrier & Seed Constellation** | `Width`, `InnerHash`, `MixedHashes[0..7]`, `KeyBits`, `Interlock`, `DRBG`, `BarrierFill` |
| **Domain 2 — Pre-Inner Parallax Schedule** | `Parallax`, `ParallaxPalette`, `ParallaxSegmentSize` |
| **Domain 3 — Outer Wrapper & Framing** | `Name`, `Mode`, `ContainerMode`, `NonceBits`, `Wrapper`, `OuterCipher`, `MacName`, `ChunkSize`, `TagStubSize` |

2. **Slice into 3 Equal Structural Fragments**: Serialize `prof` (`raw, _ := json.Marshal(prof)`), pad with trailing whitespace to a multiple of 3 bytes, and slice `raw` into three contiguous 1/3 fragments (`parts[0]`, `parts[1]`, `parts[2]`, ~140 bytes each). Each parallel asymmetric channel carries only one third of the serialized configuration, avoiding any 3x bandwidth amplification.
3. **Cross-Channel 3-of-3 Tri-KDF Masking (Zero AES-GCM Required)**: Mask each fragment `parts[frag]` (`frag = 0, 1, 2`) by XORing it with three keystream pads derived via `kdf.Derive` from all three KEM shared secrets (`"blake3"`, `"areion512"`, `"blake2b512"`). No external `AES-256-GCM` cipher is required, and under the PRF assumption on the unbroken channel's KDF, breaking any two of the three KEMs reveals **zero bytes** of any of the three configuration fragments.
4. **Optional Enterprise Pre-Shared Bootstrap Layer**: In corporate or closed-group deployments with a pre-shared tenant secret (password server or hardware token), the entire 3-KEM epoch handshake packet can additionally be wrapped inside an outer bootstrap `*triple.Pipeline` initialized from the corporate secret, isolating handshake metadata from unauthorized network observers before KEM decapsulation even begins.

```
            triple.InitKeys(baseProfile, dynamicOpts, aliceSeeds)
                                     │
                                     ▼
                       ┌───────────────────────────┐
                       │  Secret Session Blob      │
                       │  (8 Seeds + PRF/MAC Keys) │
                       └─────────────┬─────────────┘
                                     │
                        prof, _ := triple.Inspect(blob)
                        clear(blob)  // Wiped in RAM!
                                     │
                                     ▼
                       ┌───────────────────────────┐
                       │  json.Marshal(prof)       │
                       │  (~420 B, zero secrets)   │
                       └─────────────┬─────────────┘
                                     │
            ┌────────────────────────┼────────────────────────┐
            ▼                        ▼                        ▼
   ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
   │   Fragment 0    │      │   Fragment 1    │      │   Fragment 2    │
   │  (Bytes 0..L)   │      │  (Bytes L..2L)  │      │ (Bytes 2L..3L)  │
   └────────┬────────┘      └────────┬────────┘      └────────┬────────┘
            │                        │                        │
     XOR Tri-KDF Pad          XOR Tri-KDF Pad          XOR Tri-KDF Pad
  (kem[0]^kem[1]^kem[2])   (kem[0]^kem[1]^kem[2])   (kem[0]^kem[1]^kem[2])
            │                        │                        │
            ▼                        ▼                        ▼
    [ct_0 || parts[0]]       [ct_1 || parts[1]]       [ct_2 || parts[2]]
     (X25519 Channel)        (ML-KEM-1024 Chan.)        (HQC-1 Channel)
```

---

## 4. End-to-End Chat Architecture with Versioned Chameleon Epochs

In an end-to-end encrypted chat system built on ITB, the central relay server is **cryptographically blind** to message contents, session keys, and the active epoch's ITB primitive constellation.

```
┌──────────────────────┐                        ┌──────────────────────┐
│    Client A (New)    │                        │    Client B (Old)    │
│    App Schema: 2     │                        │    App Schema: 1     │
└──────────┬───────────┘                        └──────────▲───────────┘
           │                                               │
           │ 1. Fetch peer prekeys + client appVer (= 1)   │
           │    Clamp candidate pool: min(2, 1) = 1        │
           │                                               │
           │ 2. Single Epoch Packet:                       │
           │    [ct_0, parts[0] | ct_1, parts[1] |         │
           │     ct_2, parts[2] | epochID | appVer=1]      │
           ▼                                               │
┌──────────────────────────────────────────────────────────┴───────────┐
│                    UNTRUSTED CHAT RELAY SERVER                       │
│  • Knows: account IDs, room roster, online presence, client appVer   │
│  • Blind to: kem[0..2], masters[0..7], triple.Profile, plaintexts    │
└──────────────────────────────────────────────────────────────────────┘
           ▲                                               ▲
           │ 3. Out-of-Band Identity Verification          │
           └─────── Safety Numbers (Digits) / SAS Emojis ──┘
```

### 1. Server Blindness vs. Operational Metadata

The relay server stores only public prekey bundles (`X25519` public key, `ML-KEM-1024` encapsulation key, `HQC-1` public key), room participant lists, delivery receipts, and each client's advertised application schema integer (`appVer`). All three KEM ciphertexts (`ct_0, ct_1, ct_2`) and the three masked configuration fragments (`parts[0..2]`) travel in a **single atomic epoch handshake packet** so the relay never correlates separate round-trips.

### 2. Application-Level Schema Versioning (`min(appVer_A, appVer_B)`)

ITB itself does not negotiate versions over the wire: its wire format is frozen, and `triple.InitKeys` / `triple.Inspect` consume primitive names as plain strings. Version compatibility across a mixed fleet of chat clients is therefore **managed by the application developer** at the chat protocol layer:

- **Application Schema Mapping (`appVer`)**: When the application developer upgrades the ITB dependency in a new chat client release and wishes to include newly added primitives from `hashes.Registry`, `macs`, or `wrapper.CipherNames` in random chameleon epochs, the developer increments the chat application's own schema integer (`appVer = 2`).
- **Downgrade-Safe Candidate Pool (`min(appVer_A, appVer_B)`)**: If a newer client (`appVer = 2`) randomly selected a newly added primitive in `Opts.MixedHashes` or `Opts.ParallaxPalette` when initiating an epoch with an older client (`appVer = 1`) linked against an earlier ITB build, the older client would reject the unknown primitive name with `triple.ErrRecipePrimitiveUnknown`. To prevent this, the initiator reads the peer's `appVer` from the server, computes `appVer_eff = min(appVer_A, appVer_B)` (or `min(appVer_1 ... appVer_N)` in a group room), and restricts its random generator strictly to the primitive pool defined by the application for `appVer_eff`.
- **Automatic Upgrade**: Once all participants in a conversation update their chat clients, `min(appVer_A, appVer_B)` advances automatically and unlocks the expanded primitive pool on the next epoch ratchet.

### 3. Two-Speed Ratchet Lifecycle (Inter-Epoch KEM + Intra-Epoch `Rekey`)

1. **Inter-Epoch Ratchet (3-KEM + Topology Rotation)**: Triggered every `N` messages (for example, every 50 messages), upon a timer expiration, or when group membership changes. A fresh 3-KEM encapsulation produces new `masters[0..7]` and a newly randomized `triple.Profile`. Once the bounded out-of-order decryption window for the previous epoch closes, the client calls `oldPipe.Close()`, wiping all eight seed component tables, PRF keys, MAC keys, and retained blobs in memory.
2. **Intra-Epoch Ratchet (Per-Message `Pipeline.Rekey`)**: Immediately after the epoch handshake, both peers fold all three KEM secrets into a 64-byte 3-of-3 `ratchetRoot` (`deriveRatchetRoot`) and wipe `kem[0..2]`. Between heavy 3-KEM epochs, clients step a fast symmetric ratchet on every message by deriving fresh 64-byte `(permMaster, wrapMaster)` pairs from `ratchetRoot` and calling `pipe.Rekey(pm, wm)` (immediately wiping the returned blob slice). `Rekey` rebuilds the Parallax segment schedule and Wrapper outer stream key in microseconds without re-running the 8-seed `InitKeys` setup.

### 4. Active MITM Defense via Out-of-Band Safety Numbers / Emoji Verification

Because an untrusted relay server could attempt an active man-in-the-middle (MITM) attack by substituting all three ephemeral public keys (`X25519`, `ML-KEM-1024`, `HQC-1`), clients bind each participant's long-term identity public keys into the epoch `transcript` string fed to every `kdf.Derive` call.

Users verify the hash of both peers' long-term identity bundles out-of-band using **numeric safety numbers (60-digit fingerprint blocks)** or **Short Authentication String (SAS) emoji sequences** (identical in user experience to Signal safety numbers or Matrix emoji verification). If a malicious server substitutes any ephemeral or identity key on the wire, the `transcript` diverges on both endpoints, causing both `joinProfile3` and `DecryptMessage` to fail closed.

---

## 5. Reference Implementation (Go)

The following self-contained Go program demonstrates the complete E2EE chat epoch lifecycle using `github.com/everanium/itb/triple` and `github.com/everanium/itb/kdf`:

1. Deriving eight 64-byte ITB master keys from three parallel KEM shared secrets (`deriveSeeds3to8`) with 2-of-3 compromise resilience;
2. Initializing a dynamic chameleon epoch pipeline (`triple.InitKeys`), extracting only the non-secret `triple.Profile` via `triple.Inspect`, and immediately wiping the secret session blob (`clear(aliceBlob)`);
3. Slicing the serialized `triple.Profile` into three 1/3 fragments and cross-masking them across the three KEM channels (`splitProfile3` / `joinProfile3`);
4. Reconstructing the identical `*triple.Pipeline` on the receiver via `triple.InitKeys`, wiping `kem[0..2]` after deriving the 3-of-3 intra-epoch `ratchetRoot`, exchanging encrypted chat messages, and advancing the per-message symmetric ratchet (`Pipeline.Rekey`).

```go
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/everanium/itb/kdf"
	"github.com/everanium/itb/triple"
)

var (
	channelKDFs = [3]string{"blake3", "areion512", "blake2b512"}
	slotSubsets = [8]int{1, 2, 4, 6, 5, 3, 7, 7}
)

// deriveSeeds3to8 maps 3 independent KEM shared secrets into 8 64-byte ITB slot
// master keys. Combining the 7 non-empty subset PRKs with a 3-of-3 Tri-KDF XOR
// fold across every slot guarantees that compromising any 2 of 3 KEMs reveals
// zero bits about any of the 8 ITB seeds.
func deriveSeeds3to8(kem [3][]byte, transcript string) ([8][]byte, error) {
	var subsetPRK [8][]byte
	for mask := 1; mask <= 7; mask++ {
		subsetPRK[mask] = make([]byte, 64)
		for c := 0; c < 3; c++ {
			if (mask & (1 << c)) == 0 {
				continue
			}
			label := fmt.Sprintf("itb-chat-v1|prk-subset-%d|ch-%d|%s", mask, c, transcript)
			part, err := kdf.Derive(channelKDFs[c], kem[c], label, 64)
			if err != nil {
				return [8][]byte{}, err
			}
			for b := range subsetPRK[mask] {
				subsetPRK[mask][b] ^= part[b]
			}
			clear(part)
		}
	}

	var masters [8][]byte
	for slot := 0; slot < 8; slot++ {
		masters[slot] = make([]byte, 64)
		copy(masters[slot], subsetPRK[slotSubsets[slot]])
		for c := 0; c < 3; c++ {
			label := fmt.Sprintf("itb-chat-v1|slot-%d|sub-%d|ch-%d|%s", slot, slotSubsets[slot], c, transcript)
			share, err := kdf.Derive(channelKDFs[c], kem[c], label, 64)
			if err != nil {
				return [8][]byte{}, err
			}
			for b := range masters[slot] {
				masters[slot][b] ^= share[b]
			}
			clear(share)
		}
	}
	for mask := 1; mask <= 7; mask++ {
		clear(subsetPRK[mask])
	}
	return masters, nil
}

// deriveRatchetRoot folds all 3 KEM shared secrets into a 64-byte intra-epoch
// symmetric ratchet root so kem[0..2] can be wiped immediately after handshake.
func deriveRatchetRoot(kem [3][]byte, transcript string) ([]byte, error) {
	root := make([]byte, 64)
	for c := 0; c < 3; c++ {
		label := fmt.Sprintf("itb-chat-v1|ratchet-root|ch-%d|%s", c, transcript)
		share, err := kdf.Derive(channelKDFs[c], kem[c], label, 64)
		if err != nil {
			return nil, err
		}
		for b := range root {
			root[b] ^= share[b]
		}
		clear(share)
	}
	return root, nil
}

// splitProfile3 takes the non-secret triple.Profile from triple.Inspect(blob),
// slices its serialized bytes into 3 equal fragments (1/3 per asymmetric channel),
// and masks each fragment with a 3-of-3 Tri-KDF pad across all 3 KEM shared secrets.
// Breaking any 2 of 3 KEMs leaks zero bytes of the dynamic epoch configuration.
func splitProfile3(prof triple.Profile, kem [3][]byte, transcript string) ([3][]byte, error) {
	raw, err := json.Marshal(prof)
	if err != nil {
		return [3][]byte{}, err
	}
	for len(raw)%3 != 0 {
		raw = append(raw, ' ')
	}
	partLen := len(raw) / 3
	var parts [3][]byte
	for frag := 0; frag < 3; frag++ {
		parts[frag] = append([]byte(nil), raw[frag*partLen:(frag+1)*partLen]...)
		for c := 0; c < 3; c++ {
			label := fmt.Sprintf("itb-chat-v1|cfg-frag-%d|ch-%d|%s", frag, c, transcript)
			pad, err := kdf.Derive(channelKDFs[c], kem[c], label, partLen)
			if err != nil {
				return [3][]byte{}, err
			}
			for i := 0; i < partLen; i++ {
				parts[frag][i] ^= pad[i]
			}
			clear(pad)
		}
	}
	clear(raw)
	return parts, nil
}

func joinProfile3(parts [3][]byte, kem [3][]byte, transcript string) (triple.Profile, error) {
	partLen := len(parts[0])
	if partLen == 0 || len(parts[1]) != partLen || len(parts[2]) != partLen {
		return triple.Profile{}, errors.New("malformed profile fragments")
	}
	raw := make([]byte, 0, partLen*3)
	for frag := 0; frag < 3; frag++ {
		buf := append([]byte(nil), parts[frag]...)
		for c := 0; c < 3; c++ {
			label := fmt.Sprintf("itb-chat-v1|cfg-frag-%d|ch-%d|%s", frag, c, transcript)
			pad, err := kdf.Derive(channelKDFs[c], kem[c], label, partLen)
			if err != nil {
				return triple.Profile{}, err
			}
			for i := 0; i < partLen; i++ {
				buf[i] ^= pad[i]
			}
			clear(pad)
		}
		raw = append(raw, buf...)
		clear(buf)
	}
	var prof triple.Profile
	err := json.Unmarshal(raw, &prof)
	clear(raw)
	return prof, err
}

func optsFromProfile(p triple.Profile) triple.Opts {
	withParallax, withWrapper := p.Parallax, p.Wrapper
	return triple.Opts{
		Mode:                p.ContainerMode,
		Interlock:           p.Interlock,
		WithParallax:        &withParallax,
		WithWrapper:         &withWrapper,
		NonceBits:           p.NonceBits,
		BarrierFill:         p.BarrierFill,
		DRBG:                p.DRBG,
		ChunkSize:           p.ChunkSize,
		MacName:             p.MacName,
		TagStubSize:         p.TagStubSize,
		InnerHash:           p.InnerHash,
		MixedHashes:         p.MixedHashes,
		KeyBits:             p.KeyBits,
		OuterCipher:         p.OuterCipher,
		ParallaxPalette:     p.ParallaxPalette,
		ParallaxSegmentSize: p.ParallaxSegmentSize,
	}
}

func main() {
	// 1. Parallel 3-KEM shared secrets: X25519 (ch0), ML-KEM-1024 (ch1), HQC-1 (ch2).
	var kem [3][]byte
	for c := 0; c < 3; c++ {
		kem[c] = make([]byte, 32)
		_, _ = rand.Read(kem[c])
	}
	transcript := "epoch:42|appVer:min(clientA,clientB)|sas:verified-emoji-hash"

	// 2. Alice derives 8 slot seeds, builds a dynamic chameleon epoch pipeline,
	//    extracts ONLY the non-secret Profile via Inspect, and wipes the secret blob.
	aliceSeeds, err := deriveSeeds3to8(kem, transcript)
	if err != nil {
		panic(err)
	}
	epochOpts := triple.Opts{
		MixedHashes: [8]string{
			"blake3", "areion256", "blake2b256", "blake2s",
			"chacha20", "blake3", "areion256", "blake2b256",
		},
		KeyBits:             512,
		NonceBits:           128,
		Mode:                2,
		OuterCipher:         "chacha20",
		MacName:             "hmac-blake3",
		ParallaxPalette:     []string{"aescmac", "chacha20", "blake3", "areion256"},
		ParallaxSegmentSize: 17,
		DRBG:                "chacha20",
		BarrierFill:         4,
	}
	alice, aliceBlob, err := triple.InitKeys(triple.ProfileStreamingAEADTripleMACMixedV1, epochOpts, aliceSeeds)
	if err != nil {
		panic(err)
	}
	defer alice.Close()
	for i := range aliceSeeds {
		clear(aliceSeeds[i])
	}

	prof, err := triple.Inspect(aliceBlob)
	if err != nil {
		panic(err)
	}
	clear(aliceBlob) // Secret blob never leaves memory or touches the wire.

	cfgParts, err := splitProfile3(prof, kem, transcript)
	if err != nil {
		panic(err)
	}

	// 3. Bob receives the 3 KEM ciphertexts + 3 masked config fragments in one packet,
	//    reassembles triple.Profile, derives the same 8 seeds, and calls InitKeys.
	bobProf, err := joinProfile3(cfgParts, kem, transcript)
	if err != nil {
		panic(err)
	}
	bobSeeds, err := deriveSeeds3to8(kem, transcript)
	if err != nil {
		panic(err)
	}
	bob, bobBlob, err := triple.InitKeys(bobProf.Name, optsFromProfile(bobProf), bobSeeds)
	if err != nil {
		panic(err)
	}
	defer bob.Close()
	clear(bobBlob)
	for i := range bobSeeds {
		clear(bobSeeds[i])
	}

	// Both peers derive the 3-of-3 intra-epoch ratchet root and wipe kem[0..2].
	ratchetRoot, err := deriveRatchetRoot(kem, transcript)
	if err != nil {
		panic(err)
	}
	for c := range kem {
		clear(kem[c])
	}

	// 4. End-to-end message exchange + fast intra-epoch symmetric Rekey.
	ct, err := alice.EncryptMessage([]byte("Zero-blob 3-to-8 chameleon epoch online."))
	if err != nil {
		panic(err)
	}
	pt, err := bob.DecryptMessage(ct)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(pt, []byte("Zero-blob 3-to-8 chameleon epoch online.")) {
		panic("round-trip mismatch")
	}

	// Per-message symmetric ratchet step (rotates Parallax & Wrapper keys).
	pm, _ := kdf.Derive("blake3", ratchetRoot, "rekey-perm|seq:1", 64)
	wm, _ := kdf.Derive("areion512", ratchetRoot, "rekey-wrap|seq:1", 64)
	clear(ratchetRoot)
	b1, _ := alice.Rekey(pm, wm)
	b2, _ := bob.Rekey(pm, wm)
	clear(b1)
	clear(b2)
	clear(pm)
	clear(wm)

	ct2, err := alice.EncryptMessage([]byte("Post-rekey message #2."))
	if err != nil {
		panic(err)
	}
	pt2, err := bob.DecryptMessage(ct2)
	if err != nil {
		panic(err)
	}
	fmt.Printf("OK: %s | %s (fragment size=%dB)\n", string(pt), string(pt2), len(cfgParts[0]))
}
```
