# itb3 — Utility for ITB Triple Ouroboros

`itb3` is the CLI wrapper for the ITB Triple Ouroboros
construction. It wraps the shipped [`github.com/everanium/itb/triple`]
Go surface so a caller who only needs to create a session configuration blob,
encrypt / decrypt payloads, rotate outer masters, or inspect a stored
blob does not have to write Go.

## Installation

```sh
go install github.com/everanium/itb/cmd/itb3@latest
```

The binary is a `CGO_ENABLED=0` static build.

## Quick start

```sh
# Generate a Streaming AEAD session blob:
itb3 genblob aead mixed256 -k 2048 -m kmac256 -c 16 -o blob.json

# Encrypt / decrypt a payload under the session:
itb3 encrypt blob.json -i plain.txt -o cipher.bin
itb3 decrypt blob.json -i cipher.bin -o dec.txt

# Rotate outer masters (blob's toggle state must match -p / -w):
itb3 rekey blob.json -p -w -o blob.json      # in-place rewrite

# Inspect / validate a stored blob:
itb3 inspect blob.json
itb3 verify  blob.json
```

## Subcommand reference

| Subcommand | Purpose |
|---|---|
| `itb3 genblob <mode> <hash> [flags]` | Build a fresh session configuration blob. |
| `itb3 encrypt <blob.json> [-i FILE] [-o FILE]` | Encrypt input plaintext under a blob. |
| `itb3 decrypt <blob.json> [-i FILE] [-o FILE]` | Decrypt input ciphertext under a blob. |
| `itb3 rekey <blob.json> [-p] [-w] [-o FILE]` | Rotate parallax / wrapper masters (blob wins toggle assertion). |
| `itb3 inspect <blob.json> [-o FILE]` | Print blob metadata (no secret material). |
| `itb3 verify <blob.json>` | Validate a stored blob (silent on success, non-zero on failure). |
| `itb3 hashes` | List shipped hash primitives. |
| `itb3 macs` | List shipped MAC primitives. |
| `itb3 ciphers` | List shipped wrapper outer ciphers. |
| `itb3 modes` | List CLI mode positional tokens. |
| `itb3 profiles` | List registered profile catalogue names. |
| `itb3 catalog` | Unified multi-section dump of accepted inputs. |
| `itb3 version` | Print CLI + library version. |
| `itb3 completion [bash\|zsh\|fish\|powershell]` | Emit shell-completion script. |
| `itb3 help [subcmd]` | Cobra-auto help. |

### `inspect` field set

`itb3 inspect blob.json` renders the recipe carried inside the blob
via `triple.Inspect`: `profile`, `mode`, `width`, either `inner_hash`
or the 8-slot `mixed_hashes` comma list, `key_bits`, `mac_name`
(`(none)` for a No MAC profile), `tag_stub_size` when set,
`chunk_size` for streaming modes (`(default)` when the profile
inherits the compile-in default), `wrapper` / `wrapper_cipher`,
`parallax` / `parallax_palette` / `parallax_segment_size`, and
`blob_bytes`. No secret material is emitted.

## Stdin / stdout convention

- Output flag omitted → stdout.
- Input flag omitted, stdin piped → read stdin.
- Input flag omitted, stdin is a TTY → error (`missing input, use -i FILE`).
- Input flag set → strict file check (no fallback).

## Notes

- The CLI is a pure wrapper: no new cryptographic logic, no new wire
  format, no on-disk state beyond the blob file.
- `-o` writes the blob to disk with mode `0600`; every read path
  loads it via `triple.LoadF`. The blob carries the resolved
  `triple.Profile` record — the shipped-catalogue prefix reserved for
  CLI-generated handles is `itb3-<mode>-<hash>` and is only a label
  the sender attaches; the receiver reconstructs from the recipe
  alone, so no matching registration is required on the receiving
  side.
- Custom hash / MAC primitives registered through the Go library are
  not addressable from the CLI; every field the CLI encodes is a
  shipped-registry index.

See the library docs at
[`github.com/everanium/itb`](https://github.com/everanium/itb) for the
full triple / wrapper / parallax API.
