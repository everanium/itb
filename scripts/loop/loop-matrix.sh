#!/usr/bin/env bash
# Concurrency, zeroization, and memory-stability stress matrix for tools/loop
# and language-binding loop harnesses.
#
# Builds two arms of tools/loop (default CGO + SIMD assembly and
# CGO_ENABLED=0 -tags noitbasm pure-Go fallback) and executes a 92-cell
# stress matrix per arm (184 Go runs by default), plus an optional 20-cell
# matrix per selected language binding (e.g. --bindings c,ada).
#
# Matrix coverage (92 Go cells):
#   - Group 1 (16 cells): 4 (Parallax=on/off x Wrapper=on/off) x 4 surface/mode
#     configurations (both AEAD+MAC, multi-chunk stream_one_shot,
#     singlemsg-triple-nomac-v1, streaming-noaead-triple-v1).
#   - Group 2 (40 cells): all shipped PRF-grade hash primitives x all 4 layer
#     regimes (Parallax=on/off x Wrapper=on/off) across all 3 MAC constructions
#     (hmac-blake3, hmac-sha256, kmac256).
#   - Group 3 (20 cells): key widths (512 / 1024 / 2048), nonce widths
#     (128 / 256 / 512), container floor modes (Per-Region Mode 1 and
#     Per-Container Mode 2), rotating payloads, all explicit DRBG overrides,
#     and mixed-primitive streaming profiles.
#   - Group 4 (16 cells): mixed-primitive Single Message and Streaming AEAD /
#     Non-AEAD profiles, AES-ITB profiles paired with AES-CMAC outer layers,
#     and multi-chunk stream + message stress across AES-CMAC, ChaCha20,
#     Areion-SoEM-256, and Areion-SoEM-512.
#
# Every cell enables periodic rekeying (--rekey-every) and blob export/import
# cycling (--blob-cycle-every) and asserts zero data mismatches, bounded
# post-GC heap delta (heap_ok), and zero leaked goroutines (goroutines_ok).
#
# Working directory defaults to ${TMPDIR:-/tmp}/itb-loop-matrix so no build
# artifacts or logs land inside the repository working tree.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

DURATION="${LOOP_DURATION:-60s}"
PARALLEL="${LOOP_PARALLEL:-4}"
GOROUTINES="${LOOP_GOROUTINES:-3}"
GOMAXPROCS_VAL="${LOOP_GOMAXPROCS:-4}"
ARM_MODE="${LOOP_ARM:-both}"          # default | noitbasm | both | none
BINDINGS_LIST="${LOOP_BINDINGS:-}"    # comma-separated list, e.g. "c,ada"
WORK_DIR="${LOOP_WORK_DIR:-${TMPDIR:-/tmp}/itb-loop-matrix}"
FILTER="${LOOP_FILTER:-}"
CLEAN_LOGS=0

usage() {
  cat <<EOF
Usage: ./scripts/loop/loop-matrix.sh [options]

Options:
  --duration <dur>       Per-cell run duration (default: ${DURATION})
  --parallel <N>         Number of cells to run concurrently (default: ${PARALLEL})
  --goroutines <N>       Worker goroutines/threads per cell (default: ${GOROUTINES})
  --gomaxprocs <N>       GOMAXPROCS per cell (default: ${GOMAXPROCS_VAL})
  --arm <mode>           Go build arm: default | noitbasm | both | none (default: ${ARM_MODE})
  --bindings <list>      Comma-separated bindings to run 16-cell matrix on (e.g. c,ada)
  --with-bindings        Shorthand for --bindings c,ada
  --filter <substr>      Run only cells whose name contains <substr>
  --work-dir <dir>       Output directory for binaries and logs (default: ${WORK_DIR})
  --clean                Wipe existing logs in work-dir before starting
  -h, --help             Show this help text
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration)
      DURATION="$2"
      shift 2
      ;;
    --parallel)
      PARALLEL="$2"
      shift 2
      ;;
    --goroutines)
      GOROUTINES="$2"
      shift 2
      ;;
    --gomaxprocs)
      GOMAXPROCS_VAL="$2"
      shift 2
      ;;
    --arm)
      ARM_MODE="$2"
      shift 2
      ;;
    --bindings)
      BINDINGS_LIST="$2"
      shift 2
      ;;
    --with-bindings)
      BINDINGS_LIST="c,ada"
      shift
      ;;
    --filter)
      FILTER="$2"
      shift 2
      ;;
    --work-dir)
      WORK_DIR="$2"
      shift 2
      ;;
    --clean)
      CLEAN_LOGS=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

mkdir -p "${WORK_DIR}"

if [[ "${CLEAN_LOGS}" -eq 1 ]]; then
  if [[ -z "${WORK_DIR}" || "${WORK_DIR}" != /* || "${WORK_DIR}" == "/" || "${WORK_DIR}" == "${HOME}" || "${WORK_DIR}" == "${REPO_ROOT}" ]]; then
    echo "Refusing --clean on unsafe WORK_DIR: ${WORK_DIR}" >&2
    exit 2
  fi
  echo "[cleanup] removing existing logs under ${WORK_DIR}/logs_*"
  shopt -s nullglob
  for d in "${WORK_DIR}"/logs_*; do
    if [[ -d "${d}" ]]; then
      for f in "${d}"/*.log; do
        [[ -f "${f}" ]] && rm -f "${f}"
      done
      rmdir "${d}" 2>/dev/null || true
    fi
  done
  for f in "${WORK_DIR}"/failures_*.txt; do
    [[ -f "${f}" ]] && rm -f "${f}"
  done
  shopt -u nullglob
fi

# ---------------------------------------------------------------------------
# 64-Cell Go tools/loop Stress Matrix
# ---------------------------------------------------------------------------
declare -a GO_CELLS=(
  # --- Group 1 (16 cells): 4x4 (Parallax x Wrapper) x (both, multi-chunk stream_one_shot, nomac, noaead) ---
  "g1_01_p1_w1_both|--shape both --parallax on --wrapper on --hash areion512 --mac hmac-blake3 --payload-size 1MB --rekey-every 5 --blob-cycle-every 7"
  "g1_02_p1_w0_both|--shape both --parallax on --wrapper off --hash areion512 --mac hmac-blake3 --payload-size 1MB --rekey-every 5 --blob-cycle-every 7"
  "g1_03_p0_w1_both|--shape both --parallax off --wrapper on --hash areion512 --mac hmac-blake3 --payload-size 1MB --rekey-every 5 --blob-cycle-every 7"
  "g1_04_p0_w0_both|--shape both --parallax off --wrapper off --hash areion512 --mac hmac-blake3 --payload-size 1MB --rekey-every 5 --blob-cycle-every 7"

  "g1_05_p1_w1_oneshot_mc|--shape stream_one_shot --parallax on --wrapper on --hash blake3 --mac hmac-blake3 --chunk-size 256KB --payload-size 1MB --rekey-every 5 --blob-cycle-every 7"
  "g1_06_p1_w0_oneshot_mc|--shape stream_one_shot --parallax on --wrapper off --hash blake3 --mac hmac-blake3 --chunk-size 256KB --payload-size 1MB --rekey-every 5 --blob-cycle-every 7"
  "g1_07_p0_w1_oneshot_mc|--shape stream_one_shot --parallax off --wrapper on --hash blake3 --mac hmac-blake3 --chunk-size 256KB --payload-size 1MB --rekey-every 5 --blob-cycle-every 7"
  "g1_08_p0_w0_oneshot_mc|--shape stream_one_shot --parallax off --wrapper off --hash blake3 --mac hmac-blake3 --chunk-size 256KB --payload-size 1MB --rekey-every 5 --blob-cycle-every 7"

  "g1_09_p1_w1_nomac|--profile singlemsg-triple-nomac-v1 --parallax on --wrapper on --hash areion256 --payload-size 1MB --rekey-every 5 --blob-cycle-every 7"
  "g1_10_p1_w0_nomac|--profile singlemsg-triple-nomac-v1 --parallax on --wrapper off --hash areion256 --payload-size 1MB --rekey-every 5 --blob-cycle-every 7"
  "g1_11_p0_w1_nomac|--profile singlemsg-triple-nomac-v1 --parallax off --wrapper on --hash areion256 --payload-size 1MB --rekey-every 5 --blob-cycle-every 7"
  "g1_12_p0_w0_nomac|--profile singlemsg-triple-nomac-v1 --parallax off --wrapper off --hash areion256 --payload-size 1MB --rekey-every 5 --blob-cycle-every 7"

  "g1_13_p1_w1_noaead|--profile streaming-noaead-triple-v1 --shape stream --parallax on --wrapper on --hash blake2b256 --chunk-size 256KB --payload-size 1MB --rekey-every 5 --blob-cycle-every 7"
  "g1_14_p1_w0_noaead|--profile streaming-noaead-triple-v1 --shape stream --parallax on --wrapper off --hash blake2b256 --chunk-size 256KB --payload-size 1MB --rekey-every 5 --blob-cycle-every 7"
  "g1_15_p0_w1_noaead_os|--profile streaming-noaead-triple-v1 --shape stream_one_shot --parallax off --wrapper on --hash blake2b256 --chunk-size 256KB --payload-size 1MB --rekey-every 5 --blob-cycle-every 7"
  "g1_16_p0_w0_noaead_os|--profile streaming-noaead-triple-v1 --shape stream_one_shot --parallax off --wrapper off --hash blake2b256 --chunk-size 256KB --payload-size 1MB --rekey-every 5 --blob-cycle-every 7"

  # --- Group 2 (40 cells): All 10 Hash Primitives x All 4 (Parallax=on/off x Wrapper=on/off) Regimes ---
  "g2_01_aesitb128_p1w1|--shape both --parallax on --wrapper on --hash aesitb128 --mac hmac-blake3 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_02_areion256_p1w1|--shape both --parallax on --wrapper on --hash areion256 --mac hmac-blake3 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_03_areion512_p1w1|--shape both --parallax on --wrapper on --hash areion512 --mac hmac-blake3 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_04_blake2b256_p1w1|--shape both --parallax on --wrapper on --hash blake2b256 --mac hmac-blake3 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_05_blake2b512_p1w1|--shape both --parallax on --wrapper on --hash blake2b512 --mac hmac-blake3 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_06_blake2s_p1w1|--shape both --parallax on --wrapper on --hash blake2s --mac hmac-blake3 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_07_blake3_p1w1|--shape both --parallax on --wrapper on --hash blake3 --mac hmac-blake3 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_08_aescmac_p1w1|--shape both --parallax on --wrapper on --hash aescmac --mac hmac-blake3 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_09_siphash24_p1w1|--shape both --parallax on --wrapper on --hash siphash24 --mac hmac-blake3 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_10_chacha20_p1w1|--shape both --parallax on --wrapper on --hash chacha20 --mac hmac-blake3 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"

  "g2_11_aesitb128_p0w1|--shape both --parallax off --wrapper on --hash aesitb128 --mac kmac256 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_12_areion256_p0w1|--shape both --parallax off --wrapper on --hash areion256 --mac hmac-sha256 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_13_areion512_p0w1|--shape both --parallax off --wrapper on --hash areion512 --mac kmac256 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_14_blake2b256_p0w1|--shape both --parallax off --wrapper on --hash blake2b256 --mac hmac-sha256 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_15_blake2b512_p0w1|--shape both --parallax off --wrapper on --hash blake2b512 --mac hmac-sha256 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_16_blake2s_p0w1|--shape both --parallax off --wrapper on --hash blake2s --mac kmac256 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_17_blake3_p0w1|--shape both --parallax off --wrapper on --hash blake3 --mac hmac-sha256 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_18_aescmac_p0w1|--shape both --parallax off --wrapper on --hash aescmac --mac hmac-blake3 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_19_siphash24_p0w1|--shape both --parallax off --wrapper on --hash siphash24 --mac kmac256 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_20_chacha20_p0w1|--shape both --parallax off --wrapper on --hash chacha20 --mac hmac-sha256 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"

  "g2_21_aesitb128_p1w0|--shape both --parallax on --wrapper off --hash aesitb128 --mac hmac-sha256 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_22_areion256_p1w0|--shape both --parallax on --wrapper off --hash areion256 --mac kmac256 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_23_areion512_p1w0|--shape both --parallax on --wrapper off --hash areion512 --mac hmac-sha256 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_24_blake2b256_p1w0|--shape both --parallax on --wrapper off --hash blake2b256 --mac kmac256 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_25_blake2b512_p1w0|--shape both --parallax on --wrapper off --hash blake2b512 --mac kmac256 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_26_blake2s_p1w0|--shape both --parallax on --wrapper off --hash blake2s --mac hmac-sha256 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_27_blake3_p1w0|--shape both --parallax on --wrapper off --hash blake3 --mac kmac256 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_28_aescmac_p1w0|--shape both --parallax on --wrapper off --hash aescmac --mac kmac256 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_29_siphash24_p1w0|--shape both --parallax on --wrapper off --hash siphash24 --mac hmac-sha256 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_30_chacha20_p1w0|--shape both --parallax on --wrapper off --hash chacha20 --mac kmac256 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"

  "g2_31_aesitb128_p0w0|--shape both --parallax off --wrapper off --hash aesitb128 --mac hmac-blake3 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_32_areion256_p0w0|--shape both --parallax off --wrapper off --hash areion256 --mac hmac-blake3 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_33_areion512_p0w0|--shape both --parallax off --wrapper off --hash areion512 --mac hmac-blake3 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_34_blake2b256_p0w0|--shape both --parallax off --wrapper off --hash blake2b256 --mac hmac-blake3 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_35_blake2b512_p0w0|--shape both --parallax off --wrapper off --hash blake2b512 --mac hmac-blake3 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_36_blake2s_p0w0|--shape both --parallax off --wrapper off --hash blake2s --mac hmac-blake3 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_37_blake3_p0w0|--shape both --parallax off --wrapper off --hash blake3 --mac hmac-blake3 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_38_aescmac_p0w0|--shape both --parallax off --wrapper off --hash aescmac --mac hmac-sha256 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_39_siphash24_p0w0|--shape both --parallax off --wrapper off --hash siphash24 --mac hmac-blake3 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"
  "g2_40_chacha20_p0w0|--shape both --parallax off --wrapper off --hash chacha20 --mac hmac-blake3 --payload-size 512KB --rekey-every 5 --blob-cycle-every 7"

  # --- Group 3 (20 cells): MACs, Key/Nonce Widths, Container Modes 1/2, Rotating Payloads, All 11 DRBGs & Mixed Profiles ---
  "g3_01_mac_hmac_sha256|--shape both --parallax on --wrapper on --hash areion256 --mac hmac-sha256 --key-bits 512 --nonce-bits 128 --payload-size 512KB --rekey-every 4 --blob-cycle-every 6"
  "g3_02_mac_kmac256|--shape both --parallax on --wrapper on --hash areion512 --mac kmac256 --key-bits 2048 --nonce-bits 512 --payload-size 512KB --rekey-every 4 --blob-cycle-every 6"
  "g3_03_kb1024_nb256|--shape both --parallax on --wrapper off --hash blake2b512 --mac hmac-blake3 --key-bits 1024 --nonce-bits 256 --payload-size 512KB --rekey-every 4 --blob-cycle-every 6"
  "g3_04_kb512_nb256|--shape both --parallax off --wrapper off --hash blake2s --mac hmac-sha256 --key-bits 512 --nonce-bits 256 --payload-size 512KB --rekey-every 4 --blob-cycle-every 6"
  "g3_05_blobmode2_b3|--shape both --parallax on --wrapper on --hash blake3 --mac kmac256 --blob-mode 2 --payload-size 512KB --rekey-every 4 --blob-cycle-every 6"
  "g3_06_blobmode2_cmac|--shape both --parallax off --wrapper on --hash aescmac --mac hmac-blake3 --blob-mode 2 --payload-size 512KB --rekey-every 4 --blob-cycle-every 6"
  "g3_07_rot_siphash|--shape both --parallax on --wrapper on --hash siphash24 --mac kmac256 --payload-mode rotating --payload-size 512KB --rekey-every 4 --blob-cycle-every 6"
  "g3_08_drbg_chacha20|--shape both --parallax on --wrapper on --hash chacha20 --mac hmac-blake3 --drbg chacha20 --payload-mode rotating --payload-size 512KB --rekey-every 4 --blob-cycle-every 6"
  "g3_09_drbg_aesitb128|--shape both --parallax on --wrapper on --hash aesitb128 --mac hmac-blake3 --drbg aesitb128 --payload-size 512KB --rekey-every 4 --blob-cycle-every 6"
  "g3_10_drbg_areion256|--shape both --parallax on --wrapper on --hash areion256 --mac hmac-blake3 --drbg areion256 --payload-size 512KB --rekey-every 4 --blob-cycle-every 6"
  "g3_11_drbg_areion512|--shape both --parallax on --wrapper on --hash areion512 --mac hmac-blake3 --drbg areion512 --payload-size 512KB --rekey-every 4 --blob-cycle-every 6"
  "g3_12_drbg_blake2b256|--shape both --parallax on --wrapper on --hash blake2b256 --mac hmac-blake3 --drbg blake2b256 --payload-size 512KB --rekey-every 4 --blob-cycle-every 6"
  "g3_13_drbg_blake2b512|--shape both --parallax on --wrapper on --hash blake2b512 --mac hmac-blake3 --drbg blake2b512 --payload-size 512KB --rekey-every 4 --blob-cycle-every 6"
  "g3_14_drbg_blake2s|--shape both --parallax on --wrapper on --hash blake2s --mac hmac-blake3 --drbg blake2s --payload-size 512KB --rekey-every 4 --blob-cycle-every 6"
  "g3_15_drbg_blake3|--shape both --parallax on --wrapper on --hash blake3 --mac hmac-blake3 --drbg blake3 --payload-size 512KB --rekey-every 4 --blob-cycle-every 6"
  "g3_16_drbg_aescmac|--shape both --parallax on --wrapper on --hash aescmac --mac hmac-blake3 --drbg aescmac --payload-size 512KB --rekey-every 4 --blob-cycle-every 6"
  "g3_17_drbg_siphash24|--shape both --parallax on --wrapper on --hash siphash24 --mac hmac-blake3 --drbg siphash24 --payload-size 512KB --rekey-every 4 --blob-cycle-every 6"
  "g3_18_drbg_csprng|--shape both --parallax on --wrapper on --hash areion256 --mac hmac-blake3 --drbg csprng --payload-size 512KB --rekey-every 4 --blob-cycle-every 6"
  "g3_19_prof_aead_mixed|--profile streaming-aead-triple-mac-mixed-v1 --shape stream --payload-size 1MB --rekey-every 4 --blob-cycle-every 6"
  "g3_20_prof_noaead_mixed|--profile streaming-noaead-triple-mixed-v1 --shape stream_one_shot --payload-size 1MB --rekey-every 4 --blob-cycle-every 6"

  # --- Group 4 (16 cells): Mixed SingleMsg/Stream, AES-ITB Profiles, and Multi-Chunk Layer Permutations ---
  "g4_01_mixed_sm_mac|--profile singlemsg-triple-mac-mixed-v1 --parallax on --wrapper on --payload-size 1MB --rekey-every 4 --blob-cycle-every 6"
  "g4_02_mixed_sm_nomac|--profile singlemsg-triple-nomac-mixed-v1 --parallax off --wrapper on --payload-size 1MB --rekey-every 4 --blob-cycle-every 6"
  "g4_03_mixed_aead_os|--profile streaming-aead-triple-mac-mixed-v1 --shape stream_one_shot --parallax on --wrapper off --chunk-size 256KB --payload-size 1MB --rekey-every 4 --blob-cycle-every 6"
  "g4_04_mixed_noaead_st|--profile streaming-noaead-triple-mixed-v1 --shape stream --parallax on --wrapper on --chunk-size 256KB --payload-size 1MB --rekey-every 4 --blob-cycle-every 6"

  "g4_05_aesitb_aead_p1w1|--profile streaming-aead-aesitb-mac-v1 --hash aesitb128 --shape stream --parallax on --wrapper on --chunk-size 256KB --payload-size 1MB --rekey-every 4 --blob-cycle-every 6"
  "g4_06_aesitb_aead_os_p0w1|--profile streaming-aead-aesitb-mac-v1 --hash aesitb128 --shape stream_one_shot --parallax off --wrapper on --chunk-size 256KB --payload-size 1MB --rekey-every 4 --blob-cycle-every 6"
  "g4_07_aesitb_sm_mac_p1w1|--profile singlemsg-aesitb-mac-v1 --hash aesitb128 --parallax on --wrapper on --payload-size 1MB --rekey-every 4 --blob-cycle-every 6"
  "g4_08_aesitb_noaead_p1w0|--profile streaming-noaead-aesitb-v1 --hash aesitb128 --shape stream --parallax on --wrapper off --chunk-size 256KB --payload-size 1MB --rekey-every 4 --blob-cycle-every 6"

  "g4_09_aescmac_mc_p1w0|--shape both --parallax on --wrapper off --hash aescmac --mac kmac256 --chunk-size 256KB --payload-size 1MB --rekey-every 4 --blob-cycle-every 6"
  "g4_10_aescmac_mc_p0w0|--shape both --parallax off --wrapper off --hash aescmac --mac hmac-sha256 --chunk-size 256KB --payload-size 1MB --rekey-every 4 --blob-cycle-every 6"
  "g4_11_chacha20_mc_p1w0|--shape both --parallax on --wrapper off --hash chacha20 --mac kmac256 --chunk-size 256KB --payload-size 1MB --rekey-every 4 --blob-cycle-every 6"
  "g4_12_chacha20_mc_p0w0|--shape both --parallax off --wrapper off --hash chacha20 --mac hmac-blake3 --chunk-size 256KB --payload-size 1MB --rekey-every 4 --blob-cycle-every 6"

  "g4_13_areion256_mc_p1w0|--shape both --parallax on --wrapper off --hash areion256 --mac kmac256 --chunk-size 256KB --payload-size 1MB --rekey-every 4 --blob-cycle-every 6"
  "g4_14_areion256_mc_p0w0|--shape both --parallax off --wrapper off --hash areion256 --mac hmac-blake3 --chunk-size 256KB --payload-size 1MB --rekey-every 4 --blob-cycle-every 6"
  "g4_15_areion512_mc_p1w0|--shape both --parallax on --wrapper off --hash areion512 --mac hmac-sha256 --chunk-size 256KB --payload-size 1MB --rekey-every 4 --blob-cycle-every 6"
  "g4_16_areion512_mc_p0w0|--shape both --parallax off --wrapper off --hash areion512 --mac hmac-blake3 --chunk-size 256KB --payload-size 1MB --rekey-every 4 --blob-cycle-every 6"
)

# ---------------------------------------------------------------------------
# 20-Cell Binding loop Stress Matrix (per selected binding)
# ---------------------------------------------------------------------------
declare -a BINDING_CELLS=(
  "b01_p1_w1_both|--shape both --parallax on --wrapper on --hash areion512 --mac hmac-blake3 --payload-size 1MB --rekey-every 4 --blob-cycle-every 6"
  "b02_p1_w0_both|--shape both --parallax on --wrapper off --hash areion512 --mac hmac-blake3 --payload-size 1MB --rekey-every 4 --blob-cycle-every 6"
  "b03_p0_w1_both|--shape both --parallax off --wrapper on --hash areion512 --mac hmac-blake3 --payload-size 1MB --rekey-every 4 --blob-cycle-every 6"
  "b04_p0_w0_both|--shape both --parallax off --wrapper off --hash areion512 --mac hmac-blake3 --payload-size 1MB --rekey-every 4 --blob-cycle-every 6"

  "b05_mc_stream|--shape stream --parallax on --wrapper on --hash blake3 --mac hmac-blake3 --chunk-size 256KB --payload-size 1MB --rekey-every 4 --blob-cycle-every 6"
  "b06_mc_oneshot|--shape stream_one_shot --parallax on --wrapper on --hash areion256 --mac kmac256 --chunk-size 256KB --payload-size 1MB --rekey-every 4 --blob-cycle-every 6"
  "b07_nomac|--profile singlemsg-triple-nomac-v1 --parallax on --wrapper on --hash areion256 --payload-size 1MB --rekey-every 4 --blob-cycle-every 6"
  "b08_noaead|--profile streaming-noaead-triple-v1 --shape stream --parallax on --wrapper on --hash blake2b256 --chunk-size 256KB --payload-size 1MB --rekey-every 4 --blob-cycle-every 6"

  "b09_mixed_aead|--profile streaming-aead-triple-mac-mixed-v1 --shape stream --parallax on --wrapper on --chunk-size 256KB --payload-size 1MB --rekey-every 4 --blob-cycle-every 6"
  "b10_mixed_sm|--profile singlemsg-triple-mac-mixed-v1 --parallax on --wrapper on --payload-size 1MB --rekey-every 4 --blob-cycle-every 6"
  "b11_aesitb_aead|--profile streaming-aead-aesitb-mac-v1 --hash aesitb128 --shape stream --parallax on --wrapper on --chunk-size 256KB --payload-size 1MB --rekey-every 4 --blob-cycle-every 6"
  "b12_aesitb_sm|--profile singlemsg-aesitb-mac-v1 --hash aesitb128 --parallax on --wrapper on --payload-size 1MB --rekey-every 4 --blob-cycle-every 6"

  "b13_aescmac_kmac|--shape both --parallax on --wrapper on --hash aescmac --mac kmac256 --chunk-size 256KB --payload-size 512KB --rekey-every 4 --blob-cycle-every 6"
  "b14_chacha20_sha|--shape both --parallax off --wrapper on --hash chacha20 --mac hmac-sha256 --chunk-size 256KB --payload-size 512KB --rekey-every 4 --blob-cycle-every 6"
  "b15_areion256_bm2|--shape both --parallax on --wrapper off --hash areion256 --mac hmac-blake3 --blob-mode 2 --payload-size 512KB --rekey-every 4 --blob-cycle-every 6"
  "b16_blake2s_rot|--shape both --parallax on --wrapper on --hash blake2s --mac hmac-blake3 --payload-mode rotating --drbg aesitb128 --payload-size 512KB --rekey-every 4 --blob-cycle-every 6"
  "b17_blake2b512_sha|--shape both --parallax on --wrapper on --hash blake2b512 --mac hmac-sha256 --chunk-size 256KB --payload-size 512KB --rekey-every 4 --blob-cycle-every 6"
  "b18_siphash24_kmac|--shape both --parallax off --wrapper on --hash siphash24 --mac kmac256 --chunk-size 256KB --payload-size 512KB --rekey-every 4 --blob-cycle-every 6"
  "b19_mixed_nomac|--profile singlemsg-triple-nomac-mixed-v1 --parallax on --wrapper on --payload-size 1MB --rekey-every 4 --blob-cycle-every 6"
  "b20_mixed_noaead|--profile streaming-noaead-triple-mixed-v1 --shape stream --parallax on --wrapper on --chunk-size 256KB --payload-size 1MB --rekey-every 4 --blob-cycle-every 6"
)

run_suite() {
  local suite_label="$1"
  local loop_bin="$2"
  local log_dir="$3"
  local fail_summary="$4"
  shift 4
  local cells=("$@")

  mkdir -p "${log_dir}"
  : > "${fail_summary}"

  local filtered_cells=()
  for entry in "${cells[@]}"; do
    local name="${entry%%|*}"
    if [[ -z "${FILTER}" || "${name}" == *"${FILTER}"* ]]; then
      filtered_cells+=("${entry}")
    fi
  done

  local total=${#filtered_cells[@]}
  local failed=0

  echo "=================================================================="
  echo "[matrix:${suite_label}] running ${total} cells, duration=${DURATION}, goroutines=${GOROUTINES}, parallel=${PARALLEL}"
  echo "  binary: ${loop_bin}"
  echo "  logs:   ${log_dir}/"
  echo "=================================================================="

  local pending_indices=()
  for idx in "${!filtered_cells[@]}"; do
    local entry="${filtered_cells[$idx]}"
    local name="${entry%%|*}"
    local log_file="${log_dir}/${name}.log"
    if [[ -f "${log_file}" ]] && grep -q "verdict: PASS" "${log_file}" && ! grep -qE "DATA MISMATCH|verdict: FAIL|panic:" "${log_file}"; then
      local verdict
      verdict=$(grep -E "verdict:" "${log_file}" | tail -n 1 || true)
      echo "  [SKIP-PASS] (${suite_label}) ${name}: ${verdict}"
    else
      pending_indices+=("${idx}")
    fi
  done

  local num_pending=${#pending_indices[@]}
  local p_idx=0
  while [[ "${p_idx}" -lt "${num_pending}" ]]; do
    local pids=()
    local names=()
    local cmdlines=()
    local batch_start=$((p_idx + 1))
    local batch_end=$((p_idx + PARALLEL))
    if [[ "${batch_end}" -gt "${num_pending}" ]]; then
      batch_end="${num_pending}"
    fi
    echo "=== [${suite_label}] Batch ${batch_start}..${batch_end} of ${num_pending} (started $(date +%H:%M:%S)) ==="
    for ((b = 0; b < PARALLEL && p_idx < num_pending; b++, p_idx++)); do
      local c_idx="${pending_indices[$p_idx]}"
      local entry="${filtered_cells[$c_idx]}"
      local name="${entry%%|*}"
      local args="${entry#*|}"
      local log_file="${log_dir}/${name}.log"
      local full_cmd="${loop_bin} --duration ${DURATION} --goroutines ${GOROUTINES} --gomaxprocs ${GOMAXPROCS_VAL} ${args}"
      echo "# SUITE: ${suite_label}" >"${log_file}"
      echo "# CMD: ${full_cmd}" >>"${log_file}"
      # shellcheck disable=SC2086
      "${loop_bin}" --duration "${DURATION}" --goroutines "${GOROUTINES}" --gomaxprocs "${GOMAXPROCS_VAL}" ${args} >>"${log_file}" 2>&1 &
      pids+=("$!")
      names+=("${name}")
      cmdlines+=("${full_cmd}")
    done

    for i in "${!pids[@]}"; do
      local pid="${pids[$i]}"
      local name="${names[$i]}"
      local cmdline="${cmdlines[$i]}"
      local log_file="${log_dir}/${name}.log"
      local rc=0
      wait "${pid}" || rc=$?
      local verdict
      verdict=$(grep -E "verdict:" "${log_file}" | tail -n 1 || true)
      if [[ "${rc}" -eq 0 ]] && grep -q "verdict: PASS" "${log_file}" && ! grep -qE "DATA MISMATCH|verdict: FAIL|panic:" "${log_file}"; then
        echo "  [PASS] (${suite_label}) ${name}: ${verdict}"
      else
        echo "  [FAIL] (${suite_label}) ${name} (exit=${rc})"
        echo "         cmd: ${cmdline}"
        echo "         log: ${log_file}"
        grep -nE "DATA MISMATCH|g[0-9]+ iter|verdict:|FAIL|panic:|warn:" "${log_file}" || true
        tail -n 20 "${log_file}" || true
        {
          echo "[FAIL] (${suite_label}) ${name} (exit=${rc})"
          echo "  cmd: ${cmdline}"
          echo "  log: ${log_file}"
          grep -nE "DATA MISMATCH|g[0-9]+ iter|verdict:|FAIL|panic:|warn:" "${log_file}" || true
          echo ""
        } >>"${fail_summary}"
        failed=$((failed + 1))
      fi
    done
  done

  echo "=== [${suite_label}] Complete: $((total - failed))/${total} passed, ${failed} failed ==="
  if [[ "${failed}" -gt 0 ]]; then
    echo "=== [${suite_label}] Failure Summary (${fail_summary}) ==="
    cat "${fail_summary}"
  fi
  return "${failed}"
}

OVERALL_FAILED=0

if [[ "${ARM_MODE}" == "default" || "${ARM_MODE}" == "both" ]]; then
  LOOP_BIN_DEFAULT="${WORK_DIR}/loop_default"
  echo "[build] building default arm -> ${LOOP_BIN_DEFAULT}"
  (cd "${REPO_ROOT}" && go build -o "${LOOP_BIN_DEFAULT}" ./tools/loop)
  run_suite "default" "${LOOP_BIN_DEFAULT}" "${WORK_DIR}/logs_default" "${WORK_DIR}/failures_default.txt" "${GO_CELLS[@]}" || OVERALL_FAILED=$((OVERALL_FAILED + $?))
fi

if [[ "${ARM_MODE}" == "noitbasm" || "${ARM_MODE}" == "both" ]]; then
  LOOP_BIN_NOITBASM="${WORK_DIR}/loop_noitbasm"
  echo "[build] building CGO_ENABLED=0 -tags noitbasm arm -> ${LOOP_BIN_NOITBASM}"
  (cd "${REPO_ROOT}" && CGO_ENABLED=0 go build -tags noitbasm -o "${LOOP_BIN_NOITBASM}" ./tools/loop)
  run_suite "noitbasm" "${LOOP_BIN_NOITBASM}" "${WORK_DIR}/logs_noitbasm" "${WORK_DIR}/failures_noitbasm.txt" "${GO_CELLS[@]}" || OVERALL_FAILED=$((OVERALL_FAILED + $?))
fi

if [[ -n "${BINDINGS_LIST}" ]]; then
  HOST_ARCH="amd64"
  if [[ "$(uname -m)" == "aarch64" || "$(uname -m)" == "arm64" ]]; then
    HOST_ARCH="arm64"
  fi
  SHARED_LIB="${REPO_ROOT}/dist/linux-${HOST_ARCH}/libitb3.so"
  echo "[build] rebuilding shared library -> ${SHARED_LIB}"
  (cd "${REPO_ROOT}" && go build -trimpath -buildmode=c-shared -o "${SHARED_LIB}" ./cmd/cshared)
  export LD_LIBRARY_PATH="${REPO_ROOT}/dist/linux-${HOST_ARCH}:${LD_LIBRARY_PATH:-}"
  IFS=',' read -r -a BINDING_ARR <<<"${BINDINGS_LIST}"
  for b_name in "${BINDING_ARR[@]}"; do
    b_name="${b_name// /}"
    [[ -z "${b_name}" ]] && continue
    echo "[build] rebuilding binding ${b_name} against ${SHARED_LIB}"
    (cd "${REPO_ROOT}/bindings/${b_name}" && ./build.sh)
    b_bin="${REPO_ROOT}/bindings/${b_name}/loop/run_loop.sh"
    if [[ ! -x "${b_bin}" ]]; then
      b_bin="${REPO_ROOT}/bindings/${b_name}/loop/loop"
    fi
    if [[ ! -x "${b_bin}" && -f "${REPO_ROOT}/bindings/${b_name}/loop/build.sh" ]]; then
      echo "[build] building binding loop binary for ${b_name}"
      (cd "${REPO_ROOT}/bindings/${b_name}/loop" && ./build.sh)
    fi
    run_suite "binding_${b_name}" "${b_bin}" "${WORK_DIR}/logs_binding_${b_name}" "${WORK_DIR}/failures_binding_${b_name}.txt" "${BINDING_CELLS[@]}" || OVERALL_FAILED=$((OVERALL_FAILED + $?))
  done
fi

exit "${OVERALL_FAILED}"
