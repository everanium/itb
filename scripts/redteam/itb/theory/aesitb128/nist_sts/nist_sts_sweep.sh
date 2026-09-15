#!/usr/bin/env bash
# NIST STS 2.1.2 sweep runner for ChainHash<AES-ITB-128>.
#
# Grid:
#   r     in {1, 2, 3, 4, 5, 6, 7, 8, 12, 16}
#   shape in {13, 20, 36, 68}   (shipped inner-Barrier data lengths)
#   trial in {1, 2, 3}          (three fresh-seed repeats per cell)
# -> 120 cells total.
#
# Per cell:
#   1. Generate 1.25 MB of ChainHash<aesitb128> lo-lane output
#      via nist_sts_stream_gen.py (~156_250 calls, 10^7 bits).
#   2. Drive /usr/bin/nist-sts through nist_sts_run.sh on the stream:
#      10 substreams of 10^6 bits, all 15 tests, default parameters.
#   3. Deposit `finalAnalysisReport.txt` (+ per-test subdirs) under
#      ${OUTROOT}/r{R}_shape{N}_trial{T}/ .
#
# Reproducibility: each cell logs its 32-byte hex seed_hex to
# ${OUTROOT}/seed_log.txt (one line per cell). Fresh urandom per cell.
#
# Progress: prints one line per cell to stdout,
#   [cell K/120] r=R shape=N trial=T -- passed X/15 (elapsed Ss)
#
# Env overrides:
#   OUTROOT        default $HOME/scratch/redteam/aesitb128_nist_sts
#   R_LIST         default "1 2 3 4 5 6 7 8 12 16"
#   SHAPE_LIST     default "13 20 36 68"
#   TRIAL_LIST     default "1 2 3"
#   SAMPLES        default 156250   (10^7 bits per cell)
#   BITS_PER_STREAM default 1000000 (10^6 bits, NIST STS default)
#   N_STREAMS      default 10       (NIST STS default)
set -euo pipefail

HERE="$(dirname "$(readlink -f "$0")")"
GEN="$HERE/nist_sts_stream_gen.py"
DRIVER="$HERE/nist_sts_run.sh"

OUTROOT="${OUTROOT:-$HOME/scratch/redteam/aesitb128_nist_sts}"
R_LIST="${R_LIST:-1 2 3 4 5 6 7 8 12 16}"
SHAPE_LIST="${SHAPE_LIST:-13 20 36 68}"
TRIAL_LIST="${TRIAL_LIST:-1 2 3}"
SAMPLES="${SAMPLES:-156250}"
BITS_PER_STREAM="${BITS_PER_STREAM:-1000000}"
N_STREAMS="${N_STREAMS:-10}"

mkdir -p "$OUTROOT"
SEED_LOG="$OUTROOT/seed_log.txt"
: > "$SEED_LOG"
SWEEP_LOG="$OUTROOT/sweep.log"
: > "$SWEEP_LOG"

# Count total cells for progress messages.
TOTAL=0
for r in $R_LIST; do
    for s in $SHAPE_LIST; do
        for t in $TRIAL_LIST; do
            TOTAL=$((TOTAL + 1))
        done
    done
done

echo "[sweep] outroot=$OUTROOT total=$TOTAL cells" | tee -a "$SWEEP_LOG"
echo "[sweep] samples=$SAMPLES bits_per_stream=$BITS_PER_STREAM n_streams=$N_STREAMS" \
    | tee -a "$SWEEP_LOG"

K=0
SWEEP_START=$(date +%s)
for r in $R_LIST; do
    for s in $SHAPE_LIST; do
        for t in $TRIAL_LIST; do
            K=$((K + 1))
            cell_dir="$OUTROOT/r${r}_shape${s}_trial${t}"
            mkdir -p "$cell_dir"
            # Skip if this cell already has a completed report.
            if [[ -s "$cell_dir/finalAnalysisReport.txt" ]]; then
                echo "[cell $K/$TOTAL] r=$r shape=$s trial=$t -- SKIP (report exists)" \
                    | tee -a "$SWEEP_LOG"
                continue
            fi
            cell_start=$(date +%s)
            bin_file="$cell_dir/stream.bin"
            seed_hex=$(python3 -c 'import os,sys;sys.stdout.write(os.urandom(32).hex())')
            echo "cell r=$r shape=$s trial=$t seed_hex=$seed_hex" >> "$SEED_LOG"

            python3 "$GEN" \
                --rounds "$r" \
                --data-len "$s" \
                --samples "$SAMPLES" \
                --seed-hex "$seed_hex" \
                --out "$bin_file" 2>> "$cell_dir/gen.log"

            bash "$DRIVER" "$bin_file" "$cell_dir" "$BITS_PER_STREAM" "$N_STREAMS" \
                >> "$cell_dir/driver.log" 2>&1

            # Free bin file after report is generated (each is 1.25 MB * 120 cells = 150 MB).
            rm -f "$bin_file"

            elapsed=$(( $(date +%s) - cell_start ))
            if [[ -s "$cell_dir/finalAnalysisReport.txt" ]]; then
                # Quick 15-test pass count via awk (proportion column min per test).
                passed=$(awk '
                    /^[[:space:]]*([0-9]+[[:space:]]+){10}([0-9.]+|----).*[[:space:]][0-9]+\/[0-9]+[[:space:]]+[A-Za-z]+/ {
                        n = split($0, f, /[[:space:]]+/)
                        # last field = test name; second-to-last = k/N
                        # Handle leading empty field from indented lines.
                        while (f[1] == "") { for (i=1;i<n;i++) f[i]=f[i+1]; n-- }
                        test = f[n]; prop = f[n-1]
                        split(prop, kn, "/"); k = kn[1] + 0; N = kn[2] + 0
                        if (!(test in min_k) || k < min_k[test]) { min_k[test] = k; denom[test] = N }
                    }
                    END {
                        pass = 0
                        for (t in min_k) {
                            thr = (denom[t] == 10) ? 8 : (denom[t] == 7) ? 6 : denom[t] - 3
                            if (min_k[t] >= thr) pass++
                        }
                        print pass
                    }
                ' "$cell_dir/finalAnalysisReport.txt")
                msg="[cell $K/$TOTAL] r=$r shape=$s trial=$t -- passed $passed/15 (${elapsed}s)"
            else
                msg="[cell $K/$TOTAL] r=$r shape=$s trial=$t -- MISSING report (${elapsed}s)"
            fi
            echo "$msg" | tee -a "$SWEEP_LOG"
        done
    done
done

SWEEP_ELAPSED=$(( $(date +%s) - SWEEP_START ))
echo "[sweep] complete, elapsed=${SWEEP_ELAPSED}s, seed_log=$SEED_LOG" \
    | tee -a "$SWEEP_LOG"
