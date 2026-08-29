#!/usr/bin/env bash
# render-matrix.sh -- render tmp/eitb/compat-matrix.md from
# tmp/eitb/results.tsv. Separated from cross-verify.sh so a completed
# results file can be re-rendered without re-running the fleet.

set -eu
set -o pipefail

REPO="${HOME}/go/src/itb"
EITB_DIR="$REPO/tmp/eitb"
IN_FILE="$REPO/tools/eitb/in-file.txt"
RESULTS="$EITB_DIR/results.tsv"
MATRIX="$EITB_DIR/compat-matrix.md"

if [ ! -f "$RESULTS" ]; then
    echo "render-matrix: missing $RESULTS" >&2
    exit 2
fi

SOURCE_SHA=$(sha256sum "$IN_FILE" | awk '{print $1}')

PROFILES=(
    singlemsg-triple-mac-v1
    singlemsg-triple-nomac-v1
    singlemsg-triple-mac-mixed-v1
    singlemsg-triple-nomac-mixed-v1
    blob-triple-mac-v1
    streaming-aead-triple-mac-v1
    streaming-noaead-triple-v1
    streaming-aead-triple-mac-mixed-v1
    streaming-noaead-triple-mixed-v1
)

LANGS=(
    go
    ada c clojure cpp crystal csharp dart dlang elixir erlang
    fortran fsharp gleam groovy haskell java julia kotlin lfe lua
    nim nodejs ocaml php powershell python r ruby rust scala
    swift vbnet zig
)

declare -A PROFILE_SKIP_REASON
PROFILE_SKIP_REASON[blob-triple-mac-v1]="no cipher surface (blob-only profile; not exercised by eitb encrypt/decrypt)"

TOTAL=$(wc -l < "$RESULTS")
PASS=$(awk -F'\t' '$4=="PASS"{c++}END{print c+0}' "$RESULTS")
FAIL=$(awk -F'\t' '$4=="FAIL"{c++}END{print c+0}' "$RESULTS")
NA=$(awk -F'\t' '$4=="NA"{c++}END{print c+0}' "$RESULTS")

# Detect languages whose encrypt+decrypt never appear as PASS anywhere.
declare -A LANG_PASSES
for lang in "${LANGS[@]}"; do
    LANG_PASSES[$lang]=0
done
while IFS=$'\t' read -r p e d v _rest; do
    [ "$v" = "PASS" ] || continue
    LANG_PASSES[$e]=$(( ${LANG_PASSES[$e]:-0} + 1 ))
    LANG_PASSES[$d]=$(( ${LANG_PASSES[$d]:-0} + 1 ))
done < "$RESULTS"

# Build a 2D matrix cache in one awk pass per profile to avoid 34*34
# per-profile awk invocations. Emits: profile \t enc \t dec \t mark.
declare -A CELL
while IFS=$'\t' read -r p e d v _rest; do
    case "$v" in
        PASS) mark="v" ;;
        FAIL) mark="x" ;;
        NA)   mark="-" ;;
        *)    mark="?" ;;
    esac
    CELL[$p/$e/$d]="$mark"
done < "$RESULTS"

{
    echo "# Cross-Binding Wire-Compat Matrix"
    echo
    echo "Sample: \`tools/eitb/in-file.txt\` (4096 bytes, SHA-256 \`$SOURCE_SHA\`)."
    echo "Fleet: 34 eitb (33 language bindings + Go core)."
    echo "Profiles: 9 shipped."
    echo "Total cross-checks: $TOTAL (34 x 34 x 9 = 10404 nominal)."
    echo
    echo "## Summary"
    echo
    echo "- Total cells: $TOTAL"
    echo "- PASS: $PASS"
    echo "- FAIL: $FAIL"
    echo "- N/A: $NA"
    if [ "$FAIL" -eq 0 ]; then
        echo "- Verdict: **PASS** (every cell that could run round-tripped cleanly)"
    else
        echo "- Verdict: **FAIL** ($FAIL cells produced a decrypt-side failure)"
    fi
    echo
    echo "Legend: \`v\` PASS, \`x\` FAIL, \`-\` N/A (encrypter or decrypter unavailable, or the profile is skipped by design)."
    echo
    echo "N/A breakdown by reason (from results.tsv):"
    awk -F'\t' '$4=="NA"{print $5}' "$RESULTS" | sort | uniq -c | awk '{printf("- `%s`: %d cells\n", $2 " " $3 " " $4 " " $5 " " $6 " " $7 " " $8 " " $9 " " $10, $1)}' \
        | sed -E 's/  +/ /g; s/ \././g; s/`(.*[^ ]) +`/`\1`/'
    echo
    echo "## Per-profile matrix"
    echo
    for profile in "${PROFILES[@]}"; do
        echo "### $profile"
        echo
        if [ -n "${PROFILE_SKIP_REASON[$profile]:-}" ]; then
            echo "Skipped: ${PROFILE_SKIP_REASON[$profile]}. All $(( 34 * 34 )) cells N/A."
            echo
            continue
        fi
        # Header row.
        header="| enc \\\\ dec |"
        sep="|:---:|"
        for dec in "${LANGS[@]}"; do
            header="$header $dec |"
            sep="$sep:---:|"
        done
        echo "$header"
        echo "$sep"
        for enc in "${LANGS[@]}"; do
            row="| **$enc** |"
            for dec in "${LANGS[@]}"; do
                mark="${CELL[$profile/$enc/$dec]:-?}"
                row="$row $mark |"
            done
            echo "$row"
        done
        echo
    done
    if [ "$FAIL" -gt 0 ]; then
        echo "## Failure detail"
        echo
        # Bucket failures by decrypter to spot systemic bindings.
        echo "Failure counts by decrypter (encrypter → decrypter direction):"
        echo
        echo "| decrypter | FAIL count | affected profiles |"
        echo "|:---|---:|:---|"
        awk -F'\t' '$4=="FAIL"{d[$3]++; profs[$3"/"$1]=1} END {
            for (k in d) {
                plist=""; sep=""
                for (pk in profs) { split(pk,a,"/"); if (a[1]==k) { plist=plist sep a[2]; sep=", " } }
                printf("| %s | %d | %s |\n", k, d[k], plist)
            }
        }' "$RESULTS" | sort -t'|' -k3,3 -rn
        echo
        echo "Failure counts by encrypter (encrypter → decrypter direction):"
        echo
        echo "| encrypter | FAIL count |"
        echo "|:---|---:|"
        awk -F'\t' '$4=="FAIL"{e[$2]++} END {for (k in e) printf("| %s | %d |\n", k, e[k])}' "$RESULTS" | sort -t'|' -k3,3 -rn
        echo
        echo "Representative diagnostic (first FAIL line per unique decrypter):"
        echo
        echo "| decrypter | first observed diagnostic |"
        echo "|:---|:---|"
        awk -F'\t' -v OFS='\t' '$4=="FAIL" && !seen[$3]++ {
            diag=$5; gsub(/\|/,"/",diag); if (length(diag)>200) diag=substr(diag,1,200)"...";
            printf("| %s | %s |\n", $3, diag)
        }' "$RESULTS"
        echo
    fi
} > "$MATRIX"

echo "==> matrix rendered: $MATRIX ($(wc -l < "$MATRIX") lines)"
